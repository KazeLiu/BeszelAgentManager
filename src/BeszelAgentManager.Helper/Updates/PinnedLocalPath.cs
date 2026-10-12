using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace BeszelAgentManager.Helper.Updates;

// Keep every ancestor open without FILE_SHARE_DELETE. Path checks alone do not
// prevent a directory from being replaced between verification and an operation.
[SupportedOSPlatform("windows")]
internal sealed class PinnedLocalPath : IDisposable
{
    private readonly List<SafeFileHandle> _ancestors = [];
    internal SafeFileHandle Handle { get; private set; } = null!;
    internal string Path { get; }

    private PinnedLocalPath(string path, bool directory, bool writable)
    {
        Path = ValidatePath(path);
        try
        {
            var root = System.IO.Path.GetPathRoot(Path)!;
            var components = Path[root.Length..].Split(System.IO.Path.DirectorySeparatorChar,
                StringSplitOptions.RemoveEmptyEntries);
            var current = root;
            _ancestors.Add(Open(current, directory: true, writable: false));
            for (var i = 0; i < components.Length; i++)
            {
                current = System.IO.Path.Combine(current, components[i]);
                var final = i == components.Length - 1;
                _ancestors.Add(Open(current, directory: !final || directory, writable: final && writable));
            }
            Handle = _ancestors[^1];
        }
        catch { Dispose(); throw; }
    }

    internal static PinnedLocalPath Directory(string path, bool writable = false) => new(path, true, writable);
    internal static PinnedLocalPath File(string path) => new(path, false, false);

    private static string ValidatePath(string path)
    {
        // Disallow remote/device namespaces and alternate data streams.
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':'
            || path[2] != '\\' || path[3..].Contains(':') || path.Contains('/'))
            throw new IOException("Only absolute local drive paths are permitted.");
        var full = System.IO.Path.GetFullPath(path).TrimEnd('\\');
        if (full.Length == 2) full += "\\";
        if (path.Split('\\').Skip(1).Any(p => p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.')))
            throw new IOException("Ambiguous local path rejected.");
        return full;
    }

    private static SafeFileHandle Open(string path, bool directory, bool writable)
    {
        const uint readControl = 0x00020000, writeDac = 0x00040000, writeOwner = 0x00080000;
        // FILE_READ_ATTRIBUTES alone does not participate in Windows sharing
        // checks for deletion. Request read-data/list-directory as well.
        var access = readControl | 0x80000000u;
        if (writable) access |= writeDac | writeOwner;
        var handle = CreateFile(path, access, directory ? 3u : 1u, IntPtr.Zero, 3,
            0x00200000u | (directory ? 0x02000000u : 0u), IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "Could not pin a local filesystem object.");
        }
        try
        {
            if (!GetFileInformationByHandle(handle, out var info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory
                || !directory && info.NumberOfLinks != 1)
                throw new IOException("Reparse points, unexpected object types and multiply linked files are rejected.");
            return handle;
        }
        catch { handle.Dispose(); throw; }
    }

    internal RawSecurityDescriptor ReadSecurity()
    {
        const uint ownerAndDacl = 5;
        GetKernelObjectSecurity(Handle, ownerAndDacl, null, 0, out var size);
        if (size is 0 or > 64 * 1024) throw new IOException("Invalid filesystem security descriptor size.");
        var data = new byte[size];
        if (!GetKernelObjectSecurity(Handle, ownerAndDacl, data, size, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return new RawSecurityDescriptor(data, 0);
    }

    internal void SetDirectorySecurity(DirectorySecurity security, bool owner)
    {
        // Apply to the object held open, never resolve its pathname again.
        if (!SetKernelObjectSecurity(Handle, 0x80000004u | (owner ? 1u : 0u), security.GetSecurityDescriptorBinaryForm()))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not secure the pinned directory.");
    }

    internal void RequireProtected()
    {
        ValidateProtectedSecurity(ReadSecurity());
    }

    internal static void ValidateProtectedSecurity(RawSecurityDescriptor descriptor)
    {
        if (!IsTrusted(descriptor.Owner) || descriptor.DiscretionaryAcl is null)
            throw new IOException("Update storage must be owned by SYSTEM or Administrators with a restricted ACL.");
        foreach (GenericAce ace in descriptor.DiscretionaryAcl)
        {
            // Unknown/conditional ACEs cannot establish a trusted write boundary.
            if (ace is not CommonAce common || common.IsCallback)
                throw new IOException("Unsupported update-storage access rule.");
            const uint mutation = 0x10000000u | 0x40000000u | 0x000D0156u;
            if (common.AceQualifier == AceQualifier.AccessAllowed
                && !IsTrusted(common.SecurityIdentifier) && ((uint)common.AccessMask & mutation) != 0)
                throw new IOException("Update storage permits writes by an untrusted account.");
        }
    }

    private static bool IsTrusted(SecurityIdentifier? sid) => sid is not null
        && (sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));

    public void Dispose()
    {
        for (var i = _ancestors.Count - 1; i >= 0; i--) _ancestors[i].Dispose();
        _ancestors.Clear();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal uint Attributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        internal uint Volume, SizeHigh, SizeLow, NumberOfLinks, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(SafeFileHandle handle, uint information, byte[]? descriptor, uint length, out uint required);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint information, byte[] descriptor);
}
