using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using BeszelAgentManager.Helper.Updates;
using Xunit;

namespace BeszelAgentManager.Core.Tests;

[SupportedOSPlatform("windows")]
public sealed class PinnedLocalPathTests
{
    [Theory]
    [InlineData("\\\\server\\share\\checkpoint.json")]
    [InlineData("\\\\?\\C:\\data")]
    [InlineData("C:\\data\\file:stream")]
    [InlineData("C:\\data\\..\\outside")]
    [InlineData("C:\\data.\\file")]
    public void RejectsAmbiguousAndRemotePaths(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Throws<IOException>(() => PinnedLocalPath.Directory(path));
    }

    [Fact]
    public void HeldAncestorCannotBeRenamed()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new TemporaryTree();
        var child = Directory.CreateDirectory(Path.Combine(fixture.Root, "child")).FullName;
        using (var pinned = PinnedLocalPath.Directory(child))
        {
            Assert.Throws<IOException>(() => Directory.Move(fixture.Root, fixture.Root + "-moved"));
            Assert.Throws<IOException>(() => Directory.Move(child, child + "-moved"));
        }
        Directory.Move(child, child + "-moved");
    }

    [Fact]
    public void HeldFileCannotBeWrittenOrReplaced()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new TemporaryTree();
        var path = Path.Combine(fixture.Root, "checkpoint.json");
        File.WriteAllText(path, "original");
        using (var pinned = PinnedLocalPath.File(path))
        {
            Assert.Throws<IOException>(() => File.WriteAllText(path, "changed"));
            Assert.Throws<IOException>(() => File.Move(path, path + ".moved"));
        }
        Assert.Equal("original", File.ReadAllText(path));
    }

    [Fact]
    public void HardLinkedFileIsRejectedWithoutChangingIt()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new TemporaryTree();
        var path = Path.Combine(fixture.Root, "source.txt");
        var alias = Path.Combine(fixture.Root, "alias.txt");
        File.WriteAllText(path, "unchanged");
        if (!CreateHardLink(alias, path, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
        Assert.Throws<IOException>(() => PinnedLocalPath.File(alias));
        Assert.Equal("unchanged", File.ReadAllText(path));
    }

    [Fact]
    public void UnprotectedUserOwnedDirectoryCannotHostUpdates()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new TemporaryTree();
        using var pinned = PinnedLocalPath.Directory(fixture.Root);
        Assert.Throws<IOException>(() => pinned.RequireProtected());
    }

    [Fact]
    public void UpdateStoreRefusesUserWritableParentBeforeCreatingFiles()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new TemporaryTree();
        Assert.Throws<IOException>(() => new ProtectedUpdateStore(fixture.Root));
        Assert.Empty(Directory.EnumerateFileSystemEntries(fixture.Root));
    }

    [Theory]
    [InlineData("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", true)]
    [InlineData("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", true)]
    [InlineData("O:SYD:P(A;;FA;;;WD)", false)]
    [InlineData("O:SYD:P(A;;DC;;;BU)", false)]
    [InlineData("O:SYD:P(A;;0x00040000;;;BU)", false)]
    public void ProtectedAclRequiresTrustedOwnersAndWriters(string sddl, bool valid)
    {
        if (!OperatingSystem.IsWindows()) return;
        var descriptor = new RawSecurityDescriptor(sddl);
        if (valid) PinnedLocalPath.ValidateProtectedSecurity(descriptor);
        else Assert.Throws<IOException>(() => PinnedLocalPath.ValidateProtectedSecurity(descriptor));
    }

    [Fact]
    public void ReparsePointInAncestorIsRejected()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new TemporaryTree();
        var target = Directory.CreateDirectory(Path.Combine(fixture.Root, "target")).FullName;
        var child = Directory.CreateDirectory(Path.Combine(target, "child")).FullName;
        var junction = Path.Combine(fixture.Root, "junction");
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var arg in new[] { "/d", "/c", "mklink", "/J", junction, target }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new IOException("Could not create test junction.");
        if (!process.WaitForExit(5000)) { process.Kill(); throw new IOException("Junction test timed out."); }
        if (process.ExitCode != 0) throw new IOException(process.StandardError.ReadToEnd());
        try
        {
            Assert.Throws<IOException>(() => PinnedLocalPath.Directory(Path.Combine(junction, "child")));
            Assert.True(Directory.Exists(child));
        }
        finally { Directory.Delete(junction); }
    }

    [Fact]
    public void RootAclChangeDoesNotRewriteHardLinkedChildAcl()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fixture = new TemporaryTree();
        var data = Directory.CreateDirectory(Path.Combine(fixture.Root, "data")).FullName;
        var outside = Path.Combine(fixture.Root, "outside.txt");
        var alias = Path.Combine(data, "alias.txt");
        File.WriteAllText(outside, "unchanged");
        if (!CreateHardLink(alias, outside, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var before = new FileInfo(outside).GetAccessControl().GetSecurityDescriptorBinaryForm();
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        using var identity = WindowsIdentity.GetCurrent();
        security.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        using (var pinned = PinnedLocalPath.Directory(data, writable: true)) pinned.SetDirectorySecurity(security, owner: false);
        Assert.Equal(before, new FileInfo(outside).GetAccessControl().GetSecurityDescriptorBinaryForm());
    }

    private sealed class TemporaryTree : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "BeszelPinnedTest-" + Guid.NewGuid().ToString("N"));
        internal TemporaryTree() => Directory.CreateDirectory(Root);
        public void Dispose()
        {
            var full = Path.GetFullPath(Root);
            var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!full.StartsWith(temp, StringComparison.OrdinalIgnoreCase)
                || !Path.GetFileName(full).StartsWith("BeszelPinnedTest-", StringComparison.Ordinal))
                throw new IOException("Invalid temporary cleanup target.");
            Directory.Delete(full, recursive: true);
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string alias, string source, IntPtr security);
}
