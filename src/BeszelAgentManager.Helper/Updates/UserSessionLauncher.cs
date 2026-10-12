using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace BeszelAgentManager.Helper.Updates;

[SupportedOSPlatform("windows")]
internal static class UserSessionLauncher
{
    internal static void Launch(int session, string authorizedSid)
    {
        using var system = WindowsIdentity.GetCurrent();
        if (!system.IsSystem) throw new UnauthorizedAccessException("Session relaunch requires the background service identity.");
        if (!WTSQueryUserToken((uint)session, out var token)) throw new Win32Exception(Marshal.GetLastWin32Error());
        using (token)
        using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
        {
            if (identity.User?.Value != authorizedSid) throw new UnauthorizedAccessException("Installer user is no longer logged into this session.");
            var elevation = new byte[4];
            if (!GetTokenInformation(token, 20, elevation, 4, out _) || BitConverter.ToInt32(elevation) != 0)
                throw new UnauthorizedAccessException("Refusing elevated GUI relaunch.");
            using var codeRoot = PinnedLocalPath.Directory(InstalledManagerIdentity.ApplicationDirectory);
            codeRoot.RequireProtected();
            using var executable = PinnedLocalPath.File(InstalledManagerIdentity.Executable);
            executable.RequireProtected();
            if (!CreateEnvironmentBlock(out var environment, token, false)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                var startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>(), Desktop = "winsta0\\default" };
                var command = new System.Text.StringBuilder($"\"{InstalledManagerIdentity.Executable}\" --after-secure-update");
                if (!CreateProcessAsUser(token, InstalledManagerIdentity.Executable, command, IntPtr.Zero, IntPtr.Zero,
                    false, 0x00000400, environment, InstalledManagerIdentity.ApplicationDirectory, ref startup, out var process))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                CloseHandle(process.Process); CloseHandle(process.Thread);
            }
            finally { DestroyEnvironmentBlock(environment); }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        internal int Size;
        internal string? Reserved, Desktop, Title;
        internal uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        internal ushort ShowWindow, ReservedSize;
        internal IntPtr ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation { internal IntPtr Process, Thread; internal uint ProcessId, ThreadId; }
    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQueryUserToken(uint session, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int information, byte[] data, uint length, out uint required);
    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, SafeAccessTokenHandle token, [MarshalAs(UnmanagedType.Bool)] bool inherit);
    [DllImport("userenv.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);
    [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUserW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessAsUser(SafeAccessTokenHandle token, string application, System.Text.StringBuilder command,
        IntPtr processSecurity, IntPtr threadSecurity, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInformation process);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
