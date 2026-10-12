using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace BeszelAgentManager.Helper.Updates;

internal static class UpdateClientNative
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
}
