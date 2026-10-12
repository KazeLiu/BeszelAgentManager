using System.Runtime.Versioning;
using System.Diagnostics;
using Microsoft.Win32;

namespace BeszelAgentManager.Helper.Updates;

[SupportedOSPlatform("windows")]
internal static class InstalledManagerIdentity
{
    internal static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "BeszelAgentManager");
    internal static string ApplicationDirectory => Path.Combine(Root, "app");
    internal static string HelperDirectory => Path.Combine(ApplicationDirectory, "helper");
    internal static string Executable => Path.Combine(ApplicationDirectory, "BeszelAgentManager.exe");

    internal static void RequireInstalledHelper()
    {
        if (!Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\').Equals(HelperDirectory, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Background service installation requires the protected Program Files installation.");
        RequireProtectedInstallation();
    }

    internal static void RequireProtectedInstallation()
    {
        using var pinned = PinnedLocalPath.Directory(HelperDirectory);
        pinned.RequireProtected();
        using var file = PinnedLocalPath.File(Path.Combine(HelperDirectory, "BeszelAgentManager.Helper.exe"));
        file.RequireProtected();
    }

    internal static string ReadTag()
    {
        var version = ReadText(Path.Combine(ApplicationDirectory, "VERSION"));
        var channel = ReadText(Path.Combine(ApplicationDirectory, "RELEASE_CHANNEL"));
        var tag = channel == "stable" ? version : $"{version}-{channel}";
        if (!BeszelAgentManager.Core.Updates.TufUpdateVerifier.IsValidTag(tag)) throw new IOException("Installed release identity is invalid.");
        return tag;
    }

    internal static string ReadEdition()
    {
        var edition = ReadText(Path.Combine(ApplicationDirectory, "RUNTIME_VARIANT"));
        return edition is "bundled" or "lite" ? edition : throw new IOException("Protected edition marker is invalid.");
    }

    internal static void VerifyInstalledBinariesAndService(string tag)
    {
        foreach (var path in new[] { Executable, Path.Combine(HelperDirectory, "BeszelAgentManager.Helper.exe") })
        {
            using var pin = PinnedLocalPath.File(path);
            pin.RequireProtected();
            var version = FileVersionInfo.GetVersionInfo(path);
            if ($"{version.ProductMajorPart}.{version.ProductMinorPart}.{version.ProductBuildPart}" != tag.Split('-')[0])
                throw new IOException("Installed executable version differs from the signed release.");
        }
        using var service = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\BeszelAgentManager Background")
            ?? throw new IOException("Installed background service is missing.");
        var expected = $"\"{Path.Combine(HelperDirectory, "BeszelAgentManager.Helper.exe")}\" --background-service";
        if (!string.Equals(service.GetValue("ImagePath") as string, expected, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(service.GetValue("ObjectName") as string, "LocalSystem", StringComparison.OrdinalIgnoreCase))
            throw new IOException("Installed background service command or account is invalid.");
    }

    internal static string ReadText(string path)
    {
        using var parent = PinnedLocalPath.Directory(Path.GetDirectoryName(path)!);
        parent.RequireProtected();
        using var pinned = PinnedLocalPath.File(path);
        pinned.RequireProtected();
        using var stream = new FileStream(pinned.Handle, FileAccess.Read);
        if (stream.Length is <= 0 or > 4096) throw new IOException("Protected installation metadata size is invalid.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Trim();
    }
}
