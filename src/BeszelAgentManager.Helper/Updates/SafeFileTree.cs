using System.ComponentModel;
using System.Runtime.Versioning;

namespace BeszelAgentManager.Helper.Updates;

[SupportedOSPlatform("windows")]
internal static class SafeFileTree
{
    internal static void Delete(string path)
    {
        var parent = Path.GetDirectoryName(Path.GetFullPath(path)) ?? throw new IOException("Cannot delete a drive root.");
        using var anchor = PinnedLocalPath.Directory(parent);
        DeleteNode(path, depth: 0);
    }

    private static void DeleteNode(string path, int depth)
    {
        if (depth > 64) throw new IOException("Cleanup nesting limit reached.");
        PinnedLocalPath pinned;
        try { pinned = PinnedLocalPath.ForDeletion(path); }
        catch (Win32Exception ex) when (ex.NativeErrorCode is 2 or 3) { return; }
        using (pinned)
        {
            if (pinned.IsDirectory && !pinned.IsReparsePoint)
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(pinned.Path)) DeleteNode(entry, depth + 1);
            }
            // Unlink links themselves. Never clear ACLs/attributes or take ownership
            // to force deletion, and never traverse a redirected ancestor.
            pinned.DeleteOnClose();
        }
    }
}
