using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace BeszelAgentManager.Helper.Updates;

[SupportedOSPlatform("windows")]
internal static class SafeSecurityTree
{
    internal static void Ensure(string directory, string? readSid, bool setOwner, string? deferredPolicySid = null)
    {
        using var parent = PinnedLocalPath.Directory(Path.GetDirectoryName(Path.GetFullPath(directory))!);
        if (!Directory.Exists(directory)) new DirectoryInfo(directory).Create(DirectoryAcl(readSid, setOwner));
        Secure(directory, readSid, setOwner, deferredPolicySid, 0);
    }

    private static void Secure(string path, string? readSid, bool setOwner, string? deferredPolicySid, int depth)
    {
        if (depth > 64) throw new IOException("Security tree nesting limit exceeded.");
        using var pinned = PinnedLocalPath.Directory(path, writable: true);
        var owner = pinned.ReadSecurity().Owner;
        // A pre-existing installer-user root may be sealed, but arbitrary
        // untrusted child files are never promoted into privileged storage.
        if (!Trusted(owner) && !(depth == 0 && owner?.Value == deferredPolicySid))
            throw new IOException("Untrusted directory owner in privileged storage.");
        pinned.SetDirectorySecurity(DirectoryAcl(readSid, setOwner), setOwner);
        foreach (var entry in Directory.EnumerateFileSystemEntries(pinned.Path))
        {
            if (File.GetAttributes(entry).HasFlag(FileAttributes.Directory))
            {
                if (depth == 0 && Path.GetFileName(entry) == "secure-manager-updates")
                {
                    using var updates = PinnedLocalPath.Directory(entry);
                    updates.RequireProtected();
                    continue; // Active worker holds locks; never rewrite this sealed store.
                }
                Secure(entry, readSid, setOwner, deferredPolicySid: null, depth + 1);
                continue;
            }
            using var file = PinnedLocalPath.ForSecurity(entry);
            var fileOwner = file.ReadSecurity().Owner;
            var deferredPolicy = depth == 0 && Path.GetFileName(entry) == "broker-policy.json"
                && fileOwner?.Value == deferredPolicySid;
            if (!Trusted(fileOwner) && !deferredPolicy)
                throw new IOException("Untrusted file owner in privileged storage.");
            var protectedAlready = false;
            try { file.RequireProtected(); protectedAlready = true; } catch (IOException) { }
            if (protectedAlready) file.SetFileSecurity(FileAcl(readSid, setOwner), setOwner);
            else
            {
                // A previously writable file needs an exclusive read barrier.
                // Do not seal an object while an untrusted writer still has it open.
                using var exclusive = PinnedLocalPath.File(entry, writable: true);
                exclusive.SetFileSecurity(FileAcl(readSid, setOwner), setOwner);
            }
        }
    }

    private static bool Trusted(SecurityIdentifier? sid) => sid is not null
        && (sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));

    internal static DirectorySecurity DirectoryAcl(string? readSid, bool owner)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        if (owner) security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        if (readSid is not null) security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(readSid),
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    internal static FileSecurity FileAcl(string? readSid, bool owner)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(true, false);
        if (owner) security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        if (readSid is not null) security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(readSid),
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize, AccessControlType.Allow));
        return security;
    }
}
