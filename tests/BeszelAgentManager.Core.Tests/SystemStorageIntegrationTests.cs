using System.Runtime.Versioning;
using System.Security.Principal;
using BeszelAgentManager.Core.Updates;
using BeszelAgentManager.Helper.Updates;
using Xunit;

namespace BeszelAgentManager.Core.Tests;

// Run only as SYSTEM on a disposable VM with explicit operator opt-in.
// Never touch the application's real ProgramData directory or its configuration.
[SupportedOSPlatform("windows")]
public sealed class SystemStorageIntegrationTests
{
    public static bool IsSystemTestProcess => OperatingSystem.IsWindows()
        && Environment.GetEnvironmentVariable("BESZEL_ISOLATED_VM_TESTS") == "1"
        && WindowsIdentity.GetCurrent().IsSystem;

    [Fact(Skip = "Requires SYSTEM on an explicitly opted-in disposable VM.", SkipUnless = nameof(IsSystemTestProcess))]
    public async Task ProtectedStoreRetainsHistoryAndRejectsCanceledCheckpoint()
    {
        var root = Path.Combine(Path.GetTempPath(), "BeszelSystemStore-" + Guid.NewGuid().ToString("N"));
        SafeSecurityTree.Ensure(root, null, setOwner: false);
        try
        {
            using (var store = new ProtectedUpdateStore(root))
            {
                var candidate = store.State with
                {
                    TimestampVersion = 7, TimestampHash = new string('a', 64), LastVerifiedUtc = DateTimeOffset.UtcNow,
                };
                await store.SaveCheckpointAsync(candidate, TestContext.Current.CancellationToken);
                using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.SaveCheckpointAsync(candidate with
                    { TimestampVersion = 8, TimestampHash = new string('b', 64) }, cancellation.Token));
            }
            using var restored = new ProtectedUpdateStore(root);
            Assert.Equal(7, restored.State.TimestampVersion);
            Assert.Equal(new string('a', 64), restored.State.TimestampHash);
        }
        finally { SafeFileTree.Delete(root); }
    }

    [Fact(Skip = "Requires SYSTEM on an explicitly opted-in disposable VM.", SkipUnless = nameof(IsSystemTestProcess))]
    public void MissingOrCorruptCheckpointDoesNotResetTrust()
    {
        var root = Path.Combine(Path.GetTempPath(), "BeszelSystemStore-" + Guid.NewGuid().ToString("N"));
        SafeSecurityTree.Ensure(root, null, setOwner: false);
        try
        {
            string checkpoint;
            using (var store = new ProtectedUpdateStore(root)) checkpoint = Path.Combine(store.DirectoryPath, "checkpoint.json");
            File.WriteAllText(checkpoint, "{broken");
            Assert.Throws<UpdateMetadataException>(() => new ProtectedUpdateStore(root));
            File.Delete(checkpoint);
            Assert.Throws<System.ComponentModel.Win32Exception>(() => new ProtectedUpdateStore(root));
        }
        finally { SafeFileTree.Delete(root); }
    }
}
