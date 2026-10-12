namespace BeszelAgentManager.Core.Updates;

// Host callbacks must provide trusted transport and durable protected storage.
// A failed checkpoint prevents further downloads. No keys are discovered here,
// and successful metadata verification never launches an installer.
public static class TufRefreshCoordinator
{
    public static async Task<VerifiedManagerUpdate> RefreshAsync(TufTrustState state,
        Func<string, CancellationToken, Task<byte[]>> fetchMetadata,
        Func<TufTrustState, CancellationToken, Task> persistCheckpoint,
        string edition, string installedTag, bool includePrereleases,
        DateTimeOffset updateStartUtc, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var timestamp = await fetchMetadata("timestamp.json", cancellationToken);
        state = TufUpdateVerifier.AcceptTimestamp(state, timestamp, updateStartUtc);
        await persistCheckpoint(state, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var snapshot = await fetchMetadata("snapshot.json", cancellationToken);
        state = TufUpdateVerifier.AcceptSnapshot(state, timestamp, snapshot, updateStartUtc);
        await persistCheckpoint(state, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var targets = await fetchMetadata("targets.json", cancellationToken);
        var result = TufUpdateVerifier.Verify(state, timestamp, snapshot, targets,
            edition, installedTag, includePrereleases, updateStartUtc);
        await persistCheckpoint(result.State, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }
}
