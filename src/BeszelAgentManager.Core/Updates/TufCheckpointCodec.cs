using System.Globalization;
using System.Text.Json;

namespace BeszelAgentManager.Core.Updates;

// This format is NOT authenticated on its own. Only read it from durable,
// SYSTEM/admin-writable storage. Corruption must stop updates, never reset history.
// Root trust is supplied separately from embedded/authenticated root rotation.
public static class TufCheckpointCodec
{
    public static byte[] Encode(TufTrustState state) => JsonSerializer.SerializeToUtf8Bytes(new
    {
        format = 1,
        root_version = state.RootVersion,
        root_hash = RootHash(state),
        timestamp_version = state.TimestampVersion,
        timestamp_hash = state.TimestampHash,
        snapshot_version = state.SnapshotVersion,
        snapshot_hash = state.SnapshotHash,
        targets_version = state.TargetsVersion,
        targets_hash = state.TargetsHash,
        last_verified_utc = state.LastVerifiedUtc?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
    });

    public static TufTrustState Decode(ReadOnlyMemory<byte> bytes, TufTrustState authenticatedRoot)
    {
        var doc = TufJson.Parse(bytes);
        try
        {
            var fields = new HashSet<string>(["format", "root_version", "root_hash", "timestamp_version",
                "timestamp_hash", "snapshot_version", "snapshot_hash", "targets_version", "targets_hash", "last_verified_utc"]);
            if (doc.ValueKind != JsonValueKind.Object || doc.EnumerateObject().Any(p => !fields.Remove(p.Name))
                || fields.Count != 0 || doc.GetProperty("format").GetInt64() != 1
                || doc.GetProperty("root_version").GetInt64() != authenticatedRoot.RootVersion
                || doc.GetProperty("root_hash").GetString() != RootHash(authenticatedRoot))
                throw new UpdateMetadataException("Update checkpoint identity is invalid.");
            var timestamp = ReadRole(doc, "timestamp");
            var snapshot = ReadRole(doc, "snapshot");
            var targets = ReadRole(doc, "targets");
            var timeText = doc.GetProperty("last_verified_utc").GetString();
            DateTimeOffset? time = null;
            if (timeText is not null)
            {
                if (!DateTimeOffset.TryParseExact(timeText, "O", CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var parsed) || parsed.Offset != TimeSpan.Zero)
                    throw new UpdateMetadataException("Update checkpoint time is invalid.");
                time = parsed;
            }
            // Authenticated root recovery may clear online counters while keeping
            // target history and the clock floor. Those partial states are valid.
            if ((timestamp.Version != 0 || snapshot.Version != 0 || targets.Version != 0) && time is null
                || timestamp.Version < authenticatedRoot.TimestampVersion
                || snapshot.Version < authenticatedRoot.SnapshotVersion
                || targets.Version < authenticatedRoot.TargetsVersion
                || authenticatedRoot.LastVerifiedUtc is not null
                    && (time is null || time < authenticatedRoot.LastVerifiedUtc))
                throw new UpdateMetadataException("Update checkpoint history is inconsistent.");
            return authenticatedRoot with
            {
                TimestampVersion = timestamp.Version, TimestampHash = timestamp.Hash,
                SnapshotVersion = snapshot.Version, SnapshotHash = snapshot.Hash,
                TargetsVersion = targets.Version, TargetsHash = targets.Hash, LastVerifiedUtc = time,
            };
        }
        catch (Exception ex) when (ex is InvalidOperationException or KeyNotFoundException or FormatException)
        {
            throw new UpdateMetadataException("Update checkpoint format is invalid.");
        }
    }

    private static string RootHash(TufTrustState state) => TufJson.Sha256(TufJson.Canonicalize(state.Root));

    private static (long Version, string? Hash) ReadRole(JsonElement doc, string role)
    {
        var version = doc.GetProperty(role + "_version").GetInt64();
        var hash = doc.GetProperty(role + "_hash").GetString();
        if (version < 0 || version == 0 && hash is not null || version != 0
            && (hash is null || hash.Length != 64 || hash.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f'))))
            throw new UpdateMetadataException("Update checkpoint role history is invalid.");
        return (version, hash);
    }
}
