using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using BeszelAgentManager.Core.Updates;

namespace BeszelAgentManager.Helper.Updates;

// Service-only, fixed-name storage. No user-controlled staging location or
// arbitrary file operation. Keep pins alive until all update work is finished.
[SupportedOSPlatform("windows")]
internal sealed class ProtectedUpdateStore : IDisposable
{
    private readonly PinnedLocalPath _parent;
    private readonly PinnedLocalPath _directory;
    private readonly List<byte[]> _roots = [];
    private readonly SemaphoreSlim _mutation = new(1, 1);
    private TufTrustState _state;
    internal TufTrustState State => _state;

    internal ProtectedUpdateStore(string serviceDataDirectory)
    {
        _state = PinnedUpdateTrust.Bootstrap();
        _parent = PinnedLocalPath.Directory(serviceDataDirectory);
        try
        {
            _parent.RequireProtected();
            var directory = Path.Combine(_parent.Path, "secure-manager-updates");
            var initialize = !Directory.Exists(directory);
            if (initialize)
            {
                using var identity = WindowsIdentity.GetCurrent();
                if (!identity.IsSystem) throw new InvalidOperationException("Only the background service may initialize update storage.");
                var security = new DirectorySecurity();
                security.SetAccessRuleProtection(true, false);
                foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
                    security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null),
                        FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None, AccessControlType.Allow));
                new DirectoryInfo(directory).Create(security);
            }
            _directory = PinnedLocalPath.Directory(directory);
            try
            {
                _directory.RequireProtected();
                if (initialize) WriteAsync(_state, _roots, CancellationToken.None).GetAwaiter().GetResult();
                Load();
            }
            catch { _directory.Dispose(); throw; }
        }
        catch { _parent.Dispose(); throw; }
    }

    private void Load()
    {
        var path = Path.Combine(_directory.Path, "checkpoint.json");
        // Absence in an existing store is an error, not permission to forget
        // rollback history. A new store writes its genesis checkpoint above.
        using var pinned = PinnedLocalPath.File(path);
        pinned.RequireProtected();
        using var input = new FileStream(pinned.Handle, FileAccess.Read);
        if (input.Length is <= 0 or > TufJson.MaximumMetadataBytes)
            throw new UpdateMetadataException("Protected update checkpoint size is invalid.");
        var bytes = new byte[checked((int)input.Length)];
        input.ReadExactly(bytes);
        var document = TufJson.Parse(bytes);
        try
        {
            if (document.EnumerateObject().Count() != 3 || document.GetProperty("format").GetInt64() != 1)
                throw new UpdateMetadataException("Protected update checkpoint format is invalid.");
            var roots = document.GetProperty("roots");
            if (roots.ValueKind != JsonValueKind.Array || roots.GetArrayLength() > 64)
                throw new UpdateMetadataException("Protected update root history is invalid.");
            foreach (var entry in roots.EnumerateArray())
            {
                var root = Convert.FromBase64String(entry.GetString() ?? throw new FormatException());
                _state = TufUpdateVerifier.RotateRoot(_state, root);
                _roots.Add(root);
            }
            _state = TufCheckpointCodec.Decode(JsonSerializer.SerializeToUtf8Bytes(document.GetProperty("checkpoint")), _state);
        }
        catch (Exception ex) when (ex is InvalidOperationException or KeyNotFoundException or FormatException)
        {
            throw new UpdateMetadataException("Protected update checkpoint is malformed; update history was not reset.");
        }
    }

    internal async Task SaveCheckpointAsync(TufTrustState candidate, CancellationToken cancellationToken)
    {
        await _mutation.WaitAsync(cancellationToken);
        try
        {
            // Same root and monotonically accepted history, never arbitrary state.
            var restored = TufCheckpointCodec.Decode(TufCheckpointCodec.Encode(candidate), _state);
            await WriteAsync(restored, _roots, cancellationToken);
            _state = restored;
        }
        finally { _mutation.Release(); }
    }

    internal async Task AcceptRootAsync(byte[] nextRoot, CancellationToken cancellationToken)
    {
        await _mutation.WaitAsync(cancellationToken);
        try
        {
            if (_roots.Count >= 64) throw new UpdateMetadataException("Update root history limit reached.");
            // Copy caller bytes before verification; caller cannot mutate persisted trust.
            var copy = nextRoot.ToArray();
            var rotated = TufUpdateVerifier.RotateRoot(_state, copy);
            var roots = _roots.Append(copy).ToArray();
            await WriteAsync(rotated, roots, cancellationToken);
            _roots.Add(copy);
            _state = rotated;
        }
        finally { _mutation.Release(); }
    }

    private async Task WriteAsync(TufTrustState state, IReadOnlyList<byte[]> roots, CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            format = 1,
            roots = roots.Select(r => Convert.ToBase64String(r)).ToArray(),
            checkpoint = TufJson.Parse(TufCheckpointCodec.Encode(state)),
        });
        if (bytes.Length > TufJson.MaximumMetadataBytes) throw new UpdateMetadataException("Update history exceeds protected storage limit.");
        var destination = Path.Combine(_directory.Path, "checkpoint.json");
        if (File.Exists(destination))
        {
            using var existing = PinnedLocalPath.File(destination);
            existing.RequireProtected();
        }
        var temporary = Path.Combine(_directory.Path, "checkpoint-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.WriteThrough))
            {
                await output.WriteAsync(bytes, cancellationToken);
                output.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            // Only SYSTEM/admin may mutate this directory; pins prevent ancestor
            // replacement. Atomic replacement removes a link, never writes through it.
            File.Move(temporary, destination, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public void Dispose()
    {
        _directory.Dispose();
        _parent.Dispose();
        _mutation.Dispose();
    }
}
