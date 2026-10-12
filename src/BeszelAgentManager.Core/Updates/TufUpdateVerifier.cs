using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BeszelAgentManager.Core.Updates;

// Restricted TUF 1.0 profile: P-256/SHA-256, four top-level roles, no
// delegations, no consistent snapshots, and two fixed Windows x64 targets.
// Pure verification only. No network, filesystem, process launch, or key discovery.
public static class TufUpdateVerifier
{
    public const string Repository = "MiranoVerhoef/BeszelAgentManager";
    public const long MaximumInstallerBytes = 512L * 1024 * 1024;
    public static readonly string[] Roles = ["root", "targets", "snapshot", "timestamp"];
    private static readonly Regex TagPattern = new(@"\A4\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})(-rc[1-9][0-9]{0,5})?\z", RegexOptions.CultureInvariant);

    // This input must come from the protected installed application, never from
    // downloads, user config, the pipe caller, or a trust-on-first-use cache.
    public static TufTrustState Bootstrap(ReadOnlyMemory<byte> pinnedRoot)
    {
        var root = TufJson.Parse(pinnedRoot);
        ValidateRoot(root);
        VerifySignatures(root, root, "root");
        return new TufTrustState(root);
    }

    public static TufTrustState RotateRoot(TufTrustState state, ReadOnlyMemory<byte> nextRoot)
    {
        var next = TufJson.Parse(nextRoot);
        ValidateRoot(next);
        Require(Version(next) == checked(Version(state.Root) + 1), "Root rotation must be consecutive.");
        VerifySignatures(next, state.Root, "root");
        VerifySignatures(next, next, "root");
        // TUF root recovery: a compromised online key can fast-forward counters.
        // Only an authenticated offline root rotation changing timestamp/snapshot
        // authority may reset these histories. Keep target and installed-version
        // rollback protection; ordinary application upgrades never reset trust.
        var previousRoles = Object(Signed(state.Root), "roles");
        var nextRoles = Object(Signed(next), "roles");
        var onlineAuthorityChanged = new[] { "timestamp", "snapshot" }.Any(role =>
            !TufJson.Canonicalize(Object(previousRoles, role)).AsSpan().SequenceEqual(
                TufJson.Canonicalize(Object(nextRoles, role))));
        return onlineAuthorityChanged
            ? state with { Root = next, TimestampVersion = 0, TimestampHash = null,
                SnapshotVersion = 0, SnapshotHash = null }
            : state with { Root = next };
    }

    public static TufTrustState AcceptTimestamp(TufTrustState state,
        ReadOnlyMemory<byte> bytes, DateTimeOffset now)
    {
        Require(state.LastVerifiedUtc is null || now >= state.LastVerifiedUtc,
            "Clock moved backwards; updates are paused.");
        CheckFreshness(state.Root, now);
        var timestamp = ReadRole(bytes, state.Root, "timestamp", now);
        var hash = TufJson.Sha256(bytes.Span);
        CheckHistory(timestamp, hash, state.TimestampVersion, state.TimestampHash);
        return state with { TimestampVersion = Version(timestamp), TimestampHash = hash, LastVerifiedUtc = now };
    }

    public static TufTrustState AcceptSnapshot(TufTrustState state,
        ReadOnlyMemory<byte> timestampBytes, ReadOnlyMemory<byte> snapshotBytes, DateTimeOffset now)
    {
        Require(state.TimestampHash == TufJson.Sha256(timestampBytes.Span),
            "Accept and persist timestamp before accepting snapshot.");
        state = AcceptTimestamp(state, timestampBytes, now);
        CheckBoundMetadata(TufJson.Parse(timestampBytes), "snapshot.json", snapshotBytes);
        var snapshot = ReadRole(snapshotBytes, state.Root, "snapshot", now);
        var hash = TufJson.Sha256(snapshotBytes.Span);
        CheckHistory(snapshot, hash, state.SnapshotVersion, state.SnapshotHash);
        return state with { SnapshotVersion = Version(snapshot), SnapshotHash = hash };
    }

    public static VerifiedManagerUpdate Verify(TufTrustState state,
        ReadOnlyMemory<byte> timestampBytes, ReadOnlyMemory<byte> snapshotBytes,
        ReadOnlyMemory<byte> targetsBytes, string edition, string installedTag,
        bool includePrereleases, DateTimeOffset now)
    {
        Require(edition is "bundled" or "lite", "Unknown installed edition.");
        Require(IsValidTag(installedTag), "Installed release identity is invalid.");
        Require(state.LastVerifiedUtc is null || now >= state.LastVerifiedUtc, "Clock moved backwards; updates are paused.");
        CheckFreshness(state.Root, now);

        var timestamp = ReadRole(timestampBytes, state.Root, "timestamp", now);
        var timestampHash = TufJson.Sha256(timestampBytes.Span);
        CheckHistory(timestamp, timestampHash, state.TimestampVersion, state.TimestampHash);

        CheckBoundMetadata(timestamp, "snapshot.json", snapshotBytes);
        var snapshot = ReadRole(snapshotBytes, state.Root, "snapshot", now);
        var snapshotHash = TufJson.Sha256(snapshotBytes.Span);
        CheckHistory(snapshot, snapshotHash, state.SnapshotVersion, state.SnapshotHash);

        CheckBoundMetadata(snapshot, "targets.json", targetsBytes);
        var targets = ReadRole(targetsBytes, state.Root, "targets", now);
        var targetsHash = TufJson.Sha256(targetsBytes.Span);
        CheckHistory(targets, targetsHash, state.TargetsVersion, state.TargetsHash);
        var signed = Signed(targets);
        Require(!signed.TryGetProperty("delegations", out _), "Delegations are not supported.");
        var entries = Object(signed, "targets");
        Require(entries.EnumerateObject().Count() == 2, "Both fixed installer editions are required.");
        var bundled = ReadTarget(entries, "bundled");
        var lite = ReadTarget(entries, "lite");
        Require(bundled.Tag == lite.Tag, "Installer editions disagree about release identity.");
        var target = edition == "lite" ? lite : bundled;
        Require(includePrereleases || !target.Tag.Contains('-'), "Prerelease updates are disabled.");
        Require(SecureVersionPolicy.IsSameOrNewer(target.Tag, installedTag), "Manager downgrades are forbidden.");

        var updated = state with
        {
            TimestampVersion = Version(timestamp), TimestampHash = timestampHash,
            SnapshotVersion = Version(snapshot), SnapshotHash = snapshotHash,
            TargetsVersion = Version(targets), TargetsHash = targetsHash,
            LastVerifiedUtc = now,
        };
        return new VerifiedManagerUpdate(target, updated);
    }

    // Caller must hold a stable, non-writable-by-users staging-file handle until
    // execution. A true result does not make arbitrary pathname execution safe.
    public static async Task VerifyInstallerAsync(Stream installer, ManagerUpdateTarget target,
        CancellationToken cancellationToken = default)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        long size = 0;
        while (true)
        {
            var read = await installer.ReadAsync(buffer, cancellationToken);
            if (read == 0) break;
            size += read;
            Require(size <= target.Length && size <= MaximumInstallerBytes, "Installer exceeds signed size.");
            hash.AppendData(buffer, 0, read);
        }
        Require(size == target.Length, "Installer size does not match signed metadata.");
        Require(CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), Convert.FromHexString(target.Sha256)),
            "Installer hash does not match signed metadata.");
    }

    public static bool IsValidTag(string value) => value.Length <= 40 && TagPattern.IsMatch(value);

    public static JsonElement PublicKey(ECDsa key) => JsonSerializer.SerializeToElement(new
    {
        keytype = "ecdsa", scheme = "ecdsa-sha2-nistp256",
        keyval = new { @public = key.ExportSubjectPublicKeyInfoPem().Replace("\r\n", "\n", StringComparison.Ordinal) },
    });

    public static string KeyId(JsonElement key) => TufJson.Sha256(TufJson.Canonicalize(key));

    private static ManagerUpdateTarget ReadTarget(JsonElement entries, string edition)
    {
        var filename = edition == "lite" ? "BeszelAgentManagerSetup-Lite.exe" : "BeszelAgentManagerSetup.exe";
        var entry = Object(entries, filename);
        var length = Integer(entry, "length");
        Require(length is > 0 and <= MaximumInstallerBytes, "Invalid installer size.");
        var digest = Hash(entry);
        var custom = Object(Object(entry, "custom"), "beszel");
        Require(Text(custom, "repository") == Repository && Text(custom, "edition") == edition
            && Text(custom, "architecture") == "x64", "Installer identity does not match this application.");
        var tag = Text(custom, "tag");
        Require(IsValidTag(tag), "Invalid release tag.");
        // No URL from signed or caller-supplied metadata is ever executed/fetched.
        return new ManagerUpdateTarget(tag, edition, filename, length, digest);
    }

    private static JsonElement ReadRole(ReadOnlyMemory<byte> bytes, JsonElement root, string role, DateTimeOffset now)
    {
        var document = TufJson.Parse(bytes);
        Header(document, role);
        VerifySignatures(document, root, role);
        CheckFreshness(document, now);
        return document;
    }

    private static void CheckBoundMetadata(JsonElement parent, string name, ReadOnlyMemory<byte> childBytes)
    {
        var reference = Object(Object(Signed(parent), "meta"), name);
        Require(Integer(reference, "length") == childBytes.Length, "Metadata size binding failed.");
        Require(Hash(reference) == TufJson.Sha256(childBytes.Span), "Metadata hash binding failed.");
        var child = TufJson.Parse(childBytes);
        Require(Integer(reference, "version") == Version(child), "Metadata version binding failed.");
    }

    private static void CheckHistory(JsonElement document, string hash, long priorVersion, string? priorHash)
    {
        var version = Version(document);
        Require(version >= priorVersion, "Metadata rollback rejected.");
        Require(version != priorVersion || priorHash == hash, "Metadata changed without increasing its version.");
    }

    private static void ValidateRoot(JsonElement root)
    {
        Header(root, "root");
        var signed = Signed(root);
        Require(signed.TryGetProperty("consistent_snapshot", out var consistent)
            && consistent.ValueKind == JsonValueKind.False, "This profile requires unversioned target filenames.");
        var keys = Object(signed, "keys");
        Require(keys.EnumerateObject().Count() is > 0 and <= 16, "Invalid root key count.");
        var materials = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in keys.EnumerateObject())
        {
            Require(KeyId(key.Value) == key.Name, "Key identity is not canonical.");
            using var imported = ImportPublicKey(key.Value);
            Require(materials.Add(TufJson.Sha256(imported.ExportSubjectPublicKeyInfo())),
                "A public key cannot be counted under multiple identities.");
        }
        var roles = Object(signed, "roles");
        Require(roles.EnumerateObject().Count() == Roles.Length, "Only top-level roles are supported.");
        var assignedKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var role in Roles)
        {
            var definition = Object(roles, role);
            var ids = KeyIds(definition);
            var threshold = Integer(definition, "threshold");
            Require(threshold >= (role == "root" ? 2 : 1) && threshold <= ids.Count,
                "Invalid signature threshold; root requires at least two keys.");
            foreach (var id in ids)
                Require(keys.TryGetProperty(id, out _) && assignedKeys.Add(id),
                    "Signing keys must exist and must not be shared between roles.");
        }
    }

    private static void VerifySignatures(JsonElement document, JsonElement root, string role)
    {
        var definition = Object(Object(Signed(root), "roles"), role);
        var ids = KeyIds(definition);
        var keys = Object(Signed(root), "keys");
        var signatures = Array(document, "signatures");
        Require(signatures.GetArrayLength() is > 0 and <= 16, "Invalid signature count.");
        var payload = TufJson.Canonicalize(Signed(document));
        var valid = new HashSet<string>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var signature in signatures.EnumerateArray())
        {
            var id = Text(signature, "keyid");
            Require(seen.Add(id), "Duplicate signature key rejected.");
            var hex = Text(signature, "sig");
            Require(hex.Length is >= 128 and <= 160 && IsHex(hex), "Invalid ECDSA signature encoding.");
            if (!ids.Contains(id)) continue;
            using var key = ImportPublicKey(Object(keys, id));
            try
            {
                if (key.VerifyData(payload, Convert.FromHexString(hex), HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence)) valid.Add(id);
            }
            catch (CryptographicException) { /* A malformed signature never counts. */ }
        }
        Require(valid.Count >= Integer(definition, "threshold"), $"The {role} signature threshold was not met.");
    }

    private static ECDsa ImportPublicKey(JsonElement key)
    {
        Require(Text(key, "keytype") == "ecdsa" && Text(key, "scheme") == "ecdsa-sha2-nistp256",
            "Unsupported signing algorithm.");
        var pem = Text(Object(key, "keyval"), "public");
        Require(pem.Length < 2048 && pem.StartsWith("-----BEGIN PUBLIC KEY-----\n", StringComparison.Ordinal)
            && (pem.EndsWith("-----END PUBLIC KEY-----", StringComparison.Ordinal)
                || pem.EndsWith("-----END PUBLIC KEY-----\n", StringComparison.Ordinal))
            && !pem.Contains("PRIVATE", StringComparison.Ordinal), "Invalid public signing key.");
        var imported = ECDsa.Create();
        try
        {
            imported.ImportFromPem(pem);
            Require(imported.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value,
                "Only P-256 signing keys are supported.");
            return imported;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or UpdateMetadataException)
        {
            imported.Dispose();
            throw new UpdateMetadataException("Invalid public signing key.", ex);
        }
    }

    private static HashSet<string> KeyIds(JsonElement definition)
    {
        var ids = Array(definition, "keyids");
        Require(ids.GetArrayLength() is > 0 and <= 16, "Invalid role key count.");
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var id in ids.EnumerateArray())
            Require(id.ValueKind == JsonValueKind.String && result.Add(id.GetString()!), "Duplicate or invalid role key.");
        return result;
    }

    private static void Header(JsonElement document, string type)
    {
        var signed = Signed(document);
        Require(Text(signed, "_type") == type && Text(signed, "spec_version") == "1.0.31",
            "Unsupported metadata type or specification version.");
        Require(Version(document) > 0, "Metadata version must be positive.");
        _ = Expiry(document);
    }

    private static void CheckFreshness(JsonElement document, DateTimeOffset now) =>
        Require(Expiry(document) > now, "Trusted metadata expired; updates are paused.");

    private static DateTimeOffset Expiry(JsonElement document)
    {
        Require(DateTimeOffset.TryParseExact(Text(Signed(document), "expires"), "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var expires), "Invalid metadata expiry.");
        return expires;
    }

    private static string Hash(JsonElement document)
    {
        var value = Text(Object(document, "hashes"), "sha256");
        Require(value.Length == 64 && IsHex(value), "Invalid SHA-256 digest.");
        return value.ToLowerInvariant();
    }

    private static bool IsHex(string value) => value.All(char.IsAsciiHexDigit);
    private static long Version(JsonElement document) => Integer(Signed(document), "version");
    private static JsonElement Signed(JsonElement document) => Object(document, "signed");

    private static JsonElement Object(JsonElement parent, string name) => Property(parent, name, JsonValueKind.Object);
    private static JsonElement Array(JsonElement parent, string name) => Property(parent, name, JsonValueKind.Array);
    private static string Text(JsonElement parent, string name) => Property(parent, name, JsonValueKind.String).GetString()!;
    private static long Integer(JsonElement parent, string name) => Property(parent, name, JsonValueKind.Number).GetInt64();

    private static JsonElement Property(JsonElement parent, string name, JsonValueKind kind)
    {
        Require(parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out var value)
            && value.ValueKind == kind, $"Required metadata field '{name}' is invalid.");
        return parent.GetProperty(name);
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new UpdateMetadataException(message);
    }
}

public sealed record TufTrustState
{
    internal TufTrustState(JsonElement root) => Root = root;
    internal JsonElement Root { get; init; }
    public long RootVersion => Root.GetProperty("signed").GetProperty("version").GetInt64();
    public long TimestampVersion { get; internal init; }
    public string? TimestampHash { get; internal init; }
    public long SnapshotVersion { get; internal init; }
    public string? SnapshotHash { get; internal init; }
    public long TargetsVersion { get; internal init; }
    public string? TargetsHash { get; internal init; }
    public DateTimeOffset? LastVerifiedUtc { get; internal init; }
}

public sealed record ManagerUpdateTarget(string Tag, string Edition, string Filename, long Length, string Sha256)
{
    public Uri DownloadUri => new($"https://github.com/{TufUpdateVerifier.Repository}/releases/download/{Tag}/{Filename}");
}

public sealed record VerifiedManagerUpdate(ManagerUpdateTarget Target, TufTrustState State);
