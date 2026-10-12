using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace BeszelAgentManager.Core.Updates;

// Shared wire-format authoring for the local release tool and interoperability tests.
// Creating/signing an envelope does not confer trust: consumers must verify it.
public static class TufMetadataBuilder
{
    public static byte[] Root(IReadOnlyDictionary<string, IReadOnlyList<JsonElement>> roleKeys,
        long version, DateTimeOffset expires)
    {
        var keys = new Dictionary<string, JsonElement>();
        var roles = new Dictionary<string, object>();
        foreach (var role in TufUpdateVerifier.Roles)
        {
            var ids = new List<string>();
            foreach (var key in roleKeys[role])
            {
                var id = TufUpdateVerifier.KeyId(key);
                keys.Add(id, key);
                ids.Add(id);
            }
            roles.Add(role, new { keyids = ids, threshold = role == "root" ? 2 : 1 });
        }
        return Envelope(new { _type = "root", spec_version = "1.0.31", version,
            expires = Utc(expires), consistent_snapshot = false, keys, roles });
    }

    public static byte[] Targets(string tag, long version, DateTimeOffset expires,
        long bundledLength, string bundledHash, long liteLength, string liteHash)
    {
        if (!TufUpdateVerifier.IsValidTag(tag)) throw new UpdateMetadataException("Invalid release tag.");
        object Target(string edition, long length, string sha256) => new
        {
            length, hashes = new { sha256 }, custom = new
            {
                beszel = new { repository = TufUpdateVerifier.Repository, tag, edition, architecture = "x64" },
            },
        };
        return Envelope(new { _type = "targets", spec_version = "1.0.31", version, expires = Utc(expires),
            targets = new Dictionary<string, object>
            {
                ["BeszelAgentManagerSetup.exe"] = Target("bundled", bundledLength, bundledHash),
                ["BeszelAgentManagerSetup-Lite.exe"] = Target("lite", liteLength, liteHash),
            } });
    }

    public static byte[] Snapshot(byte[] signedTargets, long version, DateTimeOffset expires) =>
        Linked("snapshot", "targets.json", signedTargets, version, expires);

    public static byte[] Timestamp(byte[] signedSnapshot, long version, DateTimeOffset expires) =>
        Linked("timestamp", "snapshot.json", signedSnapshot, version, expires);

    public static byte[] Sign(byte[] envelope, ECDsa signer)
    {
        var document = TufJson.Parse(envelope);
        if (signer.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
            throw new UpdateMetadataException("Only P-256 signing keys are supported.");
        var id = TufUpdateVerifier.KeyId(TufUpdateVerifier.PublicKey(signer));
        var payload = TufJson.Canonicalize(document.GetProperty("signed"));
        var signature = Convert.ToHexStringLower(signer.SignData(payload, HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));
        var node = JsonNode.Parse(envelope)!.AsObject();
        var signatures = node["signatures"]!.AsArray();
        if (signatures.Any(s => s?["keyid"]?.GetValue<string>() == id))
            throw new UpdateMetadataException("This key already signed the envelope.");
        signatures.Add(new JsonObject { ["keyid"] = id, ["sig"] = signature });
        var output = JsonSerializer.SerializeToUtf8Bytes(node);
        _ = TufJson.Parse(output);
        return output;
    }

    private static byte[] Linked(string role, string filename, byte[] child, long version, DateTimeOffset expires)
    {
        var document = TufJson.Parse(child);
        if (document.GetProperty("signatures").GetArrayLength() == 0)
            throw new UpdateMetadataException("Sign child metadata before binding its exact bytes.");
        return Envelope(new { _type = role, spec_version = "1.0.31", version, expires = Utc(expires),
            meta = new Dictionary<string, object> { [filename] = new
            {
                version = document.GetProperty("signed").GetProperty("version").GetInt64(),
                length = child.Length, hashes = new { sha256 = TufJson.Sha256(child) },
            } } });
    }

    private static byte[] Envelope(object signed)
    {
        var output = JsonSerializer.SerializeToUtf8Bytes(new { signed, signatures = Array.Empty<object>() });
        _ = TufJson.Parse(output);
        return output;
    }

    private static string Utc(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
