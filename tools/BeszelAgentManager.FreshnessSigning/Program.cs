using System.Security.Cryptography;
using BeszelAgentManager.Core.Updates;

// Separate publisher tool: only limited online keys. Never packaged with the app.
try
{
    if (args.Length != 3 || !TufUpdateVerifier.IsValidTag(args[2]))
        throw new ArgumentException("Usage: FreshnessSigning <public-input-directory> <new-output-directory> <official-tag>");
    var state = PinnedUpdateTrust.Bootstrap();
    for (var count = 0; count < 64; count++)
    {
        var path = Path.Combine(args[0], $"{checked(state.RootVersion + 1)}.root.json");
        if (!File.Exists(path)) break;
        state = TufUpdateVerifier.RotateRoot(state, Read(path));
        if (count == 63) throw new UpdateMetadataException("Root rotation limit reached.");
    }
    var now = DateTimeOffset.UtcNow;
    var targets = Read(Path.Combine(args[0], "targets.json"));
    if (TufUpdateVerifier.ValidateRenewalTargets(state, targets, now) != args[2])
        throw new UpdateMetadataException("Offline targets do not approve the current official release.");
    var priorSnapshot = TufUpdateVerifier.ReadRenewalCounter(state, Read(Path.Combine(args[0], "snapshot.json")), "snapshot");
    var priorTimestamp = TufUpdateVerifier.ReadRenewalCounter(state, Read(Path.Combine(args[0], "timestamp.json")), "timestamp");
    var counter = Math.Max(now.ToUnixTimeSeconds(), checked(Math.Max(priorSnapshot, priorTimestamp) + 1));
    using var snapshotKey = Key("SNAPSHOT", state, "snapshot");
    using var timestampKey = Key("TIMESTAMP", state, "timestamp");
    var snapshot = TufMetadataBuilder.Sign(TufMetadataBuilder.Snapshot(targets, counter, now.AddDays(7)), snapshotKey);
    var timestamp = TufMetadataBuilder.Sign(TufMetadataBuilder.Timestamp(snapshot, counter, now.AddDays(1)), timestampKey);
    foreach (var edition in new[] { "bundled", "lite" })
        _ = TufUpdateVerifier.Verify(state, timestamp, snapshot, targets, edition, args[2], true, now);
    if (Directory.Exists(args[1]) || File.Exists(args[1])) throw new IOException("Use a new output directory.");
    Directory.CreateDirectory(args[1]);
    Write(Path.Combine(args[1], "snapshot.json"), snapshot);
    Write(Path.Combine(args[1], "timestamp.json"), timestamp);
    Console.WriteLine($"Renewed online metadata for {args[2]} at counter {counter}; installer approval is unchanged.");
    return 0;
}
catch (Exception)
{
    // Do not echo exception data from private-key import or environment values.
    Console.Error.WriteLine("Freshness renewal failed. Check public metadata, expiry and limited-role key configuration.");
    return 1;
}

static ECDsa Key(string prefix, TufTrustState state, string role)
{
    var encoded = Environment.GetEnvironmentVariable($"BESZEL_{prefix}_PRIVATE_PK8_BASE64")
        ?? throw new ArgumentException("Missing online key.");
    if (encoded.Length > 24000) throw new ArgumentException("Online key is too large.");
    var bytes = Convert.FromBase64String(encoded);
    var password = (Environment.GetEnvironmentVariable($"BESZEL_{prefix}_PASSPHRASE")
        ?? throw new ArgumentException("Missing online passphrase.")).ToCharArray();
    var signer = ECDsa.Create();
    try
    {
        signer.ImportEncryptedPkcs8PrivateKey(password, bytes, out var consumed);
        if (consumed != bytes.Length || !TufUpdateVerifier.IsAuthorizedRenewalKey(state, role, signer))
            throw new CryptographicException("Wrong online authority.");
        return signer;
    }
    catch { signer.Dispose(); throw; }
    finally { Array.Clear(password); CryptographicOperations.ZeroMemory(bytes); }
}

static byte[] Read(string path)
{
    using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    if (input.Length is <= 0 or > TufJson.MaximumMetadataBytes) throw new IOException("Invalid metadata size.");
    var bytes = new byte[checked((int)input.Length)];
    input.ReadExactly(bytes);
    _ = TufJson.Parse(bytes);
    return bytes;
}
static void Write(string path, byte[] bytes)
{
    using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
    output.Write(bytes); output.Flush(true);
}
