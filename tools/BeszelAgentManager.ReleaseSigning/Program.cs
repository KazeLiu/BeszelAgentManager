using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BeszelAgentManager.Core.Updates;

// Operator-only tool; never shipped with the application or run by the broker.
// Passwords come from an interactive console, not CLI arguments or environment.
try
{
    if (args.Length == 0) throw new ArgumentException(Usage());
    switch (args[0])
    {
        case "keygen" when args.Length == 3:
            GenerateKey(args[1], args[2]);
            break;
        case "root" when args.Length == 5:
            var roleKeys = new Dictionary<string, IReadOnlyList<JsonElement>>();
            foreach (var role in TufUpdateVerifier.Roles)
            {
                var names = role == "root" ? new[] { "root-1", "root-2", "root-3" } : new[] { role };
                roleKeys.Add(role, names.Select(name => ReadPublicKey(Path.Combine(args[1], name + ".public.pem"))).ToArray());
            }
            WriteNew(args[4], TufMetadataBuilder.Root(roleKeys, Counter(args[2]), Expiry(args[3])));
            break;
        case "targets" when args.Length == 6:
            var bundled = Installer(Path.Combine(args[1], "BeszelAgentManagerSetup.exe"), args[2]);
            var lite = Installer(Path.Combine(args[1], "BeszelAgentManagerSetup-Lite.exe"), args[2]);
            WriteNew(args[5], TufMetadataBuilder.Targets(args[2], Counter(args[3]), Expiry(args[4]),
                bundled.Length, bundled.Hash, lite.Length, lite.Hash));
            break;
        case "snapshot" when args.Length == 5:
            WriteNew(args[4], TufMetadataBuilder.Snapshot(ReadMetadata(args[1]), Counter(args[2]), Expiry(args[3])));
            break;
        case "timestamp" when args.Length == 5:
            WriteNew(args[4], TufMetadataBuilder.Timestamp(ReadMetadata(args[1]), Counter(args[2]), Expiry(args[3])));
            break;
        case "sign" when args.Length == 4:
            var input = ReadMetadata(args[1]);
            RejectRepositoryOrReparsePath(args[2]);
            var encryptedKey = ReadBounded(args[2], 16 * 1024);
            var password = Password("Key passphrase: ");
            try
            {
                using var signer = ECDsa.Create();
                signer.ImportEncryptedPkcs8PrivateKey(password, encryptedKey, out var consumed);
                if (consumed != encryptedKey.Length) throw new CryptographicException("Trailing key data rejected.");
                WriteNew(args[3], TufMetadataBuilder.Sign(input, signer));
            }
            finally
            {
                Array.Clear(password);
                CryptographicOperations.ZeroMemory(encryptedKey);
            }
            break;
        case "verify-root" when args.Length == 2:
            var rootBytes = ReadMetadata(args[1]);
            var rootState = TufUpdateVerifier.Bootstrap(rootBytes);
            Console.WriteLine($"Verified root version {rootState.RootVersion}: {TufJson.Sha256(rootBytes)}");
            break;
        case "verify" when args.Length == 7:
            var state = TufUpdateVerifier.Bootstrap(ReadMetadata(args[1]));
            var verified = TufUpdateVerifier.Verify(state, ReadMetadata(args[2]), ReadMetadata(args[3]),
                ReadMetadata(args[4]), args[5], args[6], includePrereleases: true, DateTimeOffset.UtcNow);
            Console.WriteLine($"Verified {verified.Target.Tag} ({verified.Target.Edition}): {verified.Target.Sha256}");
            break;
        default:
            throw new ArgumentException(Usage());
    }
    return 0;
}
catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException
    or CryptographicException or UpdateMetadataException or InvalidOperationException or FormatException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

static void GenerateKey(string directory, string name)
{
    if (name is not ("root-1" or "root-2" or "root-3" or "targets" or "snapshot" or "timestamp"))
        throw new ArgumentException("Use root-1, root-2, root-3, targets, snapshot, or timestamp.");
    RejectRepositoryOrReparsePath(directory);
    Directory.CreateDirectory(directory);
    var privatePath = Path.Combine(directory, name + ".private.pk8");
    var publicPath = Path.Combine(directory, name + ".public.pem");
    if (File.Exists(privatePath) || File.Exists(publicPath)) throw new IOException("Key files already exist.");
    var password = Password("New passphrase (at least 16 characters): ");
    var confirmation = Password("Confirm passphrase: ");
    try
    {
        if (password.Length < 16)
            throw new ArgumentException("Passphrase is too short: enter at least 16 characters. Each accepted character shows a star.");
        if (!password.AsSpan().SequenceEqual(confirmation))
            throw new ArgumentException("Confirmation does not match the first passphrase. No key was created.");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var encrypted = key.ExportEncryptedPkcs8PrivateKey(password,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000));
        try { WriteNew(privatePath, encrypted); }
        finally { CryptographicOperations.ZeroMemory(encrypted); }
        WriteNew(publicPath, Encoding.UTF8.GetBytes(key.ExportSubjectPublicKeyInfoPem()));
        Console.WriteLine($"Created {name}. Public key ID: {TufUpdateVerifier.KeyId(TufUpdateVerifier.PublicKey(key))}");
    }
    finally
    {
        Array.Clear(password);
        Array.Clear(confirmation);
    }
}

static JsonElement ReadPublicKey(string path)
{
    using var key = ECDsa.Create();
    var pem = Encoding.UTF8.GetString(ReadBounded(path, 2048));
    if (pem.Contains("PRIVATE", StringComparison.Ordinal)) throw new ArgumentException("Public key file required.");
    key.ImportFromPem(pem);
    return TufUpdateVerifier.PublicKey(key);
}

static (long Length, string Hash) Installer(string path, string tag)
{
    if (!TufUpdateVerifier.IsValidTag(tag)) throw new ArgumentException("Invalid release tag.");
    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    if (stream.Length is <= 0 or > TufUpdateVerifier.MaximumInstallerBytes)
        throw new IOException("Installer size is outside the allowed range.");
    if (stream.ReadByte() != 'M' || stream.ReadByte() != 'Z') throw new IOException("Windows executable required.");
    // Inno stores the numeric product version; prerelease channel is reviewed
    // separately against VERSION/RELEASE_CHANNEL and the exact build commit.
    var numeric = tag.Split('-')[0];
    var product = System.Diagnostics.FileVersionInfo.GetVersionInfo(path).ProductVersion?.Trim();
    if (product != numeric && product != numeric + ".0")
        throw new IOException("Installer product version does not match the approved release tag.");
    stream.Position = 0;
    return (stream.Length, Convert.ToHexStringLower(SHA256.HashData(stream)));
}

static byte[] ReadMetadata(string path)
{
    var bytes = ReadBounded(path, TufJson.MaximumMetadataBytes);
    _ = TufJson.Parse(bytes);
    return bytes;
}

static byte[] ReadBounded(string path, int maximum)
{
    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    if (stream.Length is <= 0 || stream.Length > maximum) throw new IOException("Input exceeds the size limit.");
    var bytes = new byte[checked((int)stream.Length)];
    stream.ReadExactly(bytes);
    if (stream.ReadByte() != -1) throw new IOException("Input changed while reading.");
    return bytes;
}

static void WriteNew(string path, byte[] bytes)
{
    using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
    stream.Write(bytes);
    stream.Flush(flushToDisk: true);
    Console.WriteLine($"Wrote {Path.GetFullPath(path)}");
}

static char[] Password(string prompt)
{
    if (Console.IsInputRedirected) throw new ArgumentException("Interactive console required; do not pass secrets in arguments.");
    Console.Write(prompt);
    var buffer = new char[1024];
    var count = 0;
    try
    {
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.V && key.Modifiers.HasFlag(ConsoleModifiers.Control))
                throw new ArgumentException("This terminal did not paste text. Type the passphrase manually or use the terminal's paste menu. No key was created.");
            if (key.Key == ConsoleKey.Backspace)
            {
                if (count > 0) { buffer[--count] = '\0'; Console.Write("\b \b"); }
                continue;
            }
            if (!char.IsControl(key.KeyChar))
            {
                if (count == buffer.Length) throw new ArgumentException("Passphrase is too long.");
                buffer[count++] = key.KeyChar;
                Console.Write('*');
            }
        }
        Console.WriteLine();
        return buffer[..count];
    }
    finally { Array.Clear(buffer); }
}

static void RejectRepositoryOrReparsePath(string path)
{
    var full = Path.GetFullPath(path);
    var current = File.Exists(full) ? Path.GetDirectoryName(full) : full;
    if (File.Exists(full) && File.GetAttributes(full).HasFlag(FileAttributes.ReparsePoint))
        throw new IOException("Redirected signing-key paths are not allowed.");
    while (current is not null)
    {
        if (Directory.Exists(current))
        {
            if (File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint))
                throw new IOException("Redirected signing-key paths are not allowed.");
            if (File.Exists(Path.Combine(current, ".git")) || Directory.Exists(Path.Combine(current, ".git")))
                throw new IOException("Private keys must be outside repository checkouts.");
        }
        current = Path.GetDirectoryName(current);
    }
}

static long Counter(string value) => long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
    && parsed > 0 ? parsed : throw new ArgumentException("Use a positive, increasing metadata version.");

static DateTimeOffset Expiry(string value) => DateTimeOffset.TryParseExact(value, "yyyy-MM-dd'T'HH:mm:ss'Z'",
    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
    && parsed > DateTimeOffset.UtcNow ? parsed : throw new ArgumentException("Use a future UTC expiry: yyyy-MM-ddTHH:mm:ssZ.");

static string Usage() => "Commands:\n"
    + "  verify-root <signed-root>\n"
    + "  keygen <outside-repository-directory> <role-name>\n"
    + "  root <public-key-directory> <version> <UTC-expiry> <output>\n"
    + "  targets <installer-directory> <tag> <version> <UTC-expiry> <output>\n"
    + "  snapshot <signed-targets> <version> <UTC-expiry> <output>\n"
    + "  timestamp <signed-snapshot> <version> <UTC-expiry> <output>\n"
    + "  sign <metadata> <encrypted-private-key> <output>\n"
    + "  verify <pinned-root> <timestamp> <snapshot> <targets> <edition> <installed-tag>";
