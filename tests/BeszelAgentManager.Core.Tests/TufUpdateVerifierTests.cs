using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using BeszelAgentManager.Core.Updates;
using Xunit;

namespace BeszelAgentManager.Core.Tests;

public sealed class TufUpdateVerifierTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-06T12:00:00Z");

    [Theory]
    [InlineData("bundled", "BeszelAgentManagerSetup.exe")]
    [InlineData("lite", "BeszelAgentManagerSetup-Lite.exe")]
    public async Task ApprovesOnlyExactSignedEditionAndInstaller(string edition, string filename)
    {
        using var fixture = new Fixture();
        var result = fixture.Verify(edition: edition);
        Assert.Equal(filename, result.Target.Filename);
        Assert.Equal(1, result.State.TimestampVersion);
        Assert.Equal($"https://github.com/MiranoVerhoef/BeszelAgentManager/releases/download/4.21.0/{filename}", result.Target.DownloadUri.AbsoluteUri);
        await TufUpdateVerifier.VerifyInstallerAsync(new MemoryStream(fixture.Installer), result.Target, TestContext.Current.CancellationToken);
        Assert.Equal(0, fixture.State.TimestampVersion); // Verification never mutates prior trust.
    }

    [Theory]
    [InlineData("root")]
    [InlineData("targets")]
    [InlineData("snapshot")]
    [InlineData("timestamp")]
    public void AlteredMetadataIsRejected(string role)
    {
        using var fixture = new Fixture();
        if (role == "root")
        {
            Assert.Throws<UpdateMetadataException>(() => TufUpdateVerifier.Bootstrap(
                Change(fixture.Root, n => n["signed"]!["expires"] = "2035-01-01T00:00:00Z")));
            return;
        }
        fixture.ChangeRole(role, n => n["signed"]!["expires"] = "2035-01-01T00:00:00Z");
        Assert.Throws<UpdateMetadataException>(() => fixture.Verify());
    }

    [Theory]
    [InlineData("targets", "timestamp")]
    [InlineData("targets", "snapshot")]
    [InlineData("snapshot", "timestamp")]
    public void LimitedOnlineKeysCannotApproveInstallers(string role, string wrongSigner)
    {
        using var fixture = new Fixture();
        fixture.Resign(role, fixture.Keys[wrongSigner]);
        Assert.Throws<UpdateMetadataException>(() => fixture.Verify());
    }

    [Fact]
    public void DuplicateRootSignaturesDoNotSatisfyThreshold()
    {
        using var fixture = new Fixture();
        var root = Change(fixture.Root, node =>
        {
            var signatures = node["signatures"]!.AsArray();
            signatures.RemoveAt(1);
            signatures.Add(signatures[0]!.DeepClone());
        });
        Assert.Throws<UpdateMetadataException>(() => TufUpdateVerifier.Bootstrap(root));
    }

    [Fact]
    public void RootRotationRequiresOldAndNewThresholds()
    {
        using var original = new Fixture();
        using var successor = new Fixture();
        var next = successor.CreateRoot(2);
        Assert.Throws<UpdateMetadataException>(() => TufUpdateVerifier.RotateRoot(original.State, next));
        next = TufMetadataBuilder.Sign(next, original.Keys["root-1"]);
        next = TufMetadataBuilder.Sign(next, original.Keys["root-2"]);
        var state = TufUpdateVerifier.RotateRoot(original.State, next);
        Assert.Equal(2, state.RootVersion);
        Assert.NotNull(successor.Verify(state: state));
        Assert.Throws<UpdateMetadataException>(() => TufUpdateVerifier.RotateRoot(state, next));
    }

    [Fact]
    public void RootCannotUseTimestampKeyForTargets()
    {
        using var fixture = new Fixture();
        var unsigned = Change(fixture.Root, node =>
        {
            node["signatures"] = new JsonArray();
            node["signed"]!["roles"]!["targets"]!["keyids"] =
                node["signed"]!["roles"]!["timestamp"]!["keyids"]!.DeepClone();
        });
        var signed = TufMetadataBuilder.Sign(TufMetadataBuilder.Sign(unsigned, fixture.Keys["root-1"]), fixture.Keys["root-2"]);
        Assert.Throws<UpdateMetadataException>(() => TufUpdateVerifier.Bootstrap(signed));
    }

    [Fact]
    public void OfflineRootRotationRecoversFromOnlineCounterFastForward()
    {
        using var original = new Fixture();
        original.ChangeRole("timestamp", n => n["signed"]!["version"] = long.MaxValue);
        original.Resign("timestamp", original.Keys["timestamp"]);
        var fastForwarded = original.Verify().State;
        Assert.Equal(long.MaxValue, fastForwarded.TimestampVersion);
        using var successor = new Fixture(counter: 2);
        var next = TufMetadataBuilder.Sign(TufMetadataBuilder.Sign(
            successor.CreateRoot(2), original.Keys["root-1"]), original.Keys["root-2"]);
        var recovered = TufUpdateVerifier.RotateRoot(fastForwarded, next);
        Assert.Equal(0, recovered.TimestampVersion);
        Assert.Equal(0, recovered.SnapshotVersion);
        Assert.Equal(1, recovered.TargetsVersion);
        Assert.NotNull(successor.Verify(state: recovered));
    }

    [Fact]
    public void RootRenewalWithoutAuthorityChangePreservesCounters()
    {
        using var fixture = new Fixture(counter: 2);
        var trusted = fixture.Verify().State;
        var renewed = TufUpdateVerifier.RotateRoot(trusted, fixture.CreateRoot(2));
        Assert.Equal(2, renewed.TimestampVersion);
        Assert.Equal(2, renewed.SnapshotVersion);
        Assert.Equal(2, renewed.TargetsVersion);
    }

    [Fact]
    public void IdenticalPublicKeysCannotSatisfyTwoIdentities()
    {
        using var fixture = new Fixture();
        var duplicate = Change(fixture.Root, node =>
        {
            var key = TufUpdateVerifier.PublicKey(fixture.Keys["root-1"]);
            var alias = JsonNode.Parse(key.GetRawText())!;
            alias["keyval"]!["public"] = alias["keyval"]!["public"]!.GetValue<string>() + "\n";
            var aliasElement = TufJson.Parse(JsonSerializer.SerializeToUtf8Bytes(alias));
            node["signed"]!["keys"]![TufUpdateVerifier.KeyId(aliasElement)] = alias;
        });
        var error = Assert.Throws<UpdateMetadataException>(() => TufUpdateVerifier.Bootstrap(duplicate));
        Assert.Contains("multiple identities", error.Message);
    }

    [Fact]
    public void EncryptedOperatorKeyRoundTripSignsValidMetadata()
    {
        using var fixture = new Fixture();
        const string password = "disposable test passphrase, never a production secret";
        var encrypted = fixture.Keys["targets"].ExportEncryptedPkcs8PrivateKey(password,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000));
        using var imported = ECDsa.Create();
        imported.ImportEncryptedPkcs8PrivateKey(password, encrypted, out var bytesRead);
        Assert.Equal(encrypted.Length, bytesRead);
        fixture.Resign("targets", imported);
        Assert.NotNull(fixture.Verify());
        using var wrongPassword = ECDsa.Create();
        Assert.Throws<CryptographicException>(() => wrongPassword.ImportEncryptedPkcs8PrivateKey("wrong", encrypted, out _));
        CryptographicOperations.ZeroMemory(encrypted);
    }

    [Theory]
    [InlineData("root")]
    [InlineData("targets")]
    [InlineData("snapshot")]
    [InlineData("timestamp")]
    public void ExpiredTrustedRolesPauseUpdates(string role)
    {
        using var fixture = new Fixture(expires: Now);
        // Expired root is allowed at bootstrap so an old installation can rotate
        // its roots. It still cannot authorize a target until a fresh root exists.
        Assert.Throws<UpdateMetadataException>(() => fixture.Verify());
        using var fresh = new Fixture();
        if (role != "root")
        {
            fresh.ChangeRole(role, n => n["signed"]!["expires"] = "2026-10-06T12:00:00Z");
            fresh.Resign(role, fresh.Keys[role]);
            Assert.Throws<UpdateMetadataException>(() => fresh.Verify());
        }
    }

    [Theory]
    [InlineData("timestamp")]
    [InlineData("snapshot")]
    [InlineData("targets")]
    public void MetadataVersionRollbackIsRejected(string role)
    {
        using var fixture = new Fixture(counter: 2);
        var trusted = fixture.Verify().State;
        fixture.ChangeRole(role, n => n["signed"]!["version"] = 1);
        fixture.Resign(role, fixture.Keys[role]);
        Assert.Throws<UpdateMetadataException>(() => fixture.Verify(state: trusted));
    }

    [Fact]
    public void ResigningSameVersionWithDifferentBytesIsRejected()
    {
        using var fixture = new Fixture();
        var trusted = fixture.Verify().State;
        fixture.Resign("timestamp", fixture.Keys["timestamp"]);
        Assert.Throws<UpdateMetadataException>(() => fixture.Verify(state: trusted));
    }

    [Fact]
    public void IdenticalMetadataCanBeCheckedAgainButClockCannotGoBackwards()
    {
        using var fixture = new Fixture();
        var trusted = fixture.Verify().State;
        Assert.NotNull(fixture.Verify(state: trusted, now: Now.AddMinutes(1)));
        Assert.Throws<UpdateMetadataException>(() => fixture.Verify(state: trusted, now: Now.AddSeconds(-1)));
    }

    [Theory]
    [InlineData("4.0.9", "4.0.10", false)]
    [InlineData("4.21.0-rc1", "4.21.0", true)]
    [InlineData("4.21.0-rc1", "4.0.10", false)]
    public void DowngradesAndUnapprovedPrereleasesAreRejected(string tag, string installed, bool includePrereleases)
    {
        using var fixture = new Fixture(tag: tag);
        Assert.Throws<UpdateMetadataException>(() => fixture.Verify(installed: installed, prereleases: includePrereleases));
    }

    [Fact]
    public void EnabledPrereleaseCanAdvanceToNewerVersion()
    {
        using var fixture = new Fixture(tag: "4.21.0-rc1");
        Assert.NotNull(fixture.Verify(prereleases: true));
    }

    [Theory]
    [InlineData("repository", "someone/another-repository")]
    [InlineData("architecture", "arm64")]
    [InlineData("edition", "lite")]
    [InlineData("tag", "../evil")]
    [InlineData("tag", "4.21.0\nPATH=C:\\evil")]
    public void SignedButIncorrectTargetIdentityIsRejected(string field, string value)
    {
        using var fixture = new Fixture();
        fixture.ChangeRole("targets", n => n["signed"]!["targets"]!["BeszelAgentManagerSetup.exe"]!["custom"]!["beszel"]![field] = value);
        fixture.Resign("targets", fixture.Keys["targets"]);
        Assert.Throws<UpdateMetadataException>(() => fixture.Verify());
    }

    [Fact]
    public void EditionsCannotPointToDifferentReleases()
    {
        using var fixture = new Fixture();
        fixture.ChangeRole("targets", n => n["signed"]!["targets"]!["BeszelAgentManagerSetup-Lite.exe"]!["custom"]!["beszel"]!["tag"] = "4.22.0");
        fixture.Resign("targets", fixture.Keys["targets"]);
        Assert.Throws<UpdateMetadataException>(() => fixture.Verify());
    }

    [Fact]
    public void MetadataCannotBeMixedAcrossReleases()
    {
        using var first = new Fixture();
        using var second = new Fixture();
        first.Targets = second.Targets;
        Assert.Throws<UpdateMetadataException>(() => first.Verify());
    }

    [Fact]
    public async Task AlteredTruncatedAndOversizedInstallersAreRejected()
    {
        using var fixture = new Fixture();
        var target = fixture.Verify().Target;
        foreach (var bytes in new[] { new byte[fixture.Installer.Length], fixture.Installer[..^1], fixture.Installer.Concat(new byte[] { 1 }).ToArray() })
            await Assert.ThrowsAsync<UpdateMetadataException>(() => TufUpdateVerifier.VerifyInstallerAsync(new MemoryStream(bytes), target, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("{\"signed\":{},\"signed\":{},\"signatures\":[]}")]
    [InlineData("{\"n\":1.5}")]
    [InlineData("{\"n\":1e0}")]
    [InlineData("{\"n\":999999999999999999999999999}")]
    [InlineData("{\"x\":{\"a\":1,\"a\":2}}")]
    [InlineData("{\"x\":\"\\ud800\"}")]
    public void AmbiguousOrUnsupportedJsonIsRejected(string json) =>
        Assert.Throws<UpdateMetadataException>(() => TufJson.Parse(Encoding.UTF8.GetBytes(json)));

    [Fact]
    public void MetadataSizeIsBounded() => Assert.Throws<UpdateMetadataException>(() =>
        TufJson.Parse(new byte[TufJson.MaximumMetadataBytes + 1]));

    [Fact]
    public void CanonicalJsonMatchesOlpcReferenceRules()
    {
        var value = TufJson.Parse(Encoding.UTF8.GetBytes("{\"z\":\"Bärbar\\n\\\"\\\\\",\"a\":[true,null,-0],\"\\ue000\":1,\"😀\":2}"));
        Assert.Equal("{\"a\":[true,null,0],\"z\":\"Bärbar\n\\\"\\\\\",\"\ue000\":1,\"😀\":2}", Encoding.UTF8.GetString(TufJson.Canonicalize(value)));
    }

    [Fact]
    public void UnknownEditionIsRejected()
    {
        using var fixture = new Fixture();
        Assert.Throws<UpdateMetadataException>(() => fixture.Verify(edition: "anything"));
    }

    [Fact]
    public void ExportPublicFixturesForIndependentReferenceCheck()
    {
        var requested = Environment.GetEnvironmentVariable("BESZEL_TUF_INTEROP_OUTPUT");
        if (requested is null) return;
        var output = Path.GetFullPath(requested);
        var checkout = new DirectoryInfo(AppContext.BaseDirectory);
        while (checkout is not null && !File.Exists(Path.Combine(checkout.FullName, "BeszelAgentManager.sln")))
            checkout = checkout.Parent;
        Assert.NotNull(checkout);
        var allowed = Path.Combine(checkout.FullName, "build") + Path.DirectorySeparatorChar;
        Assert.StartsWith(allowed, output, StringComparison.OrdinalIgnoreCase);
        using var fixture = new Fixture(expires: DateTimeOffset.UtcNow.AddDays(7));
        fixture.ExportPublic(output);
    }

    [Theory]
    [InlineData("4.21.0\n")]
    [InlineData("4.21.0 ")]
    [InlineData("v4.21.0")]
    [InlineData("4.021.0")]
    [InlineData("4.21.0-rc0")]
    [InlineData("4.21.0-rc1\n")]
    public void ReleaseTagsAreStrict(string tag) => Assert.False(TufUpdateVerifier.IsValidTag(tag));

    [Fact]
    public async Task InterruptedRefreshKeepsVerifiedHistoryAndRejectsReplay()
    {
        using var fixture = new Fixture(counter: 2);
        var saved = fixture.State;
        var downloaded = new List<string>();
        var checkpoints = new List<TufTrustState>();
        Task<byte[]> Fetch(string name, CancellationToken token)
        {
            downloaded.Add(name);
            return name switch
            {
                "timestamp.json" => Task.FromResult(fixture.Timestamp),
                "snapshot.json" => Task.FromResult(fixture.Snapshot),
                _ => throw new IOException("Interrupted targets download"),
            };
        }
        Task Save(TufTrustState state, CancellationToken token)
        {
            saved = state;
            checkpoints.Add(state);
            return Task.CompletedTask;
        }
        await Assert.ThrowsAsync<IOException>(() => TufRefreshCoordinator.RefreshAsync(fixture.State,
            Fetch, Save, "bundled", "4.0.10", false, Now, TestContext.Current.CancellationToken));
        Assert.Equal(2, checkpoints.Count);
        Assert.Equal(2, saved.TimestampVersion);
        Assert.Equal(2, saved.SnapshotVersion);
        Assert.Equal(0, saved.TargetsVersion);
        var stale = Change(fixture.Timestamp, n =>
        {
            n["signed"]!["version"] = 1;
            n["signatures"] = new JsonArray();
        });
        stale = TufMetadataBuilder.Sign(stale, fixture.Keys["timestamp"]);
        var error = Assert.Throws<UpdateMetadataException>(() => TufUpdateVerifier.AcceptTimestamp(saved, stale, Now));
        Assert.Contains("rollback", error.Message);
    }

    [Fact]
    public async Task FailedCheckpointPreventsFurtherNetworkWork()
    {
        using var fixture = new Fixture();
        var downloads = 0;
        await Assert.ThrowsAsync<IOException>(() => TufRefreshCoordinator.RefreshAsync(fixture.State,
            (name, token) => { downloads++; return Task.FromResult(fixture.Timestamp); },
            (state, token) => throw new IOException("Checkpoint failed"),
            "bundled", "4.0.10", false, Now, TestContext.Current.CancellationToken));
        Assert.Equal(1, downloads);
    }

    [Fact]
    public async Task SuccessfulRefreshPersistsEachStageBeforeReturningTarget()
    {
        using var fixture = new Fixture();
        var stages = new List<string>();
        var result = await TufRefreshCoordinator.RefreshAsync(fixture.State,
            (name, token) =>
            {
                stages.Add(name);
                return Task.FromResult(name switch
                {
                    "timestamp.json" => fixture.Timestamp,
                    "snapshot.json" => fixture.Snapshot,
                    _ => fixture.Targets,
                });
            },
            (state, token) => { stages.Add("saved"); return Task.CompletedTask; },
            "lite", "4.0.10", false, Now, TestContext.Current.CancellationToken);
        Assert.Equal(new[] { "timestamp.json", "saved", "snapshot.json", "saved", "targets.json", "saved" }, stages);
        Assert.Equal("lite", result.Target.Edition);
    }

    private static byte[] Change(byte[] input, Action<JsonNode> edit)
    {
        var node = JsonNode.Parse(input)!;
        edit(node);
        return JsonSerializer.SerializeToUtf8Bytes(node);
    }

    private sealed class Fixture : IDisposable
    {
        internal Dictionary<string, ECDsa> Keys { get; } = new();
        internal byte[] Installer { get; } = Encoding.UTF8.GetBytes("MZ approved test payload, not executable");
        internal byte[] Root { get; }
        internal byte[] Targets { get; set; }
        internal byte[] Snapshot { get; set; } = [];
        internal byte[] Timestamp { get; set; } = [];
        internal TufTrustState State { get; }
        private readonly DateTimeOffset _expiry;
        private readonly long _counter;

        internal Fixture(string tag = "4.21.0", long counter = 1, DateTimeOffset? expires = null)
        {
            _expiry = expires ?? Now.AddDays(7);
            _counter = counter;
            foreach (var name in new[] { "root-1", "root-2", "root-3", "targets", "snapshot", "timestamp" })
                Keys.Add(name, ECDsa.Create(ECCurve.NamedCurves.nistP256));
            Root = CreateRoot(1);
            State = TufUpdateVerifier.Bootstrap(Root);
            Targets = TufMetadataBuilder.Sign(TufMetadataBuilder.Targets(tag, counter, _expiry,
                Installer.Length, TufJson.Sha256(Installer), Installer.Length, TufJson.Sha256(Installer)), Keys["targets"]);
            Rebind();
        }

        internal byte[] CreateRoot(long version)
        {
            var roles = new Dictionary<string, IReadOnlyList<JsonElement>>();
            foreach (var role in TufUpdateVerifier.Roles)
            {
                var names = role == "root" ? new[] { "root-1", "root-2", "root-3" } : new[] { role };
                roles.Add(role, names.Select(name => TufUpdateVerifier.PublicKey(Keys[name])).ToArray());
            }
            return TufMetadataBuilder.Sign(TufMetadataBuilder.Sign(
                TufMetadataBuilder.Root(roles, version, _expiry), Keys["root-1"]), Keys["root-2"]);
        }

        internal VerifiedManagerUpdate Verify(string edition = "bundled", string installed = "4.0.10",
            bool prereleases = false, TufTrustState? state = null, DateTimeOffset? now = null) =>
            TufUpdateVerifier.Verify(state ?? State, Timestamp, Snapshot, Targets, edition, installed, prereleases, now ?? Now);

        internal void ChangeRole(string role, Action<JsonNode> edit)
        {
            switch (role)
            {
                case "targets": Targets = Change(Targets, edit); break;
                case "snapshot": Snapshot = Change(Snapshot, edit); break;
                case "timestamp": Timestamp = Change(Timestamp, edit); break;
            }
        }

        internal void Resign(string role, ECDsa key)
        {
            byte[] Sign(byte[] value) => TufMetadataBuilder.Sign(Change(value, n => n["signatures"] = new JsonArray()), key);
            switch (role)
            {
                case "targets": Targets = Sign(Targets); Rebind(); break;
                case "snapshot": Snapshot = Sign(Snapshot); Timestamp = MakeTimestamp(); break;
                case "timestamp": Timestamp = Sign(Timestamp); break;
            }
        }

        private void Rebind()
        {
            Snapshot = TufMetadataBuilder.Sign(TufMetadataBuilder.Snapshot(Targets, _counter, _expiry), Keys["snapshot"]);
            Timestamp = MakeTimestamp();
        }

        private byte[] MakeTimestamp() => TufMetadataBuilder.Sign(
            TufMetadataBuilder.Timestamp(Snapshot, _counter, _expiry), Keys["timestamp"]);

        internal void ExportPublic(string output)
        {
            Directory.CreateDirectory(output);
            File.WriteAllBytes(Path.Combine(output, "root.json"), Root);
            File.WriteAllBytes(Path.Combine(output, "targets.json"), Targets);
            File.WriteAllBytes(Path.Combine(output, "snapshot.json"), Snapshot);
            File.WriteAllBytes(Path.Combine(output, "timestamp.json"), Timestamp);
        }

        public void Dispose() { foreach (var key in Keys.Values) key.Dispose(); }
    }
}
