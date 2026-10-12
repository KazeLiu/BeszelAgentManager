# Signed manager updates — private implementation stage

## Status and release gates

The metadata verifier, staged refresh coordinator and local signing tool are implemented. They are **not yet
connected to a SYSTEM installer launch**. The GUI remains manual-update-only;
the legacy `manager.installVersion` broker action returns error 58. The old
checksum/any-valid-Authenticode launcher has been removed, not retained as a fallback.

The refresh coordinator awaits a durable checkpoint after each verified role,
before fetching the next role. Interrupted downloads retain accepted history;
checkpoint failures abort the refresh. Its transport/storage callbacks are not
yet connected to service-controlled HTTP and protected filesystem storage.

Before enabling automatic installation:

1. Complete the operator key ceremony and independently confirm the public root.
2. Embed that exact public root in the protected application build. Never load
   initial trust from downloaded metadata, user settings, or broker arguments.
3. Secure installer code roots, initialization, repair, and uninstall filesystem
   operations. Validate redirected ancestors, hard links and concurrent renames
   on an isolated VM; metadata signatures do not fix filesystem vulnerabilities.
4. Add bounded official-repository metadata fetching with authenticated,
   consecutive root rotation; select the installed edition from protected state.
5. Persist authenticated roots, counters, hashes and last verified time under
   protected ServiceData. Persist each accepted role before subsequent network
   work, including on partial refresh failure; do not reset history on upgrade.
6. Pin staging directory and file identity; keep non-administrators unable to
   replace the verified executable through download, verification and execution.
7. Add a fixed-argument installer runner, unelevated relaunch, and post-install
   edition/version/service checks. "Staged" is not "installed successfully".
8. Exercise the tamper, replay, clock, key-rotation, interrupted-update and
   Bundled/Lite matrix. Provide numbered installer tests and await approval.

This stage is deliberately fail-closed. No production keys were generated, no
root is trusted yet, and no release is published by this implementation.

## Protocol profile

TUF 1.0.31 top-level metadata: `root.json`, `targets.json`, `snapshot.json`,
`timestamp.json`. Canonical signatures follow OLPC canonical JSON, P-256 ECDSA,
SHA-256 and DER signature encoding. JSON rejects duplicate members, malformed
Unicode, floating-point values, excessive nesting, and inputs over 256 KiB.

This is a restricted profile, not a complete generic TUF client: no delegations,
no consistent snapshots, only Windows x64 and the two exact installer filenames.
Other profiles fail closed. Metadata versions are positive signed 64-bit
integers. Hash and byte-length
bindings are mandatory. Re-signing different bytes requires a new version.

Root requires two independent signatures (normally 2 of 3 offline keys). Each
other role uses its own distinct key. Identical public key material cannot be
counted under aliases, or shared between roles. Rotation must be signed by both
old and new root thresholds and increment the root version exactly once.

The offline targets key approves BOTH editions, their exact hashes/sizes, the
repository, tag, edition and architecture. Snapshot binds targets; timestamp
binds snapshot. A timestamp key cannot approve another installer. New metadata
cannot authorize an older manager. Clock rollback or expired metadata pauses
updates; it never enables an unsigned/manual-trust fallback.

Downloads are derived from the hardcoded official GitHub repository, verified
tag and exact asset name. No caller-provided executable, URL, path or command.
Keep prior versioned roots accessible to old clients; root rotation cannot skip
intermediate trust. Freshness metadata must be renewed even between releases.

An authenticated root rotation changing timestamp/snapshot authority clears
their cached counters/hashes, allowing recovery from online-key fast-forward
attacks. Root and target history remain protected. Normal upgrades and ordinary
refreshes never reset counters. Increase role versions during normal operation.

## Operator tool

`tools/BeszelAgentManager.ReleaseSigning` is a local .NET 10 console tool. It is
not packaged with Bundled or Lite. Passwords are entered interactively, not via
arguments, environment variables or CI secrets. Keys use encrypted PKCS#8 with
AES-256 and PBKDF2-SHA256 (600,000 iterations). Private key paths must be outside
Git checkouts and cannot traverse reparse points. Outputs never overwrite files.

Build:

```powershell
dotnet build tools/BeszelAgentManager.ReleaseSigning -c Release
```

Run the built executable with these commands:

```text
keygen <outside-repository-directory> <role-name>
root <public-key-directory> <root-counter> <UTC-expiry> <unsigned-output>
targets <installer-directory> <release-tag> <targets-counter> <UTC-expiry> <unsigned-output>
sign <input-envelope> <encrypted-private-key> <new-output>
snapshot <signed-targets> <snapshot-counter> <UTC-expiry> <unsigned-output>
timestamp <signed-snapshot> <timestamp-counter> <UTC-expiry> <unsigned-output>
verify <pinned-root> <timestamp> <snapshot> <targets> <edition> <installed-tag>
```

Role names: `root-1`, `root-2`, `root-3`, `targets`, `snapshot`, `timestamp`.
Expiries use `yyyy-MM-ddTHH:mm:ssZ`. Example lifetimes: root 3 years, targets
90 days, snapshot 7 days, timestamp 1 day. Plan renewal and secure key backups;
do not place every offline root/targets key on the release runner. The encrypted
key files and passphrases still require separate backups and access controls.

Initial ceremony: generate keys in a private operator-controlled location;
collect public PEM files; create root metadata; sign it with two root keys;
verify/review the role assignments and public-key fingerprints independently.
Only public metadata belongs in the repository/build. Do not generate a root
from unreviewed public key files supplied by a release workflow.

For each release: review the exact build/commit, test both installers, generate
targets, and sign targets locally. The tool checks each Inno numeric product
version; the RC identity must also be confirmed against the build's channel.
Then create/sign snapshot and create/sign timestamp IN THAT ORDER: signatures
change file bytes, so parents must bind the final child envelopes. Verify the
whole chain for BOTH editions and the actual installers before publishing.
The `verify` command checks metadata only; the client stream verifier checks
installer bytes. Operator approval must cover the exact artifacts, not just a
version string. Keep release-signing keys outside GitHub.

The release workflow prepares draft releases. Attach approved public metadata
to the GitHub release, complete testing, then publish manually. No separate
installer server is needed. Future freshness renewal automation must have only
limited role keys, approved release bindings, and no targets/root signing rights.
Implement and review that automation before relying on daily freshness renewal.

Existing users need one manual bootstrap upgrade. These signatures authenticate
our updater, not Windows publisher trust: SmartScreen behavior is unchanged.
SignPath can later add Authenticode signing without removing metadata checks.

## Local verification

Core tests use disposable in-memory keys, never an operator key. Optional
reference checks use Python ONLY for tests; it is not a runtime dependency:

```powershell
$env:BESZEL_TUF_INTEROP_OUTPUT = Join-Path $PWD 'build/tuf-interop'
dotnet test tests/BeszelAgentManager.Core.Tests -c Release
Remove-Item Env:BESZEL_TUF_INTEROP_OUTPUT
python -m venv .tools/tuf-reference
.tools/tuf-reference/Scripts/python -m pip install tuf cryptography
.tools/tuf-reference/Scripts/python tests/tuf_reference_check.py build/tuf-interop
tools/BeszelAgentManager.ReleaseSigning/bin/Release/net10.0/BeszelAgentManager.ReleaseSigning.exe verify build/tuf-interop/reference/root.json build/tuf-interop/reference/timestamp.json build/tuf-interop/reference/snapshot.json build/tuf-interop/reference/targets.json bundled 4.0.10
```

Reference checks verify .NET signatures/bindings with python-tuf, then verify
independently generated Python signatures/bindings with .NET. Fixture outputs
contain public metadata only, under ignored `build/`; private test keys remain
in memory. Tests do not prove filesystem, installer, or production key security.
