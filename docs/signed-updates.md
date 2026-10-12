# Signed manager updates

## Implementation and release gates

4.21.1 connects verification, protected checkpoints, official downloads, staging,
a detached SYSTEM installer worker, and unelevated user-session relaunch. No
stable release is published by this implementation. Installer/upgrade and
positive SYSTEM tests require the [private VM checklist](update-test-checklist.md).
Production metadata signing and limited renewal-key configuration remain operator
steps; neither private keys nor passphrases belong in this repository.

Existing users need one manual bootstrap upgrade. Before approved signed assets
exist on the official release, Update Manager deliberately refuses installation.
Project updater signatures are not Authenticode or SmartScreen publisher trust.

## Trust and execution

- The protected application embeds signed public root version 1. No downloaded
  initial root, user setting, pipe argument, or trust-on-first-use override.
- Restricted TUF 1.0.31: P-256 ECDSA/SHA-256, DER signatures, OLPC canonical JSON;
  no delegations or consistent snapshots. Duplicate JSON, malformed Unicode,
  floats, excessive nesting and metadata over 256 KiB are rejected.
- Root requires two distinct signatures, normally 2 of 3 offline keys. Targets,
  snapshot and timestamp each have a separate authority. Root rotation is
  consecutive and requires both the old and new thresholds.
- Offline targets approve both exact Windows x64 installer names, tag, edition,
  byte length and SHA-256. Snapshot binds targets; timestamp binds snapshot.
  Online keys cannot authorize changed installer bytes.
- Metadata freshness, counter/hash history, clock floor and installed-version
  floor are checked. An interrupted refresh durably retains every accepted role
  before requesting the next one. Missing/corrupt existing history fails closed.
- The repository is hardcoded to MiranoVerhoef/BeszelAgentManager. Stable uses
  latest; opt-in prereleases select the newest valid published version, including
  natural RC ordering. Callers cannot choose a tag, URL, executable or command.
- Downloads are bounded HTTPS requests, with at most three allowlisted redirects
  and no token, cookies or transparent decoding. Installer size is capped at
  512 MiB; the signed exact size and hash are mandatory.
- Edition comes from protected Program Files RUNTIME_VARIANT, not editable
  ProgramData or pipe arguments.
- The UI requests prepare with no arguments; commit accepts only a staged
  operation GUID for that authorized SID. The old manager.installVersion action
  stays disabled. Older releases are an explicit manual-install flow.

ServiceData/secure-manager-updates is SYSTEM/Administrators-owned and writable
only by those identities. Ancestor handles and the verified installer are pinned
through use; reparse points, hard links and untrusted owners/write ACLs are
rejected. Initial sealing and cleanup do not follow user-controlled redirects
or recursively take ownership. Manager code is fixed under Program Files;
custom installation directories are not accepted by this hardened installer.

A copied, renamed helper worker survives replacement of the running service.
Only the fixed installer, arguments, default install directory and protected log
location are used. Commit means accepted, not installed. Completion requires
installer exit 0, exact version/edition, protected GUI/helper executable versions,
the expected LocalSystem SCM command, and a running background service.

The worker relaunches only the captured session's authorized SID with its
unelevated Windows token. If the session is gone, it records a relaunch error;
it never starts a SYSTEM desktop UI. The next UI can read the persisted result.
A committed operation without a terminal result is not automatically discarded:
inspect the protected installer log and process state before operator recovery.

## Operator release approval

Build the local operator tool:

```powershell
dotnet build tools/BeszelAgentManager.ReleaseSigning -c Release
```

After both installers from the exact candidate commit pass testing:

```powershell
tools/Prepare-SignedRelease.ps1 -InstallerDirectory '<tested-installer-directory>'
```

The script reads VERSION/RELEASE_CHANNEL, creates targets, snapshot and timestamp,
asks separately for the three role-key passwords, and verifies metadata plus both
actual installer hashes/sizes and Inno product versions. It never needs offline
root private keys. Default key directory is Desktop/BeszelReleaseKeys; specify
-KeyDirectory after moving it to secure storage. Counter must exceed every
previously published role counter. Outputs never overwrite existing metadata.

Attach only signed targets.json, snapshot.json, timestamp.json, and versioned
public roots (1.root.json and every subsequent authenticated root) alongside
both installers. Do not upload private keys or unsigned intermediate files.
Keep all consecutive roots available to older clients. Root rotations also
require including their public chain in local verification inputs.

Recommended expiries: root 3 years, targets 90 days, snapshot 7 days, timestamp
1 day. Sign child metadata before creating/signing its parent, because parents
bind exact final envelope bytes. Publish snapshot before timestamp. A temporary
mismatch fails closed until a consistent set is available.

The operator tool accepts interactive passwords only, never command arguments
or environment values. Private keys use encrypted PKCS#8, AES-256-CBC and
PBKDF2-HMAC-SHA256 with 600,000 iterations. Keep encrypted keys and passwords
access-controlled and backed up separately; encryption is not permission to
leave keys exposed. Private-key paths cannot be inside Git or traverse reparse
points. The implementation never reads an operator's private keys unattended.

Useful commands:

```text
verify-root <signed-root>
verify-release <public-metadata-directory> <installer-directory> <tag>
keygen <outside-repository-directory> <role-name>
root <public-key-directory> <counter> <UTC-expiry> <output>
targets <installer-directory> <tag> <counter> <UTC-expiry> <output>
sign <input-envelope> <encrypted-private-key> <new-output>
snapshot <signed-targets> <counter> <UTC-expiry> <output>
timestamp <signed-snapshot> <counter> <UTC-expiry> <output>
```

## Limited online freshness renewal

The separate FreshnessSigning tool and renew-update-metadata workflow renew
only snapshot and timestamp, twice daily for the latest stable official release.
This does not replace offline installer approval. Unexpired root-authorized
targets must already approve that release. Authenticated previous online
counters determine strictly increasing versions; unsigned/corrupt counters
and expired targets stop renewal.

Configure the GitHub environment update-freshness on the official repository,
restricted to main, with these four environment secrets:

- BESZEL_SNAPSHOT_PRIVATE_PK8_BASE64
- BESZEL_SNAPSHOT_PASSPHRASE
- BESZEL_TIMESTAMP_PRIVATE_PK8_BASE64
- BESZEL_TIMESTAMP_PASSPHRASE

Only the two limited role keys go there. NEVER upload root or targets private
keys. Secret installation is a separate operator action, not performed by this
implementation. With no secrets, renewal refuses to sign. Scheduled workflows
may be delayed or disabled by GitHub; monitor failed renewal runs and metadata
expiry. RC metadata is deliberately not automatically renewed and must be
renewed manually for continued prerelease testing.

The online tool verifies pinned trust and consecutive public roots, targets,
release identity and key-to-role assignment before signing. It changes no
targets or installer bytes, checks the complete result for both editions, and
uploads snapshot first, timestamp last. A latest-release change aborts upload.
Targets need offline reapproval before their 90-day expiry even if installers
have not changed. The build workflow itself receives no signing secrets; PR
builds have read-only repository permissions. A separate trusted-main job only
prepares a draft release.

Limited-key theft can freeze updates or fast-forward online counters, but cannot
approve another executable. An offline-threshold root rotation changing the
online authorities resets only their accepted counters for recovery; target
history, installed-version floor and clock floor remain. Never erase client
checkpoints to bypass an error. Keep embedded root 1 as the initial anchor across
normal upgrades; changing that anchor requires an explicitly reviewed migration.

## Verification limits

Unit tests use disposable keys and filesystem fixtures, never production private
keys. They exercise signature/expiry/tamper/replay, transport limits, edition
binding, root rotation, checkpoint interruption and redirect-safe cleanup.
Two storage integration tests intentionally require a LocalSystem isolated VM.
Build success and these tests do not prove installer upgrade/uninstall behavior,
WTS relaunch on every account type, power-loss handling or a whole-program absence
of vulnerabilities.

Optional python-tuf interoperability checks remain in
tests/tuf_reference_check.py; Python is only a test dependency.
