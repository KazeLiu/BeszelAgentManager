# Release procedure

Follow this checklist for every RC and stable release. A successful build creates
a **draft**, not permission to publish. Stop at any failed or unapproved gate.
The maintainer must explicitly approve publication; installer test approval alone
does not authorize it.

Required flow for every version: version-only PR -> Actions draft -> local testing
of those exact assets -> maintainer approval -> local password-prompted metadata
signing -> upload signed public metadata -> **Verify and publish signed release**
workflow on main. Dispatch that workflow with the approved tag only after testing
and signing. It needs no signing keys or passwords; a read-only job verifies the
draft, then a write-enabled job independently downloads and verifies it again
before publication. Any failure leaves the draft unpublished. Stable becomes
latest; RC remains a prerelease. Never bypass it with manual draft publication.

The workflow checks pinned signatures, expiry, both installer hashes/sizes and
versions, channel, trusted commit ancestry and advancement beyond latest stable.
It rechecks asset identity and latest-release identity immediately before publishing.
GitHub asset mutation and publication are not a transactional lock: restrict
release-write access and do not edit drafts during verification/publication.

## 1. Prepare and review

- Use only the version number for the branch and PR title, such as `4.21.1`.
  Use a PR, never push directly to main. Keep the description to `## Summary`
  and technical change bullets; preserve manually edited contribution metadata.
- Keep security-advisory work in its temporary private fork until disclosure and
  the patched release are approved. Do not expose private test or vulnerability
  details in public release records.
- Set VERSION and RELEASE_CHANNEL deliberately. Stable uses `stable`; an RC uses
  a channel such as `rc2`, producing the tag `4.21.1-rc2`. Check GUI, helper,
  installer and release identity agree.
- Run builds, tests and security checks appropriate to the changes. Record skipped
  tests and outstanding limitations; build success is not whole-program security
  approval. Carry forward [release follow-ups](release-followups.md).

## 2. Obtain the exact release candidate

- After review/merge, use the trusted-main release workflow to prepare a draft.
  Record its commit, workflow run, tag and channel. Check the draft targets the
  intended commit and contains both installer editions.
- Download the draft's exact `BeszelAgentManagerSetup.exe`,
  `BeszelAgentManagerSetup-Lite.exe` and `SHA256SUMS.txt` into a dedicated local
  candidate directory. Verify both hashes and sizes against the build output;
  GitHub asset digests, where available, must agree too.
- Do not substitute a local rebuild, even from the same commit. Different bytes
  require new testing/approval and new signed targets. A checksum file alone is
  not the updater's trust mechanism.
- Use signing tools and VERSION/RELEASE_CHANNEL from the matching release checkout.
  `Prepare-SignedRelease.ps1` derives its tag from those files, not from a GitHub
  draft or installer filename.

## 3. Test and obtain approval

Provide the maintainer numbered installer test steps before signing/publication.
Use the [update test checklist](update-test-checklist.md) for security and SYSTEM
integration tests, with isolated VMs for destructive tests. At minimum:

1. Clean-install Bundled; verify first agent setup and normal broker actions.
2. Clean-install Lite with and without its required .NET runtime; verify the
   dependency prompt and background-service installation/repair.
3. Upgrade an existing supported installation with each edition; check config,
   credentials, fingerprint, logs and edition selection are preserved.
4. Test restart, close-to-tray, reboot startup and service scheduling; check logs
   for failures and confirm the displayed version matches the candidate.
5. Validate uninstall and optional historical-log retention on a disposable VM.
6. For updater changes, test a genuine verified GUI update and unelevated reopen,
   plus tampered/expired metadata, changed installer bytes and replay rejection.
   Record explicitly if the positive published-update test is still pending.

Record the tested hashes and maintainer's approval. Do not label skipped tests as
passed. An RC may be approved for further testing with stated limitations; do not
publish stable while required installer/upgrade or updater gates remain pending.

## 4. Approve installer bytes and sign metadata locally

Root and targets private keys stay outside Git and CI. Never upload passwords,
private keys or unsigned intermediate envelopes. Current signing is interactive:
the maintainer enters passwords locally, not in chat or command arguments.

Build the local signing tool, then run from the matching release checkout:

```powershell
dotnet build tools/BeszelAgentManager.ReleaseSigning -c Release
.\tools\Prepare-SignedRelease.ps1 -InstallerDirectory '<exact-tested-candidate-directory>' -KeyDirectory '<protected-local-key-directory>'
```

- Use role counters greater than previously published counters; supply `-Counter`
  when the default UTC Unix-seconds value is not sufficient. Do not reset client
  history or counters to make signing/verification succeed.
- The script signs targets, then snapshot, then timestamp, and verifies the actual
  installers. Parents bind the exact signed child bytes. Any failure stops the
  release; do not publish a partial output directory.
- Validate the public root chain. Initial deployments include `1.root.json`;
  rotations also require every consecutive authenticated public root. The current
  convenience script copies only root 1; rotated chains need explicit operator
  preparation and verification as described in [signed updates](signed-updates.md).
- Check expiry at publication time: normal targets last 90 days, snapshot 7 days
  and timestamp 1 day. Renew stale online metadata before publishing, preserving
  targets and increasing counters. An expired root/targets requires its own
  authorized signing step; freshness renewal cannot fix it.

Project metadata signing does not Authenticode-sign the EXEs or remove Windows
publisher/SmartScreen warnings. Do not describe the executables as publisher-signed.

## 5. Assemble and verify the draft

Attach only the two approved installers, their checksum file, signed
`targets.json`, `snapshot.json`, `timestamp.json`, and the versioned public roots.
Upload targets before snapshot and timestamp last. Never upload an entire signing
directory: it contains unsigned intermediates.

Download the assembled draft's assets into a separate verification directory and
run the built ReleaseSigning tool:

```text
verify-release <downloaded-public-metadata-directory> <downloaded-installer-directory> <exact-release-tag>
```

Check actual downloaded installer hashes/sizes, root chain, role signatures,
counters, expiry, version and both editions. Match these to the approved test
record. Do not replace EXEs or targets after this gate without repeating approval
and verification. Normal authenticated snapshot/timestamp renewal is the exception.

## 6. Publish only with explicit approval

- RC: publish the verified draft as a **prerelease**, not latest stable. Confirm
  opt-in prerelease discovery and the correct Bundled/Lite GUI update after
  publication. RC freshness needs manual renewal; the scheduled workflow ignores RCs.
- Stable: require completed installer/upgrade tests and explicit stable-release
  approval. Use a stable tag and matching metadata; do not simply relabel an RC's
  signed metadata, which binds its RC tag. Verify the final stable candidate and
  publish as latest only after all gates pass.
- Check the published assets and metadata again. Confirm both editions select the
  correct installer and a real GUI update completes and reopens the new version.
  Report any failure; do not bypass verification or silently claim success.

## 7. Maintain freshness and retain an approval record

- The main-only `update-freshness` environment contains only snapshot/timestamp
  keys. Its twice-daily workflow renews metadata for the latest stable release,
  not installers or targets. Verify successful renewal after stable publication.
- Monitor expiry and failed workflows. Targets require local reapproval before
  their 90-day expiry even when installer bytes are unchanged. Keep all public
  roots available to older clients. Never erase protected client checkpoints as
  a recovery shortcut.
- Retain a release record with: tag/channel; commit and workflow run; both EXE
  hashes/sizes; test results/skips and approval; metadata counters/expiries; public
  root versions; verification result; publication approval/time; post-publication
  GUI-update and renewal results. Include no secrets or private advisory details
  in public records.

## Future local Windows key storage

Windows-backed signing is **not implemented**. Current tools still require local
interactive passwords. A future operator-only CNG integration could retain a
user-scoped, non-exportable targets key and sign explicitly approved artifact
hashes without exposing private key bytes to the calling process. Preserve the
existing public key identity or perform an authorized root rotation.

Keep threshold root keys offline and never grant the installed application,
background broker or build workflow targets-signing authority. Non-exportability
limits extraction, not use by a compromised authorized user session. Storing a
password with DPAPI/Credential Manager does not create an application-level trust
boundary. Removing per-use prompts trades convenience for greater release-machine
compromise risk; hardware-backed user-presence protection should be considered
where supported. Implement this only after an explicit design/approval decision.
