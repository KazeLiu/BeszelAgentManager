# 4.21.1 private installer validation

Do these checks on a disposable Windows VM with a snapshot, not a production
machine. Both test installers are RC builds. Keep build artifacts, results,
and the private pull request private until release approval.

1. Install Bundled cleanly. Leave launch unchecked, then open it manually.
   Confirm the displayed version is 4.21.1-rc1, background service runs as
   LocalSystem, and Start/Stop/Restart/Apply work without routine UAC.
2. Install Lite on a separate snapshot without .NET 10 Desktop Runtime x64.
   Confirm the prerequisite prompt; install the runtime and retry. Test both
   editions with a local Windows account and an Entra ID account.
3. Upgrade an existing v3.1.0 and a v4 installation. Back up configuration,
   token, agent fingerprint and logs first. Confirm they survive, schedules
   retain due times, and the authorized Windows user remains correct.
4. Confirm Program Files code and ServiceData reject standard-user writes.
   Test junctions, hard links and rename races using disposable canary files,
   never protected OS files. A redirected/untrusted code root must produce an
   explanatory installer failure, not silently take ownership of other data.
5. Exercise Extra repair/check, scheduled update/restart/log rotation, DNS
   fallback, close-to-tray, hidden startup, reboot, uninstall with retained
   logs, and reinstall. Confirm another user cannot send privileged requests.
6. Click Update Manager before official signed metadata exists. Confirm a
   verification error with no installer execution and no claimed completion.
   Caller-chosen tag/path/URL/edition requests and legacy manager.installVersion
   must remain rejected.
7. After approval of a signed official RC release, test a genuine GUI update
   for both editions. It must exit normally, install once without UAC, reopen
   unelevated in the same user's session, and show the new version only after
   service/edition checks succeed. Do not create a public release solely to
   test an unapproved security build.
8. In isolated verifier tests, alter metadata/installers, replay old counters,
   expire timestamp/targets, move the clock backward, cancel downloads and
   interrupt checkpoint writes. All must fail closed without erasing history.
   Missing/corrupt existing checkpoints require operator review, not reset.
9. Run the two SYSTEM-only storage tests in the isolated VM under LocalSystem
   with BESZEL_ISOLATED_VM_TESTS=1. They deliberately skip under normal user
   execution. Capture results and restore the VM snapshot afterward.

Report the installer edition, account type, previous version, and any errors.
Stable publication remains blocked until this checklist is approved.
