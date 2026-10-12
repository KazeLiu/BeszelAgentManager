# Security model

## Trust boundaries

- The WinUI process runs as the signed-in user and is not trusted with administrator privileges.
- The background service runs as LocalSystem and accepts only explicitly allowlisted broker actions.
- The Windows account that installed the manager is the only non-SYSTEM broker client.
- Administrators and SYSTEM control installation files, policy, and privileged staging directories.

## Broker authorization

- Fixed local pipe: `BeszelAgentManager.Background.v1`
- Protocol version: `1`
- Pipe ACL: authorized installer SID and SYSTEM; network SID denied
- Server-side verification: connected client is impersonated and its SID must match policy
- Client-side verification: pipe server PID, service image path, and LocalSystem service account must match
- First server instance: `PipeOptions.FirstPipeInstance`
- Pipe-name collision recovery: warning logged once, five-second retries, and automatic recovery when the name is released
- Request size: bounded before JSON parsing
- Mutations: serialized through one process-wide gate
- Arguments: action-specific booleans, versions, and release tags are validated

The readable account name is used only for logging. Authorization always compares SIDs.

## Filesystem controls

`C:\ProgramData\BeszelAgentManager` contains user-editable configuration and UI logs. LocalSystem writes only below `C:\ProgramData\BeszelAgentManager.ServiceData`, which has protected ACLs granting the authorized account read and execute access but no write access. NSSM and the agent executable are protected below `C:\Program Files\Beszel-Agent`.

Privileged initialization and cleanup use pinned local object handles:

1. keep ancestors open against rename/replacement;
2. reject redirected ancestors and untrusted privileged storage ownership;
3. change ACLs on the same validated object, never a newly resolved pathname;
4. reject hard links before applying privileged file permissions;
5. unlink cleanup junctions without traversing their targets;
6. use no recursive takeown/icacls fallback.

Broker configuration is size-bounded and validated before use. Only explicit Beszel Agent variables are accepted, and every applied value rejects NUL, CR, and LF characters. `CA_CERT_FILE` is restricted to an absolute local-drive path. File-backed `TOKEN_FILE`, `KEY_FILE`, and `DATA_DIR` settings and arbitrary process-environment names are rejected for the LocalSystem agent.

During upgrade, the unelevated manager reads any legacy `TOKEN_FILE`, `KEY_FILE`, and `DATA_DIR\fingerprint` values that the signed-in user can already access. Credentials are promoted into the typed configuration and a 48-character fingerprint is passed through a dedicated validated broker action. The elevated installer never reads caller-selected legacy files. Failed migrations remain visible in the UI and are not silently discarded.

## Update verification

Manager updates:

- accept a prepare request with no caller-selected tag/path/URL/edition;
- retrieve metadata from the hardcoded manager repository;
- select the exact Bundled or Lite installer from the protected installed edition;
- require HTTPS GitHub asset URLs;
- enforce download-size limits;
- verify pinned project-signed TUF metadata and exact installer hash/byte length;
- enforce expiry, durable counters, root rotation and clock rollback protection;
- stage under a service-controlled directory;
- launch only the fixed staged installer with fixed silent arguments;
- refuse tags older than the installed manager.

Project metadata signatures authorize the secure updater without accepting an
arbitrary Authenticode publisher. Missing metadata fails closed. Older manager
versions remain an explicit manual installer flow. See [signed updates](signed-updates.md)
for the offline approval and limited-key renewal boundaries.

Agent updates accept only the expected Windows x64 asset and versioned checksum file from the hardcoded Beszel repository, enforce HTTPS GitHub URLs and size limits, verify the archive's SHA-256 entry, and extract only a verified archive into a restricted temporary directory. Missing checksum assets, missing archive entries, mismatched hashes, and broker-requested downgrades are rejected before installation.

## Secrets

- The optional GitHub token is encrypted with DPAPI `CurrentUser` scope.
- Support bundles replace key, token, and encrypted-token fields with redacted values.
- Logs do not intentionally write token values.
- Credential-bearing `ALL_PROXY` values are redacted from manager logs and support bundles.
- Broker policy stores a SID, not credentials.

## UAC boundary

Normal privileged actions use the installed broker. UAC remains for:

- initial installation;
- manager upgrade/uninstall when invoked interactively;
- the interactive NSSM **Edit service…** command.

## 4.0.10 audit status

The final source audit covered broker authentication, command and URL allowlists, privileged process resolution, download verification and limits, archive staging, reparse-point handling, ProgramData ACLs, secret redaction, uninstall cleanup, and dependency advisories.

Remediated findings include privileged writes beneath user-controlled ProgramData, unvalidated LocalSystem environment variables, pipe squatting and overbroad client impersonation, unsigned SYSTEM manager updates, and broker-requested downgrades. Debug and Release builds, core tests, NuGet advisory checks, and the private CI/VM installer matrix remain release gates.
