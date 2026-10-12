# RC2 changes and validation

## Manager-update wording — issue #68

Reference: https://github.com/MiranoVerhoef/BeszelAgentManager/issues/68

- Replace alarming unsigned/untrusted wording for releases without automatic-update metadata with a neutral explanation and an explicit manual-install option.
- Approved title: **Download BeszelAgentManager {version}**.
- Approved message: **This version needs to be installed manually. Open the official release page, download {installer asset name}, and run it to update. Windows will ask for administrator approval.**
- Approved action: **Open release page**, with **Cancel** as the secondary action. Use the correct Bundled/Lite installer filename for the current edition.
- Use informational/warning styling for missing metadata or unsupported older releases, not a generic crash/error presentation.
- Keep invalid signatures, hash mismatches, replay/downgrade attempts and corrupt protected state as genuine verification failures. Do not claim these are merely missing metadata or automatically bypass checks.
- For a verification failure, use **Update could not be verified** and **Installation was not started. Please try again later. Technical details are available in the log.**
- Keep raw exceptions and security diagnostics in logs; show a concise, actionable explanation in the UI.
- Distinguish project-signed update metadata from Windows Authenticode publisher signing. Lack of Authenticode alone must not imply that the project's verified updater cannot install a release.
- Validate the final wording against the screenshot in issue #68, normal unsigned manual installers, absent/expired metadata, and deliberately altered metadata/installers.

Implemented in RC2: releases with no update-role assets receive the neutral manual
download dialog. Any partial metadata still goes through broker verification;
verification failure does not offer an unverified automatic or manual fallback.
Friendly UI messages retain detailed exceptions in logs. VM wording and positive
published-update tests remain release gates.

## README signing clarification

- Included the README clarification from commit `8766440`: project-private-key signatures authorize update metadata; Windows Authenticode signing of the executables remains a future step, subject to acceptance by an open-source signing program.
- Public PR #70 was closed at the user's request after #69 had already merged. Preserve this documentation change in RC2 or the following release rather than losing it with the closed PR.
