# Verification ledger — 2026-10-10

## Version 0.3.0: password-backed Microsoft-account route

Instant profile follow-up: all six Release x64 CTest suites passed, including 102 policy/storage/liveness checks, 25 provider checks, 10 model checks, Settings rendering/selection, 55 authentication checks and parsing of 15 PowerShell scripts. The live demo IPC suite passed 37 checks and a separate process restart preserved the Instant setting. Deterministic acceptance checks cover the first matching frame with no elapsed time, unknown/below-threshold/invalid scores, saved thresholds, reset behavior, and the existing temporal/active profile requirements. The Face and camera page was visually reviewed with Instant selected. Evidence: build/Testing/Temporary/LastTest.log and build/test-output/settings-face.png. These checks do not establish actual Windows unlock or spoof resistance; Instant intentionally has no liveness protection.

Release x64 builds with MSVC, Windows SDK 10.0.26100.0 and OpenCV 4.12.0. All six CTest suites passed, followed by the live demo IPC and restart checks. The packages are FacePass-0.3.0-win-x64.zip and FacePass-0.3.0-source.zip.

| Check | Result and scope |
|---|---|
| policy_storage_liveness | PASS: 80 checks, including Microsoft-account record bounds, bare-email/split-domain/qualified-name handling before authentication, rejection of other domains and malformed identities, DPAPI password round-trip, absence of plaintext on disk, cross-SID write/swap rejection, provider-only release, fresh authentication for saving, and native Negotiate availability |
| protected serialization | PASS: Windows validates the packed online identity as encrypted; SAME_LOGON decryption recovers the exact synthetic password. EX2 unpacking succeeds and returns a marshaled credential string, not an ordinary password string |
| provider_contract | PASS: 22 COM/field/lifecycle checks; no credential without an authorized backend approval |
| model_inference | PASS: 10 actual ONNX inference checks |
| settings_smoke | PASS: own-window rendering, including saved-password controls; Authentication page reviewed visually without clipped controls |
| authentication_contract | PASS: 55 mock tests of the separate legacy custom LSA package, which the password-backed installer does not register |
| script_syntax | PASS: 14 PowerShell files parse |
| live demo IPC and restart | PASS: 34 checks, including ordinary-client password-release denial, no password backend in demo mode, and encrypted configuration persistence |

Evidence: build/Testing/Temporary/LastTest.log and build/test-output/settings-authentication.png. These tests use synthetic credentials and do not authenticate the user's Microsoft account. They do not establish real LogonUI loading, Session 0 camera access, biometric spoof resistance, or successful Windows unlock. Direct laptop installation and user-controlled password/enrollment steps follow separately; the user explicitly requested skipping VM validation.

Direct installation subsequently succeeded on the user's Windows 11 25H2 laptop. FacePassService runs as LocalService from the protected Program Files installation. PasswordBackedUnlock is enabled and the provider CLSID resolves to the installed FaceUnlockProvider.dll. RunAsPPL and RunAsPPLBoot remain 2; Authentication Packages remains only msv1_0. The custom LSA backend is disabled/unregistered. Initial activation hit a PowerShell New-Item -Force error on the existing options key; activation now creates that key only when absent, and the retry succeeded. Installer evidence: build/password-unlock-install.json and .log. Installed Settings opened as the normal user. Account-password saving, production face enrollment, and actual Windows unlock still require the user's interaction and remain unverified at this checkpoint.

Follow-up: the user entered a bare Gmail address in the generic Windows credential dialog. Settings previously passed that address to LogonUser without the MicrosoftAccount domain, causing rejection before its Microsoft-account record could be constructed. Settings now normalizes bare emails and split/qualified Microsoft-account names before verification, preserving Windows password validation and the current-SID check. Nine normalization/invalid-identity checks were added; all six suites and the live IPC/restart checks passed. The corrected build was installed, its Settings binary SHA-256 matches the package, and the user's production face enrollment remained present. The misleading legacy VM subtitle was corrected for the password-backed route. Evidence: build/password-unlock-email-fix.json and .log. The user still needs to retry password saving; actual Windows unlock remains unverified.

## Historical version 0.2.0 results

Release x64 version 0.2.0 builds with Visual Studio/MSVC, Windows SDK 10.0.26100.0, CMake and OpenCV 4.12.0 on this Windows development host.

## Executed this session

| Check | Result and scope |
|---|---|
| policy_storage_liveness | PASS: 51 checks; configuration, matching, retries, enrollment/storage, nonce rules, role authorization, one-use/forged/expired/session-bound tickets, revocation, minimum liveness time and bounded cancellation of an intentionally hung child |
| provider_contract | PASS: 22 checks; unregistered DLL/COM V2 contracts, per-user tile, fields, lifecycle and no fabricated credential without an authorized backend ticket |
| model_inference | PASS: 10 checks; actual YuNet/SFace ONNX inference, blank/unknown/multiple-face/poor-quality cases and same-face lighting variation |
| settings_smoke | PASS: four-page control construction, light/dark rendering and own-window screenshots; no enrollment or camera capture |
| authentication_contract | PASS: 55 checks; actual authentication DLL/export loading without registration, mock LSA initialization, denied/malformed logons, no failure token/password, audit allocation cleanup and native token/group copying in one LSA-owned block |
| script_syntax | PASS: 10 PowerShell files parse; installers were not executed |
| live demo IPC | PASS: 32 checks; Off, account isolation, persistence, real nonce rejection, ordinary-client unlock-consumption denial and no idle image/ticket |
| demo restart | PASS: encrypted configuration survived server restart; test store isolated under build/Release/test-output |
| supervised camera probe | PASS: worker captured a 320x240 (76,800-pixel) preview in memory and was stopped; no image was saved and no face was enrolled |
| layout review | PASS: settings Face and camera page reviewed visually in light/dark themes; no overlapping or clipped controls |

The latest full verification passed 6/6 CTest suites plus IPC/restart checks. Evidence: build/latest-build.log and build/Testing/Temporary/LastTest.log. Own-window screenshots: build/test-output/settings-overview.png, settings-face.png and settings-face-dark.png. Fixture inference and simulated observations do not establish biometric accuracy or spoof resistance.

The authentication DLL imports Windows APIs and the VC runtime, with no OpenCV/model dependency. Runtime signing/protection still determines whether LSASS can load it.

## Implemented but not validated end to end

- Custom package loading into LSASS, live Credential Provider registration, serialized ticket acceptance through Winlogon and actual local-account Windows unlock.
- Human seven-sample enrollment using recent native sign-in or transient password verification; live recognition of that enrollment.
- Session 0/secure-desktop camera access, real automatic/manual lock transitions, user switching, suspend/resume, account-policy behavior, native fallback and recovery.
- Backend activation/rollback/uninstall on a real disposable VM, PPL/Microsoft-signed loading and offline recovery.

No disposable VM is available. Per the user's instruction, this milestone completes builds and automated tests first. **Actual passwordless Windows unlock has not been demonstrated and the full working-authentication MVP cannot yet be certified.** No custom package/provider was registered on this host during this session. Tests did not change native sign-in providers or create a face profile.

## Remaining scope

Initial boot sign-in and MSA/AD/Entra/RDP authentication are unsupported. Production/Microsoft LSA signing, independent biometric/PAD evaluation, a trusted operation-specific Hello enrollment broker, enterprise provisioning, multiple profiles per account and responsive WinUI polish are not implemented. The general service installer is not a transactional MSI.

The older 0.1.0 ledger reported successful service-only installation/removal on 2026-10-09. That historical result does not validate the new 0.2.0 backend and was not repeated this session.
