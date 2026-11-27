# Verification ledger — 2026-10-25

## Face verification waits for lock-screen interaction

The provider now waits after face verification until a subsequent keyboard/mouse input timestamp is observed with its Winlogon desktop active. A face approval alone cannot request an auto-logon default, make tile selection auto-submit, or return a serialized credential. Both Manual and Automatic use this gate. The provider shows an interaction prompt while waiting, and an expiry prompt when the unchanged ten-second approval expires. New approval nonces require new input; repeated enumeration/Advise preserve an approval already waiting for input.

Release x64 validation passes all eight CTest suites and 37 live demo IPC checks, plus restart persistence. The automatic/provider/session suite now passes 237 checks using the production provider/controller with test-only input/desktop/capture seams. It verifies no submission during idle time or for pre-verification input; direct serialization and tile selection cannot bypass confirmation; fresh input allows a single credential release; stale/future timestamps, failed input queries and inactive desktops fail closed; expired/cancelled approvals cannot submit; a subsequent lock with the same provider needs a new interaction; and uptime tick rollover still permits valid input. Existing session, cancellation, recognition, encryption and authentication tests pass.

Evidence: `build/Testing/Temporary/LastTest.log` and the live integration script output. These are contract tests with simulated input timestamps, not a physical Space/Enter/mouse, lock-curtain, or complete Windows unlock test. Real secure-desktop behavior still needs a manual laptop check. See [interaction behavior and Windows APIs](automatic-unlock.md) for the implementation and live verification steps. No input contents are recorded, injected or hooked.

## Faster response and automatic low-light correction

Release x64 passes all eight CTest suites and 37 live demo IPC checks, followed by the encrypted Instant-preference restart check. The ONNX suite now passes 52 checks. It exercises real YuNet/SFace inference with input intensities scaled to 50%, 35%, 25% and 18%; same-identity cosine scores are approximately 0.874, 0.879, 0.887 and 0.847, respectively, above the unchanged Strict threshold of 0.55. Different-identity fixtures remain below 0.363 when detected. Dim multiple-face images, near-black/flat frames and a blurred dim face are rejected. HD frames preserve identity after landmark scaling. A scripted camera delivers an empty frame followed by a dim face: Instant returns on that first matching face before optional preview work. A cancelled scan reads no additional frame.

The final run averaged 89.6 ms for detection plus embedding on the 512x512 fixture and 128.7 ms on a 1280x720 fixture, over six repeated inferences after initialization. These are fixture measurements on this CPU, not a camera-to-Windows-unlock latency guarantee. Capture retries no longer add 90/180 ms sleeps. Active provider polling is 50 ms rather than 250 ms; idle polling is 200 ms. Worker previews are limited to 10 Hz. The detector preserves aspect ratio with a 480-pixel shorter-edge and 960-pixel longer-edge limit, while face alignment uses original-resolution pixels.

Evidence: `build/Testing/Temporary/LastTest.log`; local Release binaries and packages in `dist/FacePass` and `dist/FacePass-0.3.0-win-x64.zip`. The parallel build stages shared models and the OpenCV runtime once, avoiding concurrent post-build copies. The camera fallback test checks the current source-unavailable message.

Low-light cases are simulated pixel-intensity changes, not measured illuminance or physical-camera trials. No new physical low-light enrollment, secure-desktop capture or Windows unlock was performed, and the installed service/provider were not replaced. Existing profile challenges, cosine thresholds, enrollment sample count, camera failover resets and cancellation remain in effect. RGB capture still requires visible detail; Instant still has no liveness protection.

## Native Windows phone-camera fallback

Release x64 validation passes all eight CTest suites. The new camera_fallback suite exercises the production Camera failover with a simulated transport and passes 172 checks: primary capture preference, path-matched DirectShow indices, legacy DirectShow-only capture, failed opens, empty/invalid/exception frames, disconnect after delivery, newly available phones, custom/parenthesized/localized native-camera names, BGRA conversion, oversized frames, missing saved camera indices, multiple native virtual cameras, unrelated-camera exclusion and finite exhaustion. Stream generations change on replacement so enrollment samples and recognition challenges reset. Existing policy/provider/model/authentication/automatic lifecycle/script suites pass. Live demo IPC passes 37 checks and a separate restart preserves preferences.

The real Windows camera list contains `0: Mukhil's M35 (Windows Virtual Camera)`. An interactive-user probe with missing primary index 15 fell back through Media Foundation to that phone and delivered 1280x720 BGR frames. The same missing-index probe through the supervised worker returned a 320x240 (76,800-pixel) preview in memory, cancelled and stopped successfully. No camera images were saved and no face was enrolled. The restricted execution sandbox denied live camera and authenticated demo-pipe access; the successful live checks used the normal Windows user token outside that sandbox.

Settings' Face and camera page was visually verified in light and dark themes, including the new fallback explanation and enumerated phone name. Evidence: `build/Testing/Temporary/LastTest.log`, `build/test-output/settings-face.png`, `build/test-output/settings-face-dark.png`, and the documented `FacePassRecognition.exe --camera-probe --camera 15` / `--capture-probe --camera 15` outputs. Updated binaries are packaged in `dist/FacePass` and `dist/FacePass-0.3.0-win-x64.zip`.

The installed Windows service/provider were not replaced or registered. **Phone streaming from the installed LocalService/Session 0 worker and actual lock-screen unlock remain unverified.** A driver that blocks still requires the overall supervisor deadline to terminate it; phone failover is verified for reported open/read failure, not a hung driver. Native Windows virtual cameras are tried in enumeration order; this is not an authenticated proof of the physical capture device or spoof resistance.

## Automatic activation follow-up

The user reports the existing manual FacePass credential provider successfully unlocks Windows. This change retains that authentication backend and adds service-owned automatic activation on eligible console lock/resume, independent LogonUI status monitoring, approval-gated documented auto-logon requests, and cancellation/session cleanup. Existing Automatic/Manual/Off preferences and storage formats are preserved; IPC advances to version 4, so all binaries must be updated together.

Release x64 validation: all seven CTest suites pass, including the new automatic_unlock_lifecycle suite with 172 checks. The other suites cover 102 policy/storage/liveness checks, 25 production-provider checks, 10 real ONNX inference checks, Settings rendering/selection, 55 legacy authentication checks and PowerShell parsing. Live demo IPC passes 37 checks and its restart preserves preferences. The new suite executes the actual provider and Controller with test-only OS identity, IPC, clock and capture seams; it uses synthetic encrypted fixture credentials and the real protected Windows Negotiate packing API. It never performs Windows logon or provider registration. Production binaries have no test overrides.

The suite covers provider advice before the lock event, capture without SetSelected, no FacePass default before approval, one auto-logon notification per ticket, unchanged enumeration/callback attachment, existing manual selection and Scan again (including selection during a delayed initial mode query), one-use password release, cross-session cancellation/release denial, old-screen cancellation rejected after a new resume, failure/timeout results without repeated scanning, Off, queued-result cancellation, provider teardown, native desktop return, suspend/resume and duplicate events (including Windows retaining the same advised provider after failure or selected-tile cancellation), startup provenance, user switching after console ID changes, and diagnostic scans without authentication grants. Existing tests also exercise cancellation of a real unresponsive supervised worker.

Evidence: build/Testing/Temporary/LastTest.log; packaged binaries in dist/FacePass and FacePass-0.3.0-win-x64.zip. The installed service/provider were not replaced or registered in this change. **Real unattended unlock with PIN/password selected, actual secure-desktop camera operation after these changes, and physical sleep/user-switch transitions remain unverified.** CredentialsChanged S_OK or recognized status alone does not prove Winlogon submission or authentication. Windows may retain another provider or require its sign-in button; FacePass requests the supported auto-logon default and retains its manual tile. See [automatic behavior and verification procedure](automatic-unlock.md).

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
