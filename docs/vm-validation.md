# Required VM validation

2026-10-10: **not executed; no disposable VM is available**. Automated tests do not replace these checks.

1. Snapshot a Windows x64 VM with local account/camera passthrough. Record OS, drivers, binary/model hashes and LSASS signing/protection state. Confirm native sign-in and recovery.
2. Service only: verify Off, enrollment, preview, matching, cancellation and encrypted persistence. Exercise recent-native-token and transient-password enrollment. Confirm no password/PIN/frame is persisted.
3. Backend preflight: unsigned activation on protected LSASS must be refused without changing protection. In a suitable signed or already unprotected disposable environment, activate/reboot and confirm package loading without crashes.
4. Native sign-in, enroll, lock and select FacePass. Record **an actual unlock through Winlogon**, its NTSTATUS/audit/profile/token behavior and intact fallback. This success has not been demonstrated.
5. Unknown faces, prints, replay/generated video, multiple faces, lighting, privacy denial, camera disconnect/occupancy/hang: all failures must preserve native sign-in. Test timeout, cooldown, cancellation, Off and service restart.
6. Repeated serialization, consumed/expired tickets, wrong SID/session, tile deselection, user switching, suspend/resume and concurrent diagnostics: stale/diagnostic authorization must never unlock.
7. Automatic mode must respect Windows tile selection. Boot logon, MSA/domain/Entra/RDP and missing native proof must fail closed. Check disabled/locked/expired local-account policies.
8. Disable backend, verify immediate revocation and unchanged other provider/package entries, reboot/uninstall and exercise Safe Mode/WinRE or snapshot recovery.

A recorded real unlock plus fallback/recovery closes the authentication milestone. Signing and biometric assurance are additional production requirements.
