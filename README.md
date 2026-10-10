# FacePass_Windows

FacePass is an experimental Windows x64 face-unlock app built with C++20 and OpenCV. It recognizes faces offline with YuNet and SFace, stores encrypted face templates, and provides a native Settings app, Windows service, supervised camera worker, and Credential Provider.

The Microsoft-account unlock route stores an **encrypted Windows account password** and submits it through Windows' built-in Negotiate authentication after an approved face match. Windows performs final authentication. No PIN is stored, and this route does not install a custom LSA authentication package.

**Status:** the Release build, all six automated test suites, and demo IPC/restart checks pass. Actual Windows lock-screen unlock has not been verified. FacePass is not Windows Hello or production authentication software. See the [verification ledger](docs/test-results.md).

## Features

- Offline face detection and recognition using a standard RGB webcam.
- Seven enrollment samples, encrypted per Windows account with DPAPI.
- Instant matching or temporal/head-turn recognition profiles.
- Manual, Automatic, and Off activation modes.
- Settings for the camera, similarity threshold, retry limit, cooldown, and scan timeout.
- Live camera preview, enrollment, diagnostic recognition, and cancellation.
- A supervised capture process with cancellation and a hard deadline.
- Authenticated local IPC and session-bound, ten-second, one-use unlock approvals.
- Optional encrypted Microsoft-account password storage and Windows credential submission.
- Native Windows PIN/password sign-in remains available.

## Recognition profiles

Choose a profile in **Face and camera → Recognition profile**, then click **Save preferences**.

| Profile | Diagnostic recognition | Windows unlock |
| --- | --- | --- |
| Convenience | Stable frames with a minimum wait | Strict randomized challenge |
| Balanced | Short randomized head-turn challenge | Strict randomized challenge |
| Strict | Randomized multi-step head-turn challenge | Strict randomized challenge |
| Instant | First qualifying 2D face match | First qualifying 2D face match |

**Instant** skips head-turn challenges, liveness checks, the minimum wait, and repeated-frame requirements. It accepts the first quality face frame that meets the saved cosine threshold. **A photo or replayed video can unlock in Instant mode.** Camera startup, model inference, and Windows submission still take time. Enrollment still requires seven quality pose samples.

The saved threshold must be between `0.363` and `0.85`. Higher thresholds reject more faces. Convenience, Balanced, and Strict enforce minimum thresholds of `0.363`, `0.45`, and `0.55` respectively during diagnostics. Windows unlock enforces Strict and at least `0.55` unless Instant is explicitly selected.

Activation is separate from the recognition profile:

| Activation | Behavior |
| --- | --- |
| Off | Face scanning is disabled. |
| Manual | A scan starts when the FacePass tile is selected or a diagnostic scan is requested. |
| Automatic | Unlock scanning starts when Windows loads the provider. Windows controls tile selection and submission. Without an unlock backend, console lock events can start diagnostic scans. |

## Build from source

Requirements:

- Windows x64 and an RGB webcam for live capture.
- Visual Studio 2022 or newer with Desktop development with C++ and the Windows SDK.
- CMake 3.24 or newer; the build script can use Visual Studio's bundled CMake.
- The x64 Visual C++ runtime to run the binaries.

From the project directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1 -Configuration Release -Package
```

Setup downloads OpenCV 4.12.0 and verifies the OpenCV/model SHA-256 hashes. The ONNX models are bundled in this repository; setup downloads them again if missing or mismatched. Runtime face inference is offline. Model sources and licenses are documented in [models/README.md](models/README.md).

The build script runs CTest and isolated demo IPC/restart checks. It writes binaries to `build/Release`, the installable package to `dist/FacePass`, and binary/source ZIP archives to `dist`. Building and testing do not register Windows sign-in components.

## Try the demo

The demo uses a separate per-user service and encrypted store. It cannot authorize Windows unlock or save/release a Windows password.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-demo.ps1
```

In Settings, save **Authentication → Manual**, select your camera, and save preferences. Choose **Enroll face** for transient Windows password verification, or **Use recent sign-in** within two minutes of native Windows sign-in. Follow the preview to collect the enrollment samples, then use **Test recognition**. Closing Settings stops the demo server launched by the script.

With the demo running, equivalent CLI commands are:

```powershell
.\build\Release\FacePassRecognition.exe --demo --manual
.\build\Release\FacePassRecognition.exe --demo --profile instant
.\build\Release\FacePassRecognition.exe --demo --enroll-session --watch
.\build\Release\FacePassRecognition.exe --demo --scan --watch
.\build\Release\FacePassRecognition.exe --demo --off
```

Use `--enroll` for transient password verification. Watched enrollment/recognition jobs return `0` on success, `2` on failure, and `3` on cancellation. `--help` lists the service and standalone commands.

## Install Microsoft-account face unlock

Read the [password-backed unlock guide](docs/password-backed-unlock.md) and [recovery guide](docs/recovery.md) before installation. This experimental route supports an existing **Microsoft-account console session after native sign-in**. Boot sign-in, AD/Entra accounts, and RDP are unsupported.

After building the package, run this from an elevated x64 PowerShell in the project directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-password-unlock.ps1
```

This installs the Windows service and registers the FacePass Credential Provider. It explicitly enables testing on an unvalidated host; it does not establish that lock-screen unlock works. LSA protection and Windows Authentication Packages remain unchanged.

1. Open Settings as your normal user. Press **Win + R**, enter `"C:\Program Files\FacePass\FaceUnlockSettings.exe"`, and press Enter.
2. Save **Manual** or **Automatic** activation and the camera preferences.
3. In **Authentication**, choose **Save Windows password**. Enter the Microsoft-account email and account password, not a PIN. `MicrosoftAccount\your-email` also works. The service verifies the credentials against the signed-in user's SID before saving them encrypted.
4. Enroll your face in the installed service. Demo enrollment is separate.
5. To skip unlock challenges, choose **Face and camera → Recognition profile → Instant** and click **Save preferences**.
6. Use native Windows PIN/password once after service startup or an update. Lock again, select the FacePass tile, and try recognition. Instant accepts the first qualifying match; other profiles require the Strict head-turn challenge.

The CLI can save a profile without changing activation:

```powershell
& 'C:\Program Files\FacePass\FacePassRecognition.exe' --profile instant
& 'C:\Program Files\FacePass\FacePassRecognition.exe' --profile balanced
```

After a Microsoft-account password change, save the new password in Settings. **Remove saved password** erases the stored credential; **Delete profile** erases both the face template and credential. A passwordless Microsoft account cannot use this password-backed route.

## Disable or uninstall

Select Windows **Sign-in options → PIN/password** whenever FacePass is unavailable.

From an elevated PowerShell, disable password-backed unlock with:

```powershell
& 'C:\Program Files\FacePass\installer\disable-password-unlock.ps1'
```

To uninstall and erase saved face templates/passwords:

```powershell
& 'C:\Program Files\FacePass\installer\uninstall.ps1' -RemoveBiometrics
```

See [recovery](docs/recovery.md) for provider removal and recovery procedures. Native Windows providers remain available.

## Components

| Component | Purpose |
| --- | --- |
| `FaceUnlockSettings.exe` | Preferences, enrollment, camera preview, and diagnostics |
| `FaceUnlockService.exe` | LocalService, authenticated IPC, encrypted storage, session policy, and one-use approvals |
| `FacePassCapture.exe` | Private supervised camera/inference worker |
| `FacePassRecognition.exe` | Service and standalone CLI |
| `FaceUnlockProvider.dll` | Native account tiles and Windows credential submission |
| `FacePassAuth.dll` | Optional legacy LSA backend for local-account console unlock |

The legacy no-stored-password backend is separate from Microsoft-account password-backed unlock. It requires suitable Microsoft LSA signing and disposable-VM validation. See the [legacy backend guide](docs/passwordless-mvp.md), [authentication design](docs/authentication.md), and [VM checklist](docs/vm-validation.md).

## Tests and limitations

The latest Release validation passed all six CTest suites: policy/storage/liveness (102 checks), provider contracts (25 checks), ONNX inference (10 checks), Settings rendering/selection, legacy authentication contracts (55 checks), and PowerShell script parsing. Live demo IPC passed 37 checks, and a process restart preserved Instant preferences.

These tests cover matching policy, existing challenge timing, immediate Instant acceptance, encrypted persistence, role/session authorization, protected credential serialization, COM lifecycle behavior, and bounded worker cancellation. They do not establish successful Winlogon authentication, Session 0 webcam availability, biometric accuracy across users/cameras, or spoof resistance.

RGB challenges have no measured presentation-attack assurance, and Instant has no liveness protection. The stored password is reversibly encrypted: an administrator or compromised service can recover it. This project does not provide hardware-backed Windows Hello security.

Further reading: [architecture](docs/architecture.md), [security boundaries](docs/security.md), [installation](docs/installation.md), and [verification results](docs/test-results.md).
