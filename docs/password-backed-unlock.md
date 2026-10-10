# Face unlock using an encrypted Microsoft-account password

This experimental route uses a C++ Credential Provider in LogonUI and Windows' existing Negotiate authentication package. It does not load FacePassAuth into LSASS, change Windows Authentication Packages, disable LSA protection, or require the special Microsoft LSA signature. Device application-control policy can still restrict third-party Credential Providers. The user has opted to test directly on the laptop without VM validation; that choice does not establish that unlock works.

## What is stored and released

The account password is reversibly encrypted with DPAPI under the Windows service identity, in service-SID-protected ProgramData storage. Each bounded record contains and validates the account SID. Administrator or service compromise can expose the saved password; encryption does not turn it into a hardware-backed Windows Hello credential. Enrollment's separate password verification remains transient.

Only a SYSTEM LogonUI process, verified from its Windows executable path and OS caller token, may request password release. Its session must be the enrolled user's existing locked console session, with native sign-in/unlock observed since service startup. A private supervised worker must pass the face match and randomized Strict challenge unless the user explicitly selects Instant. Instant accepts the first quality 2D match at the saved cosine threshold without challenges, liveness, a minimum wait or repeated matching frames. Photos or replayed video can unlock in Instant. Its ten-second service approval is bound to SID/session, expires monotonically, and is consumed once. Ordinary settings/CLI scans receive neither approvals nor passwords. The per-user demo cannot save or release Windows credentials.

The provider receives the credential over the SCM-PID-verified local pipe, packs it in its own LogonUI session using CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS, and submits it to Negotiate. Windows validates the account password and account restrictions. Owned credential copies are wiped when destroyed. Passwords are never placed in CLI arguments or logs. Windows owns the final serialized buffer. An authentication rejection removes the saved credential to avoid repeatedly submitting a stale password.

Microsoft documents the distinction between [credential collection and Windows authentication](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication), and [online identity credential packing](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credpackauthenticationbufferw). Microsoft's [Credential Provider sample](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/CredentialProvider/cpp/CSampleCredential.cpp) uses these protected online identity flags and Negotiate for connected accounts.

## Direct setup

1. Build/package 0.3.0. In elevated x64 PowerShell run scripts/install-password-unlock.ps1. The separate activation command is installer/enable-password-unlock.ps1 -AllowUnvalidatedHost. No VM claim is made; native sign-in providers remain registered.
2. Launch C:\Program Files\FacePass\FaceUnlockSettings.exe as the normal user, without --demo. Save Manual mode and camera preferences. To skip unlock challenges, choose Face and camera → Recognition profile → Instant (2D match; no challenges) and Save preferences. Manual and Automatic both support Instant. Other profiles retain Strict challenges for Windows unlock. `FacePassRecognition.exe --profile instant` also saves this preference; `--profile balanced` restores challenges. Instant does not remove the seven pose samples required during enrollment.
3. In Authentication choose Save Windows password. Enter your Microsoft-account email address and password in the Windows dialog. MicrosoftAccount\your-email also works. A bare email is explicitly qualified as a MicrosoftAccount identity before LogonUser verification; other supplied domains/providers are refused. The service independently verifies that the credentials produce the currently signed-in user's SID before encrypting them. PINs and other accounts/providers are refused.
4. Enroll the face into the installed service. Demo enrollment is separate and is not silently imported across encryption identities.
5. Lock and unlock once using native PIN/password so the service observes a native session unlock. Lock again, select Sign-in options and the FacePass tile. Instant completes the face scan on its first qualifying match; other profiles show the head-turn challenge. Camera startup/inference and Windows submission still take time. Windows controls selection and final submission.
6. Check recognition failure, unknown faces, cancellation and camera disconnect preserve native sign-in. Actual LogonUI loading, Session 0 camera access and a real unlock still require direct verification on this laptop.

## Remove or recover

Remove saved password in Authentication deletes the encrypted credential. Delete profile deletes both the face template and credential. After a Microsoft-account password change, save the new password again. FacePass cannot use a passwordless Microsoft account through this password route.

Run installer/disable-password-unlock.ps1 elevated to disable password release immediately and unregister only the FacePass tile. The service and data remain so the user can delete data separately. Run installer/uninstall.ps1 -RemoveBiometrics to uninstall and erase all saved passwords/templates. Recovery via installer/recover.cmd disables both backend flags and unregisters FacePass. Native PIN/password remains available; no account conversion is performed.

Boot sign-in, AD/Entra, RDP and genuinely passwordless webcam authentication are outside this route. RGB spoof resistance remains unevaluated.
