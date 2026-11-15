# Local-account setup on this laptop

FacePass is installed at `C:\Program Files\FacePass`. Open the **FacePass Settings** desktop shortcut.

1. In **Authentication**, choose **Save Windows password**. Enter `.\mukhil` and your existing local Windows account password in the Windows dialog. A PIN is not a password. Do not send the password in chat.
2. In **Face and camera**, select the integrated camera (camera 0), then **Enroll face**. Verify the same account when prompted and follow the live preview to capture seven pose samples.
3. Choose **Test recognition**. Manual activation and Balanced recognition are already configured. Windows unlock uses Strict challenges for this profile.
4. Press **Win + L** and unlock once with your normal Windows password/PIN, so the new service observes a native unlock.
5. Lock again. Under **Sign-in options**, select **FacePass** and complete the requested head movements.

No Microsoft account, Microsoft sign-in, or conversion of the local account is required. A nonempty local password is required. If this account currently has no password, set one yourself in Windows Settings before saving it in FacePass.

The local password is stored encrypted and is released only for an approved face unlock; Windows performs password authentication. Administrators or a compromised service can recover the saved password. RGB face recognition remains experimental. Password/PIN sign-in remains available.

Verified on 2026-11-13: Release build; all six CTest suites (132 policy/storage/liveness checks, 25 provider checks, 10 model checks, Settings smoke checks, 56 legacy authentication checks, and 15 parsed scripts); 37 live demo IPC checks and encrypted preference persistence after restart; installed service running; provider registered; local-account preflight without blockers; installed binary hashes match the package; supervised webcam probe returned 76,800 pixels in memory without saving an image. Original sign-in providers, LSA protection settings, and Windows Authentication Packages were preserved.

Password saving, live face enrollment, recognition against that enrollment, and an actual lock-screen unlock still need your interaction. The webcam probe ran in your desktop session; service/lock-screen camera capture remains unverified until enrollment and unlock are tried.

To disable FacePass, open administrator PowerShell and run:

```powershell
& 'C:\Program Files\FacePass\installer\disable-password-unlock.ps1'
```

To uninstall and delete the saved face/password:

```powershell
& 'C:\Program Files\FacePass\installer\uninstall.ps1' -RemoveBiometrics
```
