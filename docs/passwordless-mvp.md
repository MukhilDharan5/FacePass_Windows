# Passwordless backend: disposable-VM trial

The source/binaries include custom authentication without stored passwords. Actual Windows unlock is unvalidated. A disposable VM and human enrollment are needed to finish that milestone.

1. Snapshot a Windows x64 VM with a local account and camera passthrough. Confirm native PIN/password and recovery. Install service only from the 0.2.0 package.
2. Run C:\Program Files\FacePass\installer\enable-passwordless.ps1 -DisposableVMVerified -PreflightOnly in elevated x64 PowerShell. It validates ownership and reads the actual LSASS protection level without activation.
3. Protected LSASS requires Microsoft LSA signing. This development package is unsigned. The script refuses to disable LSA protection or Credential Guard. An unsigned trial requires an already unprotected disposable lab VM and explicit -AllowUnsignedLabPackage.
4. In that lab VM, activate with enable-passwordless.ps1 -DisposableVMVerified -AllowUnsignedLabPackage. It copies the owned DLL to System32, preserves other Authentication Packages entries, registers only FacePass and enables authorization. Its changes roll back on failure. Reboot to load the package.
5. Perform native sign-in. As the normal user save Manual mode/camera preferences and enroll. Use recent sign-in within two minutes to avoid collecting a password, or use transient password verification. Both retain only encrypted embeddings.
6. Lock with Win+L, select FacePass and follow the challenge. Automatic mode starts when LogonUI loads the provider and can request submission after authorization. Windows controls final tile selection/sign-in; FacePass does not simulate input.
7. Record all cases in vm-validation.md. A real unlock plus intact fallback/recovery is required before calling the authentication MVP working.

## Disable/remove

Run installer/disable-passwordless.ps1 elevated. Authorization stops immediately and only FacePassAuth is removed from LSA registration. Reboot unloads it; rerun if file deletion was deferred, then uninstall. The uninstaller retains ownership information while unloading is pending. For a failed lab boot, restore the snapshot or follow recovery.md.

[Microsoft LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection), [LSA signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/file-signing-reqs).
