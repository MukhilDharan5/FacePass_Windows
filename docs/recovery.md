# Recover Windows sign-in

For password-backed face unlock, installer/disable-password-unlock.ps1 disables password release and removes only FacePass provider registration. Authentication Packages and LSA protection are untouched by that route. The shared recover.cmd disables both PasswordBackedUnlock and PasswordlessUnlock. Remove saved password or Delete profile erases the encrypted credential; uninstall -RemoveBiometrics removes all encrypted data.

FacePass never replaces Microsoft's providers. Select **Sign-in options → PIN/password** if recognition fails, the camera is unavailable, or the service stops. Custom authentication is experimental: use a disposable VM snapshot as the primary recovery method.

## Signed-in administrator or Safe Mode

Open an elevated terminal and run installer/recover.cmd. It revokes the backend and runs disable-passwordless.ps1 before removing the provider. The latter preserves all other LSA Authentication Packages entries and removes only FacePassAuth. Reboot unloads its DLL; rerun if deletion was deferred. For the provider alone, these exact commands remove its registration:

```cmd
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A528A337-5D76-4B10-89F8-7B476F2BA491}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{A528A337-5D76-4B10-89F8-7B476F2BA491}" /f
sc stop FacePassService
sc config FacePassService start= disabled
```

Restart if the DLL is loaded. Then run the uninstaller. Do not delete any other provider/filter key.

## Windows Recovery Environment

Keep your BitLocker recovery key and account password available before VM/provider testing. WinRE drive letters can differ. Identify the Windows volume with `dir C:\Windows`, `dir D:\Windows`, etc.; unlock it with the appropriate recovery procedure if encrypted. In the example below, **D:** must be replaced by the actual verified Windows volume:

```cmd
reg load HKLM\FacePassOffline D:\Windows\System32\config\SOFTWARE
reg delete "HKLM\FacePassOffline\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A528A337-5D76-4B10-89F8-7B476F2BA491}" /f
reg delete "HKLM\FacePassOffline\Classes\CLSID\{A528A337-5D76-4B10-89F8-7B476F2BA491}" /f
reg unload HKLM\FacePassOffline
```

These SOFTWARE steps remove the provider and do not unload a custom authentication package. If backend loading causes a failed lab boot, restore the snapshot. Advanced offline recovery must also load the SYSTEM hive, identify the selected ControlSet from Select/Current and remove only FacePassAuth from its Lsa/Authentication Packages multi-string while preserving every other entry. Never delete or replace the entire list. Offline backend/provider recovery has not been tested on this host. No recovery step resets passwords, decrypts data or bypasses authentication.
