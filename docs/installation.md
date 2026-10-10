# Installation

For direct Microsoft-account laptop testing, build 0.3.0 and run scripts/install-password-unlock.ps1 elevated. It installs the service and enables the password-backed Credential Provider with the user's explicit unvalidated-host choice. Follow [password-backed unlock](password-backed-unlock.md) for password setup, enrollment, native sign-in proof and the real lock-screen test. Special Microsoft LSA signing is not required for this route because FacePassAuth is not loaded.

Build with scripts/build.ps1 -Package. From elevated x64 PowerShell in the 0.2.0 package run installer/install.ps1. It installs LocalService, owned Program Files binaries and protected ProgramData storage; authentication stays inactive. Launch settings as the normal user and enroll separately from demo data.

-EnableProvider -DisposableVMVerified optionally registers a diagnostic tile. Native providers/filters are unchanged. Custom credential submission requires separate enable-passwordless.ps1 activation, suitable signing and reboot; see [backend guide](passwordless-mvp.md).

Activation validates ownership, probes actual LSASS protection, preserves other Authentication Packages and rolls back its registration on failure. It never disables LSA protection or Credential Guard. The general service installer is an MVP script; full MSI-style transactions and production signing are outstanding.

Disable/reboot before uninstalling a loaded package. Run installer/uninstall.ps1 elevated; -RemoveBiometrics optionally deletes encrypted data. Owned paths are validated and the app/marker is retained if the authentication DLL still needs unloading. See [recovery](recovery.md).
