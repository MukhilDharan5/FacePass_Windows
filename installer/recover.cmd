@echo off
rem Run as administrator in Safe Mode, or follow docs/recovery.md for WinRE offline registry.
reg.exe add "HKLM\SOFTWARE\FacePass" /v PasswordlessUnlock /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\FacePass" /v PasswordBackedUnlock /t REG_DWORD /d 0 /f
if exist "%~dp0disable-passwordless.ps1" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0disable-passwordless.ps1"
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A528A337-5D76-4B10-89F8-7B476F2BA491}" /f
reg.exe delete "HKLM\SOFTWARE\Classes\CLSID\{A528A337-5D76-4B10-89F8-7B476F2BA491}" /f
sc.exe stop FacePassService
sc.exe config FacePassService start= disabled
