#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([switch]$DisposableVMVerified,[switch]$AllowUnsignedLabPackage,[switch]$PreflightOnly)
$ErrorActionPreference='Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use x64 PowerShell.' }
if (-not $DisposableVMVerified) { throw 'Custom authentication activation requires a disposable VM snapshot and -DisposableVMVerified. See docs/passwordless-mvp.md.' }
$taskInstall=[IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'FacePass'))
$taskAuth=Join-Path $taskInstall 'FacePassAuth.dll'
$taskDll=Join-Path $env:windir 'System32\FacePassAuth.dll'
$taskMarker=Join-Path $taskInstall '.facepass-auth'
$taskKey='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$taskOptions='HKLM:\SOFTWARE\FacePass'
if (-not (Test-Path -LiteralPath (Join-Path $taskInstall '.facepass-install')) -or -not (Test-Path -LiteralPath $taskAuth)) { throw 'Install the packaged FacePass service first.' }
if ((Get-Item -LiteralPath $taskInstall).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'Refusing a redirected installation directory.' }
$taskService=Get-CimInstance Win32_Service -Filter "Name='FacePassService'"
if (-not $taskService -or $taskService.PathName.Trim('"') -ne (Join-Path $taskInstall 'FaceUnlockService.exe')) { throw 'FacePass service configuration does not match this installation.' }
if (-not ('FacePassProtectionProbe' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FacePassProtectionProbe {
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessInformation(IntPtr process, int kind, out uint level, uint size);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  public static uint Query(uint pid) {
    IntPtr p=OpenProcess(0x1000,false,pid); if(p==IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
    try { uint level; if(!GetProcessInformation(p,7,out level,4)) throw new System.ComponentModel.Win32Exception(); return level; }
    finally { CloseHandle(p); }
  }
}
'@
}
$taskProtection=[FacePassProtectionProbe]::Query([uint32](Get-Process -Name lsass).Id)
$taskSignature=Get-AuthenticodeSignature -LiteralPath $taskAuth
$taskMicrosoftSigned=$taskSignature.Status -eq 'Valid' -and $taskSignature.SignerCertificate.Subject -match 'CN=Microsoft (Windows|Corporation)'
if ($taskProtection -ne [uint32]4294967294 -and -not $taskMicrosoftSigned) { throw 'LSASS is protected. This package needs Microsoft LSA signing. FacePass will not disable LSA protection or Credential Guard.' }
if (-not $taskMicrosoftSigned -and -not $AllowUnsignedLabPackage) { throw 'Unsigned builds require -AllowUnsignedLabPackage in an already unprotected disposable lab VM.' }
$taskHash=(Get-FileHash -LiteralPath $taskAuth -Algorithm SHA256).Hash
if (Test-Path -LiteralPath $taskDll) {
  if (-not (Test-Path -LiteralPath $taskMarker) -or (Get-Item -LiteralPath $taskDll).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or (Get-FileHash -LiteralPath $taskDll -Algorithm SHA256).Hash -ne (Get-Content -LiteralPath $taskMarker -Raw).Trim()) { throw 'Refusing to overwrite an unowned authentication DLL.' }
  if ((Get-FileHash -LiteralPath $taskDll -Algorithm SHA256).Hash -ne $taskHash) { throw 'Disable the existing backend, reboot, and reinstall before replacing a loaded authentication package.' }
}
$taskPackages=@((Get-ItemProperty -LiteralPath $taskKey -Name 'Authentication Packages').'Authentication Packages')
if ($taskPackages.Count -eq 0 -or $taskPackages -notcontains 'msv1_0') { throw 'Unexpected LSA configuration; refusing to alter it.' }
Write-Output "Preflight passed. LSASS protection level: $taskProtection. Package SHA256: $taskHash. Reboot is required after activation."
if ($PreflightOnly -or -not $PSCmdlet.ShouldProcess('FacePass in this disposable VM','Install the custom passwordless authentication package and provider')) { return }
$taskPreviousEnabled=(Get-ItemProperty -LiteralPath $taskOptions -Name PasswordlessUnlock -ErrorAction SilentlyContinue).PasswordlessUnlock
$taskCreatedDll=-not (Test-Path -LiteralPath $taskDll)
$taskProviderKey='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A528A337-5D76-4B10-89F8-7B476F2BA491}'
$taskProviderExisted=Test-Path -LiteralPath $taskProviderKey
try {
  if($taskCreatedDll) { Copy-Item -LiteralPath $taskAuth -Destination $taskDll; Set-Content -LiteralPath $taskMarker -Value $taskHash }
  $taskUpdated=@($taskPackages | Where-Object { $_ -ne 'FacePassAuth' }) + 'FacePassAuth'
  Set-ItemProperty -LiteralPath $taskKey -Name 'Authentication Packages' -Value ([string[]]$taskUpdated)
  $taskRegistration=Start-Process -FilePath (Join-Path $env:windir 'System32\regsvr32.exe') -ArgumentList @('/s',('"'+(Join-Path $taskInstall 'FaceUnlockProvider.dll')+'"')) -WindowStyle Hidden -Wait -PassThru
  if($taskRegistration.ExitCode) { throw 'Credential provider registration failed.' }
  New-Item -Path $taskOptions -Force | Out-Null
  New-ItemProperty -LiteralPath $taskOptions -Name PasswordlessUnlock -PropertyType DWord -Value 1 -Force | Out-Null
} catch {
  Set-ItemProperty -LiteralPath $taskKey -Name 'Authentication Packages' -Value ([string[]]$taskPackages)
  if($null -eq $taskPreviousEnabled) { Remove-ItemProperty -LiteralPath $taskOptions -Name PasswordlessUnlock -ErrorAction SilentlyContinue }
  else { Set-ItemProperty -LiteralPath $taskOptions -Name PasswordlessUnlock -Value $taskPreviousEnabled }
  if(-not $taskProviderExisted) { & (Join-Path $env:windir 'System32\regsvr32.exe') /u /s (Join-Path $taskInstall 'FaceUnlockProvider.dll') }
  if($taskCreatedDll) { Remove-Item -LiteralPath $taskDll -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $taskMarker -Force -ErrorAction SilentlyContinue }
  throw
}
Write-Output 'Experimental passwordless backend registered. Reboot, perform native sign-in, enroll, and follow the VM validation checklist. No password is stored.'
