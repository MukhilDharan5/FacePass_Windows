#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([switch]$AllowUnvalidatedHost,[switch]$PreflightOnly)
$ErrorActionPreference='Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use x64 PowerShell.' }
if (-not $AllowUnvalidatedHost) { throw 'This experimental face-unlock provider requires explicit -AllowUnvalidatedHost for direct laptop testing.' }
$taskInstall=[IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'FacePass'))
$taskProvider=Join-Path $taskInstall 'FaceUnlockProvider.dll'
if (-not (Test-Path -LiteralPath (Join-Path $taskInstall '.facepass-install')) -or -not (Test-Path -LiteralPath $taskProvider)) { throw 'Install the packaged FacePass service first.' }
if ((Get-Item -LiteralPath $taskInstall).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'Refusing a redirected installation directory.' }
$taskService=Get-CimInstance Win32_Service -Filter "Name='FacePassService'"
if (-not $taskService -or $taskService.PathName.Trim('"') -ne (Join-Path $taskInstall 'FaceUnlockService.exe')) { throw 'The service does not match this FacePass installation.' }
$taskOptions='HKLM:\SOFTWARE\FacePass'
if ((Get-ItemProperty -LiteralPath $taskOptions -Name PasswordlessUnlock -ErrorAction SilentlyContinue).PasswordlessUnlock -eq 1) { throw 'Disable the custom authentication backend before switching to password-backed unlock.' }
$taskLsaKey='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$taskPackages=@((Get-ItemProperty -LiteralPath $taskLsaKey -Name 'Authentication Packages').'Authentication Packages')
Write-Output 'Preflight passed: installs only a Credential Provider. Windows authentication packages and LSA protection remain unchanged.'
if ($PreflightOnly -or -not $PSCmdlet.ShouldProcess('FacePass on this laptop','Enable face unlock using a saved encrypted Microsoft-account password')) { return }
$taskProviderKey='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A528A337-5D76-4B10-89F8-7B476F2BA491}'
$taskExisted=Test-Path -LiteralPath $taskProviderKey
$taskPrevious=(Get-ItemProperty -LiteralPath $taskOptions -Name PasswordBackedUnlock -ErrorAction SilentlyContinue).PasswordBackedUnlock
try {
    $taskRegistration=Start-Process -FilePath (Join-Path $env:windir 'System32\regsvr32.exe') -ArgumentList @('/s',('"'+$taskProvider+'"')) -WindowStyle Hidden -Wait -PassThru
    if ($taskRegistration.ExitCode) { throw 'Credential Provider registration failed.' }
    if (-not (Test-Path -LiteralPath $taskOptions)) { New-Item -Path $taskOptions | Out-Null }
    New-ItemProperty -LiteralPath $taskOptions -Name PasswordBackedUnlock -PropertyType DWord -Value 1 -Force | Out-Null
    $taskAfter=@((Get-ItemProperty -LiteralPath $taskLsaKey -Name 'Authentication Packages').'Authentication Packages')
    if (($taskPackages -join "`n") -cne ($taskAfter -join "`n")) { throw 'Windows authentication packages unexpectedly changed.' }
} catch {
    if ($null -eq $taskPrevious) { Remove-ItemProperty -LiteralPath $taskOptions -Name PasswordBackedUnlock -ErrorAction SilentlyContinue }
    else { Set-ItemProperty -LiteralPath $taskOptions -Name PasswordBackedUnlock -Value $taskPrevious }
    if (-not $taskExisted) { & (Join-Path $env:windir 'System32\regsvr32.exe') /u /s $taskProvider }
    throw
}
Write-Output 'Face unlock enabled. Open installed Settings, save your Microsoft-account password, enroll your face, and use native PIN/password once after service startup before testing the FacePass tile.'
