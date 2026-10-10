#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param()
$ErrorActionPreference='Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use x64 PowerShell.' }
if (-not $PSCmdlet.ShouldProcess('FacePass password-backed unlock','Disable password release and unregister the FacePass tile')) { return }
$taskOptions='HKLM:\SOFTWARE\FacePass'
if (Test-Path -LiteralPath $taskOptions) { New-ItemProperty -LiteralPath $taskOptions -Name PasswordBackedUnlock -PropertyType DWord -Value 0 -Force | Out-Null }
# Remove only this provider's registrations, preserving all Windows providers.
$taskGuid='{A528A337-5D76-4B10-89F8-7B476F2BA491}'
foreach ($taskKey in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$taskGuid","HKLM:\SOFTWARE\Classes\CLSID\$taskGuid")) {
    if (Test-Path -LiteralPath $taskKey) { Remove-Item -LiteralPath $taskKey -Recurse -Force }
}
Write-Output 'FacePass password-backed unlock disabled. Remove the saved password in Settings or uninstall with -RemoveBiometrics to erase all stored data.'
