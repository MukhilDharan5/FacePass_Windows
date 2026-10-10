#Requires -RunAsAdministrator
param([switch]$RemoveBiometrics)
$ErrorActionPreference='Stop'
$taskTarget=[IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'FacePass'))
$taskData=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'FacePass'))
$taskGuid='{A528A337-5D76-4B10-89F8-7B476F2BA491}'
$taskOptions='HKLM:\SOFTWARE\FacePass'
if (Test-Path -LiteralPath $taskOptions) { New-ItemProperty -LiteralPath $taskOptions -Name PasswordBackedUnlock -PropertyType DWord -Value 0 -Force | Out-Null }
if (Test-Path -LiteralPath (Join-Path $taskTarget '.facepass-auth')) {
  & (Join-Path $PSScriptRoot 'disable-passwordless.ps1')
  if (Test-Path -LiteralPath (Join-Path $taskTarget '.facepass-auth')) { throw 'Reboot and rerun uninstall after the authentication DLL is unloaded. Backend authorization is already disabled.' }
}
# Remove exactly our two keys; never modify a system provider or a provider filter.
foreach ($taskKey in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$taskGuid","HKLM:\SOFTWARE\Classes\CLSID\$taskGuid")) { if(Test-Path -LiteralPath $taskKey) { Remove-Item -LiteralPath $taskKey -Recurse -Force } }
if (Get-Service -Name FacePassService -ErrorAction SilentlyContinue) { Stop-Service -Name FacePassService -Force; & sc.exe delete FacePassService; if ($LASTEXITCODE) { throw 'Service removal failed' } }
if (Test-Path -LiteralPath $taskTarget) {
  $taskResolved=(Resolve-Path -LiteralPath $taskTarget).Path
  if ($taskResolved -ne (Join-Path $env:ProgramFiles 'FacePass') -or -not (Test-Path -LiteralPath (Join-Path $taskResolved '.facepass-install')) -or (Get-Item -LiteralPath $taskResolved).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'Refusing an unverified installation directory.' }
  try { Remove-Item -LiteralPath $taskResolved -Recurse -Force } catch { Write-Warning 'A loaded provider DLL can remain until sign-out/reboot. Registration is already removed; rerun to delete residual files.' }
}
if ($RemoveBiometrics -and (Test-Path -LiteralPath $taskData)) {
  $taskResolved=(Resolve-Path -LiteralPath $taskData).Path
  if ($taskResolved -ne (Join-Path $env:ProgramData 'FacePass') -or (Get-Item -LiteralPath $taskResolved).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw 'Refusing an unverified data directory.' }
  Remove-Item -LiteralPath $taskResolved -Recurse -Force
}
Write-Output 'FacePass removed. Standard Windows sign-in providers were not changed.'
