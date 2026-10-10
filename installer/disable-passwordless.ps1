#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param()
$ErrorActionPreference='Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use x64 PowerShell.' }
if (-not $PSCmdlet.ShouldProcess('FacePass custom backend','Revoke authorization and remove only FacePassAuth from LSA registration')) { return }
$taskOptions='HKLM:\SOFTWARE\FacePass'
if (Test-Path -LiteralPath $taskOptions) { New-ItemProperty -LiteralPath $taskOptions -Name PasswordlessUnlock -PropertyType DWord -Value 0 -Force | Out-Null }
$taskKey='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$taskPackages=@((Get-ItemProperty -LiteralPath $taskKey -Name 'Authentication Packages').'Authentication Packages')
if($taskPackages -contains 'FacePassAuth') { Set-ItemProperty -LiteralPath $taskKey -Name 'Authentication Packages' -Value ([string[]]@($taskPackages | Where-Object { $_ -ne 'FacePassAuth' })) }
$taskInstall=[IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'FacePass'))
$taskMarker=Join-Path $taskInstall '.facepass-auth'
$taskDll=[IO.Path]::GetFullPath((Join-Path $env:windir 'System32\FacePassAuth.dll'))
if ((Test-Path -LiteralPath $taskDll) -and (Test-Path -LiteralPath $taskMarker)) {
  $taskResolved=(Resolve-Path -LiteralPath $taskDll).Path
  if($taskResolved -ne $taskDll -or (Get-Item -LiteralPath $taskDll).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or (Get-FileHash -LiteralPath $taskDll -Algorithm SHA256).Hash -ne (Get-Content -LiteralPath $taskMarker -Raw).Trim()) { throw 'Backend is revoked, but DLL ownership validation failed; no file was removed.' }
  try { Remove-Item -LiteralPath $taskDll -Force; Remove-Item -LiteralPath $taskMarker -Force }
  catch { Write-Warning 'Backend registration is removed. Reboot and rerun this script to remove the loaded DLL before uninstalling the app.' }
}
Write-Output 'FacePass passwordless authorization is disabled. Reboot to unload the authentication package. Native Windows providers remain available.'
