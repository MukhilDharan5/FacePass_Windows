#Requires -RunAsAdministrator
param([string]$PackageDirectory=(Join-Path $PSScriptRoot '..\dist\FacePass'))
$ErrorActionPreference='Stop'
if (Get-Service -Name FacePassService -ErrorAction SilentlyContinue) { throw 'Refusing to replace an existing service during the smoke test.' }
$taskPackage=(Resolve-Path -LiteralPath $PackageDirectory).Path
$taskInstall=Join-Path $taskPackage 'installer\install.ps1'
$taskUninstall=Join-Path $taskPackage 'installer\uninstall.ps1'
$taskProvider='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A528A337-5D76-4B10-89F8-7B476F2BA491}'
$taskBefore=Test-Path -LiteralPath $taskProvider
if ($taskBefore -or (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'FacePass')) -or (Test-Path -LiteralPath (Join-Path $env:ProgramData 'FacePass'))) { throw 'Refusing to modify an existing provider, installation or data directory in this smoke test.' }
$taskLog=Join-Path $PSScriptRoot '..\test-output\service-smoke.log'
New-Item -ItemType Directory -Path (Split-Path $taskLog) -Force | Out-Null
Start-Transcript -Path $taskLog -Force
try {
  & $taskInstall -SourceDirectory $taskPackage
  $taskService=Get-Service FacePassService
  if($taskService.Status -ne 'Running') { throw 'SCM service did not start.' }
  $taskConfiguration=Get-CimInstance Win32_Service -Filter "Name='FacePassService'"
  if($taskConfiguration.StartName -ne 'NT AUTHORITY\LocalService') { throw 'Service identity is wrong.' }
  $taskCli=Join-Path $env:ProgramFiles 'FacePass\FacePassRecognition.exe'
  & $taskCli --status
  if($LASTEXITCODE) { throw 'Production SCM-verified pipe failed.' }
  & $taskCli --manual
  if($LASTEXITCODE) { throw 'LocalService encrypted configuration write failed.' }
  Restart-Service FacePassService
  $taskAfterRestart=& $taskCli --status
  if($LASTEXITCODE -or ($taskAfterRestart -join ' ') -notmatch 'Mode: 1') { throw 'Production pipe/configuration did not recover after SCM restart.' }
  & $taskCli --off
  if($LASTEXITCODE) { throw 'Production Off mode failed.' }
  if((Test-Path -LiteralPath $taskProvider) -ne $taskBefore) { throw 'Unexpected provider registration change.' }
  Write-Output 'PASS: LocalService installation, SCM lifecycle, verified production IPC, restart and unchanged provider registration'
} finally { & $taskUninstall -RemoveBiometrics }
if (Get-Service -Name FacePassService -ErrorAction SilentlyContinue) { throw 'Service was not removed.' }
Write-Output 'PASS: service-only uninstallation'
Stop-Transcript
