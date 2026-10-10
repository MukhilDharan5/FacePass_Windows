#Requires -RunAsAdministrator
param([string]$SourceDirectory,[switch]$EnableProvider,[switch]$DisposableVMVerified)
$ErrorActionPreference='Stop'
if (-not $SourceDirectory) { $SourceDirectory=Join-Path $PSScriptRoot '..' }
if (-not [Environment]::Is64BitProcess) { throw 'Use x64 PowerShell.' }
$taskSource=(Resolve-Path -LiteralPath $SourceDirectory).Path
$taskTarget=[IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'FacePass'))
$taskData=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'FacePass'))
if ($EnableProvider -and -not $DisposableVMVerified) { throw 'Provider registration requires -DisposableVMVerified inside a disposable Windows VM. See docs/vm-validation.md.' }
if ((Test-Path -LiteralPath $taskTarget) -and -not (Test-Path -LiteralPath (Join-Path $taskTarget '.facepass-install'))) { throw 'Destination exists without the FacePass ownership marker.' }
foreach ($taskPath in @($taskTarget,$taskData)) { if ((Test-Path -LiteralPath $taskPath) -and (Get-Item -LiteralPath $taskPath -Force).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { throw "Refusing a reparse-point destination: $taskPath" } }
foreach ($taskFile in @('FaceUnlockService.exe','FaceUnlockSettings.exe','FacePassRecognition.exe','FacePassCapture.exe','FaceUnlockProvider.dll','FacePassAuth.dll','opencv_world4120.dll')) { if (-not (Test-Path -LiteralPath (Join-Path $taskSource $taskFile))) { throw "Missing package file: $taskFile" } }
function Invoke-SC([string[]]$Arguments) { & sc.exe @Arguments; if ($LASTEXITCODE) { throw "sc.exe failed: $Arguments" } }
$taskExisting=Get-Service -Name FacePassService -ErrorAction SilentlyContinue
if ($taskExisting) {
  $taskServiceConfig=Get-CimInstance Win32_Service -Filter "Name='FacePassService'"
  if ($taskServiceConfig.PathName.Trim('"') -ne (Join-Path $taskTarget 'FaceUnlockService.exe')) { throw 'An unrelated service already uses the FacePass service name.' }
  Stop-Service -Name FacePassService -Force
}
New-Item -ItemType Directory -Path $taskTarget,$taskData -Force | Out-Null
Copy-Item -Path (Join-Path $taskSource '*.exe'),(Join-Path $taskSource '*.dll') -Destination $taskTarget -Force
foreach ($taskFolder in @('models','docs','installer')) { Copy-Item -LiteralPath (Join-Path $taskSource $taskFolder) -Destination $taskTarget -Recurse -Force }
Copy-Item -LiteralPath (Join-Path $taskSource 'README.md') -Destination $taskTarget -Force
Set-Content -LiteralPath (Join-Path $taskTarget '.facepass-install') -Value 'FacePass 0.3.0'
& icacls.exe $taskTarget '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'
if ($LASTEXITCODE) { throw 'Binary directory ACL failed' }
if (-not $taskExisting) { Invoke-SC @('create','FacePassService','binPath=',('"'+(Join-Path $taskTarget 'FaceUnlockService.exe')+'"'),'start=','auto','obj=','NT AUTHORITY\LocalService','DisplayName=','FacePass face recognition') }
Invoke-SC @('sidtype','FacePassService','unrestricted')
Invoke-SC @('privs','FacePassService','SeChangeNotifyPrivilege/SeImpersonatePrivilege')
Invoke-SC @('failure','FacePassService','reset=','86400','actions=','restart/5000/restart/15000/none/0')
Invoke-SC @('description','FacePassService','Offline RGB recognition. Face unlock uses a separately enabled credential provider and saved encrypted account password.')
& icacls.exe $taskData '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 'NT SERVICE\FacePassService:(OI)(CI)F'
if ($LASTEXITCODE) { throw 'Biometric directory ACL failed' }
Start-Service -Name FacePassService
try {
  if ($EnableProvider) {
    $taskRegister=Start-Process -FilePath (Join-Path $env:windir 'System32\regsvr32.exe') -ArgumentList @('/s',('"'+(Join-Path $taskTarget 'FaceUnlockProvider.dll')+'"')) -WindowStyle Hidden -Wait -PassThru
    if ($taskRegister.ExitCode) { throw "Provider registration failed: $($taskRegister.ExitCode)" }
  }
} catch { Write-Warning 'Service is installed; the provider was not registered successfully. Run uninstall.ps1 to roll back.'; throw }
Write-Output 'FacePass installed. Launch FaceUnlockSettings.exe as your normal user. Face unlock requires separate provider activation, encrypted password setup, and face enrollment.'
