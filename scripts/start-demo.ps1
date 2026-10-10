param([string]$BinaryDirectory)
$ErrorActionPreference='Stop'
if (-not $BinaryDirectory) {
  if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'FaceUnlockService.exe')) { $BinaryDirectory=$PSScriptRoot }
  else { $BinaryDirectory=Join-Path $PSScriptRoot '..\build\Release' }
}
$taskBin=(Resolve-Path -LiteralPath $BinaryDirectory).Path
$taskServer=Join-Path $taskBin 'FaceUnlockService.exe'
if (-not (Test-Path -LiteralPath $taskServer)) { throw 'Build Release first.' }
$taskProcess=Start-Process -FilePath $taskServer -ArgumentList '--console' -WorkingDirectory $taskBin -WindowStyle Hidden -PassThru
try {
  Start-Sleep -Milliseconds 600
  if ($taskProcess.HasExited) { throw 'Demo server failed to start (another demo server may already be running).' }
  $taskSettings=Start-Process -FilePath (Join-Path $taskBin 'FaceUnlockSettings.exe') -ArgumentList '--demo' -WorkingDirectory $taskBin -Wait -PassThru
} finally {
  # Terminate only the demo process launched by this script. Encrypted data persists.
  if (-not $taskProcess.HasExited) { Stop-Process -Id $taskProcess.Id }
}
