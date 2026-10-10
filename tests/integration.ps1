param([string]$BinaryDirectory=(Join-Path $PSScriptRoot '..\build\Release'))
$ErrorActionPreference='Stop'
$taskBin=(Resolve-Path -LiteralPath $BinaryDirectory).Path
$taskPreviousDemoData=$env:FACEPASS_DEMO_DATA
$env:FACEPASS_DEMO_DATA=Join-Path $taskBin 'test-output\integration-store'
$taskServer=Start-Process -FilePath (Join-Path $taskBin 'FaceUnlockService.exe') -ArgumentList '--console' -WorkingDirectory $taskBin -WindowStyle Hidden -PassThru
try {
  Start-Sleep -Milliseconds 500
  if ($taskServer.HasExited) { throw 'Demo server startup failed.' }
  & (Join-Path $taskBin 'FacePassTests.exe') --ipc
  if ($LASTEXITCODE) { throw 'Live IPC tests failed.' }
  & (Join-Path $taskBin 'FacePassRecognition.exe') --demo --manual --profile instant
  if ($LASTEXITCODE) { throw 'Configuration write failed.' }
  Stop-Process -Id $taskServer.Id
  $taskServer=Start-Process -FilePath (Join-Path $taskBin 'FaceUnlockService.exe') -ArgumentList '--console' -WorkingDirectory $taskBin -WindowStyle Hidden -PassThru
  Start-Sleep -Milliseconds 500
  $taskState=& (Join-Path $taskBin 'FacePassRecognition.exe') --demo --status
  if ($LASTEXITCODE -or ($taskState -join ' ') -notmatch 'Mode: 1' -or ($taskState -join ' ') -notmatch 'Profile: Instant') { throw 'Instant configuration did not survive process restart.' }
  Write-Output 'PASS: demo server restart and encrypted configuration persistence'
  & (Join-Path $taskBin 'FacePassRecognition.exe') --demo --off --profile balanced
  if ($LASTEXITCODE) { throw 'Failed to restore Off.' }
} finally { if(-not $taskServer.HasExited){Stop-Process -Id $taskServer.Id}; $env:FACEPASS_DEMO_DATA=$taskPreviousDemoData }
