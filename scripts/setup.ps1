$ErrorActionPreference='Stop'
$taskRoot=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
function Get-VerifiedFile([string]$Url,[string]$Path,[string]$Hash) {
  if (-not (Test-Path -LiteralPath $Path) -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Hash) {
    & curl.exe -fL --retry 2 --connect-timeout 20 --max-time 900 $Url -o $Path
    if ($LASTEXITCODE) { throw "Download failed: $Url" }
  }
  if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Hash) { throw "SHA256 mismatch: $Path" }
}
New-Item -ItemType Directory -Path (Join-Path $taskRoot 'tools'),(Join-Path $taskRoot 'models') -Force | Out-Null
$taskOpenCV=Join-Path $taskRoot 'tools\opencv-4.12.0-windows.exe'
Get-VerifiedFile 'https://github.com/opencv/opencv/releases/download/4.12.0/opencv-4.12.0-windows.exe' $taskOpenCV 'B753B14D880B9BC8D89D6ACD3B665C040BAEC0211078435432FCAE117DB707AF'
if (-not (Test-Path -LiteralPath (Join-Path $taskRoot 'tools\opencv\build\x64\vc16\lib\OpenCVConfig.cmake'))) {
  $task7zip=Join-Path $env:ProgramFiles '7-Zip\7z.exe'
  if (Test-Path -LiteralPath $task7zip) { & $task7zip x $taskOpenCV "-o$(Join-Path $taskRoot 'tools')" -y -bso0; if ($LASTEXITCODE) { throw 'OpenCV extraction failed' } }
  else { $taskProcess=Start-Process -FilePath $taskOpenCV -ArgumentList @('-y',"-o$(Join-Path $taskRoot 'tools')") -WindowStyle Hidden -Wait -PassThru; if ($taskProcess.ExitCode) { throw 'OpenCV extraction failed; install 7-Zip' } }
}
Get-VerifiedFile 'https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx' (Join-Path $taskRoot 'models\face_detection_yunet_2023mar.onnx') '8F2383E4DD3CFBB4553EA8718107FC0423210DC964F9F4280604804ED2552FA4'
Get-VerifiedFile 'https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx' (Join-Path $taskRoot 'models\face_recognition_sface_2021dec.onnx') '0BA9FBFA01B5270C96627C4EF784DA859931E02F04419C829E83484087C34E79'
Write-Output 'OpenCV and both offline models are ready. Run scripts/build.ps1.'
