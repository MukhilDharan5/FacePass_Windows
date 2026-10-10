param([ValidateSet('Release','Debug')][string]$Configuration='Release',[switch]$Package)
$ErrorActionPreference='Stop'
$taskRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$taskVswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$taskVs = & $taskVswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $taskVs) { throw 'Install Visual Studio 2022+ Desktop development with C++ and Windows SDK first (see README).' }
$taskCmake = Join-Path $taskVs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
if (-not (Test-Path -LiteralPath $taskCmake)) { $taskCmake=(Get-Command cmake -ErrorAction Stop).Source }
$taskOpenCV = Join-Path $taskRoot 'tools\opencv\build\x64\vc16\lib'
if (-not (Test-Path -LiteralPath $taskOpenCV)) { throw 'Run scripts/setup.ps1 to download OpenCV and the models.' }
$taskBuild=Join-Path $taskRoot 'build'
& $taskCmake -S $taskRoot -B $taskBuild -A x64 "-DOpenCV_DIR=$taskOpenCV"
if ($LASTEXITCODE) { throw 'CMake configure failed' }
& $taskCmake --build $taskBuild --config $Configuration --parallel 4
if ($LASTEXITCODE) { throw 'Build failed' }
$taskCtest=Join-Path (Split-Path $taskCmake) 'ctest.exe'
& $taskCtest --test-dir $taskBuild -C $Configuration --output-on-failure
if ($LASTEXITCODE) { throw 'Tests failed' }
& (Join-Path $taskRoot 'tests\integration.ps1') -BinaryDirectory (Join-Path $taskBuild $Configuration)
if (-not $?) { throw 'IPC integration tests failed' }
if ($Package) {
  $taskDist=Join-Path $taskRoot 'dist\FacePass'
  & $taskCmake --install $taskBuild --config $Configuration --prefix $taskDist
  if ($LASTEXITCODE) { throw 'Packaging failed' }
  Copy-Item -LiteralPath (Join-Path $taskRoot 'installer') -Destination $taskDist -Recurse -Force
  Copy-Item -LiteralPath (Join-Path $taskRoot 'scripts\start-demo.ps1') -Destination $taskDist -Force
  $taskManifest=Get-ChildItem -LiteralPath $taskDist -File -Recurse | Where-Object Name -ne 'manifest.json' | ForEach-Object { @{ path=$_.FullName.Substring($taskDist.Length+1).Replace('\','/'); sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash; bytes=$_.Length } }
  @{version='0.3.0'; authenticationStatus='Experimental password-backed face unlock; actual Windows unlock not yet demonstrated'; files=@($taskManifest)} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $taskDist 'manifest.json') -Encoding utf8
  $taskZip=Join-Path $taskRoot 'dist\FacePass-0.3.0-win-x64.zip'
  Compress-Archive -LiteralPath $taskDist -DestinationPath $taskZip -Force
  Write-Output "Package: $taskZip"
  $taskSourceZip=Join-Path $taskRoot 'dist\FacePass-0.3.0-source.zip'
  $taskSourceItems=@('CMakeLists.txt','README.md','.gitignore','src','include','resources','scripts','installer','tests','docs','models') | ForEach-Object { Join-Path $taskRoot $_ }
  Compress-Archive -LiteralPath $taskSourceItems -DestinationPath $taskSourceZip -Force
  Write-Output "Source: $taskSourceZip"
}
