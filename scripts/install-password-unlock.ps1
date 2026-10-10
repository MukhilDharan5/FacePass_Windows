#Requires -RunAsAdministrator
param([string]$PackageDirectory,[string]$ResultPath,[switch]$CaptureProviderEvents)
$ErrorActionPreference='Stop'
if (-not $PackageDirectory) { $PackageDirectory=Join-Path $PSScriptRoot '..\dist\FacePass' }
if (-not $ResultPath) { $ResultPath=Join-Path $PSScriptRoot '..\build\password-unlock-install.json' }
$taskTranscript=$false
try {
    Start-Transcript -LiteralPath ([IO.Path]::ChangeExtension($ResultPath,'.log')) -Force | Out-Null
    $taskTranscript=$true
    $taskPackage=(Resolve-Path -LiteralPath $PackageDirectory).Path
    & (Join-Path $taskPackage 'installer\install.ps1') -SourceDirectory $taskPackage
    & (Join-Path $taskPackage 'installer\enable-password-unlock.ps1') -AllowUnvalidatedHost
    @{ success=$true; message='Service installed and password-backed face-unlock tile registered. Account password and face enrollment still require user interaction.' } | ConvertTo-Json | Set-Content -LiteralPath $ResultPath -Encoding utf8
    if ($CaptureProviderEvents) {
        try { & (Join-Path $PSScriptRoot 'capture-provider-events.ps1') -DurationSeconds 300 }
        catch { Write-Warning ('Provider event capture failed: '+$_.Exception.Message) }
    }
} catch {
    @{ success=$false; message=$_.Exception.Message } | ConvertTo-Json | Set-Content -LiteralPath $ResultPath -Encoding utf8
    throw
} finally {
    if ($taskTranscript) { Stop-Transcript | Out-Null }
}
