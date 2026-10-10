#Requires -RunAsAdministrator
param([ValidateRange(0,600)][int]$DurationSeconds=0)
$ErrorActionPreference='Stop'
$taskRoot=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$taskOutput=Join-Path $taskRoot 'build\provider-events.json'
$taskTemporary=Join-Path $taskRoot 'build\provider-events.tmp'
$taskDeadline=[DateTime]::UtcNow.AddSeconds($DurationSeconds)
# Bounded diagnostic capture: only our stage messages and Windows status codes.
# It does not inspect credential storage, account passwords, images or templates.
do {
    $taskError=$null
    $taskRecords=@()
    try {
        $taskEvents=Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='FacePass']]]" -MaxEvents 100 -ErrorAction SilentlyContinue
        $taskRecords=@($taskEvents | ForEach-Object {
            $taskEvent=$_
            foreach ($taskValue in $taskEvent.Properties.Value) {
                if ($taskValue -is [string] -and $taskValue.StartsWith('Credential Provider: ')) {
                    [pscustomobject]@{time=$taskEvent.TimeCreated.ToUniversalTime().ToString('o'); stage=$taskValue}
                }
            }
        })
    } catch { $taskError=$_.Exception.Message }
    $taskJson=@{capturedAt=[DateTime]::UtcNow.ToString('o'); error=$taskError; events=$taskRecords} | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText($taskTemporary,$taskJson,[Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $taskTemporary -Destination $taskOutput -Force
    if ([DateTime]::UtcNow -ge $taskDeadline) { break }
    Start-Sleep -Seconds 3
} while ([DateTime]::UtcNow -lt $taskDeadline)
