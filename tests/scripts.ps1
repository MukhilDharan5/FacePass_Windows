param([string]$ProjectRoot=(Join-Path $PSScriptRoot '..'))
$ErrorActionPreference='Stop'
$taskRoot=(Resolve-Path -LiteralPath $ProjectRoot).Path
$taskCount=0
foreach($taskFolder in @('scripts','installer','tests')) {
  foreach($taskFile in Get-ChildItem -LiteralPath (Join-Path $taskRoot $taskFolder) -Filter '*.ps1' -File) {
    $taskTokens=$null; $taskErrors=$null
    [System.Management.Automation.Language.Parser]::ParseFile($taskFile.FullName,[ref]$taskTokens,[ref]$taskErrors) | Out-Null
    if($taskErrors.Count) { throw ($taskErrors | ForEach-Object Message | Out-String) }
    ++$taskCount
  }
}
Write-Output "PASS: $taskCount PowerShell scripts parse (installers were not executed)"
