[CmdletBinding()]
param([string]$PackageDirectory,[ValidateSet('PasswordBacked','CustomPasswordless')][string]$Backend='PasswordBacked')

# Read-only deployment checks. Does not install, register, or change protection.
$ErrorActionPreference = 'Stop'
if (-not $PackageDirectory) { $PackageDirectory=Join-Path $PSScriptRoot '..\dist\FacePass' }
if (-not [Environment]::Is64BitProcess) { throw 'Run this check in x64 PowerShell.' }
$taskPackage = (Resolve-Path -LiteralPath $PackageDirectory).Path
$taskAuthPath = Join-Path $taskPackage $(if($Backend -eq 'PasswordBacked'){'FaceUnlockProvider.dll'}else{'FacePassAuth.dll'})
$taskSignature = Get-AuthenticodeSignature -LiteralPath $taskAuthPath
$taskIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$taskPrincipal = [Security.Principal.WindowsPrincipal]::new($taskIdentity)
$taskAccountSource = 'Unknown'
$taskAccountCheckError = $null
try {
    $taskUser = Get-LocalUser -SID $taskIdentity.User
    $taskAccountSource = [string]$taskUser.PrincipalSource
} catch { $taskAccountCheckError = $_.Exception.Message }

$taskWindows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$taskProtection = $null
$taskProtectionError = $null
try {
    if (-not ('FacePassLaptopProtectionProbe' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FacePassLaptopProtectionProbe {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetProcessInformation(IntPtr process, int kind, out uint level, uint size);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    public static uint Query(uint pid) {
        IntPtr process = OpenProcess(0x1000, false, pid);
        if (process == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        try {
            uint level;
            if (!GetProcessInformation(process, 7, out level, 4))
                throw new System.ComponentModel.Win32Exception();
            return level;
        } finally { CloseHandle(process); }
    }
}
'@
    }
    $taskProtection = [FacePassLaptopProtectionProbe]::Query([uint32](Get-Process -Name lsass).Id)
} catch { $taskProtectionError = $_.Exception.Message }

$taskProtectionEvidence=$null
if ($null -eq $taskProtection) {
    $taskEvent=Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Wininit';Id=12} -MaxEvents 1 -ErrorAction SilentlyContinue
    if($taskEvent){$taskProtectionEvidence=$taskEvent.Message}
}
$taskBlockers = [Collections.Generic.List[string]]::new()
if($Backend -eq 'CustomPasswordless') {
    if ($null -eq $taskProtection) {$taskBlockers.Add('Cannot query the running authentication process protection level. See the Wininit evidence field.')}
    elseif ($taskProtection -ne [uint32]4294967294 -and $taskSignature.Status -ne 'Valid') {$taskBlockers.Add('Protected Windows authentication cannot load the unsigned custom LSA package.')}
}
if ($taskAccountSource -eq 'Unknown' -or [string]::IsNullOrWhiteSpace($taskAccountSource)) {
    $taskBlockers.Add('Cannot confirm that the current account is a supported local account.')
} elseif ($Backend -eq 'CustomPasswordless' -and $taskAccountSource -ne 'Local') {
    $taskBlockers.Add('The custom LSA route has no validated Microsoft-account support.')
} elseif ($Backend -eq 'PasswordBacked' -and $taskAccountSource -ne 'MicrosoftAccount') {
    $taskBlockers.Add('The password-backed route currently targets a Microsoft-connected account.')
}
$taskService = Get-Service -Name FacePassService -ErrorAction SilentlyContinue
$taskProviderKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A528A337-5D76-4B10-89F8-7B476F2BA491}'
[pscustomobject]@{
    WindowsBuild = $taskWindows.CurrentBuild
    WindowsVersion = $taskWindows.DisplayVersion
    AccountSource = $taskAccountSource
    AccountCheckError = $taskAccountCheckError
    RunningElevated = $taskPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    PackageSignature = [string]$taskSignature.Status
    Backend = $Backend
    RequiresMicrosoftLsaSigning = $Backend -eq 'CustomPasswordless'
    LsassProtectionLevel = $taskProtection
    ProtectionCheckError = $taskProtectionError
    LsassProtectionEvidence = $taskProtectionEvidence
    ActualWindowsUnlockValidated = $false
    ServiceInstalled = $null -ne $taskService
    ProviderRegistered = Test-Path -LiteralPath $taskProviderKey
    DeploymentBlockers = @($taskBlockers.ToArray())
} | ConvertTo-Json -Depth 3
