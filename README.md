
# STIG-WN11-CC-000315-# WN11-CC-000315

The Windows Installer feature 'Always install with elevated privileges' must be disabled.

```powershell
<#
.SYNOPSIS
    This PowerShell script ensures that the Windows Installer feature 'Always install with elevated privileges' is disabled (AlwaysInstallElevated = 0).

.NOTES
    Author          : Sean Keener
    LinkedIn        : https://www.linkedin.com/in/sean-k-308049210/
    GitHub          : github.com/seankeener
    Date Created    : 2026-11-15
    Last Modified   : 2026-11-15
    Version         : 1.2
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-CC-000315/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run from an elevated PowerShell prompt. The script applies the fix automatically and the window stays open when it finishes.
    Example syntax:
    PS C:\> .\WN11-CC-000315.ps1
    Result codes: 0 = compliant, 2 = error (stored in $LASTEXITCODE)
#>

[CmdletBinding()]
param()

$StigId   = 'WN11-CC-000315'
$RegPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
$RegName  = 'AlwaysInstallElevated'
$Required = 0

function Get-CurrentValue {
    (Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue).$RegName
}

function Invoke-StigFix {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[$StigId] ERROR - This script must be run as Administrator." -ForegroundColor Red
        return 2
    }

    try {
        $current = Get-CurrentValue

        if ($null -ne $current -and $current -eq $Required) {
            Write-Host "[$StigId] ALREADY COMPLIANT - $RegName is $current (required: $Required)" -ForegroundColor Green
            return 0
        }

        $shown = if ($null -eq $current) { 'not set' } else { $current }
        Write-Host "[$StigId] NON-COMPLIANT - $RegName is $shown (required: $Required). Applying fix..." -ForegroundColor Yellow

        if (-not (Test-Path -Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        New-ItemProperty -Path $RegPath -Name $RegName -Value $Required -PropertyType DWord -Force | Out-Null

        $after = Get-CurrentValue
        if ($null -ne $after -and $after -eq $Required) {
            Write-Host "[$StigId] REMEDIATED - $RegName set to $after" -ForegroundColor Green
            return 0
        }

        Write-Host "[$StigId] ERROR - Value did not persist after applying the fix." -ForegroundColor Red
        return 2
    }
    catch {
        Write-Host "[$StigId] ERROR - $($_.Exception.Message)" -ForegroundColor Red
        return 2
    }
}

$result = 2
try {
    $result = Invoke-StigFix
}
finally {
    $global:LASTEXITCODE = $result
    Write-Host ""
    Read-Host "Press Enter to close this window" | Out-Null
}
```
