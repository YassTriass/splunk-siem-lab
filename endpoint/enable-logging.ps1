#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Turns on the extra Windows logging used in this lab (Windows 10 Home VM).

.DESCRIPTION
    Windows 10 Home has no working Local Group Policy, so the settings that
    would normally be set in gpedit.msc are written directly:

      - audit policy subcategories      -> auditpol
      - Administrative Template options -> registry values

    Run in PowerShell as Administrator. Safe to run more than once.

    What it enables:
      4688        Process creation, with the full command line (Security log)
      4698/4699   Scheduled task created / deleted (Security log)
      4104        PowerShell Script Block Logging
                  (Microsoft-Windows-PowerShell/Operational log)

.NOTES
    The subcategory names below are the English ones. On a non-English Windows,
    list the local names with:  auditpol /list /subcategory:*
#>

# Creates the registry key if it is missing, then writes a DWORD (32-bit number) value.
# -Force on New-Item is only used when the key does not exist yet:
# on an existing key it would wipe the values already inside it.
function Set-RegistryDword {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

# --- 1. Audit policy -------------------------------------------------------

# Event 4688: one event for every new process.
auditpol /set /subcategory:"Process Creation" /success:enable

# Events 4698 / 4699: scheduled tasks (used in detection practice 1.5).
auditpol /set /subcategory:"Other Object Access Events" /success:enable

# --- 2. Include the command line in 4688 -----------------------------------

# Without this value, 4688 only records the program name (powershell.exe),
# not what it was asked to do (powershell.exe -enc ...).
$auditKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
Set-RegistryDword -Path $auditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

# --- 3. PowerShell Script Block Logging (4104) ------------------------------

# Records the code PowerShell really executes, after Base64 and other
# obfuscation have been undone. Applies to PowerShell sessions opened after this.
$sblKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
Set-RegistryDword -Path $sblKey -Name "EnableScriptBlockLogging" -Value 1

# --- 4. Verify --------------------------------------------------------------

# "Configured" is not the same as "active": read the settings back.
Write-Host "`n== Audit policy (expected: Success) ==" -ForegroundColor Cyan
auditpol /get /subcategory:"Process Creation"
auditpol /get /subcategory:"Other Object Access Events"

Write-Host "`n== Registry values (expected: 1) ==" -ForegroundColor Cyan
Get-ItemProperty -Path $auditKey -Name "ProcessCreationIncludeCmdLine_Enabled" |
    Select-Object ProcessCreationIncludeCmdLine_Enabled
Get-ItemProperty -Path $sblKey -Name "EnableScriptBlockLogging" |
    Select-Object EnableScriptBlockLogging

Write-Host "`nOpen a NEW PowerShell window before testing 4104." -ForegroundColor Yellow
