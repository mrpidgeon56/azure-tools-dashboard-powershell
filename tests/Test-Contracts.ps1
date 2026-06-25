#Requires -Version 7.0
<#
.SYNOPSIS
    Fast, dependency-free contract checks for the hub (no Azure, no server needed).
    Guards the conventions that this session's bugs violated: scanner scope params + envelope,
    the standardized page helpers, and "every POST fetch sends a body" (the 411 regression).
.NOTES
    Run via ./tests/Run-Tests.ps1 or directly. Exit code 0 = all pass, 1 = failures.
#>
[CmdletBinding()] param()
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$script:fail = 0
function Check([string]$name, [bool]$cond, [string]$detail = "") {
    if ($cond) { Write-Host "  [PASS] $name" -ForegroundColor Green }
    else { Write-Host "  [FAIL] $name$(if($detail){" — $detail"})" -ForegroundColor Red; $script:fail++ }
}

Write-Host "`n== Scanner contracts ==" -ForegroundColor Cyan
# Scope-aware scanners take the MG/Sub/RG targeting params. Entra (directory-wide) and
# Log Analytics (its own Subscription→RG→Workspace cascade) are intentionally exempt.
$scopeAware = 'Invoke-AzureIdleScan.ps1','Invoke-PrivilegedAccessScan.ps1','Invoke-TagComplianceScan.ps1','Invoke-QuotaScan.ps1'
$scanners = Get-ChildItem "$root/scanners/Invoke-*Scan.ps1"
Check "found scanners" ($scanners.Count -ge 6) "$($scanners.Count) found"
foreach ($s in $scanners) {
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($s.FullName, [ref]$null, [ref]$errs)
    Check "$($s.Name): parses" (-not $errs) ($errs -join '; ')
    $raw = Get-Content $s.FullName -Raw
    Check "$($s.Name): #Requires -Version 7.0" ($raw -match '#Requires\s+-Version\s+7')
    Check "$($s.Name): #Requires Az modules" ($raw -match '#Requires\s+-Modules')
    $params = @()
    if ($ast.ParamBlock) { $params = $ast.ParamBlock.Parameters.Name.VariablePath.UserPath }
    if ($scopeAware -contains $s.Name) {
        foreach ($p in 'ScopeType','ManagementGroupId','SingleSubscriptionId') {
            Check "$($s.Name): declares -$p (scope-aware)" ($params -contains $p)
        }
    }
    $op = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputPath' }
    $opDefault = if ($op -and $op.DefaultValue) { "$($op.DefaultValue)" } else { "" }
    Check "$($s.Name): OutputPath default writes to data/" ($opDefault -match 'data/')
}

Write-Host "`n== Page contracts ==" -ForegroundColor Cyan
$pages = Get-ChildItem "$root/web/*.html"
$toolPages = $pages | Where-Object { $_.Name -ne 'home.html' }
Check "found tool pages" ($toolPages.Count -ge 6) "$($toolPages.Count) found"
foreach ($p in $pages) {
    $h = Get-Content $p.FullName -Raw
    Check "$($p.Name): FOUC-free theme head-script" ($h -match "azureHub\.theme")
    # Regression guard for the 411 bug: no single-line bodyless POST fetch.
    Check "$($p.Name): no bodyless POST fetch" (-not ($h -match "method:\s*'POST'\s*\}"))
    Check "$($p.Name): standardized esc() (no escapeHtml)" (-not ($h -match 'escapeHtml'))
}
foreach ($p in $toolPages) {
    $h = Get-Content $p.FullName -Raw
    foreach ($fn in 'applyData','esc','asArray','pollStatus','getFilteredRows') {
        Check "$($p.Name): defines $fn()" ($h -match "function\s+$fn\b")
    }
    Check "$($p.Name): renders through a render fn" ($h -match 'function\s+(renderTable|render)\b')
}

Write-Host ""
if ($script:fail -gt 0) { Write-Host "CONTRACT TESTS: $script:fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "CONTRACT TESTS: all passed" -ForegroundColor Green
exit 0   # always set an explicit exit code so a caller's $LASTEXITCODE is defined (StrictMode-safe in a fresh session)
