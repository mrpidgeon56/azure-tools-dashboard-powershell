#Requires -Version 7.0
<#
.SYNOPSIS
    PowerShell lint + code-security gate (PSScriptAnalyzer). Used by CI and runnable locally.

.DESCRIPTION
    Analyzes every PowerShell file in the repo. The build is BLOCKED on:
      • any Error-severity finding (e.g. parse errors), and
      • any security-rule finding (plaintext passwords, Invoke-Expression, etc.) at any severity.
    Warning/Information findings are reported in the GitHub step summary but do NOT fail the run
    (the existing codebase carries intentional warnings — see PSScriptAnalyzerSettings.psd1).

.EXAMPLE
    pwsh .github/scripts/Run-Lint.ps1     # same gate locally as in CI
#>
[CmdletBinding()]
param(
    [string] $Path         = (Resolve-Path "$PSScriptRoot/../..").Path,
    [string] $SettingsPath  = (Join-Path (Resolve-Path "$PSScriptRoot/../..").Path 'PSScriptAnalyzerSettings.psd1')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module PSScriptAnalyzer -ErrorAction Stop

# Security-category rules that must ALWAYS block, regardless of configured severity.
$securityRules = @(
    'PSAvoidUsingPlainTextForPassword'
    'PSAvoidUsingConvertToSecureStringWithPlainText'
    'PSAvoidUsingUsernameAndPasswordParams'
    'PSAvoidUsingInvokeExpression'
    'PSAvoidUsingComputerNameHardcoded'
    'PSAvoidUsingBrokenHashAlgorithms'
    'PSUsePSCredentialType'
)

Write-Host "Running PSScriptAnalyzer over $Path ..."
# Run from the analyzed root so Resolve-Path -Relative (annotation paths) lines up with the repo.
Push-Location $Path
try {
    $params = @{ Path = $Path; Recurse = $true }
    if (Test-Path $SettingsPath) { $params['Settings'] = $SettingsPath }
    $results = @(Invoke-ScriptAnalyzer @params)

    # Mutually-exclusive buckets (priority: security > error > warning > info) so the summary
    # never double-counts a finding that is both an Error and a security rule.
    $security = @($results | Where-Object { $securityRules -contains $_.RuleName })
    $rest     = @($results | Where-Object { $securityRules -notcontains $_.RuleName })
    $errorsF  = @($rest | Where-Object { $_.Severity -eq 'Error' })
    $warnings = @($rest | Where-Object { $_.Severity -eq 'Warning' })
    $infos    = @($rest | Where-Object { $_.Severity -eq 'Information' })
    $blocking = @($security + $errorsF)

function Get-RelPath ([string] $full) {
    try { (Resolve-Path -LiteralPath $full -Relative) -replace '^\.[\\/]', '' } catch { $full }
}

# Inline annotations for the blocking findings only (keeps the PR view uncluttered).
foreach ($f in $blocking) {
    $rel = Get-RelPath $f.ScriptPath
    Write-Host ("::error file={0},line={1},col={2}::[{3}] {4}" -f $rel, $f.Line, $f.Column, $f.RuleName, $f.Message)
}

# Markdown step summary — full breakdown so warnings stay visible without blocking.
$summaryPath = $env:GITHUB_STEP_SUMMARY
if ($summaryPath) {
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('## PowerShell lint & security (PSScriptAnalyzer)')
    $lines.Add('')
    $lines.Add('| Category | Count | Gate |')
    $lines.Add('|---|---:|---|')
    $lines.Add(('| Error | {0} | ❌ blocks |' -f $errorsF.Count))
    $lines.Add(('| Security rule | {0} | ❌ blocks |' -f $security.Count))
    $lines.Add(('| Warning | {0} | ⚠️ reported |' -f $warnings.Count))
    $lines.Add(('| Information | {0} | ℹ️ reported |' -f $infos.Count))
    if ($results.Count) {
        $lines.Add('')
        $lines.Add('<details><summary>Findings by rule</summary>')
        $lines.Add('')
        $lines.Add('| Count | Severity | Rule |')
        $lines.Add('|---:|---|---|')
        foreach ($g in ($results | Group-Object RuleName | Sort-Object Count -Descending)) {
            $sev = ($g.Group | Select-Object -First 1).Severity
            $lines.Add(('| {0} | {1} | {2} |' -f $g.Count, $sev, $g.Name))
        }
        $lines.Add('')
        $lines.Add('</details>')
    }
    ($lines -join "`n") | Out-File -FilePath $summaryPath -Append -Encoding utf8
}

Write-Host ''
Write-Host ("PSScriptAnalyzer: {0} finding(s) — {1} error, {2} security, {3} warning, {4} info." -f `
    $results.Count, $errorsF.Count, $security.Count, $warnings.Count, $infos.Count)

if ($blocking.Count) {
    Write-Host ("FAIL: {0} blocking finding(s) (Errors + security rules)." -f $blocking.Count) -ForegroundColor Red
    exit 1
}
    Write-Host 'PASS: no blocking findings. Warnings/info are reported in the job summary only.' -ForegroundColor Green
    exit 0
}
finally { Pop-Location }
