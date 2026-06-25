<#
.SYNOPSIS
    Pre-flight check for the Azure Engineering dashboard. Verifies that the required
    software is installed BEFORE you run Start-Dashboard.ps1.

    Checks:
      - PowerShell 7+            (scripts use -Parallel, ternary, null-coalescing)
      - ThreadJob module         (scans run via Start-ThreadJob)
      - Az.Accounts              (authentication — all tools)
      - Az.Resources             (Idle Resource + Privileged Access scanners)
      - Az.Monitor               (Idle Resource scanner — metrics)
      - Az.CostManagement        (Idle Resource scanner — cost)
      - Az.ManagementGroups      (optional: management-group scope in PA scanner)

.EXAMPLE
    ./Test-Prerequisites.ps1
    # Exits 0 if everything required is present, 1 otherwise.
#>
[CmdletBinding()]
param()

$results = [System.Collections.Generic.List[object]]::new()
$missing = $false

function Add-Check {
    param(
        [string] $Name,
        [bool]   $Ok,
        [string] $Detail,
        [string] $Fix,
        [bool]   $Optional = $false
    )
    $results.Add([pscustomobject]@{ Name = $Name; Ok = $Ok; Detail = $Detail; Fix = $Fix; Optional = $Optional })
    if (-not $Ok -and -not $Optional) { $script:missing = $true }
}

# ── PowerShell version ───────────────────────────────────────────────────────
$psv = $PSVersionTable.PSVersion
Add-Check -Name "PowerShell 7+" -Ok ($psv.Major -ge 7) `
    -Detail "Found $psv" `
    -Fix "Install PowerShell 7: https://aka.ms/powershell"

# ── Modules ──────────────────────────────────────────────────────────────────
$modules = @(
    @{ Name = "ThreadJob";          Optional = $false },
    @{ Name = "Az.Accounts";        Optional = $false },
    @{ Name = "Az.Resources";       Optional = $false },
    @{ Name = "Az.Monitor";         Optional = $false },
    @{ Name = "Az.CostManagement";  Optional = $false },
    @{ Name = "Az.ManagementGroups";Optional = $true  }
)

foreach ($m in $modules) {
    $mod = Get-Module -ListAvailable -Name $m.Name |
           Sort-Object Version -Descending | Select-Object -First 1
    $ok  = [bool]$mod
    $detail = if ($ok) { "v$($mod.Version)" } else { "not installed" }
    Add-Check -Name $m.Name -Ok $ok -Detail $detail `
        -Fix "Install-Module $($m.Name) -Scope CurrentUser" -Optional $m.Optional
}

# ── Report ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Azure Engineering — prerequisite check" -ForegroundColor Cyan
Write-Host "  ----------------------------------------" -ForegroundColor DarkGray

foreach ($r in $results) {
    if ($r.Ok) {
        $mark = "[ OK ]"; $color = "Green"
    } elseif ($r.Optional) {
        $mark = "[ -- ]"; $color = "Yellow"
    } else {
        $mark = "[FAIL]"; $color = "Red"
    }
    $label = $r.Name.PadRight(20)
    Write-Host ("  {0} {1} {2}" -f $mark, $label, $r.Detail) -ForegroundColor $color
    if (-not $r.Ok) {
        Write-Host ("         → {0}" -f $r.Fix) -ForegroundColor DarkGray
    }
}

Write-Host ""
if ($missing) {
    Write-Host "  Missing required software. Install the items marked [FAIL], then re-run this script." -ForegroundColor Red
    Write-Host "  Tip: install everything at once:" -ForegroundColor DarkGray
    Write-Host "       Install-Module ThreadJob, Az.Accounts, Az.Resources, Az.Monitor, Az.CostManagement -Scope CurrentUser" -ForegroundColor DarkGray
    Write-Host ""
    exit 1
} else {
    $optMissing = @($results | Where-Object { -not $_.Ok -and $_.Optional }).Count
    Write-Host "  All required prerequisites are installed. You're good to run ./Start-Dashboard.ps1" -ForegroundColor Green
    if ($optMissing) {
        Write-Host "  ($optMissing optional module(s) missing — only needed for management-group scope in the Privileged Access scanner.)" -ForegroundColor Yellow
    }
    Write-Host ""
    exit 0
}
