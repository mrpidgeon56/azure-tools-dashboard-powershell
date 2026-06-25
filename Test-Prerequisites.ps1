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
      - Az.ResourceGraph         (Tag, Quota, and Log Analytics Cost scanners)
      - Az.ManagementGroups      (optional: management-group scope in PA scanner)

    Each module is also checked against a minimum version; an installed-but-too-old
    module is flagged (FAIL) the same as a missing one.

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
# MinVersion = the lowest version we've verified the scanners against. An installed
# module older than this is flagged the same as missing (update with Install-Module).
$modules = @(
    @{ Name = "ThreadJob";          Optional = $false; MinVersion = "2.0.3"  },
    @{ Name = "Az.Accounts";        Optional = $false; MinVersion = "2.13.0" },
    @{ Name = "Az.Resources";       Optional = $false; MinVersion = "6.0.0"  },
    @{ Name = "Az.Monitor";         Optional = $false; MinVersion = "4.0.0"  },
    @{ Name = "Az.CostManagement";  Optional = $false; MinVersion = "0.3.0"  },
    @{ Name = "Az.ResourceGraph";   Optional = $false; MinVersion = "0.13.0" },
    @{ Name = "Az.ManagementGroups";Optional = $true;  MinVersion = "1.0.0"  }
)

foreach ($m in $modules) {
    $mod = Get-Module -ListAvailable -Name $m.Name |
           Sort-Object Version -Descending | Select-Object -First 1
    $min = [version]$m.MinVersion
    if (-not $mod) {
        $ok     = $false
        $detail = "not installed (need >= $($m.MinVersion))"
    } elseif ($mod.Version -lt $min) {
        $ok     = $false
        $detail = "v$($mod.Version) — too old, need >= $($m.MinVersion)"
    } else {
        $ok     = $true
        $detail = "v$($mod.Version)"
    }
    Add-Check -Name $m.Name -Ok $ok -Detail $detail `
        -Fix "Install-Module $($m.Name) -MinimumVersion $($m.MinVersion) -Scope CurrentUser" -Optional $m.Optional
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
    Write-Host "       Install-Module ThreadJob, Az.Accounts, Az.Resources, Az.Monitor, Az.CostManagement, Az.ResourceGraph -Scope CurrentUser" -ForegroundColor DarkGray
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
