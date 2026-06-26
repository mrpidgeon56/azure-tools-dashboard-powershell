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

    Finally, it probes whether Az.Accounts can load inside a child runspace
    (Start-ThreadJob) — a recent Az.Accounts regression breaks this and makes scans
    return empty results, so the probe flags a known-bad build before you run a scan.

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

    # Multiple installed versions of an Az module collide at load time with
    # "Could not load assembly … assembly with same name is already loaded" and break scans.
    # Flag it (warning, not fatal — duplicates are common and don't always conflict).
    $allVers = @(Get-Module -ListAvailable -Name $m.Name | Select-Object -ExpandProperty Version)
    if ($allVers.Count -gt 1) {
        Add-Check -Name "$($m.Name) (one version)" -Ok $false -Optional $true `
            -Detail "$($allVers.Count) versions installed ($(($allVers | ForEach-Object { "$_" }) -join ', ')) — duplicates can cause 'assembly already loaded' errors mid-scan" `
            -Fix "Collapse to one: Uninstall-Module $($m.Name) -AllVersions -Force ; Install-Module $($m.Name) -Scope CurrentUser"
    }
}

# ── Az.Accounts child-runspace probe ───────────────────────────────────────────
# Scans run inside child runspaces (Start-ThreadJob + ForEach-Object -Parallel). A recent
# Az.Accounts AssemblyLoadContext regression throws "Assembly with same name is already
# loaded" when the module is imported a SECOND time in the same process — which silently
# produces empty scans (the job dies the instant it touches Az). Probe the actual failure
# mode here rather than maintaining a version blocklist.
$azMod = Get-Module -ListAvailable -Name Az.Accounts | Sort-Object Version -Descending | Select-Object -First 1
$tjMod = Get-Module -ListAvailable -Name ThreadJob   | Sort-Object Version -Descending | Select-Object -First 1
if ($azMod -and $tjMod) {
    try {
        Import-Module Az.Accounts -ErrorAction Stop
        Import-Module ThreadJob   -ErrorAction Stop
        $job = Start-ThreadJob -ScriptBlock {
            try { Import-Module Az.Accounts -ErrorAction Stop; 'ok' } catch { $_.Exception.Message }
        }
        $null = Wait-Job $job -Timeout 60
        $probe = (@(Receive-Job $job) -join ' ').Trim()
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        if ($probe -eq 'ok') {
            Add-Check -Name "Az.Accounts in ThreadJob" -Ok $true -Detail "v$($azMod.Version) loads cleanly in a child runspace"
        } else {
            $short = if ($probe.Length -gt 100) { $probe.Substring(0, 100) + '…' } else { $probe }
            Add-Check -Name "Az.Accounts in ThreadJob" -Ok $false `
                -Detail "v$($azMod.Version) FAILS in a child runspace — scans run there and will return empty. ($short)" `
                -Fix "Known Az.Accounts regression. Try 'Update-Module Az.Accounts' (may be patched), or pin a working build: Install-Module Az.Accounts -RequiredVersion 5.3.0 -Force -Scope CurrentUser"
        }
    } catch {
        # If the probe itself can't run, don't block startup over it — just note it.
        Add-Check -Name "Az.Accounts in ThreadJob" -Ok $true -Detail "probe skipped ($($_.Exception.Message))" -Optional $true
    }
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
