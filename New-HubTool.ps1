#Requires -Version 7.0
<#
.SYNOPSIS
    Scaffolds a new hub tool: a scanner skeleton (scanners/Invoke-<Name>Scan.ps1) plus a
    dashboard page (web/<slug>.html), then prints the exact Start-Dashboard.ps1 + home.html
    wiring to paste. Encodes the "adding a new tool" checklist so steps can't be missed or drift.

.DESCRIPTION
    The two generated FILES are the boilerplate that's easy to get wrong (scope params, the
    output envelope, the page chrome + standard helpers); the server/home WIRING is small and
    printed for you to paste at the marked anchors. Re-run with -Remove <slug> to delete the
    generated files.

.PARAMETER Name        Display name, e.g. "Cost Anomaly Detector".
.PARAMETER Slug        URL/file slug, e.g. "cost-anomaly". Defaults to a kebab-case of -Name.
.PARAMETER ApiPrefix   /api/<prefix>/* namespace, e.g. "anomaly". Defaults to a compact slug.
.PARAMETER Icon        Emoji for the home card + page logo. Default 🔧.
.PARAMETER Tag         Home-card category chip. Default "Governance".

.EXAMPLE
    ./New-HubTool.ps1 -Name "Cost Anomaly Detector" -Slug cost-anomaly -ApiPrefix anomaly -Icon 💸
.EXAMPLE
    ./New-HubTool.ps1 -Slug cost-anomaly -Remove
#>
[CmdletBinding(DefaultParameterSetName = 'Create')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Create')] [string] $Name,
    [Parameter(ParameterSetName = 'Create')] [string] $ApiPrefix,
    [Parameter(ParameterSetName = 'Create')] [string] $Icon = "🔧",
    [Parameter(ParameterSetName = 'Create')] [string] $Tag  = "Governance",
    [Parameter(Mandatory, ParameterSetName = 'Remove')] [switch] $Remove,
    [string] $Slug
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root        = $PSScriptRoot
$scannersDir = Join-Path $root 'scanners'
$webDir      = Join-Path $root 'web'

# ── derive identifiers ────────────────────────────────────────────────────────
function ConvertTo-Kebab([string]$s) { (($s -replace '[^A-Za-z0-9]+', '-').Trim('-')).ToLowerInvariant() }
function ConvertTo-Pascal([string]$s) { (($s -split '[^A-Za-z0-9]+' | Where-Object { $_ } | ForEach-Object { $_.Substring(0,1).ToUpperInvariant() + $_.Substring(1) }) -join '') }

if (-not $Slug) {
    if (-not $Name) { throw "Provide -Slug (with -Remove) or -Name (to create)." }
    $Slug = ConvertTo-Kebab $Name
}
$slug = ConvertTo-Kebab $Slug
$scannerPath = Join-Path $scannersDir ("Invoke-{0}Scan.ps1" -f (ConvertTo-Pascal $slug))
$pagePath    = Join-Path $webDir ("{0}.html" -f $slug)

# ── remove mode ───────────────────────────────────────────────────────────────
if ($Remove) {
    foreach ($p in @($scannerPath, $pagePath)) {
        if (Test-Path $p) { Remove-Item $p -Force; Write-Host "  removed $p" -ForegroundColor Yellow }
        else { Write-Host "  (absent) $p" -ForegroundColor DarkGray }
    }
    Write-Host "`n  NOTE: also remove the '$slug' blocks you pasted into Start-Dashboard.ps1 and web/home.html." -ForegroundColor Yellow
    return
}

$compactSlug = $slug -replace '-', ''
if (-not $ApiPrefix) { $ApiPrefix = $compactSlug }
$pascal = ConvertTo-Pascal $slug
$cmdlet = "Invoke-${pascal}Scan.ps1"

if (Test-Path $scannerPath) { throw "Scanner already exists: $scannerPath (use -Remove first)." }
if (Test-Path $pagePath)    { throw "Page already exists: $pagePath (use -Remove first)." }

# ── 1. scanner skeleton ───────────────────────────────────────────────────────
# A working skeleton: standard scope params + progress scaffolding + the
# { ScanMetadata, Items, Errors } envelope. Emits an empty-but-valid result until you
# fill in the scan body, so the page renders its empty state immediately.
$scanner = @"
#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    $Name scanner. TODO: describe what it finds.
.OUTPUTS
    JSON at -OutputPath (default ../data/$slug-scan-results.json): { ScanMetadata, Items, Errors }
.NOTES
    Reuses the in-memory Az context (no separate login). Scope params mirror the other scanners
    so the shared /api/$ApiPrefix/scan endpoint can pass them straight through.
#>
[CmdletBinding()]
param(
    [string] `$OutputPath = "`$PSScriptRoot/../data/$slug-scan-results.json",
    [string] `$ProgressPath = "",
    [ValidateSet('All','ManagementGroup','Subscription','ResourceGroup')]
    [string] `$ScopeType = "All",
    [string] `$ManagementGroupId = "",
    [string] `$SingleSubscriptionId = "",
    [string] `$ResourceGroup = ""
)
Set-StrictMode -Version Latest
`$ErrorActionPreference = "Stop"

#region ── standard hub scaffolding ──────────────────────────────────────────────
`$script:logTail       = [System.Collections.Generic.List[string]]::new()
`$script:progressState = [ordered]@{ Phase = "init"; Percent = 0; Fetched = 0; Total = 0; FlaggedSoFar = 0; Message = "" }
function Save-Progress {
    if (-not `$ProgressPath) { return }
    `$payload = [ordered]@{}
    foreach (`$k in `$script:progressState.Keys) { `$payload[`$k] = `$script:progressState[`$k] }
    `$payload.LogTail = @(`$script:logTail); `$payload.UpdatedAt = (Get-Date).ToString("o")
    try { `$payload | ConvertTo-Json -Depth 5 | Set-Content -Path `$ProgressPath -Encoding UTF8 -ErrorAction Stop } catch { }
}
function Write-Progress2 (`$msg) {
    `$line = "[`$(Get-Date -Format 'HH:mm:ss')] `$msg"
    Write-Host `$line -ForegroundColor Cyan
    `$script:logTail.Add(`$line); while (`$script:logTail.Count -gt 12) { `$script:logTail.RemoveAt(0) }
    Save-Progress
}
function Set-ScanProgress {
    param([string]`$Phase, [int]`$Fetched = 0, [int]`$Total = 0, [int]`$FlaggedSoFar = 0, [string]`$Message = "")
    if (-not `$ProgressPath) { return }
    `$percent = 0; if (`$Total -gt 0) { `$percent = [math]::Round((`$Fetched / `$Total) * 100, 1) }
    if (`$Phase -eq "done") { `$percent = 100 }
    `$script:progressState = [ordered]@{ Phase = `$Phase; Percent = `$percent; Fetched = `$Fetched; Total = `$Total; FlaggedSoFar = `$FlaggedSoFar; Message = `$Message }
    Save-Progress
}
function Format-Exception (`$err) {
    if (`$null -eq `$err) { return "" }
    `$msg = if (`$err.Exception) { `$err.Exception.Message } else { "`$err" }
    return (`$msg -replace '\s+', ' ').Trim()
}
#endregion

`$scanStartTime = Get-Date
`$items  = [System.Collections.Generic.List[object]]::new()
`$errors = [System.Collections.Generic.List[object]]::new()

`$scopeLabel = if (`$ScopeType -eq 'ManagementGroup' -and `$ManagementGroupId) { "management group '`$ManagementGroupId'" }
              elseif (`$ResourceGroup -and `$SingleSubscriptionId) { "`$SingleSubscriptionId / `$ResourceGroup" }
              elseif (`$SingleSubscriptionId) { "subscription '`$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }
Set-ScanProgress -Phase "scanning" -Message "Scanning (`$scopeLabel)..."
Write-Progress2 "$Name scan — scope: `$scopeLabel"

# ── TODO: implement the scan ──────────────────────────────────────────────────
# Discover via Search-AzGraph (PAGE with SkipToken — never -First 1000 alone) and/or call
# ARM REST with the in-memory token (Get-AzAccessToken -ResourceTypeName Arm). Honor scope:
#   ManagementGroup -> Search-AzGraph -ManagementGroup `$ManagementGroupId
#   Subscription    -> -Subscription `$SingleSubscriptionId (or KQL 'where subscriptionId ==')
#   ResourceGroup   -> the above + 'where resourceGroup =~ `$ResourceGroup'
# Add one record per finding, e.g.:
#   `$items.Add([ordered]@{ Name = "..."; SubscriptionId = "..."; SubscriptionName = "...";
#       RecommendedAction = @{ Action = "..."; Reason = "..." } })

# ── write output ──────────────────────────────────────────────────────────────
`$output = @{
    ScanMetadata = @{
        ScanTime          = `$scanStartTime.ToString("o")
        CompletedTime     = (Get-Date).ToString("o")
        ScopeType         = `$ScopeType
        ManagementGroupId = `$ManagementGroupId
        ScopeLabel        = `$scopeLabel
        TotalItems        = `$items.Count
        ErrorCount        = `$errors.Count
    }
    Items  = `$items
    Errors = `$errors
}
Set-ScanProgress -Phase "done" -Fetched `$items.Count -Total `$items.Count -Message "Scan complete."
`$output | ConvertTo-Json -Depth 8 | Set-Content -Path `$OutputPath -Encoding UTF8
Write-Progress2 "Done. `$(`$items.Count) item(s). Wrote `$OutputPath"
"@
Set-Content -Path $scannerPath -Value $scanner -Encoding UTF8
Write-Host "  created $scannerPath" -ForegroundColor Green

# ── 2. dashboard page (clone the validated reference, swap identifiers) ────────
$refPage = Join-Path $webDir 'quota-usage.html'
if (-not (Test-Path $refPage)) { throw "Reference page not found: $refPage" }
$page = Get-Content $refPage -Raw
$page = $page.Replace('Quota Usage Scanner', $Name)
$page = $page.Replace('<span class="logo">📊</span>', "<span class=`"logo`">$Icon</span>")
$page = $page.Replace('/api/quota/', "/api/$ApiPrefix/")
# Align the array field the page reads with the scanner's "Items" envelope.
$page = $page.Replace('asArray(json.Quotas)', 'asArray(json.Items)')
$page = $page.Replace('"Quotas":[]', '"Items":[]')
$banner = "<!-- TODO ($slug): customize the summary cards, the COLS/COL_FILTERS table columns, the heatmap, and renderTable() for this tool's data shape. Scanner emits { ScanMetadata, Items, Errors }. -->`n"
$page = $banner + $page
Set-Content -Path $pagePath -Value $page -Encoding UTF8
Write-Host "  created $pagePath" -ForegroundColor Green

# ── 3. print the server + home wiring to paste ─────────────────────────────────
$pascalVar = $pascal
$wire = @"

  ─────────────────────────────────────────────────────────────────────────────
  Now wire it up (3 paste steps). All are in Start-Dashboard.ps1 + web/home.html:

  [A] Start-Dashboard.ps1 — param() block, beside the other *ScanScript defaults:
        [string] `$${pascalVar}ResultsPath  = "`$PSScriptRoot/data/$slug-scan-results.json",
        [string] `$${pascalVar}ProgressPath = "`$PSScriptRoot/data/$slug-scan-progress.json",
        [string] `$${pascalVar}ScanScript   = "`$PSScriptRoot/scanners/$cmdlet",
      and the job vars beside the others:
        `$${compactSlug}ScanJob = `$null
        `$${compactSlug}ScanStatus = @{ State = "idle"; StartedAt = `$null; Message = "No scan run yet." }

  [B] Start-Dashboard.ps1 — `$pageRoutes table:
        "/$slug" = "$slug.html"

  [C] Start-Dashboard.ps1 — copy an existing /api/<tool>/* quartet (the /api/quota/* block is
      the closest match) and rename quota -> $ApiPrefix, Quota -> $pascalVar, Quotas -> Items,
      pointing at `$${pascalVar}ResultsPath / `$${pascalVar}ScanScript. Then add to the finally{}
      cleanup:  if (`$${compactSlug}ScanJob) { Remove-Job `$${compactSlug}ScanJob -Force }

  [D] web/home.html — add a tool card (clone one above) pointing href="/$slug",
      icon $Icon, tag "$Tag", and a live-state IIFE fetching /api/$ApiPrefix/results.
  ─────────────────────────────────────────────────────────────────────────────

  Then customize the TODOs in:
    $scannerPath  (the scan body)
    $pagePath     (cards + columns + renderTable)
"@
Write-Host $wire -ForegroundColor Cyan
