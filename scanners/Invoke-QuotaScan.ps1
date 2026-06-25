#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Scans Azure subscriptions for resource-usage vs. quota limits and surfaces the
    quotas closest to their ceiling, with a recommended action per quota.

    For every subscription (or a single one) it:
      - discovers the regions the subscription actually uses (via Azure Resource Graph),
        so we only query regions with deployed resources rather than every Azure region;
      - reads the per-region usage/limit for Microsoft.Compute, Microsoft.Network and
        Microsoft.Storage (the "usages" ARM APIs), keeping only quotas with non-zero usage;
      - computes a usage percentage and a severity (Critical / Warning / OK) from the
        -CriticalThreshold / -WarningThreshold, plus a recommended action.

.OUTPUTS
    JSON file at -OutputPath (default: ./quota-scan-results.json):
    { ScanMetadata, Quotas, Errors }

.NOTES
    Authentication reuses the in-memory Az context (no separate login): an ARM token is
    obtained with Get-AzAccessToken and the usages REST APIs are called directly. The
    signed-in identity needs only READER on the subscriptions.

    Required Az modules: Az.Accounts, Az.ResourceGraph.
#>
[CmdletBinding()]
param(
    [string] $OutputPath           = "$PSScriptRoot/../data/quota-scan-results.json",
    [string] $ProgressPath         = "",          # if set, incremental progress JSON is written here
    [ValidateSet('All','ManagementGroup','Subscription')]
    [string] $ScopeType            = "All",        # scan scope: whole tenant, one management group, or one subscription
    [string] $ManagementGroupId    = "",           # when -ScopeType ManagementGroup: the MG to recurse (all child subs)
    [string] $SingleSubscriptionId = "",          # optional: scan just one subscription
    [int]    $CriticalThreshold    = 90,          # usage % at/above this ⇒ Critical
    [int]    $WarningThreshold     = 75,          # usage % at/above this ⇒ Warning
    [string[]] $IncludeProviders   = @('Compute','Network','Storage')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ARM "usages" endpoints per provider (provider key → api-version).
$ProviderApi = @{
    Compute = '2023-07-01'
    Network = '2023-09-01'
    Storage = '2023-01-01'
}

#region ── helpers ──────────────────────────────────────────────────────────────

$script:logTail       = [System.Collections.Generic.List[string]]::new()
$script:progressState = [ordered]@{ Phase = "init"; Percent = 0; Fetched = 0; Total = 0; FlaggedSoFar = 0; Message = "" }

function Save-Progress {
    if (-not $ProgressPath) { return }
    $payload = [ordered]@{}
    foreach ($k in $script:progressState.Keys) { $payload[$k] = $script:progressState[$k] }
    $payload.LogTail   = @($script:logTail)
    $payload.UpdatedAt = (Get-Date).ToString("o")
    try { $payload | ConvertTo-Json -Depth 5 | Set-Content -Path $ProgressPath -Encoding UTF8 -ErrorAction Stop }
    catch { <# progress writes are best-effort #> }
}

function Write-Progress2 ($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line -ForegroundColor Cyan
    $script:logTail.Add($line)
    while ($script:logTail.Count -gt 12) { $script:logTail.RemoveAt(0) }
    Save-Progress
}

function Set-ScanProgress {
    param([string]$Phase, [int]$Fetched = 0, [int]$Total = 0, [int]$FlaggedSoFar = 0, [string]$Message = "")
    if (-not $ProgressPath) { return }
    $percent = 0
    if ($Total -gt 0) { $percent = [math]::Round(($Fetched / $Total) * 100, 1) }
    if ($Phase -eq "done") { $percent = 100 }
    $script:progressState = [ordered]@{
        Phase = $Phase; Percent = $percent; Fetched = $Fetched; Total = $Total
        FlaggedSoFar = $FlaggedSoFar; Message = $Message
    }
    Save-Progress
}

function Format-Exception ($err) {
    if ($null -eq $err) { return "" }
    $msg = if ($err.Exception) { $err.Exception.Message } else { "$err" }
    return ($msg -replace '\s+', ' ').Trim()
}

# Returns the raw ARM access token plus its expiry, so callers can refresh before it lapses.
# Uses -ResourceTypeName Arm (Az.Accounts 5.x deprecates -ResourceUrl).
function Get-ArmToken {
    $t = Get-AzAccessToken -ResourceTypeName Arm -WarningAction SilentlyContinue -ErrorAction Stop
    $tok = if ($t.Token -is [System.Security.SecureString]) {
        [System.Net.NetworkCredential]::new('', $t.Token).Password
    } else {
        [string]$t.Token
    }
    $expires = if ($t.PSObject.Properties['ExpiresOn']) { [DateTimeOffset]$t.ExpiresOn } else { [DateTimeOffset]::UtcNow.AddMinutes(55) }
    return [pscustomobject]@{ Token = $tok; ExpiresOn = $expires }
}

function Get-Prop ($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj.PSObject.Properties.Name -contains $name) { return $obj.$name }
    return $null
}

# Recommended action from usage %.
function Get-QuotaAction {
    param([double]$Pct, [string]$Severity, [double]$Headroom, [string]$Unit)
    switch ($Severity) {
        'Critical' { return @{ Action = "Request quota increase now"; Reason = "At $([math]::Round($Pct,1))% of limit — only $([math]::Round($Headroom)) $Unit headroom remaining." } }
        'Warning'  { return @{ Action = "Plan a quota increase";      Reason = "At $([math]::Round($Pct,1))% of limit — request more before you run out of headroom." } }
        default    { return @{ Action = "Within limits";              Reason = "At $([math]::Round($Pct,1))% of limit — no action needed." } }
    }
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$quotas = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()
$flaggedSoFar = 0

Set-ScanProgress -Phase "init" -Message "Acquiring ARM token..."
Write-Progress2 "Acquiring ARM token from the active Az session..."
$armTok      = Get-ArmToken
$armExpires  = $armTok.ExpiresOn
$armHeaders  = @{ Authorization = "Bearer $($armTok.Token)" }

# Lazy refresh: the ARM token is reused across the whole sub/region/provider loop, which
# can run long on large tenants and outlive the token. Before each provider request the loop
# checks $armExpires; when within ~5 minutes of expiry it re-acquires the token and rebuilds
# $armHeaders in place. Best-effort: on failure keep the current token and let the request
# surface any auth error.

# ── subscription name map ────────────────────────────────────────────────────
$subNames = @{}
try {
    foreach ($s in Get-AzSubscription -ErrorAction Stop) {
        if ($s.State -eq 'Enabled') { $subNames["$($s.Id)"] = "$($s.Name)" }
    }
} catch {
    $errors.Add(@{ Stage = "subscriptions"; Error = (Format-Exception $_) })
}

# ── discover active (subscription, region) pairs via Resource Graph ──────────
# Scope resolution: a management group recurses to all its child subscriptions
# (Search-AzGraph -ManagementGroup); a single subscription restricts to one;
# otherwise the query spans every accessible subscription. -SingleSubscriptionId
# still works on its own (standalone CLI) even when -ScopeType is left at All.
$scopeLabel = if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) { "management group '$ManagementGroupId' (recursive)" }
              elseif ($SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }
Write-Progress2 "Discovering active regions via Resource Graph — scope: $scopeLabel..."

if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
    throw "Azure Resource Graph (Search-AzGraph) is unavailable. Install it with: Install-Module Az.ResourceGraph -Scope CurrentUser"
}

$pairs = [System.Collections.Generic.List[object]]::new()
try {
    $kql = "Resources | where isnotempty(location) and location !in ('global','') | summarize by subscriptionId, location | order by subscriptionId asc, location asc"
    # Scope-specific args spliced into each paged call. Search-AzGraph caps a single page at
    # 1000 rows regardless of -First, so -First 1000 alone silently truncates large tenants —
    # we page with SkipToken until exhausted (dropped regions would hide Critical quotas).
    $scopeArgs = @{}
    if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) { $scopeArgs['ManagementGroup'] = $ManagementGroupId }
    elseif ($SingleSubscriptionId)                                { $scopeArgs['Subscription']    = $SingleSubscriptionId }

    $rows = [System.Collections.Generic.List[object]]::new()
    $skip = $null
    do {
        $page = if ($skip) { Search-AzGraph -Query $kql -First 1000 -SkipToken $skip @scopeArgs -ErrorAction Stop }
                else        { Search-AzGraph -Query $kql -First 1000 @scopeArgs -ErrorAction Stop }
        foreach ($row in @($page)) { $rows.Add($row) }
        $skip = if ($page.PSObject.Properties['SkipToken']) { $page.SkipToken } else { $null }
    } while ($skip)

    foreach ($r in $rows) {
        $sid = "$($r.subscriptionId)"; $loc = "$($r.location)"
        if ($sid -and $loc) { $pairs.Add(@{ Sub = $sid; Region = $loc }) }
    }
} catch {
    $errors.Add(@{ Stage = "resourcegraph"; Error = (Format-Exception $_) })
    Write-Progress2 "Region discovery failed ($(Format-Exception $_))."
}

$providers = @($IncludeProviders | Where-Object { $ProviderApi.ContainsKey($_) })
$subSet = @($pairs | ForEach-Object { $_.Sub } | Select-Object -Unique)
$regionSet = @($pairs | ForEach-Object { $_.Region } | Select-Object -Unique)
$total = $pairs.Count * $providers.Count
Write-Progress2 "Found $($subSet.Count) subscription(s), $($pairs.Count) sub/region pair(s); scanning $($providers -join ', ')."

# ── per (sub, region, provider): read usages ─────────────────────────────────
$done = 0
foreach ($pair in $pairs) {
    $sub = $pair.Sub
    $region = $pair.Region
    $subName = if ($subNames.ContainsKey($sub)) { $subNames[$sub] } else { $sub }

    foreach ($prov in $providers) {
        $done++

        # Refresh the ARM token if it is within ~5 minutes of expiry (long scans outlive it).
        if ($armExpires -le [DateTimeOffset]::UtcNow.AddMinutes(5)) {
            try {
                $armTok     = Get-ArmToken
                $armExpires = $armTok.ExpiresOn
                $armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }
            } catch {
                <# keep the current token; the request below will surface any auth error #>
            }
        }

        $apiVer = $ProviderApi[$prov]
        $uri = "https://management.azure.com/subscriptions/$sub/providers/Microsoft.$prov/locations/$region/usages?api-version=$apiVer"
        try {
            $items = [System.Collections.Generic.List[object]]::new()
            $guard = 0
            while ($uri -and $guard -lt 20) {
                $guard++
                $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $armHeaders -ErrorAction Stop
                foreach ($v in @(Get-Prop $resp 'value')) { $items.Add($v) }
                $next = Get-Prop $resp 'nextLink'
                $uri = if ($next) { [string]$next } else { "" }
            }
            foreach ($u in $items) {
                $current = [double](Get-Prop $u 'currentValue')
                $limit   = [double](Get-Prop $u 'limit')
                if ($limit -le 0 -or $current -le 0) { continue }   # keep only quotas in active use
                $nameObj = Get-Prop $u 'name'
                $qKey    = [string](Get-Prop $nameObj 'value')
                $qName   = [string](Get-Prop $nameObj 'localizedValue'); if (-not $qName) { $qName = $qKey }
                $unit    = [string](Get-Prop $u 'unit'); if (-not $unit) { $unit = 'Count' }

                $pct = [math]::Round(($current / $limit) * 100, 1)
                $headroom = $limit - $current
                $severity = if ($pct -ge $CriticalThreshold) { 'Critical' } elseif ($pct -ge $WarningThreshold) { 'Warning' } else { 'OK' }
                if ($severity -ne 'OK') { $flaggedSoFar++ }
                $action = Get-QuotaAction -Pct $pct -Severity $severity -Headroom $headroom -Unit $unit

                $quotas.Add([ordered]@{
                    SubscriptionId    = $sub
                    SubscriptionName  = $subName
                    Region            = $region
                    Provider          = $prov
                    QuotaName         = $qName
                    QuotaKey          = $qKey
                    CurrentValue      = $current
                    Limit             = $limit
                    Unit              = $unit
                    UsagePercent      = $pct
                    Headroom          = $headroom
                    Severity          = $severity
                    RecommendedAction = $action
                })
            }
        } catch {
            $errors.Add(@{ Stage = "$prov/$region/$sub"; Error = (Format-Exception $_) })
        }
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar $flaggedSoFar `
                         -Message "Scanned $prov in $region ($done/$total)..."
    }
}

#endregion

#region ── write output ─────────────────────────────────────────────────────────

$criticalCount = 0; $warningCount = 0; $okCount = 0
foreach ($q in $quotas) {
    switch ($q.Severity) { 'Critical' { $criticalCount++ } 'Warning' { $warningCount++ } default { $okCount++ } }
}

$output = @{
    ScanMetadata = @{
        ScanTime          = $scanStartTime.ToString("o")
        CompletedTime     = (Get-Date).ToString("o")
        ScopeType         = $ScopeType
        ManagementGroupId = $ManagementGroupId
        ScopeLabel        = $scopeLabel
        Subscriptions     = $subSet.Count
        Regions           = $regionSet.Count
        Providers         = @($providers)
        CriticalThreshold = $CriticalThreshold
        WarningThreshold  = $WarningThreshold
        TotalQuotas       = $quotas.Count
        CriticalCount     = $criticalCount
        WarningCount      = $warningCount
        OkCount           = $okCount
        ErrorCount        = $errors.Count
    }
    Quotas = $quotas
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $quotas.Count -Total $quotas.Count -FlaggedSoFar $flaggedSoFar -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($quotas.Count) active quota(s) — $criticalCount critical, $warningCount warning. Wrote $OutputPath"

#endregion
