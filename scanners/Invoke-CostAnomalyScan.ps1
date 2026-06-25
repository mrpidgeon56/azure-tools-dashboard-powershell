#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Cost Allocation & Anomaly scanner.

    Allocates spend per resource group and flags week-over-week (period-over-period)
    cost anomalies. For every in-scope subscription (or a single one) it runs two Cost
    Management `query.usage` REST calls — one for the current window (default last 30
    days) and one for the prior comparable window — grouping PreTaxCost by
    ResourceGroupName. The per-RG delta and delta-percent surface spikes (and drops);
    rows are ranked by delta so the biggest movers float to the top.

    The Cost Management query API is finicky and quota-limited, so every call is wrapped
    per-subscription: a failure records an error and the scan continues with the
    remaining subscriptions. Needs ARM Reader + Cost Management Reader.

.OUTPUTS
    JSON file at -OutputPath (default ../data/cost-anomaly-scan-results.json):
    { ScanMetadata, Items, Errors }

.NOTES
    Authentication reuses the in-memory Az context (no separate login): an ARM token is
    obtained with Get-AzAccessToken and the Microsoft.CostManagement query REST API is
    called directly. This is NOT a Resource-Graph data tool — it iterates subscriptions —
    but it uses Resource Graph only to resolve a management group's child subscriptions.

    Required Az modules: Az.Accounts, Az.ResourceGraph.
#>
[CmdletBinding()]
param(
    [string] $OutputPath           = "$PSScriptRoot/../data/cost-anomaly-scan-results.json",
    [string] $ProgressPath         = "",          # if set, incremental progress JSON is written here
    [ValidateSet('All','ManagementGroup','Subscription')]
    [string] $ScopeType            = "All",        # scan scope: whole tenant, one management group, or one subscription
    [string] $ManagementGroupId    = "",           # when -ScopeType ManagementGroup: the MG to recurse (all child subs)
    [string] $SingleSubscriptionId = "",          # optional: scan just one subscription
    [int]    $WindowDays           = 30            # length (in days) of the current and prior comparison windows
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CostApiVersion = '2023-11-01'

# A resource group counts as an anomaly when its spend jumped by at least this fraction
# *and* by at least this absolute amount (so tiny RGs going from $1 to $3 don't spam the
# table). Severity escalates at a steeper jump.
$AnomalyPct = 40.0
$AnomalyAbs = 50.0
$HighPct    = 75.0

#region ── standard hub scaffolding ──────────────────────────────────────────────
$script:logTail       = [System.Collections.Generic.List[string]]::new()
$script:progressState = [ordered]@{ Phase = "init"; Percent = 0; Fetched = 0; Total = 0; FlaggedSoFar = 0; Message = "" }
function Save-Progress {
    if (-not $ProgressPath) { return }
    $payload = [ordered]@{}
    foreach ($k in $script:progressState.Keys) { $payload[$k] = $script:progressState[$k] }
    $payload.LogTail = @($script:logTail); $payload.UpdatedAt = (Get-Date).ToString("o")
    try { $payload | ConvertTo-Json -Depth 5 | Set-Content -Path $ProgressPath -Encoding UTF8 -ErrorAction Stop } catch { }
}
function Write-Progress2 ($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line -ForegroundColor Cyan
    $script:logTail.Add($line); while ($script:logTail.Count -gt 12) { $script:logTail.RemoveAt(0) }
    Save-Progress
}
function Set-ScanProgress {
    param([string]$Phase, [int]$Fetched = 0, [int]$Total = 0, [int]$FlaggedSoFar = 0, [string]$Message = "")
    if (-not $ProgressPath) { return }
    $percent = 0; if ($Total -gt 0) { $percent = [math]::Round(($Fetched / $Total) * 100, 1) }
    if ($Phase -eq "done") { $percent = 100 }
    $script:progressState = [ordered]@{ Phase = $Phase; Percent = $percent; Fetched = $Fetched; Total = $Total; FlaggedSoFar = $FlaggedSoFar; Message = $Message }
    Save-Progress
}
function Format-Exception ($err) {
    if ($null -eq $err) { return "" }
    $msg = if ($err.Exception) { $err.Exception.Message } else { "$err" }
    return ($msg -replace '\s+', ' ').Trim()
}
#endregion

#region ── helpers ────────────────────────────────────────────────────────────────

# StrictMode-safe nested read (REST responses are PSCustomObjects / hashtables).
function Get-Prop ($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] } else { return $null } }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-Num ($v, [double]$default = 0.0) {
    if ($null -eq $v) { return $default }
    $out = 0.0
    if ([double]::TryParse("$v", [ref]$out)) { return $out }
    return $default
}

# Returns the raw ARM access token plus its expiry (Az.Accounts 5.x deprecates -ResourceUrl).
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

# A Cost Management `query.usage` body: PreTaxCost grouped by ResourceGroupName.
function Build-QueryBody {
    param([datetime]$Start, [datetime]$End)
    return @{
        type      = "ActualCost"
        timeframe = "Custom"
        timePeriod = @{
            from = $Start.ToString("yyyy-MM-dd") + "T00:00:00Z"
            to   = $End.ToString("yyyy-MM-dd")   + "T23:59:59Z"
        }
        dataset = @{
            granularity = "None"
            aggregation = @{
                totalCost = @{ name = "PreTaxCost"; function = "Sum" }
            }
            grouping = @(
                @{ type = "Dimension"; name = "ResourceGroupName" }
            )
        }
    }
}

# Pull a @{ rg_lower = cost } map plus a currency out of a column-oriented query result.
# The Cost Management result names each field in `columns` and `rows` is a list of
# value-tuples; we locate the cost/RG/currency columns by name (api-versions vary).
function Parse-Costs {
    param($Result)
    $out = @{}
    $currency = "USD"
    $props = Get-Prop $Result 'properties'
    if (-not $props) { $props = $Result }
    $cols = @(Get-Prop $props 'columns')
    $rows = @(Get-Prop $props 'rows')

    $names = @($cols | ForEach-Object { [string](Get-Prop $_ 'name') })
    $lower = @($names | ForEach-Object { $_.ToLower() })

    function Col-Idx ([string[]]$candidates) {
        foreach ($cand in $candidates) {
            $idx = $lower.IndexOf($cand.ToLower())
            if ($idx -ge 0) { return $idx }
        }
        return -1
    }
    $iCost = Col-Idx @('PreTaxCost','Cost','CostUSD')
    $iRg   = Col-Idx @('ResourceGroupName','ResourceGroup')
    $iCur  = Col-Idx @('Currency','BillingCurrency','CurrencyCode')

    foreach ($row in $rows) {
        if ($null -eq $row) { continue }
        $arr = @($row)
        $rg = ""
        if ($iRg -ge 0 -and $iRg -lt $arr.Count -and $null -ne $arr[$iRg]) { $rg = [string]$arr[$iRg] }
        $cost = 0.0
        if ($iCost -ge 0 -and $iCost -lt $arr.Count -and $null -ne $arr[$iCost]) { $cost = ConvertTo-Num $arr[$iCost] }
        if ($iCur -ge 0 -and $iCur -lt $arr.Count -and $arr[$iCur]) { $currency = [string]$arr[$iCur] }
        # An empty RG name is unallocated / subscription-level spend.
        $key = if ($rg) { $rg.ToLower() } else { "(unallocated)" }
        if ($out.ContainsKey($key)) { $out[$key] = $out[$key] + $cost } else { $out[$key] = $cost }
    }
    return @{ Costs = $out; Currency = $currency }
}

# (is_anomaly, severity) for a per-RG cost movement. Severity vocab: high/medium/ok.
function Get-AnomalyClass {
    param([double]$Delta, [double]$DeltaPercent)
    $isAnomaly = ($Delta -ge $AnomalyAbs) -and ($DeltaPercent -ge $AnomalyPct)
    if ($isAnomaly -and $DeltaPercent -ge $HighPct) { return @{ IsAnomaly = $true; Severity = 'high' } }
    if ($isAnomaly) { return @{ IsAnomaly = $true; Severity = 'medium' } }
    return @{ IsAnomaly = $false; Severity = 'ok' }
}

function Get-AnomalyAction {
    param([bool]$IsAnomaly, [string]$Severity, [double]$Delta, [double]$DeltaPercent)
    $pct = [math]::Round($DeltaPercent)
    if ($Severity -eq 'high') {
        return @{ Action = "Investigate spike"; Reason = "Spend rose $pct% period-over-period — confirm the change is intentional." }
    }
    if ($IsAnomaly) {
        return @{ Action = "Monitor"; Reason = "Spend rose $pct% — keep an eye on this resource group." }
    }
    if ($Delta -lt 0) {
        return @{ Action = "Stable"; Reason = "Spend decreased or held steady period-over-period." }
    }
    return @{ Action = "Stable"; Reason = "No material change in spend." }
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

# Current window: the last `WindowDays`. Previous window: the equally long block
# immediately before it.
$today    = (Get-Date).Date
$curEnd   = $today
$curStart = $today.AddDays(-($WindowDays - 1))
$prevEnd  = $curStart.AddDays(-1)
$prevStart = $prevEnd.AddDays(-($WindowDays - 1))

$scopeLabel = if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) { "management group '$ManagementGroupId' (recursive)" }
              elseif ($SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }

Set-ScanProgress -Phase "init" -Message "Acquiring ARM token..."
Write-Progress2 "Cost Allocation & Anomaly scan — scope: $scopeLabel; window: $WindowDays day(s)."
Write-Progress2 "Acquiring ARM token from the active Az session..."
$armTok     = Get-ArmToken
$armExpires = $armTok.ExpiresOn
$armHeaders = @{ Authorization = "Bearer $($armTok.Token)"; 'Content-Type' = 'application/json' }

# ── resolve the subscription set ──────────────────────────────────────────────
# A management group recurses to all its child subscriptions (via Resource Graph
# ResourceContainers); a single subscription restricts to one; otherwise the scan spans
# every accessible subscription. -SingleSubscriptionId works standalone even at -ScopeType All.
$subNames = @{}
try {
    foreach ($s in Get-AzSubscription -ErrorAction Stop) {
        if ($s.State -eq 'Enabled') { $subNames["$($s.Id)"] = "$($s.Name)" }
    }
} catch {
    $errors.Add(@{ Stage = "subscriptions"; Error = (Format-Exception $_) })
}

$subs = [System.Collections.Generic.List[object]]::new()
if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) {
    if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
        throw "Azure Resource Graph (Search-AzGraph) is unavailable. Install it with: Install-Module Az.ResourceGraph -Scope CurrentUser"
    }
    Write-Progress2 "Resolving child subscriptions of management group '$ManagementGroupId' via Resource Graph..."
    try {
        $kql = "ResourceContainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name = tostring(properties.displayName)"
        $rows = [System.Collections.Generic.List[object]]::new()
        $skip = $null
        do {
            $page = if ($skip) { Search-AzGraph -Query $kql -ManagementGroup $ManagementGroupId -First 1000 -SkipToken $skip -ErrorAction Stop }
                    else        { Search-AzGraph -Query $kql -ManagementGroup $ManagementGroupId -First 1000 -ErrorAction Stop }
            foreach ($row in @($page)) { $rows.Add($row) }
            $skip = if ($page.PSObject.Properties['SkipToken']) { $page.SkipToken } else { $null }
        } while ($skip)
        foreach ($r in $rows) {
            $sid = "$($r.subscriptionId)"
            if (-not $sid) { continue }
            $name = if ($r.PSObject.Properties['name'] -and $r.name) { "$($r.name)" } elseif ($subNames.ContainsKey($sid)) { $subNames[$sid] } else { $sid }
            $subs.Add([pscustomobject]@{ Id = $sid; Name = $name })
        }
    } catch {
        $errors.Add(@{ Stage = "resourcegraph"; Error = (Format-Exception $_) })
        Write-Progress2 "Management-group subscription resolution failed ($(Format-Exception $_))."
    }
} elseif ($SingleSubscriptionId) {
    $name = if ($subNames.ContainsKey($SingleSubscriptionId)) { $subNames[$SingleSubscriptionId] } else { $SingleSubscriptionId }
    $subs.Add([pscustomobject]@{ Id = $SingleSubscriptionId; Name = $name })
} else {
    foreach ($kv in $subNames.GetEnumerator()) {
        $subs.Add([pscustomobject]@{ Id = $kv.Key; Name = $kv.Value })
    }
}

$totalSubs = $subs.Count
$currency = "USD"
$flaggedSoFar = 0
$done = 0
Set-ScanProgress -Phase "scanning" -Total $totalSubs -Message "Querying cost for $totalSubs subscription(s)..."
Write-Progress2 "Querying cost for $totalSubs subscription(s)..."

foreach ($sub in $subs) {
    $done++
    $subId = $sub.Id
    $subName = $sub.Name

    # Refresh the ARM token if it is within ~5 minutes of expiry (long scans outlive it).
    if ($armExpires -le [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        try {
            $armTok     = Get-ArmToken
            $armExpires = $armTok.ExpiresOn
            $armHeaders = @{ Authorization = "Bearer $($armTok.Token)"; 'Content-Type' = 'application/json' }
        } catch { <# keep the current token; the request below will surface any auth error #> }
    }

    $uri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.CostManagement/query?api-version=$CostApiVersion"
    try {
        $curBody  = Build-QueryBody -Start $curStart  -End $curEnd  | ConvertTo-Json -Depth 8
        $prevBody = Build-QueryBody -Start $prevStart -End $prevEnd | ConvertTo-Json -Depth 8
        $cur  = Invoke-RestMethod -Method POST -Uri $uri -Headers $armHeaders -Body $curBody  -ErrorAction Stop
        $prev = Invoke-RestMethod -Method POST -Uri $uri -Headers $armHeaders -Body $prevBody -ErrorAction Stop
    } catch {
        $errors.Add(@{ Stage = "$subName ($subId)"; Error = (Format-Exception $_) })
        Write-Progress2 "${subName}: skipped (cost query failed: $(Format-Exception $_))"
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $totalSubs -FlaggedSoFar $flaggedSoFar `
                         -Message "${subName}: skipped (cost query failed)"
        continue
    }

    $curParsed  = Parse-Costs $cur
    $prevParsed = Parse-Costs $prev
    $curCosts  = $curParsed.Costs
    $prevCosts = $prevParsed.Costs
    if ($curParsed.Currency) { $currency = $curParsed.Currency }

    $rgKeys = @($curCosts.Keys) + @($prevCosts.Keys) | Select-Object -Unique | Sort-Object
    foreach ($rgKey in $rgKeys) {
        $currentCost  = [math]::Round((& { if ($curCosts.ContainsKey($rgKey))  { $curCosts[$rgKey]  } else { 0.0 } }), 2)
        $previousCost = [math]::Round((& { if ($prevCosts.ContainsKey($rgKey)) { $prevCosts[$rgKey] } else { 0.0 } }), 2)
        $delta = [math]::Round($currentCost - $previousCost, 2)
        $deltaPercent = if ($previousCost -gt 0) { [math]::Round($delta / $previousCost * 100, 1) }
                        elseif ($currentCost -gt 0) { 100.0 } else { 0.0 }

        $class = Get-AnomalyClass -Delta $delta -DeltaPercent $deltaPercent
        $isAnomaly = $class.IsAnomaly
        $severity  = $class.Severity
        if ($isAnomaly) { $flaggedSoFar++ }
        $rgName = if ($rgKey -eq "(unallocated)") { "(unallocated)" } else { $rgKey }

        $items.Add([ordered]@{
            SubscriptionId    = $subId
            SubscriptionName  = $subName
            ResourceGroup     = $rgName
            CurrentCost       = $currentCost
            PreviousCost      = $previousCost
            Delta             = $delta
            DeltaPercent      = $deltaPercent
            IsAnomaly         = $isAnomaly
            Currency          = $currency
            Severity          = $severity
            RecommendedAction = (Get-AnomalyAction -IsAnomaly $isAnomaly -Severity $severity -Delta $delta -DeltaPercent $deltaPercent)
        })
    }

    $pct = if ($totalSubs) { [math]::Round($done / $totalSubs * 100, 1) } else { 100.0 }
    Set-ScanProgress -Phase "scanning" -Fetched $done -Total $totalSubs -FlaggedSoFar $flaggedSoFar `
                     -Message "Processed $subName ($done/$totalSubs)..."
}

# Rank by the biggest movers (largest delta first).
$itemsSorted = @($items | Sort-Object -Property @{ Expression = { [double]$_.Delta }; Descending = $true })

#endregion

#region ── write output ─────────────────────────────────────────────────────────

$totalCost     = [math]::Round((($itemsSorted | ForEach-Object { [double]$_.CurrentCost }  | Measure-Object -Sum).Sum), 2)
$previousTotal = [math]::Round((($itemsSorted | ForEach-Object { [double]$_.PreviousCost } | Measure-Object -Sum).Sum), 2)
$overallDelta  = $totalCost - $previousTotal
$overallPct    = if ($previousTotal -gt 0) { [math]::Round($overallDelta / $previousTotal * 100, 1) }
                 elseif ($totalCost -gt 0) { 100.0 } else { 0.0 }
$anomalies     = @($itemsSorted | Where-Object { $_.IsAnomaly }).Count
$subsWithData  = @($itemsSorted | ForEach-Object { $_.SubscriptionId } | Select-Object -Unique).Count

$output = @{
    ScanMetadata = @{
        ScanTime          = $scanStartTime.ToString("o")
        CompletedTime     = (Get-Date).ToString("o")
        ScopeType         = $ScopeType
        ManagementGroupId = $ManagementGroupId
        ScopeLabel        = $scopeLabel
        WindowDays        = $WindowDays
        Subscriptions     = $subsWithData
        ResourceGroups    = $itemsSorted.Count
        TotalCost         = $totalCost
        PreviousTotal     = $previousTotal
        DeltaPercent      = $overallPct
        Anomalies         = $anomalies
        Currency          = $currency
        TotalItems        = $itemsSorted.Count
        ErrorCount        = $errors.Count
    }
    Items  = $itemsSorted
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $itemsSorted.Count -Total $itemsSorted.Count -FlaggedSoFar $anomalies -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($itemsSorted.Count) resource group(s) across $subsWithData subscription(s) — $anomalies anomaly(ies). Wrote $OutputPath"

#endregion
