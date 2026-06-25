#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Reservation Coverage & Right-Sizing scanner.

    Surfaces Azure cost-optimisation opportunities by pulling Azure Advisor recommendations
    in the *Cost* category for each in-scope subscription via the ARM REST surface. Advisor's
    cost recommendations cover three kinds of savings: buying a reservation (commit to
    steady-state usage for a discount), right-sizing an over-provisioned VM (swap to a smaller
    SKU), and shutting down an idle/underused resource.

    Each recommendation is mapped to a row with its impacted resource, the current→recommended
    SKU (when Advisor provides one), and the estimated monthly savings (Advisor reports an
    *annual* savings amount, divided to a monthly figure). Rows are ranked by savings and
    bucketed by severity.

.OUTPUTS
    JSON file at -OutputPath (default ../data/reservation-coverage-scan-results.json):
    { ScanMetadata, Items, Errors }

.NOTES
    Authentication reuses the in-memory Az context (no separate login): an ARM token is
    obtained with Get-AzAccessToken and the Microsoft.Advisor recommendations REST API is
    called directly, one subscription at a time, defensively (a failing subscription becomes a
    warning, never an abort). A management group resolves to its child subscriptions via
    Azure Resource Graph. ARM Reader is sufficient.

    Required Az modules: Az.Accounts, Az.ResourceGraph.
#>
[CmdletBinding()]
param(
    [string] $OutputPath           = "$PSScriptRoot/../data/reservation-coverage-scan-results.json",
    [string] $ProgressPath         = "",          # if set, incremental progress JSON is written here
    [ValidateSet('All','ManagementGroup','Subscription')]
    [string] $ScopeType            = "All",        # scan scope: whole tenant, one management group, or one subscription
    [string] $ManagementGroupId    = "",           # when -ScopeType ManagementGroup: the MG to recurse (all child subs)
    [string] $SingleSubscriptionId = ""            # optional: scan just one subscription
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ApiVersion = '2023-01-01'

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

# Mirrors the Python _prop(): first non-empty value among keys in a case-insensitive prop bag.
function Get-PropBag ($props, [string[]]$keys) {
    if ($null -eq $props) { return $null }
    # Build a lowercased lookup of the prop bag's keys.
    $lowered = @{}
    if ($props -is [System.Collections.IDictionary]) {
        foreach ($k in $props.Keys) { $lowered["$($k.ToString().ToLowerInvariant())"] = $props[$k] }
    } else {
        foreach ($p in $props.PSObject.Properties) { $lowered["$($p.Name.ToLowerInvariant())"] = $p.Value }
    }
    foreach ($k in $keys) {
        $lk = $k.ToLowerInvariant()
        if ($lowered.ContainsKey($lk)) {
            $v = $lowered[$lk]
            if ($null -ne $v -and "$v" -ne "") { return $v }
        }
    }
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

# ── classification (mirrors the Python classify()) ───────────────────────────────
$SHUTDOWN_HINTS    = @('shutdown', 'shut down', 'delete', 'idle', 'unattached', 'deallocat')
$RIGHTSIZE_HINTS   = @('right-size', 'right size', 'rightsize', 'resize', 'sku', 'underutil', 'under-util')
$RESERVATION_HINTS = @('reservation', 'reserved', 'savings plan', 'saving plan', 'commit')

function Get-CostCategory {
    param([string]$ShortDesc, $Props)
    $typeHint = "$(Get-PropBag $Props @('recommendationType', 'displayName'))"
    $haystack = "$ShortDesc $typeHint".ToLowerInvariant()
    foreach ($h in $SHUTDOWN_HINTS)    { if ($haystack.Contains($h)) { return 'shutdown' } }
    foreach ($h in $RIGHTSIZE_HINTS)   { if ($haystack.Contains($h)) { return 'rightsize' } }
    foreach ($h in $RESERVATION_HINTS) { if ($haystack.Contains($h)) { return 'reservation' } }
    # Cost recommendations that name a target SKU are right-sizing; otherwise the most
    # common remaining cost lever is a reservation purchase.
    if (Get-PropBag $Props @('targetSku', 'recommendedSku', 'target')) { return 'rightsize' }
    return 'reservation'
}

# Mirrors the Python severity_for(): bucket a monthly-savings amount.
function Get-CostSeverity ([double]$SavingsMonthly) {
    if ($SavingsMonthly -ge 200) { return 'high' }
    if ($SavingsMonthly -ge 50)  { return 'medium' }
    return 'low'
}

# Mirrors the Python recommended_action() + _ACTION_BY_CATEGORY.
function Get-CostAction {
    param([string]$Category, [string]$CurrentSku, [string]$RecommendedSku)
    switch ($Category) {
        'reservation' {
            return @{ Action = 'Buy reservation'; Reason = 'Steady-state usage qualifies for a reserved-instance / savings-plan discount.' }
        }
        'rightsize' {
            if ($CurrentSku -and $RecommendedSku) {
                return @{ Action = 'Right-size resource'; Reason = "Move $CurrentSku -> $RecommendedSku to cut spend without losing headroom." }
            }
            return @{ Action = 'Right-size resource'; Reason = 'Resource is over-provisioned — move to a smaller SKU to cut spend.' }
        }
        'shutdown' {
            return @{ Action = 'Shut down / delete'; Reason = 'Resource is idle or underused — deallocate or remove it to stop paying for it.' }
        }
        default {
            return @{ Action = 'Review opportunity'; Reason = 'Azure Advisor flagged a cost-saving opportunity.' }
        }
    }
}

# ── resource-id parsing (mirrors the Python _*_from_id() helpers) ─────────────────
function Get-RgFromId ([string]$ResourceId) {
    if ($ResourceId -match '(?i)/resourcegroups/([^/]+)') { return $Matches[1] }
    return ""
}
function Get-NameFromId ([string]$ResourceId) {
    $trimmed = ($ResourceId -replace '/+$', '')
    if (-not $trimmed) { return "" }
    return ($trimmed -split '/')[-1]
}
function Get-TypeFromId ([string]$ResourceId) {
    if ($ResourceId -match '(?i)/providers/([^/]+)/([^/]+)/[^/]+$') { return "$($Matches[1])/$($Matches[2])" }
    return ""
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

$scopeLabel = if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) { "management group '$ManagementGroupId' (recursive)" }
              elseif ($SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }

Set-ScanProgress -Phase "init" -Message "Acquiring ARM token..."
Write-Progress2 "Reservation Coverage & Right-Sizing scan — scope: $scopeLabel"
Write-Progress2 "Acquiring ARM token from the active Az session..."
$armTok     = Get-ArmToken
$armExpires = $armTok.ExpiresOn
$armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }

# ── subscription name map ────────────────────────────────────────────────────
$subNames = @{}
try {
    foreach ($s in Get-AzSubscription -ErrorAction Stop) {
        if ($s.State -eq 'Enabled') { $subNames["$($s.Id)"] = "$($s.Name)" }
    }
} catch {
    $errors.Add(@{ Stage = "subscriptions"; Error = (Format-Exception $_) })
}

# ── resolve the subscription set ──────────────────────────────────────────────
# A single subscription restricts to one; a management group recurses to all its child
# subscriptions (via Resource Graph, since Advisor's REST surface is per-subscription);
# otherwise the scan spans every accessible subscription.
$subs = [System.Collections.Generic.List[object]]::new()
if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) {
    if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
        throw "Azure Resource Graph (Search-AzGraph) is unavailable. Install it with: Install-Module Az.ResourceGraph -Scope CurrentUser"
    }
    Write-Progress2 "Resolving child subscriptions of management group '$ManagementGroupId' via Resource Graph..."
    try {
        $kql  = "ResourceContainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId = tostring(subscriptionId), name = tostring(name)"
        $rows = [System.Collections.Generic.List[object]]::new()
        $skip = $null
        do {
            $page = if ($skip) { Search-AzGraph -Query $kql -ManagementGroup $ManagementGroupId -First 1000 -SkipToken $skip -ErrorAction Stop }
                    else        { Search-AzGraph -Query $kql -ManagementGroup $ManagementGroupId -First 1000 -ErrorAction Stop }
            foreach ($r in @($page)) { $rows.Add($r) }
            $skip = if ($page.PSObject.Properties['SkipToken']) { $page.SkipToken } else { $null }
        } while ($skip)
        foreach ($r in $rows) {
            $sid = "$(Get-Prop $r 'subscriptionId')"
            if (-not $sid) { continue }
            $nm = "$(Get-Prop $r 'name')"; if (-not $nm) { $nm = if ($subNames.ContainsKey($sid)) { $subNames[$sid] } else { $sid } }
            $subs.Add([pscustomobject]@{ Id = $sid; Name = $nm })
        }
    } catch {
        $errors.Add(@{ Stage = "resourcegraph"; Error = (Format-Exception $_) })
        Write-Progress2 "Management-group resolution failed ($(Format-Exception $_))."
    }
} elseif ($SingleSubscriptionId) {
    $name = if ($subNames.ContainsKey($SingleSubscriptionId)) { $subNames[$SingleSubscriptionId] } else { $SingleSubscriptionId }
    $subs.Add([pscustomobject]@{ Id = $SingleSubscriptionId; Name = $name })
} else {
    foreach ($k in $subNames.Keys) { $subs.Add([pscustomobject]@{ Id = $k; Name = $subNames[$k] }) }
}

$totalSubs = $subs.Count
Set-ScanProgress -Phase "scanning" -Total $totalSubs -Message "Scanning Advisor cost recommendations across $totalSubs subscription(s)..."
Write-Progress2 "Scanning Advisor cost recommendations across $totalSubs subscription(s)..."

$counts       = [ordered]@{ reservation = 0; rightsize = 0; shutdown = 0 }
$totalSavings = 0.0
$currency     = "USD"
$done         = 0

foreach ($sub in $subs) {
    $done++
    $subId   = $sub.Id
    $subName = $sub.Name

    # Refresh the ARM token if it is within ~5 minutes of expiry (long scans outlive it).
    if ($armExpires -le [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        try {
            $armTok     = Get-ArmToken
            $armExpires = $armTok.ExpiresOn
            $armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }
        } catch { <# keep the current token; the request below will surface any auth error #> }
    }

    try {
        # Read all Advisor recommendations for the subscription (paged via nextLink).
        $recs  = [System.Collections.Generic.List[object]]::new()
        $uri   = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Advisor/recommendations?api-version=$ApiVersion"
        $guard = 0
        while ($uri -and $guard -lt 50) {
            $guard++
            $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $armHeaders -ErrorAction Stop
            foreach ($v in @(Get-Prop $resp 'value')) { $recs.Add($v) }
            $next = Get-Prop $resp 'nextLink'
            $uri  = if ($next) { [string]$next } else { "" }
        }

        foreach ($rec in $recs) {
            $props = Get-Prop $rec 'properties'
            if (("$(Get-Prop $props 'category')").ToLowerInvariant() -ne 'cost') { continue }

            # short_description.solution || .problem
            $short     = Get-Prop $props 'shortDescription'
            $shortDesc = "$(Get-Prop $short 'solution')"
            if (-not $shortDesc) { $shortDesc = "$(Get-Prop $short 'problem')" }

            $extProps = Get-Prop $props 'extendedProperties'

            $resMeta    = Get-Prop $props 'resourceMetadata'
            $resourceId = "$(Get-Prop $resMeta 'resourceId')"
            if (-not $resourceId) { $resourceId = "$(Get-Prop $rec 'id')" }

            $category = Get-CostCategory -ShortDesc $shortDesc -Props $extProps

            # Advisor reports an *annual* savings amount on cost recs; fall back to a plain
            # savings amount when present, and divide annual → monthly.
            $annual = ConvertTo-Num (Get-PropBag $extProps @('annualSavingsAmount', 'annualSavings'))
            $flat   = ConvertTo-Num (Get-PropBag $extProps @('savingsAmount', 'monthlySavingsAmount', 'savings'))
            $savingsMonthly = if ($annual) { [math]::Round($annual / 12.0, 2) } else { [math]::Round($flat, 2) }

            $cur = Get-PropBag $extProps @('savingsCurrency', 'currency')
            if ($cur) { $currency = "$cur" }

            $currentSku     = "$(Get-PropBag $extProps @('currentSku', 'sourceSku', 'fromSku'))"
            $recommendedSku = "$(Get-PropBag $extProps @('targetSku', 'recommendedSku', 'toSku'))"

            $resourceName = "$(Get-PropBag $extProps @('resourceName', 'name'))"
            if (-not $resourceName) { $resourceName = Get-NameFromId $resourceId }
            if (-not $resourceName) { $resourceName = '(subscription-wide)' }

            $resourceType = "$(Get-PropBag $extProps @('resourceType'))"
            if (-not $resourceType) { $resourceType = Get-TypeFromId $resourceId }
            $rg = Get-RgFromId $resourceId

            $severity = Get-CostSeverity $savingsMonthly
            $counts[$category] = $counts[$category] + 1
            $totalSavings += $savingsMonthly

            $itemId = "$(Get-Prop $rec 'id')"
            if (-not $itemId) { $itemId = $resourceId }
            if (-not $itemId) { $itemId = "${subId}:$($items.Count)" }

            $items.Add([ordered]@{
                Id                = $itemId
                ResourceName      = $resourceName
                ResourceType      = $resourceType
                SubscriptionId    = $subId
                SubscriptionName  = $subName
                ResourceGroup     = $rg
                Category          = $category
                CurrentSku        = $currentSku
                RecommendedSku    = $recommendedSku
                SavingsMonthly    = $savingsMonthly
                Currency          = $currency
                Severity          = $severity
                RecommendedAction = (Get-CostAction -Category $category -CurrentSku $currentSku -RecommendedSku $recommendedSku)
            })
        }
    } catch {
        $errors.Add(@{ Stage = "$subName ($subId)"; Error = "could not read Advisor recommendations: $(Format-Exception $_)" })
        Write-Progress2 "Skipped $subName ($subId): $(Format-Exception $_)"
    }

    Set-ScanProgress -Phase "scanning" -Fetched $done -Total $totalSubs -FlaggedSoFar $items.Count `
                     -Message "Scanned $subName ($done/$totalSubs)..."
}

# Rank by monthly savings, highest first (mirrors the Python items.sort()).
$sorted = @($items | Sort-Object -Property { $_.SavingsMonthly } -Descending)
$items.Clear()
foreach ($s in $sorted) { $items.Add($s) }

#endregion

#region ── write output ─────────────────────────────────────────────────────────

$output = @{
    ScanMetadata = @{
        ScanTime                  = $scanStartTime.ToString("o")
        CompletedTime             = (Get-Date).ToString("o")
        ScopeType                 = $ScopeType
        ManagementGroupId         = $ManagementGroupId
        ScopeLabel                = $scopeLabel
        Subscriptions             = $totalSubs
        Opportunities             = $items.Count
        TotalMonthlySavings       = [math]::Round($totalSavings, 2)
        ReservationOpportunities  = $counts['reservation']
        RightsizingOpportunities  = $counts['rightsize']
        ShutdownOpportunities     = $counts['shutdown']
        Currency                  = $currency
        TotalItems                = $items.Count
        ErrorCount                = $errors.Count
    }
    Items  = $items
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -FlaggedSoFar $items.Count -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) opportunity(ies) across $totalSubs subscription(s) — est. $([math]::Round($totalSavings,2)) $currency/mo. Wrote $OutputPath"

#endregion
