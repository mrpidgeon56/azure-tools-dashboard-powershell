#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Resource & Service Health scanner. A live operational view that fuses two Azure
    health signals, each read in one Resource Graph pass:

      - Resource Health (healthresources) — per-resource availability as Azure sees it:
        Available / Degraded / Unavailable / Unknown, with the platform's reason and
        summary. Surfaces individual resources that are currently impaired.
      - Service Health (servicehealthresources) — active platform events affecting the
        tenant's subscriptions and regions: service issues (outages), planned
        maintenance, and health/security advisories.

    Both feed one item list with a Kind discriminator so an operator sees, in one place,
    "which of my resources are unhealthy" and "is Azure itself having a problem."
.OUTPUTS
    JSON at -OutputPath (default ../data/resource-health-scan-results.json): { ScanMetadata, Items, Errors }
.NOTES
    Reuses the in-memory Az context (no separate login). Needs ARM Reader. The Service
    Health table is best-effort (reported as an error/warning if unavailable) so a missing
    permission never fails the whole scan.

    Required Az modules: Az.Accounts, Az.ResourceGraph.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = "$PSScriptRoot/../data/resource-health-scan-results.json",
    [string] $ProgressPath = "",
    [ValidateSet('All','ManagementGroup','Subscription','ResourceGroup')]
    [string] $ScopeType = "All",
    [string] $ManagementGroupId = "",
    [string] $SingleSubscriptionId = "",
    [string] $ResourceGroup = ""
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

#region ── helpers (mirror the Python normalization/labelling) ────────────────────

# StrictMode-safe nested read (Search-AzGraph rows + their `properties` are PSCustomObjects).
function Get-Prop ($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] } else { return $null } }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

# .NET DateTime ticks (100ns intervals since 0001-01-01) at the Unix epoch.
$script:UnixEpochTicks = 621355968000000000L

# Service Health timestamps arrive as .NET ticks; normalize to ISO-8601. Resource Health
# already returns ISO strings, so pass those through unchanged.
function ConvertTo-NormTime ($value) {
    if ($null -eq $value) { return $null }
    $s = ("$value").Trim()
    if (-not $s) { return $null }
    if ($s -match '^\d+$') {
        $ticks = [long]$s
        # Ticks at/below the Unix epoch are zero/sentinel values (e.g. an unset
        # ImpactMitigationTime serializes as 0 → year 0001) — treat as missing.
        if ($ticks -lt $script:UnixEpochTicks) { return $null }
        try {
            $unixSeconds = ($ticks - $script:UnixEpochTicks) / 1e7
            return [System.DateTimeOffset]::FromUnixTimeMilliseconds([long]([math]::Round($unixSeconds * 1000))).UtcDateTime.ToString("o")
        } catch { return $null }
    }
    # ISO string: an unset datetime serializes as the year-0001 min value.
    if ($s.StartsWith("0001-01-01")) { return $null }
    return $s
}

# Service Health summaries are HTML — reduce to readable plain text.
function ConvertTo-PlainText ($text) {
    if ($null -eq $text -or -not "$text") { return "" }
    $cleaned = [regex]::Replace("$text", '<[^>]+>', ' ')
    $cleaned = $cleaned.Replace('&nbsp;', ' ').Replace('&amp;', '&').Replace('&lt;', '<').Replace('&gt;', '>').Replace('&#39;', "'").Replace('&quot;', '"')
    return ([regex]::Replace($cleaned, '\s+', ' ')).Trim()
}

# Resource Health availability → severity.
$script:AvailSeverity = @{ unavailable = 'high'; degraded = 'medium'; unknown = 'low'; available = 'ok' }

# Service Health event type → friendly label.
$script:EventLabels = @{
    serviceissue       = 'Service issue'
    plannedmaintenance = 'Planned maintenance'
    healthadvisory     = 'Health advisory'
    securityadvisory   = 'Security advisory'
    emergingissue      = 'Emerging issue'
}

function Get-AvailLabel ([string]$state) {
    $s = ("$state").Trim()
    if (-not $s) { return "Unknown" }
    return $s.Substring(0, 1).ToUpperInvariant() + $s.Substring(1)
}

function Get-EventLabel ([string]$eventType) {
    $e = ("$eventType").Trim()
    $key = $e.ToLowerInvariant()
    if ($script:EventLabels.ContainsKey($key)) { return $script:EventLabels[$key] }
    if ($e) { return $e } else { return "Event" }
}

function Get-ResourceAction ([string]$state) {
    switch (("$state").ToLowerInvariant()) {
        'unavailable' { return @{ Action = "Investigate"; Reason = "Resource is reported Unavailable by Azure Resource Health." } }
        'degraded'    { return @{ Action = "Investigate"; Reason = "Resource is reported Degraded — partial impairment." } }
        'unknown'     { return @{ Action = "Check";       Reason = "Azure can't determine this resource's health (often stopped or newly created)." } }
        default       { return @{ Action = "Keep";        Reason = "Resource is Available." } }
    }
}

function Get-EventAction ([string]$eventType) {
    switch (("$eventType").ToLowerInvariant()) {
        'plannedmaintenance' { return @{ Action = "Prepare"; Reason = "Planned maintenance affecting your resources — review the maintenance window." } }
        'securityadvisory'   { return @{ Action = "Review";  Reason = "Security advisory affecting services you use." } }
        'serviceissue'       { return @{ Action = "Monitor"; Reason = "Active Azure service issue affecting your subscriptions/regions." } }
        default              { return @{ Action = "Review";  Reason = "Active Azure health advisory affecting your services." } }
    }
}

# Page through Search-AzGraph (SkipToken) so large tenants aren't silently truncated.
function Invoke-GraphPaged ([string]$Query, [hashtable]$GraphArgs) {
    $rows = [System.Collections.Generic.List[object]]::new()
    $skip = $null
    do {
        $page = if ($skip) { Search-AzGraph -Query $Query -First 1000 -SkipToken $skip @GraphArgs -ErrorAction Stop }
                else        { Search-AzGraph -Query $Query -First 1000 @GraphArgs -ErrorAction Stop }
        foreach ($r in @($page)) { $rows.Add($r) }
        $skip = if ($page.PSObject.Properties['SkipToken']) { $page.SkipToken } else { $null }
    } while ($skip)
    return $rows
}
#endregion

#region ── main scan ──────────────────────────────────────────────────────────────
$scanStartTime = Get-Date
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

$scopeLabel = if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) { "management group '$ManagementGroupId'" }
              elseif ($ResourceGroup -and $SingleSubscriptionId) { "$SingleSubscriptionId / $ResourceGroup" }
              elseif ($SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }
Set-ScanProgress -Phase "init" -Message "Scanning ($scopeLabel)..."
Write-Progress2 "Resource & Service Health scan — scope: $scopeLabel"

# ── scope → Resource Graph args + RG clause (mirrors the Python scope helper) ──
$graphArgs = @{}
$rgClause  = ""
if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) {
    $graphArgs['ManagementGroup'] = $ManagementGroupId
} elseif ($ScopeType -eq 'ResourceGroup' -and $SingleSubscriptionId -and $ResourceGroup) {
    $graphArgs['Subscription'] = $SingleSubscriptionId
    $rgClause = "| where rg =~ '$($ResourceGroup -replace "'", "''")' "
} elseif ($SingleSubscriptionId) {
    $graphArgs['Subscription'] = $SingleSubscriptionId
}

if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
    throw "Azure Resource Graph (Search-AzGraph) is unavailable. Install it with: Install-Module Az.ResourceGraph -Scope CurrentUser"
}

$sevRank = @{ high = 0; medium = 1; low = 2; ok = 3 }
$availCounts = [ordered]@{ available = 0; degraded = 0; unavailable = 0; unknown = 0 }

# ── Resource Health ───────────────────────────────────────────────────────────
Set-ScanProgress -Phase "inventory" -Message "Querying Resource Health states..."
Write-Progress2 "Querying Resource Health states via Resource Graph..."

$healthKql = @"
healthresources
| where type =~ 'microsoft.resourcehealth/availabilitystatuses'
| project targetId = tolower(tostring(properties.targetResourceId)),
  availabilityState = tostring(properties.availabilityState),
  summaryText = tostring(properties.summary),
  reasonType = tostring(properties.reasonType),
  occurredTime = tostring(properties.occurredTime)
| join kind=leftouter (Resources
  | project targetId = tolower(id), rname = name, rtype = type,
    rg = tostring(resourceGroup), sub = tostring(subscriptionId), rloc = location) on targetId
| join kind=leftouter (ResourceContainers
  | where type == 'microsoft.resources/subscriptions'
  | project sub = tostring(subscriptionId), subName = tostring(name)) on sub
$rgClause
"@

$healthRows = [System.Collections.Generic.List[object]]::new()
try {
    $healthRows = Invoke-GraphPaged -Query $healthKql -GraphArgs $graphArgs
} catch {
    $errors.Add(@{ Stage = "resourcehealth"; Error = (Format-Exception $_) })
    Write-Progress2 "Resource Health query failed ($(Format-Exception $_))."
}

$total = $healthRows.Count
Set-ScanProgress -Phase "scanning" -Total $total -Message "Evaluating $total resource health state(s)..."

$i = 0
foreach ($h in $healthRows) {
    $i++
    $state = "$(Get-Prop $h 'availabilityState')"; if (-not $state) { $state = "Unknown" }
    $key = $state.ToLowerInvariant()
    if ($availCounts.Contains($key)) { $availCounts[$key]++ } else { $availCounts[$key] = 1 }

    $target = "$(Get-Prop $h 'targetId')"
    $name = "$(Get-Prop $h 'rname')"
    if (-not $name) { $name = if ($target) { ($target.TrimEnd('/') -split '/')[-1] } else { "—" } }
    $rtype = "$(Get-Prop $h 'rtype')"
    $detail = if ($rtype) { ($rtype -split '/')[-1] } else { "—" }
    $sub = "$(Get-Prop $h 'sub')"
    $subName = "$(Get-Prop $h 'subName')"; if (-not $subName) { $subName = $sub }
    $sev = if ($script:AvailSeverity.ContainsKey($key)) { $script:AvailSeverity[$key] } else { 'low' }

    $items.Add([ordered]@{
        Kind                 = "Resource Health"
        Name                 = $name
        Detail               = $detail
        ResourceType         = $rtype
        Status               = (Get-AvailLabel $state)
        ResourceGroup        = "$(Get-Prop $h 'rg')"
        SubscriptionId       = $sub
        SubscriptionName     = $subName
        Location             = "$(Get-Prop $h 'rloc')"
        Reason               = "$(Get-Prop $h 'reasonType')"
        Summary              = "$(Get-Prop $h 'summaryText')"
        OccurredTime         = (ConvertTo-NormTime (Get-Prop $h 'occurredTime'))
        ImpactMitigationTime = $null
        TrackingId           = ""
        EventType            = ""
        ResourceId           = $target
        Severity             = $sev
        RecommendedAction    = (Get-ResourceAction $state)
    })
    if ($i % 100 -eq 0 -or $i -eq $total) {
        $flagged = $availCounts['unavailable'] + $availCounts['degraded']
        Set-ScanProgress -Phase "scanning" -Fetched $i -Total $total -FlaggedSoFar $flagged -Message "Evaluated $i/$total resource(s)..."
    }
}

# ── Service Health (active events) ──────────────────────────────────────────────
Set-ScanProgress -Phase "scanning" -Fetched $total -Total $total -Message "Querying active Service Health events..."
Write-Progress2 "Querying active Service Health events via Resource Graph..."

$eventKql = @"
servicehealthresources
| where type =~ 'microsoft.resourcehealth/events'
| where tolower(tostring(properties.Status)) == 'active'
| project eventType = tostring(properties.EventType),
  status = tostring(properties.Status),
  title = tostring(properties.Title),
  eventSummary = tostring(properties.Summary),
  trackingId = tostring(properties.TrackingId),
  impactStartTime = tostring(properties.ImpactStartTime),
  impactMitigationTime = tostring(properties.ImpactMitigationTime),
  sub = tostring(subscriptionId)
| join kind=leftouter (ResourceContainers
  | where type == 'microsoft.resources/subscriptions'
  | project sub = tostring(subscriptionId), subName = tostring(name)) on sub
"@

$eventRows = [System.Collections.Generic.List[object]]::new()
$activeEvents = 0
try {
    $eventRows = Invoke-GraphPaged -Query $eventKql -GraphArgs $graphArgs
} catch {
    # The table may be unavailable (permission/feature) — degrade gracefully.
    $errors.Add(@{ Stage = "servicehealth"; Error = (Format-Exception $_) })
    Write-Progress2 "Service Health query unavailable ($(Format-Exception $_))."
}

foreach ($e in $eventRows) {
    $et = "$(Get-Prop $e 'eventType')"
    $etl = $et.ToLowerInvariant()
    $activeEvents++
    $sev = if ($etl -eq 'serviceissue') { 'high' } elseif ($etl -in @('plannedmaintenance', 'securityadvisory')) { 'medium' } else { 'low' }
    $title = "$(Get-Prop $e 'title')"; if (-not $title) { $title = (Get-EventLabel $et) }
    $status = "$(Get-Prop $e 'status')"; if (-not $status) { $status = "Active" }
    $status = [System.Globalization.CultureInfo]::InvariantCulture.TextInfo.ToTitleCase($status.ToLowerInvariant())
    $summary = (ConvertTo-PlainText (Get-Prop $e 'eventSummary')); if (-not $summary) { $summary = $title }
    $sub = "$(Get-Prop $e 'sub')"
    $subName = "$(Get-Prop $e 'subName')"; if (-not $subName) { $subName = $sub }

    $items.Add([ordered]@{
        Kind                 = "Service Health"
        Name                 = $title
        Detail               = (Get-EventLabel $et)
        ResourceType         = ""
        Status               = $status
        ResourceGroup        = ""
        SubscriptionId       = $sub
        SubscriptionName     = $subName
        Location             = ""
        Reason               = (Get-EventLabel $et)
        Summary              = $summary
        OccurredTime         = (ConvertTo-NormTime (Get-Prop $e 'impactStartTime'))
        ImpactMitigationTime = (ConvertTo-NormTime (Get-Prop $e 'impactMitigationTime'))
        TrackingId           = "$(Get-Prop $e 'trackingId')"
        EventType            = $et
        ResourceId           = ""
        Severity             = $sev
        RecommendedAction    = (Get-EventAction $et)
    })
}

# Sort: severity (high→ok), then Kind, then Name.
$sorted = $items | Sort-Object `
    @{ Expression = { $sevRank[[string]$_.Severity] } }, `
    @{ Expression = { [string]$_.Kind } }, `
    @{ Expression = { ([string]$_.Name).ToLowerInvariant() } }
$items = [System.Collections.Generic.List[object]]::new()
foreach ($s in @($sorted)) { $items.Add($s) }

#endregion

#region ── write output ─────────────────────────────────────────────────────────
$subSet = [System.Collections.Generic.HashSet[string]]::new()
foreach ($it in $items) { $sid = [string]$it.SubscriptionId; if ($sid) { [void]$subSet.Add($sid) } }

$output = @{
    ScanMetadata = @{
        ScanTime            = $scanStartTime.ToString("o")
        CompletedTime       = (Get-Date).ToString("o")
        ScopeType           = $ScopeType
        ManagementGroupId   = $ManagementGroupId
        ScopeLabel          = $scopeLabel
        Subscriptions       = $subSet.Count
        ResourcesChecked    = $total
        Unavailable         = $availCounts['unavailable']
        Degraded            = $availCounts['degraded']
        Available           = $availCounts['available']
        Unknown             = $availCounts['unknown']
        ActiveServiceEvents = $activeEvents
        TotalItems          = $items.Count
        ErrorCount          = $errors.Count
    }
    Items  = $items
    Errors = $errors
}
Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) item(s) — $($availCounts['unavailable']) unavailable, $($availCounts['degraded']) degraded, $activeEvents active event(s). Wrote $OutputPath"
#endregion
