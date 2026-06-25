#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Resource deployment tracker.

    Reads `Microsoft.Resources/deployments/write` events from the Azure Activity Log
    over a lookback window and lists each deployment with its timestamp, target
    resource group, outcome (Succeeded/Failed), and — the point of the tool — *who*
    ran it, classified as a human **User** (the caller is a UPN) vs an automated
    **Service principal** (the caller is an app/object GUID, e.g. a CI pipeline or
    managed identity). The frontend can then filter user-driven vs automated change.

    Scope is subscription-targetable: the whole tenant, one management group (all its
    child subscriptions), or a single subscription. Needs only READER on the
    subscriptions (enough to read the Activity Log).

.OUTPUTS
    JSON file at -OutputPath (default ../data/deployment-tracker-scan-results.json):
    { ScanMetadata, Items, Errors }

.NOTES
    Authentication reuses the in-memory Az context (no separate login): an ARM token is
    obtained with Get-AzAccessToken and the Microsoft.Insights eventtypes/management REST
    API is called directly per subscription. This is NOT a Resource-Graph tool for its
    data (Resource Graph is used only to resolve a management group's child subscriptions).

    Required Az modules: Az.Accounts, Az.ResourceGraph.
#>
[CmdletBinding()]
param(
    [string] $OutputPath           = "$PSScriptRoot/../data/deployment-tracker-scan-results.json",
    [string] $ProgressPath         = "",          # if set, incremental progress JSON is written here
    [ValidateSet('All','ManagementGroup','Subscription')]
    [string] $ScopeType            = "All",        # scan scope: whole tenant, one management group, or one subscription
    [string] $ManagementGroupId    = "",           # when -ScopeType ManagementGroup: the MG to recurse (all child subs)
    [string] $SingleSubscriptionId = "",          # optional: scan just one subscription
    [int]    $LookbackDays         = 30           # how far back to read deployment events
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ApiVersion       = '2015-04-01'
$DeploymentOp     = 'microsoft.resources/deployments/write'
$GuidRegex        = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

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

# Classify an Activity Log caller as User (UPN), ServicePrincipal (GUID), or Unknown.
# Mirrors the Python caller_type().
function Get-CallerType ([string]$Caller) {
    if (-not $Caller) { return 'Unknown' }
    if ($Caller.Contains('@')) { return 'User' }
    if ($Caller.Trim() -match $GuidRegex) { return 'ServicePrincipal' }
    return 'Unknown'
}

# Last path segment of a resource id (the deployment name). Mirrors the Python _last_segment().
function Get-LastSegment ([string]$ResourceId) {
    if (-not $ResourceId) { return '' }
    $trimmed = $ResourceId.TrimEnd('/')
    if (-not $trimmed) { return '' }
    return ($trimmed -split '/')[-1]
}

# Recommended action per deployment. Mirrors the Python recommendation().
function Get-DeploymentAction {
    param([string]$Status, [string]$CallerType)
    if ($Status -eq 'Failed') {
        return @{ Action = 'Investigate failure'; Reason = 'Deployment failed — review the deployment operation details and redeploy.' }
    }
    if ($CallerType -eq 'User') {
        return @{ Action = 'Review'; Reason = 'Deployment made interactively by a user; prefer pipeline-driven change for auditability.' }
    }
    return @{ Action = 'Keep'; Reason = 'Deployment completed successfully.' }
}

# Read an Activity Log "value" property whose value may itself be wrapped as { value, localizedValue }.
function Get-EventValue ($obj, [string]$name) {
    $v = Get-Prop $obj $name
    if ($null -eq $v) { return '' }
    $inner = Get-Prop $v 'value'
    if ($null -ne $inner) { return [string]$inner }
    return [string]$v
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

$scopeLabel = if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) { "management group '$ManagementGroupId' (recursive)" }
              elseif ($SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              elseif ($ScopeType -eq 'Subscription' -and $SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }

Set-ScanProgress -Phase "init" -Message "Acquiring ARM token..."
Write-Progress2 "Deployment tracker scan — scope: $scopeLabel, lookback $LookbackDays day(s)"
Write-Progress2 "Acquiring ARM token from the active Az session..."
$armTok     = Get-ArmToken
$armExpires = $armTok.ExpiresOn
$armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }

# ── subscription name map (cosmetic display names) ────────────────────────────
$subNames = @{}
try {
    foreach ($s in Get-AzSubscription -ErrorAction Stop) {
        if ($s.State -eq 'Enabled') { $subNames["$($s.Id)"] = "$($s.Name)" }
    }
} catch {
    $errors.Add(@{ Stage = "subscriptions"; Error = (Format-Exception $_) })
}

# ── resolve the subscription set ──────────────────────────────────────────────
# A management group recurses to all its child subscriptions (via Resource Graph);
# a single subscription restricts to one; otherwise the scan spans every accessible
# subscription. -SingleSubscriptionId still works on its own even when -ScopeType is All.
$subIds = [System.Collections.Generic.List[string]]::new()
if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) {
    if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
        throw "Azure Resource Graph (Search-AzGraph) is unavailable. Install it with: Install-Module Az.ResourceGraph -Scope CurrentUser"
    }
    Write-Progress2 "Resolving child subscriptions of management group '$ManagementGroupId' via Resource Graph..."
    try {
        $kql = "ResourceContainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name | order by name asc"
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
            if ($sid) {
                $subIds.Add($sid)
                if (-not $subNames.ContainsKey($sid) -and $r.name) { $subNames[$sid] = "$($r.name)" }
            }
        }
    } catch {
        $errors.Add(@{ Stage = "resourcegraph"; Error = (Format-Exception $_) })
        Write-Progress2 "Management-group resolution failed ($(Format-Exception $_))."
    }
} elseif ($SingleSubscriptionId) {
    $subIds.Add($SingleSubscriptionId)
    if (-not $subNames.ContainsKey($SingleSubscriptionId)) { $subNames[$SingleSubscriptionId] = $SingleSubscriptionId }
} else {
    Write-Progress2 "Listing subscriptions..."
    try {
        foreach ($s in Get-AzSubscription -ErrorAction Stop) {
            if ($s.State -eq 'Enabled') { $subIds.Add("$($s.Id)") }
        }
    } catch {
        $errors.Add(@{ Stage = "subscriptions"; Error = (Format-Exception $_) })
    }
}

$totalSubs = $subIds.Count
if ($totalSubs -eq 0) {
    $errors.Add(@{ Stage = "scope"; Error = "No subscriptions were visible to scan." })
}

# ── time window + Activity Log filter ─────────────────────────────────────────
$start = [DateTimeOffset]::UtcNow.AddDays(-$LookbackDays)
$end   = [DateTimeOffset]::UtcNow
$filter = "eventTimestamp ge '$($start.ToString("o"))' and eventTimestamp le '$($end.ToString("o"))' and resourceProvider eq 'Microsoft.Resources'"
$select = "eventTimestamp,operationName,status,caller,resourceGroupName,resourceId,correlationId"

Set-ScanProgress -Phase "scanning" -Total $totalSubs -Message "Reading deployment events for $totalSubs subscription(s)..."
Write-Progress2 "Reading deployment events for $totalSubs subscription(s)..."

$failedCount = 0; $done = 0

foreach ($subId in $subIds) {
    $done++
    $subName = if ($subNames.ContainsKey($subId)) { $subNames[$subId] } else { $subId }

    # Refresh the ARM token if it is within ~5 minutes of expiry (long scans outlive it).
    if ($armExpires -le [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        try {
            $armTok     = Get-ArmToken
            $armExpires = $armTok.ExpiresOn
            $armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }
        } catch { <# keep the current token; the request below will surface any auth error #> }
    }

    # Per correlationId, keep only the latest terminal (Succeeded/Failed) deployment event.
    $seen = @{}   # key -> latest record (carries a hidden _Ts for the latest-wins comparison)
    try {
        $base = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Insights/eventtypes/management/values?api-version=$ApiVersion"
        $sep  = [Uri]::EscapeDataString($filter)
        $selEnc = [Uri]::EscapeDataString($select)
        $uri  = "$base&`$filter=$sep&`$select=$selEnc"
        $guard = 0
        while ($uri -and $guard -lt 200) {
            $guard++
            $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $armHeaders -ErrorAction Stop
            foreach ($e in @(Get-Prop $resp 'value')) {
                $op = (Get-EventValue $e 'operationName').ToLower()
                if ($op -ne $DeploymentOp) { continue }
                $status = Get-EventValue $e 'status'
                if (@('succeeded','failed') -notcontains $status.ToLower()) { continue }

                $tsRaw = Get-Prop $e 'eventTimestamp'
                $ts = if ($tsRaw) { [DateTimeOffset]$tsRaw } else { $null }
                $resourceId = [string](Get-Prop $e 'resourceId')
                $corr = [string](Get-Prop $e 'correlationId')
                $key = if ($corr) { $corr } elseif ($resourceId -or $ts) { "$resourceId$(if ($ts) { $ts.ToString("o") })" } else { "" }

                $prev = $null
                if ($seen.ContainsKey($key)) { $prev = $seen[$key] }
                if ($null -eq $prev -or ($ts -and $prev._Ts -and $ts -gt $prev._Ts)) {
                    $caller = [string](Get-Prop $e 'caller')
                    $ctype  = Get-CallerType $caller
                    # Normalize the status to title case (Succeeded / Failed).
                    $statusNorm = if ($status.ToLower() -eq 'failed') { 'Failed' } else { 'Succeeded' }
                    $severity = if ($statusNorm -eq 'Failed') { 'high' } else { 'ok' }
                    $seen[$key] = [pscustomobject]@{
                        _Ts               = $ts
                        DeploymentName    = (Get-LastSegment $resourceId)
                        OperationName     = (Get-EventValue $e 'operationName')
                        SubscriptionId    = $subId
                        SubscriptionName  = $subName
                        ResourceGroup     = [string](Get-Prop $e 'resourceGroupName')
                        ResourceId        = $resourceId
                        Caller            = $caller
                        CallerType        = $ctype
                        Status            = $statusNorm
                        Timestamp         = if ($ts) { $ts.ToString("o") } else { "" }
                        CorrelationId     = $corr
                        Severity          = $severity
                        RecommendedAction = (Get-DeploymentAction -Status $statusNorm -CallerType $ctype)
                    }
                }
            }
            $next = Get-Prop $resp 'nextLink'
            $uri = if ($next) { [string]$next } else { "" }
        }

        foreach ($rec in $seen.Values) {
            if ($rec.Status -eq 'Failed') { $failedCount++ }
            $items.Add([ordered]@{
                DeploymentName    = $rec.DeploymentName
                OperationName     = $rec.OperationName
                SubscriptionId    = $rec.SubscriptionId
                SubscriptionName  = $rec.SubscriptionName
                ResourceGroup     = $rec.ResourceGroup
                ResourceId        = $rec.ResourceId
                Caller            = $rec.Caller
                CallerType        = $rec.CallerType
                Status            = $rec.Status
                Timestamp         = $rec.Timestamp
                CorrelationId     = $rec.CorrelationId
                Severity          = $rec.Severity
                RecommendedAction = $rec.RecommendedAction
            })
        }
    } catch {
        $errors.Add(@{ Stage = "$subName ($subId)"; Error = (Format-Exception $_) })
        Write-Progress2 "Could not read deployment events for $subName ($subId): $(Format-Exception $_)"
    }

    Set-ScanProgress -Phase "scanning" -Fetched $done -Total $totalSubs -FlaggedSoFar $failedCount `
                     -Message "Scanned $done/$totalSubs subscription(s) — $($items.Count) deployment(s)..."
}

# Newest deployments first.
$sorted = @($items | Sort-Object -Property @{ Expression = { $_.Timestamp }; Descending = $true })

#endregion

#region ── write output ─────────────────────────────────────────────────────────

$succeeded = 0; $failed = 0; $users = 0; $sps = 0
$callerSet = [System.Collections.Generic.HashSet[string]]::new()
foreach ($it in $sorted) {
    if ($it.Status -eq 'Succeeded') { $succeeded++ } elseif ($it.Status -eq 'Failed') { $failed++ }
    if ($it.CallerType -eq 'User') { $users++ } elseif ($it.CallerType -eq 'ServicePrincipal') { $sps++ }
    if ($it.Caller) { [void]$callerSet.Add($it.Caller) }
}

$output = @{
    ScanMetadata = @{
        ScanTime                    = $scanStartTime.ToString("o")
        CompletedTime               = (Get-Date).ToString("o")
        ScopeType                   = $ScopeType
        ManagementGroupId           = $ManagementGroupId
        ScopeLabel                  = $scopeLabel
        LookbackDays                = $LookbackDays
        SubscriptionsScanned        = $totalSubs
        TotalDeployments            = $sorted.Count
        Succeeded                   = $succeeded
        Failed                      = $failed
        UserDeployments             = $users
        ServicePrincipalDeployments = $sps
        DistinctCallers             = $callerSet.Count
        TotalItems                  = $sorted.Count
        ErrorCount                  = $errors.Count
    }
    Items  = $sorted
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $sorted.Count -Total $sorted.Count -FlaggedSoFar $failedCount -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($sorted.Count) deployment(s) across $totalSubs subscription(s) — $failed failed, $users user, $sps service-principal. Wrote $OutputPath"

#endregion
