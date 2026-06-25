#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    VNet flow-log coverage scanner.

    Enumerates every virtual network in the chosen scope (Resource Graph) and cross-references
    it against the flow logs configured in Network Watcher. A VNet with no flow log — or one
    whose flow log exists but is **disabled** — is flagged, because without VNet flow logs there
    is no record of the traffic in/out of that network (no forensics, no anomaly detection).

    This is the coverage counterpart to the VNet Flow Logs Analyzer: that tool visualises the
    traffic in one flow log; this one tells you which VNets aren't being logged at all. ARM
    Reader is sufficient (discovery only — no blob reads).

.OUTPUTS
    JSON file at -OutputPath (default ../data/vnet-flow-coverage-scan-results.json):
    { ScanMetadata, Items, Errors }

.NOTES
    Reuses the in-memory Az context (no separate login). Scope params mirror the other scanners
    so the shared /api/vnetflowcoverage/scan endpoint can pass them straight through.

    Required Az modules: Az.Accounts, Az.ResourceGraph.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = "$PSScriptRoot/../data/vnet-flow-coverage-scan-results.json",
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

#region ── helpers ────────────────────────────────────────────────────────────────

# StrictMode-safe nested read (Search-AzGraph rows are PSCustomObjects).
function Get-Prop ($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] } else { return $null } }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

function Test-FlowBool ($v, [bool]$default = $false) {
    if ($null -eq $v) { return $default }
    if ($v -is [bool]) { return $v }
    return (("$v").Trim().ToLowerInvariant() -in @('true', '1', 'yes'))
}

# Last path segment of a resource id (the storage account name from a storageId).
function Get-NameFromResourceId ([string]$id) {
    if (-not $id) { return "" }
    $parts = ($id -split '/') | Where-Object { $_ }
    if ($parts.Count) { return $parts[-1] }
    return ""
}

# Page a Resource Graph query to exhaustion (Search-AzGraph caps a page at 1000 rows).
function Invoke-GraphPaged ([string]$Query, [hashtable]$GraphArgs) {   # NOT $Args — that is a reserved automatic variable, binding would fail
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

# Mirrors the Python recommendation().
function Get-CoverageAction {
    param([string]$State, [string]$FlowLogName)
    if ($State -eq 'covered') {
        return @{ Action = 'Keep'; Reason = "VNet flow log '$FlowLogName' is enabled." }
    }
    if ($State -eq 'disabled') {
        return @{
            Action = 'Enable flow log'
            Reason = "A VNet flow log ('$FlowLogName') is configured but disabled — turn it back on to restore traffic visibility."
        }
    }
    return @{
        Action = 'Enable flow log'
        Reason = "No VNet flow log is configured. Add one (Network Watcher → Flow logs) so inbound/outbound traffic is recorded for forensics and detection."
    }
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

$scopeLabel = if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) { "management group '$ManagementGroupId'" }
              elseif ($ResourceGroup -and $SingleSubscriptionId) { "$SingleSubscriptionId / $ResourceGroup" }
              elseif ($SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }
Set-ScanProgress -Phase "init" -Message "Scanning ($scopeLabel)..."
Write-Progress2 "VNet flow-log coverage scan — scope: $scopeLabel"

if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
    throw "Azure Resource Graph (Search-AzGraph) is unavailable. Install it with: Install-Module Az.ResourceGraph -Scope CurrentUser"
}

# ── scope → Resource Graph args + RG clause (mirrors the Python scope helper) ──
$graphArgs = @{}
$rgClause  = ""
if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) {
    $graphArgs['ManagementGroup'] = $ManagementGroupId
} elseif ($ScopeType -eq 'ResourceGroup' -and $SingleSubscriptionId -and $ResourceGroup) {
    $graphArgs['Subscription'] = $SingleSubscriptionId
    $rgClause = "| where resourceGroup =~ '$($ResourceGroup -replace "'", "''")' "
} elseif ($SingleSubscriptionId) {
    $graphArgs['Subscription'] = $SingleSubscriptionId
}

# 1) Configured flow logs (tenant-wide; matched to VNets by target id). A VNet flow log's
#    targetResourceId points at the VNet regardless of which RG the Network Watcher lives in,
#    so this cross-reference holds no matter the scan scope. Build target-id → best flow log
#    (preferring an enabled one if a VNet somehow has more than one).
Set-ScanProgress -Phase "flow-logs" -Message "Discovering configured flow logs..."
Write-Progress2 "Discovering configured flow logs..."
$byTarget = @{}
try {
    $flKql = @"
resources
| where type =~ 'microsoft.network/networkwatchers/flowlogs'
| project id, name, location, enabled = tobool(properties.enabled), targetResourceId = tostring(properties.targetResourceId), storageId = tostring(properties.storageId)
"@
    foreach ($row in (Invoke-GraphPaged -Query $flKql -GraphArgs @{})) {
        $target = "$(Get-Prop $row 'targetResourceId')"
        if ($target.ToLowerInvariant() -notlike '*/virtualnetworks/*') { continue }   # vnet_only
        $key = $target.ToLowerInvariant()
        if (-not $key) { continue }
        $enabled = Test-FlowBool (Get-Prop $row 'enabled')
        $storageId = "$(Get-Prop $row 'storageId')"
        $fl = [pscustomobject]@{
            Name           = "$(Get-Prop $row 'name')"
            Enabled        = $enabled
            StorageAccount = (Get-NameFromResourceId $storageId)
        }
        $existing = $byTarget[$key]
        if ($null -eq $existing -or ($fl.Enabled -and -not $existing.Enabled)) { $byTarget[$key] = $fl }
    }
} catch {
    $errors.Add(@{ Stage = "flowlogs"; Error = (Format-Exception $_) })
    Write-Progress2 "Could not list flow logs — every VNet will be reported as uncovered. ($(Format-Exception $_))"
}

# 2) Every VNet in scope (joined to the subscription name).
Set-ScanProgress -Phase "inventory" -Message "Querying virtual networks via Resource Graph..."
Write-Progress2 "Querying virtual networks via Resource Graph..."
$vnKql = @"
Resources
| where type =~ 'microsoft.network/virtualnetworks'
$rgClause| extend sub = tostring(subscriptionId), rg = tostring(resourceGroup)
| join kind=leftouter (ResourceContainers | where type == 'microsoft.resources/subscriptions' | project sub = tostring(subscriptionId), subName = tostring(name)) on sub
| project id, name, rg, sub, subName, location
"@
$rows = [System.Collections.Generic.List[object]]::new()
try {
    $rows = Invoke-GraphPaged -Query $vnKql -GraphArgs $graphArgs
} catch {
    $errors.Add(@{ Stage = "resourcegraph"; Error = (Format-Exception $_) })
    Write-Progress2 "Resource Graph query failed ($(Format-Exception $_))."
}

$total = $rows.Count
Set-ScanProgress -Phase "scanning" -Total $total -Message "Checking $total virtual network(s)..."

$subSet = [System.Collections.Generic.HashSet[string]]::new()
$covered = 0; $noConfig = 0; $disabled = 0; $done = 0

foreach ($vn in $rows) {
    $done++
    $vnetId = "$(Get-Prop $vn 'id')"
    $fl = $byTarget[$vnetId.ToLowerInvariant()]

    if ($null -eq $fl) {
        $state = 'no_config'; $severity = 'high'; $flowLogName = ''; $storageAccount = ''; $noConfig++
    } elseif (-not $fl.Enabled) {
        $state = 'disabled'; $severity = 'medium'; $flowLogName = $fl.Name; $storageAccount = $fl.StorageAccount; $disabled++
    } else {
        $state = 'covered'; $severity = 'ok'; $flowLogName = $fl.Name; $storageAccount = $fl.StorageAccount; $covered++
    }

    $sub = "$(Get-Prop $vn 'sub')"
    if ($sub) { [void]$subSet.Add($sub) }
    $subName = "$(Get-Prop $vn 'subName')"; if (-not $subName) { $subName = $sub }

    $items.Add([ordered]@{
        Id                = $vnetId
        Name              = "$(Get-Prop $vn 'name')"
        ResourceGroup     = "$(Get-Prop $vn 'rg')"
        SubscriptionId    = $sub
        SubscriptionName  = $subName
        Location          = "$(Get-Prop $vn 'location')"
        Coverage          = $state              # covered | disabled | no_config
        HasFlowLog        = ($null -ne $fl)
        FlowLogEnabled    = ($state -eq 'covered')
        FlowLogName       = $flowLogName
        StorageAccount    = $storageAccount
        Severity          = $severity
        RecommendedAction = (Get-CoverageAction -State $state -FlowLogName $flowLogName)
    })

    if ($done % 50 -eq 0 -or $done -eq $total) {
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar ($noConfig + $disabled) -Message "Checked $done VNet(s)..."
    }
}

#endregion

#region ── write output ─────────────────────────────────────────────────────────

$uncovered = $noConfig + $disabled
$coveragePercent = if ($total) { [math]::Round(($covered / $total) * 100, 1) } else { 100.0 }

$output = @{
    ScanMetadata = @{
        ScanTime          = $scanStartTime.ToString("o")
        CompletedTime     = (Get-Date).ToString("o")
        ScopeType         = $ScopeType
        ManagementGroupId = $ManagementGroupId
        ScopeLabel        = $scopeLabel
        Subscriptions     = $subSet.Count
        VnetsScanned      = $total
        Covered           = $covered
        Uncovered         = $uncovered
        NoFlowLog         = $noConfig
        DisabledFlowLog   = $disabled
        CoveragePercent   = $coveragePercent
        TotalItems        = $items.Count
        ErrorCount        = $errors.Count
    }
    Items  = $items
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -FlaggedSoFar $uncovered -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) VNet(s) — $covered covered, $uncovered uncovered ($noConfig no log, $disabled disabled). Wrote $OutputPath"

#endregion
