#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Availability-Zone & Redundancy Resilience Audit scanner. Audits VMs, managed disks,
    storage accounts, and public IPs for availability-zone / redundancy single-points-of-
    failure via a single scope-aware Resource Graph query, ranked by blast radius.
.OUTPUTS
    JSON at -OutputPath (default ../data/resilience-scan-results.json): { ScanMetadata, Items, Errors }
.NOTES
    Reuses the in-memory Az context (no separate login). ARM Reader is enough. Scope params
    mirror the other Resource-Graph scanners so the shared /api/resilience/scan endpoint
    can pass them straight through.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = "$PSScriptRoot/../data/resilience-scan-results.json",
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

$scanStartTime = Get-Date
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

$scopeLabel = if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) { "management group '$ManagementGroupId'" }
              elseif ($ResourceGroup -and $SingleSubscriptionId) { "$SingleSubscriptionId / $ResourceGroup" }
              elseif ($SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }
Set-ScanProgress -Phase "scanning" -Message "Scanning ($scopeLabel)..."
Write-Progress2 "Availability-Zone & Redundancy Resilience Audit — scope: $scopeLabel"

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

if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
    throw "Azure Resource Graph (Search-AzGraph) is unavailable. Install it with: Install-Module Az.ResourceGraph -Scope CurrentUser"
}

# StrictMode-safe nested read (Search-AzGraph rows are PSCustomObjects).
function Get-Prop ($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] } else { return $null } }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

# ── friendly labels + blast-radius weight per audited type ──
$kindLabels = @{
    'microsoft.compute/virtualmachines'   = 'Virtual machine'
    'microsoft.compute/disks'             = 'Managed disk'
    'microsoft.storage/storageaccounts'   = 'Storage account'
    'microsoft.network/publicipaddresses' = 'Public IP'
}
$auditedTypes = @($kindLabels.Keys)
# Blast-radius weight: how much downstream impact a zone fault on this resource carries.
$blastWeight = @{
    'microsoft.compute/virtualmachines'   = 5   # whole workload offline
    'microsoft.compute/disks'             = 4   # data + the VM it backs
    'microsoft.storage/storageaccounts'   = 3   # shared data plane
    'microsoft.network/publicipaddresses' = 2   # ingress / addressing
}
$sevWeight = @{ high = 3; medium = 2; low = 1; ok = 0 }

# Classify a row's redundancy posture → @{ ZoneStatus; Redundancy; Finding; Severity }
function Get-ResilienceVerdict ($rtype, $skuName, $zones) {
    $rtype    = ("$rtype").ToLowerInvariant()
    $skuUpper = ("$skuName").ToUpperInvariant()
    $hasZones = $false
    if ($null -ne $zones) {
        if ($zones -is [System.Collections.IEnumerable] -and $zones -isnot [string]) {
            $hasZones = @($zones).Count -gt 0
        } else {
            $hasZones = [bool]("$zones".Trim())
        }
    }

    switch ($rtype) {
        'microsoft.compute/virtualmachines' {
            if ($hasZones) { return @{ ZoneStatus = 'zonal'; Redundancy = 'Zonal'; Finding = ''; Severity = 'ok' } }
            return @{ ZoneStatus = 'single-zone'; Redundancy = 'Single-zone'
                     Finding = 'VM is not pinned to an availability zone — a zone outage takes it offline.'; Severity = 'high' }
        }
        'microsoft.compute/disks' {
            $red = if ($skuName) { $skuName } else { 'Unknown' }
            if ($skuUpper -match 'ZRS') { return @{ ZoneStatus = 'zone-redundant'; Redundancy = $red; Finding = ''; Severity = 'ok' } }
            if ($skuUpper -match 'LRS') {
                return @{ ZoneStatus = 'single-zone'; Redundancy = $red
                         Finding = 'Managed disk uses LRS — data is confined to a single zone with no zone-redundant copy.'; Severity = 'high' }
            }
            return @{ ZoneStatus = (if ($hasZones) { 'zone-redundant' } else { 'single-zone' }); Redundancy = $red; Finding = ''; Severity = 'ok' }
        }
        'microsoft.storage/storageaccounts' {
            $red = if ($skuName) { $skuName } else { 'Unknown' }
            if ($skuUpper -match 'LRS') {
                return @{ ZoneStatus = 'single-zone'; Redundancy = $red
                         Finding = 'Storage account uses LRS — locally-redundant only, lost if its zone fails.'; Severity = 'medium' }
            }
            return @{ ZoneStatus = 'zone-redundant'; Redundancy = $red; Finding = ''; Severity = 'ok' }
        }
        'microsoft.network/publicipaddresses' {
            $sku = if ($skuName) { $skuName } else { 'Standard' }
            if ($sku.ToLowerInvariant() -eq 'basic') {
                return @{ ZoneStatus = 'none'; Redundancy = 'Basic'
                         Finding = 'Basic-SKU public IP — no zone redundancy and slated for retirement.'; Severity = 'medium' }
            }
            return @{ ZoneStatus = 'zone-redundant'; Redundancy = $sku; Finding = ''; Severity = 'ok' }
        }
    }
    # Unknown type — treat as resilient rather than flag noise.
    return @{ ZoneStatus = 'none'; Redundancy = (if ($skuName) { $skuName } else { 'Unknown' }); Finding = ''; Severity = 'ok' }
}

function Get-ResilienceRecommendation ($kindLabel, $finding, $severity) {
    if ($severity -eq 'ok' -or -not $finding) { return @{ Action = 'Keep'; Reason = 'Resource is zone-resilient.' } }
    switch ($kindLabel) {
        'Virtual machine' { return @{ Action = 'Redeploy zonal / add zone redundancy'; Reason = 'Pin the VM to a zone or front it with a zone-redundant scale set.' } }
        'Managed disk'    { return @{ Action = 'Migrate disk to ZRS'; Reason = 'Move from LRS to a zone-redundant disk SKU for zone-fault tolerance.' } }
        'Storage account' { return @{ Action = 'Upgrade to ZRS/GZRS'; Reason = 'Convert the account from LRS to a zone-redundant SKU.' } }
        'Public IP'       { return @{ Action = 'Upgrade to Standard zone-redundant'; Reason = 'Replace the Basic public IP with a zone-redundant Standard SKU.' } }
    }
    return @{ Action = 'Review redundancy'; Reason = $finding }
}

# One Resource Graph query for all redundancy-sensitive resources in scope (joined to the subscription name).
$typesList = ($auditedTypes | ForEach-Object { "'$_'" }) -join ', '
$kql = @"
Resources
| where type in~ ($typesList)
$rgClause| extend sub = tostring(subscriptionId)
| join kind=leftouter (ResourceContainers | where type == 'microsoft.resources/subscriptions' | project sub = tostring(subscriptionId), subName = tostring(name)) on sub
| project id, name, type = tolower(type), rg = tostring(resourceGroup), sub, subName, location, skuName = tostring(sku.name), zones
"@

Write-Progress2 "Querying redundancy-sensitive resources via Resource Graph..."
$rows = [System.Collections.Generic.List[object]]::new()
try {
    $skip = $null
    do {
        $page = if ($skip) { Search-AzGraph -Query $kql -First 1000 -SkipToken $skip @graphArgs -ErrorAction Stop }
                else        { Search-AzGraph -Query $kql -First 1000 @graphArgs -ErrorAction Stop }
        foreach ($r in $page) { $rows.Add($r) }
        $skip = if ($page.PSObject.Properties['SkipToken']) { $page.SkipToken } else { $null }
    } while ($skip)
} catch {
    $errors.Add(@{ Stage = "resourcegraph"; Error = (Format-Exception $_) })
    Write-Progress2 "Resource Graph query failed ($(Format-Exception $_))."
}

$total = $rows.Count
Set-ScanProgress -Phase "scanning" -Total $total -Message "Evaluating $total resource(s)..."

$subSet = [System.Collections.Generic.HashSet[string]]::new()
$atRisk = 0; $singleZone = 0; $nonRedundantStorage = 0; $basicSku = 0; $resilient = 0; $done = 0

foreach ($r in $rows) {
    $done++
    $rtype     = ("$(Get-Prop $r 'type')").ToLowerInvariant()
    $skuName   = "$(Get-Prop $r 'skuName')"
    $kindLabel = if ($kindLabels.ContainsKey($rtype)) { $kindLabels[$rtype] }
                 elseif ($rtype) { ($rtype -split '/')[-1] } else { 'Resource' }
    $verdict   = Get-ResilienceVerdict $rtype $skuName (Get-Prop $r 'zones')
    $severity  = $verdict.Severity

    if ($severity -eq 'ok') {
        $resilient++
    } else {
        $atRisk++
        if ($verdict.ZoneStatus -eq 'single-zone' -and $rtype -in @('microsoft.compute/virtualmachines', 'microsoft.compute/disks')) { $singleZone++ }
        if ($rtype -eq 'microsoft.storage/storageaccounts')   { $nonRedundantStorage++ }
        if ($rtype -eq 'microsoft.network/publicipaddresses') { $basicSku++ }
    }

    # Blast radius: resource-type weight × severity weight (0 when resilient).
    $blast = (if ($blastWeight.ContainsKey($rtype)) { $blastWeight[$rtype] } else { 1 }) * $sevWeight[$severity]

    $sub = "$(Get-Prop $r 'sub')"
    if ($sub) { [void]$subSet.Add($sub) }
    $subName = "$(Get-Prop $r 'subName')"; if (-not $subName) { $subName = $sub }

    $items.Add([ordered]@{
        Id                = "$(Get-Prop $r 'id')"
        Name              = "$(Get-Prop $r 'name')"
        ResourceType      = $rtype
        KindLabel         = $kindLabel
        SubscriptionId    = $sub
        SubscriptionName  = $subName
        ResourceGroup     = "$(Get-Prop $r 'rg')"
        Location          = "$(Get-Prop $r 'location')"
        ZoneStatus        = $verdict.ZoneStatus
        Redundancy        = $verdict.Redundancy
        Finding           = $verdict.Finding
        Severity          = $severity
        BlastRadius       = $blast
        RecommendedAction = (Get-ResilienceRecommendation $kindLabel $verdict.Finding $severity)
    })

    if ($done % 50 -eq 0 -or $done -eq $total) {
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar $atRisk -Message "Evaluated $done resource(s)..."
    }
}

# ── write output ──────────────────────────────────────────────────────────────
$output = @{
    ScanMetadata = @{
        ScanTime            = $scanStartTime.ToString("o")
        CompletedTime       = (Get-Date).ToString("o")
        ScopeType           = $ScopeType
        ManagementGroupId   = $ManagementGroupId
        ScopeLabel          = $scopeLabel
        Subscriptions       = $subSet.Count
        ResourcesScanned    = $total
        AtRisk              = $atRisk
        SingleZone          = $singleZone
        NonRedundantStorage = $nonRedundantStorage
        BasicSku            = $basicSku
        Resilient           = $resilient
        TotalItems          = $items.Count
        ErrorCount          = $errors.Count
    }
    Items  = $items
    Errors = $errors
}
Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) item(s). Wrote $OutputPath"
