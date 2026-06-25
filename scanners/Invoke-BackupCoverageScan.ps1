#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Backup & DR Coverage scanner. Cross-references every virtual machine against Recovery
    Services protected items (both via Resource Graph) to find VMs with no Azure Backup
    configured, plus the last recovery point and backup health for those that do.
.OUTPUTS
    JSON at -OutputPath (default ../data/backup-coverage-scan-results.json): { ScanMetadata, Items, Errors }
.NOTES
    Reuses the in-memory Az context (no separate login). ARM Reader + Backup Reader cover it.
    Scope params mirror the other scanners so the shared /api/backup/scan endpoint can pass
    them straight through.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = "$PSScriptRoot/../data/backup-coverage-scan-results.json",
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
Write-Progress2 "Backup & DR Coverage scan — scope: $scopeLabel"

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

# StrictMode-safe nested read (Search-AzGraph rows are PSCustomObjects / dictionaries).
function Get-Prop ($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] } else { return $null } }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

# Run a paged Search-AzGraph query, returning every row across all pages.
function Invoke-GraphPaged ([string]$Query) {
    $rows = [System.Collections.Generic.List[object]]::new()
    $skip = $null
    do {
        $page = if ($skip) { Search-AzGraph -Query $Query -First 1000 -SkipToken $skip @graphArgs -ErrorAction Stop }
                else        { Search-AzGraph -Query $Query -First 1000 @graphArgs -ErrorAction Stop }
        foreach ($r in $page) { $rows.Add($r) }
        $skip = if ($page.PSObject.Properties['SkipToken']) { $page.SkipToken } else { $null }
    } while ($skip)
    return $rows
}

# ── one Resource Graph query for all VMs in scope (joined to the subscription name) ──
$vmKql = @"
Resources
| where type =~ 'microsoft.compute/virtualmachines'
$rgClause| extend sub = tostring(subscriptionId)
| join kind=leftouter (ResourceContainers | where type == 'microsoft.resources/subscriptions' | project sub = tostring(subscriptionId), subName = tostring(name)) on sub
| project id, name, rg = tostring(resourceGroup), sub, subName, location, powerState = tostring(properties.extended.instanceView.powerState.displayStatus), osType = tostring(properties.storageProfile.osDisk.osType)
"@

Write-Progress2 "Querying virtual machines via Resource Graph..."
$vms = [System.Collections.Generic.List[object]]::new()
try {
    $vms = Invoke-GraphPaged $vmKql
} catch {
    $errors.Add(@{ Stage = "resourcegraph-vms"; Error = (Format-Exception $_) })
    Write-Progress2 "VM Resource Graph query failed ($(Format-Exception $_))."
}

# ── second query: Recovery Services protected items, keyed by lowercased source resource id ──
$protectedKql = @"
recoveryservicesresources
| where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems'
| project src = tolower(tostring(properties.sourceResourceId)), vaultId = tostring(properties.vaultId), policyName = tostring(properties.policyName), lastBackup = tostring(properties.lastRecoveryPoint), health = tostring(properties.healthStatus), protectionState = tostring(properties.protectionState)
"@

Write-Progress2 "Querying Recovery Services protected items..."
$protectedMap = @{}
try {
    $protectedRows = Invoke-GraphPaged $protectedKql
    foreach ($p in $protectedRows) {
        $src = "$(Get-Prop $p 'src')"
        if ($src) { $protectedMap[$src] = $p }
    }
} catch {
    # The recoveryservicesresources table may be unavailable without Backup Reader.
    $errors.Add(@{ Stage = "resourcegraph-protecteditems"; Error = (Format-Exception $_) })
    Write-Progress2 "Recovery Services query failed ($(Format-Exception $_))."
}

$total = $vms.Count
Set-ScanProgress -Phase "scanning" -Total $total -Message "Evaluating $total VM(s)..."

$subSet = [System.Collections.Generic.HashSet[string]]::new()
$protected = 0; $unprotected = 0; $unhealthy = 0; $done = 0

foreach ($vm in $vms) {
    $done++
    $vid = "$(Get-Prop $vm 'id')".ToLowerInvariant()
    $p   = if ($vid -and $protectedMap.ContainsKey($vid)) { $protectedMap[$vid] } else { $null }
    $isProtected = ($null -ne $p)

    $health = if ($isProtected) { "$(Get-Prop $p 'health')" } else { "" }
    # "Passed" or an empty health string is treated as healthy.
    $healthy = $isProtected -and ($health.ToLowerInvariant() -in @('passed', ''))

    if ($isProtected) {
        $protected++
        if (-not $healthy) { $unhealthy++ }
        if ($healthy) {
            $severity = 'ok'
            $rec = @{ Action = 'Keep'; Reason = 'Backup configured.' }
        } else {
            $severity = 'medium'
            $rec = @{ Action = 'Check backup health'; Reason = "Backup health is '$health'. Investigate failed or stale recovery points." }
        }
    } else {
        $unprotected++
        $severity = 'high'
        $rec = @{ Action = 'Enable backup'; Reason = 'VM has no Azure Backup protection configured.' }
    }

    $sub = "$(Get-Prop $vm 'sub')"
    if ($sub) { [void]$subSet.Add($sub) }
    $subName = "$(Get-Prop $vm 'subName')"; if (-not $subName) { $subName = $sub }

    $powerState = "$(Get-Prop $vm 'powerState')" -replace 'VM ', ''
    if (-not $powerState) { $powerState = '—' }

    $lastBackup = if ($isProtected) { "$(Get-Prop $p 'lastBackup')" } else { "" }
    $healthStatus = if ($health) { $health } elseif ($isProtected) { 'Passed' } else { '—' }

    $items.Add([ordered]@{
        Id                = "$(Get-Prop $vm 'id')"
        Name              = "$(Get-Prop $vm 'name')"
        ResourceGroup     = "$(Get-Prop $vm 'rg')"
        SubscriptionId    = $sub
        SubscriptionName  = $subName
        Location          = "$(Get-Prop $vm 'location')"
        OsType            = "$(Get-Prop $vm 'osType')"
        PowerState        = $powerState
        Protected         = $isProtected
        PolicyName        = if ($isProtected) { "$(Get-Prop $p 'policyName')" } else { "" }
        LastBackup        = $lastBackup
        HealthStatus      = $healthStatus
        ProtectionState   = if ($isProtected) { "$(Get-Prop $p 'protectionState')" } else { "" }
        Severity          = $severity
        RecommendedAction = $rec
    })

    if ($done % 50 -eq 0 -or $done -eq $total) {
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar $unprotected -Message "Evaluated $done VM(s)..."
    }
}

$coverage = if ($total -gt 0) { [math]::Round(($protected / $total) * 100, 1) } else { 100.0 }

# ── write output ──────────────────────────────────────────────────────────────
$output = @{
    ScanMetadata = @{
        ScanTime          = $scanStartTime.ToString("o")
        CompletedTime     = (Get-Date).ToString("o")
        ScopeType         = $ScopeType
        ManagementGroupId = $ManagementGroupId
        ScopeLabel        = $scopeLabel
        Subscriptions     = $subSet.Count
        VmsScanned        = $total
        Protected         = $protected
        Unprotected       = $unprotected
        Unhealthy         = $unhealthy
        CoveragePercent   = $coverage
        TotalItems        = $items.Count
        ErrorCount        = $errors.Count
    }
    Items  = $items
    Errors = $errors
}
Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) VM(s). Wrote $OutputPath"
