#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Storage Account Security Posture scanner. TODO: describe what it finds.
.OUTPUTS
    JSON at -OutputPath (default ../data/storage-posture-scan-results.json): { ScanMetadata, Items, Errors }
.NOTES
    Reuses the in-memory Az context (no separate login). Scope params mirror the other scanners
    so the shared /api/storage/scan endpoint can pass them straight through.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = "$PSScriptRoot/../data/storage-posture-scan-results.json",
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
Write-Progress2 "Storage Account Security Posture scan — scope: $scopeLabel"

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

# StrictMode-safe nested read (Search-AzGraph rows + their `properties` are PSCustomObjects).
function Get-Prop ($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] } else { return $null } }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}
function Test-StorageBool ($v, [bool]$default = $false) {
    if ($null -eq $v) { return $default }
    if ($v -is [bool]) { return $v }
    return (("$v").Trim().ToLowerInvariant() -in @('true', '1', 'yes'))
}

# One Resource Graph query for all storage accounts in scope (joined to the subscription name).
$kql = @"
Resources
| where type =~ 'microsoft.storage/storageaccounts'
$rgClause| extend sub = tostring(subscriptionId)
| join kind=leftouter (ResourceContainers | where type == 'microsoft.resources/subscriptions' | project sub = tostring(subscriptionId), subName = tostring(name)) on sub
| project id, name, rg = tostring(resourceGroup), sub, subName, location, kind, skuName = tostring(sku.name), properties
"@

Write-Progress2 "Querying storage accounts via Resource Graph..."
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
Set-ScanProgress -Phase "scanning" -Total $total -Message "Evaluating $total storage account(s)..."

$sevRank    = @{ high = 3; medium = 2; low = 1 }
$kindCounts = [ordered]@{ PublicAccess = 0; InsecureTransfer = 0; WeakTls = 0; OpenNetwork = 0; SharedKey = 0 }
$subSet     = [System.Collections.Generic.HashSet[string]]::new()
$atRisk = 0; $done = 0

foreach ($sa in $rows) {
    $done++
    $props    = Get-Prop $sa 'properties'
    $findings = [System.Collections.Generic.List[object]]::new()

    # allowBlobPublicAccess defaults to true on older accounts when absent.
    if (Test-StorageBool (Get-Prop $props 'allowBlobPublicAccess') $true) {
        $findings.Add(@{ Kind = 'public_access'; Severity = 'high'; Detail = 'Public blob access is allowed (anonymous containers possible).' }); $kindCounts.PublicAccess++
    }
    if (-not (Test-StorageBool (Get-Prop $props 'supportsHttpsTrafficOnly') $false)) {
        $findings.Add(@{ Kind = 'insecure_transfer'; Severity = 'high'; Detail = 'Secure transfer (HTTPS-only) is not enforced.' }); $kindCounts.InsecureTransfer++
    }
    $tls = ("$(Get-Prop $props 'minimumTlsVersion')").Trim()
    if ($tls -and $tls -notin @('TLS1_2', 'TLS1_3')) {
        $findings.Add(@{ Kind = 'weak_tls'; Severity = 'medium'; Detail = "Minimum TLS version is $tls (should be TLS1_2 or higher)." }); $kindCounts.WeakTls++
    } elseif (-not $tls) {
        $findings.Add(@{ Kind = 'weak_tls'; Severity = 'medium'; Detail = 'Minimum TLS version is not set (defaults below TLS1_2).' }); $kindCounts.WeakTls++
    }
    $defaultAction = "$(Get-Prop (Get-Prop $props 'networkAcls') 'defaultAction')"
    if (-not $defaultAction) { $defaultAction = 'Allow' }
    if ($defaultAction.Trim().ToLowerInvariant() -eq 'allow') {
        $findings.Add(@{ Kind = 'open_network'; Severity = 'medium'; Detail = 'Network default action is Allow (reachable from all networks).' }); $kindCounts.OpenNetwork++
    }
    # allowSharedKeyAccess defaults to true when absent.
    if (Test-StorageBool (Get-Prop $props 'allowSharedKeyAccess') $true) {
        $findings.Add(@{ Kind = 'shared_key'; Severity = 'low'; Detail = 'Shared-key (account key) access is enabled; prefer Entra ID auth.' }); $kindCounts.SharedKey++
    }

    $severity = 'ok'
    if ($findings.Count) {
        $atRisk++
        $severity = ($findings | Sort-Object { $sevRank[$_.Severity] } -Descending | Select-Object -First 1).Severity
        $kinds = @($findings | ForEach-Object { $_.Kind })
        $parts = @()
        if ($kinds -contains 'public_access')     { $parts += 'disable public blob access' }
        if ($kinds -contains 'insecure_transfer') { $parts += 'require secure transfer' }
        if ($kinds -contains 'weak_tls')          { $parts += 'set min TLS 1.2' }
        if ($kinds -contains 'open_network')      { $parts += 'restrict network access' }
        if ($kinds -contains 'shared_key')        { $parts += 'disable shared-key access' }
        $rec = @{ Action = 'Harden account'; Reason = (($parts -join '; ') + '.') }
    } else {
        $rec = @{ Action = 'Keep'; Reason = 'No posture issues detected.' }
    }

    $sub = "$(Get-Prop $sa 'sub')"
    if ($sub) { [void]$subSet.Add($sub) }
    $subName = "$(Get-Prop $sa 'subName')"; if (-not $subName) { $subName = $sub }
    $items.Add([ordered]@{
        Id                = "$(Get-Prop $sa 'id')"
        Name              = "$(Get-Prop $sa 'name')"
        ResourceGroup     = "$(Get-Prop $sa 'rg')"
        SubscriptionId    = $sub
        SubscriptionName  = $subName
        Location          = "$(Get-Prop $sa 'location')"
        Sku               = "$(Get-Prop $sa 'skuName')"
        Findings          = @($findings)
        FindingCount      = $findings.Count
        Severity          = $severity
        RecommendedAction = $rec
    })
    if ($done % 50 -eq 0 -or $done -eq $total) {
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar $atRisk -Message "Evaluated $done account(s)..."
    }
}

# ── write output ──────────────────────────────────────────────────────────────
$output = @{
    ScanMetadata = @{
        ScanTime          = $scanStartTime.ToString("o")
        CompletedTime     = (Get-Date).ToString("o")
        ScopeType         = $ScopeType
        ManagementGroupId = $ManagementGroupId
        ScopeLabel        = $scopeLabel
        Subscriptions     = $subSet.Count
        AccountsScanned   = $total
        AtRisk            = $atRisk
        PublicAccess      = $kindCounts.PublicAccess
        InsecureTransfer  = $kindCounts.InsecureTransfer
        WeakTls           = $kindCounts.WeakTls
        OpenNetwork       = $kindCounts.OpenNetwork
        SharedKey         = $kindCounts.SharedKey
        TotalItems        = $items.Count
        ErrorCount        = $errors.Count
    }
    Items  = $items
    Errors = $errors
}
Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) item(s). Wrote $OutputPath"
