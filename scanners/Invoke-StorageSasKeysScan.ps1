#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Storage Account Active SAS Keys scanner.

    Azure does not track issued SAS *tokens* (they're minted client-side), so this scans the
    queryable basis for account/service SAS — the account access keys that sign them. A storage
    account is flagged when shared-key access is ENABLED (allowSharedKeyAccess != false — the
    prerequisite for account-key SAS) AND it has an active, unexpired signing key: either no
    key-expiration policy (keys never expire → always active) or a key still within
    keyPolicy.keyExpirationPeriodInDays of its keyCreationTime.

.OUTPUTS
    JSON at -OutputPath (default ../data/storage-sas-keys-scan-results.json): { ScanMetadata, Items, Errors }
.NOTES
    ARM Reader is sufficient (Resource Graph only). Scope params mirror the other tools.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = "$PSScriptRoot/../data/storage-sas-keys-scan-results.json",
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
#endregion

$scanStartTime = Get-Date
$nowUtc = (Get-Date).ToUniversalTime()
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

# ── scope → Resource Graph args + RG clause ──────────────────────────────────
$graphArgs = @{}
$rgClause  = ""
$scopeLabel = "all accessible subscriptions"
if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) {
    $graphArgs['ManagementGroup'] = $ManagementGroupId
    $scopeLabel = "management group '$ManagementGroupId'"
} elseif ($ScopeType -eq 'ResourceGroup' -and $SingleSubscriptionId -and $ResourceGroup) {
    $graphArgs['Subscription'] = $SingleSubscriptionId
    $rgClause = "| where resourceGroup =~ '$($ResourceGroup -replace "'", "''")' "
    $scopeLabel = "$SingleSubscriptionId / $ResourceGroup"
} elseif ($SingleSubscriptionId) {
    $graphArgs['Subscription'] = $SingleSubscriptionId
    $scopeLabel = "subscription '$SingleSubscriptionId'"
}
Set-ScanProgress -Phase "scanning" -Message "Scanning storage accounts ($scopeLabel)..."
Write-Progress2 "Storage Account Active SAS Keys scan — scope: $scopeLabel"

if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
    throw "Azure Resource Graph (Search-AzGraph) is unavailable. Install it with: Install-Module Az.ResourceGraph -Scope CurrentUser"
}

# One Resource Graph query: the SAS-relevant key properties per storage account.
$kql = @"
Resources
| where type =~ 'microsoft.storage/storageaccounts'
$rgClause| extend sub = tostring(subscriptionId)
| join kind=leftouter (ResourceContainers | where type == 'microsoft.resources/subscriptions' | project sub = tostring(subscriptionId), subName = tostring(name)) on sub
| project id, name, rg = tostring(resourceGroup), sub, subName, location, skuName = tostring(sku.name),
  allowSharedKeyAccess = properties.allowSharedKeyAccess,
  keyExpirationDays    = properties.keyPolicy.keyExpirationPeriodInDays,
  key1Created          = properties.keyCreationTime.key1,
  key2Created          = properties.keyCreationTime.key2,
  sasExpirationPeriod  = tostring(properties.sasPolicy.sasExpirationPeriod)
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

# Returns @{ Expiry=[datetime]|$null; Unexpired=[bool]; Known=[bool] } for one account key.
function Get-KeyState ($created, $keyExpDays) {
    if ($null -eq $keyExpDays) { return @{ Expiry = $null; Unexpired = $true; Known = $true } }  # no policy → never expires
    if (-not $created) { return @{ Expiry = $null; Unexpired = $true; Known = $false } }          # policy set but rotation time unknown → assume active
    try {
        $c = [datetimeoffset]::Parse("$created").UtcDateTime
        $exp = $c.AddDays([double]$keyExpDays)
        return @{ Expiry = $exp; Unexpired = ($exp -gt $nowUtc); Known = $true }
    } catch {
        return @{ Expiry = $null; Unexpired = $true; Known = $false }
    }
}
function Format-Expiry ($state) {
    if (-not $state.Known) { return "unknown" }
    if ($null -eq $state.Expiry) { return "never" }
    return $state.Expiry.ToString("yyyy-MM-dd")
}

$flagged = 0; $sharedKeyEnabledCount = 0; $noPolicyCount = 0; $withinPolicyCount = 0; $done = 0
$subSet = [System.Collections.Generic.HashSet[string]]::new()

foreach ($sa in $rows) {
    $done++
    $sharedKeyEnabled = Test-StorageBool (Get-Prop $sa 'allowSharedKeyAccess') $true
    $keyExpRaw = Get-Prop $sa 'keyExpirationDays'
    $keyExpDays = if ($null -ne $keyExpRaw -and "$keyExpRaw" -ne '') { [int]$keyExpRaw } else { $null }
    $sasPeriod  = "$(Get-Prop $sa 'sasExpirationPeriod')"

    $k1 = Get-KeyState (Get-Prop $sa 'key1Created') $keyExpDays
    $k2 = Get-KeyState (Get-Prop $sa 'key2Created') $keyExpDays
    $anyUnexpired = ($k1.Unexpired -or $k2.Unexpired)
    $activeUnexpiredKey = ($sharedKeyEnabled -and $anyUnexpired)

    if ($sharedKeyEnabled) { $sharedKeyEnabledCount++ }

    if (-not $sharedKeyEnabled) {
        $severity = 'ok'
        $rec = @{ Action = 'Keep'; Reason = 'Shared-key access is disabled — account-key SAS cannot be issued (Entra ID auth only).' }
    } elseif ($null -eq $keyExpDays) {
        $noPolicyCount++
        $severity = 'high'
        $rec = @{ Action = 'Disable shared key / set key-expiration policy'; Reason = 'Shared-key access is enabled with NO key-expiration policy — account-key SAS tokens can be minted and never expire. Disable shared-key access (prefer Entra ID auth) or set keyPolicy.keyExpirationPeriodInDays and rotate.' }
    } elseif ($anyUnexpired) {
        $withinPolicyCount++
        $severity = 'medium'
        $rec = @{ Action = 'Rotate keys / disable shared key'; Reason = "Shared-key access is enabled and at least one access key is still within its $keyExpDays-day expiration window — SAS signed with it remains valid. Rotate keys and consider disabling shared-key access." }
    } else {
        $severity = 'low'
        $rec = @{ Action = 'Rotate or disable shared key'; Reason = "Shared-key access is enabled but both access keys are past the $keyExpDays-day expiration policy. Rotate them or disable shared-key access." }
    }

    if ($activeUnexpiredKey) { $flagged++ }

    $sub = "$(Get-Prop $sa 'sub')"
    if ($sub) { [void]$subSet.Add($sub) }
    $subName = "$(Get-Prop $sa 'subName')"; if (-not $subName) { $subName = $sub }
    $items.Add([ordered]@{
        Id                 = "$(Get-Prop $sa 'id')"
        Name               = "$(Get-Prop $sa 'name')"
        ResourceGroup      = "$(Get-Prop $sa 'rg')"
        SubscriptionId     = $sub
        SubscriptionName   = $subName
        Location           = "$(Get-Prop $sa 'location')"
        Sku                = "$(Get-Prop $sa 'skuName')"
        SharedKeyEnabled   = $sharedKeyEnabled
        KeyExpirationDays  = $(if ($null -eq $keyExpDays) { 0 } else { $keyExpDays })
        HasKeyExpiryPolicy = ($null -ne $keyExpDays)
        Key1Expiry         = (Format-Expiry $k1)
        Key2Expiry         = (Format-Expiry $k2)
        SasExpirationPolicy = $sasPeriod
        ActiveUnexpiredKey = $activeUnexpiredKey
        Severity           = $severity
        RecommendedAction  = $rec
    })
    if ($done % 50 -eq 0 -or $done -eq $total) {
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar $flagged -Message "Evaluated $done account(s)..."
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
        Flagged           = $flagged
        SharedKeyEnabled  = $sharedKeyEnabledCount
        NoKeyExpiryPolicy = $noPolicyCount
        KeysWithinPolicy  = $withinPolicyCount
        TotalItems        = $items.Count
        ErrorCount        = $errors.Count
    }
    Items  = $items
    Errors = $errors
}
Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -FlaggedSoFar $flagged -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $total account(s), $flagged with an active unexpired SAS-signing key. Wrote $OutputPath"
