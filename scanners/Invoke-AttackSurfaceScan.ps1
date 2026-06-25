#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Attack Surface & Public Exposure scanner. Inventories internet-facing resources via
    Resource Graph — assigned public IPs and exposed storage, SQL, Key Vault, and Cosmos
    endpoints — and ranks the tenant's external attack surface. ARM Reader is sufficient.
.OUTPUTS
    JSON at -OutputPath (default ../data/attack-surface-scan-results.json): { ScanMetadata, Items, Errors }
.NOTES
    Reuses the in-memory Az context (no separate login). Scope params mirror the other scanners
    so the shared /api/attacksurface/scan endpoint can pass them straight through.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = "$PSScriptRoot/../data/attack-surface-scan-results.json",
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
Write-Progress2 "Attack Surface & Public Exposure scan — scope: $scopeLabel"

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
function Get-ShortType ([string]$t) {
    if (-not $t) { return "" }
    return ($t -split '/')[-1]
}

# Subscription-name join, identical for every query (mirrors the Python _SUB_JOIN).
$subJoin = "| extend sub = tostring(subscriptionId) | join kind=leftouter (ResourceContainers | where type == 'microsoft.resources/subscriptions' | project sub = tostring(subscriptionId), subName = tostring(name)) on sub "

# Run a paged Resource Graph query and return all rows.
function Invoke-GraphQuery ([string]$kql, [string]$stage) {
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
        $errors.Add(@{ Stage = $stage; Error = (Format-Exception $_) })
        Write-Progress2 "Resource Graph query ($stage) failed ($(Format-Exception $_))."
    }
    return $rows
}

$kindCounts = [ordered]@{ 'Public IP' = 0; 'Public storage' = 0; 'Public SQL' = 0; 'Public Key Vault' = 0; 'Public Cosmos DB' = 0 }
$subSet     = [System.Collections.Generic.HashSet[string]]::new()

# Emit one exposure record (mirrors the Python add()).
function Add-Exposure ($row, [string]$exposure, [string]$severity, [string]$detail, [string]$endpoint = "") {
    $kindCounts[$exposure]++
    $sub = "$(Get-Prop $row 'sub')"
    if ($sub) { [void]$subSet.Add($sub) }
    $subName = "$(Get-Prop $row 'subName')"; if (-not $subName) { $subName = $sub }
    $rtype = "$(Get-Prop $row 'rtype')"; if (-not $rtype) { $rtype = "$(Get-Prop $row 'type')" }
    $rec = switch ($exposure) {
        'Public IP'        { if ($severity -eq 'medium') { @{ Action = 'Review exposure'; Reason = 'Public IP is attached to a resource — confirm it must be internet-reachable, and restrict with an NSG/firewall.' } } else { @{ Action = 'Release unused IP'; Reason = 'Public IP is reserved but not attached — release it to reduce surface and cost.' } } }
        'Public storage'   { @{ Action = 'Disable public blob access'; Reason = 'Anonymous public blob access is allowed — disable allowBlobPublicAccess unless explicitly required.' } }
        'Public SQL'       { @{ Action = 'Disable public network access'; Reason = 'SQL server is reachable from the public internet — set publicNetworkAccess to Disabled and use Private Link.' } }
        'Public Key Vault' { @{ Action = 'Restrict network access'; Reason = 'Key Vault default network action is Allow — set it to Deny and add explicit rules / Private Link.' } }
        'Public Cosmos DB' { @{ Action = 'Disable public network access'; Reason = 'Cosmos DB account is reachable from the public internet — disable public network access and use Private Link.' } }
        default            { @{ Action = 'Review exposure'; Reason = $detail } }
    }
    $items.Add([ordered]@{
        Id                = "$(Get-Prop $row 'id')"
        Name              = "$(Get-Prop $row 'name')"
        ResourceType      = (Get-ShortType $rtype)
        ResourceGroup     = "$(Get-Prop $row 'rg')"
        SubscriptionId    = $sub
        SubscriptionName  = $subName
        Location          = "$(Get-Prop $row 'location')"
        ExposureType      = $exposure
        Endpoint          = $endpoint
        Detail            = $detail
        Severity          = $severity
        RecommendedAction = $rec
    })
}

# ── Public IPs that are actually assigned ───────────────────────────────────────
Set-ScanProgress -Phase "scanning" -Message "Querying public IP addresses..."
Write-Progress2 "Querying public IP addresses..."
$kql = @"
Resources
| where type =~ 'microsoft.network/publicipaddresses'
| where isnotempty(properties.ipAddress)
$rgClause$subJoin| project id, name, rtype = type, rg = tostring(resourceGroup), sub, subName, location, ip = tostring(properties.ipAddress), attachedTo = tostring(properties.ipConfiguration.id)
"@
foreach ($r in (Invoke-GraphQuery $kql "publicips")) {
    $attached = [bool]("$(Get-Prop $r 'attachedTo')")
    $sev = if ($attached) { 'medium' } else { 'low' }
    $detail = if ($attached) { "Public IP assigned and attached to a resource." } else { "Public IP reserved but not attached." }
    Add-Exposure $r 'Public IP' $sev $detail ("$(Get-Prop $r 'ip')")
}

# ── Storage with public blob access ─────────────────────────────────────────────
Set-ScanProgress -Phase "scanning" -Message "Querying storage accounts..."
Write-Progress2 "Querying storage accounts..."
$kql = @"
Resources
| where type =~ 'microsoft.storage/storageaccounts'
| where tobool(properties.allowBlobPublicAccess) == true
$rgClause$subJoin| project id, name, rtype = type, rg = tostring(resourceGroup), sub, subName, location
"@
foreach ($r in (Invoke-GraphQuery $kql "storage")) {
    Add-Exposure $r 'Public storage' 'high' "Storage account allows anonymous public blob access." ("$(Get-Prop $r 'name').blob.core.windows.net")
}

# ── SQL servers with public network access ──────────────────────────────────────
Set-ScanProgress -Phase "scanning" -Message "Querying SQL servers..."
Write-Progress2 "Querying SQL servers..."
$kql = @"
Resources
| where type =~ 'microsoft.sql/servers'
| where tostring(properties.publicNetworkAccess) =~ 'Enabled'
$rgClause$subJoin| project id, name, rtype = type, rg = tostring(resourceGroup), sub, subName, location, fqdn = tostring(properties.fullyQualifiedDomainName)
"@
foreach ($r in (Invoke-GraphQuery $kql "sql")) {
    Add-Exposure $r 'Public SQL' 'high' "SQL server has public network access enabled." ("$(Get-Prop $r 'fqdn')")
}

# ── Key Vaults reachable from public networks ───────────────────────────────────
Set-ScanProgress -Phase "scanning" -Message "Querying Key Vaults..."
Write-Progress2 "Querying Key Vaults..."
$kql = @"
Resources
| where type =~ 'microsoft.keyvault/vaults'
| where tostring(properties.networkAcls.defaultAction) =~ 'Allow' or isnull(properties.networkAcls)
$rgClause$subJoin| project id, name, rtype = type, rg = tostring(resourceGroup), sub, subName, location, uri = tostring(properties.vaultUri)
"@
foreach ($r in (Invoke-GraphQuery $kql "keyvault")) {
    Add-Exposure $r 'Public Key Vault' 'high' "Key Vault network default action is Allow (reachable from all networks)." ("$(Get-Prop $r 'uri')")
}

# ── Cosmos DB with public network access ────────────────────────────────────────
Set-ScanProgress -Phase "scanning" -Message "Querying Cosmos DB accounts..."
Write-Progress2 "Querying Cosmos DB accounts..."
$kql = @"
Resources
| where type =~ 'microsoft.documentdb/databaseaccounts'
| where tostring(properties.publicNetworkAccess) =~ 'Enabled'
$rgClause$subJoin| project id, name, rtype = type, rg = tostring(resourceGroup), sub, subName, location, ep = tostring(properties.documentEndpoint)
"@
foreach ($r in (Invoke-GraphQuery $kql "cosmos")) {
    Add-Exposure $r 'Public Cosmos DB' 'medium' "Cosmos DB account has public network access enabled." ("$(Get-Prop $r 'ep')")
}

# ── severity rollup ─────────────────────────────────────────────────────────────
$total = $items.Count
$sevCounts = [ordered]@{ high = 0; medium = 0; low = 0 }
foreach ($it in $items) { $sevCounts[[string]$it.Severity]++ }
Set-ScanProgress -Phase "scanning" -Fetched $total -Total $total -FlaggedSoFar ($sevCounts.high + $sevCounts.medium) -Message "Found $total exposed resource(s)."

# ── write output ──────────────────────────────────────────────────────────────
$output = @{
    ScanMetadata = @{
        ScanTime          = $scanStartTime.ToString("o")
        CompletedTime     = (Get-Date).ToString("o")
        ScopeType         = $ScopeType
        ManagementGroupId = $ManagementGroupId
        ScopeLabel        = $scopeLabel
        Subscriptions     = $subSet.Count
        ExposedResources  = $total
        HighSeverity      = $sevCounts.high
        MediumSeverity    = $sevCounts.medium
        LowSeverity       = $sevCounts.low
        PublicIps         = $kindCounts['Public IP']
        PublicStorage     = $kindCounts['Public storage']
        PublicSql         = $kindCounts['Public SQL']
        PublicKeyVaults   = $kindCounts['Public Key Vault']
        PublicCosmosDb    = $kindCounts['Public Cosmos DB']
        TotalItems        = $items.Count
        ErrorCount        = $errors.Count
    }
    Items  = $items
    Errors = $errors
}
Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) item(s). Wrote $OutputPath"
