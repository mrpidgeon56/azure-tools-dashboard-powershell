#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Monitoring coverage-gaps scanner.

    Finds resources that are observable in theory but unwired in practice: Azure
    services that support diagnostic settings but have none configured, or whose
    diagnostics don't route to a Log Analytics workspace (so they can't be queried,
    alerted on, or retained centrally).

    The candidate set is the high-value resource types expected to emit platform
    logs (Key Vault, Storage, SQL, NSGs, gateways, web apps, AKS, data services,
    messaging, ...). For each candidate we ask ARM for its diagnostic settings and
    classify it:
      * high   — no diagnostic settings at all (a true blind spot)
      * medium — diagnostics exist but none point at a Log Analytics workspace
      * ok     — at least one setting streams to Log Analytics

    VMs are intentionally excluded — they rely on the Azure Monitor Agent + DCRs
    rather than classic diagnostic settings.

.OUTPUTS
    JSON at -OutputPath (default ../data/monitoring-gaps-scan-results.json): { ScanMetadata, Items, Errors }

.NOTES
    Lists candidate resources via Resource Graph (Az.ResourceGraph), then reads each
    resource's diagnostic settings over ARM REST using the in-memory Az token. ARM
    Reader is sufficient. Scope params mirror the other graph scanners so the shared
    /api/monitoring/scan endpoint can pass them straight through.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = "$PSScriptRoot/../data/monitoring-gaps-scan-results.json",
    [string] $ProgressPath = "",
    [ValidateSet('All','ManagementGroup','Subscription','ResourceGroup')]
    [string] $ScopeType = "All",
    [string] $ManagementGroupId = "",
    [string] $SingleSubscriptionId = "",
    [string] $ResourceGroup = ""
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DiagApiVersion = '2021-05-01-preview'

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

# StrictMode-safe nested read (Search-AzGraph rows + REST responses are PSCustomObjects).
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

# Resource types that support diagnostic settings and are worth holding to a
# "should be monitored" bar. lowercase type -> short display label.
$MonitorableLabels = [ordered]@{
    'microsoft.keyvault/vaults'                       = 'Key Vault'
    'microsoft.storage/storageaccounts'               = 'Storage account'
    'microsoft.sql/servers/databases'                 = 'SQL database'
    'microsoft.sql/managedinstances'                  = 'SQL managed instance'
    'microsoft.network/networksecuritygroups'         = 'Network security group'
    'microsoft.network/applicationgateways'           = 'Application gateway'
    'microsoft.network/azurefirewalls'                = 'Azure Firewall'
    'microsoft.network/loadbalancers'                 = 'Load balancer'
    'microsoft.network/publicipaddresses'             = 'Public IP'
    'microsoft.network/frontdoors'                    = 'Front Door (classic)'
    'microsoft.cdn/profiles'                          = 'Front Door / CDN'
    'microsoft.web/sites'                             = 'App Service / Function'
    'microsoft.web/serverfarms'                       = 'App Service plan'
    'microsoft.containerservice/managedclusters'      = 'AKS cluster'
    'microsoft.documentdb/databaseaccounts'           = 'Cosmos DB'
    'microsoft.dbforpostgresql/flexibleservers'       = 'PostgreSQL flexible server'
    'microsoft.dbformysql/flexibleservers'            = 'MySQL flexible server'
    'microsoft.cache/redis'                           = 'Redis cache'
    'microsoft.servicebus/namespaces'                 = 'Service Bus namespace'
    'microsoft.eventhub/namespaces'                   = 'Event Hubs namespace'
    'microsoft.apimanagement/service'                 = 'API Management'
    'microsoft.recoveryservices/vaults'               = 'Recovery Services vault'
    'microsoft.datafactory/factories'                 = 'Data Factory'
    'microsoft.logic/workflows'                       = 'Logic App'
    'microsoft.cognitiveservices/accounts'            = 'Cognitive Services'
    'microsoft.search/searchservices'                 = 'Cognitive Search'
}

function Get-TypeLabel ([string]$ResourceType) {
    $t = ("$ResourceType").ToLowerInvariant()
    if ($MonitorableLabels.Contains($t)) { return $MonitorableLabels[$t] }
    $tail = ("$ResourceType" -split '/')[-1]
    if ($tail) { return $tail }
    return 'Resource'
}

# Mirrors the Python recommendation().
function Get-DiagAction {
    param([bool]$HasDiag, [bool]$ToLa)
    if (-not $HasDiag) {
        return @{ Action = 'Enable diagnostics'; Reason = 'No diagnostic settings — platform logs and metrics are not being collected.' }
    }
    if (-not $ToLa) {
        return @{ Action = 'Route to Log Analytics'; Reason = 'Diagnostics exist but none stream to a Log Analytics workspace, so logs can''t be queried or alerted on centrally.' }
    }
    return @{ Action = 'Keep'; Reason = 'Diagnostics stream to Log Analytics.' }
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
Set-ScanProgress -Phase "inventory" -Message "Scanning ($scopeLabel)..."
Write-Progress2 "Monitoring coverage-gaps scan — scope: $scopeLabel"

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

Write-Progress2 "Acquiring ARM token from the active Az session..."
$armTok     = Get-ArmToken
$armExpires = $armTok.ExpiresOn
$armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }

# ── one Resource Graph query for all monitorable resources in scope ──
$typeFilter = ($MonitorableLabels.Keys | ForEach-Object { "'$_'" }) -join ', '
$kql = @"
Resources
| where tolower(type) in ($typeFilter)
$rgClause| extend sub = tostring(subscriptionId)
| join kind=leftouter (ResourceContainers | where type == 'microsoft.resources/subscriptions' | project sub = tostring(subscriptionId), subName = tostring(name)) on sub
| project id, name, type, rg = tostring(resourceGroup), sub, subName, location
"@

Write-Progress2 "Listing monitorable resources via Resource Graph..."
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
Set-ScanProgress -Phase "scanning" -Total $total -Message "Checking diagnostic settings for $total resource(s)..."
Write-Progress2 "Checking diagnostic settings for $total resource(s)..."

$missingDiag = 0   # high: no diagnostic settings at all
$missingLa   = 0   # medium: diagnostics exist but none to Log Analytics
$withLa      = 0   # ok: at least one streams to Log Analytics
$unreadable  = 0   # diagnostic-settings read errored
$subSet      = [System.Collections.Generic.HashSet[string]]::new()
$done = 0

foreach ($res in $rows) {
    $done++
    $resId   = "$(Get-Prop $res 'id')"
    $resName = "$(Get-Prop $res 'name')"
    $resType = "$(Get-Prop $res 'type')"
    $sub     = "$(Get-Prop $res 'sub')"
    if ($sub) { [void]$subSet.Add($sub) }
    $subName = "$(Get-Prop $res 'subName')"; if (-not $subName) { $subName = $sub }

    # Refresh the ARM token if within ~5 minutes of expiry (long scans outlive it).
    if ($armExpires -le [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        try {
            $armTok     = Get-ArmToken
            $armExpires = $armTok.ExpiresOn
            $armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }
        } catch { <# keep current token; the request below will surface any auth error #> }
    }

    # Read the resource's diagnostic settings. A read error is reported as a warning,
    # not a scan failure, and the resource is skipped.
    $hasDiag = $false; $toLa = $false; $settingsCount = 0
    $dests = [System.Collections.Generic.SortedSet[string]]::new()
    $readOk = $true
    try {
        $uri  = "https://management.azure.com$resId/providers/microsoft.insights/diagnosticSettings?api-version=$DiagApiVersion"
        $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $armHeaders -ErrorAction Stop
        $value = @(Get-Prop $resp 'value')
        $settingsCount = $value.Count
        $hasDiag = $value.Count -gt 0
        foreach ($s in $value) {
            $props = Get-Prop $s 'properties'
            if (Get-Prop $props 'workspaceId') { [void]$dests.Add('Log Analytics'); $toLa = $true }
            if (Get-Prop $props 'storageAccountId') { [void]$dests.Add('Storage account') }
            if ((Get-Prop $props 'eventHubAuthorizationRuleId') -or (Get-Prop $props 'eventHubName')) { [void]$dests.Add('Event Hub') }
            if (Get-Prop $props 'marketplacePartnerId') { [void]$dests.Add('Partner solution') }
        }
    } catch {
        $readOk = $false
    }

    if (-not $readOk) {
        $unreadable++
        if ($unreadable -le 20) {
            $errors.Add(@{ Stage = "$resName"; Error = "could not read diagnostic settings" })
        }
    } else {
        if (-not $hasDiag) { $missingDiag++; $severity = 'high' }
        elseif (-not $toLa) { $missingLa++; $severity = 'medium' }
        else { $withLa++; $severity = 'ok' }

        $items.Add([ordered]@{
            Id                = $resId
            Name              = $resName
            ResourceType      = $resType
            TypeLabel         = (Get-TypeLabel $resType)
            ResourceGroup     = "$(Get-Prop $res 'rg')"
            SubscriptionId    = $sub
            SubscriptionName  = $subName
            Location          = "$(Get-Prop $res 'location')"
            HasDiagnostics    = $hasDiag
            ToLogAnalytics    = $toLa
            Destinations      = @($dests)
            SettingsCount     = $settingsCount
            Severity          = $severity
            RecommendedAction = (Get-DiagAction -HasDiag $hasDiag -ToLa $toLa)
        })
    }

    if ($done % 25 -eq 0 -or $done -eq $total) {
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar ($missingDiag + $missingLa) `
                         -Message "Checked $done/$total resource(s)..."
    }
}

#endregion

#region ── write output ─────────────────────────────────────────────────────────

# "Covered" = streams to Log Analytics. Coverage is over the resources we could read.
$scanned  = $withLa + $missingDiag + $missingLa
$coverage = if ($scanned -gt 0) { [math]::Round(($withLa / $scanned) * 100, 1) } else { 100.0 }

$output = @{
    ScanMetadata = @{
        ScanTime            = $scanStartTime.ToString("o")
        CompletedTime       = (Get-Date).ToString("o")
        ScopeType           = $ScopeType
        ManagementGroupId   = $ManagementGroupId
        ScopeLabel          = $scopeLabel
        Subscriptions       = $subSet.Count
        ResourcesScanned    = $scanned
        Covered             = $withLa
        MissingDiagnostics  = $missingDiag
        MissingLogAnalytics = $missingLa
        CoveragePercent     = $coverage
        Unreadable          = $unreadable
        TotalItems          = $items.Count
        ErrorCount          = $errors.Count
    }
    Items  = $items
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -FlaggedSoFar ($missingDiag + $missingLa) -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) resource(s) — $missingDiag blind, $missingLa off-LA, $coverage% covered. Wrote $OutputPath"

#endregion
