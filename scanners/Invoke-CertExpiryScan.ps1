#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Certificate & Secret Expiry Monitor. Surfaces App Service certificates (which Resource
    Graph exposes with an expirationDate) that are expired or expiring within 30 days, and
    lists every Key Vault in scope as a manual-review row (Resource Graph cannot read
    individual vault secret/certificate expiry).
.OUTPUTS
    JSON at -OutputPath (default ../data/cert-expiry-scan-results.json): { ScanMetadata, Items, Errors }
.NOTES
    Reuses the in-memory Az context (no separate login). Scope params mirror the other scanners
    so the shared /api/certexpiry/scan endpoint can pass them straight through. ARM Reader is enough.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = "$PSScriptRoot/../data/cert-expiry-scan-results.json",
    [string] $ProgressPath = "",
    [ValidateSet('All','ManagementGroup','Subscription','ResourceGroup')]
    [string] $ScopeType = "All",
    [string] $ManagementGroupId = "",
    [string] $SingleSubscriptionId = "",
    [string] $ResourceGroup = ""
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Certificates within this many days are treated as "expiring soon".
$script:ExpiryWarnDays = 30

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
$now    = (Get-Date).ToUniversalTime()
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

$scopeLabel = if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) { "management group '$ManagementGroupId'" }
              elseif ($ResourceGroup -and $SingleSubscriptionId) { "$SingleSubscriptionId / $ResourceGroup" }
              elseif ($SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }
Set-ScanProgress -Phase "inventory" -Message "Scanning ($scopeLabel)..."
Write-Progress2 "Certificate & Secret Expiry scan — scope: $scopeLabel"

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

# Best-effort parse of an Azure ISO-8601 expiry timestamp into a UTC DateTime (or $null).
function Get-ParsedExpiry ($value) {
    if ($null -eq $value) { return $null }
    $text = ("$value").Trim()
    if (-not $text) { return $null }
    $dt = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) {
        return $dt.ToUniversalTime()
    }
    return $null
}

# (status, severity) for a number of days to expiry ($null = unknown).
function Get-ExpiryClass ($days) {
    if ($null -eq $days) { return @('unknown', 'ok') }
    if ($days -lt 0) { return @('expired', 'high') }
    if ($days -le $script:ExpiryWarnDays) { return @('expiring', 'medium') }
    return @('valid', 'ok')
}

function Get-Recommendation ([string]$kind, [string]$status, $days) {
    if ($kind -eq 'key_vault') {
        return @{ Action = 'Manual review'; Reason = "Resource Graph cannot read individual Key Vault secret/certificate expiry — inspect this vault's secrets and certificates directly." }
    }
    if ($status -eq 'expired') {
        $ago = [math]::Abs([int]($days ?? 0))
        return @{ Action = 'Renew certificate'; Reason = "Certificate expired $ago day(s) ago; renew and rebind to restore TLS." }
    }
    if ($status -eq 'expiring') {
        return @{ Action = 'Renew certificate'; Reason = "Certificate expires in $days day(s); renew before it lapses." }
    }
    if ($status -eq 'unknown') {
        return @{ Action = 'Review'; Reason = 'No expiry date is exposed for this certificate; confirm its validity.' }
    }
    return @{ Action = 'Keep'; Reason = 'Certificate is valid and not expiring soon.' }
}

# Paged Resource Graph fetch (SkipToken — never -First alone).
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
        Write-Progress2 "Resource Graph query failed for $stage ($(Format-Exception $_))."
    }
    return $rows
}

$subJoin = "| extend sub = tostring(subscriptionId) | join kind=leftouter (ResourceContainers | where type == 'microsoft.resources/subscriptions' | project sub = tostring(subscriptionId), subName = tostring(name)) on sub"

# ── App Service certificates ────────────────────────────────────────────────
Write-Progress2 "Querying App Service certificates via Resource Graph..."
$certKql = @"
Resources
| where type =~ 'microsoft.web/certificates'
$rgClause$subJoin
| project id, name, rg = tostring(resourceGroup), sub, subName, location, expiry = tostring(properties.expirationDate)
"@
$certRows = Invoke-GraphQuery $certKql 'certificates'

# ── Key Vaults (manual-review rows) ──────────────────────────────────────────
Write-Progress2 "Querying Key Vaults via Resource Graph..."
$vaultKql = @"
Resources
| where type =~ 'microsoft.keyvault/vaults'
$rgClause$subJoin
| project id, name, rg = tostring(resourceGroup), sub, subName, location
"@
$vaultRows = Invoke-GraphQuery $vaultKql 'keyvaults'

if ($vaultRows.Count -gt 0) {
    $errors.Add(@{ Stage = 'keyvaults'; Error = "Resource Graph does not expose individual Key Vault secret or certificate expiry dates. Each vault is listed for manual review — inspect its secrets and certificates directly to confirm none are expired or expiring." })
}

$total = $certRows.Count + $vaultRows.Count
Set-ScanProgress -Phase "scanning" -Total $total -Message "Evaluating $total item(s)..."

$counts = [ordered]@{ Expired = 0; ExpiringSoon = 0; Valid = 0; Unknown = 0 }
$subSet = [System.Collections.Generic.HashSet[string]]::new()
$done = 0

foreach ($c in $certRows) {
    $done++
    $expiryDt = Get-ParsedExpiry (Get-Prop $c 'expiry')
    $days = if ($null -ne $expiryDt) { [int][math]::Floor((($expiryDt - $now)).TotalDays) } else { $null }
    $cls = Get-ExpiryClass $days
    $status = $cls[0]; $severity = $cls[1]
    switch ($status) {
        'expired'  { $counts.Expired++ }
        'expiring' { $counts.ExpiringSoon++ }
        'valid'    { $counts.Valid++ }
        default    { $counts.Unknown++ }
    }
    $sub = "$(Get-Prop $c 'sub')"; if ($sub) { [void]$subSet.Add($sub) }
    $subName = "$(Get-Prop $c 'subName')"; if (-not $subName) { $subName = $sub }
    $items.Add([ordered]@{
        Id                = "$(Get-Prop $c 'id')"
        Name              = "$(Get-Prop $c 'name')"
        Kind              = 'appservice_cert'
        SubscriptionId    = $sub
        SubscriptionName  = $subName
        ResourceGroup     = "$(Get-Prop $c 'rg')"
        Location          = "$(Get-Prop $c 'location')"
        Expiry            = if ($expiryDt) { $expiryDt.ToString("o") } else { $null }
        DaysToExpiry      = $days
        Status            = $status
        Severity          = $severity
        RecommendedAction = (Get-Recommendation 'appservice_cert' $status $days)
    })
    if ($done % 50 -eq 0 -or $done -eq $total) {
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar ($counts.Expired + $counts.ExpiringSoon) -Message "Evaluated $done item(s)..."
    }
}

foreach ($v in $vaultRows) {
    $done++
    $counts.Unknown++
    $sub = "$(Get-Prop $v 'sub')"; if ($sub) { [void]$subSet.Add($sub) }
    $subName = "$(Get-Prop $v 'subName')"; if (-not $subName) { $subName = $sub }
    $items.Add([ordered]@{
        Id                = "$(Get-Prop $v 'id')"
        Name              = "$(Get-Prop $v 'name')"
        Kind              = 'key_vault'
        SubscriptionId    = $sub
        SubscriptionName  = $subName
        ResourceGroup     = "$(Get-Prop $v 'rg')"
        Location          = "$(Get-Prop $v 'location')"
        Expiry            = $null
        DaysToExpiry      = $null
        Status            = 'unknown'
        Severity          = 'ok'
        RecommendedAction = (Get-Recommendation 'key_vault' 'unknown' $null)
    })
    if ($done % 50 -eq 0 -or $done -eq $total) {
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar ($counts.Expired + $counts.ExpiringSoon) -Message "Evaluated $done item(s)..."
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
        ExpiryWarnDays    = $script:ExpiryWarnDays
        ItemsScanned      = $items.Count
        VaultsScanned     = $vaultRows.Count
        Expired           = $counts.Expired
        ExpiringSoon      = $counts.ExpiringSoon
        Valid             = $counts.Valid
        Unknown           = $counts.Unknown
        TotalItems        = $items.Count
        ErrorCount        = $errors.Count
    }
    Items  = $items
    Errors = $errors
}
Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) item(s). Wrote $OutputPath"
