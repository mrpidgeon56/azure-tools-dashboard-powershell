#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Network & NSG Risk Map scanner. Pulls every network security group via Resource Graph,
    expands its inbound security rules, and flags risky ones — management ports (RDP/SSH)
    open to the internet, any-to-any allow rules, and broad source ranges. ARM Reader is
    sufficient; no data-plane access needed.
.OUTPUTS
    JSON at -OutputPath (default ../data/nsg-risk-scan-results.json): { ScanMetadata, Items, Errors }
.NOTES
    Reuses the in-memory Az context (no separate login). Scope params mirror the other scanners
    so the shared /api/nsgrisk/scan endpoint can pass them straight through.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = "$PSScriptRoot/../data/nsg-risk-scan-results.json",
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
Write-Progress2 "Network & NSG Risk Map scan — scope: $scopeLabel"

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

# ── NSG risk evaluation helpers (port of nsg_risk.py) ──────────────────────────
$mgmtPorts = [ordered]@{ 22 = "SSH"; 3389 = "RDP"; 3306 = "MySQL"; 5432 = "PostgreSQL"; 1433 = "SQL"; 6379 = "Redis"; 27017 = "MongoDB" }
$internetSources = @('*', 'internet', '0.0.0.0/0', '::/0', 'any')

function ConvertTo-StrList ($v) {
    if ($null -eq $v) { return @() }
    if ($v -is [string]) { return @($v) }
    if ($v -is [System.Collections.IEnumerable]) { return @($v | ForEach-Object { "$_" }) }
    return @("$v")
}

function Test-IsInternet ($props) {
    $prefixes = @()
    $prefixes += ConvertTo-StrList (Get-Prop $props 'sourceAddressPrefix')
    $prefixes += ConvertTo-StrList (Get-Prop $props 'sourceAddressPrefixes')
    foreach ($p in $prefixes) { if (($p.Trim().ToLowerInvariant()) -in $internetSources) { return $true } }
    return $false
}

function Get-RulePorts ($props) {
    $p = @()
    $p += ConvertTo-StrList (Get-Prop $props 'destinationPortRange')
    $p += ConvertTo-StrList (Get-Prop $props 'destinationPortRanges')
    return @($p | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
}

function Get-PortMgmtHits ([string[]]$ports) {
    $hits = [System.Collections.Generic.List[string]]::new()
    foreach ($labelPort in $mgmtPorts.Keys) {
        $label = $mgmtPorts[$labelPort]
        foreach ($spec in $ports) {
            if ($spec -eq '*') { $hits.Add("$label ($labelPort)"); break }
            if ($spec.Contains('-')) {
                $parts = $spec.Split('-', 2)
                $lo = 0; $hi = 0
                if ([int]::TryParse($parts[0], [ref]$lo) -and [int]::TryParse($parts[1], [ref]$hi)) {
                    if ($labelPort -ge $lo -and $labelPort -le $hi) { $hits.Add("$label ($labelPort)"); break }
                }
            } elseif ($spec -match '^\d+$' -and [int]$spec -eq $labelPort) {
                $hits.Add("$label ($labelPort)"); break
            }
        }
    }
    return @($hits)
}

function Get-RuleFinding ($rule) {
    $props = Get-Prop $rule 'properties'
    if ($null -eq $props) { $props = $rule }
    if (("$(Get-Prop $props 'access')").ToLowerInvariant() -ne 'allow') { return $null }
    if (("$(Get-Prop $props 'direction')").ToLowerInvariant() -ne 'inbound') { return $null }

    $internet = Test-IsInternet $props
    $ports    = Get-RulePorts $props
    $anyPort  = $ports -contains '*'
    $mgmt     = if ($internet) { Get-PortMgmtHits $ports } else { @() }

    $severity = $null; $reason = ""
    if ($internet -and $mgmt.Count) {
        $severity = 'high'; $reason = "Management port(s) open to the internet: " + ($mgmt -join ', ')
    } elseif ($internet -and $anyPort) {
        $severity = 'high'; $reason = "All ports open to the internet (any-to-any)."
    } elseif ($internet) {
        $severity = 'medium'; $reason = "Inbound rule allows traffic from the internet."
    } elseif ($anyPort -and ("$(Get-Prop $props 'sourceAddressPrefix')").Trim() -eq '*') {
        $severity = 'low'; $reason = "Broad any-source any-port allow rule."
    }
    if ($null -eq $severity) { return $null }

    $name = Get-Prop $rule 'name'
    if (-not $name) { $name = Get-Prop $props 'name' }
    if (-not $name) { $name = "—" }
    $source = (@(ConvertTo-StrList (Get-Prop $props 'sourceAddressPrefix')) + @(ConvertTo-StrList (Get-Prop $props 'sourceAddressPrefixes'))) -join ', '
    if (-not $source) { $source = "—" }
    $portStr = ($ports -join ', '); if (-not $portStr) { $portStr = "Any" }

    return [ordered]@{
        RuleName     = "$name"
        Priority     = Get-Prop $props 'priority'
        Protocol     = "$(Get-Prop $props 'protocol')"
        Source       = $source
        Ports        = $portStr
        MgmtServices = @($mgmt)
        Severity     = $severity
        Reason       = $reason
    }
}

function Get-NsgRecommendation ([string]$severity, [bool]$mgmt) {
    if ($severity -eq 'high') {
        if ($mgmt) { return @{ Action = 'Restrict source'; Reason = 'Limit management ports to a bastion / VPN range or use Azure Bastion; never expose RDP/SSH to the internet.' } }
        return @{ Action = 'Restrict rule'; Reason = 'Scope this internet-facing allow rule to specific ports and source ranges.' }
    }
    if ($severity -eq 'medium') {
        return @{ Action = 'Review exposure'; Reason = 'Confirm this resource is intended to be internet-facing; tighten the source range if not.' }
    }
    return @{ Action = 'Tighten rule'; Reason = 'Narrow the source and destination ports to the minimum required.' }
}

$sevRank = @{ high = 3; medium = 2; low = 1; none = 0 }

# One Resource Graph query for all NSGs in scope (joined to the subscription name).
$kql = @"
Resources
| where type =~ 'microsoft.network/networksecuritygroups'
$rgClause| extend sub = tostring(subscriptionId), rg = tostring(resourceGroup)
| join kind=leftouter (ResourceContainers | where type == 'microsoft.resources/subscriptions' | project sub = tostring(subscriptionId), subName = tostring(name)) on sub
| project id, name, rg, sub, subName, location, rules = properties.securityRules, nics = properties.networkInterfaces, subnets = properties.subnets
"@

Write-Progress2 "Querying network security groups via Resource Graph..."
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
Set-ScanProgress -Phase "scanning" -Total $total -Message "Evaluating $total NSG(s)..."

$counts      = [ordered]@{ high = 0; medium = 0; low = 0 }
$mgmtExposed = 0
$subSet      = [System.Collections.Generic.HashSet[string]]::new()
$done = 0

foreach ($nsg in $rows) {
    $done++
    $rulesRaw = Get-Prop $nsg 'rules'
    $rulesArr = @(); if ($null -ne $rulesRaw) { $rulesArr = @($rulesRaw) }

    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $rulesArr) {
        $f = Get-RuleFinding $r
        if ($null -ne $f) { $findings.Add($f) }
    }
    $sorted = @($findings | Sort-Object { $sevRank[$_.Severity] } -Descending)
    $worst  = if ($sorted.Count) { $sorted[0].Severity } else { 'none' }
    $hasMgmt = $false
    foreach ($f in $findings) { if (@($f.MgmtServices).Count) { $hasMgmt = $true; break } }

    if ($counts.Contains($worst)) { $counts[$worst]++ }
    if ($hasMgmt) { $mgmtExposed++ }

    $nics    = Get-Prop $nsg 'nics'
    $subnets = Get-Prop $nsg 'subnets'
    $attached = (@($nics).Where({ $_ }).Count -gt 0) -or (@($subnets).Where({ $_ }).Count -gt 0)

    if ($findings.Count) {
        $rec = Get-NsgRecommendation $worst $hasMgmt
    } else {
        $rec = @{ Action = 'Keep'; Reason = 'No risky inbound rules detected.' }
    }

    $sub = "$(Get-Prop $nsg 'sub')"
    if ($sub) { [void]$subSet.Add($sub) }
    $subName = "$(Get-Prop $nsg 'subName')"; if (-not $subName) { $subName = $sub }

    # Page-facing severity: 'ok' when no risky rules, else the worst finding severity.
    $itemSeverity = if ($findings.Count) { $worst } else { 'ok' }

    $items.Add([ordered]@{
        Id                = "$(Get-Prop $nsg 'id')"
        Name              = "$(Get-Prop $nsg 'name')"
        ResourceGroup     = "$(Get-Prop $nsg 'rg')"
        SubscriptionId    = $sub
        SubscriptionName  = $subName
        Location          = "$(Get-Prop $nsg 'location')"
        Attached          = [bool]$attached
        RuleCount         = $rulesArr.Count
        RiskyRules        = @($sorted)
        RiskyCount        = $findings.Count
        Severity          = $itemSeverity
        ExposesMgmt       = [bool]$hasMgmt
        RecommendedAction = $rec
    })

    if ($done % 25 -eq 0 -or $done -eq $total) {
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar ($counts.high + $counts.medium) -Message "Evaluated $done NSG(s)..."
    }
}

$atRisk = $counts.high + $counts.medium + $counts.low

# ── write output ──────────────────────────────────────────────────────────────
$output = @{
    ScanMetadata = @{
        ScanTime          = $scanStartTime.ToString("o")
        CompletedTime     = (Get-Date).ToString("o")
        ScopeType         = $ScopeType
        ManagementGroupId = $ManagementGroupId
        ScopeLabel        = $scopeLabel
        Subscriptions     = $subSet.Count
        NsgsScanned       = $total
        AtRisk            = $atRisk
        HighRisk          = $counts.high
        MediumRisk        = $counts.medium
        LowRisk           = $counts.low
        MgmtExposed       = $mgmtExposed
        TotalItems        = $items.Count
        ErrorCount        = $errors.Count
    }
    Items  = $items
    Errors = $errors
}
Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) item(s). Wrote $OutputPath"
