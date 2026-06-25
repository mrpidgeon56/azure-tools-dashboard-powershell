#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Network Topology & Connectivity-Map scanner. Pulls every virtual network via
    Resource Graph (scope-aware), expands its address space, subnets and peerings,
    and flags topology issues: subnets with no NSG, isolated VNets with no peerings,
    and address spaces that overlap another VNet in the scanned set (which blocks
    peering and breaks routing). ARM Reader is sufficient; no data-plane access needed.
.OUTPUTS
    JSON at -OutputPath (default ../data/network-topology-scan-results.json): { ScanMetadata, Items, Errors }
.NOTES
    Reuses the in-memory Az context (no separate login). Scope params mirror the other scanners
    so the shared /api/networktopology/scan endpoint can pass them straight through.
#>
[CmdletBinding()]
param(
    [string] $OutputPath = "$PSScriptRoot/../data/network-topology-scan-results.json",
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
Set-ScanProgress -Phase "inventory" -Message "Scanning ($scopeLabel)..."
Write-Progress2 "Network Topology scan — scope: $scopeLabel"

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

# Count elements of an ARM property whether it arrived as an array or a single object.
# (ConvertTo/From-Json and Resource Graph can collapse a one-element array to a scalar,
# so $x.Count is unreliable; $null → 0, scalar → 1, collection → element count.)
function Measure-Items ($v) {
    if ($null -eq $v) { return 0 }
    if ($v -is [string]) { return 1 }
    if ($v -is [System.Collections.IEnumerable]) { return @($v).Count }
    return 1
}

# Coerce a value into a list of non-empty strings, defensively (mirrors Python _as_list).
function ConvertTo-StringList ($v) {
    if ($null -eq $v) { return @() }
    if ($v -is [string]) { if ($v -eq "") { return @() } else { return @($v) } }
    if ($v -is [System.Collections.IEnumerable]) {
        $out = @(); foreach ($x in $v) { if ($null -ne $x -and "$x" -ne "") { $out += "$x" } }
        return $out
    }
    if ("$v" -eq "") { return @() }
    return @("$v")
}

# IPv4 /prefix → 32-bit network mask. Done in 64-bit arithmetic with decimal literals
# (PowerShell reads 0xFFFFFFFF as signed -1, which breaks -band), then truncated to 32 bits.
function Get-CidrMask ([int]$prefix) {
    if ($prefix -le 0)  { return [uint32]0 }
    if ($prefix -ge 32) { return [uint32]4294967295 }
    return [uint32]((4294967295L -shl (32 - $prefix)) -band 4294967295L)
}

# Parse an IPv4 CIDR into @(network_int, prefix_len), or $null if unparseable (mirrors _parse_cidr).
function ConvertFrom-Cidr ([string]$cidr) {
    try {
        $s = "$cidr".Trim()
        $slash = $s.IndexOf('/')
        if ($slash -ge 0) { $addr = $s.Substring(0, $slash); $bits = $s.Substring($slash + 1) }
        else              { $addr = $s; $bits = "" }
        $prefix = if ($bits -ne "") { [int]$bits } else { 32 }
        if ($prefix -lt 0 -or $prefix -gt 32) { return $null }
        $octets = $addr.Split('.')
        if ($octets.Count -ne 4) { return $null }
        $value = [uint32]0
        foreach ($o in $octets) {
            $n = [int]$o
            if ($n -lt 0 -or $n -gt 255) { return $null }
            $value = ([uint32](($value -shl 8) -bor $n))
        }
        $mask = Get-CidrMask $prefix
        return @([uint32]($value -band $mask), $prefix)
    } catch { return $null }
}

# True if two IPv4 CIDR blocks overlap. Non-IPv4/unparseable inputs never overlap (mirrors _cidrs_overlap).
function Test-CidrOverlap ([string]$a, [string]$b) {
    $pa = ConvertFrom-Cidr $a
    $pb = ConvertFrom-Cidr $b
    if ($null -eq $pa -or $null -eq $pb) { return $false }
    $netA = $pa[0]; $preA = $pa[1]
    $netB = $pb[0]; $preB = $pb[1]
    $shorter = [math]::Min($preA, $preB)
    $mask = Get-CidrMask $shorter
    return (([uint32]($netA -band $mask)) -eq ([uint32]($netB -band $mask)))
}

# One Resource Graph query for all virtual networks in scope (joined to the subscription name).
$kql = @"
Resources
| where type =~ 'microsoft.network/virtualnetworks'
$rgClause| extend sub = tostring(subscriptionId)
| join kind=leftouter (ResourceContainers | where type == 'microsoft.resources/subscriptions' | project sub = tostring(subscriptionId), subName = tostring(name)) on sub
| project id, name, rg = tostring(resourceGroup), sub, subName, location, properties
"@

Write-Progress2 "Querying virtual networks via Resource Graph..."
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
Set-ScanProgress -Phase "scanning" -Total $total -Message "Evaluating $total virtual network(s)..."

# ── first pass: parse address spaces, subnets, peering counts (overlap is a
#    relationship across the whole scanned set, so gather everything first) ──
$parsed = [System.Collections.Generic.List[object]]::new()
foreach ($vn in $rows) {
    $props = Get-Prop $vn 'properties'

    $addrSpaceObj = Get-Prop $props 'addressSpace'
    $addressSpace = @(ConvertTo-StringList (Get-Prop $addrSpaceObj 'addressPrefixes'))

    $subnets = [System.Collections.Generic.List[object]]::new()
    $rawSubnets = Get-Prop $props 'subnets'
    if ($rawSubnets) {
        foreach ($sn in $rawSubnets) {
            if ($null -eq $sn) { continue }
            $sp = Get-Prop $sn 'properties'; if ($null -eq $sp) { $sp = $sn }
            $snName = Get-Prop $sn 'name'; if (-not $snName) { $snName = Get-Prop $sp 'name' }; if (-not $snName) { $snName = "—" }
            $ipCount = Measure-Items (Get-Prop $sp 'ipConfigurations')
            $subnets.Add([ordered]@{
                Name      = "$snName"
                Prefix    = "$(Get-Prop $sp 'addressPrefix')"
                HasNsg    = [bool](Get-Prop $sp 'networkSecurityGroup')
                IpConfigs = $ipCount
            })
        }
    }

    $peeringCount = Measure-Items (Get-Prop $props 'virtualNetworkPeerings')

    $parsed.Add([ordered]@{
        Row          = $vn
        AddressSpace = $addressSpace
        Subnets      = $subnets
        PeeringCount = $peeringCount
    })
}

# Names of other VNets in the set whose address space overlaps this one (mirrors overlap_peers).
function Get-OverlapPeers ([int]$idx) {
    $mine = $parsed[$idx].AddressSpace
    $peers = [System.Collections.Generic.List[string]]::new()
    for ($j = 0; $j -lt $parsed.Count; $j++) {
        if ($j -eq $idx) { continue }
        $other = $parsed[$j]
        $hit = $false
        foreach ($a in $mine) { foreach ($b in $other.AddressSpace) { if (Test-CidrOverlap $a $b) { $hit = $true; break } }; if ($hit) { break } }
        if ($hit) {
            $name = Get-Prop $other.Row 'name'; if (-not $name) { $name = "—" }
            if (-not $peers.Contains("$name")) { $peers.Add("$name") }
        }
    }
    return @($peers)
}

# ── second pass: build a record per VNet with its findings + severity ──
$withFindings = 0; $overlapping = 0; $isolated = 0; $nsglessTotal = 0; $totalPeerings = 0
$subSet = [System.Collections.Generic.HashSet[string]]::new()
$done = 0

for ($i = 0; $i -lt $parsed.Count; $i++) {
    $done++
    $entry = $parsed[$i]
    $vn = $entry.Row
    $addressSpace = $entry.AddressSpace
    $subnets = $entry.Subnets
    $peeringCount = $entry.PeeringCount
    $nsgless = @($subnets | Where-Object { -not $_.HasNsg } | ForEach-Object { $_.Name })

    $findings = [System.Collections.Generic.List[object]]::new()
    $peers = @(Get-OverlapPeers $i)
    if ($peers.Count) {
        $findings.Add(@{ Type = 'overlapping_address_space'; Detail = "Address space overlaps VNet(s): " + ($peers -join ', ') + "." })
    }
    if ($peeringCount -eq 0) {
        $findings.Add(@{ Type = 'isolated_vnet'; Detail = "VNet has no peerings (isolated — no east-west connectivity)." })
    }
    if ($nsgless.Count) {
        $findings.Add(@{ Type = 'nsgless_subnets'; Detail = "$($nsgless.Count) subnet(s) without an NSG: " + ($nsgless -join ', ') + "." })
    }

    $severity = if ($peers.Count) { 'high' } elseif ($findings.Count) { 'medium' } else { 'ok' }

    if ($findings.Count)   { $withFindings++ }
    if ($peers.Count)      { $overlapping++ }
    if ($peeringCount -eq 0) { $isolated++ }
    $nsglessTotal += $nsgless.Count
    $totalPeerings += $peeringCount

    # recommended action (mirrors Python recommendation()).
    if ($findings.Count -eq 0) {
        $rec = @{ Action = 'Keep'; Reason = 'No topology issues detected.' }
    } else {
        $kinds = @($findings | ForEach-Object { $_.Type })
        $parts = @()
        if ($kinds -contains 'overlapping_address_space') { $parts += 're-address the VNet so its space no longer overlaps a peer (overlaps block peering and routing)' }
        if ($kinds -contains 'isolated_vnet')             { $parts += 'confirm this VNet is meant to be isolated or add the missing peering' }
        if ($kinds -contains 'nsgless_subnets')           { $parts += 'associate an NSG with every workload subnet' }
        $rec = @{ Action = 'Review topology'; Reason = (($parts -join '; ') + '.') }
    }

    $sub = "$(Get-Prop $vn 'sub')"
    if ($sub) { [void]$subSet.Add($sub) }
    $subName = "$(Get-Prop $vn 'subName')"; if (-not $subName) { $subName = $sub }

    $items.Add([ordered]@{
        Id                = "$(Get-Prop $vn 'id')"
        Name              = "$(Get-Prop $vn 'name')"
        ResourceGroup     = "$(Get-Prop $vn 'rg')"
        SubscriptionId    = $sub
        SubscriptionName  = $subName
        Location          = "$(Get-Prop $vn 'location')"
        AddressSpace      = @($addressSpace)
        SubnetCount       = $subnets.Count
        PeeringCount      = $peeringCount
        NsglessSubnetCount = $nsgless.Count
        Findings          = @($findings)
        FindingCount      = $findings.Count
        Severity          = $severity
        RecommendedAction = $rec
    })

    if ($done % 25 -eq 0 -or $done -eq $total) {
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar $withFindings -Message "Evaluated $done VNet(s)..."
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
        VnetsScanned      = $total
        WithFindings      = $withFindings
        Overlapping       = $overlapping
        Isolated          = $isolated
        NsglessSubnets    = $nsglessTotal
        TotalPeerings     = $totalPeerings
        TotalItems        = $items.Count
        ErrorCount        = $errors.Count
    }
    Items  = $items
    Errors = $errors
}
Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) VNet(s). Wrote $OutputPath"
