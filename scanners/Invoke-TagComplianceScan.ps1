#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Audits Azure tag usage across the tenant's subscriptions, resource groups, and
    resources, flagging objects that violate a set of required-tag rules.

    For every subscription, resource group, and resource it evaluates the EFFECTIVE
    tags — subscription tags inherit down to resource groups, and subscription + RG
    tags inherit down to resources (a child tag overrides an inherited one). Each
    object is checked against the supplied required-tag rules and classified:
      - missing key      : a required key has no tag (case-insensitive) at all
      - empty value      : a required key is present but its value is blank
      - invalid value    : a required key's value is not in its allowed-values set
      - casing drift     : a required key is present but with different casing
                           (e.g. "environment" where the rule says "Environment")
    Objects whose resource type cannot carry tags are reported as "Untaggable" and
    excluded from compliance scoring (avoids false positives).

.OUTPUTS
    JSON file at -OutputPath (default: ./tag-scan-results.json) with the envelope
    { ScanMetadata, Objects, Errors }.

.NOTES
    Inventory comes from Azure Resource Graph (Search-AzGraph), which spans every
    subscription the signed-in identity can read in a single query. This needs only
    ARM "Reader" — NO Microsoft Graph permission (unlike the Entra scanner). The scan
    reuses the in-memory Az context held by the dashboard server.

    Required Az modules: Az.Accounts, Az.ResourceGraph.
#>
[CmdletBinding()]
param(
    [string]   $OutputPath           = "$PSScriptRoot/../data/tag-scan-results.json",
    [string]   $ProgressPath         = "",      # if set, incremental progress JSON is written here
    [string[]] $RequiredTags         = @(),     # required tag KEYS (e.g. Environment, Owner, CostCenter)
    [object]   $AllowedTagValues     = $null,   # optional map: key -> allowed values[] (PSCustomObject or hashtable)
    [string]   $SingleSubscriptionId = "",      # if set, only audit this one subscription
    [ValidateSet('All','ManagementGroup','Subscription','ResourceGroup')]
    [string]   $ScopeType            = "All",   # scope selector from the dashboard
    [string]   $ManagementGroupId    = "",      # if set, scope the scan recursively to this management group's hierarchy
    [string]   $ResourceGroup        = "",      # if set (with a subscription), restrict to this resource group
    [ValidateSet('Exclusive','Inclusive')]
    [string]   $Mode                 = "Exclusive", # Exclusive = surface objects in violation; Inclusive = surface objects that carry the tags
    [string[]] $ExcludedResourceTypes = @(      # resource types that cannot carry tags (prefix match, case-insensitive)
        'microsoft.classiccompute/',
        'microsoft.classicstorage/',
        'microsoft.classicnetwork/',
        'microsoft.addons/',
        'microsoft.gallery/',
        'microsoft.marketplaceapps/',
        'microsoft.blueprint/',
        'microsoft.managedidentity/',
        'microsoft.resources/subscriptions/resourcegroups/'
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region ── helpers ──────────────────────────────────────────────────────────────

$script:logTail       = [System.Collections.Generic.List[string]]::new()
$script:progressState = [ordered]@{
    Phase = "init"; Percent = 0; Fetched = 0; Total = 0; FlaggedSoFar = 0; Message = ""
}

function Save-Progress {
    if (-not $ProgressPath) { return }
    $payload = [ordered]@{}
    foreach ($k in $script:progressState.Keys) { $payload[$k] = $script:progressState[$k] }
    $payload.LogTail   = @($script:logTail)
    $payload.UpdatedAt = (Get-Date).ToString("o")
    try { $payload | ConvertTo-Json -Depth 5 | Set-Content -Path $ProgressPath -Encoding UTF8 -ErrorAction Stop }
    catch { <# progress writes are best-effort #> }
}

function Write-Progress2 ($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line -ForegroundColor Cyan
    $script:logTail.Add($line)
    while ($script:logTail.Count -gt 12) { $script:logTail.RemoveAt(0) }
    Save-Progress
}

function Set-ScanProgress {
    param([string]$Phase, [int]$Fetched = 0, [int]$Total = 0, [int]$FlaggedSoFar = 0, [string]$Message = "")
    if (-not $ProgressPath) { return }
    $percent = 0
    if ($Total -gt 0) { $percent = [math]::Round(($Fetched / $Total) * 100, 1) }
    if ($Phase -eq "done") { $percent = 100 }
    $script:progressState = [ordered]@{
        Phase = $Phase; Percent = $percent; Fetched = $Fetched; Total = $Total
        FlaggedSoFar = $FlaggedSoFar; Message = $Message
    }
    Save-Progress
}

function Format-Exception ($err) {
    if ($null -eq $err) { return "" }
    $msg = if ($err.Exception) { $err.Exception.Message } else { "$err" }
    return ($msg -replace '\s+', ' ').Trim()
}

# StrictMode-safe property accessor: $null instead of throwing on a missing property.
function Get-Prop {
    param($obj, [string]$name)
    if ($null -eq $obj) { return $null }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

# Resource Graph returns `tags` as a nested object (or $null). Normalise it to a
# plain [hashtable] of key -> string value so downstream logic is uniform.
function ConvertTo-TagMap {
    param($tags)
    $map = @{}
    if ($null -eq $tags) { return $map }
    foreach ($p in $tags.PSObject.Properties) {
        if ($p.Name) { $map[$p.Name] = [string]$p.Value }
    }
    return $map
}

# Merge parent tags then child tags (child overrides parent) into a new hashtable.
function Merge-Tags {
    param([hashtable]$Parent, [hashtable]$Child)
    $out = @{}
    if ($Parent) { foreach ($k in $Parent.Keys) { $out[$k] = $Parent[$k] } }
    if ($Child)  { foreach ($k in $Child.Keys)  { $out[$k] = $Child[$k] } }
    return $out
}

# True when a resource type can't carry tags (prefix match against the exclusion list).
function Test-Untaggable {
    param([string]$Type)
    if (-not $Type) { return $false }
    $t = $Type.ToLowerInvariant()
    foreach ($x in $ExcludedResourceTypes) {
        if ($t.StartsWith($x.ToLowerInvariant())) { return $true }
    }
    return $false
}

# Build a quick lookup of allowed values per required key (case-insensitive key match).
# $AllowedTagValues may be a PSCustomObject (from JSON) or a hashtable.
function Get-AllowedValueMap {
    param($allowed)
    $map = @{}   # lower(key) -> string[] of allowed values
    if ($null -eq $allowed) { return $map }
    $pairs = if ($allowed -is [hashtable]) {
        $allowed.GetEnumerator() | ForEach-Object { @{ Name = $_.Key; Value = $_.Value } }
    } else {
        $allowed.PSObject.Properties | ForEach-Object { @{ Name = $_.Name; Value = $_.Value } }
    }
    foreach ($p in $pairs) {
        $vals = @($p.Value | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
        if ($p.Name) { $map[([string]$p.Name).ToLowerInvariant()] = $vals }
    }
    return $map
}

# Evaluate one object's effective tags against the required-tag rules. Returns a
# hashtable of the violation arrays + derived compliance state.
function Get-TagCompliance {
    param([hashtable]$EffectiveTags, [bool]$Taggable)

    $missing  = [System.Collections.Generic.List[string]]::new()
    $empty    = [System.Collections.Generic.List[string]]::new()
    $invalid  = [System.Collections.Generic.List[string]]::new()
    $drift    = [System.Collections.Generic.List[object]]::new()
    $violations = [System.Collections.Generic.List[object]]::new()

    if (-not $Taggable) {
        return @{
            MissingKeys = @(); EmptyValueKeys = @(); InvalidValueKeys = @(); CaseDriftKeys = @()
            Violations = @(); ComplianceState = 'Untaggable'
        }
    }

    # Index effective tag keys by lower-case for case-insensitive matching.
    $byLower = @{}
    foreach ($k in $EffectiveTags.Keys) { $byLower[$k.ToLowerInvariant()] = $k }

    foreach ($req in $RequiredTags) {
        if (-not $req) { continue }
        $lr = $req.ToLowerInvariant()
        if (-not $byLower.ContainsKey($lr)) {
            $missing.Add($req)
            $violations.Add(@{ Type = 'missing'; Key = $req; Detail = "Required tag '$req' is not present." })
            continue
        }
        $actualKey = $byLower[$lr]
        $value     = [string]$EffectiveTags[$actualKey]

        # casing drift: present but the key casing differs from the rule.
        if ($actualKey -cne $req) {
            $drift.Add(@{ Found = $actualKey; Expected = $req })
            $violations.Add(@{ Type = 'drift'; Key = $req; Detail = "Tag key '$actualKey' should be '$req'." })
        }

        if ([string]::IsNullOrWhiteSpace($value)) {
            $empty.Add($req)
            $violations.Add(@{ Type = 'empty'; Key = $req; Detail = "Tag '$req' has no value." })
            continue
        }

        if ($script:allowedMap.ContainsKey($lr)) {
            $allowed = $script:allowedMap[$lr]
            if ($allowed.Count -gt 0 -and ($allowed -notcontains $value)) {
                $invalid.Add($req)
                $violations.Add(@{ Type = 'invalid'; Key = $req; Detail = "Value '$value' is not allowed for '$req' (allowed: $($allowed -join ', '))." })
            }
        }
    }

    $state = if ($violations.Count -eq 0) { 'Compliant' } else { 'Non-compliant' }
    return @{
        MissingKeys = @($missing); EmptyValueKeys = @($empty)
        InvalidValueKeys = @($invalid); CaseDriftKeys = @($drift)
        Violations = @($violations); ComplianceState = $state
    }
}

# Suggested remediation rolled up from an object's violations.
function Get-TagRecommendation {
    param([hashtable]$Compliance)
    if ($Compliance.ComplianceState -eq 'Untaggable') {
        return @{ Action = 'Keep'; Reason = 'Resource type does not support tags.' }
    }
    if ($Compliance.ComplianceState -eq 'Compliant') {
        return @{ Action = 'Keep'; Reason = 'All required tags present and valid.' }
    }
    $parts = @()
    if ($Compliance.MissingKeys.Count)      { $parts += "add $($Compliance.MissingKeys -join ', ')" }
    if ($Compliance.EmptyValueKeys.Count)   { $parts += "set value for $($Compliance.EmptyValueKeys -join ', ')" }
    if ($Compliance.InvalidValueKeys.Count) { $parts += "fix value for $($Compliance.InvalidValueKeys -join ', ')" }
    if ($Compliance.CaseDriftKeys.Count)    { $parts += "rename $(@($Compliance.CaseDriftKeys | ForEach-Object { "$($_.Found)→$($_.Expected)" }) -join ', ')" }
    return @{ Action = 'Apply required tags'; Reason = ($parts -join '; ') }
}

# Paged Resource Graph query (SkipToken loop), returns all rows. Honours the optional
# single-subscription scope. Returns $null if Search-AzGraph is unavailable.
function Invoke-GraphQuery {
    param([string]$Query, [string[]]$ManagementGroup = @())
    if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) { return $null }
    $rows = [System.Collections.Generic.List[object]]::new()
    $skip = $null
    # When a management group is supplied, Search-AzGraph recurses its full hierarchy
    # (all child management groups + subscriptions) instead of the default tenant scope.
    $mgArgs = @{}
    if ($ManagementGroup.Count) { $mgArgs['ManagementGroup'] = $ManagementGroup }
    do {
        $page = if ($skip) { Search-AzGraph -Query $Query -First 1000 -SkipToken $skip @mgArgs }
                else        { Search-AzGraph -Query $Query -First 1000 @mgArgs }
        foreach ($row in @($page)) { $rows.Add($row) }
        $skip = $page.PSObject.Properties['SkipToken'] ? $page.SkipToken : $null
    } while ($skip)
    return $rows
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$objects = [System.Collections.Generic.List[object]]::new()
$errors  = [System.Collections.Generic.List[object]]::new()
$flaggedSoFar = 0

$script:allowedMap = Get-AllowedValueMap $AllowedTagValues

# Scope resolution. Backward-compatible: ScopeType defaults to 'All', and a lone
# -SingleSubscriptionId (ScopeType unset) still restricts to that one subscription.
# Precedence: a management group (when ScopeType=ManagementGroup) recurses its hierarchy;
# otherwise a subscription filter narrows to one subscription; an optional resource-group
# filter narrows further within that subscription (case-insensitive, =~).
$useMg     = ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId)
$subFilter = if (-not $useMg -and $SingleSubscriptionId) { " | where subscriptionId == '$SingleSubscriptionId'" } else { "" }
$rgFilter  = if ($ResourceGroup) { " | where resourceGroup =~ '$ResourceGroup'" } else { "" }
$mgScope   = if ($useMg) { @($ManagementGroupId) } else { @() }

Set-ScanProgress -Phase "init" -Message "Querying Azure Resource Graph..."
Write-Progress2 "Auditing tags against required keys: $(if ($RequiredTags.Count) { $RequiredTags -join ', ' } else { '(none specified)' })"
Write-Progress2 "Mode: $Mode$(if ($useMg) { " | management group (recursive): $ManagementGroupId" } elseif ($SingleSubscriptionId) { " | subscription: $SingleSubscriptionId$(if ($ResourceGroup) { " | resource group: $ResourceGroup" })" })"

if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
    throw "Azure Resource Graph (Search-AzGraph) is unavailable. Install it with: Install-Module Az.ResourceGraph -Scope CurrentUser"
}

# ── 1. subscriptions (tags + names) ──────────────────────────────────────────
Write-Progress2 "Querying subscriptions..."
$subRows = Invoke-GraphQuery "ResourceContainers | where type == 'microsoft.resources/subscriptions'$subFilter | project id, name, subscriptionId, tags" -ManagementGroup $mgScope
$subTags  = @{}   # subId -> [hashtable] tags
$subNames = @{}   # subId -> name
foreach ($s in @($subRows)) {
    $sid = [string](Get-Prop $s 'subscriptionId')
    if (-not $sid) { continue }
    $subTags[$sid]  = ConvertTo-TagMap (Get-Prop $s 'tags')
    $subNames[$sid] = [string](Get-Prop $s 'name')
}

# ── 2. resource groups (tags) ────────────────────────────────────────────────
Write-Progress2 "Querying resource groups..."
$rgRows = Invoke-GraphQuery "ResourceContainers | where type == 'microsoft.resources/subscriptions/resourcegroups'$subFilter$(if ($ResourceGroup) { " | where name =~ '$ResourceGroup'" }) | project id, name, subscriptionId, resourceGroup, location, tags" -ManagementGroup $mgScope
$rgTags = @{}     # "subId/rgname".ToLower() -> [hashtable] tags
foreach ($g in @($rgRows)) {
    $sid = [string](Get-Prop $g 'subscriptionId')
    $rg  = [string](Get-Prop $g 'name')
    if (-not $sid -or -not $rg) { continue }
    $rgTags["$sid/$($rg.ToLowerInvariant())"] = ConvertTo-TagMap (Get-Prop $g 'tags')
}

# ── 3. resources (tags + type) ───────────────────────────────────────────────
Write-Progress2 "Querying resources..."
$resRows = Invoke-GraphQuery "Resources$subFilter$rgFilter | project id, name, type, subscriptionId, resourceGroup, location, tags" -ManagementGroup $mgScope

$total = @($subRows).Count + @($rgRows).Count + @($resRows).Count
Set-ScanProgress -Phase "scanning" -Fetched 0 -Total $total -Message "Evaluating $total object(s)..."

# Emits one record into $objects, updating the flagged counter + progress.
$processed = 0
$addObject = {
    param([string]$ScopeType, [string]$Name, [string]$Id, [string]$SubId,
          [string]$ResourceGroup, [string]$ResourceType, [string]$Location,
          [hashtable]$DirectTags, [hashtable]$EffectiveTags, [bool]$Taggable)

    $comp = Get-TagCompliance -EffectiveTags $EffectiveTags -Taggable $Taggable
    $rec  = Get-TagRecommendation $comp

    $script:objects.Add([ordered]@{
        ScopeType         = $ScopeType
        Name              = $Name
        Id                = $Id
        SubscriptionId    = $SubId
        SubscriptionName  = if ($script:subNames.ContainsKey($SubId)) { $script:subNames[$SubId] } else { $SubId }
        ResourceGroup     = $ResourceGroup
        ResourceType      = $ResourceType
        Location          = $Location
        DirectTags        = $DirectTags
        EffectiveTags     = $EffectiveTags
        MissingKeys       = $comp.MissingKeys
        EmptyValueKeys    = $comp.EmptyValueKeys
        InvalidValueKeys  = $comp.InvalidValueKeys
        CaseDriftKeys     = $comp.CaseDriftKeys
        Taggable          = $Taggable
        ComplianceState   = $comp.ComplianceState
        Violations        = $comp.Violations
        RecommendedAction = $rec
    })
    if ($comp.ComplianceState -eq 'Non-compliant') { $script:flaggedSoFar++ }
}

# expose mutable counters/maps to the scriptblock
$script:objects = $objects
$script:flaggedSoFar = 0
$script:subNames = $subNames

# subscriptions
foreach ($s in @($subRows)) {
    $sid = [string](Get-Prop $s 'subscriptionId'); if (-not $sid) { continue }
    $tags = $subTags[$sid]
    & $addObject -ScopeType 'Subscription' -Name $subNames[$sid] -Id ([string](Get-Prop $s 'id')) `
        -SubId $sid -ResourceGroup $null -ResourceType $null -Location $null `
        -DirectTags $tags -EffectiveTags $tags -Taggable $true
    $processed++
}
Set-ScanProgress -Phase "scanning" -Fetched $processed -Total $total -FlaggedSoFar $script:flaggedSoFar -Message "Evaluated subscriptions..."

# resource groups (effective = sub tags + own)
foreach ($g in @($rgRows)) {
    $sid = [string](Get-Prop $g 'subscriptionId'); $rg = [string](Get-Prop $g 'name')
    if (-not $sid -or -not $rg) { continue }
    $own = $rgTags["$sid/$($rg.ToLowerInvariant())"]
    $eff = Merge-Tags ($subTags[$sid]) $own
    & $addObject -ScopeType 'ResourceGroup' -Name $rg -Id ([string](Get-Prop $g 'id')) `
        -SubId $sid -ResourceGroup $rg -ResourceType $null -Location ([string](Get-Prop $g 'location')) `
        -DirectTags $own -EffectiveTags $eff -Taggable $true
    $processed++
}
Set-ScanProgress -Phase "scanning" -Fetched $processed -Total $total -FlaggedSoFar $script:flaggedSoFar -Message "Evaluated resource groups..."

# resources (effective = sub tags + RG tags + own)
$n = 0
foreach ($r in @($resRows)) {
    $sid  = [string](Get-Prop $r 'subscriptionId')
    $rg   = [string](Get-Prop $r 'resourceGroup')
    $type = [string](Get-Prop $r 'type')
    $own  = ConvertTo-TagMap (Get-Prop $r 'tags')
    $parent = Merge-Tags ($subTags[$sid]) ($rg ? $rgTags["$sid/$($rg.ToLowerInvariant())"] : $null)
    $eff  = Merge-Tags $parent $own
    & $addObject -ScopeType 'Resource' -Name ([string](Get-Prop $r 'name')) -Id ([string](Get-Prop $r 'id')) `
        -SubId $sid -ResourceGroup $rg -ResourceType $type -Location ([string](Get-Prop $r 'location')) `
        -DirectTags $own -EffectiveTags $eff -Taggable (-not (Test-Untaggable $type))
    $processed++; $n++
    if ($n % 500 -eq 0) {
        Set-ScanProgress -Phase "scanning" -Fetched $processed -Total $total -FlaggedSoFar $script:flaggedSoFar -Message "Evaluated $n resource(s)..."
        Write-Progress2 "Evaluated $n / $(@($resRows).Count) resource(s)..."
    }
}

$objects = $script:objects
$flaggedSoFar = $script:flaggedSoFar

#endregion

#region ── write output ─────────────────────────────────────────────────────────

$subCount = @($objects | Where-Object { $_.ScopeType -eq 'Subscription' }).Count
$rgCount  = @($objects | Where-Object { $_.ScopeType -eq 'ResourceGroup' }).Count
$resCount = @($objects | Where-Object { $_.ScopeType -eq 'Resource' }).Count
$compliant    = @($objects | Where-Object { $_.ComplianceState -eq 'Compliant' }).Count
$nonCompliant = @($objects | Where-Object { $_.ComplianceState -eq 'Non-compliant' }).Count
$untaggable   = @($objects | Where-Object { $_.ComplianceState -eq 'Untaggable' }).Count
$missingCount = @($objects | Where-Object { $_.MissingKeys.Count -gt 0 }).Count
$emptyCount   = @($objects | Where-Object { $_.EmptyValueKeys.Count -gt 0 }).Count
$invalidCount = @($objects | Where-Object { $_.InvalidValueKeys.Count -gt 0 }).Count
$driftCount   = @($objects | Where-Object { $_.CaseDriftKeys.Count -gt 0 }).Count
$scored       = $compliant + $nonCompliant
$compliancePct = if ($scored -gt 0) { [math]::Round(($compliant / $scored) * 100, 1) } else { 0 }

$output = @{
    ScanMetadata = @{
        ScanTime          = $scanStartTime.ToString("o")
        CompletedTime     = (Get-Date).ToString("o")
        RequiredTags      = @($RequiredTags)
        Mode              = $Mode
        ScopeType         = $ScopeType
        ManagementGroupId = $ManagementGroupId
        ResourceGroup     = $ResourceGroup
        TotalObjects      = $objects.Count
        Subscriptions     = $subCount
        ResourceGroups    = $rgCount
        Resources         = $resCount
        CompliantCount    = $compliant
        NonCompliantCount = $nonCompliant
        UntaggableCount   = $untaggable
        MissingKeyCount   = $missingCount
        EmptyValueCount   = $emptyCount
        InvalidValueCount = $invalidCount
        CaseDriftCount    = $driftCount
        CompliancePercent = $compliancePct
        ErrorCount        = $errors.Count
    }
    Objects = $objects
    Errors  = $errors
}

Set-ScanProgress -Phase "done" -Fetched $total -Total $total -FlaggedSoFar $flaggedSoFar -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($objects.Count) object(s) — $compliant compliant, $nonCompliant non-compliant, $untaggable untaggable. Wrote $OutputPath"

#endregion
