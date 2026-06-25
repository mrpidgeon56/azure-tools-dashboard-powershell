#Requires -Version 7.0
#Requires -Modules Az.Accounts
<#
.SYNOPSIS
    Azure Policy compliance scanner.

    Summarizes Azure Policy compliance via the Policy Insights REST API
    (`policyStates/latest/summarize`), surfacing the policy assignments driving
    non-compliance and how many resources each one flags. The scope is selectable:

      - management group  — every subscription/resource under the group, one call
      - subscription      — a single subscription, or all visible subscriptions

    For each scope the summarize roll-up is filtered down to the assignments living
    *at that exact scope* (via policyAssignments `$filter=atExactScope()`), which also
    recovers each assignment's friendly display name. A scope that returns an error is
    reported as a warning rather than failing the whole scan. Reader is normally enough.

.OUTPUTS
    JSON file at -OutputPath (default ../data/policy-compliance-scan-results.json):
    { ScanMetadata, Items, Errors }

.NOTES
    Authentication reuses the in-memory Az context (no separate login): an ARM token is
    obtained with Get-AzAccessToken and the Microsoft.PolicyInsights / Microsoft.Authorization
    REST APIs are called directly. This is NOT a Resource-Graph tool — it iterates scopes.

    Required Az modules: Az.Accounts.
#>
[CmdletBinding()]
param(
    [string] $OutputPath           = "$PSScriptRoot/../data/policy-compliance-scan-results.json",
    [string] $ProgressPath         = "",          # if set, incremental progress JSON is written here
    [ValidateSet('All','ManagementGroup','Subscription')]
    [string] $ScopeType            = "All",        # scan scope: whole tenant, one management group, or one subscription
    [string] $ManagementGroupId    = "",           # when -ScopeType ManagementGroup: summarize at this MG (recurses descendants)
    [string] $SingleSubscriptionId = ""            # optional: scan just one subscription
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ApiVersion         = '2019-10-01'
$AssignmentsApi     = '2022-06-01'

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

# StrictMode-safe nested read (REST responses are PSCustomObjects / hashtables).
function Get-Prop ($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] } else { return $null } }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-Int ($v, [int]$default = 0) {
    if ($null -eq $v) { return $default }
    $out = 0
    if ([int]::TryParse("$v", [ref]$out)) { return $out }
    return $default
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

# Mirrors the Python _assignment_name(): best-effort display name from a resource id.
function Get-AssignmentName ([string]$AssignmentId) {
    if (-not $AssignmentId) { return "—" }
    return ($AssignmentId.TrimEnd('/') -split '/')[-1]
}

# Mirrors the Python _EFFECT_LABELS map + _effect_label().
$EffectLabels = @{
    'audit'             = 'Audit'
    'deny'              = 'Deny'
    'append'            = 'Append'
    'modify'            = 'Modify'
    'disabled'          = 'Disabled'
    'auditifnotexists'  = 'AuditIfNotExists'
    'deployifnotexists' = 'DeployIfNotExists'
    'denyaction'        = 'DenyAction'
    'manual'            = 'Manual'
}
function Get-EffectLabel ([string]$Effect) {
    $e = ("$Effect").Trim()
    if (-not $e) { return "" }
    $low = $e.ToLowerInvariant()
    if ($EffectLabels.ContainsKey($low)) { return $EffectLabels[$low] }
    return ($e.Substring(0,1).ToUpperInvariant() + $e.Substring(1))
}

# Mirrors the Python _definition_kind(): initiative (policy set) vs a single policy.
function Get-DefinitionKind ($Assignment) {
    $setId = ("$(Get-Prop $Assignment 'policySetDefinitionId')").Trim()
    if ($setId) { return 'Initiative' }
    return 'Policy'
}

# Mirrors the Python _policy_origin(): built-in lives at tenant root; custom under a sub/MG.
function Get-PolicyOrigin ([string]$DefinitionId) {
    if (-not $DefinitionId) { return 'Unknown' }
    $low = $DefinitionId.ToLowerInvariant()
    if ($low -like '*/subscriptions/*' -or $low -like '*/managementgroups/*') { return 'Custom' }
    return 'Built-in'
}

# Mirrors the Python _origin(): built-in vs custom inferred from the definition's id scope.
function Get-Origin ($Assignment) {
    $setId = ("$(Get-Prop $Assignment 'policySetDefinitionId')").Trim()
    if ($setId) {
        $ref = $setId
    } else {
        $defs = @(Get-Prop $Assignment 'policyDefinitions')
        $ref = if ($defs.Count) { "$(Get-Prop $defs[0] 'policyDefinitionId')" } else { "" }
    }
    if (-not $ref) { return 'Unknown' }
    $low = $ref.ToLowerInvariant()
    if ($low -like '*/subscriptions/*' -or $low -like '*/managementgroups/*') { return 'Custom' }
    return 'Built-in'
}

# Mirrors the Python _effects(): distinct enforcement effects across the assignment's policies.
function Get-Effects ($Assignment) {
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($d in @(Get-Prop $Assignment 'policyDefinitions')) {
        $label = Get-EffectLabel ("$(Get-Prop $d 'effect')")
        if ($label -and -not $out.Contains($label)) { $out.Add($label) }
    }
    return @($out | Sort-Object { $_.ToLowerInvariant() })
}

# Mirrors the Python _child_policies(): per-policy breakdown within an assignment.
function Get-ChildPolicies ($Assignment) {
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @(Get-Prop $Assignment 'policyDefinitions')) {
        $defId = ("$(Get-Prop $d 'policyDefinitionId')").Trim()
        $ref   = ("$(Get-Prop $d 'policyDefinitionReferenceId')").Trim()
        $res   = Get-Prop $d 'results'
        $name  = if ($ref) { $ref } else { Get-AssignmentName $defId }
        $out.Add([ordered]@{
            Name                   = $name
            DefinitionId           = $defId
            Effect                 = (Get-EffectLabel ("$(Get-Prop $d 'effect')"))
            Origin                 = (Get-PolicyOrigin $defId)
            NonCompliantResources  = (ConvertTo-Int (Get-Prop $res 'nonCompliantResources'))
        })
    }
    return @($out | Sort-Object @{ Expression = { -$_.NonCompliantResources } }, @{ Expression = { $_.Name.ToLowerInvariant() } })
}

# Mirrors the Python recommendation().
function Get-PolicyAction ([int]$NonCompliant) {
    if ($NonCompliant -le 0) { return @{ Action = 'Keep'; Reason = 'Assignment is compliant.' } }
    return @{ Action = 'Remediate'; Reason = "$NonCompliant non-compliant resource(s); run remediation or fix the resources." }
}

# Mirrors the Python severity mapping: nc>=10 high, nc>0 medium, else low.
function Get-PolicySeverity ([int]$NonCompliant) {
    if ($NonCompliant -ge 10) { return 'high' }
    if ($NonCompliant -gt 0)  { return 'medium' }
    return 'low'
}

# Mirrors the Python _scope_assignments(): list assignments at exactly this scope, paged.
# Returns a hashtable { assignmentIdLower = displayName }, or $null if the list could not be
# read (so the caller falls back to the unfiltered roll-up rather than hiding everything).
function Get-ScopeAssignments ($Headers, [string]$ScopePath) {
    $map = @{}
    $next = "https://management.azure.com$ScopePath/providers/Microsoft.Authorization/policyAssignments?api-version=$AssignmentsApi&`$filter=atExactScope()"
    $guard = 0
    try {
        while ($next -and $guard -lt 50) {
            $guard++
            $resp = Invoke-RestMethod -Method GET -Uri $next -Headers $Headers -ErrorAction Stop
            foreach ($a in @(Get-Prop $resp 'value')) {
                $aid = ("$(Get-Prop $a 'id')").ToLowerInvariant()
                if (-not $aid) { continue }
                $props = Get-Prop $a 'properties'
                $disp  = ("$(Get-Prop $props 'displayName')").Trim()
                $map[$aid] = if ($disp) { $disp } else { Get-AssignmentName ("$(Get-Prop $a 'id')") }
            }
            $nl = Get-Prop $resp 'nextLink'
            $next = if ($nl) { [string]$nl } else { "" }
        }
    } catch {
        return $null
    }
    return $map
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

Set-ScanProgress -Phase "init" -Message "Acquiring ARM token..."
$scopeLabel = if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) { "management group '$ManagementGroupId'" }
              elseif ($SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }
Write-Progress2 "Policy Compliance scan — scope: $scopeLabel"
Write-Progress2 "Acquiring ARM token from the active Az session..."
$armTok     = Get-ArmToken
$armExpires = $armTok.ExpiresOn
$armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }

# ── resolve the list of summarize targets ─────────────────────────────────────
# Each target carries the ARM path prefix (up to the PolicyInsights provider) and a label.
$targets = [System.Collections.Generic.List[object]]::new()

if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) {
    $mgName = $ManagementGroupId
    try {
        $mg = Get-AzManagementGroup -GroupName $ManagementGroupId -ErrorAction Stop
        if ($mg -and $mg.DisplayName) { $mgName = "$($mg.DisplayName)" }
    } catch { <# name resolution is cosmetic; fall back to the id #> }
    $targets.Add([pscustomobject]@{
        Path             = "/providers/Microsoft.Management/managementGroups/$ManagementGroupId"
        Label            = "Management group: $mgName"
        SubscriptionId   = ""
        SubscriptionName = ""
    })
} else {
    # Subscription scope: one sub, or all visible subscriptions.
    $subs = [System.Collections.Generic.List[object]]::new()
    if ($SingleSubscriptionId) {
        $name = $SingleSubscriptionId
        try {
            $s = Get-AzSubscription -SubscriptionId $SingleSubscriptionId -ErrorAction Stop
            if ($s -and $s.Name) { $name = "$($s.Name)" }
        } catch { <# fall back to the id as the display name #> }
        $subs.Add([pscustomobject]@{ Id = $SingleSubscriptionId; Name = $name })
    } else {
        Write-Progress2 "Listing subscriptions..."
        try {
            foreach ($s in Get-AzSubscription -ErrorAction Stop) {
                if ($s.State -eq 'Enabled') { $subs.Add([pscustomobject]@{ Id = "$($s.Id)"; Name = "$($s.Name)" }) }
            }
        } catch {
            $errors.Add(@{ Stage = "subscriptions"; Error = (Format-Exception $_) })
        }
    }
    foreach ($s in $subs) {
        $targets.Add([pscustomobject]@{
            Path             = "/subscriptions/$($s.Id)"
            Label            = $s.Name
            SubscriptionId   = $s.Id
            SubscriptionName = $s.Name
        })
    }
}

$total = $targets.Count
Set-ScanProgress -Phase "scanning" -Total $total -Message "Summarizing policy state for $total scope(s)..."
Write-Progress2 "Summarizing policy state for $total scope(s)..."

$ncResourcesTotal = 0
$ncAssignments    = 0
$targetsWithData  = 0
$done             = 0

foreach ($target in $targets) {
    $done++

    # Refresh the ARM token if it is within ~5 minutes of expiry (long scans outlive it).
    if ($armExpires -le [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        try {
            $armTok     = Get-ArmToken
            $armExpires = $armTok.ExpiresOn
            $armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }
        } catch { <# keep the current token; the request below will surface any auth error #> }
    }

    $url = "https://management.azure.com$($target.Path)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=$ApiVersion"
    try {
        $resp = Invoke-RestMethod -Method POST -Uri $url -Headers $armHeaders -Body '{}' -ContentType 'application/json' -ErrorAction Stop
    } catch {
        $errors.Add(@{ Stage = "$($target.Label)"; Error = (Format-Exception $_) })
        Write-Progress2 "$($target.Label): policy summarize failed ($(Format-Exception $_))"
        Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar $ncAssignments -Message "Summarized $done/$total scope(s)..."
        continue
    }

    $value       = @(Get-Prop $resp 'value')
    $first       = if ($value.Count) { $value[0] } else { $null }
    $assignments = @(Get-Prop $first 'policyAssignments')
    $targetsWithData++

    # Keep only assignments living on this exact scope; the summarize roll-up otherwise
    # includes every descendant/inherited one.
    $scopeMap = Get-ScopeAssignments $armHeaders $target.Path
    if ($null -eq $scopeMap) {
        $errors.Add(@{ Stage = "$($target.Label)"; Error = "Could not list scope assignments; showing the full roll-up (may include assignments from child scopes)." })
    }

    foreach ($a in $assignments) {
        $aid = ("$(Get-Prop $a 'policyAssignmentId')").ToLowerInvariant()
        if ($null -ne $scopeMap -and -not $scopeMap.ContainsKey($aid)) { continue }
        $res   = Get-Prop $a 'results'
        $nc    = ConvertTo-Int (Get-Prop $res 'nonCompliantResources')
        $ncPol = ConvertTo-Int (Get-Prop $res 'nonCompliantPolicies')
        if ($nc -le 0 -and $ncPol -le 0) { continue }
        $ncResourcesTotal += $nc
        $ncAssignments++
        $disp = if ($null -ne $scopeMap -and $scopeMap.ContainsKey($aid)) { $scopeMap[$aid] } else { "" }
        $assignmentId = "$(Get-Prop $a 'policyAssignmentId')"
        $severity = Get-PolicySeverity $nc

        $items.Add([ordered]@{
            AssignmentId          = $assignmentId
            AssignmentName        = if ($disp) { $disp } else { Get-AssignmentName $assignmentId }
            ScopeName             = $target.Label
            SubscriptionId        = $target.SubscriptionId
            SubscriptionName      = if ($target.SubscriptionName) { $target.SubscriptionName } else { $target.Label }
            DefinitionKind        = (Get-DefinitionKind $a)
            Origin                = (Get-Origin $a)
            Effects               = (Get-Effects $a)
            ChildPolicies         = (Get-ChildPolicies $a)
            NonCompliantResources = $nc
            NonCompliantPolicies  = $ncPol
            Severity              = $severity
            RecommendedAction     = (Get-PolicyAction $nc)
        })
    }

    Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar $ncAssignments `
                     -Message "Summarized $done/$total scope(s)..."
}

#endregion

#region ── write output ─────────────────────────────────────────────────────────

# Sort by non-compliant resource count, descending (mirrors the Python items.sort).
$sortedItems = @($items | Sort-Object @{ Expression = { $_.NonCompliantResources }; Descending = $true })

if ($targetsWithData -eq 0 -and $sortedItems.Count -eq 0) {
    $errors.Add(@{ Stage = "policy"; Error = "No policy compliance data was returned. Confirm the identity can read Microsoft.PolicyInsights at this scope and that Azure Policy assignments exist." })
}

# Severity rollup for the summary cards.
$highCount = 0; $mediumCount = 0; $lowCount = 0
foreach ($it in $sortedItems) {
    switch ($it.Severity) { 'high' { $highCount++ } 'medium' { $mediumCount++ } default { $lowCount++ } }
}

$output = @{
    ScanMetadata = @{
        ScanTime                  = $scanStartTime.ToString("o")
        CompletedTime             = (Get-Date).ToString("o")
        ScopeType                 = $ScopeType
        ManagementGroupId         = $ManagementGroupId
        ScopeLabel                = $scopeLabel
        ScopesScanned             = $total
        ScopesWithData            = $targetsWithData
        NonCompliantAssignments   = $ncAssignments
        NonCompliantResources     = $ncResourcesTotal
        HighCount                 = $highCount
        MediumCount               = $mediumCount
        LowCount                  = $lowCount
        TotalItems                = $sortedItems.Count
        ErrorCount                = $errors.Count
    }
    Items  = $sortedItems
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $sortedItems.Count -Total $sortedItems.Count -FlaggedSoFar $ncAssignments -Message "Scan complete."
$output | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($sortedItems.Count) non-compliant assignment(s) across $targetsWithData scope(s) — $ncResourcesTotal non-compliant resource(s). Wrote $OutputPath"

#endregion
