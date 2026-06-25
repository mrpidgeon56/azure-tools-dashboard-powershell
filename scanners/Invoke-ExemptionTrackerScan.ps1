#Requires -Version 7.0
#Requires -Modules Az.Accounts
<#
.SYNOPSIS
    Azure Policy exemption tracker.

    Enumerates Microsoft.Authorization/policyExemptions across the chosen scope and
    reports, for each exemption: the affected scope, the policy assignment it exempts,
    its category (Waiver vs Mitigated), who created it (from resource systemData), when
    it was created, and — the point of the tool — its expiry. Exemptions are flagged by
    lifecycle: expired (still present but no longer in effect — clean it up), expiring
    soon (<= 30 days — renew or let it lapse) and never-expires (a permanent waiver that
    should carry a review date).

    Scope is selectable: a whole management group (one ARM call at the MG path), a single
    subscription, or all visible subscriptions.

.OUTPUTS
    JSON file at -OutputPath (default ../data/exemption-tracker-scan-results.json):
    { ScanMetadata, Items, Errors }

.NOTES
    Authentication reuses the in-memory Az context (no separate login): an ARM token is
    obtained with Get-AzAccessToken and the policyExemptions REST APIs are called directly.
    The signed-in identity needs only READER at the chosen scope. This is NOT a Resource-
    Graph tool — it lists exemptions per target scope.

    Required Az modules: Az.Accounts.
#>
[CmdletBinding()]
param(
    [string] $OutputPath           = "$PSScriptRoot/../data/exemption-tracker-scan-results.json",
    [string] $ProgressPath         = "",          # if set, incremental progress JSON is written here
    [ValidateSet('All','ManagementGroup','Subscription')]
    [string] $ScopeType            = "All",        # scan scope: whole tenant, one management group, or one subscription
    [string] $ManagementGroupId    = "",           # when -ScopeType ManagementGroup: the MG to list exemptions on
    [string] $SingleSubscriptionId = ""            # optional: scan just one subscription
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ApiVersion       = '2022-07-01-preview'
$ExpiringSoonDays = 30
# An exemption created within this many days is "new" — worth a fresh review, since a
# just-added exemption is a deliberate hole punched in a policy.
$NewDays          = 7

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

# Parse an Azure timestamp into a UTC DateTimeOffset, or $null when absent/unparseable.
function ConvertTo-Dto ($value) {
    if (-not $value) { return $null }
    try {
        $s = "$value".Replace('Z', '+00:00')
        $dto = [DateTimeOffset]::Parse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
        return $dto.ToUniversalTime()
    } catch { return $null }
}

function Get-LastSegment ([string]$resourceId) {
    if (-not $resourceId) { return "" }
    return ($resourceId.TrimEnd('/') -split '/')[-1]
}

# The scope an exemption lives on = everything before the provider segment.
function Get-ExemptionScope ([string]$exemptionId) {
    $marker = '/providers/Microsoft.Authorization/policyExemptions/'
    $idx = $exemptionId.ToLower().IndexOf($marker.ToLower())
    if ($idx -ge 0) { return $exemptionId.Substring(0, $idx) }
    return $exemptionId
}

# Extract the subscription id from a resource id, or "" if there is none.
function Get-SubscriptionOf ([string]$resourceId) {
    $parts = @(($resourceId -split '/') | Where-Object { $_ })
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i].ToLower() -eq 'subscriptions' -and ($i + 1) -lt $parts.Count) { return $parts[$i + 1] }
    }
    return ""
}

# Human label for an exemption scope id (MG / subscription / RG / resource).
function Get-ScopeLabel ([string]$scope) {
    if (-not $scope) { return "—" }
    $parts = @(($scope -split '/') | Where-Object { $_ })
    $low = $scope.ToLower()
    if ($low.Contains('managementgroups')) {
        for ($i = 0; $i -lt $parts.Count; $i++) {
            if ($parts[$i].ToLower() -eq 'managementgroups' -and ($i + 1) -lt $parts.Count) { return "MG: $($parts[$i + 1])" }
        }
        return "Management group"
    }
    $rg = ""
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i].ToLower() -eq 'resourcegroups' -and ($i + 1) -lt $parts.Count) { $rg = $parts[$i + 1] }
    }
    if ($low.Contains('/providers/') -and $low.Contains('resourcegroups')) { return "$rg / $(Get-LastSegment $scope)" }
    if ($rg) { return "RG: $rg" }
    return "Subscription"
}

# Lifecycle state + severity for an exemption's expiry.
function Get-Lifecycle ($expiresOn, [DateTimeOffset]$now) {
    if ($null -eq $expiresOn) { return @{ State = 'never_expires'; Severity = 'low' } }
    if ($expiresOn -le $now)  { return @{ State = 'expired';       Severity = 'high' } }
    if (($expiresOn - $now).Days -le $ExpiringSoonDays) { return @{ State = 'expiring_soon'; Severity = 'medium' } }
    return @{ State = 'active'; Severity = 'ok' }
}

# Recommended action per lifecycle state.
function Get-ExemptionAction {
    param([string]$State, $ExpiresOn, [DateTimeOffset]$Now)
    switch ($State) {
        'expired' {
            $when = if ($ExpiresOn) { $ExpiresOn.ToString('yyyy-MM-dd') } else { 'previously' }
            return @{ Action = 'Remove exemption'; Reason = "Expired on $when — delete it so the policy applies again." }
        }
        'expiring_soon' {
            $days = if ($ExpiresOn) { ($ExpiresOn - $Now).Days } else { 0 }
            return @{ Action = 'Review before expiry'; Reason = "Expires in $days day(s); renew it or let it lapse deliberately." }
        }
        'never_expires' {
            return @{ Action = 'Set an expiry'; Reason = 'Permanent exemption — add an expiry date and a periodic review.' }
        }
        default {
            return @{ Action = 'Keep'; Reason = 'Active exemption with a future expiry.' }
        }
    }
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()
$now    = [DateTimeOffset]::UtcNow

$scopeLabel = if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) { "management group '$ManagementGroupId'" }
              elseif ($SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }

Set-ScanProgress -Phase "init" -Message "Acquiring ARM token..."
Write-Progress2 "Azure Policy exemption scan — scope: $scopeLabel"
Write-Progress2 "Acquiring ARM token from the active Az session..."
$armTok     = Get-ArmToken
$armExpires = $armTok.ExpiresOn
$armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }

# ── subscription name map (best-effort; name resolution is cosmetic) ───────────
$subNames = @{}
try {
    foreach ($s in Get-AzSubscription -ErrorAction Stop) {
        if ($s.State -eq 'Enabled') { $subNames["$($s.Id)"] = "$($s.Name)" }
    }
} catch {
    $errors.Add(@{ Stage = "subscriptions"; Error = (Format-Exception $_) })
}

# ── resolve the requested scope into a list of exemption-list targets ──────────
# A management group lists exemptions at its own ARM path (one call). A single
# subscription (or all visible ones) lists exemptions per subscription path.
$targets = [System.Collections.Generic.List[object]]::new()
if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) {
    $targets.Add([pscustomobject]@{
        Path             = "/providers/Microsoft.Management/managementGroups/$ManagementGroupId"
        Label            = "Management group: $ManagementGroupId"
        SubscriptionId   = ""
        SubscriptionName = ""
    })
} else {
    $subList = [System.Collections.Generic.List[object]]::new()
    if ($SingleSubscriptionId) {
        $name = if ($subNames.ContainsKey($SingleSubscriptionId)) { $subNames[$SingleSubscriptionId] } else { $SingleSubscriptionId }
        $subList.Add([pscustomobject]@{ Id = $SingleSubscriptionId; Name = $name })
    } else {
        Write-Progress2 "Listing subscriptions..."
        foreach ($id in $subNames.Keys) { $subList.Add([pscustomobject]@{ Id = $id; Name = $subNames[$id] }) }
    }
    foreach ($s in $subList) {
        $targets.Add([pscustomobject]@{
            Path             = "/subscriptions/$($s.Id)"
            Label            = $s.Name
            SubscriptionId   = $s.Id
            SubscriptionName = $s.Name
        })
    }
}

$total = $targets.Count
$flaggedSoFar = 0
Set-ScanProgress -Phase "scanning" -Total $total -Message "Listing policy exemptions for $total scope(s)..."
Write-Progress2 "Listing policy exemptions for $total scope(s)..."

$done = 0
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

    $uri = "https://management.azure.com$($target.Path)/providers/Microsoft.Authorization/policyExemptions?api-version=$ApiVersion"
    try {
        $guard = 0
        while ($uri -and $guard -lt 50) {
            $guard++
            $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $armHeaders -ErrorAction Stop
            foreach ($ex in @(Get-Prop $resp 'value')) {
                $props  = Get-Prop $ex 'properties'
                $system = Get-Prop $ex 'systemData'
                $exId   = "$(Get-Prop $ex 'id')"
                $scope  = Get-ExemptionScope $exId
                $expiresOn = ConvertTo-Dto (Get-Prop $props 'expiresOn')
                $life   = Get-Lifecycle $expiresOn $now
                $state  = $life.State
                $severity = $life.Severity
                $createdOn = ConvertTo-Dto (Get-Prop $system 'createdAt')
                $isNew = [bool]($createdOn -and (($now - $createdOn).Days -le $NewDays))
                $daysUntil = if ($expiresOn) { ($expiresOn - $now).Days } else { $null }
                $assignmentId = "$(Get-Prop $props 'policyAssignmentId')"
                $category = "$(Get-Prop $props 'exemptionCategory')".Trim(); if (-not $category) { $category = '—' }
                $exName = "$(Get-Prop $ex 'name')"; if (-not $exName) { $exName = Get-LastSegment $exId }
                $displayName = "$(Get-Prop $props 'displayName')".Trim(); if (-not $displayName) { $displayName = $exName }

                # Under an MG scope the target carries no subscription; recover the
                # exemption's own subscription id from its resource id when present.
                $subId   = if ($target.SubscriptionId) { $target.SubscriptionId } else { Get-SubscriptionOf $exId }
                $subName = if ($target.SubscriptionName) { $target.SubscriptionName }
                           elseif ($subId -and $subNames.ContainsKey($subId)) { $subNames[$subId] }
                           else { $subId }

                if ($state -eq 'expired' -or $state -eq 'expiring_soon') { $flaggedSoFar++ }

                $items.Add([ordered]@{
                    Id                  = $exId
                    Name                = $exName
                    DisplayName         = $displayName
                    SubscriptionId      = $subId
                    SubscriptionName    = $subName
                    Scope               = $scope
                    ScopeLabel          = (Get-ScopeLabel $scope)
                    PolicyAssignmentId  = $assignmentId
                    PolicyAssignmentName = (Get-LastSegment $assignmentId)
                    Category            = $category
                    Description         = "$(Get-Prop $props 'description')".Trim()
                    CreatedBy           = "$(Get-Prop $system 'createdBy')"
                    CreatedOn           = if ($createdOn) { $createdOn.ToString('o') } else { $null }
                    IsNew               = $isNew
                    ExpiresOn           = if ($expiresOn) { $expiresOn.ToString('o') } else { $null }
                    DaysUntilExpiry     = $daysUntil
                    State               = $state
                    Severity            = $severity
                    RecommendedAction   = (Get-ExemptionAction -State $state -ExpiresOn $expiresOn -Now $now)
                })
            }
            $next = Get-Prop $resp 'nextLink'
            $uri = if ($next) { [string]$next } else { "" }
        }
    } catch {
        $errors.Add(@{ Stage = "$($target.Label)"; Error = (Format-Exception $_) })
        Write-Progress2 "$($target.Label): $(Format-Exception $_)"
    }

    Set-ScanProgress -Phase "scanning" -Fetched $done -Total $total -FlaggedSoFar $flaggedSoFar `
                     -Message "Scanned $done/$total scope(s) — $($items.Count) exemption(s)..."
}

#endregion

#region ── write output ─────────────────────────────────────────────────────────

# Sort: expired first, then expiring soon, then never-expires, then active; within
# a state, by soonest expiry.
$order = @{ expired = 0; expiring_soon = 1; never_expires = 2; active = 3 }
$sorted = @($items | Sort-Object `
    @{ Expression = { $o = $order[$_.State]; if ($null -eq $o) { 9 } else { $o } } }, `
    @{ Expression = { if ($_.ExpiresOn) { $_.ExpiresOn } else { '9999' } } })

$waivers   = 0; $mitigated = 0
$expired   = 0; $expiringSoon = 0; $active = 0; $neverExpires = 0; $newExemptions = 0
foreach ($it in $sorted) {
    if ($it.Category -eq 'Waiver')    { $waivers++ }
    if ($it.Category -eq 'Mitigated') { $mitigated++ }
    switch ($it.State) {
        'expired'       { $expired++ }
        'expiring_soon' { $expiringSoon++ }
        'active'        { $active++ }
        'never_expires' { $neverExpires++ }
    }
    if ($it.IsNew) { $newExemptions++ }
}

$output = @{
    ScanMetadata = @{
        ScanTime             = $scanStartTime.ToString("o")
        CompletedTime        = (Get-Date).ToString("o")
        ScopeType            = $ScopeType
        ManagementGroupId    = $ManagementGroupId
        ScopeLabel           = $scopeLabel
        ScopesScanned        = $total
        SubscriptionsScanned = $total
        TotalExemptions      = $sorted.Count
        Waivers              = $waivers
        Mitigated            = $mitigated
        Expired              = $expired
        ExpiringSoon         = $expiringSoon
        Active               = $active
        NeverExpires         = $neverExpires
        NewExemptions        = $newExemptions
        TotalItems           = $sorted.Count
        ErrorCount           = $errors.Count
    }
    Items  = $sorted
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $sorted.Count -Total $sorted.Count -FlaggedSoFar $flaggedSoFar -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($sorted.Count) exemption(s) — $expired expired, $expiringSoon expiring soon, $neverExpires never expire. Wrote $OutputPath"

#endregion
