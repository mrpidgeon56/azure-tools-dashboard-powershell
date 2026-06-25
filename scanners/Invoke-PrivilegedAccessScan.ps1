#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources, Az.ResourceGraph, Az.ManagementGroups
<#
.SYNOPSIS
    Scans management groups, subscriptions, and resource groups for STANDING (active)
    privileged role assignments held DIRECTLY by users and service principals — i.e.
    privileged access that bypasses group-based governance.

    "Privileged" = a configurable set of high-impact built-in roles (default: Owner,
    Contributor, User Access Administrator, Role Based Access Control Administrator).

    Only assignments defined directly at each scope are reported (inherited assignments
    are filtered out so each finding is attributable to where it was granted).

.OUTPUTS
    JSON file at -OutputPath (default: ./pa-scan-results.json)

.NOTES
    Required permissions:
      - Reader (or any role granting Microsoft.Authorization/roleAssignments/read) at the
        scopes being scanned.
      - Directory read is needed for Get-AzRoleAssignment to resolve principal display
        names/UPNs; without it, names are blank and the principal shows as "Unknown"
        (which this tool reports as an orphaned assignment).
    Required Az modules: Az.Accounts, Az.Resources. (Az.ManagementGroups for MG scope.)
#>
[CmdletBinding()]
param(
    [string]   $OutputPath   = "$PSScriptRoot/../data/pa-scan-results.json",
    [string]   $ProgressPath  = "",                # if set, incremental progress JSON is written here
    [string[]] $ExcludeSubscriptions = @(),        # subscription IDs to skip
    [string]   $SingleSubscriptionId = "",         # if set, only scan this one subscription (skips MGs)
    [ValidateSet('All','ManagementGroup','Subscription','ResourceGroup')]
    [string]   $ScopeType         = "All",          # scope selector from the dashboard
    [string]   $ManagementGroupId = "",             # if set (with ScopeType=ManagementGroup), scan this MG + its descendant subscriptions
    [string]   $ResourceGroup     = "",             # if set (with ScopeType=ResourceGroup), restrict to this RG within the subscription
    [string[]] $PrivilegedRoles = @('Owner','Contributor','User Access Administrator','Role Based Access Control Administrator'),
    [bool]     $IncludeManagementGroups = $true,   # scan MG-scope assignments (ignored in single-sub mode)
    [int]      $ThrottleLimit = 8                   # max resource groups scanned concurrently (1 = sequential)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region ── helpers ──────────────────────────────────────────────────────────────

# Shared progress state + a rolling tail of human-readable log lines. The dashboard
# polls the progress file and streams the LogTail as live output during a scan.
$script:logTail       = [System.Collections.Generic.List[string]]::new()
$script:progressState = [ordered]@{
    Phase = "init"; Percent = 0; SubIndex = 0; TotalSubs = 0; CurrentSub = "";
    RgIndex = 0; TotalRgs = 0; CurrentRg = ""; FlaggedSoFar = 0; Message = ""
}

function Save-Progress {
    if (-not $ProgressPath) { return }
    $payload = [ordered]@{}
    foreach ($k in $script:progressState.Keys) { $payload[$k] = $script:progressState[$k] }
    $payload.LogTail   = @($script:logTail)
    $payload.UpdatedAt = (Get-Date).ToString("o")
    try {
        $payload | ConvertTo-Json -Depth 5 | Set-Content -Path $ProgressPath -Encoding UTF8 -ErrorAction Stop
    } catch { <# progress writes are best-effort #> }
}

function Write-Progress2 ($msg) {
    $ts   = Get-Date -Format "HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line -ForegroundColor Cyan
    $script:logTail.Add($line)
    while ($script:logTail.Count -gt 12) { $script:logTail.RemoveAt(0) }
    Save-Progress
}

function Write-ScanProgress {
    param(
        [string] $Phase,                 # init | scanning | done
        [int]    $SubIndex      = 0,
        [int]    $TotalSubs     = 0,
        [string] $CurrentSub    = "",
        [int]    $RgIndex       = 0,
        [int]    $TotalRgs      = 0,
        [string] $CurrentRg     = "",
        [int]    $FlaggedSoFar  = 0,
        [string] $Message       = ""
    )
    if (-not $ProgressPath) { return }
    $percent = 0
    if ($TotalSubs -gt 0) {
        $subFraction = if ($TotalRgs -gt 0) { $RgIndex / $TotalRgs } else { 0 }
        $percent = [math]::Round((([math]::Max($SubIndex - 1, 0)) + $subFraction) / $TotalSubs * 100, 1)
    }
    if ($Phase -eq "done") { $percent = 100 }
    $script:progressState = [ordered]@{
        Phase = $Phase; Percent = $percent; SubIndex = $SubIndex; TotalSubs = $TotalSubs
        CurrentSub = $CurrentSub; RgIndex = $RgIndex; TotalRgs = $TotalRgs; CurrentRg = $CurrentRg
        FlaggedSoFar = $FlaggedSoFar; Message = $Message
    }
    Save-Progress
}

function Format-Exception ($err) {
    if ($null -eq $err) { return "" }
    $msg = if ($err.Exception) { $err.Exception.Message } else { "$err" }
    return ($msg -replace '\s+', ' ').Trim()
}

# Suggested remediation for a single privileged assignment.
function Get-PaRecommendation {
    param([string]$PrincipalType, [bool]$IsOrphaned, [string]$Role)
    if ($IsOrphaned)                       { return @{ Action = "Remove orphaned"; Reason = "Principal no longer exists in the directory." } }
    if ($PrincipalType -eq "User")         { return @{ Action = "Convert to PIM-eligible"; Reason = "Standing privileged access for a user — prefer just-in-time elevation." } }
    if ($PrincipalType -eq "ServicePrincipal") { return @{ Action = "Review SP access"; Reason = "Privileged role held directly by a service principal." } }
    return @{ Action = "Review"; Reason = "Direct privileged assignment." }
}

# Returns the DIRECT, privileged, user/SP/orphaned role assignments at one scope.
# Reusable across MG, subscription, and resource-group scopes.
function Get-PrivilegedAssignmentsAtScope {
    param(
        [string] $Scope,
        [string] $ScopeLevel,         # ManagementGroup | Subscription | ResourceGroup
        [string] $ScopeName,
        [string] $SubscriptionId,
        [string] $SubscriptionName,
        [string] $ResourceGroupName,
        [string[]] $PrivilegedRoles
    )
    $records = [System.Collections.Generic.List[object]]::new()
    $roleSet = @{}; foreach ($r in $PrivilegedRoles) { $roleSet[$r.ToLower()] = $true }

    $assignments = @(Get-AzRoleAssignment -Scope $Scope -ErrorAction Stop)
    foreach ($a in $assignments) {
        # Direct-at-scope only: drop assignments inherited from a higher scope.
        if ($a.Scope -ne $Scope) { continue }
        # Privileged roles only.
        if (-not $roleSet.ContainsKey(("" + $a.RoleDefinitionName).ToLower())) { continue }
        # Groups are excluded by design; keep User / ServicePrincipal / Unknown(orphaned).
        $ptype = "" + $a.ObjectType
        if ($ptype -eq "Group") { continue }

        $display    = "" + $a.DisplayName
        $isOrphaned = ($ptype -eq "Unknown") -or [string]::IsNullOrWhiteSpace($display)
        $rec        = Get-PaRecommendation -PrincipalType $ptype -IsOrphaned $isOrphaned -Role $a.RoleDefinitionName

        $records.Add([ordered]@{
            ScopeLevel           = $ScopeLevel
            ScopeName            = $ScopeName
            Scope                = $Scope
            SubscriptionId       = $SubscriptionId
            SubscriptionName     = $SubscriptionName
            ResourceGroupName     = $ResourceGroupName
            RoleDefinitionName   = $a.RoleDefinitionName
            PrincipalId          = "" + $a.ObjectId
            PrincipalType        = if ($isOrphaned) { "Unknown" } else { $ptype }
            PrincipalDisplayName = if ($isOrphaned) { "(deleted principal)" } else { $display }
            PrincipalSignInName  = "" + $a.SignInName
            IsOrphaned           = $isOrphaned
            RoleAssignmentId     = "" + $a.RoleAssignmentId
            RecommendedAction    = $rec
        })
    }
    return $records
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$assignments   = [System.Collections.Generic.List[object]]::new()
$errors        = [System.Collections.Generic.List[object]]::new()
$countSoFar    = 0
$scopeCompleted = 0

if ($ThrottleLimit -gt 1) {
    $null = Enable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue
}

# ── Scope resolution ────────────────────────────────────────────────────────────
# Backward-compatible: ScopeType defaults to 'All'. A lone -SingleSubscriptionId
# (ScopeType unset) still restricts to that one subscription, as the standalone CLI
# relies on. Precedence:
#   ManagementGroup (+ $ManagementGroupId) → scan that MG scope + its descendant subscriptions.
#   else SingleSubscriptionId set          → restrict to that subscription (+ optional $ResourceGroup).
#   else                                   → all accessible subscriptions (+ all MGs).
$useMgScope = ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId)
# A resource-group restriction is only meaningful within a single subscription.
$rgFilter   = if (($ScopeType -eq 'ResourceGroup') -and $ResourceGroup) { $ResourceGroup } else { "" }

Write-ScanProgress -Phase "init" -Message "Fetching subscriptions..."
Write-Progress2 "Fetching subscriptions..."
$allSubs = @(Get-AzSubscription | Where-Object {
    $_.State -eq "Enabled" -and $_.Id -notin $ExcludeSubscriptions
})

if ($useMgScope) {
    # Management-group scope: scan the MG itself, then only its descendant subscriptions.
    $IncludeManagementGroups = $false   # handled explicitly below
    $descendantSubIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        # Resolve descendant subscriptions via a paged Resource Graph query rather than
        # walking the (throttle-prone) -Expand -Recurse management-group tree. Search-AzGraph
        # caps a single page at 1000 rows regardless of -First, so -First 1000 alone would
        # silently truncate large tenants — loop on the SkipToken until it's exhausted.
        $descQuery = "ResourceContainers | where type == 'microsoft.resources/subscriptions' | project subscriptionId"
        $skip = $null
        do {
            $page = if ($skip) { Search-AzGraph -Query $descQuery -First 1000 -SkipToken $skip -ManagementGroup $ManagementGroupId }
                    else        { Search-AzGraph -Query $descQuery -First 1000 -ManagementGroup $ManagementGroupId }
            foreach ($row in @($page)) {
                if ($row.PSObject.Properties['subscriptionId'] -and $row.subscriptionId) {
                    [void]$descendantSubIds.Add($row.subscriptionId)
                }
            }
            $skip = $page.PSObject.Properties['SkipToken'] ? $page.SkipToken : $null
        } while ($skip)
    } catch {
        $errors.Add(@{ Scope = $ManagementGroupId; ScopeLevel = "ManagementGroup"; Error = (Format-Exception $_) })
        Write-Progress2 "Could not expand management group '$ManagementGroupId' ($(Format-Exception $_))."
    }
    $subscriptions = @($allSubs | Where-Object { $descendantSubIds.Contains($_.Id) })
    Write-Progress2 "Management-group scope: $ManagementGroupId — $($subscriptions.Count) descendant subscription(s)."
} elseif ($SingleSubscriptionId) {
    $subscriptions = @($allSubs | Where-Object { $_.Id -eq $SingleSubscriptionId })
    if (-not $subscriptions) { throw "No enabled subscription found with ID '$SingleSubscriptionId'." }
    $IncludeManagementGroups = $false   # single-sub mode is intentionally narrow
    Write-Progress2 "Single-subscription mode: $($subscriptions[0].Name) ($SingleSubscriptionId)$(if ($rgFilter) { " | resource group: $rgFilter" })"
} else {
    $subscriptions = $allSubs
    Write-Progress2 "Found $($subscriptions.Count) enabled subscription(s)."
}

# ── Management-group scope assignments ──────────────────────────────────────────
# 'All' scans every MG; ManagementGroup scope scans only the chosen MG.
$mgsToScan = @()
if ($useMgScope) {
    try {
        $mg = Get-AzManagementGroup -GroupName $ManagementGroupId -ErrorAction Stop
        $mgsToScan = @($mg)
    } catch {
        $errors.Add(@{ Scope = $ManagementGroupId; ScopeLevel = "ManagementGroup"; Error = (Format-Exception $_) })
    }
} elseif ($IncludeManagementGroups) {
    try {
        $mgsToScan = @(Get-AzManagementGroup -ErrorAction Stop)
    } catch {
        Write-Progress2 "Management groups unavailable ($(Format-Exception $_)); continuing with subscriptions."
        $errors.Add(@{ Scope = "(management groups)"; ScopeLevel = "ManagementGroup"; Error = (Format-Exception $_) })
    }
}
if ($mgsToScan.Count) {
    Write-Progress2 "Scanning $($mgsToScan.Count) management group(s) for direct privileged assignments..."
    foreach ($mg in $mgsToScan) {
        try {
            $mgScope = "/providers/Microsoft.Management/managementGroups/$($mg.Name)"
            $recs = Get-PrivilegedAssignmentsAtScope -Scope $mgScope -ScopeLevel "ManagementGroup" `
                        -ScopeName $mg.DisplayName -SubscriptionId ("mg:" + $mg.Name) `
                        -SubscriptionName ("MG · " + $mg.DisplayName) -ResourceGroupName "" `
                        -PrivilegedRoles $PrivilegedRoles
            foreach ($r in $recs) { $assignments.Add($r); $countSoFar++ }
        } catch {
            $errors.Add(@{ Scope = $mg.Name; ScopeLevel = "ManagementGroup"; Error = (Format-Exception $_) })
        }
    }
}

# Consumes the stream of per-RG result objects (sequential or parallel producer),
# accumulating records/errors and advancing the progress bar. Runs in the MAIN
# runspace, so shared-state mutation here is single-threaded and race-free.
$consumeRgResult = {
    process {
        $r = $_
        $script:scopeCompleted++
        if ($r.Records) { foreach ($rec in $r.Records) { $assignments.Add($rec); $script:countSoFar++ } }
        if ($r.Error)   { $errors.Add($r.Error) }
        Write-ScanProgress -Phase "scanning" -SubIndex $subIndex -TotalSubs $subscriptions.Count `
                           -CurrentSub $sub.Name -RgIndex $script:scopeCompleted -TotalRgs $total `
                           -CurrentRg $r.ScopeName -FlaggedSoFar $script:countSoFar `
                           -Message "Scanned $($r.ScopeName)"
        Write-Progress2 "  [$($script:scopeCompleted)/$total] $($r.ScopeName)"
    }
}

$subIndex = 0
foreach ($sub in $subscriptions) {
    $subIndex++
    Write-Progress2 "[$subIndex/$($subscriptions.Count)] Scanning subscription: $($sub.Name) ($($sub.Id))"
    Write-ScanProgress -Phase "scanning" -SubIndex $subIndex -TotalSubs $subscriptions.Count `
                       -CurrentSub $sub.Name -FlaggedSoFar $countSoFar `
                       -Message "Enumerating resource groups in $($sub.Name)..."
    try {
        $null = Set-AzContext -SubscriptionId $sub.Id -WarningAction SilentlyContinue

        # Subscription-scope assignments (done once in the main runspace). Skipped when
        # scoping to a single resource group — the caller asked only for that RG.
        if (-not $rgFilter) {
            try {
                $subScope = "/subscriptions/$($sub.Id)"
                $recs = Get-PrivilegedAssignmentsAtScope -Scope $subScope -ScopeLevel "Subscription" `
                            -ScopeName $sub.Name -SubscriptionId $sub.Id -SubscriptionName $sub.Name `
                            -ResourceGroupName "" -PrivilegedRoles $PrivilegedRoles
                foreach ($r in $recs) { $assignments.Add($r); $countSoFar++ }
            } catch {
                $errors.Add(@{ Scope = $sub.Id; ScopeLevel = "Subscription"; Error = (Format-Exception $_) })
            }
        }

        # Resource groups — constrained to a single RG when one was requested (case-insensitive).
        $resourceGroups = if ($rgFilter) {
            @(Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -ieq $rgFilter })
        } else {
            @(Get-AzResourceGroup)
        }
        $total          = $resourceGroups.Count
        $scopeCompleted = 0
        $useParallel    = ($ThrottleLimit -gt 1 -and $total -gt 1)

        Write-ScanProgress -Phase "scanning" -SubIndex $subIndex -TotalSubs $subscriptions.Count `
                           -CurrentSub $sub.Name -RgIndex 0 -TotalRgs $total -FlaggedSoFar $countSoFar `
                           -Message "Scanning $total resource group(s) in $($sub.Name)$(if ($useParallel) { " — up to $ThrottleLimit at a time" })..."

        if ($useParallel) {
            # Functions defined here aren't visible inside -Parallel runspaces, so
            # serialise their definitions and rebuild them in each runspace. The Az
            # context is shared in-process via process-scoped autosave.
            $funcNames = 'Get-PrivilegedAssignmentsAtScope','Get-PaRecommendation','Format-Exception'
            $funcDefs  = ($funcNames | ForEach-Object { "function $_ {`n$((Get-Command $_).ScriptBlock)`n}" }) -join "`n"

            $resourceGroups | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                . ([scriptblock]::Create($using:funcDefs))
                $rg    = $_
                $sub2  = $using:sub
                $scope = "/subscriptions/$($sub2.Id)/resourceGroups/$($rg.ResourceGroupName)"
                try {
                    $recs = Get-PrivilegedAssignmentsAtScope -Scope $scope -ScopeLevel "ResourceGroup" `
                                -ScopeName $rg.ResourceGroupName -SubscriptionId $sub2.Id `
                                -SubscriptionName $sub2.Name -ResourceGroupName $rg.ResourceGroupName `
                                -PrivilegedRoles $using:PrivilegedRoles
                    [pscustomobject]@{ Records = $recs; Error = $null; ScopeName = $rg.ResourceGroupName }
                } catch {
                    [pscustomobject]@{ Records = @(); ScopeName = $rg.ResourceGroupName; Error = @{
                        Scope = $rg.ResourceGroupName; ScopeLevel = "ResourceGroup"; SubscriptionId = $sub2.Id
                        Error = (Format-Exception $_) } }
                }
            } | & $consumeRgResult
        } else {
            $resourceGroups | ForEach-Object {
                $rg    = $_
                $scope = "/subscriptions/$($sub.Id)/resourceGroups/$($rg.ResourceGroupName)"
                try {
                    $recs = Get-PrivilegedAssignmentsAtScope -Scope $scope -ScopeLevel "ResourceGroup" `
                                -ScopeName $rg.ResourceGroupName -SubscriptionId $sub.Id `
                                -SubscriptionName $sub.Name -ResourceGroupName $rg.ResourceGroupName `
                                -PrivilegedRoles $PrivilegedRoles
                    [pscustomobject]@{ Records = $recs; Error = $null; ScopeName = $rg.ResourceGroupName }
                } catch {
                    [pscustomobject]@{ Records = @(); ScopeName = $rg.ResourceGroupName; Error = @{
                        Scope = $rg.ResourceGroupName; ScopeLevel = "ResourceGroup"; SubscriptionId = $sub.Id
                        Error = (Format-Exception $_) } }
                }
            } | & $consumeRgResult
        }
    } catch {
        $errors.Add(@{ Scope = $sub.Id; ScopeLevel = "Subscription"; Error = (Format-Exception $_) })
        Write-Warning "Error accessing subscription $($sub.Id): $(Format-Exception $_)"
    }
}

#endregion

#region ── write output ─────────────────────────────────────────────────────────

$distinctPrincipals = @($assignments | Where-Object { -not $_.IsOrphaned } |
                        ForEach-Object { $_.PrincipalId } | Select-Object -Unique).Count
$orphanedCount = @($assignments | Where-Object { $_.IsOrphaned }).Count
$userCount     = @($assignments | Where-Object { $_.PrincipalType -eq "User" }).Count
$spCount       = @($assignments | Where-Object { $_.PrincipalType -eq "ServicePrincipal" }).Count

$output = @{
    ScanMetadata = @{
        ScanTime              = $scanStartTime.ToString("o")
        CompletedTime         = (Get-Date).ToString("o")
        SubscriptionsScanned  = $subscriptions.Count
        PrivilegedRoles       = @($PrivilegedRoles)
        IncludedManagementGroups = [bool]$IncludeManagementGroups
        ScopeType             = $ScopeType
        ManagementGroupId     = $ManagementGroupId
        ResourceGroup         = $ResourceGroup
        TotalAssignments      = $assignments.Count
        DistinctPrincipals    = $distinctPrincipals
        UserAssignments       = $userCount
        ServicePrincipalAssignments = $spCount
        OrphanedAssignments   = $orphanedCount
        ErrorCount            = $errors.Count
    }
    Assignments = $assignments
    Errors      = $errors
}

Write-ScanProgress -Phase "done" -Message "Scan complete." -FlaggedSoFar $countSoFar
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($assignments.Count) privileged assignment(s) across $($subscriptions.Count) subscription(s). Wrote $OutputPath"

#endregion
