#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources, Az.Monitor, Az.CostManagement, Az.ResourceGraph
<#
.SYNOPSIS
    Scans all subscriptions in an Azure tenant and flags resource groups with no activity
    in the last 90 days across three signals: Activity Log, resource metrics, and lastModifiedTime.
    Also pulls estimated monthly cost per resource group via Cost Management.

.OUTPUTS
    JSON file at the path specified by -OutputPath (default: ./scan-results.json)

.NOTES
    Required permissions per subscription:
      - Reader (for resource enumeration and activity logs)
      - Cost Management Reader (for cost data)
    Required Az modules: Az.Accounts, Az.Resources, Az.Monitor, Az.CostManagement
#>
[CmdletBinding()]
param(
    [int]    $LookbackDays  = 90,   # idle-detection window: no activity in this many days = idle
    [string] $OutputPath    = "$PSScriptRoot/../data/scan-results.json",
    [string] $ProgressPath  = "",                # if set, incremental progress JSON is written here
    [string] $OwnerTagName  = "Owner",          # tag key used in your tenant for ownership
    [string] $TeamTagName   = "Team",
    [string[]] $ExcludeSubscriptions = @(),     # subscription IDs to skip
    [ValidateSet('All','ManagementGroup','Subscription','ResourceGroup')]
    [string]   $ScopeType         = "All",       # scan scope target (see scope resolution below)
    [string]   $ManagementGroupId = "",          # if set (with ScopeType=ManagementGroup), scan all subscriptions under this MG
    [string]   $ResourceGroup     = "",          # if set, restrict the scan to just this resource group in the chosen subscription
    [string]   $SingleSubscriptionId = "",      # if set, only scan this one subscription (useful for testing)
    [switch] $SkipCostData,                     # omit if Cost Management perms unavailable
    [switch] $SkipMetrics,                      # omit if metric queries are too slow
    [switch] $Incremental,                      # reuse cached per-RG results when a RG's resources are unchanged
    [int]    $MaxCacheAgeHours = 24,            # force a full re-scan of a cached RG older than this
    [int]    $ThrottleLimit = 8                 # max resource groups scanned concurrently (1 = sequential)
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

# Writes the combined structured progress + log tail to the progress file.
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

# Logs a line to the console AND the streamed progress tail.
function Write-Progress2 ($msg) {
    $ts   = Get-Date -Format "HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line -ForegroundColor Cyan
    $script:logTail.Add($line)
    while ($script:logTail.Count -gt 12) { $script:logTail.RemoveAt(0) }
    Save-Progress
}

# Updates the structured progress fields (percent, current sub/RG, counts).
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

    # Overall percent: completed subs + fractional progress through current sub
    $percent = 0
    if ($TotalSubs -gt 0) {
        $subFraction = if ($TotalRgs -gt 0) { $RgIndex / $TotalRgs } else { 0 }
        $percent = [math]::Round((([math]::Max($SubIndex - 1, 0)) + $subFraction) / $TotalSubs * 100, 1)
    }
    if ($Phase -eq "done") { $percent = 100 }

    $script:progressState = [ordered]@{
        Phase        = $Phase
        Percent      = $percent
        SubIndex     = $SubIndex
        TotalSubs    = $TotalSubs
        CurrentSub   = $CurrentSub
        RgIndex      = $RgIndex
        TotalRgs     = $TotalRgs
        CurrentRg    = $CurrentRg
        FlaggedSoFar = $FlaggedSoFar
        Message      = $Message
    }
    Save-Progress
}

# Normalize a Resource Graph row to the shape the detection functions expect
# (matching Get-AzResource: .ResourceId / .Name / .ResourceType / .ManagedBy / .Properties).
function Convert-GraphResource {
    param($row)
    [pscustomobject]@{
        ResourceId        = (Get-Prop $row 'id')
        Name              = (Get-Prop $row 'name')
        ResourceType      = (Get-Prop $row 'type')
        ResourceGroupName = (Get-Prop $row 'resourceGroup')
        Location          = (Get-Prop $row 'location')
        ManagedBy         = (Get-Prop $row 'managedBy')
        Properties        = (Get-Prop $row 'properties')
    }
}

# ONE Azure Resource Graph query returns every resource in the subscription; we
# group them by resource group. This replaces a per-RG Get-AzResource call
# (N network round-trips → 1 paged query). Returns a hashtable keyed by
# lower-cased RG name → List[resource], or $null to signal "fall back to per-RG".
function Get-SubscriptionResourceMap {
    param([string]$SubscriptionId)
    if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) { return $null }
    try {
        $query = "Resources | where subscriptionId == '$SubscriptionId' | project id, name, type, resourceGroup, location, managedBy, properties"
        $map   = @{}
        $skip  = $null
        do {
            $page = if ($skip) { Search-AzGraph -Query $query -First 1000 -SkipToken $skip }
                    else        { Search-AzGraph -Query $query -First 1000 }
            foreach ($row in @($page)) {
                $rg = [string](Get-Prop $row 'resourceGroup')
                if (-not $rg) { continue }
                $key = $rg.ToLowerInvariant()
                if (-not $map.ContainsKey($key)) { $map[$key] = [System.Collections.Generic.List[object]]::new() }
                $map[$key].Add((Convert-GraphResource $row))
            }
            $skip = $page.PSObject.Properties['SkipToken'] ? $page.SkipToken : $null
        } while ($skip)
        return $map
    } catch {
        Write-Progress2 "    Resource Graph query failed for sub ${SubscriptionId}: $($_.Exception.Message) — using per-RG fallback"
        return $null
    }
}

function Get-MetricsActivity {
    param([object[]]$Resources, [datetime]$Since)
    if ($SkipMetrics) { return $false }

    # Metric-bearing resource types worth checking (add more as needed)
    $metricTypes = @{
        "microsoft.compute/virtualmachines"          = "Percentage CPU"
        "microsoft.storage/storageaccounts"          = "Transactions"
        "microsoft.web/sites"                        = "Requests"
        "microsoft.sql/servers/databases"            = "dtu_consumption_percent"
        "microsoft.containerinstance/containergroups" = "CpuUsage"
        "microsoft.keyvault/vaults"                  = "ServiceApiHit"
        "microsoft.servicebus/namespaces"            = "IncomingMessages"
        "microsoft.eventhub/namespaces"              = "IncomingMessages"
    }

    foreach ($resource in $Resources) {
        $type = $resource.ResourceType.ToLower()
        if ($metricTypes.ContainsKey($type)) {
            try {
                $metric = Get-AzMetric -ResourceId $resource.ResourceId `
                                       -MetricName $metricTypes[$type] `
                                       -StartTime $Since `
                                       -EndTime (Get-Date) `
                                       -TimeGrain "1.00:00:00" `
                                       -AggregationType Total `
                                       -WarningAction SilentlyContinue
                $total = ($metric.Data | Measure-Object -Property Total -Sum).Sum
                if ($total -and $total -gt 0) { return $true }
            } catch { <# metric not available for this resource #> }
        }
    }
    return $false
}

function Get-RgActivity {
    # SINGLE Activity Log query per RG (Azure retains ~90 days) that serves BOTH
    # the idle-detection signal AND the "last updated / by whom" columns:
    #   • HasActivityInWindow — ANY event since the idle lookback window (read or write)
    #   • LastEventTime       — newest event of any kind
    #   • LastModifiedTime    — newest write/action/delete (latest of that or a resource timestamp)
    #   • LastModifiedBy/Raw  — caller of that newest write (the Activity Log is the only
    #                            source carrying the principal; resolved to a display name)
    # Replaces the previous two separate Get-AzActivityLog calls per RG.
    param(
        [string]$ResourceGroupName,
        [object[]]$Resources,
        [datetime]$Since,
        [int]$WindowDays = 90
    )

    $latestWriteTime = $null     # newest write/action/delete (drives "last updated")
    $latestEventTime = $null     # newest event of any kind (drives in-window activity)
    $latestBy        = $null

    # Resource-level ARM timestamps (present only in the Get-AzResource fallback path;
    # Resource Graph rows don't carry ChangedTime, so this is a harmless no-op there).
    foreach ($res in $Resources) {
        foreach ($propName in @('ChangedTime', 'CreatedTime')) {
            $p = $res.PSObject.Properties[$propName]
            if ($p -and $p.Value) {
                try {
                    $t = [datetime]$p.Value
                    if (-not $latestWriteTime -or $t -gt $latestWriteTime) { $latestWriteTime = $t }
                } catch {}
            }
        }
    }

    try {
        $start  = (Get-Date).AddDays(-$WindowDays)
        # Get-AzActivityLog has no -SubscriptionId parameter; uses the current context.
        $events = Get-AzActivityLog -ResourceGroupName $ResourceGroupName `
                                    -StartTime $start -EndTime (Get-Date) `
                                    -WarningAction SilentlyContinue -ErrorAction Stop
        foreach ($e in @($events)) {
            $etProp = $e.PSObject.Properties['EventTimestamp']
            if (-not ($etProp -and $etProp.Value)) { continue }
            try { $et = [datetime]$etProp.Value } catch { continue }

            if (-not $latestEventTime -or $et -gt $latestEventTime) { $latestEventTime = $et }

            # Is this a write/action/delete? Those drive the "last modified by" attribution.
            $auth = $e.PSObject.Properties['Authorization']
            $act  = if ($auth -and $auth.Value) {
                $ap = $auth.Value.PSObject.Properties['Action']
                if ($ap) { $ap.Value } else { $null }
            } else { $null }
            if ($act -match '/(write|action|delete)$') {
                if (-not $latestWriteTime -or $et -gt $latestWriteTime) {
                    $latestWriteTime = $et
                    $callerProp = $e.PSObject.Properties['Caller']
                    $latestBy   = if ($callerProp) { $callerProp.Value } else { $null }
                }
            }
        }
    } catch {}

    $hasInWindow = ($null -ne $latestEventTime -and $latestEventTime -gt $Since) -or `
                   ($null -ne $latestWriteTime -and $latestWriteTime -gt $Since)

    return @{
        HasActivityInWindow = $hasInWindow
        LastEventTime       = $latestEventTime
        LastModifiedTime    = $latestWriteTime
        LastModifiedBy      = Resolve-PrincipalName $latestBy
        LastModifiedByRaw   = $latestBy
    }
}

# StrictMode-safe property accessor: returns $null instead of throwing when the
# property is absent. The Advisor REST payloads are deeply nested and many
# recommendations omit fields (impact/category), so every dereference must be guarded.
function Get-Prop {
    param($obj, [string]$name)
    if ($null -eq $obj) { return $null }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

# Resolves an Activity Log "Caller" (a UPN/email for users, or an object/app GUID
# for service principals & managed identities) to a human-friendly display name.
# Results are cached for the scan's lifetime — directory lookups are slow and the
# same principals recur across many resource groups. Falls back to the raw caller
# when the directory object can't be resolved (e.g. deleted identity, no Graph perms).
# ConcurrentDictionary so the cache can be shared safely across parallel runspaces.
$script:principalNameCache = [System.Collections.Concurrent.ConcurrentDictionary[string,string]]::new()
function Resolve-PrincipalName {
    param([string]$Caller)
    if (-not $Caller) { return $null }
    if ($script:principalNameCache.ContainsKey($Caller)) { return $script:principalNameCache[$Caller] }

    $name = $null
    try {
        if ($Caller -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            # GUID → service principal (by object id, then app id) or user object id.
            $sp = Get-AzADServicePrincipal -ObjectId $Caller -ErrorAction SilentlyContinue
            if (-not $sp) { $sp = Get-AzADServicePrincipal -ApplicationId $Caller -ErrorAction SilentlyContinue }
            if ($sp -and $sp.DisplayName) {
                $name = $sp.DisplayName
            } else {
                $u = Get-AzADUser -ObjectId $Caller -ErrorAction SilentlyContinue
                if ($u -and $u.DisplayName) { $name = $u.DisplayName }
            }
        } else {
            # UPN / email → look up the user's display name.
            $u = Get-AzADUser -UPN $Caller -ErrorAction SilentlyContinue
            if (-not $u) { $u = Get-AzADUser -Mail $Caller -ErrorAction SilentlyContinue }
            if ($u -and $u.DisplayName) { $name = $u.DisplayName }
        }
    } catch {}

    if (-not $name) { $name = $Caller }   # graceful fallback to the raw caller
    $script:principalNameCache[$Caller] = $name
    return $name
}

function Get-SubscriptionAdvisorScore {
    # advisorScore returns one item per category. The overall score is the item
    # whose id ends in '/advisorScore/Advisor'. Named-category items (Security,
    # Cost, Performance, OperationalExcellence, HighAvailability) carry per-category
    # scores; GUID-suffixed items are per-recommendation-type and are ignored.
    # The score lives at properties.lastRefreshedScore.score.
    param([string]$SubscriptionId)
    try {
        $response = Invoke-AzRestMethod -Method GET `
            -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Advisor/advisorScore?api-version=2023-01-01"
        if ($response.StatusCode -ne 200) {
            Write-Progress2 "    advisorScore HTTP $($response.StatusCode) for sub $SubscriptionId"
            return $null
        }
        $items = @(Get-Prop ($response.Content | ConvertFrom-Json) 'value')
        if (-not $items.Count) { return $null }

        $overall = $null
        $cats    = @{}
        foreach ($it in $items) {
            $id  = [string](Get-Prop $it 'id')
            $seg = ($id -split '/')[-1]                       # last path segment = category name or GUID
            if ($seg -notmatch '^[A-Za-z]+$') { continue }    # skip GUID-suffixed per-rec items
            $score = Get-Prop (Get-Prop (Get-Prop $it 'properties') 'lastRefreshedScore') 'score'
            if ($null -eq $score) { continue }
            $rounded = [math]::Round([double]$score, 1)
            if ($seg -eq 'Advisor') { $overall = $rounded }
            else                    { $cats[$seg] = $rounded }
        }

        if ($null -eq $overall -and $cats.Count -eq 0) { return $null }
        return @{
            Overall        = $overall
            CategoryScores = $cats
        }
    } catch {
        Write-Progress2 "    advisorScore error for sub ${SubscriptionId}: $($_.Exception.Message)"
        return $null
    }
}

function Get-SubscriptionAdvisorRecommendations {
    # The per-resource-group recommendations endpoint returns 404 — Advisor does
    # not support RG-scoped queries. Instead we pull all recommendations for the
    # subscription ONCE and group them by resource group, parsed from each
    # recommendation's properties.resourceMetadata.resourceId. Returns a hashtable
    # keyed by lower-cased RG name → @{ Total; BySeverity; ByCategory }.
    param([string]$SubscriptionId)
    $byRg = @{}
    try {
        $response = Invoke-AzRestMethod -Method GET `
            -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Advisor/recommendations?api-version=2023-01-01"
        if ($response.StatusCode -ne 200) {
            Write-Progress2 "    advisor recs HTTP $($response.StatusCode) for sub $SubscriptionId"
            return $byRg
        }
        $recs = @(Get-Prop ($response.Content | ConvertFrom-Json) 'value')
        foreach ($r in $recs) {
            $props = Get-Prop $r 'properties'
            $sev   = Get-Prop $props 'impact'    # High / Medium / Low
            $cat   = Get-Prop $props 'category'  # Cost / Security / Reliability / OperationalExcellence / Performance

            # Resolve owning RG: prefer resourceMetadata.resourceId, fall back to the recommendation id.
            $resId = [string](Get-Prop (Get-Prop $props 'resourceMetadata') 'resourceId')
            if (-not $resId) { $resId = [string](Get-Prop $r 'id') }
            if ($resId -notmatch '(?i)/resourceGroups/([^/]+)') { continue }
            $rgKey = $Matches[1].ToLower()

            if (-not $byRg.ContainsKey($rgKey)) {
                $byRg[$rgKey] = @{ Total = 0; BySeverity = @{ High = 0; Medium = 0; Low = 0 }; ByCategory = @{} }
            }
            $entry = $byRg[$rgKey]
            $entry.Total++
            if ($sev -and $entry.BySeverity.ContainsKey($sev)) { $entry.BySeverity[$sev]++ }
            if ($cat) {
                if ($entry.ByCategory.ContainsKey($cat)) { $entry.ByCategory[$cat]++ } else { $entry.ByCategory[$cat] = 1 }
            }
        }
        return $byRg
    } catch {
        Write-Progress2 "    advisor recs error for sub ${SubscriptionId}: $($_.Exception.Message)"
        return $byRg
    }
}

function Get-SubscriptionCostByRg {
    # ONE Cost Management query for the whole subscription, grouped by ResourceGroupName.
    # Replaces a per-RG cost call (N → 1). Returns a hashtable keyed by lower-cased RG
    # name → @{ EstimatedMonthlyCost; Currency; ActualCostInPeriod }, or $null on failure.
    param([string]$SubscriptionId, [datetime]$PeriodStart)
    if ($SkipCostData) { return $null }
    try {
        $end  = Get-Date
        $days = ($end - $PeriodStart).TotalDays
        if ($days -le 0) { return $null }

        $body = @{
            type       = "Usage"
            timeframe  = "Custom"
            timePeriod = @{ from = $PeriodStart.ToString("yyyy-MM-dd", [System.Globalization.CultureInfo]::InvariantCulture); to = $end.ToString("yyyy-MM-dd", [System.Globalization.CultureInfo]::InvariantCulture) }
            dataset    = @{
                granularity = "None"
                aggregation = @{ totalCost = @{ name = "PreTaxCost"; function = "Sum" } }
                grouping    = @(@{ type = "Dimension"; name = "ResourceGroupName" })
            }
        } | ConvertTo-Json -Depth 10

        $response = Invoke-AzRestMethod -Method POST `
            -Path "/subscriptions/$SubscriptionId/providers/Microsoft.CostManagement/query?api-version=2023-11-01" `
            -Payload $body
        if ($response.StatusCode -ne 200) {
            Write-Progress2 "    cost query HTTP $($response.StatusCode) for sub $SubscriptionId"
            return @{}
        }

        $data = $response.Content | ConvertFrom-Json
        $cols = @(Get-Prop (Get-Prop $data 'properties') 'columns')
        # Resolve column indices by name (order can vary).
        $idxCost = -1; $idxRg = -1; $idxCur = -1
        for ($i = 0; $i -lt $cols.Count; $i++) {
            switch ((Get-Prop $cols[$i] 'name')) {
                'PreTaxCost'        { $idxCost = $i }
                'ResourceGroupName' { $idxRg   = $i }
                'Currency'          { $idxCur  = $i }
            }
        }
        if ($idxCost -lt 0 -or $idxRg -lt 0) { return @{} }

        $map = @{}
        foreach ($row in @(Get-Prop (Get-Prop $data 'properties') 'rows')) {
            $rgName = [string]$row[$idxRg]
            if (-not $rgName) { continue }                 # subscription-level/unassigned costs
            $raw = [double]$row[$idxCost]
            $map[$rgName.ToLowerInvariant()] = @{
                EstimatedMonthlyCost = [math]::Round(($raw / $days) * 30.4, 2)
                Currency             = if ($idxCur -ge 0) { [string]$row[$idxCur] } else { "USD" }
                ActualCostInPeriod   = [math]::Round($raw, 2)
            }
        }
        return $map
    } catch {
        Write-Progress2 "    cost query error for sub ${SubscriptionId}: $($_.Exception.Message)"
        return @{}
    }
}

# ── Safety & actionability signals ───────────────────────────────────────────

# Resource locks block deletion — surface them so an idle RG isn't a dead end.
function Get-RgResourceLocks {
    param([string]$ResourceGroupName)
    try {
        $locks = @(Get-AzResourceLock -ResourceGroupName $ResourceGroupName -ErrorAction Stop)
        return @($locks | ForEach-Object {
            $lvl   = if ($_.Properties -and $_.Properties.PSObject.Properties['level']) { $_.Properties.level } else { $null }
            $notes = if ($_.Properties -and $_.Properties.PSObject.Properties['notes']) { $_.Properties.notes } else { $null }
            @{ Name = $_.Name; Level = $lvl; Notes = $notes }
        })
    } catch { return @() }
}

# Detect resource groups managed by another service (AKS, Databricks, Backup, etc.)
# or Azure system RGs. These look idle but deleting them breaks the parent service.
function Get-ManagedReason {
    param($ResourceGroup, [object[]]$Resources)
    # Explicit managedBy on the RG
    if ($ResourceGroup.PSObject.Properties['ManagedBy'] -and $ResourceGroup.ManagedBy) {
        return "Managed by: $($ResourceGroup.ManagedBy)"
    }
    # Explicit managedBy on any contained resource
    $mr = $Resources | Where-Object { $_.PSObject.Properties['ManagedBy'] -and $_.ManagedBy } | Select-Object -First 1
    if ($mr) { return "Contains resources managed by another service" }
    # Well-known managed / system RG naming patterns
    $n = $ResourceGroup.ResourceGroupName
    switch -Regex ($n) {
        '^MC_'                 { return "AKS-managed node resource group" }
        '^databricks-rg-'      { return "Databricks-managed resource group" }
        '^AzureBackupRG_'      { return "Azure Backup managed resource group" }
        '^DefaultResourceGroup-'      { return "Azure Monitor system resource group" }
        '^NetworkWatcherRG'           { return "Network Watcher system resource group" }
        '^LogAnalyticsDefaultResources' { return "Log Analytics system resource group" }
        '^cloud-shell-storage-'       { return "Cloud Shell system resource group" }
        '^ResourceMoverRG-'           { return "Resource Mover system resource group" }
    }
    return $null
}

# Identify orphaned resources that cost money but serve nothing.
function Get-OrphanedResources {
    param([object[]]$Resources)
    $orphans = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Resources) {
        $type = $r.ResourceType.ToLower()
        $p    = if ($r.PSObject.Properties['Properties']) { $r.Properties } else { $null }
        $has  = { param($obj, $name) $obj -and $obj.PSObject.Properties[$name] -and $obj.PSObject.Properties[$name].Value }
        switch ($type) {
            "microsoft.compute/disks" {
                if ($p -and $p.PSObject.Properties['diskState'] -and $p.diskState -eq 'Unattached') {
                    $orphans.Add(@{ Name = $r.Name; Type = $r.ResourceType; Reason = "Unattached managed disk" })
                }
            }
            "microsoft.network/publicipaddresses" {
                if (-not (& $has $p 'ipConfiguration')) {
                    $orphans.Add(@{ Name = $r.Name; Type = $r.ResourceType; Reason = "Unassociated public IP address" })
                }
            }
            "microsoft.network/networkinterfaces" {
                if (-not (& $has $p 'virtualMachine')) {
                    $orphans.Add(@{ Name = $r.Name; Type = $r.ResourceType; Reason = "NIC not attached to a VM" })
                }
            }
            "microsoft.web/serverfarms" {
                if ($p -and $p.PSObject.Properties['numberOfSites'] -and [int]$p.numberOfSites -eq 0) {
                    $orphans.Add(@{ Name = $r.Name; Type = $r.ResourceType; Reason = "App Service plan with no apps" })
                }
            }
        }
    }
    return @($orphans)
}

# Derive an environment label from tags first, falling back to name conventions.
function Get-RgEnvironment {
    param($Tags, [string]$Name)
    if ($Tags) {
        foreach ($k in 'environment','env','Environment','Env') {
            if ($Tags.ContainsKey($k) -and $Tags[$k]) { return [string]$Tags[$k] }
        }
    }
    $n = $Name.ToLower()
    if ($n -match 'prod')                  { return 'prod' }
    if ($n -match 'uat|stag|stg')          { return 'staging' }
    if ($n -match 'dev|test|lab|sandbox|sbx') { return 'nonprod' }
    return $null
}

# A cheap content fingerprint of an RG: resource count + a hash of its sorted
# resource ids. Used by -Incremental to detect whether an RG's composition changed
# since the last scan; if not (and the cache is fresh), the cached record is reused.
function Get-RgFingerprint {
    param([object[]]$Resources)
    $ids    = @($Resources | ForEach-Object { [string]$_.ResourceId } | Sort-Object)
    $bytes  = [System.Text.Encoding]::UTF8.GetBytes(($ids -join "`n"))
    $hash   = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($bytes)) -replace '-', ''
    return "$($ids.Count):$hash"
}

# Roll everything up into a single recommended action + potential savings.
function Get-RecommendedAction {
    param($IsFlagged, $ManagedReason, $Locks, [int]$ResourceCount, $Cost, $Orphans)
    $savings = if ($Cost -and $Cost.EstimatedMonthlyCost) { [double]$Cost.EstimatedMonthlyCost } else { 0 }

    if ($ManagedReason) {
        return @{ Action = "Keep"; Reason = $ManagedReason; PotentialSavings = 0 }
    }
    if ($Locks -and @($Locks).Count -gt 0) {
        return @{ Action = "Review lock"; Reason = "$(@($Locks).Count) resource lock(s) prevent deletion"; PotentialSavings = $savings }
    }
    if (-not $IsFlagged) {
        return @{ Action = "Keep"; Reason = "Recent activity detected"; PotentialSavings = 0 }
    }
    if ($ResourceCount -eq 0) {
        return @{ Action = "Delete"; Reason = "Empty resource group"; PotentialSavings = $savings }
    }
    if ($Orphans -and @($Orphans).Count -gt 0) {
        return @{ Action = "Clean up orphans"; Reason = "$(@($Orphans).Count) orphaned resource(s) incurring cost"; PotentialSavings = $savings }
    }
    if ($savings -gt 0) {
        return @{ Action = "Decommission"; Reason = "Idle but still incurring cost"; PotentialSavings = $savings }
    }
    return @{ Action = "Delete"; Reason = "Idle with no measurable cost"; PotentialSavings = 0 }
}

function Format-Exception {
    <#
    .SYNOPSIS
        Extracts the most useful error text from an ErrorRecord.
        Az/ARM cmdlets scatter details across several places:
          - $_.Exception.Message          — often blank or just a CorrelationId line
          - $_.ErrorDetails.Message       — JSON body from the ARM REST response (most useful)
          - $_.Exception.Body             — parsed CloudException body (has Code + Message)
          - $_.Exception.InnerException   — underlying HttpRequestException / WebException
          - $_.Exception.Response         — raw HttpResponseMessage (status code)
          - $_.ScriptStackTrace           — where in the script it blew up
    #>
    param([System.Management.Automation.ErrorRecord]$Err)

    $parts = [System.Collections.Generic.List[string]]::new()

    # StrictMode-safe property reader (returns $null instead of throwing on missing prop)
    $prop = { param($obj, $name) if ($obj -and $obj.PSObject.Properties[$name]) { $obj.PSObject.Properties[$name].Value } else { $null } }

    # 1. ARM REST response body — richest source for Az cmdlet failures
    if ($Err.ErrorDetails?.Message) {
        try {
            $body = $Err.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
            # ARM error envelope: { error: { code, message } } or { code, message }
            $armErr = if (& $prop $body 'error') { & $prop $body 'error' } else { $body }
            $armMsg  = & $prop $armErr 'message'
            $armCode = & $prop $armErr 'code'
            if ($armMsg) {
                $detail = if ($armCode) { "[$armCode] $armMsg" } else { "$armMsg" }
                $parts.Add($detail)
            }
        } catch {
            # Not JSON — use raw string, stripping whitespace
            $raw = $Err.ErrorDetails.Message.Trim() -replace '\r?\n', ' '
            if ($raw) { $parts.Add($raw) }
        }
    }

    # 2. CloudException / ServiceException .Body (Az SDK typed error)
    if (-not $parts.Count -and $Err.Exception.PSObject.Properties['Body']) {
        $body = $Err.Exception.Body
        if ($body) {
            $bodyMsg = if ($body.PSObject.Properties['Message']) { $body.Message } else { $body.ToString() }
            $bodyCode = if ($body.PSObject.Properties['Code'])    { $body.Code    } else { $null }
            if ($bodyMsg) {
                $parts.Add($(if ($bodyCode) { "[$bodyCode] $bodyMsg" } else { $bodyMsg }))
            }
        }
    }

    # 3. Exception.Message — skip if it's blank or only a CorrelationId
    $exMsg = $Err.Exception.Message?.Trim() -replace '\r?\n', ' '
    if ($exMsg -and $exMsg -notmatch '^[\s\r\n]*CorrelationId') {
        $parts.Add($exMsg)
    }

    # 4. Walk the inner exception chain
    $inner = $Err.Exception.InnerException
    $depth = 0
    while ($inner -and $depth -lt 3) {
        $innerMsg = $inner.Message?.Trim() -replace '\r?\n', ' '
        if ($innerMsg -and $innerMsg -ne $exMsg) { $parts.Add("Inner: $innerMsg") }
        $inner = $inner.InnerException
        $depth++
    }

    # 5. HTTP status code from the response if available
    $response = $Err.Exception.PSObject.Properties['Response']?.Value
    if ($response -and $response.PSObject.Properties['StatusCode']) {
        $parts.Add("HTTP $([int]$response.StatusCode) $($response.StatusCode)")
    }

    # 6. CorrelationId — always append if present, useful for Azure support
    if ($Err.Exception.Message -match 'CorrelationId[:\s]+([a-f0-9\-]{36})') {
        $parts.Add("CorrelationId: $($Matches[1])")
    } elseif ($Err.ErrorDetails?.Message -match 'CorrelationId[:\s]+([a-f0-9\-]{36})') {
        $parts.Add("CorrelationId: $($Matches[1])")
    }

    # 7. Last resort: full .ToString() (strips newlines)
    if (-not $parts.Count) {
        $fallback = $Err.Exception.ToString() -replace '\r?\n', ' ' -replace '\s{2,}', ' '
        $parts.Add($fallback.Trim())
    }

    # 8. Script location
    if ($Err.InvocationInfo?.PositionMessage) {
        $loc = ($Err.InvocationInfo.PositionMessage -split '\r?\n' | Select-Object -First 1).Trim()
        if ($loc) { $parts.Add("at $loc") }
    }

    return ($parts | Select-Object -Unique) -join ' | '
}

# Scans a SINGLE resource group and returns a structured result object. Extracted
# into its own function so the sequential and parallel (ForEach-Object -Parallel)
# code paths run byte-for-byte identical logic. All per-subscription context is
# passed in as parameters (no reliance on outer-scope variables) so the function
# works unchanged inside an isolated runspace.
#   Returns: [pscustomobject]@{ Record; Error; Reused; Flagged; RgName }
function Invoke-RgScan {
    param(
        $Rg,
        $Sub,
        [datetime]$Since,
        $SubResourceMap,
        $SubAdvisorRecs,
        $SubAdvisorScore,
        $SubCostMap,
        [hashtable]$PrevCache,
        $PrevScanTime,
        [bool]$Incremental,
        [int]$MaxCacheAgeHours,
        [string]$OwnerTagName,
        [string]$TeamTagName
    )

    $rgKey = $Rg.ResourceGroupName.ToLower()
    try {
        $rgWarnings = [System.Collections.Generic.List[string]]::new()

        # ── resources (from the sub-wide Resource Graph map; fallback per-RG) ──
        $resources = @()
        if ($null -ne $SubResourceMap) {
            if ($SubResourceMap.ContainsKey($rgKey)) { $resources = @($SubResourceMap[$rgKey]) }
        } else {
            try {
                $resources = @(Get-AzResource -ResourceGroupName $Rg.ResourceGroupName `
                                              -ExpandProperties -WarningAction SilentlyContinue)
            } catch {
                $rgWarnings.Add("Resources: $(Format-Exception $_)")
            }
        }

        # ── incremental cache: reuse the prior record if the RG is unchanged & fresh ──
        $fingerprint = Get-RgFingerprint -Resources $resources
        if ($Incremental) {
            $cacheKey = "$($Sub.Id)|$rgKey"
            $cached   = if ($PrevCache.ContainsKey($cacheKey)) { $PrevCache[$cacheKey] } else { $null }
            $fresh    = $PrevScanTime -and ((Get-Date) - $PrevScanTime).TotalHours -le $MaxCacheAgeHours
            if ($cached -and $fresh -and `
                $cached.PSObject.Properties['Fingerprint'] -and $cached.Fingerprint -eq $fingerprint) {
                return [pscustomobject]@{
                    Record  = $cached
                    Error   = $null
                    Reused  = $true
                    Flagged = [bool]$cached.IsFlagged
                    RgName  = $Rg.ResourceGroupName
                }
            }
        }

        # ── last-change + in-window activity (single Activity Log query) ──
        $activity          = @{ HasActivityInWindow = $false; LastEventTime = $null; LastModifiedTime = $null; LastModifiedBy = $null; LastModifiedByRaw = $null }
        try {
            $activity = Get-RgActivity -ResourceGroupName $Rg.ResourceGroupName `
                                       -Resources $resources -Since $Since
        } catch {
            $rgWarnings.Add("Activity: $(Format-Exception $_)")
        }
        $hasActivity       = $activity.HasActivityInWindow
        $lastModifiedTime  = $activity.LastModifiedTime
        $lastModifiedBy    = $activity.LastModifiedBy
        $lastModifiedByRaw  = $activity.LastModifiedByRaw
        $hasModified       = ($null -ne $lastModifiedTime -and $lastModifiedTime -gt $Since)

        # ── metrics: only needed if the RG isn't already proven active ──
        $hasMetrics = $false
        if (-not $hasActivity -and -not $hasModified) {
            try {
                $hasMetrics = Get-MetricsActivity -Resources $resources -Since $Since
            } catch {
                $rgWarnings.Add("Metrics: $(Format-Exception $_)")
            }
        }

        # ── safety signals: locks + managed/system RG detection ──────
        $locks = @()
        try {
            $locks = Get-RgResourceLocks -ResourceGroupName $Rg.ResourceGroupName
        } catch {
            $rgWarnings.Add("Locks: $(Format-Exception $_)")
        }

        $managedReason = $null
        try {
            $managedReason = Get-ManagedReason -ResourceGroup $Rg -Resources $resources
        } catch {
            $rgWarnings.Add("Managed: $(Format-Exception $_)")
        }

        # ── orphaned-resource detection ──────────────────────────────
        $orphans = @()
        try {
            $orphans = Get-OrphanedResources -Resources $resources
        } catch {
            $rgWarnings.Add("Orphans: $(Format-Exception $_)")
        }

        # Managed/system RGs look idle but aren't actionable — don't flag them.
        $isFlagged = (-not $managedReason) -and `
                     -not ($hasActivity -or $hasMetrics -or $hasModified)

        # ── advisor + cost: look up this RG from the sub-wide maps built above ──
        $rgAdvisor = if ($SubAdvisorRecs -and $SubAdvisorRecs.ContainsKey($rgKey)) { $SubAdvisorRecs[$rgKey] } else { $null }
        $cost      = if ($SubCostMap -and $SubCostMap.ContainsKey($rgKey)) { $SubCostMap[$rgKey] } else { $null }

        # ── recommended action (rolls up all signals) ───────────────
        $recommendation = Get-RecommendedAction -IsFlagged $isFlagged `
                                                -ManagedReason $managedReason `
                                                -Locks $locks `
                                                -ResourceCount $resources.Count `
                                                -Cost $cost `
                                                -Orphans $orphans

        $environment = Get-RgEnvironment -Tags $Rg.Tags -Name $Rg.ResourceGroupName

        # ── build record ──────────────────────────────────────────────
        $record = [ordered]@{
            SubscriptionId       = $Sub.Id
            SubscriptionName     = $Sub.Name
            ResourceGroupName    = $Rg.ResourceGroupName
            Location             = $Rg.Location
            ResourceCount        = $resources.Count
            Tags                 = $Rg.Tags
            Owner                = if ($Rg.Tags -and $Rg.Tags[$OwnerTagName])  { $Rg.Tags[$OwnerTagName] } else { $null }
            Team                 = if ($Rg.Tags -and $Rg.Tags[$TeamTagName])   { $Rg.Tags[$TeamTagName]  } else { $null }
            Environment          = $environment
            IsFlagged            = $isFlagged
            IsManaged            = [bool]$managedReason
            ManagedReason        = $managedReason
            Locks                = $locks
            OrphanedResources    = $orphans
            RecommendedAction    = $recommendation
            ActivityLog          = @{
                HasActivity    = $hasActivity
                LastEventTime  = if ($activity.LastEventTime) { $activity.LastEventTime.ToString("o") } else { $null }
                LastCaller     = $lastModifiedByRaw
            }
            MetricsHadActivity   = $hasMetrics
            LastModifiedRecently = $hasModified
            LastModifiedTime     = if ($lastModifiedTime) { $lastModifiedTime.ToString("o") } else { $null }
            LastModifiedBy       = $lastModifiedBy
            LastModifiedByRaw    = $lastModifiedByRaw
            Advisor              = @{
                SubscriptionScore = $SubAdvisorScore
                RgRecommendations = $rgAdvisor
            }
            Cost                 = $cost
            ResourceTypes        = ($resources | Group-Object ResourceType |
                                   Sort-Object Count -Descending |
                                   Select-Object -First 5 |
                                   ForEach-Object { "$($_.Name) ($($_.Count))" })
            Fingerprint          = $fingerprint
            Warnings             = if ($rgWarnings.Count) { @($rgWarnings) } else { @() }
        }

        return [pscustomobject]@{
            Record  = $record
            Error   = $null
            Reused  = $false
            Flagged = [bool]$isFlagged
            RgName  = $Rg.ResourceGroupName
        }

    } catch {
        $formatted = Format-Exception $_
        return [pscustomobject]@{
            Record = $null
            Error  = @{
                SubscriptionId    = $Sub.Id
                ResourceGroupName = $Rg.ResourceGroupName
                Error             = $formatted
                ExceptionType     = $_.Exception.GetType().FullName
                ScriptLine        = $_.InvocationInfo?.ScriptLineNumber
            }
            Reused  = $false
            Flagged = $false
            RgName  = $Rg.ResourceGroupName
        }
    }
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$since         = (Get-Date).AddDays(-$LookbackDays)
$scanStartTime = Get-Date
$results       = [System.Collections.Generic.List[object]]::new()
$errors        = [System.Collections.Generic.List[object]]::new()
$flaggedCount  = 0          # running counter (avoids re-scanning $results every iteration)
$reusedCount   = 0          # RGs served from the incremental cache
$rgCompleted   = 0          # RGs finished in the current subscription (drives the progress bar)

# Parallel runspaces share the in-process Az context via process-scoped autosave,
# so each scan thread reuses the already-acquired token instead of re-authenticating.
if ($ThrottleLimit -gt 1) {
    $null = Enable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue
}

# ── incremental cache: load the previous scan's records, keyed by sub|rg ──────
$prevCache    = @{}
$prevScanTime = $null
if ($Incremental -and (Test-Path $OutputPath)) {
    try {
        $prev = Get-Content $OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($prev.PSObject.Properties['ScanMetadata'] -and $prev.ScanMetadata -and `
            $prev.ScanMetadata.PSObject.Properties['CompletedTime']) {
            $prevScanTime = [datetime]$prev.ScanMetadata.CompletedTime
        }
        foreach ($r in @($prev.ResourceGroups)) {
            $k = "$($r.SubscriptionId)|$($r.ResourceGroupName.ToLower())"
            $prevCache[$k] = $r
        }
        Write-Progress2 "Incremental mode: loaded $($prevCache.Count) cached resource group(s) from previous scan."
    } catch {
        Write-Progress2 "Incremental mode: could not read previous results ($($_.Exception.Message)); doing a full scan."
    }
}

Write-ScanProgress -Phase "init" -Message "Fetching subscriptions..."
Write-Progress2 "Fetching subscriptions..."
$subscriptions = Get-AzSubscription | Where-Object {
    $_.State -eq "Enabled" -and $_.Id -notin $ExcludeSubscriptions
}

# ── scope resolution ─────────────────────────────────────────────────────────
# Backward-compatible: ScopeType defaults to 'All', and a lone -SingleSubscriptionId
# (with ScopeType unset) still scans just that subscription. The dashboard sends an
# explicit ScopeType; the standalone CLI may omit it.
#   ManagementGroup → all subscriptions under the MG (resolved via Resource Graph)
#   Subscription / lone -SingleSubscriptionId → that one subscription
#   ResourceGroup → that subscription, further restricted to $ResourceGroup (below)
$effectiveSubId = $SingleSubscriptionId
if ($ScopeType -eq 'ManagementGroup' -and $ManagementGroupId) {
    Write-Progress2 "Management-group scope: resolving subscriptions under '$ManagementGroupId'..."
    $mgSubIds = @()
    if (Get-Command Search-AzGraph -ErrorAction SilentlyContinue) {
        try {
            $mgQuery = "ResourceContainers | where type == 'microsoft.resources/subscriptions' | project subscriptionId"
            $mgRows  = [System.Collections.Generic.List[object]]::new()
            $skip    = $null
            do {
                $page = if ($skip) { Search-AzGraph -Query $mgQuery -First 1000 -SkipToken $skip -ManagementGroup $ManagementGroupId }
                        else        { Search-AzGraph -Query $mgQuery -First 1000 -ManagementGroup $ManagementGroupId }
                foreach ($row in @($page)) { $mgRows.Add($row) }
                $skip = $page.PSObject.Properties['SkipToken'] ? $page.SkipToken : $null
            } while ($skip)
            $mgSubIds = @($mgRows | ForEach-Object { [string](Get-Prop $_ 'subscriptionId') } | Where-Object { $_ })
        } catch {
            Write-Warning "Could not resolve management group '$ManagementGroupId' via Resource Graph: $(Format-Exception $_)"
        }
    }
    if (-not $mgSubIds.Count) {
        throw "No subscriptions found under management group '$ManagementGroupId' (check the ID and that Az.ResourceGraph is available)."
    }
    $subscriptions = @($subscriptions | Where-Object { $_.Id -in $mgSubIds })
    if (-not $subscriptions) {
        throw "No enabled, accessible subscriptions found under management group '$ManagementGroupId'."
    }
    Write-Progress2 "Management-group scope: $($subscriptions.Count) subscription(s) under '$ManagementGroupId'."
} elseif ($effectiveSubId) {
    $subscriptions = @($subscriptions | Where-Object { $_.Id -eq $effectiveSubId })
    if (-not $subscriptions) {
        throw "No enabled subscription found with ID '$effectiveSubId'."
    }
    if ($ResourceGroup) {
        Write-Progress2 "Resource-group scope: $($subscriptions[0].Name) ($effectiveSubId) / $ResourceGroup"
    } else {
        Write-Progress2 "Single-subscription mode: $($subscriptions[0].Name) ($effectiveSubId)"
    }
} else {
    Write-Progress2 "Found $($subscriptions.Count) enabled subscription(s)."
}

# Consumes the stream of per-RG result objects (from either the sequential or the
# parallel producer), accumulating records/errors and advancing the progress bar.
# Runs in the MAIN runspace, so all shared-state mutation here is single-threaded
# and therefore race-free regardless of how the producer is parallelised.
$consumeRgResult = {
    process {
        $r = $_
        $script:rgCompleted++
        if ($r.Record) {
            $results.Add($r.Record)
            if ($r.Flagged) { $script:flaggedCount++ }
            if ($r.Reused)  { $script:reusedCount++ }
        }
        if ($r.Error) { $errors.Add($r.Error) }
        Write-ScanProgress -Phase "scanning" -SubIndex $subIndex -TotalSubs $subscriptions.Count `
                           -CurrentSub $sub.Name -RgIndex $script:rgCompleted -TotalRgs $total `
                           -CurrentRg $r.RgName -FlaggedSoFar $script:flaggedCount `
                           -Message "Scanned $($r.RgName)"
        Write-Progress2 "  [$($script:rgCompleted)/$total] $($r.RgName)$(if ($r.Reused) { ' ↺ cached' })"
    }
}

$subIndex = 0
foreach ($sub in $subscriptions) {
    $subIndex++
    Write-Progress2 "[$subIndex/$($subscriptions.Count)] Scanning subscription: $($sub.Name) ($($sub.Id))"
    Write-ScanProgress -Phase "scanning" -SubIndex $subIndex -TotalSubs $subscriptions.Count `
                       -CurrentSub $sub.Name -FlaggedSoFar $flaggedCount `
                       -Message "Enumerating resource groups in $($sub.Name)..."

    try {
        $null = Set-AzContext -SubscriptionId $sub.Id -WarningAction SilentlyContinue

        $resourceGroups   = @(Get-AzResourceGroup)

        # When a specific resource group is requested, restrict the scan to it (case-insensitive).
        if ($ResourceGroup) {
            $resourceGroups = @($resourceGroups | Where-Object { $_.ResourceGroupName -ieq $ResourceGroup })
            if (-not $resourceGroups) {
                Write-Warning "Resource group '$ResourceGroup' not found in subscription $($sub.Id)."
            }
        }

        # ── subscription-level batch fetches (one call each, reused across all RGs) ──
        $subAdvisorScore  = Get-SubscriptionAdvisorScore -SubscriptionId $sub.Id
        # All Advisor recommendations for the subscription, grouped by RG (per-RG endpoint 404s).
        $subAdvisorRecs   = Get-SubscriptionAdvisorRecommendations -SubscriptionId $sub.Id
        # All resources for the subscription in ONE Resource Graph query, grouped by RG.
        # $null means Resource Graph is unavailable → fall back to per-RG Get-AzResource.
        $subResourceMap   = Get-SubscriptionResourceMap -SubscriptionId $sub.Id
        # All cost for the subscription in ONE query, grouped by RG.
        $subCostMap       = Get-SubscriptionCostByRg -SubscriptionId $sub.Id -PeriodStart $since

        $total       = $resourceGroups.Count
        $rgCompleted = 0
        # Parallelise across RGs when asked for it and there's more than one to do.
        $useParallel = ($ThrottleLimit -gt 1 -and $total -gt 1)

        Write-ScanProgress -Phase "scanning" -SubIndex $subIndex -TotalSubs $subscriptions.Count `
                           -CurrentSub $sub.Name -RgIndex 0 -TotalRgs $total `
                           -FlaggedSoFar $flaggedCount `
                           -Message "Scanning $total resource group(s) in $($sub.Name)$(if ($useParallel) { " — up to $ThrottleLimit at a time" })..."
        Write-Progress2 "  $total resource group(s) to scan$(if ($useParallel) { " — parallel (throttle $ThrottleLimit)" } else { " — sequential" })."

        if ($useParallel) {
            # Functions defined in this script aren't visible inside ForEach-Object
            # -Parallel runspaces, so serialise their definitions and rebuild them in
            # each runspace. The Az context + principal-name cache are shared in-process.
            $funcNames = 'Get-RgFingerprint','Get-RgActivity','Resolve-PrincipalName',
                         'Get-MetricsActivity','Get-RgResourceLocks','Get-ManagedReason',
                         'Get-OrphanedResources','Get-RecommendedAction','Get-RgEnvironment',
                         'Format-Exception','Invoke-RgScan'
            $funcDefs  = ($funcNames | ForEach-Object {
                "function $_ {`n$((Get-Command $_).ScriptBlock)`n}"
            }) -join "`n"
            $pcache = $script:principalNameCache   # thread-safe ConcurrentDictionary

            $resourceGroups | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                # Rebuild helpers + shared state inside this runspace, then scan one RG.
                . ([scriptblock]::Create($using:funcDefs))
                $script:principalNameCache = $using:pcache
                $SkipMetrics               = $using:SkipMetrics
                Invoke-RgScan -Rg $_ -Sub $using:sub -Since $using:since `
                              -SubResourceMap $using:subResourceMap -SubAdvisorRecs $using:subAdvisorRecs `
                              -SubAdvisorScore $using:subAdvisorScore -SubCostMap $using:subCostMap `
                              -PrevCache $using:prevCache -PrevScanTime $using:prevScanTime `
                              -Incremental ([bool]$using:Incremental) -MaxCacheAgeHours $using:MaxCacheAgeHours `
                              -OwnerTagName $using:OwnerTagName -TeamTagName $using:TeamTagName
            } | & $consumeRgResult
        } else {
            $resourceGroups | ForEach-Object {
                Invoke-RgScan -Rg $_ -Sub $sub -Since $since `
                              -SubResourceMap $subResourceMap -SubAdvisorRecs $subAdvisorRecs `
                              -SubAdvisorScore $subAdvisorScore -SubCostMap $subCostMap `
                              -PrevCache $prevCache -PrevScanTime $prevScanTime `
                              -Incremental ([bool]$Incremental) -MaxCacheAgeHours $MaxCacheAgeHours `
                              -OwnerTagName $OwnerTagName -TeamTagName $TeamTagName
            } | & $consumeRgResult
        }
    } catch {
        $formatted = Format-Exception $_
        $errors.Add(@{
            SubscriptionId = $sub.Id
            Error          = $formatted
            ExceptionType  = $_.Exception.GetType().FullName
            ScriptLine     = $_.InvocationInfo?.ScriptLineNumber
        })
        Write-Warning "Error accessing subscription $($sub.Id): $formatted"
    }
}

#endregion

#region ── write output ─────────────────────────────────────────────────────────

$output = @{
    ScanMetadata = @{
        ScanTime         = $scanStartTime.ToString("o")
        CompletedTime    = (Get-Date).ToString("o")
        LookbackDays     = $LookbackDays
        ScopeType         = $ScopeType
        ManagementGroupId = $ManagementGroupId
        ResourceGroup     = $ResourceGroup
        SubscriptionsScanned = $subscriptions.Count
        TotalResourceGroups  = $results.Count
        FlaggedCount         = $flaggedCount
        ErrorCount           = $errors.Count
        Incremental          = [bool]$Incremental
        ReusedFromCache      = $reusedCount
    }
    ResourceGroups = $results
    Errors         = $errors
}

$output | ConvertTo-Json -Depth 20 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. Results written to $OutputPath"
Write-Progress2 "Flagged: $flaggedCount / $($results.Count) resource groups$(if ($Incremental) { " ($reusedCount reused from cache)" })"

Write-ScanProgress -Phase "done" -SubIndex $subscriptions.Count -TotalSubs $subscriptions.Count `
                   -FlaggedSoFar $flaggedCount `
                   -Message "Scan complete: $($results.Count) resource groups, $flaggedCount flagged."

#endregion
