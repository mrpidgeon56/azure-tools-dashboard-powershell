#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Projects Log Analytics workspace cost per table, based on each table's billable
    ingestion volume and its current (effective) retention settings.

    For a single chosen workspace it:
      - enumerates every table and reads its retention configuration
        (interactive retentionInDays + totalRetentionInDays ⇒ archive days) and plan
        (Analytics vs Basic), via the ARM tables API;
      - measures each table's BILLABLE ingestion over the last -LookbackDays (default 31)
        using a KQL `Usage` query against the Log Analytics query API, and converts it to
        an average daily / projected monthly GB;
      - fetches live per-GB unit prices from the public Azure Retail Prices API for the
        workspace's region (ingestion $/GB, interactive retention $/GB-month, archive
        $/GB-month), with built-in fallbacks if the API is unreachable;
      - computes a steady-state MONTHLY cost per table (ingestion + interactive retention
        + archive retention). The page multiplies this run-rate by the selected 1/3/6/12
        month horizon for the forecast.

.OUTPUTS
    JSON file at -OutputPath (default: ./la-cost-scan-results.json):
    { ScanMetadata, Tables, Errors }

.NOTES
    Authentication reuses the in-memory Az context (no separate login): ARM and Log
    Analytics query tokens are obtained with Get-AzAccessToken. The signed-in identity
    needs only READER on the subscription/workspace (plus Log Analytics Reader to run the
    Usage query). The Azure Retail Prices API is public (no auth).

    Required Az modules: Az.Accounts.
#>
[CmdletBinding()]
param(
    [string] $OutputPath       = "$PSScriptRoot/../data/la-cost-scan-results.json",
    [string] $ProgressPath     = "",          # if set, incremental progress JSON is written here
    [Parameter(Mandatory)][string] $SubscriptionId,
    [Parameter(Mandatory)][string] $ResourceGroup,
    [Parameter(Mandatory)][string] $WorkspaceName,
    [string] $WorkspaceId      = "",          # workspace customerId GUID (for the query API); fetched if blank
    [int]    $LookbackDays     = 31,          # window for the billable-volume Usage query
    [int]    $FreeRetentionDays = 31,         # interactive retention included free (90 if Sentinel-enabled)
    [string] $CurrencyCode     = "USD"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DaysPerMonth = 30.4375   # average month length, for daily→monthly GB scaling

#region ── helpers ──────────────────────────────────────────────────────────────

$script:logTail       = [System.Collections.Generic.List[string]]::new()
$script:progressState = [ordered]@{ Phase = "init"; Percent = 0; Fetched = 0; Total = 0; FlaggedSoFar = 0; Message = "" }

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

# Get a bearer token for the given resource from the in-memory Az context. Handles
# both the SecureString token (Az.Accounts 5+) and the legacy plaintext token.
function Get-Token {
    param(
        [string]$ResourceUrl,
        [switch]$Arm
    )
    if ($Arm) {
        $t = Get-AzAccessToken -ResourceTypeName Arm -WarningAction SilentlyContinue -ErrorAction Stop
    } else {
        $t = Get-AzAccessToken -ResourceUrl $ResourceUrl -WarningAction SilentlyContinue -ErrorAction Stop
    }
    if ($t.Token -is [System.Security.SecureString]) {
        return [System.Net.NetworkCredential]::new('', $t.Token).Password
    }
    return [string]$t.Token
}

function Get-Prop ($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj.PSObject.Properties.Name -contains $name) { return $obj.$name }
    return $null
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$tables = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

Set-ScanProgress -Phase "init" -Message "Acquiring tokens..."
Write-Progress2 "Acquiring ARM + Log Analytics tokens from the active Az session..."
$armToken = Get-Token -Arm
$armHeaders = @{ Authorization = "Bearer $armToken" }

$wsResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"

# ── workspace metadata (region, customerId, default retention) ───────────────
$region = ""
$subName = $SubscriptionId
try {
    Write-Progress2 "Reading workspace metadata..."
    $wsUri = "https://management.azure.com$($wsResourceId)?api-version=2022-10-01"
    $ws = Invoke-RestMethod -Method GET -Uri $wsUri -Headers $armHeaders -ErrorAction Stop
    $region = [string](Get-Prop $ws 'location')
    $wsProps = Get-Prop $ws 'properties'
    if (-not $WorkspaceId) {
        $cid = Get-Prop $wsProps 'customerId'
        if ($cid) { $WorkspaceId = [string]$cid }
    }
} catch {
    $errors.Add(@{ Stage = "workspace"; Error = (Format-Exception $_) })
    Write-Progress2 "Workspace metadata fetch failed ($(Format-Exception $_))."
}
try { $sub = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop; if ($sub) { $subName = $sub.Name } } catch {}

# ── retail prices for the region ─────────────────────────────────────────────
# Public API; pick the consumption meters for Log Analytics. Fallbacks (USD, common
# defaults) are used if the API is unreachable or a meter is missing for the region.
$ingestPrice  = 2.76     # $/GB analytics ingestion (pay-as-you-go fallback)
$basicIngest  = 0.645    # $/GB basic-logs ingestion fallback
$retentPrice  = 0.12     # $/GB-month interactive retention fallback
$archivePrice = 0.025    # $/GB-month archive fallback
$priceSource  = "fallback (Retail Prices API unavailable)"
try {
    Set-ScanProgress -Phase "scanning" -Message "Fetching Azure retail prices..."
    Write-Progress2 "Fetching retail prices for region '$region'..."
    $filter = "serviceName eq 'Log Analytics' and priceType eq 'Consumption'"
    if ($region) { $filter += " and armRegionName eq '$region'" }
    $priceUri = "https://prices.azure.com/api/retail/prices?currencyCode='$CurrencyCode'&`$filter=$([System.Uri]::EscapeDataString($filter))"
    $items = [System.Collections.Generic.List[object]]::new()
    $guard = 0
    while ($priceUri -and $guard -lt 20) {
        $guard++
        $resp = Invoke-RestMethod -Method GET -Uri $priceUri -ErrorAction Stop
        foreach ($it in @(Get-Prop $resp 'Items')) { $items.Add($it) }
        $next = Get-Prop $resp 'NextPageLink'
        $priceUri = if ($next) { [string]$next } else { "" }
    }
    if ($items.Count -gt 0) {
        $priceSource = "Azure Retail Prices API ($region, $CurrencyCode)"
        foreach ($it in $items) {
            $meter = [string](Get-Prop $it 'meterName')
            $price = [double](Get-Prop $it 'retailPrice')
            if ($price -le 0) { continue }
            switch -Regex ($meter) {
                'Basic Logs'                            { $basicIngest  = $price; Write-Progress2 "Meter '$meter' -> basicIngest=$price"; break }
                '(?<!Basic Logs )(Pay-as-you-go )?Data Ingestion' { $ingestPrice  = $price; Write-Progress2 "Meter '$meter' -> ingest=$price"; break }
                '(Pay-as-you-go )?Data Analyzed'        { $ingestPrice  = $price; Write-Progress2 "Meter '$meter' -> ingest=$price"; break }
                'Data Archive'                          { $archivePrice = $price; Write-Progress2 "Meter '$meter' -> archive=$price"; break }
                'Data Retention'                        { $retentPrice  = $price; Write-Progress2 "Meter '$meter' -> retention=$price"; break }
            }
        }
        Write-Progress2 "Retail prices: ingest=$ingestPrice retention=$retentPrice archive=$archivePrice $CurrencyCode."
    } else {
        Write-Progress2 "No retail price rows returned; using fallback rates."
    }
} catch {
    $errors.Add(@{ Stage = "prices"; Error = (Format-Exception $_) })
    Write-Progress2 "Retail price fetch failed ($(Format-Exception $_)); using fallback rates."
}

# ── per-table billable volume (KQL Usage query) ──────────────────────────────
# Average daily billable GB per table over the lookback window. Quantity is in MB.
$volByTable = @{}
try {
    Set-ScanProgress -Phase "scanning" -Message "Querying billable volume..."
    Write-Progress2 "Running Usage query over last $LookbackDays day(s)..."
    if (-not $WorkspaceId) { throw "Workspace customerId (GUID) is unknown; cannot run the Usage query." }
    $laToken = Get-Token "https://api.loganalytics.io/"
    $kql = "Usage | where TimeGenerated > ago($($LookbackDays)d) | where IsBillable == true | summarize BillableMB = sum(Quantity) by DataType"
    $body = @{ query = $kql } | ConvertTo-Json
    $qUri = "https://api.loganalytics.io/v1/workspaces/$WorkspaceId/query"
    $qResp = Invoke-RestMethod -Method POST -Uri $qUri -Headers @{ Authorization = "Bearer $laToken" } -Body $body -ContentType "application/json" -ErrorAction Stop
    $qTables = @(Get-Prop $qResp 'tables')
    if ($qTables.Count -gt 0) {
        $cols = @(Get-Prop $qTables[0] 'columns')
        $colNames = @($cols | ForEach-Object { [string](Get-Prop $_ 'name') })
        $iType = $colNames.IndexOf('DataType')
        $iMB   = $colNames.IndexOf('BillableMB')
        foreach ($row in @(Get-Prop $qTables[0] 'rows')) {
            if ($iType -lt 0 -or $iMB -lt 0) { continue }
            $dt = [string]$row[$iType]
            $mb = 0.0; [double]::TryParse("$($row[$iMB])", [System.Globalization.NumberStyles]::Float -bor [System.Globalization.NumberStyles]::AllowThousands, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$mb) | Out-Null
            if ($dt) { $volByTable[$dt.ToLowerInvariant()] = $mb / 1024.0 }   # MB → GB (31-day total)
        }
    }
    Write-Progress2 "Usage query returned $($volByTable.Count) billable table(s)."
} catch {
    $errors.Add(@{ Stage = "usage"; Error = (Format-Exception $_) })
    Write-Progress2 "Usage query failed ($(Format-Exception $_)); tables will show zero volume."
}

# ── tables + retention settings (ARM tables API) ─────────────────────────────
$tableDefs = @()
try {
    Set-ScanProgress -Phase "scanning" -Message "Enumerating tables..."
    Write-Progress2 "Enumerating workspace tables + retention settings..."
    $tablesUri = "https://management.azure.com$wsResourceId/tables?api-version=2022-10-01"
    $tResp = Invoke-RestMethod -Method GET -Uri $tablesUri -Headers $armHeaders -ErrorAction Stop
    $tableDefs = @(Get-Prop $tResp 'value')
    Write-Progress2 "Found $($tableDefs.Count) table(s)."
} catch {
    $errors.Add(@{ Stage = "tables"; Error = (Format-Exception $_) })
    Write-Progress2 "Table enumeration failed ($(Format-Exception $_))."
}

$total = $tableDefs.Count
$idx = 0
foreach ($t in $tableDefs) {
    $idx++
    $name = [string](Get-Prop $t 'name')
    $props = Get-Prop $t 'properties'

    $retention = Get-Prop $props 'retentionInDays'
    $totalRet  = Get-Prop $props 'totalRetentionInDays'
    $plan      = [string](Get-Prop $props 'plan'); if (-not $plan) { $plan = 'Analytics' }
    $retention = if ($null -ne $retention) { [int]$retention } else { $FreeRetentionDays }
    $totalRet  = if ($null -ne $totalRet)  { [int]$totalRet }  else { $retention }
    $archiveDays = [math]::Max(0, $totalRet - $retention)

    # ── volume ───────────────────────────────────────────────────────────────
    $billGB31 = 0.0
    if ($volByTable.ContainsKey($name.ToLowerInvariant())) { $billGB31 = [double]$volByTable[$name.ToLowerInvariant()] }
    $dailyGB   = if ($LookbackDays -gt 0) { $billGB31 / $LookbackDays } else { 0.0 }
    $monthlyGB = $dailyGB * $DaysPerMonth

    # ── unit price for this table's plan ──────────────────────────────────────
    $ingestUnit = if ($plan -match 'Basic') { $basicIngest } else { $ingestPrice }

    # ── steady-state monthly cost ─────────────────────────────────────────────
    # ingestion: this month's billable GB × $/GB.
    $ingestCost = $monthlyGB * $ingestUnit
    # interactive retention beyond the free window: GB sitting in retention = dailyGB ×
    # billable interactive days; billed per GB-month.
    $billableInteractiveDays = [math]::Max(0, $retention - $FreeRetentionDays)
    $retainedGB = $dailyGB * $billableInteractiveDays
    $retentCost = $retainedGB * $retentPrice
    # archive retention (totalRetention beyond interactive), billed per GB-month.
    $archivedGB = $dailyGB * $archiveDays
    $archiveCost = $archivedGB * $archivePrice

    $monthlyCost = $ingestCost + $retentCost + $archiveCost

    $rec = [ordered]@{
        TableName                = $name
        Plan                     = $plan
        RetentionInDays          = $retention
        TotalRetentionInDays     = $totalRet
        ArchiveDays              = $archiveDays
        BillableGBLookback       = [math]::Round($billGB31, 4)
        DailyGB                  = [math]::Round($dailyGB, 4)
        MonthlyGB                = [math]::Round($monthlyGB, 4)
        IngestionPricePerGB      = [math]::Round($ingestUnit, 5)
        RetentionPricePerGBMonth = [math]::Round($retentPrice, 5)
        ArchivePricePerGBMonth   = [math]::Round($archivePrice, 5)
        IngestionCostMonthly     = [math]::Round($ingestCost, 2)
        RetentionCostMonthly     = [math]::Round($retentCost, 2)
        ArchiveCostMonthly       = [math]::Round($archiveCost, 2)
        MonthlyCost              = [math]::Round($monthlyCost, 2)
        Currency                 = $CurrencyCode
    }
    $tables.Add($rec)
    Set-ScanProgress -Phase "scanning" -Fetched $idx -Total $total -Message "Costed $idx/$total table(s)..."
}

#endregion

#region ── write output ─────────────────────────────────────────────────────────

# Sum manually: the records are [ordered] hashtables, whose keys are NOT object
# properties, so `Measure-Object -Property` cannot read them.
$totalMonthlyGB = 0.0; $totalMonthlyCost = 0.0; $totalIngestCost = 0.0; $totalRetentCost = 0.0
foreach ($r in $tables) {
    $totalMonthlyGB   += [double]$r.MonthlyGB
    $totalMonthlyCost += [double]$r.MonthlyCost
    $totalIngestCost  += [double]$r.IngestionCostMonthly
    $totalRetentCost  += [double]$r.RetentionCostMonthly + [double]$r.ArchiveCostMonthly
}

$output = @{
    ScanMetadata = @{
        ScanTime              = $scanStartTime.ToString("o")
        CompletedTime         = (Get-Date).ToString("o")
        SubscriptionId        = $SubscriptionId
        SubscriptionName      = $subName
        ResourceGroup         = $ResourceGroup
        WorkspaceName         = $WorkspaceName
        WorkspaceId           = $WorkspaceId
        Region                = $region
        Currency              = $CurrencyCode
        LookbackDays          = $LookbackDays
        FreeRetentionDays     = $FreeRetentionDays
        TableCount            = $tables.Count
        TotalMonthlyGB        = [math]::Round([double]$totalMonthlyGB, 4)
        TotalMonthlyCost      = [math]::Round([double]$totalMonthlyCost, 2)
        TotalIngestionMonthly = [math]::Round([double]$totalIngestCost, 2)
        TotalRetentionMonthly = [math]::Round([double]$totalRetentCost, 2)
        PriceSource           = $priceSource
        ErrorCount            = $errors.Count
    }
    Tables = $tables
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $tables.Count -Total $tables.Count -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 ("Done. {0} table(s), {1:N1} GB/mo, {2} {3:N2}/mo run-rate. Wrote {4}" -f `
    $tables.Count, [double]$totalMonthlyGB, $CurrencyCode, [double]$totalMonthlyCost, $OutputPath)

#endregion
