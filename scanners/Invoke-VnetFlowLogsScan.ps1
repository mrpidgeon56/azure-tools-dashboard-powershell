#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    VNet Flow Logs Analyzer.

    Reads VNet flow-log records straight out of the storage account they land in and turns
    them into a traffic picture: top talkers, top destinations, busiest ports, protocol mix,
    allowed-vs-denied, inbound-vs-outbound — plus a table of the heaviest individual flows.

    Unlike the other tools (which read Azure *configuration* via Resource Graph / ARM), this
    one reads blob **contents** (data plane), so the signed-in identity needs the data-plane
    role **Storage Blob Data Reader** on the flow log's storage account, on top of ARM Reader
    (used only to resolve a flow log id → its storage account when the account is not given).

    Flow logs are written to the container `insights-logs-flowlogflowevent` under an
    hour-partitioned virtual path. Each blob is JSON with a `records` array; every record
    carries flowRecords.flows[].flowGroups[].flowTuples[] where each tuple is a comma-
    separated string (VNet flow log schema v4):
        ts, srcIp, dstIp, srcPort, dstPort, proto, direction, state, encryption,
        pktsSrcToDst, bytesSrcToDst, pktsDstToSrc, bytesDstToSrc
    `proto` is T/U (TCP/UDP), `direction` is I/O (in/out), and `state` is B/C/E for an allowed
    flow's begin/continue/end or D for a denied flow.

.OUTPUTS
    JSON file at -OutputPath (default ../data/vnet-flow-logs-scan-results.json):
    { ScanMetadata, Items, Errors }
    ScanMetadata carries the aggregate summary tables (TopTalkers, TopDestinations, TopPorts,
    Protocols, Decision, Direction) plus the counts. Items are the heaviest individual flows.

.NOTES
    THE OUTLIER: this scanner does NOT take the standard scope params. It is parameter-driven
    and reads one chosen flow log. Authentication reuses the in-memory Az context: an ARM token
    resolves the flow-log → storage-account mapping, and a Storage data-plane token reads blobs.
#>
[CmdletBinding()]
param(
    [string] $OutputPath      = "$PSScriptRoot/../data/vnet-flow-logs-scan-results.json",
    [string] $ProgressPath    = "",
    [string] $FlowLogId       = "",          # ARM resource id of the flowLogs object (used to resolve storage + path prefix)
    [string] $StorageAccount  = "",          # storage account name the flow log writes to (skips ARM lookup if given)
    [string] $FlowLogName     = "",          # display name (cosmetic, for the summary)
    [string] $VnetName        = "",          # target VNet name (cosmetic, for the summary)
    [string] $PathPrefix      = "",          # blob name prefix to list under (defaults from FlowLogId)
    [int]    $LookbackHours   = 24,          # only blobs in this trailing window are read
    [int]    $MaxBlobs        = 300,         # cap on blobs downloaded (cheap metadata listing stops here)
    [string] $Container       = "insights-logs-flowlogflowevent"
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TopN        = 12     # rows kept per summary table
$MaxFlowRows = 500    # heaviest individual flows kept for the table

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

function ConvertTo-Int ($v) {
    $out = 0
    if ([int]::TryParse(("$v").Trim(), [ref]$out)) { return $out }
    return 0
}

# Raw access token for a given resource (ARM or Storage data plane) + expiry.
function Get-ResourceToken ([string]$ResourceUrl) {
    $t = Get-AzAccessToken -ResourceUrl $ResourceUrl -WarningAction SilentlyContinue -ErrorAction Stop
    if ($t.Token -is [System.Security.SecureString]) {
        return [System.Net.NetworkCredential]::new('', $t.Token).Password
    }
    return [string]$t.Token
}

# Friendly destination-port labels for the "top ports" table.
$PortLabel = @{
    20 = 'FTP-data'; 21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 25 = 'SMTP'; 53 = 'DNS'
    80 = 'HTTP'; 88 = 'Kerberos'; 110 = 'POP3'; 123 = 'NTP'; 135 = 'RPC'; 139 = 'NetBIOS'
    143 = 'IMAP'; 389 = 'LDAP'; 443 = 'HTTPS'; 445 = 'SMB'; 465 = 'SMTPS'; 587 = 'SMTP'
    636 = 'LDAPS'; 993 = 'IMAPS'; 995 = 'POP3S'; 1433 = 'SQL'; 1521 = 'Oracle'
    3306 = 'MySQL'; 3389 = 'RDP'; 5432 = 'Postgres'; 5671 = 'AMQP'; 5672 = 'AMQP'
    6379 = 'Redis'; 8080 = 'HTTP-alt'; 8443 = 'HTTPS-alt'; 9200 = 'Elastic'; 27017 = 'MongoDB'
}
function Get-PortLabel ([int]$Port) {
    if ($Port -le 0) { return "" }
    if ($PortLabel.ContainsKey($Port)) { return "$Port · $($PortLabel[$Port])" }
    return "$Port"
}

$ProtoMap     = @{ 'T' = 'TCP'; 'U' = 'UDP'; '6' = 'TCP'; '17' = 'UDP'; '1' = 'ICMP' }
$DirectionMap = @{ 'I' = 'Inbound'; 'O' = 'Outbound' }

# Parse one flow tuple (VNet flow log schema v4). Returns $null on a short/garbled tuple.
function ConvertFrom-FlowTuple ([string]$Tuple) {
    $parts = ("$Tuple").Split(',')
    if ($parts.Count -lt 13) { return $null }
    $proto = $parts[5].Trim().ToUpperInvariant()
    if ($ProtoMap.ContainsKey($proto)) { $proto = $ProtoMap[$proto] } elseif (-not $proto) { $proto = '?' }
    $dirKey = $parts[6].Trim().ToUpperInvariant()
    $direction = if ($DirectionMap.ContainsKey($dirKey)) { $DirectionMap[$dirKey] } else { 'Outbound' }
    $decision = if ($parts[7].Trim().ToUpperInvariant() -eq 'D') { 'Denied' } else { 'Allowed' }
    [pscustomobject]@{
        Src       = $parts[1]
        Dst       = $parts[2]
        DPort     = (ConvertTo-Int $parts[4])
        Proto     = $proto
        Direction = $direction
        Decision  = $decision
        Bytes     = (ConvertTo-Int $parts[10]) + (ConvertTo-Int $parts[12])
        Packets   = (ConvertTo-Int $parts[9])  + (ConvertTo-Int $parts[11])
    }
}

# Fetch (and aggregate into) an accumulator hashtable keyed by some id.
function Add-Agg ($table, $key, [long]$bytes) {
    if (-not $table.ContainsKey($key)) { $table[$key] = @{ Bytes = [long]0; Records = 0 } }
    $table[$key].Bytes += $bytes
    $table[$key].Records++
}

# Top-N rows from an {id -> @{Bytes;Records}} accumulator, biggest bytes first.
function Get-TopRows ($table, [string]$KeyName, [int]$N) {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in ($table.GetEnumerator() | Sort-Object { $_.Value.Bytes } -Descending | Select-Object -First $N)) {
        $rows.Add([ordered]@{ $KeyName = $entry.Key; Bytes = $entry.Value.Bytes; Records = $entry.Value.Records })
    }
    return $rows
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$items   = [System.Collections.Generic.List[object]]::new()
$errors  = [System.Collections.Generic.List[object]]::new()
$warnings = [System.Collections.Generic.List[string]]::new()

$flowLogId      = $FlowLogId.Trim()
$storageAccount = $StorageAccount.Trim()
$flowLogName    = $FlowLogName.Trim()
$vnetName       = $VnetName.Trim()
$pathPrefix     = $PathPrefix.Trim()
$container      = if ($Container.Trim()) { $Container.Trim() } else { 'insights-logs-flowlogflowevent' }

Set-ScanProgress -Phase "init" -Message "Resolving flow log..."
Write-Progress2 "VNet Flow Logs Analyzer — lookback ${LookbackHours}h, up to $MaxBlobs blob(s)."

# ── resolve flow log → storage account (ARM Resource Graph) when needed ──────
if ($flowLogId -and -not $storageAccount) {
    Write-Progress2 "Resolving flow log → storage account via Resource Graph..."
    if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
        throw "Azure Resource Graph (Search-AzGraph) is unavailable. Install it with: Install-Module Az.ResourceGraph -Scope CurrentUser"
    }
    try {
        $idEsc = $flowLogId -replace "'", "''"
        $kql = @"
resources
| where type =~ 'microsoft.network/networkwatchers/flowlogs'
| where id =~ '$idEsc'
| project id, name, location,
          targetResourceId = tostring(properties.targetResourceId),
          storageId = tostring(properties.storageId)
"@
        $row = $null
        $skip = $null
        do {
            $page = if ($skip) { Search-AzGraph -Query $kql -First 1000 -SkipToken $skip -ErrorAction Stop }
                    else        { Search-AzGraph -Query $kql -First 1000 -ErrorAction Stop }
            foreach ($r in @($page)) { if (-not $row) { $row = $r } }
            $skip = if ($page.PSObject.Properties['SkipToken']) { $page.SkipToken } else { $null }
        } while ($skip)

        if (-not $row) {
            throw "The selected flow log could not be found. It may have been deleted, or the credentials can no longer see it."
        }
        $storageId = "$(Get-Prop $row 'storageId')"
        $storageAccount = ($storageId.TrimEnd('/') -split '/')[-1]
        if (-not $flowLogName) { $flowLogName = "$(Get-Prop $row 'name')" }
        if (-not $vnetName) {
            $target = "$(Get-Prop $row 'targetResourceId')"
            if ($target) { $vnetName = ($target.TrimEnd('/') -split '/')[-1] }
        }
    } catch {
        $errors.Add(@{ Stage = "resolve"; Error = (Format-Exception $_) })
        throw
    }
}

if (-not $storageAccount) {
    throw "Select a VNet flow log to analyze (no storage account was provided)."
}
# VNet flow-log blobs are keyed by the upper-cased flowLogs resource id.
if (-not $pathPrefix -and $flowLogId) {
    $pathPrefix = "flowLogResourceID=" + $flowLogId.ToUpperInvariant() + "/"
}

# ── time window: the set of y/m/d/h hour partitions we will accept ───────────
$now = [datetime]::UtcNow
$windowStart = $now.AddHours(-$LookbackHours)
$allowedHours = [System.Collections.Generic.HashSet[string]]::new()
for ($i = 0; $i -le $LookbackHours; $i++) {
    [void]$allowedHours.Add($windowStart.AddHours($i).ToString('yyyy/MM/dd/HH'))
}
$hourRe = [regex]'/y=(\d{4})/m=(\d{2})/d=(\d{2})/h=(\d{2})/'

# ── data-plane access: list + read blobs over the Storage REST API ───────────
Set-ScanProgress -Phase "list" -Message "Listing flow-log blobs in $storageAccount..."
Write-Progress2 "Listing flow-log blobs in $storageAccount (container $container)..."

$storageToken = $null
try { $storageToken = Get-ResourceToken "https://storage.azure.com/" }
catch {
    $errors.Add(@{ Stage = "token"; Error = (Format-Exception $_) })
    throw "Could not acquire a Storage data-plane token. The signed-in identity needs the role 'Storage Blob Data Reader' on '$storageAccount'. Underlying error: $(Format-Exception $_)"
}
$blobHeaders = @{ Authorization = "Bearer $storageToken"; 'x-ms-version' = '2021-08-06' }
$baseUrl = "https://$storageAccount.blob.core.windows.net/$container"

# List candidate blob names within the window (cheap metadata listing).
$candidates = [System.Collections.Generic.List[string]]::new()
try {
    $marker = ""
    do {
        $listUri = "$baseUrl`?restype=container&comp=list&maxresults=5000"
        if ($pathPrefix) { $listUri += "&prefix=" + [uri]::EscapeDataString($pathPrefix) }
        if ($marker)     { $listUri += "&marker="  + [uri]::EscapeDataString($marker) }
        $resp = Invoke-RestMethod -Method GET -Uri $listUri -Headers $blobHeaders -ErrorAction Stop
        # Strip the BOM that the XML listing sometimes carries, then parse.
        $xml = [xml](("$resp") -replace '^\xEF\xBB\xBF', '' -replace '^[^<]*<', '<')
        foreach ($b in @($xml.EnumerationResults.Blobs.Blob)) {
            $name = "$($b.Name)"
            if (-not $name) { continue }
            $m = $hourRe.Match('/' + $name)
            if ($m.Success) {
                $hk = "{0}/{1}/{2}/{3}" -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value, $m.Groups[4].Value
                if (-not $allowedHours.Contains($hk)) { continue }
            }
            $candidates.Add($name)
            if ($candidates.Count -ge $MaxBlobs) { break }
        }
        $marker = "$($xml.EnumerationResults.NextMarker)"
    } while ($marker -and $candidates.Count -lt $MaxBlobs)
} catch {
    $errors.Add(@{ Stage = "list"; Error = (Format-Exception $_) })
    throw "Could not list blobs in '$container' on storage account '$storageAccount'. The signed-in identity needs the data-plane role 'Storage Blob Data Reader' on the account. Underlying error: $(Format-Exception $_)"
}

$total = $candidates.Count
if ($total -eq 0) {
    $warnings.Add("No flow-log blobs were found in the selected window. The flow log may be newly enabled, idle, or writing to a different container.")
}

# ── aggregate accumulators ───────────────────────────────────────────────────
$flows      = @{}    # "src|dst|port|proto|dir|decision" -> @{ Bytes; Packets; Records; Meta }
$talkers    = @{}
$dests      = @{}
$ports      = @{}
$protoCounts = @{}
$decisionCounts = @{ Allowed = 0; Denied = 0 }
$directionCounts = @{ Inbound = 0; Outbound = 0 }
$srcIps = [System.Collections.Generic.HashSet[string]]::new()
$dstIps = [System.Collections.Generic.HashSet[string]]::new()
[long]$totalBytes = 0
[long]$totalPackets = 0
$tuplesParsed = 0

for ($idx = 0; $idx -lt $total; $idx++) {
    $name = $candidates[$idx]
    Set-ScanProgress -Phase "parse" -Fetched $idx -Total $total -FlaggedSoFar $decisionCounts.Denied `
                     -Message "Parsing flow records ($($idx + 1)/$total)..."
    try {
        $blobUri = "$baseUrl/" + (($name -split '/') | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
        $raw = Invoke-RestMethod -Method GET -Uri $blobUri -Headers $blobHeaders -ErrorAction Stop
        $payload = if ($raw -is [string]) { $raw | ConvertFrom-Json } else { $raw }
    } catch {
        $warnings.Add("Skipped an unreadable blob: $name")
        continue
    }

    foreach ($record in @(Get-Prop $payload 'records')) {
        $fr = Get-Prop $record 'flowRecords'
        foreach ($flow in @(Get-Prop $fr 'flows')) {
            foreach ($group in @(Get-Prop $flow 'flowGroups')) {
                foreach ($tup in @(Get-Prop $group 'flowTuples')) {
                    $p = ConvertFrom-FlowTuple $tup
                    if ($null -eq $p) { continue }
                    $tuplesParsed++
                    $totalBytes   += $p.Bytes
                    $totalPackets += $p.Packets
                    [void]$srcIps.Add($p.Src)
                    [void]$dstIps.Add($p.Dst)

                    if (-not $protoCounts.ContainsKey($p.Proto)) { $protoCounts[$p.Proto] = 0 }
                    $protoCounts[$p.Proto]++
                    $decisionCounts[$p.Decision]++
                    if ($directionCounts.ContainsKey($p.Direction)) { $directionCounts[$p.Direction]++ }

                    $fk = "$($p.Src)|$($p.Dst)|$($p.DPort)|$($p.Proto)|$($p.Direction)|$($p.Decision)"
                    if (-not $flows.ContainsKey($fk)) {
                        $flows[$fk] = @{ Bytes = [long]0; Packets = [long]0; Records = 0; Meta = $p }
                    }
                    $flows[$fk].Bytes   += $p.Bytes
                    $flows[$fk].Packets += $p.Packets
                    $flows[$fk].Records++

                    Add-Agg $talkers $p.Src $p.Bytes
                    Add-Agg $dests   $p.Dst $p.Bytes
                    if ($p.Proto -in @('TCP', 'UDP') -and $p.DPort -gt 0) {
                        Add-Agg $ports $p.DPort $p.Bytes
                    }
                }
            }
        }
    }
}

#endregion

#region ── build heaviest-flow table (Items) + summary tables ─────────────────────

$ranked = $flows.GetEnumerator() | Sort-Object { $_.Value.Bytes } -Descending | Select-Object -First $MaxFlowRows
foreach ($entry in $ranked) {
    $p = $entry.Value.Meta
    $decision = $p.Decision
    $severity = if ($decision -eq 'Denied') { 'medium' } else { 'ok' }
    $rec = if ($decision -eq 'Denied') {
        @{ Action = 'Investigate denied flow'; Reason = "$($entry.Value.Records) denied $($p.Proto) record(s) from $($p.Src) to $($p.Dst):$($p.DPort) — check NSG/UDR or a probing source." }
    } else {
        @{ Action = 'No action'; Reason = "Allowed $($p.Proto) traffic from $($p.Src) to $($p.Dst):$($p.DPort)." }
    }
    $items.Add([ordered]@{
        Id                = $entry.Key
        SrcIp             = $p.Src
        DestIp            = $p.Dst
        DestPort          = $p.DPort
        PortLabel         = (Get-PortLabel $p.DPort)
        Protocol          = $p.Proto
        Direction         = $p.Direction
        Decision          = $decision
        Records           = $entry.Value.Records
        Bytes             = $entry.Value.Bytes
        Packets           = $entry.Value.Packets
        Severity          = $severity
        RecommendedAction = $rec
    })
}

$topTalkers      = Get-TopRows $talkers 'Ip'   $TopN
$topDestinations = Get-TopRows $dests   'Ip'   $TopN
$topPorts        = [System.Collections.Generic.List[object]]::new()
foreach ($entry in ($ports.GetEnumerator() | Sort-Object { $_.Value.Bytes } -Descending | Select-Object -First $TopN)) {
    $topPorts.Add([ordered]@{ Port = $entry.Key; Label = (Get-PortLabel ([int]$entry.Key)); Bytes = $entry.Value.Bytes; Records = $entry.Value.Records })
}
$protocols = [System.Collections.Generic.List[object]]::new()
foreach ($entry in ($protoCounts.GetEnumerator() | Sort-Object Value -Descending)) {
    $protocols.Add([ordered]@{ Name = $entry.Key; Value = $entry.Value })
}
$decisionTable = @(
    [ordered]@{ Name = 'Allowed'; Value = $decisionCounts.Allowed }
    [ordered]@{ Name = 'Denied';  Value = $decisionCounts.Denied }
)
$directionTable = @(
    [ordered]@{ Name = 'Inbound';  Value = $directionCounts.Inbound }
    [ordered]@{ Name = 'Outbound'; Value = $directionCounts.Outbound }
)

#endregion

#region ── write output ─────────────────────────────────────────────────────────

foreach ($w in $warnings) { $errors.Add(@{ Stage = "warning"; Error = $w }) }

$output = @{
    ScanMetadata = @{
        ScanTime         = $scanStartTime.ToString("o")
        CompletedTime    = (Get-Date).ToString("o")
        FlowLogName      = if ($flowLogName) { $flowLogName } else { '(flow log)' }
        VnetName         = $vnetName
        StorageAccount   = $storageAccount
        Container        = $container
        WindowHours      = $LookbackHours
        WindowStart      = $windowStart.ToString("o")
        WindowEnd        = $now.ToString("o")
        BlobsProcessed   = $total
        FlowsParsed      = $tuplesParsed
        TotalBytes       = $totalBytes
        TotalPackets     = $totalPackets
        UniqueSrcIps     = $srcIps.Count
        UniqueDestIps    = $dstIps.Count
        AllowedFlows     = $decisionCounts.Allowed
        DeniedFlows      = $decisionCounts.Denied
        InboundFlows     = $directionCounts.Inbound
        OutboundFlows    = $directionCounts.Outbound
        TopTalkers       = @($topTalkers)
        TopDestinations  = @($topDestinations)
        TopPorts         = @($topPorts)
        Protocols        = @($protocols)
        Decision         = @($decisionTable)
        Direction        = @($directionTable)
        TotalItems       = $items.Count
        ErrorCount       = $errors.Count
    }
    Items  = $items
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -FlaggedSoFar $decisionCounts.Denied -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. Parsed $tuplesParsed flow(s) across $total blob(s) — $($decisionCounts.Denied) denied. Wrote $OutputPath"

#endregion
