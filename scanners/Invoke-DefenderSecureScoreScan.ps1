#Requires -Version 7.0
#Requires -Modules Az.Accounts
<#
.SYNOPSIS
    Microsoft Defender for Cloud Secure Score scanner.

    For every in-scope subscription (or a single one) it reads the Defender for Cloud
    Secure Score via the ARM REST surface:
      - the overall `ascScore` percentage, and
      - the per-control breakdown (`secureScoreControls`, $expand=definition).
    Each control becomes a row, ranked by how far short of healthy it is, so operators
    can see which controls are dragging a subscription's posture down. ARM Security
    Reader (Reader) is enough.

.OUTPUTS
    JSON file at -OutputPath (default ../data/defender-secure-score-scan-results.json):
    { ScanMetadata, Items, Errors }

.NOTES
    Authentication reuses the in-memory Az context (no separate login): an ARM token is
    obtained with Get-AzAccessToken and the Microsoft.Security secureScores REST APIs are
    called directly. This is NOT a Resource-Graph tool — it iterates subscriptions.

    Required Az modules: Az.Accounts.
#>
[CmdletBinding()]
param(
    [string] $OutputPath           = "$PSScriptRoot/../data/defender-secure-score-scan-results.json",
    [string] $ProgressPath         = "",          # if set, incremental progress JSON is written here
    [ValidateSet('All','Subscription')]
    [string] $ScopeType            = "All",        # scan scope: whole tenant, or one subscription
    [string] $SingleSubscriptionId = ""            # optional: scan just one subscription
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ApiVersion = '2020-01-01'

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

function ConvertTo-Num ($v, [double]$default = 0.0) {
    if ($null -eq $v) { return $default }
    $out = 0.0
    if ([double]::TryParse("$v", [ref]$out)) { return $out }
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

# Mirrors the Python _severity(): percentage in 0-100.
function Get-ScoreSeverity ([double]$Percentage) {
    if ($Percentage -lt 50) { return 'high' }
    if ($Percentage -lt 80) { return 'medium' }
    return 'ok'
}

# Mirrors the Python recommendation().
function Get-ScoreAction {
    param([string]$Severity, [string]$ControlName, [int]$Unhealthy)
    if ($Severity -eq 'ok') {
        return @{ Action = 'Maintain'; Reason = "$ControlName is healthy; keep current controls in place." }
    }
    return @{
        Action = 'Remediate control'
        Reason = "$Unhealthy unhealthy resource(s) under $ControlName are reducing this subscription's secure score."
    }
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()

$scopeLabel = if ($ScopeType -eq 'Subscription' -and $SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              elseif ($SingleSubscriptionId) { "subscription '$SingleSubscriptionId'" }
              else { "all accessible subscriptions" }

Set-ScanProgress -Phase "init" -Message "Acquiring ARM token..."
Write-Progress2 "Defender for Cloud Secure Score scan — scope: $scopeLabel"
Write-Progress2 "Acquiring ARM token from the active Az session..."
$armTok     = Get-ArmToken
$armExpires = $armTok.ExpiresOn
$armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }

# ── resolve the subscription set ──────────────────────────────────────────────
# A single subscription (-SingleSubscriptionId, or -ScopeType Subscription) restricts to
# one; otherwise the scan spans every accessible subscription. No MG / RG scope for this tool.
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

$totalSubs = $subs.Count
Set-ScanProgress -Phase "scanning" -Total $totalSubs -Message "Reading secure score for $totalSubs subscription(s)..."
Write-Progress2 "Reading secure score for $totalSubs subscription(s)..."

$subScores = [System.Collections.Generic.List[double]]::new()
$atRisk = 0; $healthyControls = 0; $done = 0

foreach ($sub in $subs) {
    $done++
    $subId = $sub.Id
    $subName = $sub.Name

    # Refresh the ARM token if it is within ~5 minutes of expiry (long scans outlive it).
    if ($armExpires -le [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        try {
            $armTok     = Get-ArmToken
            $armExpires = $armTok.ExpiresOn
            $armHeaders = @{ Authorization = "Bearer $($armTok.Token)" }
        } catch { <# keep the current token; the request below will surface any auth error #> }
    }

    try {
        # Overall ascScore percentage.
        $scoreUri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Security/secureScores/ascScore?api-version=$ApiVersion"
        $scoreResp = Invoke-RestMethod -Method GET -Uri $scoreUri -Headers $armHeaders -ErrorAction Stop
        $scoreProps = Get-Prop $scoreResp 'properties'
        $score = Get-Prop $scoreProps 'score'
        $subOverall = [math]::Round((ConvertTo-Num (Get-Prop $score 'percentage')) * 100, 1)
        $subScores.Add($subOverall)

        # Per-control breakdown.
        $ctrlUri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Security/secureScoreControls?api-version=$ApiVersion&`$expand=definition"
        $ctrlResp = Invoke-RestMethod -Method GET -Uri $ctrlUri -Headers $armHeaders -ErrorAction Stop
        $controls = @(Get-Prop $ctrlResp 'value')

        foreach ($ctrl in $controls) {
            $props      = Get-Prop $ctrl 'properties'
            $definition = Get-Prop $props 'definition'
            $defProps   = Get-Prop $definition 'properties'
            $controlName = (Get-Prop $props 'displayName')
            if (-not $controlName) { $controlName = (Get-Prop $defProps 'displayName') }
            if (-not $controlName) { $controlName = (Get-Prop $ctrl 'name') }
            if (-not $controlName) { $controlName = 'Unknown control' }
            $controlName = "$controlName"

            $cscore     = Get-Prop $props 'score'
            $current    = ConvertTo-Num (Get-Prop $cscore 'current')
            $maximum    = ConvertTo-Num (Get-Prop $cscore 'max')
            $percentage = [math]::Round((ConvertTo-Num (Get-Prop $cscore 'percentage')) * 100, 1)
            $healthy    = [int](ConvertTo-Num (Get-Prop $props 'healthyResourceCount'))
            $unhealthy  = [int](ConvertTo-Num (Get-Prop $props 'unhealthyResourceCount'))
            $notApplic  = [int](ConvertTo-Num (Get-Prop $props 'notApplicableResourceCount'))
            $severity   = Get-ScoreSeverity $percentage

            if ($severity -eq 'ok') { $healthyControls++ } else { $atRisk++ }

            $itemId = (Get-Prop $ctrl 'id')
            if (-not $itemId) { $itemId = "/subscriptions/$subId/$controlName" }

            $items.Add([ordered]@{
                Id                      = "$itemId"
                SubscriptionId          = $subId
                SubscriptionName        = $subName
                ControlName             = $controlName
                CurrentScore            = $current
                MaxScore                = $maximum
                Percentage              = $percentage
                HealthyResources        = $healthy
                UnhealthyResources      = $unhealthy
                NotApplicableResources  = $notApplic
                SubscriptionScore       = $subOverall
                Severity                = $severity
                RecommendedAction       = (Get-ScoreAction -Severity $severity -ControlName $controlName -Unhealthy $unhealthy)
            })
        }
    } catch {
        $errors.Add(@{ Stage = "$subName ($subId)"; Error = (Format-Exception $_) })
        Write-Progress2 "Could not read secure score for $subName ($subId): $(Format-Exception $_)"
    }

    Set-ScanProgress -Phase "scanning" -Fetched $done -Total $totalSubs -FlaggedSoFar $atRisk `
                     -Message "Processed $done/$totalSubs subscription(s)..."
}

#endregion

#region ── write output ─────────────────────────────────────────────────────────

$averageScore = if ($subScores.Count) { [math]::Round((($subScores | Measure-Object -Sum).Sum / $subScores.Count), 1) } else { 0.0 }
$lowestScore  = if ($subScores.Count) { [math]::Round((($subScores | Measure-Object -Minimum).Minimum), 1) } else { 0.0 }

$output = @{
    ScanMetadata = @{
        ScanTime              = $scanStartTime.ToString("o")
        CompletedTime         = (Get-Date).ToString("o")
        ScopeType             = $ScopeType
        ScopeLabel            = $scopeLabel
        SubscriptionsScanned  = $totalSubs
        ControlsScanned       = $items.Count
        AverageScore          = $averageScore
        AtRiskControls        = $atRisk
        HealthyControls       = $healthyControls
        LowestScore           = $lowestScore
        TotalItems            = $items.Count
        ErrorCount            = $errors.Count
    }
    Items  = $items
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -FlaggedSoFar $atRisk -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) control(s) across $totalSubs subscription(s) — avg score $averageScore%, $atRisk at-risk. Wrote $OutputPath"

#endregion
