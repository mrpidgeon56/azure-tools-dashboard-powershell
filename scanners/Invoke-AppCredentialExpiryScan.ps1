#Requires -Version 7.0
#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    App Registration & Service Principal credential-expiry scanner.

    Tenant-wide Microsoft Graph tool (no subscription/scope targeting). For every
    app registration and service principal it inspects the configured client secrets
    (passwordCredentials) and certificates (keyCredentials), finds the soonest
    endDateTime, and flags identities whose credentials have already expired or are
    about to.

.OUTPUTS
    JSON at -OutputPath (default ../data/app-credential-expiry-scan-results.json):
    { ScanMetadata, Items, Errors }

.NOTES
    Authentication reuses the in-memory Az context (no separate Graph login): a
    Microsoft Graph access token is obtained with Get-AzAccessToken -ResourceTypeName
    MSGraph and the Graph REST API is called directly. The signed-in identity needs
    the Graph application permission Application.Read.All. If that permission is
    missing the scan still completes — it records a warning and returns whatever was
    gathered rather than failing outright.

    Required Az modules: Az.Accounts.
#>
[CmdletBinding()]
param(
    [string] $OutputPath   = "$PSScriptRoot/../data/app-credential-expiry-scan-results.json",
    [string] $ProgressPath = "",
    [int]    $ExpiringWindowDays = 30   # credentials whose soonest expiry falls within this many days are "expiring"
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

#region ── helpers ───────────────────────────────────────────────────────────────

# Acquire a Microsoft Graph bearer token from the in-memory Az context. Handles
# both the SecureString token (Az.Accounts 5+) and the legacy plaintext token.
function Get-GraphToken {
    $t = Get-AzAccessToken -ResourceTypeName MSGraph -WarningAction SilentlyContinue -ErrorAction Stop
    if ($t.Token -is [System.Security.SecureString]) {
        return [System.Net.NetworkCredential]::new('', $t.Token).Password
    }
    return [string]$t.Token
}

# Map (status, identityType) → a suggested action + reason, mirroring the Python recommendation().
function Get-CredentialRecommendation {
    param([string]$Status, [string]$IdentityType, [int]$WindowDays)
    switch ($Status) {
        'expired'  { return @{ Action = "Rotate now"; Reason = "All credentials have expired — automation using this identity is broken." } }
        'expiring' { return @{ Action = "Plan rotation"; Reason = "Soonest credential expires within $WindowDays days." } }
        'none'     {
            $noun = if ($IdentityType -eq 'Application') { 'application' } else { 'service principal' }
            return @{ Action = "Review (no credentials)"; Reason = "No secrets or certificates configured on this $noun (may use federated / managed identity)." }
        }
        default    { return @{ Action = "Keep"; Reason = "Credentials are valid and not expiring soon." } }
    }
}

# Inspect passwordCredentials + keyCredentials → expiry rollup for one identity.
function Get-CredentialSummary {
    param([object]$Obj, [datetime]$Now, [int]$WindowDays)
    $props   = $Obj.PSObject.Properties.Name
    $secrets = if ($props -contains 'passwordCredentials' -and $Obj.passwordCredentials) { @($Obj.passwordCredentials) } else { @() }
    $certs   = if ($props -contains 'keyCredentials' -and $Obj.keyCredentials) { @($Obj.keyCredentials) } else { @() }

    $ends = [System.Collections.Generic.List[datetime]]::new()
    foreach ($c in $secrets) {
        if ($c.PSObject.Properties.Name -contains 'endDateTime' -and $c.endDateTime) { $ends.Add([datetime]$c.endDateTime) }
    }
    foreach ($c in $certs) {
        if ($c.PSObject.Properties.Name -contains 'endDateTime' -and $c.endDateTime) { $ends.Add([datetime]$c.endDateTime) }
    }

    $hasSecrets = $secrets.Count -gt 0
    $hasCerts   = $certs.Count -gt 0
    $credType = if ($hasSecrets -and $hasCerts) { 'mixed' }
                elseif ($hasSecrets) { 'secret' }
                elseif ($hasCerts) { 'certificate' }
                else { 'none' }
    $credCount = $secrets.Count + $certs.Count

    $soonest = $null
    $daysToExpiry = $null
    if ($ends.Count -gt 0) {
        $soonest = ($ends | Sort-Object)[0]
        $daysToExpiry = [int][math]::Floor(($soonest - $Now).TotalDays)
    }

    if ($ends.Count -eq 0) {
        $status = 'none'; $severity = 'muted'
    } elseif ($daysToExpiry -lt 0) {
        $status = 'expired'; $severity = 'high'
    } elseif ($daysToExpiry -le $WindowDays) {
        $status = 'expiring'; $severity = 'medium'
    } else {
        $status = 'valid'; $severity = 'ok'
    }

    return [pscustomobject]@{
        CredentialType  = $credType
        CredentialCount = $credCount
        SoonestExpiry   = if ($soonest) { $soonest.ToString("o") } else { $null }
        DaysToExpiry    = $daysToExpiry
        Status          = $status
        Severity        = $severity
    }
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$items  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()
$flaggedSoFar = 0
$now = Get-Date

Set-ScanProgress -Phase "init" -Message "Acquiring Microsoft Graph token..."
Write-Progress2 "Acquiring Microsoft Graph token from the active Az session..."
$token   = Get-GraphToken
$headers = @{ Authorization = "Bearer $token"; ConsistencyLevel = "eventual" }

function Get-GraphPage ($uri) {
    return Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
}

# Build one record from a Graph application/servicePrincipal object.
function New-CredentialRecord {
    param([object]$Obj, [string]$IdentityType, [datetime]$Now, [int]$WindowDays, [string]$SpType)
    $props = $Obj.PSObject.Properties.Name
    $creds = Get-CredentialSummary -Obj $Obj -Now $Now -WindowDays $WindowDays
    $rec   = Get-CredentialRecommendation -Status $creds.Status -IdentityType $IdentityType -WindowDays $WindowDays
    [ordered]@{
        Id                   = if ($props -contains 'id' -and $Obj.id) { [string]$Obj.id } else { "" }
        DisplayName          = if ($props -contains 'displayName' -and $Obj.displayName) { [string]$Obj.displayName } else { "" }
        AppId                = if ($props -contains 'appId' -and $Obj.appId) { [string]$Obj.appId } else { "" }
        IdentityType         = $IdentityType
        ServicePrincipalType = $SpType
        CredentialType       = $creds.CredentialType
        CredentialCount      = $creds.CredentialCount
        SoonestExpiry        = $creds.SoonestExpiry
        DaysToExpiry         = $creds.DaysToExpiry
        Status               = $creds.Status
        Severity             = $creds.Severity
        RecommendedAction    = $rec
    }
}

# Page a Graph collection. On a first-page failure (e.g. missing Application.Read.All)
# record a warning/error and return nothing — the scan still returns the other collection.
function Invoke-GraphCollection {
    param([string]$Path, [string]$Select, [string]$Label, [string]$IdentityType, [string]$Stage)
    $enc = [System.Uri]::EscapeDataString($Select)
    $uri = "https://graph.microsoft.com/v1.0$Path`?`$select=$enc&`$top=999"
    try {
        $page = Get-GraphPage $uri
    } catch {
        Write-Progress2 "$Label unavailable ($(Format-Exception $_))."
        $errors.Add(@{ Stage = $Stage; Error = (Format-Exception $_) })
        return
    }
    $pageNum = 0
    while ($true) {
        $pageNum++
        foreach ($obj in @($page.value)) {
            try {
                $spType = $null
                if ($IdentityType -eq 'ServicePrincipal' -and $obj.PSObject.Properties.Name -contains 'servicePrincipalType') {
                    $spType = [string]$obj.servicePrincipalType
                }
                $rec = New-CredentialRecord -Obj $obj -IdentityType $IdentityType -Now $now -WindowDays $ExpiringWindowDays -SpType $spType
                $items.Add($rec)
                if ($rec.Severity -in @('high','medium')) { $script:flaggedSoFar++ }
                if ($items.Count % 200 -eq 0) {
                    Set-ScanProgress -Phase "scanning" -Fetched $items.Count -Total $items.Count `
                                     -FlaggedSoFar $script:flaggedSoFar -Message "Processed $($items.Count) identities..."
                }
            } catch {
                $errors.Add(@{ Stage = "$($IdentityType.ToLower()):$($obj.id)"; Error = (Format-Exception $_) })
            }
        }
        Write-Progress2 "$Label page $pageNum — $($items.Count) identities total."
        if ($page.PSObject.Properties.Name -contains '@odata.nextLink' -and $page.'@odata.nextLink') {
            try { $page = Get-GraphPage $page.'@odata.nextLink' }
            catch { $errors.Add(@{ Stage = "$Stage (paging)"; Error = (Format-Exception $_) }); break }
        } else { break }
    }
}

$appSelect = 'id,appId,displayName,passwordCredentials,keyCredentials'
$spSelect  = 'id,appId,displayName,passwordCredentials,keyCredentials,servicePrincipalType'

Set-ScanProgress -Phase "applications" -Message "Querying app registrations..."
Write-Progress2 "Querying app registrations..."
Invoke-GraphCollection -Path "/applications" -Select $appSelect -Label "applications" -IdentityType "Application" -Stage "applications"

Set-ScanProgress -Phase "service-principals" -Message "Querying service principals..."
Write-Progress2 "Querying service principals..."
Invoke-GraphCollection -Path "/servicePrincipals" -Select $spSelect -Label "service principals" -IdentityType "ServicePrincipal" -Stage "service principals"

#endregion

#region ── write output ─────────────────────────────────────────────────────────

# Sort: severity rank desc, then soonest expiry (fewest days first), then name.
$rank = @{ high = 3; medium = 2; ok = 1; muted = 0 }
$sorted = @($items | Sort-Object `
    @{ Expression = { -1 * ($rank[$_.Severity]) } }, `
    @{ Expression = { if ($null -ne $_.DaysToExpiry) { $_.DaysToExpiry } else { [int]::MaxValue } } }, `
    @{ Expression = { ($_.DisplayName + "").ToLower() } })

$applications      = @($items | Where-Object { $_.IdentityType -eq 'Application' }).Count
$servicePrincipals = @($items | Where-Object { $_.IdentityType -eq 'ServicePrincipal' }).Count
$expired           = @($items | Where-Object { $_.Status -eq 'expired' }).Count
$expiringSoon      = @($items | Where-Object { $_.Status -eq 'expiring' }).Count
$valid             = @($items | Where-Object { $_.Status -eq 'valid' }).Count
$noCredentials     = @($items | Where-Object { $_.Status -eq 'none' }).Count

$output = @{
    ScanMetadata = @{
        ScanTime           = $scanStartTime.ToString("o")
        CompletedTime      = (Get-Date).ToString("o")
        TotalApps          = $items.Count
        Applications       = $applications
        ServicePrincipals  = $servicePrincipals
        Expired            = $expired
        ExpiringSoon       = $expiringSoon
        Valid              = $valid
        NoCredentials      = $noCredentials
        ExpiringWindowDays = $ExpiringWindowDays
        ErrorCount         = $errors.Count
    }
    Items  = $sorted
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $items.Count -Total $items.Count -FlaggedSoFar $flaggedSoFar -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($items.Count) identities — $expired expired, $expiringSoon expiring soon. Wrote $OutputPath"

#endregion
