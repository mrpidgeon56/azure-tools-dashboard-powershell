<#
.SYNOPSIS
    Scans Microsoft Entra ID (Azure AD) users for stale / orphaned accounts.

    For every user in the tenant it reports:
      - account type: Member (password-based) vs Guest (B2B invited)
      - last interactive / non-interactive sign-in and days since last sign-in
      - password expiry for Member accounts (lastPasswordChange + validity window,
        honouring the DisablePasswordExpiration policy)
      - an "orphaned" flag: a user is orphaned if their password has EXPIRED or they
        have not signed in for longer than -StaleDays (default 180 = ~6 months;
        accounts that have NEVER signed in count as stale once older than -StaleDays).

.OUTPUTS
    JSON file at -OutputPath (default: ./entra-scan-results.json)

.NOTES
    Authentication reuses the in-memory Az context (no separate Graph login): a
    Microsoft Graph access token is obtained with Get-AzAccessToken and the Graph
    REST API is called directly. The signed-in identity therefore needs the Graph
    delegated permissions:
      - User.Read.All        (enumerate users)
      - AuditLog.Read.All    (read signInActivity — requires Entra ID P1/P2)
      - Application.Read.All (enumerate service principals, when -IncludeServicePrincipals)
    If signInActivity is unavailable (no P1, or missing AuditLog.Read.All) the scan
    still runs; sign-in fields are reported as null and staleness falls back to the
    account's creation date.

    Required Az modules: Az.Accounts.
#>
[CmdletBinding()]
param(
    [string] $OutputPath           = "$PSScriptRoot/entra-scan-results.json",
    [string] $ProgressPath         = "",      # if set, incremental progress JSON is written here
    [int]    $StaleDays            = 180,     # no sign-in older than this ⇒ stale (≈6 months)
    [int]    $PasswordValidityDays = 90,      # password lifetime for accounts without DisablePasswordExpiration
    [bool]   $IncludeDisabled      = $true,   # include accountEnabled = false users
    [bool]   $IncludeServicePrincipals = $true # also enumerate service principals (real "Principal" identities)
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

# Acquire a Microsoft Graph bearer token from the in-memory Az context. Handles
# both the SecureString token (Az.Accounts 5+) and the legacy plaintext token.
function Get-GraphToken {
    $t = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
    if ($t.Token -is [System.Security.SecureString]) {
        return [System.Net.NetworkCredential]::new('', $t.Token).Password
    }
    return [string]$t.Token
}

# Suggested remediation for a single user account.
function Get-EntraRecommendation {
    param(
        [bool]   $AccountEnabled,
        [bool]   $IsGuest,
        [bool]   $PasswordExpired,
        [bool]   $StaleByLogin,
        [object] $DaysSinceSignIn,
        [bool]   $NeverSignedIn
    )
    if (-not $AccountEnabled) {
        return @{ Action = "Keep"; Reason = "Account is already disabled — no action needed." }
    }
    if ($PasswordExpired) {
        return @{ Action = "Disable or delete"; Reason = "Password has expired and the account is still enabled." }
    }
    if ($StaleByLogin) {
        $howLong = if ($NeverSignedIn) { "has never signed in" } else { "has not signed in for $([math]::Round($DaysSinceSignIn)) days" }
        if ($IsGuest) {
            return @{ Action = "Remove guest access"; Reason = "Guest account $howLong." }
        }
        return @{ Action = "Review or disable"; Reason = "Account $howLong." }
    }
    return @{ Action = "Keep"; Reason = "Account is active and in good standing." }
}

#endregion

#region ── main scan ────────────────────────────────────────────────────────────

$scanStartTime = Get-Date
$users  = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()
$flaggedSoFar = 0

Set-ScanProgress -Phase "init" -Message "Acquiring Microsoft Graph token..."
Write-Progress2 "Acquiring Microsoft Graph token from the active Az session..."
$token   = Get-GraphToken
$headers = @{ Authorization = "Bearer $token"; ConsistencyLevel = "eventual" }

# Try to include signInActivity (needs AuditLog.Read.All + Entra ID P1). If the very
# first page fails because of it, fall back to a query without sign-in data.
$baseSelect    = 'id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime,passwordPolicies,lastPasswordChangeDateTime'
$selectWithSia = "$baseSelect,signInActivity"
$signInAvailable = $true

function Get-UsersPage ($uri) {
    return Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
}

$enc  = [System.Uri]::EscapeDataString($selectWithSia)
$uri  = "https://graph.microsoft.com/v1.0/users?`$select=$enc&`$top=999"
try {
    Write-Progress2 "Querying users (with sign-in activity)..."
    $page = Get-UsersPage $uri
} catch {
    Write-Progress2 "Sign-in activity unavailable ($(Format-Exception $_)); retrying without it."
    $signInAvailable = $false
    $errors.Add(@{ Stage = "signInActivity"; Error = (Format-Exception $_) })
    $enc = [System.Uri]::EscapeDataString($baseSelect)
    $uri = "https://graph.microsoft.com/v1.0/users?`$select=$enc&`$top=999"
    $page = Get-UsersPage $uri
}

$now = Get-Date
$processOne = {
    param($u)
    $props = $u.PSObject.Properties.Name

    $userType       = if ($props -contains 'userType' -and $u.userType) { [string]$u.userType } else { 'Member' }
    $isGuest        = ($userType -eq 'Guest')
    $accountEnabled = if ($props -contains 'accountEnabled') { [bool]$u.accountEnabled } else { $true }

    $created = $null
    if ($props -contains 'createdDateTime' -and $u.createdDateTime) { $created = [datetime]$u.createdDateTime }

    # ── sign-in activity ───────────────────────────────────────────────
    $lastInteractive = $null; $lastNonInteractive = $null
    if ($signInAvailable -and ($props -contains 'signInActivity') -and $u.signInActivity) {
        $sia = $u.signInActivity
        $siaProps = $sia.PSObject.Properties.Name
        if ($siaProps -contains 'lastSignInDateTime' -and $sia.lastSignInDateTime) { $lastInteractive = [datetime]$sia.lastSignInDateTime }
        if ($siaProps -contains 'lastNonInteractiveSignInDateTime' -and $sia.lastNonInteractiveSignInDateTime) { $lastNonInteractive = [datetime]$sia.lastNonInteractiveSignInDateTime }
    }
    $lastSignIn = $null
    foreach ($d in @($lastInteractive, $lastNonInteractive)) {
        if ($d -and (-not $lastSignIn -or $d -gt $lastSignIn)) { $lastSignIn = $d }
    }
    $neverSignedIn = (-not $lastSignIn)
    $daysSince = if ($lastSignIn) { [math]::Round(($now - $lastSignIn).TotalDays, 1) } else { $null }

    # Stale by login: last sign-in older than the window, OR never signed in and the
    # account itself is older than the window (a brand-new never-used account isn't stale yet).
    $staleByLogin = $false
    if ($neverSignedIn) {
        if ($created -and ($now - $created).TotalDays -gt $StaleDays) { $staleByLogin = $true }
    } elseif ($daysSince -gt $StaleDays) {
        $staleByLogin = $true
    }

    # ── password expiry (Member accounts only) ─────────────────────────
    $passwordNeverExpires = $false
    if ($props -contains 'passwordPolicies' -and $u.passwordPolicies) {
        $policies = ($u.passwordPolicies -split ',') | ForEach-Object { $_.Trim() }
        if ($policies -contains 'DisablePasswordExpiration') { $passwordNeverExpires = $true }
    }
    $lastPwdChange = $null
    if ($props -contains 'lastPasswordChangeDateTime' -and $u.lastPasswordChangeDateTime) { $lastPwdChange = [datetime]$u.lastPasswordChangeDateTime }

    $passwordExpired = $false; $passwordExpiry = $null; $passwordStatus = 'N/A'
    if ($isGuest) {
        $passwordStatus = 'N/A (guest)'
    } elseif ($passwordNeverExpires) {
        $passwordStatus = 'Never expires'
    } elseif ($lastPwdChange) {
        $passwordExpiry  = $lastPwdChange.AddDays($PasswordValidityDays)
        $passwordExpired = ($now -gt $passwordExpiry)
        $passwordStatus  = if ($passwordExpired) { 'Expired' } else { 'Active' }
    } else {
        $passwordStatus = 'Unknown'
    }

    # ── orphaned: expired password OR no login > StaleDays ─────────────
    $isOrphaned = ($passwordExpired -or $staleByLogin)

    $rec = Get-EntraRecommendation -AccountEnabled $accountEnabled -IsGuest $isGuest `
               -PasswordExpired $passwordExpired -StaleByLogin $staleByLogin `
               -DaysSinceSignIn $daysSince -NeverSignedIn $neverSignedIn

    [ordered]@{
        Id                       = [string]$u.id
        DisplayName              = [string]$u.displayName
        UserPrincipalName        = [string]$u.userPrincipalName
        IdentityType             = 'User'
        UserType                 = $userType
        IsGuest                  = $isGuest
        AccountEnabled           = $accountEnabled
        CreatedDateTime          = if ($created) { $created.ToString("o") } else { $null }
        LastSignIn               = if ($lastSignIn) { $lastSignIn.ToString("o") } else { $null }
        LastInteractiveSignIn    = if ($lastInteractive) { $lastInteractive.ToString("o") } else { $null }
        LastNonInteractiveSignIn = if ($lastNonInteractive) { $lastNonInteractive.ToString("o") } else { $null }
        DaysSinceLastSignIn      = $daysSince
        NeverSignedIn            = $neverSignedIn
        LastPasswordChange       = if ($lastPwdChange) { $lastPwdChange.ToString("o") } else { $null }
        PasswordNeverExpires     = $passwordNeverExpires
        PasswordExpiry           = if ($passwordExpiry) { $passwordExpiry.ToString("o") } else { $null }
        PasswordExpired          = $passwordExpired
        PasswordStatus           = $passwordStatus
        StaleByLogin             = $staleByLogin
        IsOrphaned               = $isOrphaned
        RecommendedAction        = $rec
    }
}

# Page through all users following @odata.nextLink.
$pageNum = 0
while ($true) {
    $pageNum++
    $batch = @($page.value)
    foreach ($u in $batch) {
        try {
            $rec = & $processOne $u
            $users.Add($rec)
            if ($rec.IsOrphaned) { $flaggedSoFar++ }
        } catch {
            $errors.Add(@{ Stage = "user:$($u.id)"; Error = (Format-Exception $_) })
        }
    }
    Set-ScanProgress -Phase "scanning" -Fetched $users.Count -Total $users.Count `
                     -FlaggedSoFar $flaggedSoFar -Message "Processed $($users.Count) user(s)..."
    Write-Progress2 "Page $pageNum — $($users.Count) user(s) processed so far."

    if ($page.PSObject.Properties.Name -contains '@odata.nextLink' -and $page.'@odata.nextLink') {
        $page = Get-UsersPage $page.'@odata.nextLink'
    } else {
        break
    }
}

if (-not $IncludeDisabled) {
    $before = $users.Count
    $kept = @($users | Where-Object { $_.AccountEnabled })
    $users.Clear(); foreach ($k in $kept) { $users.Add($k) }
    Write-Progress2 "Excluded $($before - $users.Count) disabled account(s)."
}

# ── service principals (real "Principal" directory identities) ───────────────
# Users and service principals are distinct directory object types. To populate
# the Identity column with the *true* type (rather than a heuristic), we also
# enumerate /servicePrincipals and emit them with the SAME record schema so the
# dashboard renders them in the same table. SPs have no sign-in/password-age data;
# instead their health comes from credential (secret/cert) expiry.
$principalCount = 0
if ($IncludeServicePrincipals) {
    $spSelect = 'id,displayName,appId,servicePrincipalType,accountEnabled,createdDateTime,passwordCredentials,keyCredentials'
    $spEnc    = [System.Uri]::EscapeDataString($spSelect)
    $spUri    = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=$spEnc&`$top=999"

    $processSp = {
        param($sp)
        $p = $sp.PSObject.Properties.Name

        $spType   = if ($p -contains 'servicePrincipalType' -and $sp.servicePrincipalType) { [string]$sp.servicePrincipalType } else { 'Application' }
        $enabled  = if ($p -contains 'accountEnabled') { [bool]$sp.accountEnabled } else { $true }
        $created  = $null
        if ($p -contains 'createdDateTime' -and $sp.createdDateTime) { $created = [datetime]$sp.createdDateTime }

        # Gather credential expiry dates from both secrets and certificates.
        $ends = [System.Collections.Generic.List[datetime]]::new()
        foreach ($coll in @('passwordCredentials','keyCredentials')) {
            if ($p -contains $coll -and $sp.$coll) {
                foreach ($c in @($sp.$coll)) {
                    if ($c.PSObject.Properties.Name -contains 'endDateTime' -and $c.endDateTime) {
                        $ends.Add([datetime]$c.endDateTime)
                    }
                }
            }
        }
        $credExpired = $false; $credExpiry = $null; $credStatus = 'No credentials'
        if ($ends.Count -gt 0) {
            $latest = ($ends | Sort-Object -Descending)[0]
            $credExpiry = $latest
            $hasActive  = @($ends | Where-Object { $_ -gt $now }).Count -gt 0
            $credExpired = -not $hasActive
            $credStatus  = if ($credExpired) { 'Expired' } else { 'Active' }
        }

        # Orphaned SP = all credentials expired (a live registration with dead secrets).
        $isOrphaned = $credExpired
        if (-not $enabled) {
            $rec = @{ Action = 'Keep'; Reason = 'Service principal is disabled — no action needed.' }
        } elseif ($credExpired) {
            $rec = @{ Action = 'Rotate or remove'; Reason = 'All service-principal credentials have expired.' }
        } elseif ($credStatus -eq 'No credentials') {
            $rec = @{ Action = 'Keep'; Reason = 'No credentials configured (may use federated/managed identity).' }
        } else {
            $rec = @{ Action = 'Keep'; Reason = 'Service principal has active credentials.' }
        }

        [ordered]@{
            Id                       = [string]$sp.id
            DisplayName              = [string]$sp.displayName
            UserPrincipalName        = [string]$sp.appId          # app (client) ID shown in the UPN slot
            IdentityType             = 'Principal'
            UserType                 = $spType                      # Application / ManagedIdentity / Legacy …
            IsGuest                  = $false
            AccountEnabled           = $enabled
            CreatedDateTime          = if ($created) { $created.ToString("o") } else { $null }
            LastSignIn               = $null
            LastInteractiveSignIn    = $null
            LastNonInteractiveSignIn = $null
            DaysSinceLastSignIn      = $null
            NeverSignedIn            = $false                       # not meaningful for SPs
            LastPasswordChange       = $null
            PasswordNeverExpires     = $false
            PasswordExpiry           = if ($credExpiry) { $credExpiry.ToString("o") } else { $null }
            PasswordExpired          = $credExpired
            PasswordStatus           = $credStatus
            StaleByLogin             = $false
            IsOrphaned               = $isOrphaned
            RecommendedAction        = $rec
        }
    }

    try {
        Set-ScanProgress -Phase "scanning" -Message "Querying service principals..."
        Write-Progress2 "Querying service principals..."
        $spPage = Get-UsersPage $spUri
        $spPageNum = 0
        while ($true) {
            $spPageNum++
            foreach ($sp in @($spPage.value)) {
                try {
                    $rec = & $processSp $sp
                    if (-not $IncludeDisabled -and -not $rec.AccountEnabled) { continue }
                    $users.Add($rec)
                    $principalCount++
                    if ($rec.IsOrphaned) { $flaggedSoFar++ }
                } catch {
                    $errors.Add(@{ Stage = "sp:$($sp.id)"; Error = (Format-Exception $_) })
                }
            }
            Write-Progress2 "Service principals page $spPageNum — $principalCount processed so far."
            if ($spPage.PSObject.Properties.Name -contains '@odata.nextLink' -and $spPage.'@odata.nextLink') {
                $spPage = Get-UsersPage $spPage.'@odata.nextLink'
            } else { break }
        }
    } catch {
        Write-Progress2 "Service-principal enumeration failed ($(Format-Exception $_))."
        $errors.Add(@{ Stage = "servicePrincipals"; Error = (Format-Exception $_) })
    }
}

#endregion

#region ── write output ─────────────────────────────────────────────────────────

$memberCount   = @($users | Where-Object { $_.IdentityType -eq 'User' -and -not $_.IsGuest }).Count
$guestCount    = @($users | Where-Object { $_.IdentityType -eq 'User' -and $_.IsGuest }).Count
$principalCount = @($users | Where-Object { $_.IdentityType -eq 'Principal' }).Count
$staleCount     = @($users | Where-Object { $_.StaleByLogin }).Count
$expiredCount   = @($users | Where-Object { $_.PasswordExpired }).Count
$orphanedCount  = @($users | Where-Object { $_.IsOrphaned }).Count
$neverCount     = @($users | Where-Object { $_.NeverSignedIn }).Count
$disabledCount  = @($users | Where-Object { -not $_.AccountEnabled }).Count

$output = @{
    ScanMetadata = @{
        ScanTime              = $scanStartTime.ToString("o")
        CompletedTime         = (Get-Date).ToString("o")
        TotalUsers            = $users.Count
        MemberUsers           = $memberCount
        GuestUsers            = $guestCount
        ServicePrincipals     = $principalCount
        StaleUsers            = $staleCount
        ExpiredPasswordUsers  = $expiredCount
        OrphanedUsers         = $orphanedCount
        NeverSignedIn         = $neverCount
        DisabledUsers         = $disabledCount
        StaleDays             = $StaleDays
        PasswordValidityDays  = $PasswordValidityDays
        SignInActivityAvailable = [bool]$signInAvailable
        ErrorCount            = $errors.Count
    }
    Users  = $users
    Errors = $errors
}

Set-ScanProgress -Phase "done" -Fetched $users.Count -Total $users.Count -FlaggedSoFar $flaggedSoFar -Message "Scan complete."
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Progress2 "Done. $($users.Count) user(s) — $orphanedCount orphaned, $staleCount stale, $expiredCount expired password(s). Wrote $OutputPath"

#endregion
