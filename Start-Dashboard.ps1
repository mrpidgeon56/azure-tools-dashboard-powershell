<#
.SYNOPSIS
    Starts a local HTTP dashboard server for the Azure Idle Resource Group scanner.

    Authentication is on-demand: the server does NOT sign in at startup. The user
    signs in/out from the dashboard (POST /api/auth/login | /api/auth/logout) and
    the Az context is held in process memory only, so no credentials are stored.

    Endpoints:
      GET  /                → serves home.html (hub)
      GET  /api/auth/status → reports whether an Az session is active
      POST /api/auth/login  → interactive Connect-AzAccount (system browser)
      POST /api/auth/logout → Disconnect-AzAccount + Clear-AzContext
      GET  /api/results     → returns last scan JSON (or empty state)
      POST /api/scan        → runs Invoke-AzureIdleScan.ps1 in background, streams status
      GET  /api/status      → returns current scan job status

.EXAMPLE
    .\Start-Dashboard.ps1
    # Then open http://localhost:8080 in your browser
#>
[CmdletBinding()]
param(
    [int]    $Port         = 8080,
    [string] $ResultsPath  = "$PSScriptRoot/scan-results.json",
    [string] $ProgressPath = "$PSScriptRoot/scan-progress.json",
    [string] $ScanScript   = "$PSScriptRoot/Invoke-AzureIdleScan.ps1",
    [string] $PaResultsPath  = "$PSScriptRoot/pa-scan-results.json",
    [string] $PaProgressPath = "$PSScriptRoot/pa-scan-progress.json",
    [string] $PaScanScript   = "$PSScriptRoot/Invoke-PrivilegedAccessScan.ps1",
    [string] $EntraResultsPath  = "$PSScriptRoot/entra-scan-results.json",
    [string] $EntraProgressPath = "$PSScriptRoot/entra-scan-progress.json",
    [string] $EntraScanScript   = "$PSScriptRoot/Invoke-EntraUserScan.ps1",
    [string] $TagResultsPath  = "$PSScriptRoot/tag-scan-results.json",
    [string] $TagProgressPath = "$PSScriptRoot/tag-scan-progress.json",
    [string] $TagScanScript   = "$PSScriptRoot/Invoke-TagComplianceScan.ps1",
    [string] $LaResultsPath  = "$PSScriptRoot/la-cost-scan-results.json",
    [string] $LaProgressPath = "$PSScriptRoot/la-cost-scan-progress.json",
    [string] $LaScanScript   = "$PSScriptRoot/Invoke-LogAnalyticsCostScan.ps1",
    [string] $QuotaResultsPath  = "$PSScriptRoot/quota-scan-results.json",
    [string] $QuotaProgressPath = "$PSScriptRoot/quota-scan-progress.json",
    [string] $QuotaScanScript   = "$PSScriptRoot/Invoke-QuotaScan.ps1",
    [int]    $LookbackDays = 14,
    [int]    $ThrottleLimit = 8   # max resource groups scanned concurrently (1 = sequential)
)

Set-StrictMode -Version Latest

# ── On-demand authentication (no auto sign-in, no stored credentials) ────────
# We deliberately do NOT call Connect-AzAccount at startup. The user signs in on
# demand from the dashboard (POST /api/auth/login) and out again (/api/auth/logout).
#
# Enable-AzContextAutosave -Scope Process keeps the context (and MSAL token cache)
# in PROCESS MEMORY only — it is never written to the on-disk Az token cache, so no
# credentials persist between server runs. It also lets the in-process ThreadJob
# scans share the live context. Sign-out clears it; stopping the server discards it.
$null = Enable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue

$azContext = $null
try { $azContext = Get-AzContext -ErrorAction Stop } catch { $azContext = $null }
if ($azContext -and $azContext.Account) {
    Write-Host "  Existing in-memory Azure session: $($azContext.Account.Id)" -ForegroundColor Gray
} else {
    Write-Host "  Not signed in — use the Sign in button on the dashboard." -ForegroundColor Yellow
}

# ── Ensure ThreadJob is available ────────────────────────────────────────────
# We run scans with Start-ThreadJob (NOT Start-Job). ThreadJob runs in-process,
# so the scan inherits the already-loaded Az modules AND the live Az context —
# no Save/Import-AzContext, no token-expiry or MSAL-cache problems in a child process.
if (-not (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)) {
    Write-Error "The ThreadJob module is required. Install it with: Install-Module ThreadJob -Scope CurrentUser"
    exit 1
}

$listener   = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()

Write-Host ""
Write-Host "  Azure Idle RG Dashboard" -ForegroundColor Cyan
Write-Host "  Running at http://localhost:$Port" -ForegroundColor Green
Write-Host "  Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host ""

$scanJob    = $null
$scanStatus = @{ State = "idle"; StartedAt = $null; Message = "No scan run yet." }
$paScanJob    = $null
$paScanStatus = @{ State = "idle"; StartedAt = $null; Message = "No scan run yet." }
$entraScanJob    = $null
$entraScanStatus = @{ State = "idle"; StartedAt = $null; Message = "No scan run yet." }
$tagScanJob    = $null
$tagScanStatus = @{ State = "idle"; StartedAt = $null; Message = "No scan run yet." }
$laScanJob    = $null
$laScanStatus = @{ State = "idle"; StartedAt = $null; Message = "No scan run yet." }
$quotaScanJob    = $null
$quotaScanStatus = @{ State = "idle"; StartedAt = $null; Message = "No scan run yet." }
$script:subscriptionCache = $null

function Get-MimeType([string]$ext) {
    switch ($ext) {
        ".html" { "text/html; charset=utf-8" }
        ".json" { "application/json; charset=utf-8" }
        ".js"   { "application/javascript; charset=utf-8" }
        ".css"  { "text/css; charset=utf-8" }
        default { "text/plain" }
    }
}

function Send-Response {
    param($context, [int]$status = 200, [string]$body = "", [string]$contentType = "application/json; charset=utf-8")
    $context.Response.StatusCode      = $status
    $context.Response.ContentType     = $contentType
    # NOTE: deliberately NO "Access-Control-Allow-Origin" header. The dashboard is
    # served from this same origin, so it never needs CORS. Omitting it means the
    # browser's same-origin policy blocks any *other* website from reading our API
    # responses (which contain sensitive tenant data: user lists, role assignments).
    $context.Response.Headers.Add("X-Content-Type-Options", "nosniff")
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    $context.Response.ContentLength64 = $bytes.Length
    $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $context.Response.OutputStream.Close()
}

# ── Request-origin guards (CSRF + DNS-rebinding) ─────────────────────────────
# The server only ever binds to localhost, but a malicious web page open in the
# same browser could still try to drive our API (CSRF) or reach us via a hostname
# that resolves to 127.0.0.1 (DNS rebinding). We defend with two checks:
#   1. Host header must be exactly our localhost binding.
#   2. State-changing requests (POST) must carry a same-origin Origin/Referer.
$script:allowedHosts   = @("localhost:$Port", "127.0.0.1:$Port")
$script:allowedOrigins = @("http://localhost:$Port", "http://127.0.0.1:$Port")

function Test-AllowedHost {
    param($req)
    $h = $req.Headers["Host"]
    # No Host header (HTTP/1.0) — only possible from a non-browser local client; allow.
    if (-not $h) { return $true }
    return ($script:allowedHosts -contains $h)
}

function Test-SameOrigin {
    param($req)
    # Browsers always attach Origin to cross-site POSTs; we also accept Referer as a
    # fallback. Absence of both on a POST is treated as untrusted and rejected.
    $origin = $req.Headers["Origin"]
    if (-not $origin) { $origin = $req.Headers["Referer"] }
    if (-not $origin) { return $false }
    foreach ($o in $script:allowedOrigins) {
        if ($origin -eq $o -or $origin.StartsWith("$o/")) { return $true }
    }
    return $false
}

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $req     = $context.Request
        $path    = $req.Url.LocalPath.TrimEnd("/")

        # ── Security guards ──────────────────────────────────────────────────
        # 1. DNS-rebinding guard: reject any request whose Host isn't our binding.
        if (-not (Test-AllowedHost $req)) {
            Send-Response $context -status 403 -body '{"error":"Invalid Host header."}'
            continue
        }
        # 2. CSRF guard: every state-changing request (anything but GET) into /api
        #    must come from our own page. Cross-site form posts can't forge Origin.
        if ($path.StartsWith("/api") -and $req.HttpMethod -ne "GET" -and -not (Test-SameOrigin $req)) {
            Send-Response $context -status 403 -body '{"error":"Cross-origin request rejected."}'
            continue
        }
        # 3. Body-size cap: our request bodies are tiny JSON blobs. Reject anything
        #    larger than 64 KB so a client can't make us buffer an unbounded stream.
        if ($req.ContentLength64 -gt 65536) {
            Send-Response $context -status 413 -body '{"error":"Request body too large."}'
            continue
        }

        # ── serve HTML pages (route table — add new tools here) ──────────────
        # Clean URL → file on disk. The home page is the hub; each tool gets a route.
        $pageRoutes = @{
            ""                  = "home.html"   # /            → Operational Tools hub
            "/idle-resources"   = "index.html"  # /idle-resources → Idle RG dashboard
            "/privileged-access" = "privileged-access.html"  # → Privileged Access Scanner
            "/entra-users"      = "entra-users.html"  # → Entra User Scanner
            "/tag-compliance"   = "tag-compliance.html"  # → Tag Auditor
            "/log-analytics-cost" = "log-analytics-cost.html"  # → Log Analytics Cost Projector
            "/quota-usage"        = "quota-usage.html"         # → Quota Usage Scanner
            "/home"             = "home.html"
        }
        if ($pageRoutes.ContainsKey($path)) {
            $htmlPath = "$PSScriptRoot/$($pageRoutes[$path])"
            if (Test-Path $htmlPath) {
                $html = Get-Content $htmlPath -Raw -Encoding UTF8
                Send-Response $context -body $html -contentType "text/html; charset=utf-8"
            } else {
                Send-Response $context -status 404 -body "{`"error`":`"$($pageRoutes[$path]) not found`"}"
            }
            continue
        }

        # ══ Authentication (on-demand; in-memory only) ═════════════════════

        # ── GET /api/auth/status ────────────────────────────────────────────
        if ($path -eq "/api/auth/status" -and $req.HttpMethod -eq "GET") {
            $ctx = $null
            try { $ctx = Get-AzContext -ErrorAction Stop } catch { $ctx = $null }
            if ($ctx -and $ctx.Account) {
                $subName = ""; $subId = ""
                if ($ctx.Subscription) { $subName = "$($ctx.Subscription.Name)"; $subId = "$($ctx.Subscription.Id)" }
                Send-Response $context -body (@{
                    authenticated  = $true
                    account        = "$($ctx.Account.Id)"
                    tenant         = "$($ctx.Tenant.Id)"
                    subscription   = $subName
                    subscriptionId = $subId
                } | ConvertTo-Json)
            } else {
                Send-Response $context -body '{"authenticated":false}'
            }
            continue
        }

        # ── POST /api/auth/subscription ─────────────────────────────────────
        # Switches the active Az context subscription from the browser (no CLI).
        if ($path -eq "/api/auth/subscription" -and $req.HttpMethod -eq "POST") {
            $subId = ""
            try {
                $bodyStream = New-Object System.IO.StreamReader($req.InputStream)
                $bodyText   = $bodyStream.ReadToEnd()
                if ($bodyText) {
                    $bodyObj = $bodyText | ConvertFrom-Json
                    if (($bodyObj.PSObject.Properties.Name -contains 'subscriptionId') -and $bodyObj.subscriptionId) {
                        $subId = [string]$bodyObj.subscriptionId
                    }
                }
            } catch {}
            if (-not $subId) {
                Send-Response $context -status 400 -body '{"error":"subscriptionId is required."}'
                continue
            }
            try {
                $null = Set-AzContext -SubscriptionId $subId -WarningAction SilentlyContinue -ErrorAction Stop
                $ctx  = Get-AzContext
                $subName = ""; $sid = ""
                if ($ctx.Subscription) { $subName = "$($ctx.Subscription.Name)"; $sid = "$($ctx.Subscription.Id)" }
                Send-Response $context -body (@{
                    authenticated  = $true
                    account        = "$($ctx.Account.Id)"
                    tenant         = "$($ctx.Tenant.Id)"
                    subscription   = $subName
                    subscriptionId = $sid
                } | ConvertTo-Json)
            } catch {
                Write-Warning "Set subscription failed: $($_.Exception.Message)"
                Send-Response $context -status 500 -body '{"error":"Failed to switch subscription. See server console for details."}'
            }
            continue
        }

        # ── POST /api/auth/login ────────────────────────────────────────────
        # Launches an interactive Connect-AzAccount (opens the system browser).
        # Blocks this request until the user completes sign-in. Because autosave
        # is process-scoped, the resulting token cache lives only in memory.
        if ($path -eq "/api/auth/login" -and $req.HttpMethod -eq "POST") {
            try {
                $ctx = (Connect-AzAccount -ErrorAction Stop).Context
                $script:subscriptionCache = $null   # re-fetch subs for the new identity
                Send-Response $context -body (@{
                    authenticated = $true
                    account       = "$($ctx.Account.Id)"
                    tenant        = "$($ctx.Tenant.Id)"
                } | ConvertTo-Json)
            } catch {
                Write-Warning "Sign-in failed: $($_.Exception.Message)"
                Send-Response $context -status 500 -body '{"authenticated":false,"error":"Sign-in failed. See server console for details."}'
            }
            continue
        }

        # ── POST /api/auth/logout ───────────────────────────────────────────
        # Signs out, clears the in-memory context so no credentials remain, AND
        # shuts the dashboard down: signing out is the explicit "I'm done" action,
        # so we stop the listener after replying. The reply is sent first; stopping
        # the listener ends the GetContext loop and runs the finally cleanup.
        if ($path -eq "/api/auth/logout" -and $req.HttpMethod -eq "POST") {
            try { $null = Disconnect-AzAccount -ErrorAction SilentlyContinue } catch {}
            try { $null = Clear-AzContext -Force -ErrorAction SilentlyContinue } catch {}
            $script:subscriptionCache = $null
            Send-Response $context -body '{"authenticated":false,"stopped":true}'
            Write-Host "  Signed out from the dashboard — stopping server." -ForegroundColor Yellow
            $listener.Stop()
            continue
        }

        # ── GET /api/results ────────────────────────────────────────────────
        if ($path -eq "/api/results" -and $req.HttpMethod -eq "GET") {
            if (Test-Path $ResultsPath) {
                $json = Get-Content $ResultsPath -Raw -Encoding UTF8
                Send-Response $context -body $json
            } else {
                Send-Response $context -body '{"ScanMetadata":null,"ResourceGroups":[],"Errors":[]}'
            }
            continue
        }

        # ── GET /api/subscriptions ──────────────────────────────────────────
        # Lists enabled subscriptions so the dashboard can offer single-sub
        # selection BEFORE any scan has run. Cached for the server's lifetime.
        if ($path -eq "/api/subscriptions" -and $req.HttpMethod -eq "GET") {
            if (-not $script:subscriptionCache) {
                try {
                    $script:subscriptionCache = @(
                        Get-AzSubscription -ErrorAction Stop |
                        Where-Object { $_.State -eq "Enabled" } |
                        Sort-Object Name |
                        ForEach-Object { @{ Id = $_.Id; Name = $_.Name } }
                    )
                } catch {
                    Write-Warning "Failed to list subscriptions: $($_.Exception.Message)"
                    Send-Response $context -status 500 -body '{"error":"Failed to list subscriptions. See server console for details."}'
                    continue
                }
            }
            Send-Response $context -body (@{ subscriptions = $script:subscriptionCache } | ConvertTo-Json -Depth 5)
            continue
        }

        # ── GET /api/status ─────────────────────────────────────────────────
        if ($path -eq "/api/status" -and $req.HttpMethod -eq "GET") {
            # refresh job state
            if ($scanJob) {
                $jobState = $scanJob.State
                if ($jobState -eq "Completed") {
                    $output = Receive-Job $scanJob -Keep
                    $scanStatus.State   = "completed"
                    $scanStatus.Message = "Scan completed successfully."
                    Remove-Job $scanJob -Force
                    $scanJob = $null
                } elseif ($jobState -eq "Failed") {
                    $jobErrors = $scanJob.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason.Message } | Where-Object { $_ }
                    $err = if ($jobErrors) { $jobErrors -join "; " } else { Receive-Job $scanJob -Keep 2>&1 | Out-String }
                    $scanStatus.State   = "failed"
                    $scanStatus.Message = $err.Trim()
                    Remove-Job $scanJob -Force
                    $scanJob = $null
                } elseif ($jobState -eq "Running") {
                    $scanStatus.State   = "running"
                    $scanStatus.Message = "Scan in progress..."
                }
            }

            # Merge live progress from the scan's progress file, if present.
            $statusOut = @{} + $scanStatus
            if (Test-Path $ProgressPath) {
                try {
                    $prog = Get-Content $ProgressPath -Raw -Encoding UTF8 | ConvertFrom-Json
                    $statusOut.Progress = $prog
                } catch { <# progress file mid-write; skip this tick #> }
            }
            Send-Response $context -body ($statusOut | ConvertTo-Json -Depth 6)
            continue
        }

        # ── POST /api/scan ──────────────────────────────────────────────────
        if ($path -eq "/api/scan" -and $req.HttpMethod -eq "POST") {
            if ($scanJob -and $scanJob.State -eq "Running") {
                Send-Response $context -status 409 -body '{"error":"Scan already running."}'
                continue
            }
            if ($scanJob) { Remove-Job $scanJob -Force; $scanJob = $null }

            # Parse optional body: { "singleSubscriptionId": "...", "lookbackDays": 14 }
            # NOTE: Set-StrictMode throws on missing-property access, so we must check
            # property existence explicitly rather than relying on $null short-circuit.
            $singleSubId  = ""
            $effectiveDays = $LookbackDays
            try {
                $bodyStream = New-Object System.IO.StreamReader($req.InputStream)
                $bodyText   = $bodyStream.ReadToEnd()
                if ($bodyText) {
                    $bodyObj = $bodyText | ConvertFrom-Json
                    $props   = $bodyObj.PSObject.Properties.Name
                    if ($props -contains 'singleSubscriptionId' -and $bodyObj.singleSubscriptionId) {
                        $singleSubId = [string]$bodyObj.singleSubscriptionId
                    }
                    if ($props -contains 'lookbackDays' -and $bodyObj.lookbackDays) {
                        $effectiveDays = [int]$bodyObj.lookbackDays
                    }
                }
            } catch {
                Write-Warning "Failed to parse /api/scan body: $($_.Exception.Message)"
            }

            $modeLabel = if ($singleSubId) { "single sub: $singleSubId" } else { "all subscriptions" }
            $scanStatus = @{ State = "running"; StartedAt = (Get-Date -Format "o"); Message = "Scan started ($modeLabel, ${effectiveDays}d window)." }

            # Clear any stale progress from a previous run so the bar starts at 0.
            if (Test-Path $ProgressPath) { Remove-Item $ProgressPath -Force -ErrorAction SilentlyContinue }

            # Start-ThreadJob runs in-process: inherits loaded Az modules + live context.
            $scanJob = Start-ThreadJob -ScriptBlock {
                param($script, $output, $progress, $days, $subId, $throttle)
                if ($subId) {
                    & $script -OutputPath $output -ProgressPath $progress -LookbackDays $days -ThrottleLimit $throttle -SingleSubscriptionId $subId
                } else {
                    & $script -OutputPath $output -ProgressPath $progress -LookbackDays $days -ThrottleLimit $throttle
                }
            } -ArgumentList $ScanScript, $ResultsPath, $ProgressPath, $effectiveDays, $singleSubId, $ThrottleLimit

            Send-Response $context -body ($scanStatus | ConvertTo-Json)
            continue
        }

        # ── POST /api/scan/cancel ───────────────────────────────────────────
        # Stops the in-flight ThreadJob. The scan script's partial output (if any)
        # is left as-is; the dashboard simply reports the scan as cancelled.
        if ($path -eq "/api/scan/cancel" -and $req.HttpMethod -eq "POST") {
            if ($scanJob -and $scanJob.State -eq "Running") {
                Stop-Job $scanJob -ErrorAction SilentlyContinue
                Remove-Job $scanJob -Force -ErrorAction SilentlyContinue
                $scanJob    = $null
                $scanStatus = @{ State = "cancelled"; StartedAt = $null; Message = "Scan cancelled by user." }
                # Clear stale progress so the next scan starts clean.
                if (Test-Path $ProgressPath) { Remove-Item $ProgressPath -Force -ErrorAction SilentlyContinue }
                Send-Response $context -body ($scanStatus | ConvertTo-Json)
            } else {
                Send-Response $context -status 409 -body '{"error":"No scan is currently running."}'
            }
            continue
        }

        # ══ Privileged Access Scanner endpoints ═════════════════════════════

        # ── GET /api/pa/results ─────────────────────────────────────────────
        if ($path -eq "/api/pa/results" -and $req.HttpMethod -eq "GET") {
            if (Test-Path $PaResultsPath) {
                $json = Get-Content $PaResultsPath -Raw -Encoding UTF8
                Send-Response $context -body $json
            } else {
                Send-Response $context -body '{"ScanMetadata":null,"Assignments":[],"Errors":[]}'
            }
            continue
        }

        # ── GET /api/pa/status ──────────────────────────────────────────────
        if ($path -eq "/api/pa/status" -and $req.HttpMethod -eq "GET") {
            if ($paScanJob) {
                $jobState = $paScanJob.State
                if ($jobState -eq "Completed") {
                    $null = Receive-Job $paScanJob -Keep
                    $paScanStatus.State   = "completed"
                    $paScanStatus.Message = "Scan completed successfully."
                    Remove-Job $paScanJob -Force
                    $paScanJob = $null
                } elseif ($jobState -eq "Failed") {
                    $jobErrors = $paScanJob.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason.Message } | Where-Object { $_ }
                    $err = if ($jobErrors) { $jobErrors -join "; " } else { Receive-Job $paScanJob -Keep 2>&1 | Out-String }
                    $paScanStatus.State   = "failed"
                    $paScanStatus.Message = $err.Trim()
                    Remove-Job $paScanJob -Force
                    $paScanJob = $null
                } elseif ($jobState -eq "Running") {
                    $paScanStatus.State   = "running"
                    $paScanStatus.Message = "Scan in progress..."
                }
            }
            $statusOut = @{} + $paScanStatus
            if (Test-Path $PaProgressPath) {
                try {
                    $prog = Get-Content $PaProgressPath -Raw -Encoding UTF8 | ConvertFrom-Json
                    $statusOut.Progress = $prog
                } catch { <# progress file mid-write; skip this tick #> }
            }
            Send-Response $context -body ($statusOut | ConvertTo-Json -Depth 6)
            continue
        }

        # ── POST /api/pa/scan ───────────────────────────────────────────────
        # Body: { "singleSubscriptionId": "...", "privilegedRoles": ["Owner", ...] }
        if ($path -eq "/api/pa/scan" -and $req.HttpMethod -eq "POST") {
            if ($paScanJob -and $paScanJob.State -eq "Running") {
                Send-Response $context -status 409 -body '{"error":"Scan already running."}'
                continue
            }
            if ($paScanJob) { Remove-Job $paScanJob -Force; $paScanJob = $null }

            $singleSubId = ""
            $roles = @('Owner','Contributor','User Access Administrator','Role Based Access Control Administrator')
            try {
                $bodyStream = New-Object System.IO.StreamReader($req.InputStream)
                $bodyText   = $bodyStream.ReadToEnd()
                if ($bodyText) {
                    $bodyObj = $bodyText | ConvertFrom-Json
                    $props   = $bodyObj.PSObject.Properties.Name
                    if ($props -contains 'singleSubscriptionId' -and $bodyObj.singleSubscriptionId) {
                        $singleSubId = [string]$bodyObj.singleSubscriptionId
                    }
                    if ($props -contains 'privilegedRoles' -and $bodyObj.privilegedRoles) {
                        $roles = @($bodyObj.privilegedRoles)
                    }
                }
            } catch {
                Write-Warning "Failed to parse /api/pa/scan body: $($_.Exception.Message)"
            }

            $modeLabel  = if ($singleSubId) { "single sub: $singleSubId" } else { "all subscriptions + MGs" }
            $paScanStatus = @{ State = "running"; StartedAt = (Get-Date -Format "o"); Message = "Scan started ($modeLabel)." }

            if (Test-Path $PaProgressPath) { Remove-Item $PaProgressPath -Force -ErrorAction SilentlyContinue }

            $paScanJob = Start-ThreadJob -ScriptBlock {
                param($script, $output, $progress, $subId, $roles, $throttle)
                if ($subId) {
                    & $script -OutputPath $output -ProgressPath $progress -PrivilegedRoles $roles -ThrottleLimit $throttle -SingleSubscriptionId $subId
                } else {
                    & $script -OutputPath $output -ProgressPath $progress -PrivilegedRoles $roles -ThrottleLimit $throttle
                }
            } -ArgumentList $PaScanScript, $PaResultsPath, $PaProgressPath, $singleSubId, $roles, $ThrottleLimit

            Send-Response $context -body ($paScanStatus | ConvertTo-Json)
            continue
        }

        # ── POST /api/pa/scan/cancel ────────────────────────────────────────
        if ($path -eq "/api/pa/scan/cancel" -and $req.HttpMethod -eq "POST") {
            if ($paScanJob -and $paScanJob.State -eq "Running") {
                Stop-Job $paScanJob -ErrorAction SilentlyContinue
                Remove-Job $paScanJob -Force -ErrorAction SilentlyContinue
                $paScanJob    = $null
                $paScanStatus = @{ State = "cancelled"; StartedAt = $null; Message = "Scan cancelled by user." }
                if (Test-Path $PaProgressPath) { Remove-Item $PaProgressPath -Force -ErrorAction SilentlyContinue }
                Send-Response $context -body ($paScanStatus | ConvertTo-Json)
            } else {
                Send-Response $context -status 409 -body '{"error":"No scan is currently running."}'
            }
            continue
        }

        # ══ Entra User Scanner endpoints ════════════════════════════════════

        # ── GET /api/entra/results ──────────────────────────────────────────
        if ($path -eq "/api/entra/results" -and $req.HttpMethod -eq "GET") {
            if (Test-Path $EntraResultsPath) {
                $json = Get-Content $EntraResultsPath -Raw -Encoding UTF8
                Send-Response $context -body $json
            } else {
                Send-Response $context -body '{"ScanMetadata":null,"Users":[],"Errors":[]}'
            }
            continue
        }

        # ── GET /api/entra/status ───────────────────────────────────────────
        if ($path -eq "/api/entra/status" -and $req.HttpMethod -eq "GET") {
            if ($entraScanJob) {
                $jobState = $entraScanJob.State
                if ($jobState -eq "Completed") {
                    $null = Receive-Job $entraScanJob -Keep
                    $entraScanStatus.State   = "completed"
                    $entraScanStatus.Message = "Scan completed successfully."
                    Remove-Job $entraScanJob -Force
                    $entraScanJob = $null
                } elseif ($jobState -eq "Failed") {
                    $jobErrors = $entraScanJob.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason.Message } | Where-Object { $_ }
                    $err = if ($jobErrors) { $jobErrors -join "; " } else { Receive-Job $entraScanJob -Keep 2>&1 | Out-String }
                    $entraScanStatus.State   = "failed"
                    $entraScanStatus.Message = $err.Trim()
                    Remove-Job $entraScanJob -Force
                    $entraScanJob = $null
                } elseif ($jobState -eq "Running") {
                    $entraScanStatus.State   = "running"
                    $entraScanStatus.Message = "Scan in progress..."
                }
            }
            $statusOut = @{} + $entraScanStatus
            if (Test-Path $EntraProgressPath) {
                try {
                    $prog = Get-Content $EntraProgressPath -Raw -Encoding UTF8 | ConvertFrom-Json
                    $statusOut.Progress = $prog
                } catch { <# progress file mid-write; skip this tick #> }
            }
            Send-Response $context -body ($statusOut | ConvertTo-Json -Depth 6)
            continue
        }

        # ── POST /api/entra/scan ────────────────────────────────────────────
        # Body: { "staleDays": 180, "passwordValidityDays": 90, "includeDisabled": true }
        if ($path -eq "/api/entra/scan" -and $req.HttpMethod -eq "POST") {
            if ($entraScanJob -and $entraScanJob.State -eq "Running") {
                Send-Response $context -status 409 -body '{"error":"Scan already running."}'
                continue
            }
            if ($entraScanJob) { Remove-Job $entraScanJob -Force; $entraScanJob = $null }

            $staleDays = 180; $pwDays = 90; $includeDisabled = $true
            try {
                $bodyStream = New-Object System.IO.StreamReader($req.InputStream)
                $bodyText   = $bodyStream.ReadToEnd()
                if ($bodyText) {
                    $bodyObj = $bodyText | ConvertFrom-Json
                    $props   = $bodyObj.PSObject.Properties.Name
                    if ($props -contains 'staleDays' -and $bodyObj.staleDays) { $staleDays = [int]$bodyObj.staleDays }
                    if ($props -contains 'passwordValidityDays' -and $bodyObj.passwordValidityDays) { $pwDays = [int]$bodyObj.passwordValidityDays }
                    if ($props -contains 'includeDisabled') { $includeDisabled = [bool]$bodyObj.includeDisabled }
                }
            } catch {
                Write-Warning "Failed to parse /api/entra/scan body: $($_.Exception.Message)"
            }

            $entraScanStatus = @{ State = "running"; StartedAt = (Get-Date -Format "o"); Message = "Scan started (stale ${staleDays}d, pw ${pwDays}d)." }
            if (Test-Path $EntraProgressPath) { Remove-Item $EntraProgressPath -Force -ErrorAction SilentlyContinue }

            $entraScanJob = Start-ThreadJob -ScriptBlock {
                param($script, $output, $progress, $stale, $pw, $incDisabled)
                & $script -OutputPath $output -ProgressPath $progress -StaleDays $stale -PasswordValidityDays $pw -IncludeDisabled $incDisabled
            } -ArgumentList $EntraScanScript, $EntraResultsPath, $EntraProgressPath, $staleDays, $pwDays, $includeDisabled

            Send-Response $context -body ($entraScanStatus | ConvertTo-Json)
            continue
        }

        # ── POST /api/entra/scan/cancel ─────────────────────────────────────
        if ($path -eq "/api/entra/scan/cancel" -and $req.HttpMethod -eq "POST") {
            if ($entraScanJob -and $entraScanJob.State -eq "Running") {
                Stop-Job $entraScanJob -ErrorAction SilentlyContinue
                Remove-Job $entraScanJob -Force -ErrorAction SilentlyContinue
                $entraScanJob    = $null
                $entraScanStatus = @{ State = "cancelled"; StartedAt = $null; Message = "Scan cancelled by user." }
                if (Test-Path $EntraProgressPath) { Remove-Item $EntraProgressPath -Force -ErrorAction SilentlyContinue }
                Send-Response $context -body ($entraScanStatus | ConvertTo-Json)
            } else {
                Send-Response $context -status 409 -body '{"error":"No scan is currently running."}'
            }
            continue
        }

        # ══ Tag Auditor endpoints ═══════════════════════════════════════════

        # ── GET /api/tags/results ───────────────────────────────────────────
        if ($path -eq "/api/tags/results" -and $req.HttpMethod -eq "GET") {
            if (Test-Path $TagResultsPath) {
                $json = Get-Content $TagResultsPath -Raw -Encoding UTF8
                Send-Response $context -body $json
            } else {
                Send-Response $context -body '{"ScanMetadata":null,"Objects":[],"Errors":[]}'
            }
            continue
        }

        # ── GET /api/tags/managementgroups ──────────────────────────────────
        # Lists the tenant's management groups so the Tag Compliance page can offer
        # a scan scope. Returns Name (the MG id passed to Search-AzGraph) +
        # DisplayName. Cached for the server's lifetime; empty list is non-fatal
        # (the page falls back to whole-tenant).
        if ($path -eq "/api/tags/managementgroups" -and $req.HttpMethod -eq "GET") {
            if ($null -eq $script:mgCache) {
                try {
                    $script:mgCache = @(
                        Get-AzManagementGroup -ErrorAction Stop |
                        Sort-Object DisplayName |
                        ForEach-Object { @{ Name = $_.Name; DisplayName = $_.DisplayName } }
                    )
                } catch {
                    Write-Warning "Failed to list management groups: $($_.Exception.Message)"
                    $script:mgCache = @()   # cache the empty result; page degrades to whole-tenant
                }
            }
            Send-Response $context -body (@{ managementGroups = $script:mgCache } | ConvertTo-Json -Depth 5)
            continue
        }

        # ── GET /api/tags/status ────────────────────────────────────────────
        if ($path -eq "/api/tags/status" -and $req.HttpMethod -eq "GET") {
            if ($tagScanJob) {
                $jobState = $tagScanJob.State
                if ($jobState -eq "Completed") {
                    $null = Receive-Job $tagScanJob -Keep
                    $tagScanStatus.State   = "completed"
                    $tagScanStatus.Message = "Scan completed successfully."
                    Remove-Job $tagScanJob -Force
                    $tagScanJob = $null
                } elseif ($jobState -eq "Failed") {
                    $jobErrors = $tagScanJob.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason.Message } | Where-Object { $_ }
                    $err = if ($jobErrors) { $jobErrors -join "; " } else { Receive-Job $tagScanJob -Keep 2>&1 | Out-String }
                    $tagScanStatus.State   = "failed"
                    $tagScanStatus.Message = $err.Trim()
                    Remove-Job $tagScanJob -Force
                    $tagScanJob = $null
                } elseif ($jobState -eq "Running") {
                    $tagScanStatus.State   = "running"
                    $tagScanStatus.Message = "Scan in progress..."
                }
            }
            $statusOut = @{} + $tagScanStatus
            if (Test-Path $TagProgressPath) {
                try {
                    $prog = Get-Content $TagProgressPath -Raw -Encoding UTF8 | ConvertFrom-Json
                    $statusOut.Progress = $prog
                } catch { <# progress file mid-write; skip this tick #> }
            }
            Send-Response $context -body ($statusOut | ConvertTo-Json -Depth 6)
            continue
        }

        # ── POST /api/tags/scan ─────────────────────────────────────────────
        # Body: { "requiredTags": ["Environment", ...], "allowedValues": { "Environment": ["Prod","Dev"] },
        #         "singleSubscriptionId": "...", "managementGroupId": "...", "mode": "Exclusive"|"Inclusive" }
        if ($path -eq "/api/tags/scan" -and $req.HttpMethod -eq "POST") {
            if ($tagScanJob -and $tagScanJob.State -eq "Running") {
                Send-Response $context -status 409 -body '{"error":"Scan already running."}'
                continue
            }
            if ($tagScanJob) { Remove-Job $tagScanJob -Force; $tagScanJob = $null }

            $requiredTags = @()
            $allowedValues = $null
            $singleSubId = ""
            $mgId = ""
            $mode = "Exclusive"
            try {
                $bodyStream = New-Object System.IO.StreamReader($req.InputStream)
                $bodyText   = $bodyStream.ReadToEnd()
                if ($bodyText) {
                    $bodyObj = $bodyText | ConvertFrom-Json
                    $props   = $bodyObj.PSObject.Properties.Name
                    if ($props -contains 'requiredTags' -and $bodyObj.requiredTags) {
                        $requiredTags = @($bodyObj.requiredTags)
                    }
                    if ($props -contains 'allowedValues' -and $bodyObj.allowedValues) {
                        $allowedValues = $bodyObj.allowedValues
                    }
                    if ($props -contains 'singleSubscriptionId' -and $bodyObj.singleSubscriptionId) {
                        $singleSubId = [string]$bodyObj.singleSubscriptionId
                    }
                    if ($props -contains 'managementGroupId' -and $bodyObj.managementGroupId) {
                        $mgId = [string]$bodyObj.managementGroupId
                    }
                    if ($props -contains 'mode' -and $bodyObj.mode -eq 'Inclusive') {
                        $mode = "Inclusive"
                    }
                }
            } catch {
                Write-Warning "Failed to parse /api/tags/scan body: $($_.Exception.Message)"
            }

            if (-not $requiredTags -or @($requiredTags).Count -eq 0) {
                Send-Response $context -status 400 -body '{"error":"At least one required tag key is needed."}'
                continue
            }

            $scopeLabel = if ($mgId) { "mgmt group: $mgId" } elseif ($singleSubId) { "single sub: $singleSubId" } else { "all subscriptions" }
            $tagScanStatus = @{ State = "running"; StartedAt = (Get-Date -Format "o"); Message = "Scan started ($scopeLabel, $mode, $(@($requiredTags).Count) required tag(s))." }
            if (Test-Path $TagProgressPath) { Remove-Item $TagProgressPath -Force -ErrorAction SilentlyContinue }

            $tagScanJob = Start-ThreadJob -ScriptBlock {
                param($script, $output, $progress, $required, $allowed, $subId, $mgId, $mode)
                $p = @{ OutputPath = $output; ProgressPath = $progress; RequiredTags = $required; AllowedTagValues = $allowed; Mode = $mode }
                if ($mgId)  { $p['ManagementGroupId'] = $mgId }
                if ($subId) { $p['SingleSubscriptionId'] = $subId }
                & $script @p
            } -ArgumentList $TagScanScript, $TagResultsPath, $TagProgressPath, $requiredTags, $allowedValues, $singleSubId, $mgId, $mode

            Send-Response $context -body ($tagScanStatus | ConvertTo-Json)
            continue
        }

        # ── POST /api/tags/scan/cancel ──────────────────────────────────────
        if ($path -eq "/api/tags/scan/cancel" -and $req.HttpMethod -eq "POST") {
            if ($tagScanJob -and $tagScanJob.State -eq "Running") {
                Stop-Job $tagScanJob -ErrorAction SilentlyContinue
                Remove-Job $tagScanJob -Force -ErrorAction SilentlyContinue
                $tagScanJob    = $null
                $tagScanStatus = @{ State = "cancelled"; StartedAt = $null; Message = "Scan cancelled by user." }
                if (Test-Path $TagProgressPath) { Remove-Item $TagProgressPath -Force -ErrorAction SilentlyContinue }
                Send-Response $context -body ($tagScanStatus | ConvertTo-Json)
            } else {
                Send-Response $context -status 409 -body '{"error":"No scan is currently running."}'
            }
            continue
        }

        # ══ Log Analytics Cost Projector endpoints ═════════════════════════

        # ── GET /api/la/workspaces?subscriptionId=... ───────────────────────
        # Lists every Log Analytics workspace in a subscription via Resource Graph so
        # the page can build cascading subscription → resource group → workspace
        # dropdowns BEFORE any scan. Returns Name, ResourceGroup, Location, CustomerId.
        if ($path -eq "/api/la/workspaces" -and $req.HttpMethod -eq "GET") {
            $subId = "$($req.QueryString["subscriptionId"])"
            if (-not $subId) {
                Send-Response $context -status 400 -body '{"error":"subscriptionId query parameter is required."}'
                continue
            }
            try {
                $kql = "Resources | where type =~ 'microsoft.operationalinsights/workspaces' | project name, resourceGroup, location, customerId = tostring(properties.customerId), id | order by resourceGroup asc, name asc"
                $rows = @(Search-AzGraph -Query $kql -Subscription $subId -First 1000 -ErrorAction Stop)
                $workspaces = @($rows | ForEach-Object {
                    @{ Name = "$($_.name)"; ResourceGroup = "$($_.resourceGroup)"; Location = "$($_.location)"; CustomerId = "$($_.customerId)"; Id = "$($_.id)" }
                })
                Send-Response $context -body (@{ workspaces = $workspaces } | ConvertTo-Json -Depth 5)
            } catch {
                Write-Warning "Failed to list Log Analytics workspaces: $($_.Exception.Message)"
                Send-Response $context -status 500 -body '{"error":"Failed to list workspaces. See server console for details."}'
            }
            continue
        }

        # ── GET /api/la/results ─────────────────────────────────────────────
        if ($path -eq "/api/la/results" -and $req.HttpMethod -eq "GET") {
            if (Test-Path $LaResultsPath) {
                $json = Get-Content $LaResultsPath -Raw -Encoding UTF8
                Send-Response $context -body $json
            } else {
                Send-Response $context -body '{"ScanMetadata":null,"Tables":[],"Errors":[]}'
            }
            continue
        }

        # ── GET /api/la/status ──────────────────────────────────────────────
        if ($path -eq "/api/la/status" -and $req.HttpMethod -eq "GET") {
            if ($laScanJob) {
                $jobState = $laScanJob.State
                if ($jobState -eq "Completed") {
                    $null = Receive-Job $laScanJob -Keep
                    $laScanStatus.State   = "completed"
                    $laScanStatus.Message = "Scan completed successfully."
                    Remove-Job $laScanJob -Force
                    $laScanJob = $null
                } elseif ($jobState -eq "Failed") {
                    $jobErrors = $laScanJob.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason.Message } | Where-Object { $_ }
                    $err = if ($jobErrors) { $jobErrors -join "; " } else { Receive-Job $laScanJob -Keep 2>&1 | Out-String }
                    $laScanStatus.State   = "failed"
                    $laScanStatus.Message = $err.Trim()
                    Remove-Job $laScanJob -Force
                    $laScanJob = $null
                } elseif ($jobState -eq "Running") {
                    $laScanStatus.State   = "running"
                    $laScanStatus.Message = "Scan in progress..."
                }
            }
            $statusOut = @{} + $laScanStatus
            if (Test-Path $LaProgressPath) {
                try {
                    $prog = Get-Content $LaProgressPath -Raw -Encoding UTF8 | ConvertFrom-Json
                    $statusOut.Progress = $prog
                } catch { <# progress file mid-write; skip this tick #> }
            }
            Send-Response $context -body ($statusOut | ConvertTo-Json -Depth 6)
            continue
        }

        # ── POST /api/la/scan ───────────────────────────────────────────────
        # Body: { "subscriptionId": "...", "resourceGroup": "...", "workspaceName": "...",
        #         "workspaceId": "<customerId GUID>", "lookbackDays": 31 }
        if ($path -eq "/api/la/scan" -and $req.HttpMethod -eq "POST") {
            if ($laScanJob -and $laScanJob.State -eq "Running") {
                Send-Response $context -status 409 -body '{"error":"Scan already running."}'
                continue
            }
            if ($laScanJob) { Remove-Job $laScanJob -Force; $laScanJob = $null }

            $subId = ""; $rg = ""; $wsName = ""; $wsId = ""; $lookback = 31
            try {
                $bodyStream = New-Object System.IO.StreamReader($req.InputStream)
                $bodyText   = $bodyStream.ReadToEnd()
                if ($bodyText) {
                    $bodyObj = $bodyText | ConvertFrom-Json
                    $props   = $bodyObj.PSObject.Properties.Name
                    if ($props -contains 'subscriptionId' -and $bodyObj.subscriptionId) { $subId  = [string]$bodyObj.subscriptionId }
                    if ($props -contains 'resourceGroup'  -and $bodyObj.resourceGroup)  { $rg     = [string]$bodyObj.resourceGroup }
                    if ($props -contains 'workspaceName'   -and $bodyObj.workspaceName)  { $wsName = [string]$bodyObj.workspaceName }
                    if ($props -contains 'workspaceId'     -and $bodyObj.workspaceId)    { $wsId   = [string]$bodyObj.workspaceId }
                    if ($props -contains 'lookbackDays'    -and $bodyObj.lookbackDays)   { $lookback = [int]$bodyObj.lookbackDays }
                }
            } catch {
                Write-Warning "Failed to parse /api/la/scan body: $($_.Exception.Message)"
            }

            if (-not $subId -or -not $rg -or -not $wsName) {
                Send-Response $context -status 400 -body '{"error":"subscriptionId, resourceGroup and workspaceName are required."}'
                continue
            }

            $laScanStatus = @{ State = "running"; StartedAt = (Get-Date -Format "o"); Message = "Projecting cost for workspace '$wsName'." }
            if (Test-Path $LaProgressPath) { Remove-Item $LaProgressPath -Force -ErrorAction SilentlyContinue }

            $laScanJob = Start-ThreadJob -ScriptBlock {
                param($script, $output, $progress, $subId, $rg, $wsName, $wsId, $lookback)
                $p = @{ OutputPath = $output; ProgressPath = $progress; SubscriptionId = $subId; ResourceGroup = $rg; WorkspaceName = $wsName; LookbackDays = $lookback }
                if ($wsId) { $p['WorkspaceId'] = $wsId }
                & $script @p
            } -ArgumentList $LaScanScript, $LaResultsPath, $LaProgressPath, $subId, $rg, $wsName, $wsId, $lookback

            Send-Response $context -body ($laScanStatus | ConvertTo-Json)
            continue
        }

        # ── POST /api/la/scan/cancel ────────────────────────────────────────
        if ($path -eq "/api/la/scan/cancel" -and $req.HttpMethod -eq "POST") {
            if ($laScanJob -and $laScanJob.State -eq "Running") {
                Stop-Job $laScanJob -ErrorAction SilentlyContinue
                Remove-Job $laScanJob -Force -ErrorAction SilentlyContinue
                $laScanJob    = $null
                $laScanStatus = @{ State = "cancelled"; StartedAt = $null; Message = "Scan cancelled by user." }
                if (Test-Path $LaProgressPath) { Remove-Item $LaProgressPath -Force -ErrorAction SilentlyContinue }
                Send-Response $context -body ($laScanStatus | ConvertTo-Json)
            } else {
                Send-Response $context -status 409 -body '{"error":"No scan is currently running."}'
            }
            continue
        }

        # ── GET /api/quota/results ──────────────────────────────────────────
        if ($path -eq "/api/quota/results" -and $req.HttpMethod -eq "GET") {
            if (Test-Path $QuotaResultsPath) {
                $json = Get-Content $QuotaResultsPath -Raw -Encoding UTF8
                Send-Response $context -body $json
            } else {
                Send-Response $context -body '{"ScanMetadata":null,"Quotas":[],"Errors":[]}'
            }
            continue
        }

        # ── GET /api/quota/status ───────────────────────────────────────────
        if ($path -eq "/api/quota/status" -and $req.HttpMethod -eq "GET") {
            if ($quotaScanJob) {
                $jobState = $quotaScanJob.State
                if ($jobState -eq "Completed") {
                    $null = Receive-Job $quotaScanJob -Keep
                    $quotaScanStatus.State   = "completed"
                    $quotaScanStatus.Message = "Scan completed successfully."
                    Remove-Job $quotaScanJob -Force
                    $quotaScanJob = $null
                } elseif ($jobState -eq "Failed") {
                    $jobErrors = $quotaScanJob.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason.Message } | Where-Object { $_ }
                    $err = if ($jobErrors) { $jobErrors -join "; " } else { Receive-Job $quotaScanJob -Keep 2>&1 | Out-String }
                    $quotaScanStatus.State   = "failed"
                    $quotaScanStatus.Message = $err.Trim()
                    Remove-Job $quotaScanJob -Force
                    $quotaScanJob = $null
                } elseif ($jobState -eq "Running") {
                    $quotaScanStatus.State   = "running"
                    $quotaScanStatus.Message = "Scan in progress..."
                }
            }
            $statusOut = @{} + $quotaScanStatus
            if (Test-Path $QuotaProgressPath) {
                try {
                    $prog = Get-Content $QuotaProgressPath -Raw -Encoding UTF8 | ConvertFrom-Json
                    $statusOut.Progress = $prog
                } catch { <# progress file mid-write; skip this tick #> }
            }
            Send-Response $context -body ($statusOut | ConvertTo-Json -Depth 6)
            continue
        }

        # ── POST /api/quota/scan ────────────────────────────────────────────
        # Body (all optional): { "singleSubscriptionId": "...", "criticalThreshold": 90, "warningThreshold": 75 }
        if ($path -eq "/api/quota/scan" -and $req.HttpMethod -eq "POST") {
            if ($quotaScanJob -and $quotaScanJob.State -eq "Running") {
                Send-Response $context -status 409 -body '{"error":"Scan already running."}'
                continue
            }
            if ($quotaScanJob) { Remove-Job $quotaScanJob -Force; $quotaScanJob = $null }

            $singleSub = ""; $critical = 90; $warning = 75
            try {
                $bodyStream = New-Object System.IO.StreamReader($req.InputStream)
                $bodyText   = $bodyStream.ReadToEnd()
                if ($bodyText) {
                    $bodyObj = $bodyText | ConvertFrom-Json
                    $props   = $bodyObj.PSObject.Properties.Name
                    if ($props -contains 'singleSubscriptionId' -and $bodyObj.singleSubscriptionId) { $singleSub = [string]$bodyObj.singleSubscriptionId }
                    if ($props -contains 'criticalThreshold'    -and $bodyObj.criticalThreshold)    { $critical  = [int]$bodyObj.criticalThreshold }
                    if ($props -contains 'warningThreshold'     -and $bodyObj.warningThreshold)     { $warning   = [int]$bodyObj.warningThreshold }
                }
            } catch {
                Write-Warning "Failed to parse /api/quota/scan body: $($_.Exception.Message)"
            }

            $quotaScanStatus = @{ State = "running"; StartedAt = (Get-Date -Format "o"); Message = "Scanning subscription quotas." }
            if (Test-Path $QuotaProgressPath) { Remove-Item $QuotaProgressPath -Force -ErrorAction SilentlyContinue }

            $quotaScanJob = Start-ThreadJob -ScriptBlock {
                param($script, $output, $progress, $singleSub, $critical, $warning)
                $p = @{ OutputPath = $output; ProgressPath = $progress; CriticalThreshold = $critical; WarningThreshold = $warning }
                if ($singleSub) { $p['SingleSubscriptionId'] = $singleSub }
                & $script @p
            } -ArgumentList $QuotaScanScript, $QuotaResultsPath, $QuotaProgressPath, $singleSub, $critical, $warning

            Send-Response $context -body ($quotaScanStatus | ConvertTo-Json)
            continue
        }

        # ── POST /api/quota/scan/cancel ─────────────────────────────────────
        if ($path -eq "/api/quota/scan/cancel" -and $req.HttpMethod -eq "POST") {
            if ($quotaScanJob -and $quotaScanJob.State -eq "Running") {
                Stop-Job $quotaScanJob -ErrorAction SilentlyContinue
                Remove-Job $quotaScanJob -Force -ErrorAction SilentlyContinue
                $quotaScanJob    = $null
                $quotaScanStatus = @{ State = "cancelled"; StartedAt = $null; Message = "Scan cancelled by user." }
                if (Test-Path $QuotaProgressPath) { Remove-Item $QuotaProgressPath -Force -ErrorAction SilentlyContinue }
                Send-Response $context -body ($quotaScanStatus | ConvertTo-Json)
            } else {
                Send-Response $context -status 409 -body '{"error":"No scan is currently running."}'
            }
            continue
        }

        # ── 404 ─────────────────────────────────────────────────────────────
        Send-Response $context -status 404 -body '{"error":"Not found"}'
    }
} finally {
    $listener.Stop()
    $listener.Close()
    if ($scanJob) { Remove-Job $scanJob -Force }
    if ($paScanJob) { Remove-Job $paScanJob -Force }
    if ($entraScanJob) { Remove-Job $entraScanJob -Force }
    if ($tagScanJob) { Remove-Job $tagScanJob -Force }
    if ($laScanJob) { Remove-Job $laScanJob -Force }
    if ($quotaScanJob) { Remove-Job $quotaScanJob -Force }
    Write-Host "Server stopped." -ForegroundColor Yellow
}
