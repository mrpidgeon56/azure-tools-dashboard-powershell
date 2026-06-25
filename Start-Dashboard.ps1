#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph, ThreadJob
<#
.SYNOPSIS
    Starts a local HTTP dashboard server for the Azure Idle Resource Group scanner.

    Authentication happens in the terminal BEFORE launch: run Connect-AzAccount, then
    start this script in the same PowerShell session. The Az context is inherited and
    held in process memory only, so no credentials are stored on disk. The dashboard
    reports the active session and lets you switch subscription; the header "Stop" button
    (POST /api/shutdown) shuts the server down without disconnecting your terminal session.

    Endpoints:
      GET  /                → serves home.html (hub)
      GET  /api/auth/status → reports whether an Az session is active
      POST /api/shutdown    → stops the server (Az context left intact)
      GET  /api/results     → returns last scan JSON (or empty state)
      POST /api/scan        → runs Invoke-AzureIdleScan.ps1 in background, streams status
      GET  /api/status      → returns current scan job status

.EXAMPLE
    Connect-AzAccount            # sign in once (opens your browser)
    .\Start-Dashboard.ps1        # then open http://localhost:8080
#>
[CmdletBinding()]
param(
    [int]    $Port         = 8080,
    # Loopback by default. Set to 127.0.0.1 for a specific IPv4 loopback, a hostname, or
    # '+'/'*' to expose beyond loopback (the latter needs a URL-ACL reservation on Windows /
    # root on Linux, and drops the loopback-only security posture — use with care).
    [string] $BindAddress  = "localhost",
    # Layout: scanners live in scanners/, runtime JSON in data/ (gitignored), pages in web/.
    [string] $ResultsPath  = "$PSScriptRoot/data/scan-results.json",
    [string] $ProgressPath = "$PSScriptRoot/data/scan-progress.json",
    [string] $ScanScript   = "$PSScriptRoot/scanners/Invoke-AzureIdleScan.ps1",
    [string] $PaResultsPath  = "$PSScriptRoot/data/pa-scan-results.json",
    [string] $PaProgressPath = "$PSScriptRoot/data/pa-scan-progress.json",
    [string] $PaScanScript   = "$PSScriptRoot/scanners/Invoke-PrivilegedAccessScan.ps1",
    [string] $EntraResultsPath  = "$PSScriptRoot/data/entra-scan-results.json",
    [string] $EntraProgressPath = "$PSScriptRoot/data/entra-scan-progress.json",
    [string] $EntraScanScript   = "$PSScriptRoot/scanners/Invoke-EntraUserScan.ps1",
    [string] $TagResultsPath  = "$PSScriptRoot/data/tag-scan-results.json",
    [string] $TagProgressPath = "$PSScriptRoot/data/tag-scan-progress.json",
    [string] $TagScanScript   = "$PSScriptRoot/scanners/Invoke-TagComplianceScan.ps1",
    [string] $LaResultsPath  = "$PSScriptRoot/data/la-cost-scan-results.json",
    [string] $LaProgressPath = "$PSScriptRoot/data/la-cost-scan-progress.json",
    [string] $LaScanScript   = "$PSScriptRoot/scanners/Invoke-LogAnalyticsCostScan.ps1",
    [string] $QuotaResultsPath  = "$PSScriptRoot/data/quota-scan-results.json",
    [string] $QuotaProgressPath = "$PSScriptRoot/data/quota-scan-progress.json",
    [string] $QuotaScanScript   = "$PSScriptRoot/scanners/Invoke-QuotaScan.ps1",
    [int]    $LookbackDays = 14,
    [int]    $ThrottleLimit = 8   # max resource groups scanned concurrently (1 = sequential)
)

Set-StrictMode -Version Latest

# ── Authentication (terminal-driven, no stored credentials) ──────────────────
# Sign in BEFORE launching: run Connect-AzAccount in this PowerShell session, then
# start this script in the same session so it inherits the live context.
#
# Enable-AzContextAutosave -Scope Process keeps the context (and MSAL token cache)
# in PROCESS MEMORY only — it is never written to the on-disk Az token cache, so no
# credentials persist between server runs. It also lets the in-process ThreadJob
# scans share the live context. Stopping the server discards it.
$null = Enable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue

$azContext = $null
try { $azContext = Get-AzContext -ErrorAction Stop } catch { $azContext = $null }
if ($azContext -and $azContext.Account) {
    Write-Host "  Existing in-memory Azure session: $($azContext.Account.Id)" -ForegroundColor Gray
} else {
    Write-Host "  Not signed in — stop the server (Ctrl+C), run Connect-AzAccount, then re-run ./Start-Dashboard.ps1." -ForegroundColor Yellow
}

# ── Ensure ThreadJob is available ────────────────────────────────────────────
# We run scans with Start-ThreadJob (NOT Start-Job). ThreadJob runs in-process,
# so the scan inherits the already-loaded Az modules AND the live Az context —
# no Save/Import-AzContext, no token-expiry or MSAL-cache problems in a child process.
if (-not (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)) {
    Write-Error "The ThreadJob module is required. Install it with: Install-Module ThreadJob -Scope CurrentUser"
    exit 1
}

# Ensure the runtime-artifact directory exists (it's gitignored, so a fresh clone may lack it).
$null = New-Item -ItemType Directory -Path "$PSScriptRoot/data" -Force -ErrorAction SilentlyContinue

$listener   = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://${BindAddress}:$Port/")
$listener.Start()

Write-Host ""
Write-Host "  Azure Idle RG Dashboard" -ForegroundColor Cyan
Write-Host "  Running at http://${BindAddress}:$Port" -ForegroundColor Green
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
$script:mgCache           = $null   # management groups (tenant-wide); cached for the server's lifetime
$script:rgCache           = @{}     # resource groups per subscription id; lazily filled
$script:fileCache         = @{}     # path → @{ Mtime; Bytes } so unchanged pages/results aren't re-read from disk

# ── Ported-tool registry ─────────────────────────────────────────────────────
# Tools ported from the Python app share an identical API shape, so instead of a
# copy-pasted endpoint quartet each they're one entry here, served by the generic
# dispatcher below. Scope: 'graph' = MG/Sub/RG, 'subscription' = MG/Sub (no RG),
# 'none' = tenant-wide (no scope params). Results/progress paths + the page route
# are derived from the slug; every ported scanner emits { ScanMetadata, Items, Errors }.
$script:portedTools = @(
    @{ Prefix = 'storage';       Slug = 'storage-posture';        Scanner = 'Invoke-StoragePostureScan.ps1';      Scope = 'graph' }
    @{ Prefix = 'attacksurface'; Slug = 'attack-surface';         Scanner = 'Invoke-AttackSurfaceScan.ps1';       Scope = 'graph' }
    @{ Prefix = 'nsgrisk';       Slug = 'nsg-risk-map';           Scanner = 'Invoke-NsgRiskScan.ps1';             Scope = 'graph' }
    @{ Prefix = 'certexpiry';    Slug = 'cert-expiry';            Scanner = 'Invoke-CertExpiryScan.ps1';          Scope = 'graph' }
    @{ Prefix = 'defender';      Slug = 'defender-secure-score';  Scanner = 'Invoke-DefenderSecureScoreScan.ps1'; Scope = 'subscription' }
    @{ Prefix = 'appcreds';      Slug = 'app-credential-expiry';  Scanner = 'Invoke-AppCredentialExpiryScan.ps1'; Scope = 'none' }
    @{ Prefix = 'policycompliance'; Slug = 'policy-compliance';   Scanner = 'Invoke-PolicyComplianceScan.ps1';    Scope = 'subscription' }
    @{ Prefix = 'exemptions';    Slug = 'exemption-tracker';      Scanner = 'Invoke-ExemptionTrackerScan.ps1';    Scope = 'subscription' }
    @{ Prefix = 'deployments';   Slug = 'deployment-tracker';     Scanner = 'Invoke-DeploymentTrackerScan.ps1';   Scope = 'subscription' }
    @{ Prefix = 'backup';        Slug = 'backup-coverage';        Scanner = 'Invoke-BackupCoverageScan.ps1';      Scope = 'graph' }
    @{ Prefix = 'resilience';    Slug = 'resilience-audit';       Scanner = 'Invoke-ResilienceAuditScan.ps1';     Scope = 'graph' }
    @{ Prefix = 'resourcehealth';Slug = 'resource-health';        Scanner = 'Invoke-ResourceHealthScan.ps1';      Scope = 'graph' }
    @{ Prefix = 'monitoring';    Slug = 'monitoring-gaps';        Scanner = 'Invoke-MonitoringGapsScan.ps1';      Scope = 'graph' }
    @{ Prefix = 'storagesas';    Slug = 'storage-sas-keys';       Scanner = 'Invoke-StorageSasKeysScan.ps1';      Scope = 'graph' }
    @{ Prefix = 'reservations';  Slug = 'reservation-coverage';   Scanner = 'Invoke-ReservationCoverageScan.ps1'; Scope = 'subscription' }
    @{ Prefix = 'networktopology'; Slug = 'network-topology';     Scanner = 'Invoke-NetworkTopologyScan.ps1';     Scope = 'graph' }
    @{ Prefix = 'vnetflowcoverage'; Slug = 'vnet-flow-coverage';  Scanner = 'Invoke-VnetFlowCoverageScan.ps1';    Scope = 'graph' }
    @{ Prefix = 'costanomaly';   Slug = 'cost-anomaly';           Scanner = 'Invoke-CostAnomalyScan.ps1';         Scope = 'subscription'
       Extra = @( @{ Body = 'windowDays'; Param = 'WindowDays'; Int = $true } ) }
    @{ Prefix = 'vnetflowlogs';  Slug = 'vnet-flow-logs';         Scanner = 'Invoke-VnetFlowLogsScan.ps1';        Scope = 'params'
       Extra = @(
           @{ Body = 'flowLogId';     Param = 'FlowLogId' }
           @{ Body = 'storageAccount';Param = 'StorageAccount' }
           @{ Body = 'flowLogName';   Param = 'FlowLogName' }
           @{ Body = 'vnetName';      Param = 'VnetName' }
           @{ Body = 'pathPrefix';    Param = 'PathPrefix' }
           @{ Body = 'lookbackHours'; Param = 'LookbackHours'; Int = $true }
           @{ Body = 'maxBlobs';      Param = 'MaxBlobs';      Int = $true }
           @{ Body = 'container';     Param = 'Container' }
       ) }
)
$script:toolByPrefix = @{}
$script:toolJobs     = @{}   # prefix → @{ Job; Status }
foreach ($t in $script:portedTools) {
    $t.ResultsPath  = "$PSScriptRoot/data/$($t.Slug)-scan-results.json"
    $t.ProgressPath = "$PSScriptRoot/data/$($t.Slug)-scan-progress.json"
    $t.ScanScript   = "$PSScriptRoot/scanners/$($t.Scanner)"
    $script:toolByPrefix[$t.Prefix] = $t
    $script:toolJobs[$t.Prefix]     = @{ Job = $null; Status = @{ State = "idle"; StartedAt = $null; Message = "No scan run yet." } }
}

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
    param($context, [int]$status = 200, [string]$body = "", [byte[]]$bytes = $null,
          [string]$contentType = "application/json; charset=utf-8", [string]$etag = $null)
    $resp = $context.Response
    $resp.StatusCode  = $status
    $resp.ContentType = $contentType
    # NOTE: deliberately NO "Access-Control-Allow-Origin" header. The dashboard is
    # served from this same origin, so it never needs CORS. Omitting it means the
    # browser's same-origin policy blocks any *other* website from reading our API
    # responses (which contain sensitive tenant data: user lists, role assignments).
    $resp.Headers.Add("X-Content-Type-Options", "nosniff")
    if ($etag) { $resp.Headers.Add("ETag", $etag) }
    if ($null -eq $bytes) { $bytes = [System.Text.Encoding]::UTF8.GetBytes($body) }
    # Transparently gzip larger payloads when the client advertises it — the results JSON
    # is multi-MB and compresses ~5-10x. Tiny responses (status polls) skip it.
    $accept = $context.Request.Headers["Accept-Encoding"]
    if ($bytes.Length -gt 1400 -and $accept -and $accept -match 'gzip') {
        $resp.Headers.Add("Content-Encoding", "gzip")
        $ms = [System.IO.MemoryStream]::new()
        $gz = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionLevel]::Fastest)
        $gz.Write($bytes, 0, $bytes.Length); $gz.Dispose()
        $bytes = $ms.ToArray(); $ms.Dispose()
    }
    $resp.ContentLength64 = $bytes.Length
    $resp.OutputStream.Write($bytes, 0, $bytes.Length)
    $resp.OutputStream.Close()
}

# Serve a file (page or results JSON) with an in-memory cache + conditional GET.
# A weak ETag derived from the file's last-write time + size lets browsers and the
# tools' own re-polls skip the transfer entirely (304) when nothing changed; on a
# miss the bytes are read once and cached until the file's mtime changes (so a new
# scan result or an edited page is picked up automatically).
function Send-CachedFile {
    param($context, [string]$path, [string]$emptyBody = "{}", [string]$contentType = "application/json; charset=utf-8")
    if (-not (Test-Path $path)) { Send-Response $context -body $emptyBody -contentType $contentType; return }
    $fi   = Get-Item $path
    $etag = '"{0:x}-{1:x}"' -f $fi.LastWriteTimeUtc.Ticks, $fi.Length
    $inm  = $context.Request.Headers["If-None-Match"]
    if ($inm -and $inm -eq $etag) {
        $context.Response.StatusCode = 304
        $context.Response.Headers.Add("ETag", $etag)
        $context.Response.OutputStream.Close()
        return
    }
    $entry = $script:fileCache[$path]
    if ($entry -and $entry.Mtime -eq $fi.LastWriteTimeUtc.Ticks) {
        $bytes = $entry.Bytes
    } else {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $script:fileCache[$path] = @{ Mtime = $fi.LastWriteTimeUtc.Ticks; Bytes = $bytes }
    }
    Send-Response $context -bytes $bytes -contentType $contentType -etag $etag
}

# ── Request-origin guards (CSRF + DNS-rebinding) ─────────────────────────────
# The server only ever binds to localhost, but a malicious web page open in the
# same browser could still try to drive our API (CSRF) or reach us via a hostname
# that resolves to 127.0.0.1 (DNS rebinding). We defend with two checks:
#   1. Host header must be exactly our localhost binding.
#   2. State-changing requests (POST) must carry a same-origin Origin/Referer.
$script:allowedHosts   = @("localhost:$Port", "127.0.0.1:$Port", "${BindAddress}:$Port") | Select-Object -Unique
$script:allowedOrigins = @("http://localhost:$Port", "http://127.0.0.1:$Port", "http://${BindAddress}:$Port") | Select-Object -Unique

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
      # Per-request guard: a single malformed request or a client that disconnects
      # mid-response (which disposes HttpListenerResponse) must NOT crash the accept
      # loop. Any handler error is logged and the loop moves on. (Body kept at its
      # original indentation to keep the diff readable.)
      try {
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
        # Ported tools get their clean URL → page automatically from the registry.
        foreach ($t in $script:portedTools) { $pageRoutes["/$($t.Slug)"] = "$($t.Slug).html" }
        if ($pageRoutes.ContainsKey($path)) {
            $htmlPath = "$PSScriptRoot/web/$($pageRoutes[$path])"
            if (Test-Path $htmlPath) {
                Send-CachedFile $context -path $htmlPath -contentType "text/html; charset=utf-8"
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
                # Re-auth may be a different principal — drop all identity-scoped caches.
                $script:subscriptionCache = $null
                $script:mgCache           = $null
                $script:rgCache           = @{}
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

        # ── POST /api/shutdown ──────────────────────────────────────────────
        # Stops the dashboard from the "Stop" button. Unlike /api/auth/logout this does
        # NOT Disconnect-AzAccount: authentication now happens in the terminal via
        # Connect-AzAccount before launch, so the Az session is left intact — stopping the
        # listener returns control to that PowerShell session, still signed in, ready to
        # re-run ./Start-Dashboard.ps1. The reply is sent first; stopping the listener ends
        # the GetContext loop and runs the finally cleanup.
        if ($path -eq "/api/shutdown" -and $req.HttpMethod -eq "POST") {
            Send-Response $context -body '{"stopped":true}'
            Write-Host "  Stop requested from the dashboard — shutting down server." -ForegroundColor Yellow
            $listener.Stop()
            continue
        }

        # ── GET /api/results ────────────────────────────────────────────────
        if ($path -eq "/api/results" -and $req.HttpMethod -eq "GET") {
            Send-CachedFile $context -path $ResultsPath -emptyBody '{"ScanMetadata":null,"ResourceGroups":[],"Errors":[]}'
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

        # ── GET /api/managementgroups ───────────────────────────────────────
        # Shared scope picker for every tool: lists the tenant's management groups
        # (Name = the id passed to Search-AzGraph -ManagementGroup; DisplayName for
        # the dropdown label). Cached; an empty list is non-fatal (tools fall back
        # to whole-tenant / subscription scope).
        if ($path -eq "/api/managementgroups" -and $req.HttpMethod -eq "GET") {
            if ($null -eq $script:mgCache) {
                try {
                    $script:mgCache = @(
                        Get-AzManagementGroup -ErrorAction Stop |
                        Sort-Object DisplayName |
                        ForEach-Object { @{ Name = $_.Name; DisplayName = $_.DisplayName } }
                    )
                } catch {
                    Write-Warning "Failed to list management groups: $($_.Exception.Message)"
                    $script:mgCache = @()
                }
            }
            Send-Response $context -body (@{ managementGroups = $script:mgCache } | ConvertTo-Json -Depth 5)
            continue
        }

        # ── GET /api/resourcegroups?subscriptionId=... ──────────────────────
        # Shared scope picker: lists the resource groups in one subscription via
        # Resource Graph so a tool can offer a cascading Subscription → RG target.
        # Cached per subscription for the server's lifetime.
        if ($path -eq "/api/resourcegroups" -and $req.HttpMethod -eq "GET") {
            $subId = "$($req.QueryString["subscriptionId"])"
            if (-not $subId) {
                Send-Response $context -status 400 -body '{"error":"subscriptionId query parameter is required."}'
                continue
            }
            if (-not $script:rgCache.ContainsKey($subId)) {
                try {
                    $kql = "ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' | project name, location | order by name asc"
                    # Page with SkipToken so subscriptions with >1000 resource groups aren't truncated.
                    $rows = [System.Collections.Generic.List[object]]::new(); $skip = $null
                    do {
                        $page = if ($skip) { Search-AzGraph -Query $kql -Subscription $subId -First 1000 -SkipToken $skip -ErrorAction Stop }
                                else        { Search-AzGraph -Query $kql -Subscription $subId -First 1000 -ErrorAction Stop }
                        foreach ($r in $page) { $rows.Add($r) }
                        $skip = if ($page.PSObject.Properties['SkipToken']) { $page.SkipToken } else { $null }
                    } while ($skip)
                    $script:rgCache[$subId] = @($rows | ForEach-Object { @{ Name = "$($_.name)"; Location = "$($_.location)" } })
                } catch {
                    Write-Warning "Failed to list resource groups for $subId : $($_.Exception.Message)"
                    Send-Response $context -status 500 -body '{"error":"Failed to list resource groups. See server console for details."}'
                    continue
                }
            }
            Send-Response $context -body (@{ resourceGroups = $script:rgCache[$subId] } | ConvertTo-Json -Depth 5)
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

            # Parse optional body: { "scopeType": "All|ManagementGroup|Subscription|ResourceGroup",
            #   "managementGroupId": "...", "singleSubscriptionId": "...", "resourceGroup": "...",
            #   "lookbackDays": 14 }
            # NOTE: Set-StrictMode throws on missing-property access, so we must check
            # property existence explicitly rather than relying on $null short-circuit.
            $scopeType    = "All"
            $mgId         = ""
            $singleSubId  = ""
            $resourceGrp  = ""
            $effectiveDays = $LookbackDays
            try {
                $bodyStream = New-Object System.IO.StreamReader($req.InputStream)
                $bodyText   = $bodyStream.ReadToEnd()
                if ($bodyText) {
                    $bodyObj = $bodyText | ConvertFrom-Json
                    $props   = $bodyObj.PSObject.Properties.Name
                    if ($props -contains 'scopeType'            -and $bodyObj.scopeType)            { $scopeType   = [string]$bodyObj.scopeType }
                    if ($props -contains 'managementGroupId'    -and $bodyObj.managementGroupId)    { $mgId        = [string]$bodyObj.managementGroupId }
                    if ($props -contains 'singleSubscriptionId' -and $bodyObj.singleSubscriptionId) { $singleSubId = [string]$bodyObj.singleSubscriptionId }
                    if ($props -contains 'resourceGroup'        -and $bodyObj.resourceGroup)        { $resourceGrp = [string]$bodyObj.resourceGroup }
                    if ($props -contains 'lookbackDays'         -and $bodyObj.lookbackDays)         { $effectiveDays = [int]$bodyObj.lookbackDays }
                }
            } catch {
                Write-Warning "Failed to parse /api/scan body: $($_.Exception.Message)"
            }

            $modeLabel = if ($scopeType -eq 'ManagementGroup' -and $mgId) { "mgmt group: $mgId" }
                         elseif ($resourceGrp) { "RG: $resourceGrp" }
                         elseif ($singleSubId) { "single sub: $singleSubId" }
                         else { "all subscriptions" }
            $scanStatus = @{ State = "running"; StartedAt = (Get-Date -Format "o"); Message = "Scan started ($modeLabel, ${effectiveDays}d window)." }

            # Clear any stale progress from a previous run so the bar starts at 0.
            if (Test-Path $ProgressPath) { Remove-Item $ProgressPath -Force -ErrorAction SilentlyContinue }

            # Start-ThreadJob runs in-process: inherits loaded Az modules + live context.
            $scanJob = Start-ThreadJob -ScriptBlock {
                param($script, $output, $progress, $days, $scopeType, $mgId, $subId, $rg, $throttle)
                $p = @{ OutputPath = $output; ProgressPath = $progress; LookbackDays = $days; ThrottleLimit = $throttle; ScopeType = $scopeType }
                if ($mgId)   { $p['ManagementGroupId'] = $mgId }
                if ($subId)  { $p['SingleSubscriptionId'] = $subId }
                if ($rg)     { $p['ResourceGroup'] = $rg }
                & $script @p
            } -ArgumentList $ScanScript, $ResultsPath, $ProgressPath, $effectiveDays, $scopeType, $mgId, $singleSubId, $resourceGrp, $ThrottleLimit

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
            Send-CachedFile $context -path $PaResultsPath -emptyBody '{"ScanMetadata":null,"Assignments":[],"Errors":[]}'
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
        # Body: { "scopeType": "All|ManagementGroup|Subscription|ResourceGroup",
        #   "managementGroupId": "...", "singleSubscriptionId": "...", "resourceGroup": "...",
        #   "privilegedRoles": ["Owner", ...] }
        if ($path -eq "/api/pa/scan" -and $req.HttpMethod -eq "POST") {
            if ($paScanJob -and $paScanJob.State -eq "Running") {
                Send-Response $context -status 409 -body '{"error":"Scan already running."}'
                continue
            }
            if ($paScanJob) { Remove-Job $paScanJob -Force; $paScanJob = $null }

            $scopeType = "All"; $mgId = ""; $singleSubId = ""; $resourceGrp = ""
            $roles = @('Owner','Contributor','User Access Administrator','Role Based Access Control Administrator')
            try {
                $bodyStream = New-Object System.IO.StreamReader($req.InputStream)
                $bodyText   = $bodyStream.ReadToEnd()
                if ($bodyText) {
                    $bodyObj = $bodyText | ConvertFrom-Json
                    $props   = $bodyObj.PSObject.Properties.Name
                    if ($props -contains 'scopeType'            -and $bodyObj.scopeType)            { $scopeType   = [string]$bodyObj.scopeType }
                    if ($props -contains 'managementGroupId'    -and $bodyObj.managementGroupId)    { $mgId        = [string]$bodyObj.managementGroupId }
                    if ($props -contains 'singleSubscriptionId' -and $bodyObj.singleSubscriptionId) { $singleSubId = [string]$bodyObj.singleSubscriptionId }
                    if ($props -contains 'resourceGroup'        -and $bodyObj.resourceGroup)        { $resourceGrp = [string]$bodyObj.resourceGroup }
                    if ($props -contains 'privilegedRoles'      -and $bodyObj.privilegedRoles)      { $roles       = @($bodyObj.privilegedRoles) }
                }
            } catch {
                Write-Warning "Failed to parse /api/pa/scan body: $($_.Exception.Message)"
            }

            $modeLabel = if ($scopeType -eq 'ManagementGroup' -and $mgId) { "mgmt group: $mgId" }
                         elseif ($resourceGrp) { "RG: $resourceGrp" }
                         elseif ($singleSubId) { "single sub: $singleSubId" }
                         else { "all subscriptions + MGs" }
            $paScanStatus = @{ State = "running"; StartedAt = (Get-Date -Format "o"); Message = "Scan started ($modeLabel)." }

            if (Test-Path $PaProgressPath) { Remove-Item $PaProgressPath -Force -ErrorAction SilentlyContinue }

            $paScanJob = Start-ThreadJob -ScriptBlock {
                param($script, $output, $progress, $scopeType, $mgId, $subId, $rg, $roles, $throttle)
                $p = @{ OutputPath = $output; ProgressPath = $progress; PrivilegedRoles = $roles; ThrottleLimit = $throttle; ScopeType = $scopeType }
                if ($mgId)  { $p['ManagementGroupId'] = $mgId }
                if ($subId) { $p['SingleSubscriptionId'] = $subId }
                if ($rg)    { $p['ResourceGroup'] = $rg }
                & $script @p
            } -ArgumentList $PaScanScript, $PaResultsPath, $PaProgressPath, $scopeType, $mgId, $singleSubId, $resourceGrp, $roles, $ThrottleLimit

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
            Send-CachedFile $context -path $EntraResultsPath -emptyBody '{"ScanMetadata":null,"Users":[],"Errors":[]}'
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
            Send-CachedFile $context -path $TagResultsPath -emptyBody '{"ScanMetadata":null,"Objects":[],"Errors":[]}'
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
            $scopeType = "All"
            $singleSubId = ""
            $mgId = ""
            $resourceGrp = ""
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
                    if ($props -contains 'scopeType' -and $bodyObj.scopeType) {
                        $scopeType = [string]$bodyObj.scopeType
                    }
                    if ($props -contains 'singleSubscriptionId' -and $bodyObj.singleSubscriptionId) {
                        $singleSubId = [string]$bodyObj.singleSubscriptionId
                    }
                    if ($props -contains 'managementGroupId' -and $bodyObj.managementGroupId) {
                        $mgId = [string]$bodyObj.managementGroupId
                    }
                    if ($props -contains 'resourceGroup' -and $bodyObj.resourceGroup) {
                        $resourceGrp = [string]$bodyObj.resourceGroup
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

            $scopeLabel = if ($mgId) { "mgmt group: $mgId" } elseif ($resourceGrp) { "RG: $resourceGrp" } elseif ($singleSubId) { "single sub: $singleSubId" } else { "all subscriptions" }
            $tagScanStatus = @{ State = "running"; StartedAt = (Get-Date -Format "o"); Message = "Scan started ($scopeLabel, $mode, $(@($requiredTags).Count) required tag(s))." }
            if (Test-Path $TagProgressPath) { Remove-Item $TagProgressPath -Force -ErrorAction SilentlyContinue }

            $tagScanJob = Start-ThreadJob -ScriptBlock {
                param($script, $output, $progress, $required, $allowed, $scopeType, $subId, $mgId, $rg, $mode)
                $p = @{ OutputPath = $output; ProgressPath = $progress; RequiredTags = $required; AllowedTagValues = $allowed; Mode = $mode; ScopeType = $scopeType }
                if ($mgId)  { $p['ManagementGroupId'] = $mgId }
                if ($subId) { $p['SingleSubscriptionId'] = $subId }
                if ($rg)    { $p['ResourceGroup'] = $rg }
                & $script @p
            } -ArgumentList $TagScanScript, $TagResultsPath, $TagProgressPath, $requiredTags, $allowedValues, $scopeType, $singleSubId, $mgId, $resourceGrp, $mode

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
                # Page with SkipToken so subscriptions with >1000 workspaces aren't truncated.
                $rows = [System.Collections.Generic.List[object]]::new(); $skip = $null
                do {
                    $page = if ($skip) { Search-AzGraph -Query $kql -Subscription $subId -First 1000 -SkipToken $skip -ErrorAction Stop }
                            else        { Search-AzGraph -Query $kql -Subscription $subId -First 1000 -ErrorAction Stop }
                    foreach ($r in $page) { $rows.Add($r) }
                    $skip = if ($page.PSObject.Properties['SkipToken']) { $page.SkipToken } else { $null }
                } while ($skip)
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
            Send-CachedFile $context -path $LaResultsPath -emptyBody '{"ScanMetadata":null,"Tables":[],"Errors":[]}'
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
            Send-CachedFile $context -path $QuotaResultsPath -emptyBody '{"ScanMetadata":null,"Quotas":[],"Errors":[]}'
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
        # Body (all optional): { "scopeType": "All|ManagementGroup|Subscription",
        #   "managementGroupId": "...", "singleSubscriptionId": "...",
        #   "criticalThreshold": 90, "warningThreshold": 75 }
        if ($path -eq "/api/quota/scan" -and $req.HttpMethod -eq "POST") {
            if ($quotaScanJob -and $quotaScanJob.State -eq "Running") {
                Send-Response $context -status 409 -body '{"error":"Scan already running."}'
                continue
            }
            if ($quotaScanJob) { Remove-Job $quotaScanJob -Force; $quotaScanJob = $null }

            $scopeType = "All"; $mgId = ""; $singleSub = ""; $critical = 90; $warning = 75
            try {
                $bodyStream = New-Object System.IO.StreamReader($req.InputStream)
                $bodyText   = $bodyStream.ReadToEnd()
                if ($bodyText) {
                    $bodyObj = $bodyText | ConvertFrom-Json
                    $props   = $bodyObj.PSObject.Properties.Name
                    if ($props -contains 'scopeType'            -and $bodyObj.scopeType)            { $scopeType = [string]$bodyObj.scopeType }
                    if ($props -contains 'managementGroupId'    -and $bodyObj.managementGroupId)    { $mgId      = [string]$bodyObj.managementGroupId }
                    if ($props -contains 'singleSubscriptionId' -and $bodyObj.singleSubscriptionId) { $singleSub = [string]$bodyObj.singleSubscriptionId }
                    if ($props -contains 'criticalThreshold'    -and $bodyObj.criticalThreshold)    { $critical  = [int]$bodyObj.criticalThreshold }
                    if ($props -contains 'warningThreshold'     -and $bodyObj.warningThreshold)     { $warning   = [int]$bodyObj.warningThreshold }
                }
            } catch {
                Write-Warning "Failed to parse /api/quota/scan body: $($_.Exception.Message)"
            }

            $scopeLabel = if ($scopeType -eq 'ManagementGroup' -and $mgId) { "mgmt group: $mgId" } elseif ($scopeType -eq 'Subscription' -and $singleSub) { "single sub: $singleSub" } else { "all subscriptions" }
            $quotaScanStatus = @{ State = "running"; StartedAt = (Get-Date -Format "o"); Message = "Scanning quotas ($scopeLabel)." }
            if (Test-Path $QuotaProgressPath) { Remove-Item $QuotaProgressPath -Force -ErrorAction SilentlyContinue }

            $quotaScanJob = Start-ThreadJob -ScriptBlock {
                param($script, $output, $progress, $scopeType, $mgId, $singleSub, $critical, $warning)
                $p = @{ OutputPath = $output; ProgressPath = $progress; CriticalThreshold = $critical; WarningThreshold = $warning; ScopeType = $scopeType }
                if ($mgId)      { $p['ManagementGroupId'] = $mgId }
                if ($singleSub) { $p['SingleSubscriptionId'] = $singleSub }
                & $script @p
            } -ArgumentList $QuotaScanScript, $QuotaResultsPath, $QuotaProgressPath, $scopeType, $mgId, $singleSub, $critical, $warning

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

        # ── Generic ported-tool API ─────────────────────────────────────────
        # Serves /api/<prefix>/{results,status,scan,scan/cancel} for every registered
        # ported tool, identical in behaviour to the hand-written quartets above but
        # driven by $script:portedTools. (Reached only after the inline endpoints,
        # which `continue` first; unregistered prefixes fall through to 404.)
        if ($path -match '^/api/([a-z0-9]+)/(results|status|scan|scan/cancel)$' -and $script:toolByPrefix.ContainsKey($matches[1])) {
            $tool   = $script:toolByPrefix[$matches[1]]
            $action = $matches[2]
            $entry  = $script:toolJobs[$tool.Prefix]

            if ($action -eq 'results' -and $req.HttpMethod -eq 'GET') {
                Send-CachedFile $context -path $tool.ResultsPath -emptyBody '{"ScanMetadata":null,"Items":[],"Errors":[]}'
                continue
            }

            if ($action -eq 'status' -and $req.HttpMethod -eq 'GET') {
                if ($entry.Job) {
                    $jobState = $entry.Job.State
                    if ($jobState -eq 'Completed') {
                        $null = Receive-Job $entry.Job -Keep
                        $entry.Status = @{ State = 'completed'; Message = 'Scan completed successfully.' }
                        Remove-Job $entry.Job -Force; $entry.Job = $null
                    } elseif ($jobState -eq 'Failed') {
                        $jobErrors = $entry.Job.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason.Message } | Where-Object { $_ }
                        $err = if ($jobErrors) { $jobErrors -join '; ' } else { Receive-Job $entry.Job -Keep 2>&1 | Out-String }
                        $entry.Status = @{ State = 'failed'; Message = $err.Trim() }
                        Remove-Job $entry.Job -Force; $entry.Job = $null
                    } elseif ($jobState -eq 'Running') {
                        $entry.Status = @{ State = 'running'; Message = 'Scan in progress...' }
                    }
                }
                $statusOut = @{} + $entry.Status
                if (Test-Path $tool.ProgressPath) {
                    try { $statusOut.Progress = Get-Content $tool.ProgressPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
                }
                Send-Response $context -body ($statusOut | ConvertTo-Json -Depth 6)
                continue
            }

            if ($action -eq 'scan' -and $req.HttpMethod -eq 'POST') {
                if ($entry.Job -and $entry.Job.State -eq 'Running') {
                    Send-Response $context -status 409 -body '{"error":"Scan already running."}'
                    continue
                }
                if ($entry.Job) { Remove-Job $entry.Job -Force; $entry.Job = $null }

                $scopeType = 'All'; $mgId = ''; $singleSub = ''; $resourceGrp = ''
                $extraVals = @{}   # non-scope params (e.g. cost window, flow-log inputs) per the tool's Extra map
                $reader = [System.IO.StreamReader]::new($req.InputStream)
                try {
                    $bodyText = $reader.ReadToEnd()
                    if ($bodyText) {
                        $bodyObj = $bodyText | ConvertFrom-Json
                        $props   = $bodyObj.PSObject.Properties.Name
                        if ($props -contains 'scopeType'            -and $bodyObj.scopeType)            { $scopeType   = [string]$bodyObj.scopeType }
                        if ($props -contains 'managementGroupId'    -and $bodyObj.managementGroupId)    { $mgId        = [string]$bodyObj.managementGroupId }
                        if ($props -contains 'singleSubscriptionId' -and $bodyObj.singleSubscriptionId) { $singleSub   = [string]$bodyObj.singleSubscriptionId }
                        if ($props -contains 'resourceGroup'        -and $bodyObj.resourceGroup)        { $resourceGrp = [string]$bodyObj.resourceGroup }
                        if ($tool.ContainsKey('Extra')) {
                            foreach ($m in $tool.Extra) {
                                if ($props -contains $m.Body -and $null -ne $bodyObj.$($m.Body) -and "$($bodyObj.$($m.Body))" -ne '') {
                                    $extraVals[$m.Param] = if ($m.ContainsKey('Int') -and $m.Int) { [int]$bodyObj.$($m.Body) } else { [string]$bodyObj.$($m.Body) }
                                }
                            }
                        }
                    }
                } catch {
                    Write-Warning "Failed to parse /api/$($tool.Prefix)/scan body: $($_.Exception.Message)"
                } finally { $reader.Dispose() }

                if (Test-Path $tool.ProgressPath) { Remove-Item $tool.ProgressPath -Force -ErrorAction SilentlyContinue }
                $entry.Status = @{ State = 'running'; StartedAt = (Get-Date -Format 'o'); Message = "Scan started ($($tool.Slug))." }

                $entry.Job = Start-ThreadJob -ScriptBlock {
                    param($script, $output, $progress, $scopeMode, $scopeType, $mgId, $subId, $rg, $extra)
                    $p = @{ OutputPath = $output; ProgressPath = $progress }
                    # Only scope-based tools get the scope params; 'params'/'none' tools take none.
                    if ($scopeMode -eq 'graph' -or $scopeMode -eq 'subscription') {
                        $p['ScopeType'] = $scopeType
                        if ($mgId)  { $p['ManagementGroupId']    = $mgId }
                        if ($subId) { $p['SingleSubscriptionId'] = $subId }
                        if ($scopeMode -eq 'graph' -and $rg) { $p['ResourceGroup'] = $rg }
                    }
                    if ($extra) { foreach ($k in $extra.Keys) { $p[$k] = $extra[$k] } }
                    & $script @p
                } -ArgumentList $tool.ScanScript, $tool.ResultsPath, $tool.ProgressPath, $tool.Scope, $scopeType, $mgId, $singleSub, $resourceGrp, $extraVals

                Send-Response $context -body ($entry.Status | ConvertTo-Json)
                continue
            }

            if ($action -eq 'scan/cancel' -and $req.HttpMethod -eq 'POST') {
                if ($entry.Job -and $entry.Job.State -eq 'Running') {
                    Stop-Job $entry.Job -ErrorAction SilentlyContinue
                    Remove-Job $entry.Job -Force -ErrorAction SilentlyContinue
                    $entry.Job = $null
                    $entry.Status = @{ State = 'cancelled'; StartedAt = $null; Message = 'Scan cancelled by user.' }
                    if (Test-Path $tool.ProgressPath) { Remove-Item $tool.ProgressPath -Force -ErrorAction SilentlyContinue }
                    Send-Response $context -body ($entry.Status | ConvertTo-Json)
                } else {
                    Send-Response $context -status 409 -body '{"error":"No scan is currently running."}'
                }
                continue
            }
        }

        # ── 404 ─────────────────────────────────────────────────────────────
        Send-Response $context -status 404 -body '{"error":"Not found"}'
      } catch {
        Write-Warning "  Request handling error ($path): $($_.Exception.Message)"
        try { $context.Response.Abort() } catch {}
      }
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
    foreach ($entry in $script:toolJobs.Values) { if ($entry.Job) { Remove-Job $entry.Job -Force } }
    Write-Host "Server stopped." -ForegroundColor Yellow
}
