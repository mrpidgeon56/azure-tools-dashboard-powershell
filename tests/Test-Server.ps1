#Requires -Version 7.0
<#
.SYNOPSIS
    Integration smoke test: boots Start-Dashboard.ps1 on a test port and asserts the HTTP
    contract — pages serve, gzip + conditional-GET work, the security guards hold, POST
    handlers are actually reached (the 411 regression), and /api/shutdown terminates it.
.NOTES
    Needs the modules the server needs to boot (Az.Accounts, ThreadJob); does NOT need an Azure
    login (it only exercises static/JSON endpoints + guards). Exit 0 = pass, 1 = fail.
#>
[CmdletBinding()] param([int]$Port = 8231)
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
$base = "http://localhost:$Port"
$script:fail = 0
function Check([string]$name, [bool]$cond, [string]$detail = "") {
    if ($cond) { Write-Host "  [PASS] $name" -ForegroundColor Green }
    else { Write-Host "  [FAIL] $name$(if($detail){" — $detail"})" -ForegroundColor Red; $script:fail++ }
}

$log  = [System.IO.Path]::GetTempFileName()
$proc = Start-Process pwsh -PassThru -RedirectStandardOutput $log -RedirectStandardError "$log.err" `
        -ArgumentList @('-NoProfile', '-File', "$root/Start-Dashboard.ps1", '-Port', "$Port")

$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AutomaticDecompression = [System.Net.DecompressionMethods]::None   # see raw Content-Encoding
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(10)
function Send([string]$method, [string]$path, [hashtable]$headers = @{}, [string]$body = $null) {
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($method), "$base$path")
    foreach ($k in $headers.Keys) { [void]$req.Headers.TryAddWithoutValidation($k, [string]$headers[$k]) }
    if ($null -ne $body) { $req.Content = [System.Net.Http.StringContent]::new($body, [System.Text.Encoding]::UTF8, 'application/json') }
    return $client.SendAsync($req).GetAwaiter().GetResult()
}

try {
    Write-Host "`n== Server integration (port $Port) ==" -ForegroundColor Cyan
    $booted = $false
    for ($i = 0; $i -lt 40; $i++) {
        try { if ([int](Send 'GET' '/').StatusCode -eq 200) { $booted = $true; break } } catch { }
        Start-Sleep -Milliseconds 500
    }
    Check "server boots" $booted
    if (-not $booted) {
        Write-Host "  server log:" -ForegroundColor DarkGray; Get-Content $log, "$log.err" -ErrorAction SilentlyContinue | Select-Object -Last 15 | ForEach-Object { "    $_" }
        return
    }

    Check "GET / -> 200"            ([int](Send 'GET' '/').StatusCode -eq 200)
    Check "GET /quota-usage -> 200" ([int](Send 'GET' '/quota-usage').StatusCode -eq 200)
    Check "GET /api/results -> 200" ([int](Send 'GET' '/api/results').StatusCode -eq 200)

    $g  = Send 'GET' '/api/results' @{ 'Accept-Encoding' = 'gzip' }
    $ce = ($g.Content.Headers.ContentEncoding) -join ','
    Check "results gzip honored" ($ce -match 'gzip') "Content-Encoding='$ce'"

    $h1 = Send 'GET' '/'
    $etag = if ($h1.Headers.ETag) { $h1.Headers.ETag.Tag } else { $null }
    Check "page sends ETag" ([bool]$etag)
    $h2 = Send 'GET' '/' @{ 'If-None-Match' = $etag }
    Check "conditional GET -> 304" ([int]$h2.StatusCode -eq 304) "got $([int]$h2.StatusCode)"

    Check "POST no-Origin -> 403 (CSRF)" ([int](Send 'POST' '/api/scan' @{} '{}').StatusCode -eq 403)
    # The 411 regression: a POST with a body must REACH the handler (409 'no scan running'), not 411.
    Check "cancel reaches handler (409, not 411)" ([int](Send 'POST' '/api/scan/cancel' @{ Origin = $base } '{}').StatusCode -eq 409)

    Check "POST /api/shutdown -> 200" ([int](Send 'POST' '/api/shutdown' @{ Origin = $base } '{}').StatusCode -eq 200)
    Start-Sleep -Milliseconds 900
    $stopped = $false; try { Send 'GET' '/' | Out-Null } catch { $stopped = $true }
    Check "server terminated by shutdown" $stopped
}
finally {
    $client.Dispose()
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item $log, "$log.err" -ErrorAction SilentlyContinue
}

Write-Host ""
if ($script:fail -gt 0) { Write-Host "SERVER TESTS: $script:fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "SERVER TESTS: all passed" -ForegroundColor Green
