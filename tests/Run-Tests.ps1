#Requires -Version 7.0
<#
.SYNOPSIS
    Runs the hub smoke-test suite: contract checks (always) + the server integration test
    (skip with -SkipServer, e.g. on a box without the Az/ThreadJob modules).
.EXAMPLE
    ./tests/Run-Tests.ps1
    ./tests/Run-Tests.ps1 -SkipServer
#>
[CmdletBinding()] param([switch]$SkipServer, [int]$Port = 8231)
Set-StrictMode -Version Latest
$failed = 0

Write-Host "=== Contract tests ===" -ForegroundColor Magenta
& "$PSScriptRoot/Test-Contracts.ps1"; if ($LASTEXITCODE -ne 0) { $failed++ }

if (-not $SkipServer) {
    Write-Host "`n=== Server integration test ===" -ForegroundColor Magenta
    & "$PSScriptRoot/Test-Server.ps1" -Port $Port; if ($LASTEXITCODE -ne 0) { $failed++ }
} else {
    Write-Host "`n(skipping server integration test)" -ForegroundColor DarkGray
}

Write-Host ""
if ($failed -gt 0) { Write-Host "SUITE: $failed test file(s) FAILED" -ForegroundColor Red; exit 1 }
Write-Host "SUITE: all tests passed ✓" -ForegroundColor Green
