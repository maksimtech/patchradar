# PatchRadar - Import installed software from winget
# Usage: .\import-winget.ps1 [-Url http://localhost:8000] [-ApiKey <key>] [-InputFile names.txt]
#
#   -ApiKey     the server's PATCHRADAR_API_KEY; read from the environment variable
#               of the same name when not given. A server with a key answers 401
#               without it, which is every server published beyond localhost.
#   -InputFile  one software name per line, instead of asking winget: a list taken
#               on another machine, or on one without winget.
#
# The body is posted as UTF-8 bytes. Windows PowerShell 5.1 encodes a string body
# in the console's code page, and on 2026-10-09 a real list of 109 names carried
# "hwinfo® 64": sent as cp1252, the ® is not valid UTF-8 and the server refused
# the whole body ("There was an error parsing the body") before reading a name.

param(
    [string]$Url = "http://localhost:8000",
    [string]$ApiKey = $env:PATCHRADAR_API_KEY,
    [string]$InputFile
)

Write-Host "PatchRadar - Winget Import" -ForegroundColor Cyan
Write-Host "Connecting to: $Url" -ForegroundColor Gray

$headers = @{}
if ($ApiKey) { $headers['X-API-Key'] = $ApiKey }

# Test connection
try {
    $health = Invoke-RestMethod -Uri "$Url/health" -Method GET -ErrorAction Stop
} catch {
    Write-Host "ERROR: Cannot connect to PatchRadar at $Url" -ForegroundColor Red
    Write-Host "Make sure PatchRadar is running: patchradar serve" -ForegroundColor Yellow
    exit 1
}

if ($InputFile) {
    Write-Host "Reading software names from $InputFile..." -ForegroundColor Yellow
    try {
        $apps = Get-Content -LiteralPath $InputFile -Encoding UTF8 -ErrorAction Stop |
            ForEach-Object { $_.Trim().ToLower() } |
            Where-Object { $_ -and $_.Length -gt 1 }
    } catch {
        Write-Host "ERROR: Cannot read $InputFile" -ForegroundColor Red
        exit 1
    }
} else {
    # Get winget list
    Write-Host "Reading installed software from winget..." -ForegroundColor Yellow
    try {
        $raw = winget list --source winget 2>$null
    } catch {
        Write-Host "ERROR: winget not found. Install it from the Microsoft Store." -ForegroundColor Red
        exit 1
    }

    # Parse software names
    $apps = $raw |
        Select-Object -Skip 3 |
        ForEach-Object { ($_ -split '\s{2,}')[0].Trim().ToLower() } |
        Where-Object { $_ -and $_.Length -gt 1 -and $_ -notmatch '^-+$' }
}

# @() keeps one name a list: ConvertTo-Json unwraps a one-element array into a
# string, and {"software": "nginx"} is a 400 at the server.
$apps = @($apps)
Write-Host "Found $($apps.Count) packages" -ForegroundColor Green

# Send to PatchRadar
$body = @{ software = $apps } | ConvertTo-Json -Compress
$bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
try {
    $result = Invoke-RestMethod -Uri "$Url/api/watchlist/import" -Method POST -Body $bytes `
        -ContentType "application/json; charset=utf-8" -Headers $headers -ErrorAction Stop
    $line = "Done! Added: $(@($result.added).Count) | Already in watchlist: $(@($result.skipped).Count)"
    if (@($result.rejected).Count -gt 0) {
        $line += " | Rejected (not a valid name): $(@($result.rejected).Count)"
    }
    Write-Host $line -ForegroundColor Green
} catch {
    $status = $null
    if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
    Write-Host "ERROR: Failed to import to PatchRadar: $_" -ForegroundColor Red
    if ($status -eq 401) {
        Write-Host "This server has a PATCHRADAR_API_KEY: pass it with -ApiKey or set the environment variable." -ForegroundColor Yellow
    }
    exit 1
}
