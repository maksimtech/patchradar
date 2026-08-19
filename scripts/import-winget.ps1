# PatchRadar - Import installed software from winget
# Usage: .\import-winget.ps1 [-Url http://localhost:8000]

param(
    [string]$Url = "http://localhost:8000"
)

Write-Host "PatchRadar - Winget Import" -ForegroundColor Cyan
Write-Host "Connecting to: $Url" -ForegroundColor Gray

# Test connection
try {
    $health = Invoke-RestMethod -Uri "$Url/health" -Method GET -ErrorAction Stop
} catch {
    Write-Host "ERROR: Cannot connect to PatchRadar at $Url" -ForegroundColor Red
    Write-Host "Make sure PatchRadar is running: patchradar serve" -ForegroundColor Yellow
    exit 1
}

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

Write-Host "Found $($apps.Count) installed packages" -ForegroundColor Green

# Send to PatchRadar
$body = @{ software = $apps } | ConvertTo-Json
try {
    $result = Invoke-RestMethod -Uri "$Url/api/watchlist/import" -Method POST -Body $body -ContentType "application/json"
    Write-Host "Done! Added: $($result.added.Count) | Already in watchlist: $($result.skipped.Count)" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to import to PatchRadar: $_" -ForegroundColor Red
    exit 1
}
