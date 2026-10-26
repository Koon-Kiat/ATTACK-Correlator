param([switch]$Start)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Push-Location $taskRoot
try {
    if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
    }
    & .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
    & .\.venv\Scripts\python.exe scripts/configure_env.py
    if ($LASTEXITCODE -ne 0) { throw 'Environment configuration failed.' }
    docker compose config --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Compose validation failed.' }
    if ($Start) {
        docker compose up -d --wait --wait-timeout 360
        if ($LASTEXITCODE -ne 0) { throw 'Stack startup failed; inspect docker compose logs.' }
    }
    Write-Output 'Setup complete. See README.md for dataset inspection and current phase limits.'
} finally {
    Pop-Location
}
