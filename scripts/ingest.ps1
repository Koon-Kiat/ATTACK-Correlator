param([switch]$Reset, [int]$TimeoutSeconds = 1200)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Push-Location $taskRoot
try {
    $ingestArgs = @('scripts/ingest.py', '--timeout', "$TimeoutSeconds")
    if ($Reset) { $ingestArgs += '--reset' }
    & .\.venv\Scripts\python.exe @ingestArgs
    if ($LASTEXITCODE -ne 0) { throw 'Ingestion or validation failed; see analysis/ingestion.' }
} finally {
    Pop-Location
}
