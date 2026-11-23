param(
    [switch]$SkipMigrate
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $root ".venv"
$python = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "Creating project virtual environment..."
    python -m venv $venv
}

& $python -m pip install -r (Join-Path $root "requirements.txt")
if (-not $SkipMigrate) {
    & $python (Join-Path $root "manage.py") migrate --noinput
}
& $python (Join-Path $root "manage.py") check
Write-Host "Local foundation is ready. Run scripts\run-local.ps1 to start it."
