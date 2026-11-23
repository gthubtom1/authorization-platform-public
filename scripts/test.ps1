$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    throw "项目虚拟环境不存在，请先运行 scripts\bootstrap.ps1"
}
& $python (Join-Path $root "manage.py") test tests --verbosity 2
if ($LASTEXITCODE -ne 0) { throw "Django tests failed with exit code $LASTEXITCODE" }
Write-Output "Django tests finished on this process engine. SQLite green is not PostgreSQL concurrency or backup-restore proof."
