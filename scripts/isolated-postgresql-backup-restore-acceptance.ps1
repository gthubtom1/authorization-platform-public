[CmdletBinding()]
param(
    [string]$PgBin = "D:\Program\pgsql\bin",
    [switch]$KeepArtifacts,
    [string]$CleanupTempRoot = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar

if (-not [string]::IsNullOrWhiteSpace($CleanupTempRoot)) {
    $cleanupTarget = [IO.Path]::GetFullPath($CleanupTempRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $cleanupTarget.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
        throw "拒绝清理临时目录：目标不在系统临时目录下。"
    }
    $cleanupDirectory = $cleanupTarget.TrimEnd('\', '/')
    if (Test-Path -LiteralPath $cleanupDirectory) {
        Remove-Item -LiteralPath $cleanupDirectory -Recurse -Force
    }
    Write-Output "temporary-cluster-cleaned"
    exit 0
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("authorization-platform-b72-pg-" + [guid]::NewGuid().ToString("N"))
$pgData = Join-Path $tempRoot "data"
$pgLog = Join-Path $tempRoot "postgres.log"
$pgCtlStartStdout = Join-Path $tempRoot "pg_ctl-start.stdout.txt"
$pgCtlStartStderr = Join-Path $tempRoot "pg_ctl-start.stderr.txt"
$pgCtlStopStdout = Join-Path $tempRoot "pg_ctl-stop.stdout.txt"
$pgCtlStopStderr = Join-Path $tempRoot "pg_ctl-stop.stderr.txt"
$artifactRoot = Join-Path $projectRoot "output\postgresql-backup-restore"
$artifactId = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmssfff") + "-" + [guid]::NewGuid().ToString("N")
$backupArtifact = Join-Path $artifactRoot $artifactId
$restoreArtifact = Join-Path $artifactRoot ($artifactId + "-restore")
$sourceDatabase = "auth_b72_source"
$restoreDatabase = "auth_b72_restore"
$role = "auth_b72_test"
$pgStarted = $false
$pgLaunchStarted = $false
$previous = @{}

function Test-IsolatedPostgresConnection {
    param([Parameter(Mandatory = $true)][int]$Port)
    try {
        & (Join-Path $PgBin "psql.exe") --host 127.0.0.1 --port $Port --username $role --dbname postgres --tuples-only --no-align --command "SELECT 1;" 2>$null | Out-Null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

foreach ($tool in @("initdb.exe", "pg_ctl.exe", "createdb.exe", "dropdb.exe", "psql.exe")) {
    if (-not (Test-Path -LiteralPath (Join-Path $PgBin $tool) -PathType Leaf)) {
        throw "PostgreSQL 工具不存在：$tool。"
    }
}
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw "项目虚拟环境不存在。" }

$portListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$portListener.Start()
$pgPort = ([Net.IPEndPoint]$portListener.LocalEndpoint).Port
$portListener.Stop()

foreach ($name in @("APP_ENV", "DATABASE_ENGINE", "DATABASE_HOST", "DATABASE_PORT", "DATABASE_NAME", "DATABASE_USER", "DATABASE_PASSWORD", "DJANGO_CACHE_BACKEND", "DJANGO_CACHE_LOCATION", "PYTHONPATH")) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

try {
    Write-Output "STEP initdb"
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    & (Join-Path $PgBin "initdb.exe") -D $pgData -U $role -A trust --no-locale 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "initdb failed" }
    Write-Output "STEP start-postgresql"
    $startArguments = "-D `"$pgData`" -o `"-p $pgPort`" -l `"$pgLog`" -w start"
    Start-Process -FilePath (Join-Path $PgBin "pg_ctl.exe") -ArgumentList $startArguments -RedirectStandardOutput $pgCtlStartStdout -RedirectStandardError $pgCtlStartStderr -WindowStyle Hidden | Out-Null
    $pgLaunchStarted = $true
    $databaseReady = $false
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        Start-Sleep -Milliseconds 100
        if (Test-IsolatedPostgresConnection -Port $pgPort) { $databaseReady = $true; break }
    }
    if (-not $databaseReady) { throw "PostgreSQL 隔离集群未在限定时间内就绪。" }
    $pgStarted = $true
    Write-Output "STEP postgresql-started"

    [Environment]::SetEnvironmentVariable("APP_ENV", "local", "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_ENGINE", "postgresql", "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_HOST", "127.0.0.1", "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_PORT", [string]$pgPort, "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_NAME", $sourceDatabase, "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_USER", $role, "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_PASSWORD", ("test-" + [guid]::NewGuid().ToString("N")), "Process")
    [Environment]::SetEnvironmentVariable("DJANGO_CACHE_BACKEND", "django.core.cache.backends.db.DatabaseCache", "Process")
    [Environment]::SetEnvironmentVariable("DJANGO_CACHE_LOCATION", "django_cache", "Process")
    [Environment]::SetEnvironmentVariable("PYTHONPATH", (Join-Path $projectRoot "src"), "Process")
    Write-Output "STEP environment-ready"

    Write-Output "STEP create-source-database"
    & (Join-Path $PgBin "createdb.exe") --host 127.0.0.1 --port $pgPort --username $role $sourceDatabase 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "createdb source failed" }
    Write-Output "STEP migrate-source"
    & $python (Join-Path $projectRoot "manage.py") migrate --noinput 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "source migrate failed" }
    Write-Output "STEP create-cache-table"
    & $python (Join-Path $projectRoot "manage.py") createcachetable 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "source createcachetable failed" }

    Write-Output "STEP seed-recovery-fixture"
    & $python (Join-Path $projectRoot "manage.py") seed_recovery_fixture 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "recovery fixture seed failed" }
    $sourceInventory = Join-Path $tempRoot "source-recovery-inventory.json"
    Write-Output "STEP source-recovery-inventory"
    & $python (Join-Path $projectRoot "manage.py") recovery_inventory --verify-ciphertext --output $sourceInventory 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "source recovery inventory failed" }

    Write-Output "STEP pg-dump"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot "scripts\postgresql-backup-restore.ps1") -Mode backup -ConfirmIsolatedTarget -ApprovedHost 127.0.0.1 -ApprovedServerAddress 127.0.0.1 -ApprovedPort $pgPort -ApprovedDatabase $sourceDatabase -ApprovedUser $role -OutputDirectory $backupArtifact 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "backup script failed" }
    $backupFile = Join-Path $backupArtifact "authorization-platform.dump"
    if (-not (Test-Path -LiteralPath $backupFile -PathType Leaf)) { throw "backup artifact missing" }
    $backupSha256 = (Get-FileHash -LiteralPath $backupFile -Algorithm SHA256).Hash.ToLowerInvariant()
    $sourceInventoryArtifact = Join-Path $backupArtifact "recovery-inventory-source.json"
    Copy-Item -LiteralPath $sourceInventory -Destination $sourceInventoryArtifact -Force

    Write-Output "STEP shared-worker-rate-limit"
    $sharedRateLimitOutput = & $python (Join-Path $projectRoot "scripts\shared_rate_limit_probe.py") --workers 2 --limit 1 --confirm-isolated-target 2>&1
    $sharedRateLimitOutput | ForEach-Object { $_.ToString() } | Set-Content -LiteralPath (Join-Path $backupArtifact "shared-worker-rate-limit.json") -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw "shared worker rate-limit probe failed" }

    Write-Output "STEP pg-restore"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot "scripts\postgresql-backup-restore.ps1") -Mode restore -ConfirmIsolatedTarget -ApprovedHost 127.0.0.1 -ApprovedServerAddress 127.0.0.1 -ApprovedPort $pgPort -ApprovedDatabase $sourceDatabase -ApprovedUser $role -BackupFile $backupFile -ExpectedBackupSha256 $backupSha256 -RestoreDatabase $restoreDatabase -OutputDirectory $restoreArtifact 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "restore script failed" }

    [Environment]::SetEnvironmentVariable("DATABASE_NAME", $restoreDatabase, "Process")
    Write-Output "STEP verify-restored-database"
    & $python (Join-Path $projectRoot "manage.py") migrate --check 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "restored migrate check failed" }
    & $python (Join-Path $projectRoot "manage.py") check 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "restored django check failed" }
    Write-Output "STEP compare-recovery-inventory"
    & $python (Join-Path $projectRoot "manage.py") recovery_inventory --verify-ciphertext --compare $sourceInventoryArtifact --output (Join-Path $restoreArtifact "recovery-inventory-restore.json") 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "restored recovery inventory mismatch" }
    $migrationCount = & (Join-Path $PgBin "psql.exe") --host 127.0.0.1 --port $pgPort --username $role --dbname $restoreDatabase --tuples-only --no-align --command "SELECT count(*) FROM django_migrations;" 2>$null
    if ([int]($migrationCount | Select-Object -First 1).ToString().Trim() -le 0) { throw "restored migration invariant failed" }

    [Environment]::SetEnvironmentVariable("DATABASE_NAME", $sourceDatabase, "Process")
    & (Join-Path $PgBin "dropdb.exe") --if-exists --host 127.0.0.1 --port $pgPort --username $role --force $restoreDatabase 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "restore database cleanup failed" }
    Write-Output ("BACKUP_RESTORE_ACCEPTED " + $backupArtifact)
} finally {
    if ($pgLaunchStarted) {
        $stopArguments = "-D `"$pgData`" -m fast stop"
        Start-Process -FilePath (Join-Path $PgBin "pg_ctl.exe") -ArgumentList $stopArguments -RedirectStandardOutput $pgCtlStopStdout -RedirectStandardError $pgCtlStopStderr -WindowStyle Hidden | Out-Null
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            Start-Sleep -Milliseconds 100
            if (-not (Test-IsolatedPostgresConnection -Port $pgPort)) { break }
        }
        $serverStillRunning = $false
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            $serverProcesses = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -eq "postgres.exe" -and $_.CommandLine -and $_.CommandLine.IndexOf($pgData, [StringComparison]::OrdinalIgnoreCase) -ge 0
            })
            if ($serverProcesses.Count -eq 0) { $serverStillRunning = $false; break }
            $serverStillRunning = $true
            Start-Sleep -Milliseconds 100
        }
        if ($serverStillRunning) { throw "隔离 PostgreSQL 进程仍占用数据目录，拒绝继续清理。" }
    }
    foreach ($name in $previous.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], "Process")
    }
    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $tempRoot)) {
        $resolvedTempRoot = [IO.Path]::GetFullPath($tempRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedTempRoot.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
            throw "拒绝清理临时目录：目标不在系统临时目录下。"
        }
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
