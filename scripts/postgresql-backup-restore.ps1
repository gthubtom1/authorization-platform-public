[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet("backup", "restore")][string]$Mode,
    [switch]$ConfirmIsolatedTarget,
    [Parameter(Mandatory = $true)][string]$ApprovedHost,
    [Parameter(Mandatory = $true)][string]$ApprovedServerAddress,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$ApprovedPort,
    [Parameter(Mandatory = $true)][string]$ApprovedDatabase,
    [Parameter(Mandatory = $true)][string]$ApprovedUser,
    [string]$BackupFile = "",
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedBackupSha256 = "",
    [string]$RestoreDatabase = "",
    [string]$OutputDirectory = "",
    [string]$PgBin = "D:\Program\pgsql\bin"
)

$ErrorActionPreference = "Stop"

function Assert-SafeDatabaseName {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -notmatch '^[A-Za-z_][A-Za-z0-9_]{0,62}$') {
        throw "数据库名不符合隔离验收格式。"
    }
}

function Invoke-PgTool {
    param(
        [Parameter(Mandatory = $true)][string]$Tool,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath
    )
    $exe = Join-Path $PgBin $Tool
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw "PostgreSQL 工具不存在：$exe。"
    }
    $stdout = & $exe @Arguments 2> $StderrPath
    $exitCode = $LASTEXITCODE
    ($stdout | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine | Set-Content -LiteralPath $StdoutPath -Encoding UTF8
    if ($exitCode -ne 0) {
        throw "PostgreSQL 工具执行失败：$Tool。详见产物文件。"
    }
}

if (-not $ConfirmIsolatedTarget) {
    throw "必须显式传入 -ConfirmIsolatedTarget；该脚本拒绝生产目标。"
}
$loopback = @("localhost", "127.0.0.1", "::1")
if ($loopback -notcontains $ApprovedHost.ToLowerInvariant() -or $loopback -notcontains $ApprovedServerAddress.ToLowerInvariant()) {
    throw "备份/恢复验收只允许 loopback 隔离 PostgreSQL。"
}
if ([Environment]::GetEnvironmentVariable("APP_ENV") -eq "production") {
    throw "备份/恢复验收脚本拒绝 APP_ENV=production。"
}
if ([Environment]::GetEnvironmentVariable("DATABASE_ENGINE") -ne "postgresql") {
    throw "当前进程必须显式设置 DATABASE_ENGINE=postgresql。"
}
$configured = @{
    DATABASE_HOST = [Environment]::GetEnvironmentVariable("DATABASE_HOST")
    DATABASE_PORT = [Environment]::GetEnvironmentVariable("DATABASE_PORT")
    DATABASE_NAME = [Environment]::GetEnvironmentVariable("DATABASE_NAME")
    DATABASE_USER = [Environment]::GetEnvironmentVariable("DATABASE_USER")
}
if ($configured.DATABASE_HOST -cne $ApprovedHost -or $configured.DATABASE_PORT -cne [string]$ApprovedPort -or $configured.DATABASE_NAME -cne $ApprovedDatabase -or $configured.DATABASE_USER -cne $ApprovedUser) {
    throw "当前进程数据库配置与批准隔离目标不一致。"
}
Assert-SafeDatabaseName -Value $ApprovedDatabase
if ($Mode -eq "restore") {
    if ([string]::IsNullOrWhiteSpace($RestoreDatabase)) { throw "restore 模式必须提供 RestoreDatabase。" }
    if ([string]::IsNullOrWhiteSpace($ExpectedBackupSha256)) { throw "restore 模式必须提供 ExpectedBackupSha256；拒绝未经批准哈希校验的恢复。" }
    Assert-SafeDatabaseName -Value $RestoreDatabase
    if ($RestoreDatabase -eq $ApprovedDatabase) { throw "恢复目标数据库不能覆盖备份源数据库。" }
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $root "output\postgresql-backup-restore"
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $artifactDirectory = Join-Path $artifactRoot ((Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmssfff") + "-" + [guid]::NewGuid().ToString("N"))
} else {
    $artifactDirectory = [IO.Path]::GetFullPath($OutputDirectory)
}
$artifactPrefix = ([IO.Path]::GetFullPath($artifactRoot)).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (-not $artifactDirectory.StartsWith($artifactPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "产物目录必须位于 output\postgresql-backup-restore 下。"
}
if (Test-Path -LiteralPath $artifactDirectory) { throw "产物目录已存在，为避免覆盖证据而停止。" }
$password = [Environment]::GetEnvironmentVariable("DATABASE_PASSWORD", "Process")
if ([string]::IsNullOrEmpty($password)) { throw "DATABASE_PASSWORD 必须通过当前进程注入；不会猜测密码。" }
New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null

if ([string]::IsNullOrWhiteSpace($BackupFile)) {
    $BackupFile = Join-Path $artifactDirectory "authorization-platform.dump"
} else {
    $BackupFile = [IO.Path]::GetFullPath($BackupFile)
}
if ($Mode -eq "backup") {
    $backupPrefix = ([IO.Path]::GetFullPath($artifactRoot)).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $BackupFile.StartsWith($backupPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "备份文件必须位于 output\postgresql-backup-restore 下。"
    }
    if (Test-Path -LiteralPath $BackupFile) {
        throw "备份文件已存在，为避免覆盖旧证据而停止。"
    }
}

$oldPassword = [Environment]::GetEnvironmentVariable("PGPASSWORD", "Process")
[Environment]::SetEnvironmentVariable("PGPASSWORD", $password, "Process")
$restoreDatabaseCreated = $false
$stage = "initializing"
$manifest = [ordered]@{
    schema_version = 2
    mode = $Mode
    status = "running"
    started_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    finished_at_utc = $null
    approved_host = $ApprovedHost
    approved_server_address = $ApprovedServerAddress
    approved_port = $ApprovedPort
    approved_database = $ApprovedDatabase
    approved_user = $ApprovedUser
    restore_database = if ($Mode -eq "restore") { $RestoreDatabase } else { $null }
    backup_file = [IO.Path]::GetFullPath($BackupFile)
    backup_sha256 = $null
    backup_sha256_verified = $false
    restore_database_created = $false
    restore_cleanup_status = if ($Mode -eq "restore") { "not_started" } else { "not_applicable" }
    failure_stage = $null
    failure_code = $null
    secret_values_exposed = $false
}
$manifestPath = Join-Path $artifactDirectory "manifest.json"

function Write-Manifest {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Document, [Parameter(Mandatory = $true)][string]$Path)
    $temporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $Document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

try {
    if ($Mode -eq "backup") {
        $stage = "pg_dump"
        Invoke-PgTool -Tool "pg_dump.exe" -Arguments @("--format=custom", "--no-owner", "--no-acl", "--host", $ApprovedHost, "--port", [string]$ApprovedPort, "--username", $ApprovedUser, "--file", $BackupFile, $ApprovedDatabase) -StdoutPath (Join-Path $artifactDirectory "pg_dump.stdout.txt") -StderrPath (Join-Path $artifactDirectory "pg_dump.stderr.txt")
        $stage = "pg_restore_list"
        Invoke-PgTool -Tool "pg_restore.exe" -Arguments @("--list", $BackupFile) -StdoutPath (Join-Path $artifactDirectory "backup.contents.txt") -StderrPath (Join-Path $artifactDirectory "pg_restore_list.stderr.txt")
    } else {
        $stage = "restore_input_hash"
        if (-not (Test-Path -LiteralPath $BackupFile -PathType Leaf)) { throw "备份文件不存在。" }
        $observedBackupSha256 = (Get-FileHash -LiteralPath $BackupFile -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($observedBackupSha256 -ne $ExpectedBackupSha256.ToLowerInvariant()) {
            throw "备份文件 SHA-256 与批准清单不一致；恢复尚未开始。"
        }
        $manifest.backup_sha256 = $observedBackupSha256
        $manifest.backup_sha256_verified = $true
        $stage = "restore_target_precheck"
        $existing = & (Join-Path $PgBin "psql.exe") --host $ApprovedHost --port $ApprovedPort --username $ApprovedUser --dbname postgres --tuples-only --no-align --command "SELECT 1 FROM pg_database WHERE datname = '$RestoreDatabase';" 2> (Join-Path $artifactDirectory "restore-precheck.stderr.txt")
        if ($LASTEXITCODE -ne 0) { throw "无法检查恢复目标数据库；未执行恢复。" }
        $existingText = (($existing | ForEach-Object { $_.ToString() }) -join "").Trim()
        if ($existingText -eq "1") { throw "恢复目标数据库已存在，为避免覆盖而停止。" }
        $stage = "restore_database_create"
        Invoke-PgTool -Tool "createdb.exe" -Arguments @("--host", $ApprovedHost, "--port", [string]$ApprovedPort, "--username", $ApprovedUser, $RestoreDatabase) -StdoutPath (Join-Path $artifactDirectory "createdb.stdout.txt") -StderrPath (Join-Path $artifactDirectory "createdb.stderr.txt")
        $restoreDatabaseCreated = $true
        $manifest.restore_database_created = $true
        $stage = "pg_restore"
        Invoke-PgTool -Tool "pg_restore.exe" -Arguments @("--exit-on-error", "--no-owner", "--no-acl", "--dbname", $RestoreDatabase, "--host", $ApprovedHost, "--port", [string]$ApprovedPort, "--username", $ApprovedUser, $BackupFile) -StdoutPath (Join-Path $artifactDirectory "pg_restore.stdout.txt") -StderrPath (Join-Path $artifactDirectory "pg_restore.stderr.txt")
        $stage = "restore_invariant"
        Invoke-PgTool -Tool "psql.exe" -Arguments @("--host", $ApprovedHost, "--port", [string]$ApprovedPort, "--username", $ApprovedUser, "--dbname", $RestoreDatabase, "--tuples-only", "--no-align", "--command", "SELECT current_database(); SELECT count(*) FROM django_migrations;") -StdoutPath (Join-Path $artifactDirectory "restore-invariant.stdout.txt") -StderrPath (Join-Path $artifactDirectory "restore-invariant.stderr.txt")
    }
    if ($null -eq $manifest.backup_sha256) {
        $manifest.backup_sha256 = (Get-FileHash -LiteralPath $BackupFile -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $manifest.status = "succeeded"
    $manifest.finished_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    if ($Mode -eq "restore") { $manifest.restore_cleanup_status = "not_needed" }
    Write-Manifest -Document $manifest -Path $manifestPath
    Write-Output ($manifest | ConvertTo-Json -Depth 8)
} catch {
    $manifest.status = "failed"
    $manifest.finished_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    $manifest.failure_stage = $stage
    $manifest.failure_code = "postgresql_tool_failed"
    if ($Mode -eq "restore" -and $restoreDatabaseCreated) {
        $manifest.restore_cleanup_status = "attempted"
        try {
            $cleanupStage = $stage
            $stage = "restore_database_cleanup"
            Invoke-PgTool -Tool "dropdb.exe" -Arguments @("--if-exists", "--force", "--host", $ApprovedHost, "--port", [string]$ApprovedPort, "--username", $ApprovedUser, $RestoreDatabase) -StdoutPath (Join-Path $artifactDirectory "failed-restore-dropdb.stdout.txt") -StderrPath (Join-Path $artifactDirectory "failed-restore-dropdb.stderr.txt")
            $manifest.restore_cleanup_status = "cleaned"
            $stage = $cleanupStage
        } catch {
            $manifest.restore_cleanup_status = "failed"
            $stage = "restore_database_cleanup"
        }
    }
    try {
        Write-Manifest -Document $manifest -Path $manifestPath
    } catch {
        throw "恢复失败 manifest 无法写入；请保留产物目录排查。"
    }
    throw
} finally {
    if ($null -eq $oldPassword) {
        [Environment]::SetEnvironmentVariable("PGPASSWORD", $null, "Process")
    } else {
        [Environment]::SetEnvironmentVariable("PGPASSWORD", $oldPassword, "Process")
    }
}
