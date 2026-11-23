[CmdletBinding()]
param(
    [switch]$ConfirmIsolatedTarget,
    [string]$ApprovedHost,
    [string]$ApprovedServerAddress,
    [int]$ApprovedPort,
    [string]$ApprovedDatabase,
    [string]$ApprovedUser,
    [string]$MaintenanceDatabase = "postgres",
    [string]$OutputDirectory = "",
    [ValidateRange(1, 3600)][int]$ProcessTimeoutSeconds = 900
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = [IO.Path]::GetFullPath((Join-Path $root "output\postgresql-concurrency")).TrimEnd('\', '/')
$python = Join-Path $root ".venv\Scripts\python.exe"
$manage = Join-Path $root "manage.py"
$preflight = Join-Path $PSScriptRoot "preflight-postgresql.ps1"

function Convert-ToText {
    param([AllowNull()][object[]]$Items)

    if ($null -eq $Items) {
        return ""
    }

    return (($Items | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
}

function Write-TextArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowEmptyString()][string]$Content
    )

    Set-Content -LiteralPath $Path -Value $Content -Encoding UTF8
}

function Protect-ArtifactDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $grantRules = @(
        "*$currentUserSid`:(OI)(CI)F",
        "*S-1-5-18`:(OI)(CI)F",
        "*S-1-5-32-544`:(OI)(CI)F"
    )
    & icacls.exe $Path /inheritance:r /grant:r @grantRules 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "无法将验收产物目录限制为当前用户、SYSTEM 和 Administrators；已停止。"
    }
}

function Write-Manifest {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Value)

    $Value | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
}

function Get-ProcessTreeIds {
    param([Parameter(Mandatory = $true)][int]$RootProcessId)

    $seen = @{}
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($RootProcessId)
    $seen[$RootProcessId] = $true

    while ($queue.Count -gt 0) {
        $parentId = [int]$queue.Dequeue()
        try {
            $children = @(
                Get-CimInstance Win32_Process -Filter ("ParentProcessId = {0}" -f $parentId) -ErrorAction Stop |
                    Select-Object -ExpandProperty ProcessId
            )
        } catch {
            continue
        }

        foreach ($childId in $children) {
            $childId = [int]$childId
            if (-not $seen.ContainsKey($childId)) {
                $seen[$childId] = $true
                $queue.Enqueue($childId)
            }
        }
    }

    return @($seen.Keys | ForEach-Object { [int]$_ })
}

function Wait-ProcessIdsExit {
    param(
        [Parameter(Mandatory = $true)][int[]]$ProcessIds,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    do {
        $alive = @(
            $ProcessIds | Where-Object {
                $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue)
            }
        )
        if ($alive.Count -eq 0) {
            return $true
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)

    return $false
}

function Invoke-CapturedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [hashtable]$EnvironmentOverrides = @{}
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($entry in $EnvironmentOverrides.GetEnumerator()) {
        if ($null -eq $entry.Value) {
            [void]$startInfo.EnvironmentVariables.Remove([string]$entry.Key)
        } else {
            $startInfo.EnvironmentVariables[[string]$entry.Key] = [string]$entry.Value
        }
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    [void]$process.Start()

    $processTreeIds = @(Get-ProcessTreeIds -RootProcessId $process.Id)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $completed = $process.WaitForExit($TimeoutSeconds * 1000)
    $timedOut = -not $completed
    $processTreeIds = @(
        $processTreeIds + @(Get-ProcessTreeIds -RootProcessId $process.Id) |
            Sort-Object -Unique
    )
    $treeTerminationExitCode = $null
    $processTreeStopped = $true
    if ($timedOut) {
        try {
            & taskkill.exe /PID $process.Id /T /F 2>$null | Out-Null
            $treeTerminationExitCode = $LASTEXITCODE
        } catch {
            $treeTerminationExitCode = -1
        }

        $processTreeStopped = Wait-ProcessIdsExit -ProcessIds $processTreeIds -TimeoutMilliseconds 5000
        if (-not $processTreeStopped) {
            try {
                $processTreeIds = @(
                    $processTreeIds + @(Get-ProcessTreeIds -RootProcessId $process.Id) |
                        Sort-Object -Unique
                )
                foreach ($processId in ($processTreeIds | Sort-Object -Descending)) {
                    Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
                }
            } catch {
                # Preserve the timeout result and record the unproven tree state below.
            }
            $processTreeStopped = Wait-ProcessIdsExit -ProcessIds $processTreeIds -TimeoutMilliseconds 5000
        }
    } else {
        $processTreeStopped = Wait-ProcessIdsExit -ProcessIds $processTreeIds -TimeoutMilliseconds 5000
    }

    $stdoutCompleted = $false
    $stderrCompleted = $false
    try { $stdoutCompleted = $stdoutTask.Wait(5000) } catch { $stdoutCompleted = $false }
    try { $stderrCompleted = $stderrTask.Wait(5000) } catch { $stderrCompleted = $false }
    $outputDrainTimedOut = -not ($stdoutCompleted -and $stderrCompleted)
    if ($outputDrainTimedOut) {
        try { $process.StandardOutput.BaseStream.Close() } catch { }
        try { $process.StandardError.BaseStream.Close() } catch { }
    }
    if ($stdoutCompleted) {
        $stdout = $stdoutTask.GetAwaiter().GetResult()
    } else {
        $stdout = "[runner] stdout drain timed out; process tree termination was not fully proven."
    }
    if ($stderrCompleted) {
        $stderr = $stderrTask.GetAwaiter().GetResult()
    } else {
        $stderr = "[runner] stderr drain timed out; process tree termination was not fully proven."
    }
    Write-TextArtifact -Path $StdoutPath -Content $stdout
    Write-TextArtifact -Path $StderrPath -Content $stderr
    $exitCode = if ($timedOut) { 124 } else { $process.ExitCode }
    $process.Dispose()

    return [pscustomobject]@{
        ExitCode = $exitCode
        TimedOut = $timedOut
        ProcessTreeStopped = $processTreeStopped
        OutputDrainTimedOut = $outputDrainTimedOut
        TreeTerminationExitCode = $treeTerminationExitCode
        Stdout = $stdout
        Stderr = $stderr
    }
}

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)

    return '"' + ($Value -replace '"', '\"') + '"'
}

if (-not $ConfirmIsolatedTarget) {
    throw "必须显式传入 -ConfirmIsolatedTarget；该 runner 只允许可丢弃的隔离 PostgreSQL 验收目标。"
}

$approvalValues = @{
    ApprovedHost = $ApprovedHost
    ApprovedServerAddress = $ApprovedServerAddress
    ApprovedDatabase = $ApprovedDatabase
    ApprovedUser = $ApprovedUser
    MaintenanceDatabase = $MaintenanceDatabase
}
$missingApproval = @(
    $approvalValues.GetEnumerator() | Where-Object {
        [string]::IsNullOrWhiteSpace([string]$_.Value)
    } | ForEach-Object { $_.Key }
)
if ($missingApproval.Count -gt 0 -or $ApprovedPort -lt 1 -or $ApprovedPort -gt 65535) {
    throw "必须提供有效的批准主机、服务器地址、端口、数据库、用户和维护库；不会读取或输出密码。"
}
if ($ApprovedDatabase -eq $MaintenanceDatabase) {
    throw "批准目标数据库不能与维护数据库相同。"
}
if ($MaintenanceDatabase -cne "postgres") {
    throw "当前 Django PostgreSQL 测试 runner 只支持使用 postgres 作为维护库；其他维护库会触发 Django 的未指定回退连接。"
}
$loopbackHosts = @("localhost", "127.0.0.1", "::1")
if ($loopbackHosts -notcontains $ApprovedHost.ToLowerInvariant() -or
    $loopbackHosts -notcontains $ApprovedServerAddress.ToLowerInvariant()) {
    throw "当前本地 runner 只允许 loopback 验收目标；远程 PostgreSQL 需要单独的 TLS/证书和目标绑定合同。"
}

foreach ($path in @($python, $manage, $preflight)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "项目验收依赖不存在：$path。"
    }
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmssfff")
    $artifactDirectory = Join-Path $artifactRoot "$timestamp-$([guid]::NewGuid().ToString('N'))"
} else {
    $artifactDirectory = $OutputDirectory
    if (-not [IO.Path]::IsPathRooted($artifactDirectory)) {
        $artifactDirectory = Join-Path $root $artifactDirectory
    }
    $artifactDirectory = [IO.Path]::GetFullPath($artifactDirectory)
}

$artifactDirectory = [IO.Path]::GetFullPath($artifactDirectory).TrimEnd('\', '/')
$artifactRootPrefix = $artifactRoot + [IO.Path]::DirectorySeparatorChar
if (-not $artifactDirectory.StartsWith($artifactRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "产物目录必须位于 output\postgresql-concurrency 下，避免污染项目文件。"
}

if (Test-Path -LiteralPath $artifactDirectory) {
    throw "产物目录已经存在，为避免覆盖旧证据请提供新的目录：$artifactDirectory"
}

$manifest = $null
try {
    $artifactParent = Split-Path -Parent $artifactDirectory
    New-Item -ItemType Directory -Path $artifactParent -Force | Out-Null
    New-Item -ItemType Directory -Path $artifactDirectory -ErrorAction Stop | Out-Null
    Protect-ArtifactDirectory -Path $artifactDirectory

    $manifestPath = Join-Path $artifactDirectory "manifest.json"
    $manifest = [ordered]@{
        schema_version = 1
        status = "running"
        started_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        finished_at_utc = $null
        commit = $null
        branch = $null
        worktree_status = "not_checked"
        approved_host = $ApprovedHost
        approved_server_address = $ApprovedServerAddress
        approved_port = $ApprovedPort
        approved_database = $ApprovedDatabase
        approved_user = $ApprovedUser
        maintenance_database = $MaintenanceDatabase
        process_timeout_seconds = $ProcessTimeoutSeconds
        expected_test_database = $null
        test_database_reserved = $false
        test_database_cleanup_required = $false
        test_database_reservation_uncertain = $false
        test_database_exists_after_cleanup = $null
        preflight_config_stdout = "preflight-config.stdout.txt"
        preflight_config_stderr = "preflight-config.stderr.txt"
        preflight_connection_stdout = "preflight-connection.stdout.txt"
        preflight_connection_stderr = "preflight-connection.stderr.txt"
        git_head_stderr = "git-head.stderr.txt"
        git_status_stderr = "git-status.stderr.txt"
        git_final_head_stderr = "git-final-head.stderr.txt"
        git_final_status_stderr = "git-final-status.stderr.txt"
        identity_stdout = "identity.stdout.txt"
        identity_stderr = "identity.stderr.txt"
        identity_script = "identity.py"
        database_lifecycle_script = "database-lifecycle.py"
        test_settings_script = "test-settings.py"
        reserve_stdout = "reserve.stdout.txt"
        reserve_stderr = "reserve.stderr.txt"
        tests_stdout = "tests.stdout.txt"
        tests_stderr = "tests.stderr.txt"
        cleanup_stdout = "cleanup.stdout.txt"
        cleanup_stderr = "cleanup.stderr.txt"
        cleanup_check_stdout = "cleanup-check.stdout.txt"
        cleanup_check_stderr = "cleanup-check.stderr.txt"
        artifact_acl_hardened = $true
    }
    Write-Manifest -Value $manifest

    $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
    $scriptArguments = "-NoProfile -ExecutionPolicy Bypass -File $(Quote-ProcessArgument -Value $preflight)"

    $preflightConfig = Invoke-CapturedProcess `
        -FilePath $powershell `
        -Arguments $scriptArguments `
        -WorkingDirectory $root `
        -StdoutPath (Join-Path $artifactDirectory $manifest.preflight_config_stdout) `
        -StderrPath (Join-Path $artifactDirectory $manifest.preflight_config_stderr) `
        -TimeoutSeconds $ProcessTimeoutSeconds
    if ($preflightConfig.ExitCode -ne 0 -or
        -not [bool]$preflightConfig.ProcessTreeStopped -or
        [bool]$preflightConfig.OutputDrainTimedOut) {
        throw "PostgreSQL 配置预检失败；未连接数据库，详见 $artifactDirectory。"
    }

    $configuredHost = [Environment]::GetEnvironmentVariable("DATABASE_HOST")
    $configuredPortText = [Environment]::GetEnvironmentVariable("DATABASE_PORT")
    $configuredDatabase = [Environment]::GetEnvironmentVariable("DATABASE_NAME")
    $configuredUser = [Environment]::GetEnvironmentVariable("DATABASE_USER")
    $configuredPort = 0
    if (-not [int]::TryParse($configuredPortText, [ref]$configuredPort)) {
        throw "DATABASE_PORT 不是有效整数；未执行测试。"
    }
    if ($configuredHost -cne $ApprovedHost -or
        $configuredPort -ne $ApprovedPort -or
        $configuredDatabase -cne $ApprovedDatabase -or
        $configuredUser -cne $ApprovedUser) {
        throw "当前进程配置与批准的隔离目标不一致；未连接数据库，未执行测试。"
    }

    $gitHeadItems = @(& git -C $root rev-parse --verify HEAD 2> (Join-Path $artifactDirectory $manifest.git_head_stderr))
    $gitHeadExitCode = $LASTEXITCODE
    $gitHead = (Convert-ToText $gitHeadItems).Trim()
    if ($gitHeadExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($gitHead)) {
        $manifest.worktree_status = "git_head_unavailable"
        Write-Manifest -Value $manifest
        throw "Git HEAD 无法读取；未连接数据库，未执行测试。"
    }

    $gitStatusItems = @(& git -C $root status --porcelain --untracked-files=all 2> (Join-Path $artifactDirectory $manifest.git_status_stderr))
    $gitStatusExitCode = $LASTEXITCODE
    $gitStatus = (Convert-ToText $gitStatusItems).Trim()
    if ($gitStatusExitCode -ne 0) {
        $manifest.commit = $gitHead
        $manifest.worktree_status = "status_unavailable"
        Write-Manifest -Value $manifest
        throw "Git 工作区状态无法核对；未连接数据库，未执行测试。"
    }
    if (-not [string]::IsNullOrWhiteSpace($gitStatus)) {
        $manifest.commit = $gitHead
        $manifest.worktree_status = "dirty"
        Write-Manifest -Value $manifest
        throw "Git 工作区不是干净状态；未连接数据库，未执行测试。"
    }

    $branchItems = @(& git -C $root branch --show-current 2> (Join-Path $artifactDirectory $manifest.git_head_stderr))
    $branchExitCode = $LASTEXITCODE
    $branch = (Convert-ToText $branchItems).Trim()
    if ($branchExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($branch)) {
        $manifest.commit = $gitHead
        $manifest.worktree_status = "branch_unavailable"
        Write-Manifest -Value $manifest
        throw "Git 当前分支无法读取；未连接数据库，未执行测试。"
    }
    $manifest.commit = $gitHead
    $manifest.branch = $branch
    $manifest.worktree_status = "clean"
    Write-Manifest -Value $manifest

    $connectionArguments = "-NoProfile -ExecutionPolicy Bypass -File $(Quote-ProcessArgument -Value $preflight) -CheckConnection"
    $preflightConnection = Invoke-CapturedProcess `
        -FilePath $powershell `
        -Arguments $connectionArguments `
        -WorkingDirectory $root `
        -StdoutPath (Join-Path $artifactDirectory $manifest.preflight_connection_stdout) `
        -StderrPath (Join-Path $artifactDirectory $manifest.preflight_connection_stderr) `
        -TimeoutSeconds $ProcessTimeoutSeconds
    if ($preflightConnection.ExitCode -ne 0 -or
        -not [bool]$preflightConnection.ProcessTreeStopped -or
        [bool]$preflightConnection.OutputDrainTimedOut) {
        throw "PostgreSQL 只读连接预检失败；未执行测试，详见 $artifactDirectory。"
    }

    $identityCode = @'
import json
import os
import sys

import psycopg


def snapshot(database_name):
    with psycopg.connect(
        host=os.environ["DATABASE_HOST"],
        port=int(os.environ["DATABASE_PORT"]),
        dbname=database_name,
        user=os.environ["DATABASE_USER"],
        password=os.environ["DATABASE_PASSWORD"],
        connect_timeout=5,
        options="-c default_transaction_read_only=on",
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    current_database(),
                    current_user,
                    COALESCE(host(inet_server_addr()), ''),
                    inet_server_port(),
                    (SELECT rolcreatedb FROM pg_roles WHERE rolname = current_user),
                    (SELECT rolsuper FROM pg_roles WHERE rolname = current_user),
                    (SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user),
                    (SELECT rolreplication FROM pg_roles WHERE rolname = current_user),
                    (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user),
                    has_database_privilege(current_user, current_database(), 'CONNECT')
                """
            )
            database, user, address, port, createdb, superuser, createrole, replication, bypassrls, can_connect = cursor.fetchone()
    return {
        "database": database,
        "user": user,
        "server_address": address,
        "server_port": port,
        "role_createdb": bool(createdb),
        "role_superuser": bool(superuser),
        "role_createrole": bool(createrole),
        "role_replication": bool(replication),
        "role_bypassrls": bool(bypassrls),
        "can_connect": bool(can_connect),
    }


try:
    target_database = os.environ["DATABASE_NAME"]
    maintenance_database = os.environ["RUNNER_MAINTENANCE_DATABASE"]
    target = snapshot(target_database)
    maintenance = snapshot(maintenance_database)
    print(json.dumps({
        "target": target,
        "maintenance": maintenance,
    }, sort_keys=True))
except (psycopg.Error, KeyError, ValueError, TypeError):
    print("PostgreSQL identity or maintenance preflight failed; details are intentionally not printed.", file=sys.stderr)
    raise SystemExit(1)
'@

    $identityScriptPath = Join-Path $artifactDirectory $manifest.identity_script
    Write-TextArtifact -Path $identityScriptPath -Content $identityCode
    $oldMaintenanceDatabase = [Environment]::GetEnvironmentVariable("RUNNER_MAINTENANCE_DATABASE", "Process")
    [Environment]::SetEnvironmentVariable("RUNNER_MAINTENANCE_DATABASE", $MaintenanceDatabase, "Process")
    try {
        $identityArguments = Quote-ProcessArgument -Value $identityScriptPath
        $identityResult = Invoke-CapturedProcess `
            -FilePath $python `
            -Arguments $identityArguments `
            -WorkingDirectory $root `
            -StdoutPath (Join-Path $artifactDirectory $manifest.identity_stdout) `
            -StderrPath (Join-Path $artifactDirectory $manifest.identity_stderr) `
            -TimeoutSeconds $ProcessTimeoutSeconds
        $identityExitCode = $identityResult.ExitCode
        $identityOutput = $identityResult.Stdout
        $manifest.identity_process = [ordered]@{
            exit_code = $identityResult.ExitCode
            timed_out = [bool]$identityResult.TimedOut
            process_tree_stopped = [bool]$identityResult.ProcessTreeStopped
            output_drain_timed_out = [bool]$identityResult.OutputDrainTimedOut
        }
        Write-Manifest -Value $manifest
    } finally {
        [Environment]::SetEnvironmentVariable("RUNNER_MAINTENANCE_DATABASE", $oldMaintenanceDatabase, "Process")
    }
    if ($identityExitCode -ne 0 -or
        -not [bool]$identityResult.ProcessTreeStopped -or
        [bool]$identityResult.OutputDrainTimedOut) {
        throw "PostgreSQL 身份或维护库权限预检失败；未执行测试，详见 $artifactDirectory。"
    }

    try {
        $identity = $identityOutput | ConvertFrom-Json
    } catch {
        throw "身份预检没有返回可解析结果；未执行测试，详见 $artifactDirectory。"
    }

    $targetIdentity = $identity.target
    $maintenanceIdentity = $identity.maintenance
    if ($targetIdentity.database -cne $ApprovedDatabase -or
        $targetIdentity.user -cne $ApprovedUser -or
        $targetIdentity.server_address -cne $ApprovedServerAddress -or
        [int]$targetIdentity.server_port -ne $ApprovedPort -or
        -not [bool]$targetIdentity.can_connect -or
        $maintenanceIdentity.database -cne $MaintenanceDatabase -or
        $maintenanceIdentity.user -cne $ApprovedUser -or
        $maintenanceIdentity.server_address -cne $ApprovedServerAddress -or
        [int]$maintenanceIdentity.server_port -ne $ApprovedPort -or
        -not [bool]$maintenanceIdentity.can_connect -or
        -not [bool]$maintenanceIdentity.role_createdb -or
        [bool]$maintenanceIdentity.role_superuser -or
        [bool]$maintenanceIdentity.role_createrole -or
        [bool]$maintenanceIdentity.role_replication -or
        [bool]$maintenanceIdentity.role_bypassrls) {
        throw "PostgreSQL 实际身份或维护库权限不符合批准门禁；未执行测试。"
    }

    $runId = [guid]::NewGuid().ToString("N")
    $testDatabaseName = "test_runner_$runId"
    $testSettingsModule = "postgresql_runner_settings_$runId"
    $manifest.test_settings_script = "$testSettingsModule.py"
    $manifest.expected_test_database = $testDatabaseName

    $manifest.identity = [ordered]@{
        target_database = $targetIdentity.database
        target_user = $targetIdentity.user
        target_server_address = $targetIdentity.server_address
        target_server_port = [int]$targetIdentity.server_port
        maintenance_database = $maintenanceIdentity.database
        maintenance_user = $maintenanceIdentity.user
        maintenance_server_address = $maintenanceIdentity.server_address
        maintenance_server_port = [int]$maintenanceIdentity.server_port
        role_createdb = [bool]$maintenanceIdentity.role_createdb
        role_superuser = [bool]$maintenanceIdentity.role_superuser
        role_createrole = [bool]$maintenanceIdentity.role_createrole
        role_replication = [bool]$maintenanceIdentity.role_replication
        role_bypassrls = [bool]$maintenanceIdentity.role_bypassrls
        expected_test_database = $testDatabaseName
    }
    Write-Manifest -Value $manifest

    $lifecycleCode = @'
import json
import os
import sys

import psycopg
from psycopg import sql


def connect():
    connection = psycopg.connect(
        host=os.environ["DATABASE_HOST"],
        port=int(os.environ["DATABASE_PORT"]),
        dbname=os.environ["RUNNER_MAINTENANCE_DATABASE"],
        user=os.environ["DATABASE_USER"],
        password=os.environ["DATABASE_PASSWORD"],
        connect_timeout=5,
    )
    connection.autocommit = True
    return connection


def main():
    mode = sys.argv[1]
    database_name = sys.argv[2]
    with connect() as connection:
        with connection.cursor() as cursor:
            if mode == "reserve":
                cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database_name)))
                print(json.dumps({"database": database_name, "action": "reserved"}, sort_keys=True))
            elif mode == "drop":
                cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(database_name)))
                print(json.dumps({"database": database_name, "action": "dropped"}, sort_keys=True))
            elif mode == "check_absent":
                cursor.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = %s)",
                    (database_name,),
                )
                exists = bool(cursor.fetchone()[0])
                print(json.dumps({"database": database_name, "exists": exists}, sort_keys=True))
                return 1 if exists else 0
            else:
                raise ValueError("unsupported lifecycle mode")
    return 0


try:
    raise SystemExit(main())
except (psycopg.Error, KeyError, ValueError, IndexError, TypeError):
    print("PostgreSQL test database lifecycle operation failed; details are intentionally not printed.", file=sys.stderr)
    raise SystemExit(1)
'@
    $lifecycleScriptPath = Join-Path $artifactDirectory $manifest.database_lifecycle_script
    Write-TextArtifact -Path $lifecycleScriptPath -Content $lifecycleCode

    $testSettingsCode = @"
from authorization_platform.settings import *  # noqa: F401,F403

DATABASES["default"]["TEST"] = {"NAME": "$testDatabaseName"}
"@
    $testSettingsScriptPath = Join-Path $artifactDirectory $manifest.test_settings_script
    Write-TextArtifact -Path $testSettingsScriptPath -Content $testSettingsCode

    $testFailure = $null
    $cleanupFailure = $null
    $testDatabaseReserved = $false
    $testDatabaseCleanupRequired = $false
    [Environment]::SetEnvironmentVariable("RUNNER_MAINTENANCE_DATABASE", $MaintenanceDatabase, "Process")
    try {
        $testDatabaseCleanupRequired = $true
        $manifest.test_database_cleanup_required = $true
        Write-Manifest -Value $manifest
        $reserveArguments = "$(Quote-ProcessArgument -Value $lifecycleScriptPath) reserve $(Quote-ProcessArgument -Value $testDatabaseName)"
        $reserveResult = Invoke-CapturedProcess `
            -FilePath $python `
            -Arguments $reserveArguments `
            -WorkingDirectory $root `
            -StdoutPath (Join-Path $artifactDirectory $manifest.reserve_stdout) `
            -StderrPath (Join-Path $artifactDirectory $manifest.reserve_stderr) `
            -TimeoutSeconds $ProcessTimeoutSeconds
        $manifest.reserve_result = [ordered]@{
            exit_code = $reserveResult.ExitCode
            timed_out = [bool]$reserveResult.TimedOut
            process_tree_stopped = [bool]$reserveResult.ProcessTreeStopped
            output_drain_timed_out = [bool]$reserveResult.OutputDrainTimedOut
        }
        if ($reserveResult.ExitCode -ne 0 -or
            -not [bool]$reserveResult.ProcessTreeStopped -or
            [bool]$reserveResult.OutputDrainTimedOut) {
            $manifest.test_database_reservation_uncertain = [bool]$reserveResult.TimedOut -or
                -not [bool]$reserveResult.ProcessTreeStopped -or
                [bool]$reserveResult.OutputDrainTimedOut
            $testFailure = "PostgreSQL 测试库无法以原子方式预留；未执行并发测试，详见 $artifactDirectory。"
        } else {
            $testDatabaseReserved = $true
            $manifest.test_database_reserved = $true
            Write-Manifest -Value $manifest

            $pythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH", "Process")
            $testEnvironment = @{
                PYTHONPATH = if ([string]::IsNullOrWhiteSpace($pythonPath)) {
                    $artifactDirectory
                } else {
                    "$artifactDirectory;$pythonPath"
                }
            }
            $testArguments = "$(Quote-ProcessArgument -Value $manage) test --settings $(Quote-ProcessArgument -Value $testSettingsModule) tests.test_accounts.InvitationConcurrencyTests tests.test_credits.CreditConcurrencyTests tests.test_licensing.LicenseConcurrencyTests tests.test_authorization.AuthorizationConcurrencyTests --keepdb --verbosity 2"
            $testResult = Invoke-CapturedProcess `
                -FilePath $python `
                -Arguments $testArguments `
                -WorkingDirectory $root `
                -StdoutPath (Join-Path $artifactDirectory $manifest.tests_stdout) `
                -StderrPath (Join-Path $artifactDirectory $manifest.tests_stderr) `
                -TimeoutSeconds $ProcessTimeoutSeconds `
                -EnvironmentOverrides $testEnvironment

            $testText = "$($testResult.Stdout)`n$($testResult.Stderr)"
            $ranMatch = [regex]::Match($testText, '(?m)^\s*Ran\s+(\d+)\s+tests?\s+in\s+')
            $skipped = 0
            $skippedMatch = [regex]::Match($testText, '(?i)\bskipped=(\d+)\b')
            if ($skippedMatch.Success) {
                $skipped = [int]$skippedMatch.Groups[1].Value
            }
            $ran = if ($ranMatch.Success) { [int]$ranMatch.Groups[1].Value } else { -1 }
            $manifest.test_result = [ordered]@{
                exit_code = $testResult.ExitCode
                timed_out = [bool]$testResult.TimedOut
                process_tree_stopped = [bool]$testResult.ProcessTreeStopped
                output_drain_timed_out = [bool]$testResult.OutputDrainTimedOut
                ran = $ran
                skipped = $skipped
            }
            if ($testResult.ExitCode -ne 0 -or
                -not [bool]$testResult.ProcessTreeStopped -or
                [bool]$testResult.OutputDrainTimedOut -or
                $ran -ne 21 -or
                $skipped -ne 0 -or
                $testText -notmatch '(?m)^\s*OK(?:\s|$)') {
                $testFailure = "PostgreSQL 并发验收未满足 21 项通过、0 skip、0 错误的门禁；详见 $artifactDirectory。"
            }
            Write-Manifest -Value $manifest
        }
    } finally {
        if ($testDatabaseCleanupRequired) {
            try {
                $cleanupArguments = "$(Quote-ProcessArgument -Value $lifecycleScriptPath) drop $(Quote-ProcessArgument -Value $testDatabaseName)"
                $cleanupResult = Invoke-CapturedProcess `
                    -FilePath $python `
                    -Arguments $cleanupArguments `
                    -WorkingDirectory $root `
                    -StdoutPath (Join-Path $artifactDirectory $manifest.cleanup_stdout) `
                    -StderrPath (Join-Path $artifactDirectory $manifest.cleanup_stderr) `
                    -TimeoutSeconds $ProcessTimeoutSeconds
                $manifest.cleanup_result = [ordered]@{
                    exit_code = $cleanupResult.ExitCode
                    timed_out = [bool]$cleanupResult.TimedOut
                    process_tree_stopped = [bool]$cleanupResult.ProcessTreeStopped
                    output_drain_timed_out = [bool]$cleanupResult.OutputDrainTimedOut
                }
                if ($cleanupResult.ExitCode -ne 0 -or
                    -not [bool]$cleanupResult.ProcessTreeStopped -or
                    [bool]$cleanupResult.OutputDrainTimedOut) {
                    $cleanupFailure = "PostgreSQL 测试库清理未被证明成功；详见 $artifactDirectory。"
                }
            } catch {
                $cleanupFailure = "PostgreSQL 测试库清理执行失败；详见 $artifactDirectory。"
            }

            try {
                $cleanupCheckArguments = "$(Quote-ProcessArgument -Value $lifecycleScriptPath) check_absent $(Quote-ProcessArgument -Value $testDatabaseName)"
                $cleanupCheckResult = Invoke-CapturedProcess `
                    -FilePath $python `
                    -Arguments $cleanupCheckArguments `
                    -WorkingDirectory $root `
                    -StdoutPath (Join-Path $artifactDirectory $manifest.cleanup_check_stdout) `
                    -StderrPath (Join-Path $artifactDirectory $manifest.cleanup_check_stderr) `
                    -TimeoutSeconds $ProcessTimeoutSeconds
                $cleanupCheck = $cleanupCheckResult.Stdout | ConvertFrom-Json
                $manifest.test_database_exists_after_cleanup = [bool]$cleanupCheck.exists
                $manifest.cleanup_check_result = [ordered]@{
                    exit_code = $cleanupCheckResult.ExitCode
                    timed_out = [bool]$cleanupCheckResult.TimedOut
                    process_tree_stopped = [bool]$cleanupCheckResult.ProcessTreeStopped
                    output_drain_timed_out = [bool]$cleanupCheckResult.OutputDrainTimedOut
                    exists = [bool]$cleanupCheck.exists
                }
                if ($cleanupCheckResult.ExitCode -ne 0 -or
                    -not [bool]$cleanupCheckResult.ProcessTreeStopped -or
                    [bool]$cleanupCheckResult.OutputDrainTimedOut -or
                    [bool]$cleanupCheck.exists) {
                    $cleanupFailure = "PostgreSQL 测试库清理后仍存在或无法核对；详见 $artifactDirectory。"
                }
            } catch {
                $manifest.test_database_exists_after_cleanup = $null
                $cleanupFailure = "PostgreSQL 测试库清理后的残留检查失败；详见 $artifactDirectory。"
            }
            Write-Manifest -Value $manifest
        }
        [Environment]::SetEnvironmentVariable("RUNNER_MAINTENANCE_DATABASE", $oldMaintenanceDatabase, "Process")
    }

    if ($null -ne $cleanupFailure) {
        throw $cleanupFailure
    }
    if ($null -ne $testFailure) {
        throw $testFailure
    }

    $finalHeadItems = @(& git -C $root rev-parse --verify HEAD 2> (Join-Path $artifactDirectory $manifest.git_final_head_stderr))
    $finalHeadExitCode = $LASTEXITCODE
    $finalHead = (Convert-ToText $finalHeadItems).Trim()
    $finalStatusItems = @(& git -C $root status --porcelain --untracked-files=all 2> (Join-Path $artifactDirectory $manifest.git_final_status_stderr))
    $finalStatusExitCode = $LASTEXITCODE
    $finalStatus = (Convert-ToText $finalStatusItems).Trim()
    $manifest.final_commit = $finalHead
    $manifest.final_worktree_status = if ([string]::IsNullOrWhiteSpace($finalStatus)) { "clean" } else { "dirty" }
    Write-Manifest -Value $manifest
    if ($finalHeadExitCode -ne 0 -or
        $finalStatusExitCode -ne 0 -or
        [string]::IsNullOrWhiteSpace($finalHead) -or
        $finalHead -cne $manifest.commit -or
        -not [string]::IsNullOrWhiteSpace($finalStatus)) {
        throw "运行期间 Git HEAD 或工作区发生变化；验收结果不可信，未通过。"
    }

    $manifest.status = "passed"
    $manifest.finished_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    Write-Manifest -Value $manifest
    Write-Output "PostgreSQL 并发验收通过：21 项实际运行，0 skip。产物：$artifactDirectory"
} catch {
    if ($null -ne $manifest) {
        $manifest.status = "failed"
        $manifest.finished_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        $manifest.failure = "fail-closed; inspect the saved stdout/stderr artifacts"
        try {
            Write-Manifest -Value $manifest
        } catch {
            # 保留原始失败结果；manifest 写入失败不应掩盖门禁失败。
        }
    }
    Write-Error $_.Exception.Message
    exit 1
}
