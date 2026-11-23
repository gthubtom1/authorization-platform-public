[CmdletBinding()]
param(
    [switch]$CheckConnection
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "项目虚拟环境不存在，请先运行 scripts\bootstrap.ps1。"
}

$engine = [Environment]::GetEnvironmentVariable("DATABASE_ENGINE")
if ([string]::IsNullOrWhiteSpace($engine) -or $engine.Trim().ToLowerInvariant() -ne "postgresql") {
    $mode = if ([string]::IsNullOrWhiteSpace($engine)) { "未设置" } else { $engine.Trim() }
    throw "PostgreSQL 预检要求显式设置 DATABASE_ENGINE=postgresql；当前值：$mode。"
}

$required = @(
    "DATABASE_HOST",
    "DATABASE_PORT",
    "DATABASE_NAME",
    "DATABASE_USER",
    "DATABASE_PASSWORD"
)
$missing = @(
    $required | Where-Object {
        [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_))
    }
)
if ($missing.Count -gt 0) {
    throw "缺少 PostgreSQL 环境变量：$($missing -join ', ')。密码只检查是否存在，不会输出密码。"
}

$port = 0
$portText = [Environment]::GetEnvironmentVariable("DATABASE_PORT")
if (-not [int]::TryParse($portText, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
    throw "DATABASE_PORT 必须是 1 至 65535 的整数。"
}

if ($CheckConnection) {
    $connectionScript = @'
import os
import sys

import psycopg


try:
    with psycopg.connect(
        host=os.environ["DATABASE_HOST"],
        port=int(os.environ["DATABASE_PORT"]),
        dbname=os.environ["DATABASE_NAME"],
        user=os.environ["DATABASE_USER"],
        password=os.environ["DATABASE_PASSWORD"],
        connect_timeout=5,
        options="-c default_transaction_read_only=on",
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database(), current_user")
            database, user = cursor.fetchone()
    print(f"PostgreSQL connection OK: database={database}; user={user}")
except psycopg.Error:
    print("PostgreSQL connection failed; details are intentionally not printed.", file=sys.stderr)
    raise SystemExit(1)
'@
    $connectionScriptPath = Join-Path ([IO.Path]::GetTempPath()) ("authorization-platform-postgresql-preflight-" + [guid]::NewGuid().ToString("N") + ".py")
    $connectionExitCode = 1
    try {
        [IO.File]::WriteAllText($connectionScriptPath, $connectionScript, [Text.UTF8Encoding]::new($false))
        & $python $connectionScriptPath
        $connectionExitCode = $LASTEXITCODE
    } finally {
        Remove-Item -LiteralPath $connectionScriptPath -Force -ErrorAction SilentlyContinue
    }
    if ($connectionExitCode -ne 0) {
        throw "PostgreSQL 连接预检失败；未执行迁移或业务写入。"
    }
}

$connectionMode = if ($CheckConnection) { "已连接并保持只读事务" } else { "仅配置检查，未连接数据库" }
Write-Output "PostgreSQL 预检通过：$connectionMode。"
