[CmdletBinding()]
param(
    [int]$FrontendPort = 8123,
    [int]$BackendPort = 8000
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "项目虚拟环境不存在，请先运行 scripts\bootstrap.ps1"
}

$backend = $null
try {
    & $python (Join-Path $root "manage.py") migrate --noinput
    if ($LASTEXITCODE -ne 0) {
        throw "Django 迁移失败，退出码 $LASTEXITCODE。"
    }

    $backend = Start-Process -FilePath $python `
        -ArgumentList @((Join-Path $root "manage.py"), "runserver", "127.0.0.1:$BackendPort", "--noreload", "--insecure") `
        -WorkingDirectory $root `
        -WindowStyle Hidden `
        -PassThru

    $backendHealth = "http://127.0.0.1:$BackendPort/healthz/"
    $backendReady = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($backend.HasExited) {
            throw "Django 本地服务提前退出，退出码 $($backend.ExitCode)。"
        }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $backendHealth -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                $backendReady = $true
                break
            }
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $backendReady) {
        throw "Django 本地服务未能在限定时间内通过健康检查。"
    }

    & $python (Join-Path $root "scripts\static_proxy.py") `
        --bind 127.0.0.1 `
        --port $FrontendPort `
        --directory (Join-Path $root "docs\ui-preview") `
        --backend-host 127.0.0.1 `
        --backend-port $BackendPort
    if ($LASTEXITCODE -ne 0) {
        throw "8123 同源网关退出，退出码 $LASTEXITCODE。"
    }
} finally {
    if ($backend -and -not $backend.HasExited) {
        Stop-Process -Id $backend.Id -Force
    }
}
