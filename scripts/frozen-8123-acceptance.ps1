[CmdletBinding()]
param(
    [int]$FrontendPort = 8123,
    [int]$BackendPort = 8000,
    [switch]$KeepArtifacts,
    [switch]$B4,
    [switch]$B5
)

$ErrorActionPreference = "Stop"
if ($B4 -and $B5) {
    throw "B4 和 B5 验收不能同时运行。"
}
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "项目虚拟环境不存在，请先运行 scripts\bootstrap.ps1"
}
if (-not (Get-Command npx.cmd -ErrorAction SilentlyContinue)) {
    throw "npx 不存在；请先安装 Node.js/npm。"
}

$artifactDir = Join-Path $root "output\playwright\frozen-8123"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("authorization-platform-b22-" + [Guid]::NewGuid().ToString("N"))
$fixturePath = Join-Path $tempRoot "fixture.json"
$backendOut = Join-Path $tempRoot "backend.stdout.log"
$backendErr = Join-Path $tempRoot "backend.stderr.log"
$proxyOut = Join-Path $tempRoot "proxy.stdout.log"
$proxyErr = Join-Path $tempRoot "proxy.stderr.log"
$databasePath = Join-Path $tempRoot "acceptance.sqlite3"
$backend = $null
$proxy = $null
$sessions = @()
$envNames = @("APP_ENV", "DATABASE_ENGINE", "DATABASE_NAME", "DJANGO_DEBUG", "ALLOWED_HOSTS", "CSRF_TRUSTED_ORIGINS")
$originalEnv = @{}
foreach ($name in $envNames) {
    $originalEnv[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

function Invoke-ProjectPython {
    param([string[]]$Arguments)
    & $python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $($LASTEXITCODE): $($Arguments -join ' ')"
    }
}

function Invoke-Playwright {
    param([string[]]$Arguments)
    $output = & npx.cmd --yes --package "@playwright/cli" playwright-cli @Arguments 2>&1
    $output | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "Playwright command failed with exit code $($LASTEXITCODE): $($Arguments -join ' ')"
    }
    return ($output -join [Environment]::NewLine)
}

function Wait-Http200 {
    param([string]$Url)
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
            if ($response.StatusCode -eq 200) { return }
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    throw "本地服务未能在限定时间内返回 200：$Url"
}

New-Item -ItemType Directory -Force -Path $tempRoot, $artifactDir | Out-Null
try {
    [Environment]::SetEnvironmentVariable("APP_ENV", "local", "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_ENGINE", "sqlite", "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_NAME", $databasePath, "Process")
    [Environment]::SetEnvironmentVariable("DJANGO_DEBUG", "false", "Process")
    [Environment]::SetEnvironmentVariable("ALLOWED_HOSTS", "127.0.0.1,localhost", "Process")
    [Environment]::SetEnvironmentVariable("CSRF_TRUSTED_ORIGINS", "http://127.0.0.1:$FrontendPort,http://localhost:$FrontendPort", "Process")

    Invoke-ProjectPython @((Join-Path $root "manage.py"), "migrate", "--noinput", "--verbosity", "0")
    Invoke-ProjectPython @((Join-Path $root "scripts\prepare_browser_acceptance.py"), "--output", $fixturePath)
    $fixture = Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json

    $backend = Start-Process -FilePath $python `
        -ArgumentList @((Join-Path $root "manage.py"), "runserver", "127.0.0.1:$BackendPort", "--noreload", "--insecure") `
        -WorkingDirectory $root `
        -WindowStyle Hidden `
        -RedirectStandardOutput $backendOut `
        -RedirectStandardError $backendErr `
        -PassThru
    Wait-Http200 "http://127.0.0.1:$BackendPort/healthz/"

    $proxy = Start-Process -FilePath $python `
        -ArgumentList @((Join-Path $root "scripts\static_proxy.py"), "--bind", "127.0.0.1", "--port", $FrontendPort, "--directory", (Join-Path $root "docs\ui-preview"), "--backend-host", "127.0.0.1", "--backend-port", $BackendPort) `
        -WorkingDirectory $root `
        -WindowStyle Hidden `
        -RedirectStandardOutput $proxyOut `
        -RedirectStandardError $proxyErr `
        -PassThru
    $baseUrl = "http://127.0.0.1:$FrontendPort"
    Wait-Http200 "$baseUrl/healthz/"
    Wait-Http200 "$baseUrl/manage.html"
    Wait-Http200 "$baseUrl/api/v1/session/"

    $source = Get-Content -LiteralPath (Join-Path $root "scripts\frozen_8123_acceptance.js") -Raw
    $flows = if ($B5) { @("b5") } elseif ($B4) { @("b4") } else { @("admin", "downstream-a", "downstream-b") }
    foreach ($flow in $flows) {
        $session = "frozen-8123-$flow-$FrontendPort"
        $sessions += $session
        $config = [ordered]@{
            base = $baseUrl
            flow = $flow
            fixture = $fixture
            artifact_dir = ($artifactDir -replace "\\", "/")
        } | ConvertTo-Json -Compress
        $code = "async (page) => {`nconst config = $config;`n$source`n}"
        $codePath = Join-Path $tempRoot ("frozen-8123-" + $flow + ".js")
        [IO.File]::WriteAllText($codePath, $code, [Text.UTF8Encoding]::new($false))
        Invoke-Playwright @("--session", $session, "open", "$baseUrl/manage.html")
        $runOutput = Invoke-Playwright @("--session", $session, "run-code", "--filename", $codePath)
        $marker = if ($B5) { "B5 frozen 8123 acceptance passed: $flow" } elseif ($B4) { "B4 frozen 8123 acceptance passed: $flow" } else { "B2.2 frozen 8123 acceptance passed: $flow" }
        if ($runOutput -notmatch [regex]::Escape($marker)) {
            throw "Frozen 8123 flow $flow did not return a success marker."
        }
        Invoke-Playwright @("--session", $session, "close")
    }
    if ($B5) {
        Write-Output "B5 frozen 8123 browser acceptance passed: $artifactDir"
    } elseif ($B4) {
        Write-Output "B4 frozen 8123 browser acceptance passed: $artifactDir"
    } else {
        Write-Output "B2.2 frozen 8123 browser acceptance passed (local sqlite; catalog first-page wait only; not pagination drain proof): $artifactDir"
    }
} finally {
    foreach ($session in $sessions) {
        try { Invoke-Playwright @("--session", $session, "close") } catch { }
    }
    if ($proxy -and -not $proxy.HasExited) { Stop-Process -Id $proxy.Id -Force }
    if ($backend -and -not $backend.HasExited) { Stop-Process -Id $backend.Id -Force }
    foreach ($name in $envNames) {
        [Environment]::SetEnvironmentVariable($name, $originalEnv[$name], "Process")
    }
    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $tempRoot)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
