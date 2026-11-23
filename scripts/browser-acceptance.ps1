[CmdletBinding()]
param(
    [int]$Port = 8030,
    [switch]$KeepArtifacts,
    [switch]$Mobile
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "项目虚拟环境不存在，请先运行 scripts\bootstrap.ps1"
}
if (-not (Get-Command npx.cmd -ErrorAction SilentlyContinue)) {
    throw "npx 不存在；请先安装 Node.js/npm。"
}

$artifactDir = Join-Path $root "output\playwright\browser-acceptance"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("authorization-platform-browser-" + [Guid]::NewGuid().ToString("N"))
$fixturePath = Join-Path $tempRoot "fixture.json"
$databasePath = Join-Path $tempRoot "acceptance.sqlite3"
$serverOut = Join-Path $tempRoot "server.stdout.log"
$serverErr = Join-Path $tempRoot "server.stderr.log"
$server = $null
$sessions = @()
$envNames = @(
    "APP_ENV",
    "DATABASE_ENGINE",
    "DATABASE_NAME",
    "DJANGO_DEBUG",
    "ALLOWED_HOSTS",
    "BROWSER_ACCEPTANCE_BASE_URL",
    "BROWSER_ACCEPTANCE_FIXTURE_JSON",
    "BROWSER_ACCEPTANCE_FLOW",
    "BROWSER_ACCEPTANCE_ADMIN_USERNAME",
    "BROWSER_ACCEPTANCE_DOWNSTREAM_A_USERNAME",
    "BROWSER_ACCEPTANCE_DOWNSTREAM_B_USERNAME"
)
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

function Set-ProcessEnvironment {
    param([string]$Name, [string]$Value)
    [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
}

function Wait-LocalHealth {
    param([string]$Url)
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                return
            }
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    throw "本地验收服务器未能在限定时间内通过健康检查。"
}

New-Item -ItemType Directory -Force -Path $tempRoot, $artifactDir | Out-Null
try {
    Set-ProcessEnvironment "APP_ENV" "local"
    Set-ProcessEnvironment "DATABASE_ENGINE" "sqlite"
    Set-ProcessEnvironment "DATABASE_NAME" $databasePath
    Set-ProcessEnvironment "DJANGO_DEBUG" "false"
    Set-ProcessEnvironment "ALLOWED_HOSTS" "127.0.0.1,localhost"
    Invoke-ProjectPython @((Join-Path $root "manage.py"), "migrate", "--noinput", "--verbosity", "0")
    Invoke-ProjectPython @((Join-Path $root "scripts\prepare_browser_acceptance.py"), "--output", $fixturePath)
    $fixture = Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json
    $fixtureJson = $fixture | ConvertTo-Json -Compress
    Set-ProcessEnvironment "BROWSER_ACCEPTANCE_FIXTURE_JSON" $fixtureJson
    Set-ProcessEnvironment "BROWSER_ACCEPTANCE_ADMIN_USERNAME" $fixture.admin_username
    Set-ProcessEnvironment "BROWSER_ACCEPTANCE_DOWNSTREAM_A_USERNAME" $fixture.downstream_a_username
    Set-ProcessEnvironment "BROWSER_ACCEPTANCE_DOWNSTREAM_B_USERNAME" $fixture.downstream_b_username

    $server = Start-Process -FilePath $python -ArgumentList @((Join-Path $root "manage.py"), "runserver", "127.0.0.1:$Port", "--noreload", "--insecure") -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr -PassThru
    $baseUrl = "http://127.0.0.1:$Port"
    Set-ProcessEnvironment "BROWSER_ACCEPTANCE_BASE_URL" $baseUrl
    Wait-LocalHealth "$baseUrl/healthz/"

    Push-Location $artifactDir
    try {
        $artifactPrefix = if ($Mobile) { "mobile-" } else { "" }
        $flowDefinitions = @(
            @{ Name = "admin"; Session = "browser-acceptance-admin-$Port"; RiskScreenshot = "${artifactPrefix}admin-risk.png"; AuditScreenshot = "${artifactPrefix}admin-audit.png" },
            @{ Name = "downstream-a"; Session = "browser-acceptance-downstream-a-$Port"; ScopeScreenshot = "${artifactPrefix}downstream-a-scope.png"; ForbiddenScreenshot = "${artifactPrefix}downstream-a-forbidden.png" },
            @{ Name = "downstream-b"; Session = "browser-acceptance-downstream-b-$Port"; ScopeScreenshot = "${artifactPrefix}downstream-b-scope.png"; ForbiddenScreenshot = "${artifactPrefix}downstream-b-forbidden.png" }
        )
        foreach ($flowDefinition in $flowDefinitions) {
            $session = $flowDefinition.Session
            $sessions += $session
            Set-ProcessEnvironment "BROWSER_ACCEPTANCE_FLOW" $flowDefinition.Name
            Set-ProcessEnvironment "BROWSER_ACCEPTANCE_SCREENSHOT" (Join-Path $artifactDir $flowDefinition.Screenshot)
            Invoke-Playwright @("--session", $session, "open", $baseUrl)
            $source = Get-Content -LiteralPath (Join-Path $root "scripts\browser_acceptance.js") -Raw
            $codeConfig = [ordered]@{
                base = $baseUrl
                flow = $flowDefinition.Name
                fixture = $fixture
                admin_username = $fixture.admin_username
                downstream_a_username = $fixture.downstream_a_username
                downstream_b_username = $fixture.downstream_b_username
                viewport = if ($Mobile) { [ordered]@{ width = 390; height = 844 } } else { $null }
                risk_screenshot = if ($flowDefinition.RiskScreenshot) { Join-Path $artifactDir $flowDefinition.RiskScreenshot } else { $null }
                audit_screenshot = if ($flowDefinition.AuditScreenshot) { Join-Path $artifactDir $flowDefinition.AuditScreenshot } else { $null }
                scope_screenshot = if ($flowDefinition.ScopeScreenshot) { Join-Path $artifactDir $flowDefinition.ScopeScreenshot } else { $null }
                forbidden_screenshot = if ($flowDefinition.ForbiddenScreenshot) { Join-Path $artifactDir $flowDefinition.ForbiddenScreenshot } else { $null }
            } | ConvertTo-Json -Compress
            $code = "async (page) => {`nconst config = $codeConfig;`n$source`n}"
            $codePath = Join-Path $tempRoot ("browser-acceptance-" + $flowDefinition.Name + ".js")
            Set-Content -LiteralPath $codePath -Value $code -Encoding utf8
            $runOutput = Invoke-Playwright @("--session", $session, "run-code", "--filename", $codePath)
            if ($runOutput -notmatch "browser acceptance passed") {
                throw "Browser acceptance flow $($flowDefinition.Name) did not return a success marker."
            }
            Invoke-Playwright @("--session", $session, "close")
        }
    } finally {
        foreach ($session in $sessions) {
            try { Invoke-Playwright @("--session", $session, "close") } catch { }
        }
        Pop-Location
    }
    Write-Output "Browser acceptance passed: $artifactDir"
} finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
    }
    foreach ($name in $envNames) {
        [Environment]::SetEnvironmentVariable($name, $originalEnv[$name], "Process")
    }
    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $tempRoot)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
