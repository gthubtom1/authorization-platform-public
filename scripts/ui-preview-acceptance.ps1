[CmdletBinding()]
param(
    [int]$Port = 8124,
    [switch]$KeepArtifacts,
    [ValidateSet("navigation", "catalog", "diagnostics", "finish")]
    [string[]]$Suites = @("navigation", "catalog", "diagnostics", "finish")
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

& $python (Join-Path $root "scripts\check_ui_preview.py")
if ($LASTEXITCODE -ne 0) {
    throw "静态原型结构检查失败。"
}

$previewRoot = Join-Path $root "docs\ui-preview"
$artifactRoot = Join-Path $root "output\playwright\ui-preview"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("authorization-ui-preview-" + [Guid]::NewGuid().ToString("N"))
$serverOut = Join-Path $tempRoot "server.stdout.log"
$serverErr = Join-Path $tempRoot "server.stderr.log"
$fixtureRoot = Join-Path $tempRoot "release-fixtures"
$invalidRelease = Join-Path $fixtureRoot "alpha-v2.4.1.exe"
$mismatchRelease = Join-Path $fixtureRoot "alpha-v2.4.1-manifest-mismatch.zip"
$validRelease = Join-Path $fixtureRoot "alpha-v2.4.1.zip"
$hashFailRelease = Join-Path $fixtureRoot "ordinary-hash-fail.zip"
$server = $null
$sessions = @()

function Invoke-Playwright {
    param([string[]]$Arguments)
    $output = & npx.cmd --yes --package "@playwright/cli" playwright-cli @Arguments 2>&1
    $output | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "Playwright command failed with exit code $($LASTEXITCODE): $($Arguments -join ' ')"
    }
    return ($output -join [Environment]::NewLine)
}

function Wait-Preview {
    param([string]$Url)
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
            if ($response.StatusCode -eq 200) { return }
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    throw "静态预览服务器未能在限定时间内响应。"
}

New-Item -ItemType Directory -Force -Path $tempRoot, $artifactRoot, $fixtureRoot | Out-Null
[IO.File]::WriteAllText($invalidRelease, "invalid", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($mismatchRelease, "manifest mismatch", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($validRelease, "valid client-release.v1 fixture", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($hashFailRelease, "hash-fail fixture", [Text.UTF8Encoding]::new($false))
try {
    $server = Start-Process -FilePath $python -ArgumentList @("-m", "http.server", $Port, "--bind", "127.0.0.1", "--directory", $previewRoot) -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr -PassThru
    $baseUrl = "http://127.0.0.1:$Port"
    Wait-Preview "$baseUrl/entry.html"
    $source = Get-Content -LiteralPath (Join-Path $root "scripts\ui_preview_acceptance.js") -Raw -Encoding utf8
    $viewports = @(
        @{ Name = "desktop"; Width = 1440; Height = 960 },
        @{ Name = "compact"; Width = 900; Height = 900 },
        @{ Name = "mobile"; Width = 390; Height = 844 }
    )
    foreach ($viewport in $viewports) {
        $screenshotDir = Join-Path $artifactRoot $viewport.Name
        New-Item -ItemType Directory -Force -Path $screenshotDir | Out-Null
        foreach ($suite in $Suites) {
            $session = "ui-preview-$($viewport.Name)-$suite-$Port"
            $sessions += $session
            $config = [ordered]@{
                base = $baseUrl
                suite = $suite
                screenshot_dir = ($screenshotDir -replace "\\", "/")
                viewport = [ordered]@{ width = $viewport.Width; height = $viewport.Height }
                release_fixtures = [ordered]@{
                    invalid = ($invalidRelease -replace "\\", "/")
                    mismatch = ($mismatchRelease -replace "\\", "/")
                    valid = ($validRelease -replace "\\", "/")
                    hash_fail = ($hashFailRelease -replace "\\", "/")
                }
            } | ConvertTo-Json -Compress
            $code = "async (page) => {`nconst config = $config;`n$source`n}"
            $codePath = Join-Path $tempRoot ("ui-preview-$($viewport.Name)-$suite.js")
            [IO.File]::WriteAllText($codePath, $code, [Text.UTF8Encoding]::new($false))
            Invoke-Playwright @("--session", $session, "open", $baseUrl)
            $runOutput = Invoke-Playwright @("--session", $session, "run-code", "--filename", $codePath)
            if ($runOutput -notmatch "UI preview acceptance passed") {
                throw "视口 $($viewport.Name) 的 $suite 验收组未返回成功标记。"
            }
            Invoke-Playwright @("--session", $session, "close")
        }
    }
    Write-Output "UI preview browser acceptance passed: $artifactRoot"
} finally {
    foreach ($session in $sessions) {
        try { Invoke-Playwright @("--session", $session, "close") } catch { }
    }
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
    }
    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $tempRoot)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
