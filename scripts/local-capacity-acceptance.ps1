[CmdletBinding()]
param(
    [ValidateRange(1, 5000)][int]$Requests = 40,
    [ValidateRange(1, 32)][int]$Concurrency = 4,
    [int]$FrontendPort = 18123,
    [int]$BackendPort = 18000
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $root ".venv\Scripts\python.exe"
$artifactRoot = Join-Path $root "output\capacity"
$artifact = Join-Path $artifactRoot ((Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmssfff") + "-" + [guid]::NewGuid().ToString("N"))
$backend = $null
$proxy = $null
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw "项目虚拟环境不存在。" }
New-Item -ItemType Directory -Path $artifact -Force | Out-Null

try {
    $backend = Start-Process -FilePath $python -ArgumentList @((Join-Path $root "manage.py"), "runserver", "127.0.0.1:$BackendPort", "--noreload", "--insecure") -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput (Join-Path $artifact "backend.stdout.txt") -RedirectStandardError (Join-Path $artifact "backend.stderr.txt") -PassThru
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($backend.HasExited) { throw "Django candidate exited before health check." }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$BackendPort/healthz/" -TimeoutSec 2
            if ($response.StatusCode -eq 200) { $ready = $true; break }
        } catch { Start-Sleep -Milliseconds 250 }
    }
    if (-not $ready) { throw "Django candidate did not become healthy." }

    $proxy = Start-Process -FilePath $python -ArgumentList @((Join-Path $root "scripts\static_proxy.py"), "--bind", "127.0.0.1", "--port", [string]$FrontendPort, "--directory", (Join-Path $root "docs\ui-preview"), "--backend-host", "127.0.0.1", "--backend-port", [string]$BackendPort) -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput (Join-Path $artifact "proxy.stdout.txt") -RedirectStandardError (Join-Path $artifact "proxy.stderr.txt") -PassThru
    $proxyReady = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($proxy.HasExited) { throw "static proxy exited before capacity probe." }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$FrontendPort/healthz/" -TimeoutSec 2
            if ($response.StatusCode -eq 200) { $proxyReady = $true; break }
        } catch { Start-Sleep -Milliseconds 250 }
    }
    if (-not $proxyReady) { throw "static proxy did not become healthy." }

    $probeOutput = & $python (Join-Path $root "scripts\capacity_probe.py") --url "http://127.0.0.1:$FrontendPort/healthz/" --requests $Requests --concurrency $Concurrency --timeout 5 2>&1
    $probeOutput | ForEach-Object { $_.ToString() } | Set-Content -LiteralPath (Join-Path $artifact "capacity.json") -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw "capacity probe failed." }
    Write-Output ("CAPACITY_ACCEPTED " + $artifact)
} finally {
    if ($proxy -and -not $proxy.HasExited) { Stop-Process -Id $proxy.Id -Force -ErrorAction SilentlyContinue }
    if ($backend -and -not $backend.HasExited) { Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue }
}
