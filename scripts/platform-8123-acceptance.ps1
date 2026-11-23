[CmdletBinding()]
param(
    [int]$FrontendPort = 8123,
    [int]$BackendPort = 8000,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) { throw "项目虚拟环境不存在，请先运行 scripts\bootstrap.ps1" }
if (-not (Get-Command npx.cmd -ErrorAction SilentlyContinue)) { throw "npx 不存在；请先安装 Node.js/npm。" }

$artifactDir = Join-Path $root "output\playwright\platform-8123"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("authorization-platform-f018-f020-" + [Guid]::NewGuid().ToString("N"))
$fixturePath = Join-Path $tempRoot "fixture.json"
$backendOut = Join-Path $tempRoot "backend.stdout.log"
$backendErr = Join-Path $tempRoot "backend.stderr.log"
$proxyOut = Join-Path $tempRoot "proxy.stdout.log"
$proxyErr = Join-Path $tempRoot "proxy.stderr.log"
$databasePath = Join-Path $tempRoot "acceptance.sqlite3"
$storageRoot = Join-Path $tempRoot "storage"
$releaseRoot = Join-Path $storageRoot "releases"
$packageOne = Join-Path $tempRoot "client-release-1.0.0.zip"
$packageTwo = Join-Path $tempRoot "client-release-1.1.0.zip"
$badPackage = Join-Path $tempRoot "invalid-release.zip"
$backend = $null
$proxy = $null
$session = "platform-8123-f018-f020-$FrontendPort"
$envNames = @(
    "APP_ENV", "DATABASE_ENGINE", "DATABASE_NAME", "DJANGO_DEBUG", "ALLOWED_HOSTS",
    "CSRF_TRUSTED_ORIGINS", "STORAGE_ROOT", "RELEASE_STORAGE_ROOT",
    "STORAGE_CLEANUP_RETENTION_DAYS", "RELEASE_REQUIRE_VERIFIED_SIGNATURE", "RELEASE_SIGNING_PUBLIC_KEY"
)
$originalEnv = @{}
foreach ($name in $envNames) { $originalEnv[$name] = [Environment]::GetEnvironmentVariable($name, "Process") }

function Invoke-ProjectPython {
    param([string[]]$Arguments)
    & $python @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Python command failed with exit code $($LASTEXITCODE): $($Arguments -join ' ')" }
}

function Invoke-Playwright {
    param([string[]]$Arguments)
    $output = & npx.cmd --yes --package "@playwright/cli" playwright-cli @Arguments 2>&1
    $output | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { throw "Playwright command failed with exit code $($LASTEXITCODE): $($Arguments -join ' ')" }
    return ($output -join [Environment]::NewLine)
}

function Wait-Http200 {
    param([string]$Url)
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
            if ($response.StatusCode -eq 200) { return }
        } catch { Start-Sleep -Milliseconds 250 }
    }
    throw "本地服务未能在限定时间内返回 200：$Url"
}

function New-ReleasePackage {
    param([string]$Path, [string]$Version, [string]$SoftwareId, [string]$ClientId)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $manifest = [ordered]@{
        schema = "client-release.v1"
        software_id = $SoftwareId
        profile_id = "stable"
        client_id = $ClientId
        version = $Version
        target = "windows"
        arch = "x64"
        channel = "stable"
        minimum_client_version = "1.0.0"
        signature = [ordered]@{ algorithm = "ed25519"; key_id = "acceptance-key"; value = "AA==" }
    } | ConvertTo-Json -Compress
    $archive = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        $entry = $archive.CreateEntry("client-release.v1.json")
        $encoding = [Text.UTF8Encoding]::new($false)
        $writer = [IO.StreamWriter]::new($entry.Open(), $encoding)
        try { $writer.Write($manifest) } finally { $writer.Dispose() }
    } finally { $archive.Dispose() }
}

New-Item -ItemType Directory -Force -Path $tempRoot, $storageRoot, $releaseRoot, (Join-Path $storageRoot "tmp"), $artifactDir | Out-Null
try {
    [Environment]::SetEnvironmentVariable("APP_ENV", "local", "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_ENGINE", "sqlite", "Process")
    [Environment]::SetEnvironmentVariable("DATABASE_NAME", $databasePath, "Process")
    [Environment]::SetEnvironmentVariable("DJANGO_DEBUG", "false", "Process")
    [Environment]::SetEnvironmentVariable("ALLOWED_HOSTS", "127.0.0.1,localhost", "Process")
    [Environment]::SetEnvironmentVariable("CSRF_TRUSTED_ORIGINS", "http://127.0.0.1:$FrontendPort,http://localhost:$FrontendPort", "Process")
    [Environment]::SetEnvironmentVariable("STORAGE_ROOT", $storageRoot, "Process")
    [Environment]::SetEnvironmentVariable("RELEASE_STORAGE_ROOT", $releaseRoot, "Process")
    [Environment]::SetEnvironmentVariable("STORAGE_CLEANUP_RETENTION_DAYS", "0", "Process")
    [Environment]::SetEnvironmentVariable("RELEASE_REQUIRE_VERIFIED_SIGNATURE", "false", "Process")
    [Environment]::SetEnvironmentVariable("RELEASE_SIGNING_PUBLIC_KEY", "", "Process")

    $staleFile = Join-Path $storageRoot "tmp\old-export.txt"
    [IO.File]::WriteAllText($staleFile, "platform acceptance temporary export")
    [IO.File]::SetLastWriteTimeUtc($staleFile, [DateTime]::UtcNow.AddDays(-2))

    Invoke-ProjectPython @((Join-Path $root "manage.py"), "migrate", "--noinput", "--verbosity", "0")
    Invoke-ProjectPython @((Join-Path $root "scripts\prepare_browser_acceptance.py"), "--output", $fixturePath)
    $fixture = Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json
    New-ReleasePackage -Path $packageOne -Version "1.0.0" -SoftwareId $fixture.software_id -ClientId $fixture.client_id
    New-ReleasePackage -Path $packageTwo -Version "1.1.0" -SoftwareId $fixture.software_id -ClientId $fixture.client_id
    Add-Type -AssemblyName System.IO.Compression
    $invalidArchive = [IO.Compression.ZipFile]::Open($badPackage, [IO.Compression.ZipArchiveMode]::Create)
    try {
        $entry = $invalidArchive.CreateEntry("not-a-manifest.txt")
        $writer = [IO.StreamWriter]::new($entry.Open(), [Text.UTF8Encoding]::new($false))
        try { $writer.Write("invalid") } finally { $writer.Dispose() }
    } finally { $invalidArchive.Dispose() }

    $backend = Start-Process -FilePath $python -ArgumentList @((Join-Path $root "manage.py"), "runserver", "127.0.0.1:$BackendPort", "--noreload", "--insecure") -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $backendOut -RedirectStandardError $backendErr -PassThru
    Wait-Http200 "http://127.0.0.1:$BackendPort/healthz/"
    $proxy = Start-Process -FilePath $python -ArgumentList @((Join-Path $root "scripts\static_proxy.py"), "--bind", "127.0.0.1", "--port", $FrontendPort, "--directory", (Join-Path $root "docs\ui-preview"), "--backend-host", "127.0.0.1", "--backend-port", $BackendPort) -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $proxyOut -RedirectStandardError $proxyErr -PassThru
    $baseUrl = "http://127.0.0.1:$FrontendPort"
    Wait-Http200 "$baseUrl/healthz/"
    Wait-Http200 "$baseUrl/manage.html"
    Wait-Http200 "$baseUrl/api/v1/session/"

    $source = Get-Content -LiteralPath (Join-Path $root "scripts\platform_8123_acceptance.js") -Raw
    $config = [ordered]@{
        base = $baseUrl
        fixture = $fixture
        package_one = ($packageOne -replace "\\", "/")
        package_two = ($packageTwo -replace "\\", "/")
        bad_package = ($badPackage -replace "\\", "/")
        artifact_dir = ($artifactDir -replace "\\", "/")
    } | ConvertTo-Json -Compress
    $code = "async (page) => {`nconst config = $config;`nreturn await $source;`n}"
    $codePath = Join-Path $tempRoot "platform-8123-acceptance.js"
    [IO.File]::WriteAllText($codePath, $code, [Text.UTF8Encoding]::new($false))
    Invoke-Playwright @("--session", $session, "open", "$baseUrl/manage.html")
    $runOutput = Invoke-Playwright @("--session", $session, "run-code", "--filename", $codePath)
    if ($runOutput -notmatch "F-018/F-019/F-020 frozen 8123 acceptance passed") { throw "F-018/F-019/F-020 browser acceptance did not return a success marker." }
    Write-Output "F-018/F-019/F-020 frozen 8123 browser acceptance passed (local sqlite; RELEASE_REQUIRE_VERIFIED_SIGNATURE=false; not production verified-signature proof): $artifactDir"
} finally {
    try { Invoke-Playwright @("--session", $session, "close") } catch { }
    if ($proxy -and -not $proxy.HasExited) { Stop-Process -Id $proxy.Id -Force }
    if ($backend -and -not $backend.HasExited) { Stop-Process -Id $backend.Id -Force }
    foreach ($name in $envNames) { [Environment]::SetEnvironmentVariable($name, $originalEnv[$name], "Process") }
    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $tempRoot)) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}
