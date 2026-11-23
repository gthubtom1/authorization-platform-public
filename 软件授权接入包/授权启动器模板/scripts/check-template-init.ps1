[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $PSScriptRoot
$initScript = Join-Path $scriptRoot 'scripts/init-product.ps1'
$startScript = Join-Path $scriptRoot 'scripts/start-here.ps1'
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("authorization-a-template-init-{0}-{1}" -f $PID, [Guid]::NewGuid().ToString('N'))
$inputRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("authorization-a-template-input-{0}-{1}" -f $PID, [Guid]::NewGuid().ToString('N'))

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-Sha256([string]$Path) {
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        return ([System.BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $stream.Dispose()
        $algorithm.Dispose()
    }
}

try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    & $initScript -ProductRoot $tempRoot -ProductId 'check-product' -DisplayName 'Template Check' -TemplateOnly | Out-Null

    $expected = @(
        'product-state/STATE.yaml',
        'product-state/PRODUCT-INDEX.md',
        'product-state/PRODUCT-DOSSIER.md',
        'product-state/CUSTOMIZATION-MANIFEST.yaml',
        'product-state/MAINTENANCE-MODE.yaml',
        'product-state/artifacts/INPUT-MANIFEST.yaml',
        'product-state/auth/AUTH-PROFILE.yaml',
        'product-state/auth/LAUNCH-CONTRACT.yaml',
        'product-state/profiles/product-manifest.json',
        'product-state/profiles/ui-profile.json',
        'product-state/release/UPDATE-PROFILE.yaml',
        'product-state/release/COMPONENT-RELEASE-MANIFEST.yaml',
        'product-state/reports/VERIFICATION-RECORD.md',
        'product-state/rollback/ROLLBACK-RUNBOOK.md'
    )
    foreach ($relative in $expected) {
        Assert-True (Test-Path -LiteralPath (Join-Path $tempRoot $relative) -PathType Leaf) "missing generated file: $relative"
    }

    $manifest = Get-Content -LiteralPath (Join-Path $tempRoot 'product-state/profiles/product-manifest.json') -Raw | ConvertFrom-Json
    $uiProfile = Get-Content -LiteralPath (Join-Path $tempRoot 'product-state/profiles/ui-profile.json') -Raw | ConvertFrom-Json
    Assert-True ($manifest.product_id -eq 'check-product') 'manifest product_id was not preserved'
    Assert-True ($manifest.core_path -eq 'core/check-product.exe') 'default core path was not generated'
    Assert-True ($uiProfile.product_id -eq 'check-product') 'UI profile product_id was not preserved'
    Assert-True ((Get-Content -LiteralPath (Join-Path $tempRoot 'product-state/STATE.yaml') -Raw) -match 'simulation_only: true') 'template-only state was not marked simulation-only'
    $startOutput = @(& $startScript -ProductRoot $tempRoot -UserRequest 'status')
    Assert-True ($startOutput -contains 'MODE=existing-product') 'start-here did not detect the initialized product'
    Assert-True ($startOutput -contains 'STATUS=INIT') 'start-here did not report the initialized status'

    $reinitRejected = $false
    try {
        & $initScript -ProductRoot $tempRoot -ProductId 'check-product' -DisplayName 'Template Check' -TemplateOnly | Out-Null
    } catch {
        $reinitRejected = $true
    }
    Assert-True $reinitRejected 'reinitialization of an existing product-state was not rejected'

    New-Item -ItemType Directory -Path $inputRoot -Force | Out-Null
    $inputPath = Join-Path $inputRoot 'owned-core.exe'
    [System.IO.File]::WriteAllBytes($inputPath, [byte[]](0x41, 0x2D, 0x54, 0x45, 0x4D, 0x50, 0x4C, 0x41, 0x54, 0x45))
    $baselineRoot = Join-Path $inputRoot 'product'
    & $initScript -ProductRoot $baselineRoot -ProductId 'baseline-product' -DisplayName 'Baseline Check' -InputPath $inputPath | Out-Null
    $hash = Get-Sha256 $inputPath
    $stateText = Get-Content -LiteralPath (Join-Path $baselineRoot 'product-state/STATE.yaml') -Raw
    $copiedPath = Join-Path $baselineRoot 'product-state/artifacts/baseline/owned-core.exe'
    Assert-True (Test-Path -LiteralPath $copiedPath -PathType Leaf) 'baseline executable was not preserved'
    Assert-True ($stateText -match "status: 'BASELINE_CREATED'") 'baseline status was not recorded'
    Assert-True ($stateText -match [regex]::Escape($hash)) 'baseline SHA-256 was not recorded'

    $unsafeRejected = $false
    try {
        & $initScript -ProductRoot (Join-Path $inputRoot 'unsafe') -ProductId 'unsafe-product' -DisplayName 'Unsafe Check' -TemplateOnly -CorePath '..\core.exe' | Out-Null
    } catch {
        $unsafeRejected = $true
    }
    Assert-True $unsafeRejected 'unsafe core path was accepted'

    Write-Output 'template-init-check: PASS'
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $inputRoot) {
        Remove-Item -LiteralPath $inputRoot -Recurse -Force
    }
}
