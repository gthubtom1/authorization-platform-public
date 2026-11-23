[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ProductRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')]
    [string]$ProductId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName,

    [string]$Category = 'uncategorized',
    [ValidatePattern('^[A-Za-z]{2,8}(-[A-Za-z0-9]{2,8}){0,2}$')]
    [string]$Locale = 'zh-CN',
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')]
    [string]$AdapterId = '',
    [string]$AdapterVersion = '0.1.0',
    [ValidateSet('native_core', 'legacy_auth', 'wrapper_only')]
    [string]$Compatibility = 'native_core',
    [string]$CorePath = '',
    [string]$StateRoot = 'product-state/runtime',
    [string]$IpcName = '',
    [string]$InputPath,
    [switch]$TemplateOnly,
    [string]$Accent = '#2563EB',
    [string]$Surface = '#FFFFFF',
    [string]$Text = '#111827',
    [string]$Danger = '#DC2626'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Quote-Yaml([string]$Value) {
    if ($null -eq $Value) {
        return "''"
    }
    return "'" + ($Value -replace "'", "''") + "'"
}

function Write-Utf8NoBom([string]$Path, [string]$Content) {
    $parent = Split-Path -Parent $Path
    if ($parent) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
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

function Validate-RelativePath([string]$Value, [string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Name must not be empty"
    }
    $normalized = $Value.Replace('\', '/')
    if ([System.IO.Path]::IsPathRooted($normalized) -or $normalized.StartsWith('/') -or $normalized -match '(^|/)\.\.?(/|$)') {
        throw "$Name must be a safe relative path"
    }
    return $normalized
}

function Validate-ShortText([string]$Value, [string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 256 -or $Value -match '[\x00-\x1F\x7F]') {
        throw "$Name must contain 1-256 non-control characters"
    }
}

if ($TemplateOnly -and $InputPath) {
    throw '-TemplateOnly cannot be combined with -InputPath'
}
if (-not $TemplateOnly -and -not $InputPath) {
    throw 'provide -InputPath for a real product baseline or use -TemplateOnly for the reusable template skeleton'
}

Validate-ShortText $DisplayName 'DisplayName'
Validate-ShortText $Category 'Category'
Validate-ShortText $AdapterVersion 'AdapterVersion'
foreach ($token in @(@{Name = 'Accent'; Value = $Accent}, @{Name = 'Surface'; Value = $Surface}, @{Name = 'Text'; Value = $Text}, @{Name = 'Danger'; Value = $Danger})) {
    Validate-ShortText $token.Value $token.Name
}

if ([string]::IsNullOrWhiteSpace($AdapterId)) {
    $AdapterId = "$ProductId-adapter"
}
if ([string]::IsNullOrWhiteSpace($CorePath)) {
    $CorePath = "core/$ProductId.exe"
}
if ([string]::IsNullOrWhiteSpace($IpcName)) {
    $IpcName = "a-auth-$ProductId"
}
$CorePath = Validate-RelativePath $CorePath 'CorePath'
$StateRoot = Validate-RelativePath $StateRoot 'StateRoot'
Validate-ShortText $IpcName 'IpcName'

$productRootFull = if ([System.IO.Path]::IsPathRooted($ProductRoot)) {
    [System.IO.Path]::GetFullPath($ProductRoot)
} else {
    [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $ProductRoot))
}
[System.IO.Directory]::CreateDirectory($productRootFull) | Out-Null
$stateRootFull = Join-Path $productRootFull 'product-state'
if (Test-Path -LiteralPath $stateRootFull) {
    throw "product-state already exists at $stateRootFull; use start-here.ps1 and resume the existing product"
}

$inputRecord = $null
$baselineStatus = 'not_provided'
$productStatus = 'INIT'
$simulationOnly = $true
$nextAction = 'Register an owned or explicitly authorized EXE with -InputPath, then run start-here.ps1 before analysis.'

if ($InputPath) {
    $inputFull = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $InputPath).Path)
    if (-not (Test-Path -LiteralPath $inputFull -PathType Leaf)) {
        throw "InputPath is not a file: $inputFull"
    }
    if ($inputFull.StartsWith(($stateRootFull + [System.IO.Path]::DirectorySeparatorChar), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'InputPath cannot be inside product-state'
    }
    $inputName = [System.IO.Path]::GetFileName($inputFull)
    $artifactPath = Join-Path (Join-Path $stateRootFull 'artifacts/baseline') $inputName
    $hash = Get-Sha256 $inputFull
    $inputRecord = [ordered]@{
        path = "product-state/artifacts/baseline/$inputName"
        source_name = $inputName
        role = 'primary_executable'
        sha256 = $hash
    }
    $baselineStatus = 'recorded'
    $productStatus = 'BASELINE_CREATED'
    $simulationOnly = $false
    $nextAction = 'Run start-here.ps1 and follow the reported static analysis and protection checks.'
}

$directories = @(
    'product-state/artifacts/baseline',
    'product-state/analysis',
    'product-state/migrations',
    'product-state/auth',
    'product-state/release',
    'product-state/rollback',
    'product-state/reports',
    'product-state/tooling',
    'product-state/learning',
    'product-state/profiles',
    'incoming'
)
foreach ($directory in $directories) {
    [System.IO.Directory]::CreateDirectory((Join-Path $productRootFull $directory)) | Out-Null
}

if ($inputRecord) {
    Copy-Item -LiteralPath $inputFull -Destination (Join-Path $productRootFull $inputRecord.path) -Force:$false
}

$manifest = [ordered]@{
    schema_version = 'product-manifest.v1'
    product_id = $ProductId
    display_name = $DisplayName
    category = $Category
    adapter_id = $AdapterId
    adapter_version = $AdapterVersion
    locale = $Locale
    theme = [ordered]@{
        accent = $Accent
        surface = $Surface
        text = $Text
        danger = $Danger
    }
    core_path = $CorePath
    state_root = $StateRoot
    ipc_name = $IpcName
    compatibility = $Compatibility
    capabilities = @(
        [ordered]@{ id = 'launch'; version = '1'; required = $true },
        [ordered]@{ id = 'contact'; version = '1'; required = $false },
        [ordered]@{ id = 'purchase'; version = '1'; required = $false }
    )
    protocol_parameters = [ordered]@{
        environment = 'test'
        platform_adapter = 'unconfigured'
    }
}
$manifestJson = $manifest | ConvertTo-Json -Depth 8
Write-Utf8NoBom (Join-Path $productRootFull 'product-state/profiles/product-manifest.json') ($manifestJson + [Environment]::NewLine)

$uiProfile = [ordered]@{
    schema_version = 'authorization-a-ui.v1'
    product_id = $ProductId
    profile_id = 'profile-default'
    locale = $Locale
    copy = [ordered]@{}
    enabled_modules = @('contact', 'purchase')
}
Write-Utf8NoBom (Join-Path $productRootFull 'product-state/profiles/ui-profile.json') (($uiProfile | ConvertTo-Json -Depth 8) + [Environment]::NewLine)

$baselineHash = if ($inputRecord) { $inputRecord.sha256 } else { 'UNVERIFIED' }
$sourceArtifact = if ($inputRecord) { $inputRecord.path } else { 'UNVERIFIED' }

$state = @"
schema_version: authorization-a-product-state.v1
track: template
product_id: $(Quote-Yaml $ProductId)
display_name: $(Quote-Yaml $DisplayName)
status: $(Quote-Yaml $productStatus)
simulation_only: $($simulationOnly.ToString().ToLowerInvariant())
baseline_status: $(Quote-Yaml $baselineStatus)
baseline_sha256: $(Quote-Yaml $baselineHash)
source_artifact: $(Quote-Yaml $sourceArtifact)
platform_status: 'UNVERIFIED'
core_compatibility: 'UNVERIFIED'
binding_strength:
  claimed_tier: 'C'
  verified_tier: 'UNVERIFIED'
  bypass_risk: 'The core and real platform have not been connected.'
next_action: $(Quote-Yaml $nextAction)
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'STATE.yaml') $state

$inputManifestLines = if ($inputRecord) {
    @(
        "  - path: $(Quote-Yaml $inputRecord.path)"
        "    source_name: $(Quote-Yaml $inputRecord.source_name)"
        '    role: primary_executable'
        "    sha256: $(Quote-Yaml $inputRecord.sha256)"
    ) -join [Environment]::NewLine
} else {
    @(
        '  - path: null'
        '    role: template_only'
        '    status: UNVERIFIED'
    ) -join [Environment]::NewLine
}
$inputManifest = @"
schema_version: input-manifest.v1
product_id: $(Quote-Yaml $ProductId)
inputs:
$inputManifestLines
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'artifacts/INPUT-MANIFEST.yaml') $inputManifest

$dossier = @"
# Product Dossier: $DisplayName

product_id: $ProductId
track: template
status: $productStatus

This directory was initialized from the Authorization A reusable template.
The common runtime is product-neutral. Product-specific behavior belongs in the
manifest, UI profile, adapter and this product-state directory.

## Evidence boundary

- simulation_only: $($simulationOnly.ToString().ToLowerInvariant())
- baseline: $sourceArtifact
- baseline_sha256: $baselineHash
- real authorization platform: UNVERIFIED
- real core compatibility: UNVERIFIED

Do not mark this product VERIFIED or RELEASED from simulated fixtures.
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'PRODUCT-DOSSIER.md') $dossier

$customization = @"
schema_version: customization-manifest.v1
product_id: $(Quote-Yaml $ProductId)
status: 'DRAFT'
rules:
  - id: branding-default
    type: branding
    anchor: product-state/profiles/product-manifest.json
    operation: configure
    verification: profile-load
  - id: ui-profile-default
    type: ui
    anchor: product-state/profiles/ui-profile.json
    operation: configure
    verification: ui-snapshot-validation
  - id: core-entrypoint
    type: runtime
    anchor: $(Quote-Yaml $CorePath)
    operation: register
    verification: launch-contract
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'CUSTOMIZATION-MANIFEST.yaml') $customization

$maintenance = @"
schema_version: maintenance-mode.v1
product_id: $(Quote-Yaml $ProductId)
components:
  launcher:
    mode: 'UNKNOWN'
    evidence: 'No concrete product executable has been analyzed.'
  core:
    mode: 'UNKNOWN'
    evidence: 'Real core compatibility is UNVERIFIED.'
  resources:
    mode: 'UNKNOWN'
    evidence: 'No resource baseline is registered.'
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'MAINTENANCE-MODE.yaml') $maintenance

$authProfile = @"
schema_version: auth-profile.v1
product_id: $(Quote-Yaml $ProductId)
platform: 'UNVERIFIED'
environment: 'test'
adapter: 'MockPlatform'
real_endpoint: 'UNVERIFIED'
production_cryptography: 'UNVERIFIED'
device_policy: 'server-owned; UNVERIFIED until the platform contract is supplied'
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'auth/AUTH-PROFILE.yaml') $authProfile

$launchContract = @"
schema_version: launch-contract.v1
product_id: $(Quote-Yaml $ProductId)
core_path: $(Quote-Yaml $CorePath)
authorization_gate: 'Authorization A re-checks launchable state before handoff.'
handoff_contract: 'authorization-a-core.v1 or the registered legacy adapter'
binding_strength:
  claimed_tier: 'C'
  verified_tier: 'UNVERIFIED'
  bypass_risk: 'The concrete core may launch independently until stronger evidence exists.'
success_exit_code: 'UNVERIFIED'
failure_mapping: 'UNVERIFIED'
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'auth/LAUNCH-CONTRACT.yaml') $launchContract

$updateProfile = @"
schema_version: update-profile.v1
product_id: $(Quote-Yaml $ProductId)
channel: 'test'
status: 'DRAFT'
upstream_input: 'UNVERIFIED'
data_migration: 'UNVERIFIED'
rollback_version: 'UNVERIFIED'
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'release/UPDATE-PROFILE.yaml') $updateProfile

$releaseManifest = @"
schema_version: component-release-manifest.v1
product_id: $(Quote-Yaml $ProductId)
status: 'DRAFT'
simulation_only: $($simulationOnly.ToString().ToLowerInvariant())
launcher: 'UNVERIFIED'
adapter: $(Quote-Yaml "$AdapterId@$AdapterVersion")
core: 'UNVERIFIED'
artifact_sha256: 'UNVERIFIED'
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'release/COMPONENT-RELEASE-MANIFEST.yaml') $releaseManifest

$verification = @"
# Verification Record

status: DRAFT
product_id: $ProductId

This file is a product-local placeholder. Replace it with literal commands,
inputs, outputs and exit codes after an owned or explicitly authorized EXE is
registered. Mock simulation evidence must remain labeled simulation-only.
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'reports/VERIFICATION-RECORD.md') $verification

$rollback = @"
# Rollback Runbook

status: DRAFT
product_id: $ProductId

No release artifact exists yet. Preserve the baseline before any real
customization, restore the last verified package, then rerun authorization,
startup, UI, feature and hash checks. Do not restore state across products,
environments or devices.
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'rollback/ROLLBACK-RUNBOOK.md') $rollback

$index = @"
# Product Index: $DisplayName

- Product ID: $ProductId
- Track: template
- Status: $productStatus
- Simulation only: $($simulationOnly.ToString().ToLowerInvariant())
- Product state: product-state/
- Manifest: product-state/profiles/product-manifest.json
- UI profile: product-state/profiles/ui-profile.json
- Next action: $nextAction

product-state/STATE.yaml is the authoritative machine-readable state. Use
start-here.ps1 before resuming work. Do not claim VERIFIED or RELEASED from
this template skeleton or from MockPlatform fixtures.
"@
Write-Utf8NoBom (Join-Path $stateRootFull 'PRODUCT-INDEX.md') $index

$summary = [ordered]@{
    schema_version = 'template-init-result.v1'
    product_id = $ProductId
    product_root = $productRootFull
    status = $productStatus
    simulation_only = $simulationOnly
    baseline_sha256 = $baselineHash
    next_action = $nextAction
}
$summary | ConvertTo-Json -Depth 4
