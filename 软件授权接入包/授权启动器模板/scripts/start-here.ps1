[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ProductRoot,
    [string]$UserRequest = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = if ([System.IO.Path]::IsPathRooted($ProductRoot)) {
    [System.IO.Path]::GetFullPath($ProductRoot)
} else {
    [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $ProductRoot))
}
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "ProductRoot does not exist: $root"
}

$statePath = Join-Path $root 'product-state/STATE.yaml'
$indexPath = Join-Path $root 'product-state/PRODUCT-INDEX.md'
Write-Output "PRODUCT_ROOT=$root"
if ($UserRequest) {
    Write-Output "USER_REQUEST=$UserRequest"
}

if (Test-Path -LiteralPath $statePath -PathType Leaf) {
    $state = Get-Content -LiteralPath $statePath -Raw
    $productId = if ($state -match '(?m)^product_id:\s*''([^'']*)''') { $Matches[1] } else { 'UNVERIFIED' }
    $status = if ($state -match '(?m)^status:\s*''([^'']*)''') { $Matches[1] } else { 'UNVERIFIED' }
    $nextAction = if ($state -match '(?m)^next_action:\s*''([^'']*)''') { $Matches[1] } else { 'Read STATE.yaml and determine the next evidence-producing step.' }
    Write-Output 'MODE=existing-product'
    Write-Output "PRODUCT_ID=$productId"
    Write-Output "STATUS=$status"
    Write-Output "NEXT_ACTION=$nextAction"
    Write-Output "STATE=$statePath"
    if (Test-Path -LiteralPath $indexPath -PathType Leaf) {
        Write-Output "INDEX=$indexPath"
    }
    Write-Output 'RULE=Do not reinitialize an existing product-state; preserve the baseline and follow the product-local next action.'
    exit 0
}

$inputs = @(Get-ChildItem -LiteralPath $root -File -Force | Where-Object { $_.Name -notlike '.*' })
Write-Output 'MODE=bootstrap'
Write-Output 'STATUS=NOT_INITIALIZED'
Write-Output "INPUT_FILE_COUNT=$($inputs.Count)"
foreach ($input in $inputs) {
    Write-Output "INPUT=$($input.Name)"
}
Write-Output 'NEXT_ACTION=Run scripts/init-product.ps1 with -InputPath for an owned or explicitly authorized EXE, or -TemplateOnly for a simulation-only skeleton.'
Write-Output 'RULE=This command is read-only; it does not change product files or status.'
