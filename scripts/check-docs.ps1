$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

function Assert-File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing required file: $Path"
    }
}

function Assert-Contains([string]$Path, [string]$Pattern) {
    $text = Get-Content -Raw -LiteralPath $Path -Encoding utf8
    if ($text -notlike ("*" + $Pattern + "*")) {
        throw "Missing '$Pattern' in $Path"
    }
}

$required = @(
    "AGENTS.md",
    "README.md",
    "docs/PROJECT.md",
    "docs/FEATURES.md",
    "docs/STATUS.md",
    "docs/ARCHITECTURE.md",
    "docs/UI-DESIGN-SYSTEM.md",
    "docs/DOMAIN-RULES.md",
    "docs/API-CONTRACT.md",
    "docs/SECURITY-BASELINE.md",
    "docs/COMPETITOR-RESEARCH.md",
    "docs/AI-ROLES.md",
    "docs/SOFTWARE-ADAPTERS.md",
    "docs/CLIENT-INTEGRATION-HANDOFF.md",
    "docs/UI-REFERENCE.md",
    "docs/PR-PLAN.md",
    "docs/ACCEPTANCE-MATRIX.md",
    "docs/adr/INDEX.md"
)

foreach ($path in $required) {
    Assert-File $path
}

Assert-Contains "docs/FEATURES.md" "用户能力"
Assert-Contains "docs/FEATURES.md" "F-020"
Assert-Contains "docs/DOMAIN-RULES.md" "LicenseInstance"
Assert-Contains "docs/API-CONTRACT.md" "Idempotency-Key"
Assert-Contains "docs/API-CONTRACT.md" "profile_id"
Assert-Contains "docs/SECURITY-BASELINE.md" "下游 A"
Assert-Contains "docs/UI-DESIGN-SYSTEM.md" "Registry / Ledger Control Room"
Assert-Contains "docs/SOFTWARE-ADAPTERS.md" "generic-online-v1"
Assert-Contains "docs/CLIENT-INTEGRATION-HANDOFF.md" "SUPPORTED"
Assert-Contains "docs/UI-REFERENCE.md" "UI 验收底线"
Assert-Contains "docs/PR-PLAN.md" "PR-12"
Assert-Contains "docs/ACCEPTANCE-MATRIX.md" "A-052"
Assert-Contains "docs/ACCEPTANCE-MATRIX.md" "项目完成终审门禁"
Assert-Contains "docs/ACCEPTANCE-MATRIX.md" "A-111"

$featureText = Get-Content -Raw -LiteralPath "docs/FEATURES.md" -Encoding utf8
$featureIds = [regex]::Matches($featureText, "(?m)^\|\s*(F-[0-9]+)\s*\|") | ForEach-Object { $_.Groups[1].Value }
if ($featureIds.Count -ne (@($featureIds | Sort-Object -Unique).Count)) {
    throw "Duplicate feature IDs found in docs/FEATURES.md"
}
if ($featureIds.Count -lt 20) {
    throw "Expected at least 20 feature records, found $($featureIds.Count)"
}

$markdownFiles = Get-ChildItem -LiteralPath "docs" -Recurse -File -Filter "*.md" |
    Where-Object { $_.Name -notlike "旧流程-已放弃-*" }
foreach ($file in $markdownFiles) {
    $content = Get-Content -Raw -LiteralPath $file.FullName -Encoding utf8
    foreach ($match in [regex]::Matches($content, "\]\(([^)]+)\)")) {
        $reference = $match.Groups[1].Value.Trim()
        $reference = ($reference -split "#", 2)[0].Trim()
        if ([string]::IsNullOrWhiteSpace($reference) -or $reference -match "^(https?://|mailto:|/)") {
            continue
        }
        $target = Join-Path $file.DirectoryName $reference
        if (-not (Test-Path -LiteralPath $target)) {
            throw "Missing relative Markdown target '$reference' in $($file.FullName)"
        }
    }
}

Write-Output "Documentation checks passed: $($required.Count) required files, $($featureIds.Count) feature records, relative links verified."
