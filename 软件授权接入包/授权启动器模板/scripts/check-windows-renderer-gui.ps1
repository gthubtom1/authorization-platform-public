param(
    [string]$Path = (Join-Path $PSScriptRoot "..\target\release\a-template-windows-renderer.exe")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$resolvedPath = [IO.Path]::GetFullPath($Path)
if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
    throw "Renderer binary was not found: $resolvedPath"
}

$bytes = [IO.File]::ReadAllBytes($resolvedPath)
if ($bytes.Length -lt 0x100) {
    throw "Renderer binary is too small to be a PE image: $resolvedPath"
}

$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
$optionalHeader = $peOffset + 24
if ($peOffset -lt 0 -or $optionalHeader + 70 -gt $bytes.Length) {
    throw "Renderer binary has an invalid PE header: $resolvedPath"
}

$signature = [Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4)
if ($signature -ne "PE`0`0") {
    throw "Renderer binary is not a PE image: $resolvedPath"
}

$subsystem = [BitConverter]::ToUInt16($bytes, $optionalHeader + 68)
if ($subsystem -ne 2) {
    throw "Expected Windows GUI subsystem (2), received ${subsystem}: $resolvedPath"
}

Write-Output "windows-renderer-gui subsystem=2 path=$resolvedPath"
