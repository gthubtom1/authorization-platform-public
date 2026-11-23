param(
    [string]$Path = (Join-Path $PSScriptRoot "..\target\release\a-template-windows-renderer.exe"),
    [string]$EvidenceDirectory = (Join-Path $env:TEMP "authorization-a-template-ui-qa"),
    [int]$Iterations = 5,
    [switch]$NoScreenshots,
    [switch]$AllowInteractiveDesktop,
    [switch]$IncludeResizeCheck,
    [int]$RequireDpiPercent = 0,
    [string[]]$Arguments = @(),
    [switch]$RequireUiaPatterns
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "The native renderer accessibility check requires Windows."
}
if (-not $AllowInteractiveDesktop) {
    throw "The native renderer accessibility check requires -AllowInteractiveDesktop because it moves focus and uses the active desktop."
}

$resolvedPath = [IO.Path]::GetFullPath($Path)
if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
    throw "Renderer binary was not found: $resolvedPath"
}
if ($Iterations -lt 1 -or $Iterations -gt 20) {
    throw "Iterations must be between 1 and 20."
}

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

if (-not ('AuthorizationATemplate.UiQa.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

namespace AuthorizationATemplate.UiQa
{
    public static class Native
    {
        public const uint GW_CHILD = 5;
        public const uint GW_HWNDNEXT = 2;
        public const uint SWP_NOMOVE = 0x0002;
        public const uint SWP_NOZORDER = 0x0004;
        public const uint SWP_NOACTIVATE = 0x0010;
        public const uint RDW_INVALIDATE = 0x0001;
        public const uint RDW_ERASE = 0x0004;
        public const uint RDW_UPDATENOW = 0x0100;
        public const uint RDW_FRAME = 0x0400;
        public const uint SPI_GETHIGHCONTRAST = 0x0042;
        public const uint HCF_HIGHCONTRASTON = 0x00000001;

        [StructLayout(LayoutKind.Sequential)]
        public struct Rect
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HighContrast
        {
            public uint Size;
            public uint Flags;
            public IntPtr DefaultScheme;
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int maxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int GetClassName(IntPtr hwnd, StringBuilder text, int maxCount);

        [DllImport("user32.dll")]
        public static extern IntPtr GetWindow(IntPtr hwnd, uint command);

        [DllImport("user32.dll")]
        public static extern int GetDlgCtrlID(IntPtr hwnd);

        [DllImport("user32.dll")]
        public static extern bool GetWindowRect(IntPtr hwnd, out Rect rect);

        [DllImport("user32.dll")]
        public static extern uint GetDpiForWindow(IntPtr hwnd);

        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hwnd);

        [DllImport("user32.dll")]
        public static extern IntPtr SetFocus(IntPtr hwnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetWindowText(IntPtr hwnd, string text);

        [DllImport("user32.dll")]
        public static extern bool RedrawWindow(
            IntPtr hwnd,
            IntPtr updateRect,
            IntPtr updateRegion,
            uint flags);

        [DllImport("kernel32.dll", EntryPoint = "GetCurrentThreadId")]
        public static extern uint GetCurrentThreadIdFromKernel();

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hwnd, IntPtr processId);

        [DllImport("user32.dll")]
        public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool attach);

        [DllImport("user32.dll")]
        public static extern bool BringWindowToTop(IntPtr hwnd);

        [DllImport("user32.dll")]
        public static extern bool SetWindowPos(
            IntPtr hwnd,
            IntPtr insertAfter,
            int x,
            int y,
            int width,
            int height,
            uint flags);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SystemParametersInfo(
            uint action,
            uint parameter,
            ref HighContrast data,
            uint flags);
    }
}
'@
}

function Get-NativeText([IntPtr]$Hwnd) {
    $buffer = New-Object Text.StringBuilder 512
    [AuthorizationATemplate.UiQa.Native]::GetWindowText($Hwnd, $buffer, $buffer.Capacity) | Out-Null
    return $buffer.ToString()
}

function Get-NativeClass([IntPtr]$Hwnd) {
    $buffer = New-Object Text.StringBuilder 128
    [AuthorizationATemplate.UiQa.Native]::GetClassName($Hwnd, $buffer, $buffer.Capacity) | Out-Null
    return $buffer.ToString()
}

function Get-ChildWindows([IntPtr]$Parent) {
    $result = @()
    $child = [AuthorizationATemplate.UiQa.Native]::GetWindow(
        $Parent,
        [AuthorizationATemplate.UiQa.Native]::GW_CHILD)
    while ($child -ne [IntPtr]::Zero) {
        $result += $child
        $child = [AuthorizationATemplate.UiQa.Native]::GetWindow(
            $child,
            [AuthorizationATemplate.UiQa.Native]::GW_HWNDNEXT)
    }
    return $result
}

function Get-UiaElement([System.Windows.Automation.AutomationElement]$Root, [string]$AutomationId) {
    $condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
        $AutomationId)
    return $Root.FindFirst(
        [System.Windows.Automation.TreeScope]::Descendants,
        $condition)
}

function Wait-FocusedId([string]$ExpectedId) {
    $lastId = "<none>"
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        $focused = [System.Windows.Automation.AutomationElement]::FocusedElement
        if ($null -ne $focused) {
            $lastId = $focused.Current.AutomationId
        }
        if ($null -ne $focused -and $lastId -eq $ExpectedId) {
            return $focused
        }
        Start-Sleep -Milliseconds 100
    }
    throw "UI Automation focus did not settle on $ExpectedId; last observed id was $lastId."
}

function Set-NativeFocusedControl(
    [IntPtr]$Hwnd,
    [IntPtr]$ControlHwnd,
    [string]$ExpectedId) {
    # The built-in Win32 UIA provider may expose a visible Edit/Button as a
    # Pane that rejects AutomationElement.SetFocus(). Native focus remains the
    # authoritative input path, so retry it while waiting for UIA to observe it.
    $lastId = "<none>"
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        Activate-RendererWindow $Hwnd $ControlHwnd
        [AuthorizationATemplate.UiQa.Native]::SetFocus($ControlHwnd) | Out-Null
        Start-Sleep -Milliseconds 75
        $focused = [System.Windows.Automation.AutomationElement]::FocusedElement
        if ($null -ne $focused) {
            $lastId = $focused.Current.AutomationId
        }
        if ($null -ne $focused -and $lastId -eq $ExpectedId) {
            return $focused
        }
    }
    throw "Native focus did not settle on $ExpectedId; last observed id was $lastId."
}

function Send-NativeTab(
    [IntPtr]$Hwnd,
    [IntPtr]$CurrentControlHwnd,
    [string]$ExpectedId) {
    Activate-RendererWindow $Hwnd $CurrentControlHwnd
    [AuthorizationATemplate.UiQa.Native]::SetFocus($CurrentControlHwnd) | Out-Null
    [System.Windows.Forms.SendKeys]::SendWait("{TAB}")
    Start-Sleep -Milliseconds 100
    return Wait-FocusedId $ExpectedId
}

function Set-VisualCredentialForQa([IntPtr]$ControlHwnd, [string]$Value) {
    Assert-True "set QA credential text" (
        [AuthorizationATemplate.UiQa.Native]::SetWindowText($ControlHwnd, $Value))
    $redrawFlags = [AuthorizationATemplate.UiQa.Native]::RDW_INVALIDATE -bor
        [AuthorizationATemplate.UiQa.Native]::RDW_ERASE -bor
        [AuthorizationATemplate.UiQa.Native]::RDW_UPDATENOW -bor
        [AuthorizationATemplate.UiQa.Native]::RDW_FRAME
    Assert-True "redraw QA credential" (
        [AuthorizationATemplate.UiQa.Native]::RedrawWindow(
            $ControlHwnd,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            $redrawFlags))
}

function Test-InvokePattern(
    [System.Windows.Automation.AutomationElement]$Element,
    [string]$Name) {
    $invoke = $null
    $available = $Element.TryGetCurrentPattern(
        [System.Windows.Automation.InvokePattern]::Pattern,
        [ref]$invoke)
    if ($RequireUiaPatterns -and -not $available) {
        throw "$Name did not expose UI Automation InvokePattern."
    }
    return $available
}

function Activate-RendererWindow([IntPtr]$Hwnd, [IntPtr]$ControlHwnd) {
    $currentThread = [AuthorizationATemplate.UiQa.Native]::GetCurrentThreadIdFromKernel()
    $targetThread = [AuthorizationATemplate.UiQa.Native]::GetWindowThreadProcessId($Hwnd, [IntPtr]::Zero)
    $attached = $false
    try {
        if ($targetThread -ne $currentThread) {
            $attached = [AuthorizationATemplate.UiQa.Native]::AttachThreadInput(
                $currentThread, $targetThread, $true)
        }
        [AuthorizationATemplate.UiQa.Native]::BringWindowToTop($Hwnd) | Out-Null
        [AuthorizationATemplate.UiQa.Native]::SetForegroundWindow($Hwnd) | Out-Null
        [AuthorizationATemplate.UiQa.Native]::SetFocus($ControlHwnd) | Out-Null
    } finally {
        if ($attached) {
            [AuthorizationATemplate.UiQa.Native]::AttachThreadInput(
                $currentThread, $targetThread, $false) | Out-Null
        }
    }
}

function Assert-Equal([string]$Name, $Expected, $Actual) {
    if ($Expected -ne $Actual) {
        throw "$Name expected '$Expected' but received '$Actual'."
    }
}

function Assert-True([string]$Name, [bool]$Value) {
    if (-not $Value) {
        throw "$Name was false."
    }
}

function Save-WindowScreenshot([IntPtr]$Hwnd, [string]$Destination) {
    $rect = New-Object AuthorizationATemplate.UiQa.Native+Rect
    Assert-True "GetWindowRect" ([AuthorizationATemplate.UiQa.Native]::GetWindowRect($Hwnd, [ref]$rect))
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    Assert-True "screenshot width" ($width -gt 0)
    Assert-True "screenshot height" ($height -gt 0)

    $bitmap = New-Object System.Drawing.Bitmap($width, $height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
        $bitmap.Save($Destination, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

function Assert-ControlHasVisibleTextPixels([IntPtr]$Hwnd) {
    $rect = New-Object AuthorizationATemplate.UiQa.Native+Rect
    Assert-True "GetWindowRect visible text control" (
        [AuthorizationATemplate.UiQa.Native]::GetWindowRect($Hwnd, [ref]$rect))
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    Assert-True "visible text control width" ($width -gt 24)
    Assert-True "visible text control height" ($height -gt 12)

    $bitmap = New-Object System.Drawing.Bitmap($width, $height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
        $brightPixels = 0
        $right = [Math]::Max(9, [Math]::Floor($width * 0.72))
        for ($y = 4; $y -lt ($height - 4); $y++) {
            for ($x = 8; $x -lt $right; $x++) {
                $pixel = $bitmap.GetPixel($x, $y)
                $luminance = (299 * $pixel.R + 587 * $pixel.G + 114 * $pixel.B) / 1000
                if ($luminance -ge 120) {
                    $brightPixels++
                }
            }
        }
        Assert-True "credential visible foreground pixels" ($brightPixels -ge 80)
    } finally {
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

function Get-HighContrastEnabled {
    $value = New-Object AuthorizationATemplate.UiQa.Native+HighContrast
    $value.Size = [Runtime.InteropServices.Marshal]::SizeOf($value)
    if (-not [AuthorizationATemplate.UiQa.Native]::SystemParametersInfo(
        [AuthorizationATemplate.UiQa.Native]::SPI_GETHIGHCONTRAST,
        $value.Size,
        [ref]$value,
        0)) {
        return $false
    }
    return ($value.Flags -band [AuthorizationATemplate.UiQa.Native]::HCF_HIGHCONTRASTON) -ne 0
}

function Wait-RendererWindow([System.Diagnostics.Process]$Process) {
    $Process.WaitForInputIdle(5000) | Out-Null
    for ($index = 0; $index -lt 50; $index++) {
        Start-Sleep -Milliseconds 100
        $Process.Refresh()
        if ($Process.MainWindowHandle -ne [IntPtr]::Zero) {
            return $Process.MainWindowHandle
        }
        if ($Process.HasExited) {
            throw "Renderer exited before exposing a native window."
        }
    }
    throw "Renderer did not expose a native window within 5 seconds."
}

function Assert-NoCompanionProcesses([int]$ProcessId) {
    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcessId")
    if ($children.Count -gt 0) {
        $names = ($children | ForEach-Object { "$($_.Name)($($_.ProcessId))" }) -join ", "
        throw "Renderer spawned companion processes: $names"
    }
}

New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
$reportPath = Join-Path $EvidenceDirectory "windows-renderer-accessibility.json"
$screenshotPaths = [ordered]@{}
$mainProcess = $null
$mainHwnd = [IntPtr]::Zero
$report = [ordered]@{
    binary = $resolvedPath
    arguments = $Arguments
    iterations = $Iterations
    interactive_desktop_allowed = [bool]$AllowInteractiveDesktop
    include_resize_check = [bool]$IncludeResizeCheck
    high_contrast_at_start = Get-HighContrastEnabled
    controls = @()
    tab_sequence = @()
    dpi = $null
    dpi_percent = $null
    screenshots = $screenshotPaths
    repeated_runs = @()
    uia_focused_patterns = @()
}

$isLoading = $Arguments -contains "--loading"
$uiaIds = @()
if ($Arguments -contains "--active") {
    $uiaIds += "1001", "1002", "1103", "1106", "1107"
} elseif ($Arguments -contains "--grace") {
    $uiaIds += "1001", "1002", "1103", "1106", "1107"
} elseif ($isLoading) {
    $uiaIds += "1001", "1002", "1005", "1101", "1102", "1106", "1107"
} else {
    $uiaIds += "1005", "1101", "1102", "1106", "1107"
}

try {
    if ($Arguments.Count -gt 0) {
        $mainProcess = Start-Process -FilePath $resolvedPath -ArgumentList $Arguments -PassThru
    } else {
        $mainProcess = Start-Process -FilePath $resolvedPath -PassThru
    }
    $mainHwnd = Wait-RendererWindow $mainProcess
    Assert-NoCompanionProcesses $mainProcess.Id

    $nativeTitle = Get-NativeText $mainHwnd
    Assert-True "native window title" (-not [string]::IsNullOrWhiteSpace($nativeTitle))

    $dpi = [AuthorizationATemplate.UiQa.Native]::GetDpiForWindow($mainHwnd)
    if ($dpi -lt 96) {
        throw "Renderer reported an invalid DPI: $dpi"
    }
    $dpiPercent = [Math]::Round(($dpi * 100.0) / 96.0)
    if ($RequireDpiPercent -gt 0 -and $dpiPercent -lt $RequireDpiPercent) {
        throw "Required DPI ${RequireDpiPercent}% was not available; window reported ${dpiPercent}%."
    }
    $report.dpi = $dpi
    $report.dpi_percent = $dpiPercent

    $root = [System.Windows.Automation.AutomationElement]::FromHandle($mainHwnd)
    if ($null -eq $root) {
        throw "UI Automation could not open the renderer root."
    }

    $nativeById = @{}
    foreach ($child in (Get-ChildWindows $mainHwnd)) {
        $id = [AuthorizationATemplate.UiQa.Native]::GetDlgCtrlID($child).ToString()
        $childRect = New-Object AuthorizationATemplate.UiQa.Native+Rect
        Assert-True "GetWindowRect child $id" ([AuthorizationATemplate.UiQa.Native]::GetWindowRect($child, [ref]$childRect))
        $nativeById[$id] = [ordered]@{
            hwnd = $child
            id = $id
            class = Get-NativeClass $child
            text = Get-NativeText $child
            rect = [ordered]@{
                left = $childRect.Left
                top = $childRect.Top
                right = $childRect.Right
                bottom = $childRect.Bottom
            }
        }
    }

    $expected = @{
        "1001" = "Static"
        "1002" = "Static"
        "1003" = "Static"
        "1004" = "Static"
        "1005" = "Static"
        "1101" = "RICHEDIT50W"
        "1102" = "Button"
        "1103" = "Button"
        "1104" = "Button"
        "1105" = "Button"
        "1106" = "Button"
        "1107" = "Button"
    }
    foreach ($id in $expected.Keys) {
        if (-not $nativeById.ContainsKey($id)) {
            throw "Native control $id was not created."
        }
        Assert-Equal "native class $id" $expected[$id] $nativeById[$id].class
    }

    Assert-True "credential reserves field-state space" (
        $nativeById["1101"].rect.right -le $nativeById["1012"].rect.left)

    if (-not $isLoading) {
        $initialControlId = if ($Arguments -contains "--active" -or $Arguments -contains "--grace") { "1103" } else { "1101" }
        $focused = Set-NativeFocusedControl $mainHwnd $nativeById[$initialControlId].hwnd $initialControlId
        if ($Arguments -contains "--active" -or $Arguments -contains "--grace") {
            Assert-Equal "initial focus" "1103" $focused.Current.AutomationId
        } else {
            Assert-Equal "initial focus" "1101" $focused.Current.AutomationId
            Assert-Equal "credential native class" "RICHEDIT50W" $nativeById["1101"].class
        }
        $first = $focused.Current.AutomationId
    }

    if ($isLoading) {
        $report.tab_sequence = @()
        $report.uia_focused_patterns = @("loading:credential-and-action-disabled")
    } elseif ($Arguments -contains "--active") {
        Assert-Equal "active initial focus" "1103" $first
        Assert-Equal "active native class" "Button" $nativeById["1103"].class
        $activePattern = Test-InvokePattern $focused "active launch"
        $focusedPurchase = Send-NativeTab $mainHwnd $nativeById["1103"].hwnd "1106"
        $focusedContact = Send-NativeTab $mainHwnd $nativeById["1106"].hwnd "1107"
        $report.tab_sequence = @(
            $first,
            $focusedPurchase.Current.AutomationId,
            $focusedContact.Current.AutomationId
        )
        $report.uia_focused_patterns = @("active:$($focused.Current.ControlType.ProgrammaticName):InvokePattern=$activePattern")
    } elseif ($Arguments -contains "--grace") {
        Assert-Equal "grace initial focus" "1103" $first
        Assert-Equal "grace launch native class" "Button" $nativeById["1103"].class
        $graceLaunchPattern = Test-InvokePattern $focused "grace launch"
        $focusedPurchase = Send-NativeTab $mainHwnd $nativeById["1103"].hwnd "1106"
        $focusedContact = Send-NativeTab $mainHwnd $nativeById["1106"].hwnd "1107"
        $report.tab_sequence = @(
            $first,
            $focusedPurchase.Current.AutomationId,
            $focusedContact.Current.AutomationId
        )
        $report.uia_focused_patterns = @(
            "grace-launch:$($focused.Current.ControlType.ProgrammaticName):InvokePattern=$graceLaunchPattern"
        )
    } else {
        $qaCredential = "ABCD-1234-5678-9000"
        Activate-RendererWindow $mainHwnd $nativeById["1101"].hwnd
        Start-Sleep -Milliseconds 100
        Set-VisualCredentialForQa $nativeById["1101"].hwnd $qaCredential
        Start-Sleep -Milliseconds 100
        Assert-Equal "visible credential text" $qaCredential (Get-NativeText $nativeById["1101"].hwnd)
        if (-not $NoScreenshots) {
            $credentialScreenshot = Join-Path $EvidenceDirectory "renderer-credential-${dpiPercent}dpi.png"
            Save-WindowScreenshot $mainHwnd $credentialScreenshot
            $screenshotPaths.credential = $credentialScreenshot
        }
        Assert-ControlHasVisibleTextPixels $nativeById["1101"].hwnd
        $focusedButton = Send-NativeTab $mainHwnd $nativeById["1101"].hwnd "1102"
        $second = $focusedButton.Current.AutomationId
        if ($null -eq $focusedButton) {
            throw "UI Automation did not expose the focused activation button."
        }
        Assert-Equal "activation native class" "Button" $nativeById["1102"].class
        $activationPattern = Test-InvokePattern $focusedButton "activation button"
        $focusedPurchase = Send-NativeTab $mainHwnd $nativeById["1102"].hwnd "1106"
        $third = $focusedPurchase.Current.AutomationId
        $focusedContact = Send-NativeTab $mainHwnd $nativeById["1106"].hwnd "1107"
        $fourth = $focusedContact.Current.AutomationId
        Assert-Equal "initial focus" "1101" $first
        Assert-Equal "first Tab focus" "1102" $second
        Assert-Equal "second Tab focus" "1106" $third
        Assert-Equal "third Tab focus" "1107" $fourth
        Assert-Equal "credential native class" "RICHEDIT50W" $nativeById["1101"].class
        $report.tab_sequence = @($first, $second, $third, $fourth)
        $report.uia_focused_patterns = @(
            "credential:native-Edit",
            "activation:$($focusedButton.Current.ControlType.ProgrammaticName):InvokePattern=$activationPattern"
        )
    }

    # Enumerate UIA properties after the focus checks. The built-in Win32 UIA
    # provider can report Pane for unfocused controls on this host, so the
    # report preserves both UIA properties and the native class/ID evidence.
    # Pattern availability is recorded as observed; -RequireUiaPatterns makes
    # it a hard gate on hosts whose provider exposes the standard patterns.
    foreach ($id in $uiaIds) {
        $uia = Get-UiaElement $root $id
        if ($null -eq $uia) {
            throw "UI Automation element $id was not discoverable."
        }
        $current = $uia.Current
        $record = [ordered]@{
            id = $id
            native_class = $nativeById[$id].class
            native_text = $nativeById[$id].text
            uia_name = $current.Name
            uia_control_type = $current.ControlType.ProgrammaticName
            uia_enabled = $current.IsEnabled
            uia_keyboard_focusable = $current.IsKeyboardFocusable
            uia_offscreen = $current.IsOffscreen
        }
        $report.controls += $record
        if ($id -in @("1001", "1002", "1003", "1004", "1005", "1102", "1103", "1104", "1105")) {
            Assert-True "UI Automation name $id" (-not [string]::IsNullOrWhiteSpace($current.Name))
        }
    }

    if ($isLoading) {
        $loadingCredential = $report.controls | Where-Object { $_.id -eq "1101" }
        $loadingAction = $report.controls | Where-Object { $_.id -eq "1102" }
        Assert-True "loading credential disabled" (-not $loadingCredential.uia_enabled)
        Assert-True "loading action disabled" (-not $loadingAction.uia_enabled)
    }

    if ($Arguments -contains "--active" -or $Arguments -contains "--grace" -or $isLoading) {
        $primaryId = if ($Arguments -contains "--active" -or $Arguments -contains "--grace") { "1103" } else { "1102" }
        Assert-True "primary action precedes feedback title" (
            $nativeById[$primaryId].rect.bottom -le $nativeById["1001"].rect.top)
        Assert-True "feedback title precedes feedback detail" (
            $nativeById["1001"].rect.bottom -le $nativeById["1002"].rect.top)
    }

    if (-not $NoScreenshots) {
        $baseline = Join-Path $EvidenceDirectory "renderer-baseline-${dpiPercent}dpi.png"
        Save-WindowScreenshot $mainHwnd $baseline
        $screenshotPaths.baseline = $baseline

        if ($IncludeResizeCheck) {
            $originalRect = New-Object AuthorizationATemplate.UiQa.Native+Rect
            Assert-True "GetWindowRect before resize" (
                [AuthorizationATemplate.UiQa.Native]::GetWindowRect($mainHwnd, [ref]$originalRect))
            $originalWidth = $originalRect.Right - $originalRect.Left
            $originalHeight = $originalRect.Bottom - $originalRect.Top
            $minimumWidth = [Math]::Ceiling(806 * $dpi / 96.0)
            $minimumHeight = [Math]::Ceiling(598 * $dpi / 96.0)
            [AuthorizationATemplate.UiQa.Native]::SetWindowPos(
                $mainHwnd,
                [IntPtr]::Zero,
                0,
                0,
                $minimumWidth,
                $minimumHeight,
                [AuthorizationATemplate.UiQa.Native]::SWP_NOMOVE -bor
                [AuthorizationATemplate.UiQa.Native]::SWP_NOZORDER -bor
                [AuthorizationATemplate.UiQa.Native]::SWP_NOACTIVATE) | Out-Null
            Start-Sleep -Milliseconds 200
            $small = Join-Path $EvidenceDirectory "renderer-minimum-${dpiPercent}dpi.png"
            Save-WindowScreenshot $mainHwnd $small
            $screenshotPaths.minimum_window = $small
            [AuthorizationATemplate.UiQa.Native]::SetWindowPos(
                $mainHwnd,
                [IntPtr]::Zero,
                0,
                0,
                $originalWidth,
                $originalHeight,
                [AuthorizationATemplate.UiQa.Native]::SWP_NOMOVE -bor
                [AuthorizationATemplate.UiQa.Native]::SWP_NOZORDER -bor
                [AuthorizationATemplate.UiQa.Native]::SWP_NOACTIVATE) | Out-Null
        }
    }

    $mainProcess.Refresh()
    $report.main_private_memory_bytes = $mainProcess.PrivateMemorySize64
    $report.main_handle_count = $mainProcess.HandleCount
} finally {
    if ($null -ne $mainProcess -and -not $mainProcess.HasExited) {
        $mainProcess.CloseMainWindow() | Out-Null
        $mainProcess.WaitForExit(5000) | Out-Null
    }
    if ($null -ne $mainProcess -and -not $mainProcess.HasExited) {
        $mainProcess.Kill()
        $mainProcess.WaitForExit(5000) | Out-Null
    }
}

if ($null -ne $mainProcess -and -not $mainProcess.HasExited) {
    throw "Renderer did not exit after its window was closed."
}

for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
    $process = Start-Process -FilePath $resolvedPath -ArgumentList "--smoke" -PassThru
    try {
        if (-not $process.WaitForExit(5000)) {
            throw "Smoke iteration $iteration did not exit within 5 seconds."
        }
        Assert-Equal "smoke exit code $iteration" 0 $process.ExitCode
        $report.repeated_runs += [ordered]@{
            iteration = $iteration
            exit_code = $process.ExitCode
        }
    } finally {
        if (-not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit(5000) | Out-Null
        }
    }
}

$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Output "windows-renderer-accessibility PASS"
Write-Output "binary=$resolvedPath"
Write-Output "dpi=$($report['dpi']) ($($report['dpi_percent'])%) high_contrast=$($report['high_contrast_at_start'])"
Write-Output "controls=$($report.controls.Count) tab=$($report.tab_sequence -join ' -> ')"
Write-Output "main_private_memory_bytes=$($report.main_private_memory_bytes) main_handle_count=$($report.main_handle_count)"
Write-Output "repeated_runs=$Iterations companion_processes=0"
Write-Output "report=$reportPath"
