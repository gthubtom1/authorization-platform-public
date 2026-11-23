//! Product-neutral native Windows renderer for `authorization-a-ui.v1`.
//!
//! This module is a thin Win32 presentation boundary. It consumes a
//! validated [`UiRenderSnapshot`], renders standard Windows controls, and reports
//! [`UiIntent`] values to its caller. It does not contact the licensing
//! platform, open the core, persist credentials, or decide whether a launch is
//! allowed. The caller remains responsible for handling an intent and
//! re-checking the signed authorization state.

use std::fmt;

use super::{
    UiAuthorizationState, UiIntent, UiModuleCard, UiRenderSnapshot, UiShellModel, UiViewState,
    AUTHORIZATION_A_UI_PROTOCOL_VERSION,
};

pub const WINDOWS_RENDERER_MINIMUM_OS: &str = "Windows 10 version 1607";
pub const WINDOWS_RENDERER_CLASS_NAME: &str = "AuthorizationATemplateNativeWindow";
/// Keep the credential control bounded so a paste cannot create an unbounded
/// temporary UTF-16 allocation on the UI thread. The runtime still owns the
/// authoritative credential policy; this is only a renderer safety ceiling.
pub const WINDOWS_RENDERER_MAX_CREDENTIAL_CHARS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsRendererConfig {
    pub title: String,
    pub width: i32,
    pub height: i32,
    pub min_width: i32,
    pub min_height: i32,
}

impl Default for WindowsRendererConfig {
    fn default() -> Self {
        Self {
            title: "软件授权".to_string(),
            width: 990,
            height: 700,
            min_width: 806,
            min_height: 598,
        }
    }
}

impl WindowsRendererConfig {
    pub fn validate(&self) -> Result<(), WindowsRendererError> {
        if self.title.trim().is_empty() || self.title.chars().count() > 128 {
            return Err(WindowsRendererError::InvalidConfig(
                "title must contain 1-128 characters".to_string(),
            ));
        }
        if self.width < self.min_width || self.height < self.min_height {
            return Err(WindowsRendererError::InvalidConfig(
                "initial size must not be smaller than the minimum size".to_string(),
            ));
        }
        if !(320..=4096).contains(&self.min_width) || !(240..=4096).contains(&self.min_height) {
            return Err(WindowsRendererError::InvalidConfig(
                "minimum size is outside the supported range".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsRendererError {
    UnsupportedPlatform,
    InvalidConfig(String),
    InvalidModel(String),
    Win32 { operation: String, code: u32 },
    MessageLoop { code: u32 },
}

impl fmt::Display for WindowsRendererError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "the native renderer requires Windows"),
            Self::InvalidConfig(message) => {
                write!(f, "invalid Windows renderer config: {message}")
            }
            Self::InvalidModel(message) => write!(f, "invalid UI shell model: {message}"),
            Self::Win32 { operation, code } => {
                write!(f, "Win32 operation {operation} failed ({code})")
            }
            Self::MessageLoop { code } => write!(f, "Windows message loop failed ({code})"),
        }
    }
}

impl std::error::Error for WindowsRendererError {}

/// A native renderer session. Construction validates the presentation snapshot;
/// the actual HWND and controls are created only by [`Self::run`] on Windows.
#[derive(Debug, Clone)]
pub struct WindowsRenderer {
    config: WindowsRendererConfig,
    snapshot: UiRenderSnapshot,
}

impl WindowsRenderer {
    pub fn new(
        config: WindowsRendererConfig,
        snapshot: UiRenderSnapshot,
    ) -> Result<Self, WindowsRendererError> {
        config.validate()?;
        validate_snapshot(&snapshot)?;
        Ok(Self { config, snapshot })
    }

    pub fn model(&self) -> &UiShellModel {
        &self.snapshot.model
    }

    /// Replace the complete validated snapshot before the next native session.
    /// A renderer never accepts a partial status update, which keeps
    /// visibility decisions tied to one coherent state snapshot. An already
    /// running `run` call owns its cloned session snapshot and is not updated
    /// by this method.
    pub fn snapshot(&self) -> &UiRenderSnapshot {
        &self.snapshot
    }

    pub fn update_snapshot(
        &mut self,
        snapshot: UiRenderSnapshot,
    ) -> Result<(), WindowsRendererError> {
        validate_snapshot(&snapshot)?;
        self.snapshot = snapshot;
        Ok(())
    }

    /// Create a native window and run its message loop. `on_intent` is the
    /// logical bridge out of the renderer. Login text is delivered separately
    /// to `on_credential` as a borrowed UTF-16 slice and is zeroed immediately
    /// after the callback returns; it is never put in `UiIntent`, the model,
    /// module fields or a persisted record.
    pub fn run<F, G>(&mut self, on_intent: F, on_credential: G) -> Result<(), WindowsRendererError>
    where
        F: FnMut(UiIntent) + 'static,
        G: FnMut(&[u16]) + 'static,
    {
        #[cfg(windows)]
        {
            native::run(&self.config, &self.snapshot, on_intent, on_credential)
        }
        #[cfg(not(windows))]
        {
            let _ = on_intent;
            let _ = on_credential;
            Err(WindowsRendererError::UnsupportedPlatform)
        }
    }

    /// Create and close one real native window without entering a user-facing
    /// session. This is intended for a local Windows smoke check; it does not
    /// prove UI Automation, screenshot quality, or production packaging.
    pub fn smoke_test(&mut self) -> Result<(), WindowsRendererError> {
        #[cfg(windows)]
        {
            native::smoke(&self.config, &self.snapshot)
        }
        #[cfg(not(windows))]
        {
            Err(WindowsRendererError::UnsupportedPlatform)
        }
    }
}

fn validate_snapshot(snapshot: &UiRenderSnapshot) -> Result<(), WindowsRendererError> {
    let model = &snapshot.model;
    if model.schema_version != AUTHORIZATION_A_UI_PROTOCOL_VERSION {
        return Err(WindowsRendererError::InvalidModel(
            "schema_version is not authorization-a-ui.v1".to_string(),
        ));
    }
    for (name, value) in [
        ("product_id", model.product_id.as_str()),
        ("profile_id", model.profile_id.as_str()),
        ("display_name", model.display_name.as_str()),
        ("locale", model.locale.as_str()),
    ] {
        if !is_safe_text(value, 256) {
            return Err(WindowsRendererError::InvalidModel(format!(
                "{name} must contain 1-256 characters"
            )));
        }
    }
    for (name, value) in [
        ("accent", model.theme.accent.as_str()),
        ("surface", model.theme.surface.as_str()),
        ("text", model.theme.text.as_str()),
        ("danger", model.theme.danger.as_str()),
    ] {
        if !is_color(value) {
            return Err(WindowsRendererError::InvalidModel(format!(
                "theme.{name} is not a #RRGGBB or #RRGGBBAA color"
            )));
        }
    }
    for (key, value) in &snapshot.copy {
        if !super::UI_COPY_KEYS.contains(&key.as_str()) || !is_safe_text(value, 256) {
            return Err(WindowsRendererError::InvalidModel(format!(
                "copy.{key} is outside the presentation allowlist"
            )));
        }
    }
    Ok(())
}

fn is_safe_text(value: &str, max_chars: usize) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= max_chars
        && !value.chars().any(char::is_control)
}

fn is_color(value: &str) -> bool {
    (value.len() == 7 || value.len() == 9)
        && value.starts_with('#')
        && value.as_bytes()[1..]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr::{null, null_mut};

    type BOOL = i32;
    type ATOM = u16;
    type DWORD = u32;
    type HRESULT = i32;
    type HBRUSH = *mut c_void;
    type HCURSOR = *mut c_void;
    type HDC = *mut c_void;
    type HFONT = *mut c_void;
    type HGDIOBJ = *mut c_void;
    type HINSTANCE = *mut c_void;
    type HMENU = *mut c_void;
    type HWND = *mut c_void;
    type LPARAM = isize;
    type LRESULT = isize;
    type UINT = u32;
    type WPARAM = usize;
    type LPCWSTR = *const u16;

    const WS_OVERLAPPEDWINDOW: DWORD = 0x00CF0000;
    const WS_EX_CONTROLPARENT: DWORD = 0x00010000;
    const WS_CHILD: DWORD = 0x40000000;
    const WS_VISIBLE: DWORD = 0x10000000;
    const WS_TABSTOP: DWORD = 0x00010000;
    const WS_CLIPCHILDREN: DWORD = 0x02000000;
    const ES_AUTOHSCROLL: DWORD = 0x00000080;
    const BS_DEFPUSHBUTTON: DWORD = 0x00000001;
    const BS_PUSHBUTTON: DWORD = 0x00000000;
    const BS_OWNERDRAW: DWORD = 0x0000000B;
    const SS_LEFT: DWORD = 0x00000000;
    const SS_CENTER: DWORD = 0x00000001;
    const SS_OWNERDRAW: DWORD = 0x0000000D;
    const SS_NOPREFIX: DWORD = 0x00000080;
    const SW_HIDE: i32 = 0;
    const SW_SHOW: i32 = 5;
    const CW_USEDEFAULT: i32 = -0x80000000_i32;
    const WM_NCCREATE: UINT = 0x0081;
    const WM_DESTROY: UINT = 0x0002;
    const WM_SIZE: UINT = 0x0005;
    const WM_SETFOCUS: UINT = 0x0007;
    const WM_CLOSE: UINT = 0x0010;
    const WM_ERASEBKGND: UINT = 0x0014;
    const WM_SYSCOLORCHANGE: UINT = 0x0015;
    const WM_PAINT: UINT = 0x000F;
    const WM_DRAWITEM: UINT = 0x002B;
    const WM_GETMINMAXINFO: UINT = 0x0024;
    const WM_SETFONT: UINT = 0x0030;
    const WM_COMMAND: UINT = 0x0111;
    const WM_CTLCOLOREDIT: UINT = 0x0133;
    const WM_CTLCOLORSTATIC: UINT = 0x0138;
    const WM_DPICHANGED: UINT = 0x02E0;
    const WM_NCDESTROY: UINT = 0x0082;
    const WM_SETTINGCHANGE: UINT = 0x001A;
    const WM_THEMECHANGED: UINT = 0x031A;
    const WM_APP: UINT = 0x8000;
    const WM_APP_RENDERER_EXIT: UINT = WM_APP + 1;
    const WM_APP_CREDENTIAL_FORMAT: UINT = WM_APP + 2;
    const PM_REMOVE: UINT = 0x0001;
    const GWLP_USERDATA: i32 = -21;
    const SWP_NOZORDER: UINT = 0x0004;
    const SWP_NOACTIVATE: UINT = 0x0010;
    const BN_CLICKED: u16 = 0;
    const EN_CHANGE: u16 = 0x0300;
    const SPI_GETHIGHCONTRAST: UINT = 0x0042;
    const HCF_HIGHCONTRASTON: DWORD = 0x00000001;
    const PROCESS_PER_MONITOR_DPI_AWARE: i32 = 2;
    const COLOR_WINDOW: i32 = 5;
    const COLOR_WINDOWTEXT: i32 = 8;
    const COLOR_HIGHLIGHT: i32 = 13;
    const COLOR_HIGHLIGHTTEXT: i32 = 14;
    const TRANSPARENT: i32 = 1;
    const EM_SETCUEBANNER: UINT = 0x1501;
    const EM_SETMARGINS: UINT = 0x00D3;
    const EM_LIMITTEXT: UINT = 0x00C5;
    const EM_EMPTYUNDOBUFFER: UINT = 0x00CD;
    const EM_SETBKGNDCOLOR: UINT = 0x0443;
    const EM_SETCHARFORMAT: UINT = 0x0444;
    const SCF_DEFAULT: WPARAM = 0x0000;
    const SCF_ALL: WPARAM = 0x0004;
    const CFM_COLOR: DWORD = 0x40000000;
    const EC_LEFTMARGIN: WPARAM = 0x0001;
    const EC_RIGHTMARGIN: WPARAM = 0x0002;
    const OPAQUE: i32 = 2;
    const PS_SOLID: i32 = 0;
    const FW_NORMAL: i32 = 400;
    const FW_SEMIBOLD: i32 = 600;
    const DEFAULT_CHARSET: UINT = 1;
    const OUT_DEFAULT_PRECIS: UINT = 0;
    const CLIP_DEFAULT_PRECIS: UINT = 0;
    const CLEARTYPE_QUALITY: UINT = 5;
    const DEFAULT_PITCH: UINT = 0;
    const FF_DONTCARE: UINT = 0;
    const DT_SINGLELINE: UINT = 0x20;
    const DT_CENTER: UINT = 0x01;
    const DT_VCENTER: UINT = 0x04;
    const DT_NOPREFIX: UINT = 0x0800;
    const ODS_SELECTED: UINT = 0x0001;
    const ODS_DISABLED: UINT = 0x0004;
    const ODS_FOCUS: UINT = 0x0010;

    const ID_STATUS: i32 = 1001;
    const ID_DETAILS: i32 = 1002;
    const ID_MODULES: i32 = 1003;
    const ID_FOOTER: i32 = 1004;
    const ID_CREDENTIAL_LABEL: i32 = 1005;
    const ID_CREDENTIAL: i32 = 1101;
    const ID_ACTIVATE: i32 = 1102;
    const ID_LAUNCH: i32 = 1103;
    const ID_RETRY: i32 = 1104;
    const ID_MODULE_ACTION: i32 = 1105;
    const ID_APP_KICKER: i32 = 1006;
    const ID_HEADLINE: i32 = 1007;
    const ID_SUBHEADLINE: i32 = 1008;
    const ID_BRAND_MARK: i32 = 1009;
    const ID_BRAND_CAPTION: i32 = 1010;
    const ID_SECTION_KICKER: i32 = 1011;
    const ID_FIELD_STATE: i32 = 1012;
    const ID_DEVICE_LABEL: i32 = 1013;
    const ID_DEVICE_STATUS: i32 = 1014;
    const ID_DEVICE_DETAIL: i32 = 1015;
    const ID_DEVICE_CODE_LABEL: i32 = 1016;
    const ID_DEVICE_CODE: i32 = 1017;
    const ID_DEVICE_HINT: i32 = 1018;
    const ID_CONNECTION: i32 = 1019;
    const ID_PURCHASE: i32 = 1106;
    const ID_CONTACT: i32 = 1107;

    #[repr(C)]
    struct POINT {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RECT {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }

    #[repr(C)]
    struct MINMAXINFO {
        pt_reserved: POINT,
        pt_max_size: POINT,
        pt_max_position: POINT,
        pt_min_track_size: POINT,
        pt_max_track_size: POINT,
    }

    #[repr(C)]
    struct MSG {
        hwnd: HWND,
        message: UINT,
        w_param: WPARAM,
        l_param: LPARAM,
        time: DWORD,
        pt: POINT,
        private: DWORD,
    }

    #[repr(C)]
    struct CREATESTRUCTW {
        lp_create_params: *mut c_void,
        h_instance: HINSTANCE,
        h_menu: HMENU,
        hwnd_parent: HWND,
        cy: i32,
        cx: i32,
        y: i32,
        x: i32,
        style: isize,
        lpsz_name: LPCWSTR,
        lpsz_class: LPCWSTR,
        dw_ex_style: DWORD,
    }

    #[repr(C)]
    struct HIGHCONTRASTW {
        cb_size: DWORD,
        dw_flags: DWORD,
        lpsz_default_scheme: *mut u16,
    }

    #[repr(C)]
    struct DRAWITEMSTRUCT {
        ctl_type: UINT,
        ctl_id: UINT,
        item_id: UINT,
        item_action: UINT,
        item_state: UINT,
        hwnd_item: HWND,
        hdc: HDC,
        rc_item: RECT,
        item_data: usize,
    }

    #[repr(C)]
    struct PAINTSTRUCT {
        hdc: HDC,
        erase: BOOL,
        rc_paint: RECT,
        restore: BOOL,
        inc_update: BOOL,
        rgb_reserved: [u8; 32],
    }

    #[repr(C)]
    struct CHARFORMAT2W {
        cb_size: UINT,
        dw_mask: DWORD,
        dw_effects: DWORD,
        y_height: i32,
        y_offset: i32,
        cr_text_color: DWORD,
        charset: u8,
        pitch_and_family: u8,
        face_name: [u16; 32],
        weight: u16,
        spacing: i16,
        back_color: DWORD,
        locale_id: DWORD,
        cookie: DWORD,
        style: i16,
        kerning: u16,
        underline_type: u8,
        animation: u8,
        revision_author: u8,
        reserved: u8,
    }

    type WNDPROC = Option<unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT>;

    #[repr(C)]
    struct WNDCLASSW {
        style: UINT,
        lpfn_wnd_proc: WNDPROC,
        cb_cls_extra: i32,
        cb_wnd_extra: i32,
        h_instance: HINSTANCE,
        h_icon: *mut c_void,
        h_cursor: HCURSOR,
        hbr_background: HBRUSH,
        lpsz_menu_name: LPCWSTR,
        lpsz_class_name: LPCWSTR,
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn RegisterClassW(class: *const WNDCLASSW) -> ATOM;
        fn CreateWindowExW(
            ex_style: DWORD,
            class_name: LPCWSTR,
            window_name: LPCWSTR,
            style: DWORD,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            parent: HWND,
            menu: HMENU,
            instance: HINSTANCE,
            param: *mut c_void,
        ) -> HWND;
        fn DefWindowProcW(hwnd: HWND, message: UINT, w_param: WPARAM, l_param: LPARAM) -> LRESULT;
        fn BeginPaint(hwnd: HWND, paint: *mut PAINTSTRUCT) -> HDC;
        fn EndPaint(hwnd: HWND, paint: *const PAINTSTRUCT) -> BOOL;
        fn DestroyWindow(hwnd: HWND) -> BOOL;
        fn DispatchMessageW(message: *const MSG) -> LRESULT;
        fn EnableWindow(hwnd: HWND, enable: BOOL) -> BOOL;
        fn GetClientRect(hwnd: HWND, rect: *mut RECT) -> BOOL;
        fn GetDpiForSystem() -> UINT;
        fn GetDpiForWindow(hwnd: HWND) -> UINT;
        fn GetDlgCtrlID(hwnd: HWND) -> i32;
        fn GetMessageW(message: *mut MSG, hwnd: HWND, min: UINT, max: UINT) -> BOOL;
        fn GetSysColor(index: i32) -> DWORD;
        fn GetWindowLongPtrW(hwnd: HWND, index: i32) -> isize;
        fn GetWindowTextLengthW(hwnd: HWND) -> i32;
        fn GetWindowTextW(hwnd: HWND, text: *mut u16, length: i32) -> i32;
        fn InvalidateRect(hwnd: HWND, rect: *const RECT, erase: BOOL) -> BOOL;
        fn IsDialogMessageW(hwnd: HWND, message: *mut MSG) -> BOOL;
        fn LoadCursorW(instance: HINSTANCE, name: LPCWSTR) -> HCURSOR;
        fn MoveWindow(hwnd: HWND, x: i32, y: i32, width: i32, height: i32, repaint: BOOL) -> BOOL;
        fn PostMessageW(hwnd: HWND, message: UINT, w_param: WPARAM, l_param: LPARAM) -> BOOL;
        fn PostThreadMessageW(
            thread_id: DWORD,
            message: UINT,
            w_param: WPARAM,
            l_param: LPARAM,
        ) -> BOOL;
        fn PeekMessageW(
            message: *mut MSG,
            hwnd: HWND,
            min: UINT,
            max: UINT,
            remove_message: UINT,
        ) -> BOOL;
        fn SendMessageW(hwnd: HWND, message: UINT, w_param: WPARAM, l_param: LPARAM) -> LRESULT;
        fn SetFocus(hwnd: HWND) -> HWND;
        fn SetWindowPos(
            hwnd: HWND,
            insert_after: HWND,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            flags: UINT,
        ) -> BOOL;
        fn SetTextColor(hdc: HDC, color: DWORD) -> DWORD;
        fn SetWindowLongPtrW(hwnd: HWND, index: i32, value: isize) -> isize;
        fn SetWindowTextW(hwnd: HWND, text: LPCWSTR) -> BOOL;
        fn ShowWindow(hwnd: HWND, command: i32) -> BOOL;
        fn SystemParametersInfoW(action: UINT, param: UINT, data: *mut c_void, flags: UINT)
            -> BOOL;
        fn TranslateMessage(message: *const MSG) -> BOOL;
        fn UpdateWindow(hwnd: HWND) -> BOOL;
        fn DrawFocusRect(hdc: HDC, rect: *const RECT) -> BOOL;
        fn DrawTextW(hdc: HDC, text: LPCWSTR, length: i32, rect: *mut RECT, format: UINT) -> i32;
    }

    #[link(name = "gdi32")]
    unsafe extern "system" {
        fn CreateSolidBrush(color: DWORD) -> HBRUSH;
        fn CreateFontW(
            height: i32,
            width: i32,
            escapement: i32,
            orientation: i32,
            weight: i32,
            italic: u32,
            underline: u32,
            strike_out: u32,
            char_set: UINT,
            out_precision: UINT,
            clip_precision: UINT,
            quality: UINT,
            pitch_and_family: UINT,
            face_name: LPCWSTR,
        ) -> HFONT;
        fn CreatePen(style: i32, width: i32, color: DWORD) -> HGDIOBJ;
        fn DeleteObject(object: HGDIOBJ) -> BOOL;
        fn FillRect(hdc: HDC, rect: *const RECT, brush: HBRUSH) -> i32;
        fn RoundRect(
            hdc: HDC,
            left: i32,
            top: i32,
            right: i32,
            bottom: i32,
            width: i32,
            height: i32,
        ) -> BOOL;
        fn SetBkMode(hdc: HDC, mode: i32) -> i32;
        fn SetBkColor(hdc: HDC, color: DWORD) -> DWORD;
        fn SelectObject(object: HDC, selected: HGDIOBJ) -> HGDIOBJ;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLastError() -> DWORD;
        fn GetCurrentThreadId() -> DWORD;
        fn GetModuleHandleW(module_name: LPCWSTR) -> HINSTANCE;
        fn LoadLibraryW(module_name: LPCWSTR) -> HINSTANCE;
    }

    #[link(name = "shcore")]
    unsafe extern "system" {
        fn SetProcessDpiAwareness(value: i32) -> HRESULT;
    }

    pub(super) fn run<F, G>(
        config: &WindowsRendererConfig,
        snapshot: &UiRenderSnapshot,
        on_intent: F,
        on_credential: G,
    ) -> Result<(), WindowsRendererError>
    where
        F: FnMut(UiIntent) + 'static,
        G: FnMut(&[u16]) + 'static,
    {
        run_internal(config, snapshot, on_intent, on_credential, false)
    }

    pub(super) fn smoke(
        config: &WindowsRendererConfig,
        snapshot: &UiRenderSnapshot,
    ) -> Result<(), WindowsRendererError> {
        run_internal(config, snapshot, |_| {}, |_| {}, true)
    }

    fn run_internal<F, G>(
        config: &WindowsRendererConfig,
        snapshot: &UiRenderSnapshot,
        on_intent: F,
        on_credential: G,
        close_after_show: bool,
    ) -> Result<(), WindowsRendererError>
    where
        F: FnMut(UiIntent) + 'static,
        G: FnMut(&[u16]) + 'static,
    {
        unsafe {
            // Prefer per-monitor awareness; the fallback keeps the renderer
            // usable if the host process already selected another awareness
            // mode before A was initialized.
            if SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE) != 0 {
                // The fallback is intentionally omitted here: changing a
                // process-wide DPI mode after a window exists is unsafe, and
                // the caller may own other windows. The layout still uses the
                // DPI reported by the native window.
            }
            let instance = GetModuleHandleW(null());
            register_class(instance);
        }

        let state = Box::new(WindowState::new(
            config.clone(),
            snapshot.clone(),
            on_intent,
            on_credential,
        ));
        // The window owns this allocation after WM_NCCREATE; WM_NCDESTROY
        // converts it back into a Box exactly once. If creation fails, retain
        // ownership here so the Box drops normally.
        let state_ptr = Box::into_raw(state);
        let class_name = wide(WINDOWS_RENDERER_CLASS_NAME);
        let title = wide(&config.title);
        let instance = unsafe { GetModuleHandleW(null()) };
        let system_dpi = unsafe { GetDpiForSystem().max(96) };
        let scale_window_size =
            |value: i32| value.saturating_mul(system_dpi as i32).saturating_div(96);
        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_CONTROLPARENT,
                class_name.as_ptr(),
                title.as_ptr(),
                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                scale_window_size(config.width),
                scale_window_size(config.height),
                null_mut(),
                null_mut(),
                instance,
                state_ptr.cast(),
            )
        };
        if hwnd.is_null() {
            unsafe {
                drop(Box::from_raw(state_ptr));
            }
            return Err(unsafe { win32_error("CreateWindowExW") });
        }

        // Some host/theme combinations do not retain the title supplied to
        // CreateWindowExW through the handwritten ABI declaration. Set it
        // explicitly so the native window and its UIA root have a stable,
        // user-visible name.
        unsafe {
            if SetWindowTextW(hwnd, title.as_ptr()) == 0 {
                DestroyWindow(hwnd);
                drain_renderer_exit_messages();
                return Err(win32_error("SetWindowTextW(title)"));
            }
        }

        let startup_error = unsafe { (*state_ptr).startup_error.take() };
        if let Some(error) = startup_error {
            unsafe { DestroyWindow(hwnd) };
            drain_renderer_exit_messages();
            return Err(error);
        }

        unsafe {
            if !close_after_show {
                ShowWindow(hwnd, SW_SHOW);
                UpdateWindow(hwnd);
            }
            if close_after_show {
                if PostMessageW(hwnd, WM_CLOSE, 0, 0) == 0 {
                    DestroyWindow(hwnd);
                    return Err(win32_error("PostMessageW(WM_CLOSE)"));
                }
            }
        }

        let mut message = MSG {
            hwnd: null_mut(),
            message: 0,
            w_param: 0,
            l_param: 0,
            time: 0,
            pt: POINT { x: 0, y: 0 },
            private: 0,
        };
        loop {
            let result = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
            if result == 0 {
                unsafe {
                    DestroyWindow(hwnd);
                }
                drain_renderer_exit_messages();
                break;
            }
            if result == -1 {
                unsafe {
                    DestroyWindow(hwnd);
                }
                drain_renderer_exit_messages();
                return Err(unsafe {
                    WindowsRendererError::MessageLoop {
                        code: GetLastError(),
                    }
                });
            }
            if message.message == WM_APP_RENDERER_EXIT {
                break;
            }
            unsafe {
                if IsDialogMessageW(hwnd, &mut message) != 0 {
                    continue;
                }
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        Ok(())
    }

    unsafe fn register_class(instance: HINSTANCE) {
        let class_name = wide(WINDOWS_RENDERER_CLASS_NAME);
        let class = WNDCLASSW {
            style: 0,
            lpfn_wnd_proc: Some(window_proc),
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: instance,
            h_icon: null_mut(),
            h_cursor: LoadCursorW(null_mut(), 32512usize as *const u16),
            hbr_background: null_mut(),
            lpsz_menu_name: null(),
            lpsz_class_name: class_name.as_ptr(),
        };
        let _ = RegisterClassW(&class);
    }

    #[derive(Clone, Copy)]
    struct UiPalette {
        canvas: DWORD,
        text: DWORD,
        muted: DWORD,
        card: DWORD,
        border: DWORD,
        accent: DWORD,
        accent_text: DWORD,
        success: DWORD,
        warning: DWORD,
        danger: DWORD,
        feedback_success: DWORD,
        feedback_warning: DWORD,
        feedback_danger: DWORD,
        button_shadow: DWORD,
        button_pressed: DWORD,
        button_highlight: DWORD,
        secondary_pressed: DWORD,
        input: DWORD,
        input_border: DWORD,
    }

    #[derive(Clone, Copy)]
    struct Rgb {
        red: u8,
        green: u8,
        blue: u8,
    }

    fn palette(model: &UiRenderSnapshot, high_contrast: bool) -> UiPalette {
        if high_contrast {
            unsafe {
                return UiPalette {
                    canvas: GetSysColor(COLOR_WINDOW),
                    text: GetSysColor(COLOR_WINDOWTEXT),
                    muted: GetSysColor(COLOR_WINDOWTEXT),
                    card: GetSysColor(COLOR_WINDOW),
                    border: GetSysColor(COLOR_WINDOWTEXT),
                    accent: GetSysColor(COLOR_HIGHLIGHT),
                    accent_text: GetSysColor(COLOR_HIGHLIGHTTEXT),
                    success: GetSysColor(COLOR_HIGHLIGHT),
                    warning: GetSysColor(COLOR_HIGHLIGHT),
                    danger: GetSysColor(COLOR_HIGHLIGHT),
                    feedback_success: GetSysColor(COLOR_WINDOW),
                    feedback_warning: GetSysColor(COLOR_WINDOW),
                    feedback_danger: GetSysColor(COLOR_WINDOW),
                    button_shadow: GetSysColor(COLOR_WINDOWTEXT),
                    button_pressed: GetSysColor(COLOR_HIGHLIGHT),
                    button_highlight: GetSysColor(COLOR_HIGHLIGHTTEXT),
                    secondary_pressed: GetSysColor(COLOR_HIGHLIGHT),
                    input: GetSysColor(COLOR_WINDOW),
                    input_border: GetSysColor(COLOR_WINDOWTEXT),
                };
            }
        }

        let surface = rgb_from_hex(&model.theme.surface, Rgb::new(242, 245, 248));
        let text = rgb_from_hex(&model.theme.text, Rgb::new(24, 32, 44));
        let accent = rgb_from_hex(&model.theme.accent, Rgb::new(52, 120, 246));
        let dark_surface = luminance(surface) < 145;
        let canvas = if dark_surface {
            surface
        } else {
            mix(surface, Rgb::new(255, 255, 255), 18)
        };
        let card = if dark_surface {
            mix(surface, Rgb::new(52, 72, 88), 20)
        } else {
            Rgb::new(255, 255, 255)
        };
        let muted = mix(text, canvas, 56);
        let border = if dark_surface {
            mix(text, canvas, 84)
        } else {
            Rgb::new(229, 229, 234)
        };
        let input = if dark_surface {
            mix(card, surface, 76)
        } else {
            Rgb::new(255, 255, 255)
        };
        let input_border = if dark_surface {
            mix(accent, card, 28)
        } else {
            Rgb::new(199, 199, 204)
        };
        let success = if dark_surface {
            accent
        } else {
            Rgb::new(52, 199, 89)
        };
        let danger = rgb_from_hex(&model.theme.danger, Rgb::new(255, 129, 119));
        let warning = Rgb::new(255, 149, 0);
        let feedback_mix = if dark_surface { 10 } else { 8 };
        let button_shadow = mix(accent, Rgb::new(0, 0, 0), 30);
        let button_pressed = mix(accent, Rgb::new(0, 0, 0), 14);
        let button_highlight = if dark_surface {
            mix(accent, Rgb::new(255, 255, 255), 22)
        } else {
            Rgb::new(255, 255, 255)
        };
        let secondary_pressed = mix(card, accent, 8);
        let accent_text = if luminance(accent) > 150 {
            Rgb::new(18, 24, 32)
        } else {
            Rgb::new(255, 255, 255)
        };
        UiPalette {
            canvas: to_colorref(canvas),
            text: to_colorref(text),
            muted: to_colorref(muted),
            card: to_colorref(card),
            border: to_colorref(border),
            accent: to_colorref(accent),
            accent_text: to_colorref(accent_text),
            success: to_colorref(success),
            warning: to_colorref(warning),
            danger: to_colorref(danger),
            feedback_success: to_colorref(mix(card, success, feedback_mix)),
            feedback_warning: to_colorref(mix(card, warning, feedback_mix)),
            feedback_danger: to_colorref(mix(card, danger, feedback_mix)),
            button_shadow: to_colorref(button_shadow),
            button_pressed: to_colorref(button_pressed),
            button_highlight: to_colorref(button_highlight),
            secondary_pressed: to_colorref(secondary_pressed),
            input: to_colorref(input),
            input_border: to_colorref(input_border),
        }
    }

    impl Rgb {
        const fn new(red: u8, green: u8, blue: u8) -> Self {
            Self { red, green, blue }
        }
    }

    fn rgb_from_hex(value: &str, fallback: Rgb) -> Rgb {
        if value.len() < 7 || !value.starts_with('#') {
            return fallback;
        }
        let parse = |start: usize| u8::from_str_radix(&value[start..start + 2], 16).ok();
        match (parse(1), parse(3), parse(5)) {
            (Some(red), Some(green), Some(blue)) => Rgb::new(red, green, blue),
            _ => fallback,
        }
    }

    fn mix(from: Rgb, to: Rgb, amount: u8) -> Rgb {
        let amount = amount.min(100) as i32;
        let blend =
            |left: u8, right: u8| (left as i32 + (right as i32 - left as i32) * amount / 100) as u8;
        Rgb::new(
            blend(from.red, to.red),
            blend(from.green, to.green),
            blend(from.blue, to.blue),
        )
    }

    fn luminance(value: Rgb) -> u32 {
        (u32::from(value.red) * 299 + u32::from(value.green) * 587 + u32::from(value.blue) * 114)
            / 1000
    }

    fn to_colorref(value: Rgb) -> DWORD {
        u32::from(value.red) | (u32::from(value.green) << 8) | (u32::from(value.blue) << 16)
    }

    #[derive(Clone, Copy)]
    struct LayoutMetrics {
        margin: i32,
        vertical_span: i32,
        header_divider_y: i32,
        header_left: i32,
        header_text_width: i32,
        connection_x: i32,
        connection_width: i32,
        card_x: i32,
        card_y: i32,
        card_width: i32,
        card_bottom: i32,
        content_x: i32,
        content_width: i32,
        credential_y: i32,
        action_y: i32,
        retry_y: i32,
        feedback_y: i32,
        feedback_height: i32,
        device_divider_y: i32,
        device_summary_y: i32,
        device_detail_y: i32,
        device_code_y: i32,
        device_code_chip_x: i32,
        device_code_chip_width: i32,
        support_divider_y: i32,
        support_y: i32,
        support_button_width: i32,
        purchase_x: i32,
        contact_x: i32,
        modules_y: i32,
        modules_height: i32,
        module_action_x: i32,
        module_action_y: i32,
        module_action_width: i32,
        footer_y: i32,
    }

    struct WindowState {
        model: UiRenderSnapshot,
        hwnd: HWND,
        brand_mark: HWND,
        app_kicker: HWND,
        brand_caption: HWND,
        connection: HWND,
        section_kicker: HWND,
        headline: HWND,
        subheadline: HWND,
        status: HWND,
        details: HWND,
        field_state: HWND,
        modules: HWND,
        footer: HWND,
        credential_label: HWND,
        credential: HWND,
        device_label: HWND,
        device_status: HWND,
        device_detail: HWND,
        device_code_label: HWND,
        device_code: HWND,
        device_hint: HWND,
        activate: HWND,
        launch: HWND,
        retry: HWND,
        module_action: HWND,
        purchase: HWND,
        contact: HWND,
        canvas_brush: HBRUSH,
        card_brush: HBRUSH,
        input_brush: HBRUSH,
        accent_brush: HBRUSH,
        feedback_brush: HBRUSH,
        palette: UiPalette,
        font_brand: HFONT,
        font_kicker: HFONT,
        font_headline: HFONT,
        font_body: HFONT,
        font_input: HFONT,
        font_status: HFONT,
        font_small: HFONT,
        font_device_code: HFONT,
        font_button: HFONT,
        min_width: i32,
        min_height: i32,
        dpi: UINT,
        startup_error: Option<WindowsRendererError>,
        on_intent: Box<dyn FnMut(UiIntent)>,
        on_credential: Box<dyn FnMut(&[u16])>,
        launch_auto_sent: bool,
    }

    impl WindowState {
        fn new<F, G>(
            config: WindowsRendererConfig,
            model: UiRenderSnapshot,
            on_intent: F,
            on_credential: G,
        ) -> Self
        where
            F: FnMut(UiIntent) + 'static,
            G: FnMut(&[u16]) + 'static,
        {
            let high_contrast = high_contrast_enabled();
            let palette = palette(&model, high_contrast);
            Self {
                model,
                hwnd: null_mut(),
                brand_mark: null_mut(),
                app_kicker: null_mut(),
                brand_caption: null_mut(),
                connection: null_mut(),
                section_kicker: null_mut(),
                headline: null_mut(),
                subheadline: null_mut(),
                status: null_mut(),
                details: null_mut(),
                field_state: null_mut(),
                modules: null_mut(),
                footer: null_mut(),
                credential_label: null_mut(),
                credential: null_mut(),
                device_label: null_mut(),
                device_status: null_mut(),
                device_detail: null_mut(),
                device_code_label: null_mut(),
                device_code: null_mut(),
                device_hint: null_mut(),
                activate: null_mut(),
                launch: null_mut(),
                retry: null_mut(),
                module_action: null_mut(),
                purchase: null_mut(),
                contact: null_mut(),
                canvas_brush: unsafe { CreateSolidBrush(palette.canvas) },
                card_brush: unsafe { CreateSolidBrush(palette.card) },
                input_brush: unsafe { CreateSolidBrush(palette.input) },
                accent_brush: unsafe { CreateSolidBrush(palette.accent) },
                feedback_brush: unsafe { CreateSolidBrush(palette.card) },
                palette,
                font_brand: null_mut(),
                font_kicker: null_mut(),
                font_headline: null_mut(),
                font_body: null_mut(),
                font_input: null_mut(),
                font_status: null_mut(),
                font_small: null_mut(),
                font_device_code: null_mut(),
                font_button: null_mut(),
                min_width: config.min_width,
                min_height: config.min_height,
                dpi: 96,
                startup_error: None,
                on_intent: Box::new(on_intent),
                on_credential: Box::new(on_credential),
                launch_auto_sent: false,
            }
        }

        unsafe fn refresh_colors(&mut self) {
            self.palette = palette(&self.model, high_contrast_enabled());
            replace_brush(&mut self.canvas_brush, self.palette.canvas);
            replace_brush(&mut self.card_brush, self.palette.card);
            replace_brush(&mut self.input_brush, self.palette.input);
            replace_brush(&mut self.accent_brush, self.palette.accent);
            let feedback_surface = self.feedback_surface();
            replace_brush(&mut self.feedback_brush, feedback_surface);
            self.apply_credential_colors();
        }

        unsafe fn invalidate_children(&self) {
            for control in [
                self.brand_mark,
                self.app_kicker,
                self.brand_caption,
                self.connection,
                self.section_kicker,
                self.headline,
                self.subheadline,
                self.status,
                self.details,
                self.field_state,
                self.modules,
                self.footer,
                self.credential_label,
                self.credential,
                self.device_label,
                self.device_status,
                self.device_detail,
                self.device_code_label,
                self.device_code,
                self.device_hint,
                self.activate,
                self.launch,
                self.retry,
                self.module_action,
                self.purchase,
                self.contact,
            ] {
                if !control.is_null() {
                    InvalidateRect(control, null(), 1);
                }
            }
        }

        unsafe fn refresh_fonts(&mut self) {
            delete_font(&mut self.font_brand);
            delete_font(&mut self.font_kicker);
            delete_font(&mut self.font_headline);
            delete_font(&mut self.font_body);
            delete_font(&mut self.font_input);
            delete_font(&mut self.font_status);
            delete_font(&mut self.font_small);
            delete_font(&mut self.font_device_code);
            delete_font(&mut self.font_button);
            self.font_brand = create_font(-self.scale(18), FW_SEMIBOLD, "Segoe UI");
            self.font_kicker = create_font(-self.scale(11), FW_SEMIBOLD, "Segoe UI");
            self.font_headline = create_font(-self.scale(28), FW_SEMIBOLD, "Segoe UI");
            self.font_body = create_font(-self.scale(13), FW_NORMAL, "Segoe UI");
            self.font_input = create_font(-self.scale(18), FW_SEMIBOLD, "Consolas");
            self.font_status = create_font(-self.scale(13), FW_SEMIBOLD, "Segoe UI");
            self.font_small = create_font(-self.scale(11), FW_NORMAL, "Segoe UI");
            self.font_device_code = create_font(-self.scale(11), FW_SEMIBOLD, "Consolas");
            self.font_button = create_font(-self.scale(13), FW_SEMIBOLD, "Segoe UI");
        }

        unsafe fn apply_fonts(&self) {
            send_font(self.brand_mark, self.font_brand);
            send_font(self.app_kicker, self.font_kicker);
            send_font(self.brand_caption, self.font_small);
            send_font(self.connection, self.font_small);
            send_font(self.section_kicker, self.font_kicker);
            send_font(self.headline, self.font_headline);
            send_font(self.subheadline, self.font_body);
            send_font(self.status, self.font_status);
            send_font(self.details, self.font_small);
            send_font(self.field_state, self.font_small);
            send_font(self.modules, self.font_small);
            send_font(self.footer, self.font_small);
            send_font(self.credential_label, self.font_status);
            send_font(self.credential, self.font_input);
            send_font(self.device_label, self.font_small);
            send_font(self.device_status, self.font_kicker);
            send_font(self.device_detail, self.font_small);
            send_font(self.device_code_label, self.font_small);
            send_font(self.device_code, self.font_device_code);
            send_font(self.device_hint, self.font_small);
            send_font(self.activate, self.font_button);
            send_font(self.launch, self.font_button);
            send_font(self.retry, self.font_button);
            send_font(self.module_action, self.font_button);
            send_font(self.purchase, self.font_button);
            send_font(self.contact, self.font_button);
        }

        unsafe fn on_create(&mut self) {
            self.dpi = GetDpiForWindow(self.hwnd).max(96);
            self.refresh_fonts();
            let rich_edit_library = wide("Msftedit.dll");
            if LoadLibraryW(rich_edit_library.as_ptr()).is_null() {
                self.startup_error = Some(win32_error("LoadLibraryW(Msftedit.dll)"));
                return;
            }
            let static_style = WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX;
            let centered_style = WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOPREFIX;
            self.brand_mark = self.child(
                "STATIC",
                ID_BRAND_MARK,
                WS_CHILD | WS_VISIBLE | SS_OWNERDRAW | SS_NOPREFIX,
                "A",
            );
            self.app_kicker = self.child(
                "STATIC",
                ID_APP_KICKER,
                static_style,
                self.model.copy_text_or_default("app_kicker"),
            );
            self.brand_caption = self.child("STATIC", ID_BRAND_CAPTION, static_style, "");
            self.connection = self.child("STATIC", ID_CONNECTION, centered_style, "");
            self.section_kicker = self.child("STATIC", ID_SECTION_KICKER, static_style, "");
            self.headline = self.child(
                "STATIC",
                ID_HEADLINE,
                static_style,
                self.model.copy_text_or_default("headline"),
            );
            self.subheadline = self.child(
                "STATIC",
                ID_SUBHEADLINE,
                static_style,
                self.model.copy_text_or_default("subheadline"),
            );
            self.status = self.child("STATIC", ID_STATUS, static_style, "");
            self.details = self.child("STATIC", ID_DETAILS, static_style, "");
            self.field_state = self.child(
                "STATIC",
                ID_FIELD_STATE,
                centered_style,
                self.model.copy_text_or_default("field_visible"),
            );
            self.modules = self.child(
                "STATIC",
                ID_MODULES,
                static_style,
                self.model.copy_text_or_default("no_modules"),
            );
            self.footer = self.child("STATIC", ID_FOOTER, static_style, "");
            self.credential_label = self.child(
                "STATIC",
                ID_CREDENTIAL_LABEL,
                static_style,
                self.model.copy_text_or_default("credential_label"),
            );
            self.credential = self.child(
                "RICHEDIT50W",
                ID_CREDENTIAL,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                "",
            );
            self.device_label = self.child(
                "STATIC",
                ID_DEVICE_LABEL,
                static_style,
                self.model.copy_text_or_default("scope_current_device"),
            );
            self.device_status = self.child("STATIC", ID_DEVICE_STATUS, static_style, "");
            self.device_detail = self.child("STATIC", ID_DEVICE_DETAIL, static_style, "");
            self.device_code_label = self.child("STATIC", ID_DEVICE_CODE_LABEL, static_style, "");
            self.device_code = self.child("STATIC", ID_DEVICE_CODE, static_style, "");
            self.device_hint = self.child("STATIC", ID_DEVICE_HINT, static_style, "");
            self.activate = self.child(
                "BUTTON",
                ID_ACTIVATE,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW | BS_DEFPUSHBUTTON,
                self.model.copy_text_or_default("activate"),
            );
            self.launch = self.child(
                "BUTTON",
                ID_LAUNCH,
                WS_CHILD | WS_TABSTOP | BS_OWNERDRAW | BS_DEFPUSHBUTTON,
                self.model.copy_text_or_default("request_launch"),
            );
            self.retry = self.child(
                "BUTTON",
                ID_RETRY,
                WS_CHILD | WS_TABSTOP | BS_OWNERDRAW | BS_PUSHBUTTON,
                self.model.copy_text_or_default("retry"),
            );
            self.module_action = self.child(
                "BUTTON",
                ID_MODULE_ACTION,
                WS_CHILD | WS_TABSTOP | BS_OWNERDRAW | BS_PUSHBUTTON,
                &self.module_action_label(),
            );
            self.purchase = self.child(
                "BUTTON",
                ID_PURCHASE,
                WS_CHILD | WS_TABSTOP | BS_OWNERDRAW | BS_PUSHBUTTON,
                self.model.copy_text_or_default("purchase"),
            );
            self.contact = self.child(
                "BUTTON",
                ID_CONTACT,
                WS_CHILD | WS_TABSTOP | BS_OWNERDRAW | BS_PUSHBUTTON,
                self.model.copy_text_or_default("support"),
            );

            self.apply_fonts();
            if self.brand_mark.is_null()
                || self.app_kicker.is_null()
                || self.brand_caption.is_null()
                || self.connection.is_null()
                || self.section_kicker.is_null()
                || self.headline.is_null()
                || self.subheadline.is_null()
                || self.status.is_null()
                || self.details.is_null()
                || self.field_state.is_null()
                || self.modules.is_null()
                || self.footer.is_null()
                || self.credential_label.is_null()
                || self.credential.is_null()
                || self.device_label.is_null()
                || self.device_status.is_null()
                || self.device_detail.is_null()
                || self.device_code_label.is_null()
                || self.device_code.is_null()
                || self.device_hint.is_null()
                || self.activate.is_null()
                || self.launch.is_null()
                || self.retry.is_null()
                || self.module_action.is_null()
                || self.purchase.is_null()
                || self.contact.is_null()
            {
                self.startup_error = Some(win32_error("CreateWindowExW child"));
                return;
            }
            let cue = wide(self.model.copy_text_or_default("credential_placeholder"));
            SendMessageW(
                self.credential,
                EM_LIMITTEXT,
                WINDOWS_RENDERER_MAX_CREDENTIAL_CHARS as WPARAM,
                0,
            );
            SendMessageW(self.credential, EM_SETCUEBANNER, 0, cue.as_ptr() as LPARAM);
            self.apply_credential_colors();
            self.apply_credential_margins();
            self.refresh_text();
            self.layout();
            self.refresh_visibility();
            self.maybe_auto_launch();
            SetFocus(self.first_focus_target());
        }

        unsafe fn apply_credential_margins(&self) {
            let left = self.scale(10).clamp(0, u16::MAX as i32) as u32;
            let right = self.scale(10).clamp(0, u16::MAX as i32) as u32;
            let margins = left | (right << 16);
            SendMessageW(
                self.credential,
                EM_SETMARGINS,
                EC_LEFTMARGIN | EC_RIGHTMARGIN,
                margins as LPARAM,
            );
        }

        unsafe fn apply_credential_colors(&self) {
            if self.credential.is_null() {
                return;
            }
            SendMessageW(
                self.credential,
                EM_SETBKGNDCOLOR,
                0,
                self.palette.input as LPARAM,
            );
            let format = CHARFORMAT2W {
                cb_size: size_of::<CHARFORMAT2W>() as UINT,
                dw_mask: CFM_COLOR,
                dw_effects: 0,
                y_height: 0,
                y_offset: 0,
                cr_text_color: self.palette.text,
                charset: DEFAULT_CHARSET as u8,
                pitch_and_family: 0,
                face_name: [0; 32],
                weight: 0,
                spacing: 0,
                back_color: self.palette.input,
                locale_id: 0,
                cookie: 0,
                style: 0,
                kerning: 0,
                underline_type: 0,
                animation: 0,
                revision_author: 0,
                reserved: 0,
            };
            SendMessageW(
                self.credential,
                EM_SETCHARFORMAT,
                SCF_DEFAULT,
                &format as *const CHARFORMAT2W as LPARAM,
            );
            SendMessageW(
                self.credential,
                EM_SETCHARFORMAT,
                SCF_ALL,
                &format as *const CHARFORMAT2W as LPARAM,
            );
        }

        unsafe fn child(&self, class: &str, id: i32, style: DWORD, text: &str) -> HWND {
            let class_name = wide(class);
            let text = wide(text);
            let instance = GetModuleHandleW(null());
            CreateWindowExW(
                0,
                class_name.as_ptr(),
                text.as_ptr(),
                style,
                0,
                0,
                0,
                0,
                self.hwnd,
                id as usize as HMENU,
                instance,
                null_mut(),
            )
        }

        unsafe fn refresh_text(&mut self) {
            let feedback_surface = self.feedback_surface();
            replace_brush(&mut self.feedback_brush, feedback_surface);
            let status = self
                .model
                .copy_text_or_default(self.model.state.status_copy_key());
            let details = format!(
                "{}  ·  {}",
                self.model
                    .copy_text_or_default(self.model.state.connectivity.copy_key()),
                self.model
                    .copy_text_or_default(self.model.state.source.copy_key())
            );
            let modules = module_summary(&self.model);
            let footer = self.model.copy_text_or_default("runtime_authority");
            let device_status = self
                .model
                .copy_text_or_default(self.device_status_copy_key());
            let device_detail = self
                .model
                .copy_text_or_default(self.device_detail_copy_key());
            set_text(self.brand_mark, "A");
            set_text(
                self.app_kicker,
                self.model.copy_text_or_default("app_kicker"),
            );
            set_text(self.brand_caption, "");
            set_text(
                self.connection,
                self.model
                    .copy_text_or_default(self.model.state.connectivity.copy_key()),
            );
            set_text(self.section_kicker, "");
            set_text(self.headline, self.model.copy_text_or_default("headline"));
            set_text(
                self.subheadline,
                self.model.copy_text_or_default("subheadline"),
            );
            set_text(self.status, status);
            set_text(self.details, &details);
            set_text(
                self.field_state,
                self.model.copy_text_or_default("field_visible"),
            );
            set_text(self.modules, &modules);
            set_text(self.footer, &footer);
            set_text(
                self.credential_label,
                self.model.copy_text_or_default("credential_label"),
            );
            set_text(
                self.device_label,
                self.model.copy_text_or_default("scope_current_device"),
            );
            set_text(self.device_status, device_status);
            set_text(self.device_detail, device_detail);
            set_text(
                self.device_code_label,
                self.model.copy_text_or_default("device_code_label"),
            );
            set_text(
                self.device_code,
                self.model
                    .device_code
                    .as_deref()
                    .unwrap_or_else(|| self.model.copy_text_or_default("device_code_pending")),
            );
            set_text(
                self.device_hint,
                self.model.copy_text_or_default("device_code_hint"),
            );
            let activation_label = match self.model.state.authorization {
                UiAuthorizationState::Pending => self.model.copy_text_or_default("loading"),
                UiAuthorizationState::Active | UiAuthorizationState::Grace => {
                    self.model.copy_text_or_default("entering")
                }
                _ => self.model.copy_text_or_default("activate"),
            };
            set_text(self.activate, activation_label);
            let launch_label = match self.model.state.authorization {
                UiAuthorizationState::Active | UiAuthorizationState::Grace => {
                    self.model.copy_text_or_default("entering")
                }
                _ => self.model.copy_text_or_default("request_launch"),
            };
            set_text(self.launch, launch_label);
            set_text(self.retry, self.model.copy_text_or_default("retry"));
            let module_label = self.module_action_label();
            set_text(self.module_action, &module_label);
            set_text(self.purchase, self.model.copy_text_or_default("purchase"));
            set_text(self.contact, self.model.copy_text_or_default("support"));
        }

        fn device_status_copy_key(&self) -> &'static str {
            match self.model.state.authorization {
                UiAuthorizationState::Active | UiAuthorizationState::Grace => "device_confirmed",
                UiAuthorizationState::Pending => "device_pending",
                _ => "device_unconfirmed",
            }
        }

        fn device_detail_copy_key(&self) -> &'static str {
            match self.model.state.authorization {
                UiAuthorizationState::Active | UiAuthorizationState::Grace => {
                    "device_confirmed_detail"
                }
                UiAuthorizationState::Pending => "device_pending_detail",
                _ => "device_unconfirmed_detail",
            }
        }

        fn show_feedback(&self) -> bool {
            !matches!(
                self.model.state.authorization,
                UiAuthorizationState::Unauthenticated
            )
        }

        fn feedback_color(&self) -> DWORD {
            match self.model.state.authorization {
                UiAuthorizationState::Pending => self.palette.warning,
                UiAuthorizationState::Active | UiAuthorizationState::Grace => self.palette.success,
                _ => self.palette.danger,
            }
        }

        fn feedback_surface(&self) -> DWORD {
            match self.model.state.authorization {
                UiAuthorizationState::Pending => self.palette.feedback_warning,
                UiAuthorizationState::Active | UiAuthorizationState::Grace => {
                    self.palette.feedback_success
                }
                _ => self.palette.feedback_danger,
            }
        }

        unsafe fn refresh_visibility(&self) {
            let pending = matches!(
                self.model.state.authorization,
                UiAuthorizationState::Pending
            );
            let launchable = matches!(
                self.model.state.authorization,
                UiAuthorizationState::Active | UiAuthorizationState::Grace
            );
            let show_activation = pending
                || launchable
                || has_intent(&self.model.state, |intent| {
                    matches!(intent, UiIntent::Activate)
                });
            let show_launch = false;
            let show_retry = !launchable
                && has_intent(&self.model.state, |intent| {
                    matches!(intent, UiIntent::Retry)
                });
            let show_purchase = self.model.module_enabled("purchase");
            let show_contact = self.model.module_enabled("contact");
            ShowWindow(self.credential_label, SW_HIDE);
            ShowWindow(self.credential, SW_SHOW);
            ShowWindow(
                self.activate,
                if show_activation { SW_SHOW } else { SW_HIDE },
            );
            ShowWindow(self.launch, if show_launch { SW_SHOW } else { SW_HIDE });
            ShowWindow(self.retry, if show_retry { SW_SHOW } else { SW_HIDE });
            ShowWindow(
                self.status,
                if self.show_feedback() {
                    SW_SHOW
                } else {
                    SW_HIDE
                },
            );
            ShowWindow(
                self.details,
                if self.show_feedback() {
                    SW_SHOW
                } else {
                    SW_HIDE
                },
            );
            ShowWindow(self.purchase, if show_purchase { SW_SHOW } else { SW_HIDE });
            ShowWindow(self.contact, if show_contact { SW_SHOW } else { SW_HIDE });
            EnableWindow(self.credential, if pending || launchable { 0 } else { 1 });
            EnableWindow(self.activate, if pending || launchable { 0 } else { 1 });
            ShowWindow(self.device_detail, SW_HIDE);
            ShowWindow(self.device_label, SW_HIDE);
            ShowWindow(self.device_status, SW_HIDE);
            ShowWindow(self.device_hint, SW_HIDE);
            ShowWindow(self.subheadline, SW_HIDE);
            ShowWindow(self.brand_caption, SW_HIDE);
            ShowWindow(self.section_kicker, SW_HIDE);
            // Optional module envelopes remain available to the runtime/core
            // boundary; the authorization entry surface stays deliberately
            // focused on activation, status and support.
            ShowWindow(self.modules, SW_HIDE);
            ShowWindow(self.module_action, SW_HIDE);
            ShowWindow(self.footer, SW_HIDE);
        }

        fn maybe_auto_launch(&mut self) {
            if self.launch_auto_sent {
                return;
            }
            let launchable = matches!(
                self.model.state.authorization,
                UiAuthorizationState::Active | UiAuthorizationState::Grace
            );
            if !launchable
                || !has_intent(&self.model.state, |intent| {
                    matches!(intent, UiIntent::RequestLaunch)
                })
            {
                return;
            }
            self.launch_auto_sent = true;
            (self.on_intent)(UiIntent::RequestLaunch);
        }

        unsafe fn paint(&self) {
            let mut paint = PAINTSTRUCT {
                hdc: null_mut(),
                erase: 0,
                rc_paint: RECT {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                },
                restore: 0,
                inc_update: 0,
                rgb_reserved: [0; 32],
            };
            let hdc = BeginPaint(self.hwnd, &mut paint);
            if hdc.is_null() {
                return;
            }
            let mut client = RECT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            };
            if GetClientRect(self.hwnd, &mut client) != 0 {
                let metrics = self.layout_metrics(client.right, client.bottom);
                let vertical_y = |offset: i32| {
                    metrics.card_y
                        + self.scale(offset).saturating_mul(metrics.vertical_span)
                            / self.scale(612).max(1)
                };
                FillRect(hdc, &client, self.canvas_brush);

                let shadow = RECT {
                    left: metrics.card_x + self.scale(2),
                    top: metrics.card_y + self.scale(3),
                    right: metrics.card_x + metrics.card_width + self.scale(2),
                    bottom: metrics.card_bottom + self.scale(3),
                };
                draw_rounded_surface(
                    hdc,
                    &shadow,
                    self.palette.border,
                    self.palette.border,
                    self.scale(8),
                );
                let card = RECT {
                    left: metrics.card_x,
                    top: metrics.card_y,
                    right: metrics.card_x + metrics.card_width,
                    bottom: metrics.card_bottom,
                };
                draw_rounded_surface(
                    hdc,
                    &card,
                    self.palette.card,
                    self.palette.border,
                    self.scale(8),
                );
                let accent_line = RECT {
                    left: metrics.content_x,
                    top: metrics.card_y,
                    right: metrics.content_x + metrics.content_width,
                    bottom: metrics.card_y + self.scale(2),
                };
                FillRect(hdc, &accent_line, self.accent_brush);

                let header_divider = RECT {
                    left: metrics.content_x,
                    top: metrics.header_divider_y,
                    right: metrics.content_x + metrics.content_width,
                    bottom: metrics.header_divider_y + self.scale(1),
                };
                FillRect(hdc, &header_divider, self.canvas_brush);

                let input = RECT {
                    left: metrics.content_x - self.scale(1),
                    top: metrics.credential_y - self.scale(1),
                    right: metrics.content_x + metrics.content_width + self.scale(1),
                    bottom: metrics.credential_y + self.scale(47),
                };
                draw_rounded_surface(
                    hdc,
                    &input,
                    self.palette.input,
                    self.palette.input_border,
                    self.scale(6),
                );

                let connection = RECT {
                    left: metrics.connection_x,
                    top: vertical_y(30),
                    right: metrics.connection_x + metrics.connection_width,
                    bottom: vertical_y(30) + self.scale(28),
                };
                draw_rounded_surface(
                    hdc,
                    &connection,
                    self.palette.input,
                    self.palette.border,
                    self.scale(4),
                );
                let status_dot = RECT {
                    left: connection.left + self.scale(12),
                    top: connection.top + self.scale(10),
                    right: connection.left + self.scale(20),
                    bottom: connection.top + self.scale(18),
                };
                FillRect(hdc, &status_dot, self.accent_brush);

                let field_divider = RECT {
                    left: metrics.content_x + metrics.content_width - self.scale(72),
                    top: metrics.credential_y + self.scale(8),
                    right: metrics.content_x + metrics.content_width - self.scale(71),
                    bottom: metrics.credential_y + self.scale(38),
                };
                FillRect(hdc, &field_divider, self.canvas_brush);

                let device_divider = RECT {
                    left: metrics.content_x,
                    top: metrics.device_divider_y,
                    right: metrics.content_x + metrics.content_width,
                    bottom: metrics.device_divider_y + self.scale(1),
                };
                FillRect(hdc, &device_divider, self.canvas_brush);

                let support_divider = RECT {
                    left: metrics.content_x,
                    top: metrics.support_divider_y,
                    right: metrics.content_x + metrics.content_width,
                    bottom: metrics.support_divider_y + self.scale(1),
                };
                FillRect(hdc, &support_divider, self.canvas_brush);

                let device_code_chip = RECT {
                    left: metrics.device_code_chip_x,
                    top: metrics.device_code_y - self.scale(2),
                    right: metrics.device_code_chip_x + metrics.device_code_chip_width,
                    bottom: metrics.device_code_y + self.scale(21),
                };
                draw_rounded_surface(
                    hdc,
                    &device_code_chip,
                    self.palette.input,
                    self.palette.input_border,
                    self.scale(4),
                );

                if self.show_feedback() {
                    let feedback = RECT {
                        left: metrics.content_x,
                        top: metrics.feedback_y,
                        right: metrics.content_x + metrics.content_width,
                        bottom: metrics.feedback_y + metrics.feedback_height,
                    };
                    draw_rounded_surface(
                        hdc,
                        &feedback,
                        self.feedback_surface(),
                        self.feedback_color(),
                        self.scale(5),
                    );
                    let feedback_bar = RECT {
                        left: feedback.left,
                        top: feedback.top + self.scale(3),
                        right: feedback.left + self.scale(4),
                        bottom: feedback.bottom - self.scale(3),
                    };
                    let feedback_brush = CreateSolidBrush(self.feedback_color());
                    FillRect(hdc, &feedback_bar, feedback_brush);
                    DeleteObject(feedback_brush.cast());
                    let feedback_dot = RECT {
                        left: feedback.left + self.scale(16),
                        top: feedback.top + self.scale(16),
                        right: feedback.left + self.scale(24),
                        bottom: feedback.top + self.scale(24),
                    };
                    draw_rounded_surface(
                        hdc,
                        &feedback_dot,
                        self.feedback_color(),
                        self.feedback_color(),
                        self.scale(8),
                    );
                }
            }
            EndPaint(self.hwnd, &paint);
        }

        unsafe fn draw_brand_mark(&self, item: &DRAWITEMSTRUCT) {
            let frame = item.rc_item;
            draw_rounded_surface(
                item.hdc,
                &frame,
                self.palette.input,
                self.palette.accent,
                self.scale(6),
            );
            SetBkMode(item.hdc, TRANSPARENT);
            SetTextColor(item.hdc, self.palette.accent);
            let label = wide("A");
            let mut text_rect = frame;
            DrawTextW(
                item.hdc,
                label.as_ptr(),
                -1,
                &mut text_rect,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
            );
        }

        unsafe fn draw_button(&self, item: &DRAWITEMSTRUCT) {
            let id = item.ctl_id as i32;
            let primary = matches!(id, ID_ACTIVATE | ID_LAUNCH | ID_RETRY);
            let pressed = item.item_state & ODS_SELECTED != 0;
            let disabled = item.item_state & ODS_DISABLED != 0;
            let fill = if disabled && !primary {
                self.palette.border
            } else if pressed {
                if primary {
                    self.palette.button_pressed
                } else {
                    self.palette.secondary_pressed
                }
            } else if primary {
                self.palette.accent
            } else {
                self.palette.card
            };
            let border = if primary {
                self.palette.accent
            } else {
                self.palette.input_border
            };
            let text_color = if disabled && !primary {
                self.palette.muted
            } else if primary {
                self.palette.accent_text
            } else {
                self.palette.text
            };
            let shadow_color = if !primary {
                self.palette.border
            } else {
                self.palette.button_shadow
            };
            let mut shadow_rect = item.rc_item;
            let shadow_offset = if pressed {
                self.scale(1)
            } else {
                self.scale(4)
            };
            shadow_rect.top += shadow_offset;
            shadow_rect.bottom += shadow_offset;
            draw_rounded_surface(
                item.hdc,
                &shadow_rect,
                shadow_color,
                shadow_color,
                self.scale(8),
            );
            let mut face = item.rc_item;
            face.bottom = face.bottom.saturating_sub(shadow_offset);
            draw_rounded_surface(item.hdc, &face, fill, border, self.scale(8));
            let highlight = RECT {
                left: face.left + self.scale(2),
                top: face.top + self.scale(1),
                right: face.right - self.scale(2),
                bottom: face.top + self.scale(2),
            };
            let highlight_brush = CreateSolidBrush(self.palette.button_highlight);
            FillRect(item.hdc, &highlight, highlight_brush);
            DeleteObject(highlight_brush.cast());

            let label = match id {
                ID_ACTIVATE => match self.model.state.authorization {
                    UiAuthorizationState::Pending => {
                        self.model.copy_text_or_default("loading").to_string()
                    }
                    UiAuthorizationState::Active | UiAuthorizationState::Grace => {
                        self.model.copy_text_or_default("entering").to_string()
                    }
                    _ => self.model.copy_text_or_default("activate").to_string(),
                },
                ID_LAUNCH => match self.model.state.authorization {
                    UiAuthorizationState::Active | UiAuthorizationState::Grace => {
                        self.model.copy_text_or_default("entering").to_string()
                    }
                    _ => self
                        .model
                        .copy_text_or_default("request_launch")
                        .to_string(),
                },
                ID_RETRY => self.model.copy_text_or_default("retry").to_string(),
                ID_MODULE_ACTION => self.module_action_label(),
                ID_PURCHASE => self.model.copy_text_or_default("purchase").to_string(),
                ID_CONTACT => self.model.copy_text_or_default("support").to_string(),
                _ => String::new(),
            };
            let title = wide(&label);
            let mut text_rect = face;
            SetBkMode(item.hdc, TRANSPARENT);
            SetTextColor(item.hdc, text_color);
            DrawTextW(
                item.hdc,
                title.as_ptr(),
                -1,
                &mut text_rect,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
            );
            if item.item_state & ODS_FOCUS != 0 {
                let mut focus_rect = face;
                focus_rect.left += self.scale(4);
                focus_rect.top += self.scale(4);
                focus_rect.right -= self.scale(4);
                focus_rect.bottom -= self.scale(4);
                DrawFocusRect(item.hdc, &focus_rect);
            }
        }

        fn scale(&self, value: i32) -> i32 {
            value.saturating_mul(self.dpi.max(96) as i32) / 96
        }

        fn layout_metrics(&self, width: i32, height: i32) -> LayoutMetrics {
            let scale = |value: i32| value.saturating_mul(self.dpi as i32) / 96;
            let margin = scale(24);
            let card_x = margin;
            let card_y = margin;
            let card_width = (width - margin * 2).max(scale(300));
            let card_bottom = (height - margin).max(card_y + scale(420));
            let vertical_span = (card_bottom - card_y).min(scale(612));
            let vertical_y = |offset: i32| {
                card_y + scale(offset).saturating_mul(vertical_span) / scale(612).max(1)
            };
            let content_x = card_x + scale(28);
            let content_width = (card_width - scale(56)).max(scale(220));
            let header_divider_y = vertical_y(106);
            let header_left = content_x + scale(52);
            let header_text_width = scale(220).min(content_width - scale(52));
            let connection_units = (36
                + self
                    .model
                    .copy_text_or_default(self.model.state.connectivity.copy_key())
                    .chars()
                    .count() as i32
                    * 13)
                .clamp(64, 140);
            let connection_width = scale(connection_units);
            let connection_x = card_x + card_width - scale(28) - connection_width;
            let credential_y = vertical_y(244);
            let action_y = vertical_y(304);
            let retry_y = action_y;
            let support_y = card_bottom - scale(110);
            let support_divider_y = support_y - scale(16);
            let device_code_y = support_y - scale(54);
            let device_summary_y = device_code_y - scale(26);
            let device_detail_y = device_summary_y;
            let device_divider_y = device_summary_y - scale(14);
            let device_code_chip_x = content_x + scale(50);
            let device_code_chip_width = scale(96);
            let feedback_y = vertical_y(356);
            let feedback_bottom = device_divider_y - scale(12);
            let feedback_height = (feedback_bottom - feedback_y).clamp(scale(58), scale(70));
            let support_gap = scale(28);
            let support_button_width = ((content_width - support_gap) / 2).min(scale(96));
            let support_total = support_button_width * 2 + support_gap;
            let support_start = content_x + (content_width - support_total).max(0) / 2;
            let purchase_x = support_start;
            let contact_x = support_start + support_button_width + support_gap;
            let footer_y = card_bottom - scale(18);
            let modules_y = device_summary_y;
            let modules_height = scale(24);
            let module_action_width = scale(160).min(content_width);
            let module_action_x = content_x;
            let module_action_y = support_y;
            LayoutMetrics {
                margin,
                vertical_span,
                header_divider_y,
                header_left,
                header_text_width,
                connection_x,
                connection_width,
                card_x,
                card_y,
                card_width,
                card_bottom,
                content_x,
                content_width,
                credential_y,
                action_y,
                retry_y,
                feedback_y,
                feedback_height,
                device_divider_y,
                device_summary_y,
                device_detail_y,
                device_code_y,
                device_code_chip_x,
                device_code_chip_width,
                support_divider_y,
                support_y,
                support_button_width,
                purchase_x,
                contact_x,
                modules_y,
                modules_height,
                module_action_x,
                module_action_y,
                module_action_width,
                footer_y,
            }
        }

        unsafe fn layout(&self) {
            let mut rect = RECT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            };
            if GetClientRect(self.hwnd, &mut rect) == 0 {
                return;
            }
            let metrics = self.layout_metrics(rect.right - rect.left, rect.bottom - rect.top);
            let vertical_y = |offset: i32| {
                metrics.card_y
                    + self.scale(offset).saturating_mul(metrics.vertical_span)
                        / self.scale(612).max(1)
            };
            move_control(
                self.brand_mark,
                metrics.content_x,
                vertical_y(28),
                self.scale(40),
                self.scale(40),
            );
            move_control(
                self.app_kicker,
                metrics.header_left,
                vertical_y(28),
                metrics.header_text_width,
                self.scale(20),
            );
            move_control(
                self.brand_caption,
                metrics.header_left,
                vertical_y(52),
                metrics.header_text_width,
                self.scale(18),
            );
            move_control(
                self.connection,
                metrics.connection_x + self.scale(28),
                vertical_y(30),
                metrics.connection_width - self.scale(36),
                self.scale(28),
            );
            move_control(
                self.section_kicker,
                metrics.content_x,
                vertical_y(114),
                metrics.content_width,
                self.scale(20),
            );
            move_control(
                self.headline,
                metrics.content_x,
                vertical_y(132),
                metrics.content_width,
                self.scale(42),
            );
            move_control(
                self.subheadline,
                metrics.content_x,
                vertical_y(178),
                metrics.content_width,
                self.scale(28),
            );
            move_control(
                self.status,
                metrics.content_x + self.scale(36),
                metrics.feedback_y + self.scale(12),
                metrics.content_width - self.scale(52),
                self.scale(20),
            );
            move_control(
                self.details,
                metrics.content_x + self.scale(36),
                metrics.feedback_y + self.scale(34),
                metrics.content_width - self.scale(52),
                self.scale(20),
            );
            move_control(
                self.credential_label,
                metrics.content_x,
                vertical_y(216),
                metrics.content_width,
                self.scale(22),
            );
            move_control(
                self.credential,
                metrics.content_x + self.scale(4),
                metrics.credential_y + self.scale(8),
                metrics.content_width - self.scale(90),
                self.scale(30),
            );
            move_control(
                self.field_state,
                metrics.content_x + metrics.content_width - self.scale(68),
                metrics.credential_y + self.scale(4),
                self.scale(60),
                self.scale(38),
            );
            move_control(
                self.activate,
                metrics.content_x,
                metrics.action_y,
                metrics.content_width,
                self.scale(46),
            );
            move_control(
                self.launch,
                metrics.content_x,
                metrics.action_y,
                metrics.content_width,
                self.scale(46),
            );
            move_control(
                self.retry,
                metrics.content_x,
                metrics.retry_y,
                metrics.content_width,
                self.scale(40),
            );
            move_control(
                self.device_label,
                metrics.content_x,
                metrics.device_summary_y,
                self.scale(52),
                self.scale(20),
            );
            move_control(
                self.device_status,
                metrics.content_x + self.scale(60),
                metrics.device_summary_y,
                self.scale(96),
                self.scale(20),
            );
            move_control(
                self.device_detail,
                metrics.content_x,
                metrics.device_detail_y,
                metrics.content_width,
                self.scale(20),
            );
            move_control(
                self.device_code_label,
                metrics.content_x,
                metrics.device_code_y,
                self.scale(44),
                self.scale(20),
            );
            move_control(
                self.device_code,
                metrics.device_code_chip_x + self.scale(6),
                metrics.device_code_y + self.scale(1),
                metrics.device_code_chip_width - self.scale(12),
                self.scale(18),
            );
            move_control(
                self.device_hint,
                metrics.device_code_chip_x + metrics.device_code_chip_width + self.scale(12),
                metrics.device_code_y,
                (metrics.content_x + metrics.content_width
                    - metrics.device_code_chip_x
                    - metrics.device_code_chip_width
                    - self.scale(12))
                .max(self.scale(80)),
                self.scale(20),
            );
            move_control(
                self.modules,
                metrics.content_x,
                metrics.modules_y,
                metrics.content_width,
                metrics.modules_height,
            );
            move_control(
                self.module_action,
                metrics.module_action_x,
                metrics.module_action_y,
                metrics.module_action_width,
                self.scale(40),
            );
            move_control(
                self.purchase,
                metrics.purchase_x,
                metrics.support_y,
                metrics.support_button_width,
                self.scale(34),
            );
            move_control(
                self.contact,
                metrics.contact_x,
                metrics.support_y,
                metrics.support_button_width,
                self.scale(34),
            );
            move_control(
                self.footer,
                metrics.margin,
                metrics.footer_y,
                (rect.right - metrics.margin * 2).max(self.scale(80)),
                self.scale(22),
            );
        }

        unsafe fn first_focus_target(&self) -> HWND {
            if has_intent(&self.model.state, |intent| {
                matches!(intent, UiIntent::Activate)
            }) {
                self.credential
            } else if has_intent(&self.model.state, |intent| {
                matches!(intent, UiIntent::RequestLaunch)
            }) {
                self.activate
            } else if has_intent(&self.model.state, |intent| {
                matches!(intent, UiIntent::Retry)
            }) {
                self.retry
            } else {
                null_mut()
            }
        }

        fn module_action_label(&self) -> String {
            self.open_module()
                .map(|module| {
                    self.model
                        .copy_text_or_default(module.kind.title_copy_key())
                        .to_string()
                })
                .unwrap_or_else(|| self.model.copy_text_or_default("support").to_string())
        }

        fn open_module(&self) -> Option<&UiModuleCard> {
            self.model.state.intents.iter().find_map(|intent| {
                let UiIntent::OpenModule(kind) = intent else {
                    return None;
                };
                self.model
                    .modules
                    .entries()
                    .iter()
                    .find(|module| module.kind.as_str() == kind)
            })
        }

        unsafe fn dispatch_command(&mut self, id: u16, notification: u16) {
            if notification != BN_CLICKED {
                return;
            }
            let intent = match id as i32 {
                ID_ACTIVATE => has_intent(&self.model.state, |intent| {
                    matches!(intent, UiIntent::Activate)
                })
                .then_some(UiIntent::Activate),
                ID_LAUNCH => has_intent(&self.model.state, |intent| {
                    matches!(intent, UiIntent::RequestLaunch)
                })
                .then_some(UiIntent::RequestLaunch),
                ID_RETRY => has_intent(&self.model.state, |intent| {
                    matches!(intent, UiIntent::Retry)
                })
                .then_some(UiIntent::Retry),
                ID_MODULE_ACTION => self
                    .open_module()
                    .map(|module| UiIntent::OpenModule(module.kind.as_str().to_string())),
                ID_PURCHASE => self
                    .model
                    .module_enabled("purchase")
                    .then(|| UiIntent::OpenModule("purchase".to_string())),
                ID_CONTACT => self
                    .model
                    .module_enabled("contact")
                    .then(|| UiIntent::OpenModule("contact".to_string())),
                _ => None,
            };
            if let Some(intent) = intent {
                let is_check = matches!(intent, UiIntent::Activate | UiIntent::Retry);
                if matches!(intent, UiIntent::Activate) {
                    let credential = CredentialBuffer::from_window(self.credential);
                    set_text(self.credential, "");
                    SendMessageW(self.credential, EM_EMPTYUNDOBUFFER, 0, 0);
                    (self.on_credential)(credential.as_slice());
                }
                (self.on_intent)(intent);
                if is_check {
                    self.model.model.state = UiViewState::loading();
                    self.refresh_text();
                    self.refresh_visibility();
                    self.layout();
                    InvalidateRect(self.hwnd, null(), 1);
                }
            }
        }
    }

    struct CredentialBuffer {
        units: Vec<u16>,
    }

    impl CredentialBuffer {
        unsafe fn from_window(hwnd: HWND) -> Self {
            let length = GetWindowTextLengthW(hwnd).max(0) as usize;
            let mut units = vec![0_u16; length.saturating_add(1)];
            let written =
                GetWindowTextW(hwnd, units.as_mut_ptr(), units.len() as i32).max(0) as usize;
            units.truncate(written.min(units.len()));
            Self { units }
        }

        fn as_slice(&self) -> &[u16] {
            &self.units
        }
    }

    impl Drop for CredentialBuffer {
        fn drop(&mut self) {
            self.units.fill(0);
        }
    }

    impl Drop for WindowState {
        fn drop(&mut self) {
            unsafe {
                delete_brush(&mut self.canvas_brush);
                delete_brush(&mut self.card_brush);
                delete_brush(&mut self.input_brush);
                delete_brush(&mut self.accent_brush);
                delete_brush(&mut self.feedback_brush);
                delete_font(&mut self.font_brand);
                delete_font(&mut self.font_kicker);
                delete_font(&mut self.font_headline);
                delete_font(&mut self.font_body);
                delete_font(&mut self.font_input);
                delete_font(&mut self.font_status);
                delete_font(&mut self.font_small);
                delete_font(&mut self.font_device_code);
                delete_font(&mut self.font_button);
            }
        }
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        message: UINT,
        w_param: WPARAM,
        l_param: LPARAM,
    ) -> LRESULT {
        if message == WM_NCCREATE {
            let create = l_param as *const CREATESTRUCTW;
            if create.is_null() {
                return 0;
            }
            let state = (*create).lp_create_params as *mut WindowState;
            if state.is_null() {
                return 0;
            }
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as isize);
            (*state).hwnd = hwnd;
            (*state).on_create();
            return 1;
        }

        let state = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut WindowState;
        if state.is_null() {
            return DefWindowProcW(hwnd, message, w_param, l_param);
        }

        match message {
            WM_SETFOCUS => {
                let focus_target = (*state).first_focus_target();
                if !focus_target.is_null() {
                    SetFocus(focus_target);
                }
                0
            }
            WM_SIZE => {
                (*state).layout();
                (*state).invalidate_children();
                InvalidateRect(hwnd, null(), 1);
                0
            }
            WM_PAINT => {
                (*state).paint();
                0
            }
            WM_DRAWITEM => {
                let item = l_param as *const DRAWITEMSTRUCT;
                if !item.is_null() {
                    if (*item).ctl_id as i32 == ID_BRAND_MARK {
                        (*state).draw_brand_mark(&*item);
                    } else {
                        (*state).draw_button(&*item);
                    }
                    return 1;
                }
                0
            }
            WM_COMMAND => {
                let id = (w_param & 0xFFFF) as u16;
                let notification = ((w_param >> 16) & 0xFFFF) as u16;
                if id as i32 == ID_CREDENTIAL && notification == EN_CHANGE {
                    PostMessageW(hwnd, WM_APP_CREDENTIAL_FORMAT, 0, 0);
                    return 0;
                }
                (*state).dispatch_command(id, notification);
                0
            }
            WM_APP_CREDENTIAL_FORMAT => {
                (*state).apply_credential_colors();
                InvalidateRect((*state).credential, null(), 1);
                UpdateWindow((*state).credential);
                0
            }
            WM_GETMINMAXINFO => {
                let info = l_param as *mut MINMAXINFO;
                if !info.is_null() {
                    let dpi = (*state).dpi.max(96) as i32;
                    (*info).pt_min_track_size.x = (*state).min_width * dpi / 96;
                    (*info).pt_min_track_size.y = (*state).min_height * dpi / 96;
                }
                0
            }
            WM_DPICHANGED => {
                (*state).dpi = (w_param as UINT & 0xFFFF).max(96);
                let suggested = l_param as *const RECT;
                if !suggested.is_null() {
                    let width = (*suggested).right.saturating_sub((*suggested).left);
                    let height = (*suggested).bottom.saturating_sub((*suggested).top);
                    if width > 0 && height > 0 {
                        SetWindowPos(
                            hwnd,
                            null_mut(),
                            (*suggested).left,
                            (*suggested).top,
                            width,
                            height,
                            SWP_NOZORDER | SWP_NOACTIVATE,
                        );
                    }
                }
                (*state).layout();
                (*state).refresh_fonts();
                (*state).apply_fonts();
                (*state).apply_credential_margins();
                InvalidateRect(hwnd, null(), 1);
                0
            }
            WM_SETTINGCHANGE | WM_THEMECHANGED | WM_SYSCOLORCHANGE => {
                (*state).refresh_colors();
                (*state).invalidate_children();
                InvalidateRect(hwnd, null(), 1);
                0
            }
            WM_ERASEBKGND => {
                let hdc = w_param as HDC;
                let mut rect = RECT {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                };
                GetClientRect(hwnd, &mut rect);
                FillRect(hdc, &rect, (*state).canvas_brush);
                1
            }
            WM_CTLCOLOREDIT | WM_CTLCOLORSTATIC => {
                let hdc = w_param as HDC;
                let control = l_param as HWND;
                let control_id = GetDlgCtrlID(control);
                if message == WM_CTLCOLOREDIT {
                    SetBkMode(hdc, OPAQUE);
                    SetBkColor(hdc, (*state).palette.input);
                    SetTextColor(hdc, (*state).palette.text);
                    (*state).input_brush as LRESULT
                } else if control_id == ID_CONNECTION || control_id == ID_FIELD_STATE {
                    SetBkMode(hdc, TRANSPARENT);
                    SetTextColor(hdc, (*state).palette.accent);
                    (*state).input_brush as LRESULT
                } else if control_id == ID_APP_KICKER
                    || control_id == ID_BRAND_MARK
                    || control_id == ID_DEVICE_CODE
                {
                    SetBkMode(hdc, TRANSPARENT);
                    SetTextColor(hdc, (*state).palette.accent);
                    (*state).card_brush as LRESULT
                } else if control_id == ID_DEVICE_LABEL
                    || control_id == ID_DEVICE_CODE_LABEL
                    || control_id == ID_DEVICE_HINT
                {
                    SetBkMode(hdc, TRANSPARENT);
                    SetTextColor(hdc, (*state).palette.muted);
                    (*state).card_brush as LRESULT
                } else if control_id == ID_STATUS || control_id == ID_DETAILS {
                    SetBkMode(hdc, OPAQUE);
                    SetBkColor(hdc, (*state).feedback_surface());
                    SetTextColor(
                        hdc,
                        if control_id == ID_STATUS {
                            (*state).palette.text
                        } else {
                            (*state).palette.muted
                        },
                    );
                    (*state).feedback_brush as LRESULT
                } else if control_id == ID_FOOTER {
                    SetBkMode(hdc, TRANSPARENT);
                    SetTextColor(hdc, (*state).palette.muted);
                    (*state).canvas_brush as LRESULT
                } else {
                    SetBkMode(hdc, TRANSPARENT);
                    SetTextColor(hdc, (*state).palette.text);
                    (*state).card_brush as LRESULT
                }
            }
            WM_CLOSE => {
                DestroyWindow(hwnd);
                0
            }
            WM_DESTROY => {
                PostThreadMessageW(GetCurrentThreadId(), WM_APP_RENDERER_EXIT, 0, 0);
                0
            }
            WM_NCDESTROY => {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                drop(Box::from_raw(state));
                DefWindowProcW(hwnd, message, w_param, l_param)
            }
            _ => DefWindowProcW(hwnd, message, w_param, l_param),
        }
    }

    fn has_intent<F>(state: &UiViewState, mut predicate: F) -> bool
    where
        F: FnMut(&UiIntent) -> bool,
    {
        state.intents.iter().any(|intent| predicate(intent))
    }

    /// Downstream contact/notice text, verbatim. The platform-owned text is
    /// shown exactly as received: no kind label, no prefix, no additions.
    /// Empty stays hidden (the caller falls back to `no_modules`).
    fn module_summary(model: &UiRenderSnapshot) -> String {
        if model.modules.entries().is_empty() {
            return model.copy_text_or_default("no_modules").to_string();
        }
        let mut lines = Vec::new();
        for module in model.modules.entries() {
            for value in module.fields.values() {
                if !value.trim().is_empty() {
                    lines.push(value.clone());
                }
            }
        }
        if lines.is_empty() {
            return model.copy_text_or_default("no_modules").to_string();
        }
        lines.join("\r\n").chars().take(960).collect()
    }

    unsafe fn replace_brush(slot: &mut HBRUSH, color: DWORD) {
        delete_brush(slot);
        *slot = CreateSolidBrush(color);
    }

    unsafe fn delete_brush(slot: &mut HBRUSH) {
        if !slot.is_null() {
            DeleteObject((*slot).cast());
            *slot = null_mut();
        }
    }

    unsafe fn create_font(height: i32, weight: i32, face: &str) -> HFONT {
        let face = wide(face);
        CreateFontW(
            height,
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE,
            face.as_ptr(),
        )
    }

    unsafe fn delete_font(slot: &mut HFONT) {
        if !slot.is_null() {
            DeleteObject((*slot).cast());
            *slot = null_mut();
        }
    }

    unsafe fn send_font(hwnd: HWND, font: HFONT) {
        if !hwnd.is_null() && !font.is_null() {
            SendMessageW(hwnd, WM_SETFONT, font as usize, 1);
        }
    }

    unsafe fn draw_rounded_surface(hdc: HDC, rect: &RECT, fill: DWORD, border: DWORD, radius: i32) {
        let pen = CreatePen(PS_SOLID, 1, border);
        let brush = CreateSolidBrush(fill);
        let old_pen = SelectObject(hdc, pen);
        let old_brush = SelectObject(hdc, brush.cast());
        RoundRect(
            hdc,
            rect.left,
            rect.top,
            rect.right,
            rect.bottom,
            radius,
            radius,
        );
        SelectObject(hdc, old_pen);
        SelectObject(hdc, old_brush);
        DeleteObject(pen);
        DeleteObject(brush.cast());
    }

    fn move_control(hwnd: HWND, x: i32, y: i32, width: i32, height: i32) {
        if !hwnd.is_null() {
            unsafe {
                MoveWindow(hwnd, x, y, width, height, 1);
            }
        }
    }

    fn set_text(hwnd: HWND, text: &str) {
        if !hwnd.is_null() {
            let text = wide(text);
            unsafe {
                SetWindowTextW(hwnd, text.as_ptr());
            }
        }
    }

    fn drain_renderer_exit_messages() {
        let mut message = MSG {
            hwnd: null_mut(),
            message: 0,
            w_param: 0,
            l_param: 0,
            time: 0,
            pt: POINT { x: 0, y: 0 },
            private: 0,
        };
        unsafe {
            while PeekMessageW(
                &mut message,
                null_mut(),
                WM_APP_RENDERER_EXIT,
                WM_APP_RENDERER_EXIT,
                PM_REMOVE,
            ) != 0
            {}
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn high_contrast_enabled() -> bool {
        let mut contrast = HIGHCONTRASTW {
            cb_size: size_of::<HIGHCONTRASTW>() as DWORD,
            dw_flags: 0,
            lpsz_default_scheme: null_mut(),
        };
        unsafe {
            SystemParametersInfoW(
                SPI_GETHIGHCONTRAST,
                contrast.cb_size,
                (&mut contrast as *mut HIGHCONTRASTW).cast(),
                0,
            ) != 0
                && contrast.dw_flags & HCF_HIGHCONTRASTON != 0
        }
    }

    unsafe fn win32_error(operation: &str) -> WindowsRendererError {
        WindowsRendererError::Win32 {
            operation: operation.to_string(),
            code: GetLastError(),
        }
    }
}
