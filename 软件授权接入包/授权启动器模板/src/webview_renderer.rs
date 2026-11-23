//! WebView2-backed desktop renderer for `authorization-a-ui.v1`.
//!
//! The web page is presentation-only. Rust supplies one bounded render
//! snapshot, receives validated bridge messages, and keeps authorization,
//! credential policy, persistence, and launch re-checks outside the page.

use std::collections::BTreeMap;
use std::fmt;

use super::codec::{serialize_json, JsonParser, JsonValue};
use super::{UiIntent, UiRenderSnapshot, AUTHORIZATION_A_UI_PROTOCOL_VERSION};

pub const WEBVIEW_RENDERER_MAX_CREDENTIAL_CHARS: usize = 512;
pub const WEBVIEW_RENDERER_MAX_MESSAGE_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebViewRendererConfig {
    pub title: String,
    pub width: i32,
    pub height: i32,
    pub min_width: i32,
    pub min_height: i32,
}

impl Default for WebViewRendererConfig {
    fn default() -> Self {
        Self {
            title: "软件授权".to_string(),
            width: 480,
            height: 540,
            min_width: 400,
            min_height: 460,
        }
    }
}

impl WebViewRendererConfig {
    pub fn validate(&self) -> Result<(), WebViewRendererError> {
        if self.title.trim().is_empty() || self.title.chars().count() > 128 {
            return Err(WebViewRendererError::InvalidConfig(
                "title must contain 1-128 characters".to_string(),
            ));
        }
        if self.width < self.min_width || self.height < self.min_height {
            return Err(WebViewRendererError::InvalidConfig(
                "initial size must not be smaller than the minimum size".to_string(),
            ));
        }
        if !(320..=4096).contains(&self.min_width) || !(240..=4096).contains(&self.min_height) {
            return Err(WebViewRendererError::InvalidConfig(
                "minimum size is outside the supported range".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebViewRendererError {
    UnsupportedPlatform,
    InvalidConfig(String),
    InvalidModel(String),
    InvalidBridge(String),
    RuntimeUnavailable(String),
    MessageLoop(String),
}

impl fmt::Display for WebViewRendererError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "the WebView2 renderer requires Windows"),
            Self::InvalidConfig(message) => {
                write!(f, "invalid WebView2 renderer config: {message}")
            }
            Self::InvalidModel(message) => write!(f, "invalid UI shell model: {message}"),
            Self::InvalidBridge(message) => {
                write!(f, "invalid WebView UI bridge message: {message}")
            }
            Self::RuntimeUnavailable(message) => {
                write!(f, "WebView2 Runtime unavailable: {message}")
            }
            Self::MessageLoop(message) => write!(f, "WebView2 message loop failed: {message}"),
        }
    }
}

impl std::error::Error for WebViewRendererError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WebViewBridgeMessage {
    Activate(String),
    Intent(UiIntent),
}

#[derive(Debug, Clone)]
pub struct WebViewRenderer {
    config: WebViewRendererConfig,
    snapshot: UiRenderSnapshot,
}

/// Explicit local acceptance only. The renderer stays hidden; the script
/// exercises the embedded page and writes a DOM receipt, never a mock grant.
#[derive(Clone)]
pub struct WebViewAcceptance {pub script:String,pub receipt:std::path::PathBuf}

impl WebViewRenderer {
    /// Current entry: every new host snapshot reaches the page; network work
    /// runs off the window loop and intents use the same current host gate.
    pub fn run_live<F>(host: std::sync::Arc<std::sync::Mutex<crate::current_runtime::DesktopHost>>, on_permit:F) -> Result<(),WebViewRendererError>
    where F: FnMut(crate::current_runtime::LaunchPermit)+'static {
        #[cfg(windows)] { windows::run_live(host,on_permit,None) }
        #[cfg(not(windows))] {let _=(host,on_permit);Err(WebViewRendererError::UnsupportedPlatform)}
    }
    pub fn run_live_acceptance(host:std::sync::Arc<std::sync::Mutex<crate::current_runtime::DesktopHost>>,probe:WebViewAcceptance)->Result<(),WebViewRendererError> {
        #[cfg(windows)] {windows::run_live(host,|_|{},Some(probe))}
        #[cfg(not(windows))] {let _=(host,probe);Err(WebViewRendererError::UnsupportedPlatform)}
    }
    /// Automates the real page while retaining the normal launch callback.
    /// No grant, ticket, or core permission is supplied by the probe.
    pub fn run_live_core_acceptance<F>(host:std::sync::Arc<std::sync::Mutex<crate::current_runtime::DesktopHost>>,on_permit:F,probe:WebViewAcceptance)->Result<(),WebViewRendererError>
    where F: FnMut(crate::current_runtime::LaunchPermit)+'static {
        #[cfg(windows)] {windows::run_live(host,on_permit,Some(probe))}
        #[cfg(not(windows))] {let _=(host,on_permit,probe);Err(WebViewRendererError::UnsupportedPlatform)}
    }
    pub fn new(
        config: WebViewRendererConfig,
        snapshot: UiRenderSnapshot,
    ) -> Result<Self, WebViewRendererError> {
        config.validate()?;
        validate_snapshot(&snapshot)?;
        Ok(Self { config, snapshot })
    }

    pub fn model(&self) -> &super::UiShellModel {
        &self.snapshot.model
    }

    pub fn snapshot(&self) -> &UiRenderSnapshot {
        &self.snapshot
    }

    pub fn update_snapshot(
        &mut self,
        snapshot: UiRenderSnapshot,
    ) -> Result<(), WebViewRendererError> {
        validate_snapshot(&snapshot)?;
        self.snapshot = snapshot;
        Ok(())
    }

    /// Open the product-owned HTML shell. The credential is delivered
    /// separately from `UiIntent`, bounded and dropped after the callback.
    pub fn run<F, G>(&mut self, on_intent: F, on_credential: G) -> Result<(), WebViewRendererError>
    where
        F: FnMut(UiIntent) + 'static,
        G: FnMut(&str) + 'static,
    {
        #[cfg(windows)]
        {
            windows::run(
                &self.config,
                &self.snapshot,
                on_intent,
                on_credential,
                false,
            )
        }
        #[cfg(not(windows))]
        {
            let _ = (on_intent, on_credential);
            Err(WebViewRendererError::UnsupportedPlatform)
        }
    }

    /// Build and tear down one real WebView2 instance without opening a user
    /// session. This validates the local runtime and packaged shell path.
    pub fn smoke_test(&mut self) -> Result<(), WebViewRendererError> {
        #[cfg(windows)]
        {
            windows::run(&self.config, &self.snapshot, |_| {}, |_| {}, true)
        }
        #[cfg(not(windows))]
        {
            Err(WebViewRendererError::UnsupportedPlatform)
        }
    }
}

fn validate_snapshot(snapshot: &UiRenderSnapshot) -> Result<(), WebViewRendererError> {
    let model = &snapshot.model;
    if model.schema_version != AUTHORIZATION_A_UI_PROTOCOL_VERSION {
        return Err(WebViewRendererError::InvalidModel(
            "schema_version is not authorization-a-ui.v1".to_string(),
        ));
    }
    for (name, value) in [
        ("product_id", model.product_id.as_str()),
        ("profile_id", model.profile_id.as_str()),
        ("display_name", model.display_name.as_str()),
        ("locale", model.locale.as_str()),
    ] {
        if value.is_empty() || value.chars().count() > 256 || value.chars().any(char::is_control) {
            return Err(WebViewRendererError::InvalidModel(format!(
                "{name} must contain 1-256 non-control characters"
            )));
        }
    }
    Ok(())
}

fn snapshot_bootstrap(snapshot: &UiRenderSnapshot) -> Result<String, WebViewRendererError> {
    validate_snapshot(snapshot)?;

    let mut profile = BTreeMap::new();
    profile.insert(
        "locale".to_string(),
        JsonValue::String(snapshot.model.locale.clone()),
    );
    profile.insert(
        "theme".to_string(),
        JsonValue::Object(BTreeMap::from([
            (
                "accent".to_string(),
                JsonValue::String(snapshot.model.theme.accent.clone()),
            ),
            (
                "surface".to_string(),
                JsonValue::String(snapshot.model.theme.surface.clone()),
            ),
            (
                "text".to_string(),
                JsonValue::String(snapshot.model.theme.text.clone()),
            ),
            (
                "danger".to_string(),
                JsonValue::String(snapshot.model.theme.danger.clone()),
            ),
        ])),
    );
    profile.insert(
        "copy".to_string(),
        JsonValue::Object(
            snapshot
                .copy
                .iter()
                .map(|(key, value)| (key.clone(), JsonValue::String(value.clone())))
                .collect(),
        ),
    );
    profile.insert(
        "enabled_modules".to_string(),
        JsonValue::Array(
            snapshot
                .enabled_modules()
                .iter()
                .cloned()
                .map(JsonValue::String)
                .collect(),
        ),
    );

    let state = BTreeMap::from([
        (
            "screen".to_string(),
            JsonValue::String(snapshot.model.state.screen.as_str().to_string()),
        ),
        (
            "authorization".to_string(),
            JsonValue::String(snapshot.model.state.authorization.as_str().to_string()),
        ),
        (
            "connectivity".to_string(),
            JsonValue::String(snapshot.model.state.connectivity.as_str().to_string()),
        ),
        (
            "source".to_string(),
            JsonValue::String(snapshot.model.state.source.as_str().to_string()),
        ),
        (
            "intents".to_string(),
            JsonValue::Array(
                snapshot
                    .model
                    .state
                    .intents
                    .iter()
                    .map(|intent| {
                        JsonValue::String(match intent {
                            UiIntent::Activate => "activate".to_string(),
                            UiIntent::Retry => "retry".to_string(),
                            UiIntent::RequestLaunch => "request_launch".to_string(),
                            UiIntent::OpenModule(module) => format!("open_module:{module}"),
                        })
                    })
                    .collect(),
            ),
        ),
    ]);
    let mut render = BTreeMap::from([
        (
            "schema_version".to_string(),
            JsonValue::String(snapshot.model.schema_version.clone()),
        ),
        (
            "product_id".to_string(),
            JsonValue::String(snapshot.model.product_id.clone()),
        ),
        (
            "profile_id".to_string(),
            JsonValue::String(snapshot.model.profile_id.clone()),
        ),
        (
            "display_name".to_string(),
            JsonValue::String(snapshot.model.display_name.clone()),
        ),
        ("state".to_string(), JsonValue::Object(state)),
    ]);
    render.insert(
        "device_code".to_string(),
        snapshot
            .model
            .device_code
            .as_ref()
            .map_or(JsonValue::Null, |value| JsonValue::String(value.clone())),
    );
    // Module cards, verbatim: downstream contact/notice text reaches the page
    // exactly as received. The shell must not add labels or prefixes.
    render.insert(
        "modules".to_string(),
        JsonValue::Array(
            snapshot
                .model
                .modules
                .entries()
                .iter()
                .map(|card| {
                    JsonValue::Object(BTreeMap::from([
                        (
                            "kind".to_string(),
                            JsonValue::String(card.kind.as_str().to_string()),
                        ),
                        (
                            "module_id".to_string(),
                            JsonValue::String(card.module_id.clone()),
                        ),
                        (
                            "fields".to_string(),
                            JsonValue::Object(
                                card.fields
                                    .iter()
                                    .map(|(key, value)| {
                                        (key.clone(), JsonValue::String(value.clone()))
                                    })
                                    .collect(),
                            ),
                        ),
                    ]))
                })
                .collect(),
        ),
    );

    let payload = JsonValue::Object(BTreeMap::from([
        ("profile".to_string(), JsonValue::Object(profile)),
        ("snapshot".to_string(), JsonValue::Object(render)),
    ]));
    let json = serialize_json(&payload);
    if json.len() > 64 * 1024 {
        return Err(WebViewRendererError::InvalidModel(
            "render bootstrap exceeds 64 KiB".to_string(),
        ));
    }
    Ok(json)
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    let mut index = 0;
    while index < input.len() {
        let first = input[index];
        let second = if index + 1 < input.len() {
            input[index + 1]
        } else {
            0
        };
        let third = if index + 2 < input.len() {
            input[index + 2]
        } else {
            0
        };
        let triple = u32::from(first) << 16 | u32::from(second) << 8 | u32::from(third);
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if index + 1 < input.len() {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if index + 2 < input.len() {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        index += 3;
    }
    out
}

fn embedded_shell() -> Result<String, WebViewRendererError> {
    let mut html = include_str!("../ui/authorization-a-shell.html").to_string();
    let css = include_str!("../ui/authorization-a-shell.css");
    let javascript = include_str!("../ui/authorization-a-shell.js");
    let mark_png = include_bytes!("../ui/app-mark.png");
    let css_marker = r#"<link rel="stylesheet" href="authorization-a-shell.css" />"#;
    let script_marker = r#"<script src="authorization-a-shell.js"></script>"#;
    let mark_marker = "app-mark.png";
    if !html.contains(css_marker) || !html.contains(script_marker) || !html.contains(mark_marker) {
        return Err(WebViewRendererError::InvalidModel(
            "HTML shell asset markers are missing".to_string(),
        ));
    }
    html = html.replace(css_marker, &format!("<style>{css}</style>"));
    html = html.replace(script_marker, &format!("<script>{javascript}</script>"));
    html = html.replace(
        mark_marker,
        &format!("data:image/png;base64,{}", encode_base64(mark_png)),
    );
    Ok(html)
}

fn parse_bridge_message(
    body: &str,
    snapshot: &UiRenderSnapshot,
) -> Result<WebViewBridgeMessage, WebViewRendererError> {
    if body.len() > WEBVIEW_RENDERER_MAX_MESSAGE_BYTES {
        return Err(WebViewRendererError::InvalidBridge(
            "message exceeds the bounded bridge size".to_string(),
        ));
    }
    let value = JsonParser::new(body).parse().map_err(|_| {
        WebViewRendererError::InvalidBridge("message is not valid JSON".to_string())
    })?;
    let object = match value {
        JsonValue::Object(object) => object,
        _ => {
            return Err(WebViewRendererError::InvalidBridge(
                "message must be a JSON object".to_string(),
            ));
        }
    };
    let kind = match object.get("type") {
        Some(JsonValue::String(value)) => value.as_str(),
        _ => {
            return Err(WebViewRendererError::InvalidBridge(
                "message type is required".to_string(),
            ));
        }
    };
    match kind {
        "activate" => {
            if !snapshot.model.state.intents.contains(&UiIntent::Activate) {
                return Err(WebViewRendererError::InvalidBridge(
                    "activation is not enabled by the render snapshot".to_string(),
                ));
            }
            let credential = match object.get("credential") {
                Some(JsonValue::String(value)) => value,
                _ => {
                    return Err(WebViewRendererError::InvalidBridge(
                        "activation credential is required".to_string(),
                    ));
                }
            };
            if credential.is_empty()
                || credential.chars().count() > WEBVIEW_RENDERER_MAX_CREDENTIAL_CHARS
                || credential.chars().any(char::is_control)
            {
                return Err(WebViewRendererError::InvalidBridge(
                    "activation credential is outside the bounded input policy".to_string(),
                ));
            }
            Ok(WebViewBridgeMessage::Activate(credential.clone()))
        }
        "intent" => {
            let name = match object.get("name") {
                Some(JsonValue::String(value)) => value.as_str(),
                _ => {
                    return Err(WebViewRendererError::InvalidBridge(
                        "intent name is required".to_string(),
                    ));
                }
            };
            let intent = match name {
                "retry" => UiIntent::Retry,
                "request_launch" => UiIntent::RequestLaunch,
                _ => {
                    return Err(WebViewRendererError::InvalidBridge(
                        "intent is not allowed".to_string(),
                    ));
                }
            };
            if !snapshot.model.state.intents.contains(&intent) {
                return Err(WebViewRendererError::InvalidBridge(
                    "intent is not enabled by the render snapshot".to_string(),
                ));
            }
            Ok(WebViewBridgeMessage::Intent(intent))
        }
        "open_module" => {
            let module = match object.get("module") {
                Some(JsonValue::String(value)) => value,
                _ => {
                    return Err(WebViewRendererError::InvalidBridge(
                        "module name is required".to_string(),
                    ));
                }
            };
            if module.is_empty()
                || module.chars().count() > 32
                || module
                    .chars()
                    .any(|character| !character.is_ascii_lowercase() && character != '_')
                || !snapshot.module_enabled(module)
            {
                return Err(WebViewRendererError::InvalidBridge(
                    "module is not enabled by the render snapshot".to_string(),
                ));
            }
            let intent = UiIntent::OpenModule(module.clone());
            if !snapshot.model.state.intents.contains(&intent) {
                return Err(WebViewRendererError::InvalidBridge(
                    "module intent is not enabled by the render snapshot".to_string(),
                ));
            }
            Ok(WebViewBridgeMessage::Intent(intent))
        }
        _ => Err(WebViewRendererError::InvalidBridge(
            "message type is not allowed".to_string(),
        )),
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::time::{Duration, Instant};
    use tao::{
        dpi::{LogicalSize, Size},
        event::{Event, StartCause, WindowEvent},
        event_loop::{ControlFlow, EventLoopBuilder},
        platform::run_return::EventLoopExtRunReturn,
        window::{Icon, WindowBuilder},
    };
    use wry::{NewWindowResponse, PageLoadEvent, WebViewBuilder};

    enum UserEvent {
        Bridge(WebViewBridgeMessage),
        PageLoaded(String),
    }

    enum LiveEvent { Raw(String), State(serde_json::Value), Permit(crate::current_runtime::LaunchPermit), Ready }
    pub(super) fn run_live<F>(host:std::sync::Arc<std::sync::Mutex<crate::current_runtime::DesktopHost>>,mut on_permit:F,probe:Option<WebViewAcceptance>)->Result<(),WebViewRendererError>
    where F: FnMut(crate::current_runtime::LaunchPermit)+'static {
        let initial=host.lock().map_err(|_|WebViewRendererError::RuntimeUnavailable("Host unavailable".into()))?.snapshot();
        let window_title=initial["snapshot"]["display_name"].as_str().unwrap_or("授权启动器").to_string();
        let mut event_loop=EventLoopBuilder::<LiveEvent>::with_user_event().build();
        let proxy=event_loop.create_proxy();
        let window=WindowBuilder::new().with_title(&window_title).with_visible(probe.is_none()).with_window_icon(product_window_icon())
            .with_inner_size(LogicalSize::new(480.,540.)).build(&event_loop)
            .map_err(|e|WebViewRendererError::RuntimeUnavailable(e.to_string()))?;
        let ipc=proxy.clone();let ready=proxy.clone();
        let webview=WebViewBuilder::new().with_html(embedded_shell()?)
            .with_initialization_script(format!("window.AUTHORIZATION_A_UI_BOOTSTRAP={};",initial.to_string().replace('<',"\\u003c")))
            .with_navigation_handler(initial_html_navigation_policy())
            .with_new_window_req_handler(|_,_|NewWindowResponse::Deny)
            .with_on_page_load_handler(move |e,_|{if matches!(e,PageLoadEvent::Finished){let _=ready.send_event(LiveEvent::Ready);}})
            .with_ipc_handler(move |r|{if r.body().len()<=WEBVIEW_RENDERER_MAX_MESSAGE_BYTES {let _=ipc.send_event(LiveEvent::Raw(r.body().to_owned()));}})
            .build(&window).map_err(|e|WebViewRendererError::RuntimeUnavailable(e.to_string()))?;
        let (send,receive)=std::sync::mpsc::sync_channel::<String>(32);
        let worker=host.clone();let publish=proxy.clone();
        std::thread::spawn(move ||{
            let mut previous=serde_json::Value::Null;
            loop {
                let input=match receive.recv_timeout(Duration::from_millis(250)) {Ok(v)=>Some(v),Err(std::sync::mpsc::RecvTimeoutError::Timeout)=>None,Err(_)=>break};
                let Ok(mut host)=worker.lock() else {break};
                if let Some(input)=input {if let Ok(command)=crate::current_runtime::parse_json(input.as_bytes()) {let _=host.dispatch(&command);}}
                host.tick();
                if let Some(permit)=host.take_launch_permit() {let _=publish.send_event(LiveEvent::Permit(permit));}
                let next=host.snapshot();
                if next!=previous {previous=next.clone();if publish.send_event(LiveEvent::State(next)).is_err(){break;}}
            }
        });
        let acceptance=probe.is_some();let timeout=Instant::now()+Duration::from_secs(60);
        let mut on_event=move |event:Event<'_,LiveEvent>,_:&tao::event_loop::EventLoopWindowTarget<LiveEvent>,flow:&mut ControlFlow|{
            *flow=if acceptance {ControlFlow::WaitUntil(timeout)} else {ControlFlow::Wait};
            match event {
                Event::UserEvent(LiveEvent::Raw(raw))=>{
                    if let Some(probe)=&probe {
                        if let Ok(value)=crate::current_runtime::parse_json(raw.as_bytes()) {
                            if value["type"]=="acceptance_result" {
                                let receipt=serde_json::json!({"dom":value["dom"],"host":host.lock().ok().map(|h|h.snapshot())});
                                let _=std::fs::write(&probe.receipt,receipt.to_string());*flow=ControlFlow::Exit;return;
                            }
                        }
                    }
                    let _=send.try_send(raw);
                },
                Event::UserEvent(LiveEvent::State(value))=>{
                    if let Some(probe)=&probe {let _=std::fs::write(probe.receipt.with_extension("host.json"),serde_json::json!({"render":value,"timing":host.lock().ok().map(|h|h.timing_receipt())}).to_string());}
                    let _=webview.evaluate_script(&format!("window.authorizationAApplySnapshot({});",value.to_string().replace('<',"\\u003c")));
                },
                Event::UserEvent(LiveEvent::Ready)=>{
                    if let Ok(host)=host.lock(){let _=webview.evaluate_script(&format!("window.authorizationAApplySnapshot({});",host.snapshot().to_string().replace('<',"\\u003c")));}
                    if let Some(probe)=&probe {let _=webview.evaluate_script(&probe.script);}
                },
                Event::UserEvent(LiveEvent::Permit(permit))=>on_permit(permit),
                Event::NewEvents(StartCause::ResumeTimeReached{..}) if acceptance=>*flow=ControlFlow::Exit,
                Event::WindowEvent{event:WindowEvent::CloseRequested,..}=>*flow=ControlFlow::Exit,
                _=>{}
            }
        };
        if acceptance {event_loop.run_return(&mut on_event);Ok(())} else {event_loop.run(on_event)}
    }

    pub(super) fn initial_html_navigation_policy() -> impl Fn(String) -> bool {
        let initial_navigation = std::cell::Cell::new(true);
        move |_url| initial_navigation.replace(false)
    }

    fn product_window_icon() -> Option<Icon> {
        const RGBA: &[u8] = include_bytes!("../ui/app-icon-32.rgba");
        const SIZE: u32 = 32;
        if RGBA.len() != (SIZE * SIZE * 4) as usize {
            return None;
        }
        Icon::from_rgba(RGBA.to_vec(), SIZE, SIZE).ok()
    }

    pub(super) fn run<F, G>(
        config: &WebViewRendererConfig,
        snapshot: &UiRenderSnapshot,
        mut on_intent: F,
        mut on_credential: G,
        smoke: bool,
    ) -> Result<(), WebViewRendererError>
    where
        F: FnMut(UiIntent) + 'static,
        G: FnMut(&str) + 'static,
    {
        let html = embedded_shell()?;
        let bootstrap = snapshot_bootstrap(snapshot)?;
        let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
        let proxy = event_loop.create_proxy();
        let window = WindowBuilder::new()
            .with_title(&config.title)
            .with_window_icon(product_window_icon())
            .with_inner_size(Size::Logical(LogicalSize::new(
                config.width as f64,
                config.height as f64,
            )))
            .with_min_inner_size(Size::Logical(LogicalSize::new(
                config.min_width as f64,
                config.min_height as f64,
            )))
            .build(&event_loop)
            .map_err(|error| WebViewRendererError::MessageLoop(error.to_string()))?;
        let init = format!(
            "window.AUTHORIZATION_A_UI_BOOTSTRAP = {};",
            bootstrap.replace('<', "\\u003c")
        );
        let proxy_for_ipc = proxy.clone();
        let proxy_for_page_load = proxy.clone();
        let snapshot_for_ipc = snapshot.clone();
        let builder = WebViewBuilder::new()
            .with_initialization_script(init)
            .with_html(html)
            .with_navigation_handler(initial_html_navigation_policy())
            .with_on_page_load_handler(move |event, url| {
                if matches!(event, PageLoadEvent::Finished) {
                    let _ = proxy_for_page_load.send_event(UserEvent::PageLoaded(url));
                }
            })
            .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
            .with_ipc_handler(move |request| {
                if let Ok(message) = parse_bridge_message(request.body(), &snapshot_for_ipc) {
                    let _ = proxy_for_ipc.send_event(UserEvent::Bridge(message));
                }
            });
        let _webview = builder.build(&window).map_err(|error| {
            WebViewRendererError::RuntimeUnavailable(format!(
                "{error}; install the Microsoft WebView2 Runtime and try again"
            ))
        })?;

        if smoke {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut page_loaded = false;
            let exit_code = event_loop.run_return(|event, _target, control_flow| {
                *control_flow = ControlFlow::WaitUntil(deadline);
                match event {
                    Event::UserEvent(UserEvent::PageLoaded(_url)) => {
                        page_loaded = true;
                        *control_flow = ControlFlow::Exit;
                    }
                    Event::NewEvents(StartCause::ResumeTimeReached { .. }) => {
                        *control_flow = ControlFlow::Exit;
                    }
                    Event::WindowEvent {
                        event: WindowEvent::CloseRequested,
                        ..
                    } => *control_flow = ControlFlow::Exit,
                    _ => {}
                }
            });
            drop(_webview);
            drop(window);
            if exit_code != 0 {
                return Err(WebViewRendererError::MessageLoop(format!(
                    "WebView2 smoke loop exited with code {exit_code}"
                )));
            }
            if !page_loaded {
                return Err(WebViewRendererError::MessageLoop(
                    "embedded HTML did not finish loading within 5 seconds".to_string(),
                ));
            }
            return Ok(());
        }

        event_loop.run(move |event, _target, control_flow| {
            *control_flow = ControlFlow::Wait;
            match event {
                Event::UserEvent(UserEvent::Bridge(WebViewBridgeMessage::Activate(credential))) => {
                    on_credential(&credential)
                }
                Event::UserEvent(UserEvent::Bridge(WebViewBridgeMessage::Intent(intent))) => {
                    on_intent(intent)
                }
                Event::WindowEvent {
                    event: WindowEvent::CloseRequested,
                    ..
                } => *control_flow = ControlFlow::Exit,
                _ => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CompatibilityMode, LicenseState, ProductManifest, ThemeTokens, UiProfile, UiShellModel,
        UiViewState,
    };

    fn snapshot_with_state(state: UiViewState) -> UiRenderSnapshot {
        let manifest = ProductManifest::new(
            "webview-test",
            "WebView test",
            "adapter",
            "1.0.0",
            "zh-CN",
            ThemeTokens::new("#D4B45A", "#0C0B09", "#F3EEE4", "#E85A6F"),
            "core/test.exe",
            "state/test",
            "ipc-test",
            CompatibilityMode::NativeCore,
            vec![],
        );
        let profile =
            UiProfile::for_manifest(&manifest, "profile").with_enabled_modules(["contact"]);
        let model = UiShellModel::new(&manifest, &profile, state).unwrap();
        UiRenderSnapshot::new(model, &profile).unwrap()
    }

    fn snapshot() -> UiRenderSnapshot {
        snapshot_with_state(UiViewState::login())
    }

    #[test]
    fn embedded_shell_inlines_product_mark() {
        let html = embedded_shell().unwrap();
        assert!(html.contains("data:image/png;base64,"));
        assert!(html.contains("本软件"));
        assert!(!html.contains("GodSkin"));
        assert!(!html.contains("app-mark.png"));
        assert!(!html.contains("href=\"authorization-a-shell.css\""));
    }

    #[test]
    fn bootstrap_contains_display_model_but_no_credential() {
        let json = snapshot_bootstrap(&snapshot()).unwrap();
        assert!(json.contains("webview-test"));
        assert!(json.contains("enabled_modules"));
        assert!(!json.contains("credential"));
    }

    #[test]
    fn bootstrap_carries_module_fields_verbatim_for_the_contact_banner() {
        use crate::{PlatformAnnouncement, PlatformModules, PlatformSupport, UiModuleCatalog};
        let manifest = ProductManifest::new(
            "webview-test",
            "WebView test",
            "adapter",
            "1.0.0",
            "zh-CN",
            ThemeTokens::new("#D4B45A", "#0C0B09", "#F3EEE4", "#E85A6F"),
            "core/test.exe",
            "state/test",
            "ipc-test",
            CompatibilityMode::NativeCore,
            vec![],
        );
        let profile = UiProfile::for_manifest(&manifest, "profile")
            .with_enabled_modules(["contact", "notice"]);
        let modules = PlatformModules {
            contact: PlatformSupport {
                purchase_url: None,
                qq: None,
                wechat: Some("微信：abc123 加我注明来意".to_string()),
            },
            notice: PlatformAnnouncement::default(),
            purchase_present: false,
            qr_present: false,
            update: None,
        };
        let model = UiShellModel::new(&manifest, &profile, UiViewState::login())
            .unwrap()
            .with_modules(UiModuleCatalog::from_platform_modules(&modules, &profile));
        let snapshot = UiRenderSnapshot::new(model, &profile).unwrap();
        let json = snapshot_bootstrap(&snapshot).unwrap();
        assert!(json.contains("微信：abc123 加我注明来意"));
    }

    #[test]
    fn bridge_accepts_bounded_activation_separately_from_intent() {
        let snapshot = snapshot();
        let message =
            parse_bridge_message(r#"{"type":"activate","credential":"demo-key"}"#, &snapshot)
                .unwrap();
        assert_eq!(
            message,
            WebViewBridgeMessage::Activate("demo-key".to_string())
        );
        let error = parse_bridge_message(r#"{"type":"intent","name":"request_launch"}"#, &snapshot)
            .unwrap_err();
        assert!(matches!(error, WebViewRendererError::InvalidBridge(_)));
    }

    #[test]
    fn bridge_rejects_activation_when_the_snapshot_is_not_login() {
        let snapshot = snapshot_with_state(
            UiViewState::from_license_state(LicenseState::Active, true).unwrap(),
        );
        let error =
            parse_bridge_message(r#"{"type":"activate","credential":"demo-key"}"#, &snapshot)
                .unwrap_err();
        assert!(matches!(error, WebViewRendererError::InvalidBridge(_)));
    }

    #[test]
    fn bridge_rejects_unknown_or_oversized_messages() {
        let snapshot = snapshot();
        let error =
            parse_bridge_message(r#"{"type":"intent","name":"activate"}"#, &snapshot).unwrap_err();
        assert!(matches!(error, WebViewRendererError::InvalidBridge(_)));
        let oversized = format!(
            r#"{{"type":"activate","credential":"{}"}}"#,
            "x".repeat(WEBVIEW_RENDERER_MAX_MESSAGE_BYTES)
        );
        let error = parse_bridge_message(&oversized, &snapshot).unwrap_err();
        assert!(matches!(error, WebViewRendererError::InvalidBridge(_)));
    }

    #[cfg(windows)]
    #[test]
    fn embedded_navigation_allows_only_the_initial_document() {
        let policy = windows::initial_html_navigation_policy();
        assert!(policy("about:blank".to_string()));
        assert!(!policy("https://example.invalid".to_string()));
    }
}
