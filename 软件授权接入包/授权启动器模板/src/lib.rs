//! Small, dependency-free reference implementation of the Authorization A
//! product-side contracts.
//!
//! The types in this crate deliberately model a local, language-neutral
//! contract. They do not connect to a VPS, inspect an EXE, or claim that a
//! simulated legacy handshake is compatible with a real product.

mod authorization;
pub mod current_runtime;
pub mod device_code;
mod codec;
mod contract;
mod credential_vault;
mod legacy;
mod lifecycle;
mod platform;
mod profile;
pub mod runtime;
mod runtime_state;
mod session;
mod simulation;
mod transport;
mod ui;
mod webview_renderer;
mod windows_renderer;

pub use authorization::*;
pub use contract::*;
pub use credential_vault::*;
pub use device_code::*;
pub use legacy::*;
pub use lifecycle::*;
pub use platform::*;
pub use profile::*;
pub use runtime::*;
pub use runtime_state::*;
pub use session::*;
pub use simulation::*;
pub use transport::*;
pub use ui::*;
pub use webview_renderer::*;
pub use windows_renderer::*;

pub(crate) use contract::{validate_identifier, validate_short_text};
