//! Shared types, configuration, validation, and error definitions for Vortex-RE.
//!
//! This crate is intentionally free of analysis logic. It defines the common
//! vocabulary (errors, limits, configuration, digests, path validation, and
//! best-effort redaction) used by every other crate in the workspace.

pub mod config;
pub mod configfile;
pub mod digest;
pub mod error;
pub mod limits;
pub mod paths;
pub mod process;
pub mod redact;
pub mod signing;
pub mod timeutil;

/// Canonical application name.
pub const APP_NAME: &str = "vortex-re";

/// Application version, shared by every crate in the workspace.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default user agent style identifier used in tool records.
pub fn tool_identifier() -> String {
    format!("{APP_NAME}/{APP_VERSION}")
}
