//! Artifact identification, static analysis, searching, and relationship
//! discovery for Vortex-RE.
//!
//! The crate exposes a provider abstraction ([`AnalysisProvider`]) and the
//! first built-in provider ([`builtin::BuiltinStaticProvider`]) which works
//! entirely offline on ordinary files, JavaScript/JSON text, and printable
//! strings — no external reverse-engineering engines required.

pub mod archive;
pub mod builtin;
pub mod identify;
pub mod javascript;
pub mod native;
pub mod provider;
pub mod search;
pub mod strings;
pub mod tree;

pub use builtin::{BuiltinStaticProvider, BUILTIN_STATIC_ID};
pub use provider::{
    AnalysisProvider, AnalysisRequest, CancelToken, Capability, Outcome, ProviderDescriptor,
    ProviderReport, ReportBuilder, SearchQuery, StopReason,
};
pub use search::SearchMatch;
