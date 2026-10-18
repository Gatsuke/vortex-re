//! Application service layer shared by the CLI and the MCP server.
//!
//! Every user-facing interface calls the same [`VortexService`] methods, so
//! CLI and MCP behavior cannot drift. The service owns run lifecycle
//! (durable `running` records, finalization, recovery), provider dispatch,
//! and evidence retrieval.

pub mod doctor;
pub mod identity;
pub mod service;

pub use doctor::{CheckResult, CheckStatus, DoctorReport, NotSupported};
pub use identity::compute_target_identity;
pub use service::{
    CapabilityReport, EvidenceSection, EvidenceView, OperationOptions, OperationResult,
    VortexService,
};
