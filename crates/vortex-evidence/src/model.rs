//! The versioned evidence data model (schema version 1).
//!
//! Field semantics:
//! * `observed` facts come directly from the artifact bytes or a tool result.
//! * `derived` facts are documented transformations of observations
//!   (for example: resolving a relative import to a file path).
//! * `inferred` facts are hypotheses that still require verification and are
//!   always paired with an entry in `unknowns` or `limitations`.
//!
//! No confidence percentages are stored: Vortex-RE does not have a defensible
//! measurement method for them, and inventing numbers would be misleading.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current evidence schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Origin classification for findings and relationships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Directly obtained from the artifact or a tool result.
    Observed,
    /// A documented transformation of one or more observations.
    Derived,
    /// A hypothesis that requires further verification.
    Inferred,
}

impl Origin {
    /// Stable string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Origin::Observed => "observed",
            Origin::Derived => "derived",
            Origin::Inferred => "inferred",
        }
    }
}

/// Lifecycle state of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Operation started; record is durable but not final.
    Running,
    /// Operation completed within its limits.
    Succeeded,
    /// Operation produced results but hit a limit or recovered from errors.
    Partial,
    /// Operation failed; partial findings may still be present.
    Failed,
    /// Operation was cancelled before completing.
    Cancelled,
}

impl RunStatus {
    /// Stable string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Succeeded => "succeeded",
            RunStatus::Partial => "partial",
            RunStatus::Failed => "failed",
            RunStatus::Cancelled => "cancelled",
        }
    }

    /// Whether this status represents a final state.
    pub const fn is_final(self) -> bool {
        !matches!(self, RunStatus::Running)
    }
}

/// A source location inside the inspected artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// Path relative to the inspection root (empty when not applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// 1-based line number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// 1-based column number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// 0-based byte offset within the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u64>,
}

impl Location {
    /// A location pointing at a file only.
    pub fn file(path: impl Into<String>) -> Self {
        Self {
            file: Some(path.into()),
            line: None,
            column: None,
            byte_offset: None,
        }
    }

    /// A location pointing at a file, line, and column.
    pub fn file_line_column(path: impl Into<String>, line: u32, column: u32) -> Self {
        Self {
            file: Some(path.into()),
            line: Some(line),
            column: Some(column),
            byte_offset: None,
        }
    }
}

/// Identity of a file that a finding came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// Path relative to the inspection root.
    pub path: String,
    /// SHA-256 of the file contents.
    pub sha256: String,
    /// File size in bytes.
    pub size_bytes: u64,
}

/// A single unit of evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier within the run (`f1`, `f2`, ...).
    pub id: String,
    /// Finding type (for example `file`, `format`, `string`, `package_manifest`).
    pub kind: String,
    /// Whether the fact was observed, derived, or inferred.
    pub origin: Origin,
    /// One-line human-readable summary.
    pub summary: String,
    /// Where the evidence came from, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// The artifact the finding came from, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactRef>,
    /// Kind-specific structured payload.
    pub details: serde_json::Value,
}

/// A node in the relationship graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// Node type: `file`, `package`, `external_package`, `builtin`, `data_uri`.
    pub kind: String,
    /// Path relative to the root, package name, or builtin name.
    pub id: String,
}

/// Whether a relationship points inside or outside the inspected artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Both endpoints are inside the inspection root.
    Internal,
    /// The target endpoint is outside the inspection root.
    External,
}

/// Resolution state of a relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// The target endpoint exists locally and was located.
    Resolved,
    /// The target endpoint could not be located; see `resolution_note`.
    Unresolved,
    /// The endpoint is embedded (for example a `data:` source map URI).
    Inline,
}

/// A directed relationship observed between two nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relationship {
    /// Unique identifier within the run (`r1`, `r2`, ...).
    pub id: String,
    /// Source node.
    pub from: Node,
    /// Target node.
    pub to: Node,
    /// Relationship type (`imports`, `requires`, `dynamic_import`,
    /// `exports_from`, `declares_dependency`, `references_sourcemap`,
    /// `references_script`).
    pub kind: String,
    /// Internal or external scope.
    pub scope: Scope,
    /// Resolution state.
    pub status: Resolution,
    /// Why a relationship is unresolved or inline, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_note: Option<String>,
    /// Whether the statement itself was observed (usually `observed`;
    /// resolution results are `derived`).
    pub origin: Origin,
    /// The finding that observed this relationship, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_finding_id: Option<String>,
    /// Source location of the observed statement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

/// Identity of the inspected artifact for one run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetIdentity {
    /// Path as provided by the caller.
    pub input_path: String,
    /// Canonical absolute path.
    pub canonical_path: String,
    /// `file` or `directory`.
    pub kind: String,
    /// SHA-256 of the file, or of the directory manifest.
    pub sha256: String,
    /// File size, or total size of hashed files for directories.
    pub size_bytes: u64,
    /// Number of files walked (directories only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_count: Option<u64>,
}

/// Which provider produced a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRef {
    /// Provider identifier (for example `builtin-static`).
    pub id: String,
    /// Provider version.
    pub version: String,
}

/// Tool and invocation context for a run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Tool name (`vortex`).
    pub name: String,
    /// Tool version.
    pub version: String,
    /// How the operation was invoked (CLI command line or `mcp:<tool>`).
    pub invocation: String,
}

/// A structured error recorded inside a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorRecord {
    /// Stable error code (snake_case).
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Actionable hint, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Where in the operation the error occurred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
}

/// A redaction that was applied to agent-facing output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionRecord {
    /// Rule identifier.
    pub rule: String,
    /// Why the value was masked.
    pub reason: String,
    /// Location the redacted value came from, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

/// Counters describing what a run covered.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunCounts {
    /// Total findings in the record.
    pub findings: usize,
    /// Total relationships in the record.
    pub relationships: usize,
    /// Files whose content was read or hashed.
    pub files_scanned: usize,
    /// Files skipped (symlinks, oversize, unreadable, binary-for-search).
    pub files_skipped: usize,
    /// True when any list in the record was truncated by a limit.
    pub truncated: bool,
}

/// The durable record of one investigation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRun {
    /// Evidence schema version; see [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Unique run identifier (`run-<uuid>`).
    pub run_id: String,
    /// Operation name (`inspect`, `search`, `relationships`).
    pub operation: String,
    /// Start time (RFC 3339, UTC).
    pub started_at: String,
    /// Completion time (RFC 3339, UTC) once the run reached a final state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    /// Lifecycle status.
    pub status: RunStatus,
    /// Why the status is not `succeeded`, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,
    /// What was inspected.
    pub target: TargetIdentity,
    /// Which provider produced the findings.
    pub provider: ProviderRef,
    /// Tool and invocation context.
    pub tool: ToolInfo,
    /// Bounded operation summary (kind-specific JSON).
    pub summary: serde_json::Value,
    /// Findings, ordered deterministically.
    pub findings: Vec<Finding>,
    /// Relationships, ordered deterministically.
    pub relationships: Vec<Relationship>,
    /// Honest statements about what this run cannot establish.
    pub limitations: Vec<String>,
    /// Open questions that require further verification.
    pub unknowns: Vec<String>,
    /// Non-fatal problems encountered during the run.
    pub warnings: Vec<String>,
    /// Structured errors (fatal and recovered).
    pub errors: Vec<ErrorRecord>,
    /// Redactions applied to agent-facing output in this run.
    pub redactions: Vec<RedactionRecord>,
    /// Coverage counters.
    pub counts: RunCounts,
}

impl EvidenceRun {
    /// Create a new run in the `running` state. Callers must persist it
    /// before starting analysis so an interrupted operation stays visible.
    pub fn new_running(
        operation: impl Into<String>,
        target: TargetIdentity,
        provider: ProviderRef,
        tool: ToolInfo,
        summary: serde_json::Value,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            run_id: new_run_id(),
            operation: operation.into(),
            started_at: vortex_core::timeutil::now_rfc3339(),
            completed_at: None,
            status: RunStatus::Running,
            status_detail: None,
            target,
            provider,
            tool,
            summary,
            findings: Vec::new(),
            relationships: Vec::new(),
            limitations: Vec::new(),
            unknowns: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            redactions: Vec::new(),
            counts: RunCounts::default(),
        }
    }

    /// Move the run to a final state and stamp the completion time.
    pub fn finalize(&mut self, status: RunStatus, detail: Option<String>) {
        self.status = status;
        self.status_detail = detail;
        self.completed_at = Some(vortex_core::timeutil::now_rfc3339());
        self.counts.findings = self.findings.len();
        self.counts.relationships = self.relationships.len();
    }
}

/// Generate a new unique run identifier.
pub fn new_run_id() -> String {
    format!("run-{}", uuid::Uuid::new_v4())
}

/// Compact header used by `runs list` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    /// Run identifier.
    pub run_id: String,
    /// Operation name.
    pub operation: String,
    /// Lifecycle status.
    pub status: RunStatus,
    /// Start time (RFC 3339, UTC).
    pub started_at: String,
    /// Completion time, when final.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    /// Target path as provided.
    pub target_input_path: String,
    /// Target digest.
    pub target_sha256: String,
    /// Provider identifier.
    pub provider_id: String,
    /// Number of findings.
    pub finding_count: usize,
    /// Number of relationships.
    pub relationship_count: usize,
}

impl From<&EvidenceRun> for RunSummary {
    fn from(run: &EvidenceRun) -> Self {
        Self {
            run_id: run.run_id.clone(),
            operation: run.operation.clone(),
            status: run.status,
            started_at: run.started_at.clone(),
            completed_at: run.completed_at.clone(),
            target_input_path: run.target.input_path.clone(),
            target_sha256: run.target.sha256.clone(),
            provider_id: run.provider.id.clone(),
            finding_count: run.findings.len(),
            relationship_count: run.relationships.len(),
        }
    }
}

/// Aggregate counts by finding kind, used in summaries.
pub fn findings_by_kind(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.kind.clone()).or_insert(0) += 1;
    }
    counts
}
