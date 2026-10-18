//! The provider abstraction: capabilities, requests, reports, and limits.
//!
//! Providers are the only place analysis happens. They receive a validated
//! [`AnalysisRequest`] and return a bounded [`ProviderReport`]. Everything
//! user-facing (CLI, MCP) works through the same provider calls, so behavior
//! cannot drift between interfaces.

use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use vortex_core::error::VortexResult;
use vortex_core::limits::ResourceLimits;
use vortex_core::paths::TargetInfo;
use vortex_evidence::{
    ArtifactRef, ErrorRecord, Finding, Location, Origin, RedactionRecord, Relationship, RunCounts,
};

/// A capability a provider can offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Capability {
    /// Inspect single files (identity, format, bounded content analysis).
    InspectFiles,
    /// Inspect directory trees with a bounded summary.
    InspectDirectories,
    /// Literal text search with source locations.
    SearchText,
    /// Relationship discovery (imports, dependencies, references).
    TraceRelationships,
    /// Identify binary formats by magic bytes.
    IdentifyBinaryFormats,
    /// Extract printable strings from binary content.
    ExtractStrings,
    /// Parse `package.json` manifests.
    ParsePackageManifest,
    /// Line-oriented JavaScript scanning (imports, source maps).
    ParseJavascript,
}

impl Capability {
    /// Stable identifier used in JSON output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::InspectFiles => "inspect_files",
            Capability::InspectDirectories => "inspect_directories",
            Capability::SearchText => "search_text",
            Capability::TraceRelationships => "trace_relationships",
            Capability::IdentifyBinaryFormats => "identify_binary_formats",
            Capability::ExtractStrings => "extract_strings",
            Capability::ParsePackageManifest => "parse_package_manifest",
            Capability::ParseJavascript => "parse_javascript",
        }
    }

    /// One-line human explanation.
    pub const fn description(self) -> &'static str {
        match self {
            Capability::InspectFiles => {
                "Inspect single files: identity, digest, format, bounded content analysis"
            }
            Capability::InspectDirectories => "Inspect directory trees with bounded summaries",
            Capability::SearchText => "Literal text search with file:line locations",
            Capability::TraceRelationships => "Discover imports, dependencies, and references",
            Capability::IdentifyBinaryFormats => "Identify binary formats from magic bytes",
            Capability::ExtractStrings => "Extract printable strings from binary content",
            Capability::ParsePackageManifest => "Parse package.json manifests",
            Capability::ParseJavascript => {
                "Line-oriented JavaScript scanning (imports, requires, source maps)"
            }
        }
    }
}

/// Static description of a provider.
#[derive(Debug, Clone)]
pub struct ProviderDescriptor {
    /// Provider identifier (for example `builtin-static`).
    pub id: String,
    /// Provider version.
    pub version: String,
    /// Capabilities the provider implements.
    pub capabilities: Vec<Capability>,
}

impl ProviderDescriptor {
    /// Whether the provider offers a capability.
    pub fn has(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// Cooperative cancellation token.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    /// A token that is not cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// Why an operation stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Cancellation was requested through the token.
    Cancelled,
    /// The time budget expired.
    Deadline,
}

/// A validated analysis request with limits and stop conditions.
#[derive(Debug, Clone)]
pub struct AnalysisRequest {
    /// Validated target information.
    pub target: TargetInfo,
    /// Inspection root: the target itself for directories, or the parent
    /// directory for single-file targets (locations are relative to it).
    pub root: std::path::PathBuf,
    /// Resource limits for this operation.
    pub limits: ResourceLimits,
    /// Optional wall-clock deadline.
    pub deadline: Option<Instant>,
    /// Cooperative cancellation token.
    pub cancel: CancelToken,
}

impl AnalysisRequest {
    /// Check whether the operation should stop early.
    pub fn stop_reason(&self) -> Option<StopReason> {
        if self.cancel.is_cancelled() {
            return Some(StopReason::Cancelled);
        }
        if let Some(deadline) = self.deadline {
            if Instant::now() >= deadline {
                return Some(StopReason::Deadline);
            }
        }
        None
    }
}

/// Search parameters.
#[derive(Debug, Clone)]
pub struct SearchQuery {
    /// Literal text to find (never a regex).
    pub text: String,
    /// Whether matching is case sensitive (default is insensitive).
    pub case_sensitive: bool,
}

/// Recommended completion state for a provider report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The operation finished within all limits.
    Succeeded,
    /// Results were produced but a limit or error was hit.
    Partial { reason: String },
    /// The operation was cancelled; findings are partial.
    Cancelled,
}

/// The bounded result of one provider operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderReport {
    /// Bounded operation summary.
    pub summary: serde_json::Value,
    /// Findings in deterministic order.
    pub findings: Vec<Finding>,
    /// Relationships in deterministic order.
    pub relationships: Vec<Relationship>,
    /// Honest limits of this analysis.
    pub limitations: Vec<String>,
    /// Open questions.
    pub unknowns: Vec<String>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Structured errors (fatal and recovered).
    pub errors: Vec<ErrorRecord>,
    /// Redactions applied to agent-facing output.
    pub redactions: Vec<RedactionRecord>,
    /// Coverage counters.
    pub counts: RunCounts,
    /// Recommended completion state.
    pub outcome: Outcome,
}

/// Accumulates findings while enforcing resource limits.
///
/// When a cap is hit the builder stops accepting items and marks the report
/// truncated; callers never need to guess whether output was complete.
#[derive(Debug)]
pub struct ReportBuilder {
    limits: ResourceLimits,
    findings: Vec<Finding>,
    relationships: Vec<Relationship>,
    limitations: Vec<String>,
    unknowns: Vec<String>,
    warnings: Vec<String>,
    errors: Vec<ErrorRecord>,
    redactions: Vec<RedactionRecord>,
    findings_truncated: bool,
    relationships_truncated: bool,
    partial_forced: Option<String>,
    next_finding: usize,
    next_relationship: usize,
    files_scanned: usize,
    files_skipped: usize,
}

impl ReportBuilder {
    /// Create a builder with the given limits.
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            findings: Vec::new(),
            relationships: Vec::new(),
            limitations: Vec::new(),
            unknowns: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            redactions: Vec::new(),
            findings_truncated: false,
            relationships_truncated: false,
            partial_forced: None,
            next_finding: 0,
            next_relationship: 0,
            files_scanned: 0,
            files_skipped: 0,
        }
    }

    /// Record a finding. Returns the finding id, or `None` when the cap hit.
    pub fn finding(
        &mut self,
        kind: &str,
        origin: Origin,
        summary: String,
        location: Option<Location>,
        artifact: Option<ArtifactRef>,
        details: serde_json::Value,
    ) -> Option<String> {
        if self.findings.len() >= self.limits.max_findings {
            self.findings_truncated = true;
            return None;
        }
        self.next_finding += 1;
        let id = format!("f{}", self.next_finding);
        self.findings.push(Finding {
            id: id.clone(),
            kind: kind.to_string(),
            origin,
            summary,
            location,
            artifact,
            details,
        });
        Some(id)
    }

    /// Record a relationship. Returns its id, or `None` when the cap hit.
    #[allow(clippy::too_many_arguments)]
    pub fn relationship(
        &mut self,
        from: vortex_evidence::Node,
        to: vortex_evidence::Node,
        kind: &str,
        scope: vortex_evidence::Scope,
        status: vortex_evidence::Resolution,
        resolution_note: Option<String>,
        origin: Origin,
        evidence_finding_id: Option<String>,
        location: Option<Location>,
    ) -> Option<String> {
        if self.relationships.len() >= self.limits.max_relationships {
            self.relationships_truncated = true;
            return None;
        }
        self.next_relationship += 1;
        let id = format!("r{}", self.next_relationship);
        self.relationships.push(Relationship {
            id: id.clone(),
            from,
            to,
            kind: kind.to_string(),
            scope,
            status,
            resolution_note,
            origin,
            evidence_finding_id,
            location,
        });
        Some(id)
    }

    /// Add a limitation statement.
    pub fn limitation(&mut self, text: impl Into<String>) {
        let text = text.into();
        if !self.limitations.contains(&text) {
            self.limitations.push(text);
        }
    }

    /// Add an unknown (open question).
    pub fn unknown(&mut self, text: impl Into<String>) {
        let text = text.into();
        if !self.unknowns.contains(&text) {
            self.unknowns.push(text);
        }
    }

    /// Add a warning.
    pub fn warning(&mut self, text: impl Into<String>) {
        let text = text.into();
        if !self.warnings.contains(&text) {
            self.warnings.push(text);
        }
    }

    /// Add a structured error.
    pub fn error(&mut self, code: &str, message: impl Into<String>, stage: Option<&str>) {
        self.errors.push(ErrorRecord {
            code: code.to_string(),
            message: message.into(),
            hint: None,
            stage: stage.map(str::to_string),
        });
    }

    /// Record a redaction that was applied to output.
    pub fn redaction(&mut self, rule: &str, reason: impl Into<String>, location: Option<Location>) {
        self.redactions.push(RedactionRecord {
            rule: rule.to_string(),
            reason: reason.into(),
            location,
        });
    }

    /// Count a scanned file.
    pub fn scanned(&mut self) {
        self.files_scanned += 1;
    }

    /// Count a skipped file.
    pub fn skipped(&mut self) {
        self.files_skipped += 1;
    }

    /// Number of files counted as scanned so far.
    pub fn scanned_count(&self) -> usize {
        self.files_scanned
    }

    /// Number of files counted as skipped so far.
    pub fn skipped_count(&self) -> usize {
        self.files_skipped
    }

    /// Whether findings or relationships were capped.
    pub fn is_truncated(&self) -> bool {
        self.findings_truncated || self.relationships_truncated
    }

    /// Force the report's outcome to [`Outcome::Partial`] with a reason.
    ///
    /// Used when an operation hits a limit that does not surface as a
    /// finding cap (for example a truncated directory walk).
    pub fn force_partial(&mut self, reason: impl Into<String>) {
        if self.partial_forced.is_none() {
            self.partial_forced = Some(reason.into());
        }
    }

    /// Number of findings collected so far.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Number of relationships collected so far.
    pub fn relationship_count(&self) -> usize {
        self.relationships.len()
    }

    /// Read-only view of relationships collected so far.
    pub fn relationships_snapshot(&self) -> &[Relationship] {
        &self.relationships
    }

    /// Read-only view of findings collected so far.
    pub fn findings_snapshot(&self) -> &[Finding] {
        &self.findings
    }

    /// Turn the accumulated state into a report with a recommended outcome.
    pub fn finish(
        mut self,
        summary: serde_json::Value,
        stop_reason: Option<StopReason>,
    ) -> ProviderReport {
        if let Some(reason) = stop_reason {
            let why = match reason {
                StopReason::Cancelled => "operation was cancelled before completion",
                StopReason::Deadline => "time budget exhausted before completion",
            };
            self.limitation(format!("Analysis stopped early: {why}."));
            return self.finish_with_outcome(summary, Outcome::Cancelled);
        }
        if let Some(reason) = self.partial_forced.clone() {
            return self.finish_with_outcome(summary, Outcome::Partial { reason });
        }
        if self.is_truncated() {
            self.limitation(format!(
                "Output was truncated by resource limits (max_findings={}, max_relationships={}); \
                 more results exist than are recorded here.",
                self.limits.max_findings, self.limits.max_relationships
            ));
            return self.finish_with_outcome(
                summary,
                Outcome::Partial {
                    reason: "output truncated by resource limits".to_string(),
                },
            );
        }
        if !self.errors.is_empty() {
            let reason = format!("{} error(s) occurred during analysis", self.errors.len());
            return self.finish_with_outcome(summary, Outcome::Partial { reason });
        }
        self.finish_with_outcome(summary, Outcome::Succeeded)
    }

    fn finish_with_outcome(self, summary: serde_json::Value, outcome: Outcome) -> ProviderReport {
        let truncated = self.findings_truncated
            || self.relationships_truncated
            || self.partial_forced.is_some();
        ProviderReport {
            summary,
            findings: self.findings,
            relationships: self.relationships,
            limitations: self.limitations,
            unknowns: self.unknowns,
            warnings: self.warnings,
            errors: self.errors,
            redactions: self.redactions,
            counts: RunCounts {
                findings: 0, // filled by the service from final vectors
                relationships: 0,
                files_scanned: self.files_scanned,
                files_skipped: self.files_skipped,
                truncated,
            },
            outcome,
        }
    }
}

/// The contract every analysis provider implements.
///
/// Implementations must be deterministic for identical inputs and limits,
/// must never execute the inspected target, and must respect the request's
/// stop conditions at safe checkpoints.
pub trait AnalysisProvider: Send + Sync {
    /// Static descriptor with id, version, and capabilities.
    fn descriptor(&self) -> &ProviderDescriptor;

    /// Reject requests the provider cannot handle at all.
    ///
    /// Returning `Err` here must mean "this provider will not run"; partial
    /// support is expressed through findings and limitations instead.
    fn validate_request(&self, _request: &AnalysisRequest) -> VortexResult<()> {
        Ok(())
    }

    /// Inspect an artifact (bounded inventory and identification).
    fn inspect(&self, request: &AnalysisRequest) -> ProviderReport;

    /// Search an artifact for literal text.
    fn search(&self, request: &AnalysisRequest, query: &SearchQuery) -> ProviderReport;

    /// Discover relationships inside an artifact.
    fn relationships(&self, request: &AnalysisRequest) -> ProviderReport;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_caps_findings_and_marks_truncation() {
        let limits = ResourceLimits {
            max_findings: 2,
            ..ResourceLimits::default()
        };
        let mut builder = ReportBuilder::new(limits);
        assert!(builder
            .finding(
                "file",
                Origin::Observed,
                "one".into(),
                None,
                None,
                serde_json::json!({})
            )
            .is_some());
        assert!(builder
            .finding(
                "file",
                Origin::Observed,
                "two".into(),
                None,
                None,
                serde_json::json!({})
            )
            .is_some());
        assert!(builder
            .finding(
                "file",
                Origin::Observed,
                "three".into(),
                None,
                None,
                serde_json::json!({})
            )
            .is_none());
        assert!(builder.is_truncated());
        let report = builder.finish(serde_json::json!({}), None);
        assert_eq!(report.findings.len(), 2);
        assert!(matches!(report.outcome, Outcome::Partial { .. }));
        assert!(report.limitations.iter().any(|l| l.contains("truncated")));
    }

    #[test]
    fn builder_deduplicates_limitations_and_warnings() {
        let mut builder = ReportBuilder::new(ResourceLimits::default());
        builder.limitation("same");
        builder.limitation("same");
        builder.warning("same");
        builder.warning("same");
        let report = builder.finish(serde_json::json!({}), None);
        assert_eq!(report.limitations, vec!["same"]);
        assert_eq!(report.warnings, vec!["same"]);
    }

    #[test]
    fn stop_reason_deadline_is_detected() {
        let request = AnalysisRequest {
            target: vortex_core::paths::TargetInfo {
                input: ".".into(),
                canonical: "/".into(),
                kind: vortex_core::paths::TargetKind::File,
                size: 0,
            },
            root: "/".into(),
            limits: ResourceLimits::default(),
            deadline: Some(Instant::now() - std::time::Duration::from_secs(1)),
            cancel: CancelToken::new(),
        };
        assert_eq!(request.stop_reason(), Some(StopReason::Deadline));
        request.cancel.cancel();
        assert_eq!(request.stop_reason(), Some(StopReason::Cancelled));
    }
}
