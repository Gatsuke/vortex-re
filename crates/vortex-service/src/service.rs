//! The application service: run lifecycle, provider dispatch, evidence
//! retrieval, comparison, and export.

use crate::doctor::DoctorReport;
use crate::identity::compute_target_identity;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vortex_core::config::VortexConfig;
use vortex_core::error::{ErrorCode, VortexError, VortexResult};
use vortex_core::paths::{validate_target, TargetInfo, TargetKind};
use vortex_evidence::compare_runs;
use vortex_evidence::pagination::{paginate, PageParams, Paged};
use vortex_evidence::store::{export_run, FileSystemRunStore, RunStore};
use vortex_evidence::{
    EvidenceRun, ProviderRef, RunComparison, RunStatus, RunSummary, TargetIdentity, ToolInfo,
    SCHEMA_VERSION,
};
use vortex_providers::builtin::BuiltinStaticProvider;
use vortex_providers::provider::{
    AnalysisProvider, AnalysisRequest, CancelToken, Outcome, ProviderReport, SearchQuery,
};

/// Options for one analysis operation.
#[derive(Debug, Clone)]
pub struct OperationOptions {
    /// How the operation was invoked (CLI command line or `mcp:<tool>`).
    pub invocation: String,
    /// Optional override of the summary entry cap.
    pub max_entries: Option<usize>,
    /// Optional override of the match cap (search only).
    pub max_matches: Option<usize>,
    /// Optional override of the time budget, in seconds.
    pub timeout_secs: Option<u64>,
    /// Case-sensitive search (search only).
    pub case_sensitive: bool,
    /// Persist the run record (default true; `--no-store` disables).
    pub persist: bool,
}

impl Default for OperationOptions {
    fn default() -> Self {
        Self {
            invocation: "vortex".to_string(),
            max_entries: None,
            max_matches: None,
            timeout_secs: None,
            case_sensitive: false,
            persist: true,
        }
    }
}

/// Result of an analysis operation: the provider report plus run status.
///
/// Analysis-level failures are in-band (`status` + `report.errors`) so
/// partial findings are never lost; only infrastructure failures return
/// `Err`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OperationResult {
    /// Run identifier when the record was persisted.
    pub run_id: Option<String>,
    /// Final run status.
    pub status: RunStatus,
    /// The provider report (findings, relationships, limitations, ...).
    pub report: ProviderReport,
}

/// Sections of a stored run that can be retrieved (paginated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSection {
    /// The bounded operation summary.
    Summary,
    /// Findings.
    Findings,
    /// Relationships.
    Relationships,
    /// Limitations.
    Limitations,
    /// Unknowns.
    Unknowns,
    /// Warnings.
    Warnings,
    /// Errors.
    Errors,
    /// A counts-only overview of every section.
    Overview,
}

impl EvidenceSection {
    /// Parse a section name (used by CLI and MCP).
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "summary" => Some(Self::Summary),
            "findings" => Some(Self::Findings),
            "relationships" => Some(Self::Relationships),
            "limitations" => Some(Self::Limitations),
            "unknowns" => Some(Self::Unknowns),
            "warnings" => Some(Self::Warnings),
            "errors" => Some(Self::Errors),
            "overview" | "all" => Some(Self::Overview),
            _ => None,
        }
    }

    /// Stable section name.
    pub const fn as_str(self) -> &'static str {
        match self {
            EvidenceSection::Summary => "summary",
            EvidenceSection::Findings => "findings",
            EvidenceSection::Relationships => "relationships",
            EvidenceSection::Limitations => "limitations",
            EvidenceSection::Unknowns => "unknowns",
            EvidenceSection::Warnings => "warnings",
            EvidenceSection::Errors => "errors",
            EvidenceSection::Overview => "overview",
        }
    }
}

/// One page of evidence from a stored run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvidenceView {
    /// Header summary of the run.
    pub run: RunSummary,
    /// Section name served.
    pub section: String,
    /// The page payload.
    pub page: Paged<serde_json::Value>,
}

/// The single application service used by both the CLI and MCP server.
pub struct VortexService {
    config: VortexConfig,
    store: Arc<FileSystemRunStore>,
    providers: Vec<Arc<dyn AnalysisProvider>>,
}

impl VortexService {
    /// Create the service with the built-in provider and an open store.
    pub fn new(config: VortexConfig) -> VortexResult<Self> {
        let store =
            Arc::new(FileSystemRunStore::open(config.runs_dir()).map_err(|err| err.into_vortex())?);
        Ok(Self {
            config,
            store,
            providers: vec![Arc::new(BuiltinStaticProvider::new())],
        })
    }

    /// Effective configuration (read-only).
    pub fn config(&self) -> &VortexConfig {
        &self.config
    }

    /// Underlying store (read-only handle).
    pub fn store(&self) -> &Arc<FileSystemRunStore> {
        &self.store
    }

    /// Capability report across all registered providers.
    pub fn capabilities(&self) -> CapabilityReport {
        let providers = self
            .providers
            .iter()
            .map(|provider| {
                let descriptor = provider.descriptor();
                ProviderCapabilities {
                    id: descriptor.id.clone(),
                    version: descriptor.version.clone(),
                    capabilities: descriptor
                        .capabilities
                        .clone()
                        .into_iter()
                        .map(|capability| CapabilityInfo {
                            id: capability.as_str().to_string(),
                            description: capability.description().to_string(),
                        })
                        .collect(),
                }
            })
            .collect::<Vec<_>>();
        CapabilityReport {
            schema_version: SCHEMA_VERSION,
            providers,
        }
    }

    /// Inspect an artifact (bounded inventory and identification).
    pub fn inspect(
        &self,
        path: &Path,
        options: &OperationOptions,
        cancel: &CancelToken,
    ) -> VortexResult<OperationResult> {
        self.run_operation("inspect", path, options, cancel, |provider, request| {
            provider.inspect(request)
        })
    }

    /// Search an artifact for literal text.
    pub fn search(
        &self,
        path: &Path,
        query: &str,
        options: &OperationOptions,
        cancel: &CancelToken,
    ) -> VortexResult<OperationResult> {
        if query.is_empty() {
            return Err(VortexError::validation("search query must not be empty")
                .with_hint("provide a non-empty literal query"));
        }
        let search_query = SearchQuery {
            text: query.to_string(),
            case_sensitive: options.case_sensitive,
        };
        self.run_operation("search", path, options, cancel, |provider, request| {
            provider.search(request, &search_query)
        })
    }

    /// Discover relationships inside an artifact.
    pub fn relationships(
        &self,
        path: &Path,
        options: &OperationOptions,
        cancel: &CancelToken,
    ) -> VortexResult<OperationResult> {
        self.run_operation(
            "relationships",
            path,
            options,
            cancel,
            |provider, request| provider.relationships(request),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn run_operation(
        &self,
        operation: &str,
        path: &Path,
        options: &OperationOptions,
        cancel: &CancelToken,
        dispatch: impl FnOnce(&dyn AnalysisProvider, &AnalysisRequest) -> ProviderReport,
    ) -> VortexResult<OperationResult> {
        // 1. Validate the target and policy.
        let target = validate_target(path)?;
        self.config.ensure_target_allowed(&target.canonical)?;

        // 2. Resolve limits with option overrides.
        let mut limits = self.config.limits.clone();
        if let Some(max_entries) = options.max_entries {
            if max_entries == 0 {
                return Err(VortexError::validation("max-entries must be >= 1"));
            }
            limits.max_entries = max_entries;
        }
        if let Some(max_matches) = options.max_matches {
            if max_matches == 0 {
                return Err(VortexError::validation("max-matches must be >= 1"));
            }
            limits.max_matches = max_matches;
        }
        if let Some(timeout_secs) = options.timeout_secs {
            if timeout_secs == 0 {
                return Err(VortexError::validation("timeout-secs must be >= 1"));
            }
            limits.timeout_secs = timeout_secs;
        }
        limits.validate().map_err(VortexError::validation)?;

        // 3. Compute target identity (digests are part of every record).
        let (identity, digest_note) = compute_target_identity(&target, &limits)?;

        // 4. Pick a provider (single built-in provider for now; selection is
        //    explicit and never silently substitutes).
        let provider = self.providers.first().ok_or_else(|| {
            VortexError::new(ErrorCode::MissingProvider, "no providers are registered")
        })?;
        provider.validate_request(&self.analysis_request(
            &target,
            &identity,
            limits.clone(),
            cancel,
        ))?;

        // 5. Create and durably persist the running record before analysis.
        let mut run = EvidenceRun::new_running(
            operation,
            identity,
            ProviderRef {
                id: provider.descriptor().id.clone(),
                version: provider.descriptor().version.clone(),
            },
            ToolInfo {
                name: "vortex".to_string(),
                version: vortex_core::APP_VERSION.to_string(),
                invocation: options.invocation.clone(),
            },
            serde_json::json!({}),
        );
        if let Some(note) = digest_note {
            run.limitations.push(note);
        }
        if options.persist {
            self.store
                .save(&run)
                .map_err(|err| err.into_vortex())
                .map_err(|err| {
                    err.with_detail(format!("run {} could not be persisted", run.run_id))
                })?;
        }

        // 6. Run the analysis with a deadline.
        let deadline = Instant::now() + Duration::from_secs(limits.timeout_secs);
        let request = AnalysisRequest {
            target: target.clone(),
            root: match target.kind {
                TargetKind::Directory => target.canonical.clone(),
                TargetKind::File => target
                    .canonical
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| target.canonical.clone()),
            },
            limits: limits.clone(),
            deadline: Some(deadline),
            cancel: cancel.clone(),
        };
        let report = dispatch(provider.as_ref(), &request);

        // 7. Merge the report into the run and finalize.
        run.summary = report.summary.clone();
        run.findings = report.findings.clone();
        run.relationships = report.relationships.clone();
        run.limitations.extend(report.limitations.iter().cloned());
        run.unknowns = report.unknowns.clone();
        run.warnings = report.warnings.clone();
        run.errors = report.errors.clone();
        run.redactions = report.redactions.clone();
        let mut counts = report.counts.clone();
        counts.findings = run.findings.len();
        counts.relationships = run.relationships.len();
        run.counts = counts;

        let (status, detail) = match &report.outcome {
            Outcome::Succeeded => (RunStatus::Succeeded, None),
            Outcome::Partial { reason } => (RunStatus::Partial, Some(reason.clone())),
            Outcome::Cancelled => (
                RunStatus::Cancelled,
                Some("operation was cancelled".to_string()),
            ),
        };
        run.finalize(status, detail);

        if options.persist {
            self.store
                .save(&run)
                .map_err(|err| err.into_vortex())
                .map_err(|err| {
                    err.with_detail(format!(
                        "analysis finished but the final record for run {} could not be saved",
                        run.run_id
                    ))
                })?;
        }

        Ok(OperationResult {
            run_id: options.persist.then(|| run.run_id.clone()),
            status: run.status,
            report,
        })
    }

    fn analysis_request(
        &self,
        target: &TargetInfo,
        identity: &TargetIdentity,
        limits: vortex_core::limits::ResourceLimits,
        cancel: &CancelToken,
    ) -> AnalysisRequest {
        let _ = identity;
        AnalysisRequest {
            target: target.clone(),
            root: match target.kind {
                TargetKind::Directory => target.canonical.clone(),
                TargetKind::File => target
                    .canonical
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| target.canonical.clone()),
            },
            limits,
            deadline: None,
            cancel: cancel.clone(),
        }
    }

    /// List stored runs, newest first.
    pub fn list_runs(&self, limit: usize) -> VortexResult<Vec<RunSummary>> {
        self.store
            .list(limit.max(1))
            .map_err(|err| err.into_vortex())
    }

    /// Retrieve one page of a section from a stored run.
    pub fn read_evidence(
        &self,
        run_id: &str,
        section: EvidenceSection,
        page: usize,
        page_size: Option<usize>,
    ) -> VortexResult<EvidenceView> {
        let run = self.store.load(run_id).map_err(|err| err.into_vortex())?;
        let params = PageParams::new(page.max(1), self.config.limits.clamp_page_size(page_size));
        let (section_name, items, paged) = match section {
            EvidenceSection::Summary => ("summary", vec![run.summary.clone()], None),
            EvidenceSection::Findings => {
                let values = run
                    .findings
                    .iter()
                    .map(|f| serde_json::to_value(f).unwrap_or_default())
                    .collect::<Vec<_>>();
                ("findings", Vec::new(), Some(paginate(&values, params)))
            }
            EvidenceSection::Relationships => {
                let values = run
                    .relationships
                    .iter()
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .collect::<Vec<_>>();
                ("relationships", Vec::new(), Some(paginate(&values, params)))
            }
            EvidenceSection::Limitations => (
                "limitations",
                run.limitations
                    .iter()
                    .map(|l| serde_json::json!(l))
                    .collect(),
                None,
            ),
            EvidenceSection::Unknowns => (
                "unknowns",
                run.unknowns.iter().map(|u| serde_json::json!(u)).collect(),
                None,
            ),
            EvidenceSection::Warnings => (
                "warnings",
                run.warnings.iter().map(|w| serde_json::json!(w)).collect(),
                None,
            ),
            EvidenceSection::Errors => (
                "errors",
                run.errors
                    .iter()
                    .map(|e| serde_json::to_value(e).unwrap_or_default())
                    .collect(),
                None,
            ),
            EvidenceSection::Overview => (
                "overview",
                vec![serde_json::json!({
                    "schema_version": run.schema_version,
                    "run_id": run.run_id,
                    "operation": run.operation,
                    "status": run.status.as_str(),
                    "started_at": run.started_at,
                    "completed_at": run.completed_at,
                    "target": run.target,
                    "provider": run.provider,
                    "tool": run.tool,
                    "counts": {
                        "findings": run.findings.len(),
                        "relationships": run.relationships.len(),
                        "limitations": run.limitations.len(),
                        "unknowns": run.unknowns.len(),
                        "warnings": run.warnings.len(),
                        "errors": run.errors.len(),
                        "redactions": run.redactions.len(),
                        "files_scanned": run.counts.files_scanned,
                        "files_skipped": run.counts.files_skipped,
                        "truncated": run.counts.truncated,
                    },
                })],
                None,
            ),
        };
        let page_payload = paged.unwrap_or(Paged {
            items,
            page: 1,
            page_size: usize::MAX,
            total_items: 0,
            total_pages: 0,
            has_next: false,
        });
        Ok(EvidenceView {
            run: RunSummary::from(&run),
            section: section_name.to_string(),
            page: page_payload,
        })
    }

    /// Export a stored run to a standalone JSON file. Returns the output path.
    pub fn export_run_record(&self, run_id: &str, out_path: &Path) -> VortexResult<PathBuf> {
        let run = self.store.load(run_id).map_err(|err| err.into_vortex())?;
        export_run(&run, out_path).map_err(|err| err.into_vortex())?;
        Ok(out_path.to_path_buf())
    }

    /// Compare two stored runs (structural comparison only).
    pub fn compare(&self, run_id_a: &str, run_id_b: &str) -> VortexResult<RunComparison> {
        let a = self.store.load(run_id_a).map_err(|err| err.into_vortex())?;
        let b = self.store.load(run_id_b).map_err(|err| err.into_vortex())?;
        Ok(compare_runs(&a, &b))
    }

    /// Mark stale `running` runs as failed. Returns recovered run ids.
    pub fn recover_stale_runs(&self, older_than: Duration) -> VortexResult<Vec<String>> {
        self.store
            .recover_stale_runs(older_than)
            .map_err(|err| err.into_vortex())
    }

    /// Run the diagnostics suite.
    pub fn doctor(&self) -> DoctorReport {
        crate::doctor::run_doctor(self)
    }
}

/// Aggregate capability report across providers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapabilityReport {
    /// Evidence schema version in use.
    pub schema_version: u32,
    /// Providers and their capabilities.
    pub providers: Vec<ProviderCapabilities>,
}

/// One provider's capabilities.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderCapabilities {
    /// Provider identifier.
    pub id: String,
    /// Provider version.
    pub version: String,
    /// Capability list.
    pub capabilities: Vec<CapabilityInfo>,
}

/// One capability entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapabilityInfo {
    /// Stable capability identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use vortex_core::limits::ResourceLimits;

    fn service_in(dir: &Path) -> VortexService {
        let config = VortexConfig {
            data_dir: dir.to_path_buf(),
            limits: ResourceLimits::default(),
            allowed_roots: None,
            notes: Vec::new(),
        };
        VortexService::new(config).expect("service")
    }

    fn fixture(dir: &Path) -> PathBuf {
        let base = dir.join("app");
        std::fs::create_dir_all(base.join("src/lib")).unwrap();
        std::fs::write(
            base.join("package.json"),
            br#"{"name":"demo","version":"1.0.0","main":"src/main.js","devDependencies":{"electron":"^33.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            base.join("src/main.js"),
            b"const config = require('./lib/config.js');\nmodule.exports = config;\n",
        )
        .unwrap();
        std::fs::write(base.join("src/lib/config.js"), b"module.exports = {};\n").unwrap();
        base
    }

    #[test]
    fn inspect_persists_a_complete_run_record() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let app = fixture(dir.path());
        let cancel = CancelToken::new();
        let result = service
            .inspect(&app, &OperationOptions::default(), &cancel)
            .expect("inspect");
        assert_eq!(result.status, RunStatus::Succeeded);

        let run_id = result.run_id.expect("persisted run id");
        let view = service
            .read_evidence(&run_id, EvidenceSection::Overview, 1, None)
            .expect("read");
        assert_eq!(view.run.operation, "inspect");
        assert!(view.run.finding_count >= 2);

        let stored = service.store().load(&run_id).expect("load");
        assert_eq!(stored.status, RunStatus::Succeeded);
        assert!(stored.completed_at.is_some());
        assert!(stored.target.sha256.len() == 64);
        assert!(vortex_evidence::validate::validate_run(&stored).is_empty());
    }

    #[test]
    fn no_store_skips_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let app = fixture(dir.path());
        let options = OperationOptions {
            persist: false,
            ..OperationOptions::default()
        };
        let result = service
            .inspect(&app, &options, &CancelToken::new())
            .unwrap();
        assert!(result.run_id.is_none());
        assert!(service.list_runs(10).unwrap().is_empty());
    }

    #[test]
    fn invalid_inputs_fail_before_run_creation() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let err = service
            .inspect(
                Path::new("/nonexistent/path"),
                &OperationOptions::default(),
                &CancelToken::new(),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(service.list_runs(10).unwrap().is_empty());

        let err = service
            .search(
                &fixture(dir.path()),
                "",
                &OperationOptions::default(),
                &CancelToken::new(),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Validation);
    }

    #[test]
    fn search_and_relationships_produce_runs() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let app = fixture(dir.path());
        let search = service
            .search(
                &app,
                "config",
                &OperationOptions::default(),
                &CancelToken::new(),
            )
            .unwrap();
        assert_eq!(search.status, RunStatus::Succeeded);
        assert!(search.report.summary["matches"].as_u64().unwrap() >= 2);

        let relationships = service
            .relationships(&app, &OperationOptions::default(), &CancelToken::new())
            .unwrap();
        assert!(
            relationships.report.summary["relationships"]
                .as_u64()
                .unwrap()
                >= 2
        );
    }

    #[test]
    fn pagination_over_findings() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let app = fixture(dir.path());
        let result = service
            .inspect(&app, &OperationOptions::default(), &CancelToken::new())
            .unwrap();
        let run_id = result.run_id.unwrap();

        let page1 = service
            .read_evidence(&run_id, EvidenceSection::Findings, 1, Some(2))
            .unwrap();
        assert_eq!(page1.page.items.len(), 2);
        assert!(page1.page.has_next);
        let page2 = service
            .read_evidence(&run_id, EvidenceSection::Findings, 2, Some(2))
            .unwrap();
        assert_ne!(page1.page.items[0], page2.page.items[0]);

        let huge = service
            .read_evidence(&run_id, EvidenceSection::Findings, 1, Some(999_999))
            .unwrap();
        assert!(huge.page.page_size <= 100);
    }

    #[test]
    fn export_and_compare_runs() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let app = fixture(dir.path());
        let first = service
            .inspect(&app, &OperationOptions::default(), &CancelToken::new())
            .unwrap();
        // Change the artifact, inspect again.
        std::fs::write(
            app.join("src/lib/config.js"),
            b"module.exports = { changed: true };\n",
        )
        .unwrap();
        let second = service
            .inspect(&app, &OperationOptions::default(), &CancelToken::new())
            .unwrap();

        let out = dir.path().join("export").join("run.json");
        service
            .export_run_record(first.run_id.as_deref().unwrap(), &out)
            .unwrap();
        assert!(out.exists());
        let body: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(body["schema_version"], serde_json::json!(SCHEMA_VERSION));

        let comparison = service
            .compare(
                first.run_id.as_deref().unwrap(),
                second.run_id.as_deref().unwrap(),
            )
            .unwrap();
        assert!(!comparison.same_artifact_digest);
        assert!(comparison.notes[0].contains("Structural"));
    }

    #[test]
    fn timeout_yields_cancelled_status_with_partial_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let app = fixture(dir.path());
        let options = OperationOptions {
            timeout_secs: Some(1),
            ..OperationOptions::default()
        };
        // Pre-cancel the token: the provider stops at the first checkpoint.
        let cancel = CancelToken::new();
        cancel.cancel();
        let result = service.inspect(&app, &options, &cancel).unwrap();
        assert_eq!(result.status, RunStatus::Cancelled);
        let run_id = result.run_id.unwrap();
        let stored = service.store().load(&run_id).unwrap();
        assert!(stored
            .limitations
            .iter()
            .any(|l| l.contains("stopped early")));
    }

    #[test]
    fn allowed_roots_reject_outside_targets() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("allowed");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"hi").unwrap();
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, b"secret").unwrap();

        let config = VortexConfig {
            data_dir: dir.path().join("data"),
            limits: ResourceLimits::default(),
            allowed_roots: Some(vec![root.clone()]),
            notes: Vec::new(),
        };
        let service = VortexService::new(config).unwrap();
        assert!(service
            .inspect(&root, &OperationOptions::default(), &CancelToken::new())
            .is_ok());
        let err = service
            .inspect(&outside, &OperationOptions::default(), &CancelToken::new())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PathOutsideRoot);
    }

    #[test]
    fn capabilities_report_lists_builtin_provider() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let report = service.capabilities();
        assert_eq!(report.providers.len(), 1);
        assert_eq!(report.providers[0].id, "builtin-static");
        assert!(report.providers[0].capabilities.len() >= 8);
    }
}
