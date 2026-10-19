//! The application service: run lifecycle, provider dispatch, evidence
//! retrieval, comparison, and export.

use crate::doctor::DoctorReport;
use crate::identity::compute_target_identity;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vortex_core::config::VortexConfig;
use vortex_core::error::{ErrorCode, VortexError, VortexResult};
use vortex_core::paths::{validate_target, TargetInfo, TargetKind};
use vortex_evidence::compare_runs;
use vortex_evidence::pagination::{paginate, PageParams, Paged};
use vortex_evidence::store::{export_run, FileSystemRunStore, RunStore};
use vortex_evidence::store::{RecoveryOptions, RecoveryReport};
use vortex_evidence::{
    EvidenceRun, OperationParams, OwnerProcess, ProviderRef, RunCheckpoint, RunComparison,
    RunStatus, RunSummary, TargetIdentity, ToolInfo, SCHEMA_VERSION,
};
use vortex_providers::builtin::BuiltinStaticProvider;
use vortex_providers::provider::{
    AnalysisProvider, AnalysisRequest, CancelToken, Outcome, ProviderReport, ResumeContext,
    SearchQuery,
};

/// Grace period used by automatic startup recovery when liveness cannot
/// decide (matches the documented `runs recover` default).
pub const STARTUP_RECOVERY_GRACE: Duration = Duration::from_secs(3600);

/// Options for one analysis operation.
///
/// Not `Debug`: the optional checkpoint hook is an opaque closure.
#[derive(Clone)]
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
    /// Optional observer invoked at every durable checkpoint. This is a
    /// progress hook (usable for MCP progress notifications and tests);
    /// it never affects what is persisted.
    #[allow(clippy::type_complexity)]
    pub on_checkpoint: Option<Arc<dyn Fn(&vortex_evidence::RunCheckpoint) + Send + Sync>>,
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
            on_checkpoint: None,
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
    /// What automatic startup recovery did when this service was created.
    startup_recovery: RecoveryReport,
}

impl VortexService {
    /// Create the service with the built-in provider and an open store.
    ///
    /// Creation runs automatic crash recovery: `running` records whose
    /// owning process is dead are marked failed (with an explanation and a
    /// resume hint); ambiguous ones are left in place and reported through
    /// [`VortexService::startup_recovery`].
    pub fn new(config: VortexConfig) -> VortexResult<Self> {
        let store =
            Arc::new(FileSystemRunStore::open(config.runs_dir()).map_err(|err| err.into_vortex())?);
        let startup_recovery = store
            .recover_interrupted_runs(RecoveryOptions {
                age_grace: STARTUP_RECOVERY_GRACE,
                force_aged: false,
            })
            .map_err(|err| err.into_vortex())?;
        Ok(Self {
            config,
            store,
            providers: vec![Arc::new(BuiltinStaticProvider::new())],
            startup_recovery,
        })
    }

    /// What startup recovery did (used by doctor and the CLI banner).
    pub fn startup_recovery(&self) -> &RecoveryReport {
        &self.startup_recovery
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
        self.run_operation(
            "inspect",
            None,
            path,
            options,
            cancel,
            |provider, request| provider.inspect(request),
        )
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
        self.run_operation(
            "search",
            Some(query),
            path,
            options,
            cancel,
            |provider, request| provider.search(request, &search_query),
        )
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
            None,
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
        query_text: Option<&str>,
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
        //    The record carries the owner process, the effective limits, and
        //    the caller parameters — everything that shaped the evidence.
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
        run.owner = Some(OwnerProcess(vortex_core::process::current()));
        run.limits = Some(limits.clone());
        run.params = Some(operation_params_of(query_text, options));
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

        // 6. Run the analysis with a deadline and (for long directory runs)
        //    a durable checkpoint sink.
        let deadline = Instant::now() + Duration::from_secs(limits.timeout_secs);
        let checkpointing = options.persist
            && target.kind == TargetKind::Directory
            && matches!(operation, "inspect" | "search");
        let sink_handle = checkpointing
            .then(|| self.build_sink_bundle(&run, options.on_checkpoint.clone(), cancel.clone()));
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
            checkpoint_sink: sink_handle.as_ref().map(|bundle| bundle.closure()),
            resume: None,
        };
        let report = dispatch(provider.as_ref(), &request);

        // 7. Merge the report into the run and finalize.
        run.summary = report.summary.clone();
        run.findings = report.findings.clone();
        run.relationships = report.relationships.clone();
        merge_text_lists(&mut run.limitations, &report.limitations);
        run.unknowns = report.unknowns.clone();
        run.warnings = report.warnings.clone();
        run.errors = report.errors.clone();
        run.redactions = report.redactions.clone();
        let mut counts = report.counts.clone();
        counts.findings = run.findings.len();
        counts.relationships = run.relationships.len();
        run.counts = counts;

        // Checkpoint write failures and the last durable position surface here.
        if let Some(bundle) = &sink_handle {
            bundle.drain_into(&mut run);
            run.checkpoint = bundle.last_checkpoint();
        }

        let (mut status, detail) = match &report.outcome {
            Outcome::Succeeded => (RunStatus::Succeeded, None),
            Outcome::Partial { reason } => (RunStatus::Partial, Some(reason.clone())),
            Outcome::Cancelled => (
                RunStatus::Cancelled,
                Some("operation was cancelled".to_string()),
            ),
        };
        // The commit rule: a cancelled run never records `succeeded`. If the
        // analysis had already finished by the time cancellation arrived, the
        // findings are kept and the detail says exactly that.
        if cancel.is_cancelled() && status == RunStatus::Succeeded {
            status = RunStatus::Cancelled;
            let detail_text = "the caller cancelled before this result was committed; the \
                               analysis had already finished by then, so the findings are retained"
                .to_string();
            run.status_detail = Some(detail_text);
        } else {
            run.status_detail = detail;
        }
        run.finalize(status, run.status_detail.clone());

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
            checkpoint_sink: None,
            resume: None,
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

    /// Mark stale `running` runs as failed (explicit request; forces aged
    /// runs whose owner still appears alive). Startup recovery already ran
    /// when the service was created — this is the manual override.
    pub fn recover_stale_runs(&self, older_than: Duration) -> VortexResult<RecoveryReport> {
        self.store
            .recover_interrupted_runs(RecoveryOptions {
                age_grace: older_than,
                force_aged: true,
            })
            .map_err(|err| err.into_vortex())
    }

    /// Continue an interrupted run from its last durable checkpoint.
    ///
    /// The resumed pass reuses the recorded limits exactly (only the time
    /// budget may be raised) and refuses to continue when the artifact has
    /// changed since the run was recorded — resuming would otherwise mix
    /// evidence from different versions of the target.
    pub fn resume_run(
        &self,
        run_id: &str,
        options: &OperationOptions,
        cancel: &CancelToken,
    ) -> VortexResult<OperationResult> {
        let mut run = self.store.load(run_id).map_err(|err| err.into_vortex())?;

        // Guard 1: a run that is still `running` may belong to a live process.
        if run.status == RunStatus::Running {
            let owner_dead = run
                .owner
                .as_ref()
                .and_then(|owner| vortex_core::process::owner_is_alive(&owner.0))
                == Some(false);
            if owner_dead {
                // The crash happened after this service started; recover this
                // one record inline (never touching others), then reload it.
                let recovered = self
                    .store
                    .recover_single_interrupted(
                        run_id,
                        RecoveryOptions {
                            age_grace: STARTUP_RECOVERY_GRACE,
                            force_aged: false,
                        },
                    )
                    .map_err(|err| err.into_vortex())?;
                if !recovered {
                    return Err(VortexError::validation(
                        "run is still 'running' and could not be recovered automatically",
                    )
                    .with_hint("if you are sure it crashed, run 'vortex runs recover' first"));
                }
                run = self.store.load(run_id).map_err(|err| err.into_vortex())?;
                if run.status == RunStatus::Running {
                    return Err(VortexError::internal(
                        "inline recovery did not finalize the run",
                    ));
                }
            } else {
                return Err(VortexError::validation(
                    "run is still 'running' and its owner may still be working; refusing to resume",
                )
                .with_hint("if you are sure it crashed, run 'vortex runs recover' first"));
            }
        }

        // Guard 2: final-state eligibility.
        if run.status == RunStatus::Succeeded {
            return Err(VortexError::validation(
                "a succeeded run is complete; there is nothing to resume",
            ));
        }

        // Guard 3: only checkpointed directory operations can resume.
        let Some(checkpoint) = run.checkpoint.clone() else {
            return Err(
                VortexError::validation("this run has no checkpoint to resume from").with_hint(
                    "nothing durable was saved mid-run (early cancellation, single-file target, \
                 or a schema v1 record); re-run the operation instead",
                ),
            );
        };
        if !matches!(run.operation.as_str(), "inspect" | "search") {
            return Err(VortexError::validation(format!(
                "resume is not supported for '{}' in this release; only inspect and search \
                 directory runs carry checkpoints",
                run.operation
            )));
        }
        if run.target.kind != "directory" {
            return Err(VortexError::validation(
                "single-file targets are not resumable; re-run instead",
            ));
        }

        // Guard 4: the artifact must be exactly what the run recorded.
        let recorded_limits = run.limits.clone().ok_or_else(|| {
            VortexError::internal("resumable record is missing its limits snapshot")
        })?;
        let input_path = PathBuf::from(&run.target.input_path);
        let target = validate_target(&input_path)?;
        self.config.ensure_target_allowed(&target.canonical)?;
        let mut limits = recorded_limits;
        if let Some(timeout_secs) = options.timeout_secs {
            if timeout_secs == 0 {
                return Err(VortexError::validation("timeout-secs must be >= 1"));
            }
            limits.timeout_secs = timeout_secs;
        }
        limits.validate().map_err(VortexError::validation)?;
        let (identity, _note) = compute_target_identity(&target, &limits)?;
        if identity.sha256 != run.target.sha256 {
            return Err(VortexError::validation(
                "the artifact changed since the run was recorded (digest mismatch)",
            )
            .with_hint(
                "resuming would mix evidence from different versions of the target; \
                 start a new run instead",
            ));
        }

        // Guard 5: search resumes need the recorded query.
        let recorded_params = run
            .params
            .clone()
            .ok_or_else(|| VortexError::internal("resumable record is missing its parameters"))?;
        let search_query = if run.operation == "search" {
            let query = recorded_params.query.clone().ok_or_else(|| {
                VortexError::validation("cannot resume a search run without its recorded query")
                    .with_hint("schema v1 records predate parameter snapshots; re-run instead")
            })?;
            SearchQuery {
                text: query,
                case_sensitive: recorded_params.case_sensitive,
            }
        } else {
            SearchQuery::default()
        };

        // Resume context: ids continue after existing content, budgets
        // continue from the checkpoint, the walk skips completed files.
        let finding_offset = run.findings.len();
        let relationship_offset = run.relationships.len();
        let prior_matches: usize = run
            .findings
            .iter()
            .filter(|finding| finding.kind == "search_match")
            .count();
        let matches_remaining = checkpoint
            .matches_remaining
            .map(|remaining| remaining as usize)
            .unwrap_or_else(|| limits.max_matches.saturating_sub(prior_matches));
        let entries_used = run
            .findings
            .iter()
            .filter(|finding| finding.kind == "sourcemap_reference")
            .count();
        let manifests_parsed = run
            .findings
            .iter()
            .filter(|finding| finding.kind == "package_manifest")
            .count();
        let resume = ResumeContext {
            from_index: checkpoint.next_file_index,
            finding_offset,
            relationship_offset,
            matches_remaining,
            bytes_remaining: checkpoint.bytes_remaining,
            prior_files_scanned: checkpoint.files_scanned,
            prior_files_skipped: checkpoint.files_skipped,
            entries_used,
            manifests_parsed,
        };

        let provider = self.providers.first().ok_or_else(|| {
            VortexError::new(ErrorCode::MissingProvider, "no providers are registered")
        })?;
        let previous_status = run.status;
        let deadline = Instant::now() + Duration::from_secs(limits.timeout_secs);

        let sink_handle =
            Some(self.build_sink_bundle(&run, options.on_checkpoint.clone(), cancel.clone()));
        let request = AnalysisRequest {
            target: target.clone(),
            root: target.canonical.clone(),
            limits: limits.clone(),
            deadline: Some(deadline),
            cancel: cancel.clone(),
            checkpoint_sink: sink_handle.as_ref().map(|bundle| bundle.closure()),
            resume: Some(resume.clone()),
        };
        let report = if run.operation == "inspect" {
            provider.inspect(&request)
        } else {
            provider.search(&request, &search_query)
        };

        // Merge this pass onto the existing record.
        run.findings.extend(report.findings.iter().cloned());
        run.relationships
            .extend(report.relationships.iter().cloned());
        merge_text_lists(&mut run.limitations, &report.limitations);
        merge_text_lists(&mut run.unknowns, &report.unknowns);
        merge_text_lists(&mut run.warnings, &report.warnings);
        run.errors.extend(report.errors.iter().cloned());
        run.redactions.extend(report.redactions.iter().cloned());

        run.summary = report.summary.clone();
        run.summary["resumed_from_checkpoint"] = serde_json::json!(checkpoint.next_file_index);
        run.summary["coverage_note"] = serde_json::json!(
            "summary breakdowns reflect the resumed pass only; run-wide totals are in counts and findings"
        );
        if run.operation == "search" {
            let total_matches = run
                .findings
                .iter()
                .filter(|finding| finding.kind == "search_match")
                .count();
            run.summary["matches"] = serde_json::json!(total_matches);
            run.summary["matches_this_pass"] = report.summary["matches"].clone();
        }

        let mut counts = report.counts.clone();
        counts.findings = run.findings.len();
        counts.relationships = run.relationships.len();
        counts.files_scanned = checkpoint.files_scanned + report.counts.files_scanned;
        counts.files_skipped = checkpoint.files_skipped + report.counts.files_skipped;
        counts.truncated = run.counts.truncated || report.counts.truncated;
        run.counts = counts;

        if let Some(bundle) = &sink_handle {
            bundle.drain_into(&mut run);
            run.checkpoint = bundle.last_checkpoint();
        }

        let (mut status, detail) = match &report.outcome {
            Outcome::Succeeded => (
                RunStatus::Succeeded,
                Some(format!(
                    "resumed from checkpoint at file {} after the earlier pass ended {}",
                    checkpoint.next_file_index,
                    previous_status.as_str()
                )),
            ),
            Outcome::Partial { reason } => {
                (RunStatus::Partial, Some(format!("resumed pass: {reason}")))
            }
            Outcome::Cancelled => (
                RunStatus::Cancelled,
                Some("cancelled during the resumed pass".to_string()),
            ),
        };
        if cancel.is_cancelled() && status == RunStatus::Succeeded {
            status = RunStatus::Cancelled;
        }
        run.mark_resumed(checkpoint.next_file_index, previous_status);
        run.finalize(status, detail);

        self.store
            .save(&run)
            .map_err(|err| err.into_vortex())
            .map_err(|err| {
                err.with_detail(format!(
                    "resume finished but the final record for run {} could not be saved",
                    run.run_id
                ))
            })?;

        let merged_report = ProviderReport {
            summary: run.summary.clone(),
            findings: run.findings.clone(),
            relationships: run.relationships.clone(),
            limitations: run.limitations.clone(),
            unknowns: run.unknowns.clone(),
            warnings: run.warnings.clone(),
            errors: run.errors.clone(),
            redactions: run.redactions.clone(),
            counts: run.counts.clone(),
            outcome: report.outcome.clone(),
        };
        Ok(OperationResult {
            run_id: Some(run.run_id.clone()),
            status: run.status,
            report: merged_report,
        })
    }

    /// Build the durable checkpoint sink for one pass of a run. The template
    /// carries everything from before this pass (identity, params, limits,
    /// and — for resumed passes — the earlier findings), so the closure only
    /// has to chain this pass's snapshot onto it.
    fn build_sink_bundle(
        &self,
        template: &EvidenceRun,
        hook: CheckpointHook,
        token: CancelToken,
    ) -> SinkHandle {
        SinkHandle::new(self.store.clone(), template.clone(), hook, token)
    }

    /// Run the diagnostics suite.
    pub fn doctor(&self) -> DoctorReport {
        crate::doctor::run_doctor(self)
    }
}

/// A live durable-checkpoint sink for one analysis pass.
///
/// The provider invokes the closure at safe boundaries; it writes the record
/// with everything produced so far (base content + this pass's snapshot) so
/// a crash at any point loses at most one checkpoint interval. It refuses to
/// write after cancellation was observed — the commit rule.
pub struct SinkHandle {
    closure: vortex_providers::provider::CheckpointSink,
    errors: Arc<Mutex<Vec<String>>>,
    last_checkpoint: Arc<Mutex<Option<RunCheckpoint>>>,
}

impl SinkHandle {
    fn new(
        store: Arc<FileSystemRunStore>,
        template: EvidenceRun,
        hook: CheckpointHook,
        token: CancelToken,
    ) -> Self {
        let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let last_checkpoint: Arc<Mutex<Option<RunCheckpoint>>> = Arc::new(Mutex::new(None));
        let closure = {
            let errors = Arc::clone(&errors);
            let last = Arc::clone(&last_checkpoint);
            Arc::new(
                move |checkpoint: &RunCheckpoint,
                      snapshot: &vortex_providers::provider::ProgressSnapshot| {
                    // Commit rule: never persist anything after cancellation.
                    if token.is_cancelled() {
                        return;
                    }
                    if let Some(hook) = &hook {
                        hook(checkpoint);
                    }
                    *last.lock().unwrap() = Some(checkpoint.clone());
                    // The template already carries everything from before
                    // this pass (for resumed runs that includes the earlier
                    // findings); chain this pass's snapshot onto it.
                    let mut durable = template.clone();
                    // A checkpoint record is always an in-flight `running`
                    // state, even when the pass being checkpointed is a resume.
                    durable.status = RunStatus::Running;
                    durable.completed_at = None;
                    durable.findings.extend(snapshot.findings.iter().cloned());
                    durable
                        .relationships
                        .extend(snapshot.relationships.iter().cloned());
                    merge_text_lists(&mut durable.limitations, &snapshot.limitations);
                    merge_text_lists(&mut durable.unknowns, &snapshot.unknowns);
                    merge_text_lists(&mut durable.warnings, &snapshot.warnings);
                    durable.errors.extend(snapshot.errors.iter().cloned());
                    durable
                        .redactions
                        .extend(snapshot.redactions.iter().cloned());
                    durable.checkpoint = Some(checkpoint.clone());
                    durable.counts.findings = durable.findings.len();
                    durable.counts.relationships = durable.relationships.len();
                    durable.counts.files_scanned = checkpoint.files_scanned;
                    durable.counts.files_skipped = checkpoint.files_skipped;
                    if let Err(err) = store.save(&durable) {
                        errors.lock().unwrap().push(format!(
                            "a durable checkpoint could not be saved (analysis continues; \
                             the last good checkpoint stands): {err}"
                        ));
                    }
                },
            )
        };
        Self {
            closure,
            errors,
            last_checkpoint,
        }
    }

    /// The sink to hand to the provider.
    fn closure(&self) -> vortex_providers::provider::CheckpointSink {
        self.closure.clone()
    }

    /// The latest checkpoint observed (None when none was emitted).
    fn last_checkpoint(&self) -> Option<RunCheckpoint> {
        self.last_checkpoint.lock().unwrap().clone()
    }

    /// Surface checkpoint-write failures as run warnings.
    fn drain_into(&self, run: &mut EvidenceRun) {
        let problems = std::mem::take(&mut *self.errors.lock().unwrap());
        merge_text_lists(&mut run.warnings, &problems);
    }
}

/// Progress-observer hook type for checkpoint events.
pub type CheckpointHook = Option<Arc<dyn Fn(&RunCheckpoint) + Send + Sync>>;

/// The one and only error for an unparseable evidence section name — shared
/// by the CLI and MCP so the surfaces cannot drift (the parity contract).
pub fn unknown_section_error(section: &str) -> VortexError {
    VortexError::validation(format!("unknown evidence section '{section}'")).with_hint(
        "valid sections: overview, summary, findings, relationships, limitations, \
         unknowns, warnings, errors",
    )
}

/// Caller parameters that can change findings, recorded on every new run.
fn operation_params_of(query_text: Option<&str>, options: &OperationOptions) -> OperationParams {
    OperationParams {
        query: query_text.map(str::to_string),
        case_sensitive: options.case_sensitive,
        max_entries: options.max_entries,
        max_matches: options.max_matches,
        timeout_secs: options.timeout_secs,
    }
}

/// Append `additions` to `dst` without creating duplicates.
fn merge_text_lists(dst: &mut Vec<String>, additions: &[String]) {
    for addition in additions {
        if !dst.contains(addition) {
            dst.push(addition.clone());
        }
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
    #[test]
    fn records_carry_owner_limits_and_params() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let app = fixture(dir.path());
        let result = service
            .inspect(&app, &OperationOptions::default(), &CancelToken::new())
            .unwrap();
        let stored = service.store().load(&result.run_id.unwrap()).unwrap();
        let owner = stored.owner.expect("owner recorded");
        assert_eq!(owner.0.pid, std::process::id());
        let limits = stored.limits.expect("limits recorded");
        assert_eq!(limits.max_files, ResourceLimits::default().max_files);
        let params = stored.params.expect("params recorded");
        assert_eq!(params.query, None);
        assert_eq!(params.timeout_secs, None);
        // Search runs record their query.
        let search = service
            .search(
                &app,
                "config",
                &OperationOptions::default(),
                &CancelToken::new(),
            )
            .unwrap();
        let stored_search = service.store().load(&search.run_id.unwrap()).unwrap();
        assert_eq!(
            stored_search.params.unwrap().query.as_deref(),
            Some("config")
        );
    }

    /// Sixty-file tree with a source-map reference in every file: inspect
    /// emits one `sourcemap_reference` finding per file under the run-wide
    /// max_entries cap (50), so a full run and an interrupted-then-resumed
    /// run must produce *identical* findings.
    fn checkpoint_tree(dir: &Path) -> PathBuf {
        let base = dir.join("tree");
        std::fs::create_dir_all(&base).unwrap();
        for i in 0..60u32 {
            std::fs::write(
                base.join(format!("f{i:02}.js")),
                format!("require('./x.js');\n//# sourceMappingURL=f{i:02}.map\n"),
            )
            .unwrap();
        }
        base
    }

    #[test]
    fn mid_run_cancel_keeps_checkpoint_and_resume_completes() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let app = checkpoint_tree(dir.path());

        // The progress hook cancels the token at the FIRST checkpoint: the
        // provider then stops at its next safe boundary — deterministically
        // right after 25 files.
        let cancel = CancelToken::new();
        let first_only = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_flag = first_only.clone();
        let hook_cancel = cancel.clone();
        let options = OperationOptions {
            on_checkpoint: Some(std::sync::Arc::new(move |_checkpoint| {
                if !hook_flag.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    hook_cancel.cancel();
                }
            })),
            ..OperationOptions::default()
        };
        let interrupted = service
            .inspect(&app, &options, &cancel)
            .expect("first pass");
        assert_eq!(
            interrupted.status,
            RunStatus::Cancelled,
            "cancelled mid-run"
        );

        let run_id = interrupted.run_id.clone().expect("persisted");
        let stored = service.store().load(&run_id).unwrap();
        let checkpoint = stored.checkpoint.clone().expect("checkpoint retained");
        assert_eq!(checkpoint.next_file_index, 25);
        assert_eq!(checkpoint.files_scanned, 25);
        assert!(stored.findings.len() >= 20, "partial findings retained");

        // The commit rule: a cancelled run never records 'succeeded'; its
        // partial findings stay.
        assert_eq!(stored.status, RunStatus::Cancelled);

        // A reference full run over the same tree, for equivalence checking.
        let full = service
            .inspect(&app, &OperationOptions::default(), &CancelToken::new())
            .unwrap();
        let full_run = service.store().load(&full.run_id.unwrap()).unwrap();

        // Resume completes the interrupted run.
        let resumed = service
            .resume_run(&run_id, &OperationOptions::default(), &CancelToken::new())
            .expect("resume completes");
        assert_eq!(resumed.status, RunStatus::Succeeded);
        assert_eq!(resumed.run_id.as_deref(), Some(run_id.as_str()));

        let final_record = service.store().load(&run_id).unwrap();
        assert_eq!(final_record.status, RunStatus::Succeeded);
        // Identity stability: same run id, same target digest, no new record.
        assert_eq!(final_record.target.sha256, full_run.target.sha256);
        assert_eq!(final_record.checkpoint, None, "succeeded clears checkpoint");
        let resumed_info = final_record.resumed.clone().expect("resumed bookkeeping");
        assert_eq!(resumed_info.attempts, 2);
        assert_eq!(resumed_info.from_checkpoint, 25);
        assert_eq!(resumed_info.previous_status, "cancelled");
        // Findings identical to an uninterrupted full run: same content,
        // same order, same ids (offsets continue the earlier pass).
        assert_eq!(final_record.findings, full_run.findings);
        assert_eq!(
            final_record.findings.len(),
            50,
            "run-wide cap of 50 entries"
        );
        assert_eq!(
            final_record.summary["file_count"],
            full_run.summary["file_count"]
        );
        // Every finding id is unique.
        let mut ids: Vec<&str> = final_record
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        ids.sort();
        let unique = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), unique, "finding ids must not collide");
        assert!(vortex_evidence::validate_run(&final_record).is_empty());
    }

    #[test]
    fn resume_refuses_when_artifact_changed() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let app = checkpoint_tree(dir.path());

        let cancel = CancelToken::new();
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_flag = flag.clone();
        let hook_cancel = cancel.clone();
        let options = OperationOptions {
            on_checkpoint: Some(std::sync::Arc::new(move |_checkpoint| {
                if !hook_flag.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    hook_cancel.cancel();
                }
            })),
            ..OperationOptions::default()
        };
        let interrupted = service
            .inspect(&app, &options, &cancel)
            .expect("first pass");
        assert_eq!(interrupted.status, RunStatus::Cancelled);
        let run_id = interrupted.run_id.unwrap();

        // Mutate the artifact, then try to resume.
        std::fs::write(app.join("f59.js"), b"changed\n").unwrap();
        let err = service
            .resume_run(&run_id, &OperationOptions::default(), &CancelToken::new())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Validation);
        assert!(err.message.contains("artifact changed"));
        let hint = err.hint.expect("hint");
        assert!(hint.contains("start a new run"));
    }

    #[test]
    fn resume_refuses_while_owner_may_be_alive() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let app = fixture(dir.path());

        // Hand-craft a 'running' record owned by this (living) process.
        let probe = service
            .inspect(&app, &OperationOptions::default(), &CancelToken::new())
            .unwrap();
        let run_id = probe.run_id.unwrap();
        let mut record = service.store().load(&run_id).unwrap();
        record.status = RunStatus::Running;
        record.completed_at = None;
        record.owner = Some(vortex_evidence::OwnerProcess(
            vortex_core::process::current(),
        ));
        use vortex_evidence::store::RunStore;
        service.store().save(&record).unwrap();

        let err = service
            .resume_run(&run_id, &OperationOptions::default(), &CancelToken::new())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Validation);
        assert!(err.message.contains("owner may still be working"));
    }

    #[test]
    fn resume_of_relationships_run_is_refused_honestly() {
        let dir = tempfile::tempdir().unwrap();
        let service = service_in(dir.path());
        let app = fixture(dir.path());
        let probe = service
            .relationships(&app, &OperationOptions::default(), &CancelToken::new())
            .unwrap();
        let run_id = probe.run_id.unwrap();
        // Give the record a checkpoint by hand so the guard that fires is the
        // operation guard, not the missing-checkpoint guard. The record must
        // be in an unfinished-looking final state for the checkpoint to be
        // valid, so mark it cancelled first.
        let mut record = service.store().load(&run_id).unwrap();
        record.status = RunStatus::Cancelled;
        record.checkpoint = Some(vortex_evidence::RunCheckpoint {
            phase: "per_file_analysis".to_string(),
            next_file_index: 2,
            files_scanned: 2,
            files_skipped: 0,
            saved_at: vortex_core::timeutil::now_rfc3339(),
            bytes_remaining: 1024,
            matches_remaining: None,
        });
        use vortex_evidence::store::RunStore;
        service.store().save(&record).unwrap();

        let err = service
            .resume_run(&run_id, &OperationOptions::default(), &CancelToken::new())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Validation);
        assert!(err.message.contains("not supported for 'relationships'"));
    }
}
