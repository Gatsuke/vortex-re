//! The Vortex-RE MCP server (official `rmcp` SDK, stdio transport).
//!
//! Contract highlights:
//! * every tool calls the same [`VortexService`] as the CLI;
//! * results are bounded and paginated so agent context windows stay safe;
//! * domain failures (bad path, unsupported input) are returned as
//!   tool-level error results (`is_error: true`) that agents can read;
//! * logs go to stderr only — stdout carries protocol messages exclusively;
//! * inspected targets are never executed, and nothing leaves the machine.

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, ErrorData, Implementation, ServerCapabilities, ServerConfig,
};
use rmcp::schemars;
use rmcp::tool;
use rmcp::tool_handler;
use rmcp::tool_router;
use rmcp::ServerHandler;
use rmcp::ServiceExt;
use serde::Deserialize;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use vortex_core::error::VortexError;
use vortex_providers::provider::CancelToken;
use vortex_service::service::{EvidenceSection, OperationOptions, VortexService};

/// Bridge an MCP protocol cancellation token to a Vortex-RE cancel token.
///
/// rmcp cancels the request-scoped `CancellationToken` when the client sends
/// `notifications/cancelled` for that request (see the rmcp serve loop). The
/// bridge task forwards that to the cooperative analysis token so the run
/// stops at its next safe boundary; callers abort the bridge when the
/// service call returns.
fn bridge_cancellation(ct: &CancellationToken) -> (CancelToken, tokio::task::JoinHandle<()>) {
    let vortex_cancel = CancelToken::new();
    let watcher_cancel = vortex_cancel.clone();
    let watcher_ct = ct.clone();
    let watcher = tokio::spawn(async move {
        watcher_ct.cancelled().await;
        watcher_cancel.cancel();
    });
    (vortex_cancel, watcher)
}

/// Response bounding for agent context windows (audit R2,
/// docs/AUDIT_2026-10.md; upstream Lesson 2).
///
/// Item-count pagination alone cannot bound a response when a single item
/// can grow: a `pe_imports` finding carries DLL rows × function names, an
/// `archive_members` finding carries one row per member. These helpers
/// keep whole items until a byte budget is hit, then trim the page and say
/// so — `byte_capped` is never silent, and counts always tell the truth.
mod bounding {
    /// Byte budget for one tool response's item list. The budget test's
    /// 256 KiB ceiling leaves room for headers, pagination metadata, and
    /// the echoed limitation/unknown text lists.
    pub const ITEM_BUDGET_BYTES: usize = 128 * 1024;
    /// Byte budget for echoed limitation/unknown text lists. Full lists
    /// stay available through `vortex_read_evidence`, which paginates them.
    pub const TEXT_BUDGET_BYTES: usize = 16 * 1024;

    /// Keep whole serialized items until `budget` is exhausted. The first
    /// item is always kept (a non-empty page is never emptied by the
    /// budget; record-time caps keep single items far below the ceiling).
    /// Returns the kept items and whether any were dropped.
    pub fn fit_items(
        items: Vec<serde_json::Value>,
        budget: usize,
    ) -> (Vec<serde_json::Value>, bool) {
        let mut kept: Vec<serde_json::Value> = Vec::with_capacity(items.len());
        let mut used = 0usize;
        let mut capped = false;
        for (index, item) in items.into_iter().enumerate() {
            let size = serde_json::to_vec(&item).map_or(0, |v| v.len());
            if index == 0 || used + size <= budget {
                used += size;
                kept.push(item);
            } else {
                capped = true;
                break;
            }
        }
        (kept, capped)
    }

    /// The same fitting for text lists (limitations, unknowns).
    pub fn fit_texts(texts: &[String], budget: usize) -> (Vec<String>, bool) {
        let mut kept: Vec<String> = Vec::with_capacity(texts.len());
        let mut used = 0usize;
        let mut capped = false;
        for (index, text) in texts.iter().enumerate() {
            // The +2 covers the JSON quotes around the string.
            let size = text.len() + 2;
            if index == 0 || used + size <= budget {
                used += size;
                kept.push(text.clone());
            } else {
                capped = true;
                break;
            }
        }
        (kept, capped)
    }
}

#[cfg(test)]
mod bounding_tests {
    use super::bounding::*;

    /// A JSON object whose serialized size is a bit over `size_hint` bytes.
    fn item(size_hint: usize) -> serde_json::Value {
        serde_json::json!({ "pad": "x".repeat(size_hint) })
    }

    #[test]
    fn small_items_all_fit() {
        let items: Vec<_> = (0..10).map(|_| item(100)).collect();
        let (kept, capped) = fit_items(items, 8 * 1024);
        assert_eq!(kept.len(), 10);
        assert!(!capped);
    }

    #[test]
    fn oversized_pages_trim_whole_items_with_a_flag() {
        let items: Vec<_> = (0..50).map(|_| item(10_000)).collect();
        let (kept, capped) = fit_items(items, 32 * 1024);
        assert!(capped);
        assert!(!kept.is_empty() && kept.len() < 50);
        let used: usize = kept
            .iter()
            .map(|i| serde_json::to_vec(i).unwrap().len())
            .sum();
        assert!(used < 32 * 1024 + 10_200, "{used}");
    }

    #[test]
    fn the_first_item_is_never_dropped_by_the_budget() {
        let items = vec![item(64 * 1024), item(100)];
        let (kept, capped) = fit_items(items, 1024);
        assert_eq!(kept.len(), 1);
        assert!(capped);
    }

    #[test]
    fn empty_lists_stay_empty_and_uncapped() {
        let (kept, capped) = fit_items(Vec::new(), 1024);
        assert!(kept.is_empty());
        assert!(!capped);
        let (kept, capped) = fit_texts(&[], 1024);
        assert!(kept.is_empty());
        assert!(!capped);
    }

    #[test]
    fn text_lists_fit_by_bytes_with_a_flag() {
        let texts: Vec<String> = (0..100)
            .map(|i| format!("limitation {i}: {}", "y".repeat(200)))
            .collect();
        let (kept, capped) = fit_texts(&texts, 4 * 1024);
        assert!(capped);
        assert!(!kept.is_empty() && kept.len() < 100);
    }
}

/// The MCP server state.
#[derive(Clone)]
pub struct VortexServer {
    service: Arc<VortexService>,
    /// Router generated by `#[tool_router]`; read by the macro-generated
    /// `#[tool_handler]` dispatch (dead-code analysis cannot see that use).
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl VortexServer {
    /// Build a server around a shared service instance.
    pub fn new(service: Arc<VortexService>) -> Self {
        Self {
            service,
            tool_router: Self::tool_router(),
        }
    }
}

/// Convert a service-layer error into a tool-level error result so the
/// calling agent can read and react to it.
fn tool_error(error: &VortexError) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(error.to_json().to_string())])
}

/// Parameters for `vortex_capabilities`.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct CapabilitiesParams {}

/// Parameters for `vortex_inspect_artifact`.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct InspectParams {
    /// Path of the artifact to inspect (file or directory).
    pub path: String,
    /// Maximum entries in summaries (1..=500, default 50).
    pub max_entries: Option<usize>,
    /// Time budget in seconds (1..=600, default 30).
    pub timeout_secs: Option<u64>,
    /// 1-based page of findings to return.
    pub page: Option<usize>,
    /// Page size for the findings list (1..=100, default 20).
    pub page_size: Option<usize>,
}

/// Parameters for `vortex_search_artifact`.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct SearchParams {
    /// Path of the artifact to search (file or directory).
    pub path: String,
    /// Literal text to find (never a regex).
    pub query: String,
    /// Match case sensitively (default false).
    pub case_sensitive: Option<bool>,
    /// Maximum matches returned (1..=500, default 100).
    pub max_matches: Option<usize>,
    /// Time budget in seconds (1..=600, default 30).
    pub timeout_secs: Option<u64>,
}

/// Parameters for `vortex_trace_relationships`.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct TraceParams {
    /// Path of the artifact to analyze (file or directory).
    pub path: String,
    /// Time budget in seconds (1..=600, default 30).
    pub timeout_secs: Option<u64>,
    /// 1-based page of relationships to return.
    pub page: Option<usize>,
    /// Page size for the relationships list (1..=100, default 20).
    pub page_size: Option<usize>,
}

/// Parameters for `vortex_list_runs`.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct ListRunsParams {
    /// Maximum runs to return (1..=100, default 20).
    pub limit: Option<usize>,
}

/// Parameters for `vortex_read_evidence`.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct ReadEvidenceParams {
    /// Run id from `vortex_list_runs` or an analysis tool result.
    pub run_id: String,
    /// Section to read: overview (default), summary, findings, relationships,
    /// limitations, unknowns, warnings, or errors.
    pub section: Option<String>,
    /// 1-based page number.
    pub page: Option<usize>,
    /// Page size (1..=100, default 20).
    pub page_size: Option<usize>,
}

/// Parameters for `vortex_compare_runs`.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct CompareRunsParams {
    /// First run id.
    pub run_id_a: String,
    /// Second run id.
    pub run_id_b: String,
}

/// Parameters for `vortex_resume_run`.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct ResumeRunParams {
    /// Run id of an interrupted run with a checkpoint (see `vortex_list_runs`).
    pub run_id: String,
    /// Optional higher time budget for this pass, in seconds (1..=3600).
    pub timeout_secs: Option<u64>,
}

/// Run a blocking service call inside the async tool handler.
///
/// The outer `Result` covers protocol/infrastructure failures; the inner
/// `Result` carries domain errors that are converted into tool-level error
/// results so agents can read them.
async fn run_service<T, F>(
    service: Arc<VortexService>,
    f: F,
) -> Result<Result<T, VortexError>, ErrorData>
where
    T: Send + 'static,
    F: FnOnce(&VortexService) -> Result<T, VortexError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || f(&service))
        .await
        .map_err(|err| ErrorData::internal_error(format!("service task failed: {err}"), None))
}

#[tool_router]
impl VortexServer {
    /// Report Vortex-RE capabilities, supported operations, and limitations.
    #[tool(
        description = "List Vortex-RE providers, capabilities, operations that work now, and operations that are not supported with reasons."
    )]
    pub async fn vortex_capabilities(
        &self,
        _params: Parameters<CapabilitiesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let capabilities = self.service.capabilities();
        let doctor = self.service.doctor();
        let payload = serde_json::json!({
            "capabilities": capabilities,
            "supported_now": doctor.supported_now,
            "not_supported": doctor.not_supported,
            "notes": [
                "Static analysis only: inspected targets are never executed.",
                "All results are bounded; use pagination on large analyses.",
            ],
        });
        Ok(CallToolResult::structured(payload))
    }

    /// Inspect an artifact with bounded static analysis.
    #[tool(
        description = "Inspect a file or directory artifact: identity, SHA-256 digest, format identification, bounded content findings. Returns a summary plus the first page of findings; paginate with page/page_size, or read stored evidence with vortex_read_evidence using the returned run_id."
    )]
    pub async fn vortex_inspect_artifact(
        &self,
        Parameters(params): Parameters<InspectParams>,
        ct: CancellationToken,
    ) -> Result<CallToolResult, ErrorData> {
        let service = self.service.clone();
        let path = params.path.clone();
        let options = OperationOptions {
            invocation: "mcp:vortex_inspect_artifact".to_string(),
            max_entries: Some(params.max_entries.unwrap_or(50).clamp(1, 500)),
            timeout_secs: params.timeout_secs.map(|s| s.clamp(1, 600)),
            ..OperationOptions::default()
        };
        let (cancel, bridge) = bridge_cancellation(&ct);
        let result = run_service(service.clone(), move |service| {
            service.inspect(std::path::Path::new(&path), &options, &cancel)
        })
        .await?;
        bridge.abort();

        match result {
            Ok(operation) => {
                let page_size = operation
                    .report
                    .findings
                    .len()
                    .clamp(1, service.config().limits.clamp_page_size(params.page_size));
                let page = params.page.unwrap_or(1).max(1);
                let start = (page - 1) * page_size;
                let total_findings = operation.report.findings.len();
                let findings_page: Vec<serde_json::Value> = operation
                    .report
                    .findings
                    .iter()
                    .skip(start)
                    .take(page_size)
                    .map(|f| serde_json::to_value(f).unwrap_or_default())
                    .collect();
                let (findings_page, byte_capped) =
                    bounding::fit_items(findings_page, bounding::ITEM_BUDGET_BYTES);
                let items_returned = findings_page.len();
                let (limitations, limitations_truncated) =
                    bounding::fit_texts(&operation.report.limitations, bounding::TEXT_BUDGET_BYTES);
                let (unknowns, unknowns_truncated) =
                    bounding::fit_texts(&operation.report.unknowns, bounding::TEXT_BUDGET_BYTES);
                let payload = serde_json::json!({
                    "run_id": operation.run_id,
                    "status": operation.status.as_str(),
                    "summary": operation.report.summary,
                    "counts": {
                        "findings": total_findings,
                        "relationships": operation.report.relationships.len(),
                        "limitations": operation.report.limitations.len(),
                        "unknowns": operation.report.unknowns.len(),
                        "warnings": operation.report.warnings.len(),
                        "errors": operation.report.errors.len(),
                        "redactions": operation.report.redactions.len(),
                        "truncated": operation.report.counts.truncated,
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total_items": total_findings,
                        "items_returned": items_returned,
                        "has_next": start + items_returned < total_findings,
                        "byte_capped": byte_capped,
                        "hint": "read more pages with page/page_size, or all sections with vortex_read_evidence",
                    },
                    "findings": findings_page,
                    "limitations": limitations,
                    "limitations_total": operation.report.limitations.len(),
                    "limitations_truncated": limitations_truncated,
                    "unknowns": unknowns,
                    "unknowns_total": operation.report.unknowns.len(),
                    "unknowns_truncated": unknowns_truncated,
                });
                Ok(CallToolResult::structured(payload))
            }
            Err(error) => Ok(tool_error(&error)),
        }
    }

    /// Search an artifact for literal text.
    #[tool(
        description = "Search a file or directory artifact for literal text (never a regex). Returns matches with file:line:column locations and redacted context lines. Binary files are skipped and reported."
    )]
    pub async fn vortex_search_artifact(
        &self,
        Parameters(params): Parameters<SearchParams>,
        ct: CancellationToken,
    ) -> Result<CallToolResult, ErrorData> {
        let service = self.service.clone();
        let path = params.path.clone();
        let options = OperationOptions {
            invocation: "mcp:vortex_search_artifact".to_string(),
            max_matches: Some(params.max_matches.unwrap_or(100).clamp(1, 500)),
            case_sensitive: params.case_sensitive.unwrap_or(false),
            timeout_secs: params.timeout_secs.map(|s| s.clamp(1, 600)),
            ..OperationOptions::default()
        };
        let query = params.query.clone();
        let (cancel, bridge) = bridge_cancellation(&ct);
        let result = run_service(service, move |service| {
            service.search(std::path::Path::new(&path), &query, &options, &cancel)
        })
        .await?;
        bridge.abort();

        match result {
            Ok(operation) => {
                let matches: Vec<serde_json::Value> = operation
                    .report
                    .findings
                    .iter()
                    .filter(|finding| finding.kind == "search_match")
                    .map(|f| serde_json::to_value(f).unwrap_or_default())
                    .collect();
                let matches_total = matches.len();
                let (matches, byte_capped) =
                    bounding::fit_items(matches, bounding::ITEM_BUDGET_BYTES);
                let (limitations, limitations_truncated) =
                    bounding::fit_texts(&operation.report.limitations, bounding::TEXT_BUDGET_BYTES);
                let payload = serde_json::json!({
                    "run_id": operation.run_id,
                    "status": operation.status.as_str(),
                    "summary": operation.report.summary,
                    "matches": matches,
                    "matches_returned": matches.len(),
                    "matches_total": matches_total,
                    "byte_capped": byte_capped,
                    "limitations": limitations,
                    "limitations_total": operation.report.limitations.len(),
                    "limitations_truncated": limitations_truncated,
                });
                Ok(CallToolResult::structured(payload))
            }
            Err(error) => Ok(tool_error(&error)),
        }
    }

    /// Trace relationships inside an artifact.
    #[tool(
        description = "Trace relationships in a JavaScript/Electron artifact: imports, requires, declared dependencies, source map references, and script references. Each edge reports scope, resolution status, and the reason when unresolved. Statements are observed evidence, not proof of runtime behavior."
    )]
    pub async fn vortex_trace_relationships(
        &self,
        Parameters(params): Parameters<TraceParams>,
        ct: CancellationToken,
    ) -> Result<CallToolResult, ErrorData> {
        let service = self.service.clone();
        let path = params.path.clone();
        let options = OperationOptions {
            invocation: "mcp:vortex_trace_relationships".to_string(),
            timeout_secs: params.timeout_secs.map(|s| s.clamp(1, 600)),
            ..OperationOptions::default()
        };
        let (cancel, bridge) = bridge_cancellation(&ct);
        let result = run_service(service.clone(), move |service| {
            service.relationships(std::path::Path::new(&path), &options, &cancel)
        })
        .await?;
        bridge.abort();

        match result {
            Ok(operation) => {
                let page_size = service.config().limits.clamp_page_size(params.page_size);
                let page = params.page.unwrap_or(1).max(1);
                let start = (page - 1) * page_size;
                let total = operation.report.relationships.len();
                let relationships_page: Vec<serde_json::Value> = operation
                    .report
                    .relationships
                    .iter()
                    .skip(start)
                    .take(page_size)
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .collect();
                let (relationships_page, byte_capped) =
                    bounding::fit_items(relationships_page, bounding::ITEM_BUDGET_BYTES);
                let items_returned = relationships_page.len();
                let (limitations, limitations_truncated) =
                    bounding::fit_texts(&operation.report.limitations, bounding::TEXT_BUDGET_BYTES);
                let payload = serde_json::json!({
                    "run_id": operation.run_id,
                    "status": operation.status.as_str(),
                    "summary": operation.report.summary,
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total_items": total,
                        "items_returned": items_returned,
                        "has_next": start + items_returned < total,
                        "byte_capped": byte_capped,
                    },
                    "relationships": relationships_page,
                    "limitations": limitations,
                    "limitations_total": operation.report.limitations.len(),
                    "limitations_truncated": limitations_truncated,
                });
                Ok(CallToolResult::structured(payload))
            }
            Err(error) => Ok(tool_error(&error)),
        }
    }

    /// List stored evidence runs.
    #[tool(
        description = "List stored Vortex-RE runs, newest first, with run id, operation, status, and finding counts."
    )]
    pub async fn vortex_list_runs(
        &self,
        Parameters(params): Parameters<ListRunsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let service = self.service.clone();
        let limit = params.limit.unwrap_or(20).clamp(1, 100);
        let result = run_service(service, move |service| service.list_runs(limit)).await?;
        match result {
            Ok(runs) => {
                let payload = serde_json::json!({
                    "runs": runs,
                    "count": runs.len(),
                });
                Ok(CallToolResult::structured(payload))
            }
            Err(error) => Ok(tool_error(&error)),
        }
    }

    /// Read stored evidence (paginated).
    #[tool(
        description = "Read a stored evidence run by id. Sections: overview, summary, findings, relationships, limitations, unknowns, warnings, errors. Findings and relationships are paginated with page/page_size (max 100 per page)."
    )]
    pub async fn vortex_read_evidence(
        &self,
        Parameters(params): Parameters<ReadEvidenceParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let service = self.service.clone();
        let section_name = params
            .section
            .clone()
            .unwrap_or_else(|| "overview".to_string());
        let Some(section) = EvidenceSection::parse(&section_name) else {
            return Ok(tool_error(&vortex_service::service::unknown_section_error(
                &section_name,
            )));
        };
        let run_id = params.run_id.clone();
        let page = params.page.unwrap_or(1).max(1);
        let page_size = params.page_size;
        let result = run_service(service, move |service| {
            service.read_evidence(&run_id, section, page, page_size)
        })
        .await?;
        match result {
            Ok(view) => {
                let total_items = view.page.total_items;
                let (items, byte_capped) =
                    bounding::fit_items(view.page.items, bounding::ITEM_BUDGET_BYTES);
                let items_returned = items.len();
                let payload = serde_json::json!({
                    "run": {
                        "run_id": view.run.run_id,
                        "operation": view.run.operation,
                        "status": view.run.status.as_str(),
                        "started_at": view.run.started_at,
                        "completed_at": view.run.completed_at,
                        "target": view.run.target_input_path,
                        "target_sha256": view.run.target_sha256,
                    },
                    "section": view.section,
                    "page": {
                        "page": view.page.page,
                        "page_size": view.page.page_size,
                        "total_items": total_items,
                        "total_pages": view.page.total_pages,
                        "items_returned": items_returned,
                        "has_next": view.page.has_next || byte_capped,
                        "byte_capped": byte_capped,
                    },
                    "items": items,
                });
                Ok(CallToolResult::structured(payload))
            }
            Err(error) => Ok(tool_error(&error)),
        }
    }

    /// Compare two stored runs.
    #[tool(
        description = "Compare two stored runs and report structural differences (findings and relationships present in one but not the other). Structural differences never imply behavioral differences."
    )]
    pub async fn vortex_compare_runs(
        &self,
        Parameters(params): Parameters<CompareRunsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let service = self.service.clone();
        let run_a = params.run_id_a.clone();
        let run_b = params.run_id_b.clone();
        let result = run_service(service, move |service| service.compare(&run_a, &run_b)).await?;
        match result {
            Ok(comparison) => Ok(CallToolResult::structured(
                serde_json::to_value(comparison).unwrap_or_default(),
            )),
            Err(error) => Ok(tool_error(&error)),
        }
    }

    /// Continue an interrupted run from its checkpoint.
    #[tool(
        description = "Continue an interrupted inspect or search run from its last durable checkpoint. Refuses when the artifact changed since the run was recorded, when no checkpoint exists, or while the original process may still be working. Reuses the recorded limits; only the time budget may be raised."
    )]
    pub async fn vortex_resume_run(
        &self,
        Parameters(params): Parameters<ResumeRunParams>,
        ct: CancellationToken,
    ) -> Result<CallToolResult, ErrorData> {
        let service = self.service.clone();
        let run_id = params.run_id.clone();
        let options = OperationOptions {
            invocation: "mcp:vortex_resume_run".to_string(),
            timeout_secs: params.timeout_secs.map(|s| s.clamp(1, 3600)),
            ..OperationOptions::default()
        };
        let (cancel, bridge) = bridge_cancellation(&ct);
        let result = run_service(service, move |service| {
            service.resume_run(&run_id, &options, &cancel)
        })
        .await?;
        bridge.abort();
        match result {
            Ok(operation) => {
                let (limitations, limitations_truncated) =
                    bounding::fit_texts(&operation.report.limitations, bounding::TEXT_BUDGET_BYTES);
                let (unknowns, unknowns_truncated) =
                    bounding::fit_texts(&operation.report.unknowns, bounding::TEXT_BUDGET_BYTES);
                let payload = serde_json::json!({
                    "run_id": operation.run_id,
                    "status": operation.status.as_str(),
                    "summary": operation.report.summary,
                    "counts": {
                        "findings": operation.report.findings.len(),
                        "relationships": operation.report.relationships.len(),
                        "files_scanned": operation.report.counts.files_scanned,
                        "files_skipped": operation.report.counts.files_skipped,
                        "truncated": operation.report.counts.truncated,
                    },
                    "limitations": limitations,
                    "limitations_total": operation.report.limitations.len(),
                    "limitations_truncated": limitations_truncated,
                    "unknowns": unknowns,
                    "unknowns_total": operation.report.unknowns.len(),
                    "unknowns_truncated": unknowns_truncated,
                });
                Ok(CallToolResult::structured(payload))
            }
            Err(error) => Ok(tool_error(&error)),
        }
    }
}

#[tool_handler]
impl ServerHandler for VortexServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("vortex-re", vortex_core::APP_VERSION))
            .with_instructions(
                "Vortex-RE performs local, static analysis of authorized software artifacts. \
             Start with vortex_capabilities, then vortex_inspect_artifact on your target. \
             Results are bounded; large analyses are paginated \u{2014} read remaining pages \
             with vortex_read_evidence instead of re-running analysis. All conclusions are \
             evidence-backed with origin (observed/derived/inferred) and recorded limitations. \
             Inspected targets are never executed.",
            )
    }
}

/// Serve the MCP server over stdio until the client disconnects.
pub async fn serve_stdio(
    service: Arc<VortexService>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "[vortex] mcp server starting on stdio (vortex-re {})",
        vortex_core::APP_VERSION
    );
    let server = VortexServer::new(service);
    let transport = rmcp::transport::io::stdio();
    let running = server.serve(transport).await?;
    running.waiting().await?;
    eprintln!("[vortex] mcp server stopped");
    Ok(())
}
