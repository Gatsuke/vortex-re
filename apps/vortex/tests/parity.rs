//! CLI/MCP error-parity tests: the same invalid input must produce the
//! identical structured error through both surfaces (the upstream #1364
//! lesson — the MCP path must not drop input refinements the CLI honors).
//!
//! Each case runs the real `vortex` binary with `--json` and calls the real
//! MCP tool over an in-memory transport, then asserts the entire error
//! object (code, message, detail, hint) is byte-identical.

use rmcp::model::CallToolRequestParams;
use rmcp::{ClientHandler, ServiceExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use vortex_app::mcp::VortexServer;
use vortex_core::config::VortexConfig;
use vortex_core::limits::ResourceLimits;
use vortex_service::service::VortexService;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_vortex")
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/javascript-demo")
        .canonicalize()
        .expect("fixture exists")
}

struct CliOutcome {
    output: Output,
    _home: Option<tempfile::TempDir>,
}

fn run_cli(args: &[&str], env: &[(&str, &str)]) -> CliOutcome {
    let home = tempfile::tempdir().expect("temp home");
    let output = Command::new(binary())
        .args(args)
        .env("VORTEX_HOME", home.path())
        .envs(env.iter().map(|(k, v)| (k.to_string(), v.to_string())))
        .output()
        .expect("run vortex");
    CliOutcome {
        output,
        _home: Some(home),
    }
}

fn cli_error_json(outcome: &CliOutcome) -> serde_json::Value {
    assert!(
        !outcome.output.status.success(),
        "the CLI must fail for an invalid input"
    );
    serde_json::from_slice(&outcome.output.stdout).expect("stdout is a JSON error object")
}

#[derive(Debug, Clone, Default)]
struct DummyClient;

impl ClientHandler for DummyClient {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        rmcp::model::ClientConfig::default()
    }
}

/// One parity case: CLI invocation vs MCP tool call.
struct Case {
    name: &'static str,
    cli_args: Vec<String>,
    cli_env: Vec<(String, String)>,
    mcp_tool: &'static str,
    mcp_args: serde_json::Value,
    mcp_allowed_roots: Option<Vec<PathBuf>>,
}

async fn mcp_error_json(case: &Case, shared_home: &std::path::Path) -> serde_json::Value {
    let config = VortexConfig {
        data_dir: shared_home.to_path_buf(),
        limits: ResourceLimits::default(),
        allowed_roots: case.mcp_allowed_roots.clone(),
        notes: Vec::new(),
        provider_overrides: Default::default(),
        stale_run_grace_secs: 3600,
        config_file: None,
    };
    let service = VortexService::new(config).expect("service");
    let service = std::sync::Arc::new(service);
    let server = VortexServer::new(service.clone());
    let (client_transport, server_transport) = tokio::io::duplex(4096);
    let server_handle = tokio::spawn(async move {
        let running = server.serve(server_transport).await.expect("server serve");
        running.waiting().await.expect("server waiting");
    });
    let client = DummyClient
        .serve(client_transport)
        .await
        .expect("client serve");
    let result = client
        .call_tool(
            CallToolRequestParams::new(case.mcp_tool.to_string())
                .with_arguments(case.mcp_args.as_object().cloned().unwrap_or_default()),
        )
        .await
        .expect("tool call completes");
    assert_eq!(
        result.is_error,
        Some(true),
        "the tool must fail for an invalid input"
    );
    let text = result
        .content
        .first()
        .unwrap()
        .as_text()
        .unwrap()
        .text
        .clone();
    client.cancel().await.expect("client cancel");
    server_handle.abort();
    serde_json::from_str(&text).expect("tool error body is JSON")
}

fn run_case(case: Case) {
    // One shared home for both surfaces: identical store paths in messages.
    let shared_home = tempfile::tempdir().expect("shared home");
    let mut cli_env = case.cli_env.clone();
    cli_env.push((
        "VORTEX_HOME".to_string(),
        shared_home.path().to_string_lossy().into_owned(),
    ));
    let cli_args: Vec<&str> = case.cli_args.iter().map(String::as_str).collect();
    let cli_env_refs: Vec<(&str, &str)> = cli_env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let cli = run_cli(&cli_args, &cli_env_refs);
    let cli_error = cli_error_json(&cli)["error"].clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mcp_error = runtime.block_on(mcp_error_json(&case, shared_home.path()));
    assert_eq!(
        cli_error, mcp_error,
        "case '{}': CLI and MCP must produce the identical structured error",
        case.name
    );
}

#[test]
fn parity_missing_path_is_not_found_everywhere() {
    run_case(Case {
        name: "missing path",
        cli_args: vec![
            "inspect".into(),
            "/definitely/not/here".into(),
            "--json".into(),
        ],
        cli_env: vec![],
        mcp_tool: "vortex_inspect_artifact",
        mcp_args: serde_json::json!({ "path": "/definitely/not/here" }),
        mcp_allowed_roots: None,
    });
}

#[test]
fn parity_empty_query_is_validation_everywhere() {
    run_case(Case {
        name: "empty search query",
        cli_args: vec![
            "search".into(),
            fixture().to_string_lossy().into_owned(),
            "".into(),
            "--json".into(),
        ],
        cli_env: vec![],
        mcp_tool: "vortex_search_artifact",
        mcp_args: serde_json::json!({ "path": fixture().to_string_lossy(), "query": "" }),
        mcp_allowed_roots: None,
    });
}

#[test]
fn parity_bad_section_is_validation_everywhere() {
    run_case(Case {
        name: "unknown evidence section",
        cli_args: vec![
            "evidence".into(),
            "show".into(),
            "run-does-not-matter".into(),
            "--section".into(),
            "bogus".into(),
            "--json".into(),
        ],
        cli_env: vec![],
        mcp_tool: "vortex_read_evidence",
        mcp_args: serde_json::json!({
            "run_id": "run-does-not-matter",
            "section": "bogus"
        }),
        mcp_allowed_roots: None,
    });
}

#[test]
fn parity_missing_run_is_storage_everywhere() {
    run_case(Case {
        name: "missing run id",
        cli_args: vec![
            "evidence".into(),
            "show".into(),
            "run-missing".into(),
            "--json".into(),
        ],
        cli_env: vec![],
        mcp_tool: "vortex_read_evidence",
        mcp_args: serde_json::json!({ "run_id": "run-missing", "section": "overview" }),
        mcp_allowed_roots: None,
    });
}

#[test]
fn parity_target_outside_roots_is_rejected_everywhere() {
    let allowed = tempfile::tempdir().expect("allowed root");
    std::fs::create_dir_all(allowed.path().join("inside")).unwrap();
    std::fs::write(allowed.path().join("inside/a.js"), b"module.exports = 1;\n").unwrap();
    let outside = tempfile::tempdir().expect("outside root");
    std::fs::create_dir_all(outside.path().join("app")).unwrap();
    std::fs::write(outside.path().join("app/b.js"), b"module.exports = 2;\n").unwrap();

    run_case(Case {
        name: "target outside allowed roots",
        cli_args: vec![
            "inspect".into(),
            outside.path().join("app").to_string_lossy().into_owned(),
            "--json".into(),
        ],
        cli_env: vec![(
            "VORTEX_ALLOWED_ROOTS".to_string(),
            allowed.path().to_string_lossy().into_owned(),
        )],
        mcp_tool: "vortex_inspect_artifact",
        mcp_args: serde_json::json!({
            "path": outside.path().join("app").to_string_lossy()
        }),
        mcp_allowed_roots: Some(vec![allowed.path().to_path_buf()]),
    });
}

/// The doctor additions: startup recovery and schema-version reporting,
/// including the malformed-input hardening (a record written by a newer
/// vortex is a FAIL with an upgrade hint, not an integrity accusation).
#[test]
fn doctor_reports_recovery_and_schema_versions() {
    let home = tempfile::tempdir().expect("temp home");
    let config = VortexConfig {
        data_dir: home.path().to_path_buf(),
        limits: ResourceLimits::default(),
        allowed_roots: None,
        notes: Vec::new(),
        provider_overrides: Default::default(),
        stale_run_grace_secs: 3600,
        config_file: None,
    };
    let service = VortexService::new(config).expect("service");

    // A v1-shaped record (older, loadable) and a v99 record (newer,
    // unreadable) written straight into the store directory.
    use vortex_evidence::store::RunStore;
    let location = service.store().location();
    let sample = serde_json::json!({
        "schema_version": 1,
        "run_id": "run-olderaaaaaaaaaaaaaaaaaaaa",
        "operation": "inspect",
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:00:01Z",
        "status": "succeeded",
        "target": {
            "input_path": "demo",
            "canonical_path": "/tmp/demo",
            "kind": "directory",
            "sha256": "a".repeat(64),
            "size_bytes": 10,
            "file_count": 1,
        },
        "provider": { "id": "builtin-static", "version": "0.1.0" },
        "tool": { "name": "vortex", "version": "0.1.0", "invocation": "test" },
        "summary": {},
        "findings": [],
        "relationships": [],
        "limitations": [],
        "unknowns": [],
        "warnings": [],
        "errors": [],
        "redactions": [],
        "counts": {
            "findings": 0,
            "relationships": 0,
            "files_scanned": 0,
            "files_skipped": 0,
            "truncated": false,
        },
    });
    let newer = {
        let mut value = sample.clone();
        value["schema_version"] = serde_json::json!(99);
        value["run_id"] = serde_json::json!("run-newerbbbbbbbbbbbbbbbbbbbb");
        value
    };
    std::fs::write(
        location.join("run-olderaaaaaaaaaaaaaaaaaaaa.json"),
        serde_json::to_vec_pretty(&sample).unwrap(),
    )
    .unwrap();
    std::fs::write(
        location.join("run-newerbbbbbbbbbbbbbbbbbbbb.json"),
        serde_json::to_vec_pretty(&newer).unwrap(),
    )
    .unwrap();

    let report = service.doctor();
    let schema_check = report
        .checks
        .iter()
        .find(|c| c.name == "schema_versions")
        .expect("schema check");
    assert_eq!(
        schema_check.status,
        vortex_service::doctor::CheckStatus::Fail
    );
    assert!(schema_check.detail.contains("1 older record"));
    assert!(schema_check
        .hint
        .as_deref()
        .unwrap()
        .contains("upgrade this binary"));

    // The startup_recovery check reports the fresh start cleanly.
    let recovery_check = report
        .checks
        .iter()
        .find(|c| c.name == "startup_recovery")
        .expect("recovery check");
    assert_eq!(
        recovery_check.status,
        vortex_service::doctor::CheckStatus::Ok
    );
    assert!(recovery_check.detail.contains("0 run(s) recovered"));

    // Truncated and garbage store entries stay honest (corrupt-file
    // behavior) instead of crashing the doctor.
    std::fs::write(location.join("run-truncated.json"), b"{\"schema_ver").unwrap();
    std::fs::write(location.join("run-garbage.json"), b"\x00\x01not json").unwrap();
    let report = service.doctor();
    let store_check = report
        .checks
        .iter()
        .find(|c| c.name == "evidence_store")
        .expect("store check");
    assert_eq!(
        store_check.status,
        vortex_service::doctor::CheckStatus::Warn
    );
    assert!(store_check.detail.contains("2 unreadable"));
    // The newer-vortex record keeps the overall report at FAIL.
    assert_eq!(report.overall(), vortex_service::doctor::CheckStatus::Fail);
}

/// Platform-filtered hints: recovery advice must never recommend an action
/// unsupported on the current platform (the #3944 lesson). The liveness
/// fallback documents itself instead.
#[test]
#[cfg(target_os = "linux")]
fn recovery_hints_stay_platform_honest() {
    // On Linux the owner-liveness path is available; a fresh run must NOT
    // be told to wait for an age threshold it does not need.
    let home = tempfile::tempdir().expect("temp home");
    let config = VortexConfig {
        data_dir: home.path().to_path_buf(),
        limits: ResourceLimits::default(),
        allowed_roots: None,
        notes: Vec::new(),
        provider_overrides: Default::default(),
        stale_run_grace_secs: 3600,
        config_file: None,
    };
    let service = VortexService::new(config).expect("service");
    let report = service.doctor();
    for check in &report.checks {
        if let Some(hint) = &check.hint {
            let unsupported = ["install rizin to fix recovery", "run on Linux for recovery"];
            for banned in unsupported {
                assert!(
                    !hint.contains(banned),
                    "hint for {} recommends an unsupported action: {hint}",
                    check.name
                );
            }
        }
    }
}
