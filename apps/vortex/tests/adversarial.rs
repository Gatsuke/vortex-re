//! Adversarial artifact corpus: pathological inputs must degrade to honest
//! `partial`/truncated results — never a crash, never a hang (ROADMAP Phase
//! Two; upstream Lesson 1: REA #1563/#1380/#1847/#1911/#1801).
//!
//! Every case here mirrors a real-world artifact class that killed other
//! tools: a giant single line, an oversized single line, a tree deeper than
//! the walk cap, a pathological package graph, symlink loops, unreadable
//! files, and more files than the walk limit.

use rmcp::ClientHandler;
use std::path::Path;
use std::sync::Arc;
use vortex_core::config::VortexConfig;
use vortex_core::limits::ResourceLimits;
use vortex_evidence::RunStatus;
use vortex_providers::provider::CancelToken;
use vortex_service::service::{OperationOptions, VortexService};

fn service_in(dir: &Path) -> VortexService {
    let config = VortexConfig {
        data_dir: dir.to_path_buf(),
        limits: ResourceLimits::default(),
        allowed_roots: None,
        notes: Vec::new(),
        provider_overrides: Default::default(),
        stale_run_grace_secs: 3600,
        config_file: None,
    };
    VortexService::new(config).expect("service")
}

fn assert_honest_terminal_state(result: &vortex_service::service::OperationResult) {
    assert_ne!(
        result.status,
        RunStatus::Running,
        "the run must reach a terminal state"
    );
    assert!(
        matches!(result.status, RunStatus::Succeeded | RunStatus::Partial),
        "adversarial inputs degrade to succeeded-with-truncation or partial, got {:?} ({:?})",
        result.status,
        result.report.errors
    );
}

/// A ~1 MiB single-line "minified bundle": thousands of require statements
/// and source-map reference, all on one physical line.
fn giant_single_line(target: &Path) {
    let mut line = String::with_capacity(1_100_000);
    while line.len() < 1_000_000 {
        line.push_str("require('./a.js');require('@scope/pkg');var x=1;/*noise*/");
    }
    line.push_str("//# sourceMappingURL=bundle.js.map");
    line.push('\n');
    std::fs::write(target, line.as_bytes()).expect("write giant line");
}

#[test]
fn giant_single_line_degrades_instead_of_dying() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = service_in(dir.path());
    let target = dir.path().join("bundle.js");
    giant_single_line(&target);

    let inspected = service
        .inspect(&target, &OperationOptions::default(), &CancelToken::new())
        .expect("inspect must not panic");
    assert_honest_terminal_state(&inspected);
    assert!(
        inspected
            .report
            .limitations
            .iter()
            .any(|l| l.contains("import scan")),
        "the per-file import cap must be visible: {:?}",
        inspected.report.limitations
    );

    // Literal search across the same giant line. Grep semantics: one match
    // reported per line, so a single-line file yields one match and no
    // hidden truncation — that is the documented honest behavior.
    let searched = service
        .search(
            &target,
            "require",
            &OperationOptions::default(),
            &CancelToken::new(),
        )
        .expect("search must not panic");
    assert_honest_terminal_state(&searched);
    let summary = &searched.report.summary;
    assert_eq!(summary["matches"], serde_json::json!(1));
    assert!(!searched.report.counts.truncated);

    // The line-context echo is capped even though the physical line is huge.
    let context = &searched.report.findings[0].details["line_text"];
    let context_len = context.as_str().map(str::len).unwrap_or_default();
    assert!(
        context_len <= ResourceLimits::default().max_line_context_bytes + 16,
        "context line capped to {}, got {context_len}",
        ResourceLimits::default().max_line_context_bytes
    );

    // Multi-line search hitting the global match cap degrades to partial
    // with a visible truncation flag (the real REA #1850 shape).
    let base = dir.path().join("many");
    std::fs::create_dir_all(&base).unwrap();
    for i in 0..300u32 {
        std::fs::write(
            base.join(format!("m{i:03}.js")),
            format!("require('./x.js'); // VORTEX_DEMO_MARKER_{i}\n"),
        )
        .unwrap();
    }
    let capped = service
        .search(
            &base,
            "require",
            &OperationOptions::default(),
            &CancelToken::new(),
        )
        .expect("search must not panic");
    assert_eq!(capped.status, RunStatus::Partial);
    assert!(
        capped.report.counts.truncated,
        "match-cap truncation must be visible in the report"
    );
    assert!(
        capped
            .report
            .limitations
            .iter()
            .any(|l| l.contains("additional matches may exist")),
        "truncation stated: {:?}",
        capped.report.limitations
    );

    // Relationships over the same giant file.
    let traced = service
        .relationships(&target, &OperationOptions::default(), &CancelToken::new())
        .expect("relationships must not panic");
    assert_honest_terminal_state(&traced);
}

#[test]
fn oversized_single_line_is_truncated_with_a_visible_note() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = service_in(dir.path());
    let target = dir.path().join("huge.js");
    // Default max_file_bytes is 8 MiB; write ~9 MiB so the read is truncated.
    let line = "require('./a.js');".repeat(9 * 1024 * 1024 / 19);
    std::fs::write(
        &target,
        format!("{line}\n//# sourceMappingURL=huge.js.map\n"),
    )
    .unwrap();

    let inspected = service
        .inspect(&target, &OperationOptions::default(), &CancelToken::new())
        .expect("inspect must not panic");
    assert_honest_terminal_state(&inspected);
    assert!(
        inspected
            .report
            .limitations
            .iter()
            .any(|l| l.contains("used only the first")),
        "the read truncation must be stated: {:?}",
        inspected.report.limitations
    );
    assert!(inspected
        .report
        .findings
        .iter()
        .any(|f| f.details["read_truncated"] == serde_json::json!(true)));
}

#[test]
fn deep_tree_is_bounded_not_crashed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = service_in(dir.path());
    let base = dir.path().join("deep");
    // tree::MAX_DEPTH is 64; build 70 levels with files at the bottom.
    let mut current = base.clone();
    std::fs::create_dir_all(&current).unwrap();
    for _ in 0..70 {
        current = current.join("level");
        std::fs::create_dir_all(&current).unwrap();
    }
    std::fs::write(current.join("bottom.js"), b"require('./x.js');\n").unwrap();
    std::fs::write(base.join("top.js"), b"require('./y.js');\n").unwrap();

    let inspected = service
        .inspect(&base, &OperationOptions::default(), &CancelToken::new())
        .expect("inspect must not panic");
    assert_honest_terminal_state(&inspected);
    assert!(
        inspected
            .report
            .warnings
            .iter()
            .any(|w| w.contains("nesting exceeds")),
        "the depth cap must be recorded as a skip: {:?}",
        inspected.report.warnings
    );
    // And the walk never descended past the cap.
    assert!(inspected.report.summary["file_count"].as_u64().unwrap() <= 2);
}

#[test]
fn pathological_package_graph_is_bounded() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = service_in(dir.path());
    let base = dir.path().join("graph");
    std::fs::create_dir_all(&base).unwrap();

    // More manifests than MAX_MANIFESTS (20): one per directory.
    for i in 0..30u32 {
        let package_dir = base.join(format!("pkg{i:02}"));
        std::fs::create_dir_all(package_dir.join("node_modules/leftpad")).unwrap();
        std::fs::write(
            package_dir.join("package.json"),
            format!(r#"{{"name":"pkg{i:02}","main":"main.js","dependencies":{{"leftpad":"^1.0.0","minimist":"^1.2.8"}}}}"#),
        )
        .unwrap();
        // Hundreds of requires, one per line, so the per-file import cap
        // fires deterministically (the line-oriented scanner sees one
        // statement cluster per line).
        let mut body = String::new();
        for j in 0..500 {
            body.push_str(&format!("require('./dep{j:03}.js');\n"));
        }
        body.push_str("require('leftpad');\n");
        std::fs::write(package_dir.join("main.js"), body).unwrap();
        std::fs::write(
            package_dir.join("node_modules/leftpad/package.json"),
            r#"{"main":"index.js"}"#,
        )
        .unwrap();
        std::fs::write(
            package_dir.join("node_modules/leftpad/index.js"),
            b"module.exports = 1;\n",
        )
        .unwrap();
    }

    let traced = service
        .relationships(&base, &OperationOptions::default(), &CancelToken::new())
        .expect("relationships must not panic");
    assert_honest_terminal_state(&traced);
    assert!(
        traced
            .report
            .limitations
            .iter()
            .any(|l| l.contains("manifest parsing stopped")),
        "the manifest cap must be visible: {:?}",
        traced.report.limitations
    );
    assert!(
        traced
            .report
            .limitations
            .iter()
            .any(|l| l.contains("per-file limit")),
        "the per-file import cap must be visible: {:?}",
        traced.report.limitations
    );
    // Bounded output despite 30 x 500 declared edges.
    assert!(
        traced.report.relationships.len() <= ResourceLimits::default().max_relationships,
        "relationships bounded: {}",
        traced.report.relationships.len()
    );

    let inspected = service
        .inspect(&base, &OperationOptions::default(), &CancelToken::new())
        .expect("inspect must not panic");
    assert_honest_terminal_state(&inspected);
}

#[cfg(unix)]
#[test]
fn symlink_loops_are_recorded_not_followed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = service_in(dir.path());
    let base = dir.path().join("loops");
    std::fs::create_dir_all(base.join("real")).unwrap();
    std::fs::write(base.join("real/a.js"), b"require('./b.js');\n").unwrap();
    std::os::unix::fs::symlink("loop_b", base.join("loop_a")).unwrap();
    std::os::unix::fs::symlink("loop_a", base.join("loop_b")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", base.join("outside")).unwrap();

    let inspected = service
        .inspect(&base, &OperationOptions::default(), &CancelToken::new())
        .expect("inspect must not panic (and must not hang)");
    assert_honest_terminal_state(&inspected);
    assert!(
        inspected
            .report
            .warnings
            .iter()
            .any(|w| w.contains("skipped by policy")),
        "symlinks must be recorded as skips: {:?}",
        inspected.report.warnings
    );
    assert_eq!(inspected.report.summary["file_count"], serde_json::json!(1));
}

#[cfg(unix)]
#[test]
fn unreadable_files_are_recorded_not_fatal() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = service_in(dir.path());
    let base = dir.path().join("perm");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("readable.js"), b"require('./x.js');\n").unwrap();
    let locked = base.join("locked.js");
    std::fs::write(&locked, b"require('./y.js');\n").unwrap();
    let mut perms = std::fs::metadata(&locked).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o000);
    std::fs::set_permissions(&locked, perms).unwrap();

    let result = service
        .inspect(&base, &OperationOptions::default(), &CancelToken::new())
        .expect("inspect must not panic");
    assert_honest_terminal_state(&result);
    // Running as root would still read the file; either way no crash and an
    // honest record. Restore permissions for tempdir cleanup.
    let mut perms = std::fs::metadata(&locked).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&locked, perms).unwrap();
}

#[test]
fn more_files_than_the_walk_limit_is_partial() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = service_in(dir.path());
    let base = dir.path().join("many");
    std::fs::create_dir_all(&base).unwrap();
    // Default max_files is 2000; write more.
    for i in 0..2500u32 {
        std::fs::write(base.join(format!("f{i:04}.js")), b"require('./x.js');\n").unwrap();
    }
    let result = service
        .inspect(&base, &OperationOptions::default(), &CancelToken::new())
        .expect("inspect must not panic");
    assert_eq!(result.status, RunStatus::Partial);
    assert!(
        result
            .report
            .limitations
            .iter()
            .any(|l| l.contains("walk was truncated by limits")),
        "walk truncation stated: {:?}",
        result.report.limitations
    );
    assert!(result.report.summary["file_count"].as_u64().unwrap() <= 2000);
    assert!(result.report.summary["walk_truncated"] == serde_json::json!(true));
}

/// The bounded-output regression guard: MCP tool responses over a
/// pathological fixture stay under a fixed byte ceiling (ROADMAP Phase Two;
/// upstream Lesson 2: REA #1850's 382 KB class search).
///
/// Ceiling derivation: the largest single response is a read_evidence page
/// with the maximum page size (100) of worst-case findings (~1 KiB each,
/// including locations, artifacts, and details payloads) plus the run
/// header and pagination envelope — comfortably under 256 KiB; anything
/// beyond that means a bounding regression.
const MCP_RESPONSE_BUDGET_BYTES: usize = 256 * 1024;

#[test]
fn mcp_responses_stay_under_the_size_budget() {
    use rmcp::model::CallToolRequestParams;
    use rmcp::ServiceExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let service = service_in(dir.path());
    let base = dir.path().join("tree");
    std::fs::create_dir_all(&base).unwrap();
    // A fixture whose findings push every list to its cap: 400 JS files with
    // source-map references (the run-wide max_entries cap is 50 findings of
    // that kind) plus binary artifacts with printable strings.
    for i in 0..400u32 {
        std::fs::write(
            base.join(format!("f{i:03}.js")),
            format!("require('./x.js');\n//# sourceMappingURL=f{i:03}.map\n"),
        )
        .unwrap();
    }
    let mut binary = Vec::new();
    for i in 0..1000u32 {
        binary.extend_from_slice(
            format!("VORTEX_STRING_{i:04} padding padding padding\n").as_bytes(),
        );
    }
    std::fs::write(base.join("blob.bin"), &binary).unwrap();

    let service = Arc::new(service);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let server = vortex_app::mcp::VortexServer::new(service.clone());
        let (client_transport, server_transport) = tokio::io::duplex(8192);
        let server_handle = tokio::spawn(async move {
            let running = server.serve(server_transport).await.expect("serve");
            running.waiting().await.expect("waiting");
        });
        let client = DummyClient
            .serve(client_transport)
            .await
            .expect("client serve");

        let fixture = base.clone();
        let inspect = client
            .call_tool(
                CallToolRequestParams::new("vortex_inspect_artifact".to_string()).with_arguments(
                    serde_json::json!({ "path": fixture, "page_size": 100 })
                        .as_object()
                        .cloned()
                        .unwrap(),
                ),
            )
            .await
            .expect("inspect tool");
        let inspect_payload: serde_json::Value =
            serde_json::from_str(&inspect.content[0].as_text().unwrap().text).unwrap();
        let inspect_bytes = serde_json::to_vec(&inspect_payload).unwrap();
        assert!(
            inspect_bytes.len() < MCP_RESPONSE_BUDGET_BYTES,
            "inspect response {} bytes exceeds the {} byte budget",
            inspect_bytes.len(),
            MCP_RESPONSE_BUDGET_BYTES
        );

        let run_id = inspect_payload["run_id"].as_str().unwrap().to_string();
        let read = client
            .call_tool(
                CallToolRequestParams::new("vortex_read_evidence".to_string()).with_arguments(
                    serde_json::json!({
                        "run_id": run_id,
                        "section": "findings",
                        "page": 1,
                        "page_size": 100,
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
            )
            .await
            .expect("read tool");
        let read_payload: serde_json::Value =
            serde_json::from_str(&read.content[0].as_text().unwrap().text).unwrap();
        let read_bytes = serde_json::to_vec(&read_payload).unwrap();
        assert!(
            read_bytes.len() < MCP_RESPONSE_BUDGET_BYTES,
            "read_evidence response {} bytes exceeds the {} byte budget",
            read_bytes.len(),
            MCP_RESPONSE_BUDGET_BYTES
        );
        // Honest pagination rather than unbounded output.
        assert!(read_payload["page"]["page_size"].as_u64().unwrap() <= 100);

        client.cancel().await.expect("client cancel");
        server_handle.abort();
    });
}

#[derive(Debug, Clone, Default)]
struct DummyClient;

impl ClientHandler for DummyClient {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        rmcp::model::ClientConfig::default()
    }
}
