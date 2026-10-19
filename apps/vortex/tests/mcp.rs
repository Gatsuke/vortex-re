//! MCP protocol tests: exercise the real server through an in-memory
//! transport using the `rmcp` client, mirroring the SDK's own test pattern.

use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use vortex_app::mcp::VortexServer;
use vortex_core::config::VortexConfig;
use vortex_core::limits::ResourceLimits;
use vortex_service::service::VortexService;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/javascript-demo")
        .canonicalize()
        .expect("fixture exists")
}

fn service_for_tests() -> (Arc<VortexService>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp home");
    let config = VortexConfig {
        data_dir: dir.path().to_path_buf(),
        limits: ResourceLimits::default(),
        allowed_roots: None,
        notes: Vec::new(),
        provider_overrides: Default::default(),
        stale_run_grace_secs: 3600,
        config_file: None,
    };
    (Arc::new(VortexService::new(config).expect("service")), dir)
}

#[derive(Debug, Clone, Default)]
struct DummyClient;

impl ClientHandler for DummyClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

async fn spawn_server(
    service: Arc<VortexService>,
) -> (
    RunningService<RoleClient, DummyClient>,
    tokio::task::JoinHandle<()>,
) {
    let (client_transport, server_transport) = tokio::io::duplex(4096);
    let server = VortexServer::new(service);
    let server_handle = tokio::spawn(async move {
        let running = server.serve(server_transport).await.expect("server serve");
        running.waiting().await.expect("server waiting");
    });
    let client = DummyClient
        .serve(client_transport)
        .await
        .expect("client serve");
    (client, server_handle)
}

async fn shutdown(
    client: RunningService<RoleClient, DummyClient>,
    handle: tokio::task::JoinHandle<()>,
) {
    client.cancel().await.expect("client cancel");
    handle.await.expect("server task finishes");
}

async fn call_tool(
    client: &RunningService<RoleClient, DummyClient>,
    name: &str,
    arguments: serde_json::Value,
) -> rmcp::model::CallToolResult {
    client
        .call_tool(
            CallToolRequestParams::new(name.to_string())
                .with_arguments(arguments.as_object().cloned().unwrap_or_default()),
        )
        .await
        .expect("tool call completes")
}

fn structured(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    result
        .structured_content
        .clone()
        .expect("structured content")
}

#[tokio::test]
async fn server_exposes_eight_tools_with_schemas() {
    let (service, _home) = service_for_tests();
    let (client, server_handle) = spawn_server(service).await;

    let tools = client
        .peer()
        .list_tools(Default::default())
        .await
        .expect("tools/list")
        .tools;
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    for expected in [
        "vortex_capabilities",
        "vortex_inspect_artifact",
        "vortex_search_artifact",
        "vortex_trace_relationships",
        "vortex_list_runs",
        "vortex_read_evidence",
        "vortex_compare_runs",
        "vortex_resume_run",
    ] {
        assert!(
            names.contains(&expected.to_string()),
            "missing tool {expected}: {names:?}"
        );
    }
    assert_eq!(names.len(), 8);

    // Input schemas exist and declare required fields.
    let inspect = tools
        .iter()
        .find(|t| t.name == "vortex_inspect_artifact")
        .unwrap();
    assert_eq!(
        inspect.input_schema.get("type"),
        Some(&serde_json::json!("object"))
    );
    let required = inspect
        .input_schema
        .get("required")
        .and_then(|r| r.as_array())
        .expect("required fields");
    assert!(required.contains(&serde_json::json!("path")));

    shutdown(client, server_handle).await;
}

#[tokio::test]
async fn capabilities_tool_reports_supported_and_unsupported() {
    let (service, _home) = service_for_tests();
    let (client, server_handle) = spawn_server(service).await;
    let result = call_tool(&client, "vortex_capabilities", serde_json::json!({})).await;
    assert_eq!(result.is_error, Some(false));
    let payload = structured(&result);
    assert_eq!(
        payload["capabilities"]["providers"][0]["id"],
        "builtin-static"
    );
    assert!(payload["supported_now"].as_array().unwrap().len() >= 8);
    assert!(payload["not_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["operation"].as_str().unwrap().contains("decompile")));
    shutdown(client, server_handle).await;
}

#[tokio::test]
async fn inspect_tool_returns_bounded_paginated_results() {
    let (service, _home) = service_for_tests();
    let (client, server_handle) = spawn_server(service).await;
    let result = call_tool(
        &client,
        "vortex_inspect_artifact",
        serde_json::json!({ "path": fixture(), "page_size": 3 }),
    )
    .await;
    assert_eq!(result.is_error, Some(false));
    let payload = structured(&result);
    assert_eq!(payload["status"], "succeeded");
    // 15 files: fixture ships a vendored node_modules/tiny-dep (+2 files).
    assert_eq!(payload["summary"]["file_count"], 15);
    // 9 findings: tiny-dep adds a second package_manifest and entry_point.
    assert_eq!(payload["counts"]["findings"], 9);
    assert_eq!(payload["pagination"]["page_size"], 3);
    assert_eq!(payload["pagination"]["total_items"], 9);
    assert_eq!(payload["pagination"]["has_next"], true);
    assert_eq!(
        payload["findings"].as_array().unwrap().len(),
        3,
        "bounded first page"
    );
    shutdown(client, server_handle).await;
}

#[tokio::test]
async fn domain_errors_are_tool_results_not_protocol_errors() {
    let (service, _home) = service_for_tests();
    let (client, server_handle) = spawn_server(service).await;
    let result = call_tool(
        &client,
        "vortex_inspect_artifact",
        serde_json::json!({ "path": "/definitely/not/here" }),
    )
    .await;
    assert_eq!(result.is_error, Some(true), "missing path is a tool error");
    let text = result
        .content
        .first()
        .unwrap()
        .as_text()
        .unwrap()
        .text
        .clone();
    let error: serde_json::Value = serde_json::from_str(&text).expect("error body is JSON");
    assert_eq!(error["code"], "not_found");
    shutdown(client, server_handle).await;
}

#[tokio::test]
async fn invalid_parameter_types_are_rejected() {
    let (service, _home) = service_for_tests();
    let (client, server_handle) = spawn_server(service).await;
    let result = call_tool(
        &client,
        "vortex_inspect_artifact",
        serde_json::json!({ "path": 123 }),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    let text = result
        .content
        .first()
        .unwrap()
        .as_text()
        .unwrap()
        .text
        .clone();
    assert!(text.contains("failed to deserialize parameters"));
    shutdown(client, server_handle).await;
}

#[tokio::test]
async fn empty_search_query_is_a_validation_error() {
    let (service, _home) = service_for_tests();
    let (client, server_handle) = spawn_server(service).await;
    let result = call_tool(
        &client,
        "vortex_search_artifact",
        serde_json::json!({ "path": fixture(), "query": "" }),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    let text = result
        .content
        .first()
        .unwrap()
        .as_text()
        .unwrap()
        .text
        .clone();
    let error: serde_json::Value = serde_json::from_str(&text).expect("error body is JSON");
    assert_eq!(error["code"], "validation");
    shutdown(client, server_handle).await;
}

#[tokio::test]
async fn search_tool_finds_known_fixture_matches() {
    let (service, _home) = service_for_tests();
    let (client, server_handle) = spawn_server(service).await;
    let result = call_tool(
        &client,
        "vortex_search_artifact",
        serde_json::json!({ "path": fixture(), "query": "VORTEX_DEMO_MARKER" }),
    )
    .await;
    assert_eq!(result.is_error, Some(false));
    let payload = structured(&result);
    assert_eq!(payload["summary"]["matches"], 3);
    let matches = payload["matches"].as_array().unwrap();
    let locations: Vec<String> = matches
        .iter()
        .map(|m| {
            format!(
                "{}:{}",
                m["location"]["file"].as_str().unwrap(),
                m["location"]["line"]
            )
        })
        .collect();
    assert!(locations.contains(&"src/main.js:11".to_string()));
    shutdown(client, server_handle).await;
}

#[tokio::test]
async fn trace_tool_returns_expected_edges() {
    let (service, _home) = service_for_tests();
    let (client, server_handle) = spawn_server(service).await;
    let result = call_tool(
        &client,
        "vortex_trace_relationships",
        serde_json::json!({ "path": fixture() }),
    )
    .await;
    assert_eq!(result.is_error, Some(false));
    let payload = structured(&result);
    // 17 edges: the vendored tiny-dep adds a resolved `requires` edge from
    // src/main.js and a resolved `declares_dependency` edge from the root
    // package, both pointing at node_modules/tiny-dep/lib/entry.js; the
    // bundle's source map adds two resolved `maps_to_source` edges from
    // dist/bundle.js to the renderer sources it declares (Phase Four).
    assert_eq!(payload["summary"]["relationships"], 17);
    assert_eq!(payload["summary"]["resolved"], 12);
    assert_eq!(payload["summary"]["unresolved"], 5);
    assert_eq!(payload["relationships"].as_array().unwrap().len(), 17);
    shutdown(client, server_handle).await;
}

#[tokio::test]
async fn evidence_round_trip_through_mcp() {
    let (service, _home) = service_for_tests();
    let (client, server_handle) = spawn_server(service).await;

    // Inspect to create a run.
    let inspect = call_tool(
        &client,
        "vortex_inspect_artifact",
        serde_json::json!({ "path": fixture() }),
    )
    .await;
    let run_id = structured(&inspect)["run_id"]
        .as_str()
        .expect("run id")
        .to_string();

    // List runs includes it.
    let listed = call_tool(
        &client,
        "vortex_list_runs",
        serde_json::json!({ "limit": 10 }),
    )
    .await;
    let payload = structured(&listed);
    let found = payload["runs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["run_id"].as_str() == Some(run_id.as_str()));
    assert!(found, "run must be listed");

    // Read evidence: findings section, page 2 with size 2.
    let read = call_tool(
        &client,
        "vortex_read_evidence",
        serde_json::json!({ "run_id": run_id, "section": "findings", "page": 2, "page_size": 2 }),
    )
    .await;
    assert_eq!(read.is_error, Some(false));
    let payload = structured(&read);
    assert_eq!(payload["section"], "findings");
    assert_eq!(payload["page"]["page"], 2);
    assert_eq!(payload["page"]["total_items"], 9);
    assert_eq!(payload["items"].as_array().unwrap().len(), 2);

    // Bad section name is a validation error the agent can read.
    let bad = call_tool(
        &client,
        "vortex_read_evidence",
        serde_json::json!({ "run_id": run_id, "section": "nope" }),
    )
    .await;
    assert_eq!(bad.is_error, Some(true));

    // Missing run id is a storage-flavored tool error.
    let missing = call_tool(
        &client,
        "vortex_read_evidence",
        serde_json::json!({ "run_id": "run-missing", "section": "overview" }),
    )
    .await;
    assert_eq!(missing.is_error, Some(true));
    let text = missing
        .content
        .first()
        .unwrap()
        .as_text()
        .unwrap()
        .text
        .clone();
    assert!(text.contains("was not found"), "error text: {text}");

    shutdown(client, server_handle).await;
}

#[tokio::test]
async fn compare_tool_disclaims_behavioral_meaning() {
    let (service, _home) = service_for_tests();
    let (client, server_handle) = spawn_server(service).await;

    let first = call_tool(
        &client,
        "vortex_inspect_artifact",
        serde_json::json!({ "path": fixture() }),
    )
    .await;
    let first_run = structured(&first)["run_id"].as_str().unwrap().to_string();

    // Modify the fixture copy? No — inspect the fixture's subdirectory for a
    // different target instead (the fixture itself stays pristine).
    let second = call_tool(
        &client,
        "vortex_inspect_artifact",
        serde_json::json!({ "path": fixture().join("src") }),
    )
    .await;
    let second_run = structured(&second)["run_id"].as_str().unwrap().to_string();

    let comparison = call_tool(
        &client,
        "vortex_compare_runs",
        serde_json::json!({ "run_id_a": first_run, "run_id_b": second_run }),
    )
    .await;
    assert_eq!(comparison.is_error, Some(false));
    let payload = structured(&comparison);
    assert!(payload["notes"][0]
        .as_str()
        .unwrap()
        .contains("Structural comparison only"));
    shutdown(client, server_handle).await;
}

#[tokio::test]
async fn unknown_tool_is_a_protocol_error() {
    let (service, _home) = service_for_tests();
    let (client, server_handle) = spawn_server(service).await;
    let err = client
        .call_tool(CallToolRequestParams::new("vortex_nope".to_string()))
        .await
        .expect_err("unknown tool must fail");
    match err {
        rmcp::ServiceError::McpError(mcp_error) => {
            assert_eq!(mcp_error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        }
        other => panic!("expected an MCP protocol error, got: {other}"),
    }
    shutdown(client, server_handle).await;
}

/// Protocol-level cancellation: the client sends `notifications/cancelled`
/// for an in-flight tool call; rmcp cancels the request-scoped token; the
/// server maps that onto the analysis cancel token, the run stops at its
/// next safe boundary, and the persisted record is `cancelled` with its
/// partial findings retained — never `succeeded`.
#[tokio::test]
async fn protocol_cancellation_maps_to_run_cancellation() {
    use rmcp::model::{
        CallToolRequest, CallToolRequestParams, CancelledNotification, CancelledNotificationParam,
        ClientNotification, ClientRequest, ServerResult,
    };
    use rmcp::service::PeerRequestOptions;
    use vortex_evidence::store::RunStore;

    let (service, _home) = service_for_tests();
    let tree_dir = tempfile::tempdir().expect("tree home");
    let tree = tree_dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let payload = "require('./x.js');\n//# sourceMappingURL=x.map\n".repeat(32);
    for i in 0..3000u32 {
        std::fs::write(tree.join(format!("f{i:04}.js")), &payload).unwrap();
    }

    let (client, server_handle) = spawn_server(service.clone()).await;
    let peer = client.peer();

    // Fire the tool call through the cancellable-request API so we know
    // the request id.
    let params = CallToolRequestParams::new("vortex_inspect_artifact".to_string()).with_arguments(
        serde_json::json!({ "path": tree })
            .as_object()
            .cloned()
            .unwrap(),
    );
    let request = ClientRequest::CallToolRequest(CallToolRequest::new(params));
    let handle = peer
        .send_cancellable_request(request, PeerRequestOptions::default())
        .await
        .expect("send request");
    let request_id = handle.id.clone();
    let response_task = tokio::spawn(async move {
        match handle.rx.await {
            Ok(Ok(ServerResult::CallToolResult(result))) => Ok(result),
            Ok(Ok(other)) => Err(format!("unexpected response variant: {other:?}")),
            Ok(Err(err)) => Err(format!("service error: {err}")),
            Err(err) => Err(format!("channel: {err}")),
        }
    });

    // Wait until the run has durably passed its first checkpoint (async
    // yields so the server task keeps making progress on the single-threaded
    // test runtime). A checkpoint means at least 25 files are analyzed and
    // their findings are on disk — exactly the partial work that must be
    // retained under cancellation.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut run_id = None;
    while std::time::Instant::now() < deadline {
        if let Ok(runs) = service.store().list(10) {
            for running in &runs {
                if running.status == vortex_evidence::RunStatus::Running {
                    if let Ok(record) = service.store().load(&running.run_id) {
                        if record.checkpoint.is_some() {
                            run_id = Some(running.run_id.clone());
                            break;
                        }
                    }
                }
            }
        }
        if run_id.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let run_id = run_id.expect("a checkpointed running record must appear");

    // Cancel the request at the protocol level.
    let notification = CancelledNotification::new(CancelledNotificationParam::new(
        Some(request_id),
        Some("test cancellation".to_string()),
    ));
    peer.send_notification(ClientNotification::CancelledNotification(notification))
        .await
        .expect("send cancellation");

    // Client-side, the call resolves immediately with a cancellation error
    // (standard MCP semantics); the server keeps finishing its work.
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), response_task)
        .await
        .expect("response within timeout")
        .expect("response task");
    match outcome {
        Ok(result) => {
            // The cancellation raced in late; the result itself must then
            // report a cancelled run, never a successful one.
            let payload = structured(&result);
            assert_eq!(payload["status"], "cancelled");
        }
        Err(message) => {
            assert!(
                message.contains("task cancelled"),
                "expected a cancellation error, got: {message}"
            );
        }
    }

    // Server-side, the run stops at its next safe boundary and the persisted
    // record ends up 'cancelled' with partial findings retained. Poll until
    // it reaches a final state.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let stored = service.store().load(&run_id).unwrap();
        if stored.status != vortex_evidence::RunStatus::Running {
            assert_eq!(
                stored.status,
                vortex_evidence::RunStatus::Cancelled,
                "a cancelled run never records 'succeeded' (detail: {:?})",
                stored.status_detail
            );
            assert!(
                !stored.findings.is_empty(),
                "partial findings must be retained under cancellation"
            );
            assert!(stored
                .limitations
                .iter()
                .any(|l| l.contains("stopped early")));
            assert!(
                stored.checkpoint.is_some(),
                "a cancelled run keeps its checkpoint for 'runs resume'"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "run never reached a final state"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    shutdown(client, server_handle).await;
}
