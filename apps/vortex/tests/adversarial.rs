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

/// Worst-case single-file PE inspection through MCP (audit R2,
/// docs/AUDIT_2026-10.md): a synthetic PE with 400 imported DLLs x 500
/// named thunks each makes the `pe_imports` finding quadratic in
/// `max_entries` (DLL rows x names per row) when uncapped. Record-time
/// absolute caps plus byte-aware page fitting must keep the response
/// inside the budget with every truncation flagged - counts stay exact.
#[test]
fn fat_pe_inspect_stays_under_the_size_budget() {
    use rmcp::model::CallToolRequestParams;
    use rmcp::ServiceExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let service = service_in(dir.path());
    let target = dir.path().join("fat.exe");
    std::fs::write(&target, fat_pe_bytes()).unwrap();

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

        let inspect = client
            .call_tool(
                CallToolRequestParams::new("vortex_inspect_artifact".to_string()).with_arguments(
                    serde_json::json!({
                        "path": target,
                        "max_entries": 500,
                        "page_size": 100,
                    })
                    .as_object()
                    .cloned()
                    .unwrap(),
                ),
            )
            .await
            .expect("inspect tool");
        let payload: serde_json::Value =
            serde_json::from_str(&inspect.content[0].as_text().unwrap().text).unwrap();
        let bytes = serde_json::to_vec(&payload).unwrap();
        assert!(
            bytes.len() < MCP_RESPONSE_BUDGET_BYTES,
            "fat PE inspect response {} bytes exceeds the {} byte budget",
            bytes.len(),
            MCP_RESPONSE_BUDGET_BYTES
        );

        // The record-time caps are visible in the finding itself: rows and
        // names bounded, exact counts kept, truncations flagged.
        let imports_finding = payload["findings"]
            .as_array()
            .expect("findings page")
            .iter()
            .find(|f| f["kind"] == "pe_imports")
            .expect("pe_imports finding on page 1");
        let details = &imports_finding["details"];
        assert_eq!(details["count"], serde_json::json!(400));
        assert_eq!(details["truncated"], serde_json::json!(true));
        let rows = details["imports"].as_array().expect("DLL rows");
        assert_eq!(rows.len(), 100, "DLL rows are capped at 100");
        assert_eq!(rows[0]["function_count"], serde_json::json!(500));
        assert_eq!(rows[0]["functions_truncated"], serde_json::json!(true));
        assert!(
            rows[0]["functions"].as_array().unwrap().len() <= 25,
            "names per DLL are capped at 25"
        );

        client.cancel().await.expect("client cancel");
        server_handle.abort();
    });
}

/// A synthetic PE32+ with 400 imported DLLs, each importing 500 named
/// functions (all names shared, to keep the test file small).
fn fat_pe_bytes() -> Vec<u8> {
    const SECTION_VA: u32 = 0x1000;
    const RAW_PTR: usize = 0x1B0;
    const SECTION_SPAN: u32 = 0x190000;
    const DLLS: usize = 400;
    const THUNKS: usize = 500;

    fn rva_off(rva: u32) -> usize {
        (rva - SECTION_VA) as usize + RAW_PTR
    }
    fn put(bytes: &mut [u8], at: usize, data: &[u8]) {
        bytes[at..at + data.len()].copy_from_slice(data);
    }
    fn put_u16(bytes: &mut [u8], at: usize, v: u16) {
        put(bytes, at, &v.to_le_bytes());
    }
    fn put_u32(bytes: &mut [u8], at: usize, v: u32) {
        put(bytes, at, &v.to_le_bytes());
    }
    fn put_u64(bytes: &mut [u8], at: usize, v: u64) {
        put(bytes, at, &v.to_le_bytes());
    }

    let mut bytes = vec![0u8; RAW_PTR + SECTION_SPAN as usize];
    put(&mut bytes, 0, b"MZ");
    put_u32(&mut bytes, 0x3C, 0x80);
    put(&mut bytes, 0x80, b"PE\0\0");
    put_u16(&mut bytes, 0x84, 0x8664); // AMD64
    put_u16(&mut bytes, 0x86, 1); // one section
    put_u16(&mut bytes, 0x94, 240); // optional header size
    put_u16(&mut bytes, 0x96, 0x0022);
    let opt = 0x98;
    put_u16(&mut bytes, opt, 0x20B); // PE32+
    put_u16(&mut bytes, opt + 68, 3); // console
    put_u32(&mut bytes, opt + 108, 16);
    let dirs = opt + 112;
    put_u32(&mut bytes, dirs + 8, SECTION_VA); // import directory RVA
    put_u32(&mut bytes, dirs + 12, (DLLS as u32 + 1) * 20);
    let table = 0x188;
    put(&mut bytes, table, b".fat\0\0\0\0");
    put_u32(&mut bytes, table + 8, SECTION_SPAN);
    put_u32(&mut bytes, table + 12, SECTION_VA);
    put_u32(&mut bytes, table + 16, SECTION_SPAN);
    put_u32(&mut bytes, table + 20, RAW_PTR as u32);
    put_u32(&mut bytes, table + 36, 0x6000_0020);

    const DESCRIPTORS: u32 = 0x1000; // 400 descriptors + null terminator
    const THUNK_ARRAYS: u32 = 0x4000; // (THUNKS + 1) entries * 8 bytes per DLL
    const DLL_NAMES: u32 = 0x18E000; // 16 bytes per name
    const HINT_NAME: u32 = 0x18F000; // shared "f"
    for i in 0..DLLS {
        let desc = rva_off(DESCRIPTORS + (i as u32) * 20);
        put_u32(
            &mut bytes,
            desc,
            THUNK_ARRAYS + (i as u32) * (THUNKS as u32 + 1) * 8,
        );
        put_u32(&mut bytes, desc + 12, DLL_NAMES + (i as u32) * 16);
        let name = rva_off(DLL_NAMES + (i as u32) * 16);
        let dll = format!("DLL{i:03}.dll\0");
        put(&mut bytes, name, dll.as_bytes());
        let array = rva_off(THUNK_ARRAYS + (i as u32) * (THUNKS as u32 + 1) * 8);
        for t in 0..THUNKS {
            put_u64(&mut bytes, array + t * 8, HINT_NAME as u64);
        }
        // The zero terminator is already in place (zeroed buffer).
    }
    let hint = rva_off(HINT_NAME);
    put_u16(&mut bytes, hint, 0);
    put(&mut bytes, hint + 2, b"f\0");
    bytes
}

/// Native and archive adversarial shapes through both inspection paths
/// (audit R7): the directory pass identifies by magic only and says what
/// deeper analysis exists; the single-file pass structurally parses, and
/// garbage must degrade to honest warnings/limitations - never a crash.
#[test]
fn native_and_archive_adversarial_inputs_degrade() {
    let dir = tempfile::tempdir().expect("temp dir");
    let service = service_in(dir.path());
    let base = dir.path().join("hostile");
    std::fs::create_dir_all(&base).unwrap();

    // ELF magic with a zeroed header (e_shentsize patched to the expected
    // 64 so the header itself parses): no section table, all reasons.
    let mut elf = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    elf.resize(256, 0);
    elf[58..60].copy_from_slice(&64u16.to_le_bytes());
    std::fs::write(base.join("elf-garbage"), &elf).unwrap();

    // MZ with a zeroed DOS header: e_lfanew cannot resolve.
    let mut pe = b"MZ".to_vec();
    pe.resize(256, 0);
    std::fs::write(base.join("pe-garbage.exe"), &pe).unwrap();

    // DEX magic with an all-zero tail: header parses, nothing follows.
    let mut dex = b"dex\n035\x00".to_vec();
    dex.resize(256, 0);
    std::fs::write(base.join("dex-garbage.dex"), &dex).unwrap();

    // A zip full of traversal names (the safety-note cap is exercised end
    // to end through the single-file path).
    {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;
        let mut writer = ZipWriter::new(std::fs::File::create(base.join("traversal.zip")).unwrap());
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for i in 0..60 {
            writer
                .start_file(format!("../evil{i}.txt"), options)
                .unwrap();
            writer.write_all(b"x").unwrap();
        }
        writer.finish().unwrap();
    }

    // Directory pass: magic-only identification, honest pointers.
    let dir_result = service
        .inspect(&base, &OperationOptions::default(), &CancelToken::new())
        .expect("directory inspect must not panic");
    assert_honest_terminal_state(&dir_result);
    assert!(
        dir_result
            .report
            .findings
            .iter()
            .filter(|f| f.kind == "binary_artifact")
            .count()
            >= 3,
        "native and archive files are listed as binary artifacts: {:?}",
        dir_result.report.findings
    );
    assert!(
        dir_result
            .report
            .limitations
            .iter()
            .any(|l| l.contains("magic bytes only in this directory pass")),
        "the directory pass says what it did NOT do: {:?}",
        dir_result.report.limitations
    );

    // Single-file passes: structural parsing runs and garbage degrades.
    let pe_result = service
        .inspect(
            &base.join("pe-garbage.exe"),
            &OperationOptions::default(),
            &CancelToken::new(),
        )
        .expect("single-file PE inspect must not panic");
    assert_honest_terminal_state(&pe_result);
    assert!(
        pe_result
            .report
            .warnings
            .iter()
            .any(|w| w.contains("identified as PE")),
        "garbage PE is called out: {:?}",
        pe_result.report.warnings
    );

    let elf_result = service
        .inspect(
            &base.join("elf-garbage"),
            &OperationOptions::default(),
            &CancelToken::new(),
        )
        .expect("single-file ELF inspect must not panic");
    assert_honest_terminal_state(&elf_result);
    assert!(
        elf_result
            .report
            .limitations
            .iter()
            .any(|l| l.contains("ELF analysis is structural only")),
        "garbage ELF still states its scope: {:?}",
        elf_result.report.limitations
    );

    let dex_result = service
        .inspect(
            &base.join("dex-garbage.dex"),
            &OperationOptions::default(),
            &CancelToken::new(),
        )
        .expect("single-file DEX inspect must not panic");
    assert_honest_terminal_state(&dex_result);
    assert!(
        dex_result
            .report
            .findings
            .iter()
            .any(|f| f.kind == "dex_header"),
        "the DEX header itself still parses: {:?}",
        dex_result.report.findings
    );

    let zip_result = service
        .inspect(
            &base.join("traversal.zip"),
            &OperationOptions::default(),
            &CancelToken::new(),
        )
        .expect("single-file zip inspect must not panic");
    assert_honest_terminal_state(&zip_result);
    assert!(
        zip_result
            .report
            .findings
            .iter()
            .any(|f| f.kind == "archive_safety"),
        "traversal names were flagged as safety findings"
    );
    assert!(
        zip_result
            .report
            .limitations
            .iter()
            .any(|l| l.contains("suppressed by the evidence cap")),
        "the safety-note cap is disclosed: {:?}",
        zip_result.report.limitations
    );
}

#[derive(Debug, Clone, Default)]
struct DummyClient;

impl ClientHandler for DummyClient {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        rmcp::model::ClientConfig::default()
    }
}
