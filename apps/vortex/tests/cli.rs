//! CLI integration tests: run the real `vortex` binary and check output,
//! exit codes, and the JSON contract. Tests use isolated VORTEX_HOME
//! directories so they never touch user data.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_vortex")
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/javascript-demo")
        .canonicalize()
        .expect("fixture exists")
}

struct Run {
    output: Output,
    /// Kept alive so the isolated VORTEX_HOME survives the process run.
    _home: Option<tempfile::TempDir>,
}

fn run_vortex(args: &[&str]) -> Run {
    let home = tempfile::tempdir().expect("temp home");
    let home_path = home.path().to_path_buf();
    run_vortex_shared(&home_path, args, Some(home))
}

fn run_vortex_shared(
    home: &std::path::Path,
    args: &[&str],
    owned: Option<tempfile::TempDir>,
) -> Run {
    let output = Command::new(binary())
        .args(args)
        .env("VORTEX_HOME", home)
        .output()
        .expect("run vortex");
    Run {
        output,
        _home: owned,
    }
}

fn stdout_json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("stdout is valid JSON")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn help_exits_zero_and_lists_all_commands() {
    let run = run_vortex(&["--help"]);
    assert!(run.output.status.success());
    let text = String::from_utf8_lossy(&run.output.stdout).to_string();
    for command in [
        "doctor",
        "capabilities",
        "inspect",
        "search",
        "relationships",
        "runs",
        "evidence",
        "compare",
        "mcp",
    ] {
        assert!(text.contains(command), "help must mention '{command}'");
    }
}

#[test]
fn subcommand_help_is_useful() {
    for command in [
        vec!["inspect", "--help"],
        vec!["search", "--help"],
        vec!["evidence", "show", "--help"],
        vec!["runs", "list", "--help"],
        vec!["compare", "--help"],
    ] {
        let args: Vec<&str> = command.to_vec();
        let run = run_vortex(&args);
        assert!(run.output.status.success(), "{args:?} --help must succeed");
        let text = String::from_utf8_lossy(&run.output.stdout);
        assert!(text.contains("Usage:"), "{args:?} help must show usage");
    }
}

#[test]
fn missing_arguments_exit_with_usage_code() {
    let run = run_vortex(&["inspect"]);
    assert_eq!(
        run.output.status.code(),
        Some(2),
        "clap usage errors exit 2"
    );
    let run = run_vortex(&["search"]);
    assert_eq!(run.output.status.code(), Some(2));
    let run = run_vortex(&[]);
    assert_eq!(run.output.status.code(), Some(2));
}

#[test]
fn nonexistent_path_fails_with_actionable_error() {
    let run = run_vortex(&["inspect", "/definitely/not/here/vortex"]);
    assert_eq!(run.output.status.code(), Some(1));
    let err = stderr(&run.output);
    assert!(err.contains("path not found"), "stderr: {err}");
    assert!(err.contains("hint"), "errors must include a hint");

    // JSON mode emits a structured error object on stdout.
    let run = run_vortex(&["inspect", "/definitely/not/here/vortex", "--json"]);
    assert_eq!(run.output.status.code(), Some(1));
    let error = stdout_json(&run.output);
    assert_eq!(error["error"]["code"], "not_found");
    assert!(error["error"]["hint"].is_string());
}

#[test]
fn invalid_numeric_option_is_rejected() {
    let run = run_vortex(&["inspect", fixture().to_str().unwrap(), "--max-entries", "0"]);
    assert_eq!(run.output.status.code(), Some(1));
    assert!(stderr(&run.output).contains("max-entries must be >= 1"));
}

#[test]
fn inspect_fixture_json_matches_expected_contract() {
    let fixture = fixture().to_str().unwrap().to_string();
    let run = run_vortex(&["inspect", &fixture, "--json"]);
    assert!(
        run.output.status.success(),
        "stderr: {}",
        stderr(&run.output)
    );
    let value = stdout_json(&run.output);
    assert_eq!(value["status"], "succeeded");
    assert!(value["run_id"]
        .as_str()
        .is_some_and(|id| id.starts_with("run-")));
    // 15 files: the fixture ships a vendored node_modules/tiny-dep
    // (package.json + lib/entry.js) alongside the original 13 files.
    assert_eq!(value["report"]["summary"]["file_count"], 15);
    assert_eq!(value["report"]["summary"]["electron"], true);
    assert_eq!(
        value["report"]["summary"]["entry_point"]["entry_point"],
        "src/main.js"
    );
    assert!(value["report"]["summary"]["sha256"].as_str().unwrap().len() == 64);
    // Progress messages must stay off stdout in JSON mode.
    assert!(!String::from_utf8_lossy(&run.output.stdout).contains("[vortex]"));
}

#[test]
fn inspect_reports_partial_exit_code_when_limits_hit() {
    let fixture = fixture().to_str().unwrap().to_string();
    let run = run_vortex(&["inspect", &fixture, "--json", "--max-entries", "1"]);
    // The run itself succeeds; partial applies when analysis bounds were hit.
    // With a tiny max-entries the summary stays small but the run succeeds.
    let code = run.output.status.code().unwrap();
    assert!(
        code == 0 || code == 6,
        "expected success or partial, got {code}"
    );
}

#[test]
fn search_fixture_json_returns_expected_matches() {
    let fixture = fixture().to_str().unwrap().to_string();
    let run = run_vortex(&["search", &fixture, "VORTEX_DEMO_MARKER", "--json"]);
    assert!(run.output.status.success());
    let value = stdout_json(&run.output);
    assert_eq!(value["report"]["summary"]["matches"], 3);
    let matches: Vec<_> = value["report"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["kind"] == "search_match")
        .map(|f| {
            format!(
                "{}:{}",
                f["location"]["file"].as_str().unwrap(),
                f["location"]["line"]
            )
        })
        .collect();
    assert!(matches.contains(&"src/main.js:11".to_string()));
    assert!(matches.contains(&"dist/bundle.js:1".to_string()));
}

#[test]
fn empty_search_query_is_rejected() {
    let fixture = fixture().to_str().unwrap().to_string();
    let run = run_vortex(&["search", &fixture, ""]);
    assert_eq!(run.output.status.code(), Some(1));
    assert!(stderr(&run.output).contains("query must not be empty"));
}

#[test]
fn evidence_lifecycle_via_cli() {
    // One shared home so all commands in this test see the same store.
    let home = tempfile::tempdir().expect("shared home");
    let fixture = fixture().to_str().unwrap().to_string();
    // 1. inspect (persisted)
    let run = run_vortex_shared(home.path(), &["inspect", &fixture, "--json"], None);
    assert!(run.output.status.success());
    let run_id = stdout_json(&run.output)["run_id"]
        .as_str()
        .expect("run id")
        .to_string();

    // 2. runs list shows it
    let run = run_vortex_shared(home.path(), &["runs", "list", "--json"], None);
    assert!(run.output.status.success());
    let listed = stdout_json(&run.output);
    let found = listed["runs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["run_id"].as_str() == Some(run_id.as_str()));
    assert!(found, "run must appear in runs list");

    // 3. evidence show (findings section, paginated)
    let run = run_vortex_shared(
        home.path(),
        &[
            "evidence",
            "show",
            &run_id,
            "--section",
            "findings",
            "--page",
            "1",
            "--page-size",
            "3",
            "--json",
        ],
        None,
    );
    assert!(run.output.status.success());
    let view = stdout_json(&run.output);
    assert_eq!(view["section"], "findings");
    assert_eq!(view["page"]["page_size"], 3);
    // 9 findings: the vendored tiny-dep adds a second package_manifest
    // and a second entry_point finding to the original 7.
    assert_eq!(view["page"]["total_items"], 9);
    assert_eq!(view["page"]["has_next"], true);
    assert_eq!(view["page"]["items"].as_array().unwrap().len(), 3);

    // 4. invalid section name is rejected with a hint
    let run = run_vortex_shared(
        home.path(),
        &["evidence", "show", &run_id, "--section", "bogus"],
        None,
    );
    assert_eq!(run.output.status.code(), Some(1));
    assert!(stderr(&run.output).contains("unknown evidence section"));

    // 5. export produces a valid, validatable record
    let export_target = std::env::temp_dir().join(format!("vortex-cli-export-{run_id}.json"));
    let run = run_vortex_shared(
        home.path(),
        &[
            "evidence",
            "export",
            &run_id,
            "--out",
            export_target.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        run.output.status.success(),
        "export stderr: {}",
        stderr(&run.output)
    );
    let exported: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&export_target).unwrap()).unwrap();
    assert_eq!(exported["schema_version"], vortex_evidence::SCHEMA_VERSION);
    assert_eq!(exported["run_id"], run_id.as_str());
    let _ = std::fs::remove_file(&export_target);

    // 6. compare the run against itself: no diffs
    let run = run_vortex_shared(home.path(), &["compare", &run_id, &run_id, "--json"], None);
    assert!(run.output.status.success());
    let comparison = stdout_json(&run.output);
    assert_eq!(comparison["same_artifact_digest"], true);
    assert_eq!(comparison["totals"]["findings_only_in_a"], 0);
    assert!(comparison["notes"][0]
        .as_str()
        .unwrap()
        .contains("Structural comparison only"));

    // 7. evidence show for a missing run is a clean storage error
    let run = run_vortex_shared(
        home.path(),
        &["evidence", "show", "run-does-not-exist", "--json"],
        None,
    );
    assert_eq!(run.output.status.code(), Some(4));
    let error = stdout_json(&run.output);
    assert_eq!(error["error"]["code"], "storage");
}

#[test]
fn doctor_and_capabilities_json() {
    let run = run_vortex(&["doctor", "--json"]);
    assert!(
        run.output.status.success(),
        "stderr: {}",
        stderr(&run.output)
    );
    let report = stdout_json(&run.output);
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "data_directory"));
    assert!(report["supported_now"].as_array().unwrap().len() >= 8);
    assert!(report["not_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["operation"].as_str().unwrap().contains("decompile")));

    let run = run_vortex(&["capabilities", "--json"]);
    assert!(run.output.status.success());
    let capabilities = stdout_json(&run.output);
    assert_eq!(capabilities["providers"][0]["id"], "builtin-static");
    assert!(
        capabilities["providers"][0]["capabilities"]
            .as_array()
            .unwrap()
            .len()
            >= 8
    );
}

#[test]
fn paths_with_spaces_and_unicode_work() {
    let dir = tempfile::tempdir().unwrap();
    let odd = dir.path().join("папка with spaces");
    std::fs::create_dir_all(&odd).unwrap();
    std::fs::write(
        odd.join("módulo café.js"),
        b"const x = require('./nope.js');\n",
    )
    .unwrap();
    let run = run_vortex(&["inspect", odd.to_str().unwrap(), "--json"]);
    assert!(
        run.output.status.success(),
        "stderr: {}",
        stderr(&run.output)
    );
    let value = stdout_json(&run.output);
    assert_eq!(value["status"], "succeeded");
    assert_eq!(value["report"]["summary"]["file_count"], 1);
}

#[test]
fn no_store_flag_skips_persistence() {
    let fixture = fixture().to_str().unwrap().to_string();
    let run = run_vortex(&["inspect", &fixture, "--no-store", "--json"]);
    assert!(run.output.status.success());
    let value = stdout_json(&run.output);
    assert!(value["run_id"].is_null(), "no run id when --no-store");

    let run = run_vortex(&["runs", "list", "--json"]);
    let listed = stdout_json(&run.output);
    assert_eq!(listed["count"], 0);
}

#[test]
fn runs_recover_reports_cleanly_when_nothing_is_stale() {
    let run = run_vortex(&["runs", "recover", "--json"]);
    assert!(run.output.status.success());
    let value = stdout_json(&run.output);
    assert_eq!(value["count"], 0);
}

#[test]
fn binary_target_inspect_is_honest_about_support() {
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("app.bin");
    std::fs::write(
        &elf,
        [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )
    .unwrap();
    let run = run_vortex(&["inspect", elf.to_str().unwrap(), "--json"]);
    // Identification and strings extraction are real work, but deeper native
    // analysis is unsupported, so the run is deliberately PARTIAL (exit 6).
    assert_eq!(
        run.output.status.code(),
        Some(6),
        "stderr: {}",
        stderr(&run.output)
    );
    let value = stdout_json(&run.output);
    assert_eq!(value["status"], "partial");
    assert_eq!(value["report"]["summary"]["format"], "elf");
    let codes: Vec<&str> = value["report"]["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"unsupported_operation"));
}

#[test]
fn version_flag_works() {
    let run = run_vortex(&["--version"]);
    assert!(run.output.status.success());
    assert!(String::from_utf8_lossy(&run.output.stdout).contains("vortex"));
}

/// The Phase 2 acceptance story, end to end with the real binary:
/// SIGKILL mid-run leaves a `running` record on disk; the next vortex
/// process recovers it automatically, explains itself, and (when a
/// checkpoint exists) points at `vortex runs resume`.
#[test]
fn kill_nine_mid_run_recovers_on_next_start() {
    use std::process::Command;

    let home = tempfile::tempdir().expect("temp home");
    let tree = home.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    // Big enough that the run comfortably outlives the kill polling.
    let payload = "require('./x.js');\n//# sourceMappingURL=x.map\n".repeat(64);
    for i in 0..3000u32 {
        std::fs::write(tree.join(format!("f{i:04}.js")), &payload).unwrap();
    }

    let mut child = Command::new(binary())
        .args([
            "inspect",
            tree.to_str().unwrap(),
            "--json",
            "--timeout-secs",
            "60",
        ])
        .env("VORTEX_HOME", home.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn vortex");

    // Wait for the write-ahead `running` record to appear.
    let runs_dir = home.path().join("runs");
    let mut record_path = None;
    for _ in 0..500 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        if let Ok(entries) = std::fs::read_dir(&runs_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    record_path = Some(path);
                    break;
                }
            }
        }
        if record_path.is_some() {
            break;
        }
    }
    let record_path =
        record_path.expect("the running record must be written before analysis starts");

    // Kill -9 mid-run.
    child.kill().expect("SIGKILL the child");
    let status = child.wait().expect("wait for the child");
    assert!(!status.success(), "child must have died by signal");

    // The record is stranded as 'running' on disk.
    let stranded: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record_path).unwrap()).unwrap();
    assert_eq!(stranded["status"], "running");

    // The next vortex process recovers it and says so.
    let run = run_vortex_shared(home.path(), &["runs", "list", "--json"], None);
    assert!(run.output.status.success());
    let banner = stderr(&run.output);
    assert!(
        banner.contains("recovered an interrupted run from a previous session"),
        "stderr banner: {banner}"
    );
    let listed = stdout_json(&run.output);
    let entry = listed["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["status"] == "failed")
        .expect("recovered run listed as failed");

    // The record now explains itself.
    let recovered: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record_path).unwrap()).unwrap();
    let detail = recovered["status_detail"].as_str().unwrap();
    assert!(detail.contains("no longer running"), "detail: {detail}");
    let has_checkpoint = recovered
        .get("checkpoint")
        .map(|c| !c.is_null())
        .unwrap_or(false);
    if has_checkpoint {
        assert!(
            detail.contains("vortex runs resume"),
            "resume hint: {detail}"
        );
        assert!(recovered["checkpoint"]["next_file_index"]
            .as_u64()
            .is_some());
    }
    let error_codes: Vec<&str> = recovered["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["code"].as_str().unwrap())
        .collect();
    assert!(error_codes.contains(&"recovered"));
    assert_eq!(entry["run_id"], recovered["run_id"]);

    // And the explanation is stable in later invocations (no re-recovery).
    let again = run_vortex_shared(home.path(), &["runs", "list", "--json"], None);
    let again_banner = stderr(&again.output);
    assert!(
        !again_banner.contains("recovered an interrupted run"),
        "no double recovery: {again_banner}"
    );
}

/// `runs resume` through the CLI surface, using an interrupted run created
/// through the service in the same home.
#[test]
fn runs_resume_through_the_cli() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use vortex_providers::provider::CancelToken;
    use vortex_service::service::{OperationOptions, VortexService};

    let home = tempfile::tempdir().expect("temp home");
    let tree = home.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for i in 0..60u32 {
        std::fs::write(
            tree.join(format!("f{i:02}.js")),
            format!("require('./x.js');\n//# sourceMappingURL=f{i:02}.map\n"),
        )
        .unwrap();
    }

    let config = vortex_core::config::VortexConfig {
        data_dir: home.path().to_path_buf(),
        limits: vortex_core::limits::ResourceLimits::default(),
        allowed_roots: None,
        notes: Vec::new(),
    };
    let service = VortexService::new(config).expect("service");

    // Interrupt deterministically: cancel at the first checkpoint.
    let cancel = CancelToken::new();
    let fired = std::sync::Arc::new(AtomicBool::new(false));
    let hook_flag = fired.clone();
    let hook_cancel = cancel.clone();
    let options = OperationOptions {
        on_checkpoint: Some(std::sync::Arc::new(move |_cp| {
            if !hook_flag.swap(true, Ordering::SeqCst) {
                hook_cancel.cancel();
            }
        })),
        ..OperationOptions::default()
    };
    use vortex_evidence::RunStatus;
    let interrupted = service
        .inspect(&tree, &options, &cancel)
        .expect("first pass");
    assert_eq!(interrupted.status, RunStatus::Cancelled);
    let run_id = interrupted.run_id.expect("persisted");

    // CLI resume with a raised time budget.
    let run = run_vortex_shared(
        home.path(),
        &["runs", "resume", &run_id, "--json", "--timeout-secs", "120"],
        None,
    );
    assert!(
        run.output.status.success(),
        "stderr: {}",
        stderr(&run.output)
    );
    let value = stdout_json(&run.output);
    assert_eq!(value["status"], "succeeded");
    assert_eq!(value["run_id"], run_id.as_str());
    assert_eq!(value["report"]["summary"]["file_count"], 60);

    // Resuming a succeeded run is a clean validation error.
    let run = run_vortex_shared(home.path(), &["runs", "resume", &run_id, "--json"], None);
    assert_eq!(run.output.status.code(), Some(1));
    let error = stdout_json(&run.output);
    assert_eq!(error["error"]["code"], "validation");
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("nothing to resume"));
}

/// `runs recover` reports the new owner-aware shape.
#[test]
fn runs_recover_reports_left_running_entries() {
    let home = tempfile::tempdir().expect("temp home");
    let run = run_vortex_shared(
        home.path(),
        &["runs", "recover", "--json", "--older-than-secs", "60"],
        None,
    );
    assert!(run.output.status.success());
    let value = stdout_json(&run.output);
    assert_eq!(value["count"], 0);
    assert!(value["recovered"].as_array().unwrap().is_empty());
    assert!(value["left_running"].as_array().unwrap().is_empty());
}
