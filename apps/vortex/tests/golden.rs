//! Golden tests: the demonstration fixture must produce exactly the
//! expected findings, relationships, and search matches recorded in
//! `fixtures/expected-results/`.
//!
//! These tests are the product's honesty check: if implementation changes
//! alter the evidence, the diff has to be reviewed deliberately by updating
//! the expected files — never silently.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use vortex_core::config::VortexConfig;
use vortex_core::limits::ResourceLimits;
use vortex_evidence::Resolution;
use vortex_evidence::RunStore;
use vortex_providers::provider::CancelToken;
use vortex_service::service::{OperationOptions, VortexService};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/javascript-demo")
        .canonicalize()
        .expect("fixture exists")
}

fn service_in_temp() -> (VortexService, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = VortexConfig {
        data_dir: dir.path().to_path_buf(),
        limits: ResourceLimits::default(),
        allowed_roots: None,
        notes: Vec::new(),
    };
    let service = VortexService::new(config).expect("service");
    (service, dir)
}

fn load_expected(name: &str) -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/expected-results")
        .join(name);
    let path = path.canonicalize().unwrap_or(path);
    serde_json::from_str(&std::fs::read_to_string(path).expect("expected results file"))
        .expect("valid expected-results JSON")
}

fn key_of(edge: &serde_json::Value) -> String {
    let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_string();
    format!(
        "{}|{}|{}|{}|{}",
        text(&edge["from"]),
        text(&edge["to"]),
        text(&edge["kind"]),
        text(&edge["scope"]),
        text(&edge["status"])
    )
}

#[test]
fn relationships_match_expected_edges_exactly() {
    let expected = load_expected("expected-relationships.json");
    let (service, _dir) = service_in_temp();
    let result = service
        .relationships(
            &fixture_root(),
            &OperationOptions::default(),
            &CancelToken::new(),
        )
        .expect("relationships");

    let actual: BTreeSet<String> = result
        .report
        .relationships
        .iter()
        .map(|r| {
            let scope = serde_json::to_value(r.scope)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            let status = serde_json::to_value(r.status)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            format!("{}|{}|{}|{}|{}", r.from.id, r.to.id, r.kind, scope, status)
        })
        .collect();
    let expected_set: BTreeSet<String> = expected["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .map(key_of)
        .collect();

    assert_eq!(
        actual, expected_set,
        "relationship edges differ from fixtures/expected-results/expected-relationships.json"
    );

    // Every unresolved relationship must explain itself.
    for relationship in &result.report.relationships {
        if relationship.status == Resolution::Unresolved {
            assert!(
                relationship.resolution_note.is_some(),
                "unresolved edge {} -> {} has no note",
                relationship.from.id,
                relationship.to.id
            );
        }
    }

    // Unresolved local references must appear in unknowns.
    assert!(result
        .report
        .unknowns
        .iter()
        .any(|u| u.contains("./missing-module.js")));
    assert!(result
        .report
        .unknowns
        .iter()
        .any(|u| u.contains("./theme.js")));
}

#[test]
fn inspection_matches_expected_summary() {
    let expected = load_expected("expected-inspection.json");
    let (service, _dir) = service_in_temp();
    let result = service
        .inspect(
            &fixture_root(),
            &OperationOptions::default(),
            &CancelToken::new(),
        )
        .expect("inspect");

    let summary = &result.report.summary;
    assert_eq!(summary["file_count"], expected["file_count"]);
    assert_eq!(summary["directory_count"], expected["directory_count"]);
    assert_eq!(summary["electron"], expected["electron"]);
    assert_eq!(
        summary["entry_point"]["entry_point"],
        expected["entry_point"]
    );

    // Manifest facts surfaced through findings.
    let manifest = result
        .report
        .findings
        .iter()
        .find(|f| f.kind == "package_manifest")
        .expect("package manifest finding");
    assert_eq!(manifest.details["name"], expected["package"]["name"]);
    assert_eq!(manifest.details["version"], expected["package"]["version"]);
    assert_eq!(manifest.details["main"], expected["package"]["main"]);

    // Finding-kind census must match exactly.
    let mut kinds = std::collections::BTreeMap::new();
    for finding in &result.report.findings {
        *kinds.entry(finding.kind.clone()).or_insert(0u32) += 1;
    }
    let expected_kinds: serde_json::Map<String, serde_json::Value> = expected["finding_kinds"]
        .as_object()
        .expect("kinds")
        .clone();
    for (kind, count) in &expected_kinds {
        assert_eq!(
            kinds.get(kind.as_str()).copied().unwrap_or(0) as u64,
            count.as_u64().expect("count"),
            "finding kind census mismatch for '{kind}'"
        );
    }
    // And no unexpected extra kinds.
    assert_eq!(
        kinds.len(),
        expected_kinds.len(),
        "unexpected kinds: {kinds:?}"
    );

    // Source map references with exact locations.
    let sourcemaps: BTreeSet<String> = result
        .report
        .findings
        .iter()
        .filter(|f| f.kind == "sourcemap_reference")
        .map(|f| {
            format!(
                "{}:{}:{}",
                f.location
                    .as_ref()
                    .and_then(|l| l.file.clone())
                    .unwrap_or_default(),
                f.location.as_ref().and_then(|l| l.line).unwrap_or(0),
                f.details["url"].as_str().unwrap_or_default()
            )
        })
        .collect();
    let expected_maps: BTreeSet<String> = expected["sourcemap_references"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            format!(
                "{}:{}:{}",
                m["file"].as_str().unwrap(),
                m["line"],
                m["url"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(sourcemaps, expected_maps);

    // The stored run must pass evidence validation.
    let run_id = result.run_id.expect("persisted");
    let stored = service.store().load(&run_id).expect("stored run");
    assert!(vortex_evidence::validate_run(&stored).is_empty());
    // Origins are classified and meaningful: directory inspection only
    // produces observed or derived findings (never unjustified inferences).
    for finding in &stored.findings {
        assert_ne!(
            finding.origin,
            vortex_evidence::Origin::Inferred,
            "directory inspect must not emit inferred findings: {}",
            finding.kind
        );
        assert!(!finding.summary.is_empty());
    }
}

#[test]
fn search_matches_expected_locations() {
    let expected = load_expected("expected-search.json");
    let (service, _dir) = service_in_temp();
    let result = service
        .search(
            &fixture_root(),
            "VORTEX_DEMO_MARKER",
            &OperationOptions::default(),
            &CancelToken::new(),
        )
        .expect("search");

    let summary = &result.report.summary;
    assert_eq!(summary["query"], expected["query"]);
    assert_eq!(summary["matches"], expected["match_count"]);
    assert_eq!(
        summary["files_skipped_binary"],
        expected["files_skipped_binary"]
    );

    let actual: BTreeSet<String> = result
        .report
        .findings
        .iter()
        .filter(|f| f.kind == "search_match")
        .map(|f| {
            let location = f.location.as_ref().expect("location");
            format!(
                "{}:{}:{}",
                location.file.clone().unwrap_or_default(),
                location.line.unwrap_or(0),
                location.column.unwrap_or(0)
            )
        })
        .collect();
    let expected_matches: BTreeSet<String> = expected["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            format!(
                "{}:{}:{}",
                m["file"].as_str().unwrap(),
                m["line"],
                m["column"]
            )
        })
        .collect();
    assert_eq!(actual, expected_matches);

    // Case-sensitive variant of a lowercase query finds nothing.
    let case_sensitive = OperationOptions {
        case_sensitive: true,
        ..OperationOptions::default()
    };
    let strict = service
        .search(
            &fixture_root(),
            "vortex_demo_marker",
            &case_sensitive,
            &CancelToken::new(),
        )
        .expect("search");
    assert_eq!(strict.report.summary["matches"], 0);
}

#[test]
fn output_is_deterministic_across_runs() {
    let (service, _dir) = service_in_temp();
    let first = service
        .inspect(
            &fixture_root(),
            &OperationOptions::default(),
            &CancelToken::new(),
        )
        .expect("first");
    let second = service
        .inspect(
            &fixture_root(),
            &OperationOptions::default(),
            &CancelToken::new(),
        )
        .expect("second");

    assert_eq!(first.report.findings, second.report.findings);
    assert_eq!(first.report.relationships, second.report.relationships);
    assert_eq!(first.report.summary, second.report.summary);

    // The same artifact must produce the same target digest.
    let run_a = service.store().load(&first.run_id.unwrap()).unwrap();
    let run_b = service.store().load(&second.run_id.unwrap()).unwrap();
    assert_eq!(run_a.target.sha256, run_b.target.sha256);
}

#[test]
fn stored_runs_pass_full_evidence_validation() {
    let (service, _dir) = service_in_temp();
    for operation in ["inspect", "search", "relationships"] {
        let result = match operation {
            "inspect" => service
                .inspect(
                    &fixture_root(),
                    &OperationOptions::default(),
                    &CancelToken::new(),
                )
                .unwrap(),
            "search" => service
                .search(
                    &fixture_root(),
                    "config",
                    &OperationOptions::default(),
                    &CancelToken::new(),
                )
                .unwrap(),
            _ => service
                .relationships(
                    &fixture_root(),
                    &OperationOptions::default(),
                    &CancelToken::new(),
                )
                .unwrap(),
        };
        let stored = service.store().load(&result.run_id.unwrap()).expect("load");
        let problems = vortex_evidence::validate_run(&stored);
        assert!(problems.is_empty(), "{operation}: {problems:?}");
    }
}

#[test]
fn binary_fixture_strings_are_redacted_in_findings() {
    // Inspect the binary sample directly and confirm the embedded
    // api_key-looking string is masked in the strings finding.
    let (service, _dir) = service_in_temp();
    let target = fixture_root().join("assets/sample.bin");
    let result = service
        .inspect(&target, &OperationOptions::default(), &CancelToken::new())
        .expect("inspect binary");
    let strings_finding = result
        .report
        .findings
        .iter()
        .find(|f| f.kind == "strings_sample")
        .expect("strings finding");
    let rendered = serde_json::to_string(strings_finding).unwrap();
    assert!(
        rendered.contains("VORTEX_BINARY_STRING_MARKER"),
        "marker string should be visible"
    );
    assert!(
        !rendered.contains("supersecret123"),
        "secret-looking value must be redacted"
    );
    assert!(rendered.contains("[REDACTED]"));
    assert!(
        !result.report.redactions.is_empty(),
        "redactions must be recorded"
    );
}

#[test]
fn unsupported_native_binary_is_reported_not_faked() {
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("program");
    std::fs::write(
        &elf,
        [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )
    .unwrap();

    let (service, _dir2) = service_in_temp();
    let result = service
        .inspect(&elf, &OperationOptions::default(), &CancelToken::new())
        .expect("inspect");
    assert_eq!(result.report.summary["format"], "elf");
    assert!(result
        .report
        .errors
        .iter()
        .any(|e| e.code == "unsupported_operation"));
    assert!(result
        .report
        .limitations
        .iter()
        .any(|l| l.contains("native-analysis provider")));
    // No fabricated findings: only file/format/strings facts are present.
    for finding in &result.report.findings {
        assert!(
            matches!(finding.kind.as_str(), "file" | "format" | "strings_sample"),
            "unexpected fabricated finding kind: {}",
            finding.kind
        );
    }
}
