//! Source map reconstruction tests (Phase Four): the committed fixtures
//! must produce exactly the structural findings recorded here, and the
//! adversarial cases must degrade with exact counts — never fabricated,
//! never silently dropped.

use std::path::{Path, PathBuf};
use vortex_core::config::VortexConfig;
use vortex_core::limits::ResourceLimits;
use vortex_evidence::Finding;
use vortex_providers::provider::CancelToken;
use vortex_service::service::{OperationOptions, OperationResult, VortexService};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

fn service_in_temp(limits: ResourceLimits) -> (VortexService, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = VortexConfig {
        data_dir: dir.path().to_path_buf(),
        limits,
        allowed_roots: None,
        notes: Vec::new(),
        provider_overrides: Default::default(),
        stale_run_grace_secs: 3600,
        config_file: None,
    };
    let service = VortexService::new(config).expect("service");
    (service, dir)
}

fn default_service() -> (VortexService, tempfile::TempDir) {
    service_in_temp(ResourceLimits::default())
}

fn inspect(service: &VortexService, path: &Path) -> OperationResult {
    service
        .inspect(path, &OperationOptions::default(), &CancelToken::new())
        .expect("inspect runs")
}

fn relationships(service: &VortexService, path: &Path) -> OperationResult {
    service
        .relationships(path, &OperationOptions::default(), &CancelToken::new())
        .expect("relationships runs")
}

fn findings_of_kind<'a>(result: &'a OperationResult, kind: &str) -> Vec<&'a Finding> {
    result
        .report
        .findings
        .iter()
        .filter(|f| f.kind == kind)
        .collect()
}

fn one_finding<'a>(result: &'a OperationResult, kind: &str) -> &'a Finding {
    findings_of_kind(result, kind)
        .first()
        .copied()
        .unwrap_or_else(|| panic!("expected one '{kind}' finding"))
}

fn limitations(result: &OperationResult) -> Vec<&str> {
    result
        .report
        .limitations
        .iter()
        .map(String::as_str)
        .collect()
}

// ---------------------------------------------------------------------------
// bundle-paired reconstruction (golden)
// ---------------------------------------------------------------------------

#[test]
fn bundle_reconstruction_finding_pinned() {
    let (service, _dir) = default_service();
    let result = inspect(&service, &fixture("sourcemaps/app.js"));
    assert_eq!(result.report.summary["format"], "javascript");

    // The reference finding (observed) plus one reconstruction finding
    // (derived) from the sibling map.
    let reference = one_finding(&result, "sourcemap_reference");
    assert_eq!(reference.details["url"], "app.js.map");
    assert_eq!(reference.location.as_ref().unwrap().line, Some(3));
    let reconstruction = one_finding(&result, "sourcemap_reconstruction");
    assert_eq!(reconstruction.origin.as_str(), "derived");

    let details = &reconstruction.details;
    // Correspondence: the map's file field names this bundle.
    assert_eq!(details["correspondence"]["check"], "matches");
    // Coverage accounting: 3-line bundle, 2-line map span, both mapped.
    assert_eq!(details["coverage"]["bundle_lines"], 3);
    assert_eq!(details["coverage"]["generated_lines_spanned"], 2);
    assert_eq!(details["coverage"]["generated_lines_with_mappings"], 2);
    assert_eq!(details["coverage"]["segments"]["mapped"], 4);
    assert_eq!(details["coverage"]["segments"]["column_only"], 1);
    assert_eq!(
        details["coverage"]["segments"]["broken_by_reason"],
        serde_json::json!({})
    );
    assert_eq!(
        details["coverage"]["note"],
        "the map's line span is shorter than the bundle's line count; \
         positions beyond the span report unmapped"
    );

    // Per-source aggregates: 2 named sources + 1 null, all listed.
    assert_eq!(details["sources"]["total"], 3);
    let entries = details["sources"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["name"], "src/orig/main.js");
    assert_eq!(entries[0]["segments"], 2);
    // seg 0 first, seg 4 last, with ordinals as provenance.
    assert_eq!(entries[0]["first"]["generated"]["line"], 1);
    assert_eq!(entries[0]["first"]["generated"]["column"], 0);
    assert_eq!(entries[0]["first"]["ordinal"], 0);
    assert_eq!(entries[0]["last"]["generated"]["column"], 20);
    assert_eq!(entries[0]["last"]["source"]["line"], 2);
    assert_eq!(entries[0]["last"]["ordinal"], 4);
    assert_eq!(entries[1]["name"], "src/orig/util.js");
    assert_eq!(entries[1]["segments"], 2);
    assert_eq!(entries[1]["first"]["generated"]["column"], 16);
    assert_eq!(entries[1]["first"]["source"]["line"], 2);
    assert_eq!(entries[1]["last"]["source"]["line"], 3);
    assert_eq!(entries[1]["last"]["source"]["column"], 4);
    // The null source is listed with zero segments, never skipped.
    assert_eq!(entries[2]["name"], "<null: source not available>");
    assert_eq!(entries[2]["segments"], 0);

    // Samples: the first three mapped segments, verbatim, with names.
    let samples = details["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 3);
    assert_eq!(samples[0]["ordinal"], 0);
    assert_eq!(samples[0]["generated"]["column"], 0);
    assert_eq!(samples[0]["source"]["name"], "src/orig/main.js");
    assert_eq!(samples[1]["ordinal"], 1);
    assert_eq!(samples[1]["generated"]["column"], 16);
    assert_eq!(samples[1]["source"]["name_field"], "makeSum");
    assert_eq!(samples[2]["ordinal"], 3);
    assert_eq!(samples[2]["source"]["name_field"], "log");
    assert_eq!(samples[2]["source"]["line"], 3);
    assert_eq!(samples[2]["source"]["column"], 4);

    // Map identity is carried for provenance.
    assert_eq!(details["map"]["path"], "app.js.map");
    assert_eq!(details["map"]["version"], 3);
    assert_eq!(details["map"]["file_field"], "app.js");

    // The standing honesty framing.
    assert!(limitations(&result)
        .iter()
        .any(|l| l.contains("cannot verify the map was generated from this exact bundle")));
}

// ---------------------------------------------------------------------------
// direct .map inspection (golden)
// ---------------------------------------------------------------------------

#[test]
fn direct_map_inspect_pinned() {
    let (service, _dir) = default_service();
    let result = inspect(&service, &fixture("sourcemaps/app.js.map"));
    assert_eq!(result.report.summary["format"], "sourcemap-json");

    let document = one_finding(&result, "sourcemap_document");
    assert_eq!(document.origin.as_str(), "observed");
    assert_eq!(document.details["version"], 3);
    assert_eq!(document.details["file"], "app.js");
    assert_eq!(document.details["sources"]["total"], 3);
    assert_eq!(document.details["sources"]["named"], 2);
    assert_eq!(document.details["sources"]["null"], 1);
    assert_eq!(document.details["names"]["total"], 2);
    // sourcesContent is measured, never echoed.
    let content_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture("sourcemaps/app.js.map")).unwrap())
            .unwrap();
    let expected_bytes = content_json["sourcesContent"][0].as_str().unwrap().len() as u64;
    assert_eq!(document.details["sources_content"]["with_content"], 1);
    assert_eq!(
        document.details["sources_content"]["total_bytes"],
        expected_bytes
    );
    assert_eq!(document.details["segments"]["total"], 5);
    assert_eq!(document.details["segments"]["mapped"], 4);
    assert_eq!(document.details["generated_lines"]["spanned"], 2);
    assert_eq!(document.details["generated_lines"]["with_mappings"], 2);

    let reconstruction = one_finding(&result, "sourcemap_reconstruction");
    // Direct inspection has no bundle to check correspondence against.
    assert_eq!(
        reconstruction.details["correspondence"]["check"],
        "not_applicable"
    );
}

// ---------------------------------------------------------------------------
// honest degradation (adversarial)
// ---------------------------------------------------------------------------

#[test]
fn broken_map_degrades_with_exact_counts() {
    let (service, _dir) = default_service();
    let result = inspect(&service, &fixture("sourcemaps/broken.map"));
    let document = one_finding(&result, "sourcemap_document");
    assert_eq!(document.details["segments"]["mapped"], 1);
    assert_eq!(document.details["segments"]["total"], 2);
    assert_eq!(
        document.details["segments"]["broken_by_reason"]["out_of_range_source_index"],
        1
    );
    // The degradation is disclosed as a limitation, with the exact count.
    assert!(limitations(&result)
        .iter()
        .any(|l| l.contains("1 mapping segment(s) are unusable (out_of_range_source_index)")));
    // The reconstruction finding still exists and the broken segment maps
    // nothing there either.
    let reconstruction = one_finding(&result, "sourcemap_reconstruction");
    assert_eq!(
        reconstruction.details["coverage"]["segments"]["broken_by_reason"]
            ["out_of_range_source_index"],
        1
    );
}

#[test]
fn garbage_map_is_not_faked() {
    let (service, _dir) = default_service();
    let result = inspect(&service, &fixture("sourcemaps/garbage.map"));
    assert!(findings_of_kind(&result, "sourcemap_document").is_empty());
    assert!(findings_of_kind(&result, "sourcemap_reconstruction").is_empty());
    assert!(result
        .report
        .warnings
        .iter()
        .any(|w| w.contains("parsing failed")));
}

#[test]
fn wrong_version_is_parsed_with_a_caution_note() {
    let (service, _dir) = default_service();
    let result = inspect(&service, &fixture("sourcemaps/wrongversion.map"));
    let document = one_finding(&result, "sourcemap_document");
    assert_eq!(document.details["version"], 2);
    assert!(limitations(&result)
        .iter()
        .any(|l| l.contains("this parser targets version 3")));
    // The mappings still decode: one mapping present.
    assert_eq!(document.details["segments"]["mapped"], 1);
}

// ---------------------------------------------------------------------------
// relationships: maps_to_source edges
// ---------------------------------------------------------------------------

#[test]
fn relationships_maps_to_source_edges() {
    let (service, _dir) = default_service();
    let result = relationships(&service, &fixture("sourcemaps"));
    let edges: Vec<_> = result
        .report
        .relationships
        .iter()
        .filter(|r| r.kind == "maps_to_source")
        .collect();
    assert_eq!(edges.len(), 2, "two named sources resolve on disk");
    for edge in &edges {
        assert_eq!(edge.from.id, "app.js");
        assert_eq!(edge.scope, vortex_evidence::Scope::Internal);
        assert_eq!(edge.status, vortex_evidence::Resolution::Resolved);
        assert_eq!(edge.origin.as_str(), "derived");
        assert!(edge
            .resolution_note
            .as_deref()
            .unwrap_or_default()
            .contains("listed in the source map"));
    }
    let targets: Vec<&str> = edges.iter().map(|e| e.to.id.as_str()).collect();
    assert!(targets.contains(&"src/orig/main.js"));
    assert!(targets.contains(&"src/orig/util.js"));
    // The null source is disclosed, not turned into an edge.
    assert!(limitations(&result)
        .iter()
        .any(|l| l.contains("1 source entry is null or unusable; no maps_to_source edge")));
    // The static-reference framing is standing for every relationships run.
    assert!(limitations(&result).iter().any(
        |l| l.contains("maps_to_source edges restate the source map's build-time declarations")
    ));
}

// ---------------------------------------------------------------------------
// budgets and caps (tempdir adversarial)
// ---------------------------------------------------------------------------

fn write(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

#[test]
fn oversized_map_is_refused_not_half_parsed() {
    let dir = tempfile::tempdir().unwrap();
    let big: String = "{\"version\":3,\"sources\":[".to_string()
        + &format!("\"{}\",", "x".repeat(64)).repeat(64)
        + "null],\"names\":[],\"mappings\":\"AAAA\"}";
    write(&dir.path().join("big.map"), &big);

    let limits = ResourceLimits {
        max_sourcemap_bytes: 16, // far below the fixture's size
        ..ResourceLimits::default()
    };
    let (service, _keep) = service_in_temp(limits);
    let result = inspect(&service, &dir.path().join("big.map"));
    assert!(findings_of_kind(&result, "sourcemap_document").is_empty());
    assert!(limitations(&result)
        .iter()
        .any(|l| l.contains("above the source map budget")));
}

#[test]
fn segment_cap_stops_and_discloses_the_floor() {
    let dir = tempfile::tempdir().unwrap();
    write(
        &dir.path().join("capped.map"),
        "{\"version\":3,\"sources\":[\"a.js\"],\"names\":[],\
         \"mappings\":\"AAAA,AAAA,AAAA,AAAA,AAAA\"}",
    );

    let limits = ResourceLimits {
        max_sourcemap_segments: 2,
        ..ResourceLimits::default()
    };
    let (service, _keep) = service_in_temp(limits);
    let result = inspect(&service, &dir.path().join("capped.map"));
    let document = one_finding(&result, "sourcemap_document");
    assert_eq!(document.details["segments"]["total"], 2);
    let stop = document.details["segments"]["stopped_early"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(stop.contains("segment cap (2)"), "stop was: {stop}");
    assert!(stop.contains("at least 2"), "stop was: {stop}");
    assert!(limitations(&result)
        .iter()
        .any(|l| l.contains("segment cap")));
}

#[test]
fn truncated_json_map_is_disclosed() {
    let dir = tempfile::tempdir().unwrap();
    write(
        &dir.path().join("huge.map"),
        &format!("{}{}{}", "{\"version\":3,\"", "x".repeat(64), "\":1}"),
    );

    let limits = ResourceLimits {
        max_file_bytes: 8, // far below the file's real size
        ..ResourceLimits::default()
    };
    let (service, _keep) = service_in_temp(limits);
    let result = inspect(&service, &dir.path().join("huge.map"));
    assert!(findings_of_kind(&result, "sourcemap_document").is_empty());
    assert!(limitations(&result)
        .iter()
        .any(|l| l.contains("truncated JSON map cannot be parsed")));
}

#[test]
fn file_field_mismatch_and_absent_are_reported_not_guessed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        &root.join("b.js"),
        "console.log(1);\n//# sourceMappingURL=b.js.map\n",
    );
    // Map says it describes a DIFFERENT file.
    write(
        &root.join("b.js.map"),
        "{\"version\":3,\"file\":\"other.js\",\"sources\":[\"a.js\"],\"names\":[],\"mappings\":\"AAAA\"}",
    );
    write(
        &root.join("c.js"),
        "console.log(2);\n//# sourceMappingURL=c.js.map\n",
    );
    // Map has no file field at all.
    write(
        &root.join("c.js.map"),
        "{\"version\":3,\"sources\":[\"a.js\"],\"names\":[],\"mappings\":\"AAAA\"}",
    );

    let (service, _keep) = default_service();
    let b = inspect(&service, &root.join("b.js"));
    let b_rec = one_finding(&b, "sourcemap_reconstruction");
    assert_eq!(b_rec.details["correspondence"]["check"], "mismatch");
    assert_eq!(
        b_rec.details["correspondence"]["map_file_field"],
        "other.js"
    );
    assert!(b_rec.details["correspondence"]["note"]
        .as_str()
        .unwrap()
        .contains("does not name this bundle"));

    let c = inspect(&service, &root.join("c.js"));
    let c_rec = one_finding(&c, "sourcemap_reconstruction");
    assert_eq!(c_rec.details["correspondence"]["check"], "absent");
    assert!(c_rec.details["correspondence"]["note"]
        .as_str()
        .unwrap()
        .contains("unverified"));
}

#[test]
fn unresolvable_and_inline_references_are_disclosed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // References a map that does not exist, plus an inline data: URI.
    write(
        &root.join("d.js"),
        "console.log(1);\n//# sourceMappingURL=missing.map\n//# sourceMappingURL=data:application/json;base64,AAAA\n",
    );

    let (service, _keep) = default_service();
    let result = inspect(&service, &root.join("d.js"));
    assert_eq!(findings_of_kind(&result, "sourcemap_reference").len(), 2);
    // The reconstruction finding is absent: nothing resolved.
    assert!(findings_of_kind(&result, "sourcemap_reconstruction").is_empty());
    let notes = limitations(&result);
    assert!(notes.iter().any(
        |l| l.contains("referenced source map 'missing.map' does not resolve to a local file")
    ));
    assert!(notes
        .iter()
        .any(|l| l.contains("inline data: URI source map reference(s) recorded but not decoded")));
}

#[test]
fn source_root_is_joined_before_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        &root.join("s/x.js"),
        "// source module\nexport const k = 1;\n",
    );
    write(
        &root.join("m/p.js"),
        "console.log(1);\n//# sourceMappingURL=p.js.map\n",
    );
    // sourceRoot ".." + source "s/x.js", resolved from the map's own
    // directory (m/), lands on s/x.js inside the root.
    write(
        &root.join("m/p.js.map"),
        "{\"version\":3,\"file\":\"p.js\",\"sourceRoot\":\"..\",\"sources\":[\"s/x.js\"],\"names\":[],\"mappings\":\"AAAA\"}",
    );

    // Directory target: the inspection root is the tempdir, so m/ is a
    // subdirectory and ".." from the map lands back inside the root.
    let (service, _keep) = default_service();
    let result = relationships(&service, root);
    let edge = result
        .report
        .relationships
        .iter()
        .find(|r| r.kind == "maps_to_source")
        .expect("the source resolves through sourceRoot");
    assert_eq!(edge.to.id, "s/x.js");
    assert_eq!(edge.status, vortex_evidence::Resolution::Resolved);
}

// ---------------------------------------------------------------------------
// the demo fixture through the new code path (regression for the audit
// honesty rules: the reference finding count must not change)
// ---------------------------------------------------------------------------

#[test]
fn directory_pass_stays_inventory_for_maps() {
    let (service, _dir) = default_service();
    let result = inspect(&service, &fixture("sourcemaps"));
    // The .map files are listed, and structural parsing is pointed at
    // single-file inspection — same pattern as native binaries.
    for map in [
        "app.js.map",
        "broken.map",
        "garbage.map",
        "wrongversion.map",
    ] {
        assert!(
            limitations(&result).iter().any(|l| l.contains(&format!(
                "{map}: source map structural parsing is available"
            ))),
            "missing pointer limitation for {map}"
        );
    }
    // No deep findings from the directory pass.
    assert!(findings_of_kind(&result, "sourcemap_document").is_empty());
    assert!(findings_of_kind(&result, "sourcemap_reconstruction").is_empty());
}
