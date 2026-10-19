//! Binding layer tests (Phase Four): which imported bindings exist, where
//! they are referenced, and which imports are statically unused — with the
//! scope-unawareness disclosed at every layer, never hidden.

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

fn limitations(result: &OperationResult) -> Vec<&str> {
    result
        .report
        .limitations
        .iter()
        .map(String::as_str)
        .collect()
}

fn write(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

// ---------------------------------------------------------------------------
// the demo fixture (golden)
// ---------------------------------------------------------------------------

#[test]
fn demo_fixture_binding_layer_pinned() {
    let (service, _dir) = default_service();
    let result = relationships(&service, &fixture("javascript-demo"));

    // Four files carry import bindings: the CJS main process, the ESM
    // renderer, the config helper (a JSON require), and the updater (whose
    // binding comes from an unresolved module — the binding still exists).
    let references = findings_of_kind(&result, "binding_references");
    assert_eq!(references.len(), 4, "{references:?}");
    let main = references
        .iter()
        .find(|f| f.details["file"] == "src/main.js")
        .expect("main.js binding finding");
    let renderer = references
        .iter()
        .find(|f| f.details["file"] == "src/renderer/renderer.js")
        .expect("renderer.js binding finding");
    let config = references
        .iter()
        .find(|f| f.details["file"] == "src/lib/config.js")
        .expect("config.js binding finding");
    let updater = references
        .iter()
        .find(|f| f.details["file"] == "src/lib/updater.js")
        .expect("updater.js binding finding");

    // config.js: one binding from a JSON module, used through members.
    assert_eq!(config.details["bindings_total"], 1);
    assert_eq!(config.details["bindings"][0]["name"], "defaults");
    assert_eq!(
        config.details["bindings"][0]["specifier"],
        "./defaults.json"
    );
    assert_eq!(config.details["bindings"][0]["role"], "default");
    assert_eq!(config.details["bindings"][0]["usage_count"], 2);
    assert_eq!(
        config.details["bindings"][0]["usage_sites"][0]["form"],
        "member"
    );

    // updater.js: the binding comes from an unresolved module; usage sites
    // still exist and are reported as-is.
    assert_eq!(updater.details["bindings_total"], 1);
    assert_eq!(updater.details["bindings"][0]["name"], "findAsset");
    assert_eq!(
        updater.details["bindings"][0]["specifier"],
        "./missing-module.js"
    );
    assert_eq!(updater.details["bindings"][0]["usage_count"], 2);
    let updater_forms: Vec<&str> = updater.details["bindings"][0]["usage_sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["form"].as_str().unwrap())
        .collect();
    assert!(updater_forms.contains(&"bare"));
    assert!(updater_forms.contains(&"call"));

    // main.js: 5 bindings (2 destructured, 3 plain requires), 3 call usages.
    assert_eq!(main.details["bindings_total"], 5);
    assert_eq!(main.details["usages_total"], 3);
    assert_eq!(main.origin.as_str(), "inferred");
    let names: Vec<&str> = main.details["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["loadConfig", "checkForUpdates", "tinyDep", "minimist", "fs"]
    );
    // Roles: the destructured requires are named; the plain ones default.
    assert_eq!(main.details["bindings"][0]["role"], "named");
    assert_eq!(main.details["bindings"][0]["specifier"], "./lib/config.js");
    assert_eq!(main.details["bindings"][2]["role"], "default");
    // Each used binding has exactly one call site with a location.
    assert_eq!(main.details["bindings"][0]["usage_count"], 1);
    let first_site = &main.details["bindings"][0]["usage_sites"][0];
    assert_eq!(first_site["form"], "call");
    assert!(first_site["line"].as_u64().unwrap() >= 1);

    // renderer.js: 2 bindings (named + default), 2 usages, none unused.
    assert_eq!(renderer.details["bindings_total"], 2);
    assert_eq!(renderer.details["usages_total"], 2);

    // The unused layer: tinyDep and fs in main.js, with the shadowing caveat.
    let unused = findings_of_kind(&result, "unused_import_binding");
    assert_eq!(unused.len(), 1);
    assert_eq!(unused[0].details["file"], "src/main.js");
    let unused_names: Vec<&str> = unused[0].details["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert_eq!(unused_names, vec!["tinyDep", "fs"]);
    assert!(unused[0].details["caveat"]
        .as_str()
        .unwrap()
        .contains("verify with `vortex search"));

    // The standing framing limitation is present for every run.
    assert!(limitations(&result)
        .iter()
        .any(|l| l.contains("binding usage sites (the Phase Four layer beyond import edges)")));
}

// ---------------------------------------------------------------------------
// shapes and honesty (tempdir)
// ---------------------------------------------------------------------------

#[test]
fn forms_and_span_exclusions_surface_through_findings() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        &root.join("app.js"),
        "const { load } = require('./lib');\n\
         const pkg = require('./pkg');\n\
         // a comment mentioning load still counts (comments are not stripped)\n\
         const value = load('x');\n\
         const meta = pkg.metadata;\n\
         export { load as loadLib };\n\
         const unused = require('./unused');\n",
    );

    let (service, _keep) = default_service();
    let result = relationships(&service, &root.join("app.js"));
    let references = findings_of_kind(&result, "binding_references");
    assert_eq!(references.len(), 1);
    let finding = references[0];
    assert_eq!(finding.details["bindings_total"], 3);
    // load: comment (bare) + call + reexport = 3 sites.
    let load = &finding.details["bindings"][0];
    assert_eq!(load["name"], "load");
    assert_eq!(load["usage_count"], 3);
    let forms: Vec<&str> = load["usage_sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["form"].as_str().unwrap())
        .collect();
    assert!(forms.contains(&"bare"));
    assert!(forms.contains(&"call"));
    assert!(forms.contains(&"reexport"));
    // pkg: exactly one member site (its declaration line is excluded).
    let pkg = &finding.details["bindings"][1];
    assert_eq!(pkg["name"], "pkg");
    assert_eq!(pkg["usage_count"], 1);
    assert_eq!(pkg["usage_sites"][0]["form"], "member");
    // unused: zero sites -> the unused layer fires.
    let unused = findings_of_kind(&result, "unused_import_binding");
    assert_eq!(unused.len(), 1);
    let unused_names: Vec<&str> = unused[0].details["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert_eq!(unused_names, vec!["unused"]);
}

#[test]
fn unparsed_shapes_are_disclosed_never_guessed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        &root.join("odd.js"),
        "import def, { extra } from './both';\n\
         const a = require('./multi'), b = 2;\n\
         const { nested: { deep } } = require('./nested');\n\
         import * as ns from './ns';\n\
         console.log(def, extra, ns, a);\n",
    );

    let (service, _keep) = default_service();
    let result = relationships(&service, &root.join("odd.js"));
    let references = findings_of_kind(&result, "binding_references");
    assert_eq!(references.len(), 1);
    let finding = references[0];
    // The understood shapes are kept; the two CJS oddities are counted.
    assert_eq!(finding.details["unparsed_statements"], 2);
    assert!(limitations(&result)
        .iter()
        .any(|l| l.contains("2 binding statement(s) were not fully understood")));
    // def/extra/ns parsed from the ESM statement.
    let names: Vec<&str> = finding.details["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"def"));
    assert!(names.contains(&"extra"));
    assert!(names.contains(&"ns"));
    assert!(
        names.contains(&"a"),
        "the first declarator of the multi-declarator line"
    );
    // Nothing was fabricated for the nested pattern.
    assert!(!names.contains(&"deep"));
}

#[test]
fn caps_disclose_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let mut body = String::from("const u0 = require('./m0');\n");
    for _ in 0..30 {
        body.push_str("u0(); u0.prop;\n");
    }

    let limits = ResourceLimits {
        max_binding_usages_per_file: 5,
        max_entries: 4,
        ..ResourceLimits::default()
    };
    write(&root.join("cap.js"), &body);
    let (service, _keep) = service_in_temp(limits);
    let result = relationships(&service, &root.join("cap.js"));
    let finding = findings_of_kind(&result, "binding_references")
        .first()
        .copied()
        .expect("binding finding");
    assert_eq!(finding.details["bindings_total"], 1);
    assert_eq!(finding.details["usages_truncated"], true);
    assert!(limitations(&result)
        .iter()
        .any(|l| l.contains("usage-site listing stopped at 5 site(s) (limit)")));
}

#[test]
fn files_without_imports_get_no_binding_findings() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        &root.join("plain.js"),
        "console.log('no imports here');\nfunction local() { return local; }\n",
    );
    let (service, _keep) = default_service();
    let result = relationships(&service, &root.join("plain.js"));
    assert!(findings_of_kind(&result, "binding_references").is_empty());
    assert!(findings_of_kind(&result, "unused_import_binding").is_empty());
}
