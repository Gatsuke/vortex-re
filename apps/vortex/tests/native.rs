//! Native-format and archive golden tests: the committed fixtures must
//! produce exactly the structural findings recorded here. When a parser
//! changes the evidence, the diff must be reviewed deliberately — the same
//! honesty contract as the JavaScript golden suite, applied to ELF, PE,
//! .NET, DEX, asar, and the zip/APK chain.

use std::path::{Path, PathBuf};
use vortex_core::config::VortexConfig;
use vortex_core::limits::ResourceLimits;
use vortex_evidence::{Finding, RunStore};
use vortex_providers::provider::CancelToken;
use vortex_service::service::{OperationOptions, OperationResult, VortexService};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

fn service_in_temp() -> (VortexService, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = VortexConfig {
        data_dir: dir.path().to_path_buf(),
        limits: ResourceLimits::default(),
        allowed_roots: None,
        notes: Vec::new(),
        provider_overrides: Default::default(),
        stale_run_grace_secs: 3600,
        config_file: None,
    };
    let service = VortexService::new(config).expect("service");
    (service, dir)
}

fn inspect(service: &VortexService, path: &Path) -> OperationResult {
    service
        .inspect(path, &OperationOptions::default(), &CancelToken::new())
        .expect("inspect runs")
}

fn findings_of_kind<'a>(result: &'a OperationResult, kind: &str) -> Vec<&'a Finding> {
    result
        .report
        .findings
        .iter()
        .filter(|f| f.kind == kind)
        .collect()
}

#[test]
fn elf64_fixture_yields_exact_structural_evidence() {
    let (service, _dir) = service_in_temp();
    let result = inspect(&service, &fixture("native/elf64-demo"));
    assert_eq!(result.report.summary["format"], "elf");
    assert!(
        result.report.errors.is_empty(),
        "{:?}",
        result.report.errors
    );

    let headers = findings_of_kind(&result, "elf_header");
    assert_eq!(headers.len(), 1);
    let details = &headers[0].details;
    assert_eq!(details["class"], "64-bit");
    assert_eq!(details["endianness"], "little");
    assert_eq!(details["type"], "executable");
    assert_eq!(details["machine"], "AMD x86-64");
    assert_eq!(details["entry_point"], 0x1000);
    assert_eq!(details["section_count"], 5);
    assert_eq!(headers[0].origin, vortex_evidence::Origin::Observed);

    let sections = findings_of_kind(&result, "elf_sections");
    assert_eq!(sections.len(), 1);
    let names: Vec<&str> = sections[0].details["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["", ".text", ".dynsym", ".dynstr", ".shstrtab"]);
    assert_eq!(sections[0].details["total"], 5);

    let imports = findings_of_kind(&result, "elf_imports");
    assert_eq!(imports.len(), 1);
    let symbols: Vec<&str> = imports[0].details["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert_eq!(symbols, vec!["puts", "malloc"]);
    assert!(result
        .report
        .limitations
        .iter()
        .any(|l| l.contains("structural only")));
}

#[test]
fn elf32_fixture_reports_shared_object_shape() {
    let (service, _dir) = service_in_temp();
    let result = inspect(&service, &fixture("native/elf32-demo"));
    let headers = findings_of_kind(&result, "elf_header");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].details["class"], "32-bit");
    assert_eq!(headers[0].details["type"], "shared object");
    assert_eq!(headers[0].details["machine"], "Intel 80386 (x86)");
    let imports = findings_of_kind(&result, "elf_imports");
    assert_eq!(imports[0].details["symbols"][0], "printf");
}

#[test]
fn pe64_fixture_yields_exact_import_table() {
    let (service, _dir) = service_in_temp();
    let result = inspect(&service, &fixture("native/pe64-demo.exe"));
    assert_eq!(result.report.summary["format"], "pe");
    let headers = findings_of_kind(&result, "pe_header");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].details["format"], "PE32+");
    assert_eq!(headers[0].details["machine"], "AMD64 (x86-64)");
    assert_eq!(headers[0].details["subsystem"], "Windows console (CUI)");
    assert_eq!(headers[0].details["managed"], false);

    let sections = findings_of_kind(&result, "pe_sections");
    let names: Vec<&str> = sections[0].details["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec![".text", ".rdata"]);

    let imports = findings_of_kind(&result, "pe_imports");
    assert_eq!(imports.len(), 1);
    let table = imports[0].details["imports"].as_array().unwrap();
    assert_eq!(table[0]["dll"], "KERNEL32.dll");
    assert_eq!(table[0]["functions"][0], "CreateFileW");
    assert_eq!(table[1]["dll"], "USER32.dll");
    assert_eq!(table[1]["functions"][0], "MessageBoxW");
    assert!(findings_of_kind(&result, "pe_exports").is_empty());
    assert!(findings_of_kind(&result, "dotnet_metadata").is_empty());
}

#[test]
fn pe32_fixture_reports_i386_shape() {
    let (service, _dir) = service_in_temp();
    let result = inspect(&service, &fixture("native/pe32-demo.exe"));
    let headers = findings_of_kind(&result, "pe_header");
    assert_eq!(headers[0].details["format"], "PE32");
    assert_eq!(headers[0].details["machine"], "Intel 386 (x86)");
    let imports = findings_of_kind(&result, "pe_imports");
    assert_eq!(imports[0].details["imports"][0]["dll"], "msvcrt.dll");
    assert_eq!(imports[0].details["imports"][0]["functions"][0], "printf");
}

#[test]
fn dotnet_fixture_yields_cli_metadata_inventory() {
    let (service, _dir) = service_in_temp();
    let result = inspect(&service, &fixture("native/dotnet-demo.exe"));
    let metadata = findings_of_kind(&result, "dotnet_metadata");
    assert_eq!(metadata.len(), 1);
    let details = &metadata[0].details;
    assert_eq!(details["runtime_version"], "2.5");
    assert_eq!(details["version_string"], "v4.0.30319");
    assert_eq!(details["entry_point_token"], "0x06000001");
    let streams: Vec<&str> = details["streams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(streams, vec!["#~", "#Strings", "#US", "#GUID", "#Blob"]);
    let headers = findings_of_kind(&result, "pe_header");
    assert_eq!(headers[0].details["managed"], true);
    assert!(result
        .report
        .limitations
        .iter()
        .any(|l| l.contains("inventory only")));
    // .NET rides on the PE import table too.
    let imports = findings_of_kind(&result, "pe_imports");
    assert_eq!(imports[0].details["imports"][0]["dll"], "KERNEL32.dll");
}

#[test]
fn dex_fixture_yields_verified_header_and_classes() {
    let (service, _dir) = service_in_temp();
    let result = inspect(&service, &fixture("native/classes-dex"));
    assert_eq!(result.report.summary["format"], "dex");
    let headers = findings_of_kind(&result, "dex_header");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].details["version"], "035");
    assert_eq!(headers[0].details["counts"]["classes"], 1);
    assert_eq!(headers[0].details["counts"]["strings"], 4);

    let checksum = findings_of_kind(&result, "dex_checksum");
    assert_eq!(checksum.len(), 1);
    assert_eq!(checksum[0].origin, vortex_evidence::Origin::Derived);
    assert_eq!(checksum[0].details["matches"], true);

    let classes = findings_of_kind(&result, "dex_classes");
    assert_eq!(classes[0].details["classes"][0], "Ldemo/Sample;");
}

#[test]
fn asar_fixture_lists_official_tool_archive() {
    let (service, _dir) = service_in_temp();
    let result = inspect(&service, &fixture("archives/demo.asar"));
    assert_eq!(result.report.summary["format"], "asar-archive");
    let archive = findings_of_kind(&result, "archive");
    assert_eq!(archive.len(), 1);
    assert_eq!(archive[0].details["format"], "asar");
    assert_eq!(archive[0].details["member_count"], 5);

    let members = findings_of_kind(&result, "archive_members");
    let paths: Vec<&str> = members[0].details["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths.len(), 5);
    assert!(paths.contains(&"package.json"));
    assert!(paths.contains(&"src/app/main.js"));
    let unpacked: Vec<_> = members[0].details["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["unpacked"] == serde_json::json!(true))
        .collect();
    assert_eq!(unpacked.len(), 1);
    assert_eq!(unpacked[0]["path"], "asset.bin");
}

#[test]
fn apk_zip_chain_reaches_dex_members() {
    // Build an APK-shaped zip at test time around the committed DEX fixture.
    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("demo-app.apk");
    let dex_bytes = std::fs::read(fixture("native/classes-dex")).unwrap();
    {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;
        let mut writer = ZipWriter::new(std::fs::File::create(&apk).unwrap());
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("AndroidManifest.xml", options).unwrap();
        writer.write_all(b"<manifest package=\"demo\"/>").unwrap();
        writer.start_file("classes.dex", options).unwrap();
        writer.write_all(&dex_bytes).unwrap();
        writer.start_file("res/layout/main.xml", options).unwrap();
        writer.write_all(b"<layout/>").unwrap();
        writer.finish().unwrap();
    }

    let (service, _dir2) = service_in_temp();
    let result = inspect(&service, &apk);
    assert_eq!(result.report.summary["format"], "zip");
    let archive = findings_of_kind(&result, "archive");
    assert_eq!(archive[0].details["looks_like_apk"], true);
    assert_eq!(archive[0].details["member_count"], 3);

    // The DEX chain: findings located inside `demo-app.apk!classes.dex`.
    let dex_headers = findings_of_kind(&result, "dex_header");
    assert_eq!(dex_headers.len(), 1, "one DEX member was parsed");
    assert_eq!(
        dex_headers[0]
            .location
            .as_ref()
            .and_then(|l| l.file.clone()),
        Some("demo-app.apk!classes.dex".to_string())
    );
    let checksum = findings_of_kind(&result, "dex_checksum");
    assert_eq!(checksum[0].details["matches"], true);
    let classes = findings_of_kind(&result, "dex_classes");
    assert_eq!(classes[0].details["classes"][0], "Ldemo/Sample;");
    assert!(result
        .report
        .limitations
        .iter()
        .any(|l| l.contains("not recursively inspected")));
}

#[test]
fn zip_safety_findings_reach_the_report() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("evil.zip");
    {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;
        let mut writer = ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
        let options = SimpleFileOptions::default();
        // Traversal and absolute names are stored verbatim.
        writer.start_file("../../etc/passwd", options).unwrap();
        writer.write_all(b"root:x:0:0").unwrap();
        writer.start_file("/absolute/path.txt", options).unwrap();
        writer.write_all(b"abs").unwrap();
        writer
            .add_symlink("evil-link", "/etc/passwd", options)
            .unwrap();
        writer.finish().unwrap();
    }
    let (service, _dir2) = service_in_temp();
    let result = inspect(&service, &zip_path);
    let safety = findings_of_kind(&result, "archive_safety");
    let kinds: Vec<&str> = safety
        .iter()
        .map(|f| f.details["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"path_traversal_name"), "{kinds:?}");
    assert!(kinds.contains(&"absolute_path_name"), "{kinds:?}");
    assert!(kinds.contains(&"symlink_member"), "{kinds:?}");
    for finding in safety {
        assert_eq!(finding.origin, vortex_evidence::Origin::Derived);
    }
}

#[test]
fn archive_findings_survive_evidence_round_trip() {
    // The full pipeline: inspect → persist → reload through the store, and
    // the structural findings must still validate against the schema.
    let (service, _dir) = service_in_temp();
    let result = inspect(&service, &fixture("native/elf64-demo"));
    let stored = service
        .store()
        .load(&result.run_id.clone().expect("run id"))
        .expect("stored run is retrievable");
    let problems = vortex_evidence::validate_run(&stored);
    assert!(problems.is_empty(), "{problems:?}");
    let kinds: Vec<&str> = stored.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains(&"elf_header"));
    assert!(kinds.contains(&"elf_sections"));
    assert!(kinds.contains(&"elf_imports"));
}
