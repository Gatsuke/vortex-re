//! The built-in static-analysis provider.
//!
//! Works fully offline on ordinary files: identity and digests, binary format
//! identification, printable strings, JavaScript/JSON content, package
//! manifests, and relationship discovery. It never executes the target and
//! never touches the network.
//!
//! Honest scope (mirrored in docs/PROVIDERS.md): this provider *identifies*
//! native executables (ELF/PE/Mach-O magic) and extracts their printable
//! strings, but it does **not** disassemble or decompile them. Requests that
//! would need a native-analysis engine produce an explicit
//! `unsupported_operation` limitation instead of fabricated results.

use crate::archive::{self, MemberRead};
use crate::identify::{self, FormatIdentification};
use crate::javascript::{self, ImportRef, PackageManifest, SpecifierKind};
use crate::native::{self, elf, pe};
use crate::provider::{
    AnalysisProvider, AnalysisRequest, Capability, ProviderDescriptor, ProviderReport,
    ReportBuilder, SearchQuery, StopReason,
};
use crate::search::SearchSession;
use crate::strings::extract_printable_strings;
use crate::tree::{self, WalkResult};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use vortex_core::digest::{directory_manifest_digest, sha256_bytes, sha256_file};
use vortex_core::error::VortexResult;
use vortex_core::limits::ResourceLimits;
use vortex_core::redact::redact_line;
use vortex_evidence::{ArtifactRef, Location, Node, Origin, Resolution, Scope};

/// Provider identifier for the built-in static analysis engine.
pub const BUILTIN_STATIC_ID: &str = "builtin-static";

/// Cap on manifests parsed per run (they are rare; the cap is a safety net).
const MAX_MANIFESTS: usize = 20;

/// Analyzed-file count between durable checkpoints. 25 keeps the worst
/// case cheap (a re-analysis of ≤24 files after a crash) while making the
/// extra write traffic negligible on multi-thousand-file runs.
const CHECKPOINT_EVERY: usize = 25;

/// Checkpoint phase label for the per-file analysis loops.
const PHASE_PER_FILE: &str = "per_file_analysis";

/// The offline built-in provider.
#[derive(Debug, Clone)]
pub struct BuiltinStaticProvider {
    descriptor: ProviderDescriptor,
}

impl BuiltinStaticProvider {
    /// Create the provider.
    pub fn new() -> Self {
        Self {
            descriptor: ProviderDescriptor {
                id: BUILTIN_STATIC_ID.to_string(),
                version: vortex_core::APP_VERSION.to_string(),
                capabilities: vec![
                    Capability::InspectFiles,
                    Capability::InspectDirectories,
                    Capability::SearchText,
                    Capability::TraceRelationships,
                    Capability::IdentifyBinaryFormats,
                    Capability::ExtractStrings,
                    Capability::ParsePackageManifest,
                    Capability::ParseJavascript,
                    Capability::InspectArchives,
                    Capability::ParseElf,
                    Capability::ParsePe,
                    Capability::ParseDex,
                ],
            },
        }
    }
}

impl Default for BuiltinStaticProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of a bounded content read.
enum ReadOutcome {
    /// The whole file was read.
    Full(Vec<u8>),
    /// Only a prefix was read; the second value is the full size.
    Truncated(Vec<u8>, u64),
    /// The read failed.
    Failed(String),
}

/// Read up to `max_bytes` from a file, tracking the total byte budget.
fn read_prefix(path: &Path, max_bytes: u64, budget: &mut u64, max_file_bytes: u64) -> ReadOutcome {
    if *budget == 0 {
        return ReadOutcome::Failed("total byte budget exhausted".to_string());
    }
    let allow = max_bytes.min(*budget).min(max_file_bytes);
    match std::fs::File::open(path) {
        Ok(file) => {
            use std::io::Read;
            let full_size = file.metadata().map(|m| m.len()).unwrap_or(0);
            let mut limited = file.take(allow);
            let mut buffer = Vec::new();
            match limited.read_to_end(&mut buffer) {
                Ok(read) => {
                    *budget = budget.saturating_sub(read as u64);
                    if (read as u64) < full_size {
                        ReadOutcome::Truncated(buffer, full_size)
                    } else {
                        ReadOutcome::Full(buffer)
                    }
                }
                Err(err) => ReadOutcome::Failed(err.to_string()),
            }
        }
        Err(err) => ReadOutcome::Failed(err.to_string()),
    }
}

/// Relativize an absolute path against the inspection root (forward slashes).
fn rel(root: &Path, abs: &Path) -> String {
    abs.strip_prefix(root)
        .map(|p| p.display().to_string().replace('\\', "/"))
        .unwrap_or_else(|_| abs.display().to_string().replace('\\', "/"))
}

/// Hash a file, reusing already-read bytes when they cover the whole file.
fn hash_file(abs: &Path, content: Option<&[u8]>) -> String {
    if let Some(bytes) = content {
        return sha256_bytes(bytes);
    }
    sha256_file(abs).unwrap_or_default()
}

/// Read-Only context shared by the provider operations.
struct OpContext<'a> {
    request: &'a AnalysisRequest,
    root: &'a Path,
    budget: u64,
}

impl<'a> OpContext<'a> {
    fn new(request: &'a AnalysisRequest) -> Self {
        // A resumed pass continues with the earlier pass's remaining budget
        // instead of a fresh one — budgets are per run, not per pass.
        let budget = request
            .resume
            .as_ref()
            .map(|resume| resume.bytes_remaining)
            .unwrap_or(request.limits.max_total_bytes);
        Self {
            request,
            root: &request.root,
            budget,
        }
    }

    fn limits(&self) -> &ResourceLimits {
        &self.request.limits
    }

    fn stop(&self) -> Option<StopReason> {
        self.request.stop_reason()
    }

    /// Where this pass continues from (0 for fresh runs).
    fn resume_from(&self) -> usize {
        self.request
            .resume
            .as_ref()
            .map(|r| r.from_index)
            .unwrap_or(0)
    }

    fn prior_scanned(&self) -> usize {
        self.request
            .resume
            .as_ref()
            .map(|r| r.prior_files_scanned)
            .unwrap_or(0)
    }

    fn prior_skipped(&self) -> usize {
        self.request
            .resume
            .as_ref()
            .map(|r| r.prior_files_skipped)
            .unwrap_or(0)
    }
}

/// Emit a durable checkpoint at `per_file_analysis` boundaries.
///
/// Called at the top of each loop iteration with `analyzed` = files completed
/// in this pass so far and `next_index` = the walk index about to be worked
/// on. Emissions are suppressed once a stop condition is observed — a
/// checkpoint is never written after cancellation (the commit rule).
fn maybe_checkpoint(
    ctx: &OpContext,
    builder: &ReportBuilder,
    analyzed: usize,
    next_index: usize,
    matches_remaining: Option<usize>,
) {
    let Some(sink) = &ctx.request.checkpoint_sink else {
        return;
    };
    if analyzed == 0 || !analyzed.is_multiple_of(CHECKPOINT_EVERY) {
        return;
    }
    if ctx.stop().is_some() {
        return; // cancelled or timed out at this boundary: no commit happens
    }
    let checkpoint = vortex_evidence::RunCheckpoint {
        phase: PHASE_PER_FILE.to_string(),
        next_file_index: next_index,
        files_scanned: ctx.prior_scanned() + builder.scanned_count(),
        files_skipped: ctx.prior_skipped() + builder.skipped_count(),
        saved_at: vortex_core::timeutil::now_rfc3339(),
        bytes_remaining: ctx.budget,
        matches_remaining: matches_remaining.map(|m| m as u64),
    };
    sink(&checkpoint, &builder.progress_snapshot());
}

/// Id offsets for a resumed pass (0 for fresh runs).
fn offsets_of(request: &AnalysisRequest) -> (usize, usize) {
    request
        .resume
        .as_ref()
        .map(|resume| (resume.finding_offset, resume.relationship_offset))
        .unwrap_or((0, 0))
}

impl AnalysisProvider for BuiltinStaticProvider {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }

    fn validate_request(&self, _request: &AnalysisRequest) -> VortexResult<()> {
        // The built-in provider degrades gracefully on any input; unsupported
        // deeper analysis is reported per-run through limitations.
        Ok(())
    }

    fn inspect(&self, request: &AnalysisRequest) -> ProviderReport {
        let mut ctx = OpContext::new(request);
        let (finding_offset, relationship_offset) = offsets_of(request);
        let mut builder = ReportBuilder::new_with_offsets(
            request.limits.clone(),
            finding_offset,
            relationship_offset,
        );
        let summary = match request.target.kind {
            vortex_core::paths::TargetKind::File => inspect_file(&mut ctx, &mut builder),
            vortex_core::paths::TargetKind::Directory => inspect_directory(&mut ctx, &mut builder),
        };
        let stop = ctx.stop();
        finish_report(builder, summary, stop)
    }

    fn search(&self, request: &AnalysisRequest, query: &SearchQuery) -> ProviderReport {
        let mut ctx = OpContext::new(request);
        let (finding_offset, relationship_offset) = offsets_of(request);
        let mut builder = ReportBuilder::new_with_offsets(
            request.limits.clone(),
            finding_offset,
            relationship_offset,
        );
        if query.text.is_empty() {
            builder.error(
                "validation",
                "search query must not be empty",
                Some("search"),
            );
            return builder.finish(serde_json::json!({}), None);
        }
        let summary = match request.target.kind {
            vortex_core::paths::TargetKind::File => {
                search_file_target(&mut ctx, &mut builder, query)
            }
            vortex_core::paths::TargetKind::Directory => {
                search_directory(&mut ctx, &mut builder, query)
            }
        };
        let stop = ctx.stop();
        builder.finish(summary, stop)
    }

    fn relationships(&self, request: &AnalysisRequest) -> ProviderReport {
        let mut ctx = OpContext::new(request);
        let (finding_offset, relationship_offset) = offsets_of(request);
        let mut builder = ReportBuilder::new_with_offsets(
            request.limits.clone(),
            finding_offset,
            relationship_offset,
        );
        if request.checkpoint_sink.is_some() || request.resume.is_some() {
            builder.limitation(
                "checkpoints and resume are not supported for relationship analysis in this \
                 release; the request was processed without them",
            );
        }
        let summary = relationships_impl(&mut ctx, &mut builder);
        let stop = ctx.stop();
        builder.finish(summary, stop)
    }
}

fn finish_report(
    builder: ReportBuilder,
    summary: serde_json::Value,
    stop: Option<StopReason>,
) -> ProviderReport {
    builder.finish(summary, stop)
}

/// Standard limitations that apply whenever JavaScript is scanned.
fn javascript_scan_limitation(builder: &mut ReportBuilder) {
    builder.limitation(
        "JavaScript import scanning is line-oriented and heuristic: comments are not stripped, \
         so import-like text inside comments may be reported, and unusual statement layouts \
         may be missed. Statements were observed; they do not prove runtime behavior.",
    );
}

// ---------------------------------------------------------------------------
// inspect: single file
// ---------------------------------------------------------------------------

fn inspect_file(ctx: &mut OpContext, builder: &mut ReportBuilder) -> serde_json::Value {
    let abs = ctx.request.target.canonical.clone();
    let rel_path = rel(ctx.root, &abs);
    let max_file_bytes = ctx.limits().max_file_bytes;
    let outcome = read_prefix(&abs, u64::MAX, &mut ctx.budget, max_file_bytes);
    let (content, full_size) = match &outcome {
        ReadOutcome::Full(bytes) => (Some(bytes.clone()), bytes.len() as u64),
        ReadOutcome::Truncated(bytes, size) => (Some(bytes.clone()), *size),
        ReadOutcome::Failed(error) => {
            builder.scanned();
            builder.error(
                "io",
                format!("cannot read {rel_path}: {error}"),
                Some("inspect"),
            );
            builder.limitation(format!(
                "file {rel_path} could not be read; only identity is reported"
            ));
            return serde_json::json!({
                "kind": "file", "path": rel_path, "status": "unreadable",
                "sha256": sha256_file(&abs).unwrap_or_default(),
            });
        }
    };
    builder.scanned();
    let prefix = content.as_deref().unwrap_or_default();
    let identification = identify::identify(&abs, prefix);
    let sha256 = hash_file(&abs, content.as_deref());

    let artifact = ArtifactRef {
        path: rel_path.clone(),
        sha256: sha256.clone(),
        size_bytes: full_size,
    };
    builder.finding(
        "file",
        Origin::Observed,
        format!("file '{rel_path}' ({full_size} bytes)"),
        Some(Location::file(&rel_path)),
        Some(artifact.clone()),
        serde_json::json!({
            "path": rel_path,
            "size_bytes": full_size,
            "sha256": sha256,
            "read_truncated": matches!(outcome, ReadOutcome::Truncated(..)),
        }),
    );
    builder.finding(
        "format",
        Origin::Derived,
        format!(
            "format: {} ({})",
            identification.format, identification.basis
        ),
        Some(Location::file(&rel_path)),
        Some(artifact.clone()),
        serde_json::json!({
            "format": identification.format,
            "label": identification.label,
            "basis": identification.basis,
            "magic_hex": identification.magic_hex,
        }),
    );
    if let ReadOutcome::Truncated(..) = outcome {
        builder.limitation(format!(
            "content analysis of {rel_path} used only the first {} bytes of {full_size}",
            prefix.len()
        ));
    }

    let is_text = identify::looks_like_text(prefix);
    let mut text_stats = None;
    let mut module_systems = Vec::new();
    if is_text {
        let text = String::from_utf8_lossy(prefix);
        let line_count = text.lines().count() as u64;
        text_stats = Some(line_count);
        builder.finding(
            "text_stats",
            Origin::Observed,
            format!("{rel_path}: {line_count} lines of text"),
            Some(Location::file(&rel_path)),
            Some(artifact.clone()),
            serde_json::json!({ "line_count": line_count, "byte_len": prefix.len() }),
        );

        let is_js =
            identification.format == "javascript" || identification.format == "javascript-dialect";
        if is_js {
            javascript_scan_limitation(builder);
            module_systems = javascript::detect_module_systems(&text);
            let (imports, imports_truncated) =
                javascript::scan_imports(&text, ctx.limits().max_imports_per_file);
            let mut by_syntax = BTreeMap::new();
            for import in &imports {
                *by_syntax.entry(import.syntax.as_str()).or_insert(0usize) += 1;
            }
            if imports_truncated {
                builder.limitation(format!(
                    "import scan of {rel_path} stopped at {} references (limit)",
                    ctx.limits().max_imports_per_file
                ));
            }
            builder.finding(
                "imports_summary",
                Origin::Observed,
                format!("{rel_path}: {} import reference(s)", imports.len()),
                Some(Location::file(&rel_path)),
                Some(artifact.clone()),
                serde_json::json!({
                    "count": imports.len(),
                    "by_syntax": by_syntax,
                    "module_systems": module_systems.iter().map(|m| m.as_str()).collect::<Vec<_>>(),
                    "imports": imports.iter().map(|i| serde_json::json!({
                        "syntax": i.syntax.as_str(),
                        "specifier": i.specifier,
                        "line": i.line,
                        "column": i.column,
                    })).collect::<Vec<_>>(),
                }),
            );
            for map_ref in javascript::scan_source_map_refs(&text) {
                builder.finding(
                    "sourcemap_reference",
                    Origin::Observed,
                    format!(
                        "{rel_path}:{} references source map '{}'",
                        map_ref.line, map_ref.url
                    ),
                    Some(Location::file_line_column(
                        &rel_path,
                        map_ref.line,
                        map_ref.column,
                    )),
                    Some(artifact.clone()),
                    serde_json::json!({
                        "url": map_ref.url,
                        "inline": map_ref.inline,
                        "line": map_ref.line,
                        "column": map_ref.column,
                    }),
                );
            }
        }

        if identification.format == "json" || identification.format == "sourcemap-json" {
            match serde_json::from_slice::<serde_json::Value>(prefix) {
                Ok(value) => {
                    let top_level_keys = value
                        .as_object()
                        .map(|object| object.keys().cloned().collect::<Vec<_>>())
                        .unwrap_or_default();
                    let is_sourcemap = top_level_keys.iter().any(|k| k == "version")
                        && top_level_keys.iter().any(|k| k == "mappings");
                    builder.finding(
                        "json_document",
                        Origin::Observed,
                        format!("{rel_path}: valid JSON with {} top-level key(s)", top_level_keys.len()),
                        Some(Location::file(&rel_path)),
                        Some(artifact.clone()),
                        serde_json::json!({
                            "top_level_keys": top_level_keys.iter().take(20).cloned().collect::<Vec<_>>(),
                            "source_map": is_sourcemap,
                        }),
                    );
                    if is_sourcemap {
                        builder.finding(
                            "sourcemap_file",
                            Origin::Observed,
                            format!("{rel_path}: source map document (version/mappings present)"),
                            Some(Location::file(&rel_path)),
                            Some(artifact.clone()),
                            serde_json::json!({
                                "sources": value.get("sources").and_then(|s| s.as_array()).map(|a| a.len()),
                            }),
                        );
                    }
                }
                Err(err) => {
                    builder.warning(format!(
                        "{rel_path}: identified as JSON by extension but parsing failed: {err}"
                    ));
                }
            }
        }

        if abs.file_name().and_then(|n| n.to_str()) == Some("package.json") {
            record_manifest_findings(builder, &rel_path, prefix, &sha256, full_size, ctx.root);
        }
    } else {
        let (extracted, truncated) = extract_printable_strings(
            prefix,
            ctx.limits().min_string_length,
            ctx.limits().max_string_length,
            ctx.limits().max_strings_per_file,
        );
        let mut values = Vec::new();
        for extracted_string in &extracted {
            let (redacted, redactions) = redact_line(&extracted_string.value);
            for redaction in redactions {
                builder.redaction(
                    redaction.rule,
                    redaction.reason.clone(),
                    Some(Location {
                        file: Some(rel_path.clone()),
                        line: None,
                        column: None,
                        byte_offset: Some(extracted_string.byte_offset),
                    }),
                );
            }
            values.push(serde_json::json!({
                "value": redacted,
                "byte_offset": extracted_string.byte_offset,
            }));
        }
        if truncated {
            builder.limitation(format!(
                "string extraction from {rel_path} stopped at {} strings (limit)",
                ctx.limits().max_strings_per_file
            ));
        }
        builder.finding(
            "strings_sample",
            Origin::Observed,
            format!("{rel_path}: {} printable string(s) extracted", values.len()),
            Some(Location::file(&rel_path)),
            Some(artifact.clone()),
            serde_json::json!({
                "count": values.len(),
                "min_length": ctx.limits().min_string_length,
                "max_length": ctx.limits().max_string_length,
                "truncated": truncated,
                "strings": values,
            }),
        );
        let structural = matches!(
            identification.format.as_str(),
            "elf" | "pe" | "dex" | "zip" | "asar-archive"
        );
        if structural {
            builder.limitation(
                "binary content: printable strings plus structural parsing; no disassembly, \
                 decompilation, or behavioral analysis is performed by the built-in provider",
            );
        } else {
            builder.limitation(
                "binary content: identification and printable-string extraction only; no \
                 disassembly or decompilation is performed by the built-in provider",
            );
        }
        native_analysis_limitation(builder, &identification);
        dispatch_structural_analysis(ctx, builder, &identification, &rel_path, &artifact, prefix);
    }

    let mut summary = serde_json::json!({
        "kind": "file",
        "path": rel_path,
        "size_bytes": full_size,
        "sha256": sha256,
        "format": identification.format,
        "format_basis": identification.basis,
        "text": is_text,
    });
    if let Some(line_count) = text_stats {
        summary["line_count"] = serde_json::json!(line_count);
    }
    if !module_systems.is_empty() {
        summary["module_systems"] = serde_json::json!(module_systems
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>());
    }
    summary
}

fn native_analysis_limitation(builder: &mut ReportBuilder, identification: &FormatIdentification) {
    // ELF, PE, and DEX have structural parsers in this release; the formats
    // below still need a native-analysis engine for anything beyond
    // identification, strings, and (for Mach-O) nothing at all.
    let native = matches!(
        identification.format.as_str(),
        "mach-o-32" | "mach-o-64" | "mach-o-fat" | "wasm"
    );
    if native {
        builder.limitation(format!(
            "artifact format '{}' requires a native-analysis provider for deeper inspection; \
             none is integrated in this release (see docs/PROVIDERS.md)",
            identification.format
        ));
        builder.error(
            "unsupported_operation",
            format!(
                "deep inspection of {} artifacts is not implemented by the built-in provider",
                identification.format
            ),
            Some("inspect"),
        );
    }
}

// ---------------------------------------------------------------------------
// structural analysis: dispatch + per-format finders
// ---------------------------------------------------------------------------

/// Run the format-specific structural parser for identified native and
/// archive formats. Formats without a parser are ignored here (their
/// unsupported_operation error was emitted above).
#[allow(clippy::too_many_arguments)]
fn dispatch_structural_analysis(
    ctx: &mut OpContext,
    builder: &mut ReportBuilder,
    identification: &FormatIdentification,
    rel_path: &str,
    artifact: &ArtifactRef,
    prefix: &[u8],
) {
    match identification.format.as_str() {
        "elf" => record_elf(builder, rel_path, artifact, prefix, ctx.limits()),
        "pe" => record_pe(builder, rel_path, artifact, prefix, ctx.limits()),
        "dex" => record_dex(builder, rel_path, artifact, prefix, ctx.limits()),
        "zip" => record_zip(ctx, builder, rel_path, artifact),
        "asar-archive" => record_asar(ctx, builder, rel_path, artifact),
        _ => {}
    }
}

fn record_elf(
    builder: &mut ReportBuilder,
    location: &str,
    artifact: &ArtifactRef,
    bytes: &[u8],
    limits: &ResourceLimits,
) {
    match native::elf::parse(bytes) {
        Ok(file) => {
            let class = if file.class == 2 { "64-bit" } else { "32-bit" };
            let endianness = if file.big_endian { "big" } else { "little" };
            builder.finding(
                "elf_header",
                Origin::Observed,
                format!(
                    "{location}: {class} {endianness}-endian ELF, {}, {}, entry 0x{:x}",
                    elf::elf_type_name(file.elf_type),
                    elf::machine_name(file.machine),
                    file.entry
                ),
                Some(Location::file(location)),
                Some(artifact.clone()),
                serde_json::json!({
                    "class": class,
                    "endianness": endianness,
                    "type": elf::elf_type_name(file.elf_type),
                    "type_raw": file.elf_type,
                    "machine": elf::machine_name(file.machine),
                    "machine_raw": file.machine,
                    "os_abi": elf::osabi_name(file.os_abi),
                    "os_abi_raw": file.os_abi,
                    "entry_point": file.entry,
                    "program_headers": file.phnum,
                    "section_count": file.section_total,
                }),
            );
            if !file.sections.is_empty() {
                let truncated = file.sections.len() > limits.max_entries;
                let sections: Vec<_> = file
                    .sections
                    .iter()
                    .take(limits.max_entries)
                    .map(|s| {
                        serde_json::json!({
                            "name": s.name,
                            "type": elf::section_type_name(s.sh_type),
                            "type_raw": s.sh_type,
                            "size": s.size,
                            "offset": s.offset,
                        })
                    })
                    .collect();
                builder.finding(
                    "elf_sections",
                    Origin::Observed,
                    format!(
                        "{location}: {} section(s) listed of {}",
                        sections.len(),
                        file.section_total
                    ),
                    Some(Location::file(location)),
                    Some(artifact.clone()),
                    serde_json::json!({
                        "count": file.sections.len(),
                        "total": file.section_total,
                        "truncated": truncated,
                        "sections": sections,
                    }),
                );
            } else if let Some(reason) = &file.sections_reason {
                builder.limitation(format!(
                    "{location}: ELF section table unavailable: {reason}"
                ));
            }
            if !file.imports.is_empty() {
                let truncated = file.imports.len() > limits.max_entries;
                let imports: Vec<&str> = file
                    .imports
                    .iter()
                    .take(limits.max_entries)
                    .map(String::as_str)
                    .collect();
                builder.finding(
                    "elf_imports",
                    Origin::Observed,
                    format!(
                        "{location}: {} undefined dynamic symbol(s)",
                        file.imports.len()
                    ),
                    Some(Location::file(location)),
                    Some(artifact.clone()),
                    serde_json::json!({
                        "count": file.imports.len(),
                        "truncated": truncated,
                        "symbols": imports,
                    }),
                );
            } else if let Some(reason) = &file.imports_reason {
                builder.limitation(format!("{location}: ELF imports unavailable: {reason}"));
            }
            builder.limitation(format!(
                "{location}: ELF analysis is structural only — header, sections, and undefined \
                 dynamic symbols; no disassembly, decompilation, relocation analysis, or \
                 behavioral claims"
            ));
        }
        Err(reason) => {
            builder.warning(format!(
                "{location}: identified as ELF but structural parsing failed: {reason}"
            ));
            builder.limitation(format!("{location}: ELF structure unavailable ({reason})"));
        }
    }
}

fn record_pe(
    builder: &mut ReportBuilder,
    location: &str,
    artifact: &ArtifactRef,
    bytes: &[u8],
    limits: &ResourceLimits,
) {
    match native::pe::parse(bytes) {
        Ok(file) => {
            let format = if file.magic == 0x20B { "PE32+" } else { "PE32" };
            builder.finding(
                "pe_header",
                Origin::Observed,
                format!(
                    "{location}: {format} image, {}, {}",
                    pe::machine_name(file.machine),
                    pe::subsystem_name(file.subsystem)
                ),
                Some(Location::file(location)),
                Some(artifact.clone()),
                serde_json::json!({
                    "format": format,
                    "machine": pe::machine_name(file.machine),
                    "machine_raw": file.machine,
                    "characteristics": pe::coff_characteristics_summary(file.characteristics),
                    "characteristics_raw": file.characteristics,
                    "timestamp": file.timestamp,
                    "timestamp_rfc3339": pe::timestamp_rfc3339(file.timestamp),
                    "entry_point_rva": file.entry_point,
                    "subsystem": pe::subsystem_name(file.subsystem),
                    "subsystem_raw": file.subsystem,
                    "section_count": file.sections.len(),
                    "managed": file.dotnet.is_some(),
                }),
            );
            if !file.sections.is_empty() {
                let truncated = file.sections.len() > limits.max_entries;
                let sections: Vec<_> = file
                    .sections
                    .iter()
                    .take(limits.max_entries)
                    .map(|s| {
                        serde_json::json!({
                            "name": s.name,
                            "virtual_size": s.virtual_size,
                            "virtual_address": s.virtual_address,
                            "raw_size": s.raw_size,
                            "flags": pe::section_flags_summary(s.characteristics),
                        })
                    })
                    .collect();
                builder.finding(
                    "pe_sections",
                    Origin::Observed,
                    format!("{location}: {} section(s)", file.sections.len()),
                    Some(Location::file(location)),
                    Some(artifact.clone()),
                    serde_json::json!({
                        "count": file.sections.len(),
                        "truncated": truncated,
                        "sections": sections,
                    }),
                );
            } else if let Some(reason) = &file.sections_reason {
                builder.limitation(format!(
                    "{location}: PE section table unavailable: {reason}"
                ));
            }
            if !file.imports.is_empty() {
                let truncated = file.imports.len() > limits.max_entries;
                let imports: Vec<_> = file
                    .imports
                    .iter()
                    .take(limits.max_entries)
                    .map(|dll| {
                        let functions_truncated = dll.functions.len() > limits.max_entries;
                        serde_json::json!({
                            "dll": dll.dll,
                            "functions": dll.functions.iter().take(limits.max_entries)
                                .collect::<Vec<_>>(),
                            "function_count": dll.functions.len(),
                            "functions_truncated": functions_truncated,
                            "ordinal_imports": dll.ordinal_count,
                        })
                    })
                    .collect();
                builder.finding(
                    "pe_imports",
                    Origin::Observed,
                    format!("{location}: {} imported DLL(s)", file.imports.len()),
                    Some(Location::file(location)),
                    Some(artifact.clone()),
                    serde_json::json!({
                        "count": file.imports.len(),
                        "truncated": truncated,
                        "imports": imports,
                    }),
                );
            } else if let Some(reason) = &file.imports_reason {
                builder.limitation(format!("{location}: PE imports unavailable: {reason}"));
            }
            if !file.exports.is_empty() {
                let truncated = file.exports.len() > limits.max_entries;
                let exports: Vec<&str> = file
                    .exports
                    .iter()
                    .take(limits.max_entries)
                    .map(String::as_str)
                    .collect();
                builder.finding(
                    "pe_exports",
                    Origin::Observed,
                    format!("{location}: {} exported name(s)", file.exports.len()),
                    Some(Location::file(location)),
                    Some(artifact.clone()),
                    serde_json::json!({
                        "count": file.exports.len(),
                        "truncated": truncated,
                        "names": exports,
                    }),
                );
            }
            if let Some(dotnet) = &file.dotnet {
                let streams: Vec<_> = dotnet
                    .streams
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "name": s.name,
                            "offset": s.offset,
                            "size": s.size,
                        })
                    })
                    .collect();
                builder.finding(
                    "dotnet_metadata",
                    Origin::Observed,
                    format!(
                        "{location}: .NET assembly, runtime {}.{} ({}), {} metadata stream(s)",
                        dotnet.runtime_version.0,
                        dotnet.runtime_version.1,
                        dotnet.version_string,
                        dotnet.streams.len()
                    ),
                    Some(Location::file(location)),
                    Some(artifact.clone()),
                    serde_json::json!({
                        "runtime_version": format!("{}.{}", dotnet.runtime_version.0, dotnet.runtime_version.1),
                        "version_string": dotnet.version_string,
                        "entry_point_token": format!("0x{:08x}", dotnet.entry_point_token),
                        "flags": dotnet.flags,
                        "streams": streams,
                    }),
                );
                builder.limitation(format!(
                    "{location}: .NET analysis is an inventory only — runtime version, \
                     entry-point token, and metadata stream names/sizes; no type system, \
                     CIL decoding, or member listing"
                ));
            } else if let Some(reason) = &file.dotnet_reason {
                builder.limitation(format!("{location}: .NET metadata unavailable: {reason}"));
            }
            builder.limitation(format!(
                "{location}: PE analysis is structural only — headers, sections, import and \
                 export names; no disassembly, decompilation, or behavioral claims"
            ));
        }
        Err(reason) => {
            builder.warning(format!(
                "{location}: identified as PE but structural parsing failed: {reason}"
            ));
            builder.limitation(format!("{location}: PE structure unavailable ({reason})"));
        }
    }
}

fn record_dex(
    builder: &mut ReportBuilder,
    location: &str,
    artifact: &ArtifactRef,
    bytes: &[u8],
    limits: &ResourceLimits,
) {
    match native::dex::parse(bytes) {
        Ok(file) => {
            builder.finding(
                "dex_header",
                Origin::Observed,
                format!(
                    "{location}: DEX version {} with {} class definition(s)",
                    file.version, file.counts.classes
                ),
                Some(Location::file(location)),
                Some(artifact.clone()),
                serde_json::json!({
                    "version": file.version,
                    "file_size": file.file_size,
                    "declared_file_size": file.file_size,
                    "available_bytes": file.available_bytes,
                    "endian_tag_ok": file.endian_tag == 0x12345678,
                    "counts": {
                        "strings": file.counts.strings,
                        "types": file.counts.types,
                        "protos": file.counts.protos,
                        "fields": file.counts.fields,
                        "methods": file.counts.methods,
                        "classes": file.counts.classes,
                    },
                }),
            );
            match file.checksum_matches {
                Some(matches) => {
                    let (summary, matches_flag) = if matches {
                        ("adler32 checksum matches the file contents", true)
                    } else {
                        ("adler32 checksum DOES NOT match the file contents", false)
                    };
                    builder.finding(
                        "dex_checksum",
                        Origin::Derived,
                        format!("{location}: {summary}"),
                        Some(Location::file(location)),
                        Some(artifact.clone()),
                        serde_json::json!({
                            "algorithm": "adler32",
                            "stored": format!("0x{:08x}", file.stored_checksum),
                            "computed": file.computed_checksum.map(|v| format!("0x{v:08x}")),
                            "matches": matches_flag,
                        }),
                    );
                }
                None => {
                    builder.limitation(format!(
                        "{location}: DEX checksum not verified — the whole file was not read"
                    ));
                }
            }
            if let Some(reason) = &file.counts_reason {
                builder.limitation(format!("{location}: DEX header concerns: {reason}"));
            }
            if !file.classes.is_empty() {
                let truncated = file.classes.len() > limits.max_entries;
                let classes: Vec<&str> = file
                    .classes
                    .iter()
                    .take(limits.max_entries)
                    .map(String::as_str)
                    .collect();
                builder.finding(
                    "dex_classes",
                    Origin::Observed,
                    format!("{location}: {} defined class(es)", file.classes.len()),
                    Some(Location::file(location)),
                    Some(artifact.clone()),
                    serde_json::json!({
                        "count": file.classes.len(),
                        "truncated": truncated,
                        "classes": classes,
                    }),
                );
            } else if let Some(reason) = &file.classes_reason {
                builder.limitation(format!("{location}: DEX class list unavailable: {reason}"));
            }
            builder.limitation(format!(
                "{location}: DEX analysis is structural only — header, table counts, and the \
                 defined-class list; no bytecode, proto, field, or method analysis"
            ));
        }
        Err(reason) => {
            builder.warning(format!(
                "{location}: identified as DEX but structural parsing failed: {reason}"
            ));
            builder.limitation(format!("{location}: DEX structure unavailable ({reason})"));
        }
    }
}

/// Zip-family archives: member listing, safety notes, and the APK → DEX
/// chain (bounded reads of `classes*.dex` members).
fn record_zip(
    ctx: &mut OpContext,
    builder: &mut ReportBuilder,
    location: &str,
    artifact: &ArtifactRef,
) {
    let abs = ctx.request.target.canonical.clone();
    match archive::zip_reader::list(&abs, ctx.limits()) {
        Ok(listing) => {
            let mut methods: BTreeMap<&str, usize> = BTreeMap::new();
            for member in &listing.members {
                *methods.entry(member.method).or_insert(0) += 1;
            }
            let kind = if listing.looks_like_apk {
                "zip (APK-shaped: AndroidManifest.xml and classes*.dex present)"
            } else {
                "zip"
            };
            builder.finding(
                "archive",
                Origin::Observed,
                format!(
                    "{location}: {kind} with {} member(s)",
                    listing.total_members
                ),
                Some(Location::file(location)),
                Some(artifact.clone()),
                serde_json::json!({
                    "format": "zip",
                    "member_count": listing.total_members,
                    "listed": listing.members.len(),
                    "truncated": listing.truncated,
                    "methods": methods,
                    "looks_like_apk": listing.looks_like_apk,
                }),
            );
            let members: Vec<_> = listing
                .members
                .iter()
                .take(ctx.limits().max_entries)
                .map(|m| {
                    serde_json::json!({
                        "name": m.name,
                        "size": m.size,
                        "compressed_size": m.compressed_size,
                        "method": m.method,
                        "readable": m.readable,
                        "is_dir": m.is_dir,
                    })
                })
                .collect();
            builder.finding(
                "archive_members",
                Origin::Observed,
                format!(
                    "{location}: {} member(s) listed of {}",
                    members.len(),
                    listing.total_members
                ),
                Some(Location::file(location)),
                Some(artifact.clone()),
                serde_json::json!({
                    "count": listing.members.len(),
                    "total": listing.total_members,
                    "truncated": listing.members.len() > ctx.limits().max_entries,
                    "members": members,
                }),
            );
            for note in &listing.safety {
                builder.finding(
                    "archive_safety",
                    Origin::Derived,
                    format!(
                        "{location}: member {:?}: {}",
                        note.member,
                        note.kind.as_str()
                    ),
                    Some(Location::file(location)),
                    Some(artifact.clone()),
                    serde_json::json!({
                        "kind": note.kind.as_str(),
                        "member": note.member,
                        "detail": note.detail,
                    }),
                );
            }
            for error in &listing.errors {
                builder.warning(format!("{location}: {error}"));
            }
            // APK chain: read classes*.dex members (bounded) and parse them.
            if listing.looks_like_apk {
                let dex_members: Vec<&archive::zip_reader::ZipMember> = listing
                    .members
                    .iter()
                    .filter(|m| archive::zip_reader::is_dex_member_name(&m.name))
                    .collect();
                let capped = dex_members.len().min(8);
                if dex_members.len() > 8 {
                    builder.limitation(format!(
                        "{location}: {} DEX members found; only the first 8 were read",
                        dex_members.len()
                    ));
                }
                for member in dex_members.iter().take(capped) {
                    if !member.readable {
                        builder.warning(format!(
                            "{location}: DEX member {} is not readable (method or encryption); skipped",
                            member.name
                        ));
                        continue;
                    }
                    let limits = ctx.limits().clone();
                    let read = archive::zip_reader::read_member(
                        &abs,
                        &member.name,
                        &limits,
                        &mut ctx.budget,
                    );
                    record_zip_member_dex(read, &member.name, location, artifact, builder, &limits);
                }
            }
            builder.limitation(format!(
                "{location}: archive members are read in memory under bounded budgets; nothing \
                 is written to disk, nested archives are listed but not recursively inspected, \
                 and text search does not enter archive members in this release"
            ));
        }
        Err(reason) => {
            builder.warning(format!(
                "{location}: identified as a zip container but the archive could not be read: {reason}"
            ));
            builder.limitation(format!(
                "{location}: archive members unavailable ({reason})"
            ));
        }
    }
}

/// Handle one bounded DEX member read: full reads parse directly,
/// truncated reads parse the prefix with an explicit limitation, failed
/// reads warn and move on.
fn record_zip_member_dex(
    read: MemberRead,
    member: &str,
    location: &str,
    artifact: &ArtifactRef,
    builder: &mut ReportBuilder,
    limits: &ResourceLimits,
) {
    match read {
        MemberRead::Full(bytes) => {
            let member_location = format!("{location}!{member}");
            record_dex(builder, &member_location, artifact, &bytes, limits);
        }
        MemberRead::Truncated(bytes, full) => {
            let member_location = format!("{location}!{member}");
            builder.limitation(format!(
                "{member_location}: DEX member is {full} bytes; only the first {} were read",
                bytes.len()
            ));
            record_dex(builder, &member_location, artifact, &bytes, limits);
        }
        MemberRead::Failed(reason) => builder.warning(format!(
            "{location}: DEX member {member} could not be read: {reason}"
        )),
    }
}

fn record_asar(
    ctx: &mut OpContext,
    builder: &mut ReportBuilder,
    location: &str,
    artifact: &ArtifactRef,
) {
    let abs = ctx.request.target.canonical.clone();
    match archive::asar::list(&abs, ctx.limits()) {
        Ok(listing) => {
            builder.finding(
                "archive",
                Origin::Observed,
                format!(
                    "{location}: asar archive with {} member(s)",
                    listing.total_members
                ),
                Some(Location::file(location)),
                Some(artifact.clone()),
                serde_json::json!({
                    "format": "asar",
                    "member_count": listing.total_members,
                    "listed": listing.members.len(),
                    "truncated": listing.truncated,
                    "header_size": listing.header_size,
                }),
            );
            let members: Vec<_> = listing
                .members
                .iter()
                .take(ctx.limits().max_entries)
                .map(|m| {
                    serde_json::json!({
                        "path": m.path,
                        "size": m.size,
                        "unpacked": m.unpacked,
                        "executable": m.executable,
                        "integrity": m.integrity,
                    })
                })
                .collect();
            builder.finding(
                "archive_members",
                Origin::Observed,
                format!(
                    "{location}: {} member(s) listed of {}",
                    members.len(),
                    listing.total_members
                ),
                Some(Location::file(location)),
                Some(artifact.clone()),
                serde_json::json!({
                    "count": listing.members.len(),
                    "total": listing.total_members,
                    "truncated": listing.members.len() > ctx.limits().max_entries,
                    "members": members,
                }),
            );
            for error in &listing.errors {
                builder.warning(format!("{location}: {error}"));
            }
            builder.limitation(format!(
                "{location}: asar members are listed from the JSON header; packed content reads \
                 are bounded and in memory, unpacked members (stored beside the archive) are \
                 listed but not read, and nothing is written to disk"
            ));
        }
        Err(reason) => {
            builder.warning(format!(
                "{location}: identified as an asar archive but it could not be read: {reason}"
            ));
            builder.limitation(format!("{location}: asar members unavailable ({reason})"));
        }
    }
}

// ---------------------------------------------------------------------------
// inspect: directory
// ---------------------------------------------------------------------------

fn inspect_directory(ctx: &mut OpContext, builder: &mut ReportBuilder) -> serde_json::Value {
    let walk_result = tree::walk(ctx.root, ctx.limits(), &|| ctx.stop());
    record_walk(builder, &walk_result);

    let mut by_extension: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_format: BTreeMap<String, usize> = BTreeMap::new();
    let mut hashed: Vec<(String, String)> = Vec::new();
    // Cross-pass counters: caps like MAX_MANIFESTS and max_entries limit the
    // *run*, so a resumed pass starts from what earlier passes consumed.
    let mut manifest_reports = ctx
        .request
        .resume
        .as_ref()
        .map(|resume| resume.manifests_parsed)
        .unwrap_or(0);
    let mut entry_point: Option<(String, String)> = None; // (manifest rel, entry rel)
    let mut electron = false;
    let mut sourcemap_refs = ctx
        .request
        .resume
        .as_ref()
        .map(|resume| resume.entries_used)
        .unwrap_or(0);

    for (index, entry) in walk_result.files.iter().enumerate() {
        // Files analyzed in an earlier pass are skipped entirely.
        if index < ctx.resume_from() {
            continue;
        }
        // Durable checkpoint at `per_file_analysis` boundaries.
        maybe_checkpoint(ctx, builder, index - ctx.resume_from(), index, None);
        if let Some(StopReason::Deadline | StopReason::Cancelled) = ctx.stop() {
            break;
        }
        let rel_path = entry.rel_path.display().to_string().replace('\\', "/");
        let extension = entry
            .rel_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_else(|| "<none>".to_string());
        *by_extension.entry(extension).or_insert(0) += 1;

        let max_file_bytes = ctx.limits().max_file_bytes;
        let outcome = read_prefix(&entry.abs_path, 64 * 1024, &mut ctx.budget, max_file_bytes);
        let prefix = match outcome {
            ReadOutcome::Full(bytes) | ReadOutcome::Truncated(bytes, _) => bytes,
            ReadOutcome::Failed(error) => {
                builder.warning(format!("{rel_path}: unreadable ({error})"));
                builder.skipped();
                continue;
            }
        };
        let identification = identify::identify(&entry.abs_path, &prefix);
        *by_format.entry(identification.format.clone()).or_insert(0) += 1;
        builder.scanned();

        // Hash: reuse the prefix when it covered the file, else stream.
        let sha256 = if entry.size <= prefix.len() as u64 {
            sha256_bytes(&prefix)
        } else {
            match sha256_file(&entry.abs_path) {
                Ok(digest) => digest,
                Err(_) => {
                    builder.warning(format!("{rel_path}: hashing failed"));
                    continue;
                }
            }
        };
        hashed.push((rel_path.clone(), sha256.clone()));

        let is_text = identify::looks_like_text(&prefix);
        let notable_binary = !is_text && matches!(identification.basis, "magic_bytes");
        if notable_binary && builder.finding_count() < ctx.limits().max_findings {
            builder.finding(
                "binary_artifact",
                Origin::Derived,
                format!(
                    "{rel_path}: {} ({})",
                    identification.format, identification.label
                ),
                Some(Location::file(&rel_path)),
                Some(ArtifactRef {
                    path: rel_path.clone(),
                    sha256: sha256.clone(),
                    size_bytes: entry.size,
                }),
                serde_json::json!({
                    "format": identification.format,
                    "basis": identification.basis,
                    "magic_hex": identification.magic_hex,
                }),
            );
            if matches!(
                identification.format.as_str(),
                "elf" | "pe" | "mach-o-32" | "mach-o-64" | "mach-o-fat" | "wasm" | "dex"
            ) {
                builder.limitation(format!(
                    "{rel_path}: native/binary format '{}' identified by magic bytes only; deeper analysis needs a native-analysis provider",
                    identification.format
                ));
            }
        }

        if is_text {
            let text = String::from_utf8_lossy(&prefix);
            let is_js = identification.format == "javascript"
                || identification.format == "javascript-dialect";
            if is_js && sourcemap_refs < ctx.limits().max_entries {
                for map_ref in javascript::scan_source_map_refs(&text) {
                    if sourcemap_refs >= ctx.limits().max_entries {
                        break;
                    }
                    sourcemap_refs += 1;
                    builder.finding(
                        "sourcemap_reference",
                        Origin::Observed,
                        format!(
                            "{rel_path}:{} references source map '{}'",
                            map_ref.line, map_ref.url
                        ),
                        Some(Location::file_line_column(
                            &rel_path,
                            map_ref.line,
                            map_ref.column,
                        )),
                        Some(ArtifactRef {
                            path: rel_path.clone(),
                            sha256: sha256.clone(),
                            size_bytes: entry.size,
                        }),
                        serde_json::json!({
                            "url": map_ref.url,
                            "inline": map_ref.inline,
                            "line": map_ref.line,
                        }),
                    );
                }
            }
            if entry.rel_path.file_name().and_then(|n| n.to_str()) == Some("package.json")
                && manifest_reports < MAX_MANIFESTS
            {
                manifest_reports += 1;
                let manifest = javascript::parse_manifest(&rel_path, &prefix, &sha256);
                if manifest.electron {
                    electron = true;
                }
                // The root manifest records the application entry point.
                if rel_path == "package.json" {
                    if let Some(entry_main) = manifest.entry_point() {
                        let resolved = javascript::resolve_specifier(
                            ctx.root,
                            Path::new("package.json"),
                            entry_main,
                        )
                        .ok()
                        .and_then(|r| r.resolved_path);
                        entry_point = Some((
                            rel_path.clone(),
                            resolved.unwrap_or_else(|| entry_main.to_string()),
                        ));
                    }
                }
                record_manifest_findings(
                    builder, &rel_path, &prefix, &sha256, entry.size, ctx.root,
                );
            }
        }

        if ctx.budget == 0 {
            builder.limitation(format!(
                "total byte budget ({} bytes) exhausted; remaining files were identified by name only",
                ctx.limits().max_total_bytes
            ));
            builder.force_partial("total byte budget exhausted");
            break;
        }
    }

    if manifest_reports >= MAX_MANIFESTS {
        builder.limitation(format!(
            "manifest parsing stopped at {MAX_MANIFESTS} manifests (limit)"
        ));
    }
    if walk_result.truncated {
        builder.limitation(format!(
            "directory walk was truncated by limits (max_files={}); {} file(s) skipped after the limit",
            ctx.limits().max_files,
            walk_result.skipped.len()
        ));
        builder.force_partial("directory walk was truncated by the max_files limit");
    }

    let digest = directory_manifest_digest(&hashed);
    let top_extensions = top_entries(&by_extension, ctx.limits().max_entries);
    let top_formats = top_entries(&by_format, ctx.limits().max_entries);
    let mut entry_summary: Option<serde_json::Value> = None;

    if electron {
        // A per-manifest classification finding is recorded by
        // record_manifest_findings; summarize the aggregate signal here.
        builder.finding(
            "classification_summary",
            Origin::Derived,
            format!("{manifest_reports} manifest(s) inspected; Electron signal present"),
            None,
            None,
            serde_json::json!({
                "electron": electron,
                "manifest_count": manifest_reports,
            }),
        );
    }
    if let Some((manifest_rel, entry)) = &entry_point {
        // The per-manifest entry point finding is recorded by
        // record_manifest_findings; expose the root manifest's entry in the
        // summary only (avoid duplicating findings).
        entry_summary = Some(serde_json::json!({
            "entry_point": entry,
            "manifest": manifest_rel,
        }));
    }

    let mut summary = serde_json::json!({
        "kind": "directory",
        "path": ctx.request.target.input.display().to_string(),
        "sha256": digest,
        "file_count": walk_result.files.len(),
        "directory_count": walk_result.directories.len(),
        "total_bytes": walk_result.total_bytes,
        "by_extension": top_extensions,
        "by_format": top_formats,
        "files_hashed": hashed.len(),
        "skipped_count": walk_result.skipped.len(),
        "walk_truncated": walk_result.truncated,
        "manifest_count": manifest_reports,
        "sourcemap_reference_count": sourcemap_refs,
        "electron": electron,
    });
    if let Some(entry) = &entry_summary {
        summary["entry_point"] = entry.clone();
    }
    summary
}

fn top_entries(map: &BTreeMap<String, usize>, max: usize) -> serde_json::Value {
    let mut entries: Vec<(&String, &usize)> = map.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let mut object = serde_json::Map::new();
    for (key, count) in entries.into_iter().take(max) {
        object.insert(key.clone(), serde_json::json!(count));
    }
    serde_json::Value::Object(object)
}

fn record_walk(builder: &mut ReportBuilder, walk_result: &WalkResult) {
    let visible_skips = walk_result.skipped.len().min(20);
    for skipped in walk_result.skipped.iter().take(visible_skips) {
        builder.warning(skipped.describe());
    }
    if walk_result.skipped.len() > visible_skips {
        builder.warning(format!(
            "... and {} more skipped entries not listed",
            walk_result.skipped.len() - visible_skips
        ));
    }
    if walk_result
        .skipped
        .iter()
        .any(|s| matches!(s.reason, tree::SkipReason::Symlink { .. }))
    {
        builder.limitation(
            "symbolic links are never followed during inspection; they are recorded as skipped entries",
        );
    }
}

/// Record manifest-derived findings (used by both file and directory inspect).
fn record_manifest_findings(
    builder: &mut ReportBuilder,
    rel_path: &str,
    bytes: &[u8],
    sha256: &str,
    size: u64,
    root: &Path,
) {
    let manifest = javascript::parse_manifest(rel_path, bytes, sha256);
    for problem in &manifest.problems {
        builder.warning(format!("{rel_path}: {problem}"));
    }
    let finding_id = builder.finding(
        "package_manifest",
        Origin::Observed,
        format!(
            "{rel_path}: package manifest for {} {}",
            manifest.name.as_deref().unwrap_or("<unnamed>"),
            manifest.version.as_deref().unwrap_or("<no version>")
        ),
        Some(Location::file(rel_path)),
        Some(ArtifactRef {
            path: rel_path.to_string(),
            sha256: sha256.to_string(),
            size_bytes: size,
        }),
        serde_json::json!({
            "name": manifest.name,
            "version": manifest.version,
            "main": manifest.main,
            "module": manifest.module,
            "type": manifest.type_field,
            "scripts": manifest.scripts,
            "dependencies": manifest.dependencies.iter().map(|d| serde_json::json!({
                "name": d.name, "range": d.range,
            })).collect::<Vec<_>>(),
            "dev_dependencies": manifest.dev_dependencies.iter().map(|d| serde_json::json!({
                "name": d.name, "range": d.range,
            })).collect::<Vec<_>>(),
            "electron": manifest.electron,
            "problems": manifest.problems,
        }),
    );
    if manifest.electron {
        builder.finding(
            "classification",
            Origin::Derived,
            format!("{rel_path}: Electron application manifest"),
            Some(Location::file(rel_path)),
            None,
            serde_json::json!({
                "classification": "electron",
                "evidence": "'electron' declared in dependencies or devDependencies",
            }),
        );
    }
    if let (Some(entry), Some(id)) = (manifest.entry_point(), finding_id) {
        let resolved = javascript::resolve_specifier(root, Path::new(rel_path), entry)
            .ok()
            .and_then(|r| r.resolved_path);
        builder.finding(
            "entry_point",
            Origin::Derived,
            format!("{rel_path}: entry point '{entry}'"),
            Some(Location::file(rel_path)),
            None,
            serde_json::json!({
                "entry_point": entry,
                "resolved_path": resolved,
                "manifest": rel_path,
                "basis": "package.json main/module field",
                "evidence_finding_id": id,
            }),
        );
    }
}

// ---------------------------------------------------------------------------
// search
// ---------------------------------------------------------------------------

fn search_file_target(
    ctx: &mut OpContext,
    builder: &mut ReportBuilder,
    query: &SearchQuery,
) -> serde_json::Value {
    let abs = ctx.request.target.canonical.clone();
    let rel_path = rel(ctx.root, &abs);
    let display_path = ctx.request.target.input.display().to_string();
    if ctx.request.target.size > ctx.limits().max_file_bytes {
        builder.skipped();
        builder.limitation(format!(
            "{rel_path} exceeds the per-file size limit ({} bytes); not searched",
            ctx.request.target.size
        ));
        return serde_json::json!({
            "query": query.text, "case_sensitive": query.case_sensitive,
            "matches": 0, "files_searched": 0, "files_skipped": 1, "truncated": false,
        });
    }
    let max_file_bytes = ctx.limits().max_file_bytes;
    let outcome = read_prefix(&abs, u64::MAX, &mut ctx.budget, max_file_bytes);
    let content = match outcome {
        ReadOutcome::Full(bytes) | ReadOutcome::Truncated(bytes, _) => bytes,
        ReadOutcome::Failed(error) => {
            builder.error(
                "io",
                format!("cannot read {rel_path}: {error}"),
                Some("search"),
            );
            builder.skipped();
            return serde_json::json!({
                "query": query.text, "case_sensitive": query.case_sensitive,
                "matches": 0, "files_searched": 0, "files_skipped": 1, "truncated": false,
            });
        }
    };
    builder.scanned();
    let mut session = SearchSession::new(ctx.limits().clone(), query.case_sensitive, &query.text);
    if session.add_file(&rel_path, &content) {
        let mut remaining = ctx.limits().max_matches;
        record_new_matches(builder, session.matches(), &mut remaining);
        if session.is_truncated() {
            // Honesty rule: a truncated search is a partial result, and the
            // truncation is visible in the report, not just the summary.
            builder.limitation(format!(
                "search stopped at {} matches (limit); additional matches may exist in {rel_path}",
                ctx.limits().max_matches
            ));
            builder.force_partial("search output truncated by the match limit");
        }
        summarize_search(&session, 1, 0, &display_path)
    } else {
        builder.skipped();
        builder.limitation(format!("{rel_path} is binary; literal search skipped it"));
        summarize_search(&session, 0, 1, &display_path)
    }
}

fn search_directory(
    ctx: &mut OpContext,
    builder: &mut ReportBuilder,
    query: &SearchQuery,
) -> serde_json::Value {
    let walk_result = tree::walk(ctx.root, ctx.limits(), &|| ctx.stop());
    record_walk(builder, &walk_result);
    if walk_result.truncated {
        builder.force_partial("directory walk was truncated by the max_files limit");
    }
    let display_path = ctx.request.target.input.display().to_string();
    let mut session = SearchSession::new(ctx.limits().clone(), query.case_sensitive, &query.text);
    let mut files_searched = 0usize;
    let mut files_skipped_binary = 0usize;
    let mut truncated_by_global = false;
    // A resumed pass continues with the earlier pass's remaining match budget.
    let mut remaining_matches = ctx
        .request
        .resume
        .as_ref()
        .map(|resume| resume.matches_remaining)
        .unwrap_or(ctx.limits().max_matches);

    for (index, entry) in walk_result.files.iter().enumerate() {
        // Files searched in an earlier pass are skipped entirely.
        if index < ctx.resume_from() {
            continue;
        }
        // Durable checkpoint at `per_file_analysis` boundaries (search cap
        // travels with the checkpoint so resume cannot exceed the total).
        maybe_checkpoint(
            ctx,
            builder,
            index - ctx.resume_from(),
            index,
            Some(remaining_matches),
        );
        if remaining_matches == 0 {
            truncated_by_global = true;
            builder.limitation(format!(
                "search stopped at {} matches (limit); additional matches may exist",
                ctx.limits().max_matches
            ));
            break;
        }
        if ctx.stop().is_some() {
            break;
        }
        let rel_path = entry.rel_path.display().to_string().replace('\\', "/");
        let max_file_bytes = ctx.limits().max_file_bytes;
        let outcome = read_prefix(&entry.abs_path, u64::MAX, &mut ctx.budget, max_file_bytes);
        let content = match outcome {
            ReadOutcome::Full(bytes) | ReadOutcome::Truncated(bytes, _) => bytes,
            ReadOutcome::Failed(error) => {
                builder.warning(format!("{rel_path}: unreadable ({error})"));
                builder.skipped();
                continue;
            }
        };
        let before = session.matches().len();
        if session.add_file(&rel_path, &content) {
            files_searched += 1;
            builder.scanned();
            record_new_matches(
                builder,
                &session.matches()[before..],
                &mut remaining_matches,
            );
        } else {
            files_skipped_binary += 1;
            builder.skipped();
        }
    }
    if files_skipped_binary > 0 {
        builder.limitation(format!(
            "{files_skipped_binary} binary file(s) were skipped by literal search"
        ));
    }
    if truncated_by_global || session.is_truncated() {
        // The summary says it; the report outcome must say it too.
        builder.force_partial("search output truncated by the match limit");
    }
    let mut summary = summarize_search(
        &session,
        files_searched,
        files_skipped_binary,
        &display_path,
    );
    if walk_result.truncated {
        summary["walk_truncated"] = serde_json::json!(true);
    }
    if truncated_by_global || session.is_truncated() {
        summary["truncated"] = serde_json::json!(true);
    }
    summary
}

/// Record search matches that have not been recorded yet, bounded by the
/// global match budget.
fn record_new_matches(
    builder: &mut ReportBuilder,
    new_matches: &[crate::search::SearchMatch],
    remaining: &mut usize,
) {
    for entry_match in new_matches {
        if *remaining == 0 {
            return;
        }
        *remaining -= 1;
        let mut redacted_flag = false;
        for redaction in &entry_match.redactions {
            redacted_flag = true;
            builder.redaction(
                redaction.rule,
                redaction.reason.clone(),
                Some(Location::file_line_column(
                    &entry_match.rel_path,
                    entry_match.line,
                    entry_match.column,
                )),
            );
        }
        builder.finding(
            "search_match",
            Origin::Observed,
            format!(
                "{}:{}:{}: match '{}' ({} bytes)",
                entry_match.rel_path,
                entry_match.line,
                entry_match.column,
                truncate_for_summary(&entry_match.matched_text, 40),
                entry_match.matched_text.len()
            ),
            Some(Location::file_line_column(
                &entry_match.rel_path,
                entry_match.line,
                entry_match.column,
            )),
            None,
            serde_json::json!({
                "line_text": entry_match.line_text,
                "matched_text": entry_match.matched_text,
                "redacted": redacted_flag,
            }),
        );
    }
}

fn summarize_search(
    session: &SearchSession,
    files_searched: usize,
    files_skipped_binary: usize,
    target: &str,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "search",
        "path": target,
        "query": session.needle(),
        "case_sensitive": session.case_sensitive(),
        "matches": session.matches().len(),
        "files_searched": files_searched,
        "files_skipped_binary": files_skipped_binary,
        "truncated": session.is_truncated(),
        "target": target,
    })
}

fn truncate_for_summary(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max_chars).collect();
        format!("{cut}...")
    }
}

// ---------------------------------------------------------------------------
// relationships
// ---------------------------------------------------------------------------

fn relationships_impl(ctx: &mut OpContext, builder: &mut ReportBuilder) -> serde_json::Value {
    javascript_scan_limitation(builder);
    builder.limitation(
        "relationship resolution implements the CommonJS lookup subset (exact, .js, .json, \
         index.js); package 'exports' maps and path aliases are not resolved",
    );
    builder.limitation(
        "observed import statements show static references only; they do not prove runtime \
         call paths or execution order",
    );

    let files: Vec<(String, PathBuf, u64)> = match ctx.request.target.kind {
        vortex_core::paths::TargetKind::File => {
            let abs = ctx.request.target.canonical.clone();
            vec![(rel(ctx.root, &abs), abs, ctx.request.target.size)]
        }
        vortex_core::paths::TargetKind::Directory => {
            let walk_result = tree::walk(ctx.root, ctx.limits(), &|| ctx.stop());
            record_walk(builder, &walk_result);
            walk_result
                .files
                .iter()
                .map(|entry| {
                    (
                        entry.rel_path.display().to_string().replace('\\', "/"),
                        entry.abs_path.clone(),
                        entry.size,
                    )
                })
                .collect()
        }
    };

    // Phase 1: manifests first, so dependency declarations are known when
    // bare imports are classified.
    let mut declared = std::collections::BTreeSet::new();
    let mut manifests: Vec<PackageManifest> = Vec::new();
    for (rel_path, abs, size) in &files {
        if rel_path.ends_with("package.json") && manifests.len() < MAX_MANIFESTS {
            let max_file_bytes = ctx.limits().max_file_bytes;
            let outcome = read_prefix(abs, u64::MAX, &mut ctx.budget, max_file_bytes);
            if let ReadOutcome::Full(bytes) | ReadOutcome::Truncated(bytes, _) = outcome {
                let sha256 = hash_file(abs, Some(&bytes));
                let manifest = javascript::parse_manifest(rel_path, &bytes, &sha256);
                for name in manifest.all_dependency_names() {
                    declared.insert(name.to_string());
                }
                let size = std::cmp::max(*size, bytes.len() as u64);
                record_manifest_findings(builder, rel_path, &bytes, &sha256, size, ctx.root);
                manifests.push(manifest);
                builder.scanned();
            }
        }
    }

    // Package -> dependency relationships.
    for manifest in &manifests {
        let package_node = Node {
            kind: "package".to_string(),
            id: manifest
                .name
                .clone()
                .unwrap_or_else(|| manifest.rel_path.clone()),
        };
        for dep in manifest
            .dependencies
            .iter()
            .chain(manifest.dev_dependencies.iter())
        {
            // Vendored dependencies resolve to their real entry file inside
            // the inspected tree (Node-style node_modules lookup, honoring
            // package.json `main`); anything else is reported as not found
            // — never as "node_modules absent", which may be false.
            let vendored_entry = javascript::resolve_bare_in_node_modules(
                ctx.root,
                Path::new(&manifest.rel_path),
                &dep.name,
            );
            match vendored_entry {
                Some(entry) => {
                    builder.relationship(
                        package_node.clone(),
                        Node {
                            kind: "file".to_string(),
                            id: entry.clone(),
                        },
                        "declares_dependency",
                        Scope::Internal,
                        Resolution::Resolved,
                        Some(format!(
                            "declared '{}' and vendored under node_modules (entry {entry}; \
                             package 'exports' maps are not evaluated)",
                            dep.range
                        )),
                        Origin::Observed,
                        None,
                        Some(Location::file(&manifest.rel_path)),
                    );
                }
                None => {
                    builder.relationship(
                        package_node.clone(),
                        Node {
                            kind: "external_package".to_string(),
                            id: dep.name.clone(),
                        },
                        "declares_dependency",
                        Scope::External,
                        Resolution::Unresolved,
                        Some(format!(
                            "declared as '{}' but not found in any inspected node_modules directory",
                            dep.range
                        )),
                        Origin::Observed,
                        None,
                        Some(Location::file(&manifest.rel_path)),
                    );
                }
            }
        }
    }

    if manifests.len() >= MAX_MANIFESTS {
        builder.limitation(format!(
            "manifest parsing stopped at {MAX_MANIFESTS} manifests (limit); manifests beyond the \
             cap were not parsed, so 'not declared in any inspected package.json' notes for \
             their dependencies may be wrong — those manifests were never read"
        ));
    }

    // Phase 2: per-file scanning.
    for (rel_path, abs, size) in &files {
        if ctx.stop().is_some() {
            break;
        }
        let max_file_bytes = ctx.limits().max_file_bytes;
        let outcome = read_prefix(abs, u64::MAX, &mut ctx.budget, max_file_bytes);
        let content = match outcome {
            ReadOutcome::Full(bytes) | ReadOutcome::Truncated(bytes, _) => bytes,
            ReadOutcome::Failed(_) => {
                builder.skipped();
                continue;
            }
        };
        let identification = identify::identify(abs, &content);
        let is_text = identify::looks_like_text(&content);
        if !is_text {
            builder.skipped();
            continue;
        }
        builder.scanned();
        let text = String::from_utf8_lossy(&content);
        let sha256 = hash_file(abs, Some(&content));

        let is_js =
            identification.format == "javascript" || identification.format == "javascript-dialect";
        let is_html = identification.format == "html";
        if !is_js && !is_html {
            continue;
        }

        if is_js {
            let systems = javascript::detect_module_systems(&text);
            let (imports, imports_truncated) =
                javascript::scan_imports(&text, ctx.limits().max_imports_per_file);
            if imports_truncated {
                builder.limitation(format!(
                    "import scan of {rel_path} stopped at the per-file limit ({}); additional references may exist",
                    ctx.limits().max_imports_per_file
                ));
            }
            let summary_id = builder.finding(
                "imports_summary",
                Origin::Observed,
                format!("{rel_path}: {} import reference(s)", imports.len()),
                Some(Location::file(rel_path)),
                Some(ArtifactRef {
                    path: rel_path.clone(),
                    sha256: sha256.clone(),
                    size_bytes: *size,
                }),
                serde_json::json!({
                    "count": imports.len(),
                    "module_systems": systems.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                    "imports": imports.iter().map(|i| serde_json::json!({
                        "syntax": i.syntax.as_str(),
                        "specifier": i.specifier,
                        "line": i.line,
                        "column": i.column,
                    })).collect::<Vec<_>>(),
                }),
            );
            for import in &imports {
                record_import_relationship(
                    builder,
                    ctx.root,
                    rel_path,
                    import,
                    &declared,
                    summary_id.as_deref(),
                );
            }
            for map_ref in javascript::scan_source_map_refs(&text) {
                record_sourcemap_relationship(
                    builder,
                    ctx.root,
                    rel_path,
                    &map_ref.url,
                    map_ref.line,
                    map_ref.column,
                    summary_id.as_deref(),
                );
            }
        }

        if is_html {
            let file_node = Node {
                kind: "file".to_string(),
                id: rel_path.clone(),
            };
            for script in javascript::scan_script_sources(&text) {
                let resolved = javascript::resolve_relative_reference(
                    ctx.root,
                    Path::new(rel_path),
                    &script.src,
                );
                let (status, note, to_id) = classify_resolved(&resolved, &script.src);
                builder.relationship(
                    file_node.clone(),
                    Node {
                        kind: if script.src.starts_with("http") || script.src.starts_with("data:") {
                            "external_resource".to_string()
                        } else {
                            "file".to_string()
                        },
                        id: to_id,
                    },
                    "references_script",
                    if script.src.starts_with("http") || script.src.starts_with("data:") {
                        Scope::External
                    } else {
                        Scope::Internal
                    },
                    status,
                    note,
                    Origin::Observed,
                    None,
                    Some(Location::file_line_column(
                        rel_path,
                        script.line,
                        script.column,
                    )),
                );
            }
        }
    }

    let resolved_count = builder
        .relationships_snapshot()
        .iter()
        .filter(|r| r.status == Resolution::Resolved)
        .count();
    let total_relationships = builder.relationship_count();
    let unresolved_total = total_relationships.saturating_sub(resolved_count);
    let files_scanned = builder.scanned_count();
    builder.limitation(format!(
        "{unresolved_total} relationship(s) could not be resolved to a local endpoint; reasons are recorded per relationship"
    ));

    serde_json::json!({
        "kind": ctx.request.target.kind.as_str(),
        "path": ctx.request.target.input.display().to_string(),
        "relationships": total_relationships,
        "resolved": resolved_count,
        "unresolved": unresolved_total,
        "manifests": manifests.len(),
        "files_scanned": files_scanned,
    })
}

#[allow(clippy::too_many_arguments)]
fn record_import_relationship(
    builder: &mut ReportBuilder,
    root: &Path,
    rel_path: &str,
    import: &ImportRef,
    declared: &std::collections::BTreeSet<String>,
    evidence_id: Option<&str>,
) {
    let from = Node {
        kind: "file".to_string(),
        id: rel_path.to_string(),
    };
    let location = Some(Location::file_line_column(
        rel_path,
        import.line,
        import.column,
    ));
    let kind = import.syntax.as_str();

    match javascript::classify_specifier(&import.specifier) {
        SpecifierKind::Relative => {
            match javascript::resolve_specifier(root, Path::new(rel_path), &import.specifier) {
                Ok(resolution) => {
                    if let Some(path) = resolution.resolved_path {
                        builder.relationship(
                            from,
                            Node {
                                kind: "file".to_string(),
                                id: path.clone(),
                            },
                            kind,
                            Scope::Internal,
                            Resolution::Resolved,
                            None,
                            Origin::Observed,
                            evidence_id.map(str::to_string),
                            location,
                        );
                    } else {
                        builder.relationship(
                            from,
                            Node {
                                kind: "file".to_string(),
                                id: import.specifier.clone(),
                            },
                            kind,
                            Scope::Internal,
                            Resolution::Unresolved,
                            Some(
                                resolution
                                    .note
                                    .unwrap_or_else(|| "no local file matched".into()),
                            ),
                            Origin::Observed,
                            evidence_id.map(str::to_string),
                            location,
                        );
                        builder.unknown(format!(
                            "{rel_path}:{}: reference '{}' does not match a local file; verify whether it is generated, optional, or broken",
                            import.line, import.specifier
                        ));
                    }
                }
                Err(error) => {
                    builder.relationship(
                        from,
                        Node {
                            kind: "file".to_string(),
                            id: import.specifier.clone(),
                        },
                        kind,
                        Scope::Internal,
                        Resolution::Unresolved,
                        Some(format!("resolution rejected: {}", error.message)),
                        Origin::Observed,
                        evidence_id.map(str::to_string),
                        location,
                    );
                    builder.unknown(format!(
                        "{rel_path}:{}: reference '{}' escapes the inspection root; verify its origin",
                        import.line, import.specifier
                    ));
                }
            }
        }
        SpecifierKind::Bare => {
            if javascript::is_node_builtin(&import.specifier) {
                builder.relationship(
                    from,
                    Node {
                        kind: "builtin".to_string(),
                        id: import.specifier.clone(),
                    },
                    kind,
                    Scope::External,
                    Resolution::Resolved,
                    Some("Node.js builtin module (not part of the inspected artifact)".to_string()),
                    Origin::Observed,
                    evidence_id.map(str::to_string),
                    location,
                );
            } else if let Some(local) = javascript::resolve_bare_in_node_modules(
                root,
                Path::new(rel_path),
                &import.specifier,
            ) {
                // Node-style node_modules lookup resolved inside the artifact.
                builder.relationship(
                    from,
                    Node {
                        kind: "file".to_string(),
                        id: local.clone(),
                    },
                    kind,
                    Scope::Internal,
                    Resolution::Resolved,
                    Some(
                        "resolved through a local node_modules directory (static path \
                         lookup; package 'exports'/'imports' maps are not evaluated)"
                            .to_string(),
                    ),
                    Origin::Observed,
                    evidence_id.map(str::to_string),
                    location,
                );
            } else {
                let name = package_name_of(&import.specifier);
                let is_declared = declared.contains(name.as_str());
                builder.relationship(
                    from,
                    Node {
                        kind: "external_package".to_string(),
                        id: name.clone(),
                    },
                    kind,
                    Scope::External,
                    if is_declared {
                        Resolution::Resolved
                    } else {
                        Resolution::Unresolved
                    },
                    Some(if is_declared {
                        "declared in an inspected package.json and not found in any inspected node_modules directory".to_string()
                    } else {
                        "not declared in any inspected package.json and not found in any inspected node_modules directory".to_string()
                    }),
                    Origin::Observed,
                    evidence_id.map(str::to_string),
                    location,
                );
                if !is_declared {
                    builder.unknown(format!(
                        "{rel_path}:{}: import '{}' is not declared in any inspected manifest; verify where it comes from",
                        import.line, import.specifier
                    ));
                }
            }
        }
        SpecifierKind::Url | SpecifierKind::DataUri => {
            builder.relationship(
                from,
                Node {
                    kind: "external_resource".to_string(),
                    id: import.specifier.clone(),
                },
                kind,
                Scope::External,
                Resolution::Unresolved,
                Some(format!(
                    "{} reference outside the artifact",
                    javascript::classify_specifier(&import.specifier).as_str()
                )),
                Origin::Observed,
                evidence_id.map(str::to_string),
                location,
            );
        }
        SpecifierKind::Absolute | SpecifierKind::Prefixed => {
            builder.relationship(
                from,
                Node {
                    kind: "external_resource".to_string(),
                    id: import.specifier.clone(),
                },
                kind,
                Scope::External,
                Resolution::Unresolved,
                Some(if import.specifier.starts_with('#') {
                    "subpath import (# specifier); package.json 'imports' maps are not resolved"
                        .to_string()
                } else {
                    "absolute path specifier outside the inspection root".to_string()
                }),
                Origin::Observed,
                evidence_id.map(str::to_string),
                location,
            );
        }
    }
}

/// Extract the package name from a bare specifier.
///
/// `@scope/name/subpath` becomes `@scope/name`; `minimist/extra` becomes
/// `minimist`.
fn package_name_of(specifier: &str) -> String {
    if specifier.starts_with('@') {
        let mut parts = specifier.splitn(3, '/');
        let scope = parts.next().unwrap_or("");
        let name = parts.next().unwrap_or("");
        if !scope.is_empty() && !name.is_empty() {
            return format!("@{scope}/{name}");
        }
    }
    specifier.split('/').next().unwrap_or(specifier).to_string()
}

#[allow(clippy::too_many_arguments)]
fn record_sourcemap_relationship(
    builder: &mut ReportBuilder,
    root: &Path,
    rel_path: &str,
    url: &str,
    line: u32,
    column: u32,
    evidence_id: Option<&str>,
) {
    let from = Node {
        kind: "file".to_string(),
        id: rel_path.to_string(),
    };
    if url.starts_with("data:") {
        builder.relationship(
            from,
            Node {
                kind: "data_uri".to_string(),
                id: url.chars().take(64).collect(),
            },
            "references_sourcemap",
            Scope::External,
            Resolution::Inline,
            Some("inline data: URI source map".to_string()),
            Origin::Observed,
            evidence_id.map(str::to_string),
            Some(Location::file_line_column(rel_path, line, column)),
        );
        return;
    }
    let resolved = javascript::resolve_relative_reference(root, Path::new(rel_path), url);
    let (status, note, to_id) = classify_resolved(&resolved, url);
    builder.relationship(
        from,
        Node {
            kind: "file".to_string(),
            id: to_id,
        },
        "references_sourcemap",
        Scope::Internal,
        status,
        note,
        Origin::Observed,
        evidence_id.map(str::to_string),
        Some(Location::file_line_column(rel_path, line, column)),
    );
}

fn classify_resolved(
    resolved: &vortex_core::error::VortexResult<javascript::resolve::Resolution>,
    raw: &str,
) -> (Resolution, Option<String>, String) {
    match resolved {
        Ok(resolution) => match &resolution.resolved_path {
            Some(path) => (Resolution::Resolved, None, path.clone()),
            None => (
                Resolution::Unresolved,
                resolution
                    .note
                    .clone()
                    .or_else(|| Some(format!("no local file matched '{raw}'"))),
                raw.to_string(),
            ),
        },
        Err(error) => (
            Resolution::Unresolved,
            Some(format!("resolution rejected: {}", error.message)),
            raw.to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{AnalysisRequest, CancelToken, Outcome, ResumeContext};
    use std::time::Instant;
    use vortex_core::limits::ResourceLimits;
    use vortex_core::paths::{validate_target, TargetKind};
    use vortex_evidence::findings_by_kind;

    fn request_for(path: &Path, limits: ResourceLimits) -> AnalysisRequest {
        let target = validate_target(path).expect("valid target");
        let root = match target.kind {
            TargetKind::Directory => target.canonical.clone(),
            TargetKind::File => target.canonical.parent().expect("parent").to_path_buf(),
        };
        AnalysisRequest {
            target,
            root,
            limits,
            deadline: None,
            cancel: CancelToken::new(),
            checkpoint_sink: None,
            resume: None,
        }
    }

    fn fixture_dir(name: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path().join(name);
        std::fs::create_dir_all(base.join("src/lib")).unwrap();
        std::fs::create_dir_all(base.join("src/renderer")).unwrap();
        std::fs::write(
            base.join("package.json"),
            br#"{"name":"demo","version":"1.0.0","main":"src/main.js","dependencies":{"minimist":"^1.2.8"},"devDependencies":{"electron":"^33.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            base.join("src/main.js"),
            b"const { loadConfig } = require('./lib/config.js');\nconst fs = require('fs');\nconst minimist = require('minimist');\nconst { gone } = require('./missing.js');\n//# sourceMappingURL=main.js.map\n",
        )
        .unwrap();
        std::fs::write(
            base.join("src/lib/config.js"),
            b"module.exports.loadConfig = () => ({});\n",
        )
        .unwrap();
        std::fs::write(base.join("src/lib/defaults.json"), b"{\"retries\": 3}\n").unwrap();
        std::fs::write(
            base.join("src/renderer/renderer.js"),
            b"import { createButton } from './components/button.js';\nimport theme from './theme.js';\n",
        )
        .unwrap();
        std::fs::create_dir_all(base.join("src/renderer/components")).unwrap();
        std::fs::write(
            base.join("src/renderer/components/button.js"),
            b"export function createButton() {}\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn inspect_directory_produces_bounded_summary_and_manifest_findings() {
        let dir = fixture_dir("app");
        let base = dir.path().join("app");
        let request = request_for(&base, ResourceLimits::default());
        let provider = BuiltinStaticProvider::new();
        let report = provider.inspect(&request);
        assert_eq!(report.outcome, Outcome::Succeeded);
        let kinds = findings_by_kind(&report.findings);
        assert_eq!(kinds.get("package_manifest"), Some(&1));
        assert_eq!(kinds.get("entry_point"), Some(&1));
        assert_eq!(kinds.get("classification"), Some(&1));
        assert_eq!(kinds.get("sourcemap_reference"), Some(&1));
        assert!(report.summary["file_count"].as_u64().unwrap() >= 6);
        assert_eq!(report.summary["electron"], serde_json::json!(true));
        assert_eq!(
            report.summary["entry_point"]["entry_point"],
            serde_json::json!("src/main.js")
        );
        assert_eq!(
            report.summary["entry_point"]["manifest"],
            serde_json::json!("package.json")
        );
    }

    #[test]
    fn inspect_is_deterministic_across_runs() {
        let dir = fixture_dir("app");
        let base = dir.path().join("app");
        let provider = BuiltinStaticProvider::new();
        let first = provider.inspect(&request_for(&base, ResourceLimits::default()));
        let second = provider.inspect(&request_for(&base, ResourceLimits::default()));
        assert_eq!(first.findings, second.findings);
        assert_eq!(first.summary, second.summary);
        assert_eq!(first.summary["file_count"], second.summary["file_count"]);
    }

    #[test]
    fn relationships_find_expected_edges() {
        let dir = fixture_dir("app");
        let base = dir.path().join("app");
        let request = request_for(&base, ResourceLimits::default());
        let provider = BuiltinStaticProvider::new();
        let report = provider.relationships(&request);

        let edge = |from: &str, to: &str, kind: &str| {
            report
                .relationships
                .iter()
                .any(|r| r.from.id == from && r.to.id == to && r.kind == kind)
        };
        // Resolved local require.
        assert!(edge("src/main.js", "src/lib/config.js", "requires"));
        // Node builtin.
        assert!(edge("src/main.js", "fs", "requires"));
        // Declared external package.
        assert!(edge("src/main.js", "minimist", "requires"));
        // Unresolved local reference.
        assert!(edge("src/main.js", "./missing.js", "requires"));
        // ESM import resolved.
        assert!(edge(
            "src/renderer/renderer.js",
            "src/renderer/components/button.js",
            "imports"
        ));
        // ESM import unresolved.
        assert!(edge("src/renderer/renderer.js", "./theme.js", "imports"));
        // Source map reference.
        assert!(edge("src/main.js", "main.js.map", "references_sourcemap"));
        // Declared dependency edges.
        assert!(edge("demo", "minimist", "declares_dependency"));
        assert!(edge("demo", "electron", "declares_dependency"));

        let unresolved: Vec<_> = report
            .relationships
            .iter()
            .filter(|r| r.status == Resolution::Unresolved)
            .collect();
        assert!(unresolved.len() >= 3);
        assert!(unresolved.iter().all(|r| r.resolution_note.is_some()));
        assert!(report.unknowns.iter().any(|u| u.contains("./missing.js")));
    }

    /// REA #4632/#2259 lesson: bare specifiers that resolve through a local
    /// `node_modules` must be reported as internal edges, and external notes
    /// must never claim absence without having looked.
    #[test]
    fn relationships_resolve_bare_specifiers_through_node_modules() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path().join("app");
        std::fs::create_dir_all(base.join("node_modules/@scope/pkg/lib")).unwrap();
        std::fs::create_dir_all(base.join("node_modules/ordinary")).unwrap();
        std::fs::write(
            base.join("package.json"),
            br#"{"name":"demo","main":"main.cjs"}"#,
        )
        .unwrap();
        std::fs::write(
            base.join("main.cjs"),
            b"require('@scope');\nrequire('@scope/pkg/lib/helper');\nrequire('ordinary');\nrequire('leftpad');\n",
        )
        .unwrap();
        std::fs::write(
            base.join("node_modules/@scope/index.js"),
            b"module.exports = 1;",
        )
        .unwrap();
        std::fs::write(
            base.join("node_modules/@scope/pkg/lib/helper.js"),
            b"module.exports = 1;",
        )
        .unwrap();
        std::fs::write(
            base.join("node_modules/ordinary/package.json"),
            br#"{"main":"entry.js"}"#,
        )
        .unwrap();
        std::fs::write(
            base.join("node_modules/ordinary/entry.js"),
            b"module.exports = 1;",
        )
        .unwrap();

        let request = request_for(&base, ResourceLimits::default());
        let provider = BuiltinStaticProvider::new();
        let report = provider.relationships(&request);

        let edge = |from: &str, to: &str, kind: &str| {
            report
                .relationships
                .iter()
                .any(|r| r.from.id == from && r.to.id == to && r.kind == kind)
        };
        let internal_edge = |to: &str| {
            report.relationships.iter().any(|r| {
                r.to.id == to && r.scope == Scope::Internal && r.status == Resolution::Resolved
            })
        };

        // REA #4632: scope directory package.
        assert!(internal_edge("node_modules/@scope/index.js"));
        // Subpath import into a scoped package.
        assert!(internal_edge("node_modules/@scope/pkg/lib/helper.js"));
        // package.json main inside node_modules.
        assert!(internal_edge("node_modules/ordinary/entry.js"));
        // A package that exists nowhere stays external and truthful.
        assert!(edge("main.cjs", "leftpad", "requires"));
        let leftpad = report
            .relationships
            .iter()
            .find(|r| r.to.id == "leftpad")
            .expect("leftpad edge");
        assert_eq!(leftpad.scope, Scope::External);
        assert!(leftpad
            .resolution_note
            .as_deref()
            .unwrap()
            .contains("not found in any inspected node_modules directory"));
    }

    #[test]
    fn search_finds_known_text_with_locations() {
        let dir = fixture_dir("app");
        let base = dir.path().join("app");
        let request = request_for(&base, ResourceLimits::default());
        let provider = BuiltinStaticProvider::new();
        let report = provider.search(
            &request,
            &SearchQuery {
                text: "loadConfig".to_string(),
                case_sensitive: false,
            },
        );
        assert!(report.summary["matches"].as_u64().unwrap() >= 2);
        let match_locations: Vec<String> = report
            .findings
            .iter()
            .filter(|f| f.kind == "search_match")
            .filter_map(|f| {
                f.location.as_ref().map(|l| {
                    format!(
                        "{}:{}",
                        l.file.clone().unwrap_or_default(),
                        l.line.unwrap_or(0)
                    )
                })
            })
            .collect();
        assert!(match_locations.contains(&"src/main.js:1".to_string()));
        assert!(match_locations.contains(&"src/lib/config.js:1".to_string()));
    }

    #[test]
    fn binary_target_reports_identification_and_unsupported_operation() {
        let dir = tempfile::tempdir().unwrap();
        // A truncated ELF: the parser exists now, so this is a warning and
        // an honest limitation — not an unsupported_operation error.
        let elf = dir.path().join("program.bin");
        std::fs::write(
            &elf,
            [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
        .unwrap();
        let request = request_for(&elf, ResourceLimits::default());
        let provider = BuiltinStaticProvider::new();
        let report = provider.inspect(&request);
        assert_eq!(report.summary["format"], serde_json::json!("elf"));
        assert!(!report
            .errors
            .iter()
            .any(|e| e.code == "unsupported_operation"));
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("structural parsing failed")));
        assert!(report
            .limitations
            .iter()
            .any(|l| l.contains("ELF structure unavailable")));
        assert!(!report.findings.iter().any(|f| f.kind == "elf_header"));
        // Strings extraction still ran (empty strings are fine for this input).
        assert!(report.findings.iter().any(|f| f.kind == "strings_sample"));

        // Mach-O: still no parser in this release — the honest
        // unsupported_operation error, exactly as before Phase 3.
        let macho = dir.path().join("mach.bin");
        std::fs::write(
            &macho,
            [
                0xcf, 0xfa, 0xed, 0xfe, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        )
        .unwrap();
        let request = request_for(&macho, ResourceLimits::default());
        let report = provider.inspect(&request);
        assert_eq!(report.summary["format"], serde_json::json!("mach-o-64"));
        assert!(report
            .errors
            .iter()
            .any(|e| e.code == "unsupported_operation"));
        assert!(report
            .limitations
            .iter()
            .any(|l| l.contains("native-analysis provider")));
        for finding in &report.findings {
            assert!(
                matches!(finding.kind.as_str(), "file" | "format" | "strings_sample"),
                "unexpected fabricated finding kind: {}",
                finding.kind
            );
        }
    }

    #[test]
    fn timeout_produces_cancelled_outcome_with_partial_findings() {
        let dir = fixture_dir("app");
        let base = dir.path().join("app");
        let mut request = request_for(&base, ResourceLimits::default());
        request.deadline = Some(Instant::now() - std::time::Duration::from_millis(1));
        let provider = BuiltinStaticProvider::new();
        let report = provider.inspect(&request);
        assert_eq!(report.outcome, Outcome::Cancelled);
        assert!(report
            .limitations
            .iter()
            .any(|l| l.contains("stopped early")));
    }

    #[test]
    fn cancellation_token_stops_analysis() {
        let dir = fixture_dir("app");
        let base = dir.path().join("app");
        let request = request_for(&base, ResourceLimits::default());
        request.cancel.cancel();
        let provider = BuiltinStaticProvider::new();
        let report = provider.inspect(&request);
        assert_eq!(report.outcome, Outcome::Cancelled);
    }

    #[test]
    fn max_files_limit_marks_partial() {
        let dir = fixture_dir("app");
        let base = dir.path().join("app");
        let limits = ResourceLimits {
            max_files: 2,
            ..ResourceLimits::default()
        };
        let request = request_for(&base, limits);
        let provider = BuiltinStaticProvider::new();
        let report = provider.inspect(&request);
        assert!(matches!(report.outcome, Outcome::Partial { .. }));
        assert!(report.counts.truncated);
    }

    #[test]
    fn malformed_manifest_is_reported_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("broken");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("package.json"), b"{ not json at all").unwrap();
        std::fs::write(base.join("index.js"), b"require('./x');\n").unwrap();
        let request = request_for(&base, ResourceLimits::default());
        let provider = BuiltinStaticProvider::new();
        let report = provider.inspect(&request);
        assert!(report.warnings.iter().any(|w| w.contains("not valid JSON")));
        // The run still succeeded overall: the problem is recorded, not fatal.
        assert_eq!(report.outcome, Outcome::Succeeded);
    }
    /// Checkpoints fire at every CHECKPOINT_EVERY boundary with the walk
    /// index of the next file, and carry honest cross-pass counters.
    #[test]
    fn checkpoints_fire_at_boundaries_with_correct_indices() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path().join("tree");
        std::fs::create_dir_all(&base).unwrap();
        for i in 0..60 {
            std::fs::write(
                base.join(format!("f{i:02}.js")),
                format!("require('./x.js');\n//# sourceMappingURL=f{i:02}.map\n"),
            )
            .unwrap();
        }
        let mut request = request_for(&base, ResourceLimits::default());
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_events = events.clone();
        request.checkpoint_sink = Some(std::sync::Arc::new(move |cp, snapshot| {
            sink_events
                .lock()
                .unwrap()
                .push((cp.clone(), snapshot.clone()));
        }));
        let provider = BuiltinStaticProvider::new();
        let report = provider.inspect(&request);
        assert_eq!(report.outcome, Outcome::Succeeded);

        let events = events.lock().unwrap();
        let indices: Vec<usize> = events.iter().map(|(cp, _)| cp.next_file_index).collect();
        // 60 files, one checkpoint every 25 analyzed: boundaries at 25 and 50.
        assert_eq!(indices, vec![25, 50], "checkpoint boundaries");
        for (cp, snapshot) in events.iter() {
            assert_eq!(cp.phase, "per_file_analysis");
            // The snapshot carries exactly the findings produced so far.
            assert_eq!(snapshot.findings.len(), cp.files_scanned);
        }
        assert_eq!(events[0].0.files_scanned, 25);
        assert_eq!(events[0].0.next_file_index, 25);
    }

    /// A resumed pass skips the first `from_index` files, keeps ids unique,
    /// and honors run-wide caps across passes.
    #[test]
    fn resumed_pass_skips_completed_files_and_continues_ids() {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path().join("tree");
        std::fs::create_dir_all(&base).unwrap();
        for i in 0..60 {
            std::fs::write(
                base.join(format!("f{i:02}.js")),
                format!("require('./x.js');\n//# sourceMappingURL=f{i:02}.map\n"),
            )
            .unwrap();
        }
        let mut request = request_for(&base, ResourceLimits::default());
        request.resume = Some(ResumeContext {
            from_index: 25,
            finding_offset: 25,
            relationship_offset: 0,
            matches_remaining: 100,
            bytes_remaining: ResourceLimits::default().max_total_bytes,
            prior_files_scanned: 25,
            prior_files_skipped: 0,
            entries_used: 25,
            manifests_parsed: 0,
        });
        let provider = BuiltinStaticProvider::new();
        let report = provider.inspect(&request);
        assert_eq!(report.outcome, Outcome::Succeeded);

        // The earlier pass consumed 25 of the 50 run-wide reference entries,
        // so this pass may record at most 25 more (files f25..f49).
        assert_eq!(
            report.findings.len(),
            25,
            "run-wide max_entries cap honored across passes"
        );
        assert_eq!(report.counts.files_scanned, 35);
        // Ids continue after the earlier pass's findings.
        assert_eq!(report.findings.first().unwrap().id, "f26");
        // The first analyzed file is index 25, never an earlier one.
        let first_file = report.findings[0]
            .location
            .as_ref()
            .and_then(|l| l.file.clone())
            .unwrap_or_default();
        assert!(
            first_file.starts_with("f25"),
            "first analyzed file: {first_file}"
        );
        // The last file analyzed is the last in walk order.
        let last_file = report
            .findings
            .last()
            .unwrap()
            .location
            .as_ref()
            .and_then(|l| l.file.clone())
            .unwrap_or_default();
        assert!(
            last_file.starts_with("f49"),
            "last analyzed file: {last_file}"
        );
    }
}
