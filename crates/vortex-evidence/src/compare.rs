//! Structural comparison of two evidence runs.
//!
//! Comparison is deliberately structural: it reports which findings and
//! relationships exist in one record but not the other. It never claims that
//! a difference is a *behavioral* difference, and every comparison result
//! carries a note saying so.

use crate::model::{EvidenceRun, Finding, Relationship, RunStatus, RunSummary};
use serde::Serialize;
use std::collections::BTreeMap;

/// Maximum entries reported per diff bucket. Larger diffs are summarized by
/// count so a comparison never floods an agent context window.
pub const MAX_DIFF_ENTRIES: usize = 100;

/// A compact finding description used in diff output.
#[derive(Debug, Clone, Serialize)]
pub struct FindingDiffEntry {
    /// Finding type.
    pub kind: String,
    /// One-line summary.
    pub summary: String,
    /// Source location, when known.
    pub location: Option<String>,
    /// Origin classification.
    pub origin: String,
}

/// A compact relationship description used in diff output.
#[derive(Debug, Clone, Serialize)]
pub struct RelationshipDiffEntry {
    /// `from` node id.
    pub from: String,
    /// `to` node id.
    pub to: String,
    /// Relationship type.
    pub kind: String,
    /// Resolution state.
    pub status: String,
    /// Scope.
    pub scope: String,
}

/// Result of comparing two runs.
#[derive(Debug, Clone, Serialize)]
pub struct RunComparison {
    /// Header of run A.
    pub run_a: RunSummary,
    /// Header of run B.
    pub run_b: RunSummary,
    /// Whether both runs inspected the same canonical target path.
    pub same_target_path: bool,
    /// Whether both runs saw the same artifact digest.
    pub same_artifact_digest: bool,
    /// Findings only present in run A.
    pub findings_only_in_a: Vec<FindingDiffEntry>,
    /// Findings only present in run B.
    pub findings_only_in_b: Vec<FindingDiffEntry>,
    /// Relationships only present in run A.
    pub relationships_only_in_a: Vec<RelationshipDiffEntry>,
    /// Relationships only present in run B.
    pub relationships_only_in_b: Vec<RelationshipDiffEntry>,
    /// Status transition, when the statuses differ.
    pub status_change: Option<(String, String)>,
    /// Total counts behind potentially truncated lists.
    pub totals: ComparisonTotals,
    /// True when any diff list was truncated.
    pub truncated: bool,
    /// What changed *inside* findings present in both runs (Phase Four):
    /// dependency declarations, import lists, native symbol lists, source
    /// map counts — recorded text only, never behavioral claims.
    pub semantic_changes: SemanticChanges,
    /// Interpretive notes (always includes the structural-only disclaimer).
    pub notes: Vec<String>,
}

/// Total counts for each diff bucket.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ComparisonTotals {
    /// Findings only in A (before truncation).
    pub findings_only_in_a: usize,
    /// Findings only in B (before truncation).
    pub findings_only_in_b: usize,
    /// Relationships only in A (before truncation).
    pub relationships_only_in_a: usize,
    /// Relationships only in B (before truncation).
    pub relationships_only_in_b: usize,
}

// ---------------------------------------------------------------------------
// semantic changes (Phase Four): what changed inside matched findings
// ---------------------------------------------------------------------------

/// One change to a declared dependency, as recorded text.
///
/// Range strings are compared verbatim: no semver interpretation is ever
/// applied ("^1.2.8" -> "^2.0.0" is a text change, not an upgrade or a
/// breaking-change claim), and nothing here is evidence of behavior.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DependencyChange {
    /// The manifest the change is about (its location in the run).
    pub manifest: String,
    /// Package name, verbatim.
    pub package: String,
    /// The change itself.
    pub change: DependencyChangeKind,
}

/// The kind of a dependency change, with every string recorded verbatim.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DependencyChangeKind {
    /// Declared in run B only.
    Added {
        /// dependencies / dev_dependencies, as recorded.
        section: String,
        /// The declared range text.
        range: String,
    },
    /// Declared in run A only.
    Removed { section: String, range: String },
    /// Declared in both runs; the range text differs.
    RangeChanged {
        section: String,
        from: String,
        to: String,
    },
    /// Declared in both runs; the declaring section moved.
    SectionMoved {
        from_section: String,
        to_section: String,
        from: String,
        to: String,
    },
}

/// Import declaration changes for one file, matched across runs.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FileImportChanges {
    /// The file whose import list changed.
    pub file: String,
    /// Imports declared in B only ("syntax:specifier").
    pub added: Vec<String>,
    /// Imports declared in A only ("syntax:specifier").
    pub removed: Vec<String>,
}

/// Native structural changes for one file, matched across runs.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NativeSymbolChanges {
    /// The file the finding is about.
    pub file: String,
    /// The finding kind the change came from (elf_imports / pe_imports /
    /// pe_exports).
    pub finding_kind: String,
    /// Entries present in B only. Plain names for symbols and exports;
    /// "dll=NAME" for a whole new DLL, "DLL::function" for functions.
    pub added: Vec<String>,
    /// Entries present in A only, same formats.
    pub removed: Vec<String>,
}

/// Count changes for one source map document, matched across runs.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SourcemapChange {
    /// The map file.
    pub file: String,
    /// "field: from -> to" entries (sources, segments, mapped lines).
    pub fields: Vec<String>,
}

/// The Phase Four semantic layer: what changed *inside* findings that
/// exist in both runs, computed over the recorded evidence only (listings
/// truncated by limits are compared exactly as recorded).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct SemanticChanges {
    /// Dependency declaration changes, matched per manifest.
    pub manifest_dependency_changes: Vec<DependencyChange>,
    /// Manifests recorded only in run A: their dependency sets are not
    /// enumerated per package (the whole declaration set is absent from B).
    pub manifests_only_in_a: Vec<String>,
    /// Manifests recorded only in run B (same rule, mirrored).
    pub manifests_only_in_b: Vec<String>,
    /// Per-file import declaration changes.
    pub import_changes: Vec<FileImportChanges>,
    /// Per-file native structural changes.
    pub native_symbol_changes: Vec<NativeSymbolChanges>,
    /// Per-map count changes.
    pub sourcemap_changes: Vec<SourcemapChange>,
    /// True when any list was truncated to MAX_DIFF_ENTRIES.
    pub truncated: bool,
}

impl SemanticChanges {
    /// Whether anything changed at the semantic layer.
    pub fn is_empty(&self) -> bool {
        self.manifest_dependency_changes.is_empty()
            && self.manifests_only_in_a.is_empty()
            && self.manifests_only_in_b.is_empty()
            && self.import_changes.is_empty()
            && self.native_symbol_changes.is_empty()
            && self.sourcemap_changes.is_empty()
    }
}

/// The location file of a finding, when it has one.
fn location_file(finding: &Finding) -> Option<&str> {
    finding.location.as_ref().and_then(|l| l.file.as_deref())
}

/// (name, range) pairs of a manifest section, as recorded.
fn manifest_section(details: &serde_json::Value, key: &str) -> Option<Vec<(String, String)>> {
    let entries = details.get(key)?.as_array()?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = entry.get("name")?.as_str()?;
        let range = entry.get("range").and_then(|r| r.as_str()).unwrap_or("");
        out.push((name.to_string(), range.to_string()));
    }
    Some(out)
}

/// Pair findings of one kind by location file. Findings without a file
/// location are skipped (there is nothing to match them by).
fn pair_by_file<'a>(
    a: &'a [Finding],
    b: &'a [Finding],
    kind: &str,
) -> (
    Vec<(&'a Finding, &'a Finding)>,
    Vec<&'a Finding>,
    Vec<&'a Finding>,
) {
    let mut pairs = Vec::new();
    let mut only_a = Vec::new();
    let mut only_b = Vec::new();
    let b_of_kind: Vec<&Finding> = b
        .iter()
        .filter(|f| f.kind == kind && location_file(f).is_some())
        .collect();
    let mut matched = vec![false; b_of_kind.len()];
    for finding_a in a.iter().filter(|f| f.kind == kind) {
        let Some(file_a) = location_file(finding_a) else {
            continue;
        };
        let mut found = None;
        for (index, finding_b) in b_of_kind.iter().enumerate() {
            if !matched[index] && location_file(finding_b) == Some(file_a) {
                found = Some(index);
                break;
            }
        }
        match found {
            Some(index) => {
                matched[index] = true;
                pairs.push((finding_a, b_of_kind[index]));
            }
            None => only_a.push(finding_a),
        }
    }
    for (index, finding_b) in b_of_kind.iter().enumerate() {
        if !matched[index] {
            only_b.push(*finding_b);
        }
    }
    (pairs, only_a, only_b)
}

/// Multiset diff of string lists: (only in a, only in b).
fn list_diff(a: &[String], b: &[String]) -> (Vec<String>, Vec<String>) {
    let mut counts_b: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    for item in b {
        *counts_b.entry(item.clone()).or_insert(0) += 1;
    }
    let mut only_a = Vec::new();
    for item in a {
        match counts_b.get_mut(item) {
            Some(count) if *count > 0 => *count -= 1,
            _ => only_a.push(item.clone()),
        }
    }
    let mut counts_a: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    for item in a {
        *counts_a.entry(item.clone()).or_insert(0) += 1;
    }
    let mut only_b = Vec::new();
    for item in b {
        match counts_a.get_mut(item) {
            Some(count) if *count > 0 => *count -= 1,
            _ => only_b.push(item.clone()),
        }
    }
    (only_a, only_b)
}

/// JSON string-list field of a finding detail ("symbols", "names").
fn string_list(details: &serde_json::Value, key: &str) -> Vec<String> {
    details
        .get(key)
        .and_then(|v| v.as_array())
        .map(|array| {
            array
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Compute the semantic layer between two runs.
fn semantic_changes(a: &EvidenceRun, b: &EvidenceRun) -> SemanticChanges {
    let mut out = SemanticChanges::default();
    let mut truncated = false;

    // ---- manifests ----
    let (manifest_pairs, manifests_only_a, manifests_only_b) =
        pair_by_file(&a.findings, &b.findings, "package_manifest");
    for finding in &manifests_only_a {
        if let Some(file) = location_file(finding) {
            if out.manifests_only_in_a.len() < MAX_DIFF_ENTRIES {
                out.manifests_only_in_a.push(file.to_string());
            } else {
                truncated = true;
            }
        }
    }
    for finding in &manifests_only_b {
        if let Some(file) = location_file(finding) {
            if out.manifests_only_in_b.len() < MAX_DIFF_ENTRIES {
                out.manifests_only_in_b.push(file.to_string());
            } else {
                truncated = true;
            }
        }
    }
    for (finding_a, finding_b) in &manifest_pairs {
        let file = location_file(finding_a).unwrap_or_default().to_string();
        for section in ["dependencies", "dev_dependencies"] {
            let entries_a = manifest_section(&finding_a.details, section).unwrap_or_default();
            let entries_b = manifest_section(&finding_b.details, section).unwrap_or_default();
            // Index the other section of the opposite run for moved deps.
            let other_a = manifest_section(
                &finding_a.details,
                if section == "dependencies" {
                    "dev_dependencies"
                } else {
                    "dependencies"
                },
            )
            .unwrap_or_default();
            let other_b = manifest_section(
                &finding_b.details,
                if section == "dependencies" {
                    "dev_dependencies"
                } else {
                    "dependencies"
                },
            )
            .unwrap_or_default();
            for (name, range_a) in &entries_a {
                let in_b_same = entries_b.iter().find(|(n, _)| n == name);
                let in_b_other = other_b.iter().find(|(n, _)| n == name);
                let change = match (in_b_same, in_b_other) {
                    (Some((_, range_b)), _) => {
                        if range_b == range_a {
                            continue; // unchanged
                        }
                        DependencyChangeKind::RangeChanged {
                            section: section.to_string(),
                            from: range_a.clone(),
                            to: range_b.clone(),
                        }
                    }
                    (None, Some((_, range_b))) => DependencyChangeKind::SectionMoved {
                        from_section: section.to_string(),
                        to_section: if section == "dependencies" {
                            "dev_dependencies".to_string()
                        } else {
                            "dependencies".to_string()
                        },
                        from: range_a.clone(),
                        to: range_b.clone(),
                    },
                    (None, None) => DependencyChangeKind::Removed {
                        section: section.to_string(),
                        range: range_a.clone(),
                    },
                };
                if out.manifest_dependency_changes.len() < MAX_DIFF_ENTRIES {
                    out.manifest_dependency_changes.push(DependencyChange {
                        manifest: file.clone(),
                        package: name.clone(),
                        change,
                    });
                } else {
                    truncated = true;
                }
            }
            for (name, range_b) in &entries_b {
                let in_a_same = entries_a.iter().find(|(n, _)| n == name);
                let in_a_other = other_a.iter().find(|(n, _)| n == name);
                if in_a_same.is_none() && in_a_other.is_none() {
                    if out.manifest_dependency_changes.len() < MAX_DIFF_ENTRIES {
                        out.manifest_dependency_changes.push(DependencyChange {
                            manifest: file.clone(),
                            package: name.clone(),
                            change: DependencyChangeKind::Added {
                                section: section.to_string(),
                                range: range_b.clone(),
                            },
                        });
                    } else {
                        truncated = true;
                    }
                }
            }
        }
    }

    // ---- per-file import declarations ----
    let (import_pairs, _, _) = pair_by_file(&a.findings, &b.findings, "imports_summary");
    for (finding_a, finding_b) in &import_pairs {
        let imports_a = import_entries(&finding_a.details);
        let imports_b = import_entries(&finding_b.details);
        let (removed, added) = list_diff(&imports_a, &imports_b);
        if added.is_empty() && removed.is_empty() {
            continue;
        }
        if out.import_changes.len() < MAX_DIFF_ENTRIES {
            out.import_changes.push(FileImportChanges {
                file: location_file(finding_a).unwrap_or_default().to_string(),
                added,
                removed,
            });
        } else {
            truncated = true;
        }
    }

    // ---- native structural lists ----
    for kind in ["elf_imports", "pe_exports"] {
        let (pairs, _, _) = pair_by_file(&a.findings, &b.findings, kind);
        for (finding_a, finding_b) in &pairs {
            let list_a = string_list(
                &finding_a.details,
                if kind == "elf_imports" {
                    "symbols"
                } else {
                    "names"
                },
            );
            let list_b = string_list(
                &finding_b.details,
                if kind == "elf_imports" {
                    "symbols"
                } else {
                    "names"
                },
            );
            let (removed, added) = list_diff(&list_a, &list_b);
            if added.is_empty() && removed.is_empty() {
                continue;
            }
            if out.native_symbol_changes.len() < MAX_DIFF_ENTRIES {
                out.native_symbol_changes.push(NativeSymbolChanges {
                    file: location_file(finding_a).unwrap_or_default().to_string(),
                    finding_kind: kind.to_string(),
                    added,
                    removed,
                });
            } else {
                truncated = true;
            }
        }
    }
    // pe_imports: DLL level plus per-DLL functions.
    let (pe_pairs, _, _) = pair_by_file(&a.findings, &b.findings, "pe_imports");
    for (finding_a, finding_b) in &pe_pairs {
        let dlls_a = pe_import_map(&finding_a.details);
        let dlls_b = pe_import_map(&finding_b.details);
        let mut added = Vec::new();
        let mut removed = Vec::new();
        for (dll, functions_a) in &dlls_a {
            match dlls_b.get(dll) {
                Some(functions_b) => {
                    let (fn_removed, fn_added) = list_diff(functions_a, functions_b);
                    for f in fn_added {
                        added.push(format!("{dll}::{f}"));
                    }
                    for f in fn_removed {
                        removed.push(format!("{dll}::{f}"));
                    }
                }
                None => {
                    for f in functions_a {
                        removed.push(format!("{dll}::{f}"));
                    }
                }
            }
        }
        for (dll, functions_b) in &dlls_b {
            if !dlls_a.contains_key(dll) {
                added.push(format!("dll={dll}"));
                for f in functions_b {
                    added.push(format!("{dll}::{f}"));
                }
            }
        }
        if added.is_empty() && removed.is_empty() {
            continue;
        }
        if out.native_symbol_changes.len() < MAX_DIFF_ENTRIES {
            out.native_symbol_changes.push(NativeSymbolChanges {
                file: location_file(finding_a).unwrap_or_default().to_string(),
                finding_kind: "pe_imports".to_string(),
                added,
                removed,
            });
        } else {
            truncated = true;
        }
    }

    // ---- source map documents ----
    let (map_pairs, _, _) = pair_by_file(&a.findings, &b.findings, "sourcemap_document");
    for (finding_a, finding_b) in &map_pairs {
        let mut fields = Vec::new();
        for (label, path) in [
            ("sources", "sources.total"),
            ("segments", "segments.total"),
            ("mapped lines", "generated_lines.with_mappings"),
        ] {
            let value_a = count_at(finding_a, path);
            let value_b = count_at(finding_b, path);
            if value_a != value_b {
                fields.push(format!(
                    "{label}: {} -> {}",
                    value_a
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "<absent>".into()),
                    value_b
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "<absent>".into())
                ));
            }
        }
        if fields.is_empty() {
            continue;
        }
        if out.sourcemap_changes.len() < MAX_DIFF_ENTRIES {
            out.sourcemap_changes.push(SourcemapChange {
                file: location_file(finding_a).unwrap_or_default().to_string(),
                fields,
            });
        } else {
            truncated = true;
        }
    }

    out.truncated = truncated;
    out
}

/// syntax:specifier pairs of an imports_summary finding.
fn import_entries(details: &serde_json::Value) -> Vec<String> {
    details
        .get("imports")
        .and_then(|v| v.as_array())
        .map(|array| {
            array
                .iter()
                .filter_map(|entry| {
                    let syntax = entry.get("syntax")?.as_str()?;
                    let specifier = entry.get("specifier")?.as_str()?;
                    Some(format!("{syntax}:{specifier}"))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// DLL -> functions map of a pe_imports finding.
fn pe_import_map(details: &serde_json::Value) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out = std::collections::BTreeMap::new();
    let Some(imports) = details.get("imports").and_then(|v| v.as_array()) else {
        return out;
    };
    for dll_entry in imports {
        let Some(dll) = dll_entry.get("dll").and_then(|d| d.as_str()) else {
            continue;
        };
        let functions: Vec<String> = dll_entry
            .get("functions")
            .and_then(|f| f.as_array())
            .map(|array| {
                array
                    .iter()
                    .filter_map(|f| f.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        out.insert(dll.to_string(), functions);
    }
    out
}

/// Numeric value at a dotted path in finding details.
fn count_at(finding: &Finding, path: &str) -> Option<u64> {
    let mut node = &finding.details;
    for part in path.split('.') {
        node = node.get(part)?;
    }
    node.as_u64()
}

fn finding_key(finding: &Finding) -> String {
    let location = finding
        .location
        .as_ref()
        .map(|l| {
            format!(
                "{}:{}:{}",
                l.file.as_deref().unwrap_or(""),
                l.line.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
                l.column
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".into()),
            )
        })
        .unwrap_or_default();
    format!("{}|{}|{}", finding.kind, location, finding.summary)
}

fn finding_entry(finding: &Finding) -> FindingDiffEntry {
    FindingDiffEntry {
        kind: finding.kind.clone(),
        summary: finding.summary.clone(),
        location: finding
            .location
            .as_ref()
            .map(|l| match (l.file.as_deref(), l.line) {
                (Some(file), Some(line)) => format!("{file}:{line}"),
                (Some(file), None) => file.to_string(),
                (None, _) => "-".to_string(),
            }),
        origin: finding.origin.as_str().to_string(),
    }
}

fn relationship_key(relationship: &Relationship) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        relationship.from.id,
        relationship.to.id,
        relationship.kind,
        relationship.status_serialized(),
        relationship.scope_serialized()
    )
}

impl Relationship {
    fn status_serialized(&self) -> String {
        serde_json::to_value(self.status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".into())
    }

    fn scope_serialized(&self) -> String {
        serde_json::to_value(self.scope)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".into())
    }
}

fn relationship_entry(relationship: &Relationship) -> RelationshipDiffEntry {
    RelationshipDiffEntry {
        from: relationship.from.id.clone(),
        to: relationship.to.id.clone(),
        kind: relationship.kind.clone(),
        status: relationship.status_serialized(),
        scope: relationship.scope_serialized(),
    }
}

/// Multiset difference: keys with counts. Returns entries that exist in `a`
/// more times than in `b`, preserving multiplicity.
fn multiset_difference<T, E, K, F>(items_a: &[T], items_b: &[T], key: K, entry: F) -> Vec<E>
where
    K: Fn(&T) -> String,
    F: Fn(&T) -> E,
{
    let mut counts_b: BTreeMap<String, i64> = BTreeMap::new();
    for item in items_b {
        *counts_b.entry(key(item)).or_insert(0) += 1;
    }
    let mut result = Vec::new();
    for item in items_a {
        let k = key(item);
        let remaining = counts_b.get_mut(&k).map(|c| {
            *c -= 1;
            *c
        });
        match remaining {
            Some(n) if n >= 0 => {}
            _ => result.push(entry(item)),
        }
    }
    result
}

/// Compare two stored runs.
pub fn compare_runs(a: &EvidenceRun, b: &EvidenceRun) -> RunComparison {
    let findings_only_in_a =
        multiset_difference(&a.findings, &b.findings, finding_key, finding_entry);
    let findings_only_in_b =
        multiset_difference(&b.findings, &a.findings, finding_key, finding_entry);
    let relationships_only_in_a = multiset_difference(
        &a.relationships,
        &b.relationships,
        relationship_key,
        relationship_entry,
    );
    let relationships_only_in_b = multiset_difference(
        &b.relationships,
        &a.relationships,
        relationship_key,
        relationship_entry,
    );

    let totals = ComparisonTotals {
        findings_only_in_a: findings_only_in_a.len(),
        findings_only_in_b: findings_only_in_b.len(),
        relationships_only_in_a: relationships_only_in_a.len(),
        relationships_only_in_b: relationships_only_in_b.len(),
    };

    let truncated = totals.findings_only_in_a > MAX_DIFF_ENTRIES
        || totals.findings_only_in_b > MAX_DIFF_ENTRIES
        || totals.relationships_only_in_a > MAX_DIFF_ENTRIES
        || totals.relationships_only_in_b > MAX_DIFF_ENTRIES;

    let status_change = if a.status != b.status {
        Some((a.status.as_str().to_string(), b.status.as_str().to_string()))
    } else {
        None
    };

    // Phase Four: the semantic layer over matched findings.
    let semantics = semantic_changes(a, b);

    let mut notes = vec![
        "Structural comparison only: differences describe the recorded evidence, not confirmed behavioral changes.".to_string(),
    ];
    if !semantics.is_empty() {
        notes.push(
            "semantic_changes describe recorded declarations and structure as text; \
             ranges are compared verbatim (no semver interpretation) and nothing in \
             them is evidence of behavioral change or equivalence"
                .to_string(),
        );
    }
    for (label, files) in [
        ("A", &semantics.manifests_only_in_a),
        ("B", &semantics.manifests_only_in_b),
    ] {
        if !files.is_empty() {
            notes.push(format!(
                "manifest(s) recorded only in run {label} ({files:?}): their dependency \
                 sets are not enumerated per package — the whole declaration set is \
                 new or absent, and the finding diff already carries the manifest itself"
            ));
        }
    }
    if !a.operation.is_empty() && a.operation != b.operation {
        notes.push(format!(
            "runs used different operations ('{}' vs '{}'); comparisons across operations are informational only",
            a.operation, b.operation
        ));
    }
    if a.provider.id != b.provider.id || a.provider.version != b.provider.version {
        notes.push(format!(
            "runs came from different providers ({} {} vs {} {})",
            a.provider.id, a.provider.version, b.provider.id, b.provider.version
        ));
    }
    // Incompleteness disclosure (upstream Lesson 2): a run that did not
    // end `succeeded` may be missing findings for reasons unrelated to the
    // artifact — truncation, cancellation, or failure. Its side of the diff
    // must never read as proof that something was removed.
    for (label, run) in [("A", a), ("B", b)] {
        if run.status != RunStatus::Succeeded {
            notes.push(format!(
                "run {label} ended '{}'; its recorded evidence may be incomplete — \
                 findings absent from run {label} are not established as absent from \
                 the artifact",
                run.status.as_str()
            ));
        }
    }
    if a.status != RunStatus::Succeeded && b.status != RunStatus::Succeeded {
        notes.push(
            "neither run is a complete record; an empty diff is not evidence of \
             equivalence"
                .to_string(),
        );
    }
    if a.target.sha256 != b.target.sha256 {
        notes.push(
            "the runs examined different artifacts (SHA-256 digests differ); the \
             differences below include the artifact change itself"
                .to_string(),
        );
    }
    if truncated {
        notes.push(format!(
            "diff lists were truncated to {MAX_DIFF_ENTRIES} entries per bucket; see totals for full counts"
        ));
    }

    RunComparison {
        run_a: RunSummary::from(a),
        run_b: RunSummary::from(b),
        same_target_path: a.target.canonical_path == b.target.canonical_path,
        same_artifact_digest: a.target.sha256 == b.target.sha256,
        findings_only_in_a: findings_only_in_a
            .into_iter()
            .take(MAX_DIFF_ENTRIES)
            .collect(),
        findings_only_in_b: findings_only_in_b
            .into_iter()
            .take(MAX_DIFF_ENTRIES)
            .collect(),
        relationships_only_in_a: relationships_only_in_a
            .into_iter()
            .take(MAX_DIFF_ENTRIES)
            .collect(),
        relationships_only_in_b: relationships_only_in_b
            .into_iter()
            .take(MAX_DIFF_ENTRIES)
            .collect(),
        status_change,
        totals,
        truncated,
        semantic_changes: semantics,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn run_with_findings(tag: &str, summaries: &[&str]) -> EvidenceRun {
        let mut run = EvidenceRun::new_running(
            "inspect",
            TargetIdentity {
                input_path: tag.into(),
                canonical_path: format!("/tmp/{tag}"),
                kind: "file".into(),
                sha256: "c".repeat(64),
                size_bytes: 1,
                file_count: None,
            },
            ProviderRef {
                id: "builtin-static".into(),
                version: "0.1.0".into(),
            },
            ToolInfo {
                name: "vortex".into(),
                version: "0.1.0".into(),
                invocation: "test".into(),
            },
            serde_json::json!({}),
        );
        for (index, summary) in summaries.iter().enumerate() {
            run.findings.push(Finding {
                id: format!("f{}", index + 1),
                kind: "file".into(),
                origin: Origin::Observed,
                summary: summary.to_string(),
                location: None,
                artifact: None,
                details: serde_json::json!({}),
            });
        }
        run.finalize(RunStatus::Succeeded, None);
        run
    }

    /// A run carrying arbitrary findings with locations and details.
    fn run_with_detailed_findings(tag: &str, findings: Vec<Finding>) -> EvidenceRun {
        let mut run = EvidenceRun::new_running(
            "inspect",
            TargetIdentity {
                input_path: tag.into(),
                canonical_path: format!("/tmp/{tag}"),
                kind: "file".into(),
                sha256: "c".repeat(64),
                size_bytes: 1,
                file_count: None,
            },
            ProviderRef {
                id: "builtin-static".into(),
                version: "0.1.0".into(),
            },
            ToolInfo {
                name: "vortex".into(),
                version: "0.1.0".into(),
                invocation: "test".into(),
            },
            serde_json::json!({}),
        );
        run.findings = findings;
        run.finalize(RunStatus::Succeeded, None);
        run
    }

    fn manifest_finding(file: &str, deps: &[(&str, &str)], dev: &[(&str, &str)]) -> Finding {
        Finding {
            id: "fm".into(),
            kind: "package_manifest".into(),
            origin: Origin::Observed,
            summary: format!("{file} manifest"),
            location: Some(Location::file(file)),
            artifact: None,
            details: serde_json::json!({
                "dependencies": deps.iter().map(|(n, r)| serde_json::json!({"name": n, "range": r})).collect::<Vec<_>>(),
                "dev_dependencies": dev.iter().map(|(n, r)| serde_json::json!({"name": n, "range": r})).collect::<Vec<_>>(),
            }),
        }
    }

    #[test]
    fn dependency_range_changes_are_reported_verbatim() {
        let a = run_with_detailed_findings(
            "a",
            vec![manifest_finding(
                "package.json",
                &[("minimist", "^1.2.8"), ("electron", "^33.0.0")],
                &[],
            )],
        );
        let b = run_with_detailed_findings(
            "b",
            vec![manifest_finding(
                "package.json",
                &[("minimist", "^2.0.0"), ("electron", "^33.0.0")],
                &[],
            )],
        );
        let comparison = compare_runs(&a, &b);
        let changes = &comparison.semantic_changes.manifest_dependency_changes;
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].package, "minimist");
        match &changes[0].change {
            DependencyChangeKind::RangeChanged { section, from, to } => {
                assert_eq!(section, "dependencies");
                assert_eq!(from, "^1.2.8");
                assert_eq!(to, "^2.0.0");
            }
            other => panic!("expected a range change, got {other:?}"),
        }
        // The framing note exists and never interprets semver.
        assert!(comparison
            .notes
            .iter()
            .any(|n| n.contains("no semver interpretation")));
        let serialized = serde_json::to_string(&comparison.semantic_changes).unwrap();
        assert!(!serialized.to_lowercase().contains("upgrade"));
        assert!(!serialized.to_lowercase().contains("breaking"));
        assert!(!serialized.to_lowercase().contains("downgrade"));
    }

    #[test]
    fn dependency_additions_and_removals_are_reported() {
        let a = run_with_detailed_findings(
            "a",
            vec![manifest_finding(
                "package.json",
                &[("kept", "^1.0.0"), ("gone", "^2.0.0")],
                &[],
            )],
        );
        let b = run_with_detailed_findings(
            "b",
            vec![manifest_finding(
                "package.json",
                &[("kept", "^1.0.0"), ("new", "^3.0.0")],
                &[],
            )],
        );
        let comparison = compare_runs(&a, &b);
        let changes = &comparison.semantic_changes.manifest_dependency_changes;
        assert_eq!(changes.len(), 2);
        for change in changes {
            match (&change.package[..], &change.change) {
                ("new", DependencyChangeKind::Added { section, range }) => {
                    assert_eq!(section, "dependencies");
                    assert_eq!(range, "^3.0.0");
                }
                ("gone", DependencyChangeKind::Removed { section, range }) => {
                    assert_eq!(section, "dependencies");
                    assert_eq!(range, "^2.0.0");
                }
                other => panic!("unexpected change {other:?}"),
            }
        }
    }

    #[test]
    fn dependency_section_moves_are_reported_with_both_ranges() {
        let a = run_with_detailed_findings(
            "a",
            vec![manifest_finding(
                "package.json",
                &[("electron", "^33.0.0")],
                &[],
            )],
        );
        // Moved to devDependencies AND the range text changed.
        let b = run_with_detailed_findings(
            "b",
            vec![manifest_finding(
                "package.json",
                &[],
                &[("electron", "^34.1.2")],
            )],
        );
        let comparison = compare_runs(&a, &b);
        let changes = &comparison.semantic_changes.manifest_dependency_changes;
        assert_eq!(changes.len(), 1);
        match &changes[0].change {
            DependencyChangeKind::SectionMoved {
                from_section,
                to_section,
                from,
                to,
            } => {
                assert_eq!(from_section, "dependencies");
                assert_eq!(to_section, "dev_dependencies");
                assert_eq!(from, "^33.0.0");
                assert_eq!(to, "^34.1.2");
            }
            other => panic!("expected a section move, got {other:?}"),
        }
    }

    #[test]
    fn manifests_only_in_one_side_are_not_enumerated_per_package() {
        let a = run_with_detailed_findings(
            "a",
            vec![
                manifest_finding("package.json", &[("shared", "^1.0.0")], &[]),
                manifest_finding("nested/package.json", &[("only-in-a", "^1.0.0")], &[]),
            ],
        );
        let b = run_with_detailed_findings(
            "b",
            vec![
                manifest_finding("package.json", &[("shared", "^1.0.0")], &[]),
                manifest_finding("other/package.json", &[("only-in-b", "^2.0.0")], &[]),
            ],
        );
        let comparison = compare_runs(&a, &b);
        let semantics = &comparison.semantic_changes;
        assert!(semantics.manifest_dependency_changes.is_empty());
        assert_eq!(semantics.manifests_only_in_a, vec!["nested/package.json"]);
        assert_eq!(semantics.manifests_only_in_b, vec!["other/package.json"]);
        assert!(comparison
            .notes
            .iter()
            .any(|n| n.contains("not enumerated per package")));
    }

    #[test]
    fn import_specifier_changes_are_reported_per_file() {
        let imports = |entries: &[(&str, &str)]| {
            serde_json::json!({
                "imports": entries.iter().map(|(syntax, specifier)| serde_json::json!({
                    "syntax": syntax, "specifier": specifier, "line": 1, "column": 1,
                })).collect::<Vec<_>>(),
            })
        };
        let a = run_with_detailed_findings(
            "a",
            vec![Finding {
                id: "f1".into(),
                kind: "imports_summary".into(),
                origin: Origin::Observed,
                summary: "src/app.js".into(),
                location: Some(Location::file("src/app.js")),
                artifact: None,
                details: imports(&[("requires", "./kept"), ("requires", "./gone")]),
            }],
        );
        let b = run_with_detailed_findings(
            "b",
            vec![Finding {
                id: "f1".into(),
                kind: "imports_summary".into(),
                origin: Origin::Observed,
                summary: "src/app.js".into(),
                location: Some(Location::file("src/app.js")),
                artifact: None,
                details: imports(&[("requires", "./kept"), ("requires", "./added")]),
            }],
        );
        let comparison = compare_runs(&a, &b);
        let changes = &comparison.semantic_changes.import_changes;
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].file, "src/app.js");
        assert_eq!(changes[0].added, vec!["requires:./added"]);
        assert_eq!(changes[0].removed, vec!["requires:./gone"]);
    }

    #[test]
    fn native_symbol_changes_are_reported_per_list() {
        let elf_imports = |symbols: &[&str]| serde_json::json!({ "symbols": symbols });
        let pe_imports = |dlls: &[(&str, &[&str])]| {
            serde_json::json!({
                "imports": dlls.iter().map(|(dll, fns)| serde_json::json!({
                    "dll": dll,
                    "functions": fns,
                })).collect::<Vec<_>>(),
            })
        };
        let a = run_with_detailed_findings(
            "a",
            vec![
                Finding {
                    id: "f1".into(),
                    kind: "elf_imports".into(),
                    origin: Origin::Observed,
                    summary: "bin".into(),
                    location: Some(Location::file("bin/app")),
                    artifact: None,
                    details: elf_imports(&["malloc", "printf"]),
                },
                Finding {
                    id: "f2".into(),
                    kind: "pe_imports".into(),
                    origin: Origin::Observed,
                    summary: "app.exe".into(),
                    location: Some(Location::file("dist/app.exe")),
                    artifact: None,
                    details: pe_imports(&[("KERNEL32.dll", &["CloseHandle", "ReadFile"])]),
                },
            ],
        );
        let b = run_with_detailed_findings(
            "b",
            vec![
                Finding {
                    id: "f1".into(),
                    kind: "elf_imports".into(),
                    origin: Origin::Observed,
                    summary: "bin".into(),
                    location: Some(Location::file("bin/app")),
                    artifact: None,
                    details: elf_imports(&["malloc", "mmap"]),
                },
                Finding {
                    id: "f2".into(),
                    kind: "pe_imports".into(),
                    origin: Origin::Observed,
                    summary: "app.exe".into(),
                    location: Some(Location::file("dist/app.exe")),
                    artifact: None,
                    details: pe_imports(&[
                        ("KERNEL32.dll", &["CloseHandle"]),
                        ("NEW.dll", &["Fresh"]),
                    ]),
                },
            ],
        );
        let comparison = compare_runs(&a, &b);
        let changes = &comparison.semantic_changes.native_symbol_changes;
        assert_eq!(changes.len(), 2);
        let elf = changes
            .iter()
            .find(|c| c.finding_kind == "elf_imports")
            .unwrap();
        assert_eq!(elf.added, vec!["mmap"]);
        assert_eq!(elf.removed, vec!["printf"]);
        let pe = changes
            .iter()
            .find(|c| c.finding_kind == "pe_imports")
            .unwrap();
        assert!(pe.added.contains(&"dll=NEW.dll".to_string()));
        assert!(pe.added.contains(&"NEW.dll::Fresh".to_string()));
        assert_eq!(pe.removed, vec!["KERNEL32.dll::ReadFile"]);
    }

    #[test]
    fn sourcemap_count_changes_are_reported_as_text() {
        let map = |sources: u64, segments: u64, lines: u64| {
            serde_json::json!({
                "sources": {"total": sources},
                "segments": {"total": segments},
                "generated_lines": {"spanned": lines, "with_mappings": lines},
            })
        };
        let a = run_with_detailed_findings(
            "a",
            vec![Finding {
                id: "f1".into(),
                kind: "sourcemap_document".into(),
                origin: Origin::Observed,
                summary: "map".into(),
                location: Some(Location::file("dist/app.js.map")),
                artifact: None,
                details: map(2, 5, 2),
            }],
        );
        let b = run_with_detailed_findings(
            "b",
            vec![Finding {
                id: "f1".into(),
                kind: "sourcemap_document".into(),
                origin: Origin::Observed,
                summary: "map".into(),
                location: Some(Location::file("dist/app.js.map")),
                artifact: None,
                details: map(3, 4, 2),
            }],
        );
        let comparison = compare_runs(&a, &b);
        let changes = &comparison.semantic_changes.sourcemap_changes;
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].file, "dist/app.js.map");
        assert!(changes[0].fields.contains(&"sources: 2 -> 3".to_string()));
        assert!(changes[0].fields.contains(&"segments: 5 -> 4".to_string()));
        assert!(
            !changes[0].fields.iter().any(|f| f.contains("mapped lines")),
            "unchanged fields are not listed"
        );
    }

    #[test]
    fn identical_runs_have_an_empty_semantic_layer() {
        let a = run_with_detailed_findings(
            "a",
            vec![manifest_finding(
                "package.json",
                &[("minimist", "^1.2.8")],
                &[],
            )],
        );
        let b = run_with_detailed_findings(
            "a",
            vec![manifest_finding(
                "package.json",
                &[("minimist", "^1.2.8")],
                &[],
            )],
        );
        let comparison = compare_runs(&a, &b);
        assert!(comparison.semantic_changes.is_empty());
        // No semantic note, and no equivalence claim either.
        assert!(!comparison
            .notes
            .iter()
            .any(|n| n.contains("semantic_changes describe")));
        assert!(!comparison.notes.iter().any(|n| n.contains("equivalence")));
    }

    #[test]
    fn semantic_lists_are_bounded() {
        let many: Vec<(&str, &str)> = (0..200)
            .map(|i| {
                let name: &'static str = Box::leak(format!("pkg-{i}").into_boxed_str());
                (name, "^1.0.0")
            })
            .collect();
        let a = run_with_detailed_findings("a", vec![manifest_finding("package.json", &many, &[])]);
        let b = run_with_detailed_findings("b", vec![manifest_finding("package.json", &[], &[])]);
        let comparison = compare_runs(&a, &b);
        let semantics = &comparison.semantic_changes;
        assert!(semantics.truncated);
        assert_eq!(
            semantics.manifest_dependency_changes.len(),
            MAX_DIFF_ENTRIES
        );
    }

    #[test]
    fn identical_runs_have_no_diffs() {
        let a = run_with_findings("a", &["one", "two"]);
        let b = run_with_findings("a", &["one", "two"]);
        let comparison = compare_runs(&a, &b);
        assert!(comparison.findings_only_in_a.is_empty());
        assert!(comparison.findings_only_in_b.is_empty());
        assert!(comparison.same_artifact_digest);
        assert!(comparison.notes[0].contains("Structural"));
    }

    #[test]
    fn added_and_removed_findings_are_reported() {
        let a = run_with_findings("a", &["kept", "removed"]);
        let b = run_with_findings("a", &["kept", "added"]);
        let comparison = compare_runs(&a, &b);
        assert_eq!(comparison.findings_only_in_a.len(), 1);
        assert_eq!(comparison.findings_only_in_a[0].summary, "removed");
        assert_eq!(comparison.findings_only_in_b.len(), 1);
        assert_eq!(comparison.findings_only_in_b[0].summary, "added");
    }

    #[test]
    fn digest_change_is_flagged_without_behavioral_claims() {
        let a = run_with_findings("a", &["x"]);
        let mut b = run_with_findings("b", &["x"]);
        b.target.sha256 = "d".repeat(64);
        let comparison = compare_runs(&a, &b);
        assert!(!comparison.same_artifact_digest);
        assert!(!comparison.same_target_path);
        // The disclaimer must be present, and no note may claim a confirmed
        // behavioral difference (the disclaimer itself negates it).
        assert!(comparison
            .notes
            .iter()
            .any(|n| n.contains("Structural comparison only")));
        assert!(!comparison
            .notes
            .iter()
            .any(
                |n| n.to_lowercase().contains("confirmed behavioral change") && !n.contains("not")
            ));
    }

    #[test]
    fn duplicate_findings_are_compared_as_multisets() {
        let a = run_with_findings("a", &["same", "same"]);
        let b = run_with_findings("a", &["same"]);
        let comparison = compare_runs(&a, &b);
        assert_eq!(comparison.totals.findings_only_in_a, 1);
        assert_eq!(comparison.totals.findings_only_in_b, 0);
    }

    #[test]
    fn diff_lists_are_bounded() {
        let many: Vec<String> = (0..500).map(|i| format!("finding-{i}")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let a = run_with_findings("a", &refs);
        let b = run_with_findings("a", &[]);
        let comparison = compare_runs(&a, &b);
        assert_eq!(comparison.findings_only_in_a.len(), MAX_DIFF_ENTRIES);
        assert_eq!(comparison.totals.findings_only_in_a, 500);
        assert!(comparison.truncated);
    }

    #[test]
    fn non_succeeded_runs_are_disclosed_as_incomplete_evidence() {
        let a = run_with_findings("a", &["one", "two"]);
        let mut b = run_with_findings("a", &["one"]);
        b.status = RunStatus::Partial;
        let comparison = compare_runs(&a, &b);
        assert!(comparison
            .notes
            .iter()
            .any(|n| n.contains("run B ended 'partial'")));
        assert!(comparison
            .notes
            .iter()
            .any(|n| n.contains("not established as absent from the artifact")));
        // The structural diff itself is still reported — with the caveat.
        assert_eq!(comparison.findings_only_in_a.len(), 1);
    }

    #[test]
    fn two_incomplete_runs_never_imply_equivalence() {
        let mut a = run_with_findings("a", &[]);
        let mut b = run_with_findings("a", &[]);
        a.status = RunStatus::Partial;
        b.status = RunStatus::Cancelled;
        let comparison = compare_runs(&a, &b);
        assert!(comparison
            .notes
            .iter()
            .any(|n| n.contains("not evidence of equivalence")));
        assert!(comparison
            .notes
            .iter()
            .any(|n| n.contains("run A ended 'partial'")));
        assert!(comparison
            .notes
            .iter()
            .any(|n| n.contains("run B ended 'cancelled'")));
    }

    #[test]
    fn different_artifacts_are_called_out_plainly() {
        let a = run_with_findings("a", &["x"]);
        let mut b = run_with_findings("b", &["x"]);
        b.target.sha256 = "d".repeat(64);
        let comparison = compare_runs(&a, &b);
        assert!(comparison
            .notes
            .iter()
            .any(|n| n.contains("different artifacts")));
    }

    #[test]
    fn succeeded_pair_adds_no_incompleteness_noise() {
        let a = run_with_findings("a", &["one"]);
        let b = run_with_findings("a", &["one"]);
        let comparison = compare_runs(&a, &b);
        assert!(!comparison
            .notes
            .iter()
            .any(|n| n.contains("may be incomplete")));
        assert!(!comparison.notes.iter().any(|n| n.contains("equivalence")));
    }
}
