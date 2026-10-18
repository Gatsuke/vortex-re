//! Structural comparison of two evidence runs.
//!
//! Comparison is deliberately structural: it reports which findings and
//! relationships exist in one record but not the other. It never claims that
//! a difference is a *behavioral* difference, and every comparison result
//! carries a note saying so.

use crate::model::{EvidenceRun, Finding, Relationship, RunSummary};
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

    let mut notes = vec![
        "Structural comparison only: differences describe the recorded evidence, not confirmed behavioral changes.".to_string(),
    ];
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
}
