//! Structural validation of evidence runs.
//!
//! Validation is deliberately strict about invariants that downstream tooling
//! relies on (unique IDs, resolvable evidence references, parseable
//! timestamps) and tolerant of unknown *details* payloads, which evolve with
//! provider capabilities.

use crate::model::{EvidenceRun, Origin, Resolution, RunStatus, SCHEMA_VERSION};
use std::collections::HashSet;

/// Validate a run record. Returns every problem found, empty when valid.
pub fn validate_run(run: &EvidenceRun) -> Vec<String> {
    let mut problems = Vec::new();

    if run.schema_version != SCHEMA_VERSION {
        problems.push(format!(
            "schema_version is {} but this tool understands {SCHEMA_VERSION}",
            run.schema_version
        ));
    }
    if !run.run_id.starts_with("run-") || run.run_id.len() < 10 {
        problems.push(format!("run_id '{}' is malformed", run.run_id));
    }
    if run.operation.trim().is_empty() {
        problems.push("operation must be a non-empty string".to_string());
    }
    if vortex_core::timeutil::parse_rfc3339(&run.started_at).is_none() {
        problems.push(format!(
            "started_at '{}' is not a valid RFC 3339 timestamp",
            run.started_at
        ));
    }
    if let Some(completed) = &run.completed_at {
        if vortex_core::timeutil::parse_rfc3339(completed).is_none() {
            problems.push(format!(
                "completed_at '{completed}' is not a valid RFC 3339 timestamp"
            ));
        }
    }
    if run.status == RunStatus::Running && run.completed_at.is_some() {
        problems.push("a running run must not have a completion time".to_string());
    }
    if run.status != RunStatus::Running && run.completed_at.is_none() {
        problems.push("a final run must have a completion time".to_string());
    }
    if run.target.sha256.len() != 64 || run.target.sha256.chars().any(|c| !c.is_ascii_hexdigit()) {
        problems.push("target.sha256 must be a 64-character hex digest".to_string());
    }
    if run.tool.name.trim().is_empty() || run.provider.id.trim().is_empty() {
        problems.push("tool.name and provider.id must be non-empty".to_string());
    }

    let mut finding_ids = HashSet::new();
    for (index, finding) in run.findings.iter().enumerate() {
        if finding.id.trim().is_empty() {
            problems.push(format!("finding #{index} has an empty id"));
        }
        if !finding_ids.insert(finding.id.clone()) {
            problems.push(format!(
                "finding id '{}' is used more than once",
                finding.id
            ));
        }
        if finding.kind.trim().is_empty() {
            problems.push(format!("finding '{}' has an empty kind", finding.id));
        }
        if finding.summary.trim().is_empty() {
            problems.push(format!("finding '{}' has an empty summary", finding.id));
        }
    }

    for (index, relationship) in run.relationships.iter().enumerate() {
        if relationship.id.trim().is_empty() {
            problems.push(format!("relationship #{index} has an empty id"));
        }
        if relationship.from.id.trim().is_empty() || relationship.to.id.trim().is_empty() {
            problems.push(format!(
                "relationship '{}' has an empty endpoint",
                relationship.id
            ));
        }
        if !matches!(
            relationship.origin,
            Origin::Observed | Origin::Derived | Origin::Inferred
        ) {
            problems.push(format!(
                "relationship '{}' has an invalid origin",
                relationship.id
            ));
        }
        if relationship.status == Resolution::Unresolved && relationship.resolution_note.is_none() {
            problems.push(format!(
                "unresolved relationship '{}' must explain why in resolution_note",
                relationship.id
            ));
        }
        if let Some(evidence_id) = &relationship.evidence_finding_id {
            if !finding_ids.contains(evidence_id) {
                problems.push(format!(
                    "relationship '{}' references unknown finding '{evidence_id}'",
                    relationship.id
                ));
            }
        }
    }

    let dedup_limitations: HashSet<_> = run.limitations.iter().collect();
    if dedup_limitations.len() != run.limitations.len() {
        problems.push("limitations contain duplicates".to_string());
    }

    if run.counts.findings != run.findings.len() {
        problems.push(format!(
            "counts.findings is {} but the record holds {}",
            run.counts.findings,
            run.findings.len()
        ));
    }
    if run.counts.relationships != run.relationships.len() {
        problems.push(format!(
            "counts.relationships is {} but the record holds {}",
            run.counts.relationships,
            run.relationships.len()
        ));
    }

    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn minimal_run() -> EvidenceRun {
        let mut run = EvidenceRun::new_running(
            "inspect",
            TargetIdentity {
                input_path: "demo".into(),
                canonical_path: "/tmp/demo".into(),
                kind: "directory".into(),
                sha256: "a".repeat(64),
                size_bytes: 10,
                file_count: Some(1),
            },
            ProviderRef {
                id: "builtin-static".into(),
                version: "0.1.0".into(),
            },
            ToolInfo {
                name: "vortex".into(),
                version: "0.1.0".into(),
                invocation: "vortex inspect demo".into(),
            },
            serde_json::json!({}),
        );
        run.finalize(RunStatus::Succeeded, None);
        run
    }

    #[test]
    fn fresh_run_is_valid() {
        let run = minimal_run();
        assert!(validate_run(&run).is_empty(), "{:?}", validate_run(&run));
    }

    #[test]
    fn duplicate_finding_ids_are_rejected() {
        let mut run = minimal_run();
        let finding = Finding {
            id: "f1".into(),
            kind: "file".into(),
            origin: Origin::Observed,
            summary: "a file".into(),
            location: None,
            artifact: None,
            details: serde_json::json!({}),
        };
        run.findings = vec![finding.clone(), finding];
        run.counts.findings = 2;
        let problems = validate_run(&run);
        assert!(problems.iter().any(|p| p.contains("used more than once")));
    }

    #[test]
    fn unresolved_relationships_need_a_note() {
        let mut run = minimal_run();
        run.relationships = vec![Relationship {
            id: "r1".into(),
            from: Node {
                kind: "file".into(),
                id: "a.js".into(),
            },
            to: Node {
                kind: "file".into(),
                id: "missing.js".into(),
            },
            kind: "imports".into(),
            scope: Scope::Internal,
            status: Resolution::Unresolved,
            resolution_note: None,
            origin: Origin::Observed,
            evidence_finding_id: None,
            location: None,
        }];
        run.counts.relationships = 1;
        let problems = validate_run(&run);
        assert!(problems.iter().any(|p| p.contains("resolution_note")));
    }

    #[test]
    fn dangling_evidence_references_are_rejected() {
        let mut run = minimal_run();
        run.relationships = vec![Relationship {
            id: "r1".into(),
            from: Node {
                kind: "file".into(),
                id: "a.js".into(),
            },
            to: Node {
                kind: "file".into(),
                id: "b.js".into(),
            },
            kind: "imports".into(),
            scope: Scope::Internal,
            status: Resolution::Resolved,
            resolution_note: None,
            origin: Origin::Observed,
            evidence_finding_id: Some("f999".into()),
            location: None,
        }];
        run.counts.relationships = 1;
        let problems = validate_run(&run);
        assert!(problems.iter().any(|p| p.contains("unknown finding")));
    }

    #[test]
    fn bad_schema_version_is_rejected() {
        let mut run = minimal_run();
        run.schema_version = 99;
        assert!(validate_run(&run)
            .iter()
            .any(|p| p.contains("schema_version")));
    }

    #[test]
    fn wrong_version_constant_guard() {
        // The serialization contract: statuses serialize as snake_case.
        let status = serde_json::to_value(RunStatus::Partial).unwrap();
        assert_eq!(status, serde_json::json!("partial"));
        let origin = serde_json::to_value(Origin::Derived).unwrap();
        assert_eq!(origin, serde_json::json!("derived"));
    }
}
