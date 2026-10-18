//! Human-readable rendering for CLI output (kept free of any IO so it is
//! trivially testable). JSON output is produced separately by serializing
//! the underlying structures.

use vortex_evidence::{RunComparison, RunSummary};
use vortex_service::doctor::{DoctorReport, NotSupported};
use vortex_service::service::{CapabilityReport, EvidenceView, OperationResult};

/// Truncate long strings for one-line display.
fn clip(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{cut}\u{2026}")
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Render an inspect/search/relationships operation result.
pub fn render_operation(operation: &str, result: &OperationResult) -> String {
    let mut out = String::new();
    let summary = &result.report.summary;
    let path = summary
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    let kind = summary
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("file");

    out.push_str(&format!("Target: {path} ({kind})\n"));
    if let Some(digest) = summary.get("sha256").and_then(|v| v.as_str()) {
        out.push_str(&format!("SHA-256: {digest}\n"));
    }
    match operation {
        "inspect" => {
            if let Some(count) = summary.get("file_count").and_then(|v| v.as_u64()) {
                let dirs = summary
                    .get("directory_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let bytes = summary
                    .get("total_bytes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                out.push_str(&format!(
                    "Files: {count} ({dirs} directories, {} total)\n",
                    format_bytes(bytes)
                ));
            }
            if let Some(size) = summary.get("size_bytes").and_then(|v| v.as_u64()) {
                out.push_str(&format!("Size: {}\n", format_bytes(size)));
            }
            if let Some(format) = summary.get("format").and_then(|v| v.as_str()) {
                out.push_str(&format!("Format: {format}\n"));
            }
            if let Some(entry) = summary.get("entry_point").and_then(|v| v.as_str()) {
                out.push_str(&format!(
                    "Entry point: {entry} (derived from package.json)\n"
                ));
            }
            if let Some(entry) = summary
                .get("entry_point")
                .and_then(|v| v.get("entry_point"))
                .and_then(|v| v.as_str())
            {
                out.push_str(&format!(
                    "Entry point: {entry} (derived from package.json)\n"
                ));
            }
            if let Some(electron) = summary.get("electron").and_then(|v| v.as_bool()) {
                if electron {
                    out.push_str("Classification: electron (derived; evidence: package.json declares 'electron')\n");
                }
            }
            if let Some(count) = summary
                .get("sourcemap_reference_count")
                .and_then(|v| v.as_u64())
            {
                if count > 0 {
                    out.push_str(&format!("Source map references: {count}\n"));
                }
            }
        }
        "search" => {
            let query = summary.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let case = if summary
                .get("case_sensitive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                "case-sensitive"
            } else {
                "case-insensitive"
            };
            let matches = summary.get("matches").and_then(|v| v.as_u64()).unwrap_or(0);
            let files = summary
                .get("files_searched")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            out.push_str(&format!("Query: '{query}' ({case})\n"));
            out.push_str(&format!(
                "Matches: {matches} across {files} searched file(s)\n"
            ));
        }
        "relationships" => {
            let total = summary
                .get("relationships")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let resolved = summary
                .get("resolved")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let unresolved = summary
                .get("unresolved")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            out.push_str(&format!(
                "Relationships: {total} ({resolved} resolved, {unresolved} unresolved)\n"
            ));
        }
        _ => {}
    }

    out.push('\n');
    if !result.report.findings.is_empty() {
        out.push_str(&format!("Findings ({}):\n", result.report.findings.len()));
        for finding in result.report.findings.iter().take(15) {
            let location = finding
                .location
                .as_ref()
                .map(|l| {
                    let file = l.file.as_deref().unwrap_or("");
                    match l.line {
                        Some(line) => format!(" {file}:{line}"),
                        None => format!(" {file}"),
                    }
                })
                .unwrap_or_default();
            out.push_str(&format!(
                "  [{}] {}{}\n",
                finding.origin.as_str(),
                finding.kind,
                location
            ));
            out.push_str(&format!("      {}\n", clip(&finding.summary, 96)));
        }
        if result.report.findings.len() > 15 {
            out.push_str(&format!(
                "  ... and {} more findings (use --json or 'vortex evidence show')\n",
                result.report.findings.len() - 15
            ));
        }
        out.push('\n');
    }
    if !result.report.relationships.is_empty() && operation == "relationships" {
        out.push_str(&format!("Edges ({}):\n", result.report.relationships.len()));
        for relationship in result.report.relationships.iter().take(20) {
            let status = match relationship.status {
                vortex_evidence::Resolution::Resolved => "resolved".to_string(),
                vortex_evidence::Resolution::Unresolved => format!(
                    "unresolved: {}",
                    clip(
                        relationship
                            .resolution_note
                            .as_deref()
                            .unwrap_or("no reason recorded"),
                        60
                    )
                ),
                vortex_evidence::Resolution::Inline => "inline".to_string(),
            };
            out.push_str(&format!(
                "  {} --{}--> {} [{}]\n",
                relationship.from.id, relationship.kind, relationship.to.id, status
            ));
        }
        if result.report.relationships.len() > 20 {
            out.push_str(&format!(
                "  ... and {} more edges (use --json or 'vortex evidence show')\n",
                result.report.relationships.len() - 20
            ));
        }
        out.push('\n');
    }
    if !result.report.limitations.is_empty() {
        out.push_str(&format!(
            "Limitations ({}):\n",
            result.report.limitations.len()
        ));
        for limitation in &result.report.limitations {
            out.push_str(&format!("  - {}\n", clip(limitation, 110)));
        }
        out.push('\n');
    }
    if !result.report.unknowns.is_empty() {
        out.push_str(&format!("Unknowns ({}):\n", result.report.unknowns.len()));
        for unknown in result.report.unknowns.iter().take(10) {
            out.push_str(&format!("  - {}\n", clip(unknown, 110)));
        }
        out.push('\n');
    }
    if let Some(run_id) = &result.run_id {
        out.push_str(&format!(
            "Run: {run_id} ({}) \u{2014} evidence stored; use 'vortex evidence show {run_id}'\n",
            result.status.as_str()
        ));
    } else {
        out.push_str(&format!(
            "Run: not persisted (--no-store); status: {}\n",
            result.status.as_str()
        ));
    }
    out
}

/// Render `runs list` output.
pub fn render_run_list(runs: &[RunSummary]) -> String {
    if runs.is_empty() {
        return "No stored runs. Run 'vortex inspect <path>' to create one.\n".to_string();
    }
    let mut out = String::from("Stored runs (newest first):\n");
    for run in runs {
        let completed = run.completed_at.as_deref().unwrap_or("-");
        out.push_str(&format!(
            "  {}  {:<14} {:<10} {}  {} ({} findings, {} relationships)\n",
            clip(&run.run_id, 18),
            run.operation,
            run.status.as_str(),
            completed,
            clip(&run.target_input_path, 44),
            run.finding_count,
            run.relationship_count
        ));
    }
    out
}

/// Render `evidence show` output.
pub fn render_evidence_view(view: &EvidenceView) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Run {} ({}, {}, started {})\n",
        view.run.run_id,
        view.run.operation,
        view.run.status.as_str(),
        view.run.started_at
    ));
    out.push_str(&format!(
        "Target: {} (digest {}...)\n\n",
        view.run.target_input_path,
        &view.run.target_sha256[..12.min(view.run.target_sha256.len())]
    ));
    if view.page.page_size == usize::MAX {
        // Non-paginated section.
        for item in &view.page.items {
            out.push_str(&format!(
                "{}\n",
                serde_json::to_string_pretty(item).unwrap_or_default()
            ));
        }
        if view.page.items.is_empty() {
            out.push_str("(empty)\n");
        }
        return out;
    }
    out.push_str(&format!(
        "Section '{}' \u{2014} page {} of {} ({} item(s) per page, {} total)\n",
        view.section,
        view.page.page,
        view.page.total_pages.max(view.page.page),
        view.page.page_size,
        view.page.total_items
    ));
    if view.page.items.is_empty() {
        out.push_str("(no items on this page)\n");
        return out;
    }
    for (index, item) in view.page.items.iter().enumerate() {
        let number = (view.page.page - 1) * view.page.page_size + index + 1;
        let summary = item
            .get("summary")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| serde_json::to_string(item).unwrap_or_default());
        let kind = item.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        out.push_str(&format!("  {number:>4}. [{kind}] {}\n", clip(&summary, 92)));
    }
    if view.page.has_next {
        out.push_str(&format!("\nNext page: add --page {}\n", view.page.page + 1));
    }
    out
}

/// Render `compare` output.
pub fn render_compare(comparison: &RunComparison) -> String {
    let mut out = String::from("Structural comparison (does not imply behavioral differences)\n\n");
    out.push_str(&format!(
        "Run A: {} ({}, {})\n",
        comparison.run_a.run_id,
        comparison.run_a.operation,
        comparison.run_a.status.as_str()
    ));
    out.push_str(&format!(
        "Run B: {} ({}, {})\n",
        comparison.run_b.run_id,
        comparison.run_b.operation,
        comparison.run_b.status.as_str()
    ));
    out.push_str(&format!(
        "Same target path: {}   Same artifact digest: {}\n",
        comparison.same_target_path, comparison.same_artifact_digest
    ));
    if let Some((from, to)) = &comparison.status_change {
        out.push_str(&format!("Status change: {from} -> {to}\n"));
    }
    out.push('\n');
    out.push_str(&format!(
        "Findings only in A: {} | only in B: {}\n",
        comparison.totals.findings_only_in_a, comparison.totals.findings_only_in_b
    ));
    for entry in comparison.findings_only_in_a.iter().take(10) {
        let location = entry.location.as_deref().unwrap_or("-");
        out.push_str(&format!(
            "  A: [{}] {} ({})\n",
            entry.kind,
            clip(&entry.summary, 80),
            location
        ));
    }
    for entry in comparison.findings_only_in_b.iter().take(10) {
        let location = entry.location.as_deref().unwrap_or("-");
        out.push_str(&format!(
            "  B: [{}] {} ({})\n",
            entry.kind,
            clip(&entry.summary, 80),
            location
        ));
    }
    out.push_str(&format!(
        "Relationships only in A: {} | only in B: {}\n",
        comparison.totals.relationships_only_in_a, comparison.totals.relationships_only_in_b
    ));
    for entry in comparison.relationships_only_in_a.iter().take(10) {
        out.push_str(&format!(
            "  A: {} --{}--> {} ({})\n",
            entry.from, entry.kind, entry.to, entry.status
        ));
    }
    for entry in comparison.relationships_only_in_b.iter().take(10) {
        out.push_str(&format!(
            "  B: {} --{}--> {} ({})\n",
            entry.from, entry.kind, entry.to, entry.status
        ));
    }
    if comparison.truncated {
        out.push_str("\n(diff lists truncated; totals above are complete)\n");
    }
    out.push('\n');
    for note in &comparison.notes {
        out.push_str(&format!("Note: {}\n", clip(note, 120)));
    }
    out
}

/// Render `doctor` output.
pub fn render_doctor(report: &DoctorReport) -> String {
    let mut out = format!(
        "vortex-re {} \u{2014} diagnostics ({} / {})\n\n",
        report.version, report.os, report.arch
    );
    for check in &report.checks {
        out.push_str(&format!(
            "[{:<4}] {}: {}\n",
            check.status.marker(),
            check.name,
            clip(&check.detail, 110)
        ));
        if let Some(hint) = &check.hint {
            out.push_str(&format!("        hint: {}\n", clip(hint, 100)));
        }
    }
    out.push_str("\nWorks now:\n");
    for item in &report.supported_now {
        out.push_str(&format!("  + {item}\n"));
    }
    out.push_str("\nNot supported (and why):\n");
    for item in &report.not_supported {
        out.push_str(&format!(
            "  - {}: {}\n",
            item.operation,
            clip(&item.reason, 90)
        ));
        if let Some(prerequisite) = &item.prerequisite {
            out.push_str(&format!("      prerequisite: {}\n", clip(prerequisite, 90)));
        }
    }
    out
}

/// Render `capabilities` output.
pub fn render_capabilities(report: &CapabilityReport) -> String {
    let mut out = format!("Providers (evidence schema v{})\n\n", report.schema_version);
    for provider in &report.providers {
        out.push_str(&format!(
            "{} {} \u{2014} {} capability(ies)\n",
            provider.id,
            provider.version,
            provider.capabilities.len()
        ));
        for capability in &provider.capabilities {
            out.push_str(&format!(
                "  - {:<24} {}\n",
                capability.id, capability.description
            ));
        }
    }
    out
}

/// Render `runs recover` output.
pub fn render_recovered(recovered: &[String], older_than_secs: u64) -> String {
    if recovered.is_empty() {
        return format!("No stale 'running' runs older than {older_than_secs}s found.\n");
    }
    let mut out = format!(
        "Marked {} stale run(s) as failed (not resumable in this version):\n",
        recovered.len()
    );
    for run_id in recovered {
        out.push_str(&format!("  {run_id}\n"));
    }
    out
}

/// Render not-supported entries as a shared helper (also used by tests).
pub fn render_not_supported(entries: &[NotSupported]) -> String {
    entries
        .iter()
        .map(|entry| format!("{}: {}", entry.operation, entry.reason))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_truncates_long_text() {
        assert_eq!(clip("short", 10), "short");
        let long = "x".repeat(50);
        assert!(clip(&long, 10).chars().count() <= 10);
    }

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(3 * 1024 * 1024), "3.0 MiB");
    }
}
