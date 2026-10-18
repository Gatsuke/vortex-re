//! Local persistence for evidence runs.
//!
//! Design (documented in docs/ARCHITECTURE.md):
//! * one JSON document per run, stored under `<data_dir>/runs/<run_id>.json`;
//! * writes are atomic (temp file + rename) so interrupted processes never
//!   leave half-written records;
//! * the on-disk format equals the export format, so runs are inspectable
//!   and validatable with independent tooling;
//! * the [`RunStore`] trait keeps the mechanism swappable (a SQLite-backed
//!   store is a documented roadmap item, not a current claim).

use crate::model::{EvidenceRun, RunStatus, RunSummary};
use crate::validate::validate_run;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use vortex_core::error::ErrorCode;

/// Errors from the run store.
#[derive(Debug, Clone, Error)]
pub enum RunStoreError {
    /// The requested run does not exist.
    #[error("run '{0}' was not found in {1}")]
    NotFound(String, PathBuf),
    /// The record exists but could not be parsed or validated.
    #[error("run '{0}' is unreadable: {1}")]
    Corrupt(String, String),
    /// The store directory is unusable.
    #[error("evidence store at {0} is unusable: {1}")]
    Unusable(PathBuf, String),
    /// Any other storage failure.
    #[error("{0}")]
    Other(String),
}

impl RunStoreError {
    /// Convert into the shared error type (storage class).
    pub fn into_vortex(self) -> vortex_core::error::VortexError {
        vortex_core::error::VortexError::new(ErrorCode::Storage, self.to_string())
            .with_detail(match &self {
                RunStoreError::NotFound(id, _) => format!("run id: {id}"),
                _ => "see the message for details".to_string(),
            })
            .with_hint(match &self {
                RunStoreError::NotFound(..) => {
                    "run 'vortex runs list' to see saved runs".to_string()
                }
                _ => "check disk space and permissions for the data directory".to_string(),
            })
    }
}

/// Result alias for store operations.
pub type StoreResult<T> = Result<T, RunStoreError>;

/// Persistence contract for run records.
pub trait RunStore: Send + Sync {
    /// Persist a full run record (validated first; atomic on disk).
    fn save(&self, run: &EvidenceRun) -> StoreResult<()>;
    /// Load one run by id.
    fn load(&self, run_id: &str) -> StoreResult<EvidenceRun>;
    /// List run summaries, newest first, at most `limit` entries.
    fn list(&self, limit: usize) -> StoreResult<Vec<RunSummary>>;
    /// Check whether a run exists.
    fn exists(&self, run_id: &str) -> StoreResult<bool>;
    /// Count stored runs and report unreadable ones (used by doctor).
    fn health(&self) -> StoreResult<(usize, Vec<String>)>;
    /// Root directory of the store (for doctor output).
    fn location(&self) -> PathBuf;
}

/// File-system backed run store.
#[derive(Debug, Clone)]
pub struct FileSystemRunStore {
    runs_dir: PathBuf,
}

impl FileSystemRunStore {
    /// Create (and ensure) a store rooted at `runs_dir`.
    pub fn open(runs_dir: impl Into<PathBuf>) -> StoreResult<Self> {
        let runs_dir = runs_dir.into();
        if runs_dir.exists() && !runs_dir.is_dir() {
            return Err(RunStoreError::Unusable(
                runs_dir,
                "path exists but is not a directory".to_string(),
            ));
        }
        std::fs::create_dir_all(&runs_dir)
            .map_err(|err| RunStoreError::Unusable(runs_dir.clone(), err.to_string()))?;
        Ok(Self { runs_dir })
    }

    fn path_for(&self, run_id: &str) -> StoreResult<PathBuf> {
        if !is_safe_run_id(run_id) {
            return Err(RunStoreError::Corrupt(
                run_id.to_string(),
                "run id contains path separators or invalid characters".to_string(),
            ));
        }
        Ok(self.runs_dir.join(format!("{run_id}.json")))
    }
}

/// Run ids must stay inside the runs directory: no separators, no `..`.
fn is_safe_run_id(run_id: &str) -> bool {
    !run_id.is_empty()
        && run_id.len() <= 128
        && run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && run_id != "."
        && run_id != ".."
}

impl RunStore for FileSystemRunStore {
    fn save(&self, run: &EvidenceRun) -> StoreResult<()> {
        let problems = validate_run(run);
        if !problems.is_empty() {
            return Err(RunStoreError::Corrupt(
                run.run_id.clone(),
                format!(
                    "refusing to save an invalid record: {}",
                    problems.join("; ")
                ),
            ));
        }
        let path = self.path_for(&run.run_id)?;
        let body = serde_json::to_vec_pretty(run)
            .map_err(|err| RunStoreError::Other(format!("serialization failed: {err}")))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body)
            .map_err(|err| RunStoreError::Unusable(self.runs_dir.clone(), err.to_string()))?;
        std::fs::rename(&tmp, &path)
            .map_err(|err| RunStoreError::Unusable(self.runs_dir.clone(), err.to_string()))?;
        Ok(())
    }

    fn load(&self, run_id: &str) -> StoreResult<EvidenceRun> {
        let path = self.path_for(run_id)?;
        if !path.exists() {
            return Err(RunStoreError::NotFound(
                run_id.to_string(),
                self.runs_dir.clone(),
            ));
        }
        let body = std::fs::read(&path)
            .map_err(|err| RunStoreError::Unusable(self.runs_dir.clone(), err.to_string()))?;
        let run: EvidenceRun = serde_json::from_slice(&body)
            .map_err(|err| RunStoreError::Corrupt(run_id.to_string(), err.to_string()))?;
        let problems = validate_run(&run);
        if !problems.is_empty() {
            return Err(RunStoreError::Corrupt(
                run_id.to_string(),
                format!("stored record failed validation: {}", problems.join("; ")),
            ));
        }
        Ok(run)
    }

    fn list(&self, limit: usize) -> StoreResult<Vec<RunSummary>> {
        let (runs, _unreadable) = self.load_all()?;
        let mut summaries: Vec<RunSummary> = runs.iter().map(RunSummary::from).collect();
        summaries.sort_by(|a, b| {
            b.started_at
                .cmp(&a.started_at)
                .then(b.run_id.cmp(&a.run_id))
        });
        summaries.truncate(limit);
        Ok(summaries)
    }

    fn exists(&self, run_id: &str) -> StoreResult<bool> {
        Ok(self.path_for(run_id)?.exists())
    }

    fn health(&self) -> StoreResult<(usize, Vec<String>)> {
        let (runs, unreadable) = self.load_all()?;
        Ok((runs.len(), unreadable))
    }

    fn location(&self) -> PathBuf {
        self.runs_dir.clone()
    }
}

impl FileSystemRunStore {
    fn load_all(&self) -> StoreResult<(Vec<EvidenceRun>, Vec<String>)> {
        let entries = std::fs::read_dir(&self.runs_dir)
            .map_err(|err| RunStoreError::Unusable(self.runs_dir.clone(), err.to_string()))?;
        let mut runs = Vec::new();
        let mut unreadable = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            match std::fs::read(&path)
                .map_err(|err| err.to_string())
                .and_then(|body| {
                    serde_json::from_slice::<EvidenceRun>(&body).map_err(|err| err.to_string())
                }) {
                Ok(run) => runs.push(run),
                Err(err) => unreadable.push(format!("{name}: {err}")),
            }
        }
        runs.sort_by(|a, b| {
            a.started_at
                .cmp(&b.started_at)
                .then(a.run_id.cmp(&b.run_id))
        });
        Ok((runs, unreadable))
    }

    /// Mark runs that are still `running` and older than `older_than` as
    /// failed, and return their ids.
    ///
    /// This is the crash-recovery path: a `running` record from a process
    /// that died never reaches a final state on its own. Runs are *not*
    /// resumable in this version; the recovery note says so explicitly.
    pub fn recover_stale_runs(&self, older_than: Duration) -> StoreResult<Vec<String>> {
        let (runs, _unreadable) = self.load_all()?;
        let mut recovered = Vec::new();
        for mut run in runs {
            if run.status != RunStatus::Running {
                continue;
            }
            let stale = vortex_core::timeutil::is_stale(&run.started_at, older_than);
            if stale != Some(true) {
                continue;
            }
            run.finalize(
                RunStatus::Failed,
                Some(
                    "run was still 'running' after its process ended; crashed or interrupted \
                     before completion. Runs are not resumable in this version; re-run the \
                     operation if needed."
                        .to_string(),
                ),
            );
            run.errors.push(crate::model::ErrorRecord {
                code: "cancelled".to_string(),
                message: "run recovered as failed after abnormal termination".to_string(),
                hint: None,
                stage: Some("recovery".to_string()),
            });
            self.save(&run)?;
            recovered.push(run.run_id);
        }
        Ok(recovered)
    }
}

/// Export a run to a standalone JSON file (same format as storage).
pub fn export_run(run: &EvidenceRun, out_path: &Path) -> StoreResult<()> {
    let problems = validate_run(run);
    if !problems.is_empty() {
        return Err(RunStoreError::Corrupt(
            run.run_id.clone(),
            format!(
                "refusing to export an invalid record: {}",
                problems.join("; ")
            ),
        ));
    }
    let mut body = serde_json::to_vec_pretty(run)
        .map_err(|err| RunStoreError::Other(format!("serialization failed: {err}")))?;
    body.push(b'\n');
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| {
                RunStoreError::Other(format!("cannot create {}: {err}", parent.display()))
            })?;
        }
    }
    std::fs::write(out_path, body).map_err(|err| {
        RunStoreError::Other(format!("cannot write {}: {err}", out_path.display()))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn sample_run(operation: &str) -> EvidenceRun {
        let mut run = EvidenceRun::new_running(
            operation,
            TargetIdentity {
                input_path: "demo".into(),
                canonical_path: "/tmp/demo".into(),
                kind: "file".into(),
                sha256: "b".repeat(64),
                size_bytes: 4,
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
            serde_json::json!({"ok": true}),
        );
        run.finalize(RunStatus::Succeeded, None);
        run
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSystemRunStore::open(dir.path().join("runs")).expect("open store");
        let run = sample_run("inspect");
        store.save(&run).expect("save");
        assert!(store.exists(&run.run_id).unwrap());
        let loaded = store.load(&run.run_id).expect("load");
        assert_eq!(loaded.run_id, run.run_id);
        assert_eq!(loaded.findings, run.findings);
        assert_eq!(
            serde_json::to_value(&loaded).unwrap(),
            serde_json::to_value(&run).unwrap()
        );
    }

    #[test]
    fn load_missing_run_reports_not_found() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSystemRunStore::open(dir.path().join("runs")).expect("open store");
        let err = store.load("run-does-not-exist").unwrap_err();
        assert!(matches!(err, RunStoreError::NotFound(..)));
        let vortex_error = err.into_vortex();
        assert_eq!(vortex_error.code, ErrorCode::Storage);
    }

    #[test]
    fn traversal_ids_are_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSystemRunStore::open(dir.path().join("runs")).expect("open store");
        for bad in ["../escape", "run/../../x", "run..", ""] {
            assert!(store.load(bad).is_err(), "id {bad:?} must be rejected");
        }
    }

    #[test]
    fn list_orders_newest_first_and_limits() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSystemRunStore::open(dir.path().join("runs")).expect("open store");
        let mut first = sample_run("inspect");
        first.started_at = "2026-01-01T00:00:01Z".into();
        let mut second = sample_run("search");
        second.started_at = "2026-01-01T00:00:02Z".into();
        store.save(&first).unwrap();
        store.save(&second).unwrap();
        let listed = store.list(10).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].run_id, second.run_id);
        assert_eq!(listed[1].run_id, first.run_id);
        let limited = store.list(1).unwrap();
        assert_eq!(limited.len(), 1);
    }

    #[test]
    fn corrupt_files_are_reported_by_health() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSystemRunStore::open(dir.path().join("runs")).expect("open store");
        store.save(&sample_run("inspect")).unwrap();
        std::fs::write(store.location().join("run-corrupt.json"), b"{ not json")
            .expect("write corrupt");
        let (count, unreadable) = store.health().unwrap();
        assert_eq!(count, 1);
        assert_eq!(unreadable.len(), 1);
        assert!(unreadable[0].contains("run-corrupt"));
    }

    #[test]
    fn stale_running_runs_are_recovered_as_failed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSystemRunStore::open(dir.path().join("runs")).expect("open store");
        let mut stale = sample_run("inspect");
        stale.status = RunStatus::Running;
        stale.completed_at = None;
        stale.started_at = "2020-01-01T00:00:00Z".into();
        store.save(&stale).unwrap();
        let fresh = sample_run("search");
        store.save(&fresh).unwrap();

        let recovered = store.recover_stale_runs(Duration::from_secs(3600)).unwrap();
        assert_eq!(recovered, vec![stale.run_id.clone()]);
        let reloaded = store.load(&stale.run_id).unwrap();
        assert_eq!(reloaded.status, RunStatus::Failed);
        assert!(reloaded
            .status_detail
            .as_deref()
            .unwrap()
            .contains("not resumable"));
        // The fresh run is untouched.
        assert_eq!(
            store.load(&fresh.run_id).unwrap().status,
            RunStatus::Succeeded
        );
    }

    #[test]
    fn export_writes_validatable_json() {
        let dir = tempfile::tempdir().expect("temp dir");
        let run = sample_run("inspect");
        let out = dir.path().join("exported").join("run.json");
        export_run(&run, &out).expect("export");
        let body = std::fs::read_to_string(&out).unwrap();
        assert!(body.ends_with('\n'));
        let reloaded: EvidenceRun = serde_json::from_str(&body).expect("re-parse export");
        assert_eq!(reloaded.run_id, run.run_id);
        assert!(validate_run(&reloaded).is_empty());
    }
}
