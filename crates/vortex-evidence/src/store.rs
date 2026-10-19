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

use crate::model::{ErrorRecord, EvidenceRun, RunStatus, RunSummary};
use crate::validate::validate_run;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use vortex_core::error::ErrorCode;
use vortex_core::timeutil::is_stale;

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
        let mut run: EvidenceRun = serde_json::from_slice(&body)
            .map_err(|err| RunStoreError::Corrupt(run_id.to_string(), err.to_string()))?;
        let problems = validate_run(&run);
        if !problems.is_empty() {
            return Err(RunStoreError::Corrupt(
                run_id.to_string(),
                format!("stored record failed validation: {}", problems.join("; ")),
            ));
        }
        // Schema tolerance: older records load fine and get an explicit
        // annotation, never an integrity complaint. The note lives only in
        // memory (serde-skip) — it describes this read, not the record.
        if run.schema_version < crate::model::SCHEMA_VERSION {
            run.load_notes.push(format!(
                "older_schema: record uses evidence schema v{} (this tool understands up to \
                 v{}); loaded tolerantly — v2+ fields absent in this record were treated as \
                 unset",
                run.schema_version,
                crate::model::SCHEMA_VERSION
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
    /// failed, and return their ids (back-compat wrapper over the
    /// owner-aware engine; see [`FileSystemRunStore::recover_interrupted_runs`]).
    pub fn recover_stale_runs(&self, older_than: Duration) -> StoreResult<Vec<String>> {
        let report = self.recover_interrupted_runs(RecoveryOptions {
            age_grace: older_than,
            force_aged: true,
        })?;
        Ok(report.recovered.into_iter().map(|r| r.run_id).collect())
    }

    /// Recover interrupted `running` runs using owner-process liveness.
    ///
    /// Decision policy (conservative by default):
    /// * owner recorded and dead — recovered immediately, regardless of age;
    ///   this is the crash path (kill -9, power loss) and waiting for an age
    ///   threshold would only delay the explanation;
    /// * owner recorded and alive — left untouched while the run is younger
    ///   than `age_grace`; an aged run with a living owner is *reported*, not
    ///   forced (the process may legitimately still be working), unless
    ///   `force_aged` was set by an explicit recovery request;
    /// * liveness undeterminable (no owner recorded, or platform without
    ///   probes) — age-based, with the reason saying exactly that.
    pub fn recover_interrupted_runs(
        &self,
        options: RecoveryOptions,
    ) -> StoreResult<RecoveryReport> {
        let (runs, _unreadable) = self.load_all()?;
        let mut report = RecoveryReport::default();
        for mut run in runs {
            if run.status != RunStatus::Running {
                continue;
            }
            let aged = is_stale(&run.started_at, options.age_grace);
            let (left_reason, recover_reason) = decide_recovery(&run, aged, &options);
            let Some(reason) = recover_reason else {
                report.left_running.push(LeftRun {
                    run_id: run.run_id.clone(),
                    reason: left_reason.unwrap_or_else(|| "left untouched".to_string()),
                });
                continue;
            };
            let entry = apply_recovery(&mut run, reason);
            match self.save(&run) {
                Ok(()) => report.recovered.push(entry),
                Err(err) => report.errors.push(format!(
                    "{}: could not persist the recovery: {err}",
                    run.run_id
                )),
            }
        }
        Ok(report)
    }

    /// Recover one specific `running` record if the decision policy says so.
    /// Returns whether it was recovered. Used by `runs resume` when it meets
    /// a crashed record this service instance never saw at startup — it
    /// never touches any other record.
    pub fn recover_single_interrupted(
        &self,
        run_id: &str,
        options: RecoveryOptions,
    ) -> StoreResult<bool> {
        let mut run = self.load(run_id)?;
        if run.status != RunStatus::Running {
            return Ok(false);
        }
        let aged = is_stale(&run.started_at, options.age_grace);
        let (_left_reason, recover_reason) = decide_recovery(&run, aged, &options);
        let Some(reason) = recover_reason else {
            return Ok(false);
        };
        apply_recovery(&mut run, reason);
        self.save(&run)?;
        Ok(true)
    }
}

/// Finalize one record as failed-after-interruption; returns the entry to
/// record in the recovery report.
fn apply_recovery(run: &mut EvidenceRun, reason: String) -> RecoveredRun {
    let resumable_note = run
        .checkpoint
        .as_ref()
        .map(|checkpoint| {
            format!(
                " The run can be continued from its checkpoint with \
                 'vortex runs resume {}' (next file index {}).",
                run.run_id, checkpoint.next_file_index
            )
        })
        .unwrap_or_else(|| {
            " There is no checkpoint to resume from; re-run the operation instead.".to_string()
        });
    let full_reason = format!("{reason}{resumable_note}");
    let resumable = run.checkpoint.is_some();
    run.finalize(RunStatus::Failed, Some(full_reason.clone()));
    run.errors.push(ErrorRecord {
        code: "recovered".to_string(),
        message: reason,
        hint: Some(if resumable {
            "run 'vortex runs resume <run-id>' to continue from the checkpoint".to_string()
        } else {
            "re-run the operation; nothing durable was saved mid-run".to_string()
        }),
        stage: Some("recovery".to_string()),
    });
    RecoveredRun {
        run_id: run.run_id.clone(),
        reason: full_reason,
        resumable,
    }
}

/// Options for the recovery engine.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryOptions {
    /// Runs older than this are candidates when liveness cannot decide.
    pub age_grace: Duration,
    /// When true (explicit `runs recover`), aged runs are recovered even if
    /// their owner process appears alive. Startup recovery keeps this false.
    pub force_aged: bool,
}

/// What the recovery engine did to one `running` record.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RecoveryReport {
    /// Runs marked failed, with the reason recorded on each.
    pub recovered: Vec<RecoveredRun>,
    /// Runs deliberately left as `running`, with why.
    pub left_running: Vec<LeftRun>,
    /// Runs whose recovery could not be persisted.
    pub errors: Vec<String>,
}

/// One recovered run.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveredRun {
    /// Run identifier.
    pub run_id: String,
    /// Human explanation stored on the record.
    pub reason: String,
    /// Whether a checkpoint exists to resume from.
    pub resumable: bool,
}

/// One run left untouched.
#[derive(Debug, Clone, Serialize)]
pub struct LeftRun {
    /// Run identifier.
    pub run_id: String,
    /// Why it was not recovered.
    pub reason: String,
}

/// Decide one run's fate. Returns (left_reason, recover_reason); exactly one
/// is `Some`.
fn decide_recovery(
    run: &EvidenceRun,
    aged: Option<bool>,
    options: &RecoveryOptions,
) -> (Option<String>, Option<String>) {
    let grace_secs = options.age_grace.as_secs();
    // 1. Owner recorded and determinately dead: recover now, any age.
    if let Some(owner) = &run.owner {
        match vortex_core::process::owner_is_alive(&owner.0) {
            Some(false) => {
                let reason = format!(
                    "the process that started this run (pid {}) is no longer running; the run \
                     was interrupted before completion (crash, kill, or shutdown)",
                    owner.0.pid
                );
                return (None, Some(reason));
            }
            Some(true) => match aged {
                Some(true) if options.force_aged => {
                    let reason = format!(
                        "the owning process still appears alive, but the run is older than \
                         {grace_secs}s and the explicit recovery request asked for it; the \
                         process may be hung, or its pid may have been reassigned",
                    );
                    return (None, Some(reason));
                }
                Some(true) => {
                    let reason = format!(
                        "owner process appears alive and the run is older than {grace_secs}s; \
                         possibly hung — not forced at startup; use 'vortex runs recover' to \
                         force it",
                    );
                    return (Some(reason), None);
                }
                Some(false) | None => {
                    let reason = "owner process is alive and the run is within the recovery \
                                    grace period";
                    return (Some(reason.to_string()), None);
                }
            },
            None => match aged {
                // Liveness undeterminable (platform without probes): age decides.
                Some(true) => {
                    let reason = format!(
                        "process liveness cannot be determined on this platform; the run is \
                         older than {grace_secs}s, so it was recovered by age",
                    );
                    return (None, Some(reason));
                }
                Some(false) | None => {
                    let reason = "liveness undeterminable and the run is within the grace period";
                    return (Some(reason.to_string()), None);
                }
            },
        }
    }
    // 2. No owner recorded (schema v1 records): age decides, and says so.
    match aged {
        Some(true) => {
            let reason = format!(
                "record predates owner tracking (schema v1) and is older than {grace_secs}s; \
                 recovered by age",
            );
            (None, Some(reason))
        }
        Some(false) => (
            Some("no owner recorded and the run is within the grace period".to_string()),
            None,
        ),
        None => (
            Some(
                "age cannot be determined (unparseable started_at); left untouched — inspect \
                 this run manually"
                    .to_string(),
            ),
            None,
        ),
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

        // Manual recovery (force_aged) over the v1-shaped record (no owner).
        let recovered = store.recover_stale_runs(Duration::from_secs(3600)).unwrap();
        assert_eq!(recovered, vec![stale.run_id.clone()]);
        let reloaded = store.load(&stale.run_id).unwrap();
        assert_eq!(reloaded.status, RunStatus::Failed);
        let detail = reloaded.status_detail.as_deref().unwrap();
        assert!(detail.contains("predates owner tracking"));
        assert!(detail.contains("re-run the operation"));
        assert!(reloaded
            .errors
            .iter()
            .any(|error| error.code == "recovered" && error.stage.as_deref() == Some("recovery")));
        // The fresh run is untouched.
        assert_eq!(
            store.load(&fresh.run_id).unwrap().status,
            RunStatus::Succeeded
        );
    }

    /// The full startup/ manual recovery decision matrix, driven by owner
    /// liveness (the kill -9 acceptance story: a dead owner recovers on the
    /// *next start*, no matter how fresh the record is).
    #[test]
    fn recovery_matrix_by_owner_liveness() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSystemRunStore::open(dir.path().join("runs")).expect("open store");

        let dead_pid = exited_pid();
        fn exited_pid() -> u32 {
            use std::process::Command;
            for _ in 0..5 {
                let out = Command::new("sh")
                    .arg("-c")
                    .arg("echo $$; exec true")
                    .output()
                    .expect("spawn sh");
                let pid: u32 = String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .parse()
                    .expect("pid");
                let probe = vortex_core::process::ProcessInfo {
                    pid,
                    proc_start: None,
                };
                if vortex_core::process::owner_is_alive(&probe) != Some(true) {
                    return pid; // dead and not immediately reused
                }
            }
            panic!("no dead pid available for the test");
        }

        let running_record =
            |name: &str, started_at: &str, owner: Option<OwnerProcess>, checkpoint: bool| {
                let mut run = sample_run(name);
                run.status = RunStatus::Running;
                run.completed_at = None;
                run.started_at = started_at.to_string();
                run.owner = owner;
                if checkpoint {
                    run.checkpoint = Some(RunCheckpoint {
                        phase: "per_file_analysis".to_string(),
                        next_file_index: 25,
                        files_scanned: 25,
                        files_skipped: 0,
                        saved_at: "2026-01-01T00:00:00Z".to_string(),
                        bytes_remaining: 1024,
                        matches_remaining: None,
                    });
                }
                store.save(&run).unwrap();
                run.run_id
            };

        let now = vortex_core::timeutil::now_rfc3339();
        let alive_owner = Some(OwnerProcess(vortex_core::process::current()));
        let dead_owner = Some(OwnerProcess(vortex_core::process::ProcessInfo {
            pid: dead_pid,
            proc_start: None,
        }));

        let dead_fresh = running_record("inspect", &now, dead_owner, true);
        let alive_fresh = running_record("inspect", &now, alive_owner.clone(), false);
        let alive_aged = running_record("inspect", "2020-01-01T00:00:00Z", alive_owner, false);
        let v1_aged = running_record("search", "2020-01-01T00:00:00Z", None, false);
        let v1_fresh = running_record("search", &now, None, false);

        // Startup recovery (conservative): dead owners and aged records with
        // no liveness information are recovered; ambiguous ones are reported.
        let startup = store
            .recover_interrupted_runs(RecoveryOptions {
                age_grace: Duration::from_secs(3600),
                force_aged: false,
            })
            .unwrap();
        let startup_ids: Vec<&str> = startup
            .recovered
            .iter()
            .map(|entry| entry.run_id.as_str())
            .collect();
        assert!(startup_ids.contains(&dead_fresh.as_str()), "dead owner");
        assert!(startup_ids.contains(&v1_aged.as_str()), "v1 aged by date");
        assert_eq!(startup.recovered.len(), 2, "exactly these two at startup");
        assert!(startup.errors.is_empty());

        let startup_left_ids: Vec<&str> = startup
            .left_running
            .iter()
            .map(|left| left.run_id.as_str())
            .collect();
        assert!(startup_left_ids.contains(&alive_fresh.as_str()));
        assert!(startup_left_ids.contains(&alive_aged.as_str()));
        assert!(startup_left_ids.contains(&v1_fresh.as_str()));
        let reason_of = |id: &str| {
            startup
                .left_running
                .iter()
                .find(|left| left.run_id == id)
                .unwrap_or_else(|| panic!("{id} should be left running"))
                .reason
                .clone()
        };
        assert!(reason_of(&alive_fresh).contains("alive and the run is within"));
        assert!(reason_of(&alive_aged).contains("possibly hung"));
        assert!(reason_of(&v1_fresh).contains("no owner recorded"));

        let dead_entry = startup
            .recovered
            .iter()
            .find(|entry| entry.run_id == dead_fresh)
            .unwrap();
        assert!(dead_entry.resumable);
        assert!(dead_entry.reason.contains("no longer running"));
        assert!(dead_entry.reason.contains("vortex runs resume"));

        // The dead-owner record now explains itself and kept its checkpoint.
        let reloaded = store.load(&dead_fresh).unwrap();
        assert_eq!(reloaded.status, RunStatus::Failed);
        let detail = reloaded.status_detail.as_deref().unwrap();
        assert!(detail.contains("kill, or shutdown"));
        assert!(detail.contains("vortex runs resume"));
        assert!(
            reloaded.checkpoint.is_some(),
            "failed runs keep checkpoints"
        );

        // Manual recovery (force) clears the remaining aged+ambiguous one.
        let manual = store
            .recover_interrupted_runs(RecoveryOptions {
                age_grace: Duration::from_secs(3600),
                force_aged: true,
            })
            .unwrap();
        let manual_ids: Vec<&str> = manual
            .recovered
            .iter()
            .map(|entry| entry.run_id.as_str())
            .collect();
        assert!(
            manual_ids.contains(&alive_aged.as_str()),
            "forced aged+alive"
        );
        assert_eq!(manual.recovered.len(), 1);
        assert!(manual
            .left_running
            .iter()
            .any(|left| left.run_id == alive_fresh && left.reason.contains("within")));
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

    /// The identity-stability policy: a v1 record must load under v2 tooling
    /// with its identity untouched and an explicit `older_schema` note —
    /// never an "integrity mismatch" (upstream #4436 lesson).
    #[test]
    fn v1_records_load_tolerantly_with_identity_intact() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSystemRunStore::open(dir.path().join("runs")).expect("open store");
        let run = sample_run("inspect");

        // Hand-write the record exactly as v1 would have: schema 1, no v2
        // fields, identical identity and content.
        let mut v1 = serde_json::to_value(&run).unwrap();
        let object = v1.as_object_mut().unwrap();
        object.insert("schema_version".into(), serde_json::json!(1));
        for field in ["owner", "limits", "params", "checkpoint", "resumed"] {
            object.remove(field);
        }
        let v1_id = format!("run-v1{}", "a".repeat(20));
        object.insert("run_id".into(), serde_json::json!(v1_id));
        std::fs::write(
            store.location().join(format!("{v1_id}.json")),
            serde_json::to_vec_pretty(&v1).unwrap(),
        )
        .unwrap();

        let loaded = store.load(&v1_id).expect("v1 record loads");
        assert_eq!(loaded.run_id, v1_id);
        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.target.sha256, run.target.sha256);
        assert_eq!(loaded.started_at, run.started_at);
        assert_eq!(loaded.findings, run.findings);
        assert_eq!(loaded.load_notes.len(), 1);
        assert!(loaded.load_notes[0].contains("older_schema"));
        assert!(validate_run(&loaded).is_empty());

        // Round-tripping a loaded v1 record re-saves it as v1: identity
        // fields (ids, digests, timestamps) are never rewritten.
        let before = serde_json::to_value(&loaded).unwrap();
        let mut roundtripped = loaded.clone();
        roundtripped
            .limitations
            .push("note added after load".into());
        store.save(&roundtripped).expect("re-save v1 record");
        let after = serde_json::to_value(store.load(&v1_id).unwrap()).unwrap();
        assert_eq!(before["run_id"], after["run_id"]);
        assert_eq!(before["target"], after["target"]);
        assert_eq!(before["started_at"], after["started_at"]);
        assert_eq!(after["schema_version"], serde_json::json!(1));
    }

    #[test]
    fn newer_schema_records_fail_with_an_upgrade_message() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FileSystemRunStore::open(dir.path().join("runs")).expect("open store");
        let run = sample_run("inspect");
        let mut future = serde_json::to_value(&run).unwrap();
        future["schema_version"] = serde_json::json!(99);
        let future_id = format!("run-future{}{}", "b".repeat(20), "c".repeat(4));
        future["run_id"] = serde_json::json!(future_id);
        std::fs::write(
            store.location().join(format!("{future_id}.json")),
            serde_json::to_vec_pretty(&future).unwrap(),
        )
        .unwrap();

        let err = store.load(&future_id).unwrap_err();
        match err {
            RunStoreError::Corrupt(_, message) => {
                assert!(message.contains("newer than this tool understands"));
            }
            other => panic!("expected corrupt error, got {other:?}"),
        }
    }
}
