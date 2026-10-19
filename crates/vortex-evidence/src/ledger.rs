//! Append-only, hash-chained export ledger.
//!
//! Every signed export appends one JSON line to `<data_dir>/exports-ledger.jsonl`.
//! Each entry carries the SHA-256 of its content and of its predecessor, so
//! any later modification or reordering of a past entry is detectable. The
//! first entry's `prev_entry_sha256` is the SHA-256 of the empty string — a
//! fixed, documented genesis value.
//!
//! Honest limits of this design (documented in docs/THREAT_MODEL.md):
//! * it detects modification and reordering of recorded entries;
//! * it does NOT detect truncation of the tail (removing the last entries
//!   leaves a shorter but internally consistent chain);
//! * it is not a substitute for a signature when authenticity (not just
//!   integrity) is required — the Ed25519 signature on each export is.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use vortex_core::digest::sha256_bytes;

/// The ledger file name inside the data directory.
pub const LEDGER_FILE: &str = "exports-ledger.jsonl";

/// SHA-256 of the empty string — the genesis predecessor.
pub const GENESIS_PREV: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// One ledger line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// 1-based sequence number.
    pub seq: u64,
    /// When the export happened (RFC 3339, UTC).
    pub timestamp: String,
    /// The exported run's id.
    pub run_id: String,
    /// SHA-256 of the exported JSON bytes.
    pub payload_sha256: String,
    /// SHA-256 of the signature sidecar bytes.
    pub signature_sha256: String,
    /// `entry_sha256` of the predecessor (genesis for the first entry).
    pub prev_entry_sha256: String,
    /// SHA-256 over this entry's JSON with `entry_sha256` removed.
    pub entry_sha256: String,
}

/// The state of a validated ledger.
#[derive(Debug, Clone, Serialize)]
pub struct LedgerStatus {
    /// Path of the ledger file (present or expected).
    pub path: PathBuf,
    /// How many entries the file holds.
    pub entries: usize,
    /// Whether the whole chain verifies.
    pub valid: bool,
    /// The first sequence number that fails to verify, when invalid.
    pub first_broken_seq: Option<u64>,
    /// Why the chain is broken, when it is.
    pub reason: Option<String>,
}

/// Compute `entry_sha256` the way the chain defines it: over the entry JSON
/// with the `entry_sha256` field removed (so the field can hold its own hash).
fn entry_digest(entry: &LedgerEntry) -> String {
    let mut value = serde_json::to_value(entry).expect("ledger entries serialize");
    if let Some(object) = value.as_object_mut() {
        object.remove("entry_sha256");
    }
    let bytes = serde_json::to_vec(&value).expect("ledger JSON serializes");
    sha256_bytes(&bytes)
}

/// Load all entries from the ledger file (missing file = empty).
fn read_entries(path: &Path) -> Result<Vec<LedgerEntry>, String> {
    let Ok(body) = std::fs::read_to_string(path) else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    for (index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: LedgerEntry = serde_json::from_str(line)
            .map_err(|err| format!("line {} is not a ledger entry: {err}", index + 1))?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Validate the whole chain: recomputes every `entry_sha256` and checks the
/// predecessor links in order.
pub fn validate(path: &Path) -> LedgerStatus {
    let entries = match read_entries(path) {
        Ok(entries) => entries,
        Err(reason) => {
            return LedgerStatus {
                path: path.to_path_buf(),
                entries: 0,
                valid: false,
                first_broken_seq: None,
                reason: Some(reason),
            };
        }
    };
    let count = entries.len();
    let mut expected_prev = GENESIS_PREV.to_string();
    for entry in &entries {
        let recomputed = entry_digest(entry);
        if recomputed != entry.entry_sha256 {
            return LedgerStatus {
                path: path.to_path_buf(),
                entries: count,
                valid: false,
                first_broken_seq: Some(entry.seq),
                reason: Some(format!(
                    "entry {} content does not match its recorded hash (recorded {}, recomputed {})",
                    entry.seq, entry.entry_sha256, recomputed
                )),
            };
        }
        if entry.prev_entry_sha256 != expected_prev {
            return LedgerStatus {
                path: path.to_path_buf(),
                entries: count,
                valid: false,
                first_broken_seq: Some(entry.seq),
                reason: Some(format!(
                    "entry {} does not link to its predecessor (recorded prev {}, expected {expected_prev})",
                    entry.seq, entry.prev_entry_sha256
                )),
            };
        }
        expected_prev = entry.entry_sha256.clone();
    }
    LedgerStatus {
        path: path.to_path_buf(),
        entries: count,
        valid: true,
        first_broken_seq: None,
        reason: None,
    }
}

/// Append one entry, computing its chain fields. Returns the entry as stored.
pub fn append(
    path: &Path,
    run_id: &str,
    payload_sha256: &str,
    signature_sha256: &str,
) -> Result<LedgerEntry, String> {
    let entries = read_entries(path)?;
    let prev_entry_sha256 = entries
        .last()
        .map(|entry| entry.entry_sha256.clone())
        .unwrap_or_else(|| GENESIS_PREV.to_string());
    let seq = entries.last().map(|entry| entry.seq).unwrap_or(0) + 1;
    let mut entry = LedgerEntry {
        seq,
        timestamp: vortex_core::timeutil::now_rfc3339(),
        run_id: run_id.to_string(),
        payload_sha256: payload_sha256.to_string(),
        signature_sha256: signature_sha256.to_string(),
        prev_entry_sha256,
        entry_sha256: String::new(),
    };
    entry.entry_sha256 = entry_digest(&entry);

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("cannot open ledger {path:?}: {err}"))?;
    let line = serde_json::to_string(&entry).map_err(|err| format!("serialize: {err}"))?;
    writeln!(file, "{line}").map_err(|err| format!("cannot append to ledger: {err}"))?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger_path(dir: &Path) -> PathBuf {
        dir.join(LEDGER_FILE)
    }

    #[test]
    fn chain_validates_and_detects_tampering() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = ledger_path(dir.path());
        for i in 0..3 {
            append(
                &path,
                &format!("run-{i}"),
                &format!("payload{i}"),
                &format!("sig{i}"),
            )
            .expect("append");
        }
        let status = validate(&path);
        assert!(status.valid);
        assert_eq!(status.entries, 3);

        // Tamper with the middle entry's payload hash (simulating a
        // modified export record): the chain breaks at that entry.
        let body = std::fs::read_to_string(&path).unwrap();
        let tampered = body.replace("payload1", "payload1-tampered");
        std::fs::write(&path, tampered).unwrap();
        let status = validate(&path);
        assert!(!status.valid);
        assert_eq!(status.first_broken_seq, Some(2));
        assert!(status.reason.unwrap().contains("does not match"));
    }

    #[test]
    fn reordering_breaks_the_chain() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = ledger_path(dir.path());
        for i in 0..3 {
            append(
                &path,
                &format!("run-{i}"),
                &format!("p{i}"),
                &format!("s{i}"),
            )
            .unwrap();
        }
        let body = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = body.lines().collect();
        lines.swap(0, 1);
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let status = validate(&path);
        assert!(!status.valid, "reordered entries must not validate");
    }

    #[test]
    fn tail_truncation_is_not_detectable_and_that_is_documented() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = ledger_path(dir.path());
        for i in 0..3 {
            append(
                &path,
                &format!("run-{i}"),
                &format!("p{i}"),
                &format!("s{i}"),
            )
            .unwrap();
        }
        // Removing the LAST entry leaves a consistent chain — the known,
        // documented limitation of any local hash chain without an external
        // anchor. This test exists so the limitation stays visible.
        let body = std::fs::read_to_string(&path).unwrap();
        let truncated: String = body.lines().take(2).map(|l| format!("{l}\n")).collect();
        std::fs::write(&path, truncated).unwrap();
        let status = validate(&path);
        assert!(status.valid);
        assert_eq!(
            status.entries, 2,
            "tail truncation is undetectable (documented)"
        );
    }

    #[test]
    fn empty_or_missing_ledger_is_valid_zero_entries() {
        let dir = tempfile::tempdir().expect("temp dir");
        let status = validate(&ledger_path(dir.path()));
        assert!(status.valid);
        assert_eq!(status.entries, 0);
    }
}
