//! Electron `asar` archive reading (read-only): listing and bounded member
//! reads.
//!
//! The on-disk format (verified against the official `asar` tool's reader at
//! implementation time — this fixture was produced by that tool) is two
//! Chromium pickles followed by the file data:
//!
//! ```text
//! u32  4                     size-pickle payload length (always 4)
//! u32  headerPickleLen       total size of the header pickle that follows
//! u32  payloadLen            header-pickle payload (== headerPickleLen - 4)
//! u32  jsonLen               JSON string length including its NUL
//! JSON bytes, NUL, padding to a 4-byte boundary
//! file data ...              member offsets are relative to here (8 + headerPickleLen)
//! ```
//!
//! Directory nodes carry `{"files": {...}}`; file nodes carry
//! `{"size": N, "offset": "decimal string"}`, and files stored beside the
//! archive instead of inside it carry `"unpacked": true` (they live in
//! `<archive>.unpacked/`, which Vortex-RE lists but does not read — the
//! sibling directory may not exist).
//!
//! Everything else follows the archive-module rules: no disk writes, bounded
//! in-memory reads, member listing capped, member bytes counted against the
//! run budget.

use serde_json::Value;
use std::io::Read;
use std::path::Path;
use vortex_core::limits::ResourceLimits;

use super::MemberRead;

/// One listed member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsarMember {
    /// Forward-slash path inside the archive.
    pub path: String,
    /// Declared size in bytes.
    pub size: u64,
    /// Offset into the data region (packed members only).
    pub offset: u64,
    /// True when the file lives in the `.unpacked` sibling directory.
    pub unpacked: bool,
    /// True when the header marks the file executable.
    pub executable: bool,
    /// True when the header carries an integrity block.
    pub integrity: bool,
}

/// The result of listing an asar archive.
#[derive(Debug, Clone, Default)]
pub struct AsarListing {
    /// Members listed (bounded by `max_archive_members`).
    pub members: Vec<AsarMember>,
    /// Total file nodes in the header.
    pub total_members: usize,
    /// Whether listing stopped at the cap.
    pub truncated: bool,
    /// Non-fatal problems observed while walking the tree.
    pub errors: Vec<String>,
    /// JSON header size in bytes (metadata, reported for evidence).
    pub header_size: u64,
    /// Where the data region starts in the file.
    pub data_base: u64,
}

/// Maximum directory-nesting depth accepted in the header tree.
const MAX_DEPTH: usize = 64;

/// List members of an asar archive. `Err` means "not an asar we can read".
pub fn list(path: &Path, limits: &ResourceLimits) -> Result<AsarListing, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("cannot open archive: {e}"))?;
    let file_len = file
        .metadata()
        .map_err(|e| format!("cannot stat archive: {e}"))?
        .len();

    // Size pickle: exactly 8 bytes (payload length 4, then the u32 value).
    let mut size_pickle = [0u8; 8];
    file.read_exact(&mut size_pickle)
        .map_err(|_| "not an asar archive (shorter than 8 bytes)".to_string())?;
    let payload_len = u32::from_le_bytes(size_pickle[0..4].try_into().unwrap());
    if payload_len != 4 {
        return Err(format!(
            "not an asar archive (size-pickle payload is {payload_len}, expected 4)"
        ));
    }
    let header_pickle_len = u32::from_le_bytes(size_pickle[4..8].try_into().unwrap()) as u64;
    if header_pickle_len < 8 {
        return Err("not an asar archive (header pickle too small)".to_string());
    }
    if 8 + header_pickle_len > file_len {
        return Err(format!(
            "header claims {header_pickle_len} bytes but only {} follow the size pickle",
            file_len - 8
        ));
    }

    // Header pickle: [u32 payload][u32 jsonLen][JSON + NUL + padding].
    let mut header_pickle = vec![0u8; header_pickle_len as usize];
    file.read_exact(&mut header_pickle)
        .map_err(|e| format!("cannot read header pickle: {e}"))?;
    let payload = u32::from_le_bytes(header_pickle[0..4].try_into().unwrap()) as u64;
    if payload + 4 != header_pickle_len {
        return Err(format!(
            "header pickle is inconsistent (payload {payload} + 4 != {header_pickle_len})"
        ));
    }
    let json_len = u32::from_le_bytes(header_pickle[4..8].try_into().unwrap()) as usize;
    if json_len == 0 || json_len + 8 > header_pickle_len as usize {
        return Err(format!(
            "header JSON length {json_len} does not fit the pickle"
        ));
    }
    let json_bytes = &header_pickle[8..8 + json_len];
    let json_bytes = &json_bytes[..json_bytes
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(json_bytes.len())];
    let header: Value =
        serde_json::from_slice(json_bytes).map_err(|e| format!("header is not valid JSON: {e}"))?;

    let mut listing = AsarListing {
        header_size: header_pickle_len,
        data_base: 8 + header_pickle_len,
        ..AsarListing::default()
    };
    walk_files(&header, "", 0, limits, &mut listing);
    if listing.members.len() > limits.max_archive_members {
        // walk_files caps pushes; note the exact total separately below.
    }
    Ok(listing)
}

/// Recursively walk the `{"files": {...}}` tree, collecting file nodes.
fn walk_files(
    node: &Value,
    prefix: &str,
    depth: usize,
    limits: &ResourceLimits,
    listing: &mut AsarListing,
) {
    if depth > MAX_DEPTH {
        listing.errors.push(format!(
            "header tree deeper than {MAX_DEPTH} levels; stopped at {prefix:?}"
        ));
        return;
    }
    let Some(files) = node.get("files").and_then(Value::as_object) else {
        listing
            .errors
            .push(format!("{prefix:?}: node has no files map"));
        return;
    };
    for (name, child) in files {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if child.get("files").is_some() {
            walk_files(child, &path, depth + 1, limits, listing);
            continue;
        }
        listing.total_members += 1;
        if listing.members.len() >= limits.max_archive_members {
            listing.truncated = true;
            continue;
        }
        let size = child.get("size").and_then(Value::as_u64).unwrap_or(0);
        let offset = child
            .get("offset")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        listing.members.push(AsarMember {
            path,
            size,
            offset,
            unpacked: child
                .get("unpacked")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            executable: child
                .get("executable")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            integrity: child.get("integrity").is_some(),
        });
    }
}

/// Read one packed member's content, bounded by the per-member cap and the
/// remaining budget. Unpacked members are refused: they live outside the
/// archive file and the sibling directory may not exist.
pub fn read_member(
    path: &Path,
    member: &str,
    limits: &ResourceLimits,
    budget: &mut u64,
) -> MemberRead {
    let listing = match list(path, limits) {
        Ok(listing) => listing,
        Err(err) => return MemberRead::Failed(err),
    };
    let Some(entry) = listing.members.iter().find(|m| m.path == member) else {
        return MemberRead::Failed(format!("member {member:?} not found in the header"));
    };
    if entry.unpacked {
        return MemberRead::Failed(format!(
            "member {member:?} is stored unpacked beside the archive, not inside it"
        ));
    }
    let allow = limits.max_archive_member_bytes.min(*budget);
    if allow == 0 {
        return MemberRead::Failed("byte budget exhausted".to_string());
    }
    // asar members are concatenated in the data region with no framing;
    // a read must stop at the member's declared size, not at the cap,
    // or it silently returns the next member's bytes too.
    let want = entry.size.min(allow);
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => return MemberRead::Failed(format!("cannot open archive: {err}")),
    };
    use std::io::Seek;
    let start = listing.data_base + entry.offset;
    if file.seek(std::io::SeekFrom::Start(start)).is_err() {
        return MemberRead::Failed("cannot seek to member data".to_string());
    }
    let mut buffer = Vec::new();
    let produced = match file.take(want).read_to_end(&mut buffer) {
        Ok(produced) => produced,
        Err(err) => return MemberRead::Failed(format!("read failed: {err}")),
    };
    *budget = budget.saturating_sub(produced as u64);
    if (produced as u64) < entry.size {
        MemberRead::Truncated(buffer, entry.size)
    } else {
        MemberRead::Full(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/archives/demo.asar")
            .canonicalize()
            .expect("asar fixture exists (built with the official asar tool)")
    }

    fn limits_with(members: usize) -> ResourceLimits {
        ResourceLimits {
            max_archive_members: members,
            max_archive_member_bytes: 4 * 1024 * 1024,
            ..ResourceLimits::default()
        }
    }

    #[test]
    fn official_tool_fixture_lists_exactly() {
        let listing = list(&fixture(), &limits_with(500)).expect("parses");
        assert_eq!(listing.total_members, 5);
        assert!(!listing.truncated);
        let paths: Vec<&str> = listing.members.iter().map(|m| m.path.as_str()).collect();
        // serde_json object keys sort alphabetically; the listing order is
        // deterministic regardless of how the producer wrote the header.
        assert_eq!(
            paths,
            vec![
                "README.md",
                "asset.bin",
                "package.json",
                "src/app/main.js",
                "src/lib/util.js",
            ]
        );
        let unpacked = listing
            .members
            .iter()
            .find(|m| m.path == "asset.bin")
            .unwrap();
        assert!(unpacked.unpacked);
        assert!(unpacked.integrity, "asar 3.x writes integrity blocks");
        let main = listing
            .members
            .iter()
            .find(|m| m.path == "src/app/main.js")
            .unwrap();
        assert_eq!(
            main.size,
            b"console.log(\"hello from main\");\n".len() as u64
        );
        assert!(!main.unpacked);
        assert!(listing.errors.is_empty(), "{:?}", listing.errors);
    }

    #[test]
    fn packed_member_content_reads_back_exactly() {
        let mut budget = u64::MAX;
        let read = read_member(
            &fixture(),
            "src/app/main.js",
            &limits_with(500),
            &mut budget,
        );
        match read {
            MemberRead::Full(bytes) => {
                // Exactly main.js — not a byte of the util.js data that
                // follows it in the unframed data region.
                assert_eq!(bytes, b"console.log(\"hello from main\");\n");
            }
            other => panic!("expected full read, got {other:?}"),
        }
        // util.js too: its content must not start with main.js leftovers.
        let read = read_member(
            &fixture(),
            "src/lib/util.js",
            &limits_with(500),
            &mut budget,
        );
        match read {
            MemberRead::Full(bytes) => assert_eq!(bytes, b"module.exports = () => 42;\n"),
            other => panic!("expected full read, got {other:?}"),
        }
    }

    #[test]
    fn unpacked_member_is_refused_with_reason() {
        let mut budget = u64::MAX;
        let read = read_member(&fixture(), "asset.bin", &limits_with(500), &mut budget);
        match read {
            MemberRead::Failed(reason) => assert!(reason.contains("unpacked"), "{reason}"),
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn reads_are_capped_and_counted() {
        let limits = ResourceLimits {
            max_archive_member_bytes: 10,
            max_archive_members: 500,
            ..ResourceLimits::default()
        };
        let mut budget = 100u64;
        match read_member(&fixture(), "package.json", &limits, &mut budget) {
            MemberRead::Truncated(bytes, full) => {
                assert_eq!(bytes.len(), 10);
                assert_eq!(full, 62);
            }
            other => panic!("expected truncated read, got {other:?}"),
        }
        assert_eq!(budget, 90);
    }

    #[test]
    fn member_listing_respects_the_cap() {
        let listing = list(&fixture(), &limits_with(2)).expect("parses");
        assert_eq!(listing.total_members, 5);
        assert!(listing.truncated);
        assert_eq!(listing.members.len(), 2);
    }

    #[test]
    fn non_asar_files_are_honest_errors() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain.txt");
        std::fs::write(&plain, b"just some text that is not an archive").unwrap();
        let err = list(&plain, &ResourceLimits::default()).unwrap_err();
        assert!(err.contains("not an asar"), "{err}");

        // A file whose first u32 is not 4 (pickle payload mismatch).
        let mut fake = dir.path().join("fake.asar");
        std::fs::write(&fake, [0u8; 16].as_slice()).unwrap();
        let err = list(&fake, &ResourceLimits::default()).unwrap_err();
        assert!(err.contains("not an asar"), "{err}");

        // Missing file.
        fake = dir.path().join("missing.asar");
        assert!(list(&fake, &ResourceLimits::default()).is_err());
    }

    #[test]
    fn lying_header_size_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lying.asar");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // absurd pickle length
        bytes.extend_from_slice(&[0u8; 64]);
        std::fs::write(&path, &bytes).unwrap();
        let err = list(&path, &ResourceLimits::default()).unwrap_err();
        assert!(err.contains("claims") || err.contains("header"), "{err}");
    }
}
