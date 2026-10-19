//! DEX (Dalvik Executable) structural reading.
//!
//! Reads the 112-byte header (version from the magic, all table counts and
//! offsets), verifies the adler32 checksum as a *derived* observation, and
//! resolves the defined-class list by walking the documented chain
//! `class_defs → type_ids → string_ids → MUTF-8 string data`. Inventory
//! only: no bytecode analysis, no proto/field/method resolution beyond what
//! the counts describe.

use super::reader::Reader;

/// Header size; anything smaller cannot be a DEX.
pub const DEX_HEADER_SIZE: usize = 112;

/// Hard caps (bounds checks against the buffer are the primary defense).
pub const MAX_STRINGS: usize = 10_000;
pub const MAX_CLASSES: usize = 10_000;
/// Cap on a single MUTF-8 string read (bytes).
pub const MAX_STRING_BYTES: usize = 1024;

/// A parsed DEX's structural view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexFile {
    /// Version from the magic (for example `035`).
    pub version: String,
    /// Stored adler32 checksum (header bytes 8..12).
    pub stored_checksum: u32,
    /// Recomputed adler32 over bytes 12..; `None` when the buffer was too
    /// short to recompute honestly.
    pub computed_checksum: Option<u32>,
    /// True when stored and computed checksums match (when both exist).
    pub checksum_matches: Option<bool>,
    /// Whether the stored SHA-1 signature length is present (20 bytes are
    /// reserved; content verification is not attempted for MUTF-8 safety —
    /// the checksum covers integrity).
    pub has_signature_field: bool,
    /// Declared file size from the header.
    pub file_size: u32,
    /// Bytes actually available.
    pub available_bytes: usize,
    /// Endian tag (0x12345678 for little-endian DEX).
    pub endian_tag: u32,
    /// Table counts from the header.
    pub counts: DexCounts,
    /// Why a table's count is implausible, when one is.
    pub counts_reason: Option<String>,
    /// Defined class descriptors (bounded by [`MAX_CLASSES`]).
    pub classes: Vec<String>,
    /// Why classes could not be listed, when they could not.
    pub classes_reason: Option<String>,
}

/// Table counts from the DEX header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DexCounts {
    /// `string_ids_size`.
    pub strings: u32,
    /// `type_ids_size`.
    pub types: u32,
    /// `proto_ids_size`.
    pub protos: u32,
    /// `field_ids_size`.
    pub fields: u32,
    /// `method_ids_size`.
    pub methods: u32,
    /// `class_defs_size`.
    pub classes: u32,
}

/// Whether the magic bytes are a DEX magic and the version they declare.
pub fn magic_version(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 || !bytes.starts_with(b"dex\n") {
        return None;
    }
    let rest = &bytes[4..8];
    if rest[3] != 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&rest[..3]).into_owned())
}

/// Parse the DEX structure from `bytes` (the prefix that was read).
///
/// `Err` means "not a DEX at all"; partial availability lives inside
/// [`DexFile`] with reasons.
pub fn parse(bytes: &[u8]) -> Result<DexFile, String> {
    let Some(version) = magic_version(bytes) else {
        return Err("not a DEX file (magic mismatch)".to_string());
    };
    let r = Reader::with_endian(bytes, false);
    let header = r
        .slice(0, DEX_HEADER_SIZE)
        .ok_or("truncated DEX header (need 112 bytes)")?;

    let stored_checksum = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let has_signature_field = header.len() >= 32;
    let file_size = u32::from_le_bytes(header[32..36].try_into().unwrap());
    let endian_tag = u32::from_le_bytes(header[40..44].try_into().unwrap());
    let map_off = u32::from_le_bytes(header[52..56].try_into().unwrap());
    let (strings, string_ids_off) = read_count_off(header, 56);
    let (types, type_ids_off) = read_count_off(header, 64);
    let (protos, _) = read_count_off(header, 72);
    let (fields, _) = read_count_off(header, 80);
    let (methods, _) = read_count_off(header, 88);
    let (classes, class_defs_off) = read_count_off(header, 96);
    let _ = map_off;

    let mut counts_reason = None;
    // type_ids must be <= string_ids, class_defs <= type_ids (a class_def
    // indexes type_ids; a type_id indexes string_ids). Implausible counts
    // are flagged, not trusted for allocation.
    if types > strings || classes > types {
        counts_reason = Some(format!(
            "implausible table counts (strings={strings}, types={types}, classes={classes})"
        ));
    }
    if endian_tag != 0x1234_5678 {
        counts_reason = Some(match counts_reason {
            Some(existing) => {
                format!("{existing}; endian tag 0x{endian_tag:x} is not little-endian DEX")
            }
            None => format!("endian tag 0x{endian_tag:x} is not little-endian DEX"),
        });
    }

    // Checksum: adler32 over bytes 12..end. Only computable when we have
    // the whole file (file_size says how big it is).
    let computed_checksum = if bytes.len() as u64 >= u64::from(file_size) && file_size >= 12 {
        Some(adler32(&bytes[12..file_size as usize]))
    } else {
        None
    };
    let checksum_matches = computed_checksum.map(|computed| computed == stored_checksum);

    let mut file = DexFile {
        version,
        stored_checksum,
        computed_checksum,
        checksum_matches,
        has_signature_field,
        file_size,
        available_bytes: bytes.len(),
        endian_tag,
        counts: DexCounts {
            strings,
            types,
            protos,
            fields,
            methods,
            classes,
        },
        counts_reason,
        classes: Vec::new(),
        classes_reason: None,
    };

    // Defined classes: class_defs -> class_idx -> type_ids -> string_ids.
    let classes_listed = classes.min(MAX_CLASSES as u32) as usize;
    if classes == 0 {
        file.classes_reason = Some("no class definitions in the header".to_string());
        return Ok(file);
    }
    if classes > MAX_CLASSES as u32 {
        file.classes_reason = Some(format!(
            "class list capped at {MAX_CLASSES} of {classes} definitions"
        ));
    }
    let mut ok = true;
    for i in 0..classes_listed {
        let def = class_defs_off as usize + i * 32;
        let Some(class_idx) = r.read_u32(def) else {
            ok = false;
            break;
        };
        let type_entry = type_ids_off as usize + class_idx as usize * 4;
        let Some(descriptor_idx) = r.read_u32(type_entry) else {
            ok = false;
            break;
        };
        match read_string(&r, string_ids_off, descriptor_idx) {
            Some(name) => file.classes.push(name),
            None => {
                ok = false;
                break;
            }
        }
    }
    if !ok {
        let reason = "class table chain (class_defs, type_ids, or string data) \
                      extends beyond the bytes read"
            .to_string();
        file.classes_reason = match file.classes_reason {
            Some(existing) => Some(format!("{existing}; {reason}")),
            None => Some(reason),
        };
    }
    Ok(file)
}

/// Read a `size`/`offset` pair from the header at the given base offset.
fn read_count_off(header: &[u8], at: usize) -> (u32, u32) {
    let size = u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
    let off = u32::from_le_bytes(header[at + 4..at + 8].try_into().unwrap());
    (size, off)
}

/// Resolve one string by its string-id index (MUTF-8, ULEB128-prefixed).
fn read_string(r: &Reader, string_ids_off: u32, index: u32) -> Option<String> {
    if index >= MAX_STRINGS as u32 {
        return None;
    }
    let id_entry = string_ids_off as usize + index as usize * 4;
    let data_off = r.read_u32(id_entry)? as usize;
    let mut at = data_off;
    let mut value: u64 = 0;
    let mut shift = 0;
    // ULEB128 length prefix (utf16_size); bounded to 5 bytes.
    for _ in 0..5 {
        let byte = r.read_u8(at)?;
        at += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    if value > MAX_STRING_BYTES as u64 {
        return None; // implausible string length
    }
    // Read up to the terminating NUL, capped.
    let mut raw = Vec::new();
    for _ in 0..MAX_STRING_BYTES {
        let byte = r.read_u8(at)?;
        at += 1;
        if byte == 0 {
            return Some(mutf8_to_string(&raw));
        }
        raw.push(byte);
    }
    Some(mutf8_to_string(&raw)) // unterminated within cap; return what we have
}

/// Lossy MUTF-8 → String conversion. MUTF-8 is CESU-8-like: surrogate
/// pairs arrive as two 3-byte sequences and NUL is encoded as 0xC0 0x80.
/// For class descriptors (ASCII) this is plain UTF-8; anything exotic
/// degrades to replacement characters, and callers treat names as labels,
/// not as exact byte evidence.
fn mutf8_to_string(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes).into_owned();
    text
}

/// adler32 as specified for DEX (identical to zlib's adler32).
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for chunk in data.chunks(5552) {
        for byte in chunk {
            a += u32::from(*byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/native")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    #[test]
    fn dex_fixture_parses_header_counts_and_checksum() {
        let file = parse(&fixture("classes-dex")).expect("parses");
        assert_eq!(file.version, "035");
        assert_eq!(file.counts.strings, 4);
        assert_eq!(file.counts.types, 2);
        assert_eq!(file.counts.protos, 1);
        assert_eq!(file.counts.fields, 0);
        assert_eq!(file.counts.methods, 1);
        assert_eq!(file.counts.classes, 1);
        assert!(file.counts_reason.is_none());
        assert_eq!(file.checksum_matches, Some(true));
        assert_eq!(file.classes, vec!["Ldemo/Sample;"]);
        assert!(file.classes_reason.is_none());
    }

    #[test]
    fn truncated_dex_reports_partial_honestly() {
        let full = fixture("classes-dex");
        let cut = parse(&full[..100]).expect_err("header needs 112 bytes");
        assert!(cut.contains("truncated"));
        // Header present, tables cut: class chain unavailable.
        let cut = parse(&full[..200]).expect("header parses");
        assert!(cut.classes.is_empty());
        assert!(cut.classes_reason.is_some());
        assert!(cut.checksum_matches.is_none()); // cannot verify honestly
    }

    #[test]
    fn bad_magic_is_an_error() {
        let mut valid = b"dex\n036\x00".to_vec();
        valid.resize(200, 0);
        assert!(parse(&valid).is_ok()); // valid magic shape
        let mut invalid = b"notdex\x00\x00".to_vec();
        invalid.resize(200, 0);
        assert!(parse(&invalid).is_err());
        assert!(parse(&[0u8; 200]).is_err());
    }

    #[test]
    fn checksum_mismatch_is_detected() {
        let mut full = fixture("classes-dex");
        // Flip one byte inside the checksummed region.
        let last = full.len() - 1;
        full[last] ^= 0xFF;
        let file = parse(&full).expect("parses");
        assert_eq!(file.checksum_matches, Some(false));
    }

    #[test]
    fn adler32_matches_reference_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"a"), 0x00620062);
        // Cross-checked against Python's zlib.adler32 at implementation
        // time; the classes-dex fixture verifies the streaming chunking on
        // real data (326 bytes) through checksum_matches.
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
    }

    #[test]
    fn magic_version_rejects_malformed_magic() {
        assert_eq!(magic_version(b"dex\n035\x00"), Some("035".to_string()));
        assert_eq!(magic_version(b"dex\n035!"), None); // missing NUL
        assert_eq!(magic_version(b"DEX\n035\x00"), None); // case matters
    }
}
