//! Zip-family container reading (zip/jar/apk): member listing, safety
//! observations, and bounded in-memory member reads.
//!
//! Listing reads only the central directory (metadata, no decompression).
//! Safety observations cover the hazards the extraction-safety review
//! enumerated: compression-bomb suspects, member names that would escape an
//! extraction root, absolute paths, symlink members, unsupported compression
//! methods, and encrypted members. Reading a member decompresses at most
//! `max_archive_member_bytes` into memory and counts every produced byte
//! against the run budget; nothing is ever written to disk.

use super::MemberRead;
use std::io::Read;
use std::path::Path;
use vortex_core::limits::ResourceLimits;

/// Ratio at which a member becomes a bomb suspect (amplification × size).
const BOMB_RATIO: u64 = 100;
/// Members smaller than this are never bomb *suspects* (amplification
/// potential is what matters, and tiny members cannot amplify much).
const BOMB_MIN_SIZE: u64 = 1024 * 1024;
/// Cap on safety observations recorded (they repeat per member; one note
/// per distinct kind with examples is enough for evidence).
const MAX_SAFETY_NOTES: usize = 50;

/// One listed member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipMember {
    /// Raw member name from the central directory.
    pub name: String,
    /// Declared uncompressed size.
    pub size: u64,
    /// Compressed size in the archive.
    pub compressed_size: u64,
    /// Compression method as a stable string (`stored`, `deflate`, ...).
    pub method: &'static str,
    /// Whether this build can read the member's compression method.
    pub readable: bool,
    /// Directory entry (trailing slash).
    pub is_dir: bool,
}

/// A safety observation about a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipSafetyNote {
    /// Classification.
    pub kind: SafetyKind,
    /// Member the note is about.
    pub member: String,
    /// Human explanation with the observed numbers.
    pub detail: String,
}

/// Safety classifications, in the vocabulary of the threat model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyKind {
    /// High amplification (compression bomb suspect).
    BombSuspect,
    /// Name contains `..` components that would escape an extraction root.
    PathTraversal,
    /// Name is absolute (POSIX or Windows drive style).
    AbsolutePath,
    /// Member is a symlink.
    SymlinkMember,
    /// Compression method outside the whitelist.
    UnsupportedMethod,
    /// Member requires a password.
    Encrypted,
}

impl SafetyKind {
    /// Stable identifier used in findings.
    pub const fn as_str(self) -> &'static str {
        match self {
            SafetyKind::BombSuspect => "compression_bomb_suspect",
            SafetyKind::PathTraversal => "path_traversal_name",
            SafetyKind::AbsolutePath => "absolute_path_name",
            SafetyKind::SymlinkMember => "symlink_member",
            SafetyKind::UnsupportedMethod => "unsupported_compression_method",
            SafetyKind::Encrypted => "encrypted_member",
        }
    }
}

/// The result of listing an archive.
#[derive(Debug, Clone, Default)]
pub struct ZipListing {
    /// Members listed (bounded by `max_archive_members`).
    pub members: Vec<ZipMember>,
    /// Total member count from the central directory.
    pub total_members: usize,
    /// Whether listing stopped at the cap.
    pub truncated: bool,
    /// Safety observations (bounded).
    pub safety: Vec<ZipSafetyNote>,
    /// Non-fatal per-member errors observed while listing.
    pub errors: Vec<String>,
    /// `AndroidManifest.xml` plus `classes*.dex` members were seen.
    pub looks_like_apk: bool,
}

/// Map a zip crate compression method to a stable name, with readability.
/// Only stored and deflate are compiled in (pure-Rust path); every other
/// method the crate reports is unsupported here — and said so.
fn method_info(method: zip::CompressionMethod) -> (&'static str, bool) {
    match method {
        zip::CompressionMethod::Stored => ("stored", true),
        zip::CompressionMethod::Deflated => ("deflate", true),
        _ => ("other", false),
    }
}

/// Whether a member name would escape an extraction root (`..` components).
pub fn name_has_traversal(name: &str) -> bool {
    name.split(['/', '\\']).any(|component| component == "..")
}

/// Whether a member name is absolute (POSIX or Windows style).
pub fn name_is_absolute(name: &str) -> bool {
    name.starts_with('/')
        || name.starts_with('\\')
        || name
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic())
            && name.as_bytes().get(1) == Some(&b':')
}

/// List members and safety observations. `Err` means the file is not a
/// readable zip at all (bad central directory, not an archive, ...).
pub fn list(path: &Path, limits: &ResourceLimits) -> Result<ZipListing, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("cannot open archive: {e}"))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("not a readable zip archive: {e}"))?;
    let total = archive.len();
    let cap = limits.max_archive_members.min(total);

    let mut listing = ZipListing {
        total_members: total,
        truncated: total > cap,
        ..ZipListing::default()
    };
    if listing.truncated {
        listing.errors.push(format!(
            "member listing capped at {} of {} entries (max_archive_members)",
            cap, total
        ));
    }

    let mut has_manifest = false;
    let mut has_dex = false;
    for index in 0..cap {
        let entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(err) => {
                if listing.errors.len() < 10 {
                    listing.errors.push(format!("entry {index}: {err}"));
                }
                continue;
            }
        };
        let name = match entry.name() {
            Ok(name) => name.to_string(),
            Err(_) => format!("<entry {index}: non-UTF-8 name>"),
        };
        let (method, readable) = method_info(entry.compression());
        let is_dir = entry.is_dir();
        let encrypted = entry.encrypted();
        let unix_mode = entry.unix_mode();
        let size = entry.size();
        let compressed_size = entry.compressed_size();

        if name.eq_ignore_ascii_case("AndroidManifest.xml") {
            has_manifest = true;
        }
        if is_dex_member_name(&name) {
            has_dex = true;
        }

        // Safety observations (independent of readability).
        if compressed_size > 0 && size >= BOMB_MIN_SIZE && size / compressed_size >= BOMB_RATIO {
            push_note(
                &mut listing,
                SafetyKind::BombSuspect,
                &name,
                format!(
                    "declares {} bytes from {} compressed (ratio {}); would be dangerous to extract",
                    size,
                    compressed_size,
                    size / compressed_size
                ),
            );
        }
        if size > limits.max_archive_member_bytes {
            push_note(
                &mut listing,
                SafetyKind::BombSuspect,
                &name,
                format!(
                    "declares {} bytes, above the per-member read cap ({}); content reads will stop at the cap",
                    size, limits.max_archive_member_bytes
                ),
            );
        }
        if name_has_traversal(&name) {
            push_note(
                &mut listing,
                SafetyKind::PathTraversal,
                &name,
                "name contains '..' components; would escape an extraction root".to_string(),
            );
        }
        if name_is_absolute(&name) {
            push_note(
                &mut listing,
                SafetyKind::AbsolutePath,
                &name,
                "name is absolute; would ignore an extraction root".to_string(),
            );
        }
        if let Some(mode) = unix_mode {
            if mode & 0o170_000 == 0o120_000 {
                push_note(
                    &mut listing,
                    SafetyKind::SymlinkMember,
                    &name,
                    format!("unix mode 0{mode:o} marks this member as a symlink"),
                );
            }
        }
        if !readable {
            push_note(
                &mut listing,
                SafetyKind::UnsupportedMethod,
                &name,
                format!("compression method '{method}' is not supported; metadata only"),
            );
        }
        if encrypted {
            push_note(
                &mut listing,
                SafetyKind::Encrypted,
                &name,
                "member is encrypted; content cannot be read without a password".to_string(),
            );
        }

        listing.members.push(ZipMember {
            name,
            size,
            compressed_size,
            method,
            readable: readable && !encrypted,
            is_dir,
        });
    }
    listing.looks_like_apk = has_manifest && has_dex;
    Ok(listing)
}

fn push_note(listing: &mut ZipListing, kind: SafetyKind, member: &str, detail: String) {
    if listing.safety.len() >= MAX_SAFETY_NOTES {
        return;
    }
    listing.safety.push(ZipSafetyNote {
        kind,
        member: member.to_string(),
        detail,
    });
}

/// Whether a member name looks like a DEX payload (`classes.dex`,
/// `classes2.dex`, ...).
pub fn is_dex_member_name(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    if let Some(stem) = base.strip_suffix(".dex") {
        stem == "classes"
            || (stem.starts_with("classes") && stem[7..].chars().all(|c| c.is_ascii_digit()))
    } else {
        false
    }
}

/// Read one member's decompressed content into memory, bounded by the
/// per-member cap and the remaining budget. Counts produced bytes against
/// `budget`.
pub fn read_member(
    path: &Path,
    member: &str,
    limits: &ResourceLimits,
    budget: &mut u64,
) -> MemberRead {
    let allow = limits.max_archive_member_bytes.min(*budget);
    if allow == 0 {
        return MemberRead::Failed("byte budget exhausted".to_string());
    }
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => return MemberRead::Failed(format!("cannot open archive: {err}")),
    };
    let mut archive = match zip::ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(err) => return MemberRead::Failed(format!("archive unreadable: {err}")),
    };
    let mut entry = match archive.by_name(member) {
        Ok(entry) => entry,
        Err(err) => return MemberRead::Failed(format!("member not readable: {err}")),
    };
    let full_size = entry.size();
    let mut buffer = Vec::new();
    match entry.by_ref().take(allow).read_to_end(&mut buffer) {
        Ok(produced) => {
            *budget = budget.saturating_sub(produced as u64);
            if (produced as u64) < full_size {
                MemberRead::Truncated(buffer, full_size)
            } else {
                MemberRead::Full(buffer)
            }
        }
        Err(err) => MemberRead::Failed(format!("decompression failed: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn limits_with(member_bytes: u64) -> ResourceLimits {
        ResourceLimits {
            max_archive_member_bytes: member_bytes,
            max_archive_members: 500,
            ..ResourceLimits::default()
        }
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8], SimpleFileOptions)]) {
        let mut writer = ZipWriter::new(std::fs::File::create(path).unwrap());
        for (name, content, options) in entries {
            writer
                .start_file(name.to_string(), *options)
                .unwrap_or_else(|e| panic!("start_file {name}: {e}"));
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap();
    }

    fn stored() -> SimpleFileOptions {
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored)
    }

    fn deflated() -> SimpleFileOptions {
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated)
    }

    #[test]
    fn normal_zip_lists_members_without_decompression() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("normal.zip");
        write_zip(
            &zip_path,
            &[
                ("alpha.txt", b"alpha content", stored()),
                (
                    "nested/beta.txt",
                    b"beta beta beta beta beta beta beta",
                    deflated(),
                ),
            ],
        );
        let listing = list(&zip_path, &limits_with(1024 * 1024)).unwrap();
        assert_eq!(listing.total_members, 2);
        assert!(!listing.truncated);
        let names: Vec<&str> = listing.members.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"alpha.txt"));
        assert!(names.contains(&"nested/beta.txt"));
        let alpha = listing
            .members
            .iter()
            .find(|m| m.name == "alpha.txt")
            .unwrap();
        assert_eq!(alpha.method, "stored");
        assert!(alpha.readable);
        assert_eq!(alpha.size, 13);
        let beta = listing
            .members
            .iter()
            .find(|m| m.name == "nested/beta.txt")
            .unwrap();
        assert_eq!(beta.method, "deflate");
        assert!(beta.readable);
        assert!(listing.safety.is_empty(), "{:?}", listing.safety);
        assert!(!listing.looks_like_apk);
    }

    #[test]
    fn member_read_is_bounded_and_counts_budget() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("content.zip");
        write_zip(&zip_path, &[("data.bin", b"0123456789", deflated())]);
        let mut budget = 100u64;
        let read = read_member(&zip_path, "data.bin", &limits_with(4), &mut budget);
        match read {
            MemberRead::Truncated(buffer, full) => {
                assert_eq!(buffer.len(), 4);
                assert_eq!(full, 10);
            }
            other => panic!("expected truncated, got {other:?}"),
        }
        assert_eq!(budget, 96);
        let mut budget = 3u64; // budget below the member cap
        let read = read_member(&zip_path, "data.bin", &limits_with(u64::MAX), &mut budget);
        assert!(matches!(read, MemberRead::Truncated(b, 10) if b.len() == 3));
        let mut budget = 0u64;
        assert!(matches!(
            read_member(&zip_path, "data.bin", &limits_with(10), &mut budget),
            MemberRead::Failed(_)
        ));
    }

    #[test]
    fn bomb_suspect_is_flagged_by_ratio_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("bomb.zip");
        // 4 MiB of zeros deflates tiny: ratio in the thousands.
        let zeros = vec![0u8; 4 * 1024 * 1024];
        write_zip(&zip_path, &[("bomb.bin", &zeros, deflated())]);
        let listing = list(&zip_path, &limits_with(1024 * 1024)).unwrap();
        let bomb = listing
            .safety
            .iter()
            .find(|n| n.kind == SafetyKind::BombSuspect)
            .expect("bomb suspect flagged");
        assert!(bomb.detail.contains("ratio"), "{}", bomb.detail);
        // The same member is also above the per-member cap in these limits.
        assert_eq!(
            listing
                .safety
                .iter()
                .filter(|n| n.kind == SafetyKind::BombSuspect)
                .count(),
            2
        );
        // And a bounded read stops at the cap instead of trusting the header.
        let mut budget = u64::MAX;
        match read_member(
            &zip_path,
            "bomb.bin",
            &limits_with(1024 * 1024),
            &mut budget,
        ) {
            MemberRead::Truncated(buffer, full) => {
                assert_eq!(buffer.len(), 1024 * 1024);
                assert_eq!(full, 4 * 1024 * 1024);
            }
            other => panic!("expected bounded read, got {other:?}"),
        }
    }

    #[test]
    fn traversal_and_absolute_names_are_flagged() {
        assert!(name_has_traversal("../../etc/passwd"));
        assert!(name_has_traversal("ok/../still-ok"));
        assert!(name_has_traversal("win\\..\\style"));
        assert!(!name_has_traversal("a/b/c.txt"));
        assert!(name_is_absolute("/etc/passwd"));
        assert!(name_is_absolute("\\\\server\\share"));
        assert!(name_is_absolute("C:\\Windows\\evil"));
        // Drive-qualified without a slash is still a Windows path on that
        // drive — dangerous to extract even though it is not fully absolute.
        assert!(name_is_absolute("c:relative-on-drive"));
        assert!(!name_is_absolute("relative/path.txt"));
        assert!(!name_is_absolute("driveletters.txt"));
    }

    #[test]
    fn symlink_members_are_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("links.zip");
        let mut writer = ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
        let options = SimpleFileOptions::default().unix_permissions(0o120_777);
        writer
            .add_symlink("evil-link", "/etc/passwd", options)
            .unwrap();
        writer.finish().unwrap();
        let listing = list(&zip_path, &limits_with(1024)).unwrap();
        assert_eq!(
            listing.safety[0].kind,
            SafetyKind::SymlinkMember,
            "{:?}",
            listing.safety
        );
        assert!(listing.safety[0].detail.contains("symlink"));
    }

    #[test]
    fn apk_shape_is_detected_from_member_names() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("app.apk");
        let dex_magic: Vec<u8> = b"dex\n035\x00".iter().copied().chain([0u8; 120]).collect();
        write_zip(
            &zip_path,
            &[
                ("AndroidManifest.xml", b"<manifest/>", deflated()),
                ("classes.dex", &dex_magic, stored()),
                ("res/layout/main.xml", b"<layout/>", deflated()),
            ],
        );
        let listing = list(&zip_path, &limits_with(1024 * 1024)).unwrap();
        assert!(listing.looks_like_apk);
        assert!(is_dex_member_name("classes.dex"));
        assert!(is_dex_member_name("classes2.dex"));
        assert!(is_dex_member_name("sub/dir/classes9.dex"));
        assert!(!is_dex_member_name("classes.dex.bak"));
        assert!(!is_dex_member_name("myclasses.dex"));
    }

    #[test]
    fn not_a_zip_is_an_honest_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.zip");
        std::fs::write(&path, b"this is not a zip file at all").unwrap();
        let err = list(&path, &ResourceLimits::default()).unwrap_err();
        assert!(err.contains("not a readable zip"), "{err}");
        let missing = dir.path().join("missing.zip");
        assert!(list(&missing, &ResourceLimits::default()).is_err());
    }

    #[test]
    fn member_listing_respects_the_member_cap() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("many.zip");
        let mut writer = ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
        for i in 0..10 {
            writer.start_file(format!("f{i}.txt"), stored()).unwrap();
            writer.write_all(b"x").unwrap();
        }
        writer.finish().unwrap();
        let small = ResourceLimits {
            max_archive_members: 3,
            ..ResourceLimits::default()
        };
        let listing = list(&zip_path, &small).unwrap();
        assert_eq!(listing.total_members, 10);
        assert!(listing.truncated);
        assert_eq!(listing.members.len(), 3);
        assert!(listing
            .errors
            .iter()
            .any(|e| e.contains("capped at 3 of 10")));
    }
}
