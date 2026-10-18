//! Target identity computation (digests used in run records).
//!
//! Single files are hashed by streaming. Directories use the manifest digest
//! defined in [`vortex_core::digest::directory_manifest_digest`]: the sorted
//! `"{relative path}\0{file sha256}\n"` lines of every regular file found
//! within the configured limits. The same formula is used by the built-in
//! provider, which keeps `TargetIdentity` and analysis summaries consistent.

use vortex_core::digest::{directory_manifest_digest, sha256_file};
use vortex_core::error::VortexResult;
use vortex_core::limits::ResourceLimits;
use vortex_core::paths::{TargetInfo, TargetKind};
use vortex_evidence::TargetIdentity;
use vortex_providers::tree;

/// Compute the evidence-model identity for a validated target.
///
/// Returns the identity plus any coverage note (for example when the walk
/// was truncated by limits, the digest only covers the files that were
/// walked — callers must record that as a limitation).
pub fn compute_target_identity(
    target: &TargetInfo,
    limits: &ResourceLimits,
) -> VortexResult<(TargetIdentity, Option<String>)> {
    match target.kind {
        TargetKind::File => {
            let sha256 = sha256_file(&target.canonical)?;
            Ok((
                TargetIdentity {
                    input_path: target.input.display().to_string(),
                    canonical_path: target.canonical.display().to_string(),
                    kind: "file".to_string(),
                    sha256,
                    size_bytes: target.size,
                    file_count: None,
                },
                None,
            ))
        }
        TargetKind::Directory => {
            let walk_result = tree::walk(&target.canonical, limits, &|| None);
            let mut entries = Vec::new();
            let mut total_bytes = 0u64;
            for entry in &walk_result.files {
                match sha256_file(&entry.abs_path) {
                    Ok(digest) => {
                        total_bytes += entry.size;
                        entries.push((
                            entry.rel_path.display().to_string().replace('\\', "/"),
                            digest,
                        ));
                    }
                    Err(_) => {
                        // Unreadable files are excluded from the digest; the
                        // note below states the digest's coverage honestly.
                    }
                }
            }
            let note = if walk_result.truncated {
                Some(format!(
                    "directory digest covers {} of the files found before the walk limit \
                     (max_files={}); it is deterministic for the same input and limits but is \
                     not a digest of the complete tree",
                    entries.len(),
                    limits.max_files
                ))
            } else {
                None
            };
            Ok((
                TargetIdentity {
                    input_path: target.input.display().to_string(),
                    canonical_path: target.canonical.display().to_string(),
                    kind: "directory".to_string(),
                    sha256: directory_manifest_digest(&entries),
                    size_bytes: total_bytes,
                    file_count: Some(walk_result.files.len() as u64),
                },
                note,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vortex_core::paths::validate_target;

    #[test]
    fn file_identity_uses_content_hash() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"hello").unwrap();
        let target = validate_target(&file).unwrap();
        let (identity, note) =
            compute_target_identity(&target, &ResourceLimits::default()).unwrap();
        assert_eq!(identity.kind, "file");
        assert_eq!(identity.size_bytes, 5);
        assert_eq!(
            identity.sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert!(note.is_none());
    }

    #[test]
    fn directory_identity_is_deterministic_and_reports_truncation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("one.js"), b"one").unwrap();
        std::fs::write(dir.path().join("two.js"), b"two").unwrap();
        let target = validate_target(dir.path()).unwrap();

        let (first, note) = compute_target_identity(&target, &ResourceLimits::default()).unwrap();
        let (second, _) = compute_target_identity(&target, &ResourceLimits::default()).unwrap();
        assert_eq!(first.sha256, second.sha256);
        assert_eq!(first.file_count, Some(2));
        assert!(note.is_none());

        let limited = ResourceLimits {
            max_files: 1,
            ..ResourceLimits::default()
        };
        let (partial, partial_note) = compute_target_identity(&target, &limited).unwrap();
        assert_eq!(partial.file_count, Some(1));
        assert!(partial_note
            .as_deref()
            .unwrap()
            .contains("not a digest of the complete tree"));
    }
}
