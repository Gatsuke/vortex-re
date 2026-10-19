//! Bounded, deterministic directory traversal.
//!
//! Policy decisions that this walk enforces:
//! * entries are visited in lexicographic order for reproducibility;
//! * relative paths are built with '/' on every platform, so the same
//!   tree yields byte-identical paths — and therefore evidence — on
//!   Linux, macOS, and Windows alike (Windows accepts '/' when these
//!   paths are rejoined onto a root);
//! * symbolic links are never followed — they are recorded as skipped with
//!   their target, because following them could read outside the inspection
//!   root;
//! * file counts and total sizes are limited, and hitting a limit marks the
//!   walk truncated rather than silently dropping entries.

use crate::provider::StopReason;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use vortex_core::limits::ResourceLimits;

/// Hard cap on directory depth to avoid pathological trees.
pub const MAX_DEPTH: usize = 64;

/// Why an entry was skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// A symbolic link (target shown when readable).
    Symlink {
        /// Where the link points, when it could be read.
        target: Option<String>,
    },
    /// The file exceeded the per-file size limit.
    TooLarge {
        /// Its size in bytes.
        size: u64,
    },
    /// The entry could not be read.
    Unreadable {
        /// The I/O error message.
        error: String,
    },
}

/// A skipped entry record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedEntry {
    /// Path relative to the root.
    pub rel_path: String,
    /// Why it was skipped.
    pub reason: SkipReason,
}

impl SkippedEntry {
    /// One-line human explanation.
    pub fn describe(&self) -> String {
        match &self.reason {
            SkipReason::Symlink { target } => match target {
                Some(target) => {
                    format!("{}: symlink (-> {target}) skipped by policy", self.rel_path)
                }
                None => format!("{}: symlink skipped by policy", self.rel_path),
            },
            SkipReason::TooLarge { size } => {
                format!(
                    "{}: skipped, {} bytes exceeds the per-file limit",
                    self.rel_path, size
                )
            }
            SkipReason::Unreadable { error } => format!("{}: unreadable ({error})", self.rel_path),
        }
    }
}

/// A walked regular file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkEntry {
    /// Path relative to the root.
    pub rel_path: PathBuf,
    /// Absolute path.
    pub abs_path: PathBuf,
    /// Size in bytes.
    pub size: u64,
}

/// The result of walking a tree.
#[derive(Debug, Clone, Default)]
pub struct WalkResult {
    /// Regular files in lexicographic order.
    pub files: Vec<WalkEntry>,
    /// Directories in lexicographic order.
    pub directories: Vec<PathBuf>,
    /// Skipped entries with reasons.
    pub skipped: Vec<SkippedEntry>,
    /// Sum of file sizes.
    pub total_bytes: u64,
    /// True when limits stopped the walk early.
    pub truncated: bool,
    /// Why the walk stopped early, when it did.
    pub stop_reason: Option<StopReason>,
}

/// Join one component onto a relative path, always with '/'.
///
/// `PathBuf::join` would use the platform separator (`\` on Windows),
/// which would make the same tree produce different evidence paths on
/// different platforms. Building the string with '/' keeps paths — and
/// the records derived from them — byte-identical everywhere, and
/// preserves arbitrary (possibly non-UTF-8) file names via `OsString`.
fn join_rel(rel: &Path, name: &OsStr) -> PathBuf {
    let mut joined = rel.as_os_str().to_os_string();
    if !joined.is_empty() {
        joined.push("/");
    }
    joined.push(name);
    joined.into()
}

/// Walk `root` deterministically within `limits`.
///
/// `stop_check` is consulted between entries so walks can be cancelled or
/// timed out at safe checkpoints.
pub fn walk(
    root: &Path,
    limits: &ResourceLimits,
    stop_check: &dyn Fn() -> Option<StopReason>,
) -> WalkResult {
    let mut result = WalkResult::default();
    let mut stack: Vec<(PathBuf, PathBuf, usize)> = vec![(root.to_path_buf(), PathBuf::new(), 0)];

    while let Some((abs_dir, rel_dir, depth)) = stack.pop() {
        if let Some(reason) = stop_check() {
            result.stop_reason = Some(reason);
            result.truncated = true;
            break;
        }
        if depth >= MAX_DEPTH {
            result.skipped.push(SkippedEntry {
                rel_path: rel_dir.display().to_string(),
                reason: SkipReason::Unreadable {
                    error: format!("directory nesting exceeds {MAX_DEPTH} levels"),
                },
            });
            continue;
        }
        let entries = match std::fs::read_dir(&abs_dir) {
            Ok(entries) => entries,
            Err(err) => {
                result.skipped.push(SkippedEntry {
                    rel_path: rel_dir.display().to_string(),
                    reason: SkipReason::Unreadable {
                        error: err.to_string(),
                    },
                });
                continue;
            }
        };
        let mut children: Vec<_> = entries.flatten().collect();
        children.sort_by_key(|entry| entry.file_name());
        // Depth-first in lexicographic order: push reversed.
        for entry in children.into_iter().rev() {
            let name = entry.file_name();
            let child_rel = join_rel(&rel_dir, &name);
            let child_abs = abs_dir.join(&name);
            // Never follow symlinks: inspect the link itself.
            let Ok(meta) = std::fs::symlink_metadata(&child_abs) else {
                result.skipped.push(SkippedEntry {
                    rel_path: child_rel.display().to_string(),
                    reason: SkipReason::Unreadable {
                        error: "metadata unavailable".to_string(),
                    },
                });
                continue;
            };
            let file_type = meta.file_type();
            if file_type.is_symlink() {
                let target = std::fs::read_link(&child_abs)
                    .ok()
                    .map(|t| t.display().to_string());
                result.skipped.push(SkippedEntry {
                    rel_path: child_rel.display().to_string(),
                    reason: SkipReason::Symlink { target },
                });
                continue;
            }
            if file_type.is_dir() {
                if result.directories.len() >= limits.max_files {
                    result.truncated = true;
                    continue;
                }
                result.directories.push(child_rel.clone());
                stack.push((child_abs, child_rel, depth + 1));
                continue;
            }
            if !file_type.is_file() {
                result.skipped.push(SkippedEntry {
                    rel_path: child_rel.display().to_string(),
                    reason: SkipReason::Unreadable {
                        error: "not a regular file (device, fifo, socket, ...)".to_string(),
                    },
                });
                continue;
            }
            if result.files.len() >= limits.max_files {
                result.truncated = true;
                continue;
            }
            let size = meta.len();
            if size > limits.max_file_bytes {
                result.skipped.push(SkippedEntry {
                    rel_path: child_rel.display().to_string(),
                    reason: SkipReason::TooLarge { size },
                });
                continue;
            }
            result.total_bytes += size;
            result.files.push(WalkEntry {
                rel_path: child_rel,
                abs_path: child_abs,
                size,
            });
        }
    }

    // Files were collected via DFS; re-sort for a stable global order.
    result.files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    result.directories.sort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    fn no_stop() -> Option<StopReason> {
        None
    }

    fn setup_tree(root: &Path) {
        let make = |rel: &str, content: &[u8]| {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            File::create(&path).unwrap().write_all(content).unwrap();
        };
        make("b.txt", b"bee");
        make("a.txt", b"apple");
        make("sub/inner.txt", b"inner");
        make("sub/deep/x.txt", b"deep");
    }

    #[test]
    fn walk_is_deterministic_and_lexicographic() {
        let dir = tempfile::tempdir().unwrap();
        setup_tree(dir.path());
        let result = walk(dir.path(), &ResourceLimits::default(), &no_stop);
        let paths: Vec<String> = result
            .files
            .iter()
            .map(|f| f.rel_path.display().to_string())
            .collect();
        // Forward slashes on every platform: identical trees must yield
        // identical evidence paths (see join_rel).
        assert_eq!(
            paths,
            vec!["a.txt", "b.txt", "sub/deep/x.txt", "sub/inner.txt"]
        );
        assert_eq!(
            result.directories,
            vec![PathBuf::from("sub"), PathBuf::from("sub/deep")]
        );
        assert_eq!(result.total_bytes, 5 + 3 + 4 + 5);
    }

    #[test]
    fn walk_enforces_max_files() {
        let dir = tempfile::tempdir().unwrap();
        setup_tree(dir.path());
        let limits = ResourceLimits {
            max_files: 2,
            ..ResourceLimits::default()
        };
        let result = walk(dir.path(), &limits, &no_stop);
        assert!(result.truncated);
        assert!(result.files.len() <= 3); // 2 files + directories counted separately
    }

    #[test]
    fn walk_skips_oversize_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.bin"), vec![0u8; 1024]).unwrap();
        std::fs::write(dir.path().join("small.txt"), b"ok").unwrap();
        let limits = ResourceLimits {
            max_file_bytes: 512,
            ..ResourceLimits::default()
        };
        let result = walk(dir.path(), &limits, &no_stop);
        assert_eq!(result.files.len(), 1);
        assert!(matches!(
            result.skipped[0].reason,
            SkipReason::TooLarge { size: 1024 }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn walk_records_symlinks_without_following() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.txt"), b"real").unwrap();
        std::os::unix::fs::symlink("real.txt", dir.path().join("link.txt")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join("outside.txt")).unwrap();
        let result = walk(dir.path(), &ResourceLimits::default(), &no_stop);
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.skipped.len(), 2);
        let descriptions: Vec<String> = result.skipped.iter().map(|s| s.describe()).collect();
        assert!(descriptions
            .iter()
            .any(|d| d.contains("link.txt") && d.contains("real.txt")));
        assert!(descriptions.iter().any(|d| d.contains("outside.txt")));
    }

    #[test]
    fn walk_respects_stop_check() {
        let dir = tempfile::tempdir().unwrap();
        setup_tree(dir.path());
        let stopped = std::cell::Cell::new(false);
        let result = walk(dir.path(), &ResourceLimits::default(), &|| {
            if stopped.get() {
                Some(StopReason::Cancelled)
            } else {
                stopped.set(true);
                None
            }
        });
        assert_eq!(result.stop_reason, Some(StopReason::Cancelled));
        assert!(result.truncated);
    }
}
