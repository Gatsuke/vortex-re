//! Target validation and path confinement.
//!
//! Inspection roots are the *only* places analysis is allowed to touch.
//! Module resolution and any derived path must stay inside the root; escapes
//! are rejected with [`ErrorCode::PathOutsideRoot`] instead of being followed.

use crate::error::{ErrorCode, VortexError, VortexResult};
use serde::Serialize;
use std::path::{Component, Path, PathBuf};

/// Whether a validated target is a single file or a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// A single regular file.
    File,
    /// A directory tree.
    Directory,
}

impl TargetKind {
    /// Stable string form used in JSON output.
    pub const fn as_str(self) -> &'static str {
        match self {
            TargetKind::File => "file",
            TargetKind::Directory => "directory",
        }
    }
}

/// A validated inspection target.
#[derive(Debug, Clone, Serialize)]
pub struct TargetInfo {
    /// Path exactly as provided by the caller.
    pub input: PathBuf,
    /// Canonical absolute path.
    pub canonical: PathBuf,
    /// File or directory.
    pub kind: TargetKind,
    /// Size in bytes (single file size, or total for directories when known).
    pub size: u64,
}

/// Validate a user-supplied target path.
///
/// Accepts only existing regular files and directories (symlinks to them are
/// resolved through canonicalization). FIFOs, sockets, and devices are
/// rejected with an actionable error because they are unsupported inputs.
pub fn validate_target(path: &Path) -> VortexResult<TargetInfo> {
    if path.as_os_str().is_empty() {
        return Err(VortexError::validation("target path is empty")
            .with_hint("provide an existing file or directory path"));
    }
    let metadata = std::fs::metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            VortexError::not_found(path.display().to_string())
        } else {
            VortexError::new(
                ErrorCode::Io,
                format!("cannot stat {}: {err}", path.display()),
            )
        }
    })?;
    let kind = if metadata.is_dir() {
        TargetKind::Directory
    } else if metadata.is_file() {
        TargetKind::File
    } else {
        return Err(VortexError::new(
            ErrorCode::NotFileOrDir,
            format!(
                "target is not a regular file or directory: {}",
                path.display()
            ),
        )
        .with_hint("FIFOs, sockets, and devices are unsupported inspection targets"));
    };
    let canonical = std::fs::canonicalize(path).map_err(|err| {
        VortexError::new(
            ErrorCode::Io,
            format!("cannot canonicalize {}: {err}", path.display()),
        )
    })?;
    Ok(TargetInfo {
        input: path.to_path_buf(),
        canonical,
        kind,
        size: metadata.len(),
    })
}

/// True when `path` equals or lies below `root` (both must be canonical
/// or at least consistently normalized).
pub fn is_within(root: &Path, path: &Path) -> bool {
    path.starts_with(root)
}

/// Lexically normalize a relative path, resolving `.` and `..` components
/// without touching the filesystem.
///
/// Returns `None` when normalization would escape upward past the start
/// (for example `../escape`).
pub fn normalize_relative(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(normalized)
}

/// Join a relative specifier onto a base directory, normalize it, and ensure
/// the result stays inside `root`.
///
/// This is the guard used for JavaScript import resolution and source map
/// references. Absolute specifiers and upward escapes are rejected.
pub fn resolve_within(root: &Path, base_dir: &Path, relative: &Path) -> VortexResult<PathBuf> {
    if relative.is_absolute() {
        return Err(VortexError::path_outside_root(format!(
            "absolute specifier '{}' is outside the inspection root",
            relative.display()
        )));
    }
    let joined = base_dir.join(relative);
    // Normalize relative to the root so the result stays comparable.
    let rel_from_root = joined
        .strip_prefix(root)
        .map_err(|_| {
            VortexError::path_outside_root(format!(
                "base directory {} is not inside root {}",
                base_dir.display(),
                root.display()
            ))
        })?
        .to_path_buf();
    let normalized = normalize_relative(&rel_from_root).ok_or_else(|| {
        VortexError::path_outside_root(format!(
            "specifier '{}' escapes the inspection root",
            relative.display()
        ))
    })?;
    Ok(root.join(normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_is_rejected() {
        let err = validate_target(Path::new("")).unwrap_err();
        assert_eq!(err.code, ErrorCode::Validation);
    }

    #[test]
    fn missing_path_is_not_found() {
        let err = validate_target(Path::new("/definitely/not/here/vortex")).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(err.hint.is_some());
    }

    #[test]
    fn normalization_resolves_dots() {
        assert_eq!(
            normalize_relative(Path::new("a/./b/../c")).unwrap(),
            PathBuf::from("a/c")
        );
        assert!(normalize_relative(Path::new("../escape")).is_none());
        assert!(normalize_relative(Path::new("a/b/../../../escape")).is_none());
        assert_eq!(normalize_relative(Path::new("./")).unwrap(), PathBuf::new());
    }

    #[test]
    fn resolve_within_keeps_specifiers_inside_root() {
        let root = Path::new("/tmp/vroot");
        let base = root.join("src/lib");
        let ok = resolve_within(root, &base, Path::new("../config.js")).unwrap();
        assert_eq!(ok, root.join("src/config.js"));

        let escaped = resolve_within(root, &base, Path::new("../../../../etc/passwd")).unwrap_err();
        assert_eq!(escaped.code, ErrorCode::PathOutsideRoot);

        let absolute = resolve_within(root, &base, Path::new("/etc/passwd")).unwrap_err();
        assert_eq!(absolute.code, ErrorCode::PathOutsideRoot);
    }

    #[test]
    fn is_within_prefix_check() {
        let root = Path::new("/data/app");
        assert!(is_within(root, Path::new("/data/app/src/a.js")));
        assert!(is_within(root, root));
        assert!(!is_within(root, Path::new("/data/application")));
    }
}
