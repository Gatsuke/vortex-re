//! JavaScript module specifier classification and resolution.
//!
//! Resolution implements the CommonJS lookup subset: exact path, then `.js`,
//! then `.json`, then `index.js` for directories. Package "exports" maps and
//! TS path aliases are out of scope and documented as limitations.

use std::path::{Path, PathBuf};
use vortex_core::error::VortexError;

/// Node.js builtin modules recognized without a `node_modules` lookup.
pub const NODE_BUILTINS: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

/// How a specifier classifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecifierKind {
    /// `./x` or `../x` — resolvable inside the artifact.
    Relative,
    /// A bare package name like `minimist` or `@scope/pkg`.
    Bare,
    /// `/abs/path` — outside the inspection root by definition.
    Absolute,
    /// A URL like `https://...`.
    Url,
    /// A `data:` URI.
    DataUri,
    /// A subpath-imports specifier like `#internal`.
    Prefixed,
}

impl SpecifierKind {
    /// Stable identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            SpecifierKind::Relative => "relative",
            SpecifierKind::Bare => "bare",
            SpecifierKind::Absolute => "absolute",
            SpecifierKind::Url => "url",
            SpecifierKind::DataUri => "data_uri",
            SpecifierKind::Prefixed => "prefixed",
        }
    }
}

/// Whether a bare specifier names a Node.js builtin module.
pub fn is_node_builtin(specifier: &str) -> bool {
    let name = specifier.strip_prefix("node:").unwrap_or(specifier);
    // Strip subpaths like "fs/promises" for the builtin check.
    let base = name.split('/').next().unwrap_or(name);
    NODE_BUILTINS.contains(&base)
}

/// Classify a raw specifier string.
pub fn classify_specifier(specifier: &str) -> SpecifierKind {
    if specifier.starts_with("data:") {
        SpecifierKind::DataUri
    } else if specifier.starts_with("http://")
        || specifier.starts_with("https://")
        || specifier.starts_with("file://")
    {
        SpecifierKind::Url
    } else if specifier.starts_with("./")
        || specifier.starts_with("../")
        || specifier == "."
        || specifier == ".."
    {
        SpecifierKind::Relative
    } else if specifier.starts_with('#') {
        SpecifierKind::Prefixed
    } else if specifier.starts_with('/') {
        SpecifierKind::Absolute
    } else {
        SpecifierKind::Bare
    }
}

/// The outcome of resolving a specifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The classified kind.
    pub kind: SpecifierKind,
    /// Resolved path relative to the inspection root, when found.
    pub resolved_path: Option<String>,
    /// Explanation for unresolved or special outcomes.
    pub note: Option<String>,
}

/// Resolve `specifier` as written in `from_rel` (a path relative to `root`).
///
/// Only relative specifiers are resolved against the filesystem. Escapes
/// outside the root return a `PathOutsideRoot` error, which callers convert
/// into an unresolved relationship with that reason.
pub fn resolve_specifier(
    root: &Path,
    from_rel: &Path,
    specifier: &str,
) -> Result<Resolution, VortexError> {
    match classify_specifier(specifier) {
        SpecifierKind::Relative => {
            let from_dir = from_rel.parent().unwrap_or(Path::new(""));
            let joined = if from_dir.as_os_str().is_empty() {
                PathBuf::from(specifier)
            } else {
                from_dir.join(specifier)
            };
            // Normalize lexically; reject escapes.
            let normalized = vortex_core::paths::normalize_relative(&joined).ok_or_else(|| {
                VortexError::path_outside_root(format!(
                    "specifier '{specifier}' (from {}) escapes the inspection root",
                    from_rel.display()
                ))
            })?;
            let target = root.join(&normalized);
            let candidates = resolution_candidates(&target);
            for candidate in &candidates {
                if candidate.is_file() {
                    let rel = candidate
                        .strip_prefix(root)
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| normalized.display().to_string());
                    return Ok(Resolution {
                        kind: SpecifierKind::Relative,
                        resolved_path: Some(rel.replace('\\', "/")),
                        note: None,
                    });
                }
            }
            Ok(Resolution {
                kind: SpecifierKind::Relative,
                resolved_path: None,
                note: Some(format!(
                    "no local file matched '{}' (tried: {})",
                    specifier,
                    candidate_names(&normalized)
                )),
            })
        }
        kind => Ok(Resolution {
            kind,
            resolved_path: None,
            note: None,
        }),
    }
}

fn resolution_candidates(target: &Path) -> Vec<PathBuf> {
    // Node-style lookup: exact, then append .js / .json, then directory index.
    // (Appending, not replacing: `./my.file` probes `my.file.js`, not `my.js`.)
    let mut with_js = target.as_os_str().to_os_string();
    with_js.push(".js");
    let mut with_json = target.as_os_str().to_os_string();
    with_json.push(".json");
    vec![
        target.to_path_buf(),
        PathBuf::from(with_js),
        PathBuf::from(with_json),
        target.join("index.js"),
    ]
}

fn candidate_names(normalized: &Path) -> String {
    let base = normalized.display().to_string();
    format!("{base}, {base}.js, {base}.json, {base}/index.js")
}

/// Resolve a reference that *reference semantics* (not module semantics)
/// treat as relative to the referring file: `sourceMappingURL=` comments and
/// HTML `src` attributes. Unlike module specifiers, a bare-looking name like
/// `bundle.js.map` is relative to the file's directory, not a package name.
///
/// URLs, `data:` URIs, and absolute paths stay external.
pub fn resolve_relative_reference(
    root: &Path,
    from_rel: &Path,
    reference: &str,
) -> Result<Resolution, VortexError> {
    match classify_specifier(reference) {
        kind @ (SpecifierKind::Url | SpecifierKind::DataUri | SpecifierKind::Absolute) => {
            Ok(Resolution {
                kind,
                resolved_path: None,
                note: None,
            })
        }
        SpecifierKind::Relative | SpecifierKind::Bare | SpecifierKind::Prefixed => {
            let spec = if reference.starts_with("./") || reference.starts_with("../") {
                reference.to_string()
            } else {
                format!("./{reference}")
            };
            resolve_specifier(root, from_rel, &spec)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vortex_core::error::ErrorCode;

    fn setup() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src/lib")).unwrap();
        std::fs::write(
            dir.path().join("src/lib/config.js"),
            b"module.exports = {};",
        )
        .unwrap();
        std::fs::write(dir.path().join("src/lib/defaults.json"), b"{}").unwrap();
        std::fs::create_dir_all(dir.path().join("src/lib/widgets")).unwrap();
        std::fs::write(dir.path().join("src/lib/widgets/index.js"), b"").unwrap();
        dir
    }

    #[test]
    fn classification() {
        assert_eq!(classify_specifier("./x"), SpecifierKind::Relative);
        assert_eq!(classify_specifier("../y"), SpecifierKind::Relative);
        assert_eq!(classify_specifier("minimist"), SpecifierKind::Bare);
        assert_eq!(classify_specifier("@scope/pkg/sub"), SpecifierKind::Bare);
        assert_eq!(classify_specifier("/etc/passwd"), SpecifierKind::Absolute);
        assert_eq!(
            classify_specifier("https://example.invalid/x"),
            SpecifierKind::Url
        );
        assert_eq!(
            classify_specifier("data:application/json,{}"),
            SpecifierKind::DataUri
        );
        assert_eq!(classify_specifier("#internal"), SpecifierKind::Prefixed);
    }

    #[test]
    fn builtins_are_recognized() {
        assert!(is_node_builtin("fs"));
        assert!(is_node_builtin("node:fs/promises"));
        assert!(!is_node_builtin("minimist"));
        assert!(!is_node_builtin("my-fs"));
    }

    #[test]
    fn relative_resolution_with_extension_variants() {
        let dir = setup();
        let root = dir.path();
        // Exact file.
        let exact = resolve_specifier(root, Path::new("src/main.js"), "./lib/config.js").unwrap();
        assert_eq!(exact.resolved_path.as_deref(), Some("src/lib/config.js"));
        // Extensionless .js lookup.
        let extless = resolve_specifier(root, Path::new("src/main.js"), "./lib/config").unwrap();
        assert_eq!(extless.resolved_path.as_deref(), Some("src/lib/config.js"));
        // .json lookup.
        let json = resolve_specifier(root, Path::new("src/lib/config.js"), "./defaults").unwrap();
        assert_eq!(json.resolved_path.as_deref(), Some("src/lib/defaults.json"));
        // Directory index.js.
        let index = resolve_specifier(root, Path::new("src/main.js"), "./lib/widgets").unwrap();
        assert_eq!(
            index.resolved_path.as_deref(),
            Some("src/lib/widgets/index.js")
        );
    }

    #[test]
    fn missing_relative_is_unresolved_with_note() {
        let dir = setup();
        let resolution =
            resolve_specifier(dir.path(), Path::new("src/main.js"), "./missing.js").unwrap();
        assert!(resolution.resolved_path.is_none());
        assert!(resolution
            .note
            .as_deref()
            .unwrap()
            .contains("no local file matched"));
    }

    #[test]
    fn relative_reference_semantics_for_comments_and_html() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("dist")).unwrap();
        std::fs::write(dir.path().join("dist/bundle.js.map"), b"{}").unwrap();
        let root = dir.path();

        // Bare-looking sourcemap name resolves next to the referring file.
        let resolved =
            resolve_relative_reference(root, Path::new("dist/bundle.js"), "bundle.js.map").unwrap();
        assert_eq!(
            resolved.resolved_path.as_deref(),
            Some("dist/bundle.js.map")
        );

        // Explicitly relative works the same way.
        let resolved =
            resolve_relative_reference(root, Path::new("dist/bundle.js"), "./bundle.js.map")
                .unwrap();
        assert_eq!(
            resolved.resolved_path.as_deref(),
            Some("dist/bundle.js.map")
        );

        // Missing targets stay unresolved.
        let missing =
            resolve_relative_reference(root, Path::new("src/main.js"), "main.js.map").unwrap();
        assert!(missing.resolved_path.is_none());

        // URLs stay external.
        let url = resolve_relative_reference(
            root,
            Path::new("src/main.js"),
            "https://cdn.example.invalid/app.js.map",
        )
        .unwrap();
        assert!(url.resolved_path.is_none());
    }

    #[test]
    fn escapes_are_rejected_as_path_outside_root() {
        let dir = setup();
        let err = resolve_specifier(dir.path(), Path::new("src/main.js"), "../../outside.js")
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PathOutsideRoot);
    }
}
