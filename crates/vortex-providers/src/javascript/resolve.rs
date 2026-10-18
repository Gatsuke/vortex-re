//! JavaScript module specifier classification and resolution.
//!
//! Resolution implements the CommonJS lookup subset: exact path, then `.js`,
//! then `.json`, then, for directories, `package.json` `main` and `index.js`.
//! Bare specifiers are additionally probed against `node_modules` directories
//! walking up from the referring file (Node-style), with `package.json` `main`
//! honored inside those packages. Package `exports`/`imports` maps and TS
//! path aliases are out of scope and documented as limitations.

use std::path::{Path, PathBuf};
use vortex_core::error::VortexError;
use vortex_core::paths::normalize_relative;

use super::manifest::parse_manifest;

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
            let normalized = normalize_relative(&joined).ok_or_else(|| {
                VortexError::path_outside_root(format!(
                    "specifier '{specifier}' (from {}) escapes the inspection root",
                    from_rel.display()
                ))
            })?;
            let target = root.join(&normalized);
            if let Some(rel) = resolve_node_style(root, &normalized, &target) {
                return Ok(Resolution {
                    kind: SpecifierKind::Relative,
                    resolved_path: Some(rel.replace('\\', "/")),
                    note: None,
                });
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

/// Node-style `LOAD_AS_FILE` probes for a target: exact, `+.js`, `+.json`.
/// (Appending, not replacing: `./my.file` probes `my.file.js`, not `my.js`.)
fn file_candidates(target: &Path) -> Vec<PathBuf> {
    let mut with_js = target.as_os_str().to_os_string();
    with_js.push(".js");
    let mut with_json = target.as_os_str().to_os_string();
    with_json.push(".json");
    vec![
        target.to_path_buf(),
        PathBuf::from(with_js),
        PathBuf::from(with_json),
    ]
}

/// Resolve a target the way Node's resolver would: file candidates first,
/// then, when the target is a directory, its `package.json` `main` entry
/// (if it stays inside the root) and finally `index.js`.
fn resolve_node_style(root: &Path, normalized: &Path, target: &Path) -> Option<String> {
    for candidate in &file_candidates(target) {
        if candidate.is_file() {
            return Some(relative_display(root, candidate, normalized));
        }
    }
    if target.is_dir() {
        if let Some(hit) = resolve_directory_entry(root, normalized, target) {
            return Some(hit);
        }
    }
    None
}

/// Directory resolution: `package.json` `main` first, then `index.js`.
/// A `main` that escapes the root is ignored (the entry cannot be verified
/// as part of the inspected artifact).
fn resolve_directory_entry(root: &Path, dir_rel: &Path, dir: &Path) -> Option<String> {
    if let Ok(bytes) = std::fs::read(dir.join("package.json")) {
        let manifest = parse_manifest("package.json", &bytes, "");
        if let Some(main) = manifest.main.as_deref().filter(|m| !m.is_empty()) {
            if let Some(main_norm) = normalize_relative(&dir_rel.join(main)) {
                let main_target = root.join(&main_norm);
                for candidate in &file_candidates(&main_target) {
                    if candidate.is_file() {
                        return Some(relative_display(root, candidate, &main_norm));
                    }
                }
                if main_target.is_dir() {
                    let index = main_target.join("index.js");
                    if index.is_file() {
                        return Some(relative_display(root, &index, &main_norm));
                    }
                }
            }
            // A missing/escaping main falls back to index.js, mirroring the
            // useful part of Node's legacy behavior; the note records what
            // was tried.
        }
    }
    let index = dir.join("index.js");
    if index.is_file() {
        return Some(relative_display(root, &index, dir_rel));
    }
    None
}

/// Split a bare specifier into package name and optional subpath.
/// `@scope/pkg/sub` -> (`@scope/pkg`, `sub`); `minimist/x` -> (`minimist`, `x`).
/// A lone `@scope` is itself treated as a package name: real Node resolves
/// `require('@scope')` through `node_modules/@scope/` directory lookup.
fn split_package_and_subpath(specifier: &str) -> Option<(String, Option<String>)> {
    if specifier.starts_with('@') {
        let mut parts = specifier.splitn(3, '/');
        let scope = parts.next()?;
        let package = match parts.next() {
            Some(package) => package,
            // Lone `@scope`: the whole specifier is the package name.
            None => return Some((specifier.to_string(), None)),
        };
        if package.is_empty() {
            return None;
        }
        Some((
            format!("{scope}/{package}"),
            parts.next().map(str::to_string),
        ))
    } else {
        let mut parts = specifier.splitn(2, '/');
        let package = parts.next()?;
        if package.is_empty() {
            return None;
        }
        Some((package.to_string(), parts.next().map(str::to_string)))
    }
}

/// Resolve a bare specifier through `node_modules` directories, walking up
/// from the referring file's directory to the inspection root (Node-style
/// lookup, static paths only). Returns the root-relative resolved path.
///
/// Package `exports` maps are not evaluated (documented limitation); a
/// subpath that would escape the root is not resolved at all.
pub fn resolve_bare_in_node_modules(
    root: &Path,
    from_rel: &Path,
    specifier: &str,
) -> Option<String> {
    let (name, subpath) = split_package_and_subpath(specifier)?;
    let mut dir = from_rel.parent().unwrap_or(Path::new("")).to_path_buf();
    loop {
        let joined = if let Some(sub) = &subpath {
            dir.join("node_modules").join(&name).join(sub)
        } else {
            dir.join("node_modules").join(&name)
        };
        if let Some(normalized) = normalize_relative(&joined) {
            let target = root.join(&normalized);
            if let Some(hit) = resolve_node_style(root, &normalized, &target) {
                return Some(hit.replace('\\', "/"));
            }
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

fn relative_display(root: &Path, absolute: &Path, fallback: &Path) -> String {
    absolute
        .strip_prefix(root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| fallback.display().to_string())
}

fn candidate_names(normalized: &Path) -> String {
    let base = normalized.display().to_string();
    format!("{base}, {base}.js, {base}.json, {base}/index.js, {base}/package.json main")
}

/// Resolve a reference that *reference semantics* (not module semantics)
/// treat as relative to the referring file: `sourceMappingURL=` comments and
/// HTML `src` attributes. Unlike module specifiers, a bare-looking name like
/// `bundle.js.map` is relative to the file's directory, not a package name.
///
/// URLs, `data:` URIs, and absolute paths stay external. Local candidates
/// are treated as URLs: the query and fragment are dropped and the path is
/// percent-decoded once before resolution, so `app%20part.js.map?v=1#s`
/// resolves to the file `app part.js.map`. The declared reference itself is
/// preserved verbatim by the caller's evidence.
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
            let local = percent_decode_once(strip_query_and_fragment(reference));
            if local.is_empty() {
                return Ok(Resolution {
                    kind: SpecifierKind::Bare,
                    resolved_path: None,
                    note: Some(
                        "reference is empty after removing the URL query and fragment".to_string(),
                    ),
                });
            }
            let spec = if local.starts_with("./") || local.starts_with("../") {
                local
            } else {
                format!("./{local}")
            };
            let mut resolution = resolve_specifier(root, from_rel, &spec)?;
            // Keep the caller-facing kind tied to the original reference, not
            // to the decoded form used for local probing.
            resolution.kind = classify_specifier(reference);
            Ok(resolution)
        }
    }
}

/// Cut a URL at the first `?` or `#` (query/fragment are not file-name
/// material for local resolution).
fn strip_query_and_fragment(reference: &str) -> &str {
    let mut end = reference.len();
    if let Some(position) = reference.find('?') {
        end = end.min(position);
    }
    if let Some(position) = reference.find('#') {
        end = end.min(position);
    }
    &reference[..end]
}

/// Percent-decode a string exactly once (`%2520` -> `%20`, not a space).
/// Invalid escapes are kept verbatim; decoded invalid UTF-8 is replaced
/// lossily. `+` is not treated as a space (path components, not queries).
fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if index + 2 < bytes.len()
            && bytes[index] == b'%'
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            let high = (bytes[index + 1] as char).to_digit(16).unwrap_or(0);
            let low = (bytes[index + 2] as char).to_digit(16).unwrap_or(0);
            out.push((high * 16 + low) as u8);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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

    // ---- cases derived from upstream (REA) failure reports ----

    fn write(root: &Path, rel: &str, bytes: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    /// REA #3896: `require("./pkg")` must honor `pkg/package.json` `main`
    /// when no `index.js` exists.
    #[test]
    fn directory_main_is_honored_when_no_index_exists() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "main.cjs", b"require('./pkg');");
        write(root, "pkg/package.json", br#"{"main":"actual.js"}"#);
        write(root, "pkg/actual.js", b"module.exports = 1;");
        let resolution = resolve_specifier(root, Path::new("main.cjs"), "./pkg").unwrap();
        assert_eq!(resolution.resolved_path.as_deref(), Some("pkg/actual.js"));
    }

    /// REA #3895: a sibling file beats a directory index (`dep.js` over
    /// `dep/index.js`), matching Node's file-before-directory order.
    #[test]
    fn file_beats_directory_index() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "main.cjs", b"require('./dep');");
        write(root, "dep.js", b"module.exports = 'file';");
        write(root, "dep/index.js", b"module.exports = 'index';");
        let resolution = resolve_specifier(root, Path::new("main.cjs"), "./dep").unwrap();
        assert_eq!(resolution.resolved_path.as_deref(), Some("dep.js"));
    }

    /// A `main` that escapes the root is ignored; the directory still
    /// resolves through `index.js`, and nothing outside the root is read.
    #[test]
    fn escaping_main_falls_back_to_index() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "main.cjs", b"require('./pkg');");
        write(root, "pkg/package.json", br#"{"main":"../../outside.js"}"#);
        write(root, "pkg/index.js", b"module.exports = 1;");
        let resolution = resolve_specifier(root, Path::new("main.cjs"), "./pkg").unwrap();
        assert_eq!(resolution.resolved_path.as_deref(), Some("pkg/index.js"));
    }

    /// REA #1782: percent-encoded local source-map URLs must resolve to the
    /// decoded local filename, and query/fragment suffixes are dropped.
    #[test]
    fn percent_encoded_reference_resolves_with_query_and_fragment() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "app.js", b"export const value = 1;\n");
        write(root, "app part.js.map", b"{}");
        let resolution =
            resolve_relative_reference(root, Path::new("app.js"), "app%20part.js.map?v=1#section")
                .unwrap();
        assert_eq!(resolution.resolved_path.as_deref(), Some("app part.js.map"));
    }

    /// REA #1782 control: `%2520` names a file whose name literally contains
    /// `%20` — decode exactly once, never twice.
    #[test]
    fn double_encoded_reference_stays_literal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "app.js", b"export const value = 1;\n");
        write(root, "app%20part.js.map", b"{}");
        let resolution =
            resolve_relative_reference(root, Path::new("app.js"), "app%2520part.js.map").unwrap();
        assert_eq!(
            resolution.resolved_path.as_deref(),
            Some("app%20part.js.map")
        );
    }

    /// REA #4632: `require("@scope")` resolves to
    /// `node_modules/@scope/index.js` when present.
    #[test]
    fn bare_scope_directory_resolves_through_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "main.cjs", b"require('@scope');");
        write(root, "node_modules/@scope/index.js", b"module.exports = 1;");
        let hit = resolve_bare_in_node_modules(root, Path::new("main.cjs"), "@scope");
        assert_eq!(hit.as_deref(), Some("node_modules/@scope/index.js"));
    }

    /// `package.json` `main` is honored inside `node_modules` packages.
    #[test]
    fn bare_package_main_is_honored() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "main.cjs", b"require('ordinary');");
        write(
            root,
            "node_modules/ordinary/package.json",
            br#"{"main":"entry.js"}"#,
        );
        write(
            root,
            "node_modules/ordinary/entry.js",
            b"module.exports = 1;",
        );
        let hit = resolve_bare_in_node_modules(root, Path::new("main.cjs"), "ordinary");
        assert_eq!(hit.as_deref(), Some("node_modules/ordinary/entry.js"));
    }

    /// Subpath bare specifiers resolve inside the package.
    #[test]
    fn bare_subpath_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "main.cjs", b"require('@scope/pkg/lib/helper');");
        write(
            root,
            "node_modules/@scope/pkg/lib/helper.js",
            b"module.exports = 1;",
        );
        let hit =
            resolve_bare_in_node_modules(root, Path::new("main.cjs"), "@scope/pkg/lib/helper");
        assert_eq!(
            hit.as_deref(),
            Some("node_modules/@scope/pkg/lib/helper.js")
        );
    }

    /// The lookup walks up from the referring file's directory, Node-style.
    #[test]
    fn bare_lookup_walks_up_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "src/deep/main.cjs", b"require('ordinary');");
        write(
            root,
            "node_modules/ordinary/index.js",
            b"module.exports = 1;",
        );
        let hit = resolve_bare_in_node_modules(root, Path::new("src/deep/main.cjs"), "ordinary");
        assert_eq!(hit.as_deref(), Some("node_modules/ordinary/index.js"));
    }

    /// A nearer `node_modules` shadows the root one.
    #[test]
    fn nearer_node_modules_wins() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "src/main.cjs", b"require('ordinary');");
        write(
            root,
            "node_modules/ordinary/index.js",
            b"module.exports = 1;",
        );
        write(
            root,
            "src/node_modules/ordinary/index.js",
            b"module.exports = 2;",
        );
        let hit = resolve_bare_in_node_modules(root, Path::new("src/main.cjs"), "ordinary");
        assert_eq!(hit.as_deref(), Some("src/node_modules/ordinary/index.js"));
    }

    /// A subpath that would escape the root is never resolved.
    #[test]
    fn escaping_bare_subpath_is_not_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "main.cjs", b"require('pkg/../../etc/passwd');");
        let hit = resolve_bare_in_node_modules(root, Path::new("main.cjs"), "pkg/../../etc/passwd");
        assert!(hit.is_none());
    }

    /// Unknown bare specifiers stay unresolved.
    #[test]
    fn missing_bare_specifier_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "main.cjs", b"require('nope');");
        let hit = resolve_bare_in_node_modules(root, Path::new("main.cjs"), "nope");
        assert!(hit.is_none());
    }

    #[test]
    fn percent_decode_once_unit_checks() {
        assert_eq!(percent_decode_once("app%20part.js.map"), "app part.js.map");
        assert_eq!(
            percent_decode_once("app%2520part.js.map"),
            "app%20part.js.map"
        );
        assert_eq!(percent_decode_once("plain.js"), "plain.js");
        assert_eq!(percent_decode_once("bad%2"), "bad%2");
        assert_eq!(percent_decode_once("bad%ZZ"), "bad%ZZ");
        assert_eq!(percent_decode_once("a+b.js"), "a+b.js");
    }

    #[test]
    fn query_and_fragment_are_stripped() {
        assert_eq!(strip_query_and_fragment("a.js.map?v=1#s"), "a.js.map");
        assert_eq!(strip_query_and_fragment("a.js.map#frag"), "a.js.map");
        assert_eq!(strip_query_and_fragment("a.js.map"), "a.js.map");
    }
}
