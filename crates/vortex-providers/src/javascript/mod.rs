//! Line-oriented JavaScript and HTML scanning plus module resolution.
//!
//! The scanner is deliberately simple: it is a documented heuristic over
//! source lines, not a JavaScript parser. Its limitations are reported with
//! every run (comments are not stripped, multi-line import lists are handled
//! only through their `from '...'` continuation lines, and import-assertion
//! attributes are ignored).

pub mod manifest;
pub mod resolve;
pub mod scanner;

pub use manifest::{parse_manifest, DependencyDecl, PackageManifest};
pub use resolve::{
    classify_specifier, is_node_builtin, resolve_relative_reference, resolve_specifier, Resolution,
    SpecifierKind,
};
pub use scanner::{
    detect_module_systems, scan_imports, scan_script_sources, scan_source_map_refs, ImportRef,
    ImportSyntax, ModuleSystem, ScriptRef, SourceMapRef,
};
