//! Line-oriented scanning for imports, requires, source maps, and scripts.
//!
//! Supported statement shapes (all verified by tests in this module):
//! * `import x from './y.js'`
//! * `import { a, b } from "./y"`
//! * `import './side-effect'`
//! * `import x, { y } from './z'`
//! * `export { a } from './y'`
//! * `} from './y'` (continuation of a multi-line import/export)
//! * `const x = require('./y')` and bare `require('./y')`
//! * dynamic `import('./y')`
//! * `//# sourceMappingURL=...` / `//@ sourceMappingURL=...`
//! * `<script src="...">` in HTML

/// How an import-like reference was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportSyntax {
    /// Static `import ... from '...'` / `import '...'`.
    Import,
    /// `export ... from '...'`.
    ExportFrom,
    /// CommonJS `require('...')`.
    Require,
    /// Dynamic `import('...')`.
    DynamicImport,
}

impl ImportSyntax {
    /// Stable identifier used in relationship kinds.
    pub const fn as_str(self) -> &'static str {
        match self {
            ImportSyntax::Import => "imports",
            ImportSyntax::ExportFrom => "exports_from",
            ImportSyntax::Require => "requires",
            ImportSyntax::DynamicImport => "dynamic_import",
        }
    }
}

/// An observed import-like reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRef {
    /// The statement syntax used.
    pub syntax: ImportSyntax,
    /// The raw specifier string (for example `./lib/config.js`).
    pub specifier: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based byte column of the opening quote.
    pub column: u32,
}

/// A source map reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMapRef {
    /// The referenced URL or `data:` URI.
    pub url: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based byte column of the URL start.
    pub column: u32,
    /// Whether the reference is an inline `data:` URI.
    pub inline: bool,
}

/// An HTML `<script src="...">` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptRef {
    /// The `src` value.
    pub src: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based byte column of the opening quote.
    pub column: u32,
}

/// Observed module system signals in a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleSystem {
    /// `require(...)` / `module.exports` observed.
    CommonJs,
    /// `import` / `export` statements observed.
    EsModule,
}

impl ModuleSystem {
    /// Stable identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            ModuleSystem::CommonJs => "commonjs",
            ModuleSystem::EsModule => "esm",
        }
    }
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

/// True when `pos` starts a standalone occurrence of `word` (identifier
/// boundaries on both sides).
fn word_boundary(line: &str, pos: usize, word: &str) -> bool {
    let bytes = line.as_bytes();
    if pos > 0 && is_ident_byte(bytes[pos - 1]) {
        return false;
    }
    let end = pos + word.len();
    if end < bytes.len() && is_ident_byte(bytes[end]) {
        // `requireX(` is not `require(`.
        return false;
    }
    true
}

/// Parse a quoted string starting at `quote_index` (must point at the quote).
///
/// Handles `\\` escapes minimally: the escaped character is kept literally.
fn parse_quoted(line: &str, quote_index: usize) -> Option<(String, usize)> {
    let bytes = line.as_bytes();
    let quote = bytes[quote_index];
    let mut value = String::new();
    let mut index = quote_index + 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' && index + 1 < bytes.len() {
            value.push(bytes[index + 1] as char);
            index += 2;
            continue;
        }
        if byte == quote {
            return Some((value, index));
        }
        value.push(byte as char);
        index += 1;
    }
    None // unterminated string
}

/// All quoted string literals on a line with their 1-based columns.
fn quoted_strings(line: &str) -> Vec<(String, u32)> {
    let mut found = Vec::new();
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\'' || byte == b'"' {
            if let Some((value, end)) = parse_quoted(line, index) {
                found.push((value, index as u32 + 1));
                index = end + 1;
                continue;
            }
        }
        index += 1;
    }
    found
}

/// Scan source text for import-like references.
///
/// Returns the references (bounded by `max`) plus whether the bound was hit.
pub fn scan_imports(content: &str, max: usize) -> (Vec<ImportRef>, bool) {
    let mut refs = Vec::new();
    let mut truncated = false;
    for (index, line) in content.lines().enumerate() {
        if refs.len() >= max {
            truncated = true;
            break;
        }
        let line_no = index as u32 + 1;
        let trimmed = line.trim_start();

        // Static import statements (but not import( or import.meta).
        if trimmed.starts_with("import ") || trimmed.starts_with("import'") {
            if let Some((specifier, column)) = quoted_strings(line).last() {
                refs.push(ImportRef {
                    syntax: ImportSyntax::Import,
                    specifier: specifier.clone(),
                    line: line_no,
                    column: *column,
                });
            }
        }

        // export ... from '...'
        if trimmed.starts_with("export ") && line.contains(" from ") {
            if let Some((specifier, column)) = quoted_strings(line).last() {
                refs.push(ImportRef {
                    syntax: ImportSyntax::ExportFrom,
                    specifier: specifier.clone(),
                    line: line_no,
                    column: *column,
                });
            }
        }

        // Continuation lines of multi-line imports: `} from './x'`.
        if (trimmed.starts_with('}') || trimmed.starts_with("* from")) && line.contains(" from ") {
            if let Some((specifier, column)) = quoted_strings(line).last() {
                // Guard: `* from` alone means re-export; `} from` closes a
                // brace list. Both are import-like.
                refs.push(ImportRef {
                    syntax: ImportSyntax::Import,
                    specifier: specifier.clone(),
                    line: line_no,
                    column: *column,
                });
            }
        }

        // require('...') anywhere on the line with identifier boundaries.
        for (position, _) in line.match_indices("require") {
            if !word_boundary(line, position, "require") {
                continue;
            }
            if let Some((specifier, column)) =
                quoted_after_separator(line, position + "require".len(), b'(')
            {
                refs.push(ImportRef {
                    syntax: ImportSyntax::Require,
                    specifier,
                    line: line_no,
                    column,
                });
            }
        }

        // Dynamic import('...').
        for (position, _) in line.match_indices("import") {
            if !word_boundary(line, position, "import") {
                continue;
            }
            if let Some((specifier, column)) =
                quoted_after_separator(line, position + "import".len(), b'(')
            {
                refs.push(ImportRef {
                    syntax: ImportSyntax::DynamicImport,
                    specifier,
                    line: line_no,
                    column,
                });
            }
        }
    }
    (refs, truncated)
}

/// First quoted string after `from_index`, requiring a single separator
/// character (for example `(` for require/import calls) before the quote.
///
/// Requiring the separator prevents `import './x'` from also matching the
/// dynamic-import rule and `require = 'x'` from matching the require rule.
fn quoted_after_separator(line: &str, from_index: usize, separator: u8) -> Option<(String, u32)> {
    let bytes = line.as_bytes();
    let mut index = from_index;
    let mut saw_separator = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b' ' || byte == b'\t' {
            index += 1;
            continue;
        }
        if !saw_separator && byte == separator {
            saw_separator = true;
            index += 1;
            continue;
        }
        if saw_separator && (byte == b'\'' || byte == b'"') {
            return parse_quoted(line, index).map(|(value, _)| (value, index as u32 + 1));
        }
        return None;
    }
    None
}

/// Find `sourceMappingURL=` references.
pub fn scan_source_map_refs(content: &str) -> Vec<SourceMapRef> {
    let mut refs = Vec::new();
    for (index, line) in content.lines().enumerate() {
        for (position, _) in line.match_indices("sourceMappingURL=") {
            let start = position + "sourceMappingURL=".len();
            let rest = line[start..].trim();
            if rest.is_empty() {
                continue;
            }
            refs.push(SourceMapRef {
                url: rest.to_string(),
                line: index as u32 + 1,
                column: start as u32 + 1,
                inline: rest.starts_with("data:"),
            });
        }
    }
    refs
}

/// Find `<script src="...">` references in HTML.
pub fn scan_script_sources(content: &str) -> Vec<ScriptRef> {
    let mut refs = Vec::new();
    for (index, line) in content.lines().enumerate() {
        for (position, _) in line.match_indices("<script") {
            let rest = &line[position..];
            let Some(src_at) = find_attribute(rest, "src") else {
                continue;
            };
            let absolute = position + src_at + "src".len();
            if let Some((value, column)) = quoted_after_separator(line, absolute, b'=') {
                refs.push(ScriptRef {
                    src: value,
                    line: index as u32 + 1,
                    column,
                });
            }
        }
    }
    refs
}

/// Locate the byte offset of an attribute name inside a tag string.
fn find_attribute(tag: &str, attribute: &str) -> Option<usize> {
    let mut search_from = 0;
    while let Some(found) = tag[search_from..].find(attribute) {
        let absolute = search_from + found;
        let before_ok = absolute == 0
            || tag
                .as_bytes()
                .get(absolute - 1)
                .is_some_and(|b| b.is_ascii_whitespace());
        let after = &tag[absolute + attribute.len()..];
        let after_ok = after.starts_with(|c: char| c == '=' || c.is_whitespace());
        if before_ok && after_ok {
            return Some(absolute);
        }
        search_from = absolute + attribute.len();
    }
    None
}

/// Detect observed module system signals.
pub fn detect_module_systems(content: &str) -> Vec<ModuleSystem> {
    let mut systems = Vec::new();
    let has_commonjs = content.contains("require(")
        || content.contains("module.exports")
        || content.contains("exports.");
    let has_esm = content.contains("import ")
        || content.contains("import(")
        || content.contains("export ")
        || content.contains("export{")
        || content.contains("export default");
    if has_commonjs {
        systems.push(ModuleSystem::CommonJs);
    }
    if has_esm {
        systems.push(ModuleSystem::EsModule);
    }
    systems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_imports() {
        let source =
            "import x from './y.js';\nimport { a, b } from \"./z\";\nimport './side-effect';\n";
        let (refs, truncated) = scan_imports(source, 100);
        assert!(!truncated);
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].specifier, "./y.js");
        assert_eq!(refs[0].syntax, ImportSyntax::Import);
        assert_eq!(refs[0].line, 1);
        assert_eq!(refs[1].specifier, "./z");
        assert_eq!(refs[2].specifier, "./side-effect");
    }

    #[test]
    fn require_forms() {
        let source =
            "const fs = require('fs');\nrequire(\"./config\");\nconst x = myrequire('./nope');\n";
        let (refs, _) = scan_imports(source, 100);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].specifier, "fs");
        assert_eq!(refs[0].syntax, ImportSyntax::Require);
        assert_eq!(refs[0].line, 1);
        assert_eq!(refs[1].specifier, "./config");
    }

    #[test]
    fn dynamic_imports() {
        let source = "const mod = import('./lazy.js');\nimportantFunction();\n";
        let (refs, _) = scan_imports(source, 100);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].syntax, ImportSyntax::DynamicImport);
        assert_eq!(refs[0].specifier, "./lazy.js");
    }

    #[test]
    fn export_from_and_multiline_continuation() {
        let source = "export { helper } from './helpers.js';\nimport {\n  one,\n  two,\n} from './multi.js';\n";
        let (refs, _) = scan_imports(source, 100);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].syntax, ImportSyntax::ExportFrom);
        assert_eq!(refs[0].specifier, "./helpers.js");
        assert_eq!(refs[1].syntax, ImportSyntax::Import);
        assert_eq!(refs[1].specifier, "./multi.js");
        assert_eq!(refs[1].line, 5);
    }

    #[test]
    fn import_cap_truncates() {
        let source = "require('./a');\nrequire('./b');\nrequire('./c');\n";
        let (refs, truncated) = scan_imports(source, 2);
        assert_eq!(refs.len(), 2);
        assert!(truncated);
    }

    #[test]
    fn source_map_refs_file_and_inline() {
        let source = "//# sourceMappingURL=bundle.js.map\n//@ sourceMappingURL=data:application/json;base64,AAAA\n";
        let refs = scan_source_map_refs(source);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].url, "bundle.js.map");
        assert!(!refs[0].inline);
        assert_eq!(refs[0].line, 1);
        assert!(refs[1].inline);
        assert!(refs[1].url.starts_with("data:"));
    }

    #[test]
    fn html_script_sources() {
        let source = "<!DOCTYPE html>\n<html><head>\n<script src=\"./renderer.js\"></script>\n<script>inline()</script>\n</head></html>\n";
        let refs = scan_script_sources(source);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].src, "./renderer.js");
        assert_eq!(refs[0].line, 3);
    }

    #[test]
    fn module_system_detection() {
        let cjs = "const x = require('y');\nmodule.exports = x;\n";
        let esm = "import a from 'b';\nexport default a;\n";
        let mixed = "require('c');\nimport d from 'e';\n";
        let none = "console.log('hi');\n";
        assert_eq!(detect_module_systems(cjs), vec![ModuleSystem::CommonJs]);
        assert_eq!(detect_module_systems(esm), vec![ModuleSystem::EsModule]);
        assert_eq!(detect_module_systems(mixed).len(), 2);
        assert!(detect_module_systems(none).is_empty());
    }

    #[test]
    fn escaped_quotes_in_specifiers() {
        let source = "require('./we\\'ird.js');\n";
        let (refs, _) = scan_imports(source, 10);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].specifier, "./we'ird.js");
    }

    #[test]
    fn import_meta_and_comments_are_not_fooled_by_keywords() {
        // import.meta is not an import statement.
        let source = "const dir = import.meta.dir;\n";
        let (refs, _) = scan_imports(source, 10);
        assert!(refs.is_empty());
    }
}
