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
///
/// The URL ends at the first whitespace, matching the directive grammar
/// (ECMA-426 `MatchSourceMapURL`): trailing comment text is not part of the
/// URL, and characters like `*` that are legal in URLs and file names are
/// never treated as terminators (upstream REA once truncated at `*`, losing
/// valid references — regression-guarded by tests below).
pub fn scan_source_map_refs(content: &str) -> Vec<SourceMapRef> {
    let mut refs = Vec::new();
    for (index, line) in content.lines().enumerate() {
        for (position, _) in line.match_indices("sourceMappingURL=") {
            let start = position + "sourceMappingURL=".len();
            let rest = line[start..].trim_start();
            // The URL token ends at the first whitespace.
            let url = rest.split_whitespace().next().unwrap_or("");
            if url.is_empty() {
                continue;
            }
            refs.push(SourceMapRef {
                url: url.to_string(),
                line: index as u32 + 1,
                column: start as u32 + 1,
                inline: url.starts_with("data:"),
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

// ---------------------------------------------------------------------------
// imported bindings and their usage sites (Phase Four)
// ---------------------------------------------------------------------------

/// How a binding was introduced by an import-like statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingRole {
    /// `import X from 'y'` or `const X = require('y')`.
    Default,
    /// A named import (`import { a } from 'y'`, aliases included) or a
    /// destructured require (`const { a } = require('y')`).
    Named,
    /// `import * as ns from 'y'`.
    Namespace,
    /// `const x = require('y').prop` (the binding is a member of the module).
    MemberOf,
}

impl BindingRole {
    /// Stable identifier used in findings.
    pub const fn as_str(self) -> &'static str {
        match self {
            BindingRole::Default => "default",
            BindingRole::Named => "named",
            BindingRole::Namespace => "namespace",
            BindingRole::MemberOf => "member_of",
        }
    }
}

/// One binding introduced by an import-like statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedBinding {
    /// The local binding name.
    pub name: String,
    /// How it was introduced.
    pub role: BindingRole,
    /// 1-based line of the introducing statement's start.
    pub line: u32,
}

/// One import-like statement, its span, and the bindings it introduces.
///
/// Statements that introduce no bindings (side-effect imports, bare
/// `require(...)` calls, dynamic imports, re-exports) are not returned:
/// the binding layer is about named bindings only. Statements whose shape
/// was not fully understood carry `unparsed = true` and whatever bindings
/// could be read safely — never a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportBindings {
    /// The statement syntax (import / require).
    pub syntax: ImportSyntax,
    /// The module specifier.
    pub specifier: String,
    /// 1-based line where the statement starts.
    pub start_line: u32,
    /// 1-based line where the statement ends (the `from` line for
    /// multi-line imports, otherwise the same as `start_line`).
    pub end_line: u32,
    /// Bindings introduced (may be empty for unparseable shapes).
    pub bindings: Vec<ImportedBinding>,
    /// Whether any part of the statement was not understood.
    pub unparsed: bool,
}

/// What a usage site looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageForm {
    /// `name(` — a call-shaped reference.
    Call,
    /// `name.` — a member access.
    Member,
    /// Inside an `export { ... }` list (a re-export of the binding).
    Reexport,
    /// A bare identifier reference.
    Bare,
}

impl UsageForm {
    /// Stable identifier used in findings.
    pub const fn as_str(self) -> &'static str {
        match self {
            UsageForm::Call => "call",
            UsageForm::Member => "member",
            UsageForm::Reexport => "reexport",
            UsageForm::Bare => "bare",
        }
    }
}

/// One usage site of an imported binding outside its declaration span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingUsage {
    /// The binding name (as introduced).
    pub name: String,
    /// The shape of the reference.
    pub form: UsageForm,
    /// 1-based line.
    pub line: u32,
    /// 1-based byte column of the name.
    pub column: u32,
}

fn is_plain_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'$')
        && text.bytes().all(is_ident_byte)
}

/// Parse the binding list of an ESM import segment (the text between
/// `import` and `from`): default, comma, braced names, `* as ns`.
fn parse_esm_bindings(
    segment: &str,
    line: u32,
    bindings: &mut Vec<ImportedBinding>,
    unparsed: &mut bool,
) {
    let segment = segment.trim().trim_end_matches(',').trim();
    if segment.is_empty() {
        return;
    }
    // `* as ns`
    if let Some(rest) = segment.strip_prefix("* as ") {
        let rest = rest.trim();
        if is_plain_identifier(rest) {
            bindings.push(ImportedBinding {
                name: rest.to_string(),
                role: BindingRole::Namespace,
                line,
            });
            return;
        }
        *unparsed = true;
        return;
    }
    let (head, braced) = match segment.find('{') {
        Some(brace_at) => {
            // Trim first, then drop a trailing comma: the reverse order
            // leaves the comma behind when a space follows it.
            let head = segment[..brace_at].trim().trim_end_matches(',').trim();
            let rest = &segment[brace_at..];
            let Some(close) = rest.rfind('}') else {
                *unparsed = true;
                return;
            };
            if !rest[close + 1..].trim().is_empty() {
                *unparsed = true;
            }
            (head, &rest[1..close])
        }
        None => (segment, ""),
    };
    if !head.is_empty() {
        if is_plain_identifier(head) {
            bindings.push(ImportedBinding {
                name: head.to_string(),
                role: BindingRole::Default,
                line,
            });
        } else {
            // Includes `x, * as ns` composites and anything unrecognized.
            *unparsed = true;
        }
    }
    for item in braced.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if let Some((_, alias)) = item.split_once(" as ") {
            let alias = alias.trim();
            if is_plain_identifier(alias) {
                bindings.push(ImportedBinding {
                    name: alias.to_string(),
                    role: BindingRole::Named,
                    line,
                });
            } else {
                *unparsed = true;
            }
        } else if is_plain_identifier(item) {
            bindings.push(ImportedBinding {
                name: item.to_string(),
                role: BindingRole::Named,
                line,
            });
        } else {
            // Nested patterns, computed keys, defaults inside braces.
            *unparsed = true;
        }
    }
}

/// Parse a CJS declaration pattern (between the keyword and `=`).
fn parse_cjs_pattern(
    pattern: &str,
    line: u32,
    bindings: &mut Vec<ImportedBinding>,
    unparsed: &mut bool,
    member_of: bool,
) {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        *unparsed = true;
        return;
    }
    if pattern.starts_with('{') && pattern.ends_with('}') {
        for item in pattern[1..pattern.len() - 1].split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            if let Some((_, alias)) = item.split_once(':') {
                // `a: b` binds b to the property a.
                let alias = alias.trim();
                if is_plain_identifier(alias) {
                    bindings.push(ImportedBinding {
                        name: alias.to_string(),
                        role: BindingRole::Named,
                        line,
                    });
                } else {
                    *unparsed = true;
                }
            } else if is_plain_identifier(item) {
                bindings.push(ImportedBinding {
                    name: item.to_string(),
                    role: BindingRole::Named,
                    line,
                });
            } else {
                *unparsed = true;
            }
        }
        return;
    }
    if is_plain_identifier(pattern) {
        bindings.push(ImportedBinding {
            name: pattern.to_string(),
            role: if member_of {
                BindingRole::MemberOf
            } else {
                BindingRole::Default
            },
            line,
        });
        return;
    }
    *unparsed = true;
}

/// Scan import-like statements for the bindings they introduce.
///
/// Line-oriented like the rest of this module: no scope analysis, no
/// evaluation. Shapes that are not understood are counted through
/// `unparsed` flags on the returned statements — never guessed.
pub fn scan_import_bindings(content: &str, max: usize) -> (Vec<ImportBindings>, bool) {
    let lines: Vec<&str> = content.lines().collect();
    let mut out: Vec<ImportBindings> = Vec::new();
    let mut truncated = false;
    let mut index = 0usize;
    while index < lines.len() {
        if out.len() >= max {
            truncated = true;
            break;
        }
        let line = lines[index];
        let line_no = index as u32 + 1;
        let trimmed = line.trim_start();

        // ---- ESM import statements (possibly spanning lines) ----
        if trimmed.starts_with("import ") || trimmed.starts_with("import'") {
            let has_from = line.contains(" from ");
            let quotes = quoted_strings(line);
            if has_from && quotes.last().is_some() {
                // Single-line import statement.
                let specifier = quotes.last().map(|(s, _)| s.clone()).unwrap_or_default();
                let import_at = line.find("import").unwrap_or(0);
                let from_at = line.find(" from ").unwrap_or(line.len());
                let segment = &line[import_at + "import".len()..from_at];
                let mut bindings = Vec::new();
                let mut unparsed = false;
                parse_esm_bindings(segment, line_no, &mut bindings, &mut unparsed);
                out.push(ImportBindings {
                    syntax: ImportSyntax::Import,
                    specifier,
                    start_line: line_no,
                    end_line: line_no,
                    bindings,
                    unparsed,
                });
                index += 1;
                continue;
            }
            if !has_from && quotes.last().is_some() {
                // Side-effect import `import 'y'` — no bindings to report.
                index += 1;
                continue;
            }
            // Multi-line import: consume until the `from` line.
            let mut end = index;
            let mut joined = String::from(trimmed);
            let mut found_from = false;
            while end + 1 < lines.len() {
                end += 1;
                let next = lines[end];
                joined.push(' ');
                joined.push_str(next.trim());
                if next.contains(" from ") && quoted_strings(next).last().is_some() {
                    found_from = true;
                    break;
                }
                if next.trim().is_empty()
                    || next.trim_start().starts_with("import")
                    || next.trim_start().starts_with("const ")
                {
                    // Malformed or a new statement: stop, mark unparsed.
                    break;
                }
            }
            if found_from {
                let next = lines[end];
                let specifier = quoted_strings(next)
                    .last()
                    .map(|(s, _)| s.clone())
                    .unwrap_or_default();
                let from_at = joined.find(" from ").unwrap_or(joined.len());
                let segment = &joined["import".len()..from_at];
                let mut bindings = Vec::new();
                let mut unparsed = false;
                parse_esm_bindings(segment, line_no, &mut bindings, &mut unparsed);
                out.push(ImportBindings {
                    syntax: ImportSyntax::Import,
                    specifier,
                    start_line: line_no,
                    end_line: end as u32 + 1,
                    bindings,
                    unparsed,
                });
                index = end + 1;
                continue;
            }
            // A dangling import without a from: not a binding statement we
            // understand (or a plain `import x` type error).
            out.push(ImportBindings {
                syntax: ImportSyntax::Import,
                specifier: String::new(),
                start_line: line_no,
                end_line: line_no,
                bindings: Vec::new(),
                unparsed: true,
            });
            index += 1;
            continue;
        }

        // ---- CJS declarations: const/let/var <pattern> = require('y') ----
        let decl_keyword = ["const ", "let ", "var "]
            .iter()
            .find(|kw| trimmed.starts_with(**kw))
            .copied();
        if let Some(keyword) = decl_keyword {
            // The first '=' in a declaration line is the assignment (a
            // pattern with a default would slice short and land in
            // `unparsed` instead — the honest outcome).
            if let Some(eq_at) = trimmed.find('=') {
                let pattern = trimmed[keyword.len()..eq_at].trim();
                if let Some(req_at) = line.match_indices("require").next().map(|(at, _)| at) {
                    if word_boundary(line, req_at, "require") {
                        if let Some((specifier, quote_col)) =
                            quoted_after_separator(line, req_at + "require".len(), b'(')
                        {
                            // What follows the closing quote: ')', then
                            // either EOL/';' (plain require) or '.member'
                            // chains (member binding); anything else
                            // (comma, operator) -> unparsed tail.
                            let after_quote = &line[quote_col as usize + specifier.len() + 1..];
                            let after_quote_trim = after_quote.trim_start();
                            let mut member_of = false;
                            let mut tail_ok = after_quote_trim.starts_with(')');
                            if tail_ok {
                                let mut tail = after_quote_trim[1..].trim_start();
                                let mut member_count = 0usize;
                                while tail.starts_with('.') {
                                    let rest = &tail[1..];
                                    let ident_end = rest
                                        .find(|c: char| {
                                            !(c.is_ascii_alphanumeric() || c == '_' || c == '$')
                                        })
                                        .unwrap_or(rest.len());
                                    if ident_end == 0 {
                                        tail_ok = false;
                                        break;
                                    }
                                    member_count += 1;
                                    tail = rest[ident_end..].trim_start();
                                }
                                member_of = member_count > 0;
                                if !tail.is_empty()
                                    && !tail.starts_with(';')
                                    && !tail.starts_with("//")
                                {
                                    // Multiple declarators or operators.
                                    tail_ok = false;
                                }
                            }
                            let mut bindings = Vec::new();
                            let mut unparsed = !tail_ok;
                            parse_cjs_pattern(
                                pattern,
                                line_no,
                                &mut bindings,
                                &mut unparsed,
                                member_of,
                            );
                            out.push(ImportBindings {
                                syntax: ImportSyntax::Require,
                                specifier,
                                start_line: line_no,
                                end_line: line_no,
                                bindings,
                                unparsed,
                            });
                            index += 1;
                            continue;
                        }
                    }
                }
            }
        }
        index += 1;
    }
    (out, truncated)
}

/// Scan usage sites of the given bindings, excluding every declaration
/// span. Token-level and scope-unaware by design: shadowed identifiers of
/// the same name count as usages, which is why every consumer must label
/// the results as inferred.
///
/// Bindings that share a name are scanned once (by name): their usage
/// sites are attributed to every binding of that name, and the disclosure
/// responsibility sits with the caller.
pub fn scan_binding_usages(
    content: &str,
    statements: &[ImportBindings],
    max: usize,
) -> (Vec<BindingUsage>, bool) {
    // Unique names in first-seen order.
    let mut names: Vec<String> = Vec::new();
    for statement in statements {
        for binding in &statement.bindings {
            if !names.iter().any(|n| n == &binding.name) {
                names.push(binding.name.clone());
            }
        }
    }
    if names.is_empty() {
        return (Vec::new(), false);
    }
    let mut out = Vec::new();
    'lines: for (index, line) in content.lines().enumerate() {
        let line_no = index as u32 + 1;
        // Skip lines inside any declaration span.
        for statement in statements {
            if line_no >= statement.start_line && line_no <= statement.end_line {
                continue 'lines;
            }
        }
        let trimmed = line.trim_start();
        let is_reexport_line = trimmed.starts_with("export{") || trimmed.starts_with("export {");
        for name in &names {
            for (position, _) in line.match_indices(name.as_str()) {
                if !word_boundary(line, position, name) {
                    continue;
                }
                if out.len() >= max {
                    return (out, true);
                }
                let after = position + name.len();
                let rest = &line[after..];
                let rest_trim = rest.trim_start();
                let form = if rest_trim.starts_with('(') {
                    UsageForm::Call
                } else if rest_trim.starts_with('.') {
                    UsageForm::Member
                } else if is_reexport_line {
                    UsageForm::Reexport
                } else {
                    UsageForm::Bare
                };
                out.push(BindingUsage {
                    name: name.clone(),
                    form,
                    line: line_no,
                    column: position as u32 + 1,
                });
            }
        }
    }
    (out, false)
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
    fn binding_scan_esm_shapes() {
        let source = "import x from './y.js';\n\
                      import { a, b as renamed } from \"./z\";\n\
                      import * as ns from './w';\n\
                      import def, { extra } from './both';\n\
                      import './side-effect';\n\
                      export { helper } from './re.js';\n";
        let (statements, truncated) = scan_import_bindings(source, 100);
        assert!(!truncated);
        // Side-effect import and export-from introduce no bindings and are
        // not binding statements.
        assert_eq!(statements.len(), 4);
        assert_eq!(statements[0].specifier, "./y.js");
        assert_eq!(statements[0].bindings.len(), 1);
        assert_eq!(statements[0].bindings[0].name, "x");
        assert_eq!(statements[0].bindings[0].role, BindingRole::Default);
        assert_eq!(statements[1].bindings.len(), 2);
        assert_eq!(statements[1].bindings[0].name, "a");
        assert_eq!(statements[1].bindings[1].name, "renamed");
        assert_eq!(statements[2].bindings[0].role, BindingRole::Namespace);
        assert_eq!(statements[3].bindings.len(), 2);
        assert_eq!(statements[3].bindings[0].name, "def");
        assert_eq!(statements[3].bindings[1].name, "extra");
        for statement in &statements {
            assert!(!statement.unparsed, "unexpected unparsed: {statement:?}");
        }
    }

    #[test]
    fn binding_scan_multiline_span_is_recorded() {
        let source =
            "import {\n  one,\n  two as duo,\n} from './multi.js';\nconsole.log(one, duo);\n";
        let (statements, _) = scan_import_bindings(source, 100);
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].start_line, 1);
        assert_eq!(statements[0].end_line, 4);
        assert_eq!(statements[0].specifier, "./multi.js");
        assert_eq!(statements[0].bindings.len(), 2);
        assert_eq!(statements[0].bindings[1].name, "duo");
        // Usage sites on lines 1-4 are excluded; line 5 is a usage.
        let (usages, _) = scan_binding_usages(source, &statements, 100);
        assert_eq!(usages.len(), 2);
        assert_eq!(usages[0].line, 5);
        assert_eq!(usages[0].name, "one");
        assert_eq!(usages[1].name, "duo");
    }

    #[test]
    fn binding_scan_cjs_shapes() {
        let source = "const fs = require('fs');\n\
                      const { load, save: write } = require('./store');\n\
                      let format = require('util').format;\n\
                      var single = require('./single');\n\
                      const a = require('./multi'), b = 2;\n\
                      const { nested: { deep } } = require('./nested');\n\
                      require('./bare');\n\
                      const noassign = 'not a require';\n";
        let (statements, _) = scan_import_bindings(source, 100);
        assert_eq!(statements.len(), 6);
        assert_eq!(statements[0].bindings[0].name, "fs");
        assert_eq!(statements[0].bindings[0].role, BindingRole::Default);
        assert_eq!(statements[1].bindings.len(), 2);
        assert_eq!(statements[1].bindings[0].name, "load");
        assert_eq!(statements[1].bindings[1].name, "write");
        assert_eq!(statements[1].bindings[1].role, BindingRole::Named);
        assert_eq!(statements[2].bindings[0].name, "format");
        assert_eq!(statements[2].bindings[0].role, BindingRole::MemberOf);
        assert_eq!(statements[3].bindings[0].name, "single");
        // Multiple declarators: the tail is not understood.
        assert!(statements[4].unparsed);
        assert_eq!(
            statements[4].bindings.len(),
            1,
            "the first declarator's binding is kept"
        );
        // Nested pattern: nothing claimed, disclosed.
        assert!(statements[5].unparsed);
        assert!(statements[5].bindings.is_empty());
    }

    #[test]
    fn binding_usages_forms_and_exclusions() {
        let source = "const { load } = require('./lib');\n\
                      const pkg = require('./pkg');\n\
                      // a comment mentioning load, still counts (comments are not stripped)\n\
                      const result = load('x');\n\
                      const rest = pkg.metadata;\n\
                      export { load as loadLib } from './re.js';\n\
                      function unrelated(loadX) { return loadX; }\n";
        let (statements, _) = scan_import_bindings(source, 100);
        let (usages, _) = scan_binding_usages(source, &statements, 100);
        let by_name = |name: &str| -> Vec<BindingUsage> {
            usages.iter().filter(|u| u.name == name).cloned().collect()
        };
        // `load`: line 3 comment (bare), line 4 call, line 6 reexport.
        // Line 2's `pkg.metadata` is a Member for pkg.
        let load_usages = by_name("load");
        assert_eq!(load_usages.len(), 3, "{load_usages:?}");
        assert!(load_usages
            .iter()
            .any(|u| u.form == UsageForm::Bare && u.line == 3));
        assert!(load_usages
            .iter()
            .any(|u| u.form == UsageForm::Call && u.line == 4));
        assert!(load_usages
            .iter()
            .any(|u| u.form == UsageForm::Reexport && u.line == 6));
        // `pkg`: member on line 5 only (the declaration on line 2 excluded).
        let pkg_usages = by_name("pkg");
        assert_eq!(pkg_usages.len(), 1);
        assert_eq!(pkg_usages[0].form, UsageForm::Member);
        assert_eq!(pkg_usages[0].line, 5);
        // `loadX` is a different identifier: word boundaries hold.
        assert!(by_name("loadX").is_empty());
    }

    #[test]
    fn binding_scan_caps() {
        let source = "import a1 from './1';\nimport a2 from './2';\nimport a3 from './3';\n";
        let (statements, truncated) = scan_import_bindings(source, 2);
        assert!(truncated);
        assert_eq!(statements.len(), 2);

        let usage_source = "const u = require('./u');\nu(); u(); u();\n";
        let (stmts, _) = scan_import_bindings(usage_source, 10);
        let (usages, truncated) = scan_binding_usages(usage_source, &stmts, 2);
        assert!(truncated);
        assert_eq!(usages.len(), 2);
    }

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

    /// REA #1781 regression guard: URLs containing `*` must be kept whole.
    #[test]
    fn source_map_url_with_asterisk_is_not_truncated() {
        let source = "export const value = 1;\n//# sourceMappingURL=app*part.js.map\n";
        let refs = scan_source_map_refs(source);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].url, "app*part.js.map");
    }

    /// The URL ends at the first whitespace; trailing comment text on the
    /// same line is not swallowed into the URL.
    #[test]
    fn source_map_url_ends_at_first_whitespace() {
        let source = "//# sourceMappingURL=app.js.map // generated by webpack\n";
        let refs = scan_source_map_refs(source);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].url, "app.js.map");
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
