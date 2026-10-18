//! Literal text search over supported text files.
//!
//! Semantics (documented in the README):
//! * matching is literal — there is no regex mode;
//! * default matching is case-insensitive (simple Unicode lowercase folding);
//! * matching is grep-like: one match is reported per line, with the column
//!   of the first occurrence;
//! * binary-looking files are skipped and counted, not searched;
//! * match counts are bounded per file, and every bound is reported so an
//!   agent knows when to narrow the query or inspect the file directly.

use vortex_core::limits::ResourceLimits;
use vortex_core::redact::{redact_line, Redaction};

/// One search hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMatch {
    /// Path relative to the inspection root.
    pub rel_path: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based byte column of the first match on the line.
    pub column: u32,
    /// Matched text as it appears in the file.
    pub matched_text: String,
    /// Trimmed, length-capped, redacted line for context.
    pub line_text: String,
    /// Redactions applied to `line_text`.
    pub redactions: Vec<Redaction>,
}

/// A bounded search session across multiple files.
pub struct SearchSession {
    limits: ResourceLimits,
    case_sensitive: bool,
    needle: String,
    matches: Vec<SearchMatch>,
    truncated: bool,
}

impl SearchSession {
    /// Create a session for one query.
    pub fn new(limits: ResourceLimits, case_sensitive: bool, needle: &str) -> Self {
        Self {
            limits,
            case_sensitive,
            needle: needle.to_string(),
            matches: Vec::new(),
            truncated: false,
        }
    }

    /// Search one file's bytes. Returns `false` when the content is not
    /// searchable text (binary), leaving the session untouched.
    pub fn add_file(&mut self, rel_path: &str, content: &[u8]) -> bool {
        if !crate::identify::looks_like_text(content) {
            return false;
        }
        let Ok(text) = std::str::from_utf8(content) else {
            return false;
        };
        if self.needle.is_empty() {
            return true;
        }
        let mut per_file = 0usize;
        for (index, raw_line) in text.lines().enumerate() {
            if per_file >= self.limits.max_matches_per_file {
                self.truncated = true;
                break;
            }
            let (haystack, needle) = if self.case_sensitive {
                (raw_line.to_string(), self.needle.clone())
            } else {
                (raw_line.to_lowercase(), self.needle.to_lowercase())
            };
            if let Some(found) = haystack.find(&needle) {
                let matched = raw_line
                    .get(found..found + needle.len())
                    .unwrap_or_default()
                    .to_string();
                let (context, redactions) = redact_line(raw_line);
                let context = cap_line(&context, self.limits.max_line_context_bytes);
                self.matches.push(SearchMatch {
                    rel_path: rel_path.to_string(),
                    line: index as u32 + 1,
                    column: found as u32 + 1,
                    matched_text: matched,
                    line_text: context,
                    redactions,
                });
                per_file += 1;
            }
        }
        true
    }

    /// Whether any per-file cap was hit (more matches exist than reported).
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The configured needle.
    pub fn needle(&self) -> &str {
        &self.needle
    }

    /// Whether matching is case sensitive.
    pub fn case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Matches collected so far.
    pub fn matches(&self) -> &[SearchMatch] {
        &self.matches
    }

    /// Consume the session, returning its matches.
    pub fn into_matches(self) -> Vec<SearchMatch> {
        self.matches
    }
}

/// Cap a context line by bytes, respecting char boundaries, and trim it.
fn cap_line(line: &str, max_bytes: usize) -> String {
    if line.len() <= max_bytes {
        return line.trim().to_string();
    }
    let mut cut = max_bytes;
    while cut > 0 && !line.is_char_boundary(cut) {
        cut -= 1;
    }
    line[..cut].trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_finds_matches_with_lines_and_columns() {
        let mut session = SearchSession::new(ResourceLimits::default(), false, "marker");
        let content = b"first line\nhas MARKER inside\nand marker again\n";
        assert!(session.add_file("a.js", content));
        let matches = session.matches();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].line, 2);
        assert_eq!(matches[0].column, 5);
        assert_eq!(matches[1].line, 3);
        assert_eq!(matches[1].column, 5);
    }

    #[test]
    fn case_sensitive_matching() {
        let mut session = SearchSession::new(ResourceLimits::default(), true, "MARKER");
        let content = b"has MARKER inside\nand marker again\n";
        assert!(session.add_file("a.js", content));
        assert_eq!(session.matches().len(), 1);
        assert_eq!(session.matches()[0].line, 1);
    }

    #[test]
    fn one_match_per_line_grep_like() {
        let mut session = SearchSession::new(ResourceLimits::default(), false, "x");
        session.add_file("f", b"x x x\n");
        assert_eq!(session.matches().len(), 1);
    }

    #[test]
    fn per_file_cap_marks_truncation() {
        let limits = ResourceLimits {
            max_matches_per_file: 2,
            ..ResourceLimits::default()
        };
        let mut session = SearchSession::new(limits, false, "hit");
        session.add_file("f", b"hit one\nhit two\nhit three\nhit four\n");
        assert_eq!(session.matches().len(), 2);
        assert!(session.is_truncated());
    }

    #[test]
    fn binary_content_is_rejected() {
        let mut session = SearchSession::new(ResourceLimits::default(), false, "anything");
        assert!(!session.add_file("bin", b"\x00\x01\x02text\x00"));
        assert!(session.matches().is_empty());
    }

    #[test]
    fn redaction_applies_to_context_lines() {
        let mut session = SearchSession::new(ResourceLimits::default(), false, "config");
        let content = b"const config = { api_key: \"abcdef123456\" };\n";
        session.add_file("cfg.js", content);
        let m = &session.matches()[0];
        assert!(m.line_text.contains("[REDACTED]"));
        assert!(!m.line_text.contains("abcdef123456"));
        assert_eq!(m.redactions.len(), 1);
    }

    #[test]
    fn long_context_lines_are_capped() {
        let long_line = format!("{}needle{}", "a".repeat(1000), "b".repeat(1000));
        let mut session = SearchSession::new(ResourceLimits::default(), false, "needle");
        session.add_file("f", long_line.as_bytes());
        assert!(session.matches()[0].line_text.len() <= 400);
    }

    #[test]
    fn empty_needle_matches_nothing() {
        let mut session = SearchSession::new(ResourceLimits::default(), false, "");
        session.add_file("f", b"anything at all\n");
        assert!(session.matches().is_empty());
    }
}
