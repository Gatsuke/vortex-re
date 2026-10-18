//! Best-effort redaction of secret-looking values in agent-facing output.
//!
//! Vortex-RE shows small excerpts of inspected files (search matches,
//! extracted strings). Those excerpts can contain credentials. This module
//! applies conservative, pattern-based masking before values leave the
//! process.
//!
//! Limitations (documented, not hidden): this is a heuristic. It catches
//! common `key=value` assignments, AWS-style access key ids, bearer tokens,
//! and PEM private key headers. It will miss secrets with unusual names,
//! secrets split across lines, and secrets stored in encodings the patterns
//! do not recognize. Redaction is a safety net, not a guarantee.

/// A single redaction that was applied.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Redaction {
    /// Short identifier of the rule that fired.
    pub rule: &'static str,
    /// Human-readable explanation.
    pub reason: String,
}

/// Rules that scan for secret-shaped assignments.
const KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "secret_key",
    "private_key",
    "auth",
    "credential",
    "client_secret",
];

const MASK: &str = "[REDACTED]";

/// Redact a single line of text.
///
/// Returns the redacted line plus the list of redactions applied. The input is
/// never mutated; masking replaces the *value* portion after a `=` or `:`
/// separator, keeping the key visible so the finding stays useful.
pub fn redact_line(line: &str) -> (String, Vec<Redaction>) {
    let mut redactions = Vec::new();
    let mut output = String::with_capacity(line.len());
    let lower = line.to_ascii_lowercase();

    // Rule 1: PEM private key block markers mask the whole line.
    if line.contains("-----BEGIN") && line.to_ascii_uppercase().contains("PRIVATE KEY-----") {
        return (
            "[REDACTED: private key block]".to_string(),
            vec![Redaction {
                rule: "pem_private_key",
                reason: "line matched a PEM private key header".to_string(),
            }],
        );
    }

    // Rule 2: keyword=value (or keyword: value) assignments.
    let mut masked_span: Option<(usize, usize)> = None; // value span to mask
    for keyword in KEYWORDS {
        let Some(start) = lower.find(keyword) else {
            continue;
        };
        // The keyword must be at a word boundary.
        let boundary_before = start == 0
            || !lower.as_bytes()[start - 1].is_ascii_alphanumeric()
                && lower.as_bytes()[start - 1] != b'_';
        if !boundary_before {
            continue;
        }
        let after_keyword = &line[start + keyword.len()..];
        let trimmed_start = after_keyword.len() - after_keyword.trim_start().len();
        let rest = &after_keyword[trimmed_start..];
        let has_separator = matches!(rest.chars().next(), Some('=' | ':'));
        if !has_separator {
            continue;
        }
        let value_part = &rest[1..];
        let value_start_abs = start + keyword.len() + trimmed_start + 1;
        let value_trimmed = value_part.trim_start();
        if value_trimmed.is_empty() || value_trimmed.starts_with(MASK) {
            continue;
        }
        // Skip an optional opening quote, then mask up to the closing quote
        // or the next whitespace character.
        let opening_quote = value_trimmed
            .chars()
            .next()
            .filter(|c| *c == '"' || *c == '\'');
        let after_quote = match opening_quote {
            Some(_) => &value_trimmed[1..],
            None => value_trimmed,
        };
        let value_len = after_quote
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(after_quote.len());
        if value_len == 0 {
            continue;
        }
        let span_start = value_start_abs
            + (value_part.len() - value_trimmed.len())
            + opening_quote.is_some() as usize;
        masked_span = Some((span_start, value_len));
        break;
    }

    // Rule 3: AWS-style access key ids (AKIA + 16 upper alphanumerics).
    let mut aws_span: Option<(usize, usize)> = None;
    if let Some(pos) = line.find("AKIA") {
        let candidate = &line[pos..];
        let len = candidate
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            .count();
        if len >= 16 {
            aws_span = Some((pos, len));
        }
    }

    // Rule 4: Bearer tokens.
    let mut bearer_span: Option<(usize, usize)> = None;
    if let Some(pos) = lower.find("bearer ") {
        let token_start = pos + "bearer ".len();
        let token = &line[token_start..];
        let len = token.find(char::is_whitespace).unwrap_or(token.len());
        if len >= 8 {
            bearer_span = Some((token_start, len));
        }
    }

    // Apply the earliest span, then AWS/bearer if they do not overlap.
    let mut spans: Vec<(usize, usize, &'static str, &'static str)> = Vec::new();
    if let Some((start, len)) = masked_span {
        spans.push((
            start,
            len,
            "keyword_assignment",
            "value after a secret-like key",
        ));
    }
    if let Some((start, len)) = aws_span {
        spans.push((start, len, "aws_access_key_id", "AWS-style access key id"));
    }
    if let Some((start, len)) = bearer_span {
        spans.push((start, len, "bearer_token", "bearer authorization token"));
    }
    spans.sort_by_key(|(start, _, _, _)| *start);

    let mut cursor = 0usize;
    for (start, len, rule, what) in spans {
        if start < cursor {
            continue; // overlapping span already masked
        }
        output.push_str(&line[cursor..start]);
        output.push_str(MASK);
        cursor = start + len;
        redactions.push(Redaction {
            rule,
            reason: format!("masked {what}"),
        });
    }
    output.push_str(&line[cursor..]);
    if redactions.is_empty() {
        (line.to_string(), redactions)
    } else {
        (output, redactions)
    }
}

/// Redact a multi-line text block, returning redactions per line.
pub fn redact_text(text: &str, max_line_bytes: usize) -> (String, Vec<(usize, Redaction)>) {
    let mut out_lines = Vec::new();
    let mut all_redactions = Vec::new();
    for (index, line) in text.lines().take(10_000).enumerate() {
        let truncated_line: String = if line.len() > max_line_bytes {
            let mut cut = max_line_bytes;
            while cut > 0 && !line.is_char_boundary(cut) {
                cut -= 1;
            }
            line[..cut].to_string()
        } else {
            line.to_string()
        };
        let (redacted, redactions) = redact_line(&truncated_line);
        out_lines.push(redacted);
        for redaction in redactions {
            all_redactions.push((index + 1, redaction));
        }
    }
    (out_lines.join("\n"), all_redactions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_assignment_is_masked() {
        let (line, redactions) = redact_line("const api_key = \"abc123def456\";");
        assert!(line.contains(MASK));
        assert!(!line.contains("abc123def456"));
        assert_eq!(redactions.len(), 1);
        assert_eq!(redactions[0].rule, "keyword_assignment");
    }

    #[test]
    fn colon_separator_is_masked() {
        let (line, _) = redact_line("password: hunter2");
        assert!(line.contains(MASK));
        assert!(!line.contains("hunter2"));
    }

    #[test]
    fn ordinary_text_is_untouched() {
        let (line, redactions) = redact_line("const greeting = 'hello world';");
        assert_eq!(line, "const greeting = 'hello world';");
        assert!(redactions.is_empty());
    }

    #[test]
    fn aws_access_key_is_masked() {
        let (line, redactions) = redact_line("found id AKIAIOSFODNN7EXAMPLE in config");
        assert!(line.contains(MASK));
        assert!(!line.contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(redactions[0].rule, "aws_access_key_id");
    }

    #[test]
    fn short_akia_prefix_is_not_masked() {
        let (line, redactions) = redact_line("AKIASHORT stays visible");
        assert_eq!(line, "AKIASHORT stays visible");
        assert!(redactions.is_empty());
    }

    #[test]
    fn bearer_token_is_masked() {
        let (line, _) = redact_line("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload");
        assert!(line.contains(MASK));
        assert!(!line.contains("eyJhbGciOiJIUzI1NiJ9.payload"));
    }

    #[test]
    fn pem_header_masks_whole_line() {
        let (line, redactions) = redact_line("-----BEGIN RSA PRIVATE KEY-----");
        assert!(line.contains("REDACTED"));
        assert_eq!(redactions[0].rule, "pem_private_key");
    }

    #[test]
    fn already_redacted_values_are_idempotent() {
        let (line, redactions) = redact_line("password: [REDACTED]");
        assert_eq!(line, "password: [REDACTED]");
        assert!(redactions.is_empty());
    }

    #[test]
    fn multiline_redaction_reports_line_numbers() {
        let (text, redactions) = redact_text("line one\ntoken: abc12345\nline three", 400);
        assert_eq!(redactions.len(), 1);
        assert_eq!(redactions[0].0, 2);
        assert!(text.contains(MASK));
    }
}
