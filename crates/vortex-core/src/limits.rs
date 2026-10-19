//! Resource limits that bound every analysis operation.
//!
//! Bounded output is a core product property: it protects AI context windows
//! and keeps large artifacts queryable. Limits are enforced by providers and
//! any truncation is recorded as an explicit limitation, never silently.

use serde::{Deserialize, Serialize};

/// Limits applied to a single analysis operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum number of files considered during a directory walk.
    pub max_files: usize,
    /// Maximum bytes read from any single file.
    pub max_file_bytes: u64,
    /// Maximum total bytes read during one operation.
    pub max_total_bytes: u64,
    /// Maximum findings retained in one run.
    pub max_findings: usize,
    /// Maximum relationships retained in one run.
    pub max_relationships: usize,
    /// Maximum entries listed in summaries (files, extensions, strings, ...).
    pub max_entries: usize,
    /// Maximum search matches returned.
    pub max_matches: usize,
    /// Maximum matches reported per file.
    pub max_matches_per_file: usize,
    /// Maximum import references scanned per file.
    pub max_imports_per_file: usize,
    /// Minimum length for extracted printable strings.
    pub min_string_length: usize,
    /// Maximum length for extracted printable strings.
    pub max_string_length: usize,
    /// Maximum printable strings extracted per binary file.
    pub max_strings_per_file: usize,
    /// Maximum line length echoed back in search results.
    pub max_line_context_bytes: usize,
    /// Time budget for one operation, in seconds.
    pub timeout_secs: u64,
    /// Default page size for paginated evidence retrieval.
    pub page_size_default: usize,
    /// Maximum accepted page size for paginated evidence retrieval.
    pub page_size_max: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_files: 2000,
            max_file_bytes: 8 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
            max_findings: 500,
            max_relationships: 500,
            max_entries: 50,
            max_matches: 100,
            max_matches_per_file: 20,
            max_imports_per_file: 200,
            min_string_length: 5,
            max_string_length: 256,
            max_strings_per_file: 50,
            max_line_context_bytes: 400,
            timeout_secs: 30,
            page_size_default: 20,
            page_size_max: 100,
        }
    }
}

impl ResourceLimits {
    /// Validate that configured limits are self-consistent.
    ///
    /// Errors list every problem so callers can fix all values at once.
    pub fn validate(&self) -> Result<(), String> {
        let mut problems = Vec::new();
        if self.max_files == 0 {
            problems.push("max_files must be >= 1");
        }
        if self.max_file_bytes == 0 {
            problems.push("max_file_bytes must be >= 1");
        }
        if self.max_findings == 0 {
            problems.push("max_findings must be >= 1");
        }
        if self.max_entries == 0 {
            problems.push("max_entries must be >= 1");
        }
        if self.max_matches == 0 {
            problems.push("max_matches must be >= 1");
        }
        if self.min_string_length < 4 {
            problems.push("min_string_length must be >= 4 (lower values produce noise)");
        }
        if self.max_string_length < self.min_string_length {
            problems.push("max_string_length must be >= min_string_length");
        }
        if self.timeout_secs == 0 {
            problems.push("timeout_secs must be >= 1");
        }
        if self.page_size_default == 0 || self.page_size_max == 0 {
            problems.push("page sizes must be >= 1");
        }
        if self.page_size_default > self.page_size_max {
            problems.push("page_size_default must be <= page_size_max");
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    /// Clamp a requested page size into the allowed range.
    pub fn clamp_page_size(&self, requested: Option<usize>) -> usize {
        match requested {
            Some(n) => n.clamp(1, self.page_size_max),
            None => self.page_size_default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_are_valid() {
        assert!(ResourceLimits::default().validate().is_ok());
    }

    #[test]
    fn invalid_limits_report_all_problems() {
        let limits = ResourceLimits {
            max_files: 0,
            timeout_secs: 0,
            min_string_length: 2,
            page_size_default: 200,
            page_size_max: 100,
            ..ResourceLimits::default()
        };
        let err = limits.validate().unwrap_err();
        assert!(err.contains("max_files"));
        assert!(err.contains("timeout_secs"));
        assert!(err.contains("min_string_length"));
        assert!(err.contains("page_size_default"));
    }

    #[test]
    fn page_size_clamping() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.clamp_page_size(None), limits.page_size_default);
        assert_eq!(limits.clamp_page_size(Some(0)), 1);
        assert_eq!(limits.clamp_page_size(Some(10_000)), limits.page_size_max);
        assert_eq!(limits.clamp_page_size(Some(50)), 50);
    }
}
