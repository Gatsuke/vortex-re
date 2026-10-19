//! The optional TOML configuration file (`vortex-re/config.toml`).
//!
//! Sections:
//! * `[limits]` — partial overrides of the built-in defaults; anything not
//!   listed keeps its default. Validation is the same `ResourceLimits`
//!   validation the CLI honors, listing every problem at once.
//! * `[providers."<id>"]` — per-provider settings; today that is
//!   `timeout_secs`, the only knob that makes sense per engine.
//! * `[recovery]` — `grace_secs`, the age threshold startup recovery uses
//!   when process liveness cannot decide.
//!
//! Precedence, lowest to highest: built-in defaults < config file <
//! environment (where env applies) < command flags. Security-relevant
//! settings (`VORTEX_HOME`, `VORTEX_ALLOWED_ROOTS`) stay environment-only
//! by design: a file that can weaken a policy is a policy downgrade vector.
//!
//! Unknown keys and sections are rejected with their exact names, all in
//! one pass — a silently ignored typo is a misconfiguration the user
//! cannot see, and a one-at-a-time typo parade is a frustration the user
//! should not have to endure.

use crate::error::VortexError;
use crate::limits::ResourceLimits;
use std::collections::BTreeMap;

/// Top-level sections the file may contain.
const SECTION_KEYS: &[&str] = &["limits", "providers", "recovery"];
/// Keys allowed under `[limits]` (mirrors [`PartialLimits`]; the
/// all-limit-keys test fails if the two drift apart).
const LIMIT_KEYS: &[&str] = &[
    "max_files",
    "max_file_bytes",
    "max_total_bytes",
    "max_findings",
    "max_relationships",
    "max_entries",
    "max_matches",
    "max_matches_per_file",
    "max_imports_per_file",
    "min_string_length",
    "max_string_length",
    "max_strings_per_file",
    "max_line_context_bytes",
    "timeout_secs",
    "page_size_default",
    "page_size_max",
];
/// Keys allowed under `[providers."<id>"]`.
const PROVIDER_KEYS: &[&str] = &["timeout_secs"];
/// Keys allowed under `[recovery]`.
const RECOVERY_KEYS: &[&str] = &["grace_secs"];

/// Walk the parsed TOML tree and name every unknown section or key at once.
/// Serde's `deny_unknown_fields` only reports the first offender; this scan
/// upholds the "every problem listed at once" contract.
fn scan_unknown_keys(value: &toml::Value, problems: &mut Vec<String>) {
    let Some(root) = value.as_table() else {
        return;
    };
    for (section, body) in root {
        if !SECTION_KEYS.contains(&section.as_str()) {
            problems.push(format!("unknown section `{section}`"));
            continue;
        }
        let Some(table) = body.as_table() else {
            problems.push(format!("section `{section}` must be a table"));
            continue;
        };
        match section.as_str() {
            "providers" => {
                for (provider_id, provider_value) in table {
                    let Some(provider_table) = provider_value.as_table() else {
                        problems.push(format!("providers.'{provider_id}' must be a table"));
                        continue;
                    };
                    for (key, _) in provider_table {
                        if !PROVIDER_KEYS.contains(&key.as_str()) {
                            problems.push(format!("unknown key `providers.'{provider_id}'.{key}`"));
                        }
                    }
                }
            }
            "recovery" => {
                for (key, _) in table {
                    if !RECOVERY_KEYS.contains(&key.as_str()) {
                        problems.push(format!("unknown key `recovery.{key}`"));
                    }
                }
            }
            _ => {
                for (key, _) in table {
                    if !LIMIT_KEYS.contains(&key.as_str()) {
                        problems.push(format!("unknown key `limits.{key}`"));
                    }
                }
            }
        }
    }
}

/// Per-provider settings from the config file.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProviderOverrides {
    /// Time budget for this provider's operations, in seconds.
    pub timeout_secs: Option<u64>,
}

/// The `[recovery]` section.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoverySection {
    /// Age threshold for startup recovery when liveness cannot decide.
    pub grace_secs: Option<u64>,
}

/// Parsed file contents (partial by design).
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    /// Partial resource-limit overrides.
    pub limits: Option<PartialLimits>,
    /// Per-provider overrides, keyed by provider id.
    pub providers: Option<BTreeMap<String, ProviderOverrides>>,
    /// Recovery tuning.
    pub recovery: Option<RecoverySection>,
}

/// Partial `[limits]` — every field optional; absent keeps the default.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PartialLimits {
    /// See [`ResourceLimits::max_files`].
    pub max_files: Option<usize>,
    /// See [`ResourceLimits::max_file_bytes`].
    pub max_file_bytes: Option<u64>,
    /// See [`ResourceLimits::max_total_bytes`].
    pub max_total_bytes: Option<u64>,
    /// See [`ResourceLimits::max_findings`].
    pub max_findings: Option<usize>,
    /// See [`ResourceLimits::max_relationships`].
    pub max_relationships: Option<usize>,
    /// See [`ResourceLimits::max_entries`].
    pub max_entries: Option<usize>,
    /// See [`ResourceLimits::max_matches`].
    pub max_matches: Option<usize>,
    /// See [`ResourceLimits::max_matches_per_file`].
    pub max_matches_per_file: Option<usize>,
    /// See [`ResourceLimits::max_imports_per_file`].
    pub max_imports_per_file: Option<usize>,
    /// See [`ResourceLimits::min_string_length`].
    pub min_string_length: Option<usize>,
    /// See [`ResourceLimits::max_string_length`].
    pub max_string_length: Option<usize>,
    /// See [`ResourceLimits::max_strings_per_file`].
    pub max_strings_per_file: Option<usize>,
    /// See [`ResourceLimits::max_line_context_bytes`].
    pub max_line_context_bytes: Option<usize>,
    /// See [`ResourceLimits::timeout_secs`].
    pub timeout_secs: Option<u64>,
    /// See [`ResourceLimits::page_size_default`].
    pub page_size_default: Option<usize>,
    /// See [`ResourceLimits::page_size_max`].
    pub page_size_max: Option<usize>,
}

impl FileConfig {
    /// Parse a config file's text. Every problem is listed at once: syntax
    /// first (there can only be one), then all unknown keys and sections
    /// together, then type errors, then limit validation as a batch.
    pub fn parse(text: &str) -> Result<FileConfig, Vec<String>> {
        let mut problems = Vec::new();
        let value: toml::Value = match toml::from_str(text) {
            Ok(value) => value,
            Err(err) => {
                return Err(vec![format!("not valid TOML: {err}")]);
            }
        };
        scan_unknown_keys(&value, &mut problems);
        if !problems.is_empty() {
            return Err(problems);
        }
        let config: FileConfig = match serde::Deserialize::deserialize(value) {
            Ok(config) => config,
            Err(err) => {
                return Err(vec![err.to_string()]);
            }
        };
        if config.limits.is_some() {
            let effective = config.effective_limits(ResourceLimits::default());
            if let Err(limit_problems) = effective.validate() {
                problems.push(limit_problems);
            }
        }
        if problems.is_empty() {
            Ok(config)
        } else {
            Err(problems)
        }
    }

    /// Apply the file's partial limits onto a base (defaults or the
    /// effective set so far).
    pub fn effective_limits(&self, base: ResourceLimits) -> ResourceLimits {
        let mut limits = base;
        if let Some(file) = &self.limits {
            if let Some(v) = file.max_files {
                limits.max_files = v;
            }
            if let Some(v) = file.max_file_bytes {
                limits.max_file_bytes = v;
            }
            if let Some(v) = file.max_total_bytes {
                limits.max_total_bytes = v;
            }
            if let Some(v) = file.max_findings {
                limits.max_findings = v;
            }
            if let Some(v) = file.max_relationships {
                limits.max_relationships = v;
            }
            if let Some(v) = file.max_entries {
                limits.max_entries = v;
            }
            if let Some(v) = file.max_matches {
                limits.max_matches = v;
            }
            if let Some(v) = file.max_matches_per_file {
                limits.max_matches_per_file = v;
            }
            if let Some(v) = file.max_imports_per_file {
                limits.max_imports_per_file = v;
            }
            if let Some(v) = file.min_string_length {
                limits.min_string_length = v;
            }
            if let Some(v) = file.max_string_length {
                limits.max_string_length = v;
            }
            if let Some(v) = file.max_strings_per_file {
                limits.max_strings_per_file = v;
            }
            if let Some(v) = file.max_line_context_bytes {
                limits.max_line_context_bytes = v;
            }
            if let Some(v) = file.timeout_secs {
                limits.timeout_secs = v;
            }
            if let Some(v) = file.page_size_default {
                limits.page_size_default = v;
            }
            if let Some(v) = file.page_size_max {
                limits.page_size_max = v;
            }
        }
        limits
    }

    /// Provider override lookup by id (empty when absent).
    pub fn provider_override(&self, provider_id: &str) -> ProviderOverrides {
        self.providers
            .as_ref()
            .and_then(|providers| providers.get(provider_id))
            .cloned()
            .unwrap_or_default()
    }

    /// The recovery grace period (default 3600s when unset).
    pub fn recovery_grace_secs(&self) -> u64 {
        self.recovery
            .as_ref()
            .and_then(|recovery| recovery.grace_secs)
            .unwrap_or(3600)
    }
}

/// Convert config-file problems into the shared error type.
pub fn config_error(path: &std::path::Path, problems: &[String]) -> VortexError {
    VortexError::validation(format!(
        "config file {} is not usable: {}",
        path.display(),
        problems.join("; ")
    ))
    .with_hint("fix the listed keys in the config file, or pass --config to point at another one")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_file_applies_limits_and_providers() {
        let text = r#"
[limits]
max_entries = 100
timeout_secs = 90

[providers."builtin-static"]
timeout_secs = 60

[recovery]
grace_secs = 120
"#;
        let config = FileConfig::parse(text).expect("parses");
        let limits = config.effective_limits(ResourceLimits::default());
        assert_eq!(limits.max_entries, 100);
        assert_eq!(limits.timeout_secs, 90);
        assert_eq!(limits.max_findings, ResourceLimits::default().max_findings);
        let provider = config.provider_override("builtin-static");
        assert_eq!(provider.timeout_secs, Some(60));
        assert_eq!(config.provider_override("unknown").timeout_secs, None);
        assert_eq!(config.recovery_grace_secs(), 120);
    }

    #[test]
    fn syntax_garbage_is_rejected_with_one_clear_error() {
        let err = FileConfig::parse("[limits\ngarbage").unwrap_err();
        assert_eq!(err.len(), 1);
        assert!(err[0].contains("not valid TOML"));
    }

    #[test]
    fn unknown_keys_are_rejected_by_name() {
        let text = r#"
[limits]
max_entriess = 5

[providers."builtin-static"]
timeout_secss = 60

[unknown_section]
whatever = 1
"#;
        let err = FileConfig::parse(text).unwrap_err();
        let joined = err.join("; ");
        assert!(joined.contains("max_entriess"), "typo listed: {joined}");
        assert!(joined.contains("timeout_secss"), "typo listed: {joined}");
        assert!(
            joined.contains("unknown_section"),
            "unknown section listed: {joined}"
        );
    }

    #[test]
    fn invalid_limit_values_are_listed_together() {
        let text = r#"
[limits]
max_files = 0
timeout_secs = 0
min_string_length = 2
"#;
        let err = FileConfig::parse(text).unwrap_err();
        let joined = err.join("; ");
        assert!(joined.contains("max_files"));
        assert!(joined.contains("timeout_secs"));
        assert!(joined.contains("min_string_length"));
    }

    #[test]
    fn truncated_file_is_a_syntax_error() {
        let err = FileConfig::parse("[limits]\nmax_entries =").unwrap_err();
        assert!(err[0].contains("not valid TOML"));
    }

    #[test]
    fn every_limit_key_is_recognized() {
        // Every key of [limits], set to a valid value. If a limit is added
        // to PartialLimits without updating LIMIT_KEYS the scan flags it as
        // unknown; if LIMIT_KEYS lists a field PartialLimits lost, serde
        // rejects it. Either way, this test names the drift.
        let text = "\
[limits]
max_files = 11
max_file_bytes = 1000
max_total_bytes = 10000
max_findings = 12
max_relationships = 13
max_entries = 14
max_matches = 15
max_matches_per_file = 16
max_imports_per_file = 17
min_string_length = 4
max_string_length = 200
max_strings_per_file = 18
max_line_context_bytes = 19
timeout_secs = 20
page_size_default = 21
page_size_max = 22

[recovery]
grace_secs = 23
";
        let config = FileConfig::parse(text).expect("all limit keys recognized");
        let limits = config.effective_limits(ResourceLimits::default());
        assert_eq!(limits.max_files, 11);
        assert_eq!(limits.max_total_bytes, 10000);
        assert_eq!(limits.max_matches_per_file, 16);
        assert_eq!(limits.page_size_max, 22);
        assert_eq!(config.recovery_grace_secs(), 23);
    }
}
