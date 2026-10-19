//! Runtime configuration resolved from the environment and an optional
//! TOML config file.
//!
//! Vortex-RE is local-first: security-relevant settings
//! (`VORTEX_HOME`, `VORTEX_ALLOWED_ROOTS`) are environment-only, while
//! resource limits, per-provider timeouts, and recovery tuning may come
//! from `vortex-re/config.toml` (see [`crate::configfile`]). Every knob
//! that affects evidence is recorded inside each run record.

use crate::configfile::FileConfig;
use crate::error::VortexError;
use crate::limits::ResourceLimits;
use crate::paths;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Environment variable that overrides the data directory entirely.
pub const ENV_VORTEX_HOME: &str = "VORTEX_HOME";
/// Standard XDG data home variable (Linux convention, honored everywhere).
pub const ENV_XDG_DATA_HOME: &str = "XDG_DATA_HOME";
/// Environment variable that restricts inspection to a set of roots.
pub const ENV_ALLOWED_ROOTS: &str = "VORTEX_ALLOWED_ROOTS";

/// Effective application configuration.
#[derive(Debug, Clone)]
pub struct VortexConfig {
    /// Root directory for local state (run records live under `runs/`).
    pub data_dir: PathBuf,
    /// Resource limits applied to every operation.
    pub limits: ResourceLimits,
    /// Optional allow-list of inspection roots. When set, every requested
    /// target (and every resolved path) must live under one of these roots.
    pub allowed_roots: Option<Vec<PathBuf>>,
    /// Human-readable notes about how configuration was resolved.
    pub notes: Vec<String>,
    /// Per-provider overrides from the config file (keyed by provider id).
    pub provider_overrides: BTreeMap<String, crate::configfile::ProviderOverrides>,
    /// Age threshold (seconds) startup recovery uses when process liveness
    /// cannot decide.
    pub stale_run_grace_secs: u64,
    /// The config file this configuration was built from, when one loaded.
    pub config_file: Option<PathBuf>,
}

impl VortexConfig {
    /// Resolve configuration from the process environment.
    pub fn from_env() -> Self {
        let mut notes = Vec::new();

        let data_dir = match std::env::var_os(ENV_VORTEX_HOME) {
            Some(value) if !value.is_empty() => {
                let dir = PathBuf::from(value);
                notes.push(format!(
                    "{ENV_VORTEX_HOME} is set; using {} as data directory",
                    dir.display()
                ));
                dir
            }
            _ => default_data_dir(),
        };

        let allowed_roots = std::env::var_os(ENV_ALLOWED_ROOTS).and_then(|value| {
            let roots: Vec<PathBuf> = std::env::split_paths(&value)
                .filter(|p| !p.as_os_str().is_empty())
                .collect();
            if roots.is_empty() {
                None
            } else {
                notes.push(format!(
                    "{ENV_ALLOWED_ROOTS} is set; inspections are restricted to {} root(s)",
                    roots.len()
                ));
                Some(roots)
            }
        });

        Self {
            data_dir,
            limits: ResourceLimits::default(),
            allowed_roots,
            notes,
            provider_overrides: BTreeMap::new(),
            stale_run_grace_secs: 3600,
            config_file: None,
        }
    }

    /// Resolve configuration from the environment plus an optional config
    /// file: `explicit` (from `--config`), else the default location when it
    /// exists. An explicit path that does not exist or does not parse is an
    /// error with the exact problem listed; a missing default is the normal
    /// no-file state.
    pub fn resolve(explicit: Option<PathBuf>) -> Result<Self, VortexError> {
        let mut config = Self::from_env();
        let was_explicit = explicit.is_some();
        let path = match explicit {
            Some(path) => Some(path),
            None => default_config_path(),
        };
        let Some(path) = path else {
            return Ok(config);
        };
        if !path.exists() {
            if was_explicit {
                return Err(VortexError::validation(format!(
                    "config file {} not found",
                    path.display()
                ))
                .with_hint("check the path passed to --config"));
            }
            return Ok(config);
        }
        let text = std::fs::read_to_string(&path).map_err(|err| {
            VortexError::validation(format!("cannot read {}: {err}", path.display()))
        })?;
        let file = FileConfig::parse(&text)
            .map_err(|problems| crate::configfile::config_error(&path, &problems))?;
        config.limits = file.effective_limits(config.limits);
        config.stale_run_grace_secs = file.recovery_grace_secs();
        let mut applied: Vec<String> = Vec::new();
        for (provider_id, overrides) in file.providers.iter().flatten() {
            if let Some(timeout) = overrides.timeout_secs {
                if timeout == 0 {
                    return Err(VortexError::validation(format!(
                        "providers.'{provider_id}'.timeout_secs must be >= 1"
                    )));
                }
                applied.push(format!("{provider_id}: timeout {timeout}s"));
            }
            config
                .provider_overrides
                .insert(provider_id.clone(), overrides.clone());
        }
        config.config_file = Some(path.clone());
        config.notes.push(format!(
            "config file loaded from {} (limits overridden where listed)",
            path.display()
        ));
        if !applied.is_empty() {
            config
                .notes
                .push(format!("provider overrides: {}", applied.join(", ")));
        }
        config
            .notes
            .push(format!("recovery grace: {}s", config.stale_run_grace_secs));
        Ok(config)
    }

    /// Directory holding persisted run records.
    pub fn runs_dir(&self) -> PathBuf {
        self.data_dir.join("runs")
    }

    /// Check a candidate target against the configured allowed roots.
    ///
    /// Returns `Ok(())` when no roots are configured (default, unrestricted)
    /// or when the canonical target lives under one of the roots.
    pub fn ensure_target_allowed(
        &self,
        target: &std::path::Path,
    ) -> crate::error::VortexResult<()> {
        let Some(roots) = &self.allowed_roots else {
            return Ok(());
        };
        if roots.is_empty() {
            return Ok(());
        }
        let canonical = std::fs::canonicalize(target).map_err(crate::error::VortexError::from)?;
        for root in roots {
            if let Ok(root_canonical) = std::fs::canonicalize(root) {
                if paths::is_within(&root_canonical, &canonical) {
                    return Ok(());
                }
            }
        }
        Err(crate::error::VortexError::path_outside_root(format!(
            "target {} is not under any allowed root from {ENV_ALLOWED_ROOTS}",
            target.display()
        ))
        .with_hint("add the root to VORTEX_ALLOWED_ROOTS or unset it to remove the restriction"))
    }
}

/// Default config file location (`<config_dir>/vortex-re/config.toml`),
/// following the same platform conventions as the data directory.
pub fn default_config_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(Path::new(&xdg).join(crate::APP_NAME).join("config.toml"));
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            if cfg!(target_os = "macos") {
                return Some(
                    Path::new(&home)
                        .join("Library/Application Support")
                        .join(crate::APP_NAME)
                        .join("config.toml"),
                );
            }
            return Some(
                Path::new(&home)
                    .join(".config")
                    .join(crate::APP_NAME)
                    .join("config.toml"),
            );
        }
    }
    if let Some(app_data) = std::env::var_os("AppData") {
        if !app_data.is_empty() {
            return Some(
                Path::new(&app_data)
                    .join(crate::APP_NAME)
                    .join("config.toml"),
            );
        }
    }
    None
}

/// Compute the default data directory without side effects.
///
/// Priority: `XDG_DATA_HOME`, then platform defaults
/// (`~/.local/share`, `~/Library/Application Support`, `%LOCALAPPDATA%`),
/// then a `.vortex-re` fallback in the working directory (flagged by doctor).
pub fn default_data_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os(ENV_XDG_DATA_HOME) {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join(crate::APP_NAME);
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            if cfg!(target_os = "macos") {
                return PathBuf::from(home)
                    .join("Library/Application Support")
                    .join(crate::APP_NAME);
            }
            return PathBuf::from(home)
                .join(".local/share")
                .join(crate::APP_NAME);
        }
    }
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        if !local_app_data.is_empty() {
            return PathBuf::from(local_app_data).join(crate::APP_NAME);
        }
    }
    PathBuf::from(".vortex-re")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Single lock: environment mutation is process-global, so all env
    /// touching tests in this module must serialize.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn xdg_data_home_takes_priority() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tmp = tempfile_dir();
        std::env::set_var(ENV_XDG_DATA_HOME, &tmp);
        let dir = default_data_dir();
        std::env::remove_var(ENV_XDG_DATA_HOME);
        assert_eq!(dir, tmp.join(crate::APP_NAME));
    }

    #[test]
    fn home_fallback_builds_unix_style_path() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::remove_var(ENV_XDG_DATA_HOME);
        // On this platform HOME is normally set; the assertion covers the
        // common unix layout. Windows CI would take the LOCALAPPDATA branch.
        if std::env::var_os("HOME").is_some() && !cfg!(target_os = "macos") {
            let dir = default_data_dir();
            assert!(dir.ends_with(Path::new(".local/share").join(crate::APP_NAME)));
        }
    }

    fn tempfile_dir() -> PathBuf {
        // Tiny helper so the config crate keeps its dependency surface small.
        let dir = std::env::temp_dir().join(format!(
            "vortex-core-config-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn resolve_applies_config_file_over_defaults() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile_dir();
        std::env::set_var(ENV_XDG_DATA_HOME, &dir);

        let file = std::path::Path::new(&dir).join("cfg.toml");
        std::fs::write(
            &file,
            "[limits]\nmax_entries = 77\ntimeout_secs = 55\n\n[providers.\"builtin-static\"]\ntimeout_secs = 44\n\n[recovery]\ngrace_secs = 33\n",
        )
        .unwrap();

        let config = VortexConfig::resolve(Some(file.clone())).expect("resolve");
        assert_eq!(config.limits.max_entries, 77);
        assert_eq!(config.limits.timeout_secs, 55);
        assert_eq!(config.stale_run_grace_secs, 33);
        assert_eq!(
            config
                .provider_overrides
                .get("builtin-static")
                .and_then(|o| o.timeout_secs),
            Some(44)
        );
        assert_eq!(config.config_file.as_deref(), Some(file.as_path()));
        assert!(config
            .notes
            .iter()
            .any(|note| note.starts_with("config file loaded")));

        std::env::remove_var(ENV_XDG_DATA_HOME);
    }

    #[test]
    fn resolve_rejects_missing_explicit_file() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::remove_var(ENV_XDG_DATA_HOME);
        let err = VortexConfig::resolve(Some(PathBuf::from("/definitely/not/here.toml")))
            .expect_err("missing explicit file");
        assert_eq!(err.code, crate::error::ErrorCode::Validation);
        assert!(err.message.contains("not found"));
    }

    #[test]
    fn resolve_reports_malformed_file_precisely() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::remove_var(ENV_XDG_DATA_HOME);
        let dir = tempfile_dir();
        let file = std::path::Path::new(&dir).join("broken.toml");
        std::fs::write(&file, "[limits]\ngarbage =\n").unwrap();
        let err = VortexConfig::resolve(Some(file)).expect_err("malformed file");
        assert!(err.message.contains("not valid TOML"), "{err}");
    }
}
