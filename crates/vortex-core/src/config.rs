//! Runtime configuration resolved from the environment.
//!
//! Vortex-RE is local-first: all configuration is environment-based for the
//! MVP (no config file), which keeps behavior transparent and easy to audit.
//! Every knob that affects evidence is recorded inside each run record.

use crate::limits::ResourceLimits;
use crate::paths;
use std::path::PathBuf;

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
        }
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
}
