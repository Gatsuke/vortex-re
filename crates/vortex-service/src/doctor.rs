//! Diagnostics: `vortex doctor`.
//!
//! Doctor answers one question honestly: *what works right now, and what
//! does not, and why?* Every check reports `ok`, `warn`, `fail`, or `info`,
//! and unsupported operations always carry a reason and, where applicable,
//! the prerequisite that would enable them.

use crate::service::VortexService;
use serde::Serialize;
use std::path::Path;
use vortex_evidence::store::RunStore;

/// Status of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// The check passed.
    Ok,
    /// The check passed with a caveat.
    Warn,
    /// The check failed; the related capability is unavailable.
    Fail,
    /// Informational output (no pass/fail semantics).
    Info,
}

impl CheckStatus {
    /// Single-character marker for human output.
    pub const fn marker(self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
            CheckStatus::Info => "info",
        }
    }
}

/// One diagnostic check result.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    /// Short check name.
    pub name: String,
    /// Outcome.
    pub status: CheckStatus,
    /// What was observed.
    pub detail: String,
    /// How to fix a warning or failure, when known.
    pub hint: Option<String>,
}

/// An operation that is not available and why.
#[derive(Debug, Clone, Serialize)]
pub struct NotSupported {
    /// Operation identifier.
    pub operation: String,
    /// Why it is unavailable.
    pub reason: String,
    /// What would enable it.
    pub prerequisite: Option<String>,
}

/// The full doctor report.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// Vortex-RE version.
    pub version: String,
    /// Operating system.
    pub os: String,
    /// CPU architecture.
    pub arch: String,
    /// Individual checks.
    pub checks: Vec<CheckResult>,
    /// Operations that work right now.
    pub supported_now: Vec<String>,
    /// Operations that do not work and why.
    pub not_supported: Vec<NotSupported>,
}

impl DoctorReport {
    /// Worst status across checks (fail beats warn beats ok; info ignored).
    pub fn overall(&self) -> CheckStatus {
        if self.checks.iter().any(|c| c.status == CheckStatus::Fail) {
            CheckStatus::Fail
        } else if self.checks.iter().any(|c| c.status == CheckStatus::Warn) {
            CheckStatus::Warn
        } else {
            CheckStatus::Ok
        }
    }
}

/// Probe whether a directory is writable by creating and removing a file.
fn probe_writable(dir: &Path) -> Result<(), String> {
    let probe = dir.join(".vortex-doctor-probe");
    std::fs::write(&probe, b"probe").map_err(|err| err.to_string())?;
    std::fs::remove_file(&probe).map_err(|err| err.to_string())?;
    Ok(())
}

/// Run all diagnostics against a live service.
pub fn run_doctor(service: &VortexService) -> DoctorReport {
    let mut checks = Vec::new();

    checks.push(CheckResult {
        name: "version".to_string(),
        status: CheckStatus::Info,
        detail: format!(
            "vortex-re {} (evidence schema v{})",
            vortex_core::APP_VERSION,
            vortex_evidence::SCHEMA_VERSION
        ),
        hint: None,
    });

    checks.push(CheckResult {
        name: "platform".to_string(),
        status: CheckStatus::Info,
        detail: format!(
            "{} / {} ({} family)",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::env::consts::FAMILY
        ),
        hint: None,
    });

    // Data directory.
    let data_dir = service.config().data_dir.clone();
    let mut data_check = match std::fs::create_dir_all(&data_dir) {
        Ok(()) => match probe_writable(&data_dir) {
            Ok(()) => CheckResult {
                name: "data_directory".to_string(),
                status: CheckStatus::Ok,
                detail: format!("{} is writable", data_dir.display()),
                hint: None,
            },
            Err(err) => CheckResult {
                name: "data_directory".to_string(),
                status: CheckStatus::Fail,
                detail: format!("{} is not writable: {err}", data_dir.display()),
                hint: Some("set VORTEX_HOME to a writable directory".to_string()),
            },
        },
        Err(err) => CheckResult {
            name: "data_directory".to_string(),
            status: CheckStatus::Fail,
            detail: format!("cannot create {}: {err}", data_dir.display()),
            hint: Some("set VORTEX_HOME to a writable directory".to_string()),
        },
    };
    for note in &service.config().notes {
        if note.starts_with("VORTEX_HOME") || note.starts_with("VORTEX_ALLOWED_ROOTS") {
            data_check.detail.push_str(format!("; {note}").as_str());
        }
    }
    checks.push(data_check);

    // Evidence store.
    match service.store().health() {
        Ok((count, unreadable)) => {
            let status = if unreadable.is_empty() {
                CheckStatus::Ok
            } else {
                CheckStatus::Warn
            };
            checks.push(CheckResult {
                name: "evidence_store".to_string(),
                status,
                detail: format!(
                    "{} run record(s) in {}; {} unreadable",
                    count,
                    service.store().location().display(),
                    unreadable.len()
                ),
                hint: if unreadable.is_empty() {
                    None
                } else {
                    Some(format!(
                        "unreadable records: {}. Re-export or delete them; 'vortex runs recover' can also mark stale 'running' records as failed",
                        unreadable.join(", ")
                    ))
                },
            });
        }
        Err(err) => checks.push(CheckResult {
            name: "evidence_store".to_string(),
            status: CheckStatus::Fail,
            detail: format!("store unusable: {err}"),
            hint: Some("check permissions for the data directory".to_string()),
        }),
    }

    // Startup recovery: what automatic crash recovery did when this service
    // instance was created. This is the "recovers cleanly with an
    // explanation" acceptance made inspectable.
    {
        let recovery = service.startup_recovery();
        let status = if recovery.errors.is_empty() {
            if recovery.recovered.is_empty() {
                CheckStatus::Ok
            } else {
                CheckStatus::Warn
            }
        } else {
            CheckStatus::Fail
        };
        checks.push(CheckResult {
            name: "startup_recovery".to_string(),
            status,
            detail: format!(
                "{} run(s) recovered as failed, {} left as 'running', {} persistence problem(s)",
                recovery.recovered.len(),
                recovery.left_running.len(),
                recovery.errors.len()
            ),
            hint: if recovery.recovered.is_empty() && recovery.errors.is_empty() {
                None
            } else {
                Some(
                    "recovered runs explain themselves in their status_detail; resumable ones \
                     point at 'vortex runs resume'"
                        .to_string(),
                )
            },
        });
        for entry in &recovery.recovered {
            checks.push(CheckResult {
                name: format!("recovered_run:{}", entry.run_id),
                status: CheckStatus::Warn,
                detail: entry.reason.clone(),
                hint: Some(if entry.resumable {
                    "run 'vortex runs resume <run-id>' to continue from the checkpoint".to_string()
                } else {
                    "re-run the operation; nothing durable was saved mid-run".to_string()
                }),
            });
        }
    }

    // Schema versions across the store: older records load tolerantly (with
    // an explicit note); newer ones cannot be read at all.
    {
        let store = service.store();
        let mut older = 0usize;
        let mut current = 0usize;
        let mut newer: Vec<String> = Vec::new();
        // The store's public trait does not expose per-record schema
        // versions; read them straight from the store directory (the same
        // JSON the store itself would parse).
        let location = store.location();
        if let Ok(entries) = std::fs::read_dir(&location) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let Ok(body) = std::fs::read(&path) else {
                    continue;
                };
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
                    continue;
                };
                match value.get("schema_version").and_then(|v| v.as_u64()) {
                    Some(version) if version < u64::from(vortex_evidence::SCHEMA_VERSION) => {
                        older += 1;
                    }
                    Some(version) if version > u64::from(vortex_evidence::SCHEMA_VERSION) => {
                        let id = value
                            .get("run_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("<unknown>")
                            .to_string();
                        newer.push(id);
                    }
                    Some(_) => current += 1,
                    None => continue,
                }
            }
        }
        let status = if newer.is_empty() {
            if older == 0 {
                CheckStatus::Ok
            } else {
                CheckStatus::Warn
            }
        } else {
            CheckStatus::Fail
        };
        checks.push(CheckResult {
            name: "schema_versions".to_string(),
            status,
            detail: format!(
                "{} record(s) at the current schema (v{}), {} older record(s) loaded tolerantly, \
                 {} newer than this tool",
                current,
                vortex_evidence::SCHEMA_VERSION,
                older,
                newer.len()
            ),
            hint: if newer.is_empty() {
                if older > 0 {
                    Some(
                        "older records are readable but carry no owner/checkpoint; they cannot be \
                         resumed — re-run instead"
                            .to_string(),
                    )
                } else {
                    None
                }
            } else {
                Some(format!(
                    "records written by a newer vortex exist ({}) — upgrade this binary to read them",
                    newer.join(", ")
                ))
            },
        });
    }

    // Config file resolution.
    {
        let notes = &service.config().notes;
        let has_file = service.config().config_file.is_some();
        let mentioned = notes.iter().any(|note| note.starts_with("config file"));
        let status = if mentioned {
            CheckStatus::Ok
        } else {
            CheckStatus::Info
        };
        let detail = if let Some(path) = &service.config().config_file {
            let overrides: Vec<&String> = notes
                .iter()
                .filter(|note| {
                    note.starts_with("provider overrides") || note.starts_with("recovery grace")
                })
                .collect();
            format!("{} ({} applied note(s))", path.display(), overrides.len())
        } else {
            "no config file loaded; defaults apply".to_string()
        };
        checks.push(CheckResult {
            name: "config_file".to_string(),
            status,
            detail,
            hint: if has_file {
                None
            } else {
                Some(
                    "create vortex-re/config.toml or pass --config to override defaults"
                        .to_string(),
                )
            },
        });
    }

    // Signing key for --signed exports.
    {
        let public_key_file = service.config().data_dir.join("keys").join("signing.pub");
        let status = if public_key_file.exists() {
            match std::fs::read_to_string(&public_key_file) {
                Ok(hex) if hex.trim().len() == 64 => CheckStatus::Ok,
                Ok(_) => CheckStatus::Warn,
                Err(_) => CheckStatus::Warn,
            }
        } else {
            CheckStatus::Info
        };
        let detail = if public_key_file.exists() {
            std::fs::read_to_string(&public_key_file)
                .unwrap_or_default()
                .trim()
                .chars()
                .take(16)
                .collect::<String>()
        } else {
            "not generated; exports are unsigned until 'evidence export --signed' is used"
                .to_string()
        };
        checks.push(CheckResult {
            name: "signing_key".to_string(),
            status,
            detail: format!("ed25519 public key: {detail}"),
            hint: None,
        });
    }

    // Export ledger chain.
    {
        let ledger = service.export_ledger_status();
        let status = if ledger.valid {
            if ledger.entries == 0 {
                CheckStatus::Info
            } else {
                CheckStatus::Ok
            }
        } else {
            CheckStatus::Fail
        };
        checks.push(CheckResult {
            name: "export_ledger".to_string(),
            status,
            detail: if ledger.valid {
                format!("{} export(s) recorded, chain verifies", ledger.entries)
            } else {
                format!(
                    "chain broken at entry {:?}: {}",
                    ledger.first_broken_seq,
                    ledger.reason.as_deref().unwrap_or("unknown reason")
                )
            },
            hint: if ledger.valid {
                None
            } else {
                Some(
                    "a recorded export entry was modified after the fact; find the tampered \
                     export and re-verify from a trusted copy"
                        .to_string(),
                )
            },
        });
    }

    // Providers.
    let capabilities = service.capabilities();
    for provider in &capabilities.providers {
        checks.push(CheckResult {
            name: format!("provider:{}", provider.id),
            status: CheckStatus::Ok,
            detail: format!(
                "built-in provider {} ({}) with {} capability(ies): {}",
                provider.id,
                provider.version,
                provider.capabilities.len(),
                provider
                    .capabilities
                    .iter()
                    .map(|c| c.id.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            hint: None,
        });
    }

    // Optional providers: none integrated in this release. Reported as info
    // (they are optional), with prerequisites for each planned integration.
    let optional = [
        (
            "rizin",
            "native binary analysis (ELF/PE/Mach-O disassembly)",
        ),
        ("ghidra", "deeper native analysis via Ghidra headless"),
        ("frida", "dynamic instrumentation (authorized targets only)"),
    ];
    for (name, what) in optional {
        checks.push(CheckResult {
            name: format!("optional_provider:{name}"),
            status: CheckStatus::Info,
            detail: format!("not integrated in this release; would provide {what}"),
            hint: Some(format!(
                "see docs/PROVIDERS.md; {name} requires its own technical and license review before integration"
            )),
        });
    }

    DoctorReport {
        version: vortex_core::APP_VERSION.to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        checks,
        supported_now: vec![
            "inspect file (identity, digest, format, bounded content analysis)".to_string(),
            "inspect directory (bounded inventory, manifests, source map references)".to_string(),
            "search literal text in text files with file:line locations".to_string(),
            "trace relationships (imports, requires, dependencies, source maps, scripts)"
                .to_string(),
            "identify binary formats by magic bytes".to_string(),
            "extract printable strings from binary files (redacted)".to_string(),
            "list zip/jar/apk and Electron asar archive members (read-only, bounded, in-memory)"
                .to_string(),
            "parse ELF and PE/COFF structure (headers, sections, imports/exports)".to_string(),
            "read Android DEX headers, counts, and class inventories (also inside APKs)"
                .to_string(),
            "inventory .NET assembly metadata (runtime, entry point, metadata streams)".to_string(),
            "persist, list, page through, export, and compare evidence runs".to_string(),
            "serve MCP tools over stdio".to_string(),
        ],
        not_supported: vec![
            NotSupported {
                operation: "decompile / disassemble native executables".to_string(),
                reason: "no native-analysis provider is integrated".to_string(),
                prerequisite: Some(
                    "a future Rizin-based provider (planned, not available)".to_string(),
                ),
            },
            NotSupported {
                operation: "analyze .NET assemblies".to_string(),
                reason: "no managed-code provider is integrated".to_string(),
                prerequisite: Some("planned provider (see docs/ROADMAP.md)".to_string()),
            },
            NotSupported {
                operation: "analyze Android DEX/APK".to_string(),
                reason: "no Android provider is integrated; DEX files are identified by magic only"
                    .to_string(),
                prerequisite: Some("planned provider (see docs/ROADMAP.md)".to_string()),
            },
            NotSupported {
                operation: "extract archives (zip/asar)".to_string(),
                reason: "archive extraction is not implemented in this release".to_string(),
                prerequisite: Some(
                    "planned capability with explicit safety review (see docs/THREAT_MODEL.md)"
                        .to_string(),
                ),
            },
            NotSupported {
                operation: "execute or observe the target at runtime".to_string(),
                reason: "static analysis only in this release, by design".to_string(),
                prerequisite: Some(
                    "controlled dynamic analysis is a later roadmap phase".to_string(),
                ),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vortex_core::config::VortexConfig;
    use vortex_core::limits::ResourceLimits;

    #[test]
    fn doctor_reports_ok_on_a_fresh_environment() {
        let dir = tempfile::tempdir().unwrap();
        let config = VortexConfig {
            data_dir: dir.path().join("data"),
            limits: ResourceLimits::default(),
            allowed_roots: None,
            notes: Vec::new(),
            provider_overrides: Default::default(),
            stale_run_grace_secs: 3600,
            config_file: None,
        };
        let service = VortexService::new(config).unwrap();
        let report = service.doctor();
        assert_eq!(report.overall(), CheckStatus::Ok);
        assert!(report.checks.iter().any(|c| c.name == "version"));
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "evidence_store" && c.status == CheckStatus::Ok));
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "provider:builtin-static"));
        assert!(!report.supported_now.is_empty());
        assert!(report
            .not_supported
            .iter()
            .any(|n| n.operation.contains("decompile")));
    }

    #[test]
    fn doctor_counts_existing_runs_and_flags_unreadable_records() {
        let dir = tempfile::tempdir().unwrap();
        let config = VortexConfig {
            data_dir: dir.path().join("data"),
            limits: ResourceLimits::default(),
            allowed_roots: None,
            notes: Vec::new(),
            provider_overrides: Default::default(),
            stale_run_grace_secs: 3600,
            config_file: None,
        };
        let service = VortexService::new(config).unwrap();
        // Store one healthy run and one corrupt record.
        let app_dir = dir.path().join("app");
        std::fs::create_dir_all(&app_dir).unwrap();
        std::fs::write(app_dir.join("a.js"), b"console.log('hi');\n").unwrap();
        service
            .inspect(
                &app_dir,
                &crate::service::OperationOptions::default(),
                &vortex_providers::provider::CancelToken::new(),
            )
            .unwrap();
        std::fs::write(
            service.store().location().join("run-corrupt.json"),
            b"{ broken",
        )
        .unwrap();

        let report = service.doctor();
        let store_check = report
            .checks
            .iter()
            .find(|c| c.name == "evidence_store")
            .expect("evidence store check");
        assert_eq!(store_check.status, CheckStatus::Warn);
        assert!(store_check.detail.contains("1 unreadable"));
        assert_eq!(report.overall(), CheckStatus::Warn);
    }
}
