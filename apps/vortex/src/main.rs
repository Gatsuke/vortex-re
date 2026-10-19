//! The `vortex` binary entry point.
//!
//! Output contract:
//! * machine-readable JSON goes to stdout (opt in with `--json`);
//! * progress and diagnostics go to stderr;
//! * exit codes: 0 success, 1 failure, 2 usage, 3 unsupported, 4 storage,
//!   5 cancelled, 6 partial results (see README "Exit codes").

use clap::Parser;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use vortex_app::cli::{Cli, Command, EvidenceCommand, McpCommand, RunsCommand};
use vortex_app::render;
use vortex_core::config::VortexConfig;
use vortex_core::error::{ErrorCode, VortexError};
use vortex_evidence::store::RunStore;
use vortex_evidence::RunStatus;
use vortex_providers::provider::CancelToken;
use vortex_service::service::{EvidenceSection, OperationOptions, VortexService};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> ExitCode {
    match cli.command {
        Command::Mcp {
            command: McpCommand::Serve,
        } => serve_mcp().await,
        command => run_command(command).await,
    }
}

async fn serve_mcp() -> ExitCode {
    let config = VortexConfig::from_env();
    match VortexService::new(config) {
        Ok(service) => {
            report_startup_recovery(&service);
            let service = Arc::new(service);
            match vortex_app::mcp::serve_stdio(service).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("[vortex] mcp server failed: {err}");
                    ExitCode::from(1)
                }
            }
        }
        Err(err) => {
            eprintln!("[vortex] cannot open the evidence store: {err}");
            ExitCode::from(err.code.exit_code() as u8)
        }
    }
}

fn build_service() -> Result<Arc<VortexService>, VortexError> {
    let config = VortexConfig::from_env();
    let service = VortexService::new(config).map(Arc::new).map_err(|err| {
        VortexError::new(
            ErrorCode::Storage,
            format!("cannot open the evidence store: {err}"),
        )
        .with_hint("set VORTEX_HOME to a writable directory and retry")
    })?;
    report_startup_recovery(&service);
    Ok(service)
}

/// Tell the user what automatic crash recovery did at startup — the
/// "recovers cleanly on next start with an explanation" acceptance.
fn report_startup_recovery(service: &VortexService) {
    let report = service.startup_recovery();
    for entry in &report.recovered {
        eprintln!(
            "[vortex] recovered an interrupted run from a previous session: {}{}",
            entry.run_id,
            if entry.resumable {
                " (resumable: 'vortex runs resume')"
            } else {
                ""
            }
        );
    }
    for left in &report.left_running {
        eprintln!(
            "[vortex] note: run {} is still 'running': {}",
            left.run_id, left.reason
        );
    }
    for problem in &report.errors {
        eprintln!("[vortex] warning: {problem}");
    }
}

async fn run_command(command: Command) -> ExitCode {
    let service = match build_service() {
        Ok(service) => service,
        Err(err) => {
            eprintln!("vortex: error: {err}");
            if let Some(hint) = &err.hint {
                eprintln!("hint: {hint}");
            }
            return ExitCode::from(err.code.exit_code() as u8);
        }
    };

    match command {
        Command::Doctor { json } => {
            let report = service.doctor();
            if json {
                print_json(&serde_json::to_value(&report).unwrap_or_default());
            } else {
                println!("{}", render::render_doctor(&report));
            }
            if report.overall() == vortex_service::doctor::CheckStatus::Fail {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Command::Capabilities { json } => {
            let report = service.capabilities();
            if json {
                print_json(&serde_json::to_value(&report).unwrap_or_default());
            } else {
                println!("{}", render::render_capabilities(&report));
            }
            ExitCode::SUCCESS
        }
        Command::Inspect {
            path,
            json,
            max_entries,
            timeout_secs,
            no_store,
        } => {
            let options = OperationOptions {
                invocation: format!("vortex inspect {}", path.display()),
                max_entries: Some(max_entries),
                timeout_secs,
                persist: !no_store,
                ..OperationOptions::default()
            };
            let result = analyze_with_ctrl_c(service, "inspect", &path, &options, None).await;
            match result {
                Ok(operation) => {
                    if json {
                        print_json(&serde_json::to_value(&operation).unwrap_or_default());
                    } else {
                        println!("{}", render::render_operation("inspect", &operation));
                    }
                    status_exit(operation.status)
                }
                Err(err) => error_exit(err, json),
            }
        }
        Command::Search {
            path,
            query,
            json,
            max_matches,
            case_sensitive,
            timeout_secs,
            no_store,
        } => {
            let options = OperationOptions {
                invocation: format!("vortex search {} '{}'", path.display(), query),
                max_matches,
                case_sensitive,
                timeout_secs,
                persist: !no_store,
                ..OperationOptions::default()
            };
            let result =
                analyze_with_ctrl_c(service, "search", &path, &options, Some(query.clone())).await;
            match result {
                Ok(operation) => {
                    if json {
                        print_json(&serde_json::to_value(&operation).unwrap_or_default());
                    } else {
                        println!("{}", render::render_operation("search", &operation));
                    }
                    status_exit(operation.status)
                }
                Err(err) => error_exit(err, json),
            }
        }
        Command::Relationships {
            path,
            json,
            timeout_secs,
            no_store,
        } => {
            let options = OperationOptions {
                invocation: format!("vortex relationships {}", path.display()),
                timeout_secs,
                persist: !no_store,
                ..OperationOptions::default()
            };
            let result = analyze_with_ctrl_c(service, "relationships", &path, &options, None).await;
            match result {
                Ok(operation) => {
                    if json {
                        print_json(&serde_json::to_value(&operation).unwrap_or_default());
                    } else {
                        println!("{}", render::render_operation("relationships", &operation));
                    }
                    status_exit(operation.status)
                }
                Err(err) => error_exit(err, json),
            }
        }
        Command::Runs { command } => match command {
            RunsCommand::List { json, limit } => match service.list_runs(limit) {
                Ok(runs) => {
                    if json {
                        print_json(&serde_json::json!({ "runs": runs, "count": runs.len() }));
                    } else {
                        println!("{}", render::render_run_list(&runs));
                    }
                    ExitCode::SUCCESS
                }
                Err(err) => error_exit(err, json),
            },
            RunsCommand::Recover {
                json,
                older_than_secs,
            } => match service.recover_stale_runs(Duration::from_secs(older_than_secs)) {
                Ok(report) => {
                    if json {
                        print_json(&serde_json::json!({
                            "recovered": report.recovered,
                            "left_running": report.left_running,
                            "errors": report.errors,
                            "count": report.recovered.len(),
                            "older_than_secs": older_than_secs,
                        }));
                    } else {
                        println!("{}", render::render_recovered(&report, older_than_secs));
                    }
                    ExitCode::SUCCESS
                }
                Err(err) => error_exit(err, json),
            },
            RunsCommand::Resume {
                run_id,
                json,
                timeout_secs,
            } => {
                let options = OperationOptions {
                    invocation: format!("vortex runs resume {run_id}"),
                    timeout_secs,
                    ..OperationOptions::default()
                };
                let result = resume_with_ctrl_c(service.clone(), &run_id, &options).await;
                match result {
                    Ok(operation) => {
                        // The stored record carries the resume detail.
                        let detail = operation
                            .run_id
                            .as_deref()
                            .and_then(|id| service.store().load(id).ok())
                            .and_then(|run| run.status_detail);
                        if json {
                            print_json(&serde_json::to_value(&operation).unwrap_or_default());
                        } else {
                            let underlying = if operation.report.summary.get("query").is_some() {
                                "search"
                            } else {
                                "inspect"
                            };
                            println!(
                                "{}",
                                render::render_resume(underlying, &operation, detail.as_deref())
                            );
                        }
                        status_exit(operation.status)
                    }
                    Err(err) => error_exit(err, json),
                }
            }
        },
        Command::Evidence { command } => match command {
            EvidenceCommand::Show {
                run_id,
                json,
                section,
                page,
                page_size,
            } => {
                let Some(section) = EvidenceSection::parse(&section) else {
                    return error_exit(
                        vortex_service::service::unknown_section_error(&section),
                        json,
                    );
                };
                match service.read_evidence(&run_id, section, page, page_size) {
                    Ok(view) => {
                        if json {
                            print_json(&serde_json::to_value(&view).unwrap_or_default());
                        } else {
                            println!("{}", render::render_evidence_view(&view));
                        }
                        ExitCode::SUCCESS
                    }
                    Err(err) => error_exit(err, json),
                }
            }
            EvidenceCommand::Export {
                run_id,
                out,
                format,
            } => {
                if format != "json" {
                    let err =
                        VortexError::validation(format!("unsupported export format '{format}'"))
                            .with_hint("the only supported format is 'json'");
                    return error_exit(err, false);
                }
                match service.export_run_record(&run_id, &out) {
                    Ok(path) => {
                        eprintln!("[vortex] exported run {run_id} to {}", path.display());
                        ExitCode::SUCCESS
                    }
                    Err(err) => error_exit(err, false),
                }
            }
        },
        Command::Compare {
            run_id_a,
            run_id_b,
            json,
        } => match service.compare(&run_id_a, &run_id_b) {
            Ok(comparison) => {
                if json {
                    print_json(&serde_json::to_value(&comparison).unwrap_or_default());
                } else {
                    println!("{}", render::render_compare(&comparison));
                }
                ExitCode::SUCCESS
            }
            Err(err) => error_exit(err, json),
        },
        Command::Mcp { .. } => ExitCode::SUCCESS,
    }
}

/// Run one analysis operation with Ctrl-C wired to cooperative cancellation.
async fn analyze_with_ctrl_c(
    service: Arc<VortexService>,
    operation: &str,
    path: &Path,
    options: &OperationOptions,
    query: Option<String>,
) -> Result<vortex_service::service::OperationResult, VortexError> {
    eprintln!("[vortex] {operation} {} ...", path.display());
    let cancel = CancelToken::new();
    let watcher_cancel = cancel.clone();
    let watcher = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("[vortex] cancellation requested; stopping at the next checkpoint");
            watcher_cancel.cancel();
        }
    });

    let service_handle = service.clone();
    let operation_name = operation.to_string();
    let path = path.to_path_buf();
    let options = options.clone();
    let task = tokio::task::spawn_blocking(move || match operation_name.as_str() {
        "inspect" => service_handle.inspect(&path, &options, &cancel),
        "search" => {
            let query = query.unwrap_or_default();
            service_handle.search(&path, &query, &options, &cancel)
        }
        "relationships" => service_handle.relationships(&path, &options, &cancel),
        _ => Err(VortexError::internal(format!(
            "unknown operation '{operation_name}'"
        ))),
    });

    let result = match task.await {
        Ok(result) => result,
        Err(join_err) => Err(VortexError::internal(format!(
            "analysis task failed abnormally: {join_err}"
        ))
        .with_hint(
            "this looks like a bug; please report it with the command you ran and the target",
        )),
    };
    watcher.abort();
    if let Ok(operation) = &result {
        eprintln!(
            "[vortex] done: {} findings, {} relationships (status: {})",
            operation.report.findings.len(),
            operation.report.relationships.len(),
            operation.status.as_str()
        );
    }
    result
}

/// Run `runs resume` with Ctrl-C wired to cooperative cancellation.
async fn resume_with_ctrl_c(
    service: Arc<VortexService>,
    run_id: &str,
    options: &OperationOptions,
) -> Result<vortex_service::service::OperationResult, VortexError> {
    eprintln!("[vortex] resuming run {run_id} ...");
    let cancel = CancelToken::new();
    let watcher_cancel = cancel.clone();
    let watcher = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("[vortex] cancellation requested; stopping at the next checkpoint");
            watcher_cancel.cancel();
        }
    });

    let service_handle = service.clone();
    let run_id = run_id.to_string();
    let options = options.clone();
    let task =
        tokio::task::spawn_blocking(move || service_handle.resume_run(&run_id, &options, &cancel));

    let result = match task.await {
        Ok(result) => result,
        Err(join_err) => Err(VortexError::internal(format!(
            "resume task failed abnormally: {join_err}"
        ))
        .with_hint(
            "this looks like a bug; please report it with the run id and the original command",
        )),
    };
    watcher.abort();
    if let Ok(operation) = &result {
        eprintln!(
            "[vortex] done: {} findings, {} relationships (status: {})",
            operation.report.findings.len(),
            operation.report.relationships.len(),
            operation.status.as_str()
        );
    }
    result
}

fn status_exit(status: RunStatus) -> ExitCode {
    match status {
        RunStatus::Succeeded => ExitCode::SUCCESS,
        RunStatus::Partial => ExitCode::from(6),
        RunStatus::Cancelled => ExitCode::from(5),
        RunStatus::Failed => ExitCode::from(1),
        RunStatus::Running => ExitCode::from(1),
    }
}

fn error_exit(error: VortexError, json: bool) -> ExitCode {
    if json {
        print_json(&serde_json::json!({ "error": error.to_json() }));
    }
    eprintln!("vortex: error: {error}");
    if let Some(detail) = &error.detail {
        eprintln!("  detail: {detail}");
    }
    if let Some(hint) = &error.hint {
        eprintln!("  hint: {hint}");
    }
    ExitCode::from(error.code.exit_code() as u8)
}

fn print_json(value: &serde_json::Value) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(err) => eprintln!("vortex: error: cannot serialize JSON output: {err}"),
    }
}
