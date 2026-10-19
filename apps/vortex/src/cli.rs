//! CLI argument definitions (clap derive).

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Vortex-RE: local-first, evidence-backed static analysis for AI coding
/// agents.
///
/// Inspect authorized software artifacts without executing them, search
/// them, trace their relationships, and keep durable evidence records you
/// can review, export, and compare.
#[derive(Parser, Debug)]
#[command(
    name = "vortex",
    version,
    about = "Local-first, evidence-backed static analysis for AI coding agents",
    long_about = "Vortex-RE inspects software artifacts you own or are authorized to analyze.\n\n \
                  It performs static analysis only: inspected targets are never executed.\n \
                  Every conclusion is recorded as evidence with its origin (observed, derived,\n \
                  or inferred), its source location, and its limitations."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Show what works on this machine, what is missing, and why.
    Doctor {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List registered providers and their capabilities.
    Capabilities {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a file or directory (bounded static analysis).
    Inspect {
        /// Target file or directory to inspect.
        path: PathBuf,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Maximum entries in summaries and per-file listings.
        #[arg(long, default_value_t = 50)]
        max_entries: usize,
        /// Time budget for the operation, in seconds.
        #[arg(long)]
        timeout_secs: Option<u64>,
        /// Do not persist an evidence run record.
        #[arg(long)]
        no_store: bool,
    },
    /// Search for literal text across supported files.
    Search {
        /// Target file or directory to search.
        path: PathBuf,
        /// Literal text to find (never a regex).
        query: String,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Maximum matches returned.
        #[arg(long)]
        max_matches: Option<usize>,
        /// Match case sensitively (default is case-insensitive).
        #[arg(long)]
        case_sensitive: bool,
        /// Time budget for the operation, in seconds.
        #[arg(long)]
        timeout_secs: Option<u64>,
        /// Do not persist an evidence run record.
        #[arg(long)]
        no_store: bool,
    },
    /// Trace relationships: imports, dependencies, source maps, scripts.
    Relationships {
        /// Target file or directory to analyze.
        path: PathBuf,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Time budget for the operation, in seconds.
        #[arg(long)]
        timeout_secs: Option<u64>,
        /// Do not persist an evidence run record.
        #[arg(long)]
        no_store: bool,
    },
    /// Manage investigation runs.
    Runs {
        #[command(subcommand)]
        command: RunsCommand,
    },
    /// Read stored evidence.
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
    /// Compare two stored runs (structural differences only).
    Compare {
        /// First run id.
        run_id_a: String,
        /// Second run id.
        run_id_b: String,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// MCP server commands.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
}

/// Run management subcommands.
#[derive(Subcommand, Debug)]
pub enum RunsCommand {
    /// List stored runs, newest first.
    List {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Maximum runs to list.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Mark stale `running` runs (from crashed or interrupted processes)
    /// as failed. Startup recovery already does this for runs whose owner
    /// process is dead; this command is the explicit override for ambiguous
    /// cases (hung processes, unknown ages).
    Recover {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Treat `running` runs older than this many seconds as stale, even
        /// when their owner process still appears alive.
        #[arg(long, default_value_t = 3600)]
        older_than_secs: u64,
    },
    /// Continue an interrupted run from its last durable checkpoint. Only
    /// inspect and search runs over directories carry checkpoints; the
    /// artifact must be unchanged since the run was recorded.
    Resume {
        /// Run id to resume (see `vortex runs list`).
        run_id: String,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Raise the time budget for this pass, in seconds (all other limits
        /// come from the recorded run and cannot change).
        #[arg(long)]
        timeout_secs: Option<u64>,
    },
}

/// Evidence subcommands.
#[derive(Subcommand, Debug)]
pub enum EvidenceCommand {
    /// Show one section of a stored run, paginated.
    Show {
        /// Run id (see `vortex runs list`).
        run_id: String,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Section to show: overview, summary, findings, relationships,
        /// limitations, unknowns, warnings, or errors.
        #[arg(long, default_value = "overview")]
        section: String,
        /// 1-based page number.
        #[arg(long, default_value_t = 1)]
        page: usize,
        /// Items per page (bounded by the configured maximum).
        #[arg(long)]
        page_size: Option<usize>,
    },
    /// Export a stored run to a standalone, validatable JSON file.
    Export {
        /// Run id to export.
        run_id: String,
        /// Output file path.
        #[arg(long)]
        out: PathBuf,
        /// Export format (only `json` is supported).
        #[arg(long, default_value = "json")]
        format: String,
    },
}

/// MCP subcommands.
#[derive(Subcommand, Debug)]
pub enum McpCommand {
    /// Serve the Model Context Protocol over stdio.
    Serve,
}
