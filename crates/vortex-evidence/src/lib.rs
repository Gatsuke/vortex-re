//! Evidence records, persistence, pagination, and comparison.
//!
//! An *evidence run* is the durable record of one investigation operation.
//! Runs are stored as individual JSON documents under the data directory
//! (`VORTEX_HOME`, or the platform default; see vortex-core::config). The
//! storage format is identical to the export format, so any stored run can
//! be read, validated, and diffed by independent tooling.

pub mod compare;
pub mod ledger;
pub mod model;
pub mod pagination;
pub mod store;
pub mod validate;

pub use compare::{compare_runs, RunComparison};
pub use ledger::{LedgerEntry, LedgerStatus, LEDGER_FILE};
pub use model::*;
pub use pagination::{paginate, PageParams, Paged};
pub use store::{FileSystemRunStore, RunStore, RunStoreError};
pub use validate::validate_run;
