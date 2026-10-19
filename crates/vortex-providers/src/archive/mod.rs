//! Archive member access (zip-family containers, asar) — read-only and
//! in-memory.
//!
//! The safety decision made here, once, for every archive format: Vortex-RE
//! **never writes archive contents to disk**. Members are decompressed into
//! memory under hard caps (`max_archive_member_bytes` per member, the run's
//! byte budget in total) and everything else about a member is metadata
//! from the central directory. This removes the classic extraction attack
//! surface — path traversal writes, symlink planting, permission bits,
//! filesystem encoding quirks — by not having an extraction step at all.
//! Hazardous member *names* and attributes are still reported as findings,
//! because "would be dangerous to extract" is worth saying even when we
//! never extract.
//!
//! Other standing rules:
//! * compression methods are whitelisted (stored, deflate); anything else
//!   is reported as unsupported for that member, never silently skipped;
//! * archives are never recursed into automatically — a zip inside a zip is
//!   a listed member, not an implicit deep inspection;
//! * decompressed bytes count against the run's byte budget like any other
//!   read.

pub mod asar;
pub mod zip_reader;

/// The bounded outcome of reading one archive member (zip or asar).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberRead {
    /// The member's content, fully read (`len` ≤ both caps).
    Full(Vec<u8>),
    /// The member is larger; only the first bytes were produced.
    Truncated(Vec<u8>, u64),
    /// The member could not be read at all (absent, unsupported method,
    /// encrypted, unpacked, budget exhausted, ...).
    Failed(String),
}
