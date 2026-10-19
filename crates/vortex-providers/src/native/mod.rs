//! Structural parsers for native binary formats (ELF, PE/COFF, DEX).
//!
//! Scope and honesty rules for everything in this module:
//!
//! * Parsers are **structural only**: headers, tables, and name lists read
//!   directly from bytes. There is no disassembly, decompilation, or
//!   emulation here, and none may be added without a new provider and its
//!   own review.
//! * Every table access is bounds-checked against the bytes actually read;
//!   a table that falls outside the read prefix is reported as unavailable
//!   with a reason, never guessed at.
//! * Parsers return plain data structures; findings are emitted by the
//!   built-in provider so origins and locations stay consistent with every
//!   other analysis.
//! * Nothing in this module allocates proportional to attacker-controlled
//!   counts: a header may claim a billion sections, but the bound checks
//!   reject anything that does not fit in the buffer that was read.

mod reader;

pub mod dex;
pub mod elf;
pub mod pe;
