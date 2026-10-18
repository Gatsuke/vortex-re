//! Vortex-RE application crate: the `vortex` CLI and MCP server.
//!
//! The crate is split into a library (for integration tests) and a thin
//! binary. Both the CLI and the MCP server call the same
//! [`vortex_service::VortexService`] operations.

pub mod cli;
pub mod mcp;
pub mod render;
