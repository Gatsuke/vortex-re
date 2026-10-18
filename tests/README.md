# Tests

Rust integration tests live inside each crate, where cargo can compile and
run them per-crate. This directory documents where each suite lives.

| Suite | Location | What it covers |
| --- | --- | --- |
| Unit tests | `crates/*/src/*.rs` (`#[cfg(test)]`) | Digests, path validation, redaction, limits, evidence model, store, pagination, comparison, format identification, string extraction, JS scanning, resolution, manifests, tree walk, search session, provider behavior, service lifecycle, doctor, rendering |
| CLI integration tests | `apps/vortex/tests/cli.rs` | Real binary runs: help, usage errors, exit codes, JSON output contract, evidence lifecycle (inspect → list → show → export → compare), doctor, unicode/space paths, `--no-store`, unsupported formats |
| Golden tests | `apps/vortex/tests/golden.rs` | Fixture must reproduce `fixtures/expected-results/` exactly: relationships, inspection facts, search locations, determinism, evidence validation, redaction, unsupported-format honesty |
| MCP protocol tests | `apps/vortex/tests/mcp.rs` | Real protocol sessions over an in-memory transport (rmcp client): tool discovery, schema validation, paginated results, tool-level vs protocol errors, evidence round trips, comparison disclaimers |

Run everything with:

```bash
cargo test --workspace
```
