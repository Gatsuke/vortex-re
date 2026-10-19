# Tests

Rust integration tests live inside each crate, where cargo can compile and
run them per-crate. This directory documents where each suite lives.

| Suite | Location | What it covers |
| --- | --- | --- |
| Unit tests | `crates/*/src/*.rs` (`#[cfg(test)]`) | Digests, path validation, redaction, limits, evidence model, store (checkpoints, owner-aware recovery, older-schema loads), pagination, comparison, format identification, string extraction, JS scanning, resolution, manifests, tree walk, search session, provider behavior, service lifecycle (resume, signed export, ledger), config file parsing and precedence, signing, doctor, rendering |
| CLI integration tests | `apps/vortex/tests/cli.rs` | Real binary runs: help, usage errors, exit codes, JSON output contract, evidence lifecycle (inspect → list → show → export → verify → compare), doctor, unicode/space paths, `--no-store`, unsupported formats, kill -9 crash recovery, resume, config file behavior and failure modes |
| Golden tests | `apps/vortex/tests/golden.rs` | Fixture must reproduce `fixtures/expected-results/` exactly: relationships, inspection facts, search locations, determinism, evidence validation, redaction, unsupported-format honesty |
| MCP protocol tests | `apps/vortex/tests/mcp.rs` | Real protocol sessions over an in-memory transport (rmcp client): tool discovery, schema validation, paginated results, tool-level vs protocol errors, protocol-level cancellation mapping, evidence round trips, comparison disclaimers |
| Parity tests | `apps/vortex/tests/parity.rs` | Identical invalid inputs through the CLI binary and the MCP server must produce identical structured error bodies; doctor recovery/schema diagnostics; platform-honest recovery hints |
| Adversarial tests | `apps/vortex/tests/adversarial.rs` | Pathological corpus (giant single line, deep tree, pathological package graph, boundary sizes): every case produces bounded `partial` output, never a crash; MCP response-size budget ceiling |
| Native-format tests | `apps/vortex/tests/native.rs` | Golden evidence for the committed native fixtures: ELF64/ELF32 headers, sections, `.dynsym` imports; PE32+/PE32 headers, sections, import tables; .NET CLI metadata inventory; DEX header, verified checksum, class list; asar listing (fixture built by the official `asar` tool); APK → DEX chain with `archive!member` locations; zip safety findings (traversal, absolute, symlink); evidence round trip |
| Archive/native unit tests | `crates/vortex-providers/src/archive/`, `crates/vortex-providers/src/native/` | Zip listing/reads (bombs, caps, budgets, member caps), asar pickle layout (bounded reads, unframed data region, lying headers), ELF/PE/DEX parsers (truncation, lying tables, both endians, big-endian ELF, checksum vectors) |

Run everything with:

```bash
cargo test --workspace
```
