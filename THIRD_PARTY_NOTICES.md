# Third-Party Notices and Dependency Inventory

Vortex-RE is dual-licensed MIT OR Apache-2.0 (see [LICENSE](LICENSE)). This
file inventories the third-party software it depends on and records
attribution obligations. It was generated from the committed `Cargo.lock`
and hand-annotated with licenses; regenerate the list after dependency
changes (`cargo tree --workspace` plus `cargo metadata`).

## Direct dependencies (runtime)

| Crate | Version | License | Why it is used |
| --- | --- | --- | --- |
| clap | 4.6 | MIT OR Apache-2.0 | CLI argument parsing (derive API) |
| rmcp | 3.5.1 | Apache-2.0 | Official Rust SDK for the Model Context Protocol |
| serde / serde_json | 1.0 | MIT OR Apache-2.0 | Evidence serialization and JSON output |
| sha2 | 0.10 | MIT OR Apache-2.0 | SHA-256 artifact digests (RustCrypto) |
| thiserror | 2.0 | MIT OR Apache-2.0 | Ergonomic structured error types |
| time | 0.3 | MIT OR Apache-2.0 | RFC 3339 timestamps in evidence records |
| tokio | 1.53 | MIT | Async runtime (MCP stdio transport, cancellation) |
| uuid | 1.28 | MIT OR Apache-2.0 | Run identifiers (v4) |

## Direct dependencies (development only)

| Crate | Version | License | Why it is used |
| --- | --- | --- | --- |
| tempfile | 3.27 | MIT OR Apache-2.0 | Isolated test directories |

## Notable transitive dependencies

All transitive dependencies are pulled in by the direct dependencies above
and their licenses are compatible with this project's distribution:

* `rmcp` (Apache-2.0) brings: `schemars` (MIT OR Apache-2.0) for tool input
  schemas, `futures`/`tokio-stream`/`tokio-util` (MIT OR Apache-2.0),
  `pastey` (Apache-2.0), `chrono` (MIT OR Apache-2.0), `base64` (MIT OR
  Apache-2.0), and `rmcp-macros` (Apache-2.0).
* `clap` brings `anstream`/`anstyle` (MIT OR Apache-2.0) for terminal
  styling.
* `tokio` brings `mio`, `libc`/`rustix`, `signal-hook-registry`,
  `socket2`-equivalent platform crates (MIT OR Apache-2.0).
* `time` brings `deranged`, `num-conv`, `powerfmt`, `time-core`,
  `time-macros`, and platform timezone crates (MIT OR Apache-2.0).
* `sha2` brings the RustCrypto `digest`/`crypto-common`/`block-buffer`/
  `cpufeatures`/`generic-array`/`typenum` family (MIT OR Apache-2.0).
* `uuid` brings `getrandom` (MIT OR Apache-2.0).

The full resolved list (124 packages at the time of writing) is recorded in
the committed [`Cargo.lock`](Cargo.lock), which includes names and versions
for every transitive dependency.

## No embedded third-party engines

This release embeds or invokes **no** third-party reverse-engineering
engines. Optional integrations (Rizin, Ghidra, Frida, ...) are future work
and will each require their own technical and license review before being
integrated; see [docs/PROVIDERS.md](docs/PROVIDERS.md). Until an integration
ships with tests, Vortex-RE does not claim its capabilities.

## Trademarks

Product names used in documentation (Electron, Node.js, Ghidra, Rizin,
Frida, IDA, Hopper, and others) are trademarks of their respective owners.
Their appearance here describes interoperability or planned integrations and
implies no endorsement or affiliation.
