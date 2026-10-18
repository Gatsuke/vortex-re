# Providers

Providers are the only place analysis happens. Everything user-facing —
CLI, MCP, evidence records — consumes their output through the shared
service layer.

## Provider contract

Implemented in `crates/vortex-providers/src/provider.rs`:

| Obligation | Detail |
| --- | --- |
| Identity | Stable `id` + `version` in every run record |
| Capabilities | Declared up front; surfaced by `vortex capabilities` and the `vortex_capabilities` MCP tool |
| Input validation | `validate_request` rejects requests the provider cannot run at all |
| Operations | `inspect`, `search`, `relationships` |
| Structured results | Findings/relationships with origins and locations |
| Errors and warnings | Recovered problems are in-band; fatal ones still preserve partial findings |
| Resource limits | Enforce `ResourceLimits`; every cap hit is recorded and flips the outcome to `partial` |
| Cancellation | Check `stop_reason()` (deadline + cancel token) at safe checkpoints |
| Determinism | Same input + limits → same output |

Two hard rules from the project charter:

1. **No silent substitution.** If a provider fails, the failure is
   surfaced. Vortex-RE never quietly falls back to a different engine.
2. **No fabricated results.** "Not detected because the provider could not
   detect it" is reported as an unknown or limitation, never as an absence
   claim.

## Available now: `builtin-static`

The built-in provider works fully offline on ordinary files. It requires
**no** Node.js, no Python, no JVM, and no reverse-engineining engines.

| Capability | Status |
| --- | --- |
| `inspect_files` | Implemented + tested |
| `inspect_directories` | Implemented + tested |
| `search_text` | Implemented + tested |
| `trace_relationships` | Implemented + tested (CommonJS/ESM scanning, package manifests, source maps, HTML scripts) |
| `identify_binary_formats` | Implemented + tested (magic bytes: ELF, Mach-O 32/64/fat, PE, ZIP, gzip, PNG, JPEG, GIF, PDF, WASM, DEX, SQLite, tar) |
| `extract_strings` | Implemented + tested (ASCII printable runs, bounded, redacted) |
| `parse_package_manifest` | Implemented + tested (tolerant `package.json`) |
| `parse_javascript` | Implemented + tested (line-oriented heuristic scanner) |

### What `builtin-static` deliberately does NOT do

* Disassembly or decompilation of native executables. Identifying an ELF
  and extracting its strings is honest work; pretending to "analyze" it
  further would not be. Inspect reports the format, the strings, and an
  explicit `unsupported_operation` error naming the missing native-analysis
  provider. The run status is `partial`.
* Archive extraction (zip, asar, tar). Not implemented in this release;
  safe extraction needs its own threat-model pass (see
  `docs/THREAT_MODEL.md`).
* Package `exports` map resolution, TypeScript path aliases, or runtime
  behavior of any kind. Static references only; runs say so.

## Not available yet (planned integrations)

Nothing in this table is available, and Vortex-RE does not claim otherwise
— `vortex doctor` reports every one of them as not integrated. Each row
requires its own technical + license review before integration; an adapter
interface is not a completed integration.

| Provider | Would add | Key questions to resolve first |
| --- | --- | --- |
| **Rizin-based native analysis** | Disassembly, symbols, xrefs for ELF/PE/Mach-O | LGPL-3 licensing implications for distribution; native build matrix (capstone, etc.); whether to link, wrap the CLI, or use r2pipe; timeout/output governance |
| **Ghidra integration** | Deeper native analysis, decompilation via headless Ghidra | Apache-2.0 license is workable, but JDK is a heavyweight runtime prerequisite; process supervision; output bounding |
| **.NET assemblies** | PE/CLI metadata, CIL member inventory | Deployment forms (single-file, IL2CPP, NativeAOT) need different parsers; which forms to support first |
| **Android DEX/APK** | DEX parsing, resource inventory | DEX is identified by magic today; real parsing needs a DEX reader plus an archive story (APK is a zip) |
| **Firmware extraction** | Blob carving, filesystem identification | Extraction safety review (this is where archive handling rules get defined) |
| **Browser / process observation** | Runtime behavior (authorized targets) | Phase Five territory: target selection, permissions, audit, timeouts, cleanup — a completely different security posture from static analysis |

### Runtime dependency reality

* **Build dependencies**: a stable Rust toolchain and crates.io access.
* **Runtime dependencies**: none beyond the `vortex` binary for everything
  shipped today.
* **Optional provider prerequisites**: none exist yet. When they do, they
  will be listed here and in `vortex doctor`, including exact versions and
  what breaks without them.

We do not claim the binary "has zero external dependencies across every
platform" — dynamic platform libraries (via Rust's std) are always in play.
What we do claim: no reverse-engineering engines are needed for anything
the current release advertises.

## Adding a provider

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-provider). The short
version: implement the trait, obey the limits, classify your origins
correctly, test against known inputs, document what you do not support,
and pass a license review if you wrap a third-party engine.
