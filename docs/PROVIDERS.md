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
| Timeouts | The service applies the effective time budget (flag > config-file per-provider `timeout_secs` > default) and passes it in the request |
| Cancellation | Check `stop_reason()` (deadline + cancel token) at safe checkpoints |
| Checkpoints | Long directory runs call the checkpoint sink at safe boundaries so the durable record can be resumed (`vortex runs resume`) |
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
| `identify_binary_formats` | Implemented + tested (magic bytes: ELF, Mach-O 32/64/fat, PE, ZIP, gzip, PNG, JPEG, GIF, PDF, WASM, DEX, SQLite, tar; asar by structural check) |
| `extract_strings` | Implemented + tested (ASCII printable runs, bounded, redacted) |
| `parse_package_manifest` | Implemented + tested (tolerant `package.json`) |
| `parse_javascript` | Implemented + tested (line-oriented heuristic scanner) |
| `inspect_archives` | Implemented + tested (zip/jar/apk member listing, safety observations, bounded in-memory reads; asar listing) |
| `parse_elf` | Implemented + tested (32/64-bit, both endians; header, sections, `.dynsym` undefined symbols) |
| `parse_pe` | Implemented + tested (PE32/PE32+ headers, sections, imports/exports, .NET CLI metadata inventory) |
| `parse_dex` | Implemented + tested (header, counts, verified adler32, class inventory; inside APKs too) |

### What `builtin-static` deliberately does NOT do

* Disassembly or decompilation of native executables — of ELF and PE, what
  ships is **structural parsing**: headers, sections, import/export name
  lists, and (for .NET) a metadata inventory. Identifying an ELF and
  extracting its strings is honest work; pretending to "analyze" it
  further would not be. Deeper native analysis reports an explicit
  `unsupported_operation` error naming the missing native-analysis
  provider (Mach-O and WASM today). The run status is `partial`.
* **Archive extraction to disk — of any format.** Members are read in
  memory under hard caps; nothing target-derived is ever written to the
  filesystem. See the archive section of `docs/THREAT_MODEL.md` for the
  reasoning and the hazard list.
* Recursive archive descent: a zip inside a zip is a listed member, not an
  implicit deep inspection.
* Text search inside archive members (roadmap candidate, not shipped).
* Compression methods beyond stored and deflate — reported per member as
  unsupported, never silently skipped.
* Package `exports`/`imports` map resolution, TypeScript path aliases,
  pnpm-style symlinked `node_modules` layouts, or runtime behavior of any
  kind. Static references only; runs say so. What *is* resolved, Node-style:
  relative specifiers probe `name`, `name.js`, `name.json`, then (for
  directories) `package.json` `main` and `index.js`; bare specifiers probe
  `node_modules/<name>` walking up from the referring file (scoped packages
  and subpaths included). A lone `@scope` resolves through
  `node_modules/@scope/` exactly like real Node. `sourceMappingURL` and HTML
  `src` references resolve relative to the referring file with URL
  semantics: query/fragment stripped, path percent-decoded once.

## Not available yet (planned integrations)

Nothing in this table is available, and Vortex-RE does not claim otherwise
— `vortex doctor` reports every one of them as not integrated. Each row
requires its own technical + license review before integration; an adapter
interface is not a completed integration.

| Provider | Would add | Key questions to resolve first |
| --- | --- | --- |
| **Rizin-based native analysis** | Disassembly, symbols, xrefs for ELF/PE/Mach-O | **Review (2026-10, documented not decided):** rizin is LGPL-3.0(+); linking it into the Rust binary (static or dynamic) triggers LGPL relinking obligations that conflict with shipping a static musl binary; wrapping the CLI as a subprocess avoids the linking question but adds process supervision, output bounding, and a supply-chain surface (which rizin? whose build? verified how?). Integration would also be the first *optional, system-provided* dependency, which needs its own doctor story. Decision: deliberately deferred — revisit when a concrete use case justifies the operational surface, or when a permissively-licensed engine is evaluated instead (e.g. capstone-based parsing under a new provider) |
| **Ghidra integration** | Deeper native analysis, decompilation via headless Ghidra | Apache-2.0 license is workable, but JDK is a heavyweight runtime prerequisite; process supervision; output bounding |
| **.NET assemblies** | *Shipped as inventory (PE/CLI metadata).* Deeper: CIL member inventory, type references | Deployment forms (single-file, IL2CPP, NativeAOT) need different parsers; which forms to support next |
| **Android DEX/APK** | *Shipped (header, counts, verified checksum, class inventory; APK member access).* Deeper: method-level analysis, resource (AXML/ARSC) parsing | AXML/ARSC parsing is its own format family with its own ambiguities |
| **Firmware extraction** | Blob carving, filesystem identification | Extraction safety review (this is where archive handling rules get defined) |
| **Browser / process observation** | Runtime behavior (authorized targets) | Phase Five territory: target selection, permissions, audit, timeouts, cleanup — a completely different security posture from static analysis |

### Runtime dependency reality

* **Build dependencies**: a stable Rust toolchain and crates.io access.
* **Runtime dependencies**: none beyond the `vortex` binary for everything
  shipped today. The archive reader uses the `zip` crate compiled with
  only stored+deflate support (pure-Rust `zlib-rs` backend — no C code in
  that path; every other method is honestly reported as unsupported per
  member).
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
