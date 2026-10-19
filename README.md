# Vortex-RE

**Local-first AI reverse-engineering toolkit with evidence-backed static analysis, CLI and MCP interfaces.**

Vortex-RE is a single Rust binary that inspects software artifacts **you
own or are authorized to analyze** — without executing them — and turns
what it finds into durable evidence records: findings with origins, source
locations, artifact digests, limitations, and open questions. It works from
the terminal and as a Model Context Protocol (MCP) server for AI coding
agents, through the same core service.

```
What can we establish about how this software works,
what evidence supports each conclusion,
and what still needs to be verified?
```

That question is the product. Vortex-RE answers it with evidence you can
check — and it tells you plainly when it cannot.

---

## The problem

Static analysis for AI agents today tends to fail in one of three ways:

1. **Setup gravity.** Heavyweight engines (disassemblers, JVMs, Node
   toolchains) are needed before the first useful result. Phase One of
   Vortex-RE needs only the binary itself.
2. **Unfalsifiable output.** Agent tools that return plausible conclusions
   without provenance. Every Vortex-RE finding carries an origin
   (`observed` / `derived` / `inferred`), a source location, and the
   digest of what it came from — and runs record what they *could not*
   establish.
3. **Context flooding.** Analyses that return megabytes. Vortex-RE output
   is bounded by explicit resource limits; every truncation is reported,
   and large results are paginated rather than dumped.

Vortex-RE does **not** claim to reverse-engineer every application, recover
original source code, or guarantee behavioral reconstruction. It claims
exactly what its implementation and tests support — see
[Verifying this release](#verifying-this-release).

## Current capabilities (Phases One + Two + Three)

* **Inspect** files and directories: SHA-256 digests, format
  identification by magic bytes (ELF, Mach-O, PE, ZIP, PNG, WASM, DEX,
  SQLite, ...; asar by structural check), text statistics, `package.json`
  manifests, Electron classification, entry points, source map references,
  printable strings (redacted).
* **Parse native binaries structurally**: ELF (32/64-bit, both endians —
  header, sections, `.dynsym` undefined imports) and PE/COFF (PE32/PE32+ —
  headers, sections, import/export tables). Structural only, honestly:
  no disassembly or decompilation, and the runs say so.
* **Inventory .NET assemblies**: runtime version, entry-point token, and
  the metadata streams (`#~`, `#Strings`, `#US`, `#GUID`, `#Blob`) from
  the PE/CLI header — an inventory, not a decompiler.
* **Read Android DEX**: version, table counts, defined classes, and an
  adler32 checksum verification — including `classes*.dex` members inside
  APKs, with findings located at `archive!member` addresses.
* **List archive members** (zip/jar/apk and Electron asar) read-only:
  member listings, APK shape detection from member names, and safety
  observations (compression-bomb suspects, traversal/absolute names,
  symlink members, unsupported methods, encryption). Members are read in
  memory under hard caps — **never extracted to disk**.
* **Search** literal text (case-insensitive by default) across supported
  files with `file:line:column` locations and redacted context lines;
  binary files are skipped and counted.
* **Trace relationships** in JavaScript/Electron artifacts: `import` /
  `require` / dynamic import / `export-from`, declared dependencies,
  source map references, HTML `<script src>` references — each edge with
  scope (`internal`/`external`), resolution status, and the reason when
  unresolved.
* **Durable evidence**: every operation is a versioned run record (schema
  v2), stored locally, paginable, exportable as standalone JSON,
  **optionally Ed25519-signed** with a hash-chained append-only export
  ledger, and comparable across runs.
* **Crash recovery and resumable runs**: a `running` record is durably
  persisted *before* analysis starts and carries its owner process; on the
  next start, runs whose owner is dead are automatically marked `failed`
  with an explanation, and interrupted directory runs can be continued
  from their last checkpoint (`vortex runs resume`).
* **Cancellation everywhere**: Ctrl-C in the CLI and MCP
  `notifications/cancelled` both map onto run cancellation — partial
  findings are preserved and labeled `cancelled`, never `succeeded`.
* **Configuration**: an optional `vortex-re/config.toml` (or `--config`)
  overrides resource limits, per-provider timeouts, and recovery grace;
  unknown keys are rejected by name, all at once. Security-relevant
  settings stay environment-only.
* **Diagnostics**: `vortex doctor` reports what works, what is missing,
  and why — including recovery state, schema versions, the config file,
  and the signing key.
* **MCP server**: seven tools over stdio (official `rmcp` SDK), bounded
  and paginated, tested through a real protocol client; CLI and MCP are
  held to identical error behavior by a parity test suite.
* **Safety**: static analysis only (targets are never executed), symlinks
  never followed, path confinement enforced, best-effort secret redaction,
  no network access.

## Explicitly NOT supported (this release)

* Disassembly/decompilation of native executables — identified and
  string-extracted only; deeper analysis reports `unsupported_operation`.
* .NET assemblies, Android DEX/APK contents, firmware extraction.
* Archive extraction (zip/asar/tar) — deliberately deferred until the
  safety review in `docs/THREAT_MODEL.md` is done.
* Any runtime/dynamic analysis, instrumentation, or patching.
* Recovering original source code; claiming behavioral equivalence.

`vortex doctor` lists all of this at runtime — it is the source of truth
on any machine.

## Architecture overview

```
apps/vortex (CLI + MCP server)   ← two thin frontends
        │
crates/vortex-service            ← one application service layer:
        │                          run lifecycle, dispatch, retrieval
crates/vortex-providers          ← analysis (builtin-static provider)
        │
crates/vortex-evidence           ← evidence model, store, pagination, compare
        │
crates/vortex-core               ← errors, limits, config, digests,
                                   path validation, redaction
```

Full details, run lifecycle, and design decisions: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Prerequisites

* To use the prebuilt npm package on Linux x64: Node.js 16+ (only for the
  launcher; the analysis binary itself is a static executable with no
  runtime dependencies).
* To build from source: a stable Rust toolchain (1.88+). No Node.js, no
  Python, no JVM, no reverse-engineering engines.
* At runtime: nothing beyond the `vortex` binary.

## Build and install

Install the prebuilt package (Linux x64 ships a fully static binary; other
platforms build from the bundled source when a Rust toolchain is present):

```bash
npm install -g vortex-re
vortex doctor
```

Or build from source with a locked, reproducible dependency set:

```bash
git clone https://github.com/Gatsuke/vortex-re vortex-re
cd vortex-re
cargo build --release --locked
# binary: target/release/vortex
```

Prebuilt binaries for each release are also attached to
https://github.com/Gatsuke/vortex-re/releases (with SHA-256 checksums).

The lockfile is committed, so `--locked` builds are reproducible. For a
debug build use `cargo build`; for tests see
[Testing](#testing-instructions).

## Quickstart with the bundled fixture

The repository ships a JavaScript/Electron-shaped demonstration fixture
(`fixtures/javascript-demo`) with known properties — safe to inspect,
never executed, verified by golden tests.

```bash
export VORTEX_HOME=/tmp/vortex-demo        # optional: isolate run storage
./target/release/vortex inspect fixtures/javascript-demo
```

Real output (paths trimmed):

```
Target: fixtures/javascript-demo (directory)
SHA-256: 54ab9de75f4b7988ec614fd3fa613968f2d21267b796355e3c498ca6a7ea5c07
Files: 15 (9 directories, 6.4 KiB total)
Entry point: src/main.js (derived from package.json)
Classification: electron (derived; evidence: package.json declares 'electron')
Source map references: 2

Findings (9):
  [derived] binary_artifact assets/icon.png
      assets/icon.png: png (PNG image)
  [observed] sourcemap_reference dist/bundle.js:2
      dist/bundle.js:2 references source map 'bundle.js.map'
  [observed] package_manifest node_modules/tiny-dep/package.json
      node_modules/tiny-dep/package.json: package manifest for tiny-dep 1.0.0
  [derived] entry_point node_modules/tiny-dep/package.json
      node_modules/tiny-dep/package.json: entry point 'lib/entry.js'
  [observed] package_manifest package.json
      package.json: package manifest for vortex-js-demo 1.2.3
  ...
Run: run-6932a645-934a-4bf1-b756-335c55114f68 (succeeded) — evidence stored; use 'vortex evidence show run-6932a645-934a-4bf1-b756-335c55114f68'
```

Search for the known marker:

```bash
./target/release/vortex search fixtures/javascript-demo VORTEX_DEMO_MARKER
```

```
Query: 'VORTEX_DEMO_MARKER' (case-insensitive)
Matches: 3 across 13 searched file(s)

Findings (3):
  [observed] search_match README.md:16
      README.md:16:26: match 'VORTEX_DEMO_MARKER' (18 bytes)
  [observed] search_match dist/bundle.js:1
      dist/bundle.js:1:245: match 'VORTEX_DEMO_MARKER' (18 bytes)
  [observed] search_match src/main.js:11
      src/main.js:11:21: match 'VORTEX_DEMO_MARKER' (18 bytes)

Limitations (1):
  - 2 binary file(s) were skipped by literal search
```

Trace relationships:

```bash
./target/release/vortex relationships fixtures/javascript-demo
```

```
Relationships: 15 (10 resolved, 5 unresolved)

Edges (15):
  vortex-js-demo --declares_dependency--> minimist [unresolved: declared as '^1.2.8' but not found in any inspected node_mo…]
  vortex-js-demo --declares_dependency--> node_modules/tiny-dep/lib/entry.js [resolved]
  vortex-js-demo --declares_dependency--> electron [unresolved: declared as '^33.0.0' but not found in any inspected node_m…]
  dist/bundle.js --references_sourcemap--> dist/bundle.js.map [resolved]
  src/lib/config.js --requires--> src/lib/defaults.json [resolved]
  src/lib/updater.js --requires--> ./missing-module.js [unresolved: no local file matched './missing-module.js' (tried: src/lib…]
  src/main.js --requires--> src/lib/config.js [resolved]
  src/main.js --requires--> src/lib/updater.js [resolved]
  src/main.js --requires--> node_modules/tiny-dep/lib/entry.js [resolved]
  src/main.js --requires--> minimist [resolved]
  src/main.js --requires--> fs [resolved]
  src/main.js --references_sourcemap--> main.js.map [unresolved: no local file matched './main.js.map' (tried: src/main.js.m…]
  src/renderer/index.html --references_script--> src/renderer/renderer.js [resolved]
  src/renderer/renderer.js --imports--> src/renderer/components/button.js [resolved]
  src/renderer/renderer.js --imports--> ./theme.js [unresolved: no local file matched './theme.js' (tried: src/renderer/the…]
```

(The two unresolved imports are deliberate fixture properties, and they
also appear in the run's `unknowns`. The vendored `tiny-dep` resolves
through `node_modules` exactly like Node would, honoring its `package.json`
`main` — including for bare, scoped, and subpath specifiers.)

Then work with the stored evidence:

```bash
./target/release/vortex runs list
./target/release/vortex evidence show <run-id> --section findings --page 1 --page-size 20
./target/release/vortex evidence export <run-id> --out evidence.json
./target/release/vortex evidence export <run-id> --out evidence.json --signed   # + .sig sidecar
./target/release/vortex evidence verify evidence.json
./target/release/vortex runs resume <run-id>     # continue an interrupted run
./target/release/vortex compare <run-id-a> <run-id-b>
./target/release/vortex doctor
./target/release/vortex capabilities
```

Every command takes `--json` for machine-readable output (clean JSON on
stdout; progress and diagnostics go to stderr).

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | failure (actionable message on stderr) |
| 2 | usage error (invalid arguments) |
| 3 | unsupported operation/format for this input |
| 4 | evidence storage error |
| 5 | cancelled (Ctrl-C, MCP cancellation, or time budget) |
| 6 | partial results (limits hit; evidence is still valid) |

## Configuration

Defaults cover normal use. To make overrides persistent, create a config
file at `~/.config/vortex-re/config.toml` (platform equivalent — see
`vortex doctor`) or pass any file explicitly:

```bash
vortex --config /path/to/config.toml inspect ./my-app
```

```toml
[limits]                       # every key optional; unlisted keys keep defaults
max_entries = 100
timeout_secs = 90

[providers."builtin-static"]   # per-provider settings
timeout_secs = 60

[recovery]
grace_secs = 3600              # age threshold when liveness can't decide
```

Rules the implementation enforces:

* **Precedence**: built-in defaults < `[limits]` in the file <
  `[providers."<id>"]` in the file < command flags.
* **Unknown keys and sections are rejected, all named at once** — a
  silently ignored typo is a misconfiguration you cannot see.
* **Security-relevant settings (`VORTEX_HOME`, `VORTEX_ALLOWED_ROOTS`) are
  environment-only by design**: a file that could weaken a policy is a
  policy downgrade vector.
* The effective limits of every run — whatever produced them — are
  recorded inside the run itself.

## MCP client configuration

`vortex mcp serve` runs the MCP server on stdio. Example client config
(Claude Code, Cursor, and any stdio MCP client):

```json
{
  "mcpServers": {
    "vortex-re": {
      "command": "/absolute/path/to/vortex",
      "args": ["mcp", "serve"],
      "env": {
        "VORTEX_ALLOWED_ROOTS": "/home/you/projects"
      }
    }
  }
}
```

Tools: `vortex_capabilities`, `vortex_inspect_artifact`,
`vortex_search_artifact`, `vortex_trace_relationships`, `vortex_list_runs`,
`vortex_read_evidence`, `vortex_compare_runs` — all bounded and paginated.
Domain errors are tool-level results with structured JSON bodies agents
can read. Full details and a manual smoke test:
[docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md).

## Evidence schema and storage

* One JSON document per run: `$VORTEX_HOME` (or the platform default, see
  `vortex doctor`) → `runs/<run_id>.json`, written atomically.
* The storage format **is** the export format; exports validate
  independently of the tool. Schema is versioned (currently **v2**);
  records written by older versions load unchanged with an explicit
  `older_schema` note — run IDs and digests never silently change.
* Every run records its **effective resource limits** and caller
  parameters, the **owner process** (for crash recovery), and — for
  directory runs — the latest durable **checkpoint** so interrupted runs
  can resume.
* `evidence export --signed` adds an Ed25519 signature sidecar and appends
  to a hash-chained, append-only export ledger (`exports-ledger.jsonl`);
  `evidence verify` checks either against the exporter's public key.
* Findings carry origins (`observed`/`derived`/`inferred`), locations,
  artifact digests; relationships carry scope, resolution status, and
  reasons. No fabricated confidence numbers.
* Delete your data by removing the files/`VORTEX_HOME` — nothing is sent
  or stored anywhere else.

Field-by-field specification: [docs/EVIDENCE_FORMAT.md](docs/EVIDENCE_FORMAT.md).

## Security and privacy

* **Static analysis only.** Inspected targets are never executed; there is
  no shell execution anywhere in the tool.
* Path confinement: resolved references cannot escape the inspection
  root; symlinks are never followed (recorded as skipped).
* Resource limits bound file counts, sizes, output sizes, and time —
  every cap is reported when hit.
* Best-effort redaction masks secret-looking values (documented
  heuristics, not a guarantee) before they reach agent-facing output.
* Tamper evidence: Ed25519-signed exports verify against a public key you
  can hand to a third party; the export ledger's hash chain detects
  modification and reordering of past exports (its honest limits — tail
  truncation, key compromise — are in `docs/THREAT_MODEL.md`).
* No network access, no telemetry.
* Intended for software you own or are authorized to inspect — see
  [DISCLAIMER.md](DISCLAIMER.md).

Full analysis, including residual risks and what Vortex-RE deliberately is
*not*: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Troubleshooting

| Symptom | Do this |
| --- | --- |
| "path not found" | Quote paths with spaces; check the path exists. |
| Exit code 4 (storage) | `vortex doctor` checks the data directory; set `VORTEX_HOME` to a writable location. |
| Exit code 6 (partial) | Expected under limits: raise `--max-entries`/`--max-matches`/`--timeout-secs`, or read the rest via `vortex evidence show`. |
| "unsupported_format" for native binaries | Correct behavior: identification + strings only in this release (see [docs/PROVIDERS.md](docs/PROVIDERS.md)). |
| Runs stuck in `running` | A process died mid-operation. Startup recovery detects dead owners automatically on the next start; `vortex runs recover` is the explicit override (for hung or ambiguous owners). Directory runs with a checkpoint can be continued: `vortex runs resume <run-id>`. |
| MCP client shows no tools | Ensure the command points at the built binary and your client supports stdio servers; check `vortex mcp serve` starts without errors on stderr. |
| Agent reading files you didn't intend | Set `VORTEX_ALLOWED_ROOTS` to fence inspection roots. |

## Testing instructions

```bash
cargo test --workspace             # 284 tests at the time of writing
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The suites: unit tests per crate; CLI integration tests that run the real
binary and assert on exit codes and JSON; **golden tests** pinning the
fixture's exact relationships, findings, and search locations
(`fixtures/expected-results/`); MCP protocol tests driving the server
through an `rmcp` client over an in-memory transport; **parity tests**
asserting CLI and MCP produce identical structured errors; and an
**adversarial corpus** (giant single line, deep tree, pathological package
graph) that must produce `partial`, never a crash. Test map:
[tests/README.md](tests/README.md).

### Verifying this release

The acceptance bar for the MVP, with the evidence that meets it:

| Criterion | Where to verify |
| --- | --- |
| Workspace builds (committed lockfile) | `cargo build --release --locked` |
| CLI help correct | `vortex --help`, per-command `--help` |
| Doctor reports real capabilities | `vortex doctor` (lists unsupported items with reasons) |
| Fixture inspects successfully | Quickstart above; golden tests |
| Search returns traceable matches | `search` output + `expected-search.json` |
| Relationship discovery works | `relationships` output + `expected-relationships.json` |
| Origins distinguish observed/derived | any `--json` output; golden tests assert it |
| Evidence persists and paginates | `runs list` + `evidence show --page` |
| Export valid standalone JSON | `evidence export` + golden tests re-parse it |
| Comparison reports real diffs only | `compare` output carries the structural-only disclaimer |
| MCP server works with 7 tools | MCP protocol tests; manual smoke test in docs/MCP_INTEGRATION.md |
| CLI and MCP share services | single `vortex-service` crate; no analysis code in the app crate |
| Output bounded + paginated | limits tests; MCP pagination tests |
| Malformed input → controlled errors | malformed-manifest tests; CLI error tests |
| Targets never executed | no execution path exists; static-only rule enforced in review |
| kill -9 mid-run recovers cleanly | `kill_nine_mid_run_recovers_on_next_start` (CLI suite) |
| Cancellation preserves partial findings | cancellation tests in the MCP suite; `cancelled` never `succeeded` |
| CLI and MCP agree on errors | parity suite (`tests/parity.rs`) runs both surfaces on identical inputs |
| Signed exports verify | `signed_export_round_trip_through_the_cli` (CLI suite) |
| Config precedence holds | `config_flag_overrides_and_fails_loudly` (CLI suite) |
| ELF/PE structure parses with exact evidence | `native.rs` suite against committed fixtures (`fixtures/native/`), cross-validated with `readelf`/`objdump` at creation |
| .NET metadata inventory works | `dotnet_fixture_yields_cli_metadata_inventory` |
| DEX header, checksum, and classes read | `dex_fixture_yields_verified_header_and_classes` |
| Archive members listed, never extracted | `asar_fixture_lists_official_tool_archive` (fixture built by the official `asar` tool); zip suite |
| APK → DEX chain works | `apk_zip_chain_reaches_dex_members` (findings at `archive!member` locations) |
| Archive hazards reported | `zip_safety_findings_reach_the_report` (traversal, absolute, symlink) + bomb tests |
| Unsupported depth still honest | Mach-O/WASM keep `unsupported_operation`; truncated ELF/PE warn with reasons |
| Tests cover functionality | 284 tests, incl. golden, protocol, parity, adversarial, and native suites |
| No known ignored security issue | docs/THREAT_MODEL.md tracks residual risks explicitly |

## Tested platforms

* **Linux x86_64** — developed and fully tested here (all suites green).
* **macOS, Windows** — CI jobs run the full test suite, but they are
  marked *advisory* until confirmed by a maintainer on real hardware; code
  uses platform-conditional path handling and no Unix-only APIs outside
  `#[cfg(unix)]` tests. Treat support as expected-but-unverified.

## Roadmap

Phase One (v0.1.0, working MVP) → Phase Two (**shipped**: automatic crash
recovery, resumable runs, protocol-level cancellation, signed exports +
ledger, parity tests, adversarial corpus, config file with per-provider
timeouts) → Phase Three (**shipped**: bounded in-memory archive access for
zip/jar/apk/asar with a written safety review — no disk extraction, ever;
structural parsing for ELF and PE/COFF; .NET metadata inventory; DEX
reading with verified checksums, including inside APKs; the Rizin provider
deliberately deferred with its license review documented) → Phase Four
(source map reconstruction, deeper comparisons) → Phase Five (controlled
dynamic analysis) → Phase Six (patch-and-verify labs). Details and
acceptance criteria per phase: [docs/ROADMAP.md](docs/ROADMAP.md).

The roadmap is informed by systematic study of real-world failures in the
category: [docs/UPSTREAM_LESSONS.md](docs/UPSTREAM_LESSONS.md) analyzes
2,098 issues from the upstream project that inspired this space, records
which of those failure modes existed in early Vortex-RE code (and were
fixed, with tests), and lists the standing engineering rules adopted as a
result.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — the short version: claims need
tests, findings need origins, output needs bounds, and unknown is a valid
answer. Security reports follow [SECURITY.md](SECURITY.md).

## License and attribution

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option. Dependency inventory and licenses (including the MCP Rust
SDK, `rmcp`, Apache-2.0): [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Responsible-use terms: [DISCLAIMER.md](DISCLAIMER.md).

Vortex-RE is an independent project. Product names of other tools appear
only to describe interoperability or planned integrations; no endorsement
or affiliation is implied, and no comparison claims are made without a
reproducible benchmark.
