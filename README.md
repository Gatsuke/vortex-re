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

## Current capabilities (MVP, Phase One)

* **Inspect** files and directories: SHA-256 digests, format
  identification by magic bytes (ELF, Mach-O, PE, ZIP, PNG, WASM, DEX,
  SQLite, ...), text statistics, `package.json` manifests, Electron
  classification, entry points, source map references, printable strings
  (redacted).
* **Search** literal text (case-insensitive by default) across supported
  files with `file:line:column` locations and redacted context lines;
  binary files are skipped and counted.
* **Trace relationships** in JavaScript/Electron artifacts: `import` /
  `require` / dynamic import / `export-from`, declared dependencies,
  source map references, HTML `<script src>` references — each edge with
  scope (`internal`/`external`), resolution status, and the reason when
  unresolved.
* **Durable evidence**: every operation is a versioned run record, stored
  locally, paginable, exportable as standalone JSON, and comparable
  across runs.
* **Diagnostics**: `vortex doctor` reports what works, what is missing,
  and why.
* **MCP server**: seven tools over stdio (official `rmcp` SDK), bounded
  and paginated, tested through a real protocol client.
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

* A stable Rust toolchain (1.88+) to build. That's it — no Node.js, no
  Python, no JVM, no reverse-engineering engines.
* At runtime: nothing beyond the `vortex` binary.

## Build and install

```bash
git clone <repository-url> vortex-re
cd vortex-re
cargo build --release --locked
# binary: target/release/vortex
```

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
SHA-256: 5949bd712e1b37c5b17c21e1b7972ab075756eb50f038482d261577f1c476018
Files: 13 (6 directories, 3.5 KiB total)
Entry point: src/main.js (derived from package.json)
Classification: electron (derived; evidence: package.json declares 'electron')
Source map references: 2

Findings (7):
  [derived] binary_artifact assets/icon.png
      assets/icon.png: png (PNG image)
  [observed] sourcemap_reference dist/bundle.js:2
      dist/bundle.js:2 references source map 'bundle.js.map'
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
Matches: 3 across 11 searched file(s)

Findings (3):
  [observed] search_match README.md:16
      README.md:16:26: match 'VORTEX_DEMO_MARKER' (18 bytes)
  [observed] search_match dist/bundle.js:1
      dist/bundle.js:1:245: match 'VORTEX_DEMO_MARKER' (18 bytes)
  [observed] search_match src/main.js:10
      src/main.js:10:21: match 'VORTEX_DEMO_MARKER' (18 bytes)

Limitations (1):
  - 2 binary file(s) were skipped by literal search
```

Trace relationships:

```bash
./target/release/vortex relationships fixtures/javascript-demo
```

```
Relationships: 13 (8 resolved, 5 unresolved)

Edges (13):
  vortex-js-demo --declares_dependency--> minimist [unresolved: declared as '^1.2.8' but not installed locally (node_module…]
  dist/bundle.js --references_sourcemap--> dist/bundle.js.map [resolved]
  src/lib/updater.js --requires--> ./missing-module.js [unresolved: no local file matched './missing-module.js' (tried: src/lib…]
  src/main.js --requires--> src/lib/config.js [resolved]
  src/main.js --requires--> fs [resolved]
  src/renderer/index.html --references_script--> src/renderer/renderer.js [resolved]
  src/renderer/renderer.js --imports--> src/renderer/components/button.js [resolved]
  src/renderer/renderer.js --imports--> ./theme.js [unresolved: no local file matched './theme.js' (tried: src/renderer/the…]
  ...
```

(The two unresolved imports are deliberate fixture properties, and they
also appear in the run's `unknowns`.)

Then work with the stored evidence:

```bash
./target/release/vortex runs list
./target/release/vortex evidence show <run-id> --section findings --page 1 --page-size 20
./target/release/vortex evidence export <run-id> --out evidence.json
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
| 5 | cancelled (Ctrl-C or time budget) |
| 6 | partial results (limits hit; evidence is still valid) |

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
  independently of the tool.
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
| Runs stuck in `running` | A process died mid-operation; `vortex runs recover` marks them failed with an explanation. |
| MCP client shows no tools | Ensure the command points at the built binary and your client supports stdio servers; check `vortex mcp serve` starts without errors on stderr. |
| Agent reading files you didn't intend | Set `VORTEX_ALLOWED_ROOTS` to fence inspection roots. |

## Testing instructions

```bash
cargo test --workspace             # 159 tests at the time of writing
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The suites: unit tests per crate; CLI integration tests that run the real
binary and assert on exit codes and JSON; **golden tests** pinning the
fixture's exact relationships, findings, and search locations
(`fixtures/expected-results/`); MCP protocol tests driving the server
through an `rmcp` client over an in-memory transport. Test map:
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
| Tests cover functionality | 159 tests, incl. golden + protocol suites |
| No known ignored security issue | docs/THREAT_MODEL.md tracks residual risks explicitly |

## Tested platforms

* **Linux x86_64** — developed and fully tested here (all suites green).
* **macOS, Windows** — CI jobs run the full test suite, but they are
  marked *advisory* until confirmed by a maintainer on real hardware; code
  uses platform-conditional path handling and no Unix-only APIs outside
  `#[cfg(unix)]` tests. Treat support as expected-but-unverified.

## Roadmap

Phase One (this release) → Phase Two (reliability: automatic crash
recovery, resumable runs, protocol-level cancellation) → Phase Three
(broader static analysis: safe archive extraction, native structural
parsing, Rizin after license review) → Phase Four (source map
reconstruction, deeper comparisons) → Phase Five (controlled dynamic
analysis) → Phase Six (patch-and-verify labs). Details and acceptance
criteria per phase: [docs/ROADMAP.md](docs/ROADMAP.md).

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
