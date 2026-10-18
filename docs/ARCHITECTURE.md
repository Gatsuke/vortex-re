# Architecture

## Design goals

1. **Evidence-first**: every user-visible conclusion is a record with an
   origin, a location when known, and honest limitations.
2. **One service, two interfaces**: CLI and MCP call the same application
   service, so behavior cannot drift between them.
3. **Bounded output**: results are capped by resource limits, and every cap
   is reported rather than silently applied.
4. **Static only**: inspected targets are never executed.
5. **Small enough to maintain**: no abstraction without a concrete second
   use.

## Workspace layout

```
vortex-re/
├── crates/
│   ├── vortex-core/       # Shared vocabulary: errors, limits, config,
│   │                      # digests, path validation, redaction, time.
│   ├── vortex-evidence/   # Evidence model (schema v1), validation, the
│   │                      # file-based run store, pagination, comparison.
│   ├── vortex-providers/  # Provider abstraction + the built-in static
│   │                      # analysis provider (identification, strings,
│   │                      # JS/JSON/manifest scanning, search, walk).
│   └── vortex-service/    # The application service layer: run lifecycle,
│                          # provider dispatch, evidence retrieval, doctor.
└── apps/vortex/           # The `vortex` binary: clap CLI, human
                           # rendering, and the rmcp MCP server.
```

### Dependency direction

```
vortex-core  (no workspace dependencies)
     ^
vortex-evidence  (depends on core)
     ^
vortex-providers (depends on core + evidence)
     ^
vortex-service   (depends on all three)
     ^
apps/vortex      (CLI + MCP; depends on the service)
```

Nothing depends upward. The app crate is split into a library and a thin
binary so integration tests (`apps/vortex/tests/`) can construct the MCP
server and rendering code directly.

## Why a separate `vortex-service` crate

The task specification described four crates. A fifth — the service layer —
was added for one concrete reason: **CLI and MCP must be thin, interchangeable
frontends over the same operations**. Putting that orchestration in the app
crate would have made it untestable without the binary and temptingly easy
to bypass from UI code. The service crate owns:

* run lifecycle — a durable `running` record is persisted *before* analysis
  starts, so crashed operations stay visible and recoverable;
* provider dispatch — explicit, never silently substituting providers;
* evidence retrieval with pagination, export, and comparison;
* diagnostics (`doctor`).

## Run lifecycle

```
        ┌────────────┐  validate path + policy (allowed roots)
        │  request   │────────────────────────────────────────┐
        └────────────┘                                        │
                                                              v
   compute TargetIdentity (streamed file hash, or directory    │
   manifest digest over the walked tree)                       │
        │                                                      │
        v                                                      │
   create EvidenceRun(status=running) ── save() (durable)      │
        │                                                      │
        v                                                      │
   provider.inspect/search/relationships                       │
   with ResourceLimits + deadline + CancelToken ───────────────┘
        │
        v
   merge ProviderReport into the run, map Outcome to
   Succeeded / Partial / Cancelled, finalize() + save()
```

Failure semantics: analysis-level failures are **in-band** — the operation
returns a status and an errors list, and partial findings are preserved in
the stored record. Only infrastructure failures (invalid arguments, storage
errors) surface as process/tool errors.

**Crash recovery** (initial implementation): a run interrupted by a killed
process stays `running` forever. `vortex runs recover` marks `running` runs
older than the threshold (default 1 hour) as `failed` with an explicit note
that runs are not resumable in this version. Automatic resumption is a
Phase Two roadmap item, not a current claim.

## The built-in provider (`builtin-static`)

Capabilities and their implementation:

| Capability | Implementation |
| --- | --- |
| `inspect_files` | Streamed SHA-256, magic-byte format identification, text stats, JS import summary, source map refs, package.json findings, bounded strings extraction for binaries |
| `inspect_directories` | Deterministic bounded walk (sorted DFS, symlinks never followed), per-file identification, extension/format census, manifest + entry-point + Electron classification findings, bounded notable findings |
| `search_text` | Literal search (case-insensitive by default), grep-like one-match-per-line, per-file and global caps, redacted context lines, binary files skipped and counted |
| `trace_relationships` | Import/require/dynamic-import/export-from scanning, Node-style relative resolution (exact / `.js` / `.json` / `index.js`), builtin + declared-dependency classification, source map reference resolution, HTML `<script src>` resolution, unknowns for every unresolved local reference |
| `identify_binary_formats` | Magic-byte table: ELF, Mach-O (32/64/fat), PE, ZIP, gzip, PNG, JPEG, GIF, PDF, WASM, DEX, SQLite, tar |
| `extract_strings` | ASCII printable runs, bounded by count and length, redacted |
| `parse_package_manifest` | Tolerant `package.json` parsing; malformed fields become warnings, never aborts |
| `parse_javascript` | Line-oriented heuristic scanner — deliberately not a JS parser; limitations recorded in every run |

### Honest degradation example

Inspecting an ELF binary returns real work (identity, digest, format,
strings) **and** an explicit `unsupported_operation` error plus a limitation
naming the missing native-analysis provider. The run status is `partial`,
and the CLI exits 6. It never fabricates disassembly.

## Evidence storage

The store is one JSON document per run under `<data_dir>/runs/`, written
atomically (temp file + rename). The storage format **is** the export
format, so exports are independently readable and validatable. The
`RunStore` trait keeps the mechanism swappable — a SQLite-backed store is a
documented Phase Two option, not a current claim.

Data directory resolution (first match wins):

1. `$VORTEX_HOME`
2. `$XDG_DATA_HOME/vortex-re`
3. `~/.local/share/vortex-re` (Linux), `~/Library/Application
   Support/vortex-re` (macOS), `%LOCALAPPDATA%\vortex-re` (Windows)
4. `./.vortex-re` (flagged by `doctor`)

## MCP server

Built on the official Rust SDK (`rmcp` 3.5) over stdio. Tool input schemas
are generated from typed parameter structs (`schemars`); domain failures are
returned as tool-level error results (`is_error: true`) carrying a
structured JSON error body, so agents can read and react; only protocol
faults become JSON-RPC errors. All tool handlers run the service through
`spawn_blocking`; logs go to stderr only. See `docs/MCP_INTEGRATION.md`.

## Determinism

* Directory walks are lexicographic; findings are emitted in walk order.
* Directory digests hash the sorted `(path, file digest)` manifest.
* Golden tests pin exact relationship edges, finding kinds, and search
  locations for the fixture, and assert two runs of the same artifact
  produce identical findings.

## Deliberate limitations

Documented rather than hidden — each also appears in run output:

* JS scanning is line-oriented; comments are not stripped.
* Symlinks are never followed (recorded as skipped entries).
* The CommonJS resolution subset only; no package `exports` maps.
* No archive extraction (zip/asar) in this release.
* Native binaries: identification and strings only.
