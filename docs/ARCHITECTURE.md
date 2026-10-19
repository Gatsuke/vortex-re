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
│   ├── vortex-core/       # Shared vocabulary: errors, limits, config +
│   │                      # config file, digests, path validation, redaction,
│   │                      # time, process identity, Ed25519 signing.
│   ├── vortex-evidence/   # Evidence model (schema v2), validation, the
│   │                      # file-based run store with checkpoints and
│   │                      # owner-aware recovery, pagination, comparison
│   │                      # with the semantic layer, and the append-only
│   │                      # export ledger.
│   ├── vortex-providers/  # Provider abstraction + the built-in static
│   │                      # analysis provider (identification, strings,
│   │                      # JS/JSON/manifest scanning incl. the Source Map
│   │                      # v3 parser and the binding layer, search, walk,
│   │                      # plus native/ and archive/ structural parsers:
│   │                      # ELF, PE/COFF + .NET metadata, DEX, zip, asar).
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
  starts (with owner process and, for directory runs, walk checkpoints),
  so crashed operations stay visible, recoverable, and resumable;
* provider dispatch — explicit, never silently substituting providers;
* evidence retrieval with pagination, export (optionally signed),
  comparison, and resume;
* diagnostics (`doctor`).

Configuration resolution (`VortexConfig::resolve`: environment + optional
TOML config file + flags, in that precedence) lives in `vortex-core` and is
invoked identically by both frontends — the MCP server accepts the same
`--config` flag as the CLI.

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

**Crash recovery** (Phase Two): the durable `running` record also carries
its **owner process** (PID + start time, where the platform provides it).
On the next start, `VortexService::new` asks the operating system whether
each stranded run's owner is still alive: dead owners are marked `failed`
with an explanation immediately; ambiguous cases (unknown platform,
undecidable liveness) wait out a configurable grace period (default one
hour, `[recovery] grace_secs`) or are handled explicitly by `vortex runs
recover`. Long directory runs additionally write a durable **walk
checkpoint** every file, so `vortex runs resume` re-walks, skips to the
recorded index, and continues — reusing the recorded limits and refusing
to resume if the artifact changed (digest mismatch). Recovery is idempotent:
a recovered run is never recovered twice.

## The built-in provider (`builtin-static`)

Capabilities and their implementation:

| Capability | Implementation |
| --- | --- |
| `inspect_files` | Streamed SHA-256, magic-byte format identification, text stats, JS import summary, source map refs, package.json findings, bounded strings extraction for binaries |
| `inspect_directories` | Deterministic bounded walk (sorted DFS, symlinks never followed), per-file identification, extension/format census, manifest + entry-point + Electron classification findings, bounded notable findings |
| `search_text` | Literal search (case-insensitive by default), grep-like one-match-per-line, per-file and global caps, redacted context lines, binary files skipped and counted |
| `trace_relationships` | Import/require/dynamic-import/export-from scanning, Node-style relative resolution (exact / `.js` / `.json` / `index.js`), builtin + declared-dependency classification, source map reference resolution, HTML `<script src>` resolution, `maps_to_source` edges from parsed bundle maps (sourceRoot-aware), the binding layer (`binding_references` / `unused_import_binding`, inferred with standing caveats), unknowns for every unresolved local reference |
| `identify_binary_formats` | Magic-byte table: ELF, Mach-O (32/64/fat), PE, ZIP, gzip, PNG, JPEG, GIF, PDF, WASM, DEX, SQLite, tar; asar by structural pickle shape |
| `extract_strings` | ASCII printable runs, bounded by count and length, redacted |
| `parse_package_manifest` | Tolerant `package.json` parsing; malformed fields become warnings, never aborts |
| `parse_javascript` | Line-oriented heuristic scanner — deliberately not a JS parser; limitations recorded in every run. Phase Four adds on top: the Source Map v3 structural parser (`javascript/sourcemap.rs`, VLQ decoding with revision-3 continuation semantics, honest error accounting) and the binding layer (`scan_import_bindings` + `scan_binding_usages`, token-level and scope-unaware, labeled `inferred`) |
| `inspect_archives` | zip/jar/apk member listing from the central directory only; safety observations (bomb suspects, traversal/absolute names, symlinks, unsupported methods, encryption); bounded in-memory member reads (never disk extraction); asar listing from the JSON header with the official tool's pickle layout |
| `parse_elf` | 32/64-bit, both endians; header, section table with extended-numbering escapes, `.dynsym` undefined symbols; every table bounds-checked against the bytes read |
| `parse_pe` | PE32/PE32+ headers, sections, import table (ordinals counted not fabricated), exports, RVA mapping through sections; .NET CLR header + BSJB metadata stream inventory |
| `parse_dex` | Header, all table counts, adler32 verified as a derived observation when the whole file was read, defined-class list via the documented table chain; inside APKs with findings at `archive!member` locations |

### Honest degradation example

Inspecting a Mach-O binary returns real work (identity, digest, format,
strings) **and** an explicit `unsupported_operation` error plus a limitation
naming the missing native-analysis provider. The run status is `partial`,
and the CLI exits 6. It never fabricates disassembly. A *truncated* ELF or
PE, by contrast, is a different story now that parsers exist: the run
completes with a warning and a limitation saying exactly which structure
could not be read and why.

## Evidence storage

The store is one JSON document per run under `<data_dir>/runs/`, written
atomically (temp file + rename). The storage format **is** the export
format, so exports are independently readable and validatable. The
`RunStore` trait keeps the mechanism swappable — a SQLite-backed store is a
documented future option, not a current claim.

Two more durable files live beside the runs: `<data_dir>/keys/` holds the
Ed25519 signing keypair used by `evidence export --signed` (generated on
first use, announced by `doctor`), and `<data_dir>/exports-ledger.jsonl`
is the hash-chained, append-only ledger of signed exports. Run records are
versioned (`schema_version`); older versions load unchanged with an
`older_schema` note, and run IDs and digests never silently change.

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
`spawn_blocking`; logs go to stderr only. Protocol-level cancellation
(`notifications/cancelled`) is bridged onto the service's `CancelToken`, so
an agent cancelling a request cancels the underlying run; partial findings
are kept and the run is finalized as `cancelled`, never `succeeded`. The
`tests/parity.rs` suite runs identical invalid inputs through both the CLI
and the MCP server and asserts identical structured errors. See
`docs/MCP_INTEGRATION.md`.

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
* Source map reconstruction: the format carries no checksum linkage, so
  bundle-map correspondence is checked textually against the `file`
  field, never verified; maps inside archives are listed, not
  reconstructed; `sourcesContent` is measured by presence and byte
  length, never echoed.
* The binding layer is token-level and scope-unaware by design:
  shadowing can both hide and invent usages (disclosed in every run);
  it never claims runtime call paths.
* Comparisons interpret dependency range changes as recorded text
  only — no semver interpretation, no behavioral claims.
