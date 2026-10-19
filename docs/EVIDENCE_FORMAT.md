# Evidence Format (Schema Version 2)

Every Vortex-RE investigation produces an **evidence run**: a JSON document
that is persisted locally (`<data_dir>/runs/<run_id>.json`), served through
the CLI and MCP, and exportable byte-for-byte (`vortex evidence export`).
Storage format and export format are identical, so any stored run can be
validated independently of the tool that wrote it.

* Schema version: **2** (`schema_version` field)
* Serialization: UTF-8 JSON, pretty-printed, trailing newline on export
* Validation: `vortex_evidence::validate::validate_run` — strict on
  invariants (unique finding ids, resolvable evidence references, RFC 3339
  timestamps, 64-hex digests), tolerant of unknown `details` payloads

### Identity stability policy

Schema changes never silently alter run IDs, target digests, or finding
identity. A record written by an older minor version loads unchanged; the
reader annotates it in memory with an `older_schema` load note rather than
rewriting or rejecting it, and `vortex doctor`'s `schema_versions` check
reports which schema versions are present in the store. New top-level
fields are always optional with defaults, so v1 records remain valid v2
documents.

## Top-level record

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | number | `2` |
| `run_id` | string | `run-<uuid v4>` |
| `operation` | string | `inspect`, `search`, or `relationships` |
| `started_at` | string | RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`), second precision |
| `completed_at` | string? | Set once the run reaches a final state |
| `status` | string | `running` \| `succeeded` \| `partial` \| `failed` \| `cancelled` |
| `status_detail` | string? | Why the status is not `succeeded` |
| `target` | object | See below |
| `provider` | object | `{ id, version }` — e.g. `builtin-static` |
| `tool` | object | `{ name, version, invocation }` — invocation is the CLI command line or `mcp:<tool>` |
| `summary` | object | Bounded, operation-specific summary (see per-operation sections) |
| `findings` | array | Ordered findings (see below) |
| `relationships` | array | Ordered edges (see below) |
| `limitations` | string[] | Honest statements of what this run cannot establish |
| `unknowns` | string[] | Open questions requiring verification |
| `warnings` | string[] | Non-fatal problems (unreadable files, malformed manifests, ...) |
| `errors` | object[] | Structured errors `{ code, message, hint?, stage? }` |
| `redactions` | object[] | Applied redactions `{ rule, reason, location? }` |
| `counts` | object | `{ findings, relationships, files_scanned, files_skipped, truncated }` |
| `owner` | object? | Creating process identity (v2): PID and start time, used by crash recovery to ask the OS whether the owner is still alive |
| `limits` | object? | Effective `ResourceLimits` for this run (v2) — every knob that can affect evidence, whatever produced it (defaults, config file, or flags) |
| `params` | object? | Caller parameters that can change findings (v2): `query`, `case_sensitive`, `max_entries`, `max_matches`, `timeout_secs` |
| `checkpoint` | object? | Latest durable walk checkpoint (v2): `{ phase, next_file_index, files_scanned, files_skipped, saved_at, bytes_remaining, matches_remaining? }`. Cleared on `succeeded`; retained on `failed`/`cancelled`/`partial` so the run can be resumed |
| `resumed` | object? | Set when `runs resume` continued this run (v2): `{ attempts, from_checkpoint, previous_status }` |

### Status semantics

* `succeeded` — completed within all limits.
* `partial` — results were produced but a limit or recoverable error was
  hit (truncated output, unsupported deeper analysis, budget exhausted).
* `cancelled` — stopped by user cancellation or the time budget; partial
  findings are preserved.
* `failed` — the operation failed (including runs recovered after a
  crashed process).

Partial findings on failure are intentional: a run that fails after
collecting evidence keeps it.

## Target identity

| Field | Meaning |
| --- | --- |
| `input_path` | Path exactly as the caller provided it |
| `canonical_path` | Canonical absolute path |
| `kind` | `file` or `directory` |
| `sha256` | File content digest, or the directory manifest digest (below) |
| `size_bytes` | File size, or total size of hashed files for directories |
| `file_count` | Number of walked files (directories only) |

**Directory digest**: SHA-256 over the sorted concatenation of
`"<relative_path>\0<file_sha256>\n"` for every regular file within the walk
limits. Deterministic for the same input and limits; if the walk was
truncated, the run records a limitation saying the digest is not a digest
of the complete tree.

## Findings

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Unique within the run: `f1`, `f2`, ... |
| `kind` | string | Finding type (table below) |
| `origin` | string | `observed` \| `derived` \| `inferred` |
| `summary` | string | One-line human-readable statement |
| `location` | object? | `{ file?, line?, column?, byte_offset? }`; paths relative to the inspection root; for single-file targets the root is the file's parent directory |
| `artifact` | object? | `{ path, sha256, size_bytes }` of the file the finding came from |
| `details` | object | Kind-specific structured payload |

### Origin semantics (the point of the whole format)

* **observed** — directly obtained from the artifact bytes or a tool result
  (an import statement's text, a magic byte prefix, a search hit, a
  manifest field).
* **derived** — a documented transformation of observations (resolving a
  specifier to a path; classifying a manifest as Electron because it
  declares the `electron` dependency; "entry point" from `package.json`
  `main`).
* **inferred** — a hypothesis that still needs verification. The
  built-in provider emits these for the Phase Four binding layer
  (token-level, scope-unaware usage sites and unused-import
  conclusions); every one of them carries its caveat in `details`
  and a matching limitation on the run. An `inferred` finding without a
  matching `unknowns`/`limitations` entry is a validation smell.

**No confidence percentages.** There is no defensible measurement method
behind such numbers, so the format does not carry them.

### Finding kinds emitted by the built-in provider

| Kind | Origin | Meaning |
| --- | --- | --- |
| `file` | observed | Single-file target identity (path, size, digest) |
| `format` | derived | Format identification with its basis (`magic_bytes` / `extension` / `content`) and observed magic hex |
| `text_stats` | observed | Line/byte counts for text files |
| `imports_summary` | observed | Per-file import census; raw refs (specifier, line, column, syntax) in `details` |
| `sourcemap_reference` | observed | A `sourceMappingURL` comment (file:line:column + target URL) |
| `json_document` | observed | Valid JSON with top-level key census |
| `sourcemap_document` | observed | A parsed `.map`: version, file/sourceRoot, sources and names listings (exact totals), sourcesContent measured by presence and byte length, segment accounting by exact reason |
| `sourcemap_reconstruction` | derived | What the map maps: per-source aggregates with first/last mappings and segment ordinals as provenance, sample segments verbatim, coverage vs the bundle's line count when paired, and the `file`-field correspondence check |
| `binding_references` | inferred | Imported bindings (ESM and CJS shapes) and their usage sites (call/member/reexport/bare) with line:column locations; scope-unaware by design and labeled so |
| `unused_import_binding` | inferred | Bindings with zero usage sites outside their declaration — the statically-unused imports — with the shadowing caveat spelled out |
| `package_manifest` | observed | Parsed `package.json` facts (name, version, main, deps, ...) |
| `entry_point` | derived | Entry point derived from a manifest `main`/`module` field |
| `classification` | derived | Electron classification derived from manifest dependency declarations |
| `classification_summary` | derived | Aggregate classification signal for directory targets |
| `binary_artifact` | derived | Magic-byte identification of a binary file in a tree |
| `strings_sample` | observed | Bounded printable strings from a binary (values redacted) |
| `search_match` | observed | Literal search hit with redacted context line |
| `elf_header` | observed | ELF identity: class, endianness, type, machine, OS/ABI, entry point |
| `elf_sections` | observed | Section table census (name, type, size, offset; bounded) |
| `elf_imports` | observed | Undefined dynamic symbols from `.dynsym` (bounded) |
| `pe_header` | observed | PE/COFF identity: machine, subsystem, characteristics, timestamp, entry RVA, managed flag |
| `pe_sections` | observed | Section table census with flags |
| `pe_imports` | observed | Import table: DLLs with named functions; ordinals counted |
| `pe_exports` | observed | Exported names (bounded) |
| `dotnet_metadata` | observed | .NET CLI inventory: runtime version, version string, entry-point token, metadata streams |
| `dex_header` | observed | DEX identity: version, file size, all table counts |
| `dex_checksum` | derived | adler32 recomputed vs stored — match, mismatch, or not-verifiable note |
| `dex_classes` | observed | Defined class descriptors (bounded) |
| `archive` | observed | Container census: format, member count, methods, APK shape |
| `archive_members` | observed | Member listing (bounded; zip from the central directory, asar from the JSON header) |
| `archive_safety` | derived | Hazard observations: bomb suspects, traversal/absolute names, symlink members, unsupported methods, encryption |

**Archive member locations.** Findings derived from a member inside an
archive use the `archive!member` notation in `location.file` — for example
`demo-app.apk!classes.dex`. The artifact reference stays the archive
itself (the member's bytes are not separately digested in this release).
Tables that fall outside the bytes actually read are reported as
limitations with reasons, never as absent.

## Relationships

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | `r1`, `r2`, ... |
| `from` / `to` | object | `{ kind, id }` — `kind` is `file`, `package`, `external_package`, `builtin`, `data_uri`, or `external_resource`; `id` is a root-relative path, package name, or builtin name |
| `kind` | string | `imports` \| `exports_from` \| `requires` \| `dynamic_import` \| `declares_dependency` \| `references_sourcemap` \| `references_script` \| `maps_to_source` |
| `scope` | string | `internal` (both endpoints inside the root) or `external` |
| `status` | string | `resolved` \| `unresolved` \| `inline` |
| `resolution_note` | string? | Required whenever `status` is `unresolved`: why (missing file, not installed, builtin, outside root, ...) |
| `origin` | string | Usually `observed` (the statement text was seen); resolution results are `derived` by definition and recorded via `status` + `note` |
| `evidence_finding_id` | string? | Links the edge to the finding that captured the raw statement |
| `location` | object? | File:line:column of the observed statement |

Semantics worth internalizing:

* An import statement is **observed evidence of a static reference**. It is
  not proof of a runtime call path, and runs say so in `limitations`.
* `scope: external, status: resolved` means the reference is fully
  understood without being locally present (a Node builtin, or a dependency
  declared in an inspected manifest). `unresolved` external references
  (undeclared bare imports) also produce an `unknowns` entry.
* Unresolved local references always carry the resolution attempts in
  `resolution_note` (for example, `tried: ./x, ./x.js, ./x.json, ./x/index.js`).
* `maps_to_source` edges are **derived** from a bundle's source map: they
  restate what the map declares about the bundle's build-time inputs,
  resolved on disk when possible. They are not verified runtime
  relationships, and runs say so in `limitations`.

## Comparison output (`vortex compare`)

Comparisons are computed at read time from stored runs; they are not
part of the persisted record. The output carries:

* `findings_only_in_a/b`, `relationships_only_in_a/b` — multiset presence
  diffs, bounded to 100 entries per bucket with exact `totals`.
* `semantic_changes` (Phase Four) — what changed *inside* matched
  findings, computed over the recorded evidence only:
  * `manifest_dependency_changes`: added / removed / `range_changed` /
    `section_moved`, every range string verbatim. No semver interpretation
    is ever applied — a changed range text is never called an upgrade,
    downgrade, or breaking change.
  * `manifests_only_in_a/b`: manifests present in one run only, explicitly
    *not* enumerated per package (the whole declaration set is new or
    absent).
  * `import_changes` per file, `native_symbol_changes` per file
    (symbols, exports, DLLs and per-DLL functions), and `sourcemap_changes`
    as `field: a -> b` text — all informational.
* `notes` — always led by the structural-only disclaimer; when anything
  semantic changed, a second note states that semantic changes describe
  recorded declarations and structure as text, with no behavioral
  meaning and no equivalence claim. Identical runs add no note at all.

## Storage, export, deletion

* Location: `$VORTEX_HOME` (or platform default) / `runs/<run_id>.json`.
  See `vortex doctor` for the effective path on your machine.
* Export: `vortex evidence export <run-id> --out file.json` — writes the
  exact stored record.
* Signed export: `vortex evidence export <run-id> --out file.json
  --signed` — additionally writes an Ed25519 signature sidecar
  (`file.json.sig`) and appends an entry to the export ledger. The keypair
  is generated on first use under `<data_dir>/keys/` (owner-only
  permissions) and announced by `doctor`; the public half is shareable so
  third parties can verify with `vortex evidence verify file.json --key
  <pubkey-hex>`.
* The **export ledger** (`<data_dir>/exports-ledger.jsonl`) is append-only
  and hash-chained: each JSON line carries the SHA-256 of the exported
  payload, of the signature, of its predecessor line, and of itself. It
  detects modification and reordering of past entries. It does **not**
  detect tail truncation, and it is not a substitute for the signature
  when authenticity (not just integrity) is required.
* Delete: remove the JSON file (or the whole data directory). Nothing is
  stored anywhere else; there is no telemetry and no network access.
* Pagination: `vortex evidence show <run-id> --section findings --page 2
  --page-size 20` (page size clamped to 100) and the equivalent MCP
  parameters.

## Versioning

`schema_version` gates the format. Version 2 validation is implemented in
`crates/vortex-evidence/src/validate.rs` and enforced on save and load;
version 1 records load unchanged with an `older_schema` note. Future field
additions within v2 must be optional. Incompatible changes bump the
version and keep the old reader where practical.
