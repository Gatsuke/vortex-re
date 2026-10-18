# Evidence Format (Schema Version 1)

Every Vortex-RE investigation produces an **evidence run**: a JSON document
that is persisted locally (`<data_dir>/runs/<run_id>.json`), served through
the CLI and MCP, and exportable byte-for-byte (`vortex evidence export`).
Storage format and export format are identical, so any stored run can be
validated independently of the tool that wrote it.

* Schema version: **1** (`schema_version` field)
* Serialization: UTF-8 JSON, pretty-printed, trailing newline on export
* Validation: `vortex_evidence::validate::validate_run` — strict on
  invariants (unique finding ids, resolvable evidence references, RFC 3339
  timestamps, 64-hex digests), tolerant of unknown `details` payloads

## Top-level record

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | number | `1` |
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
* **inferred** — a hypothesis that still needs verification. The current
  built-in provider emits none; the classification exists so future
  providers can mark guesses honestly. An `inferred` finding without a
  matching `unknowns`/`limitations` entry is a validation smell.

**No confidence percentages.** There is no defensible measurement method
behind such numbers, so the format does not carry them.

### Finding kinds emitted by the built-in provider (v1)

| Kind | Origin | Meaning |
| --- | --- | --- |
| `file` | observed | Single-file target identity (path, size, digest) |
| `format` | derived | Format identification with its basis (`magic_bytes` / `extension` / `content`) and observed magic hex |
| `text_stats` | observed | Line/byte counts for text files |
| `imports_summary` | observed | Per-file import census; raw refs (specifier, line, column, syntax) in `details` |
| `sourcemap_reference` | observed | A `sourceMappingURL` comment (file:line:column + target URL) |
| `json_document` | observed | Valid JSON with top-level key census |
| `sourcemap_file` | observed | A `.map` document with `version` + `mappings` |
| `package_manifest` | observed | Parsed `package.json` facts (name, version, main, deps, ...) |
| `entry_point` | derived | Entry point derived from a manifest `main`/`module` field |
| `classification` | derived | Electron classification derived from manifest dependency declarations |
| `classification_summary` | derived | Aggregate classification signal for directory targets |
| `binary_artifact` | derived | Magic-byte identification of a binary file in a tree |
| `strings_sample` | observed | Bounded printable strings from a binary (values redacted) |
| `search_match` | observed | Literal search hit with redacted context line |

## Relationships

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | `r1`, `r2`, ... |
| `from` / `to` | object | `{ kind, id }` — `kind` is `file`, `package`, `external_package`, `builtin`, `data_uri`, or `external_resource`; `id` is a root-relative path, package name, or builtin name |
| `kind` | string | `imports` \| `exports_from` \| `requires` \| `dynamic_import` \| `declares_dependency` \| `references_sourcemap` \| `references_script` |
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

## Storage, export, deletion

* Location: `$VORTEX_HOME` (or platform default) / `runs/<run_id>.json`.
  See `vortex doctor` for the effective path on your machine.
* Export: `vortex evidence export <run-id> --out file.json` — writes the
  exact stored record.
* Delete: remove the JSON file (or the whole data directory). Nothing is
  stored anywhere else; there is no telemetry and no network access.
* Pagination: `vortex evidence show <run-id> --section findings --page 2
  --page-size 20` (page size clamped to 100) and the equivalent MCP
  parameters.

## Versioning

`schema_version` gates the format. Version 1 validation is implemented in
`crates/vortex-evidence/src/validate.rs` and enforced on save and load.
Future field additions within v1 must be optional. Incompatible changes
bump the version and keep the old reader where practical.
