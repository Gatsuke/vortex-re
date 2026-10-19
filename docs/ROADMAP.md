# Roadmap

Phases are ordered deliberately: each one makes the next safer. Nothing on
this page is available until it ships with tests, and `vortex doctor` is
the source of truth for what works in any given release.

## Phase One — working MVP (v0.1.0)

**Goal**: a developer can inspect the bundled JavaScript/Electron fixture,
search it, discover its relationships, retrieve durable evidence through
the CLI or MCP, and verify the findings are correct.

Acceptance criteria (all met; see README "Verifying this release"):

- [x] Rust workspace builds with a committed lockfile.
- [x] CLI with help for every command; meaningful exit codes; JSON output.
- [x] `vortex doctor` reports real capabilities and missing prerequisites.
- [x] Fixture inspection, search, and relationship discovery with expected
      results pinned by golden tests.
- [x] Findings distinguish `observed` / `derived` / `inferred`.
- [x] Evidence persists, paginates, exports, and compares.
- [x] MCP server with seven tools over stdio, tested through a real
      protocol client; CLI and MCP share one service layer.
- [x] Bounded output with reported truncation.
- [x] Malformed inputs produce controlled errors.
- [x] Static analysis only; targets are never executed.
- [x] CI runs fmt/check/clippy(-D warnings)/tests.
- [x] Docs: architecture, threat model, evidence format, providers, MCP.

Known initial limitations (documented, tracked below): comments not
stripped in JS scanning; no archive extraction. The original limitation
"manual crash recovery via `runs recover`" was resolved in Phase Two
(owner-aware automatic recovery; `runs recover` remains as the explicit
override).

## Phase Two — reliability (shipped)

**Goal**: make durability and failure handling boring.

- [x] Automatic detection of stale `running` runs on startup, using the
      recorded owner process to ask the OS whether it is still alive; the
      grace period for undecidable cases is configurable
      (`[recovery] grace_secs`), default one hour.
- [x] Resumable runs for large artifacts: directory `inspect` and `search`
      runs checkpoint the walk position; `vortex runs resume` continues
      from the last durable checkpoint when the artifact is unchanged.
- [x] MCP protocol-level cancellation mapped to run cancellation
      (application-level cancellation exists today). Cancellation rules from
      upstream research (docs/UPSTREAM_LESSONS.md, Lesson 3): check before
      every store commit; a cancelled run never emits `succeeded`; completed
      partial findings are retained and labeled `cancelled`.
- [x] CLI/MCP error-code parity tests: identical invalid input must produce
      the identical structured error through both surfaces.
- [x] Doctor hardening: malformed-input unit tests (truncated records,
      garbage data, schema-version diagnostics), platform-filtered recovery
      hints.
- [x] Response-size budget test: a pathological fixture's MCP response stays
      under a fixed byte ceiling (bounded-output regression guard).
- [x] Adversarial artifact corpus in CI (giant single line, deep tree,
      pathological package graph) — all must produce `partial`, never a
      crash (docs/UPSTREAM_LESSONS.md, Lesson 1).
- [x] Provider timeouts as first-class, per-provider configuration
      (`[providers."<id>"] timeout_secs`).
- [x] Signed/append-only evidence export option (tamper evidence):
      Ed25519-signed exports with `evidence verify`, and a hash-chained
      append-only export ledger.
- [x] Evidence-record identity stability policy: schema changes never
      silently alter run IDs or digests; older records import with an
      explicit `older_schema` note (upstream #4436 lesson). Schema v2
      loads v1 records unchanged.
- [ ] SQLite-backed `RunStore` behind the existing trait if query needs
      outgrow file scanning (deliberately not done for its own sake; the
      trait keeps the door open).
- [x] Config file for persistent limit overrides (`vortex-re/config.toml`
      or `--config`): partial `[limits]`, per-provider timeouts, recovery
      grace. Security-relevant settings stay environment-only.

**Acceptance** (met, verified by the test suite): kill -9 during a run
recovers cleanly on next start with an explanation; cancellation returns
within one checkpoint; partial results never regress.

## Phase Three — broader static analysis (shipped)

**Goal**: more artifact types with the same honesty rules.

- [x] Zip-family containers (zip/jar/apk) — shipped as **bounded, in-memory
      member access** after the safety review concluded that extracting to
      disk is an attack surface better removed than defended: member listing
      from the central directory only, per-member reads capped
      (`max_archive_member_bytes`) and budget-accounted, hazardous names and
      attributes (traversal, drive-qualified, symlink members, bomb
      suspects, unsupported methods, encryption) reported as findings,
      stored+deflate only (pure-Rust backend; other methods honestly
      unsupported per member), no recursive archive descent.
- [x] Electron `asar` archive listing (read-only): header parsed per the
      format the official `asar` tool writes (verified against that tool at
      implementation time), packed member reads bounded and in-memory,
      unpacked members listed but not read.
- [x] PE/COFF structural parsing (PE32 and PE32+): DOS/COFF/optional
      headers, sections, import table (DLLs + named functions; ordinals
      counted not fabricated), export names, RVA mapping through the
      section table — all bounds-checked against the bytes read.
- [x] ELF structural parsing (32/64-bit, both endians): header, section
      table with extended-numbering escapes, undefined dynamic symbols from
      `.dynsym`.
- [ ] Rizin-based native analysis provider — **deliberately open**: the
      license and distribution review is documented in
      `docs/PROVIDERS.md` (LGPL-3 + linking/distribution constraints +
      process-supervision surface); integration deferred until that
      decision is made deliberately, not by momentum.
- [x] Android DEX reading (post zip): header, all table counts, adler32
      checksum verified as a derived observation (only when the whole file
      was read), defined-class list through the documented table chain —
      including `classes*.dex` members inside APKs, with findings located
      at `archive!member` addresses.
- [x] `.NET` PE/CLI metadata inventory: CLR header (runtime version,
      entry-point token, flags) and the BSJB metadata root (version string,
      stream names/sizes). Inventory only — no type system, no CIL.

**Acceptance** (met): every shipped type has fixtures and golden tests
(`apps/vortex/tests/native.rs`, plus committed fixtures under
`fixtures/native/` and `fixtures/archives/`); unsupported depth still
reports `unsupported_operation` honestly (Mach-O and WASM today).

Known limitations (documented, tracked below): text search does not enter
archive members; directory inspection lists native binaries but deep
structural parsing is single-file inspection; the SQLite `RunStore`
remains deliberately open from Phase Two.

## Phase Four — deeper investigation (shipped)

**Goal**: answer harder questions about supported artifacts.

- [x] Source map reconstruction (mapping bundle positions back to
      sources). Shipped as: a dedicated Source Map v3 parser
      (`crates/vortex-providers/src/javascript/sourcemap.rs`) with the
      exact revision-3 continuation semantics, per-segment honest
      degradation, and exact error accounting; structural
      `sourcemap_document` findings for directly inspected maps;
      bundle-paired `sourcemap_reconstruction` findings carrying
      per-mapping provenance (segment ordinals, map identity) and the
      `file`-field correspondence check; and `maps_to_source`
      relationship edges resolved on disk through `sourceRoot`-aware
      joining.
- [x] Call-graph refinement beyond import edges (with explicit
      "static reference, not runtime path" framing). Shipped as: the
      binding layer (`scan_import_bindings` + `scan_binding_usages`,
      token-level and scope-unaware, labeled `inferred` with standing
      caveats), reporting every binding an import introduces and every
      usage site outside its declaration span, plus the
      statically-unused imports with the shadowing caveat.
- [x] Version-to-version structural comparison improvements (semantics
      of dependency changes, not just presence). Shipped as: the
      `semantic_changes` layer on `vortex compare` — per-dependency
      added/removed/range-changed/section-moved with every range
      string verbatim (no semver interpretation, ever), per-file import
      declaration changes, ELF/PE symbol-level changes, and source map
      count changes as text.

**Acceptance** (met): reconstruction results carry per-mapping
provenance — every mapping cites its segment ordinal in the map's
`mappings` string and the map's own identity (path, SHA-256, size) —
and honest error accounting instead of fabricated error rates: exact
per-reason counts of unusable segments, exact coverage statistics
(spanned lines, mapped lines, bundle line count), and the standing
disclosure that the format carries no checksum linkage, so
bundle-map correspondence is never verified, only checked textually
against the `file` field. Comparisons never claim behavioral
equivalence without a verification method — the standing note says
recorded declarations and structure as text, and a test asserts the
words upgrade/downgrade/breaking never appear in the serialized layer.

Known limitations (documented, tracked below): source map
reconstruction does not enter archive members; binding analysis is
scope-unaware by design (disclosed); semver interpretation of range
changes is deliberately absent.

## Phase Five — controlled dynamic analysis

**Goal**: observe authorized targets at runtime — only after the static
foundation is trustworthy.

Before any implementation: a written security model covering target
selection, authorization, scope-limited permissions, auditable operations,
timeouts, and tested cleanup. Candidate capabilities: browser observation,
optional Frida integration, platform tracing. All of it opt-in, separately
packaged if licensing requires.

## Phase Six — controlled patch-and-verify workflows

**Goal**: reversible modification of test artifacts in restricted lab
environments. Furthest out on purpose; requires Phase Two reliability and a
recovery story for anything it touches.

## Not on the roadmap

* Claiming parity or superiority over other tools without a reproducible
  benchmark.
* "Zero dependency" marketing for a multi-platform binary.
* Behavioral-equivalence claims without a verification method.
