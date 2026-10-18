# Roadmap

Phases are ordered deliberately: each one makes the next safer. Nothing on
this page is available until it ships with tests, and `vortex doctor` is
the source of truth for what works in any given release.

## Phase One — working MVP (this release)

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

Known initial limitations (documented, tracked below): manual crash
recovery via `runs recover`; comments not stripped in JS scanning; no
archive extraction.

## Phase Two — reliability

**Goal**: make durability and failure handling boring.

- [ ] Automatic detection of stale `running` runs on startup (today:
      `vortex runs recover` is manual).
- [ ] Resumable runs for large artifacts (checkpoint the walk position).
- [ ] MCP protocol-level cancellation mapped to run cancellation
      (application-level cancellation exists today).
- [ ] Provider timeouts as first-class, per-provider configuration.
- [ ] Signed/append-only evidence export option (tamper evidence).
- [ ] SQLite-backed `RunStore` behind the existing trait if query needs
      outgrow file scanning (not planned for its own sake).
- [ ] Config file for persistent limit overrides (environment + flags today).

**Acceptance**: kill -9 during a run recovers cleanly on next start with an
explanation; cancellation returns within one checkpoint; partial results
never regress.

## Phase Three — broader static analysis

**Goal**: more artifact types with the same honesty rules.

- [ ] Zip extraction with a hard safety review (bomb limits, member path
      traversal, symlink members) — gates APK/asar work.
- [ ] Electron `asar` archive listing (extraction-adjacent, read-only).
- [ ] PE/COFF and ELF structural parsing (sections, imports) without a
      native engine, where licenses allow.
- [ ] Rizin-based native analysis provider — after the license and
      distribution review described in `docs/PROVIDERS.md`.
- [ ] Android DEX reading (post zip extraction).
- [ ] `.NET` PE/CLI metadata inventory.

**Acceptance**: each type ships with fixtures and golden tests; unsupported
depth still reports `unsupported_operation` honestly.

## Phase Four — deeper investigation

**Goal**: answer harder questions about supported artifacts.

- [ ] Source map reconstruction (mapping bundle positions back to sources).
- [ ] Call-graph refinement beyond import edges (with explicit "static
      reference, not runtime path" framing).
- [ ] Version-to-version structural comparison improvements (semantics of
      dependency changes, not just presence).

**Acceptance**: reconstruction results carry per-mapping provenance and
error rates; comparisons never claim behavioral equivalence without a
verification method.

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
