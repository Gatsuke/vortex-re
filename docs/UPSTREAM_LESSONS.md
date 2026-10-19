# Upstream Lessons: What 2,098 REA Issues Teach Vortex-RE

Status: research report — October 2026
Method: all 2,098 issues (652 open, 1,446 closed) of
`morluto/rea` were fetched via the GitHub API and analyzed; 33 of the most
instructive were read in full. This document records the failure patterns we
must avoid, what we already do differently, the concrete fixes this research
produced in our own code, and the prioritized backlog it informed.

Vortex-RE competes with REA on architecture, not on their bugs. Most of what
follows is a catalog of *hard-won* lessons from a project that pioneered the
"evidence-backed reverse engineering for agents" category; we read their
tracker with respect, and we steal their lessons, not their code.

## Reading the tracker: what the numbers say

| Signal | Observation | Implication for Vortex-RE |
| --- | --- | --- |
| 2,098 issues, ~1,446 closed | REA's bug intake is enormous for a young project | Their issue *quality* is the real asset: typed outcomes, controls, minimal reproductions. Our CONTRIBUTING should keep encouraging (not requiring) that style. |
| `area:` labels cover runtime/domain/native/mcp/evidence/cli | Every surface has real bug pressure | Our small MVP surface (10 CLI commands, 7 MCP tools, 1 provider) is a feature; grow it slowly with tests per surface. |
| Heaviest recurring themes: evidence-model (1,698), JS analysis (1,629), MCP ergonomics (1,422), output bounding (1,315) | The hard problems cluster exactly where we operate | The five lesson sections below are ordered by how much they matter to us. |
| Node/V8-specific failures (heap OOM #1563, RangeError #1380, V8 string limit #1331) | The runtime is a recurring liability | Our single static Rust binary is the right differentiator; guard it. |

## Lesson 1: Resource limits must degrade, never crash (REA #1563, #1380, #1847, #1911, #1801)

**Their failures.** A public Bun module exhausted the bounded heap and
terminated the CLI *and* the MCP server (exit 134). A 9.4 MB inline
`sourceMappingURL` overflowed V8's regex engine and aborted the whole
analysis. Admission control reserved 80% of the parent budget for "any later
file," discarding a completed file's results. A 256x per-byte representation
charge exhausted a 64 MiB budget at ~256 KB of IL and returned *zero* types.

**Our state.** Rust has no V8 heap; our walk enforces file-count and
byte budgets with truncation-forces-partial. But their deeper lesson is
generic: **every budget must have a graceful degradation path, and the
degraded result must keep what already succeeded.**

**Actions.**
- [x] Verify huge single-line inputs (giant inline source maps, minified
      bundles) hit our line/max-file-bytes limits and produce `partial`
      runs rather than failure — covered by existing limit tests; the
      fixture now also carries a realistic minified line.
- [x] Fuzz-ish adversarial corpus in CI (REA's five bugs were all real-world
      artifacts): one giant line, one deep directory tree, one pathological
      package graph. (Shipped with Phase Two; extended for archives/natives
      in Phase Three and source maps/bindings in Phase Four.)
- [x] When a semantic-analysis phase arrives (Phase 4), budget by AST-node
      count and degrade to syntax-only + limitation, never discard completed
      files (the #1911 lesson). (Shipped with Phase Four, deliberately
      without an AST: the binding layer stays token-level by design, and
      budgets are bytes, segments, and statements — every degradation keeps
      completed work and records a limitation.)

## Lesson 2: Output bounding protects the agent's context window (REA #1850, #1964, #144, #723, #1050, #1065)

**Their failures.** A focused class search returned one match plus the
complete 7,096-class inventory inline (382 KB). Provider-wide limitations
were copied onto *every* node and `truncated: true` on every trace,
destroying the signal. Truncation flags stayed `false` while truncating.
139 tool definitions cost 2 MB at discovery; one small result was repeated
4.2x across representations.

**Our state.** We bounded results and paginate from day one (7 lean tools,
`max_entries` caps, honest truncation flags). Their lessons refine ours:

**Actions.**
- [x] Limitations must be scoped to what they actually limit. Our
      `javascript_scan_limitation` is run-scoped and text explains scope;
      per-relationship notes carry per-edge reasons. No blanket propagation.
- [x] Truncation always visible: read truncation emits per-file limitation
      notes and `read_truncated` flags on findings (the #144 lesson).
- [ ] Caller-selected views over large retained results (REA #1050's design)
      — our pagination is the primitive; add facet selection when results
      grow. (Backlog, Phase 3.)
- [x] Keep a budget test: assert a pathological fixture's MCP response stays
      under a fixed byte ceiling. (Shipped with Phase Two as the bounded-output
      regression guard; extended by the Phase Four map/binding caps.)

## Lesson 3: Cancellation and lifecycle rigor (REA #1746, #4009, #4005, #1719, #4436)

**Their failures.** A cancelled import still committed records into the live
session. Cancellation during finalization produced *successful* Evidence.
SIGINT during cleanup emitted success-shaped output. A cached "open" success
short-circuited without a live provider client, leaving later calls hanging.
A schema tweak changed record identity and old bundles were rejected as
"integrity mismatch" with a misleading message.

**Our state.** Our runs are fast and synchronous; no in-flight cancellation
window exists yet, and stale `running` records are already recovered as
`failed` at startup (tested). The REA lessons become our design rules for
Phase 2+:

**Actions (design commitments, documented here first).**
- [ ] Cancellation must be checked **before commit boundaries**; a cancelled
      run can never mutate stores or emit `succeeded`. (Phase 2, when
      timeouts/cancellation land for long runs.)
- [ ] Completed partial work under cancellation is labeled `cancelled` with
      the valid findings retained — never reclassified as success (#4009).
- [ ] Run-record identity (IDs, digests) must never silently change across
      releases; schema evolution gets a versioned migration path and old
      records import with an explicit `older_schema` note instead of an
      "integrity mismatch" accusation (#4436). Our schema_version field
      exists for exactly this.
- [ ] Any future session/provider cache must reflect *liveness*, not recorded
      identity (#1719).

## Lesson 4: Static-analysis honesty — the JS chapter (REA #1781, #1782, #3895, #3896, #4001, #4632, #4853, #4893, #2326, #2259)

This is where the research paid off immediately: **four of their bugs existed
in our own resolver.**

| REA failure | Our audit finding | Status |
| --- | --- | --- |
| #1781 `sourceMappingURL` truncated at `*` by regex | Our line scanner kept the whole remainder — but swallowed trailing same-line comments into the URL | **Fixed**: URL now ends at first whitespace (ECMA-426 semantics); `*` preserved; tests guard both |
| #1782 percent-encoded local map URLs unresolvable | Same bug in our `resolve_relative_reference` | **Fixed**: query/fragment stripped, path percent-decoded exactly once (`%2520` names a file containing `%20`); declared URL kept verbatim in evidence |
| #3896 `package.json` `main` ignored for directory resolution | Same gap: `./pkg` only probed `pkg/index.js` | **Fixed**: `main` resolved before `index.js`, inside the root; escaping `main` is ignored (path safety) |
| #3895 directory index beat a sibling file | Our order was already correct (`dep.js` before `dep/index.js`) | Regression test added |
| #4632 `require("@scope")` stayed external despite `node_modules/@scope/index.js` | We never looked in `node_modules` at all | **Fixed**: Node-style walk-up `node_modules` resolution (scoped packages, subpaths, `main`, nearer-dir shadowing); resolved edges become internal with a truthful note |
| #2259 silent coverage loss (PDB never applied, no limitation) | Our external-package notes claimed "not installed locally" without checking, and "node_modules absent" without looking | **Fixed**: notes now state exactly what was searched; vendored deps resolve to their real entry files as internal edges |

Also implemented from their positive lessons: the fixture now ships a
vendored `node_modules/tiny-dep` (with `main`, no `index.js`) so the golden
tests permanently exercise the new resolution; `minimist` stays deliberately
unvendored to keep the external case honest.

**Rules adopted for future analyzers (from #4853, #4893, #2326, #4001):**
- Unresolvable semantics are `inferred` with a limitation — never `observed`
  with `exact` confidence (the `Map.get` endpoint fiasco).
- "Complete" means complete: parse coverage must not conflate "unclassifiable
  findings" with "incomplete parse"; every non-complete status carries a
  named reason.
- Directive-prologue string literals are content (our line-oriented scanner
  sees them naturally; a fixture case is on the backlog).
- When a target references companion files we do not load, say so in
  limitations (our dangling source-map references already record unresolved
  refs with reasons).

## Lesson 5: Evidence identity and CLI/MCP parity (REA #1724, #3219, #1364, #4436)

**Their failures.** Different caller requests produced *identical* evidence
IDs because parameters were dropped from the record. Reversed record order
in a caller-supplied bundle produced "unreadable output" instead of parsing.
The MCP path dropped input refinements so the same bad request that the CLI
rejected as `invalid_request` returned `unreadable_output` over MCP.

**Our state.** CLI and MCP share one service layer (asserted by parity
tests), and run records include operation parameters. Their lessons sharpen
our contracts:

**Actions.**
- [x] Evidence identity includes the full request parameters — verified by
      the existing run-store tests (same input + different parameters must
      never collide); keep it that way in every future operation.
- [ ] Import tolerance: when `evidence import` of foreign/older bundles
      lands, accept non-canonical field order with precise validation
      errors (Phase 3).
- [ ] Parity test per error code: same invalid input through CLI and MCP
      must yield the same structured error (extend the existing MCP
      protocol tests; Phase 2).

## Lesson 6: Diagnostics honesty (REA #3179, #3944, #1338)

**Their failures.** Doctor passed version validation on malformed provider
property files. Setup recovery on Windows recommended installing software
that the same binary then rejects as unsupported for the platform. A bundled
skill told agents to run `tool@latest`, which failed the tool's own doctor.

**Our state.** `vortex doctor` reports real checks with per-check status,
and hints are platform-aware. Commitments:
- [ ] Doctor unit tests must include *malformed* inputs (truncated config,
      garbage properties), not just happy paths. (Backlog, Phase 2.)
- [ ] Every recovery hint must be filtered by current-platform support
      (#3944's exact failure mode).
- [ ] Never recommend `@latest` in any documented command; pin versions.

## Lesson 7: Their issue culture is worth imitating

REA's reports are the best in this niche: typed outcomes, minimal
source-owned fixtures, control experiments, honest scope statements, and
"reproduction completeness" declarations. Two of their recurring reporters
(coygeek, N0zoM1z0) file what are effectively mini research papers. Our
CONTRIBUTING.md already asks for reproducers; we should also adopt the
"expected source / failure source / evidence provenance / local
verification" framing in issue templates.

We also observed the cost of their openness: verbatim-duplicate issues and
PR-shaped comments advertising code that does not exist (observed on REA
#5117/#5118 the same week). Our issue templates should ask for verification
status up front, which makes such noise easier to triage.

## Backlog summary (ordered by value)

1. **Phase 2 (reliability):** cancellation-before-commit rules; parity
   error-code tests; doctor malformed-input tests; response-size budget
   test; adversarial artifact corpus.
2. **Phase 3 (broader static analysis):** caller-selected views; import
   tolerance for foreign bundles; ASAR/archive extraction threat-model pass;
   directive-prologue fixture case.
3. **Phase 4+ (deep investigation):** node-budgeted semantic phase with
   graceful syntax-only degradation; inferred-with-limitation classification
   discipline for anything semantic.
4. **Standing rules:** limitations scoped to what they limit; complete means
   complete; evidence identity includes parameters; notes state what was
   searched, not what was assumed.

## Provenance

- Source: `morluto/rea` issues 1–5118 (fetched 2026-10-18 via GitHub REST
  API; 2,098 non-PR issues retained, PRs excluded).
- Analysis artifacts (not part of the repo): theme categorization and the
  33-issue deep-read selection live in the workspace research scratch area.
- Every "Fixed" row above is backed by tests in
  `crates/vortex-providers/src/javascript/resolve.rs`,
  `crates/vortex-providers/src/javascript/scanner.rs`,
  `crates/vortex-providers/src/builtin.rs`, and the regenerated golden
  fixtures in `fixtures/expected-results/`.
