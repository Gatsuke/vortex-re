# Threat Model

## What Vortex-RE is

A local, static-analysis toolkit. It reads artifacts the user points it at,
produces bounded evidence records, and stores them on the user's machine.
It does not execute inspected targets, does not access the network, and
does not embed third-party analysis engines in this release.

## Assets

1. **The user's machine and data** — must not be compromised by analyzing a
   malicious artifact.
2. **Evidence integrity** — records must faithfully describe what was (and
   was not) observed.
3. **Agent context health** — MCP results must be bounded so a hostile
   artifact cannot flood an AI agent's context window.
4. **The user's secrets** — inspected artifacts may contain credentials;
   they must not leak unmasked into agent-facing output.

## Actors and trust

| Actor | Trust level | Notes |
| --- | --- | --- |
| The user running the CLI | Trusted | Full filesystem access is assumed; the tool runs with the user's own privileges. |
| The MCP client / AI agent | Semi-trusted | It chooses paths and queries. Its output budget is protected by caps; its reach can be limited with `VORTEX_ALLOWED_ROOTS`. |
| The inspected artifact | **Untrusted** | Assume an adversary crafted it. |

## Attack surface and mitigations

### 1. Malicious artifact → filesystem escape

**Threat**: import specifiers or reference targets that traverse outside
the inspection root (`../../secrets`), or symlinks planted inside the tree.

**Mitigations**:
* All specifier resolution goes through lexical normalization
  (`vortex_core::paths::normalize_relative`); upward escapes are rejected
  with `path_outside_root`.
* The directory walk never follows symlinks; they are recorded as skipped
  entries with their targets.
* The target itself is canonicalized; FIFOs, sockets, and devices are
  rejected as unsupported targets.
* With `VORTEX_ALLOWED_ROOTS` set, every target must live under a
  configured root — a coarse fence for agent-driven use.

**Residual risk**: the *existence* of files outside the root can be inferred
from error messages (for example, a traversal rejection). That is
informational only; contents are never read.

### 2. Malicious artifact → resource exhaustion

**Threat**: a deep directory tree, a giant file, or endless matches that
hang the process or exhaust memory.

**Mitigations** (all enforced in `ResourceLimits`, defaults in parentheses):
* `max_files` (2,000) files per walk; `MAX_DEPTH` 64 directory levels.
* `max_file_bytes` (8 MiB) per-file read cap; oversize files are skipped
  and reported.
* `max_total_bytes` (128 MiB) read budget across an operation.
* `max_findings` / `max_relationships` (500) / `max_matches` (100) /
  `max_matches_per_file` (20) output caps; every hit cap is recorded as a
  limitation and flips the run to `partial`.
* `timeout_secs` (30) wall-clock deadline checked at safe checkpoints; CLI
  operations also wire Ctrl-C to cooperative cancellation.
* MCP `page_size` is clamped to 100.

**Residual risk**: a crafted artifact can still consume up to the full
budget before being cut off; this is an availability cost, not a
compromise. Hashing streams in 64 KiB chunks, so memory stays bounded.

### 3. Malicious artifact → log/terminal injection

**Threat**: artifact content containing terminal escape sequences or
structured-looking text designed to deceive.

**Mitigations**: search context lines are trimmed and byte-capped; JSON
output is produced by a serializer, not string concatenation. Human output
does not interpret control sequences.

**Residual risk**: text from the artifact is displayed as-is after
trimming (minus redactions). Consumers should treat it as data, which is
also true of any source-viewing tool.

### 4. Secrets leakage

**Threat**: an artifact contains credentials (`.env` files, embedded keys);
they end up in agent-facing output or stored evidence.

**Mitigations**:
* Best-effort redaction (`vortex_core::redact`) masks values after
  secret-looking keys (`password`, `api_key`, ...), AWS-style `AKIA…`
  ids, `Bearer` tokens, and PEM private-key headers before they reach
  findings; every application is recorded as a `redactions` entry.
* Search context lines pass through the same redactor.
* Redaction is **local, in-process**; nothing is sent anywhere.

**Residual risk (documented, not hidden)**: the patterns are heuristics.
Unusual key names, split secrets, or encodings the patterns do not
recognize will pass through. Raw evidence stays in the local store and in
exports; exports share the redacted form of what the run emitted. Do not
publish exports of artifacts that may contain secrets.

### 5. Agent-driven misuse

**Threat**: a confused or malicious agent uses Vortex-RE to read files the
user did not intend.

**Mitigations**: `VORTEX_ALLOWED_ROOTS` restricts all interfaces to the
configured roots; without it, the tool has the same filesystem reach as the
user running it (identical to any local tool). The MCP server never
executes targets or shells out, so the tool itself grants no execution
capability.

**Residual risk**: without `VORTEX_ALLOWED_ROOTS`, an agent can point the
tool at any file readable by the user. Treat MCP tool permissions in your
client accordingly.

### 6. Evidence tampering

**Threat**: someone edits stored run records to change conclusions.

**Mitigations**: records carry the artifact digest and provider/tool
versions, and `vortex evidence export` output can be re-validated with the
same schema rules. Run files are written atomically. For tamper evidence,
`evidence export --signed` produces an Ed25519 signature sidecar
verifiable by any third party holding the exporter's public key
(`evidence verify`), and every signed export appends to a hash-chained,
append-only ledger (`exports-ledger.jsonl`) whose `doctor` check reports
the chain's health.

**Residual risk**: the store is plain JSON on local disk with local file
permissions — anyone with write access to the data directory can edit
unsigned records. The ledger detects modification and reordering of past
entries, but **not** truncation of the ledger's tail, and a compromised
signing key can sign anything. The tool is not a notary; if an adversary
controls the machine, use an external signature made off-box.

### 7. Config-file policy weakening

**Threat**: a writable config file is used to weaken safety posture
silently (for example, loosening limits so an agent can hammer a target,
or repointing storage).

**Mitigations**: the config file can only tune resource limits,
per-provider timeouts, and recovery grace — it cannot set `VORTEX_HOME` or
`VORTEX_ALLOWED_ROOTS`, which are environment-only by design. A file that
could weaken a policy is a policy downgrade vector. Unknown keys and
sections are rejected by name (all at once), so a typo cannot silently
disable a limit. The effective limits of every run are recorded inside the
run itself, and `doctor` reports which config file was applied.

### 8. Archive handling safety review (Phase Three, shipped)

Phase Three added member access for zip-family containers and Electron
asar archives. The hazards considered, and the decisions:

| Hazard | Decision |
| --- | --- |
| Zip bombs (high compression ratio) | Reads are capped by `max_archive_member_bytes` per member and by the run byte budget in total; a member declaring more than the cap is read only up to the cap and the truncation is a recorded limitation. Ratios ≥ 100× on members ≥ 1 MiB are flagged as derived `compression_bomb_suspect` findings with the observed numbers. |
| Member path traversal (`../../x`) | Nothing is ever written to disk, so traversal cannot escape — the write step does not exist. Names with `..` components are still flagged as findings, because "would be dangerous to extract" is evidence worth having. |
| Absolute / drive-qualified member names | Same reasoning: flagged, never used as a path. |
| Symlink members | Never created and never followed; unix mode bits are inspected and symlink members are flagged. |
| Unsupported compression methods | Whitelist: stored and deflate (pure-Rust `zlib-rs` backend, no C). Everything else is listed with metadata only and reported as unsupported per member — never silently skipped and never "supported" via a C library we have not reviewed. |
| Encrypted members | Flagged; content is honestly unreadable without a password. |
| Nested archives (zip in zip) | No recursive descent: a nested archive is a listed member, not an implicit deep inspection. The user can inspect it explicitly. |
| Lying headers (huge declared sizes/counts) | Every table access is bounds-checked against the bytes actually read; declared sizes above the file length or the read cap are rejected or truncated-with-note, never trusted for allocation. |
| Resource use during listing | Listing reads only the central directory (metadata), capped by `max_archive_members`; per-member work is bounded by fixed constants in the parsers. |

The single decision that simplifies all of it: **no disk extraction, ever**.
Everything a member can contribute to evidence is decompressed into memory
under caps and accounted against the run budget. There is no extraction
directory to escape, no symlink to plant, no permission bit to honor, no
filename encoding to normalize. This is stronger than sanitizing an
extraction step, and it is the reasoning the roadmap's "hard safety review"
gate asked for.

## Explicit non-goals

* **This is not a sandbox.** "Static analysis only" means the analyzed
  target is never executed — it is not a claim that analyzing hostile
  artifacts is risk-free in every environment.
* No network access exists to attack; none is added.
* Archive **extraction to disk is not implemented and will not be**: the
  archive safety review (§8) concluded that in-memory, bounded member
  access removes the extraction attack surface entirely rather than
  defending it. The gate this document set for archive work was met by
  *not* building extraction.
* Dynamic instrumentation, process injection, and binary patching are out
  of scope for the static phases and would require a dedicated security
  review before any release.

## Future capability gate

Any provider that launches an external program, executes a target, or
extracts archives must, before merging: use argument-based process
invocation (no shell strings), explicit executable paths, timeouts, output
caps, and a controlled environment; and update this document with its
threat analysis.
