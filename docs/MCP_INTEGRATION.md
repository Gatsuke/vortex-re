# MCP Integration

Vortex-RE ships a Model Context Protocol server built on the official Rust
SDK ([`rmcp`](https://crates.io/crates/rmcp) 3.5), served over **stdio**.
Both the CLI and the MCP server call the same application service layer, so
results are identical across interfaces by construction.

## Starting the server

```bash
vortex mcp serve
```

The server speaks MCP on stdin/stdout and logs to stderr only, so protocol
output is never corrupted. Inspected targets are never executed by any
tool. The server accepts the same global `--config` flag as the CLI, so a
config file's limits, per-provider timeouts, and recovery grace apply to
MCP sessions too; malformed config files abort startup with the exact
problem on stderr.

## Tools

| Tool | Input (required fields) | Returns |
| --- | --- | --- |
| `vortex_capabilities` | — | Providers, capabilities, operations that work now, and operations that are not supported with reasons |
| `vortex_inspect_artifact` | `path` | Bounded summary + first page of findings with pagination metadata (`page`, `page_size`, `max 100`), counts, limitations, unknowns, and the persisted `run_id` |
| `vortex_search_artifact` | `path`, `query` | Literal search matches with `file:line:column` and redacted context, per-file/global caps reported |
| `vortex_trace_relationships` | `path` | Relationship edges (first page, default 20/max 100) with scope, resolution status, and notes for unresolved references |
| `vortex_list_runs` | — | Stored runs, newest first (default 20, max 100) |
| `vortex_read_evidence` | `run_id` | Any section of a stored run (`overview`, `summary`, `findings`, `relationships`, `limitations`, `unknowns`, `warnings`, `errors`), paginated |
| `vortex_compare_runs` | `run_id_a`, `run_id_b` | Structural diff with totals and disclaimers |

Optional parameters (`page`, `page_size`, `max_entries`, `max_matches`,
`timeout_secs`, `case_sensitive`, `limit`, `section`) are validated and
clamped; input schemas are generated from typed structs and advertised via
`tools/list`.

### Cancellation

A client `notifications/cancelled` for a pending request is bridged onto
the run's cancel token. Cancellation rules (they are tested, not
aspirational):

* the run stops at its next safe boundary (a run already checkpointing
  per-file stops within one file);
* partial findings collected before cancellation are preserved and the
  run is finalized as `cancelled`, never `succeeded`;
* the tool result the client receives reports the cancelled status, so the
  agent knows exactly what it has.

### Error semantics

* **Tool-level errors** (`is_error: true`) for domain failures the agent
  should read and react to: missing paths, invalid queries, unknown
  sections, unsupported formats. The content is a JSON error object:
  `{ "code": "not_found", "message": "...", "hint": "..." }`.
* **Protocol errors** (`-32602`) for malformed requests: wrong argument
  types, unknown tool names.
* Partial analyses (limits hit) are **successes** with `status: "partial"`
  and recorded limitations — not errors.

### Context-window safety

* Inspect returns a summary plus one page of findings (default 20); the
  `pagination` object tells the agent how to fetch more with
  `vortex_read_evidence` instead of re-running analysis.
* Every list in output is bounded, and truncation is reported in
  `counts.truncated` and `limitations`.
* Agents should treat `unknowns` as questions to investigate, not as
  findings.

## Client configuration examples

### Claude Code

```bash
claude mcp add vortex-re -- /path/to/vortex mcp serve
```

or in `.mcp.json`:

```json
{
  "mcpServers": {
    "vortex-re": {
      "command": "/absolute/path/to/vortex",
      "args": ["mcp", "serve"]
    }
  }
}
```

### Cursor / generic stdio MCP client

```json
{
  "mcpServers": {
    "vortex-re": {
      "command": "/absolute/path/to/vortex",
      "args": ["mcp", "serve"],
      "env": {
        "VORTEX_HOME": "/home/you/.local/share/vortex-re",
        "VORTEX_ALLOWED_ROOTS": "/home/you/projects"
      }
    }
  }
}
```

`VORTEX_ALLOWED_ROOTS` (path-list) restricts **all** inspection to the
given roots — recommended when an agent, rather than you, chooses targets.
`VORTEX_HOME` overrides where run records are stored. A manual smoke test:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}\n{"jsonrpc":"2.0","method":"notifications/initialized"}\n{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n' | vortex mcp serve
```

## Testing

The server is exercised by real protocol sessions in
`apps/vortex/tests/mcp.rs`: an `rmcp` client connects over an in-memory
duplex transport and asserts tool discovery, schema validation, pagination,
error semantics, cancellation, and evidence round trips — the same pattern
used by the SDK's own test suite. The `tests/parity.rs` suite runs
identical invalid inputs through the CLI binary and the MCP server and
asserts byte-identical structured error bodies, so the two surfaces cannot
drift apart.
