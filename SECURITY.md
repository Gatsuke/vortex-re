# Security Policy

## Supported versions

Only the latest release line on `main` receives security fixes during the
Phase One period. Support policy for tagged releases will be documented when
tagged releases exist.

## Reporting a vulnerability

**Please report vulnerabilities privately.** Use GitHub's
*Report a vulnerability* feature (Security tab → Advisories), or email the
maintainers if an advisory channel is not yet configured for the repository.
Do not open a public issue for security problems.

Include, where possible:

* the commit or release you tested;
* the exact command or MCP tool call involved;
* a minimal artifact or fixture that reproduces the issue;
* the observed behavior and its security impact;
* any mitigations you identified.

We aim to acknowledge reports within 7 days. Once a fix is released, we will
credit reporters unless they prefer to remain anonymous.

## What counts as a security issue

* Path traversal outside the configured inspection root.
* Following symlinks that escape the inspection root.
* Unbounded resource consumption triggered by a crafted artifact
  (decompression is not implemented in this release, but the rule stands).
* Injection of attacker-controlled content into logs or evidence in a way
  that executes in downstream tooling.
* Secrets or private data ending up in committed fixtures, logs, or evidence
  exports without documentation.
* Any code path that executes an inspected target.

## What does NOT count (by design)

* Vortex-RE reading files you point it at. It is a local tool run by the
  user; the user's own filesystem access is assumed.
* "An AI agent could ask the tool to inspect sensitive files." Restrict
  agent reach with `VORTEX_ALLOWED_ROOTS` and your client's own permission
  model; see `docs/THREAT_MODEL.md` for the trust model.
* Static analysis revealing information that is inherently present in the
  artifact you asked it to inspect.
