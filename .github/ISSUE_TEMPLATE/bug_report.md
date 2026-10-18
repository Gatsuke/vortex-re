---
name: Bug report
about: Report a reproducible defect in Vortex-RE
title: "[bug] "
labels: bug
assignees: ""
---

## What happened?

<!-- A clear description of the defect. -->

## What did you expect to happen?

## Reproduction

1. Command or MCP tool call:
   ```bash
   # exact command, including flags
   ```
2. Artifact shape (attach or describe a minimal fixture; do NOT attach
   software you are not authorized to distribute):
3. Observed output (stdout/stderr or tool result):

```
<paste output>
```

## Environment

* Vortex-RE version: `vortex --version`
* Operating system and architecture: `vortex doctor` platform line
* How you invoked it: CLI / MCP client (which client and version)

## Evidence

* Exit code (if CLI):
* Stored run id (if persisted): `vortex runs list`
* Does `vortex doctor` report anything unusual?

## Notes

<!-- Anything else that helps: logs, what you already tried, whether the
     same artifact analyzed differently in another tool (please describe the
     evidence rather than just naming the other tool). -->
