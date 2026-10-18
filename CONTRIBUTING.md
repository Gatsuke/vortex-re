# Contributing to Vortex-RE

Thank you for considering a contribution. This project's core value is
**trustworthy evidence**: a finding a developer cannot verify is worse than
no finding at all. Contributions are held to that standard.

## How to contribute

1. **Open an issue first** for anything larger than a typo fix. Describe the
   problem, the expected behavior, and — for analysis changes — the artifact
   shape that triggers it.
2. **Fork and branch** from `main`.
3. **Make the change**, following the rules below.
4. **Run the full quality gate** before pushing:
   ```bash
   cargo fmt --all
   cargo check --workspace --all-targets
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
5. **Open a pull request** using the PR template.

## Engineering rules (non-negotiable)

* **Never claim a feature works unless its implementation and tests support
  the claim.** If a capability is partial, document the limitation in the
  code, the evidence output, and the docs.
* **No fabricated results.** Do not add placeholder providers, dummy
  findings, or fake test fixtures that assert nothing.
* **No silent provider substitution.** If a provider fails, surface the
  failure; never fall back to a different engine without saying so.
* **Unknown is a valid answer.** Reporting "not detected" when a provider
  could not detect something is a bug; report the uncertainty instead.
* **Evidence first.** Every user-visible analysis result must carry its
  origin (`observed` / `derived` / `inferred`) and source location when
  known.
* **Static analysis only.** Phase One never executes inspected targets. Any
  change that would execute target code requires an explicit design review
  against `docs/THREAT_MODEL.md`.
* **Bounded output.** Anything shown to an AI agent must be capped, and the
  cap must be reported when hit.
* **Keep dependencies minimal.** New dependencies require a justification in
  the PR description (license, size, maintenance status, why a hand-rolled
  version is worse).
* **Commit `Cargo.lock`.** Builds must be reproducible.

## Golden tests

`fixtures/javascript-demo` and `fixtures/expected-results/` form the golden
suite. If your change intentionally alters analysis output:

1. Re-run the golden tests.
2. Review the diff against the expected files.
3. Update the expected files **in the same commit** and explain the change
   in the PR description.

## Adding a provider

Providers live in `crates/vortex-providers`. A new provider must:

* implement `AnalysisProvider` (id, version, capabilities, validation,
  operations);
* enforce `ResourceLimits` and stop conditions;
* produce findings/relationships with correct origins;
* document what it does *not* support, and say so at runtime;
* include tests that verify findings against known inputs — not just
  "command exits successfully";
* pass a license review if it wraps a third-party engine (see
  `docs/PROVIDERS.md`).

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open public issues for
vulnerabilities.
