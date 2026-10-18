## Summary

<!-- What does this PR change, and why? Reference the issue if one exists. -->

## Evidence impact

<!-- If analysis output changes: what differs, and why is the new output
     more correct? Golden fixtures must be updated in the same PR. -->

- [ ] Analysis output is unchanged, or `fixtures/expected-results/` was
      updated in this PR with an explanation.

## Checklist

- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo check --workspace --all-targets` passes.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [ ] `cargo test --workspace` passes.
- [ ] New behavior is covered by tests that assert **findings**, not just
      exit codes.
- [ ] New/changed findings carry correct origins and locations.
- [ ] Limitations are recorded in run output where results are partial.
- [ ] Documentation updated (README and/or docs/) if user-visible behavior
      changed.
- [ ] No new dependency, or the dependency is justified (license, size,
      why hand-rolling is worse).
- [ ] No secrets, private data, or artifacts I am not authorized to
      redistribute were added to the repository.

## Static-analysis-only rule

- [ ] This PR does not execute inspected targets, and does not weaken any
      check documented in docs/THREAT_MODEL.md.
