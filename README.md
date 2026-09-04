# bench-baseline branch

**Do not merge this branch.** It is a rolling data branch
holding the current CI benchmark baseline — one file at tip,
updated by the `ci/benchmarks` workflow on every push to
`dev`. See
[`docs/benchmarks/README.md`](../dev/docs/benchmarks/README.md)
"CI integration" section for the full protocol.

**Tip file:**
- `baseline.json` — `shekyl_rust_v0`-schema envelope
  captured on a GitHub-hosted `ubuntu-latest` runner.
- `baseline.iai.snapshot` — raw gungraun stdout
  corresponding to the same capture.

Current source commit: `ab4693d0e835d3a4ddfecaeccbf0e6d40d54e3e5`.
