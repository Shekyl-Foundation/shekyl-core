# Reference benchmark captures

This directory holds canonical `shekyl_rust_v0.json` artifacts cited
by review-time documentation
([`docs/PERFORMANCE_BASELINE.md`](../../PERFORMANCE_BASELINE.md),
preparatory PR descriptions, etc.) for review-surface verification
gates that need a stable, in-tree artifact to compare against.

## Why these are committed in-tree

GitHub Actions artifact retention defaults to 90 days and is
configurable lower. PR descriptions that cite "see CI run X's
artifact" are reproducible only while the artifact is retained;
once aged out, the reproduction window closes and the verification
gate becomes "works on my machine."

Committing a small number of canonical artifacts in-tree gives
review-surface verification gates a stable target. The artifacts
are ~15 KB each; the repository can absorb the few that matter for
review continuity.

## What goes here

Only artifacts cited by **review-surface verification gates** for
preparatory PRs and frozen-baseline transcription. Routine CI
captures stay on the GHA artifact path; they aren't committed here.

The naming convention is `<originating-pr-or-context>-shekyl_rust_v0.json`
so future readers can trace each artifact's provenance from the
filename alone.

## Current contents

- **`stage-0-pr-2-c4c-shekyl_rust_v0.json`**: the post-Q
  invariance-verified capture from Stage 0 PR-2's commit 4c
  (`0276d210e7705a5d691e2d85bb9ad5fa340dd633`), GHA run
  25239954863. Cited by Stage 0 PR-B's review-surface verification
  gate as the column-shape reference for the
  [`PERFORMANCE_BASELINE.md`](../../PERFORMANCE_BASELINE.md)
  rewrite. Stage 0 PR-2's commit 5 will produce the actual frozen
  baseline against the merge SHA; that capture supersedes this one
  for transcription purposes but this one stays as the PR-B
  review-time reference.

## Relationship to the in-tree iai snapshot

[`docs/benchmarks/shekyl_rust_v0.iai.snapshot`](../shekyl_rust_v0.iai.snapshot)
is a **rolling** snapshot refreshed by the `update-baseline`
workflow on every push to `dev`. The artifacts in this directory
are **frozen** captures cited by specific review surfaces; they do
not refresh.
