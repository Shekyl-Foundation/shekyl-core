<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# `shekyl-engine-state` fuzz harness

Coverage-guided fuzzing of the region-2 payload parser
([`WalletLedger::from_postcard_bytes`]). This is the
cargo-fuzz / libFuzzer half of hardening-pass commit 8
(`docs/MID_REWIRE_HARDENING.md` §3.8); the stable-Rust proptest
half lives at
[`../tests/fuzz_region2.rs`](../tests/fuzz_region2.rs).

## Status

**Run every night in CI.** The nightly workflow's `fuzz` job
(`.github/workflows/nightly.yml`) runs this target, like every fuzz
target in the tree, for five minutes on the pinned nightly toolchain,
and `ci/fuzz-harness` type-checks it on stable for every change that
reaches it. The crate stays excluded from the parent workspace
(`rust/Cargo.toml`'s `[workspace].exclude`): `libfuzzer-sys` and the
sanitizer runtime need nightly Rust and `cargo install cargo-fuzz`.
The stable proptest harness still runs on every PR.

## Invocation

```bash
cd rust/shekyl-engine-state/fuzz
cargo +nightly fuzz run region2_parser
```

Or, with a wall-clock budget and parallel workers:

```bash
cargo +nightly fuzz run region2_parser -- -max_total_time=300 -jobs=4
```

A corpus will accumulate under `fuzz/corpus/region2_parser/`.
That directory is gitignored for the same reason the proptest
regression file is disabled in CI: the cheap-and-reproducible
failures are the ones that belong in a commit, not the
accumulated coverage corpus.

## What the harness asserts

Exactly the same property as the proptest harness:
**`WalletLedger::from_postcard_bytes` must never panic on any byte
input.** libFuzzer's oracle is its exit status — a panic surfaces
as a non-zero exit and a crash artifact under
`fuzz/artifacts/region2_parser/`. Any such artifact found during
a campaign is a commit-blocker on the PR that introduced the
regression. The fix lands with the crashing input added to
`fuzz/seeds/region2_parser/`, the committed regression corpus every
run reads.

## Why the harness is trivial

The target function is a single call. The interesting content is
in the *corpus evolution* libFuzzer performs, not in the harness
wrapper. Keeping the harness trivial makes it easy to verify by
inspection that it does not accidentally wrap the call in code
that could itself panic and mask a parser regression.

[`WalletLedger::from_postcard_bytes`]: ../src/wallet_ledger.rs
