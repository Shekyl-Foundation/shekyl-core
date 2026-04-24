<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# `shekyl-wallet-state` fuzz harness

Coverage-guided fuzzing of the region-2 payload parser
([`WalletLedger::from_postcard_bytes`]). This is the
cargo-fuzz / libFuzzer half of hardening-pass commit 8
(`docs/MID_REWIRE_HARDENING.md` §3.8); the stable-Rust proptest
half lives at
[`../tests/fuzz_region2.rs`](../tests/fuzz_region2.rs).

## Status

**Local-only, not CI-integrated.** This crate is deliberately
excluded from the parent workspace (`rust/Cargo.toml`'s
`[workspace].exclude`) and requires:

- **Nightly Rust toolchain.** `libfuzzer-sys` + the sanitizer
  runtime are nightly-only.
- **`cargo install cargo-fuzz`.** The `cargo fuzz` subcommand is
  not shipped with the toolchain itself.

The stable proptest harness runs on every PR; this harness is
reserved for authors running a deeper campaign locally before a
significant parser change, and for pre-mainnet-freeze
integration as a nightly sidecar job.

## Invocation

```bash
cd rust/shekyl-wallet-state/fuzz
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

## Graduation plan

Two conditions must be met before this harness moves into CI as a
nightly sidecar:

1. **Toolchain stability.** Either `libfuzzer-sys` stabilizes on
   stable Rust (tracking issue in the rust-fuzz repo) or the
   project accepts nightly as a permanent sidecar dependency.
2. **Mainnet-freeze proximity.** Pre-mainnet is the natural point
   to absorb the operational cost (nightly install cache, per-PR
   wall-clock budget) for the deeper coverage guarantee. Before
   that, the proptest harness is the cheaper and sufficient
   check.

Until both conditions hold, the stable proptest harness is the
load-bearing fuzzer for this parser and the cargo-fuzz harness is
the on-demand depth tool.

## What the harness asserts

Exactly the same property as the proptest harness:
**`WalletLedger::from_postcard_bytes` must never panic on any byte
input.** libFuzzer's oracle is its exit status — a panic surfaces
as a non-zero exit and a crash artifact under
`fuzz/artifacts/region2_parser/`. Any such artifact found during
a campaign is a commit-blocker on the PR that introduced the
regression; checked-in artifacts are added to `fuzz/corpus/` only
after the underlying bug is fixed.

## Why the harness is trivial

The target function is a single call. The interesting content is
in the *corpus evolution* libFuzzer performs, not in the harness
wrapper. Keeping the harness trivial makes it easy to verify by
inspection that it does not accidentally wrap the call in code
that could itself panic and mask a parser regression.

[`WalletLedger::from_postcard_bytes`]: ../src/wallet_ledger.rs
