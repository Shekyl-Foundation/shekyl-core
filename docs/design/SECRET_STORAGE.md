# Secret storage — locked pages for the long-lived secret types

**Status:** OPEN — design round (rule 26) not yet run. Scope ruled by Rick,
2026-11-08 (`SSR-R1`). The work lands after the alpha.12 cut, and the
`unsafe` scoping PR (`SSR-R2`) follows it.

This doc is where the round runs. It holds the ruled scope, the inputs and
the questions the round answers; it does not answer them yet.

## 1. Ruled scope

- **`SSR-R1` — the secrets-storage PR.** The long-lived secret types in
  `shekyl-crypto-pq` apply `mlock` and `madvise(MADV_DONTDUMP)` (and
  `VirtualLock` on Windows) once, at construction. A `TxKey` constructor
  returns its `R`; `x` comes from `derive_output_secrets`. Those two
  constructors retire the seven rows of `docs/ci/secret-byte-locality.tsv`
  where a wallet or node crate reduces a key itself (`R = r·G` ×5,
  `x = ho + b` ×2). This is the implementation
  [`35-secure-memory`](../../.cursor/rules/35-secure-memory.mdc)'s
  OS-level section names, and the move
  [`36-secret-locality`](../../.cursor/rules/36-secret-locality.mdc)'s
  inventory note names.
- **`SSR-R2` — the `unsafe` scoping PR, after `SSR-R1`.** `shekyl-process`,
  `shekyl-thread-priority`, `shekyl-tor-control-client`, `shekyl-logging`
  and `shekyl-engine-prefs` take `#![deny(unsafe_code)]` with item-level
  allows and `// SAFETY:` comments; `randomx-v2-sys` and
  `shekyl-randomx-differential` keep a crate-level allow with the reason
  stated at the root
  ([`45-rust-lint-checks`](../../.cursor/rules/45-rust-lint-checks.mdc)).

## 2. Inputs

- The typed secret wrappers in `shekyl-crypto-pq` (`keys.rs`: `SpendSecret`,
  `ViewSecret`, `MlKem768DecapKey`, and the rest) and `AllKeysBlob`
  (`account.rs`), which is built by value and holds every key of one
  account.
- The seven inventory rows: `shekyl-block-template` `lib.rs`;
  `shekyl-engine-core` `drain_assembly.rs`, `sign_bridge.rs`,
  `stake_engine/bond_post_assemble.rs`, `stake_engine/claim.rs` (`R`);
  `shekyl-engine-core` `local_keys.rs`, `stake_engine/helpers.rs` (`x`).
- `shekyl_process::harden::harden_process()`, which every binary calls
  first; it covers core dumps, not swap.

## 3. Questions for the round

- `SSR-Q1` — Which types are "long-lived"? Name each type that is locked
  and each that is not, with the reason.
- `SSR-Q2` — Where the locked bytes live: a type that moves cannot keep its
  pages locked, so the storage is a stable heap allocation. What owns it,
  and what happens when locking fails (the process's `RLIMIT_MEMLOCK`, a
  platform without it)?
- `SSR-Q3` — The `TxKey` type: its constructor, what it exposes besides
  `R`, and how each of the five call sites changes.
- `SSR-Q4` — The `x = ho + b` call sites against `derive_output_secrets`:
  what each one needs that the function does not yet return.
- `SSR-Q5` — The tests that observe the locking from outside the process,
  per platform.
