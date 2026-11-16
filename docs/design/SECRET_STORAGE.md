# Secret storage — locked pages for the long-lived secret types

**Status:** OPEN — design round (rule 26) not yet run. Scope ruled by Rick,
2026-11-08 (`SSR-R1`). The work lands after the alpha.12 cut, and the
`unsafe` scoping PR (`SSR-R2`) follows it. `SSR-Q3`, the transaction key,
is answered ahead of the round (R-21, Rick, 2026-11-15) and built.

This doc is where the round runs. It holds the ruled scope, the inputs and
the questions the round answers; `SSR-Q3` is the one answered.

## 1. Ruled scope

- **`SSR-R1` — the secrets-storage PR.** The long-lived secret types in
  `shekyl-crypto-pq` apply `mlock` and `madvise(MADV_DONTDUMP)` (and
  `VirtualLock` on Windows) once, at construction; locking `TxKey`'s pages
  is part of it. `x` comes from `derive_output_secrets`, which retires the
  two rows `docs/ci/secret-byte-locality.tsv` still holds (the `x = ho + b`
  sites, `SSR-Q4`); the inventory then holds none. The transaction-key rows
  went with `TxKey` (`SSR-Q3`). This is the implementation
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
  The same PR lands the decoder gate: a source scan that refuses an
  allocation sized by a count read from untrusted bytes with no bound
  before it
  ([`25-rust-architecture`](../../.cursor/rules/25-rust-architecture.mdc),
  §"Decoding untrusted bytes"; ruled by Rick, 2026-11-08).

## 2. Inputs

- The typed secret wrappers in `shekyl-crypto-pq` (`keys.rs`: `SpendSecret`,
  `ViewSecret`, `MlKem768DecapKey`, and the rest) and `AllKeysBlob`
  (`account.rs`), which is built by value and holds every key of one
  account.
- The two inventory rows: `shekyl-engine-core` `local_keys.rs` and
  `stake_engine/helpers.rs`, each reducing the spend secret `b` to form
  `x = ho + b`.
- `shekyl_crypto_pq::TxKey` (`tx_key.rs`), whose scalar sits behind a
  pointer (`HeapSecret`) and is the first type `SSR-R1` locks.
- `shekyl_process::harden::harden_process()`, which every binary calls
  first; it covers core dumps, not swap.

## 3. Questions for the round

- `SSR-Q1` — Which types are "long-lived"? Name each type that is locked
  and each that is not, with the reason.
- `SSR-Q2` — Where the locked bytes live: a type that moves cannot keep its
  pages locked, so the storage is a stable heap allocation. What owns it,
  and what happens when locking fails (the process's `RLIMIT_MEMLOCK`, a
  platform without it)?
- `SSR-Q3` — **Answered (R-21, Rick, 2026-11-15; built).** One type,
  `shekyl_crypto_pq::TxKey` (`tx_key.rs`): a canonical scalar behind a
  pointer, wiped on drop, never cloned or printed, with no accessor for its
  bytes. It gives `R` (`public`, `public_bytes`) and builds outputs: every
  output constructor and the encapsulation re-derivation take `&TxKey`.
  - Constructors: `random` (every wallet-built transaction and the coinbase
    template; fallible, `RandomnessUnavailable` when the OS source fails),
    `from_genesis_seed` (the genesis tool: `GENESIS_TXKEY`'s frame over the
    network's `name_id` and the recipients, reduced mod ℓ; the same bytes
    as before), and `seeded`, only under the TEST_ONLY `seeded-rng` feature.
    The multisig intent's constructor lands with slice 4a-1.
  - Two named exits, each its own type. `StoredTxKey` is what the wallet
    keeps for later OUTBOUND proofs (`store`, opened by `open`, which
    refuses a non-canonical record); its serialized bytes are the record's
    unchanged 32. `DisclosedTxKey` is what an OUTBOUND proof publishes: the
    proof's wire format carries `r`, so `disclose` signs and yields it, and
    the verifier reads it back with `DisclosedTxKey::from_bytes`.
  - A caller that builds from one key more than once borrows it (the
    template, the emission byte-identity test).
  - No transaction-key row is left in the inventory: every reduction of
    `r` happens in `shekyl-crypto-pq`.
- `SSR-Q4` — The `x = ho + b` call sites against `derive_output_secrets`:
  what each one needs that the function does not yet return.
- `SSR-Q5` — The tests that observe the locking from outside the process,
  per platform.
