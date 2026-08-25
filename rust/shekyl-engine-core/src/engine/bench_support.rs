// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bench-internals helpers (`bench-internals` feature; see `lib.rs`'s
//! `__bench_internals`). Split from `engine/mod.rs` by the decomposition
//! ratchet: a child module still names the otherwise-private
//! `Engine.ledger` field (Rust privacy: descendants see ancestors'
//! private items), so the production visibility stays unchanged.

use super::*;

// ── Bench-internals helpers (gated; see `lib.rs`'s `__bench_internals`)
//
// These free functions live in this module so they can name the
// otherwise-private `Engine.ledger` field; they are re-exported through
// `crate::__bench_internals` for `engine_trait_bench_ledger_balance{,_iai}.rs`
// without widening the field's production visibility. The pattern is
// the same one PR 1 uses for `LedgerSnapshot::from_ledger_for_bench`:
// the hot-path code stays in its production module while the bench
// surface is unlocked with a focused feature flag.

/// Borrow the engine's [`LocalLedger`] field directly. See
/// [`crate::__bench_internals::engine_local_ledger_for_bench`] for the
/// public-facing wrapper and the use-site rationale.
#[cfg(feature = "bench-internals")]
pub fn engine_local_ledger_for_bench(
    engine: &Engine<SoloSigner, DaemonClient, LocalLedger>,
) -> &LocalLedger {
    &engine.ledger
}

/// Project the wallet's balance through the
/// [`LedgerEngine::balance`](traits::LedgerEngine::balance) trait
/// method, dispatched on `engine.ledger`. See
/// [`crate::__bench_internals::engine_balance_for_bench`] for the
/// public-facing wrapper and the use-site rationale.
///
/// The trait surface is `pub(crate)`, so this thin wrapper performs
/// the trait call inside the crate (where the trait is visible) and
/// surfaces the [`shekyl_scanner::BalanceSummary`] result across the
/// bench-target boundary.
#[cfg(feature = "bench-internals")]
pub fn engine_balance_for_bench(
    engine: &Engine<SoloSigner, DaemonClient, LocalLedger>,
) -> shekyl_scanner::BalanceSummary {
    use crate::engine::traits::LedgerEngine;
    engine.ledger.balance()
}

/// Project a wallet's account public address through the
/// `KeyEngine::account_public_address` trait method (the trait is
/// `pub(crate)` so rustdoc intra-doc links to it from a `pub`
/// item would render as private-link warnings; plain backticks
/// throughout match the convention used in the bench files'
/// module-level docstrings), dispatched on a standalone
/// [`local_keys::LocalKeys`] fixture. See
/// [`crate::__bench_internals::engine_account_public_address_for_bench`]
/// for the public-facing wrapper and the use-site rationale.
///
/// # Why this takes `&LocalKeys` and not `&Engine<...>`
///
/// Since Stage 2 (`docs/design/STAGE_2_KEY_ENGINE_ACTOR.md` §6) the
/// `Engine` holds `key: KeyEngineHandle` — a handle to the `KeyActor`
/// that owns the `AllKeysBlob`. Its `KeyEngine::account_public_address`
/// resolves synchronously from a projection, but the secret-touching
/// surface routes through the actor mailbox. This bench deliberately
/// measures the **synchronous in-process** trait dispatch over a
/// standalone [`local_keys::LocalKeys`] fixture (the same crypto bodies
/// the actor replicates), isolating the trait-call cost from the actor
/// task / mailbox overhead. Benchmarking through `&Engine` would
/// conflate the two; the standalone `LocalKeys` fixture is the correct
/// measurement substrate. `LocalKeys` is retained as the `KeyEngine`
/// implementor for exactly this in-process bench/oracle use.
///
/// Given the substrate, the bench fixture is a standalone
/// `Box<LocalKeys>` rather than the unified
/// `(Box<Engine<SoloSigner, DaemonClient, LocalLedger>>, TempDir)`
/// shape the LedgerEngine bench uses. This divergence from the
/// canonical `engine_trait_bench_*` fixture shape is forced by the
/// substrate, not chosen for convenience; it is documented in the
/// bench module's file-level docstring and in the close-out PR's
/// pre-flight §1.2.
///
/// The bench still classifies under the `engine_trait_bench_*`
/// threshold class via the function-name routing discipline (per
/// `STAGE_0_HARNESS.md` §3.3.1's `classify()` rule, which routes on
/// the `#[library_benchmark]` function name, not on fixture shape).
///
/// # Why this returns `usize` rather than `&AccountPublicAddress`
///
/// The natural return type of the trait method is
/// `&AccountPublicAddress`, but that type is `pub(crate)` — exposing
/// it through this `pub fn`'s signature would widen the crate's
/// public API beyond the `bench-internals` gate. The helper instead
/// returns a `usize` summary (the sum of both field byte-lengths),
/// which is a primitive `pub` type. The trait call itself is
/// preserved against compiler elision by the internal
/// `std::hint::black_box(...)` around the address reference; the
/// returned length sum is a small additional load (two `Vec::len()`
/// metadata reads — the field bytes themselves are not touched) that
/// gives the criterion / gungraun bench loops something
/// observable to consume so the bench function's overall result is
/// not elided. The measurement surface is unchanged from the natural
/// shape; only the API-widening footprint differs (zero added types
/// in `__bench_internals`).
#[cfg(feature = "bench-internals")]
pub fn engine_account_public_address_for_bench(keys: &local_keys::LocalKeys) -> usize {
    use crate::engine::traits::key::KeyEngine;
    let addr = std::hint::black_box(keys.account_public_address());
    addr.pqc_public_key.len() + addr.classical_address_bytes.len()
}

/// Project `base_emission_at(height)` through the `EconomicsEngine`
/// trait method (the trait is `pub(crate)`, so this thin wrapper
/// performs the trait call inside the crate where the trait is
/// visible), dispatched on the engine's `economics` field. See
/// [`crate::__bench_internals::engine_economics_base_emission_at_for_bench`]
/// for the public-facing wrapper and the use-site rationale.
///
/// # Workload class — state-independent compute, O(height)
///
/// `base_emission_at` is a pure projection that does **not** read
/// `ChainEconomicsSource`; under interpretation (A) it iterates
/// `projected_already_generated(height)` block-by-block from genesis
/// (`shekyl-economics::emission`), so per-call cost is **O(height)**,
/// not a trivial pure-read. The bench drives a representative height
/// (`ECONOMICS_BENCH_HEIGHT` in the bench `common` module) so the loop
/// dominates; if a hot consumer ever lands, the FOLLOWUPS checkpoint-table
/// disposition (§5.2 B.6) replaces the naive loop with an O(1)
/// checkpoint lookup. The `Err` arm is overflow-only (B.7) and the
/// neutral trajectory does not overflow at the bench height, so the
/// `expect` is unreachable in practice.
#[cfg(feature = "bench-internals")]
pub fn engine_economics_base_emission_at_for_bench(
    engine: &Engine<SoloSigner, DaemonClient, LocalLedger>,
    height: u64,
) -> u64 {
    use crate::engine::traits::EconomicsEngine;
    engine
        .economics
        .base_emission_at(height)
        .expect("neutral-trajectory base_emission_at does not overflow at the bench height")
}

/// Project `parameters_snapshot()` through the `EconomicsEngine` trait
/// method, dispatched on the engine's `economics` field. See
/// [`crate::__bench_internals::engine_economics_parameters_snapshot_for_bench`]
/// for the public-facing wrapper and the use-site rationale.
///
/// # Why this returns `u64` rather than `EconomicsParametersSnapshot`
///
/// The natural return type is `pub(crate)`
/// `EconomicsParametersSnapshot`; surfacing it through this `pub fn`
/// would widen the crate's public API beyond the `bench-internals`
/// gate. The helper returns the snapshot's `money_supply_atomic`
/// (`u64`, a primitive `pub` type) instead — the same API-narrowing
/// pattern the `KeyEngine` bench's `usize`-summary uses. The trait
/// call is preserved against compiler elision by the internal
/// `black_box` around the snapshot before the field is read.
///
/// # Workload class — pure compute with a digest
///
/// `parameters_snapshot` rebuilds the snapshot fresh on every call
/// (§6.3 G5, no process-wide cache) and computes a Blake2b-256
/// `params_digest` over the fixed-width parameter layout — it is
/// **not** a trivial pure-read; the digest is the dominant per-call
/// cost. `parameters_snapshot` does not read `ChainEconomicsSource`.
#[cfg(feature = "bench-internals")]
pub fn engine_economics_parameters_snapshot_for_bench(
    engine: &Engine<SoloSigner, DaemonClient, LocalLedger>,
) -> u64 {
    use crate::engine::traits::EconomicsEngine;
    let snapshot = std::hint::black_box(engine.economics.parameters_snapshot());
    snapshot.money_supply_atomic
}
