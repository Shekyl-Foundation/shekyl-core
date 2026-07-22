// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `P`-lane **exit-fee reserve** — the spend-time floor every mid-life
//! `P` constructor leaves in the pool so the terminal `Unbond` stays fundable.
//!
//! `ARCHIVAL_BOND_CONSTRUCTION.md` §7.2 rule 2: mid-life constructors (claim
//! fee inputs, both `HoldingsUpdate` directions, `Rebond`, and — from
//! `ARCHIVAL_DRAIN_SEND_FD2.md` DS-4 — a partial drain from a **live**
//! persona) never spend the pool below [`EXIT_FEE_RESERVE_ATOMIC`]. A
//! post-retirement sweep has no future `Unbond`, so the reserve is moot and a
//! drain-all may take the pool to zero (the live/retired branch is the
//! consumer's, e.g. the drain selector's — this module owns only the floor).
//!
//! Spend-time invariant only: the cover **draw** ([`crate::cover`]) is never
//! consulted or narrowed by it (`ARCHIVAL_COVER_DRAW.md` §1.9 DQ4). Kept in
//! this crate — the single source for `P`-lane wallet-side amount floors,
//! beside [`COVER_RUNG_ATOMIC`] — so the dominance relation between
//! the two floors is asserted at the one site that sees both.

use crate::cover::COVER_RUNG_ATOMIC;

/// The exit-fee reserve in atomic units (1 SKL = 1_000_000_000 atomic).
///
/// **Pinned: `0.05 SKL = 50_000_000 atomic`** — one pessimistically-priced
/// `Unbond` fee. Derivation (`ARCHIVAL_DRAIN_SEND_FD2.md` DS-4,
/// `ARCHIVAL_BOND_CONSTRUCTION.md` §7.2):
///
/// - **Worst-case `Unbond` weight.** An `Unbond` spends the typed `P` pool
///   (cover + earnings) and pays out; bound by `MAX_INPUTS = 8` inputs, two
///   outputs, `MAX_TREE_DEPTH = 24`. The dominant term is the FCMP++ proof
///   (`tx_fee_model::FCMP_PROOF_SIZE_KAT[8][24] = 33_600` bytes); with the
///   per-input KEM/PQC-auth and per-output CT/KEM framing the whole tx is well
///   under ~64_000 weight-bytes.
/// - **Pessimistic rate.** The economy floor rate is daemon-derived and
///   historically ~1 atomic/weight-byte; this reserve provisions three orders
///   of magnitude of head-room (~768 atomic/weight-byte), so
///   `~64_000 × 768 ≈ 49.2M < 50M` covers a fee market far above any observed
///   floor.
///
/// **Bounds for safe adjustment** (rule 75). Must satisfy
/// `0 < EXIT_FEE_RESERVE_ATOMIC < COVER_RUNG_ATOMIC` (asserted below):
/// the smallest cover draw is `C_min = 0.75 SKL`, so a freshly-funded persona's
/// pool always clears the reserve with margin — the reserve never pathologically
/// blocks a first drain. **Raising** it strands more value on live personas
/// (recoverable: it releases at retirement). **Lowering** it risks an
/// underfunded terminal `Unbond` under a fee spike — mitigated, not fatal, by
/// the §7.2 destitute-corner escape (a zero-fee-input claim funds the `Unbond`
/// from the claimed output when the pool is below the reserve).
pub const EXIT_FEE_RESERVE_ATOMIC: u64 = 50_000_000;

/// Pinned dominance assert (`ARCHIVAL_BOND_CONSTRUCTION.md` §7.2: "Lands with a
/// pinned dominance assert against `COVER_RUNG_ATOMIC`"): the reserve is
/// a small carve-out of the runway floor, never the other way round. If a future
/// re-sizing inverts the relation this fails to compile.
const _: () = assert!(EXIT_FEE_RESERVE_ATOMIC < COVER_RUNG_ATOMIC);

/// The reserve is nonzero (a zero reserve would silently disable the spend-time
/// floor for every live-persona mid-life constructor).
const _: () = assert!(EXIT_FEE_RESERVE_ATOMIC > 0);
