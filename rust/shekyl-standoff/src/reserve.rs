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
//! this crate — the single source for `P`-lane wallet-side amount constants,
//! beside [`COVER_RUNG_ATOMIC`] — so the sizing relation between the reserve
//! and the cover draw's bound is asserted at the one site that sees both.

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
///   (`FCMP_PROOF_SIZE_KAT[8][24] = 33_600` bytes); with the per-input
///   KEM/PQC-auth and per-output CT/KEM framing the full structural weight is
///   **80,456 bytes** — computed, not estimated, by engine-core's
///   `p_lane_weight_ceiling_bytes()` (the same bound the P-lane floor fee is
///   quoted over), and tied back to this constant by the
///   `p_lane_ceiling_covers_the_heaviest_legal_shape` test. An earlier
///   revision hand-estimated "well under ~64,000" here; the computed model
///   corrected it upward.
/// - **Pessimistic rate.** The economy floor rate is daemon-derived and
///   historically ~1 atomic/weight-byte; this reserve provisions
///   `>= 600 atomic/weight-byte` of head-room (`80_456 × 600 ≈ 48.3M < 50M`),
///   covering a fee market ~600× above any observed floor. The engine-core
///   ceiling test pins this 600 bound: a weight-model regeneration that grows
///   the ceiling past `50M / 600` turns it red, forcing this derivation to be
///   re-run rather than silently under-covering.
///
/// **Bounds for safe adjustment** (rule 75). Must satisfy
/// `0 < EXIT_FEE_RESERVE_ATOMIC < COVER_RUNG_ATOMIC` (asserted below).
/// Re-grounded against the tiling cover model (`ARCHIVAL_COVER_DRAW.md`,
/// 2026-07-21, which retired the runway floor): the protocol **always** adds a
/// cover draw to a derived bond amount — uniform over `[1, COVER_RUNG_ATOMIC)`,
/// spreading every funded bond across a rung so no tx is identifiable as a
/// bond by amount — but the draw has an exclusive upper bound and **no floor**,
/// so the old absolute "a fresh pool always clears the reserve" guarantee is
/// gone. The bound is now a **corner-fraction bound**: the reserve is a small
/// fraction (`1/15`) of the draw's range, so the protocol-drawn cover alone
/// clears the reserve with probability `1 − reserve/RUNG ≈ 93.3%` (an optional
/// user top-up at funding time shrinks the corner further), and the
/// below-reserve corner (until earnings accrue or a top-up) strands nothing —
/// a cover-only pool has no earnings worth draining, the reserve releases at
/// retirement, and a terminal `Unbond` over a destitute pool is funded by the
/// §7.2 zero-fee-input claim escape. **Raising** it strands more value on live
/// personas (recoverable: it releases at retirement) and grows the
/// blocked-fresh-drain fraction proportionally (`reserve/RUNG`). **Lowering**
/// it risks an underfunded terminal `Unbond` under a fee spike — mitigated,
/// not fatal, by the same §7.2 destitute-corner escape.
pub const EXIT_FEE_RESERVE_ATOMIC: u64 = 50_000_000;

/// Pinned sizing assert (`ARCHIVAL_BOND_CONSTRUCTION.md` §7.2's dominance
/// assert, re-grounded after `ARCHIVAL_COVER_DRAW.md` retired the runway
/// floor): the reserve stays strictly below one cover rung — the tiling draw's
/// exclusive upper bound — so a fresh cover draw clears the reserve with high
/// probability, and the fully-inverted sizing (reserve ≥ rung: **every** fresh
/// pool below the reserve, every fresh live drain blocked) cannot compile.
const _: () = assert!(EXIT_FEE_RESERVE_ATOMIC < COVER_RUNG_ATOMIC);

/// The reserve is nonzero (a zero reserve would silently disable the spend-time
/// floor for every live-persona mid-life constructor).
const _: () = assert!(EXIT_FEE_RESERVE_ATOMIC > 0);
