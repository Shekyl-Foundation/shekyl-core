// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `P`-lane **exit-fee reserve** — the spend-time floor every mid-life
//! `P` constructor leaves in the pool so the terminal `Release` stays fundable.
//!
//! `ARCHIVAL_BOND_CONSTRUCTION.md` §7.2 rule 2: mid-life constructors (claim
//! fee inputs, `Reinstate`, and — from `ARCHIVAL_DRAIN_SEND_FD2.md` DS-4 — a
//! partial drain from a **live** persona) never spend the pool below
//! [`EXIT_FEE_RESERVE_ATOMIC`]. A
//! post-retirement sweep has no future `Release`, so the reserve is moot and a
//! drain-all may take the pool to zero (the live/retired branch is the
//! consumer's, e.g. the drain selector's — this module owns only the floor).
//!
//! Spend-time invariant only: the cover **draw** ([`crate::cover`]) is never
//! consulted or narrowed by it (`ARCHIVAL_COVER_DRAW.md` §1.9 DQ4). Kept in
//! this crate — the single source for `P`-lane wallet-side amount
//! constants, beside the cover draw. The cover draw's bound is the archival
//! bond floor, which this crate does not read, so the sizing relation between
//! the reserve and that bound is asserted in `shekyl-engine-core`, the one
//! site that sees both.

use shekyl_economics::quantized_fee;
use shekyl_wire::transaction::weight::heaviest_legal_release_weight;

/// The weight the exit-fee reserve is priced on: the heaviest legal
/// `Release` (`ICD-R10`, ruled 2026-11-23), derived from the wire's weight
/// model — every legal depth and funding count under the weight limit, the
/// consensus minimum of outputs, the widest debit and fee varints. A `P`-lane
/// spend pays the floor rate on its own weight, so no fee reads this; it is
/// the reserve's operand alone.
pub const EXIT_RESERVE_WEIGHT: usize = heaviest_legal_release_weight();

/// The fee rate, in atomic units per weight byte, the exit-fee reserve is
/// priced at. **Assumption** (`ICD-R10`,
/// `docs/design/CEN_I4_INPUT_CAP_DERIVATION.md`).
pub const EXIT_FEE_HEADROOM_RATE: u64 = 600;

/// The exit-fee reserve in atomic units (1 SKL = 1_000_000_000 atomic): the
/// fee of the heaviest legal `Release` at [`EXIT_FEE_HEADROOM_RATE`]
/// (`ICD-R10`; `ARCHIVAL_DRAIN_SEND_FD2.md` DS-4,
/// `ARCHIVAL_BOND_CONSTRUCTION.md` §7.2).
///
/// A `Release` pays the floor rate on its own weight, so the reserve covers
/// any exit by pricing the heaviest one, [`EXIT_RESERVE_WEIGHT`]. The product
/// rounds up to the fee lattice, as every paid fee does. At today's limit
/// that is `148,388 × 600`, or `89,033,000` atomic.
///
/// **Bounds for safe adjustment** (rule 175). Must satisfy
/// `0 < EXIT_FEE_RESERVE_ATOMIC < rung`, the rung the archival bond floor
/// (asserted below and, against the floor, in `shekyl-engine-core`).
/// Re-grounded against the tiling cover model (`ARCHIVAL_COVER_DRAW.md`,
/// 2026-07-21, which retired the runway floor): the protocol **always** adds a
/// cover draw to a derived bond amount — uniform over `[1, rung)`,
/// spreading every funded bond across a rung so no tx is identifiable as a
/// bond by amount — but the draw has an exclusive upper bound and **no floor**,
/// so a fresh pool is not guaranteed to clear the reserve. The bound is a
/// **corner-fraction bound**: the reserve is a small fraction (about `1/8.4`)
/// of the draw's range, so the protocol-drawn cover alone clears the reserve with probability `1 − reserve/RUNG ≈ 88.1%` (an optional
/// user top-up at funding time shrinks the corner further), and the
/// below-reserve corner (until earnings accrue or a top-up) strands nothing —
/// a cover-only pool has no earnings worth draining, the reserve releases at
/// retirement, and a terminal `Release` over a destitute pool is funded by the
/// §7.2 zero-fee-input claim escape. **Raising** it strands more value on live
/// personas (recoverable: it releases at retirement) and grows the
/// blocked-fresh-drain fraction proportionally (`reserve/RUNG`). **Lowering**
/// it risks an underfunded terminal `Release` under a fee spike — mitigated,
/// not fatal, by the same §7.2 destitute-corner escape.
pub const EXIT_FEE_RESERVE_ATOMIC: u64 =
    match quantized_fee(EXIT_RESERVE_WEIGHT as u64, EXIT_FEE_HEADROOM_RATE) {
        Some(fee) => fee,
        None => panic!("the exit-fee reserve does not fit in u64"),
    };

// The dominance relation (`ARCHIVAL_BOND_CONSTRUCTION.md` §7.2, re-grounded
// after `ARCHIVAL_COVER_DRAW.md` retired the runway floor) — the reserve
// strictly below one cover rung, the tiling draw's exclusive upper bound — is
// asserted where the rung is visible: `shekyl-engine-core`'s
// `the_exit_fee_reserve_is_below_one_cover_rung`, against the archival bond
// floor.

/// The reserve is nonzero (a zero reserve would silently disable the spend-time
/// floor for every live-persona mid-life constructor).
const _: () = assert!(EXIT_FEE_RESERVE_ATOMIC > 0);
