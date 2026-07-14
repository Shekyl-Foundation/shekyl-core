// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-shard retention-commitment horizon `bond_duration(age)` (gate-4 §4.4;
//! `ARCHIVAL_TIMING_CONSTANTS.md` §1; `PHASE_2B_FSM_RETOOL.md` P2B-7 Pin 3 / P2B-8 Q3).
//!
//! A held shard is **ineligible for voluntary `HoldingsUpdate`-drop** until its
//! retention-commitment horizon elapses:
//!
//! ```text
//! drop-eligible(s)  ⇔  current_epoch − add_epoch(s)  ≥  bond_duration(ShardAgeAtAdd(s))
//! ```
//!
//! Both operands are powered by the **one** v3.0 per-shard add-epoch record field
//! (the "two dependencies are one" collapse): the tenure LHS is
//! `current_epoch − add_epoch`, and the age inside `bond_duration` is derived from
//! the same `add_epoch` (plus the shard's segment freeze height).
//!
//! ## The age-realization invariant (GENESIS-FROZEN)
//!
//! The `age ∈ [0,1]` here is the **same age normalization the reward curve
//! consumes**, realized as [`shard_age_milli`](crate::consensus_state::shard_age_milli)
//! (relative tree-depth fraction, milli-scaled to `[0, WORK_MILLI_SCALE]`). The sim
//! feeds one age variable into both the scarcity/reward curve and the retention lock
//! (`agent.rs`), and consensus already realizes that age as `shard_age_milli` in the
//! reward path — so retention uses the same realization; forking a separate age
//! would split a normalization the sim never split.
//!
//! Two consensus properties are made **unrepresentable at the type**, not
//! tested-against:
//!
//! - **Reference time is age-at-ADD, not age-at-drop.** The sim arms the lock only
//!   on fresh acquisition and counts it down (`agent.rs:275-280`), so the horizon is
//!   fixed at acquisition. [`ShardAgeAtAdd`] can only be constructed from the add
//!   epoch, so evaluating at drop time (a rising target as the shard ages) cannot be
//!   expressed.
//! - **The close reference is `H_close(add_epoch)`, not a raw within-epoch height.**
//!   The reward path feeds `shard_age_milli` the settlement-close height, and its
//!   `floor((close − freeze)/SEB)` numerator shifts by an epoch-unit depending on
//!   where in the epoch it is evaluated. [`ShardAgeAtAdd::from_add`] derives
//!   `close = H_close(add_epoch) = (add_epoch + 1)·SEB` itself, so a raw block height
//!   cannot be passed — one normalization, shared with reward, by construction.
//!
//! The counting-down↔fixed-threshold equivalence is exact: the sim's lock
//! (`bond_duration(age)` at add, decrementing) reaches zero at `add_epoch + D`; the
//! consensus predicate `current_epoch − add_epoch ≥ D` fires at `add_epoch + D` — the
//! same epoch, no drift.
//!
//! ## `bond_duration` is the frozen artifact; the sim's f64 is the model
//!
//! There is no prior consensus `bond_duration`; the integer form here is
//! **canonical**. The sim computes `base·(1 + scale·age).round().max(1)` in f64
//! (`model.rs:417`), which carries representation error the exact-rational integer
//! form does not, so the two can diverge at round-half boundaries. The parity KAT
//! sweeps every `age_milli ∈ [0, WORK_MILLI_SCALE]` and asserts the integer output
//! equals the sim's f64 output; **the integer is authoritative** — a divergence fails
//! the KAT loudly as the signal to re-check the sim's economics at those age points
//! (not to "fix" the integer toward the float). At the genesis 4/4 constants there
//! are no half-boundary cases (`SCALE·age_milli ≡ WORK_MILLI_SCALE/2 (mod
//! WORK_MILLI_SCALE)` has no integer solution), so the sweep passes clean; the KAT is
//! the tripwire if a constant re-pin ever introduces one.

use crate::bond_floor::{BOND_DURATION_AGE_SCALE, BOND_DURATION_BASE_EPOCHS};
use crate::consensus_state::{epoch_close_height, shard_age_milli};
use crate::constants::effective_settlement_epoch_blocks;
use crate::reward_arithmetic::WORK_MILLI_SCALE;

/// The shard's relative-depth age in `shard_age_milli` units (`[0, WORK_MILLI_SCALE]`),
/// **evaluated at the shard's add-epoch settlement close and frozen there**.
///
/// [`bond_duration`] consumes only this newtype: the constructor takes the add
/// **epoch** (not a block height) and the segment freeze height and derives the close
/// itself, so neither a drop-time evaluation nor a raw within-epoch block height can
/// be expressed (see the module docs for the two consensus properties this encodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardAgeAtAdd {
    age_milli: u64,
}

impl ShardAgeAtAdd {
    /// Construct the frozen age-at-add from the shard's **add settlement epoch** and
    /// its segment **freeze height**, deriving `close = H_close(add_epoch)` — the same
    /// settlement-close height the reward path feeds `shard_age_milli`.
    ///
    /// `H_close(E) = (E + 1)·SEB` ([`epoch_close_height`]). `epoch_close_height` returns
    /// `None` only on the overflow of `(E+1)·SEB`, which is unreachable: `add_epoch`
    /// comes from the v6 record and equals `height/SEB`, so an epoch large enough to
    /// overflow is itself unreachable. A `debug_assert` fails loudly in tests/CI if a
    /// substrate bug ever produces such an epoch (so it surfaces rather than hiding);
    /// release saturates the close to `u64::MAX`, which yields age ≈ max — fail-safe
    /// toward the *longest* commitment (hardest to drop), never the shortest.
    ///
    /// A freshly-frozen shard added immediately gets age ≈ 0, i.e.
    /// `bond_duration = BASE` — the genuine youngest-deep minimum. (The `close ≤ freeze`
    /// path in `shard_age_milli` is a defensive backstop: a shard cannot be added before
    /// its segment freezes, so `H_close(add_epoch) > freeze_height` holds by the ADD
    /// verify's frozen-segment check — gate-4 §4.4 / P2B-7 Pin 5.)
    #[must_use]
    pub fn from_add(add_settlement_epoch: u64, freeze_height: u64) -> Self {
        let seb = effective_settlement_epoch_blocks();
        let close_opt = epoch_close_height(add_settlement_epoch);
        debug_assert!(
            close_opt.is_some(),
            "ShardAgeAtAdd::from_add: H_close({add_settlement_epoch}) overflowed — an \
             add-epoch this large is unreachable from the v6 record; a substrate bug \
             produced it"
        );
        let close = close_opt.unwrap_or(u64::MAX);
        Self {
            age_milli: shard_age_milli(close, freeze_height, seb),
        }
    }

    /// The frozen age in `shard_age_milli` milli-units (`[0, WORK_MILLI_SCALE]`).
    #[must_use]
    pub fn age_milli(self) -> u64 {
        self.age_milli
    }
}

/// Per-shard retention-commitment horizon in **settlement epochs** (gate-4 §4.4).
///
/// GENESIS-FROZEN consensus formula, integer-canonical (see the module docs):
/// `d = base·(1 + scale·age)` with `age = age_milli / WORK_MILLI_SCALE`, computed in
/// exact integer milli as `base·(WORK_MILLI_SCALE + scale·age_milli)`, rounded
/// half-up, floored at 1.
#[must_use]
pub fn bond_duration(age: ShardAgeAtAdd) -> u64 {
    let den = WORK_MILLI_SCALE;
    // base·(den + scale·age_milli): exact integer, no float. Saturating guards a
    // pathological re-pin; the genesis 4/4 values keep this far below u64::MAX for
    // age_milli ∈ [0, den].
    let scaled = BOND_DURATION_BASE_EPOCHS
        .saturating_mul(den.saturating_add(BOND_DURATION_AGE_SCALE.saturating_mul(age.age_milli)));
    // Round half up: (scaled + den/2) / den — matches f64 round-half-away-from-zero
    // for the non-negative values here. Floored at 1 so any deep shard commits.
    let rounded = scaled.saturating_add(den / 2) / den;
    rounded.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::SETTLEMENT_EPOCH_BLOCKS;

    // Construct a raw age for the pure-formula sweeps (bypasses `from_add`; the
    // add-epoch derivation is covered separately below).
    fn age(age_milli: u64) -> ShardAgeAtAdd {
        ShardAgeAtAdd { age_milli }
    }

    #[test]
    fn genesis_constants_are_the_h2_plateau_arm() {
        // Guard the config-generated pair against silent drift (shape frozen,
        // numerics provisional within the scale band [2,8]).
        assert_eq!(BOND_DURATION_BASE_EPOCHS, 4);
        assert_eq!(BOND_DURATION_AGE_SCALE, 4);
    }

    #[test]
    fn bond_duration_endpoints_and_midpoint() {
        // age 0 → BASE (youngest-deep minimum); age 1 → BASE·(1+SCALE); age 0.5 → BASE·(1+SCALE/2).
        assert_eq!(bond_duration(age(0)), 4);
        assert_eq!(bond_duration(age(WORK_MILLI_SCALE)), 20);
        assert_eq!(bond_duration(age(WORK_MILLI_SCALE / 2)), 12);
    }

    #[test]
    fn bond_duration_is_monotone_nondecreasing_in_age() {
        let mut prev = 0;
        for m in 0..=WORK_MILLI_SCALE {
            let d = bond_duration(age(m));
            assert!(d >= prev, "non-monotone at age_milli={m}: {d} < {prev}");
            prev = d;
        }
    }

    #[test]
    fn bond_duration_floored_at_one() {
        // Even a degenerate near-zero base commits for at least one epoch.
        // (Uses the real constants; the floor is unconditional in the formula.)
        assert!(bond_duration(age(0)) >= 1);
    }

    /// F2 parity: the integer artifact must equal the sim's f64 model over the full
    /// age sweep; the integer is authoritative, so any divergence fails loudly as the
    /// signal to re-check the sim economics at those age points.
    ///
    /// The f64 casts here deliberately reproduce the sim's `model.rs:417` arithmetic —
    /// that is the point of the parity check. All values are tiny (`base·(1+scale·age)`
    /// ≤ 20 at the genesis constants, `age_milli` ≤ 1000), well inside f64's exact-integer
    /// range, so the precision/truncation lints do not apply to this reproduction.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    #[test]
    fn bond_duration_matches_sim_f64_over_full_age_sweep() {
        let base = BOND_DURATION_BASE_EPOCHS as f64;
        let scale = BOND_DURATION_AGE_SCALE as f64;
        let den = WORK_MILLI_SCALE as f64;
        for m in 0..=WORK_MILLI_SCALE {
            let a = m as f64 / den;
            let sim = (base * (1.0 + scale * a)).round().max(1.0) as u64;
            let got = bond_duration(age(m));
            assert_eq!(
                got, sim,
                "F2 divergence at age_milli={m}: integer {got} vs sim f64 {sim} — \
                 integer is authoritative; re-check the sim economics at this age"
            );
        }
    }

    #[test]
    fn shard_age_at_add_uses_settlement_close_not_raw_height() {
        // F1: the age is computed at H_close(add_epoch) = (add_epoch+1)·SEB, the SAME
        // close the reward path uses — reproduce it independently and require equality.
        let add_epoch = 3u64;
        let freeze_height = 5_000u64;
        let close = (add_epoch + 1) * SETTLEMENT_EPOCH_BLOCKS;
        let expected = shard_age_milli(close, freeze_height, SETTLEMENT_EPOCH_BLOCKS);
        assert_eq!(
            ShardAgeAtAdd::from_add(add_epoch, freeze_height).age_milli(),
            expected
        );
    }

    #[test]
    fn genesis_band_shard_added_at_tip_is_oldest() {
        // A genesis-band shard (freeze_height 0) added at epoch E has close (E+1)·SEB,
        // so age → WORK_MILLI_SCALE (oldest) → the longest commitment. Mirrors the
        // reward path's "genesis-band shard is oldest" (shard_age_milli KAT).
        let a = ShardAgeAtAdd::from_add(10, 0);
        assert_eq!(a.age_milli(), WORK_MILLI_SCALE);
        assert_eq!(bond_duration(a), 20);
    }

    #[test]
    fn freshly_frozen_shard_is_youngest_minimum() {
        // Segment freezes at the add epoch's close ⇒ age 0 ⇒ bond_duration = BASE.
        // (Backstop path: close == freeze; the real add invariant is freeze < close.)
        let add_epoch = 7u64;
        let close = (add_epoch + 1) * SETTLEMENT_EPOCH_BLOCKS;
        let a = ShardAgeAtAdd::from_add(add_epoch, close);
        assert_eq!(a.age_milli(), 0);
        assert_eq!(bond_duration(a), 4);
    }
}
