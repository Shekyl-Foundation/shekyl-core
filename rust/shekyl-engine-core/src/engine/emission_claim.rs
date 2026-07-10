// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Emission claim assembly — the pure module of the wallet-side claim
//! builder (`EMISSION_CLAIM_BUILDER.md` §2, PR 2 of the §8 chain).
//!
//! This module is deterministic given a decoded [`EmissionClaimSource`]:
//! no daemon, no actor harness, no clock — KAT-able end-to-end with a
//! fixture source (§8 PR-2 validation surface). The RPC fetch/decode is
//! [`emission_source`](super::emission_source) (PR 1); backing selection,
//! membership proof, dual auth, and tx assembly are the PR-3 `StakeEngine`
//! handler's, which consumes this module's outputs.
//!
//! ## Step-1 claimable-epoch derivation (the M1 forward pin, discharged)
//!
//! `docs/FOLLOWUPS.md` M1 round-1 record: claimable epochs derive from
//! **the same positive-share recompute the verifier runs** — never from
//! `K_COVER` (this module contains no `K_COVER` read; the gate's outcome
//! reaches the wallet only through the persisted `Σwork(E)` denominator,
//! same as verify) and never from row-absence proxies. Claimable ⇔ the
//! recomputed share is strictly positive, which is exactly the §2.3 wire
//! positivity predicate (`reward_amount_plain[i] > 0` — a zero row is
//! unencodable, so the builder omits the epoch rather than encode it).
//!
//! ## The scratch-oracle purity pin (boundary verdicts)
//!
//! All three boundary verdicts — **top** (`E ≥ settled` ⇒ `NotSettled`),
//! **bottom** (`E < floor` ⇒ `Expired`), **dedup** (`Ok(false)` ⇒ already
//! claimed) — come from [`claimed_epochs_check_and_set`] run on a
//! **scratch clone** of the bond record's claimed set: the literal
//! function the connect path runs, used as a read-only classifier. This
//! satisfies §2 step 1's single-source intent for the top boundary —
//! `E < settled` lives only inside that function (expiry and dedup have
//! read-only siblings, `epoch_is_claim_expired` / `claimed_epochs_contains`;
//! the top boundary does not), and an inline `E < settled` guard here
//! would be a second copy that silently diverges the moment the connect
//! path's check changes.
//!
//! **Purity pin:** the scratch-oracle pattern is sound only while
//! `claimed_epochs_check_and_set` is pure w.r.t. all state but the passed
//! set — verified at `claimed_epochs.rs:118-146` on 2026-07-09 (reads
//! `epoch` / `current_settled_epoch` by value and one const; mutates only
//! the passed `Vec`; no log, metric, global, or I/O; the `debug_assert!`
//! is a release no-op touching nothing external). A future side-effect
//! addition to that function **reopens this disposition** — the scratch
//! clone isolates the set, not the side effect, and the builder fires the
//! oracle once per window epoch (≤ `MAX_CLAIM_AGE_W + 1` calls per
//! derivation). The read-only sibling extraction
//! (`epoch_is_not_settled`) that would retire the oracle entirely is
//! filed in `docs/FOLLOWUPS.md` (V3.1, trigger-gated).
//!
//! ## Cause-blindness (CB-5)
//!
//! A zero-share epoch is skipped as [`EpochSkip::ZeroShare`] — one
//! verdict for every zero cause (pre-`K_COVER`-gated epoch, no serve
//! credit, floored-to-zero share). The distinction is not merely withheld;
//! it is **not derivable here**: `K_COVER` is compared at exactly one
//! site (`epoch_close_compute`), the claim path never consults it, so the
//! wallet cannot tell the causes apart and neither can an observer of the
//! refusal. Do not add a branch that could.

// PR-2 lands the assembly core ahead of its consumer: PR-3's `StakeEngine`
// claim handler is the call site. This allow is deleted by PR-3
// (`EMISSION_CLAIM_BUILDER.md` §8) — staging, not tolerated dead code per
// `15-deletion-and-debt.mdc` (the emission_source PR-1 allow this PR deletes
// followed the same protocol).
#![allow(dead_code)]

use shekyl_archival_retention::{
    as_of_e_served_work, capped_work_milli, claimed_epochs_check_and_set, reward_share_floor,
    ClaimedEpochsError, ServedWork, MAX_SETTLEMENT_EPOCHS_PER_EMISSION,
};

use super::emission_source::EmissionClaimSource;

/// Builder refusals (CB-5 taxonomy, the arms this module constructs).
///
/// Staged completeness (§8 / rule 15 — no dead variants): `ScarcityConversion`
/// and `SelfCheckFailed` land with their constructor sites (work-claim
/// assembly and the step-7 self-check, later commits of this PR);
/// `InsufficientBacking` lands with `BackingSet` selection (PR 3).
#[derive(Debug, thiserror::Error)]
pub enum EmissionClaimError {
    /// Nothing claimable — an **idle state, not an error** (rule 82 /
    /// CB-5): every window epoch was skipped (zero share, expired,
    /// already claimed, not settled, no close row) or the daemon has no
    /// bond record for `P`. Cause-blind by construction: the refusal
    /// carries no per-epoch reasons (the [`EpochSkip`] diagnostics ride
    /// the `Ok` path only, and `ZeroShare` is itself one verdict for all
    /// zero causes).
    #[error("no claimable epochs")]
    NoClaimableEpochs,
    /// The daemon's gather rows are internally inconsistent (a credit
    /// pair or the claimant index references outside the bond/shard
    /// arrays) — malformed input from an untrusted daemon, refused
    /// loudly (`20-rust-vs-cpp-policy.mdc` §3), never skipped-and-continued:
    /// a daemon that mis-serializes one epoch cannot be trusted for the
    /// window.
    #[error("epoch {epoch}: claim-source rows are internally inconsistent")]
    SourceInvalid { epoch: u64 },
}

/// Why a window epoch was not selected — **local diagnostics**, never a
/// transport operand or an observable refusal payload (CB-5: the claim
/// query is cause-blind; nothing derived from these verdicts may shape
/// daemon-visible behavior).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochSkip {
    /// `E ≥ current_settled_epoch` (the connect predicate's `NotSettled`).
    NotSettled,
    /// `E` fell below the claim window floor (the connect predicate's
    /// `Expired`).
    WindowExpired,
    /// `E` is already in the bond record's claimed set (the connect
    /// predicate's dedup verdict).
    AlreadyClaimed,
    /// No frozen close row for `E` (`has_budget_row == false`) — mirrors
    /// the verify shim's reject; there is no denominator to claim against.
    NoCloseRow,
    /// The recomputed share is zero. **One verdict for every zero cause**
    /// (gated, no serve credit, floored) — see the module doc's
    /// cause-blindness section.
    ZeroShare,
    /// Claimable, but the batch already holds
    /// [`MAX_SETTLEMENT_EPOCHS_PER_EMISSION`] older epochs — deferred to
    /// the next claim tx (§6.6 F4 drain-vs-batch: `W = 26`, batch 15, so
    /// a full backlog drains in two txs before anything expires).
    BatchDeferred,
}

/// One claimable epoch: the boundary verdicts passed and the recomputed
/// share is strictly positive.
///
/// Carries the recompute's outputs so the work-claim assembly consumes
/// **the same evaluation** the derivation selected on (single-evaluator
/// discipline — assembly must not re-run the recompute and risk pairing
/// rows with a different evaluation than the one that admitted the epoch).
#[derive(Debug, Clone)]
pub struct ClaimableEpoch {
    /// The claimed `E`.
    pub settlement_epoch: u64,
    /// Index of this epoch's snapshot in the source's `epochs` (the
    /// assembly re-reads shard rows and `claimant_bond_idx` from it).
    pub snapshot_idx: usize,
    /// The `as_of_e_served_work` outputs for this epoch's frozen rows.
    pub served: ServedWork,
    /// `P`'s recomputed reward share — strictly positive (the §2.3 wire
    /// positivity predicate is the claimability predicate), byte-exactly
    /// what verify's step 5 recomputes: `reward_share_floor(budget,
    /// capped_work_milli(work_P, member, curve), persisted Σwork)`.
    pub reward: u64,
}

/// Step-1 output: the selected batch plus per-epoch skip diagnostics.
#[derive(Debug)]
pub struct ClaimableEpochs {
    /// Strictly increasing (window order), `1..=15` entries.
    pub claimable: Vec<ClaimableEpoch>,
    /// Local diagnostics for every window epoch **not** selected, in
    /// window order. See [`EpochSkip`]'s observability caveat.
    pub skipped: Vec<(u64, EpochSkip)>,
}

/// §2 step 1 — derive the claimable-epoch batch from a decoded claim
/// source.
///
/// Per window epoch, in ascending (window) order:
///
/// 1. **Boundary** — the scratch-oracle call (module doc): clone the bond
///    record's claimed set, run [`claimed_epochs_check_and_set`] against
///    the daemon's `current_settled_epoch`, map the verdict
///    (`NotSettled` / `Expired` / dedup) to a skip or proceed. The clone
///    is discarded; the builder never mutates the decoded record.
/// 2. **Close row** — no frozen close row (`has_budget_row == false`)
///    skips ([`EpochSkip::NoCloseRow`]).
/// 3. **Share recompute** — the verify-exact chain over the frozen rows:
///    [`as_of_e_served_work`] → `work_P` at `claimant_bond_idx` (absent
///    index ⇒ zero work, exactly as verify treats it) →
///    [`capped_work_milli`] → [`reward_share_floor`] against the
///    **persisted** `Σwork(E)` and frozen `budget(E)`. Claimable ⇔ share
///    `> 0`.
///
/// Selection is oldest-first (window order) up to
/// [`MAX_SETTLEMENT_EPOCHS_PER_EMISSION`]; younger claimable epochs
/// beyond the cap defer to the next claim tx ([`EpochSkip::BatchDeferred`]).
/// Oldest-first is load-bearing: the oldest epochs are nearest the
/// expiry floor, so deferral never pushes an epoch out of the window
/// that a different order could have saved.
///
/// Refuses [`EmissionClaimError::NoClaimableEpochs`] when the batch is
/// empty (including the no-bond-record case — an idle state, not an
/// error) and [`EmissionClaimError::SourceInvalid`] on internally
/// inconsistent gather rows.
pub fn derive_claimable_epochs(
    source: &EmissionClaimSource,
) -> Result<ClaimableEpochs, EmissionClaimError> {
    let Some(bond) = source.bond.as_ref() else {
        return Err(EmissionClaimError::NoClaimableEpochs);
    };

    let mut claimable: Vec<ClaimableEpoch> = Vec::new();
    let mut skipped: Vec<(u64, EpochSkip)> = Vec::new();

    for (snapshot_idx, snap) in source.epochs.iter().enumerate() {
        let epoch = snap.settlement_epoch;

        // Boundary — the scratch-oracle call (purity pin in the module
        // doc). All three verdicts from the one connect-path function;
        // no inline boundary arithmetic.
        let mut scratch = bond.claimed_settlement_epochs.clone();
        match claimed_epochs_check_and_set(&mut scratch, epoch, source.current_settled_epoch) {
            Err(ClaimedEpochsError::NotSettled) => {
                skipped.push((epoch, EpochSkip::NotSettled));
                continue;
            }
            Err(ClaimedEpochsError::Expired) => {
                skipped.push((epoch, EpochSkip::WindowExpired));
                continue;
            }
            Ok(false) => {
                skipped.push((epoch, EpochSkip::AlreadyClaimed));
                continue;
            }
            Ok(true) => {}
        }

        if !snap.has_budget_row {
            skipped.push((epoch, EpochSkip::NoCloseRow));
            continue;
        }

        // Share recompute — the verify-exact chain over the same decoded
        // views the assembly and self-check consume (§7.3 decode-locus
        // pin). Malformed gather indices refuse loudly (untrusted
        // daemon), mirroring verify's GatherMalformed /
        // ClaimantIndexOutOfRange rejections.
        let bonds = snap.bonds_view();
        let view = snap.source(&bonds);
        let served = as_of_e_served_work(&view.inputs)
            .map_err(|_| EmissionClaimError::SourceInvalid { epoch })?;
        let (work_p, is_member) = match view.claimant_bond_idx {
            Some(idx) if idx >= served.work_by_bond.len() => {
                return Err(EmissionClaimError::SourceInvalid { epoch });
            }
            Some(idx) => (served.work_by_bond[idx], served.member[idx]),
            None => (0, false),
        };
        let capped = capped_work_milli(work_p, is_member, &view.inputs.curve);
        let reward = reward_share_floor(view.budget, capped, view.persisted_sigma_work_milli);
        if reward == 0 {
            skipped.push((epoch, EpochSkip::ZeroShare));
            continue;
        }

        if claimable.len() == MAX_SETTLEMENT_EPOCHS_PER_EMISSION {
            skipped.push((epoch, EpochSkip::BatchDeferred));
            continue;
        }
        claimable.push(ClaimableEpoch {
            settlement_epoch: epoch,
            snapshot_idx,
            served,
            reward,
        });
    }

    if claimable.is_empty() {
        return Err(EmissionClaimError::NoClaimableEpochs);
    }
    Ok(ClaimableEpochs { claimable, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::emission_source::{BondContext, BondRow, EpochSnapshot};
    use shekyl_archival_retention::{
        claimed_epochs_contains, epoch_close_height, epoch_is_claim_expired, sigma_work_milli,
        CreditPair, EpochCloseShard, HoldingsDescriptor, HoldingsKind, MAX_CLAIM_AGE_W,
        SETTLEMENT_EPOCH_BLOCKS,
    };

    const BUDGET: u64 = 1_000_000;
    const SHARD_A: u64 = 7;
    const SHARD_B: u64 = 9;

    /// The emission_verify_kat fixture shape, owned: two bonds (idx 0 =
    /// claimant, idx 1 = other), two shards, credits {claimant→A,
    /// other→A, other→B}. `sigma_work_milli` is derived through the same
    /// sourcing functions the close persists with, so the fixture's
    /// denominator is exactly what a real close would have stored.
    fn snapshot(epoch: u64) -> EpochSnapshot {
        let close = epoch_close_height(epoch).expect("fixture epoch closes");
        let mut snap = EpochSnapshot {
            settlement_epoch: epoch,
            close_block_height: close,
            sigma_work_milli: 0,
            budget_atomic: BUDGET,
            has_budget_row: true,
            bonds: vec![
                BondRow {
                    join_settlement_epoch: 0,
                    is_foundation_complete_tree: false,
                    bad_intervals: vec![],
                },
                BondRow {
                    join_settlement_epoch: 0,
                    is_foundation_complete_tree: false,
                    bad_intervals: vec![],
                },
            ],
            shards: vec![
                EpochCloseShard {
                    shard_id: SHARD_A,
                    has_segment: true,
                    freeze_height: close - 5_000,
                },
                EpochCloseShard {
                    shard_id: SHARD_B,
                    has_segment: true,
                    freeze_height: close - 8_000,
                },
            ],
            credit_pairs: vec![
                CreditPair {
                    bond_idx: 0,
                    shard_idx: 0,
                },
                CreditPair {
                    bond_idx: 1,
                    shard_idx: 0,
                },
                CreditPair {
                    bond_idx: 1,
                    shard_idx: 1,
                },
            ],
            claimant_bond_idx: Some(0),
        };
        let sigma = {
            let bonds = snap.bonds_view();
            let view = snap.source(&bonds);
            let served = as_of_e_served_work(&view.inputs).expect("well-formed fixture");
            sigma_work_milli(&served.work_by_bond, &view.inputs.curve, &served.member)
        };
        assert!(sigma > 0, "fixture must have a live denominator");
        snap.sigma_work_milli = sigma;
        snap
    }

    /// A zero-share snapshot in its two indistinguishable causes: gated
    /// (`sigma == 0`, the M1 zero-at-top outcome as persisted) or
    /// no-serve-credit (`claimant_bond_idx == None`). Both must classify
    /// identically ([`EpochSkip::ZeroShare`]) — the cause-blindness KAT
    /// drives both through this one constructor.
    fn zero_share_snapshot(epoch: u64, gated: bool) -> EpochSnapshot {
        let mut snap = snapshot(epoch);
        if gated {
            snap.sigma_work_milli = 0;
        } else {
            snap.claimant_bond_idx = None;
        }
        snap
    }

    fn source_with(
        current_settled_epoch: u64,
        claimed: Vec<u64>,
        epochs: Vec<EpochSnapshot>,
    ) -> EmissionClaimSource {
        EmissionClaimSource {
            chain_height: current_settled_epoch * SETTLEMENT_EPOCH_BLOCKS + 1,
            current_settled_epoch,
            bond: Some(BondContext {
                join_settlement_epoch: 0,
                holdings: HoldingsDescriptor {
                    kind: HoldingsKind::ShardSetCompact,
                    shard_ids: vec![SHARD_A],
                },
                claimed_settlement_epochs: claimed,
            }),
            epochs,
        }
    }

    /// The derivation's three structural checks in one grid: boundary
    /// verdicts come from the connect predicate (each skip reason at its
    /// exact boundary), share positivity is the claimability predicate,
    /// and the selected epochs are the survivors in window order.
    #[test]
    fn boundary_verdicts_and_share_positivity_select_the_batch() {
        // settled = W + 10 puts the expiry floor at 10 (a real bottom
        // boundary, not saturated-to-zero).
        let settled = MAX_CLAIM_AGE_W + 10;
        let floor = settled - MAX_CLAIM_AGE_W;
        let source = source_with(
            settled,
            vec![20],
            vec![
                snapshot(floor - 1),            // expired (one below the floor)
                snapshot(floor),                // claimable (the floor itself)
                snapshot(20),                   // already claimed
                zero_share_snapshot(25, true),  // zero share (gated cause)
                zero_share_snapshot(26, false), // zero share (no-credit cause)
                snapshot(settled - 1),          // claimable (youngest settled)
                snapshot(settled),              // not settled (== settled)
            ],
        );
        let derived = derive_claimable_epochs(&source).expect("two epochs claimable");

        let selected: Vec<u64> = derived
            .claimable
            .iter()
            .map(|c| c.settlement_epoch)
            .collect();
        assert_eq!(selected, vec![floor, settled - 1]);
        assert_eq!(
            derived.skipped,
            vec![
                (floor - 1, EpochSkip::WindowExpired),
                (20, EpochSkip::AlreadyClaimed),
                (25, EpochSkip::ZeroShare),
                (26, EpochSkip::ZeroShare),
                (settled, EpochSkip::NotSettled),
            ],
            "each boundary must map to its connect-predicate verdict; the \
             two zero causes must be indistinguishable (cause-blind)"
        );

        // Share positivity is the wire-positivity predicate: every
        // selected reward is strictly positive (encodable) and byte-exact
        // against verify's step-4/5 recompute over the same view.
        for c in &derived.claimable {
            assert!(c.reward > 0, "claimable ⇒ wire-encodable (> 0)");
            let snap = &source.epochs[c.snapshot_idx];
            let bonds = snap.bonds_view();
            let view = snap.source(&bonds);
            let served = as_of_e_served_work(&view.inputs).unwrap();
            assert_eq!(c.served, served, "assembly must consume this evaluation");
            let idx = view.claimant_bond_idx.unwrap();
            let capped = capped_work_milli(
                served.work_by_bond[idx],
                served.member[idx],
                &view.inputs.curve,
            );
            assert_eq!(
                c.reward,
                reward_share_floor(view.budget, capped, view.persisted_sigma_work_milli),
                "derivation reward must equal verify's recompute"
            );
        }
    }

    /// Drift tripwire for the scratch-oracle disposition: the oracle's
    /// classification must agree with the read-only predicates where
    /// siblings exist (`epoch_is_claim_expired`, `claimed_epochs_contains`)
    /// and with the documented top boundary (`E < settled`). If the
    /// connect predicate's boundaries ever move, this differential fails
    /// before any consensus KAT does.
    #[test]
    fn scratch_oracle_agrees_with_read_only_predicates() {
        let settled = MAX_CLAIM_AGE_W + 10;
        let claimed = vec![15, 20, 30];
        for epoch in 0..=settled + 2 {
            let mut scratch = claimed.clone();
            let verdict = claimed_epochs_check_and_set(&mut scratch, epoch, settled);
            let expected = if epoch >= settled {
                Err(ClaimedEpochsError::NotSettled)
            } else if epoch_is_claim_expired(epoch, settled) {
                Err(ClaimedEpochsError::Expired)
            } else if claimed_epochs_contains(&claimed, epoch) {
                Ok(false)
            } else {
                Ok(true)
            };
            assert_eq!(verdict, expected, "oracle diverged at epoch {epoch}");
        }
    }

    /// Oldest-first 15-cap: with more claimable epochs than the batch
    /// bound, exactly the oldest 15 are selected (nearest expiry — the
    /// order that never strands a savable epoch) and the rest defer.
    #[test]
    fn batch_caps_at_fifteen_oldest_first() {
        let settled = 20;
        let epochs: Vec<EpochSnapshot> = (1..=18).map(snapshot).collect();
        let source = source_with(settled, vec![], epochs);
        let derived = derive_claimable_epochs(&source).expect("claimable");

        let selected: Vec<u64> = derived
            .claimable
            .iter()
            .map(|c| c.settlement_epoch)
            .collect();
        let expected: Vec<u64> = (1..=MAX_SETTLEMENT_EPOCHS_PER_EMISSION as u64).collect();
        assert_eq!(selected, expected, "oldest 15, window order");
        assert!(
            selected.windows(2).all(|w| w[0] < w[1]),
            "wire invariant: strictly increasing"
        );
        assert_eq!(
            derived.skipped,
            vec![
                (16, EpochSkip::BatchDeferred),
                (17, EpochSkip::BatchDeferred),
                (18, EpochSkip::BatchDeferred),
            ]
        );
    }

    /// Idle refusals: no bond record, an empty window, and an
    /// all-skipped window each refuse `NoClaimableEpochs` — an idle
    /// state, not an error, and cause-blind (no per-epoch payload).
    #[test]
    fn refuses_idle_when_nothing_claimable() {
        // No bond record.
        let mut source = source_with(10, vec![], vec![snapshot(5)]);
        source.bond = None;
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::NoClaimableEpochs)
        ));

        // Empty window.
        let source = source_with(10, vec![], vec![]);
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::NoClaimableEpochs)
        ));

        // Every epoch skipped (zero share both causes + already claimed).
        let source = source_with(
            10,
            vec![5],
            vec![
                zero_share_snapshot(4, true),
                snapshot(5),
                zero_share_snapshot(6, false),
            ],
        );
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::NoClaimableEpochs)
        ));
    }

    /// A window epoch without a frozen close row skips (`NoCloseRow`,
    /// mirroring the verify shim's reject) without poisoning the batch.
    #[test]
    fn missing_close_row_skips_the_epoch_only() {
        let mut no_row = snapshot(5);
        no_row.has_budget_row = false;
        let source = source_with(10, vec![], vec![no_row, snapshot(6)]);
        let derived = derive_claimable_epochs(&source).expect("epoch 6 claimable");
        assert_eq!(derived.claimable.len(), 1);
        assert_eq!(derived.claimable[0].settlement_epoch, 6);
        assert_eq!(derived.skipped, vec![(5, EpochSkip::NoCloseRow)]);
    }

    /// Internally inconsistent gather rows refuse loudly (untrusted
    /// daemon), never skip-and-continue: a credit pair indexing outside
    /// the arrays, and a claimant index outside the bond rows.
    #[test]
    fn malformed_gather_is_loud() {
        let mut bad_pair = snapshot(5);
        bad_pair.credit_pairs.push(CreditPair {
            bond_idx: 9,
            shard_idx: 0,
        });
        let source = source_with(10, vec![], vec![bad_pair]);
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::SourceInvalid { epoch: 5 })
        ));

        let mut bad_claimant = snapshot(5);
        bad_claimant.claimant_bond_idx = Some(9);
        let source = source_with(10, vec![], vec![bad_claimant]);
        assert!(matches!(
            derive_claimable_epochs(&source),
            Err(EmissionClaimError::SourceInvalid { epoch: 5 })
        ));
    }
}
