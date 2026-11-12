// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use crate::engine::emission_source::{
    BondContext, BondRow, EmissionClaimSource, EpochSnapshot, ServeAnchor, SlashWatermark,
};
use shekyl_archival_retention::{
    as_of_e_served_work, epoch_close_height, settlement_epoch_at_height, sigma_work_milli,
    CreditPair, EpochCloseShard, HoldingsDescriptor, HoldingsKind, ShardClose, ShardSet,
    EMISSION_KAT_SHAPE,
};
use shekyl_rpc_types::wire::archival as reply;
use shekyl_types::{BlockHeight, ChainCount};

pub(crate) const BUDGET: u64 = 1_000_000;
pub(crate) const SHARD_A: u64 = EMISSION_KAT_SHAPE.shard_a;
pub(crate) const SHARD_B: u64 = EMISSION_KAT_SHAPE.shard_b;

/// The canonical emission KAT snapshot. `sigma_work_milli` is derived
/// through the same sourcing functions the close persists with, so the
/// fixture's denominator is exactly what a real close would have stored.
pub(crate) fn snapshot(epoch: u64) -> EpochSnapshot {
    let shape = EMISSION_KAT_SHAPE;
    let close = epoch_close_height(epoch).expect("fixture epoch closes");
    let mut snap = EpochSnapshot {
        settlement_epoch: epoch,
        close_block_height: close,
        sigma_work_milli: 0,
        budget_atomic: BUDGET,
        has_budget_row: true,
        bonds: vec![
            BondRow {
                join_settlement_epoch: shape.join_settlement_epoch,
                is_support_complete_tree: false,
                bad_intervals: vec![],
            },
            BondRow {
                join_settlement_epoch: shape.join_settlement_epoch,
                is_support_complete_tree: false,
                bad_intervals: vec![],
            },
        ],
        shards: vec![
            EpochCloseShard {
                shard_id: shape.shard_a,
                close: ShardClose::ClosedAt(BlockHeight::from_raw(
                    close - shape.shard_a_freeze_offset,
                )),
            },
            EpochCloseShard {
                shard_id: shape.shard_b,
                close: ShardClose::ClosedAt(BlockHeight::from_raw(
                    close - shape.shard_b_freeze_offset,
                )),
            },
        ],
        credit_pairs: shape
            .credit_pairs
            .iter()
            .map(|&(bond_idx, shard_idx)| CreditPair {
                bond_idx,
                shard_idx,
            })
            .collect(),
        claimant_bond_idx: Some(shape.claimant_bond_idx),
    };
    resigma(&mut snap);
    assert!(
        snap.sigma_work_milli > 0,
        "fixture must have a live denominator"
    );
    snap
}

/// Recompute a (possibly mutated) fixture's denominator through the
/// same sourcing functions the close persists with.
pub(crate) fn resigma(snap: &mut EpochSnapshot) {
    let sigma = {
        let bonds = snap.bonds_view();
        let view = snap.source(&bonds);
        let served = as_of_e_served_work(&view.inputs).expect("well-formed fixture");
        sigma_work_milli(&served.work_by_bond, &served.member)
    };
    snap.sigma_work_milli = sigma;
}

/// A zero-share snapshot in its two indistinguishable causes: gated
/// (`sigma == 0`, the M1 zero-at-top outcome as persisted) or
/// no-serve-credit (`claimant_bond_idx == None`). Both must classify
/// identically ([`EpochSkip::ZeroShare`]) — the cause-blindness KAT
/// drives both through this one constructor.
pub(crate) fn zero_share_snapshot(epoch: u64, gated: bool) -> EpochSnapshot {
    let mut snap = snapshot(epoch);
    if gated {
        snap.sigma_work_milli = 0;
    } else {
        snap.claimant_bond_idx = None;
    }
    snap
}

/// A source at the smallest tip reporting `current_settled_epoch` —
/// one block past `settled − 1`'s close, derived through the landed
/// mapping functions (never `(E+1)·SEB` by hand) and asserted
/// consistent under `settlement_epoch_at_height`, the same invariant
/// PR 1's decode enforces on a real daemon reply.
pub(crate) fn source_with(
    current_settled_epoch: u64,
    claimed: Vec<u64>,
    epochs: Vec<EpochSnapshot>,
) -> EmissionClaimSource {
    let chain_height = match current_settled_epoch.checked_sub(1) {
        Some(prev) => epoch_close_height(prev).expect("fixture settled epoch maps") + 1,
        None => 1,
    };
    assert_eq!(
        settlement_epoch_at_height(chain_height),
        current_settled_epoch,
        "fixture coherence: the pair must satisfy the decode invariant"
    );
    EmissionClaimSource {
        chain_height: ChainCount::from_raw(chain_height),
        tip_hash: crate::engine::test_support::test_block_hash_at(chain_height - 1),
        current_settled_epoch,
        bond: Some(BondContext {
            join_settlement_epoch: EMISSION_KAT_SHAPE.join_settlement_epoch,
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![SHARD_A]).unwrap(),
            },
            claimed_settlement_epochs: claimed,
            bonded_total_atomic: 0,
            bad_interval_count: 0,
            last_served: ServeAnchor::NeverServed,
            last_settled_slash: SlashWatermark::NothingSettled,
        }),
        epochs,
    }
}

/// A source gathered at an explicit tip count, the settled epoch
/// derived from it through the same helper the daemon uses
/// (`archival_claim_source.cpp`: both from one `db.height()` read).
pub(crate) fn source_at_count(
    chain_height: u64,
    claimed: Vec<u64>,
    epochs: Vec<EpochSnapshot>,
) -> EmissionClaimSource {
    let mut source = source_with(settlement_epoch_at_height(chain_height), claimed, epochs);
    source.chain_height = ChainCount::from_raw(chain_height);
    source.tip_hash = crate::engine::test_support::test_block_hash_at(chain_height - 1);
    source
}

// ── The single test-side wire encoder ───────────────────────────────
//
// One Rust re-encoding of the daemon's `archival_claim_show` reply: the
// decode tests (`emission_source.rs`) and the claim orchestrator's e2e
// fetch leg both derive their fixtures from it, so a field rename cannot
// leave two test files updated out of lockstep. It builds the shared wire
// type, so the shape it writes is the method table's.

fn integer(value: u64) -> shekyl_rpc_types::kinds::Integer {
    shekyl_rpc_types::kinds::Integer(value)
}

fn amount(value: u64) -> shekyl_units::wire::AtomicUnitsString {
    shekyl_units::AtomicUnits::from_raw(value).into()
}

/// An [`EpochSnapshot`] as the daemon writes it.
pub(crate) fn epoch_reply(e: &EpochSnapshot) -> reply::Epoch {
    reply::Epoch {
        id: integer(e.settlement_epoch),
        closing_height: shekyl_rpc_types::kinds::Height(e.close_block_height),
        work: shekyl_rpc_types::kinds::Milli(e.sigma_work_milli),
        budget: e.has_budget_row.then(|| amount(e.budget_atomic)).into(),
        bond: e
            .bonds
            .iter()
            .map(|b| reply::ClaimBond {
                joined_epoch: integer(b.join_settlement_epoch),
                complete_tree: b.is_support_complete_tree,
                // Inclusive on the wire.
                failure: b
                    .bad_intervals
                    .iter()
                    .map(|i| reply::Failure {
                        from: integer(i.start_epoch),
                        to: integer(i.end_exclusive - 1),
                    })
                    .collect(),
            })
            .collect(),
        shard: e
            .shards
            .iter()
            .map(|s| {
                let wire = s.close.to_wire();
                reply::ClaimShard {
                    id: integer(s.shard_id),
                    freeze_height: shekyl_rpc_types::kinds::Height(wire.freeze_height),
                    segment: wire.has_segment,
                }
            })
            .collect(),
        credit: e
            .credit_pairs
            .iter()
            .map(|p| reply::Credit {
                bond: integer(p.bond_idx as u64),
                shard: integer(p.shard_idx as u64),
            })
            .collect(),
        claimant: e.claimant_bond_idx.map(|i| integer(i as u64)).into(),
    }
}

/// The `archival_claim_show` reply for a typed source — the inverse of
/// [`EmissionClaimSource::from_reply`], so a fixture built here decodes
/// through the real untrusted-boundary path.
pub(crate) fn source_reply(source: &EmissionClaimSource) -> reply::ClaimSource {
    let bond = source.bond.as_ref();
    reply::ClaimSource {
        height: shekyl_rpc_types::kinds::Height(source.chain_height.to_raw() - 1),
        hash: shekyl_rpc_types::hash::HashHex::from_bytes(*source.tip_hash.as_bytes()),
        settled_epoch: integer(source.current_settled_epoch),
        joined_epoch: bond.map(|b| integer(b.join_settlement_epoch)).into(),
        holding: match bond.map(|b| b.holdings.kind) {
            Some(HoldingsKind::CompleteTree) => reply::Holding::CompleteTree,
            _ => reply::Holding::Shards,
        },
        shard: bond.map_or_else(Vec::new, |b| {
            b.holdings.shard_ids.iter().copied().map(integer).collect()
        }),
        claimed: bond.map_or_else(Vec::new, |b| {
            b.claimed_settlement_epochs
                .iter()
                .copied()
                .map(integer)
                .collect()
        }),
        bond_total: amount(bond.map_or(0, |b| b.bonded_total_atomic)),
        failure_count: shekyl_rpc_types::kinds::Count(
            bond.map_or(0, |b| b.bad_interval_count as u64),
        ),
        served_epoch: bond
            .and_then(|b| b.last_served.as_verify_operand())
            .map(integer)
            .into(),
        slash_epoch: bond
            .and_then(|b| b.last_settled_slash.as_verify_operand())
            .map(integer)
            .into(),
        epoch: source.epochs.iter().map(epoch_reply).collect(),
    }
}

/// [`source_reply`] as the JSON a double answers with.
pub(crate) fn source_json(source: &EmissionClaimSource) -> serde_json::Value {
    serde_json::to_value(source_reply(source)).expect("a claim source serializes")
}
