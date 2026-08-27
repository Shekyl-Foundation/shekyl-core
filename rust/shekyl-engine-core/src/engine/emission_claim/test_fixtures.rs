// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use crate::engine::emission_source::{
    BondContext, BondRow, EmissionClaimSource, EpochSnapshot, ServeAnchor, SlashWatermark,
};
use shekyl_archival_retention::{
    as_of_e_served_work, epoch_close_height, settlement_epoch_at_height, sigma_work_milli,
    CreditPair, EpochCloseShard, HoldingsDescriptor, HoldingsKind, ShardSet, EMISSION_KAT_SHAPE,
};
use shekyl_types::ChainCount;

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
                is_foundation_complete_tree: false,
                bad_intervals: vec![],
            },
            BondRow {
                join_settlement_epoch: shape.join_settlement_epoch,
                is_foundation_complete_tree: false,
                bad_intervals: vec![],
            },
        ],
        shards: vec![
            EpochCloseShard {
                shard_id: shape.shard_a,
                has_segment: true,
                freeze_height: close - shape.shard_a_freeze_offset,
            },
            EpochCloseShard {
                shard_id: shape.shard_b,
                has_segment: true,
                freeze_height: close - shape.shard_b_freeze_offset,
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
    source
}

// ── The single test-side wire encoder ───────────────────────────────
//
// One Rust re-encoding of the daemon's `get_archival_emission_claim_source`
// JSON shape: the decode tests (`emission_source.rs`) and the claim
// orchestrator's e2e fetch leg both derive their fixtures from it, so a
// field rename cannot leave two test files updated out of lockstep. The
// shape's independent pin is the C++ wire-contract test on the
// serializer side (`archival_claim_source_rpc.cpp`) — one Rust copy,
// one C++ pin, no third source of truth.

/// A JSON array field the way epee KV serialization emits it: **omitted
/// when empty** (epee omits empty containers), so the decoder's
/// absent-decodes-empty rule stays exercised by every fixture built
/// through this encoder.
fn put_array<T: Clone + Into<serde_json::Value>>(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
    values: &[T],
) {
    if !values.is_empty() {
        obj.insert(
            field.to_owned(),
            serde_json::Value::Array(values.iter().cloned().map(Into::into).collect()),
        );
    }
}

/// Re-encode an [`EpochSnapshot`] as the daemon's epee KV JSON emits it.
pub(crate) fn epoch_json(e: &EpochSnapshot) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("settlement_epoch".into(), e.settlement_epoch.into());
    obj.insert("close_block_height".into(), e.close_block_height.into());
    obj.insert("sigma_work_milli".into(), e.sigma_work_milli.into());
    obj.insert("budget_atomic".into(), e.budget_atomic.into());
    obj.insert("has_budget_row".into(), e.has_budget_row.into());
    let bonds: Vec<serde_json::Value> = e
        .bonds
        .iter()
        .map(|b| {
            let mut bond = serde_json::Map::new();
            bond.insert(
                "join_settlement_epoch".into(),
                b.join_settlement_epoch.into(),
            );
            bond.insert(
                "is_foundation_complete_tree".into(),
                b.is_foundation_complete_tree.into(),
            );
            let flat: Vec<u64> = b
                .bad_intervals
                .iter()
                .flat_map(|i| [i.start_epoch, i.end_exclusive])
                .collect();
            put_array(&mut bond, "bad_intervals_flat", &flat);
            serde_json::Value::Object(bond)
        })
        .collect();
    put_array(&mut obj, "bonds", &bonds);
    let shards: Vec<serde_json::Value> = e
        .shards
        .iter()
        .map(|s| {
            serde_json::json!({
                "shard_id": s.shard_id,
                "freeze_height": s.freeze_height,
                "has_segment": s.has_segment,
            })
        })
        .collect();
    put_array(&mut obj, "shards", &shards);
    let pairs: Vec<serde_json::Value> = e
        .credit_pairs
        .iter()
        .map(|p| {
            serde_json::json!({
                "bond_idx": p.bond_idx,
                "shard_idx": p.shard_idx,
            })
        })
        .collect();
    put_array(&mut obj, "credit_pairs", &pairs);
    obj.insert(
        "claimant_bond_idx".into(),
        e.claimant_bond_idx.map_or(u64::MAX, |i| i as u64).into(),
    );
    serde_json::Value::Object(obj)
}

/// The full `get_archival_emission_claim_source` result body for a
/// typed source — the inverse of `EmissionClaimSource::from_json`, so a
/// fixture built here decodes through the real untrusted-boundary path.
pub(crate) fn source_json(source: &EmissionClaimSource) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("status".into(), "OK".into());
    obj.insert("chain_height".into(), source.chain_height.to_raw().into());
    obj.insert(
        "current_settled_epoch".into(),
        source.current_settled_epoch.into(),
    );
    obj.insert("has_bond_record".into(), source.bond.is_some().into());
    if let Some(bond) = source.bond.as_ref() {
        obj.insert(
            "join_settlement_epoch".into(),
            bond.join_settlement_epoch.into(),
        );
        obj.insert(
            "holdings_kind".into(),
            match bond.holdings.kind {
                HoldingsKind::ShardSetCompact => 0u8,
                HoldingsKind::CompleteTree => 1u8,
            }
            .into(),
        );
        put_array(&mut obj, "held_shard_ids", &bond.holdings.shard_ids);
        put_array(
            &mut obj,
            "claimed_settlement_epochs",
            &bond.claimed_settlement_epochs,
        );
        obj.insert(
            "bonded_total_atomic".into(),
            bond.bonded_total_atomic.into(),
        );
        obj.insert(
            "bad_interval_count".into(),
            (bond.bad_interval_count as u64).into(),
        );
        // Emitted as the daemon emits them — flag plus value — so a fixture
        // cannot accidentally exercise a shape the wire never produces.
        let (served_flag, served_epoch) = match bond.last_served {
            ServeAnchor::NeverServed => (false, 0u64),
            ServeAnchor::ServedAt(e) => (true, e),
        };
        obj.insert("has_last_served_epoch".into(), served_flag.into());
        obj.insert("last_served_epoch".into(), served_epoch.into());
        let (slash_flag, slash_epoch) = match bond.last_settled_slash {
            SlashWatermark::NothingSettled => (false, 0u64),
            SlashWatermark::SettledThrough(e) => (true, e),
        };
        obj.insert("has_last_settled_slash_epoch".into(), slash_flag.into());
        obj.insert("last_settled_slash_epoch".into(), slash_epoch.into());
    }
    let epochs: Vec<serde_json::Value> = source.epochs.iter().map(epoch_json).collect();
    put_array(&mut obj, "epochs", &epochs);
    serde_json::Value::Object(obj)
}
