// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `rule_set.rs` — the identity seed, the schedule lookup, and the invariant
//! that keeps a schedule from ever lacking an answer
//! (`CHAIN_RULES_CRATE.md` §8.4).

use shekyl_address::Network;
use shekyl_types::BlockHeight;

use super::{well_formed, AdmissionPolicy, AdmissionPolicyId, RuleSchedule, RuleSet, RuleSetId};
use crate::census::{CenRow, RowStatus};

const NETWORKS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Stagenet];

const fn height(raw: u64) -> BlockHeight {
    BlockHeight::from_raw(raw)
}

/// The identity seed, pinned: every network, every height → `GENESIS`.
/// Bites: a schedule that names a second rule set before one is issued.
#[test]
fn every_schedule_is_the_identity_today() {
    for network in NETWORKS {
        let schedule = RuleSchedule::for_network(network);
        for raw in [0, 1, u64::MAX] {
            assert_eq!(
                schedule.rules_at(height(raw)),
                RuleSetId::GENESIS,
                "{network:?} at height {raw}"
            );
        }
    }
}

/// Bites: a `rules_at` that takes the first step *above* the height, that
/// treats a step's own height as before the step, or that ignores `genesis`
/// below the first step.
#[test]
fn rules_at_is_the_last_step_at_or_below_the_height() {
    const TWO: RuleSetId = RuleSetId::from_raw(2);
    const THREE: RuleSetId = RuleSetId::from_raw(3);
    const STEPS: &[(BlockHeight, RuleSetId)] = &[(height(10), TWO), (height(20), THREE)];
    let schedule = RuleSchedule {
        genesis: RuleSetId::GENESIS,
        steps: STEPS,
    };
    let at = |raw: u64| schedule.rules_at(height(raw));

    assert_eq!(at(0), RuleSetId::GENESIS);
    assert_eq!(at(9), RuleSetId::GENESIS);
    assert_eq!(at(10), TWO, "a step is in force at its own height");
    assert_eq!(at(19), TWO);
    assert_eq!(at(20), THREE);
    assert_eq!(at(u64::MAX), THREE);
}

/// The compile-time pin's predicate, exercised on the shapes it refuses so
/// its green on the real schedules means something. Bites: a `well_formed`
/// that accepts a step at `ZERO`, an out-of-order step, or an unissued id.
#[test]
fn well_formed_refuses_each_malformed_shape() {
    const UNISSUED: RuleSetId = RuleSetId::from_raw(7);
    const GENESIS_STEP: &[(BlockHeight, RuleSetId)] = &[(height(0), RuleSetId::GENESIS)];
    const REPEATED: &[(BlockHeight, RuleSetId)] = &[
        (height(10), RuleSetId::GENESIS),
        (height(10), RuleSetId::GENESIS),
    ];
    const DESCENDING: &[(BlockHeight, RuleSetId)] = &[
        (height(20), RuleSetId::GENESIS),
        (height(10), RuleSetId::GENESIS),
    ];
    const UNISSUED_STEP: &[(BlockHeight, RuleSetId)] = &[(height(10), UNISSUED)];
    const ASCENDING: &[(BlockHeight, RuleSetId)] = &[
        (height(10), RuleSetId::GENESIS),
        (height(20), RuleSetId::GENESIS),
    ];
    const NONE: &[(BlockHeight, RuleSetId)] = &[];

    let with = |genesis, steps| RuleSchedule { genesis, steps };

    assert!(well_formed(&RuleSchedule::for_network(Network::Mainnet)));
    assert!(well_formed(&with(RuleSetId::GENESIS, ASCENDING)));

    assert!(
        !well_formed(&with(RuleSetId::GENESIS, GENESIS_STEP)),
        "a step at ZERO shadows `genesis`"
    );
    assert!(!well_formed(&with(RuleSetId::GENESIS, REPEATED)));
    assert!(!well_formed(&with(RuleSetId::GENESIS, DESCENDING)));
    assert!(!well_formed(&with(RuleSetId::GENESIS, UNISSUED_STEP)));
    assert!(
        !well_formed(&with(UNISSUED, NONE)),
        "genesis itself must be issued"
    );
}

/// Bites: a `for_id` that mints a rule set for any id, or that misses the
/// one it has.
#[test]
fn for_id_resolves_issued_ids_only() {
    assert_eq!(RuleSet::for_id(RuleSetId::GENESIS), Some(RuleSet::GENESIS));
    assert_eq!(
        RuleSet::for_id(RuleSet::GENESIS.id()),
        Some(RuleSet::GENESIS)
    );
    assert_eq!(RuleSet::for_id(RuleSetId::from_raw(0)), None);
    assert_eq!(RuleSet::for_id(RuleSetId::from_raw(2)), None);
}

/// `GENESIS` is raw `1` — coincident with `major_version == 1`, documented as
/// a fact about the table and not a definition (no `PartialEq<u8>` exists;
/// the doctest on `RuleSetId` pins that). Bites: a renumbering.
#[test]
fn genesis_id_is_one_and_round_trips() {
    assert_eq!(RuleSetId::GENESIS.to_raw(), 1);
    assert_eq!(RuleSetId::from_raw(1), RuleSetId::GENESIS);
}

/// Bites: a genesis rule set that omits a validator-enforced consensus row,
/// lists one out of census order, or lets a `held_by_cxx` or `enforced_at`
/// row into the denominator per-block coverage is measured against.
#[test]
fn genesis_enforces_the_census_minus_held_rows_in_order() {
    let genesis = RuleSet::GENESIS;
    let enforced: Vec<CenRow> = genesis.enforced().collect();
    let expected: Vec<CenRow> = CenRow::ALL
        .iter()
        .copied()
        .filter(|row| {
            !matches!(
                row.status(),
                RowStatus::HeldByCxx | RowStatus::EnforcedAt | RowStatus::ByConstruction
            )
        })
        .collect();
    assert_eq!(enforced, expected);
    assert_eq!(
        enforced.len(),
        CenRow::ALL.len() - 3,
        "A1 and A4 are held; E5 is enforced at open"
    );
    assert_eq!(
        format!("{genesis:?}"),
        format!(
            "RuleSet {{ id: RuleSetId(1), enforced: {v} of {n} rows (per-block; held and at-open rows excluded), header_major_version: 1, difficulty: Lwma1 }}",
            v = CenRow::ALL.len() - 3,
            n = CenRow::ALL.len()
        )
    );
}

#[test]
fn admission_policy_is_the_staged_identity() {
    assert_eq!(AdmissionPolicy::GENESIS.id(), AdmissionPolicyId::GENESIS);
}
