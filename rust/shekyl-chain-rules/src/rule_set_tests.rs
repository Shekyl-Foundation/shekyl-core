// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `rule_set.rs` — the identity seed, the schedule lookup, and the invariant
//! that keeps a schedule from ever lacking an answer
//! (`CHAIN_RULES_CRATE.md` §8.4).

use shekyl_address::Network;
use shekyl_types::{BlockCount, BlockHeight};

use super::{
    well_formed, AdmissionPolicy, AdmissionPolicyId, FakechainSchedule, FakechainScheduleRefused,
    ReorgCapNotInsideEpoch, ResponseWindowOutrunsAnchor, RuleSchedule, RuleSet, RuleSetId,
    SettlementEpochBlocks, SettlementSchedule,
};
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

/// Bites: a genesis rule set that omits a per-block consensus row, lists
/// one out of census order, or lets an `enforced_at`, `by_construction` or
/// `held_by_store` row into the denominator per-block coverage is measured
/// against.
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
                RowStatus::EnforcedAt | RowStatus::ByConstruction | RowStatus::HeldByStore
            )
        })
        .collect();
    assert_eq!(enforced, expected);
    assert_eq!(
        enforced.len(),
        CenRow::ALL.len() - 41,
        "E5 is enforced at open and K1b, K4, D5, E2 at the alt tier; A3, A6, A7, F2, F8, F19, F21, G3, G4, G5, H2, H8, H12, H13, H23, I2, I3, L8, L9, L11, L12, L16 hold by construction; B3, K1a, K2, K3, K8 are held by the store, K5, K5b, K6, K7 by its writer's switch, M2, M8, K9 by the pool and A1, A4 by the ingest router"
    );
    assert_eq!(
        format!("{genesis:?}"),
        format!(
            "RuleSet {{ id: RuleSetId(1), enforced: {v} of {n} rows (per-block; held, at-open, by-construction and store-held rows excluded), header_major_version: 1, difficulty: Lwma1, mined_money_unlock_window: BlockCount(60), reorg_cap: BlockCount(720), tx_spendable_age: BlockCount(10), settlement_schedule: SettlementSchedule(10000) }}",
            v = CenRow::ALL.len() - 41,
            n = CenRow::ALL.len()
        )
    );
}

#[test]
fn admission_policy_is_the_staged_identity() {
    assert_eq!(AdmissionPolicy::GENESIS.id(), AdmissionPolicyId::GENESIS);
}

// ---- slice 4 Q5: the unlock window is the C++ define, not a restated number ----

/// CEN-F6's window is the C++ `#define` — read from `cryptonote_config.h`
/// itself, not from a copy of the number, so a C++ edit that moves the
/// window fails here rather than diverging silently.
#[test]
fn the_unlock_window_is_the_cxx_define() {
    let config_h = include_str!("../../../src/cryptonote_config.h");
    let line = config_h
        .lines()
        .find(|l| l.contains("#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW"))
        .expect("cryptonote_config.h defines CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW");
    let value: u64 = line
        .split_whitespace()
        .nth(2)
        .expect("the define carries a value")
        .parse()
        .expect("the value is an integer");
    assert_eq!(
        RuleSet::GENESIS.mined_money_unlock_window(),
        BlockCount::from_raw(value)
    );
    assert_eq!(value, 60, "the shipped window");
}

// ---- CEN-B1 / CEN-B2: the header's version pair is the C++ defines ----

/// The two bytes every header's version pair must equal are `#define`s in
/// `cryptonote_config.h` on the C++ side, where the validator and the
/// template both read them. Read from the header itself, as the window is,
/// so an edit to either side fails here.
#[test]
fn the_header_version_pair_is_the_cxx_defines() {
    let config_h = include_str!("../../../src/cryptonote_config.h");
    let define = |name: &str| -> u8 {
        config_h
            .lines()
            .find_map(|l| {
                let mut words = l.split_whitespace();
                (words.next() == Some("#define") && words.next() == Some(name))
                    .then(|| words.next().expect("the define carries a value"))
            })
            .unwrap_or_else(|| panic!("cryptonote_config.h defines {name}"))
            .parse()
            .unwrap_or_else(|_| panic!("{name}'s value is a u8"))
    };
    assert_eq!(
        define("CURRENT_BLOCK_MAJOR_VERSION"),
        RuleSet::GENESIS.header_major_version()
    );
    assert_eq!(
        define("CURRENT_BLOCK_MINOR_VERSION"),
        shekyl_wire::block::HEADER_MINOR_VERSION
    );
}

// ---- DRS-E3 CTW-Q5: the spendable age is the window's sibling ----

/// The listed-output maturity is the C++ `#define`, read from
/// `cryptonote_config.h` as the window is.
#[test]
fn the_spendable_age_is_the_cxx_define() {
    let config_h = include_str!("../../../src/cryptonote_config.h");
    let line = config_h
        .lines()
        .find(|l| l.contains("#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE"))
        .expect("cryptonote_config.h defines CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE");
    let value: u64 = line
        .split_whitespace()
        .nth(2)
        .expect("the define carries a value")
        .parse()
        .expect("the value is an integer");
    assert_eq!(
        RuleSet::GENESIS.tx_spendable_age(),
        BlockCount::from_raw(value)
    );
    assert_eq!(value, 10, "the shipped age");
}

/// The maturity pair the tree grows by is the pair the wallet side's
/// eligibility arithmetic assumes (`shekyl_engine_state::transfer::SPENDABLE_AGE`
/// is `shekyl_consensus::DEFAULT_LOCK_WINDOW`; `recon::maturity_height` reads
/// both) — two names for one number on each side, held equal here so the
/// daemon's insertion height and the wallet's eligibility height cannot
/// drift (CTW-6: the age had two Rust homes and neither was this crate).
#[test]
fn the_maturity_pair_is_the_wallet_sides_lock_windows() {
    let g = RuleSet::GENESIS;
    assert_eq!(
        g.tx_spendable_age().to_raw(),
        u64::try_from(shekyl_consensus::DEFAULT_LOCK_WINDOW).expect("fits"),
    );
    assert_eq!(
        g.mined_money_unlock_window().to_raw(),
        u64::try_from(shekyl_consensus::COINBASE_LOCK_WINDOW).expect("fits"),
    );
    assert!(
        g.tx_spendable_age() < g.mined_money_unlock_window(),
        "a listed output enters the tree before the same block's coinbase (SOK-10)"
    );
}

// ---- PR #861 review: the reorg cap is rule-set data ----
// ---- DRS-E4 ARW-15: so is the settlement schedule, and the two are a pair ----

/// `GENESIS` carries `D_MAX` and the genesis epoch; a Fakechain set names
/// its own pair through the same witness `Fixed` uses, and the `RuleSetId`
/// caveat covers it: same id, compared by value.
/// `fakechain(None, PRODUCTION)` is `GENESIS`.
#[test]
fn the_schedule_is_the_rule_sets_and_fakechain_names_its_own() {
    use crate::D_MAX;
    assert_eq!(RuleSet::GENESIS.reorg_cap(), D_MAX);
    assert_eq!(
        RuleSet::GENESIS.settlement_schedule(),
        SettlementSchedule::GENESIS
    );
    assert_eq!(
        RuleSet::fakechain(None, FakechainSchedule::PRODUCTION),
        RuleSet::GENESIS
    );
    let short = RuleSet::fakechain(None, pair(10_000, 50));
    assert_eq!(short.id(), RuleSet::GENESIS.id(), "the caveat: same id");
    assert_ne!(short, RuleSet::GENESIS, "different set, compared by value");
    assert_eq!(short.reorg_cap(), BlockCount::from_raw(50));
    assert_eq!(
        short.settlement_schedule(),
        SettlementSchedule::GENESIS,
        "the cap moves without the epoch"
    );
    assert_eq!(
        short.difficulty(),
        RuleSet::GENESIS.difficulty(),
        "the cap moves without the target"
    );
    // The capture schedule the emission-claim vector runs (512/64).
    let shortened = RuleSet::fakechain(None, pair(512, 64));
    assert_eq!(shortened.settlement_schedule().blocks().get(), 512);
    assert_eq!(shortened.settlement_schedule().epoch_at_height(1025), 2);
    assert_eq!(shortened.reorg_cap(), BlockCount::from_raw(64));
    // Three Fakechain parameters, one witness.
    let all = RuleSet::fakechain(core::num::NonZeroU128::new(7), pair(512, 64));
    assert_ne!(all, shortened);
    assert_eq!(all.reorg_cap(), shortened.reorg_cap());
    assert_eq!(all.settlement_schedule(), shortened.settlement_schedule());
}

/// SPR-9 at the rule-set site: the pair refuses a cap that is not strictly
/// inside its epoch — zero, equal, or above — so `fakechain` cannot build
/// a set whose undo floor would cross the body horizon. Bites if the
/// constructor turns infallible or the bound goes non-strict.
#[test]
fn a_fakechain_schedule_refuses_a_cap_not_inside_its_epoch() {
    let seb = SettlementEpochBlocks::new(512).expect("non-zero");
    for cap in [0u64, 512, 513, u64::MAX] {
        assert_eq!(
            FakechainSchedule::new(seb, BlockCount::from_raw(cap)),
            Err(FakechainScheduleRefused::ReorgCapNotInsideEpoch(
                ReorgCapNotInsideEpoch {
                    settlement_epoch: seb,
                    reorg_cap: BlockCount::from_raw(cap),
                }
            )),
            "cap {cap} against SEB 512"
        );
    }
    for cap in [1u64, 64, 511] {
        assert!(
            FakechainSchedule::new(seb, BlockCount::from_raw(cap)).is_ok(),
            "cap {cap} against SEB 512"
        );
    }
    assert_eq!(
        FakechainSchedule::new(
            SettlementEpochBlocks::new(10_000).expect("non-zero"),
            crate::D_MAX
        ),
        Ok(FakechainSchedule::PRODUCTION),
        "the production pair is what `new` builds from the production numbers"
    );
    assert_eq!(
        ReorgCapNotInsideEpoch {
            settlement_epoch: seb,
            reorg_cap: BlockCount::from_raw(512),
        }
        .to_string(),
        "reorg cap 512 is not strictly inside the settlement epoch (512 blocks/epoch): 0 < cap < SEB is required"
    );
}

/// The three epochs the anchor relation turns on, derived from the
/// constants it is stated over and not written as numbers: the first and
/// last epoch whose response window is the widest that fits
/// (`depth − L`), and the first epoch past it.
struct AnchorBoundary {
    widest_window: u64,
    first_at: u64,
    last_at: u64,
    first_past: u64,
}

fn anchor_boundary() -> AnchorBoundary {
    use shekyl_archival_retention::constants::W2_EPOCH_DIVISOR;
    use shekyl_archival_retention::{PASS_ANCHOR_DEPTH_BLOCKS, PASS_ANCHOR_LAG_BLOCKS};
    let widest_window = PASS_ANCHOR_DEPTH_BLOCKS.to_raw() - PASS_ANCHOR_LAG_BLOCKS.to_raw();
    AnchorBoundary {
        widest_window,
        first_at: widest_window * W2_EPOCH_DIVISOR,
        last_at: (widest_window + 1) * W2_EPOCH_DIVISOR - 1,
        first_past: (widest_window + 1) * W2_EPOCH_DIVISOR,
    }
}

/// `SCS-P32`'s rule-set relation, `W₂ + L ≤` anchor depth, at its exact
/// boundary and one past it, as `FakechainSchedule::new`'s typed refusal.
/// Every epoch here is computed from `PASS_ANCHOR_DEPTH_BLOCKS`,
/// `PASS_ANCHOR_LAG_BLOCKS` and `W2_EPOCH_DIVISOR`, so a re-pin of any of
/// them moves the test with it and cannot leave it asserting about a
/// boundary that is no longer the boundary.
///
/// Bites against `<` for `≤` (the boundary epochs are refused), against a
/// relation that ignores `L` (the epochs just past the boundary build),
/// against a `None` window read as a violation, and against the refusal
/// going back to a panic or to the cap's arm. Does not cover whether the
/// persona's gate and the requester agree on `L`; that is `SF-D8`'s.
#[test]
fn a_schedule_whose_window_outruns_the_anchor_is_refused_at_its_boundary() {
    use shekyl_archival_retention::anchor_depth_covers_response_window;
    let boundary = anchor_boundary();
    let schedule =
        |seb: u64| SettlementSchedule::new(SettlementEpochBlocks::new(seb).expect("non-zero"));
    let window = |seb: u64| {
        schedule(seb)
            .challenge_response_blocks()
            .map(core::num::NonZeroU64::get)
    };
    let build = |seb: u64| {
        FakechainSchedule::new(
            SettlementEpochBlocks::new(seb).expect("non-zero"),
            BlockCount::from_raw(1),
        )
    };
    assert_eq!(
        ResponseWindowOutrunsAnchor::LONGEST_EPOCH_BLOCKS,
        boundary.last_at,
        "the ceiling the refusal names is the boundary"
    );

    // At the boundary: the widest window that fits, at both ends of the
    // run of epochs that have it.
    for seb in [boundary.first_at, boundary.last_at] {
        assert_eq!(window(seb), Some(boundary.widest_window), "SEB {seb}");
        assert!(anchor_depth_covers_response_window(schedule(seb)));
        let pair = build(seb).unwrap_or_else(|e| panic!("SEB {seb} is at the boundary: {e}"));
        assert!(pair.anchor_covers_response_window());
        assert!(RuleSet::fakechain(None, pair).anchor_covers_response_window());
    }
    // One block of window past it, and far past it.
    for seb in [
        boundary.first_past,
        boundary.first_past + 1,
        boundary.first_past * 2,
        u64::MAX,
    ] {
        let wide = window(seb).expect("an epoch this long has a window");
        assert!(wide > boundary.widest_window, "SEB {seb}");
        assert!(!anchor_depth_covers_response_window(schedule(seb)));
        assert_eq!(
            build(seb),
            Err(FakechainScheduleRefused::ResponseWindowOutrunsAnchor(
                ResponseWindowOutrunsAnchor {
                    settlement_epoch: SettlementEpochBlocks::new(seb).expect("non-zero"),
                    response_window: BlockCount::from_raw(wide),
                }
            )),
            "SEB {seb}"
        );
    }
    // An epoch too short to have a window has nothing to cover.
    let windowless = shekyl_archival_retention::constants::W2_EPOCH_DIVISOR - 1;
    assert_eq!(window(windowless), None);
    assert!(build(windowless).is_ok());

    // The cap is asked first, so a pair that breaks both is refused for
    // the cap: each existing refusal keeps its meaning.
    assert!(matches!(
        FakechainSchedule::new(
            SettlementEpochBlocks::new(boundary.first_past).expect("non-zero"),
            BlockCount::ZERO,
        ),
        Err(FakechainScheduleRefused::ReorgCapNotInsideEpoch(_))
    ));
}

/// The refusal tells an operator what they asked for, why it is refused
/// and the value that works (`82-failure-mode-ux`): the epoch, the window
/// it implies, the lag and the depth, and the longest epoch a schedule may
/// name. Bites if the message stops naming the ceiling, or names a
/// number that is not the one `new` enforces.
#[test]
fn the_anchor_refusal_says_which_epoch_would_work() {
    let boundary = anchor_boundary();
    let refused = FakechainSchedule::new(
        SettlementEpochBlocks::new(boundary.first_past).expect("non-zero"),
        BlockCount::from_raw(1),
    )
    .expect_err("one past the boundary");
    let message = refused.to_string();
    for needed in [
        format!(
            "settlement epoch of {} blocks is too long",
            boundary.first_past
        ),
        format!("window is {} blocks", boundary.widest_window + 1),
        format!("at most {} blocks", boundary.last_at),
    ] {
        assert!(message.contains(&needed), "{message:?} lacks {needed:?}");
    }
    // The ceiling it names is admitted, and the next epoch is not.
    let at = |seb: u64| {
        FakechainSchedule::new(
            SettlementEpochBlocks::new(seb).expect("non-zero"),
            BlockCount::from_raw(1),
        )
    };
    assert!(at(ResponseWindowOutrunsAnchor::LONGEST_EPOCH_BLOCKS).is_ok());
    assert!(at(ResponseWindowOutrunsAnchor::LONGEST_EPOCH_BLOCKS + 1).is_err());
}

/// Every rule set the crate can build satisfies the relation: each issued
/// set, the set every network's schedule names at any height, and the
/// production pair. A Fakechain set needs no list of epochs here: a
/// `FakechainSchedule` exists only if `new` admitted it, so each fixture
/// that builds one — in this crate, the store's or the ingest's — is
/// checked where it is built, with the epoch it actually uses. Bites if
/// the compile-time assertion over `ISSUED` is dropped and a set with a
/// longer epoch is issued.
#[test]
fn every_rule_set_the_crate_builds_anchors_below_its_block() {
    assert!(RuleSet::GENESIS.anchor_covers_response_window());
    assert!(FakechainSchedule::PRODUCTION.anchor_covers_response_window());
    assert!(RuleSet::fakechain(None, FakechainSchedule::PRODUCTION).anchor_covers_response_window());
    for set in RuleSet::ISSUED {
        assert!(set.anchor_covers_response_window(), "{:?}", set.id());
    }
    for network in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        let schedule = RuleSchedule::for_network(network);
        for height in [0u64, 1, 10_000, u64::MAX] {
            let id = schedule.rules_at(BlockHeight::from_raw(height));
            let set = RuleSet::for_id(id).expect("a schedule names issued sets");
            assert!(
                set.anchor_covers_response_window(),
                "{network:?} at {height}"
            );
        }
    }
}

/// A valid `(SEB, cap)` pair for the tests above.
fn pair(seb: u64, cap: u64) -> FakechainSchedule {
    FakechainSchedule::new(
        SettlementEpochBlocks::new(seb).expect("non-zero"),
        BlockCount::from_raw(cap),
    )
    .expect("a valid pair")
}
