// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for the bond-state rows: CEN-J4/J5/J6 on a serve-credit vin
//! and CEN-J13 on a bond post (below) — the arms a view with **no bonds**
//! can witness. `MockChain` holds no
//! records by policy (`harness.rs`, `archival_reads!(empty)`; DRS-E4 §5.2,
//! *No `Mock*` archival state*), which is exactly J4's negative: a credit
//! for a persona with no record. J5 and J6 need a record to read a join
//! epoch and an interval log from, so their negatives are the ingest
//! driver's — a real chain that posted the bond, through `connect`
//! (`archival_admission_tests.rs`, the J5 and J6 pins) — never a record
//! constructed here. The three rows' vacuity on every other class is also
//! this file's.

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::harness::fixture::{
    anchored_on, candidate_on, coinbase, join_market, listed, persona, point, serve_credit_only,
    spendable_chain,
};
use crate::harness::{assert_refused, defined, formed_on, judged, MockChain};
use crate::rule_set::RuleSet;
use crate::rules::tx_bond::{judge_bond_post_key, judge_serve_credit_bond};
use crate::rules::TxContext;
use crate::trust::Trust;
use crate::validate::{tx_against, validate};
use crate::verdict::{Locus, TxSlot};
use shekyl_archival_retention::BondPostKind as RetentionKind;
use shekyl_wire::{BondPostKind, Ct, Input, Transaction};

const P: [u8; 32] = [0x5e; 32];
const ROWS: [CenRow; 3] = [CenRow::J4, CenRow::J5, CenRow::J6];

/// CEN-J4 at the pool's slot: a credit for a persona the view has no
/// record for is refused on J4 at its **vin**, through `tx_against` — the
/// pool's call. Until E6 slice 8 row 3 this body passed every rule and met
/// the fold's L7 at connect (row 2's measurement); the refusal is now the
/// rule's, and the fold's arm is the backstop beneath it.
#[test]
fn j4_refuses_a_credit_for_a_persona_with_no_record_at_the_pool_slot() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        assert_refused(
            defined(tx_against(
                &serve_credit_only(P),
                TxSlot::Lone,
                &view,
                &RuleSet::GENESIS,
            )),
            CenRow::J4,
            Locus::Input {
                slot: TxSlot::Lone,
                input: 0,
            },
        );
    });
}

/// The same body listed first in a block is refused by `validate` on J4 at
/// `Listed(0)`'s vin — one function, two sites — and **before** the
/// archival fold runs (L7 would refuse it there; the row that names the
/// reason is J4's, and the census pin in `scenario_archival_tests.rs`
/// moved from L7 to J4 with this rule).
#[test]
fn j4_refuses_the_same_credit_listed_before_the_fold_reaches_it() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        let formed = formed_on(
            &chain,
            candidate_on(&chain, vec![anchored_on(&chain, serve_credit_only(P))]),
        );
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            CenRow::J4,
            Locus::Input {
                slot: TxSlot::Listed(0),
                input: 0,
            },
        );
    });
}

/// A multi-vin credit is refused at the vin that fails, in vin order: two
/// credits for two personas with no record name vin 0, not the body.
#[test]
fn j4_names_the_first_failing_vin() {
    let chain = spendable_chain();
    let mut two = serve_credit_only(P);
    two.prefix
        .inputs
        .push(serve_credit_only([0x5f; 32]).prefix.inputs[0].clone());
    chain.with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        let cx = TxContext::derive(&two, TxSlot::Lone, &mut coverage)
            .expect("two serve-credit vins classify as serve-credit-only");
        assert_refused(
            judge_serve_credit_bond(&cx, &view, &mut coverage)
                .unwrap_or_else(|never| match never {}),
            CenRow::J4,
            Locus::Input {
                slot: TxSlot::Lone,
                input: 0,
            },
        );
        for row in ROWS {
            assert!(
                !coverage.contains(row),
                "{row}: a refusal records nothing — the rows are recorded after the loop"
            );
        }
    });
}

/// On every class that is not a serve credit the three rows are recorded
/// **vacuous, not absent** (slice 5 Q2): a spend and a coinbase have no
/// credit vin, and the sequence reads nothing.
#[test]
fn j4_j5_j6_are_vacuous_off_the_serve_credit_class() {
    let chain = MockChain::default();
    chain.with_view(|view| {
        for (name, tx, slot) in [
            ("spend", listed(point(9)), TxSlot::Lone),
            ("coinbase", coinbase(0), TxSlot::Miner),
        ] {
            let mut coverage = RuleCoverage::EMPTY;
            let cx = TxContext::derive(&tx, slot, &mut coverage)
                .unwrap_or_else(|refused| panic!("{name} classifies: {refused}"));
            judge_serve_credit_bond(&cx, &view, &mut coverage)
                .unwrap_or_else(|never| match never {})
                .unwrap_or_else(|refused| panic!("{name}: nothing to judge, but {refused}"));
            for row in ROWS {
                assert!(coverage.contains(row), "{name}: {row} recorded vacuous");
            }
        }
    });
}

// ---- CEN-J13, the key-selection rule on a bond post (slice 8 row 4) -----
//
// The arms a view with **no bonds** can witness: the credit arms, which
// read no record — a JoinMarket or Reinstate whose slot carries a key
// other than the post's identity key — and the Release-without-a-record
// case, which is not this row's. The Release arm with a record (the
// poster's identity key against the record's `bond_spend_pk`; the pin
// `cold_authority_pin` refuses) is the ingest driver's, over a chain that
// posted the bond (`archival_admission_tests.rs`, the J13 pin), by the
// same policy as J5 and J6.

const BOND_KI: [u8; 32] = point(11);
const WHO: [u8; 32] = [0x6a; 32];

/// `tx`'s bond slot carrying `key` — edited **after** [`anchored_on`] has
/// signed, so the slot's signature is the persona's and only the key the
/// verifier reads has moved. J13 runs before I18, so the row that fires is
/// the key's, not the signature's.
fn slot_carrying(mut tx: Transaction, key: Vec<u8>) -> Transaction {
    let slot = tx
        .prefix
        .inputs
        .iter()
        .position(|item| matches!(item, Input::BondPost(_)))
        .expect("a bond post");
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths[slot].hybrid_public_key = key;
    }
    tx
}

/// CEN-J13's credit arm at the pool's slot: a JoinMarket whose slot
/// carries another persona's identity key — or the poster's own
/// bond-spend key — is refused on J13 at the post's **vin**, through
/// `tx_against`; the same join with its identity key in the slot passes
/// the row. A Reinstate is judged on the same arm.
#[test]
fn j13_a_credit_post_signs_with_the_identity_key() {
    let chain = spendable_chain();
    let who = persona(WHO);
    let stranger = persona([0x6b; 32]);
    let reinstate = |mut tx: Transaction| {
        for item in &mut tx.prefix.inputs {
            if let Input::BondPost(post) = item {
                post.kind = BondPostKind::Other(RetentionKind::Reinstate as u8);
            }
        }
        tx
    };
    chain.with_view(|view| {
        let join = anchored_on(&chain, join_market(BOND_KI, WHO));
        for (name, tx) in [
            (
                "a stranger's key on a join",
                slot_carrying(join.clone(), stranger.identity.clone()),
            ),
            (
                "the bond-spend key on a join",
                slot_carrying(join.clone(), who.bond_spend.clone()),
            ),
            (
                "a stranger's key on a reinstate",
                slot_carrying(
                    anchored_on(&chain, reinstate(join_market(BOND_KI, WHO))),
                    stranger.identity.clone(),
                ),
            ),
        ] {
            let mut coverage = RuleCoverage::EMPTY;
            let cx = TxContext::derive(&tx, TxSlot::Lone, &mut coverage)
                .unwrap_or_else(|r| panic!("{name} classifies: {r}"));
            assert_refused(
                judge_bond_post_key(&cx, &view, &mut coverage)
                    .unwrap_or_else(|never| match never {}),
                CenRow::J13,
                Locus::Input {
                    slot: TxSlot::Lone,
                    input: 1,
                },
            );
            assert!(
                !coverage.contains(CenRow::J13),
                "{name}: a refusal records nothing"
            );
            assert_refused(
                defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
                CenRow::J13,
                Locus::Input {
                    slot: TxSlot::Lone,
                    input: 1,
                },
            );
        }
        let against = defined(tx_against(&join, TxSlot::Lone, &view, &RuleSet::GENESIS))
            .expect("the fixture join signs with its identity key");
        assert!(against.contains(CenRow::J13));
    });
}

/// The same mis-keyed join listed first in a block is refused by
/// `validate` on J13 at `Listed(0)`'s vin — before the signatures (I18)
/// and before the fold writes the record.
#[test]
fn j13_refuses_the_same_mis_keyed_join_listed() {
    let chain = spendable_chain();
    let stranger = persona([0x6b; 32]);
    chain.with_view(|view| {
        let join = slot_carrying(
            anchored_on(&chain, join_market(BOND_KI, WHO)),
            stranger.identity,
        );
        let formed = formed_on(&chain, candidate_on(&chain, vec![join]));
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            CenRow::J13,
            Locus::Input {
                slot: TxSlot::Listed(0),
                input: 1,
            },
        );
    });
}

/// A Release for a persona the view has **no record** for is not J13's:
/// the C++ gates `cold_authority_pin` on `have_record` and the missing
/// record is the semantic verify's — here the fold's L7. The row records
/// evaluated whichever key the slot carries; what refuses the body is
/// L7 at connect. (With a record, the identity key in the slot is the
/// refusal the driver pins.) A kind no arm names is likewise not this
/// row's.
#[test]
fn j13_a_release_with_no_record_is_the_folds_not_this_rows() {
    let chain = spendable_chain();
    let who = persona(WHO);
    let as_kind = |kind: u8| {
        let mut tx = join_market(BOND_KI, WHO);
        for item in &mut tx.prefix.inputs {
            if let Input::BondPost(post) = item {
                post.kind = BondPostKind::Other(kind);
                post.bond_credit = 0;
            }
        }
        anchored_on(&chain, tx)
    };
    chain.with_view(|view| {
        for (name, tx) in [
            (
                "a release under the bond-spend key",
                as_kind(RetentionKind::Release as u8),
            ),
            (
                "a release under the identity key",
                slot_carrying(as_kind(RetentionKind::Release as u8), who.identity.clone()),
            ),
            ("a kind no arm names", as_kind(9)),
        ] {
            let mut coverage = RuleCoverage::EMPTY;
            let cx = TxContext::derive(&tx, TxSlot::Lone, &mut coverage)
                .unwrap_or_else(|r| panic!("{name} classifies: {r}"));
            judge_bond_post_key(&cx, &view, &mut coverage)
                .unwrap_or_else(|never| match never {})
                .unwrap_or_else(|r| panic!("{name}: not J13's, but {r}"));
            assert!(coverage.contains(CenRow::J13), "{name}: J13 recorded");
        }
    });
}

/// On every class that is not a bond post the row is recorded **vacuous,
/// not absent** (slice 5 Q2).
#[test]
fn j13_is_vacuous_off_the_bond_post_class() {
    let chain = MockChain::default();
    chain.with_view(|view| {
        for (name, tx, slot) in [
            ("spend", listed(point(9)), TxSlot::Lone),
            ("serve credit", serve_credit_only(P), TxSlot::Lone),
            ("coinbase", coinbase(0), TxSlot::Miner),
        ] {
            let mut coverage = RuleCoverage::EMPTY;
            let cx = TxContext::derive(&tx, slot, &mut coverage)
                .unwrap_or_else(|refused| panic!("{name} classifies: {refused}"));
            judge_bond_post_key(&cx, &view, &mut coverage)
                .unwrap_or_else(|never| match never {})
                .unwrap_or_else(|refused| panic!("{name}: nothing to judge, but {refused}"));
            assert!(
                coverage.contains(CenRow::J13),
                "{name}: J13 recorded vacuous"
            );
        }
    });
}
