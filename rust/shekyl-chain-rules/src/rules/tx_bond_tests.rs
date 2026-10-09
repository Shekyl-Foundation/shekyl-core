// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for the bond-state rows: CEN-J4/J5/J6 on a serve-credit vin
//! and CEN-J13/J14/J15/J16/J18 on a bond post (below) — the arms a view
//! with **no bonds** can witness. `MockChain` holds no records by policy
//! (`harness.rs`, `archival_reads!(empty, r_market from …)`; DRS-E4 §5.2,
//! *No `Mock*` archival state*), which is exactly J4's negative: a credit
//! for a persona with no record. The one planted archival read is J15's
//! market price, for the reason `MockChain::with_r_market` gives. J5 and
//! J6 need a record to read a join epoch and an interval log from, so
//! their negatives are the ingest driver's — a real chain that posted the
//! bond, through `connect` (`archival_slash_tests.rs`, the J5 and J6
//! pins) — never a record constructed here. The three rows' vacuity on
//! every other class is also this file's.

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::harness::fixture::{
    anchored_on, candidate_on, coinbase, join_market, listed, persona, point, serve_credit_only,
    spendable_chain, BOND_FLOOR,
};
use crate::harness::{assert_refused, defined, formed_on, judged, MockChain, MockView};
use crate::rule_set::RuleSet;
use crate::rules::tx_bond::{judge_bond_post, judge_serve_credit_bond};
use crate::rules::TxContext;
use crate::trust::Trust;
use crate::validate::{tx_against, validate};
use crate::verdict::{Locus, TxSlot, Verdict};
use shekyl_archival_retention::BondPostKind as RetentionKind;
use shekyl_types::archival::RMarket;
use shekyl_types::{SettlementEpoch, ShardId};
use shekyl_wire::transaction::{BondPost, Holdings};
use shekyl_wire::{BondPostKind, Ct, Input, Transaction};

const P: [u8; 32] = [0x5e; 32];
const ROWS: [CenRow; 3] = [CenRow::J4, CenRow::J5, CenRow::J6];
const POST_ROWS: [CenRow; 5] = [
    CenRow::J13,
    CenRow::J14,
    CenRow::J15,
    CenRow::J16,
    CenRow::J18,
];

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

// ---- CEN-J13, J14, J16, J18: the bond post against its record ----------
// ---- (slice 8 rows 4 and 5) ---------------------------------------------
//
// The arms a view with **no bonds** can witness: J14 whole (a join reads
// only the record's absence — its statics are the post's own); J13's join
// arm (a slot carrying a key other than the post's identity key); and the
// two `RecordMissing` refusals — a Release is J16's, a Reinstate J18's.
// Every arm that reads a record — J13's Release pin over the committed
// `bond_spend_pk`, J14's `RecordExists`, J16's full exit, cooldown and
// settlement, J18's open interval and holdings, J13's Reinstate arm (J18
// runs first and refuses the missing record) — is the ingest driver's,
// over a chain that posted the bond (`archival_slash_tests.rs`,
// `scenario_archival_tests.rs`), by the same policy as J5 and J6.

const BOND_KI: [u8; 32] = point(11);
const WHO: [u8; 32] = [0x6a; 32];

/// The post's vin at the pool's slot — every bond-post fixture spends at
/// input 0 and posts at input 1.
const POST_VIN: Locus = Locus::Input {
    slot: TxSlot::Lone,
    input: 1,
};

/// [`join_market`] with its post edited by `edit` before [`anchored_on`]
/// signs it — the statics J14 reads are the post's own, so the signature
/// is over the edited post and only the row under test is in question.
fn join_edited(chain: &MockChain, edit: impl FnOnce(&mut BondPost)) -> Transaction {
    let mut tx = join_market(BOND_KI, WHO);
    let post = tx
        .prefix
        .inputs
        .iter_mut()
        .find_map(|item| match item {
            Input::BondPost(post) => Some(post),
            _ => None,
        })
        .expect("a bond post");
    edit(post);
    anchored_on(chain, tx)
}

/// `judge_bond_post` over `tx` at the pool's slot, with the coverage it
/// recorded.
fn judged_post(tx: &Transaction, view: &MockView<'_, '_>) -> (Verdict<()>, RuleCoverage) {
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(tx, TxSlot::Lone, &mut coverage)
        .unwrap_or_else(|r| panic!("the post classifies: {r}"));
    let verdict = defined(judge_bond_post(&cx, view, &RuleSet::GENESIS, &mut coverage));
    (verdict, coverage)
}

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

/// CEN-J13's join arm at the pool's slot: a JoinMarket whose slot carries
/// another persona's identity key — or the poster's own bond-spend key —
/// is refused on J13 at the post's **vin**, through `tx_against`; the same
/// join with its identity key in the slot passes the row and records all
/// five on the sequence. Through `tx_against` whole that join reaches the
/// funding half and is refused there (CEN-J27, at the transaction): the
/// fixture's funding spend carries no proof over a tree the mock never
/// planted. The refusal row being J27 and not J13 is the order's witness
/// — the post rows ran, and passed, first. The accept whole is the
/// driver's (`scenario_join_tests`, slice 6 row 6). The Reinstate arm's
/// mis-key is the driver's too: with no record, J18 refuses the post
/// before J13 reads its key (the C++'s order, verify then pin), so the
/// arm is reachable here only through a record.
#[test]
fn j13_a_join_signs_with_the_identity_key() {
    let chain = spendable_chain();
    let who = persona(WHO);
    let stranger = persona([0x6b; 32]);
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
        ] {
            let (verdict, coverage) = judged_post(&tx, &view);
            assert_refused(verdict, CenRow::J13, POST_VIN);
            assert!(
                !coverage.contains(CenRow::J13),
                "{name}: a refusal records nothing"
            );
            assert_refused(
                defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
                CenRow::J13,
                POST_VIN,
            );
        }
        let (verdict, coverage) = judged_post(&join, &view);
        verdict.expect("the fixture join signs with its identity key at the floor");
        for row in POST_ROWS {
            assert!(coverage.contains(row), "{row} recorded on the fixture join");
        }
        assert_refused(
            defined(tx_against(&join, TxSlot::Lone, &view, &RuleSet::GENESIS)),
            CenRow::J27,
            Locus::Tx { slot: TxSlot::Lone },
        );
    });
}

/// CEN-J14 at the pool's slot, the statics `verify_join_market_bond_post`
/// reads off the post with **no record** behind it: a two-shard compact
/// join bonded at **one** floor (the multiplier — slice 8 §2's corpus gap;
/// the two-shard join at two floors is the driver's accept), an empty
/// compact set, a zero endpoint, a credit post carrying a debit, and a
/// post whose `bonded_total` and `bond_credit` disagree. Each is refused
/// on J14 at the post's vin, before J13 reads the slot's key — so a
/// mis-keyed under-bonded join refuses on J14, the C++'s order.
#[test]
fn j14_refuses_a_join_whose_statics_fail_the_verify() {
    let chain = spendable_chain();
    let stranger = persona([0x6b; 32]);
    chain.with_view(|view| {
        let cases: [(&str, Transaction); 6] = [
            (
                "two shards at one floor",
                join_edited(&chain, |post| {
                    post.holdings = Holdings::ShardSetCompact(vec![3, 4]);
                }),
            ),
            (
                "two shards at one floor, mis-keyed — J14 before J13",
                slot_carrying(
                    join_edited(&chain, |post| {
                        post.holdings = Holdings::ShardSetCompact(vec![3, 4]);
                    }),
                    stranger.identity.clone(),
                ),
            ),
            (
                "an empty compact set",
                join_edited(&chain, |post| {
                    post.holdings = Holdings::ShardSetCompact(Vec::new());
                }),
            ),
            (
                "a zero endpoint",
                join_edited(&chain, |post| {
                    if let BondPostKind::JoinMarket { endpoint, .. } = &mut post.kind {
                        *endpoint = [0; 32];
                    }
                }),
            ),
            (
                "a credit post carrying a debit",
                join_edited(&chain, |post| post.bond_debit = 1),
            ),
            (
                "a total the credit does not match",
                join_edited(&chain, |post| post.bonded_total_atomic += 1),
            ),
        ];
        for (name, tx) in cases {
            let (verdict, coverage) = judged_post(&tx, &view);
            assert_refused(verdict, CenRow::J14, POST_VIN);
            assert!(
                !coverage.contains(CenRow::J14),
                "{name}: a refusal records nothing"
            );
            assert_refused(
                defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
                CenRow::J14,
                POST_VIN,
            );
        }
    });
}

/// The under-bonded two-shard join listed first in a block is refused by
/// `validate` on J14 at `Listed(0)`'s vin — before the fold writes a
/// record it would have written at one floor for two shards. Until this
/// row that block connected in this crate and never in the C++.
#[test]
fn j14_refuses_the_same_under_bonded_join_listed() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        let join = join_edited(&chain, |post| {
            post.holdings = Holdings::ShardSetCompact(vec![3, 4]);
        });
        let formed = formed_on(&chain, candidate_on(&chain, vec![join]));
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            CenRow::J14,
            Locus::Input {
                slot: TxSlot::Listed(0),
                input: 1,
            },
        );
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

// ---- CEN-J15: a compact join's held shards at the parent --------------
//
// The fold is synthesized and the price planted (`MockChain::with_r_market`,
// which says why): a shard closes when the fold reaches `(shard + 1) · W`,
// `W` being 3 MB of real proof bytes, which no driven chain in the tree
// produces. So the accept and the refusals are both this file's, over the
// genesis rule set's cap (720) and schedule (epoch 0 through every height
// here, so the last settled epoch as of the parent is 0).

/// The height shard 0 closes at: the youngest a spend can anchor on, so
/// the chain is about the fold and not about the reference.
const CLOSE: u64 = crate::rules::tx_against::REFERENCE_BLOCK_MIN_AGE.to_raw();

/// A chain of `len` blocks whose archival fold reaches `W` at [`CLOSE`] and
/// stays there: shard 0 closes at `CLOSE`, shard 1 never does. The next
/// block connects at `len`, reading parent `len − 1`.
fn chain_closing_shard_zero(len: u64) -> MockChain {
    use crate::harness::fixture::{recorded_with_work, root};
    use shekyl_difficulty::{CumulativeDifficulty, GENESIS_DIFFICULTY};
    use shekyl_types::{ArchivalLength, SHARD_LENGTH};
    (0..len).fold(MockChain::default(), |chain, h| {
        let fold = if h >= CLOSE { SHARD_LENGTH.to_raw() } else { 0 };
        chain.push(
            crate::view::RecordedBlock {
                cumulative_archival_len: ArchivalLength::from_raw(fold),
                ..recorded_with_work(
                    1_000 + h * 120,
                    CumulativeDifficulty::from_raw(u128::from(h + 1) * GENESIS_DIFFICULTY),
                )
            },
            root(u8::try_from(h % 250).expect("fits") + 1),
        )
    })
}

/// A one-shard compact join of `shard` bonded at one floor, anchored on
/// `chain`: J14's statics hold, so the row in question is J15's.
fn compact_join(chain: &MockChain, shard: u64) -> Transaction {
    join_edited(chain, |post| {
        post.holdings = Holdings::ShardSetCompact(vec![shard]);
    })
}

/// The chain on which shard 0 is closed, final by exactly the cap (its
/// parent is `CLOSE + cap`), and priced: the accept, and the chain every
/// refusal below perturbs one operand of.
fn admissible_chain() -> MockChain {
    chain_closing_shard_zero(CLOSE + RuleSet::GENESIS.reorg_cap().to_raw() + 1).with_r_market(
        ShardId::from_raw(0),
        SettlementEpoch::from_raw(0),
        RMarket::from_raw(0),
    )
}

/// CEN-J15's accept at the pool's slot: a compact join of a shard that is
/// closed, final (`close + cap ≤ parent`, at the boundary: equal) and
/// priced at the last settled epoch passes the row and records all five
/// on the sequence. The complete-tree fixture join passes on the same
/// chain with no price planted — a complete tree gathers nothing. Through
/// `tx_against` whole each is refused on CEN-J27 at the transaction — the
/// funding half, after the post rows: the fixture's funding spend has no
/// proof and the mock no tree. J27 and not J15 is the admission's witness
/// through the pipeline; the accept whole is the driver's
/// (`scenario_join_tests`).
#[test]
fn j15_admits_a_compact_join_of_a_closed_final_priced_shard() {
    let chain = admissible_chain();
    chain.with_view(|view| {
        for (name, tx) in [
            ("a priced closed-and-final shard", compact_join(&chain, 0)),
            (
                "a complete tree",
                anchored_on(&chain, join_market(BOND_KI, WHO)),
            ),
        ] {
            let (verdict, coverage) = judged_post(&tx, &view);
            verdict.unwrap_or_else(|refused| panic!("{name}: {refused}"));
            for row in POST_ROWS {
                assert!(coverage.contains(row), "{name}: {row} recorded");
            }
            assert_refused(
                defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
                CenRow::J27,
                Locus::Tx { slot: TxSlot::Lone },
            );
        }
    });
}

/// CEN-J15's refusals at the pool's slot, each one operand away from the
/// accept, each refused on J15 at the post's **vin** — not at the fold,
/// not on J13 (the key is read after admission, the C++'s order), and
/// with nothing recorded: a ghost shard past the frontier; the open
/// frontier shard; shard 0 on a chain one block too short for its close
/// to be final; shard 0 at `at = c`, the close itself; shard 0 closed and
/// final but unpriced — the Q4 arm, where the C++ scores the missing row
/// as `0` and admits; shard 0 priced beyond viability. A mis-keyed
/// inadmissible join refuses on J15, not J13.
#[test]
fn j15_refuses_a_compact_join_one_operand_from_admissible() {
    let cap = RuleSet::GENESIS.reorg_cap().to_raw();
    let priced = |chain: MockChain, shard: u64, price: u64| {
        chain.with_r_market(
            ShardId::from_raw(shard),
            SettlementEpoch::from_raw(0),
            RMarket::from_raw(price),
        )
    };
    let stranger = persona([0x6b; 32]);
    let cases: [(&str, MockChain, u64); 6] = [
        (
            "a ghost shard past the frontier",
            priced(admissible_chain(), 7, 0),
            7,
        ),
        (
            "the open frontier shard",
            priced(admissible_chain(), 1, 0),
            1,
        ),
        (
            "closed, one block short of final",
            priced(chain_closing_shard_zero(CLOSE + cap), 0, 0),
            0,
        ),
        (
            "the close itself, at = c",
            priced(chain_closing_shard_zero(CLOSE + 1), 0, 0),
            0,
        ),
        (
            "closed and final, unpriced (Q4)",
            chain_closing_shard_zero(CLOSE + cap + 1),
            0,
        ),
        (
            "priced beyond viability",
            priced(chain_closing_shard_zero(CLOSE + cap + 1), 0, 1_000_000),
            0,
        ),
    ];
    for (name, chain, shard) in cases {
        chain.with_view(|view| {
            let join = compact_join(&chain, shard);
            let (verdict, coverage) = judged_post(&join, &view);
            assert_refused(verdict, CenRow::J15, POST_VIN);
            assert!(
                !coverage.contains(CenRow::J15),
                "{name}: a refusal records nothing"
            );
            assert_refused(
                defined(tx_against(&join, TxSlot::Lone, &view, &RuleSet::GENESIS)),
                CenRow::J15,
                POST_VIN,
            );
            assert_refused(
                judged_post(&slot_carrying(join, stranger.identity.clone()), &view).0,
                CenRow::J15,
                POST_VIN,
            );
        });
    }
}

/// The unpriced compact join listed first in a block is refused by
/// `validate` on J15 at `Listed(0)`'s vin — before the fold writes a
/// record for a shard no epoch has priced. This is the pin slice 8 §5.1
/// row 6 names: a join onto an unclosed or unpriced shard connected in
/// this crate until this row.
#[test]
fn j15_refuses_the_same_unpriced_join_listed() {
    let chain = chain_closing_shard_zero(CLOSE + RuleSet::GENESIS.reorg_cap().to_raw() + 1);
    chain.with_view(|view| {
        let join = compact_join(&chain, 0);
        let formed = formed_on(&chain, candidate_on(&chain, vec![join]));
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            CenRow::J15,
            Locus::Input {
                slot: TxSlot::Listed(0),
                input: 1,
            },
        );
    });
}

/// The fixture join's post re-kinded to a unit kind (its credit zeroed, as
/// a Release's is) and signed, at the pool's slot.
fn unit_kind_post(chain: &MockChain, kind: u8, debit: u64) -> Transaction {
    join_edited(chain, |post| {
        post.kind = BondPostKind::Other(kind);
        post.bond_credit = 0;
        post.bond_debit = debit;
    })
}

/// A Release for a persona the view has **no record** for is CEN-J16's
/// `RecordMissing`, under either key: the C++ gates `cold_authority_pin`
/// on `have_record` (so J13 passes, as it did at row 4) and the semantic
/// verify refuses the missing record — the row that stands ahead of the
/// fold's L7 since row 5. (Row 4 recorded this body as *"the fold's L7"*;
/// true until J16 landed — records-was.) With a record, the terms the
/// verify reads — the full exit, the cooldown, the settlement — are the
/// driver's.
#[test]
fn j16_a_release_with_no_record_is_refused_on_the_missing_record() {
    let chain = spendable_chain();
    let who = persona(WHO);
    chain.with_view(|view| {
        let release = unit_kind_post(&chain, RetentionKind::Release as u8, BOND_FLOOR);
        for (name, tx) in [
            ("a release under the bond-spend key", release.clone()),
            (
                "a release under the identity key",
                slot_carrying(release.clone(), who.identity.clone()),
            ),
        ] {
            let (verdict, coverage) = judged_post(&tx, &view);
            assert_refused(verdict, CenRow::J16, POST_VIN);
            assert!(
                !coverage.contains(CenRow::J16),
                "{name}: a refusal records nothing"
            );
            assert_refused(
                defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
                CenRow::J16,
                POST_VIN,
            );
        }
    });
}

/// A Reinstate for a persona the view has **no record** for is CEN-J18's
/// `RecordMissing` — and it is J18's **whatever key the slot carries**: the
/// C++ verifies the Reinstate before it pins the identity key, so a
/// mis-keyed Reinstate of a missing record refuses on the record, not the
/// key (row 4 judged this body on J13; the order moved it at row 5).
#[test]
fn j18_a_reinstate_with_no_record_is_refused_on_the_missing_record() {
    let chain = spendable_chain();
    let stranger = persona([0x6b; 32]);
    chain.with_view(|view| {
        let reinstate = join_edited(&chain, |post| {
            post.kind = BondPostKind::Other(RetentionKind::Reinstate as u8);
        });
        for (name, tx) in [
            ("a reinstate under the identity key", reinstate.clone()),
            (
                "a reinstate under a stranger's key — J18 before J13",
                slot_carrying(reinstate.clone(), stranger.identity.clone()),
            ),
        ] {
            let (verdict, coverage) = judged_post(&tx, &view);
            assert_refused(verdict, CenRow::J18, POST_VIN);
            assert!(
                !coverage.contains(CenRow::J18),
                "{name}: a refusal records nothing"
            );
            assert_refused(
                defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
                CenRow::J18,
                POST_VIN,
            );
        }
    });
}

/// A kind no arm names is CEN-L7 at the post's vin, inside `judge_bond_post`
/// and through `tx_against`. The four post rows are not recorded: the post
/// was not judged. The fold's L7 arm stays the belt beneath
/// (`scenario_archival_tests`, the unknown-kind pin, the same row and locus).
#[test]
fn an_unnamed_kind_is_l7_in_the_sequence() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        let tx = unit_kind_post(&chain, 9, 0);
        let (verdict, coverage) = judged_post(&tx, &view);
        assert_refused(verdict, CenRow::L7, POST_VIN);
        for row in POST_ROWS {
            assert!(
                !coverage.contains(row),
                "{row} not recorded for an unnamed kind"
            );
        }
        assert_refused(
            defined(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
            CenRow::L7,
            POST_VIN,
        );
    });
}

/// `tx` with the bond post's auth slot removed, after [`anchored_on`] signed
/// it. `tx_form`'s H21 would refuse the short list; these pins call
/// `judge_bond_post` directly, which is the caller a pool migration must
/// stay safe under if it ever reaches the sequence without that check.
fn without_the_post_slot(mut tx: Transaction) -> Transaction {
    let slot = tx
        .prefix
        .inputs
        .iter()
        .position(|item| matches!(item, Input::BondPost(_)))
        .expect("a bond post");
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths.remove(slot);
    }
    tx
}

/// A missing auth slot refuses at the point that arm reads the slot, and
/// records none of the post rows. The C++ order still holds: a JoinMarket
/// whose statics fail is J14's before the slot is read; a Release or a
/// Reinstate with no record never reaches the slot (J16, J18).
#[test]
fn a_missing_slot_refuses_at_the_arm_that_reads_it() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        let cases = [
            (
                "a join with no slot",
                without_the_post_slot(anchored_on(&chain, join_market(BOND_KI, WHO))),
                CenRow::J13,
            ),
            (
                "an under-bonded join with no slot — J14 before the slot",
                without_the_post_slot(join_edited(&chain, |post| {
                    post.holdings = Holdings::ShardSetCompact(vec![3, 4]);
                })),
                CenRow::J14,
            ),
            (
                "a release with no record and no slot — J16, the pin is gated",
                without_the_post_slot(unit_kind_post(
                    &chain,
                    RetentionKind::Release as u8,
                    BOND_FLOOR,
                )),
                CenRow::J16,
            ),
            (
                "a reinstate with no record and no slot — J18 before the slot",
                without_the_post_slot(unit_kind_post(&chain, RetentionKind::Reinstate as u8, 0)),
                CenRow::J18,
            ),
        ];
        for (name, tx, row) in cases {
            let (verdict, coverage) = judged_post(&tx, &view);
            assert_refused(verdict, row, POST_VIN);
            for recorded in POST_ROWS {
                assert!(
                    !coverage.contains(recorded),
                    "{name}: {recorded} not recorded"
                );
            }
        }
    });
}

/// On every class that is not a bond post the four rows are recorded
/// **vacuous, not absent** (slice 5 Q2).
#[test]
fn the_post_rows_are_vacuous_off_the_bond_post_class() {
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
            defined(judge_bond_post(
                &cx,
                &view,
                &RuleSet::GENESIS,
                &mut coverage,
            ))
            .unwrap_or_else(|refused| panic!("{name}: nothing to judge, but {refused}"));
            for row in POST_ROWS {
                assert!(coverage.contains(row), "{name}: {row} recorded vacuous");
            }
        }
    });
}
