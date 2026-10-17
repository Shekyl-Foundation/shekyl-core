// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool door against the validator, over real spends (DRS-E5 PR-b b2;
//! `DRS_E5_POOL_ALT_PRUNE.md` §2.2).
//!
//! The door is the validator's own judgement at `TxSlot::Lone`, so a
//! transaction it admits on consensus is one a block listing it alone
//! connects with, and one it refuses is refused by that block on the same
//! row — at the block's slot instead of `Lone`. Each spend here is judged
//! both ways on the same chain: by the door over the committed snapshot,
//! and by `form` + `validate` + `connect` in a block of its own (rewound
//! after, when it lands). The refusals are the ones only a real spend can
//! reach: a moved body (CEN-I18), a range proof one bit off (CEN-H19's
//! verification half, which the door verifies as a batch of one), a respend
//! of an image the chain holds (CEN-I7, the M6 leg).
//!
//! Then the pool's own rows over the same chain: CEN-M1 (a transaction
//! held or mined is a duplicate), CEN-M7 (a second spender of a key image
//! the pool holds is refused by the decorator, and the first is untouched)
//! and CEN-M3 (below the floor is refused on policy).

use shekyl_chain_rules::{AdmissionPolicy, CenRow, InvalidBlock, Locus, PolicyRow, TxSlot};
use shekyl_harness_spender::Spender;
use shekyl_mempool::{judge, Admission, Arrival, Duplicate, Judged, KeyImages, Pool};
use shekyl_types::{BlockHeight, UnixSeconds};
use shekyl_wire::Transaction;

use crate::scenario::{FreeHash, Mined, Scenario, StepOutcome};
use crate::test_support::{h, tmp, Family, FIRST_SPEND_HEIGHT};

/// The spending height: block 0's, 1's and 2's coinbases have matured.
pub(crate) const AT: u64 = FIRST_SPEND_HEIGHT + 2;

/// What one judgement said, reduced to what the door and a block must
/// agree on: admitted on consensus, or the row and the locus at `Lone`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Verdict {
    Admitted,
    Refused { rule: CenRow, locus: Locus },
}

/// A block's locus at its one listed slot, written at `Lone`.
fn at_lone(locus: Locus) -> Locus {
    match locus {
        Locus::Tx {
            slot: TxSlot::Listed(0),
        } => Locus::Tx { slot: TxSlot::Lone },
        Locus::Input {
            slot: TxSlot::Listed(0),
            input,
        } => Locus::Input {
            slot: TxSlot::Lone,
            input,
        },
        other => other,
    }
}

fn refused(r: &InvalidBlock) -> Verdict {
    Verdict::Refused {
        rule: r.rule,
        locus: r.locus,
    }
}

/// The door's verdict on `tx` over the chain the scenario holds now. A
/// policy refusal is consensus-admitted: the policy is not the validator's.
async fn door(scenario: &mut Scenario<FreeHash>, tx: &Transaction) -> (Verdict, Judged) {
    let judged = scenario
        .read_chain(|view, rule_set| {
            judge(
                tx,
                view,
                &KeyImages::default(),
                rule_set,
                &AdmissionPolicy::GENESIS,
                None,
            )
            .unwrap_or_else(|fault| panic!("the door faulted: {fault:?}"))
        })
        .await;
    let verdict = match &judged {
        Judged::Admitted { .. } | Judged::Policy(_) => Verdict::Admitted,
        Judged::Stateless(r) | Judged::Chain(r) => refused(r),
    };
    (verdict, judged)
}

/// The validator's verdict on a block listing `tx` alone, and the chain
/// put back where it was.
async fn block(scenario: &mut Scenario<FreeHash>, tx: Transaction) -> Verdict {
    let connecting = scenario.facts().await.expect("facts").connecting;
    let tip = BlockHeight::from_raw(connecting.to_raw() - 1);
    match scenario.mine_listing(vec![tx]).await {
        Ok(_) => {
            scenario.rewind_to(tip).await.expect("the block rewinds");
            Verdict::Admitted
        }
        Err(StepOutcome::Refused(r)) => Verdict::Refused {
            rule: r.rule,
            locus: at_lone(r.locus),
        },
        Err(other) => panic!("the block did not reach a verdict: {other}"),
    }
}

/// Block `coinbase`'s output spent at `AT`, paying exactly the relay
/// requirement the chain prices now: `quantized_fee(weight, min F)` over
/// the floor window at the connecting height (CEN-M3's predicate), re-priced
/// until the fee's varint holds the weight still.
pub(crate) async fn paying_the_floor(
    scenario: &mut Scenario<FreeHash>,
    mined: &[Mined],
    coinbase: u64,
) -> Transaction {
    let floor = scenario
        .read_chain(|view, _| {
            let connecting = shekyl_chain_rules::Tip::connecting_height(
                shekyl_chain_rules::HeaderView::tip(view)
                    .expect("tip")
                    .as_ref(),
            );
            match shekyl_chain_rules::relay_floor_window(view, connecting).expect("floors") {
                shekyl_chain_rules::AtHeight::Recorded(floors) => {
                    floors.into_iter().min().expect("a window")
                }
                shekyl_chain_rules::AtHeight::AboveTip => unreachable!("the connecting height"),
            }
        })
        .await;
    let spender = Spender::over(mined);
    let wallet = scenario.wallet();
    let mut fee = Family::Main.fee();
    for _ in 0..8 {
        let tx = spender.spend_coinbase(wallet, h(coinbase), h(AT), fee);
        let weight = u64::try_from(tx.weight()).expect("a weight fits");
        let needed = shekyl_economics::quantized_fee(weight, floor).expect("priceable");
        if needed == fee {
            return tx;
        }
        fee = needed;
    }
    panic!("the floor price did not settle");
}

pub(crate) async fn matured(name: &str) -> (Scenario<FreeHash>, Vec<Mined>) {
    let mut scenario = Scenario::open(name);
    let mined = scenario.mine(AT).await;
    (scenario, mined)
}

/// Door == validator, the same row both ways, over every spend shape a
/// real chain can carry to this door: one that connects, a moved body, a
/// range proof one bit off, and — after the first spend connects — a
/// respend of its image. The subject exists: four judgements, one admitted
/// and three refused on three different rows.
#[tokio::test]
async fn the_door_and_a_block_of_one_agree_on_every_spend() {
    let (mut scenario, mut mined) = matured("pool-door-agree").await;
    let (good, flipped) = {
        let spender = Spender::over(&mined);
        let wallet = scenario.wallet();
        (
            spender.spend_coinbase(wallet, h(0), h(AT), Family::Main.fee()),
            spender.spend_coinbase_breaking_range_proof(wallet, h(1), h(AT), Family::Main.fee()),
        )
    };
    let mut moved = good.clone();
    moved.prefix.unlock_time += 1;

    let mut seen = Vec::new();
    for tx in [good.clone(), moved, flipped] {
        let (by_door, _) = door(&mut scenario, &tx).await;
        let by_block = block(&mut scenario, tx).await;
        assert_eq!(by_door, by_block, "the door and the block disagree");
        seen.push(by_door);
    }

    // The respend: `good` connects, and a new body over its image is
    // refused on I7 — the chain half of CEN-M6, through the decorator.
    mined.push(
        scenario
            .mine_listing(vec![good])
            .await
            .unwrap_or_else(|outcome| panic!("the spend connects: {outcome}")),
    );
    let respend = Spender::over(&mined).spend_coinbase(
        scenario.wallet(),
        h(0),
        h(AT + 1),
        Family::Main.fee() + 1,
    );
    let (by_door, _) = door(&mut scenario, &respend).await;
    let by_block = block(&mut scenario, respend).await;
    assert_eq!(
        by_door, by_block,
        "the door and the block disagree on a respend"
    );
    seen.push(by_door);

    assert_eq!(
        seen,
        vec![
            Verdict::Admitted,
            Verdict::Refused {
                rule: CenRow::I18,
                locus: Locus::Input {
                    slot: TxSlot::Lone,
                    input: 0
                },
            },
            Verdict::Refused {
                rule: CenRow::H19,
                locus: Locus::Tx { slot: TxSlot::Lone },
            },
            Verdict::Refused {
                rule: CenRow::I7,
                locus: Locus::Input {
                    slot: TxSlot::Lone,
                    input: 0
                },
            },
        ],
        "the four judgements, each on its own row"
    );
    scenario.close().await;
}

/// The admitted spend's judgement carries what its proof verified against
/// — CEN-M8's anchor — and the rows both halves recorded, H19 among the
/// stateless ones (the batch of one).
#[tokio::test]
async fn an_admitted_spend_carries_its_anchor_and_the_range_proof_row() {
    let (mut scenario, mined) = matured("pool-door-anchor").await;
    let good = paying_the_floor(&mut scenario, &mined, 0).await;
    let (_, judged) = door(&mut scenario, &good).await;
    let Judged::Admitted {
        proven, stateless, ..
    } = judged
    else {
        panic!("a well-formed spend paying the floor is admitted: {judged:?}");
    };
    let proven = proven.expect("a spend's proof verified against its reference");
    assert_eq!(Some(proven.reference), reference_of(&good));
    assert!(stateless.contains(CenRow::H19), "the batch of one decided");
    assert!(stateless.contains(CenRow::I15), "the proof verified");
    scenario.close().await;
}

fn reference_of(tx: &Transaction) -> Option<shekyl_types::BlockHash> {
    match &tx.ct {
        shekyl_wire::transaction::Ct::Fcmp {
            reference_block, ..
        } => Some(*reference_block),
        shekyl_wire::transaction::Ct::Null(_) => None,
    }
}

/// The pool over the same chain: CEN-M1, CEN-M7 and CEN-M3.
#[tokio::test]
async fn the_pool_holds_one_spender_per_image_refuses_duplicates_and_the_floor() {
    let (mut scenario, mined) = matured("pool-door-rows").await;
    let good = paying_the_floor(&mut scenario, &mined, 0).await;
    let (twin, cheap) = {
        let spender = Spender::over(&mined);
        let wallet = scenario.wallet();
        let fee = match &good.ct {
            shekyl_wire::transaction::Ct::Fcmp { fee, .. } => *fee,
            shekyl_wire::transaction::Ct::Null(_) => unreachable!("a spend"),
        };
        (
            // Another body over the same image, paying more.
            spender.spend_coinbase(wallet, h(0), h(AT), fee + 1_000),
            spender.spend_coinbase(wallet, h(1), h(AT), 1),
        )
    };
    let path = tmp("pool-door-rows-pool");
    let txid = good.txid_parts().hash;
    let admissions = scenario
        .read_chain(|view, rule_set| {
            let policy = AdmissionPolicy::GENESIS;
            let (mut pool, _, _) = Pool::open(&path, view, rule_set, &policy).expect("open");
            let mut admit = |tx: &Transaction| {
                pool.admit(
                    tx.clone(),
                    Arrival::Relayed,
                    UnixSeconds::from_raw(1),
                    view,
                    rule_set,
                    &policy,
                )
                .expect("no fault")
            };
            let first = admit(&good);
            let again = admit(&good);
            let second_spender = admit(&twin);
            let below_floor = admit(&cheap);
            let held = pool.record(&txid);
            (first, again, second_spender, below_floor, held, pool.len())
        })
        .await;
    let (first, again, second_spender, below_floor, held, len) = admissions;
    assert_eq!(first, Admission::Admitted);
    assert_eq!(again, Admission::Duplicate(Duplicate::InPool), "CEN-M1");
    match second_spender {
        Admission::Refused(Judged::Chain(r)) => {
            assert_eq!(
                r.rule,
                CenRow::I7,
                "CEN-M7, judged by I7 through the decorator"
            );
        }
        other => panic!("a second spender of a held image is refused: {other:?}"),
    }
    match below_floor {
        Admission::Refused(Judged::Policy(r)) => assert_eq!(r.rule, PolicyRow::M3),
        other => panic!("a fee of one is below the floor: {other:?}"),
    }
    let held = held.expect("the first spender is held");
    assert!(
        !held.public,
        "a relayed transaction is not public until fluffed"
    );
    assert_eq!(len, 1, "only the first spender is held");

    // Mined, it is a duplicate on the chain's side (CEN-M1).
    let _connected = scenario
        .mine_listing(vec![good.clone()])
        .await
        .unwrap_or_else(|outcome| panic!("the spend connects: {outcome}"));
    let mined_dup = scenario
        .read_chain(|view, rule_set| {
            let policy = AdmissionPolicy::GENESIS;
            let (mut pool, _, reconciled) =
                Pool::open(&path, view, rule_set, &policy).expect("reopen");
            assert_eq!(
                reconciled.removed.len(),
                1,
                "the reconcile at open removes the mined entry"
            );
            pool.admit(
                good,
                Arrival::Relayed,
                UnixSeconds::from_raw(2),
                view,
                rule_set,
                &policy,
            )
            .expect("no fault")
        })
        .await;
    assert_eq!(mined_dup, Admission::Duplicate(Duplicate::OnChain));
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// D++ acceptance criterion 2: a transaction the relay has not fluffed is
/// in no listing the node shows — the pool listing, peer pool sync — and
/// is in both once the relay's fluff event sets the bit. The relay's own
/// view of what it still holds back (`unpublished`) is the complement.
#[tokio::test]
async fn an_unfluffed_transaction_is_shown_nowhere_until_the_relay_fluffs_it() {
    let (mut scenario, mined) = matured("pool-criterion-2").await;
    let good = paying_the_floor(&mut scenario, &mined, 0).await;
    let txid = good.txid_parts().hash;
    let path = tmp("pool-criterion-2-pool");
    let (before, after, reopened) = scenario
        .read_chain(|view, rule_set| {
            let policy = AdmissionPolicy::GENESIS;
            let (mut pool, _, _) = Pool::open(&path, view, rule_set, &policy).expect("open");
            let admitted = pool
                .admit(
                    good,
                    Arrival::Relayed,
                    UnixSeconds::from_raw(1),
                    view,
                    rule_set,
                    &policy,
                )
                .expect("no fault");
            assert_eq!(admitted, Admission::Admitted, "fixture: the spend is held");
            let seen = |pool: &Pool| {
                (
                    pool.listing().any(|(id, _)| id == txid),
                    pool.peer_sync().any(|(id, _)| id == txid),
                    pool.unpublished().any(|(id, _)| id == txid),
                )
            };
            let before = seen(&pool);
            assert!(pool.fluffed(&txid).expect("publish"), "the pool holds it");
            let after = seen(&pool);
            drop(pool);
            // The bit is the file's too: a reopen shows it.
            let (pool, _, _) = Pool::open(&path, view, rule_set, &policy).expect("reopen");
            (before, after, seen(&pool))
        })
        .await;
    assert_eq!(before, (false, false, true), "unfluffed: shown nowhere");
    assert_eq!(
        after,
        (true, true, false),
        "fluffed: in the listing and peer sync"
    );
    assert_eq!(reopened, after, "the public bit survives a restart");
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}
