// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hint and the debit key, through the driver (`CHAIN_RULES_SLICE_8.md`
//! §5 row 4).
//!
//! Three personas on a genesis-schedule chain: `bonded` joins; `stranger`
//! and `signer` never do. Every join here is a complete tree: the holding's
//! shape is not the subject, and a compact join needs a closed, final,
//! priced shard (CEN-J15, §5 row 6) — the live lane's `scenario_shard`
//! fill, which these two refusals do not need.
//!
//! - **J11:** `signer`'s JoinMarket with its `p_canonical_id` overwritten to
//!   `stranger`'s is refused at the transaction. The hint is the recompute
//!   over the key. Neither persona gains a record.
//! - **J13:** `signer` posts a Release whose fields are `bonded`'s — key and
//!   id consistent, so J11 passes — with the slot signed by `signer`'s
//!   identity key. The Release is refused at the post's vin. `bonded`'s
//!   record is untouched: the debit does not follow the slot's key.
//!
//! *Records-was (pinned until §5 row 4, 2026-10-04):* both connected. The
//! join inserted a record under `stranger`'s id carrying `signer`'s key; the
//! Release emptied `bonded`'s record and paid the collateral to the signer.

use shekyl_archival_retention::{p_canonical_id_from_hybrid_pubkey, ARCHIVAL_BOND_FLOOR_ATOMIC};
use shekyl_chain_rules::{CenRow, Locus, TxSlot};
use shekyl_types::{BlockHeight, ChainCount};

use crate::archival_driver::{
    at_post, first_spending_height, record_of, refused_at, ENDPOINT, FEE,
};
use crate::scenario::{Mined, Scenario};
use crate::scenario_archival::{complete_tree, Persona};
use crate::scenario_spend::Spender;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_post_is_keyed_by_the_recompute_and_a_release_by_the_record_key() {
    let mut scenario = Scenario::open("slice-8-hint");
    let mut chain: Vec<Mined> = scenario
        .mine(ChainCount::from_next_height(first_spending_height()).to_raw())
        .await;
    let next = |chain: &Vec<Mined>| {
        ChainCount::from_raw(u64::try_from(chain.len()).expect("small")).next_height()
    };
    let (bonded, stranger, signer) = (Persona::at(21), Persona::at(22), Persona::at(23));
    let total = ARCHIVAL_BOND_FLOOR_ATOMIC;

    // `bonded` joins.
    {
        let spender = Spender::over(&chain);
        let height = next(&chain);
        let joining = spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::ZERO,
            height,
            FEE,
            Some(&bonded.join(complete_tree(), ENDPOINT)),
        );
        chain.push(
            scenario
                .mine_listing(vec![joining])
                .await
                .expect("the join connects"),
        );
    }
    let before = record_of(&scenario, &bonded).await;
    assert_eq!(before.bonded_total.to_raw(), total);

    // J11: signer's join under stranger's id.
    {
        let spender = Spender::over(&chain);
        let height = next(&chain);
        let mut post = signer.join_post(complete_tree(), ENDPOINT);
        assert_eq!(
            p_canonical_id_from_hybrid_pubkey(&post.hybrid_public_key),
            signer.id(),
            "the constructor's hint recomputes"
        );
        post.p_canonical_id = stranger.id();
        let riding = spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::from_raw(1),
            height,
            FEE,
            Some(&signer.post_by_hand(post)),
        );
        refused_at(
            scenario.mine_listing(vec![riding]).await,
            CenRow::J11,
            Locus::Tx {
                slot: TxSlot::Listed(0),
            },
        );
        for (who, name) in [(&signer, "the signer"), (&stranger, "the stranger")] {
            assert!(
                scenario
                    .bond_record(who.id())
                    .await
                    .expect("answers")
                    .is_none(),
                "{name} has no record"
            );
        }
    }

    // J13: signer releases bonded's bond.
    {
        let spender = Spender::over(&chain);
        let height = next(&chain);
        let post = bonded.release_post(total);
        assert_eq!(post.p_canonical_id, bonded.id());
        assert_eq!(post.hybrid_public_key, bonded.identity());
        assert_eq!(post.bond_debit, total);
        let riding = spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::from_raw(2),
            height,
            FEE,
            Some(&signer.post_by_hand(post)),
        );
        refused_at(
            scenario.mine_listing(vec![riding]).await,
            CenRow::J13,
            at_post(0),
        );
    }
    let after = record_of(&scenario, &bonded).await;
    assert_eq!(
        after.bonded_total.to_raw(),
        total,
        "the debit did not follow"
    );
    assert_eq!(after.holdings, before.holdings);

    scenario.close().await;
}
