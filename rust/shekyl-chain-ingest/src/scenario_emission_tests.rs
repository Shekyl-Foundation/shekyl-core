// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The driver's emission claim through the production stack (E6 slice 8
//! PR-b, `CHAIN_RULES_SLICE_8.md` §5 row 7, Q3; re-timed by `SO-D11`): a
//! persona funded by a coinbase spend joins a closed shard, is Served on
//! it for one epoch, and — once that epoch has closed **and its slash pass
//! has run**, so its budget and its `Σwork` are both the store's rows —
//! claims its reward with a transaction `emission_assembly` built the way
//! the engine handler builds one. `validate` admits it on the block after
//! the pass; the fold writes the claim onto the record; the store holds
//! what the verdict derived. That is the one admitted claim the row pins,
//! and the one place the pass's gather and the claim verify's re-gather
//! are held to each other on a driven chain. Beside it, three refusals
//! with a pipeline witness nowhere else: the same claim in the pass block
//! itself is CEN-J23's (closed, not yet settled), listed with a twin it is
//! CEN-G9's (slice 8 row 9 retired the mutation family's `DuplicateClaim`
//! here — `Mutation` docs), and with its fee proof corrupted it is
//! CEN-J26's (the one emission row the backing proof does not cover). The
//! row's other half — the driver's bytes and the engine's held identical
//! for one shape — lives in `shekyl-engine-core`'s `stake_engine_tests`,
//! which reaches this crate's assembly through the `harness` feature.
//!
//! # What the chain has to do first
//!
//! A compact join needs a closed shard (CEN-J15), so the chain fills one
//! under the levered schedule (`scenario_shard`); the claim needs a
//! settled epoch the persona served, so the credit lands in the join's
//! epoch for the epoch after it (CEN-J5) and the chain mines through that
//! epoch's close; and the claim's inputs are the persona's own outputs —
//! the backing and the fee — paid by the funding spend, which is why the
//! spend pays a [`Recipient`] and the tree [`Spender::own`]s what it
//! paid. The reward is the close's own arithmetic re-run over the rows
//! the test knows it fed: `epoch_close_compute` over the one bond, the
//! one shard and the one credit pair must equal the close the fold wrote,
//! and `claimant_reward_share` over the persisted `Σwork` and budget is
//! the amount the claim names. A reward of zero would stop the test
//! before the claim: a claim for nothing is not what the row admits.
//!
//! Minutes of proofs; the live lane (`cargo test -p shekyl-chain-ingest
//! --features pipeline -- --ignored the_drivers_emission_claim`).
//!
//! # What this does not witness
//!
//! The claim's economics against the store (CEN-J21/J23/J25) and its
//! shape against the record (J19/J20/J22/J24) are rows 8–10's; today the
//! fold checks the claimed epochs against the record's window and sets
//! the paying height (CEN-L7's claim arm), and `validate` judges the
//! class (CEN-H22) and the auth slots (CEN-I18). The claim's own verify
//! legs — the membership-only backing proof and the dual auth — run here
//! against the wallet-side root as a self-check, as the spend's FCMP does.

use shekyl_archival_retention::settlement_select::issued_draw_term;
use shekyl_archival_retention::{
    claimant_reward_share, emission_vin_verify_auth, emission_vin_verify_backing,
    epoch_close_compute, shard_contribution_micro, CreditPair, EmissionEpochSource, EpochCloseBond,
    EpochCloseInputs, EpochCloseShard, ShardClose, ShardWorkEntry, WorkEpochClaim,
};
use shekyl_chain_rules::{CenRow, Locus, RecordWriteKind, TxSlot};
use shekyl_fcmp::proof::{self, ShekylFcmpProof};
use shekyl_fcmp::PqcKeyScalar;
use shekyl_types::archival::{
    FirstPayingHeight, IndexedDraw, IssuedDigest, IssuedDraw, SettlementOutcome,
};
use shekyl_types::{BlockCount, BlockHeight, SettlementEpoch, ShardId};
use shekyl_wire::{Ct, Transaction};
use zeroize::Zeroizing;

use crate::archival_driver::{first_spending_height, refused_at, ENDPOINT, FEE};
use crate::connector::IssueDraws;
use crate::emission_assembly::{assemble_emission_claim, ClaimTerms};
use crate::scenario::{FreeHash, Mined, Scenario};
use crate::scenario_archival::{shard_set, Persona};
use crate::scenario_shard::{
    close_shards, first_admissible_compact_join, inside_one_epoch, levered_rules, levered_schedule,
    mine_to, EPOCH_BLOCKS,
};
use shekyl_harness_spender::{Owner, Recipient, Spender};

/// The fill spends coinbases from here up; the funding spend rides
/// coinbase 0, below it.
const FILL_FROM_COINBASE: u64 = 10;

/// The claim's transaction key. The engine draws one from the OS; the
/// driver takes it as an argument, and this scenario needs only that it
/// is not the funding spend's.
const CLAIM_TX_KEY: [u8; 32] = [0x5c; 32];

/// The twin claim's transaction key — a second claim for the same terms,
/// so G9 has a pair to refuse.
const TWIN_TX_KEY: [u8; 32] = [0x5d; 32];

/// Feed `spender` every block of `chain` it has not seen.
fn catch_up(spender: &mut Spender, chain: &[Mined], seen: &mut usize) {
    for block in &chain[*seen..] {
        spender.push(block);
    }
    *seen = chain.len();
}

#[tokio::test]
#[ignore = "minutes of proofs; the live lane"]
async fn the_drivers_emission_claim_connects_and_pays_the_persona() {
    let rules = levered_rules();
    let mut scenario = Scenario::open_under("scenario-emission-claim", FreeHash, rules);
    let mut mined = scenario.mine(first_spending_height().to_raw()).await;
    let filled = close_shards(&mut scenario, &mut mined, FILL_FROM_COINBASE, 1).await;
    let [closed] = filled.closed.as_slice() else {
        panic!("one shard closed");
    };
    assert_eq!(closed.shard.to_raw(), 0);

    // The join and the credit after it sit in one epoch, neither a close.
    let join_height = inside_one_epoch(first_admissible_compact_join(&rules, *closed), 1);
    mine_to(&mut scenario, &mut mined, join_height).await;
    let mut spender = Spender::over(&mined);
    let mut seen = mined.len();

    // The funding spend: coinbase 0 to the persona in two outputs — the
    // payment (index 0) is the claim's backing, the change (index 1) its
    // fee — with the persona's join riding it.
    let persona = Persona::at(1);
    let recipient = Recipient::persona(persona.keys());
    let join = persona.join(shard_set(vec![0]), ENDPOINT);
    let funding = spender.spend_coinbase_to(
        scenario.wallet(),
        BlockHeight::ZERO,
        join_height,
        FEE,
        Some(&join),
        &recipient,
    );
    let backing_key = funding.prefix.outputs[0].key;
    let fee_key = funding.prefix.outputs[1].key;
    spender.own(backing_key);
    spender.own(fee_key);
    let block = scenario
        .mine_listing(vec![funding])
        .await
        .unwrap_or_else(|outcome| panic!("the funding spend and the join connect: {outcome}"));
    assert_eq!(block.height, join_height);
    assert!(
        block.judged_by.contains(&CenRow::J15),
        "J15 judged the join"
    );
    mined.push(block);
    let join_epoch = levered_schedule().epoch_at(join_height);
    // The first epoch a persona joining in `join_epoch` may serve (CEN-J5).
    let served = SettlementEpoch::from_raw(join_epoch.to_raw() + 1);
    // Beside the credit, a second funding spend — coinbase 1 to the same
    // persona, no post — for the twin claim G9 refuses below. Its own
    // block: the spender's output keys are drawn from the connecting
    // height, so two spends to one recipient at one height would pay the
    // same keys, and the twin's fee would be the claim's.
    let twin_height = join_height + BlockCount::ONE;
    let twin_funding = spender.spend_coinbase_to(
        scenario.wallet(),
        BlockHeight::from_raw(1),
        twin_height,
        FEE,
        None,
        &recipient,
    );
    let twin_fee_key = twin_funding.prefix.outputs[1].key;
    assert_ne!(twin_fee_key, fee_key, "the twin's fee is its own output");
    spender.own(twin_fee_key);
    let block = scenario
        .mine_listing(vec![persona.serve_credit(0, served.to_raw()), twin_funding])
        .await
        .unwrap_or_else(|outcome| panic!("the credit and the twin's funding connect: {outcome}"));
    assert_eq!(block.height, twin_height);
    mined.push(block);

    // The persona's three draws of `served` on the shard, each passed: the
    // epoch settles Served for the pair, which is what the gather credits
    // (`SO-D11a`). Nothing admits a draw yet, so they go in through the
    // regtest door, with the digest they fold to.
    let shard = ShardId::from_raw(0);
    let open = levered_schedule().open_height(served.to_raw());
    let mut digest = IssuedDigest::ZERO;
    let draws: Vec<IndexedDraw> = (0..3u64)
        .map(|k| {
            let issuing_height = BlockHeight::from_raw(open + k);
            digest.fold(&issued_draw_term(
                &persona.id(),
                shard,
                served,
                issuing_height,
                0,
            ));
            IndexedDraw {
                persona: persona.id(),
                shard,
                issuing_height,
                draw: 0,
                state: IssuedDraw {
                    revealed_at: BlockHeight::from_raw(open + k + 1),
                    passed: true,
                },
            }
        })
        .collect();
    scenario
        .connector()
        .ask(IssueDraws {
            epoch: served,
            draws,
            digest,
        })
        .await
        .expect("the door issues the draws");

    // Up to the slash pass of `served`, not through it. The epoch closed
    // when the count reached `(served + 1) · SEB`, at the block before
    // that height, and that block froze its budget and nothing else. Its
    // `Σwork` is the pass's, at the block where the count reaches
    // `(served + 2) · SEB`.
    let count_at_close = (served.to_raw() + 1) * EPOCH_BLOCKS;
    let at_pass = BlockHeight::from_raw(levered_schedule().slash_deadline_height(served.to_raw()));
    assert_eq!(
        at_pass.to_raw() + 1,
        (served.to_raw() + 2) * EPOCH_BLOCKS,
        "the pass is the last block of the epoch after"
    );
    mine_to(&mut scenario, &mut mined, at_pass).await;
    catch_up(&mut spender, &mined, &mut seen);
    let closing = &mined[usize::try_from(count_at_close - 1).expect("small")].archival;
    let close = *closing
        .close()
        .expect("the block that completes the epoch carries its close");
    assert_eq!(close.epoch(), served);
    assert!(
        closing.gathers().iter().all(|g| g.epoch() != served),
        "the close does not gather the epoch it closes"
    );

    // The gather, computed here over the rows this test fed it before the
    // pass has run: one bond that joined in `join_epoch`, one shard closed
    // where the fill closed it and long final, one Served pair. Ages are
    // read at the epoch's own close height. The pass's rows must be this
    // arithmetic, and the claim below is built from it.
    let bonds = [EpochCloseBond {
        join_settlement_epoch: join_epoch.to_raw(),
        is_foundation_complete_tree: false,
        bad_intervals: &[],
    }];
    let shards = [EpochCloseShard {
        shard_id: 0,
        close: ShardClose::ClosedAt(closed.close_height),
    }];
    let pairs = [CreditPair {
        bond_idx: 0,
        shard_idx: 0,
    }];
    let inputs = EpochCloseInputs::under_schedule(
        levered_schedule(),
        served.to_raw(),
        count_at_close,
        &bonds,
        &shards,
        &pairs,
    );
    let result = epoch_close_compute(&inputs).expect("the pair indexes its bond and shard");
    let share = claimant_reward_share(&EmissionEpochSource {
        inputs: inputs.clone(),
        persisted_sigma_work_milli: result.sigma_work_milli,
        claimant_bond_idx: Some(0),
        budget: close.budget().to_raw(),
    })
    .expect("the claimant indexes its bond");
    assert!(share.is_member, "the one server is in the market");
    assert!(
        share.reward > 0,
        "the one server of the one shard is owed the epoch's budget share \
         (budget {}, Σwork {})",
        close.budget().to_raw(),
        result.sigma_work_milli
    );
    let scarcity = shard_contribution_micro(&inputs, &result.r_market_by_shard, 0);
    let terms = ClaimTerms {
        holdings: shard_set(vec![0]),
        settlement_epochs: vec![served.to_raw()],
        work_claim: vec![WorkEpochClaim {
            epoch: served.to_raw(),
            shard_entries: vec![ShardWorkEntry {
                shard_id: 0,
                serve_credit_bit: true,
                scarcity_micro: u32::try_from(scarcity).expect("a per-entry term fits (F-C)"),
            }],
        }],
        reward_amount_plain: vec![share.reward],
    };

    // The claim is assembled against the pass block's height and connects
    // one block later, the first block at which `Σwork(served)` is a row
    // (`SO-D11d`: the row's existence is the citing gate). Both heights
    // are past the persona outputs' maturity and inside the reference
    // window.
    let connecting = at_pass + BlockCount::ONE;
    let owner = Owner::persona(persona.keys());
    let backing = spender.owned_input(&owner, backing_key, at_pass);
    let fee_input = spender.owned_input(&owner, fee_key, at_pass);
    let claim = assemble_emission_claim(
        persona.keys(),
        &Zeroizing::new(CLAIM_TX_KEY),
        vec![fee_input.input],
        backing.input,
        terms.clone(),
        FEE,
        &backing.tree,
    );
    assert_eq!(claim.persona, persona.id());
    let claim_tx =
        Transaction::from_bytes(&claim.bytes).expect("the encoder's bytes parse as a transaction");

    // CEN-J23 on the pipeline: the claim listed in the pass block itself.
    // The epoch closed a whole epoch ago and has its budget; its `Σwork`
    // is written by this very block's pass, after its transactions are
    // judged against the parent. Closed and not yet settled is J23's
    // refusal at the transaction. The block does not connect.
    //
    // *Records-was:* until `SO-D11` the driven negative here was CEN-J25's
    // `EpochNotFinalized`, the claim at `h_close(served)`. J23 now refuses
    // every height from there to the pass first, so that bound no longer
    // binds on a chain; the retention crate's KAT still pins it.
    refused_at(
        scenario.mine_listing(vec![claim_tx.clone()]).await,
        CenRow::J23,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );
    mine_to(&mut scenario, &mut mined, connecting).await;
    catch_up(&mut spender, &mined, &mut seen);

    // The pass block: it settled the pair Served and gathered the epoch,
    // and the rows are the arithmetic above.
    let pass = &mined[usize::try_from(at_pass.to_raw()).expect("small")].archival;
    let settled: Vec<_> = pass
        .settlements()
        .iter()
        .map(|s| (s.persona, s.shard, s.epoch, s.row.outcome()))
        .collect();
    assert_eq!(
        settled,
        [(persona.id(), shard, served, SettlementOutcome::Served)]
    );
    let gather = pass
        .gathers()
        .iter()
        .find(|g| g.epoch() == served)
        .expect("the pass gathers the epoch it settles");
    let r_market: Vec<(u64, u64)> = gather
        .r_market()
        .iter()
        .map(|(shard, r)| (shard.to_raw(), r.to_raw()))
        .collect();
    assert_eq!(r_market, vec![(0, result.r_market_by_shard[0])]);
    assert_eq!(gather.sigma_work().to_raw(), result.sigma_work_milli);

    // CEN-G9 on the pipeline: a block listing this claim beside a twin —
    // the same persona and terms, its own fee input and transaction key,
    // so every per-transaction row admits both — is refused at the twin's
    // emission vin (the second occurrence of `(P, served)`; input 1, after
    // the one fee slot). The block does not connect, so the claim below
    // still lands at `connecting`. This is the witness the mutation
    // family's `DuplicateClaim` was, retired with slice 8 row 9: a claim
    // the family hand-built cannot pass the emission rows, and a claim
    // that passes them is this assembly's.
    let twin_fee_input = spender.owned_input(&owner, twin_fee_key, connecting);
    let twin_backing = spender.owned_input(&owner, backing_key, connecting);
    let twin = assemble_emission_claim(
        persona.keys(),
        &Zeroizing::new(TWIN_TX_KEY),
        vec![twin_fee_input.input],
        twin_backing.input,
        terms,
        FEE,
        &twin_backing.tree,
    );
    let twin_tx = Transaction::from_bytes(&twin.bytes).expect("the twin's bytes parse");
    refused_at(
        scenario.mine_listing(vec![claim_tx.clone(), twin_tx]).await,
        CenRow::G9,
        Locus::Input {
            slot: TxSlot::Listed(1),
            input: 1,
        },
    );

    // CEN-J26 on the pipeline: the claim with one byte of its fee-input
    // FCMP++ proof flipped. The prunable region is outside the prefix, so
    // J22's signable hash and the vin's backing proof are untouched and
    // J21, J23 and J25 admit the body as before; the fee proof is the
    // first row that reads what changed, and it refuses at the
    // transaction before the signatures (I18, whose preimage also covers
    // the prunable) are asked. The block does not connect.
    let mut corrupt_fee_proof = claim_tx.clone();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut corrupt_fee_proof.ct
    {
        p.fcmp_proof[0] ^= 0x01;
    }
    refused_at(
        scenario.mine_listing(vec![corrupt_fee_proof]).await,
        CenRow::J26,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );

    // Self-check every proving leg against the wallet-side root before any
    // rule judges it: the membership-only backing proof and the dual auth
    // through the retention crate's verifiers (the consensus operations
    // CEN-J22/J24 will call), the fee spend's FCMP through CEN-I15's.
    let root = backing.tree.tree_root.as_bytes();
    emission_vin_verify_backing(
        &claim.vin,
        root,
        claim.tree_depth,
        claim.signable.to_bytes(),
    )
    .expect("the backing's membership-only proof verifies against the wallet-side root");
    emission_vin_verify_auth(
        &claim.vin,
        &claim.reward_commits,
        &claim.signable.to_bytes(),
    )
    .expect("both auth legs verify over the Q1 messages");
    let fee_verified = proof::verify(
        &ShekylFcmpProof {
            data: claim.fcmp_proof.clone(),
            num_inputs: 1,
            tree_depth: claim.tree_depth,
        },
        &[shekyl_types::KeyImage::from_canonical_bytes(
            claim.key_images[0],
        )],
        &claim.pseudo_outs,
        &[PqcKeyScalar::from_pqc_public_key(&claim.fee_pubkeys[0])],
        root,
        claim.tree_depth,
        claim.prefix_hash.to_bytes(),
    )
    .expect("verify runs");
    assert!(fee_verified, "the fee spend's FCMP verifies");

    let block = scenario
        .mine_listing(vec![claim_tx])
        .await
        .unwrap_or_else(|outcome| panic!("the driver's emission claim connects: {outcome}"));
    assert_eq!(block.height, connecting);
    // The claim's rows in the connect: the shape (H22), the reference
    // context, the gathered closes, the verify over them and the fee
    // proof (J21, J23, J25, J26 — slice 8 row 9), the signatures (I18),
    // the fold (L7). This is the one positive witness for J23, J25 and
    // J26; the mock cannot close an epoch.
    for row in [
        CenRow::H22,
        CenRow::J21,
        CenRow::J23,
        CenRow::J25,
        CenRow::J26,
        CenRow::I18,
        CenRow::L7,
    ] {
        assert!(block.judged_by.contains(&row), "{row} judged the claim");
    }

    // The fold's write: the record updated with the claimed epoch and the
    // first paying height, set once; the store holds that row.
    let records = block.archival.records();
    assert_eq!(records.len(), 1, "the claim is the block's one write");
    assert_eq!(records[0].persona(), &persona.id());
    assert_eq!(records[0].kind(), RecordWriteKind::Update);
    let record = records[0].record();
    assert_eq!(record.claimed_settlement_epochs, vec![served]);
    assert_eq!(
        record.first_paying_emission_height,
        FirstPayingHeight::new(connecting)
    );
    assert_eq!(
        scenario.bond_record(persona.id()).await.expect("read"),
        Some(record.clone()),
        "the claim's update is the store's row"
    );
    scenario.close().await;
}
