// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-L7 through the production stack (DRS-E4 commits 4 and 5,
//! `DRS_E4_ARCHIVAL_WRITER.md` §6 rows 4–5): bond posts a persona's keys
//! built and signed, riding the driver's real spend, judged by `validate`
//! over the redb store's view, connected by `ChainStore::connect` — which
//! since commit 5 writes the verdict's delta (`archival_write.rs`) — and
//! read back two ways: the transition off the connector's reply, and the
//! rows the next block's rules read off the store.
//!
//! # Which arms are witnessed here
//!
//! The archival transition has two kinds of arm. **Single-block arms**
//! judge the block in hand over a view that holds no bond — a join (the
//! record it inserts), the refusals of a post for a persona with no
//! record. **Multi-block arms** read a record a previous block wrote — a
//! release, a reinstate, a second join, a credit for a persona who joined
//! earlier. Commit 4 witnessed the first kind and pinned the second as
//! unreachable (nothing wrote a record); commit 5's writer turned that
//! pin, and `scenario_join_tests`'s
//! `a_join_is_written_and_the_blocks_after_it_read_the_record`
//! is the same test with the two assertions inverted: the record is `Some`
//! after the join, and the next block's credit for it connects. (*Was*,
//! until E6 slice 8 row 3: "a serve credit for a persona whose join is in
//! the same block" stood among the single-block arms. It is no arm at all
//! — CEN-J4 reads the record off the view before the block, so that
//! credit is refused on the record's absence; the credit's one witness is
//! multi-block.) The multi-block
//! arms follow on the same chain: a release of the persisted record (its
//! post-image read back), a release whose debit is not that record's total
//! refused at CEN-J16 before the valid one connects, a second join for a
//! bonded persona refused at CEN-J14, and a reinstate against a record
//! whose only interval is a clean close refused at CEN-J18 (*was* L7's,
//! all three, until E6 slice 8 row 5 landed the post rows ahead of the
//! fold) — the reinstate arm's *positive* witness needs an open interval,
//! which only a slash writes, and no fixture chain here reaches the slash
//! scan (a slash needs `M` epochs of settled misses and one epoch of
//! grace; `shekyl-chain-store`'s `slash_writes_land_at_the_m_epoch_deadline`
//! is that path's witness).
//!
//! One arm the plan listed as single-block is not. A join and a release
//! for one persona in one block do not reach L7, and the release arm's
//! positive witness is a release of a *persisted* record. *Records-was:*
//! until E6 slice 8 row 5 this file read the pair as **CEN-G10**'s refusal
//! (`bond_post_block_unique`, ratified 2026-07-12: one bond post per `P`
//! per block, whatever its kind) on the ground that "G10 runs before the
//! transition". It does — but the slot loop runs before G10, and with
//! CEN-J16 in it the release reads the view before the block, finds no
//! record for `P`, and is refused there (`RecordMissing`) a pass ahead of
//! G10. The C++ has the same order (`check_tx_inputs` per body, the
//! block's duplicate-post pass after), so the pair never reached G10 there
//! either; the sentence was true of the design and false of both
//! implementations. G10's witness is two posts that each pass the slot
//! loop alone: two **joins** for one `P`, pinned below.
//!
//! # The shards
//!
//! The compact persona joins shards 0 and 1, and the chain fills them
//! first (`scenario_shard`, E6 slice 8 §5 row 6): CEN-J15 admits a compact
//! join only onto shards closed, final and priced at its parent, so the
//! join scenario (`scenario_join_tests`) mines under the levered schedule,
//! closes the two shards with real spends, and joins at the first height
//! both operands lift. That is minutes of proofs, and it runs in the live
//! lane (`cargo test -p shekyl-chain-ingest --features pipeline -- --ignored
//! a_join_is_written`). The tests in this file post no compact holding and
//! stay on the production schedule in the default lane. (*Was:* shards 7
//! and 42 on a chain that had closed none — green because the C++ admitted
//! any shard id, and never a holding of anything.)
//!
//! # What the store says
//!
//! The accrual assertion is derived, not recomputed by the scenario: the verdict's
//! `Accrual` is the epoch's row as the store held it before the block plus
//! the block's own archival leg (`PaidEmission::accrual`), and the row the
//! store holds after the block is that sum. Both reads go through the
//! connector (`BudgetAccruingOf`, `BondRecordOf`), the same store the
//! validator's view reads.
//!
//! # What is fixture here
//!
//! The serve credit's Ed25519 countersignature (no Rust countersigner
//! exists; CEN-J1/J10 pending). That is not what L7 judges. Everything L7
//! reads — the post's fields, the persona's standing, the block's own
//! posts — is the production object over the production view. (*Was*,
//! until slice 6 row 6 on 2026-10-08: the funding spend's FCMP proof was
//! fixture too, the consensus-side verify pending on this class. It is
//! CEN-J27's now — the bond post's funding half, the reference context and
//! the proof over the funding spends as one row — and the honest join in
//! `posts_for_a_persona_with_no_record_are_refused_on_the_store` is its
//! pass, the same join with one proof byte flipped its refusal.)

use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_chain_rules::{CenRow, Locus, RuleSet, TxSlot};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, SettlementEpoch};
use shekyl_wire::transaction::{BondPostKind, Holdings as WireHoldings};
use shekyl_wire::Transaction;

use crate::archival_driver::{first_spending_height, refused_at, ENDPOINT, FEE};
use crate::scenario::Scenario;
use crate::scenario_archival::{complete_tree, shard_set, Persona};
use shekyl_harness_spender::Spender;

/// The settlement epoch open at `height` under the genesis rule set — the
/// epoch a join at `height` records and a credit at `height` is keyed by.
fn epoch_at(height: BlockHeight) -> SettlementEpoch {
    RuleSet::GENESIS.settlement_schedule().epoch_at(height)
}

/// The refusals a view with no bonds produces, each through the production
/// stack: a post is assembled and signed as a wallet would (so CEN-H21 and
/// I18 pass and L7 is the row that fires), listed at the same height — a
/// refused block leaves the chain where it was — and refused at the post's
/// own input: the release at **CEN-J16**, the reinstate at **CEN-J18**,
/// the empty compact join at **CEN-J14** (all three *were* L7's until E6
/// slice 8 row 5), the unnamed kind at L7 in the sequence itself — the
/// same row and locus the fold refuses, whose arm stays the belt. The
/// join-and-release pair is
/// J16's too, not G10's (module docs). The serve credit is **CEN-J4**'s
/// (E6 slice 8 row 3): the one bond-state read the transaction pass makes,
/// ahead of the fold — *was* L7's until row 3 landed, the pin slice 8's
/// row 2 held. The funding half is **CEN-J27**'s (slice 6 row 6): the
/// honest join records it, and the same join with one byte of its funding
/// proof flipped is refused on it at the transaction — after the post rows,
/// which read nothing the flip changed, and before the signatures, whose
/// preimage covers the prunable region too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn posts_for_a_persona_with_no_record_are_refused_on_the_store() {
    let connecting = first_spending_height();
    let mut scenario = Scenario::open("scenario-archival-refusals");
    let mined = scenario
        .mine(ChainCount::from_next_height(connecting).to_raw())
        .await;
    let spender = Spender::over(&mined);
    let persona = Persona::at(3);
    let epoch = epoch_at(connecting);
    let at_post = Locus::Input {
        slot: TxSlot::Listed(0),
        input: 1,
    };
    // Every post spends block 0's coinbase at the same height — a refused
    // block leaves the chain where it was, so one funding serves them all.
    let riding = |bond| {
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::ZERO,
            connecting,
            FEE,
            Some(&bond),
        )
    };

    // A release (through `build_release_vin`, `bond_spend_sk` signing the
    // slot, the debit a source the outputs grow by) with no record to
    // empty: J16's `RecordMissing`. J13's Release arm is gated on the
    // record, so with none it has nothing to pin the slot against.
    let release = riding(persona.release(ARCHIVAL_BOND_FLOOR_ATOMIC));
    // A reinstate with no record. No wallet producer exists for one, so the
    // post is a join's fields under the Reinstate tag.
    let mut reinstate = persona.join_post(shard_set(vec![7]), ENDPOINT);
    reinstate.kind = BondPostKind::Other(shekyl_archival_retention::BondPostKind::Reinstate as u8);
    let reinstate = riding(persona.post_by_hand(reinstate));
    // A kind no rule set names.
    let mut unknown = persona.join_post(shard_set(vec![7]), ENDPOINT);
    unknown.kind = BondPostKind::Other(9);
    let unknown = riding(persona.post_by_hand(unknown));
    // A compact join holding nothing: the wire carries an empty list,
    // J14's `ShardSetCompactEmpty` refuses it; the transition's refusal of
    // a record with no holdings is the belt beneath. (A repeated shard is
    // not listed here: the wire decoder refuses it before any rule reads
    // the block, so L7's duplicate arm is a belt behind the decoder — the
    // fixture's case, `archival_tests`, is its witness.)
    let mut empty = persona.join_post(shard_set(vec![7]), ENDPOINT);
    empty.holdings = WireHoldings::ShardSetCompact(Vec::new());
    let empty = riding(persona.post_by_hand(empty));
    // The positive control: a complete tree. A compact join names a shard
    // that must be closed, final and priced (CEN-J15); this scenario closes
    // none, and the shard shape is not its subject.
    let honest = riding(persona.join(complete_tree(), ENDPOINT));

    // A serve credit for a persona with no record: J4 at the credit's own
    // input, before the fold's L7 is reached.
    refused_at(
        scenario
            .mine_listing(vec![persona.serve_credit(7, epoch.to_raw() + 1)])
            .await,
        CenRow::J4,
        Locus::Input {
            slot: TxSlot::Listed(0),
            input: 0,
        },
    );
    refused_at(
        scenario.mine_listing(vec![release]).await,
        CenRow::J16,
        at_post,
    );
    refused_at(
        scenario.mine_listing(vec![reinstate]).await,
        CenRow::J18,
        at_post,
    );
    refused_at(
        scenario.mine_listing(vec![unknown]).await,
        CenRow::L7,
        at_post,
    );
    refused_at(
        scenario.mine_listing(vec![empty]).await,
        CenRow::J14,
        at_post,
    );

    // CEN-J27 on the pipeline: the honest join with one byte of its
    // funding-spend FCMP++ proof flipped — wallet-made, the flip signed
    // over (the spender flips before it signs), so the signatures verify
    // and the funding half is the only row that reads what changed. It
    // refuses at the transaction in `form`, against the driver's reference
    // claim, before any post row reads the view (2026-10-16; until then
    // the post rows J13–J15 ran first in `validate` and the proof was
    // flipped after signing, which the signature sequence — now ahead of
    // every view-bound row — would refuse as I18). The block does not
    // connect.
    let corrupt_funding_proof = spender.spend_coinbase_posting_breaking_membership_proof(
        scenario.wallet(),
        BlockHeight::ZERO,
        connecting,
        FEE,
        Some(&persona.join(complete_tree(), ENDPOINT)),
    );
    refused_at(
        scenario.mine_listing(vec![corrupt_funding_proof]).await,
        CenRow::J27,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );

    // Positive control on the same chain: the honest join connects, so the
    // refusals above were the posts', not the height's or the funding's —
    // and its funding half is judged, not skipped: J27 is in the verdict.
    let block = scenario
        .mine_listing(vec![honest])
        .await
        .unwrap_or_else(|outcome| panic!("the honest join connects: {outcome}"));
    assert!(
        block.judged_by.contains(&CenRow::J27),
        "the funding half (CEN-J27) judged the honest join"
    );
    assert_eq!(block.archival.records().len(), 1);
    assert_eq!(block.archival.records()[0].persona(), &persona.id());

    scenario.close().await;
}

/// A join and a release for one persona in one block is **CEN-J16**'s
/// refusal at the release — the view the slot loop reads is the one before
/// the block, so the record the join would open is not there (module
/// docs: *was* pinned as CEN-G10's until E6 slice 8 row 5, on a sentence
/// true of neither implementation). It never reaches the transition, so
/// the release arm's positive witness needs a persisted record: commit
/// 5's. CEN-G10's own witness is the second block: two joins for one
/// persona, each passing the slot loop alone, the second refused after it
/// at its post.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_posts_for_one_persona_in_one_block_are_j16s_then_g10s() {
    // Two spends in one block, of coinbases 0 and 1: the block connects
    // where the later of the two is mature, one past coinbase 0's first
    // spending height.
    let connecting = first_spending_height() + BlockCount::ONE;
    let mut scenario = Scenario::open("scenario-archival-g10");
    let mined = scenario
        .mine(ChainCount::from_next_height(connecting).to_raw())
        .await;
    let spender = Spender::over(&mined);
    let persona = Persona::at(4);
    let second = Locus::Input {
        slot: TxSlot::Listed(1),
        input: 1,
    };
    // Complete trees throughout: the subject is the order of the rows over
    // two posts, not the holding — a compact join would need a closed,
    // final, priced shard (CEN-J15), and this scenario closes none.
    let join = persona.join(complete_tree(), ENDPOINT);
    let release = persona.release(ARCHIVAL_BOND_FLOOR_ATOMIC);
    let listed: Vec<Transaction> = vec![
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::ZERO,
            connecting,
            FEE,
            Some(&join),
        ),
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::from_raw(1),
            connecting,
            FEE,
            Some(&release),
        ),
    ];
    refused_at(scenario.mine_listing(listed).await, CenRow::J16, second);
    // The refused block wrote nothing, so both joins read no record and
    // J14 passes each; G10 counts the second.
    let again = persona.join(complete_tree(), ENDPOINT);
    let joins: Vec<Transaction> = vec![
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::ZERO,
            connecting,
            FEE,
            Some(&join),
        ),
        spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::from_raw(1),
            connecting,
            FEE,
            Some(&again),
        ),
    ];
    refused_at(scenario.mine_listing(joins).await, CenRow::G10, second);
    scenario.close().await;
}

/// The persona's JoinMarket post from the production constructor, with its
/// receipt key replaced by `receipt_sign_pk`, signed by the identity key
/// over the post as it then stands.
fn join_committing(
    persona: &Persona,
    receipt_sign_pk: shekyl_types::archival::ReceiptSignPk,
) -> shekyl_harness_spender::PostedBond<'_> {
    let mut post = persona.join_post(complete_tree(), ENDPOINT);
    match &mut post.kind {
        BondPostKind::JoinMarket {
            receipt_sign_pk: slot,
            ..
        } => *slot = receipt_sign_pk,
        BondPostKind::Other(_) => unreachable!("the constructor builds a JoinMarket"),
    }
    persona.post_by_hand(post)
}

/// The receipt key through the production stack (FN-DSA increment 3,
/// `FN_DSA_HYBRID.md` §8): posts a persona's keys built and signed, riding
/// real spends, judged by `validate` over the redb store's view and
/// connected.
///
/// - **CEN-J28's refusal.** A JoinMarket whose receipt key is the persona's
///   own with one byte of its FN-DSA half made undecodable — the wire
///   carries it, the length being the type's — is refused on J28 at the
///   transaction, and no record is written.
/// - **The accept, and the record.** The persona's JoinMarket from the
///   production constructor, committing its real derived receipt key
///   (`ArchivalPKeys::receipt_sign_pk`), connects, J28 among the rows that
///   judged the block; the verdict's `Insert` carries **exactly that key**
///   as `receipt_sign_pk`, and the store's row is the verdict's.
/// - **A second persona's key is its own.** The join beside it writes a
///   record with a different key.
/// - **A Release leaves the key alone.** The next block releases the first
///   record: the `Update` post-image — bonded to zero, holding nothing —
///   still carries the key, in the verdict and in the store. The receipt
///   key is set once at JoinMarket and no later post changes it.
///
/// A Reinstate's positive needs an open interval, which only a slash
/// writes, and no default-lane chain reaches the slash scan (module docs);
/// the Release here is this lane's witness that an in-place record update
/// keeps the key. The Reinstate's — and the slash's before it — is the
/// live lane's `the_levered_slash_chain_judges_each_row_on_one_record`.
///
/// Red edits: delete `J28` from `tx_form`'s `judge_tx!` line and the
/// corrupted key connects; make the fold's `join` in `archival/inputs.rs`
/// write another persona's key and the record's is not the post's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_join_markets_receipt_key_is_the_records_and_a_release_leaves_it() {
    // Two spends in the join block, of coinbases 0 and 1; the release
    // spends coinbase 2 one block later.
    let connecting = first_spending_height() + BlockCount::ONE;
    let mut scenario = Scenario::open("scenario-archival-receipt-key");
    let mined = scenario
        .mine(ChainCount::from_next_height(connecting).to_raw())
        .await;
    let mut spender = Spender::over(&mined);
    let first = Persona::at(5);
    let second = Persona::at(6);
    let key = first.receipt_key();
    assert_ne!(key, second.receipt_key());

    // The FN-DSA half starts at byte 44 of the canonical encoding
    // (`version ‖ scheme ‖ reserved(2) ‖ len(4) ‖ ed25519(32) ‖ len(4)`);
    // its first byte is the encoding's header, and no other value decodes.
    let not_a_key = {
        let mut bytes = *key.as_bytes();
        bytes[44] ^= 0xff;
        shekyl_types::archival::ReceiptSignPk::from_bytes(bytes)
    };
    let refused = join_committing(&first, not_a_key);
    refused_at(
        scenario
            .mine_listing(vec![spender.spend_coinbase_posting(
                scenario.wallet(),
                BlockHeight::ZERO,
                connecting,
                FEE,
                Some(&refused),
            )])
            .await,
        CenRow::J28,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );
    assert!(
        scenario
            .bond_record(first.id())
            .await
            .expect("answers")
            .is_none(),
        "a refused join writes no record"
    );

    // The refused block wrote nothing: the honest joins land at the same
    // height, on the same coinbases.
    let join_first = first.join(complete_tree(), ENDPOINT);
    let join_second = second.join(complete_tree(), ENDPOINT);
    let block = scenario
        .mine_listing(vec![
            spender.spend_coinbase_posting(
                scenario.wallet(),
                BlockHeight::ZERO,
                connecting,
                FEE,
                Some(&join_first),
            ),
            spender.spend_coinbase_posting(
                scenario.wallet(),
                BlockHeight::from_raw(1),
                connecting,
                FEE,
                Some(&join_second),
            ),
        ])
        .await
        .unwrap_or_else(|outcome| panic!("both joins connect: {outcome}"));
    assert_eq!(block.height, connecting);
    for row in [
        CenRow::J11,
        CenRow::J12,
        CenRow::J28,
        CenRow::J13,
        CenRow::J14,
        CenRow::J27,
        CenRow::I18,
        CenRow::L7,
    ] {
        assert!(block.judged_by.contains(&row), "{row} judged the block");
    }
    let records = block.archival.records();
    assert_eq!(records.len(), 2, "one insert per join");
    assert_eq!(records[0].persona(), &first.id());
    assert_eq!(
        records[0].record().receipt_sign_pk,
        key,
        "the record carries exactly the key the post committed"
    );
    assert_eq!(records[0].record().bond_spend_pk, first.bond_spend());
    assert_eq!(records[0].record().hybrid_pubkey, first.identity());
    assert_eq!(records[1].persona(), &second.id());
    assert_eq!(
        records[1].record().receipt_sign_pk,
        second.receipt_key(),
        "each record carries its own persona's key"
    );
    let joined = records[0].record().clone();
    assert_eq!(
        scenario.bond_record(first.id()).await.expect("read"),
        Some(joined.clone()),
        "the store's row is the verdict's, receipt key included"
    );
    assert_eq!(
        scenario.bond_record(second.id()).await.expect("read"),
        Some(records[1].record().clone()),
    );
    spender.push(&block);

    // The release of the first record: its post-image keeps the key.
    let next = connecting + BlockCount::ONE;
    let release = first.release(joined.bonded_total.to_raw());
    let block = scenario
        .mine_listing(vec![spender.spend_coinbase_posting(
            scenario.wallet(),
            BlockHeight::from_raw(2),
            next,
            FEE,
            Some(&release),
        )])
        .await
        .unwrap_or_else(|outcome| panic!("the release connects: {outcome}"));
    let records = block.archival.records();
    assert_eq!(records.len(), 1, "the release is the block's one write");
    assert_eq!(records[0].persona(), &first.id());
    let released = records[0].record();
    assert_eq!(
        released.bonded_total.to_raw(),
        0,
        "the release emptied the bond"
    );
    assert_ne!(released, &joined, "the release changed the record");
    assert_eq!(
        released.receipt_sign_pk, key,
        "a Release does not touch the receipt key"
    );
    assert_eq!(
        scenario.bond_record(first.id()).await.expect("read"),
        Some(released.clone()),
        "the store's post-image keeps the key"
    );
    assert_eq!(
        scenario
            .bond_record(second.id())
            .await
            .expect("read")
            .map(|record| record.receipt_sign_pk),
        Some(second.receipt_key()),
        "another persona's release does not touch this record"
    );
    scenario.close().await;
}
