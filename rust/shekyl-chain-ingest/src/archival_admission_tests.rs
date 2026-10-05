// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.J through the driver, **before any 4.J rule exists**
//! (`CHAIN_RULES_SLICE_8.md` §5 row 2, PR-a commits 3–4). Four measurements,
//! each a pin on what `validate` does today over the production store;
//! every pin names the row that flips it and the commit that lands the
//! row. Slice 7's commit 2 had this shape (`body_pairing_tests`) and
//! found G5's mis-keying and the `Unmutable` census before a rule depended
//! on either.
//!
//! **(a) The corpus, enumerated.** [`the_corpus_carries_exactly_these_archival_inputs`]
//! reads every archival input off the two captured chains that have any
//! — `bond-post` and `emission-claim` — and holds them to a table written
//! from the first run: height, slot, kind, and the facts the 4.J rows will
//! judge (the hint recomputes; the credit's epoch against the join's; the
//! claim's epochs). The positive witnesses §2 lists as *corpus accept* are
//! then a list, not a belief: a rule that refuses one of these blocks has
//! refused a named input.
//!
//! **(b) Reinstate, built and connected.** The driver can now make a
//! Reinstate ([`Persona::reinstate`]); its positive witness needs an open
//! bad interval, which only a slash writes, so
//! [`a_slashed_persona_reinstates_and_the_fold_agrees_with_the_wallet_side_verify`]
//! runs a levered schedule to the first deadline eleven settled misses
//! reach, loses one of two shards, and reinstates over the one it kept.
//! The §5 row 2 text also named *"a Release that the driver validates
//! (today it only constructs)"*; that premise was stale at the pin — a
//! Release has reached `validate` and connected since DRS-E4 commit 5
//! (`scenario_archival_tests.rs`, the `whole` persona's release). What
//! the driver had never made was the Reinstate, and that is what lands.
//!
//! **(c) The bond-state rows J4–J6 on a serve-credit vin — landed at §5
//! row 3.** Three credits, each refused at its own input by its own row:
//! a credit for a persona with **no record** is J4's
//! (`scenario_archival_tests`; row 2 had found it refused by L7's fold,
//! `inputs.rs:49–53`, so the flip there was `L7 → J4`, not a first
//! refusal); a credit at the **join epoch** is J5's
//! (`serve_credit_epoch_ok`, which row 2 found nothing in the validator
//! calling); a credit from a persona **past its `good_through`** — the
//! slashed persona of (b), inside its open interval — is J6's, whether or
//! not it still holds the shard. Whether it *holds* the shard is CEN-J8's
//! question (E6 slice C), not J6's: the credit for the shard it lost is
//! refused here on the interval, and that pin is carried in the test
//! body. *Records-was (row 2's pins, 2026-10-04):* J5's and J6's credits
//! both connected, the fold reading *a record exists* and nothing of its
//! state.
//!
//! **(d) The hint, trusted.** §2's finding made concrete: the transition
//! keys a post's record on the vin's `p_canonical_id` **as decoded**, never
//! recomputed from the `hybrid_public_key` beside it. A JoinMarket whose
//! hint names a stranger connects and inserts a record under the
//! stranger's id. And the money-moving form: a Release whose fields are a
//! bonded persona's — key and id consistent, so a J11 recompute would pass
//! — with the slot signed by **another persona's** key connects today, empties
//! the victim's record, and CEN-H21 balances the victim's collateral onto
//! the signer's outputs. I18 verifies the slot's signature against
//! whatever key the slot carries; *which* key a debit arm must carry is
//! J13, unlanded. Both pins flip at §5 row 4 (J11; J13).

use std::path::Path;

use shekyl_archival_retention::{
    good_through, p_canonical_id_from_hybrid_pubkey, serve_credit_epoch_ok,
    verify_reinstate_bond_post, BondPostKind as RetentionKind, HoldingsKind,
    ARCHIVAL_BOND_FLOOR_ATOMIC, RELEASE_COOLDOWN_EPOCHS,
};
use shekyl_chain_rules::{
    ArchivalKey, CenRow, FakechainSchedule, Locus, RecordWriteKind, RuleSet, SettlementEpochBlocks,
    SettlementSchedule, TxSlot,
};
use shekyl_types::archival::{BadInterval, Holdings};
use shekyl_types::{BlockCount, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{BondPostKind, Holdings as WireHoldings};
use shekyl_wire::Input;

use crate::connector::{Inject, Injected};
use crate::corpus::CorpusReader;
use crate::scenario::{FreeHash, Mined, Scenario, StepOutcome};
use crate::scenario_archival::{shard_set, Persona};
use crate::scenario_spend::Spender;
use crate::schedule::ChainRules;
use crate::source::{IngestEvent, ServeCredit, Source};
use crate::vectors_tests::captured_chains;

const FEE: u64 = 1_000_000;
const ENDPOINT: [u8; 32] = [0xEE; 32];

/// The first height that can spend block 0's coinbase against a root that
/// holds it (`scenario_tests`: unlock window + spendable age + 1). The same
/// under every regtest rule set here: the lever moves the settlement
/// schedule, not the unlock window.
fn first_spending_height() -> u64 {
    RuleSet::GENESIS.mined_money_unlock_window().to_raw()
        + RuleSet::GENESIS.tx_spendable_age().to_raw()
        + 1
}

fn at_post(slot: usize) -> Locus {
    Locus::Input {
        slot: TxSlot::Listed(slot),
        input: 1,
    }
}

fn refused_at(outcome: Result<Mined, StepOutcome>, row: CenRow, locus: Locus) {
    match outcome {
        Err(StepOutcome::Refused(refused)) => {
            assert_eq!(refused.rule, row, "the row that refused: {refused}");
            assert_eq!(refused.locus, locus, "where it refused: {refused}");
        }
        Ok(block) => panic!("admitted at {}, expected {row}'s refusal", block.height),
        Err(other) => panic!("expected {row}'s refusal, got {other}"),
    }
}

// ---------------------------------------------------------------------
// (a) The corpus, enumerated
// ---------------------------------------------------------------------

/// One archival input as the corpus carries it, reduced to the facts the
/// 4.J rows read. Heights are the block's; `slot` is the listed index.
#[derive(Debug, PartialEq, Eq)]
enum Archival {
    /// A bond post vin: its kind, whether the vin's `p_canonical_id` hint
    /// is the recompute over its `hybrid_public_key` (J11's clause), and
    /// the money terms J14 reads.
    Post {
        height: u64,
        slot: usize,
        kind: &'static str,
        hint_recomputes: bool,
        holdings: WireHoldings,
        bonded_total: u64,
        credit: u64,
        debit: u64,
    },
    /// A serve-credit **vin** (none in the corpus today — the injected
    /// credit is a record, below).
    CreditVin {
        height: u64,
        slot: usize,
        shard: u64,
        epoch: u64,
    },
    /// An `Inject` record: a credit no block produced, attributed to the
    /// tip it was written at. Not a vin: J4–J6 never see it.
    Injected { at_tip: u64, shard: u64, epoch: u64 },
    /// An emission vin: the claimant and the epochs claimed (J19's parse).
    Claim {
        height: u64,
        slot: usize,
        epochs: Vec<u64>,
    },
}

/// Every archival input of the chain at `dir`, in corpus order, with the
/// persona each names — so the table can say *the claim is the join's
/// persona* rather than carry two hashes.
fn enumerate(dir: &Path) -> (Vec<(PCanonicalId, Archival)>, SettlementSchedule) {
    let manifest_text = std::fs::read_to_string(dir.join("manifest.json")).expect("manifest");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text).expect("json");
    let seb = manifest["settlement_epoch_blocks"]
        .as_u64()
        .expect("the manifest names its schedule");
    let schedule = SettlementSchedule::new(SettlementEpochBlocks::new(seb).expect("non-zero"));

    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let mut reader =
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus");
    let mut height = reader.first_height().to_raw();
    let mut tip: Option<u64> = None;
    let mut found = Vec::new();
    while let Some(event) = reader.next().expect("corpus reads") {
        match event.event {
            IngestEvent::Extend(candidate) => {
                for (slot, tx) in candidate.transactions.iter().enumerate() {
                    for input in &tx.prefix.inputs {
                        match input {
                            Input::BondPost(post) => {
                                let recomputed =
                                    p_canonical_id_from_hybrid_pubkey(&post.hybrid_public_key);
                                let kind = match &post.kind {
                                    BondPostKind::JoinMarket { .. } => "JoinMarket",
                                    BondPostKind::Other(k) => match RetentionKind::from_u8(*k) {
                                        Ok(RetentionKind::Release) => "Release",
                                        Ok(RetentionKind::Reinstate) => "Reinstate",
                                        _ => "unknown",
                                    },
                                };
                                found.push((
                                    post.p_canonical_id,
                                    Archival::Post {
                                        height,
                                        slot,
                                        kind,
                                        hint_recomputes: recomputed == post.p_canonical_id,
                                        holdings: post.holdings.clone(),
                                        bonded_total: post.bonded_total_atomic,
                                        credit: post.bond_credit,
                                        debit: post.bond_debit,
                                    },
                                ));
                            }
                            Input::ServeCredit { .. } => {
                                let Some(ArchivalKey::ServeCredit { p, shard, epoch }) =
                                    ArchivalKey::of(input)
                                else {
                                    panic!(
                                        "{}: an unparseable serve credit at {height}",
                                        dir.display()
                                    );
                                };
                                found.push((
                                    PCanonicalId::from_bytes(p),
                                    Archival::CreditVin {
                                        height,
                                        slot,
                                        shard,
                                        epoch,
                                    },
                                ));
                            }
                            Input::ArchivalRewardEmission { .. } => {
                                let Some(ArchivalKey::Claims { p, epochs }) =
                                    ArchivalKey::of(input)
                                else {
                                    panic!(
                                        "{}: an unparseable emission vin at {height}",
                                        dir.display()
                                    );
                                };
                                found.push((
                                    PCanonicalId::from_bytes(p),
                                    Archival::Claim {
                                        height,
                                        slot,
                                        epochs,
                                    },
                                ));
                            }
                            Input::Gen(_) | Input::ToKey { .. } => {}
                        }
                    }
                }
                tip = Some(height);
                height += 1;
            }
            IngestEvent::Rewind { to } => {
                tip = Some(to.to_raw());
                height = to.to_raw() + 1;
            }
            IngestEvent::Inject(credit) => found.push((
                credit.persona,
                Archival::Injected {
                    at_tip: tip.expect("the corpus law refuses an inject before any block"),
                    shard: credit.shard.to_raw(),
                    epoch: credit.epoch.to_raw(),
                },
            )),
        }
    }
    (found, schedule)
}

/// What the corpus carries, read off the two chains on 2026-10-04 and
/// held. **Both directions:** every chain in the corpus is here, the four
/// with no archival input as the empty list, so a capture that grows one
/// fails this table rather than slipping past it.
///
/// The facts the 4.J rows will judge, as the corpus has them today:
///
/// - **J11** — both posts' hints recompute from their `hybrid_public_key`.
/// - **J14** — both joins carry `credit == bonded_total == one floor`:
///   the complete tree's floor and a one-shard compact set's are the same
///   number (`bond_floor_of`), so the corpus does **not** distinguish a
///   per-shard floor from a flat one; a rule that gets the multiplier
///   wrong passes the corpus. The driver's two-shard join and its
///   one-floor negative (`scenario_archival_tests`) are the witnesses
///   that do.
/// - **J5** — the one credit is the injector's, at epoch `E_join + 1`,
///   written while epoch 0 was still open (tip 115 of a 512-block epoch):
///   a credit *for* an epoch that has not begun. It is a record, not a
///   vin, so J4–J6 never read it; its epoch arithmetic is the injector's
///   contract (`Inject`'s law), not 4.J's.
/// - **J19/J20** — the one claim names the credited epoch and no other,
///   two epochs after the join, by the join's persona.
/// - **No serve-credit vin and no Release or Reinstate** anywhere in the
///   corpus: J4–J6, J13, J18 have no corpus-positive witness, which is why
///   (b)–(d) build theirs on the driver.
fn expected(shape: &str) -> Vec<Archival> {
    match shape {
        "bond-post" => vec![Archival::Post {
            height: 98,
            slot: 0,
            kind: "JoinMarket",
            hint_recomputes: true,
            holdings: WireHoldings::CompleteTree,
            bonded_total: ARCHIVAL_BOND_FLOOR_ATOMIC,
            credit: ARCHIVAL_BOND_FLOOR_ATOMIC,
            debit: 0,
        }],
        "emission-claim" => vec![
            Archival::Post {
                height: 98,
                slot: 0,
                kind: "JoinMarket",
                hint_recomputes: true,
                holdings: WireHoldings::ShardSetCompact(vec![0]),
                bonded_total: ARCHIVAL_BOND_FLOOR_ATOMIC,
                credit: ARCHIVAL_BOND_FLOOR_ATOMIC,
                debit: 0,
            },
            Archival::Injected {
                at_tip: 115,
                shard: 0,
                epoch: 1,
            },
            Archival::Claim {
                height: 1025,
                slot: 0,
                epochs: vec![1],
            },
        ],
        "limit-full" | "median-full" | "spend-1in-2out" | "spend-depth3" => Vec::new(),
        other => panic!("a chain this table does not know: {other}"),
    }
}

#[test]
fn the_corpus_carries_exactly_these_archival_inputs() {
    let chains = captured_chains();
    assert_eq!(chains.len(), 6, "the corpus has six chains");
    for (dir, manifest) in chains {
        let (found, schedule) = enumerate(&dir);
        let inputs: Vec<&Archival> = found.iter().map(|(_, input)| input).collect();
        let expected = expected(&manifest.shape);
        assert_eq!(
            inputs,
            expected.iter().collect::<Vec<_>>(),
            "{}: the archival inputs the corpus carries",
            manifest.shape
        );
        // Every archival input of a chain names one persona — the join's.
        let personas: std::collections::BTreeSet<&PCanonicalId> =
            found.iter().map(|(p, _)| p).collect();
        assert!(
            personas.len() <= 1,
            "{}: one persona per chain, found {}",
            manifest.shape,
            personas.len()
        );
        if manifest.shape == "emission-claim" {
            // The injected credit sits at `E_join + 1` — the epoch J5 will
            // accept — and the claim lands after that epoch settled.
            let join_epoch = schedule.epoch_at_height(98);
            assert_eq!(join_epoch, 0);
            assert!(serve_credit_epoch_ok(1, join_epoch));
            assert_eq!(
                schedule.epoch_at_height(115),
                0,
                "injected before its epoch opened"
            );
            assert_eq!(schedule.epoch_at_height(1025), 2);
        }
    }
}

// ---------------------------------------------------------------------
// (b) Reinstate, and (c) J5/J6 on the same levered chain
// ---------------------------------------------------------------------

/// A 20-block epoch with a 10-block reorg cap: the first slash deadline
/// eleven settled misses can reach sits at height 319, inside what a test
/// mines in seconds. `FAILURE_WINDOW_M = 11` misses over epochs
/// `E_join + 1 ..= E_join + 11` are judged when the count passes
/// `slash_deadline_height(E_join + 11) = last_block(E_join + 12)`.
const SEB: u64 = 20;
const CAP: u64 = 10;

fn levered_rules() -> ChainRules {
    ChainRules::Regtest {
        fixed_difficulty: Some(std::num::NonZeroU128::MIN),
        schedule: FakechainSchedule::new(
            SettlementEpochBlocks::new(SEB).expect("non-zero"),
            BlockCount::from_raw(CAP),
        )
        .expect("the cap sits inside the epoch"),
    }
}

fn levered_schedule() -> SettlementSchedule {
    SettlementSchedule::new(SettlementEpochBlocks::new(SEB).expect("non-zero"))
}

/// The persona's record, which must exist.
async fn record_of(
    scenario: &Scenario<FreeHash>,
    persona: &Persona,
) -> shekyl_types::archival::BondRecord {
    scenario
        .bond_record(persona.id())
        .await
        .expect("the store answers")
        .expect("the persona has a record")
}

/// One persona joins two shards, serves one of them for eleven epochs and
/// never the other, and is slashed on the deadline the schedule names:
/// the record keeps the served shard, carries one open interval, and is
/// down one floor. Then:
///
/// - **(c) J5:** its credit at the join epoch — the block after the join —
///   is refused at the credit's input; the credit for `E_join + 1` on the
///   same chain connects (the positive control, and the first pass the
///   slash below counts against). *Was pinned* (row 2) as connecting.
/// - **(c) J6:** inside the open interval, a credit for the kept shard is
///   refused at the credit's input, and so is one for the shard it **no
///   longer holds** — on the interval, which is J6's reading; the holding
///   itself is J8's (slice C), and a credit for the lost shard **after**
///   the reinstate closes the interval is pinned below as connecting
///   today. *Was pinned* (row 2) as both connecting.
/// - **(b) Reinstate, positive witness:** the driver's Reinstate over the
///   record as it stands connects; the wallet-side
///   `verify_reinstate_bond_post` agrees with the fold on the same vin;
///   the interval closes at `reinstate epoch + 1`, the write is an
///   `Update`, and the store reads it back.
/// - **(b) the belts, under J18:** a second Reinstate (no open interval)
///   and one naming the holdings it had before the slash
///   (`HoldingsChanged`) refuse at the post under **CEN-J18** (*were*
///   L7's until §5 row 5); the fold's arms are the belts beneath. A
///   Release two epochs inside the cooldown is **CEN-J16**'s
///   (`CooldownNotElapsed`) — the one negative of that arm a chain with a
///   served record can shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slashed_persona_reinstates_and_the_fold_agrees_with_the_wallet_side_verify() {
    let schedule = levered_schedule();
    let mut scenario = Scenario::open_under("slice-8-reinstate", FreeHash, levered_rules());
    let mut chain: Vec<Mined> = scenario.mine(first_spending_height()).await;
    let next = |chain: &Vec<Mined>| chain.len() as u64;

    // The join, at the first spending height.
    let persona = Persona::at(11);
    let (served, unserved) = (42u64, 7u64);
    let join_height = next(&chain);
    let join_epoch = schedule.epoch_at_height(join_height);
    assert_eq!(join_epoch, 3, "71 / 20");
    {
        let spender = Spender::over(&chain);
        let joining = spender.spend_coinbase_posting(
            scenario.wallet(),
            0,
            join_height,
            FEE,
            Some(&persona.join(shard_set(vec![unserved, served]), ENDPOINT)),
        );
        let block = scenario
            .mine_listing(vec![joining])
            .await
            .expect("the join connects");
        assert_eq!(block.archival.records()[0].kind(), RecordWriteKind::Insert);
        chain.push(block);
    }

    // (c) J5: a credit at the join epoch, the block after the join, is
    // refused at its input; the same credit for `E_join + 1` connects.
    let at_credit = Locus::Input {
        slot: TxSlot::Listed(0),
        input: 0,
    };
    assert!(
        !serve_credit_epoch_ok(join_epoch, join_epoch),
        "the retention crate refuses a credit at E_join"
    );
    refused_at(
        scenario
            .mine_listing(vec![persona.serve_credit(served, join_epoch)])
            .await,
        CenRow::J5,
        at_credit,
    );
    let first_serving = scenario
        .mine_listing(vec![persona.serve_credit(served, join_epoch + 1)])
        .await
        .expect("the credit for E_join + 1 connects (J4, J5, J6 over the record)");
    assert_eq!(first_serving.archival.serve_credits().len(), 1);
    chain.push(first_serving);

    // Eleven passes on the served shard, none on the other: the mined
    // credit above is the first; the injector writes the other ten.
    for epoch in (join_epoch + 2)..=(join_epoch + 11) {
        let Injected { .. } = scenario
            .connector()
            .ask(Inject(ServeCredit {
                persona: persona.id(),
                shard: ShardId::from_raw(served),
                epoch: SettlementEpoch::from_raw(epoch),
            }))
            .await
            .expect("the injector writes");
    }

    // To the deadline: the slash fires in the block whose count first
    // exceeds `slash_deadline_height(E_join + 11)`.
    let slash_epoch = join_epoch + 11;
    let deadline = schedule.slash_deadline_height(slash_epoch);
    assert_eq!(deadline, 319);
    while next(&chain) <= deadline {
        let block = scenario
            .mine_listing(Vec::new())
            .await
            .expect("empty blocks land");
        chain.push(block);
    }
    let slashed_at: Vec<u64> = chain
        .iter()
        .filter(|b| !b.archival.slashes().is_empty())
        .map(|b| b.height.to_raw())
        .collect();
    assert_eq!(
        slashed_at,
        vec![deadline],
        "one slash, in the deadline block"
    );
    let slash = &chain.last().expect("mined").archival.slashes()[0];
    assert_eq!(slash.entry.persona, persona.id());
    assert_eq!(slash.entry.shard.to_raw(), unserved);
    assert_eq!(slash.entry.epoch.to_raw(), slash_epoch);
    assert_eq!(slash.burned.to_raw(), ARCHIVAL_BOND_FLOOR_ATOMIC);

    let record = record_of(&scenario, &persona).await;
    assert_eq!(record.bonded_total.to_raw(), ARCHIVAL_BOND_FLOOR_ATOMIC);
    let Holdings::ShardSet(held) = &record.holdings else {
        panic!("compact");
    };
    assert_eq!(
        held.iter().map(|h| h.shard.to_raw()).collect::<Vec<_>>(),
        vec![served]
    );
    assert_eq!(
        record.bad_intervals,
        vec![BadInterval {
            start_epoch: slash_epoch,
            end_exclusive: BadInterval::OPEN_END,
        }]
    );

    // (c) J6: inside the open interval, a credit for the kept shard and one
    // for the slashed shard are each refused at the credit's input — both
    // on the interval (`good_through`), which is all J6 reads.
    let inside = slash_epoch + 1;
    assert!(
        !good_through(join_epoch, inside, &record.bad_intervals),
        "the retention crate says the persona is not good through `inside`"
    );
    for shard in [served, unserved] {
        refused_at(
            scenario
                .mine_listing(vec![persona.serve_credit(shard, inside)])
                .await,
            CenRow::J6,
            at_credit,
        );
    }

    // (b) The Reinstate. The wallet-side verify and the fold read the same
    // vin; both say yes.
    let vin = persona.reinstate_vin(&record);
    verify_reinstate_bond_post(
        &vin,
        Some(record.bonded_total.to_raw()),
        HoldingsKind::ShardSetCompact,
        &[served],
        &record.bad_intervals,
    )
    .expect("the wallet-side verify accepts the driver's reinstate");
    let reinstate_height = next(&chain);
    let reinstate_epoch = schedule.epoch_at_height(reinstate_height);
    let reinstated = {
        let spender = Spender::over(&chain);
        let riding = spender.spend_coinbase_posting(
            scenario.wallet(),
            1,
            reinstate_height,
            FEE,
            Some(&persona.reinstate(&record)),
        );
        scenario
            .mine_listing(vec![riding])
            .await
            .expect("the reinstate connects")
    };
    let write = &reinstated.archival.records()[0];
    assert_eq!(write.persona(), &persona.id());
    assert_eq!(write.kind(), RecordWriteKind::Update);
    assert_eq!(
        write.record().bad_intervals,
        vec![BadInterval {
            start_epoch: slash_epoch,
            end_exclusive: reinstate_epoch + 1,
        }]
    );
    assert_eq!(
        write.record().holdings,
        record.holdings,
        "holdings unchanged"
    );
    assert_eq!(
        write.record().bonded_total,
        record.bonded_total,
        "zero money"
    );
    let written = write.record().clone();
    chain.push(reinstated);
    let stored = record_of(&scenario, &persona).await;
    assert_eq!(stored, written, "the store holds the post-image");

    // Past the closed interval the persona is good through again: a credit
    // for the kept shard connects. So does one for the shard it **lost**
    // — J6 reads the interval and nothing of the holdings. PIN (J8,
    // `holds_shard_at`, E6 slice C): a credit for an unheld shard connects
    // today.
    let after_close = reinstate_epoch + 1;
    assert!(good_through(join_epoch, after_close, &stored.bad_intervals));
    let past_interval = scenario
        .mine_listing(vec![
            persona.serve_credit(served, after_close),
            persona.serve_credit(unserved, after_close),
        ])
        .await
        .expect("PIN (J8, slice C): a credit for a shard no longer held connects today");
    assert_eq!(past_interval.archival.serve_credits().len(), 2);
    chain.push(past_interval);

    // (b) The belts, under J18. Every post below rides coinbase 2 at the
    // same height; a refused block leaves the chain where it was.
    let spender = Spender::over(&chain);
    let height = next(&chain);
    let riding =
        |bond| spender.spend_coinbase_posting(scenario.wallet(), 2, height, FEE, Some(&bond));
    // No open interval to close.
    let no_open_interval = riding(persona.reinstate(&stored));
    // The holdings before the slash: `HoldingsChanged`.
    let mut before_slash = stored.clone();
    before_slash.holdings = Holdings::shard_set(
        [unserved, served]
            .iter()
            .map(|&s| shekyl_types::archival::HeldShard {
                shard: ShardId::from_raw(s),
                add_epoch: SettlementEpoch::from_raw(join_epoch),
            })
            .collect(),
    )
    .expect("two shards");
    before_slash.bad_intervals = record.bad_intervals.clone();
    let holdings_changed = riding(persona.reinstate(&before_slash));
    // J16's cooldown: the persona's last pass on its kept shard is
    // `after_close`, the block connecting now is still in
    // `reinstate_epoch`, and a Release waits `RELEASE_COOLDOWN_EPOCHS`
    // past the last pass. J13 passes it first (the bond-spend slot).
    let current = schedule.epoch_at_height(height);
    assert!(
        current < after_close + RELEASE_COOLDOWN_EPOCHS,
        "the release lists inside the cooldown ({current} < {after_close} + {RELEASE_COOLDOWN_EPOCHS})"
    );
    let early_release = riding(persona.release(stored.bonded_total.to_raw()));

    refused_at(
        scenario.mine_listing(vec![no_open_interval]).await,
        CenRow::J18,
        at_post(0),
    );
    refused_at(
        scenario.mine_listing(vec![holdings_changed]).await,
        CenRow::J18,
        at_post(0),
    );
    refused_at(
        scenario.mine_listing(vec![early_release]).await,
        CenRow::J16,
        at_post(0),
    );

    // (e) J16's accept arm over a **served** anchor — the operand the
    // gather reads (`release_terms_hold`: the kept shard's last pass,
    // `after_close`), not the vacuous `None` of a persona that never
    // served. The two serving operands lift at one height: the slash fold
    // settles `after_close` in the block at its deadline (`scan_slashes`,
    // count past `slash_deadline_height`), and the next block is the first
    // of epoch `after_close + RELEASE_COOLDOWN_EPOCHS` — the cooldown's
    // boundary, inclusive. So the pair is one block apart: at the deadline
    // the epoch is one short and the watermark pre-block is one behind;
    // one block later both hold and the Release is the record's `Update`.
    let anchor = after_close;
    let boundary = schedule.slash_deadline_height(anchor);
    assert_eq!(schedule.epoch_at_height(boundary), anchor + 1);
    assert_eq!(
        schedule.epoch_at_height(boundary + 1),
        anchor + RELEASE_COOLDOWN_EPOCHS,
        "the block after the anchor's deadline opens the cooldown's boundary epoch"
    );
    while next(&chain) < boundary {
        let block = scenario
            .mine_listing(Vec::new())
            .await
            .expect("empty blocks land");
        assert!(
            block.archival.slashes().is_empty(),
            "a persona serving past its closed interval is not slashed again (height {})",
            block.height
        );
        chain.push(block);
    }
    // Each release is built over the chain it rides and before the mine
    // that follows it (the spender borrows the wallet, `mine_listing` the
    // scenario); the deadline block lands between the two.
    let full_release = persona.release(stored.bonded_total.to_raw());
    let at_deadline = Spender::over(&chain).spend_coinbase_posting(
        scenario.wallet(),
        2,
        boundary,
        FEE,
        Some(&full_release),
    );
    refused_at(
        scenario.mine_listing(vec![at_deadline]).await,
        CenRow::J16,
        at_post(0),
    );
    let settling = scenario
        .mine_listing(Vec::new())
        .await
        .expect("the deadline block lands");
    assert_eq!(settling.height, BlockHeight::from_raw(boundary));
    assert!(
        settling.archival.slashes().is_empty(),
        "nothing to slash at the anchor's deadline"
    );
    chain.push(settling);
    let past_boundary = Spender::over(&chain).spend_coinbase_posting(
        scenario.wallet(),
        2,
        boundary + 1,
        FEE,
        Some(&full_release),
    );
    let released = scenario
        .mine_listing(vec![past_boundary])
        .await
        .unwrap_or_else(|outcome| {
            panic!("the release connects at the cooldown's boundary with the anchor settled: {outcome}")
        });
    for row in [CenRow::J13, CenRow::J16] {
        assert!(
            released.judged_by.contains(&row),
            "{row} judged the release"
        );
    }
    let write = &released.archival.records()[0];
    assert_eq!(write.persona(), &persona.id());
    assert_eq!(write.kind(), RecordWriteKind::Update);
    assert_eq!(write.record().bonded_total, AtomicUnits::ZERO);
    assert_eq!(
        write.record().holdings,
        Holdings::shard_set(Vec::new()).expect("empty"),
        "a release empties the holdings"
    );
    assert_eq!(
        record_of(&scenario, &persona).await,
        write.record().clone(),
        "the store holds the post-image"
    );

    scenario.close().await;
}

// ---------------------------------------------------------------------
// (d) The hint, trusted
// ---------------------------------------------------------------------

/// Three personas on a genesis-schedule chain: `bonded` joins; `stranger`
/// and `signer` never do. Then:
///
/// - **J11:** `signer`'s JoinMarket with its `p_canonical_id` overwritten
///   to `stranger`'s is refused on CEN-J11 at the transaction — the hint
///   is the recompute over the key, not a field the poster addresses the
///   store with. Neither `signer` nor `stranger` gains a record.
/// - **J13 (the money form of J11's finding):** `signer` posts a Release
///   whose fields are `bonded`'s — key and id consistent, so J11 passes —
///   with the slot signed by `signer`'s identity key. I18 would accept
///   it: the slot's signature verifies against the key the slot carries.
///   **Which** key a Release's slot must carry is CEN-J13 — the record's
///   `bond_spend_pk` — and the Release is refused at the post's vin before
///   the fold writes and before CEN-H21 would balance `bonded`'s
///   collateral onto `signer`'s outputs. `bonded`'s record is untouched.
///
/// Records-was (pinned until §5 row 4, 2026-10-04): both connected. The
/// join inserted a record under `stranger`'s id carrying `signer`'s key;
/// the Release emptied `bonded`'s record and the debit followed. That is
/// the finding the slice's §2 predicted and the reason PR-b leads with
/// the hint rows: the store's record was addressed by a field the poster
/// wrote, and the money followed the address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_post_is_keyed_by_the_recompute_and_a_release_by_the_record_key() {
    let mut scenario = Scenario::open("slice-8-hint");
    let mut chain: Vec<Mined> = scenario.mine(first_spending_height()).await;
    let next = |chain: &Vec<Mined>| chain.len() as u64;
    let (bonded, stranger, signer) = (Persona::at(21), Persona::at(22), Persona::at(23));
    let total = ARCHIVAL_BOND_FLOOR_ATOMIC;

    // `bonded` joins one shard.
    {
        let spender = Spender::over(&chain);
        let height = next(&chain);
        let joining = spender.spend_coinbase_posting(
            scenario.wallet(),
            0,
            height,
            FEE,
            Some(&bonded.join(shard_set(vec![7]), ENDPOINT)),
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
        let mut post = signer.join_post(shard_set(vec![9]), ENDPOINT);
        assert_eq!(
            p_canonical_id_from_hybrid_pubkey(&post.hybrid_public_key),
            signer.id(),
            "the constructor's hint recomputes"
        );
        post.p_canonical_id = stranger.id();
        let riding = spender.spend_coinbase_posting(
            scenario.wallet(),
            1,
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
            2,
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
