// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for what `staking_info` reports in flight and how it ended
//! (`engine/staking_outcomes.rs`).
//!
//! Wired as a `#[path]` child of `staking_outcomes::tests`, so `use super::*`
//! resolves into the module and its private projection stays testable; the
//! sibling file exists so the decomposition ratchet counts the module rather
//! than its suite (the `block_fetch_tests` pattern).

use super::*;

/// [`super::in_flight`] for tests, whose fixtures cannot overflow.
fn in_flight(
    block: &PendingPostBlock,
    ledger_tip: BlockHeight,
    evidence: ScanEvidence<'_>,
) -> Vec<InFlightRecord> {
    super::in_flight(block, ledger_tip, evidence).expect("a fixture's amounts fit u64")
}

use std::collections::BTreeSet;

use shekyl_engine_state::pending_post_block::SealAdmission;
use shekyl_engine_state::{PendingBondPost, PendingDrain, PendingEmissionClaim, PendingRelease};
use shekyl_types::{BlockCount, GlobalOutputIndex, PCanonicalId, PSlot};

const REFERENCE: BlockHeight = BlockHeight::from_raw(5_000);
const END: BlockHeight = BlockHeight::from_raw(5_100);

fn persona(b: u8) -> PCanonicalId {
    PCanonicalId::from_bytes([b; 32])
}

fn gindexes(g: &[u64]) -> Vec<GlobalOutputIndex> {
    g.iter().copied().map(GlobalOutputIndex::from_raw).collect()
}

fn post(b: u8, g: &[u64]) -> PendingBondPost {
    PendingBondPost {
        p_slot: PSlot::from_raw(u32::from(b)),
        persona: persona(b),
        tx_bytes: vec![b],
        bond_post_offset_blocks: BlockCount::from_raw(0),
        anchor_t0: ChainCount::from_raw(4_990),
        funding_gindexes: gindexes(g),
        state: PendingPostState::Pending,
        reference_height: REFERENCE,
        terminal: None,
    }
}

fn claim(b: u8, g: &[u64]) -> PendingEmissionClaim {
    PendingEmissionClaim {
        persona: persona(b),
        tx_bytes: vec![b],
        fee_gindexes: gindexes(g),
        state: PendingPostState::Pending,
        reference_height: REFERENCE,
        terminal: None,
    }
}

fn drain(b: u8, g: &[u64]) -> PendingDrain {
    PendingDrain {
        persona: persona(b),
        tx_bytes: vec![b],
        funding_gindexes: gindexes(g),
        state: PendingPostState::Pending,
        reference_height: REFERENCE,
        terminal: None,
    }
}

fn at(tip: u64) -> BlockHeight {
    BlockHeight::from_raw(tip)
}

/// Seal through the production admission path. A post seals `Pending`;
/// the reservation kinds seal `Dispatched` (seal-before-send).
fn seal(block: &mut PendingPostBlock, record: Record) {
    let g = block.generation();
    let sent_at = ChainCount::from_raw(5_007);
    let admitted = match record {
        Record::Post(r) => block.seal_post(r, g),
        Record::Claim(r) => block.seal_claim(r, sent_at, g),
        Record::Drain(r) => block.seal_drain(r, sent_at, g),
        Record::Release(r) => block.seal_release(r, sent_at, g),
    };
    assert_eq!(admitted, SealAdmission::Admit);
}

enum Record {
    Post(PendingBondPost),
    Claim(PendingEmissionClaim),
    Drain(PendingDrain),
    Release(PendingRelease),
}

#[test]
fn a_sealed_record_reads_pending_then_dispatched_with_its_height() {
    let mut block = PendingPostBlock::empty();
    seal(&mut block, Record::Post(post(1, &[1])));
    assert_eq!(
        in_flight(&block, at(5_010), ScanEvidence::unscanned()),
        vec![InFlightRecord {
            kind: RecordKind::Post,
            state: InFlightState::Pending,
            sends: None,
            reserved: None,
        }]
    );

    assert!(block
        .mark_dispatched(&persona(1), ChainCount::from_raw(5_011))
        .is_some());
    assert!(block
        .mark_dispatched(&persona(1), ChainCount::from_raw(5_012))
        .is_some());
    let dispatched = in_flight(&block, at(5_020), ScanEvidence::unscanned())[0];
    assert_eq!(dispatched.state, InFlightState::Dispatched);
    assert_eq!(
        dispatched.sends,
        Some(Sends {
            first_at_height: at(5_010),
            attempts: 2,
        }),
        "the first send's count, as a tip height"
    );
}

/// The boundary is the driver's no-send rule on the ledger clock: at a
/// tip one below the end date the next block can still include it; at
/// the end date it cannot.
#[test]
fn a_record_reads_expired_from_a_tip_at_its_end_date() {
    let mut block = PendingPostBlock::empty();
    seal(&mut block, Record::Drain(drain(2, &[2])));
    let before = BlockHeight::from_raw(END.to_raw() - 1);
    assert_eq!(
        in_flight(&block, before, ScanEvidence::unscanned())[0].state,
        InFlightState::Dispatched
    );
    for tip in [END, at(END.to_raw() + 900)] {
        let expired = in_flight(&block, tip, ScanEvidence::unscanned())[0];
        assert_eq!(
            expired.state,
            InFlightState::Expired {
                funds_return_at: END,
                cause: None,
            },
            "tip {tip:?}"
        );
        assert_eq!(
            expired.sends.map(|s| s.first_at_height),
            Some(at(5_006)),
            "an expired record still says when it first went out"
        );
    }
}

/// WR-Q1's falsifier as amended 2026-10-16: a record with a recorded
/// verdict reads `Refused` with its reason and `funds_return_at` below
/// the end date, and `Expired` with the same reason from the end date
/// until the release writes the outcome.
#[test]
fn a_recorded_verdict_reads_refused_then_expired_with_its_reason() {
    let mut block = PendingPostBlock::empty();
    seal(&mut block, Record::Post(post(3, &[3])));
    assert!(block.record_terminal(
        RecordKind::Post,
        &persona(3),
        TerminalCause::JoinMarketUnsupported
    ));
    let cause = TerminalCause::JoinMarketUnsupported;
    let before = in_flight(&block, at(END.to_raw() - 1), ScanEvidence::unscanned())[0].state;
    assert_eq!(
        before,
        InFlightState::Refused {
            cause,
            funds_return_at: END,
        }
    );
    let after = in_flight(&block, END, ScanEvidence::unscanned())[0].state;
    assert_eq!(
        after,
        InFlightState::Expired {
            funds_return_at: END,
            cause: Some(cause),
        }
    );
    let (before, after) = (
        before.reason().expect("refused"),
        after.reason().expect("expired"),
    );
    assert!(
        before.starts_with(refusal(&cause).as_ref()) && after.starts_with(refusal(&cause).as_ref()),
        "the same reason on both sides: {before} / {after}"
    );
}

/// Every kind is reported, and the release moves a record from
/// `in_flight` to `outcomes` in one step: at a frontier equal to
/// `funds_return_at` it is still held; one block further it has ended.
#[test]
fn the_release_moves_each_kind_from_in_flight_to_outcomes() {
    let mut block = PendingPostBlock::empty();
    seal(&mut block, Record::Post(post(4, &[4])));
    seal(&mut block, Record::Claim(claim(5, &[])));
    seal(&mut block, Record::Drain(drain(6, &[6])));
    seal(
        &mut block,
        Record::Release(PendingRelease {
            persona: persona(7),
            tx_bytes: vec![7],
            funding_gindexes: gindexes(&[7]),
            state: PendingPostState::Pending,
            reference_height: REFERENCE,
            terminal: None,
        }),
    );

    let mut kinds: Vec<_> = in_flight(&block, END, ScanEvidence::unscanned())
        .iter()
        .map(|r| r.kind)
        .collect();
    kinds.sort();
    assert_eq!(
        kinds,
        vec![
            RecordKind::Post,
            RecordKind::Claim,
            RecordKind::Drain,
            RecordKind::Release
        ]
    );
    assert!(outcomes(&block).is_empty());

    let live: BTreeSet<_> = gindexes(&[4, 6, 7]).into_iter().collect();
    // A sealed frontier of `END` (exclusive) has scanned through `END - 1`.
    let scanned_through = BlockHeight::from_raw(END.to_raw() - 1);
    assert!(block
        .release_ended(scanned_through, &live, REFERENCE_MAX_AGE, END)
        .is_empty());
    assert_eq!(
        in_flight(&block, END, ScanEvidence::unscanned()).len(),
        4,
        "still held at the end date"
    );

    let ended = block.release_ended(END, &live, REFERENCE_MAX_AGE, at(5_900));
    assert_eq!(ended.released.len(), 4);
    assert!(in_flight(&block, at(5_900), ScanEvidence::unscanned()).is_empty());
    let mut reported = outcomes(&block);
    reported.sort_by_key(|o| o.kind);
    assert_eq!(
        reported,
        vec![
            ReportedOutcome {
                kind: RecordKind::Post,
                outcome: OutcomeKind::Expired,
                at_height: at(5_900),
                sent: false,
            },
            ReportedOutcome {
                kind: RecordKind::Claim,
                outcome: OutcomeKind::EndedUnconfirmed(None),
                at_height: at(5_900),
                sent: true,
            },
            ReportedOutcome {
                kind: RecordKind::Drain,
                outcome: OutcomeKind::Expired,
                at_height: at(5_900),
                sent: true,
            },
            ReportedOutcome {
                kind: RecordKind::Release,
                outcome: OutcomeKind::Expired,
                at_height: at(5_900),
                sent: true,
            },
        ]
    );
}

/// The acknowledgement as ruled 2026-10-17, through the facade and the
/// seal: every persona's outcome of the kind at or below the height
/// shown, durably, with no active persona needed; a second call clears
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_acknowledgement_clears_every_personas_outcome_through_the_height_shown() {
    use crate::engine::test_support::staker_engine;

    let (_tmp, engine) = staker_engine(3, 21).await;
    let wrap = *engine.state_wrap_key().as_bytes();
    let engine = Arc::new(RwLock::new(engine));
    assert_eq!(
        StakeFacade::acknowledge_staking_outcome(engine.clone(), RecordKind::Claim, END)
            .await
            .expect("no seal yet"),
        0,
        "nothing sealed: nothing to clear, nothing written"
    );

    // Two personas' ended claims and one ended drain, written by the
    // release itself at END, and a third claim ending after the height
    // the owner was shown.
    let mut block = PendingPostBlock::empty();
    for b in [0x71, 0x72] {
        seal(&mut block, Record::Claim(claim(b, &[])));
    }
    seal(&mut block, Record::Drain(drain(0x73, &[9])));
    let live: BTreeSet<_> = gindexes(&[9]).into_iter().collect();
    assert_eq!(
        block
            .release_ended(END, &live, REFERENCE_MAX_AGE, END)
            .released
            .len(),
        3
    );
    let mut late = claim(0x74, &[]);
    late.reference_height = at(5_050);
    seal(&mut block, Record::Claim(late));
    let after = at(END.to_raw() + 1);
    assert_eq!(
        block
            .release_ended(at(5_150), &live, REFERENCE_MAX_AGE, after)
            .released
            .len(),
        1
    );
    // Through the locked write path, the only writer of the seal.
    let gate = engine.read().await.pending_gate.clone();
    pending_post_store_for_engine(engine.clone(), gate)
        .mutate(|sealed| {
            *sealed = block;
            (true, ())
        })
        .await
        .expect("seal");

    let ack = |kind| StakeFacade::acknowledge_staking_outcome(engine.clone(), kind, END);
    assert_eq!(ack(RecordKind::Claim).await.expect("ack"), 2);
    assert_eq!(ack(RecordKind::Claim).await.expect("ack twice"), 0);
    assert_eq!(ack(RecordKind::Post).await.expect("no stake outcome"), 0);

    let reread = PendingPostBlock::from_postcard_bytes(
        &engine
            .read()
            .await
            .persistence()
            .open_pending_posts(&wrap)
            .expect("open")
            .expect("sealed"),
    )
    .expect("decode");
    let left: Vec<_> = reread
        .outcomes()
        .iter()
        .map(|o| (o.kind, o.persona.to_bytes()[0]))
        .collect();
    assert_eq!(
        left,
        vec![(RecordKind::Drain, 0x73), (RecordKind::Claim, 0x74)],
        "the drain, and the claim written after the height shown, stay"
    );
}

/// WR-Q6: an entry says what it still holds, the amounts of its
/// reserved inputs still in the live funding set. A partly spent
/// reservation holds what is left; a fully spent one and an empty one
/// hold zero. With no scan evidence, or a frontier still at zero, what
/// is held cannot be read, which is not zero.
#[test]
fn an_in_flight_record_reports_what_it_still_holds() {
    use shekyl_engine_state::pscan_cursor::PScanCursor;
    use shekyl_engine_state::pscan_state::PFundingOutputRecord;

    let funding = |g: u64, amount: u64| PFundingOutputRecord {
        p_slot: PSlot::from_raw(0),
        index_in_transaction: 0,
        gindex: GlobalOutputIndex::from_raw(g),
        output_key: [0; 32],
        commitment: [0; 32],
        ciphertext_x25519: [0; 32],
        ciphertext_ml_kem: Vec::new(),
        amount: AtomicUnits::from_raw(amount),
        height: BlockHeight::from_raw(2_000),
        epoch: shekyl_types::SettlementEpoch::from_raw(1),
        lineage: shekyl_engine_state::pscan_state::MintLineageOutput::ExternalTransfer,
        spendable_height: BlockHeight::from_raw(2_010),
    };
    // Live: 10 and 11 (the first stake's), 21 (one of the second's), and
    // 99, which no record reserves.
    let scan_at = |frontier: u64| {
        PScanState::new(
            PScanCursor::at(BlockHeight::from_raw(frontier), [0; 32]),
            Default::default(),
            Default::default(),
            Vec::new(),
            vec![
                funding(10, 300),
                funding(11, 50),
                funding(21, 7),
                funding(99, 1_000),
            ],
            Vec::new(),
            Default::default(),
        )
    };
    let held = |record: Record, pscan: Option<&PScanState>| {
        let mut block = PendingPostBlock::empty();
        seal(&mut block, record);
        let scan = FundingScan::from_seal(pscan);
        let reported = in_flight(&block, at(5_010), scan.evidence());
        assert_eq!(reported.len(), 1);
        reported[0].reserved
    };
    let scanned = scan_at(5_009);
    let units = |n: u64| Some(AtomicUnits::from_raw(n));

    assert_eq!(
        held(Record::Post(post(1, &[10, 11])), Some(&scanned)),
        units(350),
        "every reserved input is live"
    );
    assert_eq!(
        held(Record::Post(post(2, &[20, 21])), Some(&scanned)),
        units(7),
        "a partly spent reservation holds what is left"
    );
    assert_eq!(
        held(Record::Drain(drain(3, &[30])), Some(&scanned)),
        units(0),
        "a fully spent reservation holds nothing"
    );
    assert_eq!(
        held(Record::Claim(claim(4, &[])), Some(&scanned)),
        units(0),
        "an empty reservation holds nothing"
    );
    assert_eq!(
        held(Record::Post(post(5, &[10, 11])), None),
        None,
        "no scan: what is held cannot be read"
    );
    assert_eq!(
        held(Record::Post(post(6, &[10, 11])), Some(&scan_at(0))),
        None,
        "a frontier still at zero has shown nothing"
    );

    let mut block = PendingPostBlock::empty();
    seal(&mut block, Record::Post(post(7, &[10])));
    let scan = FundingScan::from_seal(Some(&scanned));
    let rendered = format!("{:?}", in_flight(&block, at(5_010), scan.evidence())[0]);
    assert!(
        rendered.contains("<redacted>") && !rendered.contains("300"),
        "the held amount never renders: {rendered}"
    );
}

/// A stake past its end date with every input spent and no match reads
/// `Held`, from the two seals alone; a matched stake is the tick's to
/// retire and is not held; a partly spent one is not held either.
#[test]
fn a_stake_with_every_input_spent_reads_held() {
    use shekyl_engine_state::pscan_cursor::PScanCursor;
    use shekyl_engine_state::pscan_state::{BondPostRecord, PFundingOutputRecord};
    const JOIN: u8 = shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET;

    let mut block = PendingPostBlock::empty();
    seal(&mut block, Record::Post(post(0x81, &[40])));
    seal(&mut block, Record::Post(post(0x82, &[41])));
    seal(&mut block, Record::Post(post(0x83, &[42, 43])));
    let funding = |g: u64| PFundingOutputRecord {
        p_slot: PSlot::from_raw(0),
        index_in_transaction: 0,
        gindex: GlobalOutputIndex::from_raw(g),
        output_key: [0; 32],
        commitment: [0; 32],
        ciphertext_x25519: [0; 32],
        ciphertext_ml_kem: Vec::new(),
        amount: shekyl_units::AtomicUnits::from_raw(1),
        height: BlockHeight::from_raw(2_000),
        epoch: shekyl_types::SettlementEpoch::from_raw(1),
        lineage: shekyl_engine_state::pscan_state::MintLineageOutput::ExternalTransfer,
        spendable_height: BlockHeight::from_raw(2_010),
    };
    let matched = BondPostRecord {
        height: BlockHeight::from_raw(5_090),
        p_canonical_id: persona(0x82),
        post_kind: JOIN,
    };
    let state = |frontier: u64| {
        PScanState::new(
            PScanCursor::at(BlockHeight::from_raw(frontier), [0; 32]),
            Default::default(),
            Default::default(),
            vec![matched.clone()],
            vec![funding(43)],
            Vec::new(),
            Default::default(),
        )
    };

    let live_funding: BTreeSet<_> = gindexes(&[43]).into_iter().collect();
    assert!(
        block
            .held_spent_posts(
                BlockHeight::from_raw(END.to_raw() - 1),
                &live_funding,
                REFERENCE_MAX_AGE,
            )
            .next()
            .is_none(),
        "the release still waits until the frontier covers the end date"
    );
    assert_eq!(
        block
            .held_spent_posts(END, &live_funding, REFERENCE_MAX_AGE)
            .map(|post| post.persona)
            .collect::<Vec<_>>(),
        vec![persona(0x81), persona(0x82)],
        "the release keeps every fully spent stake; a sealed match is the tick's to retire"
    );

    let behind = state(END.to_raw());
    assert!(
        held_spent_stakes(&block, Some(&behind), at(END.to_raw() - 1)).is_empty(),
        "the ledger has not reached the end date"
    );
    let held = held_spent_stakes(&block, Some(&behind), END);
    assert_eq!(
        held,
        [persona(0x81)].into_iter().collect(),
        "the funding set already shows the spend, so the read does not wait for the frontier"
    );
    assert_eq!(
        held_spent_stakes(&block, Some(&state(END.to_raw() + 1)), END),
        held,
        "once the frontier catches up the same stake is held"
    );
    assert!(
        held_spent_stakes(&block, None, END).is_empty(),
        "no scan, nothing held"
    );
    assert!(
        held_spent_stakes(&block, Some(&state(0)), END).is_empty(),
        "a frontier still at zero has not shown a spend"
    );

    let reported = in_flight(
        &block,
        END,
        FundingScan::from_seal(Some(&behind)).evidence(),
    );
    let states: Vec<_> = reported.iter().map(|record| record.state).collect();
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == InFlightState::Held)
            .count(),
        1
    );
    assert!(
        states.contains(&InFlightState::Pending),
        "a matched stake is the tick's to retire and does not read expired: {states:?}"
    );
    assert!(
        states.contains(&InFlightState::Expired {
            funds_return_at: END,
            cause: None,
        }),
        "a partly spent stake still reads expired until the release: {states:?}"
    );
    let reason = InFlightState::Held
        .reason()
        .expect("a held stake has a reason");
    assert!(reason.contains("not lost"), "{reason}");

    let mut settled = PendingPostBlock::empty();
    seal(&mut settled, Record::Drain(drain(0x91, &[9])));
    let live = BTreeSet::new();
    let confirmed = BTreeSet::new();
    assert_eq!(
        in_flight(&settled, END, ScanEvidence::scanned(&live, &confirmed))[0].state,
        InFlightState::Dispatched,
        "a fully spent drain is settlement's, and does not promise a return"
    );
}

const CAUSES: [TerminalCause; 5] = [
    TerminalCause::DoubleSpend,
    TerminalCause::FeeTooLow,
    TerminalCause::Malformed,
    TerminalCause::Unrecognized,
    TerminalCause::JoinMarketUnsupported,
];

/// Every reason is a user sentence (rule 81): distinct per cause, never
/// an enum name, and the linkage sentence appears exactly on an ending
/// that returned the funds of a record that was sent (WR-Q5).
#[test]
fn reasons_are_user_sentences_and_linkage_follows_the_send() {
    let mut seen = BTreeSet::new();
    for cause in CAUSES {
        let held = InFlightState::Refused {
            cause,
            funds_return_at: END,
        }
        .reason()
        .expect("a refused record has a reason");
        assert!(seen.insert(refusal(&cause)), "{cause:?} shares a sentence");
        assert!(held.contains("Nothing more will be sent"), "{held}");
        for name in ["Refused", "TerminalCause", &format!("{cause:?}")] {
            assert!(!held.contains(name), "{name} leaked into: {held}");
        }
    }
    for state in [
        InFlightState::Pending,
        InFlightState::Dispatched,
        InFlightState::Expired {
            funds_return_at: END,
            cause: None,
        },
    ] {
        assert_eq!(state.reason(), None);
    }

    let ended = |kind, outcome, sent| ReportedOutcome {
        kind,
        outcome,
        at_height: END,
        sent,
    };
    for sent in [false, true] {
        for (kind, outcome, linkable) in [
            (
                RecordKind::Post,
                OutcomeKind::Rejected(TerminalCause::JoinMarketUnsupported),
                true,
            ),
            (RecordKind::Post, OutcomeKind::Expired, true),
            (
                RecordKind::Claim,
                OutcomeKind::EndedUnconfirmed(None),
                false,
            ),
            (
                RecordKind::Claim,
                OutcomeKind::EndedUnconfirmed(Some(TerminalCause::FeeTooLow)),
                false,
            ),
            (RecordKind::Release, OutcomeKind::SpentElsewhere, true),
        ] {
            let o = ended(kind, outcome, sent);
            assert_eq!(
                o.reason().contains(LINKAGE_SENTENCE),
                linkable && sent,
                "{outcome:?} sent={sent}: {}",
                o.reason()
            );
            assert_eq!(
                o.returned_funds(),
                !matches!(outcome, OutcomeKind::EndedUnconfirmed(_))
            );
        }
    }
    assert!(ended(RecordKind::Post, OutcomeKind::Expired, false)
        .reason()
        .starts_with("The stake was not accepted in time"));
    // A refused zero-fee claim held no funds: it keeps the node's
    // sentence, never says its funds came back, and carries no linkage.
    let refused_claim = ended(
        RecordKind::Claim,
        OutcomeKind::EndedUnconfirmed(Some(TerminalCause::FeeTooLow)),
        true,
    );
    let reason = refused_claim.reason();
    assert!(
        reason.starts_with(refusal(&TerminalCause::FeeTooLow).as_ref()),
        "{reason}"
    );
    assert!(reason.contains("could not be confirmed"), "{reason}");
    assert!(!reason.contains("spendable again"), "{reason}");
    assert!(!refused_claim.returned_funds());
}

/// The falsifier WR-Q1 names: a dispatched record with reference height
/// `r` reads `expired` with `funds_return_at == r + 100` after the seal
/// is written and read back, as a restart reads it.
#[test]
fn an_expired_record_reads_the_same_after_a_reload() {
    let mut block = PendingPostBlock::empty();
    seal(&mut block, Record::Post(post(8, &[8])));
    assert!(block
        .mark_dispatched(&persona(8), ChainCount::from_raw(5_011))
        .is_some());
    let reloaded =
        PendingPostBlock::from_postcard_bytes(&block.to_postcard_bytes().expect("encode"))
            .expect("decode");
    assert_eq!(
        in_flight(&reloaded, at(5_101), ScanEvidence::unscanned())[0].state,
        InFlightState::Expired {
            funds_return_at: BlockHeight::from_raw(REFERENCE.to_raw() + 100),
            cause: None,
        }
    );
}
