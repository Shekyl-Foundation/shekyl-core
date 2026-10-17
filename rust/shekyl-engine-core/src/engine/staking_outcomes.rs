// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What `staking_info` reports about staking work in flight and how it
//! ended (`WALLET_RPC_STAKING_OUTCOMES.md` WR-Q1, WR-Q2, WR-Q5).
//!
//! A pure projection over the sealed [`PendingPostBlock`] and the wallet
//! ledger's synced tip. Every state comes from sealed records, never from the
//! dispatcher's in-memory sets, so a restart reads the same answer.
//!
//! Nothing here names a persona, a slot, a funding output or the bond-post
//! delay (WR-Q5): the report says what kind of work it was and where it
//! stands, and a wallet acts on the active persona.

use std::sync::Arc;

use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::{
    end_date, OutcomeKind, RecordKind, StakingOutcome, TerminalCause,
};
use shekyl_engine_state::{PendingPostBlock, PendingPostState};
use shekyl_types::{BlockHeight, ChainCount};
use tokio::sync::RwLock;

use super::local_ledger::LocalLedger;
use super::pscan::end_date::REFERENCE_MAX_AGE;
use super::pscan::start::pending_post_store_for_engine;
use super::signer::EngineSignerKind;
use super::stake_facade::StakeFacade;
use super::traits::{DaemonEngine, EconomicsEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// One live pending record, as `staking_info`'s `in_flight` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InFlightRecord {
    /// Which staking action the record carries.
    pub kind: RecordKind,
    /// Where it stands.
    pub state: InFlightState,
    /// Its sends so far; `None` when it was never handed to a daemon.
    pub sends: Option<Sends>,
}

/// A record's sends: a fact independent of where it stands, so a rejected or
/// expired record still says when it first went out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sends {
    /// The tip height the first send was judged against.
    pub first_at_height: BlockHeight,
    /// Total sends, the first included.
    pub attempts: u32,
}

/// Where a live pending record stands (WR-Q1, with BD-Q3 Rule 2's
/// `Rejected`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InFlightState {
    /// Sealed, not yet sent.
    Pending,
    /// Sent at least once and still able to land.
    Dispatched,
    /// A daemon refused it outright. Nothing more is sent; the record and its
    /// funds are held until the end date, because only the chain can say
    /// whether the bytes landed (BD-Q3 Rule 2).
    Rejected {
        /// What the daemon said.
        cause: TerminalCause,
        /// The end date; the funds return once the staking scan is past it.
        funds_return_at: BlockHeight,
    },
    /// The end date has passed, so the transaction can never be mined. The
    /// funds return once the staking scan is past `funds_return_at`.
    Expired {
        /// The end date.
        funds_return_at: BlockHeight,
    },
}

impl InFlightState {
    /// The user sentence for a rejected record (rule 81); `None` for every
    /// other state, which needs none.
    #[must_use]
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Rejected { cause, .. } => Some(format!(
                "{} Nothing more will be sent. Its funds stay set aside until \
                 its transaction can no longer be mined.",
                refusal(*cause)
            )),
            Self::Pending | Self::Dispatched | Self::Expired { .. } => None,
        }
    }
}

/// A durable outcome as reported: the sealed [`StakingOutcome`] without its
/// persona.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportedOutcome {
    /// Which staking action ended.
    pub kind: RecordKind,
    /// How it ended.
    pub outcome: OutcomeKind,
    /// The tip height when the ending was written.
    pub at_height: BlockHeight,
    /// Whether the record was ever sent, so anyone who saw it can link a
    /// later spend of its funds to it.
    pub sent: bool,
}

impl From<&StakingOutcome> for ReportedOutcome {
    fn from(o: &StakingOutcome) -> Self {
        Self {
            kind: o.kind,
            outcome: o.outcome,
            at_height: o.at_height,
            sent: o.sent,
        }
    }
}

/// The sentence a sent record's ending carries, because its inputs' key
/// images were published to every node that saw it (WR-Q5).
pub const LINKAGE_SENTENCE: &str =
    "Anyone who saw this attempt can link a later spend of these funds to it.";

impl ReportedOutcome {
    /// The user sentence for this ending (WR-Q2, rule 81), with the linkage
    /// sentence when the record was sent and its funds came back.
    #[must_use]
    pub fn reason(&self) -> String {
        let (sentence, linkable) = match self.outcome {
            OutcomeKind::Rejected(cause) => (
                format!("{} Its funds are spendable again.", refusal(cause)),
                true,
            ),
            OutcomeKind::Expired => (
                format!(
                    "The {} was not accepted in time and has been withdrawn. \
                     Its funds are spendable again.",
                    noun(self.kind)
                ),
                true,
            ),
            OutcomeKind::EndedUnconfirmed => (
                "This reward claim could not be confirmed. If it was accepted, \
                 the reward it earned will appear in your balance."
                    .to_owned(),
                false,
            ),
            OutcomeKind::SpentElsewhere => (
                "Some of the funds set aside for this were spent by another \
                 transaction. The rest are spendable again. This should not \
                 happen; check the wallet's logs and your keys."
                    .to_owned(),
                true,
            ),
        };
        if linkable && self.sent {
            format!("{sentence} {LINKAGE_SENTENCE}")
        } else {
            sentence
        }
    }

    /// Whether the ending returned funds: every ending but the zero-fee
    /// claim's, which held none.
    #[must_use]
    pub fn returned_funds(&self) -> bool {
        !matches!(self.outcome, OutcomeKind::EndedUnconfirmed)
    }
}

/// What the user calls each kind of record.
fn noun(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Post => "stake",
        RecordKind::Claim => "reward claim",
        RecordKind::Drain => "return of staking funds",
        RecordKind::Release => "release of the stake",
    }
}

/// What a daemon's refusal means, in the user's words. Exhaustive with no
/// wildcard: a new cause does not compile until it has a sentence.
fn refusal(cause: TerminalCause) -> &'static str {
    match cause {
        TerminalCause::JoinMarketUnsupported => {
            "Staking is not available on this node: it cannot accept the \
             transaction that joins the archival market yet. Stake again once \
             the node is updated."
        }
        TerminalCause::DoubleSpend => "The node reports that funds this used were already spent.",
        TerminalCause::FeeTooLow => "The node refused its fee as too low.",
        TerminalCause::Malformed => {
            "The node refused the transaction as invalid. This is a wallet \
             fault; check for a wallet update."
        }
        TerminalCause::Unrecognized => {
            "The node refused it for a reason this wallet does not recognise."
        }
    }
}

/// The state of one record against the ledger clock.
///
/// Precedence: a recorded verdict reads `Rejected` whatever the clock says,
/// so its reason shows at once; otherwise a tip at or past the end date reads
/// `Expired`, because the next block cannot include the transaction (the
/// driver's no-send rule on the same clock); otherwise the sealed state.
fn record(
    kind: RecordKind,
    state: PendingPostState,
    reference_height: BlockHeight,
    terminal: Option<TerminalCause>,
    ledger_tip: BlockHeight,
) -> InFlightRecord {
    let sends = match state {
        PendingPostState::Pending => None,
        PendingPostState::Dispatched { at, attempts } => Some(Sends {
            first_at_height: tip_of(at),
            attempts,
        }),
    };
    let funds_return_at = end_date(reference_height, REFERENCE_MAX_AGE);
    let state = if let Some(cause) = terminal {
        InFlightState::Rejected {
            cause,
            funds_return_at,
        }
    } else if ledger_tip >= funds_return_at {
        InFlightState::Expired { funds_return_at }
    } else if sends.is_some() {
        InFlightState::Dispatched
    } else {
        InFlightState::Pending
    };
    InFlightRecord { kind, state, sends }
}

/// `at` is the claimed chain count the first send was judged against; the
/// wire reports heights (`HEIGHT_SEMANTICS.md`), so it becomes the tip,
/// `count − 1`. No send is judged against an empty chain (a reference block
/// is at least six below the tip), so the empty count's `0` is unreachable.
fn tip_of(at: ChainCount) -> BlockHeight {
    at.tip().unwrap_or(BlockHeight::ZERO)
}

/// Every live record in `block`, judged at `ledger_tip` (the wallet ledger's
/// synced height, inclusive).
pub(crate) fn in_flight(block: &PendingPostBlock, ledger_tip: BlockHeight) -> Vec<InFlightRecord> {
    let entry = |kind, state, reference_height, terminal| {
        record(kind, state, reference_height, terminal, ledger_tip)
    };
    let posts = block
        .posts()
        .iter()
        .map(|r| entry(RecordKind::Post, r.state, r.reference_height, r.terminal));
    let claims = block
        .claims()
        .iter()
        .map(|r| entry(RecordKind::Claim, r.state, r.reference_height, r.terminal));
    let drains = block
        .drains()
        .iter()
        .map(|r| entry(RecordKind::Drain, r.state, r.reference_height, r.terminal));
    let releases = block
        .releases()
        .iter()
        .map(|r| entry(RecordKind::Release, r.state, r.reference_height, r.terminal));
    posts.chain(claims).chain(drains).chain(releases).collect()
}

/// Every durable outcome in `block`, persona dropped.
pub(crate) fn outcomes(block: &PendingPostBlock) -> Vec<ReportedOutcome> {
    block.outcomes().iter().map(ReportedOutcome::from).collect()
}

/// Why an acknowledgement could not be read or written. An outcome that is
/// not there is not an error: [`StakeStakeFacade::acknowledge_staking_outcome`]
/// answers `false`.
#[derive(Debug, thiserror::Error)]
pub enum AcknowledgeOutcomeError {
    /// The stake engine could not answer which persona is active, or the
    /// pending seal could not be read or written. The detail is for the log;
    /// it can name filesystem paths.
    #[error("staking state failed ({context}): {detail}")]
    State {
        /// Which step failed.
        context: &'static str,
        /// The underlying error, rendered.
        detail: String,
    },
}

#[allow(private_bounds, clippy::type_complexity)]
impl<S, D, E, R, P> StakeFacade<'_, S, D, LocalLedger, E, R, P, WalletFile>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, LocalLedger, E, R, P, WalletFile>: Send + Sync,
{
    /// Clear the active persona's last outcome of `kind` (WR-Q2), so
    /// `staking_info` stops reporting it. Returns whether there was one.
    ///
    /// Acts on the active persona, as every staking action does (WR-Q5): the
    /// caller names no slot or record. `false` covers every case where the
    /// active persona has no such outcome, including a wallet that is not a
    /// staker or has no active persona, and an outcome that belongs to a
    /// persona that is not active; only that persona's next admitted seal of
    /// the kind clears such an outcome. Acknowledging twice is harmless.
    ///
    /// # Errors
    ///
    /// [`AcknowledgeOutcomeError::State`] when the active persona or the
    /// pending seal cannot be read, or the seal cannot be rewritten.
    pub async fn acknowledge_staking_outcome(
        engine: Arc<RwLock<Engine<S, D, LocalLedger, E, R, P, WalletFile>>>,
        kind: RecordKind,
    ) -> Result<bool, AcknowledgeOutcomeError> {
        let (stake, gate) = {
            let g = engine.read().await;
            (g.stake_handle(), g.pending_gate.clone())
        };
        let Some(stake) = stake else {
            return Ok(false);
        };
        let identity =
            stake
                .active_persona()
                .await
                .map_err(|e| AcknowledgeOutcomeError::State {
                    context: "active persona",
                    detail: e.to_string(),
                })?;
        let Some(identity) = identity else {
            return Ok(false);
        };
        let bond_id =
            identity
                .bond_id
                .to_canonical_bytes()
                .map_err(|e| AcknowledgeOutcomeError::State {
                    context: "persona identity",
                    detail: e.to_string(),
                })?;
        let persona = p_canonical_id_from_hybrid_pubkey(&bond_id);
        pending_post_store_for_engine(engine, gate)
            .mutate(|block| {
                let cleared = block.acknowledge_outcome(kind, &persona);
                (cleared, cleared)
            })
            .await
            .map_err(|e| AcknowledgeOutcomeError::State {
                context: "pending seal",
                detail: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use shekyl_engine_state::pending_post_block::SealAdmission;
    use shekyl_engine_state::{
        PendingBondPost, PendingDrain, PendingEmissionClaim, PendingRelease,
    };
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
            in_flight(&block, at(5_010)),
            vec![InFlightRecord {
                kind: RecordKind::Post,
                state: InFlightState::Pending,
                sends: None,
            }]
        );

        assert!(block
            .mark_dispatched(&persona(1), ChainCount::from_raw(5_011))
            .is_some());
        assert!(block
            .mark_dispatched(&persona(1), ChainCount::from_raw(5_012))
            .is_some());
        let dispatched = in_flight(&block, at(5_020))[0];
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
            in_flight(&block, before)[0].state,
            InFlightState::Dispatched
        );
        for tip in [END, at(END.to_raw() + 900)] {
            let expired = in_flight(&block, tip)[0];
            assert_eq!(
                expired.state,
                InFlightState::Expired {
                    funds_return_at: END,
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

    /// A recorded verdict shows its reason at once and keeps reading
    /// `Rejected` past the end date, until the release writes the outcome.
    #[test]
    fn a_recorded_verdict_reads_rejected_before_and_after_the_end_date() {
        let mut block = PendingPostBlock::empty();
        seal(&mut block, Record::Post(post(3, &[3])));
        assert!(block.record_terminal(
            RecordKind::Post,
            &persona(3),
            TerminalCause::JoinMarketUnsupported
        ));
        let rejected = InFlightState::Rejected {
            cause: TerminalCause::JoinMarketUnsupported,
            funds_return_at: END,
        };
        assert_eq!(in_flight(&block, at(5_010))[0].state, rejected);
        assert_eq!(in_flight(&block, END)[0].state, rejected);
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

        let mut kinds: Vec<_> = in_flight(&block, END).iter().map(|r| r.kind).collect();
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
            in_flight(&block, END).len(),
            4,
            "still held at the end date"
        );

        let ended = block.release_ended(END, &live, REFERENCE_MAX_AGE, at(5_900));
        assert_eq!(ended.released.len(), 4);
        assert!(in_flight(&block, at(5_900)).is_empty());
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
                    outcome: OutcomeKind::EndedUnconfirmed,
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

    /// The acknowledgement clears only the active persona's outcome of the
    /// named kind, durably, and a second one is a harmless `false`. A wallet
    /// with no active persona clears nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_acknowledgement_clears_only_the_active_personas_outcome_of_its_kind() {
        use crate::engine::test_support::{activate_persona, staker_engine};

        let (_tmp, engine) = staker_engine(3, 21);
        let wrap = *engine.state_wrap_key().as_bytes();
        let stake = engine.stake_handle().expect("staker");
        let engine = Arc::new(RwLock::new(engine));
        assert!(
            !StakeFacade::acknowledge_staking_outcome(engine.clone(), RecordKind::Claim)
                .await
                .expect("idle staker"),
            "no active persona: nothing to clear"
        );

        activate_persona(&*engine.read().await, 3).await;
        let identity = stake.active_persona().await.expect("ask").expect("active");
        let active = p_canonical_id_from_hybrid_pubkey(
            &identity.bond_id.to_canonical_bytes().expect("bond id"),
        );
        let other = persona(0x77);

        // Two ended claims (the active persona's and another's) and the
        // active persona's ended drain, written by the release itself.
        let mut block = PendingPostBlock::empty();
        for who in [active, other] {
            let mut c = claim(0, &[]);
            c.persona = who;
            seal(&mut block, Record::Claim(c));
        }
        let mut d = drain(0, &[9]);
        d.persona = active;
        seal(&mut block, Record::Drain(d));
        let live: BTreeSet<_> = gindexes(&[9]).into_iter().collect();
        assert_eq!(
            block
                .release_ended(END, &live, REFERENCE_MAX_AGE, END)
                .released
                .len(),
            3
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

        let ack = |kind| StakeFacade::acknowledge_staking_outcome(engine.clone(), kind);
        assert!(ack(RecordKind::Claim).await.expect("ack"));
        assert!(!ack(RecordKind::Claim).await.expect("ack twice"));
        assert!(!ack(RecordKind::Post).await.expect("no stake outcome"));

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
            .map(|o| (o.kind, o.persona == active))
            .collect();
        assert_eq!(
            left,
            vec![(RecordKind::Claim, false), (RecordKind::Drain, true)],
            "the other persona's claim and the active persona's drain stay"
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
            let held = InFlightState::Rejected {
                cause,
                funds_return_at: END,
            }
            .reason()
            .expect("a rejected record has a reason");
            assert!(seen.insert(refusal(cause)), "{cause:?} shares a sentence");
            assert!(held.contains("Nothing more will be sent"), "{held}");
            for name in ["Rejected", "TerminalCause", &format!("{cause:?}")] {
                assert!(!held.contains(name), "{name} leaked into: {held}");
            }
        }
        for state in [
            InFlightState::Pending,
            InFlightState::Dispatched,
            InFlightState::Expired {
                funds_return_at: END,
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
                (RecordKind::Claim, OutcomeKind::EndedUnconfirmed, false),
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
                    !matches!(outcome, OutcomeKind::EndedUnconfirmed)
                );
            }
        }
        assert!(ended(RecordKind::Post, OutcomeKind::Expired, false)
            .reason()
            .starts_with("The stake was not accepted in time"));
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
            in_flight(&reloaded, at(5_101))[0].state,
            InFlightState::Expired {
                funds_return_at: BlockHeight::from_raw(REFERENCE.to_raw() + 100),
            }
        );
    }
}
