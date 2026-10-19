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

use std::collections::BTreeSet;
use std::sync::Arc;

use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::{
    end_date, end_date_disposition, EndDateDisposition, OutcomeKind, RecordKind, SealedRecord,
    StakingOutcome, TerminalCause,
};
use shekyl_engine_state::pscan_state::PScanState;
use shekyl_engine_state::{PendingPostBlock, PendingPostState};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, GlobalOutputIndex, PCanonicalId};
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

/// Where a live pending record stands (WR-Q1 as amended 2026-10-16, with
/// the `held` stake of 2026-10-17).
///
/// Precedence follows whether the transaction can still land: a record that
/// saw a terminal verdict is `Refused` until its end date and `Expired`
/// after it, still carrying the cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InFlightState {
    /// Sealed, not yet sent.
    Pending,
    /// Sent at least once and still able to land.
    Dispatched,
    /// A daemon refused it outright and its end date has not passed. Not
    /// final: nothing more is sent, but the record and its funds are held
    /// until the end date, because only the chain can say whether the bytes
    /// land (BD-Q3 Rule 2).
    Refused {
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
        /// What a daemon said, if it refused the record before the end date.
        cause: Option<TerminalCause>,
    },
    /// A stake past its end date whose every reserved input is spent, with
    /// no confirmation seen. It is either the stake itself, landed and not
    /// matched, or a spend elsewhere; the record is held so a stake that did
    /// land keeps its slot, and the integrity alarm is raised. Nothing is
    /// returned, because nothing reserved is left.
    Held,
}

impl InFlightState {
    /// The user sentence for a refused or held record, and for an expired
    /// one a daemon refused (rule 81); `None` for every other state, which
    /// needs none.
    #[must_use]
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Refused { cause, .. } => Some(format!(
                "{} Nothing more will be sent. Its funds stay set aside until \
                 its transaction can no longer be mined.",
                refusal(*cause)
            )),
            Self::Expired {
                cause: Some(cause), ..
            } => Some(refusal(*cause).to_owned()),
            Self::Held => Some(
                "Every input this stake set aside has been spent, but the wallet has not \
                 seen the stake confirm. It is kept rather than withdrawn, so a stake that \
                 did land is not lost. This should not happen; check the wallet's logs."
                    .to_owned(),
            ),
            Self::Pending | Self::Dispatched | Self::Expired { cause: None, .. } => None,
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
            OutcomeKind::EndedUnconfirmed(cause) => {
                let unconfirmed = "This reward claim could not be confirmed. If it was \
                                   accepted, the reward it earned will appear in your balance.";
                (
                    match cause {
                        Some(cause) => format!("{} {unconfirmed}", refusal(cause)),
                        None => unconfirmed.to_owned(),
                    },
                    false,
                )
            }
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
        !matches!(self.outcome, OutcomeKind::EndedUnconfirmed(_))
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

/// What the sealed scan contributes to a read. `live` is `Some` only when a
/// scan exists and its frontier has moved off zero: absence from that set is
/// a spend. `None` means the scan has not produced evidence, so absence is
/// not a spend and a fully spent stake is not yet held.
#[derive(Clone, Copy)]
pub(crate) struct ScanEvidence<'a> {
    live: Option<&'a BTreeSet<GlobalOutputIndex>>,
    confirmed_posts: &'a BTreeSet<PCanonicalId>,
}

#[cfg(test)]
impl ScanEvidence<'static> {
    /// No scan evidence. A record past its end date reads expired.
    fn unscanned() -> Self {
        Self {
            live: None,
            confirmed_posts: &EMPTY_CONFIRMED,
        }
    }
}

#[cfg(test)]
impl<'a> ScanEvidence<'a> {
    /// Evidence the caller already knows a moved frontier produced.
    fn scanned(
        live: &'a BTreeSet<GlobalOutputIndex>,
        confirmed_posts: &'a BTreeSet<PCanonicalId>,
    ) -> Self {
        Self {
            live: Some(live),
            confirmed_posts,
        }
    }
}

#[cfg(test)]
static EMPTY_CONFIRMED: BTreeSet<PCanonicalId> = BTreeSet::new();

/// The funding set and JoinMarket matches of one sealed scan, or the
/// absence of evidence when there is no scan or the frontier is still zero.
pub(crate) struct FundingScan {
    live: Option<BTreeSet<GlobalOutputIndex>>,
    confirmed_posts: BTreeSet<PCanonicalId>,
}

impl FundingScan {
    /// `None` for `live` when `pscan` is absent or its frontier cannot step
    /// back one block. An empty funding set is then not read as "every input
    /// is spent".
    pub(crate) fn from_seal(pscan: Option<&PScanState>) -> Self {
        let Some(pscan) = pscan else {
            return Self {
                live: None,
                confirmed_posts: BTreeSet::new(),
            };
        };
        if pscan
            .synced_height()
            .checked_sub_count(BlockCount::ONE)
            .is_none()
        {
            return Self {
                live: None,
                confirmed_posts: BTreeSet::new(),
            };
        }
        let live = pscan
            .funding_outputs()
            .iter()
            .map(|output| output.gindex)
            .collect();
        let confirmed_posts = pscan
            .bond_post_matches()
            .iter()
            .filter(|matched| shekyl_wire::transaction::is_join_market_post_kind(matched.post_kind))
            .map(|matched| matched.p_canonical_id)
            .collect();
        Self {
            live: Some(live),
            confirmed_posts,
        }
    }

    pub(crate) fn evidence(&self) -> ScanEvidence<'_> {
        ScanEvidence {
            live: self.live.as_ref(),
            confirmed_posts: &self.confirmed_posts,
        }
    }
}

/// Where one sealed record stands at `ledger_tip`.
///
/// Past the end date, [`end_date_disposition`] decides. A hold the scan has
/// not matched reads [`InFlightState::Held`]. A release reads
/// [`InFlightState::Expired`]: the funds come back once the frontier covers
/// the end date. A settlement, and a hold the scan has already matched, do
/// not promise a return; they fall through to the sealed state. With no scan
/// evidence, past the end date reads expired, because absence has not been
/// shown to be a spend. Before the end date a recorded verdict reads
/// [`InFlightState::Refused`].
fn project(
    record: SealedRecord<'_>,
    ledger_tip: BlockHeight,
    evidence: ScanEvidence<'_>,
) -> InFlightState {
    let funds_return_at = end_date(record.reference_height, REFERENCE_MAX_AGE);
    if ledger_tip >= funds_return_at {
        match evidence.live {
            Some(live) => {
                match end_date_disposition(record.kind, record.reserved, record.terminal, live) {
                    EndDateDisposition::Hold
                        if record.kind == RecordKind::Post
                            && !evidence.confirmed_posts.contains(record.persona) =>
                    {
                        return InFlightState::Held;
                    }
                    EndDateDisposition::Release(_) => {
                        return InFlightState::Expired {
                            funds_return_at,
                            cause: record.terminal,
                        };
                    }
                    EndDateDisposition::Hold | EndDateDisposition::Settled => {}
                }
            }
            None => {
                return InFlightState::Expired {
                    funds_return_at,
                    cause: record.terminal,
                };
            }
        }
    }
    if let Some(cause) = record.terminal {
        return InFlightState::Refused {
            cause,
            funds_return_at,
        };
    }
    if matches!(record.state, PendingPostState::Dispatched { .. }) {
        InFlightState::Dispatched
    } else {
        InFlightState::Pending
    }
}

/// `at` is the claimed chain count the first send was judged against; the
/// wire reports heights (`HEIGHT_SEMANTICS.md`), so it becomes the tip,
/// `count − 1`. No send is judged against an empty chain (a reference block
/// is at least six below the tip), so the empty count's `0` is unreachable.
fn tip_of(at: ChainCount) -> BlockHeight {
    at.tip().unwrap_or(BlockHeight::ZERO)
}

/// Every live record in `block`, judged at `ledger_tip` (the wallet ledger's
/// synced height, inclusive) against `evidence`.
pub(crate) fn in_flight(
    block: &PendingPostBlock,
    ledger_tip: BlockHeight,
    evidence: ScanEvidence<'_>,
) -> Vec<InFlightRecord> {
    block
        .sealed_records()
        .map(|record| InFlightRecord {
            kind: record.kind,
            state: project(record, ledger_tip, evidence),
            sends: match record.state {
                PendingPostState::Pending => None,
                PendingPostState::Dispatched { at, attempts } => Some(Sends {
                    first_at_height: tip_of(at),
                    attempts,
                }),
            },
        })
        .collect()
}

/// Stakes [`project`] reads as [`InFlightState::Held`] at `ledger_tip`.
///
/// The same classification and the same scan evidence as [`in_flight`], on
/// the ledger clock. The release's [`PendingPostBlock::held_spent_posts`]
/// still waits until the frontier covers the end date. No scan, or a
/// frontier at zero, holds nothing: an empty funding set is not a total spend.
pub(crate) fn held_spent_stakes(
    pending: &PendingPostBlock,
    pscan: Option<&PScanState>,
    ledger_tip: BlockHeight,
) -> BTreeSet<PCanonicalId> {
    let scan = FundingScan::from_seal(pscan);
    let evidence = scan.evidence();
    pending
        .sealed_records()
        .filter(|record| {
            record.kind == RecordKind::Post
                && project(*record, ledger_tip, evidence) == InFlightState::Held
        })
        .map(|record| *record.persona)
        .collect()
}

/// Every durable outcome in `block`, persona dropped.
pub(crate) fn outcomes(block: &PendingPostBlock) -> Vec<ReportedOutcome> {
    block.outcomes().iter().map(ReportedOutcome::from).collect()
}

/// Why an acknowledgement could not be read or written. An outcome that is
/// not there is not an error: [`StakeFacade::acknowledge_staking_outcome`]
/// answers `0`.
#[derive(Debug, thiserror::Error)]
pub enum AcknowledgeOutcomeError {
    /// The pending seal could not be read or written. The detail is for the
    /// log; it can name filesystem paths.
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
    /// Clear every outcome of `kind`, for every persona, written at or
    /// below `through_height` (WR-Q2, ruled 2026-10-17), so `staking_info`
    /// stops reporting it. Returns how many were cleared.
    ///
    /// `through_height` is the newest ending the owner was shown, so one
    /// written after it is never cleared unseen. The caller names no persona,
    /// slot or record (WR-Q5), so an ending of a persona that is no longer
    /// active, such as an exited one, can be cleared too. Acknowledging twice
    /// clears nothing the second time; a wallet with no pending seal clears
    /// nothing and writes nothing.
    ///
    /// # Errors
    ///
    /// [`AcknowledgeOutcomeError::State`] when the pending seal cannot be
    /// read or rewritten.
    pub async fn acknowledge_staking_outcome(
        engine: Arc<RwLock<Engine<S, D, LocalLedger, E, R, P, WalletFile>>>,
        kind: RecordKind,
        through_height: BlockHeight,
    ) -> Result<usize, AcknowledgeOutcomeError> {
        let gate = engine.read().await.pending_gate.clone();
        pending_post_store_for_engine(engine, gate)
            .mutate(|block| {
                let cleared = block.acknowledge_outcomes(kind, through_height);
                (cleared > 0, cleared)
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
            in_flight(&block, at(5_010), ScanEvidence::unscanned()),
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
            before.starts_with(refusal(cause)) && after.starts_with(refusal(cause)),
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

        let (_tmp, engine) = staker_engine(3, 21);
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
            assert!(seen.insert(refusal(cause)), "{cause:?} shares a sentence");
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
            reason.starts_with(refusal(TerminalCause::FeeTooLow)),
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
}
