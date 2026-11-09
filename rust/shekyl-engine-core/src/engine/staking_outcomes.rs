// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What `staking_info` reports about staking work in flight and how it
//! ended (`WALLET_RPC_STAKING_OUTCOMES.md` WR-Q1, WR-Q2, WR-Q5, WR-Q6).
//!
//! A pure projection over the sealed [`PendingPostBlock`] and the wallet
//! ledger's synced tip. Every state comes from sealed records, never from the
//! dispatcher's in-memory sets, so a restart reads the same answer.
//!
//! Nothing here names a persona, a slot, a funding output or the bond-post
//! delay (WR-Q5): the report says what kind of work it was and where it
//! stands, and a wallet acts on the active persona.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::{
    end_date, end_date_disposition, EndDateDisposition, OutcomeKind, RecordKind, SealedRecord,
    StakingOutcome, TerminalCause,
};
use shekyl_engine_state::pscan_state::PScanState;
use shekyl_engine_state::{PendingPostBlock, PendingPostState};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, GlobalOutputIndex, PCanonicalId};
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::local_ledger::LocalLedger;
use super::pscan::end_date::REFERENCE_MAX_AGE;
use super::pscan::start::pending_post_store_for_engine;
use super::signer::EngineSignerKind;
use super::stake_facade::StakeFacade;
use super::traits::{DaemonEngine, EconomicsEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// One live pending record, as `staking_info`'s `in_flight` reports it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InFlightRecord {
    /// Which staking action the record carries.
    pub kind: RecordKind,
    /// Where it stands.
    pub state: InFlightState,
    /// Its sends so far; `None` when it was never handed to a daemon.
    pub sends: Option<Sends>,
    /// What the record still holds (WR-Q6): the amounts of its reserved
    /// inputs that are still unspent. Zero when nothing is held, as for a
    /// `Held` stake or an empty reservation. `None` when the staking scan
    /// has produced no evidence yet, so what is held cannot be read; zero
    /// would say nothing is held.
    pub reserved: Option<AtomicUnits>,
}

impl std::fmt::Debug for InFlightRecord {
    /// Redacts `reserved`: the amount ties a persona's funding to its
    /// staking work, the same class as the funding records it is summed
    /// from (`PFundingOutputRecord`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InFlightRecord")
            .field("kind", &self.kind)
            .field("state", &self.state)
            .field("sends", &self.sends)
            .field("reserved", &"<redacted>")
            .finish()
    }
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
        /// The end date; what the record holds returns once the staking scan
        /// is past it.
        funds_return_at: BlockHeight,
    },
    /// The end date has passed, so the transaction can never be mined. What
    /// the record holds returns once the staking scan is past
    /// `funds_return_at`.
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
    /// needs none. It never says the record holds funds: a zero-fee claim
    /// reserves none, and only [`InFlightRecord::reserved`] knows (WR-Q6).
    #[must_use]
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Refused { cause, .. } => {
                Some(format!("{} Nothing more will be sent.", refusal(cause)))
            }
            Self::Expired {
                cause: Some(cause), ..
            } => Some(refusal(cause).into_owned()),
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
                format!("{} Its funds are spendable again.", refusal(&cause)),
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
                        Some(cause) => format!("{} {unconfirmed}", refusal(&cause)),
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
fn refusal(cause: &TerminalCause) -> std::borrow::Cow<'static, str> {
    match cause {
        TerminalCause::ConsensusRule { row } => std::borrow::Cow::Owned(format!(
            "The chain refused it under consensus rule {row}. The post was sound; \
             the chain's state did not admit it."
        )),
        // A record a pre-flip daemon refused; no daemon gives this answer
        // now, so the sentence says what happened, not what to wait for.
        TerminalCause::JoinMarketUnsupported => std::borrow::Cow::Borrowed(
            "An older node refused it: that node could not accept a stake. \
             Stake again.",
        ),
        TerminalCause::DoubleSpend => {
            std::borrow::Cow::Borrowed("The node reports that funds this used were already spent.")
        }
        TerminalCause::FeeTooLow => {
            std::borrow::Cow::Borrowed("The node refused its fee as too low.")
        }
        TerminalCause::Malformed => std::borrow::Cow::Borrowed(
            "The node refused the transaction as invalid. This is a wallet \
             fault; check for a wallet update.",
        ),
        TerminalCause::Unrecognized => std::borrow::Cow::Borrowed(
            "The node refused it for a reason this wallet does not recognise.",
        ),
    }
}

/// What the sealed scan contributes to a read. `live` is `Some` only when a
/// scan exists and its frontier has moved off zero: absence from that set is
/// a spend. `None` means the scan has not produced evidence, so absence is
/// not a spend and a fully spent stake is not yet held. `amounts` holds each
/// live output's amount, and is read only when `live` is `Some`.
#[derive(Clone, Copy)]
pub(crate) struct ScanEvidence<'a> {
    live: Option<&'a BTreeSet<GlobalOutputIndex>>,
    amounts: &'a BTreeMap<GlobalOutputIndex, AtomicUnits>,
    confirmed_posts: &'a BTreeSet<PCanonicalId>,
}

#[cfg(test)]
impl ScanEvidence<'static> {
    /// No scan evidence. A record past its end date reads expired.
    fn unscanned() -> Self {
        Self {
            live: None,
            amounts: &EMPTY_AMOUNTS,
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
            amounts: &EMPTY_AMOUNTS,
            confirmed_posts,
        }
    }
}

#[cfg(test)]
static EMPTY_CONFIRMED: BTreeSet<PCanonicalId> = BTreeSet::new();
#[cfg(test)]
static EMPTY_AMOUNTS: BTreeMap<GlobalOutputIndex, AtomicUnits> = BTreeMap::new();

/// The funding set and JoinMarket matches of one sealed scan, or the
/// absence of evidence when there is no scan or the frontier is still zero.
pub(crate) struct FundingScan {
    live: Option<BTreeSet<GlobalOutputIndex>>,
    amounts: BTreeMap<GlobalOutputIndex, AtomicUnits>,
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
                amounts: BTreeMap::new(),
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
                amounts: BTreeMap::new(),
                confirmed_posts: BTreeSet::new(),
            };
        }
        let amounts: BTreeMap<_, _> = pscan
            .funding_outputs()
            .iter()
            .map(|output| (output.gindex, output.amount))
            .collect();
        let live = amounts.keys().copied().collect();
        let confirmed_posts = pscan
            .bond_post_matches()
            .iter()
            .filter(|matched| shekyl_wire::transaction::is_join_market_post_kind(matched.post_kind))
            .map(|matched| matched.p_canonical_id)
            .collect();
        Self {
            live: Some(live),
            amounts,
            confirmed_posts,
        }
    }

    pub(crate) fn evidence(&self) -> ScanEvidence<'_> {
        ScanEvidence {
            live: self.live.as_ref(),
            amounts: &self.amounts,
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

/// What `record` still holds (WR-Q6): the sum of its reserved inputs'
/// amounts that are still in the live funding set. `Ok(None)` with no scan
/// evidence.
///
/// # Errors
///
/// [`ReservedOverflow`] when the sum overflows `u64`. The inputs are the
/// wallet's own distinct outputs, so that is corrupt state; a money total
/// is never wrapped.
fn reserved_amount(
    record: &SealedRecord<'_>,
    evidence: ScanEvidence<'_>,
) -> Result<Option<AtomicUnits>, ReservedOverflow> {
    if evidence.live.is_none() {
        return Ok(None);
    }
    AtomicUnits::checked_sum(
        record
            .reserved
            .iter()
            .filter_map(|gindex| evidence.amounts.get(gindex).copied()),
    )
    .map(Some)
    .ok_or(ReservedOverflow)
}

/// A record's held amount overflowed `u64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReservedOverflow;

/// Every live record in `block`, judged at `ledger_tip` (the wallet ledger's
/// synced height, inclusive) against `evidence`.
///
/// # Errors
///
/// [`ReservedOverflow`] when a record's held amount overflows `u64`.
pub(crate) fn in_flight(
    block: &PendingPostBlock,
    ledger_tip: BlockHeight,
    evidence: ScanEvidence<'_>,
) -> Result<Vec<InFlightRecord>, ReservedOverflow> {
    block
        .sealed_records()
        .map(|record| {
            Ok(InFlightRecord {
                kind: record.kind,
                state: project(record, ledger_tip, evidence),
                sends: match record.state {
                    PendingPostState::Pending => None,
                    PendingPostState::Dispatched { at, attempts } => Some(Sends {
                        first_at_height: tip_of(at),
                        attempts,
                    }),
                },
                reserved: reserved_amount(&record, evidence)?,
            })
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
#[path = "staking_outcomes_tests.rs"]
mod tests;
