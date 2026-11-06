// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How a sealed staking record ends, and what the wallet reports before
//! the release writes that ending (`WALLET_RPC_STAKING_OUTCOMES.md`).
//!
//! One classification, [`end_date_disposition`], names what the end date
//! does with a record. The release applies it once the sealed scan has
//! covered the end date. The read applies the same classification once
//! the wallet ledger reaches the end date, which can be earlier: the
//! scan frontier trails the tip. A stake the funding set already shows
//! fully spent therefore reads held while the release is still waiting
//! to keep the record.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use shekyl_types::{BlockCount, BlockHeight, GlobalOutputIndex, PCanonicalId};

use super::{PendingBondPost, PendingPostBlock, PendingPostState, TerminalCause};

/// Which kind of pending record an outcome is about. Public, unlike the
/// seal classifier's private kind: the seal methods still choose the kind,
/// and this one only names it in an outcome.
#[derive(
    Clone,
    Copy,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    postcard_schema::Schema,
)]
pub enum RecordKind {
    /// A bond post (a stake).
    Post,
    /// An emission claim.
    Claim,
    /// A `P`→principal drain.
    Drain,
    /// A terminal `Release` exit.
    Release,
}

/// How a pending record ended without landing (WR-Q2). A record that landed
/// leaves no outcome: confirmation and settlement are the ordinary paths.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum OutcomeKind {
    /// A terminal verdict was seen and the record reached its end date
    /// without landing. Its reservation was returned.
    Rejected(TerminalCause),
    /// The end date passed with every reserved input still live: the
    /// transaction never landed. Its reservation was returned.
    Expired,
    /// The end date passed for a record that reserves no inputs (the Q11
    /// zero-fee emission claim), whose landing the scan cannot see. Nothing
    /// was held. A terminal verdict does not make it `Rejected`, because a
    /// daemon can relay what it refused and the scan could not tell; the
    /// cause, if one was recorded, is kept so its sentence can be shown.
    EndedUnconfirmed(Option<TerminalCause>),
    /// The end date passed with the record's reserved inputs partly spent
    /// by another transaction. Nothing outside the wallet can spend `P`'s
    /// outputs, so this is a wallet bug or a compromised key. The unspent
    /// rest was returned.
    SpentElsewhere,
}

/// The durable last outcome for one `(kind, persona)` (WR-Q2).
///
/// Written in the same seal that removes the record. A later ending of the
/// same kind for the same persona replaces it, and so does that persona's
/// next admitted seal of the kind, and so does an acknowledgement
/// ([`PendingPostBlock::acknowledge_outcomes`]). A `spent_elsewhere`
/// outcome is the exception: neither a later ending nor a new seal touches
/// it, and only an acknowledgement clears it, so the two endings sit side
/// by side.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct StakingOutcome {
    /// The record kind that ended.
    pub kind: RecordKind,
    /// The persona whose record ended.
    pub persona: PCanonicalId,
    /// How it ended.
    pub outcome: OutcomeKind,
    /// The tip height when the outcome was written.
    pub at_height: BlockHeight,
    /// Whether the record's bytes may have reached a daemon: its state
    /// reached `Dispatched`, which is sealed *before* the first send, or a
    /// daemon answered it with a terminal verdict. A first send that died in
    /// transport still counts, the same "maybe sent" reading as
    /// `Dispatched` itself, so the linkage sentence errs toward warning.
    /// Only a sent record published its inputs' key images, so only its
    /// ending carries that sentence (WR-Q5); a post that reached its end
    /// date before it was due was never seen.
    pub sent: bool,
}

impl std::fmt::Debug for StakingOutcome {
    /// Redacted for the same reason as [`super::PendingBondPost`]: an outcome
    /// ties a persona to an ending, which is `P`-side history.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StakingOutcome(<redacted outcome>)")
    }
}

/// A record's end date: the last height at which a block can include its
/// transaction, `reference_height + max_age`, inclusive. Past it, every
/// daemon refuses the reference as too old, on every chain.
///
/// `max_age` is the consensus `FCMP_REFERENCE_BLOCK_MAX_AGE`, passed by the
/// caller, which also pins it (WR-Q3's invariant: the end date assumes the
/// limit never rises). Saturating: an overflowing end date never arrives,
/// which only holds funds longer.
#[must_use]
pub const fn end_date(reference_height: BlockHeight, max_age: BlockCount) -> BlockHeight {
    reference_height.saturating_add(max_age)
}

/// Whether a record reserves inputs and every one of them has left the
/// live funding set. An empty reservation is not spent: `all` would be
/// vacuously true, and a zero-fee claim would retire the moment it sealed.
#[must_use]
pub fn every_reserved_spent(
    reserved: &[GlobalOutputIndex],
    live: &BTreeSet<GlobalOutputIndex>,
) -> bool {
    !reserved.is_empty() && reserved.iter().all(|g| !live.contains(g))
}

/// What the end date does with one sealed record, given the live funding
/// set. The clock that says the end date has arrived is the caller's:
/// the release uses the sealed frontier, the read uses the wallet ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndDateDisposition {
    /// A bond post whose every reserved input is gone. The release keeps
    /// the record, because it is the bridge a landed-but-unmatched stake
    /// needs. The read reports it held once the ledger is at the end date,
    /// unless a JoinMarket match already names the post.
    Hold,
    /// A claim, drain, or exit whose every reserved input is gone. Settlement
    /// retires it and writes no outcome. The release leaves it in place.
    Settled,
    /// The record did not land. The release writes this outcome and frees
    /// the reservation. The read reports it expired until that release.
    Release(OutcomeKind),
}

/// Classify `reserved` against `live`. See [`EndDateDisposition`].
///
/// Precedence: every reserved input gone is [`EndDateDisposition::Hold`] for
/// a post and [`EndDateDisposition::Settled`] for every other kind; some
/// gone is [`OutcomeKind::SpentElsewhere`]; an empty reservation is
/// [`OutcomeKind::EndedUnconfirmed`]; a recorded verdict is
/// [`OutcomeKind::Rejected`]; otherwise [`OutcomeKind::Expired`].
#[must_use]
pub fn end_date_disposition(
    kind: RecordKind,
    reserved: &[GlobalOutputIndex],
    terminal: Option<TerminalCause>,
    live: &BTreeSet<GlobalOutputIndex>,
) -> EndDateDisposition {
    if every_reserved_spent(reserved, live) {
        return if kind == RecordKind::Post {
            EndDateDisposition::Hold
        } else {
            EndDateDisposition::Settled
        };
    }
    let some_spent = reserved.iter().any(|g| !live.contains(g));
    let outcome = if some_spent {
        OutcomeKind::SpentElsewhere
    } else if reserved.is_empty() {
        OutcomeKind::EndedUnconfirmed(terminal)
    } else if let Some(cause) = terminal {
        OutcomeKind::Rejected(cause)
    } else {
        OutcomeKind::Expired
    };
    EndDateDisposition::Release(outcome)
}

/// Whether the record's bytes may have reached a daemon. `Dispatched` is
/// sealed before the first send, and a terminal verdict is a daemon's
/// answer, so either one counts. A send that died in transport still
/// counts: the linkage sentence errs toward warning.
#[must_use]
pub fn record_was_sent(state: PendingPostState, terminal: Option<TerminalCause>) -> bool {
    matches!(state, PendingPostState::Dispatched { .. }) || terminal.is_some()
}

/// One live sealed record, borrowed. Not persisted: the four record structs
/// stay the postcard layout, and this view is how a walk sees them as one
/// family.
#[derive(Clone, Copy)]
pub struct SealedRecord<'a> {
    /// Which staking action the record carries.
    pub kind: RecordKind,
    /// The persona it is bound to.
    pub persona: &'a PCanonicalId,
    /// Whether it has been handed to a daemon.
    pub state: PendingPostState,
    /// The FCMP++ reference the bytes were proved against.
    pub reference_height: BlockHeight,
    /// A terminal verdict's cause, once one has been recorded.
    pub terminal: Option<TerminalCause>,
    /// The inputs the record reserves.
    pub reserved: &'a [GlobalOutputIndex],
}

impl std::fmt::Debug for SealedRecord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedRecord")
            .field("kind", &self.kind)
            .field("persona", &"<redacted>")
            .field("state", &self.state)
            .field("reference_height", &self.reference_height)
            .field("terminal", &self.terminal)
            .field("reserved", &self.reserved.len())
            .finish()
    }
}

/// One record [`PendingPostBlock::release_ended`] released, with the
/// outcome it wrote and whether the record had been sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndedRecord {
    /// Which staking action ended.
    pub kind: RecordKind,
    /// The persona whose record ended.
    pub persona: PCanonicalId,
    /// How it ended.
    pub outcome: OutcomeKind,
    /// [`record_was_sent`] at the moment the release decided.
    pub sent: bool,
}

/// What [`PendingPostBlock::release_ended`] released, one entry per record.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EndedRelease {
    /// Every record released this call.
    pub released: Vec<EndedRecord>,
}

impl EndedRelease {
    /// Nothing reached its end date this call.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.released.is_empty()
    }
}

impl PendingPostBlock {
    /// Every live record, posts then claims then drains then exits.
    pub fn sealed_records(&self) -> impl Iterator<Item = SealedRecord<'_>> + '_ {
        let posts = self.posts.iter().map(|record| SealedRecord {
            kind: RecordKind::Post,
            persona: &record.persona,
            state: record.state,
            reference_height: record.reference_height,
            terminal: record.terminal,
            reserved: record.funding_gindexes.as_slice(),
        });
        let claims = self.claims.iter().map(|record| SealedRecord {
            kind: RecordKind::Claim,
            persona: &record.persona,
            state: record.state,
            reference_height: record.reference_height,
            terminal: record.terminal,
            reserved: record.fee_gindexes.as_slice(),
        });
        let drains = self.drains.iter().map(|record| SealedRecord {
            kind: RecordKind::Drain,
            persona: &record.persona,
            state: record.state,
            reference_height: record.reference_height,
            terminal: record.terminal,
            reserved: record.funding_gindexes.as_slice(),
        });
        let releases = self.releases.iter().map(|record| SealedRecord {
            kind: RecordKind::Release,
            persona: &record.persona,
            state: record.state,
            reference_height: record.reference_height,
            terminal: record.terminal,
            reserved: record.funding_gindexes.as_slice(),
        });
        posts.chain(claims).chain(drains).chain(releases)
    }

    /// The durable outcomes. A `(kind, persona)` has one entry, except
    /// `spent_elsewhere`, which can sit beside a later ending of the same
    /// pair (see [`Self::replace_outcome`]).
    pub fn outcomes(&self) -> &[StakingOutcome] {
        &self.outcomes
    }

    /// Record the cause of a terminal daemon verdict on `persona`'s live
    /// record of `kind` (BD-Q3 Rule 2). The record and its reservation stay;
    /// a recorded cause stops further sends and names the outcome if the
    /// record reaches its end date without landing. The first cause seen is
    /// kept. Returns `true` when this call recorded it.
    #[must_use]
    pub fn record_terminal(
        &mut self,
        kind: RecordKind,
        persona: &PCanonicalId,
        cause: TerminalCause,
    ) -> bool {
        let Some(slot) = self.terminal_slot(kind, persona) else {
            return false;
        };
        if slot.is_some() {
            return false;
        }
        *slot = Some(cause);
        true
    }

    fn terminal_slot(
        &mut self,
        kind: RecordKind,
        persona: &PCanonicalId,
    ) -> Option<&mut Option<TerminalCause>> {
        match kind {
            RecordKind::Post => self
                .posts
                .iter_mut()
                .find(|record| &record.persona == persona)
                .map(|record| &mut record.terminal),
            RecordKind::Claim => self
                .claims
                .iter_mut()
                .find(|record| &record.persona == persona)
                .map(|record| &mut record.terminal),
            RecordKind::Drain => self
                .drains
                .iter_mut()
                .find(|record| &record.persona == persona)
                .map(|record| &mut record.terminal),
            RecordKind::Release => self
                .releases
                .iter_mut()
                .find(|record| &record.persona == persona)
                .map(|record| &mut record.terminal),
        }
    }

    /// Release every record whose end date the sealed scan has covered,
    /// writing its outcome in the same mutation (WR-Q3, WR-Q4).
    ///
    /// `scanned_through` is the highest height the sealed scan has covered,
    /// **inclusive**. The scan's own frontier is exclusive (the first
    /// unscanned height), so the caller passes one below it: a record is
    /// released only once the block at its end date has itself been
    /// scanned, since that block can still include the transaction.
    ///
    /// What the end date does is [`end_date_disposition`], the same
    /// classification the read uses. This method applies it only once
    /// `scanned_through` covers the end date, and only
    /// [`EndDateDisposition::Release`] removes a record.
    /// [`EndDateDisposition::Hold`] keeps a fully spent stake, the bridge
    /// `reconcile_phantom_bonded_slots` reads. [`EndDateDisposition::Settled`]
    /// leaves a fully spent claim, drain, or exit for [`Self::remove_settled`].
    ///
    /// **Call it after [`Self::remove_confirmed`] and [`Self::remove_settled`],
    /// in the same pass and over the same evidence.** A record that landed has
    /// landed at or below its end date, so once the scan has covered the end
    /// date those two retires have already removed it.
    ///
    /// [`Self::held_spent_posts`] is this method's hold, on the same frontier
    /// clock, so the release and the query cannot name different posts.
    /// The read's hold uses the ledger tip instead, and can name a post
    /// while this method is still waiting for the frontier.
    ///
    /// Releasing is safe at the end date because no block above it can
    /// include the transaction and every block at or below it is inside the
    /// sealed, reorg-deep scan the evidence came from.
    #[must_use]
    pub fn release_ended(
        &mut self,
        scanned_through: BlockHeight,
        live_funding: &BTreeSet<GlobalOutputIndex>,
        max_age: BlockCount,
        at_height: BlockHeight,
    ) -> EndedRelease {
        let mut out = EndedRelease::default();
        let mut take = |kind: RecordKind,
                        persona: PCanonicalId,
                        state: PendingPostState,
                        reference_height: BlockHeight,
                        terminal: Option<TerminalCause>,
                        reserved: &[GlobalOutputIndex]| {
            if scanned_through < end_date(reference_height, max_age) {
                return false;
            }
            match end_date_disposition(kind, reserved, terminal, live_funding) {
                EndDateDisposition::Release(outcome) => {
                    out.released.push(EndedRecord {
                        kind,
                        persona,
                        outcome,
                        sent: record_was_sent(state, terminal),
                    });
                    true
                }
                EndDateDisposition::Hold | EndDateDisposition::Settled => false,
            }
        };
        self.posts.retain(|record| {
            !take(
                RecordKind::Post,
                record.persona,
                record.state,
                record.reference_height,
                record.terminal,
                &record.funding_gindexes,
            )
        });
        self.claims.retain(|record| {
            !take(
                RecordKind::Claim,
                record.persona,
                record.state,
                record.reference_height,
                record.terminal,
                &record.fee_gindexes,
            )
        });
        self.drains.retain(|record| {
            !take(
                RecordKind::Drain,
                record.persona,
                record.state,
                record.reference_height,
                record.terminal,
                &record.funding_gindexes,
            )
        });
        self.releases.retain(|record| {
            !take(
                RecordKind::Release,
                record.persona,
                record.state,
                record.reference_height,
                record.terminal,
                &record.funding_gindexes,
            )
        });
        if !out.is_empty() {
            self.generation += 1;
            for record in &out.released {
                self.replace_outcome(record.kind, &record.persona);
                self.outcomes.push(StakingOutcome {
                    kind: record.kind,
                    persona: record.persona,
                    outcome: record.outcome,
                    at_height,
                    sent: record.sent,
                });
            }
        }
        out
    }

    /// Posts the release keeps because every reserved input is gone and the
    /// sealed frontier covers the end date. A post whose match the scan has
    /// sealed is the dispatch tick's to retire, so the caller drops it. This
    /// is the release clock. The read's hold does not wait for this frontier.
    pub fn held_spent_posts<'a>(
        &'a self,
        scanned_through: BlockHeight,
        live_funding: &'a BTreeSet<GlobalOutputIndex>,
        max_age: BlockCount,
    ) -> impl Iterator<Item = &'a PendingBondPost> + 'a {
        self.posts.iter().filter(move |post| {
            scanned_through >= end_date(post.reference_height, max_age)
                && matches!(
                    end_date_disposition(
                        RecordKind::Post,
                        &post.funding_gindexes,
                        post.terminal,
                        live_funding,
                    ),
                    EndDateDisposition::Hold,
                )
        })
    }

    /// Clear every outcome of `kind`, for every persona, written at or below
    /// `through_height` (the acknowledgement, WR-Q2 as ruled 2026-10-17).
    /// The height is the newest ending the owner was shown, so an ending
    /// written after that is never cleared unseen. Returns how many were
    /// cleared; acknowledging twice clears nothing the second time.
    #[must_use]
    pub fn acknowledge_outcomes(&mut self, kind: RecordKind, through_height: BlockHeight) -> usize {
        let before = self.outcomes.len();
        self.outcomes
            .retain(|outcome| !(outcome.kind == kind && outcome.at_height <= through_height));
        before - self.outcomes.len()
    }

    /// A new seal or a new ending of `kind` for `persona` replaces its last
    /// outcome, except `spent_elsewhere`: that one is an integrity signal and
    /// clears only on acknowledgement, so it can sit beside the later ending.
    pub(super) fn replace_outcome(&mut self, kind: RecordKind, persona: &PCanonicalId) {
        self.outcomes.retain(|outcome| {
            !(outcome.kind == kind && &outcome.persona == persona)
                || outcome.outcome == OutcomeKind::SpentElsewhere
        });
    }
}

#[cfg(test)]
mod tests {
    use shekyl_types::{
        BlockCount, BlockHeight, ChainCount, GlobalOutputIndex, PCanonicalId, PSlot,
    };

    use super::super::*;

    const TEST_REFERENCE: BlockHeight = BlockHeight::from_raw(5_000);
    const TEST_MAX_AGE: BlockCount = BlockCount::from_raw(100);
    const TEST_END: BlockHeight = BlockHeight::from_raw(5_100);

    fn gindexes(v: &[u64]) -> Vec<GlobalOutputIndex> {
        v.iter().copied().map(GlobalOutputIndex::from_raw).collect()
    }

    fn live(v: &[u64]) -> std::collections::BTreeSet<GlobalOutputIndex> {
        v.iter().copied().map(GlobalOutputIndex::from_raw).collect()
    }

    fn post(persona_byte: u8, funding: &[u64]) -> PendingBondPost {
        PendingBondPost {
            p_slot: PSlot::from_raw(0),
            persona: PCanonicalId::from_bytes([persona_byte; 32]),
            tx_bytes: vec![0xAB; 16],
            bond_post_offset_blocks: BlockCount::from_raw(12),
            anchor_t0: ChainCount::from_raw(1_000),
            funding_gindexes: gindexes(funding),
            state: PendingPostState::Pending,
            reference_height: TEST_REFERENCE,
            terminal: None,
        }
    }

    fn claim(persona_byte: u8, fee: &[u64]) -> PendingEmissionClaim {
        PendingEmissionClaim {
            persona: PCanonicalId::from_bytes([persona_byte; 32]),
            tx_bytes: vec![0xCD; 16],
            fee_gindexes: gindexes(fee),
            state: PendingPostState::Pending,
            reference_height: TEST_REFERENCE,
            terminal: None,
        }
    }

    fn drain(persona_byte: u8, funding: &[u64]) -> PendingDrain {
        PendingDrain {
            persona: PCanonicalId::from_bytes([persona_byte; 32]),
            tx_bytes: vec![0xDE; 16],
            funding_gindexes: gindexes(funding),
            state: PendingPostState::Pending,
            reference_height: TEST_REFERENCE,
            terminal: None,
        }
    }

    fn release(persona_byte: u8, funding: &[u64]) -> PendingRelease {
        PendingRelease {
            persona: PCanonicalId::from_bytes([persona_byte; 32]),
            tx_bytes: vec![0xEB; 16],
            funding_gindexes: gindexes(funding),
            state: PendingPostState::Pending,
            reference_height: TEST_REFERENCE,
            terminal: None,
        }
    }

    // -- WR-Q2 / WR-Q3 / WR-Q4: end-date release and durable outcomes --------

    fn sealed(records: impl FnOnce(&mut PendingPostBlock)) -> PendingPostBlock {
        let mut block = PendingPostBlock::empty();
        records(&mut block);
        block
    }

    /// The classification the release, the settlement retire, and the read
    /// share. The clocks differ; this does not.
    #[test]
    fn end_date_disposition_names_hold_settled_and_release() {
        let present = live(&[1]);
        let absent = live(&[]);
        let one = gindexes(&[1]);
        let two = gindexes(&[1, 2]);
        assert_eq!(
            end_date_disposition(RecordKind::Post, &one, None, &absent),
            EndDateDisposition::Hold
        );
        assert_eq!(
            end_date_disposition(RecordKind::Drain, &one, None, &absent),
            EndDateDisposition::Settled
        );
        assert!(
            !every_reserved_spent(&[], &absent),
            "an empty reservation is not a total spend"
        );
        assert_eq!(
            end_date_disposition(RecordKind::Post, &two, None, &present),
            EndDateDisposition::Release(OutcomeKind::SpentElsewhere)
        );
        assert_eq!(
            end_date_disposition(
                RecordKind::Claim,
                &[],
                Some(TerminalCause::FeeTooLow),
                &present
            ),
            EndDateDisposition::Release(OutcomeKind::EndedUnconfirmed(Some(
                TerminalCause::FeeTooLow
            )))
        );
        assert_eq!(
            end_date_disposition(
                RecordKind::Drain,
                &one,
                Some(TerminalCause::Malformed),
                &present
            ),
            EndDateDisposition::Release(OutcomeKind::Rejected(TerminalCause::Malformed))
        );
        assert_eq!(
            end_date_disposition(RecordKind::Release, &one, None, &present),
            EndDateDisposition::Release(OutcomeKind::Expired)
        );
    }

    #[test]
    fn the_end_date_is_reference_plus_max_age_inclusive() {
        assert_eq!(end_date(TEST_REFERENCE, TEST_MAX_AGE), TEST_END);
        assert_eq!(
            end_date(BlockHeight::from_raw(u64::MAX - 1), TEST_MAX_AGE),
            BlockHeight::from_raw(u64::MAX),
            "an overflowing end date saturates: it never arrives, which only holds funds longer"
        );
    }

    /// One block short of the end date nothing is released; at the end date
    /// the record goes, with its outcome, in the same mutation.
    #[test]
    fn a_record_is_released_at_its_end_date_and_not_a_block_before() {
        let mut block = sealed(|b| assert!(b.push_drain(drain(0x01, &[7]))));
        let before = block.release_ended(
            BlockHeight::from_raw(TEST_END.to_raw() - 1),
            &live(&[7]),
            TEST_MAX_AGE,
            BlockHeight::from_raw(6_000),
        );
        assert!(before.is_empty());
        assert_eq!(block.drains().len(), 1);
        let g = block.generation();

        let at = block.release_ended(
            TEST_END,
            &live(&[7]),
            TEST_MAX_AGE,
            BlockHeight::from_raw(6_000),
        );
        assert_eq!(
            at.released,
            vec![EndedRecord {
                kind: RecordKind::Drain,
                persona: PCanonicalId::from_bytes([0x01; 32]),
                outcome: OutcomeKind::Expired,
                sent: false,
            }]
        );
        assert!(block.drains().is_empty());
        assert!(
            block.reserved_gindexes().is_empty(),
            "the reservation goes with the record"
        );
        assert!(
            block.generation() > g,
            "a release is a reservation-releasing operation"
        );
        assert_eq!(block.outcomes().len(), 1);
        assert_eq!(block.outcomes()[0].outcome, OutcomeKind::Expired);
        assert_eq!(block.outcomes()[0].at_height, BlockHeight::from_raw(6_000));
    }

    /// The release table, row by row, for every kind it applies to.
    #[test]
    fn the_release_outcome_follows_the_precedence_table() {
        let p = |b: u8| PCanonicalId::from_bytes([b; 32]);
        let mut block = sealed(|b| {
            // stake, inputs live, no verdict -> expired
            assert!(b.push_post(post(0x10, &[1])));
            // stake, an input gone without a match -> spent elsewhere
            assert!(b.push_post(post(0x11, &[2, 3])));
            // claim, nothing reserved -> ended unconfirmed
            assert!(b.push_claim(claim(0x12, &[])));
            // drain, inputs live, a terminal verdict seen -> rejected
            assert!(b.push_drain(drain(0x13, &[4])));
            // exit, part of its inputs gone -> spent elsewhere
            let g = b.generation();
            assert_eq!(
                b.seal_release(release(0x14, &[5, 6]), ChainCount::from_raw(1), g),
                SealAdmission::Admit
            );
            // claim, nothing reserved, a verdict seen -> ended unconfirmed,
            // the cause kept: the scan cannot see whether it landed
            assert!(b.push_claim(claim(0x15, &[])));
            // stake, every input gone, no match -> held, not released
            assert!(b.push_post(post(0x16, &[7, 8])));
        });
        assert!(block.record_terminal(RecordKind::Drain, &p(0x13), TerminalCause::FeeTooLow));
        assert!(block.record_terminal(RecordKind::Claim, &p(0x15), TerminalCause::Malformed));

        let out = block.release_ended(TEST_END, &live(&[1, 3, 4, 6]), TEST_MAX_AGE, TEST_END);
        let got: std::collections::BTreeMap<_, _> = out
            .released
            .iter()
            .map(|record| ((record.kind, record.persona.to_bytes()[0]), record.outcome))
            .collect();
        assert_eq!(got.len(), 6, "every ended record is released: {got:?}");
        assert_eq!(got[&(RecordKind::Post, 0x10)], OutcomeKind::Expired);
        assert_eq!(got[&(RecordKind::Post, 0x11)], OutcomeKind::SpentElsewhere);
        assert_eq!(
            got[&(RecordKind::Claim, 0x12)],
            OutcomeKind::EndedUnconfirmed(None)
        );
        assert_eq!(
            got[&(RecordKind::Drain, 0x13)],
            OutcomeKind::Rejected(TerminalCause::FeeTooLow)
        );
        assert_eq!(
            got[&(RecordKind::Release, 0x14)],
            OutcomeKind::SpentElsewhere
        );
        assert_eq!(
            got[&(RecordKind::Claim, 0x15)],
            OutcomeKind::EndedUnconfirmed(Some(TerminalCause::Malformed))
        );
        assert!(
            !got.contains_key(&(RecordKind::Post, 0x16)),
            "a stake with every input gone is held"
        );
        assert!(
            block.has_live_post_for(&p(0x16)),
            "its record stays the bridge"
        );
        let held: Vec<u8> = block
            .held_spent_posts(TEST_END, &live(&[1, 3, 4, 6]), TEST_MAX_AGE)
            .map(|post| post.persona.to_bytes()[0])
            .collect();
        assert_eq!(held, vec![0x16], "the held query names it, and only it");
        assert_eq!(
            block.reserved_gindexes(),
            gindexes(&[7, 8]).into_iter().collect(),
            "every other reservation, partly spent ones included, is freed"
        );
        assert!(
            !block.has_live_claim_for(&p(0x12)),
            "the zero-fee claim's gate reopens"
        );
        assert_eq!(block.outcomes().len(), 6);
        // Sent: the exit (sealed as dispatched, seal-before-send) and the two
        // records a daemon answered with a verdict. The others were never
        // handed to a daemon, so their endings say nothing about linkage
        // (WR-Q5).
        for o in block.outcomes() {
            let byte = o.persona.to_bytes()[0];
            assert_eq!(
                o.sent,
                (0x13..=0x15).contains(&byte),
                "sent flag for {byte:#x}"
            );
        }
    }

    /// A reservation-kind record whose every input is gone landed: it is
    /// `remove_settled`'s, so the release leaves it alone even when called
    /// out of order, and no outcome is written for it.
    #[test]
    fn a_settled_record_is_never_released_as_an_ending() {
        let mut block = sealed(|b| assert!(b.push_drain(drain(0x20, &[8, 9]))));
        let out = block.release_ended(TEST_END, &live(&[]), TEST_MAX_AGE, TEST_END);
        assert!(out.is_empty());
        assert_eq!(block.drains().len(), 1);
        let settled = block.remove_settled(&live(&[]));
        assert_eq!(settled.drains.len(), 1);
        assert!(block.outcomes().is_empty());
    }

    /// A terminal verdict holds the record and its reservation (BD-Q3 Rule
    /// 2). The first cause is kept, and only a live record can take one.
    #[test]
    fn a_terminal_verdict_is_recorded_and_holds_the_record() {
        let who = PCanonicalId::from_bytes([0x30; 32]);
        let mut block = sealed(|b| assert!(b.push_post(post(0x30, &[11]))));
        assert!(block.record_terminal(
            RecordKind::Post,
            &who,
            TerminalCause::JoinMarketUnsupported
        ));
        assert!(
            !block.record_terminal(RecordKind::Post, &who, TerminalCause::DoubleSpend),
            "the first cause is kept"
        );
        assert!(
            !block.record_terminal(RecordKind::Claim, &who, TerminalCause::DoubleSpend),
            "no live claim to mark"
        );
        assert_eq!(
            block.posts().len(),
            1,
            "a verdict never removes a submitted record"
        );
        assert_eq!(
            block.posts()[0].terminal,
            Some(TerminalCause::JoinMarketUnsupported)
        );
        assert_eq!(
            block.reserved_gindexes(),
            live(&[11]),
            "and never releases its reservation"
        );
    }

    /// An outcome is per `(kind, persona)`: a later ending replaces it, the
    /// persona's next admitted seal of the kind clears it, and so does an
    /// acknowledgement.
    #[test]
    fn an_outcome_is_replaced_cleared_by_a_new_seal_and_acknowledged() {
        let mut block = sealed(|b| assert!(b.push_drain(drain(0x40, &[12]))));
        assert_eq!(
            block
                .release_ended(TEST_END, &live(&[12]), TEST_MAX_AGE, TEST_END)
                .released
                .len(),
            1
        );
        assert_eq!(block.outcomes().len(), 1);

        let g = block.generation();
        assert_eq!(
            block.seal_drain(drain(0x40, &[13]), ChainCount::from_raw(6_000), g),
            SealAdmission::Admit
        );
        assert!(
            block.outcomes().is_empty(),
            "the next admitted seal of the kind clears it"
        );

        assert_eq!(
            block
                .release_ended(TEST_END, &live(&[13]), TEST_MAX_AGE, TEST_END)
                .released
                .len(),
            1
        );
        assert_eq!(block.outcomes().len(), 1, "one outcome per (kind, persona)");
        assert_eq!(
            block.acknowledge_outcomes(RecordKind::Claim, TEST_END),
            0,
            "another kind's is untouched"
        );
        assert_eq!(block.acknowledge_outcomes(RecordKind::Drain, TEST_END), 1);
        assert!(block.outcomes().is_empty());
        assert_eq!(
            block.acknowledge_outcomes(RecordKind::Drain, TEST_END),
            0,
            "nothing left to acknowledge"
        );
    }

    /// The acknowledgement as ruled 2026-10-17: every outcome of the kind,
    /// across personas, written at or below the height shown; a newer one is
    /// never cleared unseen.
    #[test]
    fn an_acknowledgement_clears_every_persona_through_the_height_shown() {
        let mut block = sealed(|b| {
            assert!(b.push_drain(drain(0x41, &[20])));
            assert!(b.push_drain(drain(0x42, &[21])));
            assert!(b.push_claim(claim(0x43, &[])));
        });
        let shown = BlockHeight::from_raw(TEST_END.to_raw() + 10);
        let ended = block.release_ended(TEST_END, &live(&[20, 21]), TEST_MAX_AGE, shown);
        assert_eq!(ended.released.len(), 3);
        let mut late = drain(0x44, &[22]);
        late.reference_height = BlockHeight::from_raw(TEST_REFERENCE.to_raw() + 50);
        assert!(block.push_drain(late));
        let later_end = BlockHeight::from_raw(TEST_END.to_raw() + 50);
        let after = BlockHeight::from_raw(shown.to_raw() + 1);
        assert_eq!(
            block
                .release_ended(later_end, &live(&[22]), TEST_MAX_AGE, after)
                .released
                .len(),
            1
        );

        assert_eq!(
            block.acknowledge_outcomes(RecordKind::Drain, shown),
            2,
            "both personas' drains at or below the height shown"
        );
        let left: Vec<_> = block
            .outcomes()
            .iter()
            .map(|o| (o.kind, o.persona.to_bytes()[0]))
            .collect();
        assert_eq!(
            left,
            vec![(RecordKind::Claim, 0x43), (RecordKind::Drain, 0x44)],
            "the other kind, and the drain written after the height shown, stay"
        );
        assert_eq!(block.acknowledge_outcomes(RecordKind::Drain, shown), 0);
    }

    /// `spent_elsewhere` clears only on acknowledgement: a new seal, or a new
    /// ending, of the same kind for that persona leaves it in place.
    #[test]
    fn spent_elsewhere_survives_a_new_seal_and_a_new_ending() {
        let mut block = sealed(|b| assert!(b.push_drain(drain(0x45, &[30, 31]))));
        let ended = block.release_ended(TEST_END, &live(&[30]), TEST_MAX_AGE, TEST_END);
        assert_eq!(
            ended.released[0].outcome,
            OutcomeKind::SpentElsewhere,
            "one of two inputs gone"
        );

        let g = block.generation();
        assert_eq!(
            block.seal_drain(drain(0x45, &[32]), ChainCount::from_raw(6_000), g),
            SealAdmission::Admit
        );
        assert_eq!(block.outcomes().len(), 1, "the seal leaves it");
        assert_eq!(block.outcomes()[0].outcome, OutcomeKind::SpentElsewhere);

        let next = block.release_ended(TEST_END, &live(&[32]), TEST_MAX_AGE, TEST_END);
        assert_eq!(next.released[0].outcome, OutcomeKind::Expired);
        let kinds: Vec<_> = block.outcomes().iter().map(|o| o.outcome).collect();
        assert_eq!(
            kinds,
            vec![OutcomeKind::SpentElsewhere, OutcomeKind::Expired],
            "a later ending is added beside it, not over it"
        );
        assert_eq!(block.acknowledge_outcomes(RecordKind::Drain, TEST_END), 2);
        assert!(block.outcomes().is_empty());
    }

    /// The outcome and its cause survive the codec, and `Debug` names no
    /// persona.
    #[test]
    fn outcomes_round_trip_and_debug_redacts_them() {
        let mut block = sealed(|b| assert!(b.push_post(post(0x50, &[14]))));
        assert!(block.record_terminal(
            RecordKind::Post,
            &PCanonicalId::from_bytes([0x50; 32]),
            TerminalCause::DoubleSpend
        ));
        assert_eq!(
            block
                .release_ended(TEST_END, &live(&[14]), TEST_MAX_AGE, TEST_END)
                .released
                .len(),
            1
        );
        let back =
            PendingPostBlock::from_postcard_bytes(&block.to_postcard_bytes().unwrap()).unwrap();
        assert_eq!(back, block);
        assert_eq!(
            back.outcomes()[0].outcome,
            OutcomeKind::Rejected(TerminalCause::DoubleSpend)
        );
        let shown = format!("{block:?} {:?}", block.outcomes()[0]);
        assert!(
            !shown.contains("80, 80"),
            "no persona bytes in Debug: {shown}"
        );
        assert!(shown.contains("redacted outcome"));
    }
}
