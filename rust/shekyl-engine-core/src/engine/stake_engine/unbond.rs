// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `AssembleUnbond` — the terminal full exit's producer-side preconditions.
//!
//! `verify_unbond_bond_post`'s rejection arms are two categories, and this
//! module owns the half [`build_unbond_vin`] cannot.
//!
//! The builder fixes the five fields a producer controls. The remaining arms —
//! `RecordMissing`, `IntervalLogFull`, `CooldownNotElapsed`,
//! `SlashSettlementPending` — are **record state**: facts about the chain that
//! no vin construction can satisfy. A producer that ignored them would assemble
//! a well-formed post the daemon then rejects, and on this path that is the
//! difference that matters. An exit is the last step before an irreversible
//! persona-key wipe; a wallet that says "sent" and fails at the chain has told
//! the user the wrong thing about an operation they cannot take back. So the
//! refusal happens **here**, with a named cause, before anything is built.
//!
//! **The predicates are consensus's own, called — not restated.**
//! [`release_cooldown_elapsed`] and [`slashes_settled_through`] are the exact
//! functions the verify arm runs, and `MAX_BOND_BAD_INTERVALS` is the same
//! constant. A second implementation here could drift from the verifier that
//! decides the transaction, and the drift would be invisible until a real exit
//! failed. A gate could report that divergence after the fact; calling the same
//! function makes it not happen.

use kameo::message::{Context, Message};

use shekyl_archival_bond_builder::build_unbond_vin;
use shekyl_archival_retention::bond_connect::MAX_BOND_BAD_INTERVALS;
use shekyl_archival_retention::release_cooldown::{
    release_cooldown_elapsed, slashes_settled_through,
};
use shekyl_archival_retention::ArchivalBondPostVin;

use crate::engine::emission_source::{ServeAnchor, SlashWatermark};

use super::actor::StakeEngine;
use super::types::*;

/// The record facts an exit's preconditions read, as the daemon reported them.
///
/// Every field arrives from one claim-source response and therefore one LMDB
/// read view: `bonded_total_atomic` and the cooldown anchor cannot straddle a
/// block here, which would otherwise let readiness be computed on one view and
/// the vin built against another.
///
/// [`ServeAnchor`] and [`SlashWatermark`] rather than `Option<u64>` on purpose.
/// Both consensus predicates treat an absent anchor as *permissive*, so a bare
/// `Option` reaching this struct could carry "the daemon says nothing served"
/// (correct, permissive) or "the field never arrived" (must be fail-closed) with
/// no way to tell them apart. The decoder makes the second unconstructible — an
/// absent field is a decode error — and these types carry that guarantee the
/// rest of the way.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // PR-P4 slice 2b: the tx-assembly caller populates this from `BondContext`.
pub(crate) struct UnbondRecordState {
    /// The record's current bonded balance; the exit's `bond_debit` by contract.
    pub bonded_total_atomic: u64,
    /// The record's interval-log length.
    pub bad_interval_count: usize,
    /// The whole-record release-cooldown anchor, folded by the daemon.
    pub last_served: ServeAnchor,
    /// The slash scheduler's monotone watermark.
    pub last_settled_slash: SlashWatermark,
    /// The settled epoch the daemon derived from its own tip.
    pub current_settlement_epoch: u64,
}

impl UnbondRecordState {
    /// Refuse, with a named cause, if this record cannot support a full exit.
    ///
    /// Mirrors the verify arm's record-state checks in the same order, using the
    /// same predicates, so a refusal here and a rejection there cannot disagree
    /// about *why*.
    #[allow(dead_code)] // PR-P4 slice 2b: called by the tx-assembly path.
    pub(crate) fn ensure_exit_ready(&self) -> Result<(), UnbondNotReady> {
        // A zero balance is `NothingToUnbond` at the builder, which owns that
        // operand; it is not repeated here.

        // The connect must append a clean interval-close; a full log makes the
        // tx unconnectable, so verify rejects it too. Same bound, one constant.
        if self.bad_interval_count >= MAX_BOND_BAD_INTERVALS {
            return Err(UnbondNotReady::IntervalLogFull {
                count: self.bad_interval_count,
                max: MAX_BOND_BAD_INTERVALS,
            });
        }

        // Both predicates are called unconditionally, on the operand form
        // `as_verify_operand` produces and nothing else. A tempting shortening
        // is to note that neither can refuse a never-served record
        // (`release_cooldown_elapsed(None, _)` and `slashes_settled_through(_,
        // None)` are both `true`) and wrap the pair in a `ServedAt` match. That
        // trades a wrong message for a missing check: if either absent arm ever
        // moved, the match would *skip* the predicate instead of running it.
        // The refusals carry the anchor as read, so no branch here has to
        // restate what consensus does with `None`.
        let anchor = self.last_served.as_verify_operand();
        if !release_cooldown_elapsed(anchor, self.current_settlement_epoch) {
            return Err(UnbondNotReady::CooldownNotElapsed {
                last_served: self.last_served,
                current_settlement_epoch: self.current_settlement_epoch,
            });
        }

        if !slashes_settled_through(self.last_settled_slash.as_verify_operand(), anchor) {
            return Err(UnbondNotReady::SlashSettlementPending {
                last_served: self.last_served,
                watermark: self.last_settled_slash,
            });
        }

        Ok(())
    }
}

/// Assemble the `Unbond` post's vin for a held persona (gate-4 §3.5).
///
/// Returns the vin only. The persona-bound transaction around it — funding,
/// outputs, the surface-A `pqc_auths` slot — is slice 2b, and is deliberately
/// not reachable from any RPC method or CLI verb until slice 3's regtest walk
/// has exercised the retire path end to end.
#[allow(dead_code)] // PR-P4 slice 2b: sent by the tx-assembly path.
pub(crate) struct AssembleUnbond {
    /// Operation-scoped capability proving the slot is currently held.
    pub handle: PersonaHandle,
    /// The record facts, from one claim-source read view.
    pub record: UnbondRecordState,
}

impl Message<AssembleUnbond> for StakeEngine {
    type Reply = Result<ArchivalBondPostVin, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: AssembleUnbond,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.validate_handle(&msg.handle)?;

        // Preconditions BEFORE construction: nothing is built for a record that
        // cannot exit, so a refusal never produces a post that could be
        // broadcast by a caller ignoring the error.
        msg.record.ensure_exit_ready()?;

        let keys = self
            .held
            .get(&msg.handle.p_slot)
            .expect("validate_handle confirmed the slot is held")
            .keys();

        build_unbond_vin(keys.bond_post_keys(), msg.record.bonded_total_atomic)
            .map_err(StakeEngineError::BondBuild)
    }
}

#[cfg(test)]
mod tests {
    use shekyl_archival_retention::RELEASE_COOLDOWN_EPOCHS;

    use super::*;

    /// The record-state arms are tested here as PRECONDITIONS, not as verifier
    /// behaviour. Driving `verify_unbond_bond_post` into `CooldownNotElapsed`
    /// would test consensus, which already covers itself; what is worth
    /// asserting on this side is that the producer refuses first, so the
    /// failure reaches the user at the wallet instead of at the chain.
    fn ready() -> UnbondRecordState {
        UnbondRecordState {
            bonded_total_atomic: 3 * 750_000_000,
            bad_interval_count: 0,
            last_served: ServeAnchor::ServedAt(4),
            last_settled_slash: SlashWatermark::SettledThrough(4),
            // The boundary, read from the config-generated constant rather than
            // written out: a fixture that hardcodes the genesis value states the
            // cooldown a second time, and the copy is what goes stale.
            current_settlement_epoch: 4 + RELEASE_COOLDOWN_EPOCHS,
        }
    }

    #[test]
    fn a_ready_record_passes_every_precondition() {
        ready()
            .ensure_exit_ready()
            .expect("a ready record must not be refused");
    }

    #[test]
    fn a_full_interval_log_is_refused_with_its_bound() {
        let mut r = ready();
        r.bad_interval_count = MAX_BOND_BAD_INTERVALS;
        assert_eq!(
            r.ensure_exit_ready(),
            Err(UnbondNotReady::IntervalLogFull {
                count: MAX_BOND_BAD_INTERVALS,
                max: MAX_BOND_BAD_INTERVALS,
            })
        );
    }

    /// Epoch 0 is a real settlement epoch, and this is the refusal that proves
    /// the error reports the anchor it was given rather than a stand-in for it.
    ///
    /// The arm is only reachable for a served record, which invites deriving
    /// the epoch from that reasoning instead of carrying it — an `Option`
    /// unwrapped to its default. That renders a record served at epoch 0 and a
    /// record with no anchor at all as the same `0`, and the second is the
    /// *permissive* state: the message would name the absence of the condition
    /// that is in fact blocking the exit. So this asserts the rendering too,
    /// not just the variant — the collapse lives in the string, not the shape.
    #[test]
    fn a_record_served_at_epoch_zero_is_refused_by_its_own_anchor() {
        // Premise, from consensus's own predicate rather than restated here: an
        // exit at the very epoch a record served is inside the cooldown.
        assert!(
            !release_cooldown_elapsed(Some(0), 0),
            "premise: the serving epoch itself is not past the cooldown"
        );
        let mut r = ready();
        r.last_served = ServeAnchor::ServedAt(0);
        r.last_settled_slash = SlashWatermark::SettledThrough(0);
        r.current_settlement_epoch = 0;

        let err = r
            .ensure_exit_ready()
            .expect_err("a record inside its cooldown must be refused");
        assert_eq!(
            err,
            UnbondNotReady::CooldownNotElapsed {
                last_served: ServeAnchor::ServedAt(0),
                current_settlement_epoch: 0,
            }
        );
        let rendered = err.to_string();
        assert!(rendered.contains("last served epoch 0"), "{rendered}");
        assert!(
            !rendered.contains("never"),
            "a record served at epoch 0 must not read as never served: {rendered}"
        );
    }

    /// One epoch short of the boundary is refused; the boundary itself is not.
    /// Asserting both sides is what makes this a boundary test rather than a
    /// test that any old value fails.
    #[test]
    fn the_cooldown_boundary_is_refused_below_and_allowed_at() {
        let mut r = ready();
        // Both sides derived from the constant for the reason `ready()` gives:
        // the boundary is `anchor + RELEASE_COOLDOWN_EPOCHS`, and writing 5 and
        // 6 restates the genesis cooldown in a third place.
        let boundary = 4 + RELEASE_COOLDOWN_EPOCHS;
        r.current_settlement_epoch = boundary - 1;
        assert_eq!(
            r.ensure_exit_ready(),
            Err(UnbondNotReady::CooldownNotElapsed {
                last_served: ServeAnchor::ServedAt(4),
                current_settlement_epoch: boundary - 1,
            })
        );
        r.current_settlement_epoch = boundary;
        r.ensure_exit_ready()
            .expect("the boundary epoch itself is elapsed");
    }

    /// Slash settlement is a separate gate from the cooldown and is NOT implied
    /// by it: this record's cooldown has elapsed and it is still refused,
    /// because the scheduler has not folded the anchor epoch. That is the
    /// one-block connect-ordering race the second predicate closes.
    #[test]
    fn slash_settlement_is_checked_even_when_the_cooldown_has_elapsed() {
        let mut r = ready();
        r.last_settled_slash = SlashWatermark::SettledThrough(3);
        assert!(release_cooldown_elapsed(
            r.last_served.as_verify_operand(),
            r.current_settlement_epoch
        ));
        assert_eq!(
            r.ensure_exit_ready(),
            Err(UnbondNotReady::SlashSettlementPending {
                last_served: ServeAnchor::ServedAt(4),
                watermark: SlashWatermark::SettledThrough(3),
            })
        );
    }

    /// A watermark of "nothing settled yet" refuses a served record — the one
    /// operand whose absence is restrictive rather than permissive. A shared
    /// "absent" encoding across both anchors would have made this permissive by
    /// construction, which is why they are separate types.
    #[test]
    fn an_unsettled_scheduler_refuses_a_served_record() {
        let mut r = ready();
        r.last_settled_slash = SlashWatermark::NothingSettled;
        assert_eq!(
            r.ensure_exit_ready(),
            Err(UnbondNotReady::SlashSettlementPending {
                last_served: ServeAnchor::ServedAt(4),
                watermark: SlashWatermark::NothingSettled,
            })
        );
    }

    /// A never-served record exits immediately: both predicates are vacuous,
    /// and the watermark being absent does not matter because there is no
    /// anchor to cover. The permissive branch is correct when the daemon
    /// asserts it — the producer must not be fail-closed on a fact not in
    /// doubt.
    #[test]
    fn a_never_served_record_is_ready_regardless_of_the_watermark() {
        let mut r = ready();
        r.last_served = ServeAnchor::NeverServed;
        r.last_settled_slash = SlashWatermark::NothingSettled;
        r.current_settlement_epoch = 0;
        r.ensure_exit_ready()
            .expect("nothing served means nothing whose settlement an exit could outrun");
    }
}
