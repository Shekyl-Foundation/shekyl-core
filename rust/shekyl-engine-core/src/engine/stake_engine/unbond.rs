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

use shekyl_archival_bond_builder::{build_unbond_vin, UnbondVin};
use shekyl_archival_retention::bond_connect::MAX_BOND_BAD_INTERVALS;
use shekyl_archival_retention::release_cooldown::{
    release_cooldown_elapsed, slashes_settled_through,
};

use shekyl_types::PCanonicalId;

use crate::engine::emission_source::{ClaimSourceFor, ServeAnchor, SlashWatermark};

use super::actor::{persona_canonical_id, StakeEngine};
use super::types::*;

/// The record facts an exit's preconditions read, as the daemon reported them,
/// **bound to the persona they were read for**.
///
/// Fields are private and [`Self::from_claim_source`] is the only production
/// constructor, which takes one decoded [`EmissionClaimSource`] and the `P` it
/// was requested for. Two properties follow structurally rather than by
/// convention, and both matter on a path whose confirmation is irreversible:
///
/// - **One read view.** Every field comes from a single response, so
///   `bonded_total_atomic` and the cooldown anchor cannot straddle a block —
///   which would otherwise let readiness be computed on one view and the vin be
///   built against another.
/// - **One persona.** The id travels with the facts, so a caller cannot pair
///   persona A's balance and anchors with persona B's handle. Field-by-field
///   assembly is what would allow that, and it is not available.
///
/// [`ServeAnchor`] and [`SlashWatermark`] rather than `Option<u64>` on purpose.
/// Both consensus predicates treat an absent anchor as *permissive*, so a bare
/// `Option` reaching this struct could carry "the daemon says nothing served"
/// (correct, permissive) or "the field never arrived" (must be fail-closed) with
/// no way to tell them apart. The decoder makes the second unconstructible — an
/// absent field is a decode error — and these types carry that guarantee the
/// rest of the way.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UnbondRecordState {
    /// The persona these facts describe — checked against the handle's own
    /// derived id before anything is built for it.
    p_id: PCanonicalId,
    /// The record's current bonded balance; the exit's `bond_debit` by contract.
    bonded_total_atomic: u64,
    /// The record's interval-log length.
    bad_interval_count: usize,
    /// The whole-record release-cooldown anchor, folded by the daemon.
    last_served: ServeAnchor,
    /// The slash scheduler's monotone watermark.
    last_settled_slash: SlashWatermark,
    /// The settled epoch the daemon derived from its own tip.
    current_settlement_epoch: u64,
}

impl UnbondRecordState {
    /// Build from one [`ClaimSourceFor`] — the only production constructor.
    ///
    /// **Takes no `p_id` argument on purpose.** An earlier revision accepted the
    /// id and the response separately, which labels rather than binds: passing
    /// persona A's response with persona B's id produced A's facts wearing B's
    /// name, and the handler's equality check then agreed with the name. The id
    /// now arrives already fastened to the response by the code that sent the
    /// request, so the mismatched pair cannot be expressed here at all.
    ///
    /// `None` when the daemon holds no bond record for that `P`: there is no
    /// exit to assess, which the caller reports rather than treating as an
    /// error. Both the record facts and `current_settlement_epoch` come from
    /// this one response, so the settled epoch a refusal quotes is the epoch
    /// the anchors were read against.
    #[allow(dead_code)] // PR-P4 slice 2b: the tx-assembly path is its caller.
    pub(crate) fn from_claim_source(fetched: &ClaimSourceFor) -> Option<Self> {
        let source = fetched.source();
        let bond = source.bond.as_ref()?;
        Some(Self {
            p_id: fetched.p_id(),
            bonded_total_atomic: bond.bonded_total_atomic,
            bad_interval_count: bond.bad_interval_count,
            last_served: bond.last_served,
            last_settled_slash: bond.last_settled_slash,
            current_settlement_epoch: source.current_settled_epoch,
        })
    }

    /// The persona these facts describe.
    pub(crate) fn p_id(&self) -> PCanonicalId {
        self.p_id
    }

    /// The exit's `bond_debit` by contract — `verify_unbond_bond_post` requires
    /// the vin's debit to equal this exactly.
    pub(crate) fn bonded_total_atomic(&self) -> u64 {
        self.bonded_total_atomic
    }

    /// Refuse, with a named cause, if this record cannot support a full exit.
    ///
    /// Mirrors the verify arm's record-state checks in the same order, using the
    /// same predicates, so a refusal here and a rejection there cannot disagree
    /// about *why*.
    pub(crate) fn ensure_exit_ready(&self) -> Result<(), UnbondNotReady> {
        // FIRST, because it is first at the verifier: `NothingToUnbond` is
        // checked before the interval log, the cooldown, or the watermark
        // (`verify_unbond_bond_post` step 3). An earlier revision left this to
        // `build_unbond_vin` on the grounds that the builder consumes the
        // operand — true, and it does still check it as its own constructor
        // invariant. But deferring it here reordered the *reasons*: a
        // zero-balance record with a full interval log was refused as
        // `IntervalLogFull` while the chain would have said `NothingToUnbond`.
        // The whole point of running consensus's own predicates in consensus's
        // own order is that a wallet refusal and a chain rejection cannot
        // disagree about why, so the operand this struct already holds is
        // tested here too. The two checks cannot diverge: same field, same
        // comparison, no derivation between them.
        if self.bonded_total_atomic == 0 {
            return Err(UnbondNotReady::NothingToUnbond);
        }

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
/// Returns the witness only. The persona-bound transaction around it — funding,
/// outputs, the surface-A `pqc_auths` slot — is slice 2b, and is deliberately
/// not reachable from any RPC method or CLI verb until slice 3's regtest walk
/// has exercised the retire path end to end.
pub(crate) struct AssembleUnbond {
    /// Operation-scoped capability proving the slot is currently held.
    pub handle: PersonaHandle,
    /// The record facts, from one claim-source read view.
    pub record: UnbondRecordState,
}

impl Message<AssembleUnbond> for StakeEngine {
    /// The witness, not the bare vin: the invariants `build_unbond_vin`
    /// established travel to slice 2b's assembly rather than being asserted
    /// once and then forgotten at the actor boundary. `verify_debit_funding`
    /// is the consumer that requires them.
    type Reply = Result<UnbondVin, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: AssembleUnbond,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.validate_handle(&msg.handle)?;

        let keys = self
            .held
            .get(&msg.handle.p_slot)
            .expect("validate_handle confirmed the slot is held")
            .keys();

        // The handle and the record facts arrive as two independent values, so
        // BEFORE either is used, prove they describe the same persona. The
        // handle proves the slot is held; it says nothing about whose record
        // was read. Without this, a caller holding two claim-source responses
        // could pair persona A's balance and anchors with persona B's handle,
        // and the wallet would answer readiness from A's cooldown while
        // building B's post. The daemon would reject the result — but the
        // readiness answer would already have been wrong, and this path's
        // confirmation is an irreversible persona-key wipe.
        //
        // Derived from the resident keys rather than carried on the handle:
        // `persona_canonical_id` hashes the same canonical bytes an on-chain
        // bond-post carries, so this compares the id the chain will see.
        //
        // `a_record_read_for_another_persona_is_refused_at_the_actor` drives
        // this through the actor and goes red if the comparison is deleted. A
        // unit test on `UnbondRecordState` cannot cover it: the id it would
        // check is the one the test itself supplied, so the refusal has to be
        // observed where the two independent values actually meet.
        let handle_p_id = persona_canonical_id(keys)
            .map_err(|e| StakeEngineError::ScanSetup(ScanSetupError::CanonicalId(e)))?;
        if handle_p_id != msg.record.p_id() {
            return Err(StakeEngineError::RecordPersonaMismatch);
        }

        // Preconditions BEFORE construction: nothing is built for a record that
        // cannot exit, so a refusal never produces a post that could be
        // broadcast by a caller ignoring the error.
        msg.record.ensure_exit_ready()?;

        build_unbond_vin(keys.bond_post_keys(), msg.record.bonded_total_atomic())
            .map_err(StakeEngineError::BondBuild)
    }
}

#[cfg(test)]
mod tests {
    use shekyl_archival_retention::{
        HoldingsDescriptor, HoldingsKind, ShardSet, RELEASE_COOLDOWN_EPOCHS,
    };
    use shekyl_types::ChainCount;

    use crate::engine::emission_source::{BondContext, ClaimSourceFor, EmissionClaimSource};

    use super::super::test_fixtures::spawn_over;

    use super::*;

    /// The record-state arms are tested here as PRECONDITIONS, not as verifier
    /// behaviour. Driving `verify_unbond_bond_post` into `CooldownNotElapsed`
    /// would test consensus, which already covers itself; what is worth
    /// asserting on this side is that the producer refuses first, so the
    /// failure reaches the user at the wallet instead of at the chain.
    fn ready() -> UnbondRecordState {
        UnbondRecordState {
            p_id: PCanonicalId::from_bytes([7u8; 32]),
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

    /// The refusal ORDER is consensus's, not a convenient one — on the exact
    /// state where the two orders disagree.
    ///
    /// `verify_unbond_bond_post` checks `NothingToUnbond` (step 3) before
    /// `IntervalLogFull` (step 9). A record that is both zero-balance and
    /// interval-log-full satisfies both conditions, so it is the only input
    /// that can tell which order this function actually runs. Leaving the
    /// zero-balance check to the builder made this state report
    /// `IntervalLogFull` while the chain would say `NothingToUnbond` — a wallet
    /// and a chain disagreeing about why an irreversible operation was refused.
    ///
    /// The single-condition cases are asserted alongside, so a fix that
    /// reordered into a *different* wrong order would not pass.
    #[test]
    fn the_refusal_order_is_the_verifiers_where_two_conditions_both_hold() {
        let mut r = ready();
        r.bonded_total_atomic = 0;
        r.bad_interval_count = MAX_BOND_BAD_INTERVALS;
        assert_eq!(
            r.ensure_exit_ready(),
            Err(UnbondNotReady::NothingToUnbond),
            "both conditions hold; the verifier names the balance first"
        );

        // Each alone still names itself, so the ordering fix did not collapse
        // one arm into the other.
        let mut only_zero = ready();
        only_zero.bonded_total_atomic = 0;
        assert_eq!(
            only_zero.ensure_exit_ready(),
            Err(UnbondNotReady::NothingToUnbond)
        );
        let mut only_full = ready();
        only_full.bad_interval_count = MAX_BOND_BAD_INTERVALS;
        assert_eq!(
            only_full.ensure_exit_ready(),
            Err(UnbondNotReady::IntervalLogFull {
                count: MAX_BOND_BAD_INTERVALS,
                max: MAX_BOND_BAD_INTERVALS,
            })
        );
    }

    /// The handler refuses a record fetched for a different persona.
    ///
    /// This is the arm the constructor cannot cover. `ClaimSourceFor` proves the
    /// facts describe the persona they were *fetched* for; only the handler can
    /// prove that persona is the one whose *handle* is being spent, because the
    /// handle is a separate value arriving on the same message. Driving it
    /// through the actor is the only way the two meet.
    ///
    /// The positive control matters as much as the refusal: a record fetched for
    /// the handle's own persona must get **past** this check. Without it the test
    /// would still pass if the handler refused everything, which is the failure
    /// mode a binding check is most likely to have.
    #[tokio::test]
    async fn a_record_read_for_another_persona_is_refused_at_the_actor() {
        let slot = 3u32;
        let stake = spawn_over(&[slot], &[], Some(slot));
        let p_slot = PSlot::from_raw(slot);

        // A record that is ready in every respect EXCEPT whose persona it
        // describes, so a refusal can only be the binding check.
        let ready_source = || EmissionClaimSource {
            chain_height: ChainCount::from_raw(30001),
            current_settled_epoch: 4 + RELEASE_COOLDOWN_EPOCHS,
            bond: Some(BondContext {
                join_settlement_epoch: 1,
                holdings: HoldingsDescriptor {
                    kind: HoldingsKind::ShardSetCompact,
                    shard_ids: ShardSet::new(vec![4]).expect("one shard"),
                },
                claimed_settlement_epochs: vec![1],
                bonded_total_atomic: 3 * 750_000_000,
                bad_interval_count: 0,
                last_served: ServeAnchor::ServedAt(4),
                last_settled_slash: SlashWatermark::SettledThrough(4),
            }),
            epochs: vec![],
        };

        // Someone else's record, honestly fetched for THEM.
        let stranger = PCanonicalId::from_bytes([0xEE; 32]);
        let theirs = ClaimSourceFor::for_test(stranger, ready_source());
        let handle = stake.mint_handle(p_slot).await.expect("mint a handle");
        let err = stake
            .assemble_unbond(AssembleUnbond {
                handle,
                record: UnbondRecordState::from_claim_source(&theirs).expect("bond record"),
            })
            .await
            .expect_err("a record read for another persona must not build this exit");
        assert!(
            matches!(err, StakeEngineError::RecordPersonaMismatch),
            "expected RecordPersonaMismatch, got {err:?}"
        );

        // Positive control: the same record, fetched for THIS persona, clears
        // the binding check and assembles.
        let mine = stake
            .persona_canonical_id(p_slot)
            .await
            .expect("project this persona's canonical id");
        let ours = ClaimSourceFor::for_test(mine, ready_source());
        let handle = stake.mint_handle(p_slot).await.expect("mint a handle");
        let vin = stake
            .assemble_unbond(AssembleUnbond {
                handle,
                record: UnbondRecordState::from_claim_source(&ours).expect("bond record"),
            })
            .await
            .expect("this persona's own record assembles");
        assert_eq!(vin.vin().bond_debit, 3 * 750_000_000);
    }

    /// A record read for one persona cannot be spent through another's handle.
    ///
    /// The constructor is what makes this hard to get wrong — record facts and
    /// the settled epoch come from one response together — but the binding
    /// itself is the handler's equality check, because the handle is a separate
    /// value that arrives on the same message. This asserts the id survives
    /// construction so that check has something true to compare; the handler's
    /// refusal is exercised where the actor is driven.
    #[test]
    fn the_record_carries_the_persona_it_was_read_for() {
        let want = PCanonicalId::from_bytes([0xA5; 32]);
        let source = EmissionClaimSource {
            chain_height: ChainCount::from_raw(30001),
            current_settled_epoch: 3,
            bond: Some(BondContext {
                join_settlement_epoch: 1,
                holdings: HoldingsDescriptor {
                    kind: HoldingsKind::ShardSetCompact,
                    shard_ids: ShardSet::new(vec![4]).expect("one shard"),
                },
                claimed_settlement_epochs: vec![1],
                bonded_total_atomic: 2_250_000_000,
                bad_interval_count: 1,
                last_served: ServeAnchor::ServedAt(4),
                last_settled_slash: SlashWatermark::SettledThrough(4),
            }),
            epochs: vec![],
        };
        let fetched = ClaimSourceFor::for_test(want, source);
        let state = UnbondRecordState::from_claim_source(&fetched)
            .expect("the response carries a bond record");
        assert_eq!(state.p_id(), want);
        assert_ne!(state.p_id(), PCanonicalId::from_bytes([0x5A; 32]));
        // Every fact came from this one response, including the settled epoch
        // the anchors are judged against.
        assert_eq!(state.bonded_total_atomic(), 2_250_000_000);
        assert_eq!(state.bad_interval_count, 1);
        assert_eq!(state.current_settlement_epoch, 3);
    }

    /// No bond record is "nothing to assess", not an error: the caller reports
    /// it rather than refusing with a cause that would imply a record exists.
    #[test]
    fn a_response_without_a_bond_record_yields_no_state() {
        let source = EmissionClaimSource {
            chain_height: ChainCount::from_raw(30001),
            current_settled_epoch: 3,
            bond: None,
            epochs: vec![],
        };
        let fetched = ClaimSourceFor::for_test(PCanonicalId::from_bytes([1; 32]), source);
        assert!(UnbondRecordState::from_claim_source(&fetched).is_none());
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
