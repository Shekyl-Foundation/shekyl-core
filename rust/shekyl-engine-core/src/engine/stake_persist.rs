// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Persist-before-use for archival bond records — the [`PersistedBondTicket`]
//! typestate (typed contract #1, `ARCHIVAL_BOND_CONSTRUCTION.md` §10.2) and its
//! sole producer [`Engine::persist_bond_record`].
//!
//! # Why a typestate, not a discipline
//!
//! A bond's building persona must have its live-bond record durably committed
//! **before** the persona key signs the bond. The ordering is load-bearing:
//! under Model D the seed is gone after `assemble()`, so the bonded-union
//! derive-forward set is reconstructed at reopen *from the persisted record*. If
//! a crash lands between the sign and the persist, reopen reconstructs a set
//! that is **behind reality** and the building persona can fall out of the
//! derived set entirely — unreachable for the wallet's life, the bond
//! un-unbondable. Persist-before-use makes the only crash failure a *wasted
//! slot* (cursor ahead of chain — benign, slots are free), never a *lost* one.
//!
//! A two-line sign/persist reordering is invisible in review and catastrophic
//! in effect, so the ordering is lifted into the type system rather than left as
//! a comment: [`Engine::persist_bond_record`] returns a [`PersistedBondTicket`],
//! and 2c-2b's `sign_bond(ticket: PersistedBondTicket, ..)` *consumes* it. With
//! no other constructor, "sign before persist" has no expressible form — there
//! is no ticket to pass.
//!
//! # Why the ticket witnesses durability
//!
//! The only way to obtain a [`PersistedBondTicket`] is to call
//! [`Engine::persist_bond_record`], whose body goes through
//! [`PersistenceEngine::save_state`] → `shekyl-engine-file`'s `atomic_write_file`
//! (`tmp → fsync → rename → fsync(parent)`). The ticket therefore witnesses a
//! **durable, crash-atomic** commit, not merely an in-memory mutation — the
//! persist-before-use guarantee is downstream of the same write atomicity the
//! `LMDB_WRITE_ATOMICITY_AUDIT` lineage covers for every ledger block.
//!
//! # The cross-split seam
//!
//! This module *produces* the type (PR 2c-2a); the 2c-2b request path *consumes*
//! it. The contract between the two PRs is a Rust type the consumer cannot
//! forge, not a convention it has to remember. Inert until 2c-2b wires the
//! consumer, so the producer carries `#[allow(dead_code)]`.

use shekyl_engine_state::StakingBlock;

use super::error::PersistenceError;
use super::lifecycle::drive_persistence;
use super::stake_engine::PSlot;
use super::traits::PersistenceEngine;
use super::{Engine, EngineSignerKind, LocalLedger};

/// Proof that an archival bond's per-persona live-bond record was **durably
/// persisted** for a specific persona slot (typed contract #1).
///
/// Minted only by [`Engine::persist_bond_record`] after a successful
/// crash-atomic `save_state`; the field is module-private and there is no other
/// constructor, so a ticket cannot exist without the durable commit having
/// happened. Consumed **by value** by 2c-2b's `sign_bond`, so one persist
/// authorizes one sign — persist-before-use, enforced structurally.
///
/// Deliberately **not** `Clone`: a ticket is single-use evidence of one commit;
/// duplicating it would let one persist authorize two signs (mirrors the
/// `AllKeysBlob` Not-Clone discipline, `21-reversion-clause-discipline.mdc`).
/// Reopen this only if a 2c-2b caller provably needs to re-sign the *same*
/// already-persisted record, with documented justification.
#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)] // inert until 2c-2b consumes it via sign_bond
pub(crate) struct PersistedBondTicket {
    /// The persona slot whose live-bond record this ticket witnesses. Bound so
    /// 2c-2b's `sign_bond` can assert the ticket matches the persona being
    /// signed (a ticket for slot A cannot authorize a sign for slot B).
    p_slot: PSlot,
}

#[allow(dead_code)] // inert until 2c-2b consumes it via sign_bond
impl PersistedBondTicket {
    /// The persona slot this ticket was minted for.
    #[must_use]
    pub(crate) fn p_slot(&self) -> PSlot {
        self.p_slot
    }

    /// Test-only ticket constructor for negative-control tests that need a
    /// ticket without going through the real `Engine::persist_bond_record`
    /// path (e.g. slot-mismatch tests that need a ticket for a specific slot
    /// that was never actually persisted).
    ///
    /// **Must not be used in production paths.** The name is intentionally
    /// awkward to prevent accidental use: a legitimate caller always goes
    /// through `persist_bond_record`.
    #[cfg(test)]
    pub(crate) fn __test_only_forge(p_slot: PSlot) -> Self {
        Self { p_slot }
    }
}

// `D: DaemonEngine` / `L = LocalLedger` / `R = LocalRefresh` specialization
// mirrors `Engine::close` (see `lifecycle.rs`): the persist path acquires a
// `LocalLedger` write guard to mutate the `StakingBlock`, then a read guard to
// hand `&WalletLedger` to `save_state`, exactly as `close` does for the final
// flush. The trait surface does not yet expose a borrowed-state mutation
// accessor (Stage 4 design space).
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: super::traits::DaemonEngine,
        E: super::traits::EconomicsEngine,
        P: super::traits::PendingTxEngine,
        F: PersistenceEngine,
    > Engine<S, D, LocalLedger, E, super::LocalRefresh, P, F>
{
    /// Durably commit the live-bond record for persona `slot`, returning the
    /// [`PersistedBondTicket`] that 2c-2b's `sign_bond` consumes.
    ///
    /// Records `slot` in [`StakingBlock::bonded_slots`] (idempotent — a repeat
    /// of an already-recorded slot is a no-op on the set), flips
    /// `staking_enabled` on (a wallet that holds a bond *must* re-derive that
    /// persona at the next `assemble()`, which `staking_enabled` gates), and
    /// advances the persona cursor to the scan-reconciled monotone value
    /// ([`StakingBlock::monotone_current_slot_from_record`]) so the persisted
    /// cursor never sits at or below a bonded slot — the privacy guard against
    /// re-activating a rotated-past persona.
    ///
    /// The mutation commits to the in-memory ledger under a write guard, which
    /// is dropped before the read-guarded `save_state` (the two guards are on
    /// the same `RwLock`; holding the write guard across the save would
    /// deadlock). On `Ok`, the record is durably on disk (`atomic_write_file`),
    /// so the returned ticket witnesses a crash-atomic commit.
    ///
    /// # Errors
    ///
    /// [`PersistenceError`] if the durable `save_state` fails; in that case **no
    /// ticket is produced**, so the caller cannot proceed to sign — persist
    /// failure fails the operation closed, never open.
    #[allow(dead_code)] // inert until 2c-2b consumes the ticket via sign_bond
    pub(crate) fn persist_bond_record(
        &self,
        slot: PSlot,
    ) -> Result<PersistedBondTicket, PersistenceError> {
        // Mutate the staking block under a scoped write guard, then drop it
        // before saving (same lock; write-then-read would deadlock).
        {
            let mut guard = self.ledger.write();
            let staking: &mut StakingBlock = &mut guard.ledger.staking;
            staking.staking_enabled = true;
            let index = slot.index();
            if !staking.bonded_slots.contains(&index) {
                staking.bonded_slots.push(index);
            }
            // Monotone-forward: cursor never at/below an observed bonded slot.
            staking.p_slot = staking.monotone_current_slot_from_record();
        }

        // Durable, crash-atomic write — the property the ticket witnesses.
        let ledger_guard = self.ledger.read();
        drive_persistence(
            self.persistence
                .save_state(self.state_wrap_key(), &ledger_guard.ledger),
        )
        .map_err(Into::into)?;
        drop(ledger_guard);

        Ok(PersistedBondTicket { p_slot: slot })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_address::Network;
    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_engine_file::SafetyOverrides;
    use shekyl_rpc_transport::SimpleRequestRpc;
    use tempfile::tempdir;

    use crate::engine::{Credentials, DaemonClient, EngineCreateParams, OpenedEngine, SoloSigner};

    /// A `DaemonClient` against a never-resolved URL. The persist path issues no
    /// RPC; the daemon is held only to build the `Engine`. Mirrors the bridge in
    /// `lifecycle.rs`'s `dummy_daemon` (sync body → async ctor via the ambient
    /// multi-thread runtime), which is why every test here is `multi_thread`.
    fn dummy_daemon() -> DaemonClient {
        let rpc = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(SimpleRequestRpc::new("http://127.0.0.1:1".to_string()))
        })
        .expect("construct SimpleRequestRpc (no actual connection attempted)");
        DaemonClient::new(rpc)
    }

    fn fixed_seed() -> [u8; MASTER_SEED_BYTES] {
        let mut s = [0u8; MASTER_SEED_BYTES];
        for (i, b) in s.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(7);
        }
        s
    }

    /// The ticket witnesses a durable commit, not an in-memory mutation: a record
    /// persisted, then closed and reopened through the real
    /// seal → `atomic_write_file` → read path, is still present with the cursor
    /// advanced monotonically past the bonded slot. Also covers idempotency (a
    /// repeat persist of the same slot neither duplicates the slot nor moves the
    /// cursor).
    #[tokio::test(flavor = "multi_thread")]
    async fn persist_bond_record_commits_durably_and_survives_reopen() {
        let tmp = tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let password: &[u8] = b"correct horse battery staple";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let network: Network = params.network;
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

        // A fresh wallet stakes nothing.
        {
            let g = engine.ledger.read();
            assert!(!g.ledger.staking.staking_enabled);
            assert!(g.ledger.staking.bonded_slots.is_empty());
            assert_eq!(g.ledger.staking.p_slot, 0);
        }

        let slot = PSlot(7);
        let ticket = engine
            .persist_bond_record(slot)
            .expect("persist bond record");
        assert_eq!(ticket.p_slot(), slot);

        // In-memory effect: enabled, slot recorded, cursor monotone-advanced past it.
        {
            let g = engine.ledger.read();
            assert!(g.ledger.staking.staking_enabled);
            assert_eq!(g.ledger.staking.bonded_slots, vec![7]);
            assert_eq!(g.ledger.staking.p_slot, 8); // max(0, 7 + 1)
        }

        // Idempotent: re-persisting the same slot is a no-op on the set and cursor.
        let ticket_again = engine
            .persist_bond_record(slot)
            .expect("re-persist same slot");
        assert_eq!(ticket_again.p_slot(), slot);
        {
            let g = engine.ledger.read();
            assert_eq!(g.ledger.staking.bonded_slots, vec![7]);
            assert_eq!(g.ledger.staking.p_slot, 8);
        }

        engine.close(&creds).expect("close created wallet");

        // Durability: the record survives a real seal → write → read round trip.
        let opened = Engine::<SoloSigner>::open_full(
            &base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen FULL wallet");
        assert!(
            matches!(opened, OpenedEngine::Loaded(_)),
            "expected loaded state"
        );
        let reopened = opened.into_wallet();

        let g = reopened.ledger.read();
        assert!(g.ledger.staking.staking_enabled);
        assert_eq!(g.ledger.staking.bonded_slots, vec![7]);
        assert_eq!(g.ledger.staking.p_slot, 8);
    }

    /// The persist→reopen seam wires Model D end to end: a fresh wallet is a
    /// non-staker (no actor), and after a bond record is persisted, reopen
    /// spawns the `StakeEngine` over exactly `{bonded} ∪ {cursor ..= cursor+k}`
    /// — the bonded slot held for unbonding, the lookahead window held for
    /// in-session rotation, and nothing outside it.
    #[tokio::test(flavor = "multi_thread")]
    async fn staker_reopen_spawns_stake_engine_over_bonded_union_lookahead() {
        use crate::engine::stake_engine::{StakeEngineError, ARCHIVAL_PERSONA_LOOKAHEAD};

        let tmp = tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let password: &[u8] = b"correct horse battery staple";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let network: Network = params.network;
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

        // A fresh wallet is not a staker: no actor, no derived personas.
        assert!(engine.stake.is_none(), "non-staker spawns no StakeEngine");

        // Become a staker at slot 3; the cursor advances to max(0, 3 + 1) = 4.
        engine
            .persist_bond_record(PSlot(3))
            .expect("persist bond record");
        engine.close(&creds).expect("close created wallet");

        let opened = Engine::<SoloSigner>::open_full(
            &base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen FULL wallet");
        assert!(
            matches!(opened, OpenedEngine::Loaded(_)),
            "expected loaded state"
        );
        let reopened = opened.into_wallet();

        let stake = reopened
            .stake
            .as_ref()
            .expect("a staker reopen spawns a StakeEngine");

        // The bonded slot is held — reachable for unbonding after the seed is gone.
        stake
            .mint_handle(PSlot(3))
            .await
            .expect("bonded slot 3 is held");

        // The full lookahead window from the cursor is held.
        let cursor = 4u32;
        for offset in 0..=ARCHIVAL_PERSONA_LOOKAHEAD {
            stake
                .mint_handle(PSlot(cursor + offset))
                .await
                .unwrap_or_else(|e| panic!("cursor+{offset} must be held, got {e:?}"));
        }

        // One slot past the window is not held — a real domain state (reopen to extend).
        let beyond = cursor + ARCHIVAL_PERSONA_LOOKAHEAD + 1;
        assert!(
            matches!(
                stake.mint_handle(PSlot(beyond)).await,
                Err(StakeEngineError::LookaheadExhausted { .. })
            ),
            "slot beyond the lookahead window must not be held"
        );

        // A slot below the cursor that is not bonded is not held either.
        assert!(
            matches!(
                stake.mint_handle(PSlot(2)).await,
                Err(StakeEngineError::LookaheadExhausted { .. })
            ),
            "an unbonded slot below the cursor must not be held"
        );
    }
}
