// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persona's **resident** `SF-D13` countersignature key — the SH-2
//! remainder.
//!
//! `shekyl-p-serve` needs one thing from the persona: a signature over the
//! 112-byte pass transcript under `SCHEME_DOMAIN_ATTESTATION`, per served
//! shard. The key that produces it is the bond identity key
//! (`ArchivalPKeys::hybrid_sign_sk`), which under Model D lives inside the
//! stake actor and is wiped with it. [`ResidentPassKey`] is the serving
//! role's view of that key, and it is deliberately **not** a key: it holds a
//! non-owning handle to the actor and a slot, and every `sign_pass` is a
//! message round-trip in which only the transcript goes in and only the
//! signature comes out (`SH2_RESIDENT_KEY_AUDIT.md` §3 Q1).
//!
//! Two properties follow from the handle being weak:
//!
//! - **The serving role cannot extend the secret's life.** The actor stops
//!   when the engine drops its last strong `ActorRef`; a live serving task
//!   holding this key does not keep the persona bundles resident past the
//!   close that was meant to wipe them.
//! - **`ready` is actor liveness** (Q2). The signing capability can go away
//!   while the listener is up in exactly one way — the actor fail-stopped
//!   after a handler panic — and that case is now the shared pre-flight 503
//!   (`sign_failures`), not a distinguishable truncated 200. The late
//!   refusal trailer (`late_sign_failures`) is reserved for a fault at sign
//!   time: the actor went away between pre-flight and sign, or the scheme
//!   rejected the key material.
//!
//! In the production close order the question does not arise: the wallet
//! tenant shuts the serving task down (awaited) before it drops the engine,
//! so serving life ⊂ actor life. The weak handle makes that true by
//! construction wherever the order is not controlled.

use std::sync::Arc;

use shekyl_archival_retention::PASS_COUNTERSIGNATURE_MESSAGE_LEN;
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_p_host::{PassKey, SignRefused};
use shekyl_types::BlockHeight;

use crate::engine::stake_engine::handle::{StakeEngineHandle, WeakStakeEngineHandle};
use crate::engine::stake_engine::types::{PSlot, StakeEngineError};

/// The serving role's view of the active persona's bond identity key.
///
/// Constructed once per serving start by `start_serving_if_staker`, bound to
/// the slot that was active at that moment. There is no production re-key
/// path (`activate_persona` has no production caller), so a slot that stops
/// being held while the host runs is a wallet close, and the key observes it
/// as a refusal.
pub(crate) struct ResidentPassKey {
    stake: WeakStakeEngineHandle,
    p_slot: PSlot,
}

impl ResidentPassKey {
    pub(crate) fn new(stake: &StakeEngineHandle, p_slot: PSlot) -> Arc<Self> {
        Arc::new(Self {
            stake: stake.downgrade(),
            p_slot,
        })
    }

    fn live_handle(&self) -> Result<StakeEngineHandle, SignRefused> {
        self.stake
            .upgrade()
            .ok_or_else(|| SignRefused::new(StakeEngineError::StakeActorUnavailable.to_string()))
    }
}

impl PassKey for ResidentPassKey {
    /// The anchor gate is the host's (`HostSigner`, over the daemon tip); this
    /// key's pre-flight is only whether the actor that holds the secret is
    /// alive. The shard and anchor are not consulted: the persona's key does
    /// not vary by shard, and a slot-level refusal (`LookaheadExhausted`)
    /// surfaces at sign time because it costs a round-trip to ask.
    fn ready(&self, _shard_id: u64, _anchor_height: BlockHeight) -> Result<(), SignRefused> {
        self.live_handle().map(drop)
    }

    /// Runs on the blocking pool (`shekyl-p-serve` wraps it in
    /// `spawn_blocking`), so the parked wait on the actor's reply is
    /// legitimate here and nowhere else.
    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        self.live_handle()?
            .sign_pass_transcript_blocking(self.p_slot, *message)
            .map_err(|e| SignRefused::new(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_archival_retention::{pass_countersignature_message, verify_pass_transcript};

    use crate::engine::stake_engine::types::PersonaIdentity;
    use crate::engine::test_support::{activate_persona, staker_engine};
    use crate::engine::{Engine, SoloSigner};

    const SLOT: u32 = 3;
    const SHARD: u64 = 7;
    const ANCHOR: BlockHeight = BlockHeight::from_raw(1_000);
    const NONCE: [u8; 32] = [0x11; 32];
    const ANCHOR_HASH: [u8; 32] = [0x22; 32];
    const DIGEST: [u8; 32] = [0x5a; 32];

    fn message() -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
        pass_countersignature_message(&NONCE, ANCHOR, &ANCHOR_HASH, SHARD, &DIGEST)
    }

    async fn active_staker() -> (
        tempfile::TempDir,
        Engine<SoloSigner>,
        StakeEngineHandle,
        PersonaIdentity,
    ) {
        let (tmp, engine) = staker_engine(SLOT, 7);
        activate_persona(&engine, SLOT).await;
        let stake = engine.stake_handle().expect("staker has a StakeEngine");
        let active = stake
            .active_persona()
            .await
            .expect("ask")
            .expect("persona active");
        (tmp, engine, stake, active)
    }

    /// The production call graph for one shard: the key signs on the blocking
    /// pool, and the signature verifies against the persona's **bond
    /// identity** — the key the bond record publishes — not against any key
    /// the serving role holds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn signs_under_the_bond_identity_key() {
        let (_tmp, _engine, stake, active) = active_staker().await;
        let key = ResidentPassKey::new(&stake, active.p_slot);

        key.ready(SHARD, ANCHOR).expect("actor alive → ready");

        let signature = tokio::task::spawn_blocking(move || key.sign_pass(&message()))
            .await
            .expect("blocking task")
            .expect("held slot signs");

        verify_pass_transcript(
            &active.bond_id,
            &NONCE,
            ANCHOR,
            &ANCHOR_HASH,
            SHARD,
            &DIGEST,
            &signature,
        )
        .expect("verifies under bond_id");
    }

    /// An unheld slot refuses at sign time, with the slot-boundary error the
    /// rest of the actor uses, and the refusal is a `SignRefused` (the host's
    /// late-refusal trailer), not a panic and not a signature.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unheld_slot_refuses() {
        let (_tmp, _engine, stake, active) = active_staker().await;
        let unheld = PSlot::from_raw(active.p_slot.to_raw() + 1_000);
        let key = ResidentPassKey::new(&stake, unheld);

        // `ready` is liveness only — the slot question is asked at sign time.
        key.ready(SHARD, ANCHOR).expect("actor alive → ready");

        let refused = tokio::task::spawn_blocking(move || key.sign_pass(&message()))
            .await
            .expect("blocking task")
            .expect_err("unheld slot refuses");
        assert!(
            refused.detail.contains("lookahead exhausted"),
            "refusal names the slot boundary: {refused}"
        );
    }

    /// The Q2 ruling: once the actor is gone the key reports it at the
    /// pre-flight, and the serving role never kept it alive — the key held
    /// only a weak handle, so dropping the engine (the last strong owner)
    /// stops the actor even while the key is still held.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actor_stop_is_observed_not_prevented() {
        let (_tmp, engine, stake, active) = active_staker().await;
        let key = ResidentPassKey::new(&stake, active.p_slot);
        key.ready(SHARD, ANCHOR).expect("actor alive → ready");

        drop(stake);
        drop(engine);
        // Actor stop is asynchronous to the last drop; wait for the mailbox
        // to close rather than for a fixed interval.
        for _ in 0..500 {
            if key.ready(SHARD, ANCHOR).is_err() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let refused = key
            .ready(SHARD, ANCHOR)
            .expect_err("stopped actor → refused");
        assert!(
            refused.detail.contains("stake engine unavailable"),
            "refusal names the recovery action: {refused}"
        );
        tokio::task::spawn_blocking(move || key.sign_pass(&message()))
            .await
            .expect("blocking task")
            .expect_err("stopped actor → sign refused");
    }
}
