// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **STAGED** — the persona's resident **receipt key** as a signing
//! capability: Ed25519 + FN-DSA-1024, hybrid scheme 3, under
//! `SCHEME_DOMAIN_RECEIPT` (`FN_DSA_HYBRID.md` §6, increment 4).
//!
//! # Disposition (rule 23)
//!
//! - **What is here.** [`ResidentReceiptKey`], the receipt-key counterpart of
//!   [`ResidentPassKey`](super::pass_key::ResidentPassKey), with the actor
//!   message behind it (`SignReceiptTranscript`) and the key the actor holds
//!   decoded for it (`HeldReceiptKey`). Built and tested.
//! - **What selects it.** Nothing. The serving task is started with
//!   [`ResidentPassKey`](super::pass_key::ResidentPassKey), which signs with
//!   the bond identity key under hybrid scheme 1, exactly as before this
//!   module existed. No production code constructs a [`ResidentReceiptKey`].
//! - **Who switches.** The settlement lane's cutover: the change that makes
//!   a verifier accept scheme-3 receipts (the bundle verifier) is the change
//!   that hands this capability to the serving task. A persona that signed
//!   with the receipt key before a verifier accepted it would be serving
//!   shards whose countersignature every requester rejects.
//! - **Falsifier.** `serving/start.rs` handing the serving task this
//!   capability while no verifier accepts a scheme-3 receipt. Held by
//!   `the_serving_task_is_not_started_with_the_receipt_key`, which reads
//!   that file, and by the `expect(dead_code)` on this type's methods: a
//!   production caller makes the expectation unfulfilled and the lint lane
//!   fails.
//!
//! # Why it is not a `PassKey`
//!
//! The serving route's signer trait returns the scheme-1 signature by type
//! (`shekyl_p_host::PassKey::sign_pass -> HybridSignature`), and the
//! response envelope's width is that signature's canonical length
//! (`shekyl_p_serve::SIGNATURE_ENVELOPE_LEN`, 3,385 bytes). A scheme-3
//! signature is another type and 1,356 bytes. Fitting this capability to the
//! trait means changing the trait, its implementors and the envelope on both
//! ends of the wire, and that is the cutover. So this type has the trait's
//! two methods as inherent methods — the same names' shape, the same
//! arguments, the same refusal type — and no trait implementation. The
//! cutover generalizes the trait and this becomes an implementor of it.
//!
//! # What it is
//!
//! [`ResidentPassKey`](super::pass_key::ResidentPassKey)'s shape, for its
//! reasons. It is not a key: it holds a non-owning handle to the stake actor
//! and a slot. A signature is a message round-trip in which the 112-byte
//! transcript goes in and the signature comes out. The handle is weak, so
//! this role cannot keep the persona's secrets resident past the wallet
//! close that wipes them, and a stopped actor is a refusal at pre-flight.
//!
//! The decoded receipt key — 118,640 bytes of secret basis and working
//! buffers — lives in the actor beside the bundle it was decoded from, and
//! is wiped with it. Nothing of it reaches this type.

use std::sync::Arc;

use shekyl_archival_retention::PASS_COUNTERSIGNATURE_MESSAGE_LEN;
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridSignature;
use shekyl_p_host::SignRefused;
use shekyl_types::BlockHeight;

use crate::engine::stake_engine::handle::{StakeEngineHandle, WeakStakeEngineHandle};
use crate::engine::stake_engine::types::{PSlot, StakeEngineError};

/// The serving role's view of a persona's receipt key. STAGED: see the
/// module.
pub(crate) struct ResidentReceiptKey {
    stake: WeakStakeEngineHandle,
    p_slot: PSlot,
}

// The one marker for the whole staged chain. The compiler treats an item
// under a dead-code expectation as a root, so the type above, the actor
// message and the handle method these methods reach are not reported on
// their own and carry no marker. When a production caller appears, this
// expectation is unfulfilled and the lint lane fails until it is removed.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "STAGED (rule 23): no production caller until the settlement lane's cutover"
    )
)]
impl ResidentReceiptKey {
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

    /// Whether the actor that holds the key is alive — `PassKey::ready`'s
    /// contract and [`ResidentPassKey`](super::pass_key::ResidentPassKey)'s
    /// answer. The shard and anchor are not consulted, and a slot-level
    /// refusal surfaces at sign time.
    ///
    /// # Errors
    ///
    /// [`SignRefused`] when the stake actor has stopped.
    pub(crate) fn ready(
        &self,
        _shard_id: u64,
        _anchor_height: BlockHeight,
    ) -> Result<(), SignRefused> {
        self.live_handle().map(drop)
    }

    /// Sign the 112-byte pass transcript with the persona's receipt key.
    ///
    /// Blocking, as `PassKey::sign_pass` is: it parks on the actor's reply
    /// and belongs on the blocking pool.
    ///
    /// # Errors
    ///
    /// [`SignRefused`] when the actor has stopped, the slot is not held, or
    /// the scheme refused the key material.
    pub(crate) fn sign_receipt(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<FnDsaHybridSignature, SignRefused> {
        self.live_handle()?
            .sign_receipt_transcript_blocking(self.p_slot, *message)
            .map_err(|e| SignRefused::new(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_archival_retention::{pass_countersignature_message, verify_pass_transcript};
    use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridPublicKey, HybridEd25519FnDsa};
    use shekyl_crypto_pq::signature::{
        HybridSignature, SignatureScheme, SCHEME_DOMAIN_ATTESTATION, SCHEME_DOMAIN_RECEIPT,
        SCHEME_DOMAIN_WITNESS_CARRIER,
    };
    use shekyl_p_host::PassKey;

    use crate::engine::stake_engine::serving::pass_key::ResidentPassKey;
    use crate::engine::stake_engine::test_fixtures::{derive_bundle, spawn_over};

    const SLOT: u32 = 3;
    const OTHER_SLOT: u32 = 4;
    const SHARD: u64 = 7;
    const ANCHOR: BlockHeight = BlockHeight::from_raw(1_000);
    const NONCE: [u8; 32] = [0x11; 32];
    const ANCHOR_HASH: [u8; 32] = [0x22; 32];
    const DIGEST: [u8; 32] = [0x5a; 32];

    /// A real transcript, from the consensus builder both ends agree on.
    fn message() -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
        pass_countersignature_message(&NONCE, ANCHOR, &ANCHOR_HASH, SHARD, &DIGEST)
    }

    /// The persona's public receipt key, from the derivation oracle the
    /// actor's bundles came from. The actor is not asked: it has no message
    /// that gives the key out, and none is added for a test.
    fn receipt_pk(slot: u32) -> FnDsaHybridPublicKey {
        derive_bundle(slot).receipt_sign_pk.clone()
    }

    fn slot(raw: u32) -> PSlot {
        PSlot::from_raw(raw)
    }

    async fn sign(
        key: Arc<ResidentReceiptKey>,
        message: [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<FnDsaHybridSignature, SignRefused> {
        tokio::task::spawn_blocking(move || key.sign_receipt(&message))
            .await
            .expect("blocking task")
    }

    /// Through the actor: a signature over a real transcript verifies under
    /// the persona's receipt key with scheme 3 and the receipt domain, and
    /// under nothing else — not another domain, not another transcript, and
    /// not as an identity signature.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn signs_under_the_receipt_key_and_the_receipt_domain() {
        let stake = spawn_over(&[SLOT, OTHER_SLOT], &[SLOT], Some(SLOT));
        let key = ResidentReceiptKey::new(&stake, slot(SLOT));
        key.ready(SHARD, ANCHOR).expect("actor alive → ready");

        let signature = sign(key, message()).await.expect("held slot signs");
        let public = receipt_pk(SLOT);
        let scheme = HybridEd25519FnDsa;
        scheme
            .verify(&public, SCHEME_DOMAIN_RECEIPT, &message(), &signature)
            .expect("verifies under receipt_sign_pk and the receipt domain");

        // The canonical scheme-3 signature, at its specified length.
        let bytes = signature.to_canonical_bytes();
        assert_eq!(bytes.len(), FnDsaHybridSignature::CANONICAL_LEN);
        assert_eq!(bytes.len(), 1_356);

        // Not under another domain: the identity key's, or the other
        // scheme-3 surface's.
        for other in [SCHEME_DOMAIN_ATTESTATION, SCHEME_DOMAIN_WITNESS_CARRIER] {
            assert!(scheme
                .verify(&public, other, &message(), &signature)
                .is_err());
        }
        // Not over another transcript.
        let other_shard =
            pass_countersignature_message(&NONCE, ANCHOR, &ANCHOR_HASH, SHARD + 1, &DIGEST);
        assert!(scheme
            .verify(&public, SCHEME_DOMAIN_RECEIPT, &other_shard, &signature)
            .is_err());
    }

    /// The receipt signature is not an identity signature and the identity
    /// signature is not a receipt. The types already say so — the identity
    /// verifier takes a `HybridSignature` and cannot be handed this one — so
    /// what is left to hold is the bytes: neither signature parses as the
    /// other scheme's, and the identity key's own signature over the same
    /// transcript still verifies under the bond identity, untouched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_receipt_is_not_an_identity_signature() {
        let stake = spawn_over(&[SLOT], &[SLOT], Some(SLOT));
        let receipt = sign(ResidentReceiptKey::new(&stake, slot(SLOT)), message())
            .await
            .expect("receipt key signs");
        let identity_key = ResidentPassKey::new(&stake, slot(SLOT));
        let identity = tokio::task::spawn_blocking(move || identity_key.sign_pass(&message()))
            .await
            .expect("blocking task")
            .expect("identity key signs");

        let receipt_bytes = receipt.to_canonical_bytes();
        let identity_bytes = identity.to_canonical_bytes().expect("canonical");
        assert!(HybridSignature::from_canonical_bytes(&receipt_bytes).is_err());
        assert!(FnDsaHybridSignature::from_canonical_bytes(&identity_bytes).is_err());
        assert_eq!(identity_bytes.len(), shekyl_p_serve_envelope_len());
        assert_ne!(receipt_bytes.len(), shekyl_p_serve_envelope_len());

        // The live signer is what it was: the identity key, scheme 1, the
        // attestation domain, verified by the consensus verifier.
        let bundle = derive_bundle(SLOT);
        verify_pass_transcript(
            bundle.hybrid_bond_id(),
            &NONCE,
            ANCHOR,
            &ANCHOR_HASH,
            SHARD,
            &DIGEST,
            &identity,
        )
        .expect("the identity signature verifies under bond_id");
    }

    /// The serving route's envelope width: the scheme-1 signature's
    /// canonical length. A receipt does not fit it, which is why this
    /// capability is not on the route (module docs).
    fn shekyl_p_serve_envelope_len() -> usize {
        HybridSignature::CANONICAL_LEN
    }

    /// Two personas' capabilities are not interchangeable: each signs with
    /// its own slot's key, and neither signature verifies under the other
    /// persona's public key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_personas_do_not_sign_for_each_other() {
        let stake = spawn_over(&[SLOT, OTHER_SLOT], &[SLOT], Some(SLOT));
        let here = sign(ResidentReceiptKey::new(&stake, slot(SLOT)), message())
            .await
            .expect("signs");
        let there = sign(ResidentReceiptKey::new(&stake, slot(OTHER_SLOT)), message())
            .await
            .expect("signs");

        let scheme = HybridEd25519FnDsa;
        let (pk_here, pk_there) = (receipt_pk(SLOT), receipt_pk(OTHER_SLOT));
        assert_ne!(pk_here, pk_there);
        scheme
            .verify(&pk_here, SCHEME_DOMAIN_RECEIPT, &message(), &here)
            .expect("own key");
        scheme
            .verify(&pk_there, SCHEME_DOMAIN_RECEIPT, &message(), &there)
            .expect("own key");
        assert!(scheme
            .verify(&pk_here, SCHEME_DOMAIN_RECEIPT, &message(), &there)
            .is_err());
        assert!(scheme
            .verify(&pk_there, SCHEME_DOMAIN_RECEIPT, &message(), &here)
            .is_err());
    }

    /// One held key, many receipts: every signature verifies and no two are
    /// alike. The actor decoded the key once, when it took the persona in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_held_key_signs_many_receipts() {
        let stake = spawn_over(&[SLOT], &[SLOT], Some(SLOT));
        let key = ResidentReceiptKey::new(&stake, slot(SLOT));
        let public = receipt_pk(SLOT);
        let mut seen = Vec::new();
        for _ in 0..8 {
            let signature = sign(Arc::clone(&key), message()).await.expect("signs");
            HybridEd25519FnDsa
                .verify(&public, SCHEME_DOMAIN_RECEIPT, &message(), &signature)
                .expect("verifies");
            let bytes = signature.to_canonical_bytes();
            assert!(!seen.contains(&bytes), "each receipt draws a fresh seed");
            seen.push(bytes);
        }
    }

    /// An unheld slot refuses at sign time with the slot-boundary error, as
    /// the identity capability does — and with the same refusal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unheld_slot_refuses_as_the_identity_key_does() {
        let stake = spawn_over(&[SLOT], &[SLOT], Some(SLOT));
        let unheld = slot(SLOT + 1_000);
        let key = ResidentReceiptKey::new(&stake, unheld);
        // `ready` is liveness only — the slot question is asked at sign time.
        key.ready(SHARD, ANCHOR).expect("actor alive → ready");

        let refused = sign(key, message()).await.expect_err("unheld slot refuses");
        assert!(
            refused.detail.contains("lookahead exhausted"),
            "refusal names the slot boundary: {refused}"
        );

        let identity_key = ResidentPassKey::new(&stake, unheld);
        let identity_refused =
            tokio::task::spawn_blocking(move || identity_key.sign_pass(&message()))
                .await
                .expect("blocking task")
                .expect_err("unheld slot refuses");
        assert_eq!(refused, identity_refused);
    }

    /// The decoded key's life is the persona's. Activating the next slot
    /// wipes the retired ephemeral persona, and the receipt key goes with
    /// it: there is no second place it is held.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wiped_persona_takes_its_receipt_key_with_it() {
        let stake = spawn_over(&[SLOT, OTHER_SLOT], &[], Some(SLOT));
        let key = ResidentReceiptKey::new(&stake, slot(SLOT));
        sign(Arc::clone(&key), message())
            .await
            .expect("held → signs");

        let handle = stake.mint_handle(slot(OTHER_SLOT)).await.expect("mint");
        stake.activate_persona(handle).await.expect("activate");

        let refused = sign(key, message())
            .await
            .expect_err("the retired ephemeral slot was wiped");
        assert!(refused.detail.contains("lookahead exhausted"), "{refused}");
    }

    /// Once the actor is gone the capability reports it at the pre-flight
    /// and at sign time, with the typed refusal the identity capability
    /// returns — and it never kept the actor alive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actor_stop_is_observed_not_prevented() {
        let stake = spawn_over(&[SLOT], &[SLOT], Some(SLOT));
        let key = ResidentReceiptKey::new(&stake, slot(SLOT));
        let identity_key = ResidentPassKey::new(&stake, slot(SLOT));
        key.ready(SHARD, ANCHOR).expect("actor alive → ready");

        // The last strong owner. Both capabilities hold weak handles only.
        drop(stake);
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
        assert_eq!(
            refused,
            identity_key
                .ready(SHARD, ANCHOR)
                .expect_err("the identity capability refuses too"),
            "the two capabilities refuse a stopped actor identically"
        );
        let sign_refused = sign(key, message())
            .await
            .expect_err("stopped actor → sign refused");
        assert_eq!(sign_refused, refused);
    }

    /// A receipt key that did not decode refuses each signature with the
    /// scheme's error, and that is all it does: the persona stays held and
    /// the actor is not asked to fail (`HeldReceiptKey`).
    #[test]
    fn an_undecoded_receipt_key_refuses_to_sign() {
        use crate::engine::stake_engine::types::HeldReceiptKey;
        assert!(matches!(
            HeldReceiptKey::undecoded().sign_transcript(&message()),
            Err(shekyl_crypto_pq::CryptoError::InvalidKeyMaterial)
        ));
    }

    /// The staged surface (rule 23): the serving task is started with the
    /// identity capability and not with this one. Reads `start.rs`, the one
    /// construction site of `PersonaServing`, and `task.rs`, which defines
    /// it.
    ///
    /// Rule 47: the subject is asserted first. If the live line is not
    /// found, this test has lost sight of the start site and fails; it does
    /// not pass because a file it no longer understands does not mention
    /// the receipt key.
    ///
    /// This test changes in the cutover, deliberately: the change that
    /// hands the serving task the receipt capability must also be the one
    /// that makes a verifier accept scheme-3 receipts.
    #[test]
    fn the_serving_task_is_not_started_with_the_receipt_key() {
        let start = include_str!("start.rs");
        let task = include_str!("task.rs");

        assert_eq!(
            start
                .matches("key: ResidentPassKey::new(&stake, active.p_slot),")
                .count(),
            1,
            "start.rs must hand the serving task the identity capability, once"
        );
        assert!(
            task.contains("PersonaServing"),
            "task.rs must still be where the serving task's inputs are defined"
        );
        for (name, source) in [("start.rs", start), ("task.rs", task)] {
            for staged in ["ResidentReceiptKey", "receipt_key", "sign_receipt"] {
                assert!(
                    !source.contains(staged),
                    "{name} names `{staged}`: the receipt capability is STAGED \
                     and is switched on only by the settlement lane's cutover, \
                     with the scheme-3 receipt verifier"
                );
            }
        }
    }
}
