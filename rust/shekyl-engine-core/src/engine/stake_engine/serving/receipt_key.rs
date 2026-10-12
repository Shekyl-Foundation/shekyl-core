// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **STAGED** — the persona's resident **receipt key** as the serving
//! route's signer: Ed25519 + FN-DSA-1024, hybrid scheme 3, under
//! `SCHEME_DOMAIN_RECEIPT` (`FN_DSA_HYBRID.md` §9).
//!
//! # Disposition (rule 23)
//!
//! - **What is here.** [`ResidentReceiptKey`], the receipt-key counterpart of
//!   [`ResidentPassKey`](super::pass_key::ResidentPassKey), with the actor
//!   messages behind it (`SignReceiptTranscript`, `ReceiptKeyReadiness`) and
//!   the slot the actor holds its decoded key in (`HeldReceiptKey`). It
//!   **implements the serving route's signer trait**, `PassKey`, at the
//!   receipt envelope's width (1,356 bytes): an endpoint bound with it
//!   closes every response with a scheme-3 receipt. Built and tested,
//!   end to end against the fetch client (`receipt_round_trip_tests.rs`).
//! - **What selects it.** Nothing. The serving task is started with
//!   [`ResidentPassKey`](super::pass_key::ResidentPassKey), which signs with
//!   the bond identity key under hybrid scheme 1 at the identity width,
//!   exactly as before this module existed. No production code constructs a
//!   [`ResidentReceiptKey`].
//! - **Who switches, and what switching is.** The settlement lane's
//!   cutover, in the change that makes a verifier accept scheme-3 receipts
//!   (the bundle verifier). The trait, the envelope and both ends of the
//!   wire are already generic over the scheme, so what is left is
//!   *selection*: the host's key type declares the receipt width
//!   (`shekyl_p_host::PersonaServing::key`), `serving/start.rs` constructs
//!   this type in place of the identity capability, and the daemon builds
//!   its fetch targets with the receipt key from the bond record. A persona
//!   that signed with the receipt key before a verifier accepted it would
//!   be serving shards whose countersignature every requester rejects.
//! - **Falsifier.** `serving/start.rs` handing the serving task this
//!   capability while no verifier accepts a scheme-3 receipt. Held three
//!   ways. `the_serving_task_is_not_started_with_the_receipt_key` reads that
//!   file. The `expect(dead_code)` on [`ResidentReceiptKey::new`] fails the
//!   lint lane the moment production code constructs one. And the types
//!   refuse it on their own: the host's key field is the identity width's,
//!   and this type is not a `PassKey` at that width.
//!
//! # The cutover's obligation on an undecodable key
//!
//! The receipt key is decoded by the first signature asked of it, not when
//! the actor starts (`HeldReceiptKey`), so a key that does not decode is
//! found by the first reader. Once this capability is selected, one of two
//! things must hold: the key is decoded when the serving task starts, so
//! that an undecodable key is found before any reader; or `ready` refuses
//! once a decode has failed. **This type does the second.** [`PassKey::ready`]
//! asks the actor, and the actor answers from the slot's remembered state:
//! after a failed decode every request gets the bare 503 before any shard
//! byte. The cost of doing only the second is one response: the request
//! that triggers the first decode has its body sent and closed with the
//! refusal trailer. A cutover that wants no such response decodes at
//! serving-task start as well.
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
//! It differs from the identity capability in one place. That one's
//! pre-flight is actor liveness alone and costs no round-trip; this one's
//! also asks the actor about the slot, because here the actor can know
//! ahead of a signature that it will refuse.
//!
//! The decoded receipt key — 118,640 bytes of secret basis and working
//! buffers — lives in the actor beside the bundle it was decoded from, and
//! is wiped with it. Nothing of it reaches this type. It is decoded by the
//! first signature this capability asks for and not before
//! (`HeldReceiptKey`): while this module is staged, no persona decodes one.

use std::sync::Arc;

use shekyl_archival_retention::PASS_COUNTERSIGNATURE_MESSAGE_LEN;
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridSignature;
use shekyl_p_host::{PassKey, SignRefused, RECEIPT_ENVELOPE_LEN};
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
// messages and the handle methods the trait impl below reaches are not
// reported on their own and carry no marker. When production code
// constructs a `ResidentReceiptKey`, this expectation is unfulfilled and
// the lint lane fails until it is removed.
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
}

impl ResidentReceiptKey {
    fn live_handle(&self) -> Result<StakeEngineHandle, SignRefused> {
        self.stake
            .upgrade()
            .ok_or_else(|| SignRefused::new(StakeEngineError::StakeActorUnavailable.to_string()))
    }
}

/// The staged instantiation of the serving route's signer: the receipt key,
/// hybrid scheme 3, a 1,356-byte envelope ([`RECEIPT_ENVELOPE_LEN`]). An
/// endpoint bound with this key writes that envelope and no other, and it
/// is not a `PassKey` at the identity width, so it cannot be handed where
/// the live key is expected.
impl PassKey<RECEIPT_ENVELOPE_LEN> for ResidentReceiptKey {
    /// Refuses when the answer is already known: the actor that holds the
    /// key has stopped, the slot is not held, or an earlier signature found
    /// the receipt key undecodable (`ReceiptKeyReadiness`). The shard and
    /// anchor are not consulted.
    ///
    /// One actor round-trip, on the blocking pool the serve loop asks from.
    /// It decodes nothing: a key not yet decoded answers `Ok`.
    fn ready(&self, _shard_id: u64, _anchor_height: BlockHeight) -> Result<(), SignRefused> {
        self.live_handle()?
            .receipt_key_ready_blocking(self.p_slot)
            .map_err(|e| SignRefused::new(e.to_string()))
    }

    /// Sign the 112-byte pass transcript with the persona's receipt key.
    /// Runs on the blocking pool: it parks on the actor's reply.
    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<FnDsaHybridSignature, SignRefused> {
        self.live_handle()?
            .sign_receipt_transcript_blocking(self.p_slot, *message)
            .map_err(|e| SignRefused::new(e.to_string()))
    }
}

// The types' own refusal of the falsifier, as a compile-time fact: this
// capability is not a `PassKey` at the identity width, which is the width
// of the key the serving host takes (`PersonaServing::key`). If an impl at
// that width were ever added, the resolution below becomes ambiguous and
// this crate stops compiling.
const _: fn() = || {
    trait AmbiguousIfImpl<A> {
        fn receipt_key_must_not_be_an_identity_width_key() {}
    }
    impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
    struct AtTheIdentityWidth;
    impl<T: ?Sized + PassKey<{ shekyl_p_host::IDENTITY_ENVELOPE_LEN }>>
        AmbiguousIfImpl<AtTheIdentityWidth> for T
    {
    }
    let _ =
        <ResidentReceiptKey as AmbiguousIfImpl<_>>::receipt_key_must_not_be_an_identity_width_key;
};

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_archival_retention::{pass_countersignature_message, verify_pass_transcript};
    use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridPublicKey, HybridEd25519FnDsa};
    use shekyl_crypto_pq::signature::{
        HybridSignature, SignatureScheme, SCHEME_DOMAIN_ATTESTATION, SCHEME_DOMAIN_RECEIPT,
        SCHEME_DOMAIN_WITNESS_CARRIER,
    };

    use std::collections::{BTreeMap, BTreeSet};

    use shekyl_crypto_pq::archival_p::ArchivalPKeys;

    use crate::engine::stake_engine::persona::{ReceiptKeyIsBuilt, SignReceiptTranscript};
    use crate::engine::stake_engine::serving::pass_key::ResidentPassKey;
    use crate::engine::stake_engine::test_fixtures::{
        derive_bundle, ephemeral_body_store, spawn_over,
    };
    use crate::engine::stake_engine::types::{HeldPersona, HeldReceiptKey};

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

    /// The pre-flight, asked where the serve loop asks it: on the blocking
    /// pool. It parks on the actor's reply.
    async fn ready(key: &Arc<ResidentReceiptKey>) -> Result<(), SignRefused> {
        let key = Arc::clone(key);
        tokio::task::spawn_blocking(move || key.ready(SHARD, ANCHOR))
            .await
            .expect("blocking task")
    }

    async fn sign(
        key: Arc<ResidentReceiptKey>,
        message: [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<FnDsaHybridSignature, SignRefused> {
        tokio::task::spawn_blocking(move || key.sign_pass(&message))
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
        ready(&key).await.expect("actor alive, slot held → ready");

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
    /// alike. The actor decoded the key once, for the first of them.
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

    /// An unheld slot refuses with the slot-boundary error the identity
    /// capability gives — and here already at the pre-flight, because this
    /// capability's pre-flight asks the actor: no shard is sent for a slot
    /// that cannot sign for it. The identity capability's pre-flight is
    /// liveness only, and it finds out at sign time.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unheld_slot_refuses_as_the_identity_key_does() {
        let stake = spawn_over(&[SLOT], &[SLOT], Some(SLOT));
        let unheld = slot(SLOT + 1_000);
        let key = ResidentReceiptKey::new(&stake, unheld);

        let refused = sign(Arc::clone(&key), message())
            .await
            .expect_err("unheld slot refuses");
        assert!(
            refused.detail.contains("lookahead exhausted"),
            "refusal names the slot boundary: {refused}"
        );
        assert_eq!(
            ready(&key).await.expect_err("and at the pre-flight"),
            refused
        );

        let identity_key = ResidentPassKey::new(&stake, unheld);
        identity_key
            .ready(SHARD, ANCHOR)
            .expect("the identity pre-flight is liveness only");
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
        ready(&key).await.expect("actor alive → ready");

        // The last strong owner. Both capabilities hold weak handles only.
        drop(stake);
        // Actor stop is asynchronous to the last drop; wait for the mailbox
        // to close rather than for a fixed interval.
        for _ in 0..500 {
            if ready(&key).await.is_err() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let refused = ready(&key).await.expect_err("stopped actor → refused");
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

    async fn is_built(stake: &StakeEngineHandle, raw: u32) -> Option<bool> {
        stake
            .actor
            .ask(ReceiptKeyIsBuilt { p_slot: slot(raw) })
            .await
            .expect("actor alive")
    }

    /// Starting the actor decodes no receipt key, however many personas it
    /// holds: the staged capability costs the live path nothing. The first
    /// receipt asked of a persona decodes that persona's key and no other,
    /// and the identity key signing does not decode one at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn starting_the_actor_decodes_no_receipt_key() {
        const THIRD_SLOT: u32 = 5;
        let stake = spawn_over(&[SLOT, OTHER_SLOT, THIRD_SLOT], &[SLOT], Some(SLOT));
        for held in [SLOT, OTHER_SLOT, THIRD_SLOT] {
            assert_eq!(is_built(&stake, held).await, Some(false), "slot {held}");
        }
        assert_eq!(is_built(&stake, SLOT + 1_000).await, None, "unheld");

        // The live signer runs and the slot stays empty.
        let identity_key = ResidentPassKey::new(&stake, slot(SLOT));
        tokio::task::spawn_blocking(move || identity_key.sign_pass(&message()))
            .await
            .expect("blocking task")
            .expect("identity key signs");
        assert_eq!(is_built(&stake, SLOT).await, Some(false));

        sign(ResidentReceiptKey::new(&stake, slot(SLOT)), message())
            .await
            .expect("signs");
        assert_eq!(is_built(&stake, SLOT).await, Some(true));
        assert_eq!(is_built(&stake, OTHER_SLOT).await, Some(false));
        assert_eq!(is_built(&stake, THIRD_SLOT).await, Some(false));
    }

    /// The first receipt builds the held key and the second signs from that
    /// same key: one decode, at one address, for the persona's life.
    #[test]
    fn the_first_receipt_builds_the_key_and_the_second_reuses_it() {
        let mut persona = HeldPersona::hold(derive_bundle(SLOT), true);
        assert!(
            matches!(persona.receipt_key(), HeldReceiptKey::NotBuilt),
            "nothing at hold"
        );

        let first = persona.sign_receipt_transcript(&message()).expect("signs");
        let built = persona.receipt_key().built().expect("the first built it");
        let second = persona.sign_receipt_transcript(&message()).expect("signs");
        assert_eq!(
            persona.receipt_key().built(),
            Some(built),
            "the second signature used the key the first decoded"
        );

        let public = receipt_pk(SLOT);
        for signature in [&first, &second] {
            HybridEd25519FnDsa
                .verify(&public, SCHEME_DOMAIN_RECEIPT, &message(), signature)
                .expect("verifies");
        }
        assert_ne!(first, second, "each receipt draws a fresh seed");
    }

    /// A bundle whose receipt secret does not decode. The corruption is the
    /// scheme crate's test seam; this crate's tests reach it through the
    /// `test-signer` edge the loopback tests already use.
    fn bundle_with_a_corrupted_receipt_key(raw: u32) -> ArchivalPKeys {
        let mut bundle = derive_bundle(raw);
        bundle.receipt_sign_sk.corrupt_fn_dsa_half_for_tests();
        bundle
    }

    /// A receipt secret that does not decode refuses at the first signature
    /// with the scheme's typed error, and the slot remembers it: later
    /// requests get the same error and hold no key.
    #[test]
    fn a_corrupted_receipt_key_refuses_at_the_first_signature() {
        let mut persona = HeldPersona::hold(bundle_with_a_corrupted_receipt_key(SLOT), true);
        assert!(matches!(persona.receipt_key(), HeldReceiptKey::NotBuilt));
        for _ in 0..3 {
            assert!(matches!(
                persona.sign_receipt_transcript(&message()),
                Err(shekyl_crypto_pq::CryptoError::InvalidKeyMaterial)
            ));
            assert!(matches!(persona.receipt_key(), HeldReceiptKey::Undecodable));
        }
    }

    /// After the first refusal, a request does not attempt the decode again.
    /// Held by stack: the second and third requests run on a thread whose
    /// stack is the bound a later receipt from a good key is held to, which
    /// a decode attempt on this corrupted key does not fit in. A slot that
    /// went back to `NotBuilt` on failure would retry there and overflow,
    /// not fail an assertion; that edit was made and it aborts this test in
    /// both profiles.
    #[test]
    fn an_undecodable_key_is_not_decoded_again() {
        const NO_DECODE_STACK: usize = if cfg!(debug_assertions) {
            256 * 1024
        } else {
            64 * 1024
        };
        // Boxed so the persona is handed to the small thread as a pointer.
        let mut persona = Box::new(HeldPersona::hold(
            bundle_with_a_corrupted_receipt_key(SLOT),
            true,
        ));
        persona
            .sign_receipt_transcript(&message())
            .expect_err("the first request, on this thread, attempts the decode");

        let persona = std::thread::Builder::new()
            .stack_size(NO_DECODE_STACK)
            .spawn(move || {
                for _ in 0..2 {
                    assert!(matches!(
                        persona.sign_receipt_transcript(&message()),
                        Err(shekyl_crypto_pq::CryptoError::InvalidKeyMaterial)
                    ));
                }
                persona
            })
            .expect("spawn")
            .join()
            .expect("later requests were refused without a decode");
        assert!(matches!(persona.receipt_key(), HeldReceiptKey::Undecodable));
    }

    /// The state is the persona's own. One persona's undecodable key leaves
    /// its neighbour's slot as it was, and the neighbour builds and signs.
    #[test]
    fn an_undecodable_key_is_one_personas_state() {
        let mut broken = HeldPersona::hold(bundle_with_a_corrupted_receipt_key(SLOT), true);
        let mut sound = HeldPersona::hold(derive_bundle(OTHER_SLOT), false);
        broken
            .sign_receipt_transcript(&message())
            .expect_err("does not decode");
        assert!(matches!(broken.receipt_key(), HeldReceiptKey::Undecodable));
        assert!(matches!(sound.receipt_key(), HeldReceiptKey::NotBuilt));

        let signature = sound.sign_receipt_transcript(&message()).expect("signs");
        assert!(matches!(sound.receipt_key(), HeldReceiptKey::Built(_)));
        HybridEd25519FnDsa
            .verify(
                &receipt_pk(OTHER_SLOT),
                SCHEME_DOMAIN_RECEIPT,
                &message(),
                &signature,
            )
            .expect("verifies");
        assert!(matches!(broken.receipt_key(), HeldReceiptKey::Undecodable));
    }

    /// The same through the actor. Holding the corrupted key does not stop
    /// the actor from starting; the capability's refusal is the actor's
    /// `ReceiptSign` error, identical on every call; the persona's identity
    /// key and the other persona's receipt key are unaffected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_corrupted_receipt_key_refuses_through_the_actor() {
        let bundles = BTreeMap::from([
            (slot(SLOT), bundle_with_a_corrupted_receipt_key(SLOT)),
            (slot(OTHER_SLOT), derive_bundle(OTHER_SLOT)),
        ]);
        let stake = StakeEngineHandle::spawn(
            bundles,
            BTreeSet::from([slot(SLOT)]),
            Some(slot(SLOT)),
            ephemeral_body_store(),
        );
        let key = ResidentReceiptKey::new(&stake, slot(SLOT));
        // Not decoded yet, so the pre-flight has nothing to refuse on — and
        // asking it decodes nothing.
        ready(&key)
            .await
            .expect("the actor started; nothing known yet");
        assert_eq!(is_built(&stake, SLOT).await, Some(false));

        let first = sign(Arc::clone(&key), message())
            .await
            .expect_err("a key that does not decode refuses");
        assert_eq!(
            first,
            SignRefused::new(
                StakeEngineError::ReceiptSign(shekyl_crypto_pq::CryptoError::InvalidKeyMaterial)
                    .to_string()
            )
        );
        // From the remembered state this time, not from a second decode.
        let second = sign(Arc::clone(&key), message())
            .await
            .expect_err("and again");
        assert_eq!(first, second, "a later call is refused the same way");
        // And the pre-flight now knows: after a failed decode `ready`
        // refuses, with the same typed refusal, so the serve loop answers
        // the bare 503 and sends no shard it cannot sign for.
        assert_eq!(
            ready(&key)
                .await
                .expect_err("ready refuses after a failed decode"),
            first
        );
        // The neighbour's pre-flight is its own.
        ready(&ResidentReceiptKey::new(&stake, slot(OTHER_SLOT)))
            .await
            .expect("the other persona is ready");
        assert_eq!(is_built(&stake, SLOT).await, Some(false));

        let identity_key = ResidentPassKey::new(&stake, slot(SLOT));
        let identity = tokio::task::spawn_blocking(move || identity_key.sign_pass(&message()))
            .await
            .expect("blocking task")
            .expect("the identity key still signs");
        verify_pass_transcript(
            derive_bundle(SLOT).hybrid_bond_id(),
            &NONCE,
            ANCHOR,
            &ANCHOR_HASH,
            SHARD,
            &DIGEST,
            &identity,
        )
        .expect("verifies under bond_id");

        let other = sign(ResidentReceiptKey::new(&stake, slot(OTHER_SLOT)), message())
            .await
            .expect("the other persona's receipt key signs");
        HybridEd25519FnDsa
            .verify(
                &receipt_pk(OTHER_SLOT),
                SCHEME_DOMAIN_RECEIPT,
                &message(),
                &other,
            )
            .expect("verifies");
    }

    /// Run `work` against a freshly started actor on a current-thread
    /// runtime whose one thread has `stack_bytes` of stack: the actor's task,
    /// and so every handler, runs on that stack. The bundles are derived by
    /// the caller, outside it — key generation has stack needs of its own
    /// that are not the actor's.
    fn on_an_actor_with_stack<W, F>(
        stack_bytes: usize,
        bundles: BTreeMap<PSlot, ArchivalPKeys>,
        work: W,
    ) where
        W: FnOnce(StakeEngineHandle) -> F + Send + 'static,
        F: std::future::Future<Output = ()>,
    {
        std::thread::Builder::new()
            .stack_size(stack_bytes)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                runtime.block_on(Box::pin(async move {
                    let stake = StakeEngineHandle::spawn(
                        bundles,
                        BTreeSet::from([slot(SLOT)]),
                        Some(slot(SLOT)),
                        ephemeral_body_store(),
                    );
                    work(stake).await;
                }));
            })
            .expect("spawn")
            .join()
            .expect("ran within the stack");
    }

    fn three_bundles() -> BTreeMap<PSlot, ArchivalPKeys> {
        [SLOT, OTHER_SLOT, OTHER_SLOT + 1]
            .into_iter()
            .map(|raw| (slot(raw), derive_bundle(raw)))
            .collect()
    }

    /// Where the decode's stack is paid, now that it is lazy. The smallest
    /// stack each step ran on, x86_64 at this commit, by a ladder of 8 KiB
    /// steps from 16 KiB (so each figure is an upper bound on the need):
    ///
    /// | | unoptimized | optimized |
    /// | --- | --- | --- |
    /// | start the actor and query it, no receipt | 152 KiB | 56 KiB |
    /// | start the actor, first receipt, second receipt | 608 KiB | 376 KiB |
    /// | a persona's first receipt, alone | 544 KiB | 360 KiB |
    /// | a persona's later receipt, alone | 112 KiB | 16 KiB |
    ///
    /// The first receipt pays construction (`FnDsaHybridSigner::new`), on the
    /// actor's task. A later receipt cannot be given a stack of its own
    /// through the actor, whose task stays on the thread it started on, so
    /// the last two rows are of the held persona directly.
    ///
    /// Three bounds, each about twice the figure it holds or less:
    ///
    /// - **Start decodes nothing.** An actor holding three personas starts
    ///   and answers on a stack a single decode does not fit in. Were `hold`
    ///   to decode again, this would overflow, not fail an assertion.
    /// - **The first receipt** through the actor, and the second after it,
    ///   run in half a default thread stack unoptimized and a quarter
    ///   optimized — the bound the scheme as a whole is held to.
    /// - **A later receipt** runs in an eighth of a default thread stack
    ///   unoptimized and a thirty-second optimized.
    #[test]
    fn the_first_receipt_pays_the_decode_and_later_ones_do_not() {
        const START_STACK: usize = if cfg!(debug_assertions) {
            256 * 1024
        } else {
            128 * 1024
        };
        const FIRST_STACK: usize = if cfg!(debug_assertions) {
            1024 * 1024
        } else {
            512 * 1024
        };
        const LATER_STACK: usize = if cfg!(debug_assertions) {
            256 * 1024
        } else {
            64 * 1024
        };

        on_an_actor_with_stack(START_STACK, three_bundles(), |stake| async move {
            for raw in [SLOT, OTHER_SLOT, OTHER_SLOT + 1] {
                assert_eq!(is_built(&stake, raw).await, Some(false));
            }
        });

        let public = receipt_pk(SLOT);
        on_an_actor_with_stack(FIRST_STACK, three_bundles(), |stake| async move {
            for _ in 0..2 {
                let signature = stake
                    .actor
                    .ask(SignReceiptTranscript {
                        p_slot: slot(SLOT),
                        message: message(),
                    })
                    .await
                    .expect("signs");
                HybridEd25519FnDsa
                    .verify(&public, SCHEME_DOMAIN_RECEIPT, &message(), &signature)
                    .expect("verifies");
            }
            assert_eq!(is_built(&stake, SLOT).await, Some(true));
        });

        // Boxed so the persona is handed to the small thread as a pointer.
        let mut persona = Box::new(HeldPersona::hold(derive_bundle(SLOT), true));
        persona
            .sign_receipt_transcript(&message())
            .expect("the first receipt, on this thread, builds the key");
        let later = std::thread::Builder::new()
            .stack_size(LATER_STACK)
            .spawn(move || persona.sign_receipt_transcript(&message()))
            .expect("spawn")
            .join()
            .expect("a later receipt ran, and the persona dropped, within the stack")
            .expect("signs");
        HybridEd25519FnDsa
            .verify(&receipt_pk(SLOT), SCHEME_DOMAIN_RECEIPT, &message(), &later)
            .expect("verifies");
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
            for staged in [
                "ResidentReceiptKey",
                "receipt_key",
                "sign_receipt",
                "RECEIPT_ENVELOPE_LEN",
            ] {
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
