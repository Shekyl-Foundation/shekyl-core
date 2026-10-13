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
//!   message behind it (`SignReceiptTranscript`) and the slot the actor
//!   holds its decoded key in (`HeldReceiptKey`). It
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
//!   The cutover's edit sites, each of which names the identity scheme or
//!   its width today (checked at source 2026-10-13):
//!   - `rust/shekyl-p-host/src/host.rs`: the `key` field's
//!     `PassKey<IDENTITY_ENVELOPE_LEN>` (`:59`), its `Debug` rendering
//!     (`:81`), and the bind, which hard-codes
//!     `PassSigner<IDENTITY_ENVELOPE_LEN>` beside them (`:429`);
//!   - `rust/shekyl-daemon-image/src/shard_view.rs` (`:95-103`): the
//!     holder's target is built from `record.hybrid_pubkey` with
//!     `HybridPublicKey::from_canonical_bytes`; it becomes
//!     `FnDsaHybridPublicKey::from_receipt_sign_pk(&record.receipt_sign_pk)`;
//!   - `rust/shekyl-archival-fetch-sched/src/facts.rs:55`
//!     (`FetchTarget<HybridPublicKey>`) and `read.rs:91`, `:460`
//!     (`VerifiedShard<HybridPublicKey>`);
//!   - the harnesses: `rust/shekyl-sp-t3-spike/src/harness.rs:354` builds
//!     `FetchTarget<HybridPublicKey>`; `rust/shekyl-p-loopback/src/lib.rs:154`
//!     (`fetch_target<K: PassVerifyingKey>`) is already generic and needs
//!     no edit — its callers choose the key, and change with it;
//!   - `serving/start.rs` and the `expect(dead_code)` on
//!     [`ResidentReceiptKey::new`], below.
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
//! once a decode has failed. **This type does the second.** The first
//! signature through *this capability* that the actor refuses with
//! [`StakeEngineError::ReceiptKeyUndecodable`] is remembered on the
//! capability, and every later [`PassKey::ready`] returns that same refusal
//! without asking the actor.
//!
//! The cost of doing only the second is **one response per capability
//! instance**, not one per persona: the memory is on the
//! [`ResidentReceiptKey`] value, so each [`ResidentReceiptKey::new`] over a
//! persona whose key does not decode sends one shard body that it closes
//! with the refusal trailer before its pre-flight starts refusing. The
//! actor's slot refuses that request without decoding again; only the
//! capability's pre-flight is new to it. The serving task makes one
//! capability per start, so in production that is one response per
//! serving start. A cutover that wants no such response decodes at
//! serving-task start as well.
//!
//! # Why the pre-flight latches here, and does not ask the actor
//!
//! The alternative is a pre-flight that asks the actor for the slot's state
//! on every request: always current, and one actor round-trip per request,
//! paid before the first response byte. The latch costs nothing per
//! request. It is sound because of what may set it and what it then
//! claims:
//!
//! - **Only one error sets it**, [`StakeEngineError::ReceiptKeyUndecodable`]
//!   ([`latches_preflight`]). That variant is produced only from the actor
//!   slot's `Undecodable` state, so it proves the key does not decode. A
//!   decoded key whose signature fails is `ReceiptSign` — the scheme's
//!   error value for that is the same `InvalidKeyMaterial` an undecodable
//!   key gets, which is why the decision is on the variant and never on the
//!   value. An unheld slot, a stopped actor and a failed signature leave the
//!   latch as it was.
//! - **What it then claims is that every signature this capability could
//!   ask for is refused.** The slot never leaves `Undecodable` while the
//!   persona is held; the actor's held set is built once, at its start, and
//!   never re-populated (the watch upkeep moves the same map out and back);
//!   and this capability is bound to that one actor by its handle. So once
//!   the latch is set the actor would refuse every request this capability
//!   could send, and the two cannot disagree in the direction that matters:
//!   the latch never refuses a request the actor would sign. In the other
//!   direction — the actor knows, the latch does not yet — the cost is the
//!   one response above.
//!
//! The actor stays the authority for signing: the latch only lets the
//! pre-flight say early what the actor would say late.
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
//! Pre-flight matches the identity capability: actor liveness, and no
//! round-trip. It differs afterwards. A signature that finds the receipt
//! key undecodable is remembered on this capability, and later pre-flights
//! refuse with that refusal. An unheld slot is still found at sign time, as
//! the identity key finds it.
//!
//! The decoded receipt key — 118,640 bytes of secret basis and working
//! buffers — lives in the actor beside the bundle it was decoded from, and
//! is wiped with it. Nothing of it reaches this type. It is decoded by the
//! first signature this capability asks for and not before
//! (`HeldReceiptKey`): while this module is staged, no persona decodes one.

use std::sync::{Arc, OnceLock};

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
    /// The refusal the actor gave when it found this persona's receipt key
    /// undecodable, once it has; empty until then. Later pre-flights return
    /// it and do not ask the actor (module docs: why a latch, and why it is
    /// sound). Set only from [`StakeEngineError::ReceiptKeyUndecodable`]
    /// ([`latches_preflight`]). The actor's `HeldReceiptKey::Undecodable`
    /// slot is what refuses another decode.
    undecodable: OnceLock<SignRefused>,
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
            undecodable: OnceLock::new(),
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
    /// Refuses when the actor that holds the key has stopped, or when an
    /// earlier signature through this capability found the receipt key
    /// undecodable. The shard, the
    /// anchor and whether the slot is held are not consulted: an unheld slot
    /// is the signer's answer, as it is for the identity key.
    ///
    /// No actor round-trip. A key not yet decoded answers `Ok`.
    fn ready(&self, _shard_id: u64, _anchor_height: BlockHeight) -> Result<(), SignRefused> {
        if let Some(refused) = self.undecodable.get() {
            return Err(refused.clone());
        }
        self.live_handle()?;
        Ok(())
    }

    /// Sign the 112-byte pass transcript with the persona's receipt key.
    /// Runs on the blocking pool: it parks on the actor's reply. A refusal
    /// that proves the key undecodable is remembered, so the next pre-flight
    /// refuses with it.
    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<FnDsaHybridSignature, SignRefused> {
        self.live_handle()?
            .sign_receipt_transcript_blocking(self.p_slot, *message)
            .map_err(|error| {
                let refused = SignRefused::new(error.to_string());
                if latches_preflight(&error) {
                    // First writer wins; every writer has the same words.
                    self.undecodable.get_or_init(|| refused.clone());
                }
                refused
            })
    }
}

/// Whether a refused signature proves this persona's receipt key does not
/// decode, and so latches the capability's pre-flight. True for
/// [`StakeEngineError::ReceiptKeyUndecodable`] and nothing else: not for a
/// decoded key's failed signature (`ReceiptSign`, whatever the scheme's
/// error value), not for an unheld slot, not for a stopped actor. A free
/// function so the decision is tested on every error value directly.
fn latches_preflight(error: &StakeEngineError) -> bool {
    matches!(error, StakeEngineError::ReceiptKeyUndecodable)
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
    use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
    use shekyl_crypto_pq::signature::{
        HybridSignature, SignatureScheme, SCHEME_DOMAIN_ATTESTATION, SCHEME_DOMAIN_RECEIPT,
        SCHEME_DOMAIN_WITNESS_CARRIER,
    };

    use std::collections::{BTreeMap, BTreeSet};

    use crate::engine::stake_engine::receipt_test_fixtures::{
        bundle_with_a_corrupted_receipt_key, is_built, message, receipt_pk, sign, slot, ANCHOR,
        ANCHOR_HASH, DIGEST, NONCE, OTHER_SLOT, SHARD, SLOT,
    };
    use crate::engine::stake_engine::serving::pass_key::ResidentPassKey;
    use crate::engine::stake_engine::test_fixtures::{
        derive_bundle, ephemeral_body_store, spawn_over,
    };

    /// The pre-flight, asked where the serve loop asks it: on the blocking
    /// pool. It is liveness plus the capability's remembered refusal, not an
    /// actor round-trip.
    async fn ready(key: &Arc<ResidentReceiptKey>) -> Result<(), SignRefused> {
        let key = Arc::clone(key);
        tokio::task::spawn_blocking(move || key.ready(SHARD, ANCHOR))
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
    /// capability gives, and at the same moment: sign time. Pre-flight is
    /// liveness only for both, so a slot that is not held is still ready.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unheld_slot_refuses_as_the_identity_key_does() {
        let stake = spawn_over(&[SLOT], &[SLOT], Some(SLOT));
        let unheld = slot(SLOT + 1_000);
        let key = ResidentReceiptKey::new(&stake, unheld);
        ready(&key).await.expect("pre-flight is liveness only");

        let refused = sign(Arc::clone(&key), message())
            .await
            .expect_err("unheld slot refuses");
        assert!(
            refused.detail.contains("lookahead exhausted"),
            "refusal names the slot boundary: {refused}"
        );
        // The refusal did not latch the pre-flight: an unheld slot does not
        // prove the key undecodable.
        ready(&key)
            .await
            .expect("an unheld slot's refusal leaves the pre-flight as it was");

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

        let refused = sign(Arc::clone(&key), message())
            .await
            .expect_err("the retired ephemeral slot was wiped");
        assert!(refused.detail.contains("lookahead exhausted"), "{refused}");
        // Nor did a wiped persona's refusal latch it.
        ready(&key)
            .await
            .expect("a wiped persona's refusal leaves the pre-flight as it was");
    }

    /// The latch decision, on every refusal a receipt signature can come
    /// back with. Only the error that proves the key undecodable latches.
    /// In particular a decoded key's failed signature does not, though the
    /// scheme's error value for it is the `InvalidKeyMaterial` an
    /// undecodable key gets: the decision is on the variant. That give-up
    /// cannot be provoked through the actor without a production seam (it
    /// takes 27 rejected samples in a row from a valid key), so it is held
    /// here, on the value the actor would return for it.
    #[test]
    fn only_an_undecodable_key_latches_the_pre_flight() {
        use shekyl_crypto_pq::CryptoError;
        assert!(latches_preflight(&StakeEngineError::ReceiptKeyUndecodable));
        for error in [
            StakeEngineError::ReceiptSign(CryptoError::InvalidKeyMaterial),
            StakeEngineError::ReceiptSign(CryptoError::InvalidInput("domain".into())),
            StakeEngineError::LookaheadExhausted {
                requested: slot(SLOT),
            },
            StakeEngineError::StakeActorUnavailable,
            StakeEngineError::PassCountersign(CryptoError::InvalidKeyMaterial),
        ] {
            assert!(!latches_preflight(&error), "{error} latched the pre-flight");
        }
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
        // Not decoded yet, so the pre-flight has nothing to refuse on.
        // Pre-flight is liveness plus the capability's remembered refusal:
        // it does not ask the actor, and it decodes nothing.
        ready(&key)
            .await
            .expect("the actor started; nothing known yet");
        assert_eq!(is_built(&stake, SLOT).await, Some(false));

        let first = sign(Arc::clone(&key), message())
            .await
            .expect_err("a key that does not decode refuses");
        assert_eq!(
            first,
            SignRefused::new(StakeEngineError::ReceiptKeyUndecodable.to_string())
        );
        // The second sign is the actor's remembered `Undecodable`, not a
        // second decode. `ready` is the capability's remembered refusal, set
        // from the first refusal, not an actor ask. The serve loop then
        // answers the bare 503 and sends no shard it cannot sign for.
        let second = sign(Arc::clone(&key), message())
            .await
            .expect_err("and again");
        assert_eq!(first, second, "a later call is refused the same way");
        assert_eq!(
            ready(&key)
                .await
                .expect_err("ready refuses after a failed decode"),
            first
        );
        // The memory is the capability's, not the persona's: a second
        // capability over the same slot starts ready, learns from its own
        // first refusal (which the actor gives from its remembered state,
        // decoding nothing), and refuses from then on. One response per
        // capability instance, not one per persona.
        let again = ResidentReceiptKey::new(&stake, slot(SLOT));
        ready(&again)
            .await
            .expect("a new capability has not been refused yet");
        assert_eq!(
            sign(Arc::clone(&again), message())
                .await
                .expect_err("its first request is refused by the actor"),
            first
        );
        assert_eq!(ready(&again).await.expect_err("and then it knows"), first);
        assert_eq!(is_built(&stake, SLOT).await, Some(false));

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
