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
//! is wiped with it. Nothing of it reaches this type. It is decoded by the
//! first signature this capability asks for and not before
//! (`HeldReceiptKey`): while this module is staged, no persona decodes one.

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

    use std::collections::{BTreeMap, BTreeSet};

    use shekyl_crypto_pq::archival_p::ArchivalPKeys;

    use crate::engine::stake_engine::persona::{ReceiptKeyIsBuilt, SignReceiptTranscript};
    use crate::engine::stake_engine::serving::pass_key::ResidentPassKey;
    use crate::engine::stake_engine::test_fixtures::{
        derive_bundle, ephemeral_body_store, spawn_over,
    };
    use crate::engine::stake_engine::types::HeldPersona;

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
        assert!(persona.receipt_key().built().is_none(), "nothing at hold");

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
    /// with the scheme's typed error, and at the next one the same way: no
    /// key is held, and no failure is remembered in its place.
    #[test]
    fn a_corrupted_receipt_key_refuses_at_the_first_signature() {
        let mut persona = HeldPersona::hold(bundle_with_a_corrupted_receipt_key(SLOT), true);
        for _ in 0..3 {
            assert!(matches!(
                persona.sign_receipt_transcript(&message()),
                Err(shekyl_crypto_pq::CryptoError::InvalidKeyMaterial)
            ));
            assert!(persona.receipt_key().built().is_none());
        }
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
        key.ready(SHARD, ANCHOR).expect("the actor started");

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
        let second = sign(key, message()).await.expect_err("and again");
        assert_eq!(first, second, "a later call is refused the same way");
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
