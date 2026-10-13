// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The receipt-key slot's own tests: when it decodes, when it refuses, and
//! what stack that costs.
//!
//! These observe [`HeldReceiptKey`] directly, or the actor that holds it.
//! The capability's behaviour — what a serving request sees — stays with
//! `ResidentReceiptKey`. Included from `types.rs` so that module does not
//! itself carry the tests.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_crypto_pq::signature::{SignatureScheme, SCHEME_DOMAIN_RECEIPT};
use shekyl_p_host::PassKey;

use super::{HeldPersona, HeldReceiptKey, PSlot, StakeEngineError};
use crate::engine::stake_engine::handle::StakeEngineHandle;
use crate::engine::stake_engine::persona::SignReceiptTranscript;
use crate::engine::stake_engine::receipt_test_fixtures::{
    bundle_with_a_corrupted_receipt_key, is_built, message, receipt_pk, sign, slot, OTHER_SLOT,
    SLOT,
};
use crate::engine::stake_engine::serving::pass_key::ResidentPassKey;
use crate::engine::stake_engine::serving::receipt_key::ResidentReceiptKey;
use crate::engine::stake_engine::test_fixtures::{derive_bundle, ephemeral_body_store, spawn_over};

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
            Err(StakeEngineError::ReceiptKeyUndecodable)
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
                    Err(StakeEngineError::ReceiptKeyUndecodable)
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
