// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit suite for the message-signing workflow. Sibling of
//! `message_signing/mod.rs` so the decomposition ratchet measures the
//! workflow file, not its tests (same pattern as `proofs_tests.rs`).
//!
//! # What this suite can and cannot assert
//!
//! The production success path of [`super::verify_message`] is live:
//! every decodable address carries the fourth classical field, and
//! verify takes the address's [`shekyl_address::BoundClassicalSegment`]
//! so the keys cannot be unbound from the bound bytes. This suite pins
//! the assembly in front of that AND — signature-first taxonomy, the
//! full-address requirement — plus the part the crypto crate's own
//! tests structurally cannot see: that the σ_cl the **key actor**
//! produced from the wallet's real derived spend scalar verifies
//! against the **address's** spend key, over exactly the preimage built
//! from the **address's** bound segment.

use super::*;

use std::path::PathBuf;

use shekyl_crypto_pq::account::{
    generate_account_from_raw_seed, DerivationNetwork, MASTER_SEED_BYTES,
};
use shekyl_crypto_pq::message_signing as ms;
use shekyl_crypto_pq::schnorr;
use shekyl_rpc_transport::HttpRpc;
use tempfile::TempDir;

use crate::engine::key_actor::KeyEngineHandle;
use crate::engine::lifecycle::{Credentials, EngineCreateParams};
use crate::engine::signer::SoloSigner;
use crate::engine::{DaemonClient, Engine};

/// Lifecycle helpers are private to that module; mirror the minimum
/// fixture surface for Engine::sign_message coverage.
fn dummy_daemon() -> DaemonClient {
    let rpc = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(HttpRpc::new("http://127.0.0.1:1".to_string()))
    })
    .expect("construct HttpRpc (no actual connection attempted)");
    DaemonClient::new(rpc)
}

fn fixed_seed() -> [u8; MASTER_SEED_BYTES] {
    let mut s = [0u8; MASTER_SEED_BYTES];
    for (i, b) in s.iter_mut().enumerate() {
        *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(7);
    }
    s
}

struct CreateFixture {
    _tmp: TempDir,
    base_path: PathBuf,
}

fn make_create_fixture() -> CreateFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base_path = tmp.path().join("wallet");
    CreateFixture {
        _tmp: tmp,
        base_path,
    }
}

/// Assert that `armored`'s classical half is a valid house Schnorr by
/// `spend_pk` over `preimage ‖ σ_pq` — the chain described in the module
/// docs above.
fn assert_outer_half_binds(
    armored: &str,
    spend_pk: &[u8; 32],
    network: DerivationNetwork,
    segment: &shekyl_address::BoundClassicalSegment,
    message: &[u8],
) {
    let sig = ms::ArmoredSignature::decode(armored).expect("armored string decodes");
    let preimage = ms::message_preimage(network, segment.as_bytes(), message);
    let outer = ms::outer_bytes(&preimage, sig.sig_pq());
    assert!(
        schnorr::verify_compressed(
            ms::MSG_SIGN_OUTER_DOMAIN,
            spend_pk,
            outer.as_ref(),
            sig.sig_cl(),
        ),
        "the actor's classical half must verify under the address spend key"
    );
    // Negative control: the same signature must NOT verify against a
    // different transcript, or the assertion above proves nothing.
    let other = ms::message_preimage(network, segment.as_bytes(), b"a different message");
    let other_outer = ms::outer_bytes(&other, sig.sig_pq());
    assert!(
        !schnorr::verify_compressed(
            ms::MSG_SIGN_OUTER_DOMAIN,
            spend_pk,
            other_outer.as_ref(),
            sig.sig_cl(),
        ),
        "verification must be message-bound"
    );
}

/// Production path: wallet-file seed borrow → PQ half on a blocking
/// thread → actor classical half → armored assembly, checked against the
/// wallet's own public address material.
#[tokio::test(flavor = "multi_thread")]
async fn sign_message_round_trips_through_wallet_file() {
    let fix = make_create_fixture();
    let creds = Credentials::password_only(b"correct horse");
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    let wallet = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

    let message = b"engine surface end to end";

    // Single-flight observable, ridden along the one expensive sign this
    // suite pays for: while the multi-second PQ half runs, the engine's
    // sign permit is held (it rides inside the blocking job), and it is
    // free again once the call returns. A permit dropped before or at
    // entry to the blocking task would leave the gate open for nearly
    // the whole sign and fail the `observed_held` assertion.
    let permit = wallet.key.sign_permit().clone();
    // Scoped so the pinned call future is dropped before `wallet.close`
    // moves the engine below.
    let armored = {
        let call = wallet.sign_message(message);
        tokio::pin!(call);
        let mut observed_held = false;
        let armored = loop {
            tokio::select! {
                out = call.as_mut() => break out.expect("FULL wallet signs"),
                () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {
                    observed_held |= permit.try_acquire().is_err();
                }
            }
        };
        assert!(
            observed_held,
            "the sign permit must be held across the PQ half"
        );
        armored
    };
    assert!(
        permit.try_acquire().is_ok(),
        "the permit must be free again once the job exits"
    );

    assert!(armored.starts_with(ms::MSG_SIG_PREFIX));
    assert!(!armored.contains('='));

    // Public address surface — no private field access, and no
    // hand-assembled segment: the address owns its own layout.
    let addr = wallet.primary_address();
    assert_outer_half_binds(
        &armored,
        &addr.spend_key,
        crate::engine::lifecycle::network_to_derivation(network),
        &addr.bound_classical_segment(),
        message,
    );

    // Session-less verify assembly (this module's free function). This
    // assertion WAS the R6-a tripwire (refuse with UnboundIdentity); the
    // fork-(ii) layout landing flipped it, by design, into the full
    // production round trip: sign through the wallet file and key actor,
    // verify from nothing but the encoded address string.
    let encoded = addr.encode().expect("encode primary address");
    verify_message(network, &encoded, message, &armored)
        .expect("the wallet's own address verifies its own signature");

    // And the negative that makes it non-vacuous: a different message
    // under the same address and signature is the honest refusal.
    assert!(matches!(
        verify_message(network, &encoded, b"a different message", &armored),
        Err(VerifyMessageError::Crypto(
            ms::MessageSigError::VerifyFailed
        ))
    ));

    // Signature-first: a junk paste is Malformed even with a junk address.
    assert!(matches!(
        verify_message(network, "not-an-address", message, "not-a-signature"),
        Err(VerifyMessageError::Crypto(ms::MessageSigError::Malformed(
            _
        )))
    ));

    // Well-formed signature + undecodable address: address shape, not
    // a verify-failed answer.
    assert!(matches!(
        verify_message(network, "not-an-address", message, &armored),
        Err(VerifyMessageError::InvalidAddress)
    ));

    // Classical-only display form: the bound segment cannot be rebuilt.
    let classical = addr
        .encode_classical_display()
        .expect("classical display form");
    assert!(matches!(
        verify_message(network, &classical, message, &armored),
        Err(VerifyMessageError::ClassicalOnly)
    ));

    wallet.close(&creds).expect("close");
}

/// Capability-gate mapping: the seed extractor's typed refusals become
/// the workflow's ViewOnly / HardwareOffload errors.
#[test]
fn extract_error_maps_to_capability_refusals() {
    assert_eq!(
        map_extract_error(ExtractRederivationInputsError::ViewOnly),
        SignMessageError::ViewOnly
    );
    assert_eq!(
        map_extract_error(ExtractRederivationInputsError::HardwareOffload),
        SignMessageError::HardwareOffload
    );
}

/// A stopped key actor is terminal and gets its own variant, because it
/// is the one key-engine failure whose user action differs: close and
/// reopen, not retry (rule 82). Folding it into the rendered `Key`
/// string would tell the user "key engine: ..." for a session that
/// cannot recover no matter how often they try.
#[test]
fn stopped_key_actor_is_its_own_terminal_error() {
    assert_eq!(
        SignMessageError::from(KeyEngineError::KeyActorUnavailable),
        SignMessageError::WalletSessionEnded
    );
    assert_eq!(
        SignMessageError::from(KeyEngineError::Primitive { detail: "boom" }),
        SignMessageError::Key(KeyEngineError::Primitive { detail: "boom" }.to_string())
    );
}

/// Actor classical half with real derived keys, driven directly rather
/// than through the Engine: proves the same seed→blob spend-scalar
/// consistency without the wallet-file layer in the way.
#[tokio::test]
async fn sign_message_outer_with_real_keys() {
    // Raw 32-byte seed (Testnet-permitted `SeedFormat::Raw32`); distinct
    // from the Engine-create fixture's 64-byte master seed.
    let raw_seed = [7u8; 32];
    let network = DerivationNetwork::Testnet;
    let seed_format = SeedFormat::Raw32;

    let (master_seed, blob) =
        generate_account_from_raw_seed(&raw_seed, network).expect("test rederivation succeeds");
    let spend_pk = *blob.spend_pk.as_canonical_bytes();
    let classical = blob.classical_address_bytes;
    let ml_kem_ek = blob.ml_kem_ek;
    let handle = KeyEngineHandle::spawn(blob);

    let segment = shekyl_address::BoundClassicalSegment::from_address_parts(&classical, &ml_kem_ek)
        .expect("segment assembles");

    let message = b"actor end to end";
    let (preimage, sig_pq) =
        ms::sign_message_pq_half(&master_seed, network, seed_format, &segment, message)
            .expect("pq half");
    let sig_cl = handle
        .sign_message_outer(ms::outer_bytes(&preimage, &sig_pq))
        .await
        .expect("actor signs the outer bytes");
    let armored = ms::assemble_armored(&sig_pq, &sig_cl);

    assert_outer_half_binds(&armored, &spend_pk, network, &segment, message);
}
