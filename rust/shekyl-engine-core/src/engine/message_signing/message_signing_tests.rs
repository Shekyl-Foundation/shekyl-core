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
//! It cannot call `verify_message`: that needs a
//! `shekyl_crypto_pq::message_signing::SignerIdentity`, which only the
//! address can produce and no address version produces yet (fork (ii),
//! see that type's docs). What it *can* assert is the part the crypto
//! crate's own tests structurally cannot see — that the σ_cl the **key
//! actor** produced from the wallet's real derived spend scalar verifies
//! against the **address's** spend key, over exactly the preimage built
//! from the **address's** bound segment. That is the seed → blob →
//! address → transcript chain, end to end, and it is this suite's job.

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
    let armored = wallet
        .sign_message(message)
        .await
        .expect("FULL wallet signs");

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
    let (preimage, sig_pq) = ms::sign_message_pq_half(
        &master_seed,
        network,
        seed_format,
        segment.as_bytes(),
        message,
    )
    .expect("pq half");
    let sig_cl = handle
        .sign_message_outer(ms::outer_bytes(&preimage, &sig_pq))
        .await
        .expect("actor signs the outer bytes");
    let armored = ms::assemble_armored(&sig_pq, &sig_cl);

    assert_outer_half_binds(&armored, &spend_pk, network, &segment, message);
}
