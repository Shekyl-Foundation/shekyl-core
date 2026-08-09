// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit suite for the message-signing workflow. Sibling of
//! `message_signing/mod.rs` so the decomposition ratchet measures the
//! workflow file, not its tests (same pattern as `proofs_tests.rs`).

use super::*;

use std::path::PathBuf;

use shekyl_crypto_pq::account::{
    generate_account_from_raw_seed, DerivationNetwork, MASTER_SEED_BYTES,
};
use shekyl_crypto_pq::message_signing as ms;
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

/// Production path: wallet-file seed borrow → PQ half → actor classical
/// half → armored assembly → session-less verify against the wallet's
/// real keys and bound segment. Exercises the thin Engine delegator and
/// the free-function body behind it.
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

    // Public address surface — no private field access.
    let addr = wallet.primary_address();
    let mut classical = [0u8; shekyl_address::CLASSICAL_SEGMENT_LEN];
    classical[0] = addr.version;
    classical[1..33].copy_from_slice(&addr.spend_key);
    classical[33..65].copy_from_slice(&addr.view_key);
    let segment =
        shekyl_address::classical_bound_segment_from_parts(&classical, &addr.ml_kem_encap_key)
            .expect("segment");
    let slh_pk = ms::derive_message_signing_public_key(&seed).expect("slh pk");

    ms::verify_message(
        &addr.spend_key,
        &slh_pk,
        network.as_u8(),
        &segment,
        message,
        &armored,
    )
    .expect("session-less verify against the open wallet's material");

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

/// Actor classical half with real derived keys: proves seed→blob
/// spend-scalar consistency the crypto module's synthetic tests cannot
/// see. Lives with the workflow suite (not in `key_actor`) so the
/// feature does not grow the shared actor file.
#[tokio::test]
async fn sign_message_outer_with_real_keys() {
    // Raw 32-byte seed (Testnet-permitted `SeedFormat::Raw32`); distinct
    // from the Engine-create fixture's 64-byte master seed.
    let raw_seed = [7u8; 32];

    let (master_seed, blob) = generate_account_from_raw_seed(&raw_seed, DerivationNetwork::Testnet)
        .expect("test rederivation succeeds");
    let spend_pk = *blob.spend_pk.as_canonical_bytes();
    let classical = blob.classical_address_bytes;
    let ml_kem_ek = blob.ml_kem_ek;
    let handle = KeyEngineHandle::spawn(blob);

    let segment = shekyl_address::classical_bound_segment_from_parts(&classical, &ml_kem_ek)
        .expect("segment assembles");
    let network_id = 1u8; // testnet discriminant

    let (preimage, sig_pq) =
        ms::sign_message_pq_half(&master_seed, network_id, &segment, b"actor end to end")
            .expect("pq half");
    let sig_cl = handle
        .sign_message_outer(ms::outer_bytes(&preimage, &sig_pq))
        .await
        .expect("actor signs the outer bytes");
    let armored = ms::assemble_armored(&sig_pq, &sig_cl);

    let slh_pk = ms::derive_message_signing_public_key(&master_seed).expect("slh pk");
    ms::verify_message(
        &spend_pk,
        &slh_pk,
        network_id,
        &segment,
        b"actor end to end",
        &armored,
    )
    .expect("full nested hybrid verifies against the wallet's real keys");
}
