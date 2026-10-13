// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **No dual-scheme acceptance**, scripted (`FN_DSA_HYBRID.md` §9,
//! `FND-21`).
//!
//! `tests/scheme_separation.rs` puts the two real stacks together; its
//! fixture shard is small, so a response of the other scheme is refused
//! from the head. This file scripts the responses a head check cannot
//! refuse: a shard large enough that the other scheme's response is a
//! plausible length, and envelopes of exactly the right width holding the
//! other scheme's signature. In every case the client reads the target's
//! scheme's width, parses the target's scheme's signature and stops; none
//! of them verifies, and none is tried a second way.
//!
//! The receipt half is STAGED: no production target carries a receipt key.

use shekyl_crypto_pq::fn_dsa_hybrid::{
    FnDsaHybridPublicKey, FnDsaHybridSecretKey, HybridEd25519FnDsa,
};
use shekyl_crypto_pq::signature::SCHEME_DOMAIN_RECEIPT;

use super::*;
use crate::{PassVerifyingKey, IDENTITY_ENVELOPE_LEN, RECEIPT_ENVELOPE_LEN};

/// Transactions in the large fixture shard. Enough that the frame is longer
/// than the two envelopes differ by (2,029 bytes), and that the frame's
/// ceiling has more than that much slack over the frame — so neither
/// scheme's response is refusable by its declared length alone.
const BIG_TXS: u8 = 120;

fn big_entries() -> Vec<Entry> {
    (0..BIG_TXS).map(|i| (0, Vec::new(), vec![i; 40])).collect()
}

fn big_rows() -> Vec<TxidParts> {
    let entries = big_entries();
    frame_txs(&entries)
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            let (pqc_auth_hash, prunable_hash, archival_len) = rows_of(tx);
            let mut hash = [0xc0; 32];
            hash[0] = u8::try_from(i).expect("under 256 transactions");
            TxidParts {
                hash: TxHash::from_bytes(hash),
                pqc_auth_hash,
                prunable_hash,
                archival_len,
            }
        })
        .collect()
}

fn big_body() -> Vec<u8> {
    encode_frame(&frame_txs(&big_entries()))
}

fn big_expected() -> ExpectedShard {
    let rows = big_rows();
    let total: u64 = rows.iter().map(|r| r.archival_len.to_raw()).sum();
    let cum_before = (SHARD.to_raw() + 1) * SHARD_LENGTH.to_raw() - total;
    ExpectedShard::new(SHARD, ArchivalLength::from_raw(cum_before), rows).expect("closed")
}

struct ReceiptKeys {
    public: FnDsaHybridPublicKey,
    secret: FnDsaHybridSecretKey,
}

fn receipt_keys() -> ReceiptKeys {
    let (public, secret) = HybridEd25519FnDsa::generate_keypair().expect("keygen");
    ReceiptKeys { public, secret }
}

/// The identity key's envelope for a response whose body is `body`.
fn identity_envelope(keys: &Keys, body: &[u8]) -> Vec<u8> {
    sign(keys, &header(), SHARD.to_raw(), body)
        .to_canonical_bytes()
        .expect("canonical")
}

/// The receipt key's envelope for a response whose body is `body`.
fn receipt_envelope(keys: &ReceiptKeys, body: &[u8]) -> Vec<u8> {
    let header = header();
    HybridEd25519FnDsa
        .sign(
            &keys.secret,
            SCHEME_DOMAIN_RECEIPT,
            &header.transcript(SHARD.to_raw(), &pass_delivery_digest(header.nonce(), body)),
        )
        .expect("sign")
        .to_canonical_bytes()
}

/// One scripted exchange against a target of key type `K`.
async fn fetch_as<K: PassVerifyingKey>(
    response: Vec<u8>,
    verifying_key: K,
) -> Result<VerifiedShard<K>, FetchError> {
    let stub = Stub::start(Script::Respond(response)).await;
    let client = PFetchClient::with_timeouts(stub.proxy, fast());
    let target = FetchTarget {
        endpoint: endpoint(),
        verifying_key,
    };
    client
        .fetch(&target, &header(), &big_expected(), Sink::new())
        .await
}

#[test]
fn the_large_fixture_defeats_the_head_checks() {
    let frame = u64::try_from(big_body().len()).expect("fits");
    let gap = u64::try_from(IDENTITY_ENVELOPE_LEN - RECEIPT_ENVELOPE_LEN).expect("fits");
    assert_eq!(gap, 2_029);
    let expected = big_expected();
    // A receipt-scheme response is at least an identity envelope long…
    assert!(frame + u64::try_from(RECEIPT_ENVELOPE_LEN).expect("fits") >= 3_385);
    // …and an identity-scheme response is within a receipt target's bound.
    assert!(
        frame + u64::try_from(IDENTITY_ENVELOPE_LEN).expect("fits")
            <= expected.max_response_len::<FnDsaHybridPublicKey>()
    );
}

/// The controls: each scheme's own response, over the large shard, is
/// accepted by its own target.
#[tokio::test]
async fn each_scheme_accepts_its_own_response_over_the_large_shard() {
    let body = big_body();
    let identity = keys();
    let response = ok_response(&identity_envelope(&identity, &body), &body);
    let shard = fetch_as(response, identity.public.clone())
        .await
        .expect("identity target, identity response");
    assert_eq!(shard.tx_count(), u64::from(BIG_TXS));

    let receipt = receipt_keys();
    let response = ok_response(&receipt_envelope(&receipt, &body), &body);
    let shard = fetch_as(response, receipt.public.clone())
        .await
        .expect("receipt target, receipt response");
    assert_eq!(shard.signature().to_canonical_bytes().len(), 1_356);
}

/// An identity target is handed a whole, valid **receipt-scheme** response.
/// It reads 3,385 bytes of envelope, which reaches 2,029 bytes back into
/// the frame; what is left of the frame is not the shard.
#[tokio::test]
async fn an_identity_target_refuses_a_valid_receipt_response() {
    let body = big_body();
    let receipt = receipt_keys();
    let response = ok_response(&receipt_envelope(&receipt, &body), &body);
    let err = fetch_as(response, keys().public).await.unwrap_err();
    assert!(
        matches!(err, FetchError::Malformed(Malformed::FrameShort)),
        "{err:?}"
    );
}

/// A receipt target is handed a whole, valid **identity-scheme** response.
/// It reads 1,356 bytes of envelope, so 2,029 bytes of the identity
/// signature are read as frame.
#[tokio::test]
async fn a_receipt_target_refuses_a_valid_identity_response() {
    let body = big_body();
    let identity = keys();
    let response = ok_response(&identity_envelope(&identity, &body), &body);
    let err = fetch_as(response, receipt_keys().public).await.unwrap_err();
    assert!(
        matches!(err, FetchError::Malformed(Malformed::FrameLong)),
        "{err:?}"
    );
}

/// The frame is intact and the envelope is exactly this scheme's width,
/// but its bytes are the other scheme's signature, cut or padded to fit.
/// It does not parse as this scheme's signature, and nothing tries it as
/// the other's.
#[tokio::test]
async fn an_envelope_of_the_right_width_holding_the_other_scheme_is_malformed() {
    let body = big_body();
    let identity = keys();
    let receipt = receipt_keys();

    // To an identity target: a valid receipt, padded to 3,385 bytes.
    let mut padded = receipt_envelope(&receipt, &body);
    padded.resize(IDENTITY_ENVELOPE_LEN, 0);
    let err = fetch_as(ok_response(&padded, &body), identity.public.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Malformed(Malformed::Envelope)),
        "{err:?}"
    );

    // To a receipt target: a valid identity signature's first 1,356 bytes.
    let mut cut = identity_envelope(&identity, &body);
    cut.truncate(RECEIPT_ENVELOPE_LEN);
    let err = fetch_as(ok_response(&cut, &body), receipt.public.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Malformed(Malformed::Envelope)),
        "{err:?}"
    );
}
