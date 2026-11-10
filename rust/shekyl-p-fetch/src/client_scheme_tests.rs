// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **A wrong-scheme answer is an ordinary failed read** (`FN_DSA_HYBRID.md`
//! §9). A target's key is a receipt key, so the client reads a receipt's
//! width of envelope, parses a receipt and verifies it, once. A response
//! closed by a scheme-1 (identity-key) signature — whole, or cut to the
//! receipt's width — is malformed, and nothing tries it another way.
//!
//! The fixture shard is large, so the identity-scheme response is a
//! plausible length and cannot be refused from the head.

use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridSignature, SCHEME_DOMAIN_RECEIPT};

use super::*;

/// The scheme-1 signature's canonical length.
const IDENTITY_SIGNATURE_LEN: usize = HybridSignature::CANONICAL_LEN;

/// Transactions in the large fixture shard. Enough that the frame's
/// ceiling has more slack over the frame than the two signatures differ by
/// (2,029 bytes), so an identity-scheme response is not refusable by its
/// declared length alone.
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

/// A scheme-1 signature by a fresh identity key, as the envelope of a
/// response whose body is `body`.
fn identity_envelope(body: &[u8]) -> Vec<u8> {
    let (_, secret) = HybridEd25519MlDsa
        .generate_ephemeral_keypair_for_tests()
        .expect("keygen");
    let header = header();
    HybridEd25519MlDsa
        .sign(
            &secret,
            SCHEME_DOMAIN_RECEIPT,
            &header
                .transcript(SHARD.to_raw(), pass_delivery_digest(header.nonce(), body))
                .message(),
        )
        .expect("sign")
        .to_canonical_bytes()
        .expect("canonical")
}

/// One scripted exchange against a receipt-key target.
async fn fetch(response: Vec<u8>, keys: &Keys) -> Result<VerifiedShard, FetchError> {
    let stub = Stub::start(Script::Respond(response)).await;
    let client = PFetchClient::with_timeouts(stub.proxy, fast());
    client
        .fetch(&target(keys), &header(), &big_expected(), Sink::new())
        .await
}

#[test]
fn the_large_fixture_defeats_the_head_check() {
    let frame = u64::try_from(big_body().len()).expect("fits");
    assert_eq!(IDENTITY_SIGNATURE_LEN - RECEIPT_ENVELOPE_LEN, 2_029);
    assert!(
        frame + u64::try_from(IDENTITY_SIGNATURE_LEN).expect("fits")
            <= big_expected().max_response_len()
    );
}

/// The control: a receipt over the large shard is accepted.
#[tokio::test]
async fn a_receipt_over_the_large_shard_is_accepted() {
    let body = big_body();
    let keys = keys();
    let receipt = sign(&keys, &header(), SHARD.to_raw(), &body).to_canonical_bytes();
    let shard = fetch(ok_response(&receipt, &body), &keys)
        .await
        .expect("a receipt");
    assert_eq!(shard.tx_count(), u64::from(BIG_TXS));
    assert_eq!(
        shard.signature().to_canonical_bytes().len(),
        RECEIPT_ENVELOPE_LEN
    );
}

/// A whole, valid **identity-scheme** response. The client reads a
/// receipt's width of envelope, so 2,029 bytes of the identity signature
/// are read as frame: the whole frame parses and exactly those bytes are
/// left over. Red edit: report the frame's own excess as zero — the count
/// is not the two widths' difference.
#[tokio::test]
async fn an_identity_scheme_response_is_a_long_frame() {
    let body = big_body();
    let response = ok_response(&identity_envelope(&body), &body);
    let err = fetch(response, &keys()).await.unwrap_err();
    assert!(
        matches!(
            err,
            FetchError::Malformed(Malformed::FrameLong { left })
                if left == (IDENTITY_SIGNATURE_LEN - RECEIPT_ENVELOPE_LEN) as u64
        ),
        "{err:?}"
    );
}

/// The frame is intact and the envelope is exactly a receipt's width, but
/// its bytes are an identity signature's first 1,356. It does not parse as
/// a receipt, and nothing tries it as anything else.
#[tokio::test]
async fn an_identity_signature_cut_to_a_receipts_width_is_malformed() {
    let body = big_body();
    let mut cut = identity_envelope(&body);
    cut.truncate(RECEIPT_ENVELOPE_LEN);
    let err = fetch(ok_response(&cut, &body), &keys()).await.unwrap_err();
    assert!(
        matches!(err, FetchError::Malformed(Malformed::Envelope)),
        "{err:?}"
    );
}
