// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fetch client's exchange, pinned **byte for byte**, for the one
//! scheme that is live: a target whose key is the bond identity key
//! (hybrid scheme 1), and so a 3,385-byte envelope.
//!
//! Captured from the tree before the target became generic over its key's
//! scheme (`FN_DSA_HYBRID.md` `FND-21`), and held since:
//!
//! - the **request** the client writes for a shard and a header;
//! - a **200 closed by a countersignature**, replayed to the client, and
//!   what the client hands back for it — the delivery digest, the view
//!   hash, and the signature's own bytes;
//! - a **200 closed by the refusal trailer**, and the verdict it gets.
//!
//! The responses are replayed from the fixture files, not rebuilt: the
//! client is shown exactly the bytes an earlier build's peer would have
//! sent. The signature in the first is a real one over a fixed key and a
//! fixed ML-DSA seed, so it verifies, and a client that read another width,
//! or parsed another scheme's signature, fails here whatever the types say.
//!
//! ```text
//! SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
//!   cargo test -p shekyl-p-fetch --lib regenerate_identity_exchange_pins -- --ignored
//! ```

use std::path::PathBuf;

use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::derive_archival_p_keys;

use super::*;

/// Frozen with the fixtures.
const KEY_SEED: [u8; MASTER_SEED_BYTES] = [0x33; MASTER_SEED_BYTES];
const ML_DSA_SIGN_SEED: [u8; 32] = [0x44; 32];
/// The live envelope's width, as a number.
const ENVELOPE_LEN: usize = 3_385;

fn pinned_keys() -> Keys {
    let keys = derive_archival_p_keys(&KEY_SEED, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0)
        .expect("derivation");
    Keys {
        public: keys.hybrid_bond_id().clone(),
        secret: keys.hybrid_sign_sk.clone(),
    }
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/wire_pin")
        .join(name)
}

fn to_hex_lines(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for line in bytes.chunks(32) {
        for byte in line {
            write!(out, "{byte:02x}").expect("write to a string");
        }
        out.push('\n');
    }
    out
}

fn read_fixture(name: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|e| panic!("{name} readable: {e}"));
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert_eq!(digits.len() % 2, 0, "{name}: an odd number of hex digits");
    digits
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ascii");
            u8::from_str_radix(pair, 16).unwrap_or_else(|_| panic!("{name}: `{pair}` is not hex"))
        })
        .collect()
}

/// The deterministic 200 for the fixture body: the pinned key over the
/// fixture header, shard and body, the ML-DSA half from a fixed seed.
fn deterministic_response(keys: &Keys) -> Vec<u8> {
    let header = header();
    let signature = HybridEd25519MlDsa
        .sign_with_ml_dsa_seed(
            &keys.secret,
            SCHEME_DOMAIN_ATTESTATION,
            &header.transcript(
                SHARD.to_raw(),
                &pass_delivery_digest(header.nonce(), &body()),
            ),
            &ML_DSA_SIGN_SEED,
        )
        .expect("sign")
        .to_canonical_bytes()
        .expect("canonical");
    ok_response(&signature, &body())
}

fn refusal_response() -> Vec<u8> {
    ok_response(&[0xFF; ENVELOPE_LEN], &body())
}

#[tokio::test]
async fn the_request_and_a_verified_response_are_the_pinned_bytes() {
    let keys = pinned_keys();
    let response = read_fixture("identity_response.hex");
    let (out, seen) = run(Script::Respond(response.clone()), Sink::new(), &keys).await;
    let shard = out.expect("the pinned response verifies");

    // What the client wrote.
    let [exchange] = seen.as_slice() else {
        panic!("one exchange, saw {seen:?}")
    };
    assert_eq!(
        exchange.request.as_bytes(),
        read_fixture("identity_request.hex"),
        "the request moved off the pin"
    );

    // What the client read: the envelope is the response's last 3,385
    // bytes, and it is the signature handed back.
    assert_eq!(
        shard.signature().to_canonical_bytes().expect("canonical"),
        &response[response.len() - ENVELOPE_LEN..]
    );
    let mut verified = shard.delivery_digest().to_vec();
    verified.extend_from_slice(shard.view_hash().as_bytes());
    assert_eq!(
        verified,
        read_fixture("identity_verified.hex"),
        "the delivery digest or the view hash moved off the pin"
    );
    assert_eq!(shard.shard_id(), SHARD);
    assert_eq!(shard.tx_count(), 2);
}

#[tokio::test]
async fn a_pinned_refusal_trailer_response_is_unsigned() {
    let keys = pinned_keys();
    let response = read_fixture("identity_refusal_response.hex");
    assert_eq!(
        &response[response.len() - ENVELOPE_LEN..],
        [0xFF; ENVELOPE_LEN]
    );
    let (out, _) = run(Script::Respond(response), Sink::new(), &keys).await;
    assert!(matches!(out, Err(FetchError::Unsigned)), "{out:?}");
}

/// One byte fewer or more than the pinned response is not the response:
/// the width the client reads is exactly the envelope's.
#[tokio::test]
async fn the_pinned_response_off_by_one_byte_is_not_accepted() {
    let keys = pinned_keys();
    let response = read_fixture("identity_response.hex");
    let short = response[..response.len() - 1].to_vec();
    let (out, _) = run(Script::Respond(short), Sink::new(), &keys).await;
    assert!(out.is_err(), "a response one byte short was accepted");
    let mut long = response;
    long.push(0);
    let (out, _) = run(Script::Respond(long), Sink::new(), &keys).await;
    assert!(out.is_err(), "a response one byte long was accepted");
}

#[tokio::test]
#[ignore = "armed fixture regenerator; requires SHEKYL_PINNED_REGEN_DECISION"]
async fn regenerate_identity_exchange_pins() {
    let decision = std::env::var("SHEKYL_PINNED_REGEN_DECISION").unwrap_or_default();
    assert!(
        decision.trim().len() > 10,
        "set SHEKYL_PINNED_REGEN_DECISION to a dated rationale to rewrite the exchange pins"
    );
    let keys = pinned_keys();
    let response = deterministic_response(&keys);
    let (out, seen) = run(Script::Respond(response.clone()), Sink::new(), &keys).await;
    let shard = out.expect("the deterministic response verifies");
    let mut verified = shard.delivery_digest().to_vec();
    verified.extend_from_slice(shard.view_hash().as_bytes());
    let request = seen[0].request.as_bytes().to_vec();
    for (name, bytes) in [
        ("identity_request.hex", request),
        ("identity_response.hex", response),
        ("identity_verified.hex", verified),
        ("identity_refusal_response.hex", refusal_response()),
    ] {
        std::fs::write(fixture_path(name), to_hex_lines(&bytes)).expect("write the pin");
    }
}
