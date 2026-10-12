// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve path's response, pinned **byte for byte**, for the one scheme
//! that is live: the bond identity key's countersignature (hybrid scheme 1,
//! a 3,385-byte envelope).
//!
//! Two responses are held against bytes captured from the tree before the
//! signer trait became generic over the envelope's width
//! (`FN_DSA_HYBRID.md` `FND-19`): a 200 closed by the countersignature, and
//! a 200 closed by the refusal trailer. Each is the whole response — status
//! line, headers with the content length, body, envelope — so a change that
//! moves the envelope's width, its place, the content length or the
//! trailer's fill for the live scheme fails here, whatever the types say.
//!
//! The signer is deterministic: a key derived from a fixed seed, and the
//! ML-DSA half signed from a fixed seed (the Ed25519 half is deterministic
//! by construction). The signature in the fixture is therefore a real one,
//! and the first test verifies it under the key before comparing anything.
//!
//! The fixtures are hex, 32 bytes to a line, in `wire_pin/`. They are read,
//! never written, by the tests. The regenerator is armed like the other
//! pinned fixtures':
//!
//! ```text
//! SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
//!   cargo test -p shekyl-p-serve --lib regenerate_identity_wire_pins -- --ignored
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN;
use shekyl_archival_retention::{pass_delivery_digest, verify_pass_transcript};
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, HybridSignature,
    SCHEME_DOMAIN_ATTESTATION,
};
use shekyl_types::BlockHeight;

use super::{
    filler, good_get_shard_0, is_refusal_trailer, parse_served, request_raw, serve_one_in_memory,
    FixtureProvider, InMemoryServe, PServeEndpoint, ANCHOR_HASH, IN_GATE_ANCHOR, NONCE, OWN_HEIGHT,
    REFUSAL_TRAILER_BYTE,
};
use crate::countersign::{PassKey, PassSigner, SignRefused, IDENTITY_ENVELOPE_LEN};

/// Frozen with the fixtures.
const KEY_SEED: [u8; MASTER_SEED_BYTES] = [0x33; MASTER_SEED_BYTES];
const ML_DSA_SIGN_SEED: [u8; 32] = [0x44; 32];
const BODY_LEN: usize = 300;
const BODY_SEED: u8 = 0x40;
/// The live envelope's width, as a number: the canonical scheme-1
/// signature. Written out so that this file does not follow a constant.
const ENVELOPE_LEN: usize = 3_385;

fn body() -> Vec<u8> {
    filler(BODY_LEN, BODY_SEED)
}

fn pinned_keys() -> (HybridPublicKey, HybridSecretKey) {
    let keys = derive_archival_p_keys(&KEY_SEED, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0)
        .expect("derivation");
    (keys.hybrid_bond_id().clone(), keys.hybrid_sign_sk.clone())
}

/// The pinned key, signing deterministically — or, with `signs` off, a key
/// that says it can sign and then refuses, which is the refusal trailer.
struct PinnedKeySigner {
    secret: HybridSecretKey,
    signs: bool,
}

impl PinnedKeySigner {
    fn new(signs: bool) -> Arc<Self> {
        Arc::new(Self {
            secret: pinned_keys().1,
            signs,
        })
    }
}

impl PassKey<IDENTITY_ENVELOPE_LEN> for PinnedKeySigner {
    fn ready(&self, _: u64, _: BlockHeight) -> Result<(), SignRefused> {
        Ok(())
    }
    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        if !self.signs {
            return Err(SignRefused::new("signer went away"));
        }
        HybridEd25519MlDsa
            .sign_with_ml_dsa_seed(
                &self.secret,
                SCHEME_DOMAIN_ATTESTATION,
                message,
                &ML_DSA_SIGN_SEED,
            )
            .map_err(|e| SignRefused::new(e.to_string()))
    }
}

impl PassSigner<IDENTITY_ENVELOPE_LEN> for PinnedKeySigner {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(OWN_HEIGHT))
    }
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/wire_pin")
        .join(name)
}

fn to_hex_lines(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2 + bytes.len() / 32 + 1);
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

/// The response the live endpoint gives the good request for shard 0.
async fn over_the_wire(signer: Arc<PinnedKeySigner>) -> Vec<u8> {
    let endpoint = PServeEndpoint::bind(
        FixtureProvider::new([(0, body())]),
        signer as Arc<dyn PassSigner<IDENTITY_ENVELOPE_LEN>>,
    )
    .await
    .expect("bind");
    request_raw(endpoint.addr(), &good_get_shard_0()).await
}

/// The same response from the endpoint's steps composed in memory.
fn in_memory(signer: &PinnedKeySigner) -> (InMemoryServe, Vec<u8>) {
    let mut out = Vec::new();
    let outcome = serve_one_in_memory(
        &*FixtureProvider::new([(0, body())]),
        signer,
        good_get_shard_0().as_bytes(),
        &mut out,
    );
    (outcome, out)
}

fn content_length_of(response: &[u8]) -> usize {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head");
    String::from_utf8_lossy(&response[..end])
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .expect("a content length")
        .parse()
        .expect("a number")
}

#[tokio::test]
async fn a_served_response_is_the_pinned_bytes() {
    let pinned = read_fixture("identity_served.hex");

    // The fixture is a real response: its envelope is the last 3,385 bytes,
    // the content length counts the body and the envelope, and the
    // signature verifies under the pinned key over this request and body.
    let served = parse_served(&pinned);
    assert_eq!(served.body, body());
    assert_eq!(content_length_of(&pinned), BODY_LEN + ENVELOPE_LEN);
    assert_eq!(
        served.signature.to_canonical_bytes().expect("canonical"),
        &pinned[pinned.len() - ENVELOPE_LEN..]
    );
    verify_pass_transcript(
        &pinned_keys().0,
        &NONCE,
        BlockHeight::from_raw(IN_GATE_ANCHOR),
        &ANCHOR_HASH,
        0,
        &pass_delivery_digest(&NONCE, &served.body),
        &served.signature,
    )
    .expect("the pinned signature verifies");

    let signer = PinnedKeySigner::new(true);
    let (outcome, composed) = in_memory(&signer);
    assert_eq!(outcome, InMemoryServe::Served);
    assert!(composed == pinned, "the in-memory serve moved off the pin");
    assert!(
        over_the_wire(signer).await == pinned,
        "the endpoint's response moved off the pin"
    );
}

#[tokio::test]
async fn a_refusal_trailer_response_is_the_pinned_bytes() {
    let pinned = read_fixture("identity_unsigned.hex");

    // The fixture is the full declared length, the body is whole, and the
    // envelope is the refusal fill at the envelope's width.
    let (rest, trailer) = pinned.split_at(pinned.len() - ENVELOPE_LEN);
    assert_eq!(trailer, [REFUSAL_TRAILER_BYTE; ENVELOPE_LEN]);
    assert!(is_refusal_trailer(trailer));
    assert!(rest.ends_with(&body()));
    assert_eq!(content_length_of(&pinned), BODY_LEN + ENVELOPE_LEN);

    let signer = PinnedKeySigner::new(false);
    let (outcome, composed) = in_memory(&signer);
    assert_eq!(outcome, InMemoryServe::Unsigned);
    assert!(composed == pinned, "the in-memory serve moved off the pin");
    assert!(
        over_the_wire(signer).await == pinned,
        "the endpoint's response moved off the pin"
    );
}

/// The two responses differ in their envelopes and in nothing else: same
/// head, same body. A refusal is not distinguishable before its last bytes.
#[test]
fn the_two_pins_share_everything_ahead_of_the_envelope() {
    let served = read_fixture("identity_served.hex");
    let unsigned = read_fixture("identity_unsigned.hex");
    assert_eq!(served.len(), unsigned.len());
    let ahead = served.len() - ENVELOPE_LEN;
    assert_eq!(served[..ahead], unsigned[..ahead]);
    assert_ne!(served[ahead..], unsigned[ahead..]);
}

#[test]
#[ignore = "armed fixture regenerator; requires SHEKYL_PINNED_REGEN_DECISION"]
fn regenerate_identity_wire_pins() {
    let decision = std::env::var("SHEKYL_PINNED_REGEN_DECISION").unwrap_or_default();
    assert!(
        decision.trim().len() > 10,
        "set SHEKYL_PINNED_REGEN_DECISION to a dated rationale to rewrite the wire pins"
    );
    for (name, signs) in [
        ("identity_served.hex", true),
        ("identity_unsigned.hex", false),
    ] {
        let (_, response) = in_memory(&PinnedKeySigner::new(signs));
        std::fs::write(fixture_path(name), to_hex_lines(&response)).expect("write the pin");
    }
}
