// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hybrid vectors (`RPC_CHANNEL.md` §4.1, anchor 2; RT-O11).
//!
//! clatter's `hybridXK` is driven from seeded randomness with the channel's
//! real prologue, and the result is held to the vectors committed under
//! `docs/test_vectors/RPC_CHANNEL_HYBRIDXK_V1/`.
//!
//! **What this is and is not.** The vectors record what clatter 2.3.0
//! produces. Slice RT-W9 implements Shekyl's handshake and must reproduce
//! them from the same seeded stream; until it does, nothing here says
//! Shekyl's code agrees with clatter. The tests below check the vectors the
//! ways that are possible without that code: they are stable, they have the
//! sizes the design states, and they move under the edits that should move
//! them.
//!
//! Regenerate (only for a deliberate change, which is a new prologue label
//! or a new clatter pin):
//! `cargo test -p shekyl-rpc-channel-xcheck --test hybrid_xk regenerate -- --ignored`

mod support;

use clatter::bytearray::ByteArray;
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Blake2s;
use clatter::crypto::kem::rust_crypto_ml_kem::MlKem768;
use clatter::handshakepattern::{noise_hybrid_xk, HandshakePattern, Token};
use clatter::traits::{Dh, Handshaker, Kem};
use clatter::{HybridHandshakeCore, HybridHandshakeParams, KeyPair};
use serde_json::{json, Value};
use sha3::digest::Digest;
use shekyl_rpc_channel::{prologue, NetworkId, MLKEM768_EK_LEN, X25519_PUBLIC_LEN};
use support::{SeededRng, RNG_LABEL};

const PINNED: &str =
    include_str!("../../../docs/test_vectors/RPC_CHANNEL_HYBRIDXK_V1/vectors.json");
const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/test_vectors/RPC_CHANNEL_HYBRIDXK_V1/vectors.json"
);
const MANIFEST_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/test_vectors/RPC_CHANNEL_HYBRIDXK_V1/manifest.json"
);

const PROTOCOL_NAME: &str = "Noise_hybridXK_25519+MLKEM768_ChaChaPoly_BLAKE2s";

/// The roles' streams. Statics are drawn from their own streams so that a
/// handshake's ephemeral draws start at the head of its own.
const CLIENT_STATIC: u8 = 1;
const DAEMON_STATIC: u8 = 2;
const CLIENT: u8 = 3;
const DAEMON: u8 = 4;
const OTHER_CLIENT: u8 = 5;

const NETWORK_ID: NetworkId = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const OTHER_NETWORK_ID: NetworkId = [0x0f; 16];

/// Message 3 carries the grant request and message 4 the grant. Their
/// encoding is RT-W10's; these are stand-ins of fixed, different lengths.
const GRANT_REQUEST: &[u8] = b"grant-request:view";
const GRANT: &[u8] = b"grant:view";
const FIRST_REQUEST: &[u8] = b"first transport record, client to daemon";
const FIRST_REPLY: &[u8] = b"first transport record, daemon to client";

const TAG_LEN: usize = 16;
const MLKEM768_CT_LEN: usize = 1088;

type DhPair = KeyPair<<X25519 as Dh>::PubKey, <X25519 as Dh>::PrivateKey>;
type KemPair = KeyPair<<MlKem768 as Kem>::PubKey, <MlKem768 as Kem>::SecretKey>;
type Handshake<const ROLE: u8> =
    HybridHandshakeCore<X25519, MlKem768, MlKem768, ChaChaPoly, Blake2s, SeededRng<ROLE>>;

#[derive(Clone)]
struct Statics {
    dh: DhPair,
    kem: KemPair,
}

fn statics<const ROLE: u8>() -> Statics {
    let mut rng = SeededRng::<ROLE>::default();
    // X25519 first, then ML-KEM: the order a static bundle is sent in.
    let dh = X25519::genkey_rng(&mut rng).expect("static X25519");
    let kem = MlKem768::genkey_rng(&mut rng).expect("static ML-KEM");
    Statics { dh, kem }
}

struct Run {
    name: String,
    messages: Vec<Vec<u8>>,
    handshake_hash: Vec<u8>,
    transport: Vec<Vec<u8>>,
}

/// One complete handshake and one transport record each way. `C` and `D`
/// are the client's and the daemon's ephemeral streams.
fn run<const C: u8, const D: u8>(pattern: &HandshakePattern, prologue: &[u8]) -> Run {
    let client_statics = statics::<CLIENT_STATIC>();
    let daemon_statics = statics::<DAEMON_STATIC>();

    let mut client = Handshake::<C>::new(HybridHandshakeParams {
        pattern: pattern.clone(),
        initiator: true,
        prologue: Some(prologue),
        s: Some(client_statics.dh),
        e: None,
        rs: Some(daemon_statics.dh.public),
        re: None,
        s_kem: Some(client_statics.kem),
        e_kem: None,
        rs_kem: Some(daemon_statics.kem.public.clone()),
        re_kem: None,
    })
    .expect("client handshake");
    let mut daemon = Handshake::<D>::new(HybridHandshakeParams {
        pattern: pattern.clone(),
        initiator: false,
        prologue: Some(prologue),
        s: Some(daemon_statics.dh),
        e: None,
        rs: None,
        re: None,
        s_kem: Some(daemon_statics.kem),
        e_kem: None,
        rs_kem: None,
        re_kem: None,
    })
    .expect("daemon handshake");

    let name = client.get_name().as_str().to_owned();
    let payloads: [&[u8]; 4] = [&[], &[], GRANT_REQUEST, GRANT];
    let mut wire = vec![0u8; 8192];
    let mut plain = vec![0u8; 8192];
    let mut messages = Vec::new();
    for (index, payload) in payloads.iter().enumerate() {
        let written = if index % 2 == 0 {
            let n = client
                .write_message(payload, &mut wire)
                .expect("client write");
            let read = daemon
                .read_message(&wire[..n], &mut plain)
                .expect("daemon read");
            assert_eq!(&plain[..read], *payload);
            n
        } else {
            let n = daemon
                .write_message(payload, &mut wire)
                .expect("daemon write");
            let read = client
                .read_message(&wire[..n], &mut plain)
                .expect("client read");
            assert_eq!(&plain[..read], *payload);
            n
        };
        messages.push(wire[..written].to_vec());
    }
    assert!(client.is_finished() && daemon.is_finished());

    let mut client = client.finalize().expect("client transport");
    let mut daemon = daemon.finalize().expect("daemon transport");
    let handshake_hash = client.get_handshake_hash().as_slice().to_vec();
    assert_eq!(daemon.get_handshake_hash().as_slice(), handshake_hash);

    let request = client.send_vec(FIRST_REQUEST).expect("client send");
    assert_eq!(
        daemon.receive_vec(&request).expect("daemon receive"),
        FIRST_REQUEST
    );
    let reply = daemon.send_vec(FIRST_REPLY).expect("daemon send");
    assert_eq!(
        client.receive_vec(&reply).expect("client receive"),
        FIRST_REPLY
    );

    Run {
        name,
        messages,
        handshake_hash,
        transport: vec![request, reply],
    }
}

fn bundle(statics: &Statics) -> Value {
    json!({
        "x25519_public_hex": hex::encode(statics.dh.public.as_slice()),
        "x25519_secret_hex": hex::encode(statics.dh.secret.as_slice()),
        "mlkem768_ek_hex": hex::encode(statics.kem.public.as_slice()),
        "mlkem768_dk_hex": hex::encode(statics.kem.secret.as_slice()),
    })
}

fn hexes(items: &[Vec<u8>]) -> Vec<String> {
    items.iter().map(hex::encode).collect()
}

/// The vector document, built from scratch.
fn build() -> Value {
    let channel_prologue = prologue(&NETWORK_ID);
    let run = run::<CLIENT, DAEMON>(&noise_hybrid_xk(), &channel_prologue);
    json!({
        "protocol_name": run.name,
        "oracle": "clatter 2.3.0 (crates.io), ML-KEM backend ml-kem (RustCrypto) as locked in rust/Cargo.lock",
        "network_id_hex": hex::encode(NETWORK_ID),
        "prologue_hex": hex::encode(channel_prologue),
        "rng": {
            "construction": "SHAKE256(label || role_byte), read from the start as one byte stream",
            "label_hex": hex::encode(RNG_LABEL),
            "roles": {
                "client_static": CLIENT_STATIC,
                "daemon_static": DAEMON_STATIC,
                "client_handshake": CLIENT,
                "daemon_handshake": DAEMON,
            },
            "draw_order": [
                "static stream: X25519 secret (32), then ML-KEM d (32), then z (32)",
                "client handshake stream: message 1 skem m (32), X25519 ephemeral secret (32), ML-KEM ephemeral d (32), z (32)",
                "daemon handshake stream: message 2 ekem m (32), X25519 ephemeral secret (32), ML-KEM ephemeral d (32), z (32); message 4 skem m (32)",
            ],
        },
        "client_static": bundle(&statics::<CLIENT_STATIC>()),
        "daemon_static": bundle(&statics::<DAEMON_STATIC>()),
        "payloads_hex": [
            "",
            "",
            hex::encode(GRANT_REQUEST),
            hex::encode(GRANT),
        ],
        "messages_hex": hexes(&run.messages),
        "handshake_hash_hex": hex::encode(&run.handshake_hash),
        "transport": {
            "client_to_daemon_plaintext_hex": hex::encode(FIRST_REQUEST),
            "client_to_daemon_ciphertext_hex": hex::encode(&run.transport[0]),
            "daemon_to_client_plaintext_hex": hex::encode(FIRST_REPLY),
            "daemon_to_client_ciphertext_hex": hex::encode(&run.transport[1]),
        },
    })
}

fn pinned() -> Value {
    serde_json::from_str(PINNED).expect("pinned vectors parse")
}

fn pinned_messages() -> Vec<Vec<u8>> {
    pinned()["messages_hex"]
        .as_array()
        .expect("messages_hex")
        .iter()
        .map(|m| hex::decode(m.as_str().expect("hex string")).expect("hex"))
        .collect()
}

fn rendered(document: &Value) -> String {
    let mut text = serde_json::to_string_pretty(document).expect("serializes");
    text.push('\n');
    text
}

#[test]
fn clatter_hybrid_xk_matches_the_pinned_vectors() {
    let built = build();
    let pinned = pinned();
    // Field by field first, so a mismatch names what moved.
    for field in [
        "protocol_name",
        "prologue_hex",
        "client_static",
        "daemon_static",
        "messages_hex",
        "handshake_hash_hex",
        "transport",
    ] {
        assert_eq!(built[field], pinned[field], "{field}");
    }
    assert_eq!(
        rendered(&built),
        PINNED,
        "the whole document, byte for byte"
    );
}

/// The sizes `RPC_CHANNEL.md` §4.1 states, and the name it states.
#[test]
fn messages_have_the_sizes_the_design_states() {
    let messages = pinned_messages();
    assert_eq!(pinned()["protocol_name"].as_str(), Some(PROTOCOL_NAME));
    assert_eq!(messages.len(), 4);
    let ephemerals = X25519_PUBLIC_LEN + MLKEM768_EK_LEN;
    // 1: skem ciphertext, both ephemeral keys, the empty payload's tag.
    assert_eq!(messages[0].len(), MLKEM768_CT_LEN + ephemerals + TAG_LEN);
    assert_eq!(messages[0].len(), 2320);
    // 2: ekem ciphertext, both ephemeral keys, the empty payload's tag.
    assert_eq!(messages[1].len(), 2320);
    // 3: both statics, each encrypted with its own tag, then the payload.
    assert_eq!(
        messages[2].len(),
        (X25519_PUBLIC_LEN + TAG_LEN) + (MLKEM768_EK_LEN + TAG_LEN) + GRANT_REQUEST.len() + TAG_LEN
    );
    assert_eq!(messages[2].len(), 1264 + GRANT_REQUEST.len());
    // 4: the skem ciphertext, encrypted, then the payload.
    assert_eq!(messages[3].len(), 1120 + GRANT.len());
}

/// Named edit: another seed. Every message must move, or the vectors do not
/// depend on the randomness they claim to.
#[test]
fn another_client_seed_changes_every_client_message() {
    let other = run::<OTHER_CLIENT, DAEMON>(&noise_hybrid_xk(), &prologue(&NETWORK_ID));
    let pinned = pinned_messages();
    for index in [0, 2] {
        assert_ne!(
            other.messages[index],
            pinned[index],
            "message {}",
            index + 1
        );
    }
    assert_ne!(hex::encode(&other.handshake_hash), pinned_hash());
}

/// Named edit: another network. The randomness is the same, so message 1's
/// ciphertext and ephemeral keys are the same bytes; only its tag moves,
/// because the prologue is hashed into what the tag authenticates. That is
/// the prologue binding, observed.
#[test]
fn another_network_changes_only_the_tag_of_message_one() {
    let other = run::<CLIENT, DAEMON>(&noise_hybrid_xk(), &prologue(&OTHER_NETWORK_ID));
    let pinned = pinned_messages();
    let body = pinned[0].len() - TAG_LEN;
    assert_eq!(other.messages[0][..body], pinned[0][..body]);
    assert_ne!(other.messages[0][body..], pinned[0][body..]);
    assert_ne!(hex::encode(&other.handshake_hash), pinned_hash());
}

/// Named edit: the token order this round first drafted, `e, es, skem`. It
/// puts `skem` after a public key, against PQNoise's ordering rule, and
/// clatter refuses to build it.
#[test]
fn the_first_drafts_token_order_is_refused() {
    let drafted = HandshakePattern::try_new(
        "hybridXK",
        &[],
        &[Token::S],
        &[&[Token::E, Token::ES, Token::Skem], &[Token::S, Token::SE]],
        &[&[Token::Ekem, Token::E, Token::EE], &[Token::Skem]],
    );
    assert!(drafted.is_err());
    // The same call with the canonical order builds, so the refusal above is
    // about the order and not about the call.
    let canonical = HandshakePattern::try_new(
        "hybridXK",
        &[],
        &[Token::S],
        &[&[Token::Skem, Token::E, Token::ES], &[Token::S, Token::SE]],
        &[&[Token::Ekem, Token::E, Token::EE], &[Token::Skem]],
    )
    .expect("the canonical order is accepted");
    let rebuilt = run::<CLIENT, DAEMON>(&canonical, &prologue(&NETWORK_ID));
    assert_eq!(rebuilt.messages, pinned_messages());
}

fn pinned_hash() -> String {
    pinned()["handshake_hash_hex"]
        .as_str()
        .expect("handshake_hash_hex")
        .to_owned()
}

#[test]
#[ignore = "writes the committed vector files; run only for a deliberate change"]
fn regenerate() {
    let vectors = rendered(&build());
    let digest = sha3::Sha3_256::digest(vectors.as_bytes());
    let manifest = rendered(&json!({
        "_comment": [
            "Vectors for the RPC channel's handshake, Noise hybridXK (RPC_CHANNEL.md 4.1).",
            "They record what clatter 2.3.0 produces from seeded randomness with the",
            "channel's real prologue. RT-W9's implementation must reproduce them from the",
            "same seeded streams; until it does they say nothing about Shekyl's code.",
            "The seeded generator is defined in",
            "rust/shekyl-rpc-channel-xcheck/tests/support/mod.rs and described in",
            "vectors.json under `rng`. The static keys' secret halves are test values.",
        ],
        "oracle": "clatter =2.3.0, default features off, RustCrypto ml-kem as locked",
        "regeneration_command": "cargo test -p shekyl-rpc-channel-xcheck --test hybrid_xk regenerate -- --ignored",
        "vectors_sha3_256_hex": hex::encode(digest),
    }));
    std::fs::write(VECTORS_PATH, vectors).expect("write vectors.json");
    std::fs::write(MANIFEST_PATH, manifest).expect("write manifest.json");
}
