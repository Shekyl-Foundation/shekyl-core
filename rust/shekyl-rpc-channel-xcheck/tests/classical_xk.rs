// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The classical anchor (`RPC_CHANNEL.md` §4.1, anchor 1): clatter's XK
//! reproduces the community vector byte for byte.
//!
//! This says nothing yet about the hybrid pattern. It establishes that the
//! harness drives clatter correctly and that clatter's classical half is the
//! Noise everyone else implements, which is what the hybrid cross-check
//! stands on.

mod support;

use clatter::bytearray::ByteArray;
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Blake2s;
use clatter::handshakepattern::noise_xk;
use clatter::traits::{Dh, Handshaker};
use clatter::{KeyPair, NqHandshakeCore};
use serde_json::Value;
use support::SeededRng;

const VECTOR: &str = include_str!("vectors/cacophony_xk_25519_chachapoly_blake2s.json");

type PublicKey = <X25519 as Dh>::PubKey;
type PrivateKey = <X25519 as Dh>::PrivateKey;
/// Every key the vector needs is given, so the generator is never drawn
/// from; its role is arbitrary.
type Handshake = NqHandshakeCore<X25519, ChaChaPoly, Blake2s, SeededRng<0>>;

fn field(vector: &Value, name: &str) -> Vec<u8> {
    let text = vector[name]
        .as_str()
        .unwrap_or_else(|| panic!("vector has no string field {name}"));
    hex::decode(text).expect("vector field is hex")
}

fn keypair(vector: &Value, name: &str) -> KeyPair<PublicKey, PrivateKey> {
    let secret = PrivateKey::from_slice(&field(vector, name));
    KeyPair {
        public: X25519::pubkey(&secret),
        secret,
    }
}

#[test]
fn clatter_xk_reproduces_the_community_vector() {
    let root: Value = serde_json::from_str(VECTOR).expect("vector file parses");
    let vector = &root["vector"];
    assert_eq!(
        vector["protocol_name"].as_str(),
        Some("Noise_XK_25519_ChaChaPoly_BLAKE2s")
    );

    let responder_static = keypair(vector, "resp_static");
    assert_eq!(
        responder_static.public.as_slice(),
        field(vector, "init_remote_static").as_slice(),
        "the initiator's pinned key is the responder's static"
    );

    let mut initiator = Handshake::new(
        noise_xk(),
        &field(vector, "init_prologue"),
        true,
        Some(keypair(vector, "init_static")),
        Some(keypair(vector, "init_ephemeral")),
        Some(responder_static.public),
        None,
    )
    .expect("initiator");
    let mut responder = Handshake::new(
        noise_xk(),
        &field(vector, "resp_prologue"),
        false,
        Some(responder_static),
        Some(keypair(vector, "resp_ephemeral")),
        None,
        None,
    )
    .expect("responder");

    let messages = vector["messages"].as_array().expect("messages");
    // XK is three handshake messages; the vector then carries transport
    // messages. Fewer would leave the transport half unchecked.
    assert!(messages.len() > 3, "vector carries transport messages too");

    let mut wire = vec![0u8; 4096];
    let mut plain = vec![0u8; 4096];
    for (index, message) in messages.iter().take(3).enumerate() {
        let payload = field(message, "payload");
        let (writer, reader) = if index % 2 == 0 {
            (&mut initiator, &mut responder)
        } else {
            (&mut responder, &mut initiator)
        };
        let written = writer.write_message(&payload, &mut wire).expect("write");
        assert_eq!(
            hex::encode(&wire[..written]),
            message["ciphertext"].as_str().expect("ciphertext"),
            "handshake message {index}"
        );
        let read = reader
            .read_message(&wire[..written], &mut plain)
            .expect("read");
        assert_eq!(&plain[..read], payload.as_slice(), "payload {index}");
    }
    assert!(initiator.is_finished() && responder.is_finished());

    let mut initiator = initiator.finalize().expect("initiator transport");
    let mut responder = responder.finalize().expect("responder transport");
    let hash = field(vector, "handshake_hash");
    assert_eq!(initiator.get_handshake_hash().as_slice(), hash.as_slice());
    assert_eq!(responder.get_handshake_hash().as_slice(), hash.as_slice());

    for (index, message) in messages.iter().enumerate().skip(3) {
        let payload = field(message, "payload");
        let (sender, receiver) = if index % 2 == 0 {
            (&mut initiator, &mut responder)
        } else {
            (&mut responder, &mut initiator)
        };
        let sealed = sender.send_vec(&payload).expect("send");
        assert_eq!(
            hex::encode(&sealed),
            message["ciphertext"].as_str().expect("ciphertext"),
            "transport message {index}"
        );
        assert_eq!(receiver.receive_vec(&sealed).expect("receive"), payload);
    }
}
