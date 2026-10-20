// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Anchor 2 (`RPC_CHANNEL.md` §4.1): Shekyl's own `hybridXK` handshake
//! reproduces, byte for byte, what clatter produced from the same seeded
//! randomness.
//!
//! RT-W8 pinned the vectors from clatter (`shekyl-rpc-channel-xcheck`).
//! This drives our handshake from the generator those vectors were made
//! with and compares the four messages, the handshake hash, and one
//! transport message each way.
//!
//! **Our handshake draws; it is not handed seeds.** The statics and every
//! ephemeral come out of the role's stream through the private constructors
//! production calls with the operating system's generator (RT-O18). One
//! generator source, compiled here and into the cross-check crate. Neither
//! exports it.
//!
//! **The transport comparison is one Noise ciphertext.** `Direction::seal`
//! under [`TRANSPORT_AD`] at the initial epoch is the plain Noise transport
//! message the vectors pin. The same ciphertext is what
//! [`PendingSession::open_first_message`] opens. There is no framing in
//! this comparison, and no raw key leaves `shekyl-noise`.
//!
//! If the bytes differ, the difference is the finding. A weaker comparison
//! is not substituted and called this anchor.

#[path = "../../shekyl-rpc-channel-xcheck/tests/support/mod.rs"]
mod seeded;

use serde_json::Value;
use shekyl_noise::KeyEpoch;

use super::{
    Client, Daemon, StaticKeypair, MESSAGE1_LEN, MESSAGE1_WIRE_LEN, MESSAGE2_LEN,
    MESSAGE3_OVERHEAD, MESSAGE4_OVERHEAD, TRANSPORT_AD,
};
use crate::budget::HandshakeBudget;
use crate::{NetworkId, MAC1_LEN};
use seeded::SeededRng;

const PINNED: &str =
    include_str!("../../../docs/test_vectors/RPC_CHANNEL_HYBRIDXK_V1/vectors.json");

/// The roles' streams, as the vectors name them (`rng.roles`).
const CLIENT_STATIC: u8 = 1;
const DAEMON_STATIC: u8 = 2;
const CLIENT: u8 = 3;
const DAEMON: u8 = 4;

fn pinned() -> Value {
    serde_json::from_str(PINNED).expect("pinned vectors parse")
}

fn hex_field(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("hex")
}

fn network_id(vectors: &Value) -> NetworkId {
    hex_field(&vectors["network_id_hex"])
        .try_into()
        .expect("16-byte network id")
}

/// Everything one run of our handshake produces that the vectors pin.
struct Run {
    client_static: StaticKeypair,
    daemon_static: StaticKeypair,
    messages: Vec<Vec<u8>>,
    handshake_hash: [[u8; 32]; 2],
    transport: [Vec<u8>; 2],
}

fn run() -> Run {
    let vectors = pinned();
    let network_id = network_id(&vectors);
    let payloads: Vec<Vec<u8>> = vectors["payloads_hex"]
        .as_array()
        .expect("payloads_hex")
        .iter()
        .map(hex_field)
        .collect();
    assert!(payloads[0].is_empty() && payloads[1].is_empty());

    // Statics from their own streams: X25519, then ML-KEM `d`, then `z`.
    let client_static = StaticKeypair::generate_from(&mut SeededRng::<CLIENT_STATIC>::default())
        .expect("client static");
    let daemon_static = StaticKeypair::generate_from(&mut SeededRng::<DAEMON_STATIC>::default())
        .expect("daemon static");

    // One generator per role for the whole handshake, as clatter holds one.
    let mut client_rng = SeededRng::<CLIENT>::default();
    let mut daemon_rng = SeededRng::<DAEMON>::default();

    let (client, message1) = Client::start_from(
        &network_id,
        &client_static,
        daemon_static.public(),
        &mut client_rng,
    )
    .expect("message 1");
    // On the wire, message 1 is the Noise message and its mac1. The Noise
    // bytes are what is compared with clatter's, exactly as before mac1
    // existed; the mac1 is the daemon bundle's over exactly those bytes.
    assert_eq!(message1.len(), MESSAGE1_WIRE_LEN);
    let (noise_message1, mac1) = message1.split_at(MESSAGE1_LEN);
    assert_eq!(
        mac1,
        daemon_static.public().mac1(noise_message1),
        "message 1's mac1 is the daemon bundle's, over the Noise message"
    );
    let budget = HandshakeBudget::new(std::time::Instant::now());
    let daemon = Daemon::new(&network_id, &daemon_static)
        .read_message1(&message1, &budget, std::time::Instant::now())
        .expect("daemon reads message 1");
    let message1 = noise_message1.to_vec();
    let (daemon, message2) = daemon.write_from(&mut daemon_rng).expect("message 2");
    let client = client
        .read_message2(&message2)
        .expect("client reads message 2");
    let (client, message3) = client.write_message3(&payloads[2]).expect("message 3");
    let daemon = daemon
        .read_message3(&message3)
        .expect("daemon reads message 3");
    assert_eq!(
        daemon.fingerprint().as_bytes(),
        client_static.public().fingerprint().as_bytes(),
        "message 3's claim is the client's fingerprint, and only that"
    );
    let (pending, message4) = daemon
        .write_from(&payloads[3], &mut daemon_rng)
        .expect("message 4");
    let (client, grant) = client
        .read_message4(&message4)
        .expect("client reads message 4");
    assert_eq!(grant, payloads[3], "message 4's payload");

    let handshake_hash = [client.handshake_hash(), pending.handshake_hash()];

    let request = hex_field(&vectors["transport"]["client_to_daemon_plaintext_hex"]);
    let reply = hex_field(&vectors["transport"]["daemon_to_client_plaintext_hex"]);
    let (mut client_send, _client_recv) = client.into_directions();
    let (client_ciphertext, epoch) = client_send
        .seal(&request, TRANSPORT_AD)
        .expect("client transport message");
    assert_eq!(epoch, KeyEpoch::INITIAL);
    let (mut session, first_message) = pending
        .open_first_message(|recv| {
            recv.open(&client_ciphertext, TRANSPORT_AD)
                .map(|(plaintext, _)| plaintext)
        })
        .expect("the client's first message opens");
    assert_eq!(first_message, request);
    assert_eq!(session.request, payloads[2], "message 3's payload");
    assert_eq!(
        session.client.x25519(),
        client_static.public().x25519(),
        "the authenticated client is the static that was drawn"
    );
    assert_eq!(
        session.client.mlkem_ek(),
        client_static.public().mlkem_ek(),
        "the authenticated client's ML-KEM key is the static that was drawn"
    );

    // Opening the request advanced the daemon's receive nonce only. Its
    // send direction is still the key `Split` gave the responder, at nonce 0.
    let (daemon_ciphertext, epoch) = session
        .send
        .seal(&reply, TRANSPORT_AD)
        .expect("daemon transport message");
    assert_eq!(epoch, KeyEpoch::INITIAL);

    Run {
        client_static,
        daemon_static,
        messages: vec![message1, message2, message3, message4],
        handshake_hash,
        transport: [client_ciphertext, daemon_ciphertext],
    }
}

#[test]
fn our_statics_are_the_pinned_statics() {
    let vectors = pinned();
    let run = run();
    for (name, ours) in [
        ("client_static", &run.client_static),
        ("daemon_static", &run.daemon_static),
    ] {
        assert_eq!(
            hex::encode(ours.public().x25519()),
            vectors[name]["x25519_public_hex"].as_str().expect("hex"),
            "{name}: X25519 public key"
        );
        assert_eq!(
            hex::encode(ours.public().mlkem_ek()),
            vectors[name]["mlkem768_ek_hex"].as_str().expect("hex"),
            "{name}: ML-KEM encapsulation key"
        );
    }
}

#[test]
fn our_handshake_reproduces_the_pinned_vectors() {
    let vectors = pinned();
    let run = run();

    let pinned_messages: Vec<Vec<u8>> = vectors["messages_hex"]
        .as_array()
        .expect("messages_hex")
        .iter()
        .map(hex_field)
        .collect();
    assert_eq!(run.messages.len(), pinned_messages.len());
    for (index, (ours, theirs)) in run.messages.iter().zip(&pinned_messages).enumerate() {
        assert_eq!(ours.len(), theirs.len(), "message {} length", index + 1);
        // Hex, so a failure prints where the bytes part company.
        assert_eq!(
            hex::encode(ours),
            hex::encode(theirs),
            "message {} differs from clatter's",
            index + 1
        );
    }

    let pinned_hash = vectors["handshake_hash_hex"].as_str().expect("hex");
    assert_eq!(hex::encode(run.handshake_hash[0]), pinned_hash, "client h");
    assert_eq!(hex::encode(run.handshake_hash[1]), pinned_hash, "daemon h");

    assert_eq!(
        hex::encode(&run.transport[0]),
        vectors["transport"]["client_to_daemon_ciphertext_hex"]
            .as_str()
            .expect("hex"),
        "the client's sending direction is not clatter's initiator-to-responder key"
    );
    assert_eq!(
        hex::encode(&run.transport[1]),
        vectors["transport"]["daemon_to_client_ciphertext_hex"]
            .as_str()
            .expect("hex"),
        "the daemon's sending direction is not clatter's responder-to-initiator key"
    );
}

#[test]
fn our_message_sizes_are_the_designs() {
    let run = run();
    assert_eq!(run.messages[0].len(), MESSAGE1_LEN);
    assert_eq!(run.messages[1].len(), MESSAGE2_LEN);
    assert_eq!(MESSAGE1_LEN, 2320);
    assert_eq!(MESSAGE1_WIRE_LEN, 2320 + MAC1_LEN);
    assert_eq!(MAC1_LEN, 16);
    assert_eq!(MESSAGE2_LEN, 2320);
    assert_eq!(MESSAGE3_OVERHEAD, 1264);
    assert_eq!(MESSAGE4_OVERHEAD, 1120);
}
