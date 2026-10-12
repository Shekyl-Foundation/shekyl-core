// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Anchor 2 (`RPC_CHANNEL.md` §4.1): Shekyl's own `hybridXK` handshake
//! reproduces, byte for byte, what clatter produced from the same seeded
//! randomness.
//!
//! RT-W8 pinned the vectors from clatter (`hybrid_xk.rs` beside this file).
//! This drives our handshake from the generator those vectors were made with
//! and compares the four messages, the handshake hash, and one transport
//! message each way.
//!
//! **Our handshake draws; it is not handed seeds.** The statics and every
//! ephemeral come out of the role's stream through the same calls production
//! makes on the operating system's generator. So the comparison also tests
//! the claim §4.1 rests the anchor on: that both libraries draw the same
//! randomness in the same order.
//!
//! **The transport comparison is of keys, not of framing.** clatter's
//! transport message is plain Noise: one AEAD over the payload with empty
//! associated data. Shekyl's record layer is a different framing, here and on
//! P2P. Sealing with the raw key `Split` produced, as clatter does, shows the
//! two sides derived the same transport keys; it says nothing about records.
//!
//! If the bytes differ, the difference is the finding. A weaker comparison is
//! not substituted and called this anchor.

mod support;

use serde_json::Value;
use shekyl_noise::aead;
use shekyl_rpc_channel::handshake::{
    Client, Daemon, StaticKeypair, MESSAGE1_LEN, MESSAGE2_LEN, MESSAGE3_OVERHEAD, MESSAGE4_OVERHEAD,
};
use shekyl_rpc_channel::NetworkId;
use support::SeededRng;

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
    let client_static =
        StaticKeypair::generate_with_rng(&mut SeededRng::<CLIENT_STATIC>::default())
            .expect("client static");
    let daemon_static =
        StaticKeypair::generate_with_rng(&mut SeededRng::<DAEMON_STATIC>::default())
            .expect("daemon static");

    // One generator per role for the whole handshake, as clatter holds one.
    let mut client_rng = SeededRng::<CLIENT>::default();
    let mut daemon_rng = SeededRng::<DAEMON>::default();

    let (client, message1) = Client::start_with_rng(
        &network_id,
        &client_static,
        daemon_static.public(),
        &mut client_rng,
    )
    .expect("message 1");
    let daemon = Daemon::new(&network_id, &daemon_static)
        .read_message1(&message1)
        .expect("daemon reads message 1");
    let (daemon, message2) = daemon
        .write_message2_with_rng(&mut daemon_rng)
        .expect("message 2");
    let client = client
        .read_message2(&message2)
        .expect("client reads message 2");
    let (client, message3) = client.write_message3(&payloads[2]).expect("message 3");
    let (daemon, claimed) = daemon
        .read_message3(&message3)
        .expect("daemon reads message 3");
    assert_eq!(
        claimed.claimed_static().x25519(),
        client_static.public().x25519(),
        "the daemon learns the client's X25519 static"
    );
    assert_eq!(
        claimed.claimed_static().mlkem_ek()[..],
        client_static.public().mlkem_ek()[..],
        "the daemon learns the client's ML-KEM static"
    );
    let (pending, message4) = daemon
        .write_message4_with_rng(&payloads[3], &mut daemon_rng)
        .expect("message 4");
    let (client, grant) = client
        .read_message4(&message4)
        .expect("client reads message 4");
    assert_eq!(grant, payloads[3], "message 4's payload");

    let handshake_hash = [client.handshake_hash(), pending.handshake_hash()];

    // The daemon has no record halves until the client's first record
    // opens. That record is in Shekyl's framing, which the vectors do not
    // pin; what it yields is the daemon's halves and message 3's payload.
    let request = hex_field(&vectors["transport"]["client_to_daemon_plaintext_hex"]);
    let reply = hex_field(&vectors["transport"]["daemon_to_client_plaintext_hex"]);
    let (mut client_send, _client_recv) = client.split();
    let first_record = client_send.seal(&request).expect("first record");
    let session = pending
        .open_first_record(&first_record)
        .expect("the client's first record opens");
    assert_eq!(session.first_record, request);
    assert_eq!(session.request, payloads[2], "message 3's payload");

    // The initiator's sending key is the first key `Split` yields; the
    // daemon's is the second. Seal as plain Noise does: nonce 0, no
    // associated data. One record has not reached the rekey, so each half
    // still holds the key `Split` gave it.
    let transport = [
        aead::seal(&client_send.ck_and_k().1, 0, &[], &request).expect("seal"),
        aead::seal(&session.send.ck_and_k().1, 0, &[], &reply).expect("seal"),
    ];

    Run {
        client_static,
        daemon_static,
        messages: vec![message1, message2, message3, message4],
        handshake_hash,
        transport,
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
        "the client's sending key is not clatter's initiator-to-responder key"
    );
    assert_eq!(
        hex::encode(&run.transport[1]),
        vectors["transport"]["daemon_to_client_ciphertext_hex"]
            .as_str()
            .expect("hex"),
        "the daemon's sending key is not clatter's responder-to-initiator key"
    );
}

#[test]
fn our_message_sizes_are_the_designs() {
    let run = run();
    assert_eq!(run.messages[0].len(), MESSAGE1_LEN);
    assert_eq!(run.messages[1].len(), MESSAGE2_LEN);
    assert_eq!(MESSAGE1_LEN, 2320);
    assert_eq!(MESSAGE2_LEN, 2320);
    assert_eq!(MESSAGE3_OVERHEAD, 1264);
    assert_eq!(MESSAGE4_OVERHEAD, 1120);
}
