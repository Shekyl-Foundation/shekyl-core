// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! LV-2b first-drop command maps: 1001 / 1002.
//!
//! Round-trips pin the `network_address` union and
//! `cumulative_difficulty_top64` store-always. Empty peerlists omit the key
//! (C++ STL-container store).

use std::net::{Ipv4Addr, Ipv6Addr};

use shekyl_levin::{
    invoke, BasicNodeData, BucketReader, CoreSyncData, HandshakeRequest, HandshakeResponse,
    NetworkAddress, PayloadError, PeerlistEntry, PortableMap, Received, TimedSyncRequest,
    TimedSyncResponse, COMMAND_HANDSHAKE,
};
use shekyl_portable_storage::{store_to_binary, Section};

fn node() -> BasicNodeData {
    BasicNodeData {
        network_id: [0x11; 16],
    }
}

const NONCE: [u8; 32] = [0x5a; 32];

fn sync_data() -> CoreSyncData {
    CoreSyncData {
        current_height: 1,
        cumulative_difficulty: 2,
        cumulative_difficulty_top64: 0,
        top_id: [0xab; 32],
    }
}

fn round_trip<T: PortableMap + PartialEq + std::fmt::Debug>(value: &T) {
    let bytes = value.store().expect("store");
    let decoded = T::load(&bytes).expect("load");
    assert_eq!(&decoded, value);
}

/// `support_flags` left `basic_node_data` with compression (Rick,
/// 2026-10-19): it negotiated nothing. A peer that still sends the key is
/// decoded with it ignored, and a Shekyl node never emits it.
#[test]
fn a_support_flags_key_is_ignored_and_never_emitted() {
    let mut section = node().to_section().expect("section");
    assert!(section.get("support_flags").is_none());
    section.insert(
        "support_flags",
        shekyl_portable_storage::Value::UInt32(0x02),
    );
    let bytes = store_to_binary(&section).expect("encode");
    let loaded = BasicNodeData::load(&bytes).expect("load");
    assert_eq!(loaded, node());
    assert!(loaded
        .to_section()
        .expect("section")
        .get("support_flags")
        .is_none());
}

/// `rpc_port` / `rpc_credits_per_hash` were deleted from `basic_node_data`
/// and `peerlist_entry` pre-genesis (RPC is operator-to-operator, never
/// advertised over P2P — `RPC_TRANSPORT_POSTURE.md` RT-9). This bites when
/// either field is re-added to a Rust map (the keys reappear, or the loader
/// picks up the inserted `18_081`/`100` and the equality fails); it does
/// NOT cover the C++ emitter — that half is pinned only by the `#[ignore]`d
/// `dual_stack.rs` live run.
fn stale_rpc_keys_ignored<T: PortableMap + PartialEq + std::fmt::Debug>(value: &T) {
    let mut section = value.to_section().expect("section");
    assert!(section.get("rpc_port").is_none());
    assert!(section.get("rpc_credits_per_hash").is_none());
    section.insert("rpc_port", shekyl_portable_storage::Value::UInt16(18_081));
    section.insert(
        "rpc_credits_per_hash",
        shekyl_portable_storage::Value::UInt32(100),
    );
    let bytes = store_to_binary(&section).expect("encode");
    assert_eq!(&T::load(&bytes).expect("load"), value);
}

#[test]
fn deleted_rpc_advert_fields_never_written_still_readable() {
    stale_rpc_keys_ignored(&node());
    stale_rpc_keys_ignored(&PeerlistEntry {
        adr: NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            port: 18_080,
        },
    });
}

/// `last_seen` left the wire entry in PR-3 (Rick, 2026-10-13: a field
/// always sent as 0 and ignored on receipt is a sentinel and a
/// peer-controlled slot). This build never writes it, and an entry that
/// carries one, at any value, is read as its address with the key ignored.
#[test]
fn a_last_seen_key_on_a_received_entry_is_read_with_the_key_ignored() {
    let entry = PeerlistEntry {
        adr: NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            port: 18_080,
        },
    };
    let mut section = entry.to_section().expect("section");
    assert!(section.get("last_seen").is_none(), "never written");
    section.insert(
        "last_seen",
        shekyl_portable_storage::Value::Int64(1_750_000_000),
    );
    let bytes = store_to_binary(&section).expect("encode");
    assert_eq!(PeerlistEntry::load(&bytes).expect("load"), entry);
}

/// Neither `CORE_SYNC_DATA` nor `peerlist_entry` carries a key this build
/// does not define: the stripe seed went with the stripe engine (`PDM-Q7`),
/// the peer identifier with `PWD-I1`. Nothing is ever emitted for them, and
/// a section carrying a key this build never wrote decodes with the key
/// ignored, so a value of either shape on the wire is not a refusal.
fn unknown_key_ignored<T: PortableMap + PartialEq + std::fmt::Debug>(value: &T) {
    let mut section = value.to_section().expect("section");
    assert!(section.get("a_key_this_build_never_wrote").is_none());
    section.insert(
        "a_key_this_build_never_wrote",
        shekyl_portable_storage::Value::UInt32(384),
    );
    let bytes = store_to_binary(&section).expect("encode");
    assert_eq!(&T::load(&bytes).expect("load"), value);
}

#[test]
fn a_key_this_build_never_wrote_is_read_with_the_key_ignored() {
    unknown_key_ignored(&sync_data());
    unknown_key_ignored(&PeerlistEntry {
        adr: NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            port: 18_080,
        },
    });
}

/// `CORE_SYNC_DATA` carries no `top_version`: the block version is the
/// constant 1, so a tip version is not information. Never emitted; a peer
/// that still sends the key — as a `uint8`, the type it had on the wire —
/// decodes with the key ignored, as any key this build never wrote is.
#[test]
fn deleted_top_version_never_written_still_readable() {
    let value = sync_data();
    let mut section = value.to_section().expect("section");
    assert!(section.get("top_version").is_none());
    section.insert("top_version", shekyl_portable_storage::Value::UInt8(1));
    let bytes = store_to_binary(&section).expect("encode");
    assert_eq!(CoreSyncData::load(&bytes).expect("load"), value);
}

#[test]
fn cumulative_difficulty_top64_stored_when_zero() {
    let sync = sync_data();
    let section = sync.to_section().expect("section");
    assert!(section.get("cumulative_difficulty_top64").is_some());
    round_trip(&sync);
}

#[test]
fn cumulative_difficulty_top64_missing_loads_as_zero() {
    let sync = sync_data();
    let section = sync.to_section().expect("section");
    // Rebuild without the field: C++ load-OPT path.
    let mut stripped = Section::new();
    for (key, value) in section.iter() {
        if key != "cumulative_difficulty_top64" {
            stripped.insert(key, value.clone());
        }
    }
    let bytes = store_to_binary(&stripped).expect("encode");
    let loaded = CoreSyncData::load(&bytes).expect("load");
    assert_eq!(loaded.cumulative_difficulty_top64, 0);
}

#[test]
fn network_address_ipv4_round_trip() {
    round_trip(&NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(127, 0, 0, 1),
        port: 18_080,
    });
}

#[test]
fn network_address_ipv6_round_trip() {
    round_trip(&NetworkAddress::Ipv6 {
        ip: Ipv6Addr::LOCALHOST,
        port: 18_080,
    });
}

#[test]
fn network_address_tor_round_trip() {
    round_trip(&NetworkAddress::Tor {
        host: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr.onion".to_string(),
        port: 18_080,
    });
}

#[test]
fn unknown_address_type_is_hard_error() {
    let mut inner = Section::new();
    inner.insert("m_ip", shekyl_portable_storage::Value::UInt32(0));
    inner.insert("m_port", shekyl_portable_storage::Value::UInt16(1));
    let mut root = Section::new();
    root.insert("addr", shekyl_portable_storage::Value::Object(inner));
    root.insert("type", shekyl_portable_storage::Value::UInt8(99));
    let bytes = store_to_binary(&root).expect("encode");
    assert_eq!(
        NetworkAddress::load(&bytes),
        Err(PayloadError::UnknownAddressType(99))
    );
}

#[test]
fn extra_fields_ignored() {
    let mut section = TimedSyncRequest {
        payload_data: sync_data(),
    }
    .to_section()
    .expect("section");
    section.insert("future", shekyl_portable_storage::Value::Bool(true));
    let bytes = store_to_binary(&section).expect("encode");
    let loaded = TimedSyncRequest::load(&bytes).expect("load");
    assert_eq!(loaded.payload_data, sync_data());
}

#[test]
fn handshake_with_ipv4_peerlist_round_trip() {
    let req = HandshakeRequest {
        node_data: node(),
        payload_data: sync_data(),
        nonce: NONCE,
    };
    round_trip(&req);

    let rsp = HandshakeResponse {
        node_data: node(),
        payload_data: sync_data(),
        local_peerlist_new: vec![PeerlistEntry {
            adr: NetworkAddress::Ipv4 {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                port: 18_080,
            },
        }],
    };
    round_trip(&rsp);
}

#[test]
fn timed_sync_round_trip() {
    round_trip(&TimedSyncRequest {
        payload_data: sync_data(),
    });
    round_trip(&TimedSyncResponse {
        payload_data: sync_data(),
        local_peerlist_new: Vec::new(),
    });
}

#[test]
fn empty_peerlist_omitted() {
    let rsp = TimedSyncResponse {
        payload_data: sync_data(),
        local_peerlist_new: Vec::new(),
    };
    let section = rsp.to_section().expect("section");
    assert!(section.get("local_peerlist_new").is_none());
}

#[test]
fn handshake_invoke_survives_bucket_reader() {
    let req = HandshakeRequest {
        node_data: node(),
        payload_data: sync_data(),
        nonce: NONCE,
    };
    let body = req.store().expect("store");
    let bucket = invoke(COMMAND_HANDSHAKE, &body);
    let mut reader = BucketReader::new();
    reader.feed(&bucket).expect("feed");
    match reader.next_message().expect("parse") {
        Some(Received::Request { command, payload }) => {
            assert_eq!(command, COMMAND_HANDSHAKE);
            assert_eq!(HandshakeRequest::load(&payload).expect("load"), req);
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(reader.next_message().expect("drain"), None);
}

/// The handshake carries no address on any connector (ruled 2026-10-09).
/// `basic_node_data` never emits the key, and a peer that still sends it,
/// as every node before the cutover does, is decoded with the key ignored.
#[test]
fn node_data_emits_no_address_and_ignores_one_a_peer_sends() {
    let ours = node().to_section().expect("encode");
    assert!(ours.get("address").is_none(), "no address key is emitted");

    let mut theirs = node().to_section().expect("encode");
    let old_advert = NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(0, 0, 0, 0),
        port: 18_080,
    };
    theirs.insert(
        "address",
        shekyl_portable_storage::Value::Object(old_advert.to_section().expect("address")),
    );
    assert_eq!(
        BasicNodeData::from_section(&theirs).expect("decodes with the key ignored"),
        node()
    );
}
