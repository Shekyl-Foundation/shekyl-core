// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! LV-2b first-drop command maps: 1001 / 1002 / 1003 / 1007.
//!
//! Round-trips pin OPT-omit, the `network_address` union, and
//! `cumulative_difficulty_top64` store-always. Empty ping/support-flags
//! requests match the LV-2a empty-section encoding. Empty peerlists
//! omit the key (C++ STL-container store).

use std::net::{Ipv4Addr, Ipv6Addr};

use shekyl_levin::{
    invoke, BasicNodeData, BucketReader, CoreSyncData, HandshakeRequest, HandshakeResponse,
    NetworkAddress, PayloadError, PeerlistEntry, PortableMap, Received, SupportFlagsRequest,
    SupportFlagsResponse, TimedSyncRequest, TimedSyncResponse, COMMAND_HANDSHAKE,
};
use shekyl_portable_storage::{store_to_binary, Section, HEADER};

fn node() -> BasicNodeData {
    BasicNodeData {
        network_id: [0x11; 16],
        // The public-zone port-only advert: host zeroed, only the port is
        // the claim.
        address: NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(0, 0, 0, 0),
            port: 18_080,
        },
        support_flags: 0,
    }
}

const NONCE: [u8; 32] = [0x5a; 32];

fn sync_data() -> CoreSyncData {
    CoreSyncData {
        current_height: 1,
        cumulative_difficulty: 2,
        cumulative_difficulty_top64: 0,
        top_id: [0xab; 32],
        top_version: 0,
        pruning_seed: 0,
    }
}

fn round_trip<T: PortableMap + PartialEq + std::fmt::Debug>(value: &T) {
    let bytes = value.store().expect("store");
    let decoded = T::load(&bytes).expect("load");
    assert_eq!(&decoded, value);
}

#[test]
fn support_flags_request_is_empty_section() {
    // COMMAND_PING is deleted (PWD-B10); this is the surviving empty-map
    // command, so it carries the LV-2a empty-section byte pin directly.
    let bytes = SupportFlagsRequest.store().expect("store");
    let mut expected = HEADER.to_vec();
    expected.push(0x00);
    assert_eq!(bytes, expected);
    assert_eq!(
        SupportFlagsRequest::load(&bytes).expect("load"),
        SupportFlagsRequest
    );
}

#[test]
fn support_flags_response_round_trip() {
    round_trip(&SupportFlagsResponse { support_flags: 1 });
}

#[test]
fn opt_fields_omitted_at_default() {
    let node = node();
    let section = node.to_section().expect("section");
    assert!(section.get("support_flags").is_none());
    round_trip(&node);
}

#[test]
fn opt_fields_present_when_nonzero() {
    let mut node = node();
    node.support_flags = 1;
    let section = node.to_section().expect("section");
    assert!(section.get("support_flags").is_some());
    round_trip(&node);
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
        last_seen: 0,
        pruning_seed: 0,
    });
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
fn network_address_i2p_round_trip() {
    round_trip(&NetworkAddress::I2p {
        host: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr.b32.i2p".to_string(),
        port: 0,
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
    let mut flags = SupportFlagsResponse { support_flags: 1 }
        .to_section()
        .expect("section");
    flags.insert("future", shekyl_portable_storage::Value::Bool(true));
    let bytes = store_to_binary(&flags).expect("encode");
    let loaded = SupportFlagsResponse::load(&bytes).expect("load");
    assert_eq!(loaded.support_flags, 1);
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
            last_seen: 0,
            pruning_seed: 0,
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
