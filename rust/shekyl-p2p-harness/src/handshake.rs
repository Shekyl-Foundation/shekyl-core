// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handshake every script uses.
//!
//! `COMMAND_HANDSHAKE` is not a notify. The dialer sends the invoke and
//! waits. The session is established when the response is back. The nonce's
//! first eight bytes are 1 little-endian, so every script's handshake is
//! the same bytes. The script seed selects the leg; it does not mint a
//! second handshake.

use shekyl_levin::{
    invoke, response, BasicNodeData, CoreSyncData, HandshakeRequest, HandshakeResponse,
    NetworkAddress, PortableMap, SupportFlags, COMMAND_HANDSHAKE,
};
use std::net::Ipv4Addr;

use crate::Error;

/// First eight bytes of the handshake nonce, little-endian. Independent of
/// the script seed: every leg uses this same invoke.
const HANDSHAKE_NONCE: u64 = 1;
const ADVERTISED_PORT: u16 = 18_080;
const NETWORK_ID_BYTE: u8 = 0x11;
const TOP_ID_BYTE: u8 = 0xab;

/// What every established leg sends, and the response both hosts reply with.
pub struct Handshake {
    pub invoke: Vec<u8>,
    pub response: Vec<u8>,
}

pub fn handshake() -> Result<Handshake, Error> {
    let mut nonce = [0u8; 32];
    nonce[..8].copy_from_slice(&HANDSHAKE_NONCE.to_le_bytes());
    let request = HandshakeRequest {
        node_data: node(),
        payload_data: sync(),
        nonce,
    };
    let reply = HandshakeResponse {
        node_data: node(),
        payload_data: sync(),
        local_peerlist_new: Vec::new(),
    };
    let invoke = invoke(
        COMMAND_HANDSHAKE,
        &request.store().map_err(|err| Error::new(err.to_string()))?,
    );
    let response = response(
        COMMAND_HANDSHAKE,
        &reply.store().map_err(|err| Error::new(err.to_string()))?,
    );
    Ok(Handshake { invoke, response })
}

fn node() -> BasicNodeData {
    BasicNodeData {
        network_id: [NETWORK_ID_BYTE; 16],
        address: NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(0, 0, 0, 0),
            port: ADVERTISED_PORT,
        },
        support_flags: SupportFlags::default(),
    }
}

fn sync() -> CoreSyncData {
    CoreSyncData {
        current_height: 1,
        cumulative_difficulty: 2,
        cumulative_difficulty_top64: 0,
        top_id: [TOP_ID_BYTE; 32],
    }
}
