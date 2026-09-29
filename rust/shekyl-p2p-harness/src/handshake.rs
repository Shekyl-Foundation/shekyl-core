// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Seed 1: a handshake invoke and the response that establishes the session.
//!
//! `COMMAND_HANDSHAKE` is not a notify. The dialer sends the invoke and
//! waits. The session is established when the response is back. The nonce
//! is the seed, so the same seed is the same bytes.

use shekyl_levin::{
    invoke, response, BasicNodeData, CoreSyncData, HandshakeRequest, HandshakeResponse,
    NetworkAddress, PortableMap, SupportFlags, COMMAND_HANDSHAKE,
};
use std::net::Ipv4Addr;

use crate::Error;

/// The only seed with a script. Later legs add seeds; they do not add hosts.
pub const HANDSHAKE_SEED: u64 = 1;

/// What seed 1 sends, and the response both hosts reply with.
pub struct Handshake {
    pub invoke: Vec<u8>,
    pub response: Vec<u8>,
    /// End offset of each write. Seed 1 is one write of the whole invoke.
    pub splits: Vec<usize>,
}

pub fn handshake(seed: u64) -> Result<Handshake, Error> {
    if seed != HANDSHAKE_SEED {
        return Err(Error::new(format!("no script for seed {seed}")));
    }
    let mut nonce = [0u8; 32];
    nonce[..8].copy_from_slice(&seed.to_le_bytes());
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
    let splits = vec![invoke.len()];
    Ok(Handshake {
        invoke,
        response,
        splits,
    })
}

fn node() -> BasicNodeData {
    BasicNodeData {
        network_id: [0x11; 16],
        address: NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(0, 0, 0, 0),
            port: 18_080,
        },
        support_flags: SupportFlags::default(),
    }
}

fn sync() -> CoreSyncData {
    CoreSyncData {
        current_height: 1,
        cumulative_difficulty: 2,
        cumulative_difficulty_top64: 0,
        top_id: [0xab; 32],
        top_version: 0,
    }
}
