// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Handshake network id, and the eight-byte clearnet prefix derived from it.
//!
//! Both are the network table's (`shekyl_network`): the id is the derived
//! form of a network (`NETWORK_IDENTITY.md` NI-R10), the first 16 bytes of
//! `cSHAKE256(S = "shekyl/p2p-network-id-v1", X = genesis_block_hash)`, and
//! PWD-T5's prefix is the first eight bytes of
//! `cSHAKE256(S = "shekyl/p2p-wire-prefix-v1", X = network_id)`. The
//! transport re-exports them so its callers keep their path.

pub use shekyl_network::{
    network_id_from_genesis, prefix_for, NetworkId, NETWORK_ID_DST, PREFIX_LEN, WIRE_PREFIX_DST,
};
