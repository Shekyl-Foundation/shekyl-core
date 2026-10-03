// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Handshake network id, and the eight-byte clearnet prefix derived from it.
//!
//! The id is the first 16 bytes of
//! `cSHAKE256(S = "shekyl/p2p-network-id-v1", X = genesis_block_hash)`.
//! A different genesis is a different network, so a regenesis rotates the
//! id. PWD-T5's prefix is the first eight bytes of
//! `cSHAKE256(S = "shekyl/p2p-wire-prefix-v1", X = network_id)`.

use shekyl_crypto_hash::cshake256_32;

/// Customization for the handshake network id.
/// Registered in `CRYPTO_DOMAIN_REGISTRY.tsv` beside [`WIRE_PREFIX_DST`].
pub const NETWORK_ID_DST: &[u8] = b"shekyl/p2p-network-id-v1";

/// Customization for the clearnet framing prefix.
/// Registered in `CRYPTO_DOMAIN_REGISTRY.tsv`.
pub const WIRE_PREFIX_DST: &[u8] = b"shekyl/p2p-wire-prefix-v1";

pub const PREFIX_LEN: usize = 8;

pub type NetworkId = [u8; 16];

/// The handshake id of the chain whose genesis block hash is
/// `genesis_block_hash`. First 16 bytes of
/// `cSHAKE256(S = NETWORK_ID_DST, X = genesis_block_hash)`, digest order.
#[must_use]
pub fn network_id_from_genesis(genesis_block_hash: &[u8; 32]) -> NetworkId {
    let digest = cshake256_32(NETWORK_ID_DST, genesis_block_hash);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[must_use]
pub fn prefix_for(network_id: &NetworkId) -> [u8; PREFIX_LEN] {
    let digest = cshake256_32(WIRE_PREFIX_DST, network_id);
    let mut out = [0u8; PREFIX_LEN];
    out.copy_from_slice(&digest[..PREFIX_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_id_is_a_function_of_the_genesis_hash() {
        let a = [1u8; 32];
        let mut b = a;
        b[31] = 2;
        let id_a = network_id_from_genesis(&a);
        assert_eq!(id_a, network_id_from_genesis(&a));
        assert_ne!(id_a, network_id_from_genesis(&b));
        assert_ne!(prefix_for(&id_a), prefix_for(&network_id_from_genesis(&b)));
    }
}
