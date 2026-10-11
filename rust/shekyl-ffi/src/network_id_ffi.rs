// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Production network ids for the daemon.
//!
//! `shekyl_network_id(nettype)` is
//! `network_id_from_genesis(genesis_hash_for(nettype))`. The genesis hash
//! is the pin this build already holds. C++ asks; it does not state a byte.
//!
//! `nettype` is `cryptonote::network_type`, decoded by
//! [`DaemonNetwork::from_cryptonote`]. Fakechain's pin is mainnet's genesis
//! today, so the two ids match; a genesis of fakechain's own rotates only
//! fakechain. Any other byte is refused.

use shekyl_p2p_transport::network_id_from_genesis;
use shekyl_rpc_types::{genesis_hash_for, DaemonNetwork};

/// Writes the 16-byte id for `nettype` into `out`. Returns 0, or -1 when
/// `out` is null or `nettype` is not one of the four networks.
#[no_mangle]
pub extern "C" fn shekyl_network_id(nettype: u8, out: *mut u8) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(net) = DaemonNetwork::from_cryptonote(nettype) else {
        return -1;
    };
    let id = network_id_from_genesis(&genesis_hash_for(net));
    // The caller asked for 16 bytes and `id` is `[u8; 16]`.
    unsafe { std::ptr::copy_nonoverlapping(id.as_ptr(), out, id.len()) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_p2p_transport::prefix_for;

    /// Recorded output of `network_id_from_genesis(genesis_hash_for(net))`.
    /// A regenesis that moves the hash fails this until the bytes are
    /// re-recorded with it. These are not a second definition of the id.
    const MAINNET_ID: [u8; 16] = [
        0x8E, 0x2F, 0x85, 0x4E, 0xE0, 0x62, 0x3A, 0x16, 0xD1, 0x21, 0x84, 0x96, 0xDC, 0x17, 0xD3,
        0x98,
    ];
    const TESTNET_ID: [u8; 16] = [
        0xD6, 0x1A, 0xF1, 0xFE, 0x44, 0x75, 0xB6, 0x75, 0x4B, 0x5F, 0x03, 0x40, 0xAA, 0x73, 0x5A,
        0x63,
    ];
    const STAGENET_ID: [u8; 16] = [
        0xC1, 0xE3, 0xB5, 0x49, 0x8D, 0xB1, 0xE7, 0xA6, 0x3B, 0xB8, 0x92, 0xC1, 0x9E, 0x7F, 0x76,
        0x8C,
    ];
    const MAINNET_PREFIX: [u8; 8] = [0xA7, 0xBE, 0xD0, 0xCC, 0xF3, 0xF6, 0x23, 0xE8];
    const TESTNET_PREFIX: [u8; 8] = [0xC3, 0xDC, 0x15, 0x69, 0x01, 0x25, 0x72, 0x8A];
    const STAGENET_PREFIX: [u8; 8] = [0x16, 0x61, 0x95, 0x00, 0x3A, 0xFF, 0x95, 0x3A];

    fn fill(nettype: u8) -> [u8; 16] {
        let mut out = [0u8; 16];
        assert_eq!(shekyl_network_id(nettype, out.as_mut_ptr()), 0);
        out
    }

    #[test]
    fn each_genesis_derives_its_recorded_id_and_prefix() {
        let cases = [
            (DaemonNetwork::Mainnet, 0u8, MAINNET_ID, MAINNET_PREFIX),
            (DaemonNetwork::Testnet, 1, TESTNET_ID, TESTNET_PREFIX),
            (DaemonNetwork::Stagenet, 2, STAGENET_ID, STAGENET_PREFIX),
        ];
        for (net, code, id_kat, prefix_kat) in cases {
            let id = network_id_from_genesis(&genesis_hash_for(net));
            assert_eq!(id, id_kat);
            assert_eq!(prefix_for(&id), prefix_kat);
            assert_eq!(fill(code), id);
        }
        assert_eq!(fill(3), MAINNET_ID);
        assert_eq!(
            genesis_hash_for(DaemonNetwork::Fakechain),
            genesis_hash_for(DaemonNetwork::Mainnet)
        );
        assert_ne!(MAINNET_ID, TESTNET_ID);
        assert_ne!(MAINNET_ID, STAGENET_ID);
        assert_ne!(TESTNET_ID, STAGENET_ID);
        assert_ne!(MAINNET_PREFIX, TESTNET_PREFIX);
        assert_ne!(MAINNET_PREFIX, STAGENET_PREFIX);
        assert_ne!(TESTNET_PREFIX, STAGENET_PREFIX);
        let mut refused = [0u8; 16];
        assert_eq!(shekyl_network_id(4, refused.as_mut_ptr()), -1);
        assert_eq!(shekyl_network_id(0, std::ptr::null_mut()), -1);
    }
}
