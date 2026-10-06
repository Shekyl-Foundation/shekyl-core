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

/// Writes the 32-byte genesis pin for `nettype` into `out`.
///
/// The pin is [`genesis_hash_for`]. Fakechain's pin is mainnet's. Returns
/// 0, or -1 when `out` is null or `nettype` is not one of the four networks.
///
/// # Safety
/// `out` points at 32 bytes the caller owns.
#[no_mangle]
pub unsafe extern "C" fn shekyl_genesis_hash(nettype: u8, out: *mut u8) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(net) = DaemonNetwork::from_cryptonote(nettype) else {
        return -1;
    };
    let pin = genesis_hash_for(net);
    unsafe { std::ptr::copy_nonoverlapping(pin.as_ptr(), out, pin.len()) };
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
        0xC9, 0xFF, 0x78, 0x76, 0xB6, 0x8A, 0x92, 0xF9, 0x4E, 0xC0, 0x19, 0x87, 0x2B, 0xE7, 0x89,
        0x57,
    ];
    const STAGENET_ID: [u8; 16] = [
        0xC1, 0xE3, 0xB5, 0x49, 0x8D, 0xB1, 0xE7, 0xA6, 0x3B, 0xB8, 0x92, 0xC1, 0x9E, 0x7F, 0x76,
        0x8C,
    ];
    const MAINNET_PREFIX: [u8; 8] = [0xA7, 0xBE, 0xD0, 0xCC, 0xF3, 0xF6, 0x23, 0xE8];
    const TESTNET_PREFIX: [u8; 8] = [0x4C, 0x77, 0x1D, 0x50, 0x3D, 0x5D, 0x43, 0xD9];
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
        let mut genesis = [0u8; 32];
        assert_eq!(unsafe { shekyl_genesis_hash(1, genesis.as_mut_ptr()) }, 0);
        assert_eq!(genesis, genesis_hash_for(DaemonNetwork::Testnet));
        assert_eq!(unsafe { shekyl_genesis_hash(3, genesis.as_mut_ptr()) }, 0);
        assert_eq!(genesis, genesis_hash_for(DaemonNetwork::Mainnet));
        assert_eq!(unsafe { shekyl_genesis_hash(4, genesis.as_mut_ptr()) }, -1);
        assert_eq!(unsafe { shekyl_genesis_hash(0, std::ptr::null_mut()) }, -1);
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
