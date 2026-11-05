// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Production network ids for the daemon.
//!
//! `shekyl_network_id(nettype)` is the network's id: `network_id_from_genesis`
//! of its table genesis (`Network::network_id`). The genesis hash
//! is the pin this build already holds. C++ asks; it does not state a byte.
//!
//! `nettype` is the network's one code (`cryptonote::network_type`),
//! decoded by [`Network::from_code`]; each network, regtest included, has
//! its own genesis and so its own id (`NETWORK_IDENTITY.md` NI-Q8). Any
//! other byte is refused.
//!
//! The derivation records nothing: it answers for whichever network is
//! asked. The dialer's seeds are recorded by
//! [`crate::dialer_ffi::shekyl_dialer_note_network`] from the network the
//! daemon actually chose.

use shekyl_rpc_types::Network;

/// The 16-byte id of the network `cryptonote::network_type` code `nettype`
/// names, for Rust callers; `None` for any other code.
#[must_use]
pub fn network_id_of(nettype: u8) -> Option<[u8; 16]> {
    Network::from_code(nettype).map(Network::network_id)
}

/// Writes the 16-byte id for `nettype` into `out`. Returns 0, or -1 when
/// `out` is null or `nettype` is not one of the four networks.
#[no_mangle]
pub extern "C" fn shekyl_network_id(nettype: u8, out: *mut u8) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(id) = network_id_of(nettype) else {
        return -1;
    };
    // The caller asked for 16 bytes and `id` is `[u8; 16]`.
    unsafe { std::ptr::copy_nonoverlapping(id.as_ptr(), out, id.len()) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_p2p_transport::{network_id_from_genesis, prefix_for};

    /// Recorded output of `network_id_from_genesis` over each network's
    /// table genesis (re-recorded 2026-11-03 with the round's regenesis,
    /// `NETWORK_IDENTITY.md` NI-R4). A regenesis that moves a hash fails this
    /// until the bytes are re-recorded with it. These are not a second
    /// definition of the id.
    const RECORDED: [(Network, [u8; 16], [u8; 8]); 4] = [
        (
            Network::Mainnet,
            [
                0xCF, 0x9F, 0x42, 0x83, 0x03, 0x2B, 0x6C, 0xA1, 0x95, 0x45, 0xF2, 0x69, 0x6A, 0x22,
                0x8D, 0x80,
            ],
            [0x1D, 0xE3, 0x4F, 0x8F, 0xBC, 0x89, 0x4A, 0xC5],
        ),
        (
            Network::Testnet,
            [
                0xFF, 0x92, 0x7A, 0x10, 0x9A, 0xBA, 0x94, 0x00, 0xD6, 0x81, 0xE9, 0xF9, 0x93, 0x4C,
                0x78, 0x60,
            ],
            [0x28, 0x88, 0xDE, 0x32, 0xEA, 0x8A, 0xA2, 0x34],
        ),
        (
            Network::Stagenet,
            [
                0x6A, 0xC7, 0x98, 0x95, 0xE5, 0x19, 0xD7, 0x01, 0xC3, 0x07, 0x6D, 0xEA, 0xE5, 0xEE,
                0xF0, 0xD8,
            ],
            [0xF3, 0x43, 0xF3, 0x68, 0xF6, 0x44, 0x4E, 0x6D],
        ),
        (
            Network::Regtest,
            [
                0x72, 0x4B, 0x36, 0xA3, 0xB4, 0x6F, 0x9C, 0xCD, 0x5E, 0x50, 0xC6, 0x3B, 0x6F, 0xB6,
                0xE7, 0x31,
            ],
            [0xAF, 0xE6, 0x47, 0xF3, 0xED, 0x6B, 0x9D, 0x6E],
        ),
    ];

    fn fill(nettype: u8) -> [u8; 16] {
        let mut out = [0u8; 16];
        assert_eq!(shekyl_network_id(nettype, out.as_mut_ptr()), 0);
        out
    }

    /// Every network, regtest included, derives its own recorded id from its
    /// own genesis, and the FFI hands out exactly that (NI-Q8: regtest's id
    /// is not mainnet's).
    #[test]
    fn each_genesis_derives_its_recorded_id_and_prefix() {
        for (net, id_kat, prefix_kat) in RECORDED {
            let id = network_id_from_genesis(&net.genesis().hash());
            assert_eq!(id, id_kat, "{net}");
            assert_eq!(prefix_for(&id), prefix_kat, "{net}");
            assert_eq!(fill(net.code()), id, "{net}");
        }
        let mut refused = [0u8; 16];
        assert_eq!(shekyl_network_id(4, refused.as_mut_ptr()), -1);
        assert_eq!(shekyl_network_id(0, std::ptr::null_mut()), -1);
    }
}
