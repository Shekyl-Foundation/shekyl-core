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
    /// table genesis (re-recorded 2026-11-04 with the round's regenesis,
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
                0x8C, 0x20, 0x77, 0x93, 0xB0, 0xF7, 0xA3, 0x73, 0xDD, 0x41, 0x88, 0x13, 0x47, 0x7E,
                0x7A, 0x72,
            ],
            [0x00, 0x88, 0xE5, 0x68, 0x5C, 0xF7, 0xC5, 0x07],
        ),
        (
            Network::Stagenet,
            [
                0xD8, 0x39, 0x82, 0x31, 0x61, 0xB3, 0x4F, 0xBE, 0xD9, 0x69, 0xD6, 0x41, 0x1E, 0x64,
                0x9D, 0x61,
            ],
            [0x5A, 0xB5, 0x7F, 0x6C, 0xC7, 0xAF, 0x57, 0x17],
        ),
        (
            Network::Regtest,
            [
                0x65, 0x45, 0x66, 0x6F, 0x7B, 0x24, 0xEB, 0x45, 0xEF, 0x7C, 0x05, 0x0D, 0xE5, 0x93,
                0x23, 0x30,
            ],
            [0x1E, 0x6D, 0xE1, 0x3D, 0x68, 0xA3, 0x4E, 0x5C],
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
