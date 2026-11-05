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
    /// table genesis, as the stdlib oracle (`scripts/kat/stdlib_cshake.py`)
    /// derives them (`NETWORK_IDENTITY.md` NI-R4). A regenesis that moves a hash fails this
    /// until the bytes are re-recorded with it. These are not a second
    /// definition of the id.
    const RECORDED: [(Network, [u8; 16], [u8; 8]); 4] = [
        (
            Network::Mainnet,
            [
                0x9E, 0x77, 0xDD, 0x8E, 0xF6, 0x4F, 0xAE, 0xF2, 0xC4, 0x3C, 0x42, 0xB1, 0xCF, 0x5B,
                0xC5, 0x54,
            ],
            [0x6A, 0xEE, 0x8B, 0x20, 0x26, 0x94, 0xAA, 0xA4],
        ),
        (
            Network::Testnet,
            [
                0x4E, 0x94, 0x8C, 0xF2, 0x48, 0x14, 0x73, 0xD8, 0x94, 0x9D, 0xA6, 0x45, 0x69, 0x24,
                0x64, 0xDE,
            ],
            [0xA3, 0x2D, 0x47, 0x0A, 0x0E, 0xF9, 0x45, 0x7E],
        ),
        (
            Network::Stagenet,
            [
                0x3A, 0x6B, 0x9B, 0x9F, 0xF5, 0xB7, 0x32, 0x7C, 0xB4, 0x4B, 0x19, 0x2C, 0xC1, 0xD9,
                0x8E, 0xC8,
            ],
            [0x5E, 0xAF, 0x7F, 0x64, 0xCE, 0xFF, 0x6F, 0x5B],
        ),
        (
            Network::Regtest,
            [
                0x39, 0x90, 0x64, 0x29, 0x84, 0x36, 0xB7, 0x6E, 0x73, 0x49, 0xDF, 0x0A, 0x18, 0xCF,
                0xBA, 0xDF,
            ],
            [0xCB, 0x51, 0xD2, 0xBD, 0x58, 0xBB, 0x9A, 0x64],
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
