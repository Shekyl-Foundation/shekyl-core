// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Production network ids for the daemon. The bytes live in
//! `shekyl-p2p-transport::prefix`. C++ asks; it does not state a byte.
//!
//! `nettype` is `cryptonote::network_type`: mainnet 0, testnet 1, stagenet 2,
//! fakechain 3. Fakechain uses the mainnet id. Any other byte is refused.

use shekyl_p2p_transport::{MAINNET_ID, STAGENET_ID, TESTNET_ID};

/// Writes the 16-byte id for `nettype` into `out`. Returns 0, or -1 when
/// `out` is null or `nettype` is not one of the four networks.
#[no_mangle]
pub extern "C" fn shekyl_network_id(nettype: u8, out: *mut u8) -> i32 {
    if out.is_null() {
        return -1;
    }
    let id = match nettype {
        0 | 3 => MAINNET_ID,
        1 => TESTNET_ID,
        2 => STAGENET_ID,
        _ => return -1,
    };
    // The caller asked for 16 bytes and `id` is `[u8; 16]`.
    unsafe { std::ptr::copy_nonoverlapping(id.as_ptr(), out, id.len()) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_p2p_transport::{prefix_for, MAINNET_PREFIX, STAGENET_PREFIX, TESTNET_PREFIX};

    #[test]
    fn the_four_networks_are_the_alpha6_ids() {
        let mut out = [0u8; 16];
        assert_eq!(shekyl_network_id(0, out.as_mut_ptr()), 0);
        assert_eq!(out, MAINNET_ID);
        assert_eq!(shekyl_network_id(3, out.as_mut_ptr()), 0);
        assert_eq!(out, MAINNET_ID);
        assert_eq!(shekyl_network_id(1, out.as_mut_ptr()), 0);
        assert_eq!(out, TESTNET_ID);
        assert_eq!(shekyl_network_id(2, out.as_mut_ptr()), 0);
        assert_eq!(out, STAGENET_ID);
        assert_eq!(shekyl_network_id(4, out.as_mut_ptr()), -1);
        assert_eq!(shekyl_network_id(0, std::ptr::null_mut()), -1);
        assert_eq!(prefix_for(&MAINNET_ID), MAINNET_PREFIX);
        assert_eq!(prefix_for(&TESTNET_ID), TESTNET_PREFIX);
        assert_eq!(prefix_for(&STAGENET_ID), STAGENET_PREFIX);
    }
}
