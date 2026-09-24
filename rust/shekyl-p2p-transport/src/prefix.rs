// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Eight-byte clearnet prefix. PWD-T5: the first eight bytes of
//! `cSHAKE256(S = "shekyl/p2p-wire-prefix-v1", X = network_id)`.

use shekyl_crypto_hash::cshake256_32;

/// Customization string. Registered in `CRYPTO_DOMAIN_REGISTRY.tsv`.
pub const WIRE_PREFIX_DST: &[u8] = b"shekyl/p2p-wire-prefix-v1";

pub const PREFIX_LEN: usize = 8;

pub type NetworkId = [u8; 16];

#[must_use]
pub fn prefix_for(network_id: &NetworkId) -> [u8; PREFIX_LEN] {
    let digest = cshake256_32(WIRE_PREFIX_DST, network_id);
    let mut out = [0u8; PREFIX_LEN];
    out.copy_from_slice(&digest[..PREFIX_LEN]);
    out
}

/// Mainnet, testnet, and stagenet prefixes pinned by PWD-T5.
pub const MAINNET_PREFIX: [u8; PREFIX_LEN] = hex_prefix(0xAFBC_D4D1_FAB9_8B6D);
pub const TESTNET_PREFIX: [u8; PREFIX_LEN] = hex_prefix(0xF0B3_52E8_928F_8D56);
pub const STAGENET_PREFIX: [u8; PREFIX_LEN] = hex_prefix(0x5C29_42C0_F9F9_8A21);

const fn hex_prefix(v: u64) -> [u8; PREFIX_LEN] {
    v.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAINNET_ID: NetworkId = hex_id(0x556C_A970_8FF9_1F7A, 0x4069_DAF3_FC55_BBBD);
    const TESTNET_ID: NetworkId = hex_id(0x78CE_055B_BBDA_7956, 0xB9C8_A1A2_EC1F_7672);
    const STAGENET_ID: NetworkId = hex_id(0x2D21_9754_A1BD_79BA, 0x0540_FDFB_8DC8_A4AE);

    const fn hex_id(hi: u64, lo: u64) -> NetworkId {
        let mut out = [0u8; 16];
        let h = hi.to_be_bytes();
        let l = lo.to_be_bytes();
        let mut i = 0;
        while i < 8 {
            out[i] = h[i];
            out[i + 8] = l[i];
            i += 1;
        }
        out
    }

    #[test]
    fn pinned_network_prefixes() {
        assert_eq!(prefix_for(&MAINNET_ID), MAINNET_PREFIX);
        assert_eq!(prefix_for(&TESTNET_ID), TESTNET_PREFIX);
        assert_eq!(prefix_for(&STAGENET_ID), STAGENET_PREFIX);
        assert_ne!(MAINNET_PREFIX, TESTNET_PREFIX);
        assert_ne!(MAINNET_PREFIX, STAGENET_PREFIX);
        assert_ne!(TESTNET_PREFIX, STAGENET_PREFIX);
        assert_eq!(prefix_for(&MAINNET_ID), prefix_for(&MAINNET_ID));
    }
}
