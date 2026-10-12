// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Address validity: which addresses a peer may not hand this node
//! (`P2P_3_SLICE_1_PEERLIST_BRIEF.md` §2, ruled 2026-10-11; R4 2026-10-12).
//!
//! A remote peer that sends `192.168.1.1:80` or `10.0.0.5:22` is aiming
//! this node's dialer at its own LAN. The rule turns on who supplied the
//! address, not on its range: an address learned from the network is
//! refused when it is in the refused set, and an address the operator
//! named is admitted whatever its range.
//!
//! The tables below are the check. It does not call `Ipv4Addr::is_global`
//! or `Ipv6Addr::is_global`: both are unstable, and a later std change
//! would move a network rule.
//!
//! `--allow-local-ip` does not add a branch to the rule. It chooses the
//! set the rule reads: [`RefusedSet::NON_GLOBAL`], or [`RefusedSet::EMPTY`]
//! for a private test network whose nodes find each other by peerlist
//! exchange.

use std::net::IpAddr;

use shekyl_net_address::NetworkAddress;

/// One refused IPv4 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeV4 {
    /// What the range is, for a log line and a test message.
    pub name: &'static str,
    /// The first address of the range.
    pub base: [u8; 4],
    /// The prefix length in bits.
    pub prefix: u8,
}

/// One refused IPv6 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeV6 {
    /// What the range is, for a log line and a test message.
    pub name: &'static str,
    /// The first address of the range.
    pub base: [u8; 16],
    /// The prefix length in bits.
    pub prefix: u8,
}

/// The refused IPv4 ranges (brief §2). `198.18.0.0/15` is the
/// benchmarking range (RFC 2544): a peer that names one is aiming a dial
/// at a device on a lab network, the same class as a private LAN address.
pub const REFUSED_V4: &[RangeV4] = &[
    v4("this network", [0, 0, 0, 0], 8),
    v4("private (10/8)", [10, 0, 0, 0], 8),
    v4("carrier-grade NAT", [100, 64, 0, 0], 10),
    v4("loopback", [127, 0, 0, 0], 8),
    v4("link-local", [169, 254, 0, 0], 16),
    v4("private (172.16/12)", [172, 16, 0, 0], 12),
    v4("private (192.168/16)", [192, 168, 0, 0], 16),
    v4("documentation (192.0.2/24)", [192, 0, 2, 0], 24),
    v4("documentation (198.51.100/24)", [198, 51, 100, 0], 24),
    v4("documentation (203.0.113/24)", [203, 0, 113, 0], 24),
    v4("benchmarking", [198, 18, 0, 0], 15),
    v4("multicast", [224, 0, 0, 0], 4),
    v4("reserved", [240, 0, 0, 0], 4),
];

/// The refused IPv6 ranges (brief §2). The IPv4-mapped prefix
/// (`::ffff:0:0/96`) is refused whole, not rewritten into the embedded
/// IPv4: the transport dials the 16 bytes unchanged, so
/// `::ffff:192.168.1.1` is a dial to `192.168.1.1`, and `::ffff:8.8.8.8`
/// is a second spelling of an address the IPv4 variant already names.
pub const REFUSED_V6: &[RangeV6] = &[
    v6("unspecified", [0; 16], 128),
    v6(
        "loopback",
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        128,
    ),
    v6("link-local", head([0xfe, 0x80, 0, 0]), 10),
    v6("unique local", head([0xfc, 0, 0, 0]), 7),
    v6("documentation", head([0x20, 0x01, 0x0d, 0xb8]), 32),
    v6(
        "benchmarking",
        [0x20, 0x01, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        48,
    ),
    v6("multicast", head([0xff, 0, 0, 0]), 8),
    v6("6to4", head([0x20, 0x02, 0, 0]), 16),
    v6("Teredo", head([0x20, 0x01, 0, 0]), 32),
    v6(
        "NAT64",
        [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        96,
    ),
    v6(
        "IPv4-mapped",
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
        96,
    ),
];

const fn v4(name: &'static str, base: [u8; 4], prefix: u8) -> RangeV4 {
    RangeV4 { name, base, prefix }
}

const fn v6(name: &'static str, base: [u8; 16], prefix: u8) -> RangeV6 {
    RangeV6 { name, base, prefix }
}

/// Sixteen bytes that start with `first` and are zero after it.
const fn head(first: [u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0] = first[0];
    out[1] = first[1];
    out[2] = first[2];
    out[3] = first[3];
    out
}

/// Whether the first `prefix` bits of `address` and `base` are equal.
fn in_prefix(address: &[u8], base: &[u8], prefix: u8) -> bool {
    let whole = usize::from(prefix / 8);
    let rest = prefix % 8;
    if address[..whole] != base[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    address[whole] & mask == base[whole] & mask
}

/// The set of addresses the network may not hand this node.
///
/// A constructor input of [`crate::Peerlist`]. The daemon builds
/// [`Self::NON_GLOBAL`], or [`Self::EMPTY`] under `--allow-local-ip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusedSet {
    v4: &'static [RangeV4],
    v6: &'static [RangeV6],
    port_zero: bool,
}

impl RefusedSet {
    /// Every address that is not dialable on the public internet: the
    /// ranges of [`REFUSED_V4`] and [`REFUSED_V6`], and port 0 on every
    /// address type.
    pub const NON_GLOBAL: Self = Self {
        v4: REFUSED_V4,
        v6: REFUSED_V6,
        port_zero: true,
    };

    /// Nothing is refused: `--allow-local-ip`.
    pub const EMPTY: Self = Self {
        v4: &[],
        v6: &[],
        port_zero: false,
    };

    /// Why `address` is in the set, or `None` when it is not.
    #[must_use]
    pub fn refuses(&self, address: &NetworkAddress) -> Option<&'static str> {
        let port = match address {
            NetworkAddress::Ipv4 { port, .. }
            | NetworkAddress::Ipv6 { port, .. }
            | NetworkAddress::Tor { port, .. } => *port,
        };
        if self.port_zero && port == 0 {
            return Some("port 0");
        }
        match address.ip() {
            Some(IpAddr::V4(ip)) => self
                .v4
                .iter()
                .find(|range| in_prefix(&ip.octets(), &range.base, range.prefix))
                .map(|range| range.name),
            Some(IpAddr::V6(ip)) => self
                .v6
                .iter()
                .find(|range| in_prefix(&ip.octets(), &range.base, range.prefix))
                .map(|range| range.name),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{in_prefix, RefusedSet, REFUSED_V4, REFUSED_V6};

    #[test]
    fn a_prefix_compares_whole_bytes_and_the_bits_of_the_last_one() {
        assert!(in_prefix(&[172, 16, 0, 1], &[172, 16, 0, 0], 12));
        assert!(in_prefix(&[172, 31, 255, 255], &[172, 16, 0, 0], 12));
        assert!(!in_prefix(&[172, 32, 0, 0], &[172, 16, 0, 0], 12));
        assert!(!in_prefix(&[172, 15, 255, 255], &[172, 16, 0, 0], 12));
        assert!(in_prefix(&[1, 2, 3, 4], &[9, 9, 9, 9], 0));
        assert!(in_prefix(&[1, 2, 3, 4], &[1, 2, 3, 4], 32));
        assert!(!in_prefix(&[1, 2, 3, 5], &[1, 2, 3, 4], 32));
    }

    #[test]
    fn every_base_has_no_bits_set_past_its_prefix() {
        for range in REFUSED_V4 {
            let mut masked = range.base;
            for (i, byte) in masked.iter_mut().enumerate() {
                let bit = u8::try_from(i * 8).expect("small");
                if range.prefix <= bit {
                    *byte = 0;
                } else if range.prefix < bit + 8 {
                    *byte &= 0xffu8 << (8 - (range.prefix - bit));
                }
            }
            assert_eq!(masked, range.base, "{}", range.name);
        }
        for range in REFUSED_V6 {
            let mut masked = range.base;
            for (i, byte) in masked.iter_mut().enumerate() {
                let bit = u8::try_from(i * 8).expect("small");
                if range.prefix <= bit {
                    *byte = 0;
                } else if range.prefix < bit.saturating_add(8) {
                    *byte &= 0xffu8 << (8 - (range.prefix - bit));
                }
            }
            assert_eq!(masked, range.base, "{}", range.name);
        }
    }

    #[test]
    fn the_non_global_set_reads_both_tables_and_the_empty_set_reads_none() {
        assert_eq!(RefusedSet::NON_GLOBAL.v4, REFUSED_V4);
        assert_eq!(RefusedSet::NON_GLOBAL.v6, REFUSED_V6);
        assert!(RefusedSet::NON_GLOBAL.port_zero);
        assert!(RefusedSet::EMPTY.v4.is_empty() && RefusedSet::EMPTY.v6.is_empty());
        assert!(!RefusedSet::EMPTY.port_zero);
    }
}
