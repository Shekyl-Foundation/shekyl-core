// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The compiled seed addresses (slice 1 brief §3, Rick 2026-10-11).
//!
//! Seeds are ordinary peers: the daemon admits them to gray at each start
//! as operator-named addresses, and they reach white only through a drawn
//! dial. The list is data the dialer reads, not an arm of the fill. It
//! moved here from the C++ `get_ip_seed_nodes`, which the cutover deletes
//! with its callers.
//!
//! There are no onion seeds yet: a node whose only hidden-service peers
//! would come from this list has no bootstrap path until Shekyl's own
//! hidden services exist (Q12-R1). `--add-peer` bootstraps one by hand.

use std::net::Ipv4Addr;

use shekyl_peerlist::NetworkAddress;

/// Which network's seeds to admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedNetwork {
    /// Mainnet, P2P port 11021.
    Mainnet,
    /// Testnet, P2P port 12021.
    Testnet,
    /// Stagenet and regtest: no seeds.
    None,
}

/// The Foundation's six clearnet seed hosts.
const SEED_HOSTS: [([u8; 4], &str); 6] = [
    ([134, 199, 166, 22], "seedaus, Sydney"),
    ([45, 77, 147, 65], "seeduse, US East"),
    ([45, 76, 171, 128], "seedusw, US West"),
    ([45, 77, 66, 189], "seedeu, EU Frankfurt"),
    ([139, 162, 71, 114], "seedjp, Tokyo"),
    ([104, 64, 59, 31], "seedbrz, Brazil"),
];

/// The seed addresses of `network`, each with that network's P2P port.
#[must_use]
pub fn seeds(network: SeedNetwork) -> Vec<NetworkAddress> {
    let port = match network {
        SeedNetwork::Mainnet => 11021,
        SeedNetwork::Testnet => 12021,
        SeedNetwork::None => return Vec::new(),
    };
    SEED_HOSTS
        .iter()
        .map(|(octets, _)| NetworkAddress::Ipv4 {
            ip: Ipv4Addr::from(*octets),
            port,
        })
        .collect()
}
