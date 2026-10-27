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
//! Each Foundation host is one row: its clearnet octets and, on testnet,
//! its v3 onion. Mainnet has no hidden service, so its list is the
//! clearnet hosts alone. Testnet's onions are the canonical Tor bootstrap
//! (Q12-R1, landed 2026-10-21): a node does not hand-configure them. A
//! connector admits only the rows of its own address type, and only after
//! the p2p section is applied, so a closed network is already the
//! population when the first wake draws.

use std::net::Ipv4Addr;

use shekyl_peerlist::NetworkAddress;

/// Which network's seeds to admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedNetwork {
    /// Mainnet. P2P port [`Self::MAINNET_P2P_PORT`].
    Mainnet,
    /// Testnet. P2P port [`Self::TESTNET_P2P_PORT`].
    Testnet,
    /// Stagenet and regtest: no compiled seeds.
    None,
}

impl SeedNetwork {
    /// Mainnet P2P port (`config::P2P_DEFAULT_PORT`).
    pub const MAINNET_P2P_PORT: u16 = 11021;

    /// Testnet P2P port (`config::testnet::P2P_DEFAULT_PORT`).
    ///
    /// The virtual port of each testnet seed onion is this same value.
    pub const TESTNET_P2P_PORT: u16 = 12021;

    /// The P2P port compiled into this network's seeds.
    ///
    /// [`Self::None`] has no seeds, so it has no port here. Stagenet's
    /// port and regtest's port stay with the daemon's network row.
    #[must_use]
    pub const fn p2p_port(self) -> Option<u16> {
        match self {
            Self::Mainnet => Some(Self::MAINNET_P2P_PORT),
            Self::Testnet => Some(Self::TESTNET_P2P_PORT),
            Self::None => None,
        }
    }
}

/// One Foundation seed host.
///
/// The clearnet address and the testnet onion are one row, so replacing
/// either keeps the pair. Mainnet reads the octets only.
struct SeedHost {
    /// Clearnet address octets.
    octets: [u8; 4],
    /// Where the host sits. A dial does not read this. It keeps the row
    /// recognizable when an address is replaced.
    #[allow(dead_code)] // the unit test pins the six places; a dial does not read them
    place: &'static str,
    /// This host's testnet v3 onion, including `.onion`.
    testnet_onion: &'static str,
}

/// The Foundation's six seed hosts, clearnet and testnet onion together.
const SEED_HOSTS: [SeedHost; 6] = [
    SeedHost {
        octets: [134, 199, 166, 22],
        place: "Sydney",
        testnet_onion: "aghoxa757l2wqribeto2hv2rk3wjwcwdqzvu5hjkqdjcm24nuhaszjqd.onion",
    },
    SeedHost {
        octets: [45, 77, 147, 65],
        place: "US East",
        testnet_onion: "23dkgevx7qnhrx2wmhmjvhsz2mpp54xomkujcvhuhm3ajgdciwztypad.onion",
    },
    SeedHost {
        octets: [45, 76, 171, 128],
        place: "US West",
        testnet_onion: "nqkfnallpz5kaoxkj2y6bmeifk4helrwp5z2fdtayo3rfzbx4q7z2tqd.onion",
    },
    SeedHost {
        octets: [45, 77, 66, 189],
        place: "EU Frankfurt",
        testnet_onion: "aks2vbpjb5ojfyqcataqedodws7ardjxczy76bqwmlv55mgfunsxoiyd.onion",
    },
    SeedHost {
        octets: [139, 162, 71, 114],
        place: "Tokyo",
        testnet_onion: "e2fafquqkf4jodx6rwh2akgyu2gy3spxcyc2ustnuqw46vrk2xe365qd.onion",
    },
    SeedHost {
        octets: [104, 64, 59, 31],
        place: "Brazil",
        testnet_onion: "mjgznic6uwrccelrq6fqjmmv2f7gaskd3nxcs76hjrrfc4tse7wioqqd.onion",
    },
];

/// The seed addresses of `network`, each on that network's P2P port.
///
/// Testnet returns the six clearnet addresses and then the six onions.
/// Mainnet returns the six clearnet addresses. Stagenet and regtest
/// return nothing.
#[must_use]
pub fn seeds(network: SeedNetwork) -> Vec<NetworkAddress> {
    let Some(port) = network.p2p_port() else {
        return Vec::new();
    };
    let mut addresses = Vec::with_capacity(SEED_HOSTS.len() * 2);
    for host in &SEED_HOSTS {
        addresses.push(NetworkAddress::Ipv4 {
            ip: Ipv4Addr::from(host.octets),
            port,
        });
    }
    if network == SeedNetwork::Testnet {
        for host in &SEED_HOSTS {
            debug_assert!(
                shekyl_onion_v3::is_v3_onion_hostname(host.testnet_onion),
                "a compiled testnet onion must be a v3 hostname the dialer can dial"
            );
            addresses.push(NetworkAddress::Tor {
                host: host.testnet_onion.to_owned(),
                port,
            });
        }
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clearnet rows, then the onion rows, each in [`SEED_HOSTS`] order.
    fn paired(port: u16, onions: bool) -> Vec<NetworkAddress> {
        let mut addresses = Vec::with_capacity(SEED_HOSTS.len() * 2);
        for host in &SEED_HOSTS {
            addresses.push(NetworkAddress::Ipv4 {
                ip: Ipv4Addr::from(host.octets),
                port,
            });
        }
        if onions {
            for host in &SEED_HOSTS {
                addresses.push(NetworkAddress::Tor {
                    host: host.testnet_onion.to_owned(),
                    port,
                });
            }
        }
        addresses
    }

    #[test]
    fn testnet_pairs_each_clearnet_host_with_its_onion() {
        assert_eq!(
            seeds(SeedNetwork::Testnet),
            paired(SeedNetwork::TESTNET_P2P_PORT, true)
        );
        for host in &SEED_HOSTS {
            assert!(
                shekyl_onion_v3::is_v3_onion_hostname(host.testnet_onion),
                "{} is not a v3 onion the dialer can dial",
                host.place
            );
        }
        let mut places: Vec<_> = SEED_HOSTS.iter().map(|host| host.place).collect();
        places.sort_unstable();
        places.dedup();
        assert_eq!(
            places.len(),
            SEED_HOSTS.len(),
            "each host names its own place"
        );
    }

    #[test]
    fn mainnet_is_the_clearnet_hosts() {
        assert_eq!(
            seeds(SeedNetwork::Mainnet),
            paired(SeedNetwork::MAINNET_P2P_PORT, false)
        );
    }

    #[test]
    fn stagenet_and_regtest_have_no_seeds() {
        assert!(seeds(SeedNetwork::None).is_empty());
        assert_eq!(SeedNetwork::None.p2p_port(), None);
    }
}
