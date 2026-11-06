// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HRP lookups over the network table (`shekyl_network`).
//!
//! The network type and every network's prefixes live in one table
//! (`docs/design/NETWORK_IDENTITY.md`, NI-Q3); this module reads them for
//! address encoding and decoding.

pub use shekyl_network::Network;

// --- HRP lookups ---

/// Classical address HRP for a given network.
#[must_use]
pub fn classical_hrp(net: Network) -> &'static str {
    net.prefixes().classical
}

/// PQC segment A HRP for a given network.
#[must_use]
pub fn pqc_a_hrp(net: Network) -> &'static str {
    net.prefixes().pqc_a
}

/// PQC segment B HRP for a given network.
#[must_use]
pub fn pqc_b_hrp(net: Network) -> &'static str {
    net.prefixes().pqc_b
}

/// Multisig address HRP for a given network (PQC_MULTISIG.md SS6.1).
#[must_use]
pub fn multisig_hrp(net: Network) -> &'static str {
    net.prefixes().multisig
}

/// Distinguishes single-sig from multisig addresses at the HRP level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressKind {
    SingleSig,
    Multisig,
}

/// Infer the network from a classical (single-sig) segment HRP string.
/// HRPs compare case-insensitively, as Bech32m defines them.
#[must_use]
pub fn network_from_hrp(hrp: &str) -> Option<Network> {
    match network_and_kind_from_hrp(hrp) {
        Some((net, AddressKind::SingleSig)) => Some(net),
        _ => None,
    }
}

/// Infer the network and address kind from a segment-head HRP: a
/// classical (single-sig) or multisig prefix.
#[must_use]
pub fn network_and_kind_from_hrp(hrp: &str) -> Option<(Network, AddressKind)> {
    let lower = hrp.to_lowercase();
    Network::ALL.into_iter().find_map(|net| {
        let prefixes = net.prefixes();
        if prefixes.classical == lower {
            Some((net, AddressKind::SingleSig))
        } else if prefixes.multisig == lower {
            Some((net, AddressKind::Multisig))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multisig_hrp_distinct_from_single_sig() {
        for net in Network::ALL {
            assert_ne!(classical_hrp(net), multisig_hrp(net));
        }
    }

    #[test]
    fn network_from_hrp_works() {
        for net in Network::ALL {
            assert_eq!(network_from_hrp(classical_hrp(net)), Some(net));
            assert_eq!(
                network_from_hrp(&classical_hrp(net).to_uppercase()),
                Some(net)
            );
            assert_eq!(
                network_from_hrp(multisig_hrp(net)),
                None,
                "multisig HRP not returned by single-sig lookup"
            );
        }
        assert_eq!(network_from_hrp("rshekyl"), Some(Network::Regtest));
        assert_eq!(network_from_hrp("bitcoin"), None);
    }

    #[test]
    fn network_and_kind_from_hrp_works() {
        for net in Network::ALL {
            assert_eq!(
                network_and_kind_from_hrp(classical_hrp(net)),
                Some((net, AddressKind::SingleSig))
            );
            assert_eq!(
                network_and_kind_from_hrp(multisig_hrp(net)),
                Some((net, AddressKind::Multisig))
            );
        }
        assert_eq!(network_and_kind_from_hrp("bitcoin"), None);
        assert_eq!(
            network_and_kind_from_hrp("skpq"),
            None,
            "a PQC segment HRP heads no address"
        );
    }
}
