// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Network types and HRP lookup tables for Shekyl address encoding.

use std::fmt;
use std::str::FromStr;

/// Shekyl network type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Network {
    Mainnet,
    Testnet,
    Stagenet,
}

impl Network {
    /// Numeric discriminant used across FFI (0=mainnet, 1=testnet, 2=stagenet).
    pub fn as_u8(self) -> u8 {
        match self {
            Network::Mainnet => 0,
            Network::Testnet => 1,
            Network::Stagenet => 2,
        }
    }

    /// Convert from FFI discriminant.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Network::Mainnet),
            1 => Some(Network::Testnet),
            2 => Some(Network::Stagenet),
            _ => None,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
            Network::Stagenet => write!(f, "stagenet"),
        }
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Network::Mainnet),
            "testnet" => Ok(Network::Testnet),
            "stagenet" => Ok(Network::Stagenet),
            _ => Err(format!(
                "unknown network '{s}' -- expected mainnet, testnet, or stagenet"
            )),
        }
    }
}

// --- HRP lookup tables ---

/// Classical address HRP for a given network.
pub fn classical_hrp(net: Network) -> &'static str {
    match net {
        Network::Mainnet => "shekyl",
        Network::Testnet => "tshekyl",
        Network::Stagenet => "sshekyl",
    }
}

/// PQC segment A HRP for a given network.
pub fn pqc_a_hrp(net: Network) -> &'static str {
    match net {
        Network::Mainnet => "skpq",
        Network::Testnet => "tskpq",
        Network::Stagenet => "sskpq",
    }
}

/// PQC segment B HRP for a given network.
pub fn pqc_b_hrp(net: Network) -> &'static str {
    match net {
        Network::Mainnet => "skpq2",
        Network::Testnet => "tskpq2",
        Network::Stagenet => "sskpq2",
    }
}

/// Multisig address HRP for a given network (PQC_MULTISIG.md SS6.1).
pub fn multisig_hrp(net: Network) -> &'static str {
    match net {
        Network::Mainnet => "shekyl1m",
        Network::Testnet => "shekyltest1m",
        Network::Stagenet => "sshekyl1m",
    }
}

/// All known HRPs mapped to (Network, AddressKind).
const ALL_HRPS: &[(&str, Network, AddressKind)] = &[
    ("shekyl", Network::Mainnet, AddressKind::SingleSig),
    ("tshekyl", Network::Testnet, AddressKind::SingleSig),
    ("sshekyl", Network::Stagenet, AddressKind::SingleSig),
    ("shekyl1m", Network::Mainnet, AddressKind::Multisig),
    ("shekyltest1m", Network::Testnet, AddressKind::Multisig),
    ("sshekyl1m", Network::Stagenet, AddressKind::Multisig),
];

/// Distinguishes single-sig from multisig addresses at the HRP level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressKind {
    SingleSig,
    Multisig,
}

/// Infer the network from a classical (single-sig) segment HRP string.
pub fn network_from_hrp(hrp: &str) -> Option<Network> {
    let lower = hrp.to_lowercase();
    ALL_HRPS
        .iter()
        .find(|(h, _, kind)| *h == lower.as_str() && *kind == AddressKind::SingleSig)
        .map(|(_, net, _)| *net)
}

/// Infer the network and address kind from any known HRP string.
pub fn network_and_kind_from_hrp(hrp: &str) -> Option<(Network, AddressKind)> {
    let lower = hrp.to_lowercase();
    ALL_HRPS
        .iter()
        .find(|(h, _, _)| *h == lower.as_str())
        .map(|(_, net, kind)| (*net, *kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u8() {
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            assert_eq!(Network::from_u8(net.as_u8()), Some(net));
        }
        assert_eq!(Network::from_u8(3), None);
        assert_eq!(Network::from_u8(255), None);
    }

    #[test]
    fn display_fromstr_roundtrip() {
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            let s = net.to_string();
            let parsed: Network = s.parse().unwrap();
            assert_eq!(parsed, net);
        }
    }

    #[test]
    fn fromstr_case_insensitive() {
        assert_eq!("MAINNET".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("Testnet".parse::<Network>().unwrap(), Network::Testnet);
    }

    #[test]
    fn fromstr_invalid() {
        assert!("devnet".parse::<Network>().is_err());
    }

    #[test]
    fn hrp_lookup_all_distinct() {
        let nets = [Network::Mainnet, Network::Testnet, Network::Stagenet];
        for i in 0..nets.len() {
            for j in (i + 1)..nets.len() {
                assert_ne!(classical_hrp(nets[i]), classical_hrp(nets[j]));
                assert_ne!(pqc_a_hrp(nets[i]), pqc_a_hrp(nets[j]));
                assert_ne!(pqc_b_hrp(nets[i]), pqc_b_hrp(nets[j]));
                assert_ne!(multisig_hrp(nets[i]), multisig_hrp(nets[j]));
            }
        }
    }

    #[test]
    fn multisig_hrp_distinct_from_single_sig() {
        for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            assert_ne!(classical_hrp(net), multisig_hrp(net));
        }
    }

    #[test]
    fn network_from_hrp_works() {
        assert_eq!(network_from_hrp("shekyl"), Some(Network::Mainnet));
        assert_eq!(network_from_hrp("tshekyl"), Some(Network::Testnet));
        assert_eq!(network_from_hrp("sshekyl"), Some(Network::Stagenet));
        assert_eq!(network_from_hrp("SHEKYL"), Some(Network::Mainnet));
        assert_eq!(network_from_hrp("bitcoin"), None);
        assert_eq!(network_from_hrp("shekyl1m"), None, "multisig HRP not returned by single-sig lookup");
    }

    #[test]
    fn network_and_kind_from_hrp_works() {
        assert_eq!(
            network_and_kind_from_hrp("shekyl"),
            Some((Network::Mainnet, AddressKind::SingleSig))
        );
        assert_eq!(
            network_and_kind_from_hrp("shekyl1m"),
            Some((Network::Mainnet, AddressKind::Multisig))
        );
        assert_eq!(
            network_and_kind_from_hrp("shekyltest1m"),
            Some((Network::Testnet, AddressKind::Multisig))
        );
        assert_eq!(network_and_kind_from_hrp("bitcoin"), None);
    }
}
