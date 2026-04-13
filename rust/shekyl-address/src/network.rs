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
            _ => Err(format!("unknown network '{s}' -- expected mainnet, testnet, or stagenet")),
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

/// All classical HRPs across all networks.
const ALL_CLASSICAL_HRPS: &[(&str, Network)] = &[
    ("shekyl", Network::Mainnet),
    ("tshekyl", Network::Testnet),
    ("sshekyl", Network::Stagenet),
];

/// Infer the network from a classical segment HRP string.
pub fn network_from_hrp(hrp: &str) -> Option<Network> {
    let lower = hrp.to_lowercase();
    ALL_CLASSICAL_HRPS
        .iter()
        .find(|(h, _)| *h == lower.as_str())
        .map(|(_, net)| *net)
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
            }
        }
    }

    #[test]
    fn network_from_hrp_works() {
        assert_eq!(network_from_hrp("shekyl"), Some(Network::Mainnet));
        assert_eq!(network_from_hrp("tshekyl"), Some(Network::Testnet));
        assert_eq!(network_from_hrp("sshekyl"), Some(Network::Stagenet));
        assert_eq!(network_from_hrp("SHEKYL"), Some(Network::Mainnet));
        assert_eq!(network_from_hrp("bitcoin"), None);
    }
}
