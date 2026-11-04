// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one network table (`docs/design/NETWORK_IDENTITY.md`, NI-Q3).
//!
//! Every Shekyl network, mainnet, testnet, stagenet and regtest, is a row
//! in one table and goes through one code path. A network differs from the
//! others only as data in its row; nothing branches on which network it is
//! (rule 71), and nothing treats one network as another.
//!
//! A network has two forms (NI-R10):
//!
//! - its **name**, the root: the tag `shekyl/<network>` ([`Network::tag`]),
//!   fixed before genesis exists. Key derivation, address prefixes and the
//!   genesis coinbase use it.
//! - its **id**, derived: [`network_id_from_genesis`] of the genesis block
//!   hash, used by everything after genesis: the handshake and wire prefix,
//!   the store pin, the pool seal and signing.
//!
//! Genesis commits to the name in its coinbase, so the id commits to it.
//!
//! Regtest's armed levers are [`Lever`]s in its row ([`Network::permits`],
//! NI-R6); every other row permits none. Staging flags ([`Staging`], NI-R9)
//! are a separate class: candidate mainnet behaviour staged on the test
//! networks, each with an owner and an exit, none surviving mainnet
//! genesis.

#![deny(unsafe_code)]

use std::fmt;
use std::str::FromStr;

use shekyl_crypto_hash::cshake256_32;

mod genesis;
pub use genesis::Genesis;

/// A Shekyl network. The discriminant is the network's one code: the
/// wallet file's network byte, the FFI's network argument and the C++
/// `cryptonote::network_type` (NI-F5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "lowercase")
)]
#[repr(u8)]
pub enum Network {
    /// `mainnet`.
    Mainnet = 0,
    /// `testnet`.
    Testnet = 1,
    /// `stagenet`.
    Stagenet = 2,
    /// `regtest`: an ordinary network with its own genesis, prefixes and
    /// ports, whose row alone permits levers (NI-R6, NI-R8).
    Regtest = 3,
}

impl Network {
    /// Every network, in code order.
    pub const ALL: [Self; 4] = [Self::Mainnet, Self::Testnet, Self::Stagenet, Self::Regtest];

    /// This network's row.
    #[must_use]
    pub const fn row(self) -> &'static Row {
        &ROWS[self as usize]
    }

    /// The network's one numeric code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The network a code names; `None` for any other byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Mainnet),
            1 => Some(Self::Testnet),
            2 => Some(Self::Stagenet),
            3 => Some(Self::Regtest),
            _ => None,
        }
    }

    /// The network's name, as the operator writes it and the RPC wire
    /// carries it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.row().name
    }

    /// The network a name names. Exact and lowercase: one spelling per
    /// network, no aliases (rule 83).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|n| n.name() == name)
    }

    /// The network's tag, `shekyl/<name>`: the root of its identity
    /// (NI-R10). Key derivation is salted by it, and the genesis coinbase
    /// carries it.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        self.row().tag
    }

    /// The network's address prefixes.
    #[must_use]
    pub const fn prefixes(self) -> &'static Prefixes {
        &self.row().prefixes
    }

    /// The daemon's default ports on this network.
    #[must_use]
    pub const fn ports(self) -> Ports {
        self.row().ports
    }

    /// The seed hosts a node admits at start (the dialer's compiled
    /// seeds); empty where the network has none.
    #[must_use]
    pub const fn seeds(self) -> &'static [Seed] {
        self.row().seeds
    }

    /// The subdirectory of the daemon's root its default data directory
    /// is; `None` for the root itself.
    #[must_use]
    pub const fn subdirectory(self) -> Option<&'static str> {
        self.row().subdirectory
    }

    /// Whether this network's row permits `lever` (NI-R6).
    #[must_use]
    pub const fn permits(self, lever: Lever) -> bool {
        let permits = self.row().permits;
        let mut i = 0;
        while i < permits.len() {
            if permits[i] as u8 == lever as u8 {
                return true;
            }
            i += 1;
        }
        false
    }

    /// The proof that this network's row permits `lever`, for a caller
    /// that holds no network (the store, rule 71): `None` where the row
    /// does not permit it.
    #[must_use]
    pub const fn permit(self, lever: Lever) -> Option<Permit> {
        if self.permits(lever) {
            Some(Permit { lever })
        } else {
            None
        }
    }

    /// This network's genesis.
    #[must_use]
    pub const fn genesis(self) -> &'static Genesis {
        self.row().genesis
    }

    /// The network id: the derived form of the network (NI-R10).
    #[must_use]
    pub fn network_id(self) -> NetworkId {
        network_id_from_genesis(&self.genesis().hash())
    }

    /// Whether this network accepts the staging flag `flag` (NI-R9).
    #[must_use]
    pub fn stages(self, flag: Staging) -> bool {
        self.row().staging.contains(&flag)
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A name that names no network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownNetwork(pub String);

impl fmt::Display for UnknownNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown network '{}': expected mainnet, testnet, stagenet or regtest",
            self.0
        )
    }
}

impl std::error::Error for UnknownNetwork {}

impl FromStr for Network {
    type Err = UnknownNetwork;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s).ok_or_else(|| UnknownNetwork(s.to_owned()))
    }
}

/// One network's row.
#[derive(Debug)]
pub struct Row {
    /// The network this row is.
    pub network: Network,
    /// The name.
    pub name: &'static str,
    /// `shekyl/<name>`.
    pub tag: &'static str,
    /// The address prefixes.
    pub prefixes: Prefixes,
    /// The daemon's default ports.
    pub ports: Ports,
    /// The default data directory's subdirectory of the daemon's root.
    pub subdirectory: Option<&'static str>,
    /// The levers this network permits: empty on every row but regtest's.
    pub permits: &'static [Lever],
    /// The staging flags this network accepts: test networks only.
    pub staging: &'static [Staging],
    /// The seed hosts a node admits at start; empty where there are none.
    pub seeds: &'static [Seed],
    /// The genesis.
    pub genesis: &'static Genesis,
}

/// One Foundation seed host on a network's row: its clearnet address and,
/// where the network runs one, its v3 onion (with `.onion`). Both are
/// dialed on the row's p2p port. The address and the onion are one entry,
/// so replacing either keeps the pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seed {
    /// The host's IPv4 octets.
    pub ipv4: [u8; 4],
    /// The host's onion on this network, if it runs one.
    pub onion: Option<&'static str>,
    /// Where the host sits; a dial does not read it. It keeps the entry
    /// recognizable when an address is replaced.
    pub place: &'static str,
}

/// A network's Bech32m address prefixes (human-readable parts).
#[derive(Debug, PartialEq, Eq)]
pub struct Prefixes {
    /// The classical segment of a single-signature address.
    pub classical: &'static str,
    /// The first post-quantum segment.
    pub pqc_a: &'static str,
    /// The second post-quantum segment.
    pub pqc_b: &'static str,
    /// A multisig address (`PQC_MULTISIG.md` §6.1).
    pub multisig: &'static str,
}

impl Prefixes {
    /// Every prefix of the set.
    #[must_use]
    pub const fn all(&self) -> [&'static str; 4] {
        [self.classical, self.pqc_a, self.pqc_b, self.multisig]
    }
}

/// A daemon's default ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ports {
    /// Peer-to-peer.
    pub p2p: u16,
    /// RPC.
    pub rpc: u16,
}

/// A behaviour a network's row may permit (NI-R6). The armed-lever gate
/// reads the row; nothing else decides whether a lever runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lever {
    /// `dev-rpc`: the armed RPC levers, `generateblocks` and `pop_blocks`
    /// (NI-R8).
    DevRpc,
    /// `dev-sync`: chain synchronisation with peers switched off.
    Sync,
    /// `dev-difficulty`: a fixed difficulty.
    Difficulty,
    /// `dev-pow-seed-epoch-blocks`: the RandomX seed epoch length.
    PowSeedEpochBlocks,
    /// `dev-pow-seed-epoch-lag`: the RandomX seed epoch lag.
    PowSeedEpochLag,
    /// `dev-settlement-epoch-blocks`: the settlement epoch length.
    SettlementEpochBlocks,
    /// `dev-archival-reorg-depth`: the archival reorg depth.
    ArchivalReorgDepth,
    /// The out-of-band serve-credit write a corpus `inject` record replays
    /// through (NI-F6).
    InjectServeCredit,
    /// The issued-draws write a corpus replays through (NI-F6).
    IssueDraws,
}

impl Lever {
    /// What an operator or a refusal calls it: the option's name, or the
    /// write's for the two a corpus replays through.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DevRpc => "dev-rpc",
            Self::Sync => "dev-sync",
            Self::Difficulty => "dev-difficulty",
            Self::PowSeedEpochBlocks => "dev-pow-seed-epoch-blocks",
            Self::PowSeedEpochLag => "dev-pow-seed-epoch-lag",
            Self::SettlementEpochBlocks => "dev-settlement-epoch-blocks",
            Self::ArchivalReorgDepth => "dev-archival-reorg-depth",
            Self::InjectServeCredit => "the injected serve-credit write",
            Self::IssueDraws => "the issued-draws write",
        }
    }

    /// Every lever.
    pub const ALL: [Self; 9] = [
        Self::DevRpc,
        Self::Sync,
        Self::Difficulty,
        Self::PowSeedEpochBlocks,
        Self::PowSeedEpochLag,
        Self::SettlementEpochBlocks,
        Self::ArchivalReorgDepth,
        Self::InjectServeCredit,
        Self::IssueDraws,
    ];
}

/// A network row's permission for one lever (NI-R6). Only
/// [`Network::permit`] makes one, so a callee that requires a `Permit`
/// runs only where a row allowed it, without learning which network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Permit {
    lever: Lever,
}

impl Permit {
    /// The lever permitted.
    #[must_use]
    pub const fn lever(self) -> Lever {
        self.lever
    }
}

/// A staging flag (NI-R9): a candidate mainnet behaviour staged on the
/// test networks. Each names its owner and its exit, and none survives
/// mainnet genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Staging {
    /// `dev-clearnet-encrypt`.
    ClearnetEncrypt,
    /// `dev-relay-cover`.
    RelayCover,
}

impl Staging {
    /// Every staging flag.
    pub const ALL: [Self; 2] = [Self::ClearnetEncrypt, Self::RelayCover];

    /// Who owns the flag's exit.
    #[must_use]
    pub const fn owner(self) -> &'static str {
        match self {
            Self::ClearnetEncrypt => "the Noise flip",
            Self::RelayCover => "the cover-traffic lane (TRC-1)",
        }
    }

    /// How the flag leaves: promoted to default behaviour, or deleted.
    #[must_use]
    pub const fn exit(self) -> &'static str {
        match self {
            Self::ClearnetEncrypt => "deleted at the Noise flip",
            Self::RelayCover => "promoted or deleted by TRC-1's outcome",
        }
    }
}

/// Mainnet's seeds: the six Foundation hosts' clearnet addresses. Mainnet
/// runs no hidden service.
const MAINNET_SEEDS: [Seed; 6] = [
    Seed {
        ipv4: [134, 199, 166, 22],
        onion: None,
        place: "Sydney",
    },
    Seed {
        ipv4: [45, 77, 147, 65],
        onion: None,
        place: "US East",
    },
    Seed {
        ipv4: [45, 76, 171, 128],
        onion: None,
        place: "US West",
    },
    Seed {
        ipv4: [45, 77, 66, 189],
        onion: None,
        place: "EU Frankfurt",
    },
    Seed {
        ipv4: [139, 162, 71, 114],
        onion: None,
        place: "Tokyo",
    },
    Seed {
        ipv4: [104, 64, 59, 31],
        onion: None,
        place: "Brazil",
    },
];

/// Testnet's seeds: the same six hosts, each with its testnet onion, the
/// canonical Tor bootstrap (Q12-R1).
const TESTNET_SEEDS: [Seed; 6] = [
    Seed {
        ipv4: [134, 199, 166, 22],
        onion: Some("aghoxa757l2wqribeto2hv2rk3wjwcwdqzvu5hjkqdjcm24nuhaszjqd.onion"),
        place: "Sydney",
    },
    Seed {
        ipv4: [45, 77, 147, 65],
        onion: Some("23dkgevx7qnhrx2wmhmjvhsz2mpp54xomkujcvhuhm3ajgdciwztypad.onion"),
        place: "US East",
    },
    Seed {
        ipv4: [45, 76, 171, 128],
        onion: Some("nqkfnallpz5kaoxkj2y6bmeifk4helrwp5z2fdtayo3rfzbx4q7z2tqd.onion"),
        place: "US West",
    },
    Seed {
        ipv4: [45, 77, 66, 189],
        onion: Some("aks2vbpjb5ojfyqcataqedodws7ardjxczy76bqwmlv55mgfunsxoiyd.onion"),
        place: "EU Frankfurt",
    },
    Seed {
        ipv4: [139, 162, 71, 114],
        onion: Some("e2fafquqkf4jodx6rwh2akgyu2gy3spxcyc2ustnuqw46vrk2xe365qd.onion"),
        place: "Tokyo",
    },
    Seed {
        ipv4: [104, 64, 59, 31],
        onion: Some("mjgznic6uwrccelrq6fqjmmv2f7gaskd3nxcs76hjrrfc4tse7wioqqd.onion"),
        place: "Brazil",
    },
];

const STAGED: &[Staging] = &[Staging::ClearnetEncrypt, Staging::RelayCover];

const ROWS: [Row; 4] = [
    Row {
        network: Network::Mainnet,
        name: "mainnet",
        tag: "shekyl/mainnet",
        prefixes: Prefixes {
            classical: "shekyl",
            pqc_a: "skpq",
            pqc_b: "skpq2",
            multisig: "shekyl1m",
        },
        ports: Ports {
            p2p: 11021,
            rpc: 11029,
        },
        subdirectory: None,
        permits: &[],
        staging: &[],
        seeds: &MAINNET_SEEDS,
        genesis: &genesis::MAINNET,
    },
    Row {
        network: Network::Testnet,
        name: "testnet",
        tag: "shekyl/testnet",
        prefixes: Prefixes {
            classical: "tshekyl",
            pqc_a: "tskpq",
            pqc_b: "tskpq2",
            multisig: "shekyltest1m",
        },
        ports: Ports {
            p2p: 12021,
            rpc: 12029,
        },
        subdirectory: Some("testnet"),
        permits: &[],
        staging: STAGED,
        seeds: &TESTNET_SEEDS,
        genesis: &genesis::TESTNET,
    },
    Row {
        network: Network::Stagenet,
        name: "stagenet",
        tag: "shekyl/stagenet",
        prefixes: Prefixes {
            classical: "sshekyl",
            pqc_a: "sskpq",
            pqc_b: "sskpq2",
            multisig: "sshekyl1m",
        },
        ports: Ports {
            p2p: 13021,
            rpc: 13029,
        },
        subdirectory: Some("stagenet"),
        permits: &[],
        staging: STAGED,
        seeds: &[],
        genesis: &genesis::STAGENET,
    },
    Row {
        network: Network::Regtest,
        name: "regtest",
        tag: "shekyl/regtest",
        prefixes: Prefixes {
            classical: "rshekyl",
            pqc_a: "rskpq",
            pqc_b: "rskpq2",
            multisig: "rshekyl1m",
        },
        ports: Ports {
            p2p: 14021,
            rpc: 14029,
        },
        subdirectory: Some("regtest"),
        permits: &Lever::ALL,
        staging: STAGED,
        seeds: &[],
        genesis: &genesis::REGTEST,
    },
];

/// Customization for the network id.
/// Registered in `CRYPTO_DOMAIN_REGISTRY.tsv` beside [`WIRE_PREFIX_DST`].
pub const NETWORK_ID_DST: &[u8] = b"shekyl/p2p-network-id-v1";

/// Customization for the clearnet framing prefix.
/// Registered in `CRYPTO_DOMAIN_REGISTRY.tsv`.
pub const WIRE_PREFIX_DST: &[u8] = b"shekyl/p2p-wire-prefix-v1";

/// The clearnet framing prefix's length.
pub const PREFIX_LEN: usize = 8;

/// A network id: the derived form of a network (NI-R10).
pub type NetworkId = [u8; 16];

/// The id a harness chain is judged under: a chain that mines its own
/// genesis and so has no row (`Trust::UNPINNED` in `shekyl-chain-rules`).
/// One value, so every harness signer and the trust it is validated under
/// agree (`NETWORK_IDENTITY.md` NI-Q4). No network's row has this id, and
/// no release path reads it.
pub const HARNESS_NETWORK_ID: NetworkId = [0; 16];

/// The id of the chain whose genesis block hash is `genesis_block_hash`:
/// the first 16 bytes of `cSHAKE256(S = NETWORK_ID_DST, X = genesis hash)`,
/// digest order. A different genesis is a different network.
#[must_use]
pub fn network_id_from_genesis(genesis_block_hash: &[u8; 32]) -> NetworkId {
    let digest = cshake256_32(NETWORK_ID_DST, genesis_block_hash);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// PWD-T5's clearnet prefix: the first eight bytes of
/// `cSHAKE256(S = WIRE_PREFIX_DST, X = network_id)`.
#[must_use]
pub fn prefix_for(network_id: &NetworkId) -> [u8; PREFIX_LEN] {
    let digest = cshake256_32(WIRE_PREFIX_DST, network_id);
    let mut out = [0u8; PREFIX_LEN];
    out.copy_from_slice(&digest[..PREFIX_LEN]);
    out
}

#[cfg(test)]
mod tests;
