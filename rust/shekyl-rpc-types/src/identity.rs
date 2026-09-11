// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Connect-time identity tuple: one comparison, every client (`VC-2`…`VC-4`).
//!
//! [`IdentityExpectation::check`] is the only place a `get_version` reply is
//! compared to this build. The wallet (`VC-4`) and the remote console (`VC-3`)
//! fetch over their own transports and format the refusal in their own voice;
//! they do not reimplement the axes. Genesis is [`genesis_hash_for`] per
//! network (`VC-D18` armed): the frozen block-0 ids from
//! `docs/GENESIS_ALLOCATIONS.md` / `mining_parity`. A remint of `GENESIS_TX`
//! updates those pins in the same change.

use crate::chain::{core_rpc_version_string, GetVersionResponse, CORE_RPC_VERSION};
use crate::consensus_digest::{DaemonNetwork, CONSENSUS_CONSTANTS_DIGEST_HASH};
use crate::hash::HashHex;

/// Which axis of the identity tuple disagreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAxis {
    /// `CORE_RPC_VERSION`: the two binaries do not share an RPC contract.
    Wire,
    /// The consensus-constant digest: built from different `config/`
    /// authorities, which is a different rule set.
    Rules,
    /// `nettype`: same rules, a different instance of them.
    Network,
    /// Block 0's hash: the chain does not start where this build's does.
    Genesis,
}

impl std::fmt::Display for IdentityAxis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Wire => "RPC contract",
            Self::Rules => "consensus constants",
            Self::Network => "network",
            Self::Genesis => "genesis block",
        })
    }
}

/// What this client requires of a daemon's identity tuple.
///
/// Constructed from this build's compiled pins plus the network the client is
/// bound to. [`Self::exact_or_fakechain`] is the wallet regtest harness
/// (`FakechainPolicy::Accept`); every shipped path uses [`Self::exact`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityExpectation {
    network: DaemonNetwork,
    accept_fakechain: bool,
}

impl IdentityExpectation {
    /// Refuse any daemon whose `nettype` is not `network`.
    #[must_use]
    pub const fn exact(network: DaemonNetwork) -> Self {
        Self {
            network,
            accept_fakechain: false,
        }
    }

    /// Accept `network` or `fakechain`. Wallet-only: a `shekyld --regtest`
    /// daemon reports `fakechain` while sharing mainnet's genesis and digest.
    #[must_use]
    pub const fn exact_or_fakechain(network: DaemonNetwork) -> Self {
        Self {
            network,
            accept_fakechain: true,
        }
    }

    /// The network this client is bound to.
    #[must_use]
    pub const fn network(self) -> DaemonNetwork {
        self.network
    }

    /// Compare `reply` to this build's pins.
    ///
    /// Wire, then rules, then network, then genesis. Fakechain shares
    /// mainnet's genesis (`cryptonote_config.h`: `FAKECHAIN` takes mainnet's
    /// configuration), so [`Self::exact_or_fakechain`] on mainnet still
    /// compares the mainnet pin.
    pub fn check(self, reply: &GetVersionResponse) -> Result<(), IdentityMismatch> {
        if reply.version != CORE_RPC_VERSION {
            return Err(IdentityMismatch::Wire {
                ours: CORE_RPC_VERSION,
                theirs: reply.version,
            });
        }
        if reply.consensus_constants_digest != CONSENSUS_CONSTANTS_DIGEST_HASH {
            return Err(IdentityMismatch::Rules {
                ours: CONSENSUS_CONSTANTS_DIGEST_HASH,
                theirs: reply.consensus_constants_digest,
            });
        }
        let network_ok = reply.nettype == self.network
            || (self.accept_fakechain && reply.nettype == DaemonNetwork::Fakechain);
        if !network_ok {
            return Err(IdentityMismatch::Network {
                ours: self.network,
                theirs: reply.nettype,
            });
        }
        let expected = genesis_hash_for(self.network);
        if reply.genesis_hash.to_bytes() != expected {
            return Err(IdentityMismatch::Genesis {
                ours: HashHex::from_bytes(expected),
                theirs: reply.genesis_hash,
                network: self.network,
            });
        }
        Ok(())
    }
}

/// Why a `get_version` reply is not this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityMismatch {
    /// Packed `CORE_RPC_VERSION` disagrees; `theirs < ours` means the daemon
    /// is the older binary.
    Wire {
        /// This build's packed version.
        ours: u32,
        /// The daemon's packed version.
        theirs: u32,
    },
    /// The reply was not this build's `GetVersionResponse` (VC-D16).
    WireUnreadable {
        /// This build's packed version, for the message that cannot name theirs.
        ours: u32,
        /// Deserializer or envelope evidence; not shown as a version number.
        evidence: String,
    },
    /// Digest disagrees. A hash has no ordering (`VC-D15`).
    Rules {
        /// This build's digest.
        ours: HashHex,
        /// The daemon's digest.
        theirs: HashHex,
    },
    /// `nettype` disagrees.
    Network {
        /// The network this client is bound to.
        ours: DaemonNetwork,
        /// The network the daemon reported.
        theirs: DaemonNetwork,
    },
    /// Block 0 disagrees.
    Genesis {
        /// This build's pin for [`Self::Genesis::network`].
        ours: HashHex,
        /// The daemon's block 0.
        theirs: HashHex,
        /// The network whose pin was compared.
        network: DaemonNetwork,
    },
}

impl IdentityMismatch {
    /// A reply that did not parse as this build's `get_version` shape.
    #[must_use]
    pub fn unreadable(evidence: impl std::fmt::Display) -> Self {
        Self::WireUnreadable {
            ours: CORE_RPC_VERSION,
            evidence: evidence.to_string(),
        }
    }

    /// Which axis failed.
    #[must_use]
    pub const fn axis(&self) -> IdentityAxis {
        match self {
            Self::Wire { .. } | Self::WireUnreadable { .. } => IdentityAxis::Wire,
            Self::Rules { .. } => IdentityAxis::Rules,
            Self::Network { .. } => IdentityAxis::Network,
            Self::Genesis { .. } => IdentityAxis::Genesis,
        }
    }

    /// Packed versions as `major.minor`, for operator-facing copy.
    #[must_use]
    pub fn version_display(packed: u32) -> String {
        core_rpc_version_string(packed)
    }
}

/// Decode 64 lowercase hex characters into 32 bytes.
///
/// The pin literals below are the only callers; a non-hex byte would be a
/// compile-time panic on a constant this crate ships.
const fn hex_nibble_const(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => panic!("genesis pin is not lowercase hex"),
    }
}

const fn hex32(s: &[u8; 64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble_const(s[i * 2]) << 4) | hex_nibble_const(s[i * 2 + 1]);
        i += 1;
    }
    out
}

/// Mainnet (and fakechain) block 0. Same string as
/// `docs/GENESIS_ALLOCATIONS.md`, `mining_parity`'s `frozen_id`, and
/// `shekyl-wire`'s `MAINNET_GENESIS_BLOCK_ID`.
const MAINNET_GENESIS: [u8; 32] =
    hex32(b"e623214c06d3ec19a8326c166ff4ee920fe85badbfadd67966c15a315ed7aa12");
const TESTNET_GENESIS: [u8; 32] =
    hex32(b"7cbb852932d7c1b35991e5880c8158da2a36c9101e4daf2620139c0585663280");
const STAGENET_GENESIS: [u8; 32] =
    hex32(b"82ccf33577a4833d0bfd0eef768de21130cc2a9b66f83b9d32c8a91e6cedf7b4");

/// The genesis block hash this build expects on `network`.
///
/// These are the frozen block-0 ids (`get_block_id_by_height(0)` /
/// `geblock block-id`), not `GENESIS_TX`. Fakechain shares mainnet's genesis
/// (`cryptonote_config.h`: `FAKECHAIN` takes mainnet's configuration). Reminting
/// genesis updates `GENESIS_TX` / nonce and these pins in the same change.
#[must_use]
pub const fn genesis_hash_for(network: DaemonNetwork) -> [u8; 32] {
    match network {
        DaemonNetwork::Mainnet | DaemonNetwork::Fakechain => MAINNET_GENESIS,
        DaemonNetwork::Testnet => TESTNET_GENESIS,
        DaemonNetwork::Stagenet => STAGENET_GENESIS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::RpcStatus;

    fn agreeing() -> GetVersionResponse {
        GetVersionResponse {
            status: RpcStatus::ok(),
            version: CORE_RPC_VERSION,
            release: false,
            current_height: 1,
            target_height: 0,
            hard_forks: vec![],
            consensus_constants_digest: CONSENSUS_CONSTANTS_DIGEST_HASH,
            nettype: DaemonNetwork::Mainnet,
            genesis_hash: HashHex::from_bytes(genesis_hash_for(DaemonNetwork::Mainnet)),
        }
    }

    #[test]
    fn an_agreeing_reply_passes() {
        assert_eq!(
            IdentityExpectation::exact(DaemonNetwork::Mainnet).check(&agreeing()),
            Ok(())
        );
    }

    #[test]
    fn wire_mismatch_names_both_packed_versions() {
        let mut reply = agreeing();
        reply.version -= 1;
        match IdentityExpectation::exact(DaemonNetwork::Mainnet).check(&reply) {
            Err(IdentityMismatch::Wire { ours, theirs }) => {
                assert_eq!(ours, CORE_RPC_VERSION);
                assert_eq!(theirs, CORE_RPC_VERSION - 1);
                assert!(theirs < ours);
            }
            other => panic!("expected Wire, got {other:?}"),
        }
    }

    #[test]
    fn rules_mismatch_carries_both_digests_and_is_not_wire() {
        let mut reply = agreeing();
        reply.consensus_constants_digest = HashHex::from_bytes([0x99; 32]);
        match IdentityExpectation::exact(DaemonNetwork::Mainnet).check(&reply) {
            Err(m @ IdentityMismatch::Rules { .. }) => {
                assert_eq!(m.axis(), IdentityAxis::Rules);
            }
            other => panic!("expected Rules, got {other:?}"),
        }
    }

    #[test]
    fn network_mismatch_is_the_only_axis_that_sees_testnet() {
        let mut reply = agreeing();
        reply.nettype = DaemonNetwork::Testnet;
        match IdentityExpectation::exact(DaemonNetwork::Mainnet).check(&reply) {
            Err(IdentityMismatch::Network { ours, theirs }) => {
                assert_eq!(ours, DaemonNetwork::Mainnet);
                assert_eq!(theirs, DaemonNetwork::Testnet);
            }
            other => panic!("expected Network, got {other:?}"),
        }
    }

    #[test]
    fn fakechain_is_refused_unless_the_expectation_allows_it() {
        let mut reply = agreeing();
        reply.nettype = DaemonNetwork::Fakechain;
        assert!(matches!(
            IdentityExpectation::exact(DaemonNetwork::Mainnet).check(&reply),
            Err(IdentityMismatch::Network { .. })
        ));
        assert_eq!(
            IdentityExpectation::exact_or_fakechain(DaemonNetwork::Mainnet).check(&reply),
            Ok(())
        );
    }

    #[test]
    fn fakechain_still_compares_the_mainnet_genesis_pin() {
        let mut reply = agreeing();
        reply.nettype = DaemonNetwork::Fakechain;
        reply.genesis_hash = HashHex::from_bytes([0xff; 32]);
        assert!(matches!(
            IdentityExpectation::exact_or_fakechain(DaemonNetwork::Mainnet).check(&reply),
            Err(IdentityMismatch::Genesis { .. })
        ));
    }

    #[test]
    fn a_foreign_genesis_is_refused() {
        let mut reply = agreeing();
        reply.genesis_hash = HashHex::from_bytes([0xff; 32]);
        match IdentityExpectation::exact(DaemonNetwork::Mainnet).check(&reply) {
            Err(IdentityMismatch::Genesis {
                ours,
                theirs,
                network,
            }) => {
                assert_eq!(ours.to_bytes(), genesis_hash_for(DaemonNetwork::Mainnet));
                assert_eq!(theirs.to_bytes(), [0xff; 32]);
                assert_eq!(network, DaemonNetwork::Mainnet);
            }
            other => panic!("expected Genesis, got {other:?}"),
        }
    }

    #[test]
    fn pins_are_the_frozen_block_ids() {
        // Same strings as `mining_parity.genesis_identity_is_pow_independent`
        // and `docs/GENESIS_ALLOCATIONS.md`. A remint that updates those and
        // not this file fails here.
        assert_eq!(
            HashHex::from_bytes(genesis_hash_for(DaemonNetwork::Mainnet)).to_string(),
            "e623214c06d3ec19a8326c166ff4ee920fe85badbfadd67966c15a315ed7aa12"
        );
        assert_eq!(
            HashHex::from_bytes(genesis_hash_for(DaemonNetwork::Testnet)).to_string(),
            "7cbb852932d7c1b35991e5880c8158da2a36c9101e4daf2620139c0585663280"
        );
        assert_eq!(
            HashHex::from_bytes(genesis_hash_for(DaemonNetwork::Stagenet)).to_string(),
            "82ccf33577a4833d0bfd0eef768de21130cc2a9b66f83b9d32c8a91e6cedf7b4"
        );
        assert_eq!(
            genesis_hash_for(DaemonNetwork::Fakechain),
            genesis_hash_for(DaemonNetwork::Mainnet)
        );
        assert_ne!(
            genesis_hash_for(DaemonNetwork::Testnet),
            genesis_hash_for(DaemonNetwork::Mainnet)
        );
        assert_ne!(
            genesis_hash_for(DaemonNetwork::Stagenet),
            genesis_hash_for(DaemonNetwork::Mainnet)
        );
    }

    #[test]
    fn unreadable_is_the_wire_axis() {
        let m = IdentityMismatch::unreadable("missing field `nettype`");
        assert_eq!(m.axis(), IdentityAxis::Wire);
        assert!(matches!(m, IdentityMismatch::WireUnreadable { .. }));
    }
}
