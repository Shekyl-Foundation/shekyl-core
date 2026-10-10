// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Connect-time identity tuple: one comparison, every client (`VC-2`…`VC-4`).
//!
//! [`IdentityExpectation::read`] is the only place a `get_version` reply is
//! decoded and compared to this build. The wallet (`VC-4`) and the remote
//! console (`VC-3`) fetch over their own transports and format the refusal in
//! their own voice; they do not reimplement the axes.
//!
//! # The version is read first, and its field is frozen (`RK-D25`)
//!
//! [`daemon_rpc_version`] reads one member of the reply, `version`, and
//! nothing else. [`IdentityExpectation::read`] calls it and compares before
//! it decodes the rest, so a daemon whose reply has a different shape is
//! reported as what it is — a different RPC version, both sides named — and
//! not as an unreadable reply. The strict decode runs only when the versions
//! agree, and nothing is trusted from a reply whose version differs.
//!
//! That only works if the one field can always be read, so three things are
//! frozen across every future shape change, a new major version included:
//! the key is `version`, its value is a JSON integer, and the integer is
//! `(major << 16) | minor`. [`daemon_rpc_version`] is **the only lenient
//! reader of a daemon reply in the tree**; do not add a second. Genesis is [`genesis_hash_for`] per
//! network (`VC-D18` armed): the frozen block-0 ids from
//! `docs/GENESIS_ALLOCATIONS.md` / `mining_parity`. A remint of `GENESIS_TX`
//! updates those pins in the same change.

use crate::chain::{core_rpc_version_string, GetVersionResponse, CORE_RPC_VERSION};
use crate::consensus_digest::{DaemonNetwork, CONSENSUS_CONSTANTS_DIGEST_HASH};
use crate::hash::HashHex;
use serde::Deserialize as _;

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

    /// Decode a `get_version` result and compare it to this build's pins.
    ///
    /// `result` is the JSON-RPC `result` member. Wire first, through
    /// [`daemon_rpc_version`], **before** the rest is decoded: a version
    /// that differs is [`IdentityMismatch::Wire`] whatever else the reply
    /// holds. Then the strict decode, then rules, network and genesis.
    ///
    /// A refusal carries the parse failure as `evidence` when there was one.
    /// That is the daemon's own text: log it where it was read, and do not
    /// carry it further.
    ///
    /// Generic over the deserializer, and `Copy` because the result is read
    /// twice; callers pass a `&serde_json::Value`.
    pub fn read<'de, D>(self, result: D) -> Result<GetVersionResponse, IdentityRefusal>
    where
        D: serde::Deserializer<'de> + Copy,
    {
        let theirs = daemon_rpc_version(result).map_err(|unreadable| IdentityRefusal {
            mismatch: IdentityMismatch::unreadable(),
            evidence: Some(unreadable.to_string()),
        })?;
        if theirs != CORE_RPC_VERSION {
            return Err(IdentityRefusal {
                mismatch: IdentityMismatch::Wire {
                    ours: CORE_RPC_VERSION,
                    theirs,
                },
                evidence: None,
            });
        }
        // Same version, so the shape is this build's. A reply that still
        // does not decode is a daemon contradicting its own version.
        let reply = GetVersionResponse::deserialize(result).map_err(|e| IdentityRefusal {
            mismatch: IdentityMismatch::unreadable(),
            evidence: Some(e.to_string()),
        })?;
        self.check_tuple(&reply)
            .map_err(|mismatch| IdentityRefusal {
                mismatch,
                evidence: None,
            })?;
        Ok(reply)
    }

    /// Rules, then network, then genesis. The wire axis is [`Self::read`]'s,
    /// which is the only caller. Fakechain shares mainnet's genesis
    /// (`cryptonote_config.h`: `FAKECHAIN` takes mainnet's configuration), so
    /// [`Self::exact_or_fakechain`] on mainnet still compares the mainnet pin.
    fn check_tuple(self, reply: &GetVersionResponse) -> Result<(), IdentityMismatch> {
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

/// The frozen key (`RK-D25`).
const VERSION_KEY: &str = "version";

/// A `get_version` result with no readable `version` member.
///
/// Holds the parse failure, which is the daemon's own text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionUnreadable(String);

impl std::fmt::Display for VersionUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for VersionUnreadable {}

/// The packed RPC version a daemon reports, read from a `get_version`
/// result on its own (`RK-D25`).
///
/// `result` is the JSON-RPC `result` member. Only `version` is read: a
/// JSON integer, `(major << 16) | minor`. Every other member is ignored
/// and none is required, so `{"version": N}` alone reads. That is the
/// frozen part of the wire; see the module docs.
///
/// Generic over the deserializer so this crate takes no JSON dependency;
/// callers pass a `&serde_json::Value`.
pub fn daemon_rpc_version<'de, D>(result: D) -> Result<u32, VersionUnreadable>
where
    D: serde::Deserializer<'de>,
{
    result
        .deserialize_map(VersionVisitor)
        .map_err(|e| VersionUnreadable(e.to_string()))
}

/// Reads `version` out of a map and ignores every other member.
///
/// Written by hand, not derived: serde's derive would also take a struct
/// from a JSON array, positionally, and the key is part of what is frozen.
struct VersionVisitor;

impl<'de> serde::de::Visitor<'de> for VersionVisitor {
    type Value = u32;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a get_version result: an object with an integer `version`")
    }

    fn visit_map<A>(self, mut map: A) -> Result<u32, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        use serde::de::Error as _;

        let mut version = None;
        while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            if key == VERSION_KEY {
                if version.is_some() {
                    return Err(A::Error::duplicate_field(VERSION_KEY));
                }
                version = Some(map.next_value::<u32>()?);
            } else {
                map.next_value::<serde::de::IgnoredAny>()?;
            }
        }
        version.ok_or_else(|| A::Error::missing_field(VERSION_KEY))
    }
}

/// A refused `get_version` reply: which axis, and what failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRefusal {
    /// Why the reply is not this build.
    pub mismatch: IdentityMismatch,
    /// The parse failure, when the refusal is an unreadable reply. The
    /// daemon's own text: for the log of the client that read it.
    pub evidence: Option<String>,
}

/// Why a `get_version` reply is not this build.
///
/// A fixed-size value with no text from the reply in it, so every error type
/// on the way up can carry it, including the refresh producer's `Copy`-only
/// error (`STAGE_1_PR_4_REFRESH_ENGINE.md` §5.4.7 R6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMismatch {
    /// Packed `CORE_RPC_VERSION` disagrees; `theirs < ours` means the daemon
    /// is the older binary.
    Wire {
        /// This build's packed version.
        ours: u32,
        /// The daemon's packed version.
        theirs: u32,
    },
    /// The reply was not this build's `GetVersionResponse` (VC-D16). What
    /// failed to parse is the daemon's own text, so it stays in the log of
    /// the client that parsed it and is not carried here.
    WireUnreadable {
        /// This build's packed version, for the message that cannot name theirs.
        ours: u32,
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
    /// A reply that did not parse as this build's `get_version` shape. The
    /// caller logs what failed to parse; see [`Self::WireUnreadable`].
    #[must_use]
    pub const fn unreadable() -> Self {
        Self::WireUnreadable {
            ours: CORE_RPC_VERSION,
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
    hex32(b"16c616a504e5d33a78e2ec3a5dd7d87ffdd3edd46a351199cffcc7c30af770e3");
const TESTNET_GENESIS: [u8; 32] =
    hex32(b"52425d8da3a90e41ff54780129bdbe9897aa28c3d0a9c80b04b4b5ea35c911d8");
const STAGENET_GENESIS: [u8; 32] =
    hex32(b"65173901b049468133e5f821f668772f13936b1abdff0e2add80ff3b03ccf5f0");

/// The genesis block hash this build expects on `network`.
///
/// These are the frozen block-0 ids (`get_block_id_by_height(0)` /
/// `geblock block-id`), not `GENESIS_TX`. Fakechain shares mainnet's genesis
/// (`cryptonote_config.h`: `FAKECHAIN` takes mainnet's configuration). Reminting
/// genesis updates `GENESIS_TX` / nonce and these pins in the same change.
/// The handshake network id is `network_id_from_genesis` of this pin, so that
/// change rotates the id; the KAT in `shekyl-ffi`'s `network_id_ffi` fails
/// until it is re-recorded.
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
            consensus_constants_digest: CONSENSUS_CONSTANTS_DIGEST_HASH,
            nettype: DaemonNetwork::Mainnet,
            genesis_hash: HashHex::from_bytes(genesis_hash_for(DaemonNetwork::Mainnet)),
        }
    }

    /// What [`IdentityExpectation::read`] says of `reply` as the wire
    /// would carry it.
    fn verdict(
        expectation: IdentityExpectation,
        reply: &GetVersionResponse,
    ) -> Result<(), IdentityMismatch> {
        let result = serde_json::to_value(reply).expect("a reply serializes");
        expectation
            .read(&result)
            .map(|_| ())
            .map_err(|refusal| refusal.mismatch)
    }

    /// RK-D25's pin: the frozen field reads with nothing around it.
    #[test]
    fn the_version_alone_reads_through() {
        for packed in [0, 1, CORE_RPC_VERSION, 4 << 16, u32::MAX] {
            assert_eq!(
                daemon_rpc_version(serde_json::json!({ "version": packed })),
                Ok(packed),
                "{{\"version\": {packed}}} alone is a readable version"
            );
        }
    }

    /// The reason the version is read first: a reply this build cannot
    /// decode, from a daemon of another version, is a version difference
    /// with both sides named, in both directions.
    #[test]
    fn another_versions_reply_is_a_version_mismatch_whatever_its_shape() {
        for theirs in [CORE_RPC_VERSION - 1, CORE_RPC_VERSION + 1, 4 << 16] {
            for result in [
                serde_json::json!({ "version": theirs }),
                serde_json::json!({
                    "version": theirs,
                    "a_member_this_build_has_never_heard_of": [1, 2, 3],
                    "target_height": "not what this build expects",
                }),
            ] {
                let refusal = IdentityExpectation::exact(DaemonNetwork::Mainnet)
                    .read(&result)
                    .expect_err("another version is refused");
                assert_eq!(
                    refusal.mismatch,
                    IdentityMismatch::Wire {
                        ours: CORE_RPC_VERSION,
                        theirs
                    }
                );
                assert_eq!(refusal.evidence, None, "nothing failed to parse");
            }
        }
    }

    /// The frozen field's type is part of what is frozen: an integer, and
    /// nothing that merely looks like one.
    #[test]
    fn a_version_that_is_not_a_json_integer_is_unreadable() {
        for result in [
            serde_json::json!({}),
            serde_json::json!({ "version": null }),
            serde_json::json!({ "version": "196653" }),
            serde_json::json!({ "version": 3.45 }),
            serde_json::json!({ "version": -1 }),
            serde_json::json!({ "version": u64::from(u32::MAX) + 1 }),
            serde_json::json!({ "Version": CORE_RPC_VERSION }),
            serde_json::json!([CORE_RPC_VERSION]),
            serde_json::json!(CORE_RPC_VERSION),
        ] {
            assert!(
                daemon_rpc_version(&result).is_err(),
                "{result} carries no readable version"
            );
            let refusal = IdentityExpectation::exact(DaemonNetwork::Mainnet)
                .read(&result)
                .expect_err("no version, no identity");
            assert_eq!(refusal.mismatch, IdentityMismatch::unreadable());
            assert!(refusal.evidence.is_some(), "the parse failure is kept");
        }
    }

    /// A daemon that reports this build's version and then does not answer
    /// in this build's shape contradicts itself. That is still refused, as
    /// unreadable: the strict decode is not relaxed by the version read.
    #[test]
    fn this_versions_reply_is_still_decoded_strictly() {
        let whole = serde_json::to_value(agreeing()).expect("a reply serializes");

        let mut extra = whole.clone();
        extra["a_member_this_build_has_never_heard_of"] = serde_json::json!(1);
        let mut missing = whole;
        missing
            .as_object_mut()
            .expect("an object")
            .remove("genesis_hash")
            .expect("the member is there to remove");

        for result in [extra, missing] {
            let refusal = IdentityExpectation::exact(DaemonNetwork::Mainnet)
                .read(&result)
                .expect_err("not this build's shape");
            assert_eq!(refusal.mismatch, IdentityMismatch::unreadable());
            assert!(refusal.evidence.is_some());
        }
    }

    #[test]
    fn an_agreeing_reply_passes() {
        assert_eq!(
            verdict(
                IdentityExpectation::exact(DaemonNetwork::Mainnet),
                &agreeing()
            ),
            Ok(())
        );
    }

    #[test]
    fn wire_mismatch_names_both_packed_versions() {
        let mut reply = agreeing();
        reply.version -= 1;
        match verdict(IdentityExpectation::exact(DaemonNetwork::Mainnet), &reply) {
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
        match verdict(IdentityExpectation::exact(DaemonNetwork::Mainnet), &reply) {
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
        match verdict(IdentityExpectation::exact(DaemonNetwork::Mainnet), &reply) {
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
            verdict(IdentityExpectation::exact(DaemonNetwork::Mainnet), &reply),
            Err(IdentityMismatch::Network { .. })
        ));
        assert_eq!(
            verdict(
                IdentityExpectation::exact_or_fakechain(DaemonNetwork::Mainnet),
                &reply
            ),
            Ok(())
        );
    }

    #[test]
    fn fakechain_still_compares_the_mainnet_genesis_pin() {
        let mut reply = agreeing();
        reply.nettype = DaemonNetwork::Fakechain;
        reply.genesis_hash = HashHex::from_bytes([0xff; 32]);
        assert!(matches!(
            verdict(
                IdentityExpectation::exact_or_fakechain(DaemonNetwork::Mainnet),
                &reply
            ),
            Err(IdentityMismatch::Genesis { .. })
        ));
    }

    #[test]
    fn a_foreign_genesis_is_refused() {
        let mut reply = agreeing();
        reply.genesis_hash = HashHex::from_bytes([0xff; 32]);
        match verdict(IdentityExpectation::exact(DaemonNetwork::Mainnet), &reply) {
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
            "16c616a504e5d33a78e2ec3a5dd7d87ffdd3edd46a351199cffcc7c30af770e3"
        );
        assert_eq!(
            HashHex::from_bytes(genesis_hash_for(DaemonNetwork::Testnet)).to_string(),
            "52425d8da3a90e41ff54780129bdbe9897aa28c3d0a9c80b04b4b5ea35c911d8"
        );
        assert_eq!(
            HashHex::from_bytes(genesis_hash_for(DaemonNetwork::Stagenet)).to_string(),
            "65173901b049468133e5f821f668772f13936b1abdff0e2add80ff3b03ccf5f0"
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
        let m = IdentityMismatch::unreadable();
        assert_eq!(m.axis(), IdentityAxis::Wire);
        assert!(matches!(m, IdentityMismatch::WireUnreadable { .. }));
    }
}
