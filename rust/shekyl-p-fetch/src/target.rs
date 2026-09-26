// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a fetch is *for* — the typed target the scheduler supplies, the
//! content-verify hole it plugs, and the verified result.

use std::fmt;

use shekyl_crypto_pq::signature::{HybridPublicKey, HybridSignature};

/// The raw 32-byte Ed25519 public key of a persona's v3 onion service, as
/// the bond record carries it (`EU-D3`: the `.onion` is display form; the
/// wire never carries it).
///
/// This is the **daemon's** typed dial target. The wallet serving path
/// publishes through `OnionIdentity` (expanded credential, `ADD_ONION`).
/// Those stay different types (`PWD-E9`): mixing them would let a fetch
/// client hold serving-key material, or a serving host dial through the
/// daemon's SOCKS. The hostname both derive is one function in
/// `shekyl-onion-v3`.
///
/// The provenance obligation: build this from the **record** read (the
/// `ArchivalBondValue` endpoint column at the drawable snapshot, `EU-D4`),
/// never from a vin and never from a response. The crate cannot check
/// where the bytes came from; the type is what the review checks. The
/// bond wire itself stays a bare array (rule 42).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ServingEndpoint([u8; 32]);

impl ServingEndpoint {
    /// Wrap the endpoint column of an authorized bond record. Consensus has
    /// already refused the all-zero endpoint on both sides of the record,
    /// so there is nothing left for this constructor to validate — the
    /// name is the provenance statement.
    #[must_use]
    pub const fn from_record_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw key, as the record holds it.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The v3 `.onion` hostname this endpoint is dialled at.
    #[must_use]
    pub fn onion_address(&self) -> String {
        shekyl_onion_v3::v3_onion_hostname(&self.0)
    }
}

/// Whom to dial, whose signature to accept, and which shard to name.
///
/// Every field is read from **local chain state** — the bond record's
/// endpoint column and identity key, and the scheduler's own assignment —
/// and never from a response (`SF-D7` amendment). The types carry that
/// obligation: a [`ServingEndpoint`] is minted from record bytes, a
/// [`HybridPublicKey`] parses only its canonical encoding. A call site
/// constructing either from wire or response bytes is the review's
/// rule-19 catch, not this crate's.
///
/// The ruled target also names `expected: FrozenSegmentRecord`. It is
/// absent here on purpose: what the body is verified *against* is the
/// content-verify's business, so it lives inside the caller's
/// [`ContentVerify`] impl until `PDM-Q6` names the unit (sub-PR 2). Adding
/// it here would make this crate leaf-aware, which is the split leaking.
#[derive(Clone, Debug)]
pub struct FetchTarget {
    /// The persona's onion, from the bond record.
    pub endpoint: ServingEndpoint,
    /// The persona's stable hybrid identity key, from the bond record
    /// (`SF-D13`). The envelope's countersignature must verify under it.
    pub verifying_key: HybridPublicKey,
    /// The shard the path names.
    pub shard_id: u64,
}

/// The content-verify hole (`PDM-Q-F25` split): does this body hold what
/// the caller expected for `shard_id`?
///
/// Sub-PR 1 knows the body is bytes and that `P` signed for them. Whether
/// they are the *right* bytes — today an `RF-D4` frame whose leaves
/// recompute to the committed `R_k`, tomorrow whatever `PDM-Q6` rules — is
/// this trait's, plugged by the caller. The countersignature check is
/// **not** inside the hole; it ran before this is called, and a refusal
/// here is typed separately ([`FetchError::ContentRefused`](crate::FetchError::ContentRefused))
/// from a bad signature so the scheduler can tell "`P` served the wrong
/// thing" from "`P` did not serve".
///
/// The body is `&[u8]` and nothing more shaped than that. An
/// implementation parses it however its unit demands.
pub trait ContentVerify: Send + Sync {
    /// Accept or refuse `body` as the content of `shard_id`.
    ///
    /// # Errors
    ///
    /// [`ContentRefused`] with the implementation's reason. The client does
    /// not interpret the reason; it carries it to the scheduler.
    fn verify(&self, shard_id: u64, body: &[u8]) -> Result<(), ContentRefused>;
}

/// A [`ContentVerify`] refusal. Opaque to this crate: the reason is the
/// implementation's vocabulary, not the transport's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentRefused {
    reason: String,
}

impl ContentRefused {
    /// A refusal carrying `reason`.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// The implementation's reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for ContentRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for ContentRefused {}

/// A shard whose countersignature verified under the target's key **and**
/// whose content the caller's [`ContentVerify`] accepted.
///
/// There is no unverified variant of this type: the only way to obtain one
/// is through [`PFetchClient::fetch`](crate::PFetchClient::fetch), after
/// both checks (`SF-D8`: verified-or-refused). The signature is kept
/// because the pass record the requester goes on to build carries it.
#[derive(Clone, Debug)]
pub struct VerifiedShard {
    shard_id: u64,
    signature: HybridSignature,
    body: Vec<u8>,
}

impl VerifiedShard {
    pub(crate) fn new(shard_id: u64, signature: HybridSignature, body: Vec<u8>) -> Self {
        Self {
            shard_id,
            signature,
            body,
        }
    }

    /// The shard the path named.
    #[must_use]
    pub fn shard_id(&self) -> u64 {
        self.shard_id
    }

    /// `P`'s countersignature over the request transcript — the pass
    /// record's payload.
    #[must_use]
    pub fn signature(&self) -> &HybridSignature {
        &self.signature
    }

    /// The content bytes after the envelope, as the hole accepted them.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Take the content bytes.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_address_matches_the_publish_side_golden_kat() {
        let pubkey: [u8; 32] = [
            0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e,
            0xab, 0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06,
            0x98, 0x81, 0xdb, 0x12,
        ];
        let endpoint = ServingEndpoint::from_record_bytes(pubkey);
        assert_eq!(
            endpoint.onion_address(),
            "efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad.onion"
        );
        assert_eq!(endpoint.as_bytes(), &pubkey);
    }
}
