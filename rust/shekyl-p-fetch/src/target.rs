// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a fetch is *for* — the typed target the scheduler supplies, the
//! content-verify hole it plugs, and the verified result.

use std::fmt;

use shekyl_crypto_pq::signature::{HybridPublicKey, HybridSignature};
use shekyl_curve_tree::ServingEndpoint;

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
