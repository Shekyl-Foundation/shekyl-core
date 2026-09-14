// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The host's half of the `SF-D8` countersignature: **which height** the
//! anchor gate runs against, and **where the key is**.
//!
//! `shekyl-p-serve` asks one object ([`PassSigner`]) two questions — the
//! persona's own height, and a signature over the transcript. This module
//! answers the first from the store the host is already serving and leaves
//! the second to [`PassKey`], which a caller supplies.
//!
//! # Why height is not a parameter
//!
//! The gate is `anchor ∈ [p − 720 − L, p − 720 + L]` for the persona's own
//! height `p`. Taking `p` from the caller would make it one more thing the
//! host does not choose about its own duty but *could be told wrongly* — a
//! stale `p` refuses the network; a forward `p` admits anchors the persona
//! has not seen. The store the pins landed in already carries the height
//! the principal's block scan advanced it to
//! ([`ServingReader::sync_tip_height`]),
//! and that is the same store whose shards are being signed for. Reading
//! it there is the one answer that cannot disagree with the bytes served.
//!
//! # Why the key is
//!
//! The key is the persona's bonded attestation key, and its custody is the
//! wallet's design (`ARCHIVAL_CHALLENGE_MECHANISM.md` §7.2; SH-2 for the
//! resident shape). This crate holds an `Arc<dyn PassKey>` and calls it
//! once per served shard from the blocking pool; it never sees the secret.
//! Until the resident key is wired, the caller passes [`NoResidentKey`] and
//! the endpoint answers every request with the identical 404 — up,
//! counted, and never serving an unsigned body.

use std::sync::Arc;

use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_tree::ServingReader;
use shekyl_p_serve::{PassKey, PassSigner, SignRefused, PASS_COUNTERSIGNATURE_MESSAGE_LEN};

/// The key a host binds before its resident attestation key is wired.
///
/// Refuses every transcript with a fixed reason, so a persona whose serving
/// stack is up but whose key is not answers 404 (counted under
/// `sign_failure_count`) rather than serving bytes a daemon cannot verify.
/// This is the SH-2 placeholder made a type: there is no unsigned code path
/// to fall back to, only a key that says no.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoResidentKey;

impl NoResidentKey {
    /// The refusal detail, operator-facing only.
    pub const REASON: &'static str = "persona attestation key not resident (SH-2 not wired)";
}

impl PassKey for NoResidentKey {
    fn sign_pass(
        &self,
        _message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        Err(SignRefused::new(Self::REASON))
    }
}

/// The [`PassSigner`] a [`PersonaServingHost`](crate::PersonaServingHost)
/// binds: height from the served store, signature from the caller's key.
///
/// Built inside `start` from the witness's reader — never from an argument
/// — for the reason the module doc gives.
pub(crate) struct HostSigner {
    reader: ServingReader,
    key: Arc<dyn PassKey>,
}

impl HostSigner {
    pub(crate) fn new(reader: ServingReader, key: Arc<dyn PassKey>) -> Self {
        Self { reader, key }
    }
}

impl PassKey for HostSigner {
    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        self.key.sign_pass(message)
    }
}

impl PassSigner for HostSigner {
    /// The store's synced tip, live. A store that cannot be read is `None`:
    /// the serve loop renders the 404 and counts a lookup failure, so a
    /// persona that has lost its store shows up in `ServeCounters` rather
    /// than refusing every anchor behind an indistinguishable sentinel.
    fn own_height(&self) -> Option<u64> {
        self.reader.sync_tip_height().ok().map(|h| h.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_curve_tree::{BlockHeight, LeafStore};

    #[test]
    fn no_resident_key_refuses_with_its_fixed_reason() {
        let err = NoResidentKey
            .sign_pass(&[0u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN])
            .unwrap_err();
        assert_eq!(err.detail, NoResidentKey::REASON);
    }

    #[test]
    fn host_signer_height_is_the_stores_sync_tip() {
        let store = Arc::new(LeafStore::open_ephemeral().expect("open"));
        let reader = ServingReader::new(Arc::clone(&store));
        let signer = HostSigner::new(reader, Arc::new(NoResidentKey));
        assert_eq!(
            signer.own_height(),
            Some(0),
            "a fresh store is readable at height 0 — below the gate, not unreadable"
        );
        store
            .append_block_deltas(&[], &[], &[], BlockHeight(4_321))
            .expect("advance tip");
        assert_eq!(
            signer.own_height(),
            Some(4_321),
            "the gate reads the height the block scan advanced, live"
        );
        assert!(signer
            .sign_pass(&[0u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN])
            .is_err());
    }
}
