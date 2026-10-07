// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The host's half of the `SF-D8` countersignature: **which height** the
//! anchor gate runs against, and **where the key is**.
//!
//! `shekyl-p-serve` asks one object ([`PassSigner`]) two questions — the
//! persona's own height, and a signature over the transcript. This module
//! answers the first from the configured daemon's tip and leaves the
//! second to [`PassKey`], which a caller supplies.
//!
//! # Why height comes from the daemon, not from the served store
//!
//! The gate is `anchor ∈ [p − 720 − L, p − 720 + L]` for the persona's own
//! height `p`, with `L = 4`. Taking `p` from the caller would make it one
//! more thing the host does not choose about its own duty but *could be
//! told wrongly* — a stale `p` refuses the network; a forward `p` admits
//! anchors the persona has not seen. So `p` is not an argument, and the
//! only question is which reading the host takes.
//!
//! It used to be [`ServingReader::sync_tip_height`](shekyl_curve_tree::ServingReader::sync_tip_height)
//! — the height the
//! **principal's block scan** had advanced the served store to. The
//! argument was that the store being read is the store being signed for, so
//! the two cannot disagree. That is true and it is not the property the
//! gate needs: the anchor is a claim about the *chain*, and the scan tip is
//! a fact about the *wallet*. Nothing bounds the scan's lag below `L` — the
//! serving side's only freshness check (`caught_up`, slack 64) feeds the
//! alarm board and gates nothing — so an honest `P` five blocks behind on
//! refresh refused a valid challenge, missed the pass, and was slashed for
//! its own scanner's cadence (`WSS-24`).
//!
//! The reading is therefore the configured daemon's tip, taken on `P`'s own
//! transport and never from a peer draw, stamped into a
//! [`DaemonTipCache`] by a producer on a cadence and
//! read here synchronously. A `p` that is stale past the cache's age bound,
//! or a daemon that has stopped following the chain, is `None` — the same answer an
//! unreadable store gave, on the same path.
//!
//! # Why the key is
//!
//! The key is the persona's bonded attestation key, and its custody is the
//! wallet's design (`ARCHIVAL_CHALLENGE_MECHANISM.md` §7.2; `SF-D13`). This
//! crate holds an `Arc<dyn PassKey>` and calls it once per served shard from
//! the blocking pool; it never sees the secret. The production key is
//! `shekyl-engine-core`'s resident pass key, which answers each call with a
//! round-trip into the stake actor that holds the secret. A key that answers
//! "no" keeps the endpoint up and counted: a valid request for a held shard
//! is the bare 503, before any shard byte is sent. [`RefusingKey`] is that
//! key for tests, on the same dev-only edge as `TestKeySigner`.

use std::sync::Arc;

use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_p_serve::{PassKey, PassSigner, SignRefused, PASS_COUNTERSIGNATURE_MESSAGE_LEN};
use shekyl_types::BlockHeight;

use crate::daemon_tip::DaemonTipCache;

/// A key that says no — the test fixture for the host's keyless path.
///
/// Refuses the pre-flight and every transcript with a fixed reason. The
/// serve loop asks [`PassKey::ready`] before the first response byte, so a
/// host bound to this key answers a valid request for a held shard with the
/// bare 503 and sends no shard, counted under `sign_failures`; that is the
/// bucket the lifecycle and counter tests read. Production never binds it:
/// the engine's resident pass key refuses on the same path when the actor
/// holding the secret is gone, which is why the fixture is useful and why it
/// is on the dev-only `test-signer` edge rather than in the shipped graph.
#[cfg(any(test, feature = "test-signer"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct RefusingKey;

#[cfg(any(test, feature = "test-signer"))]
impl RefusingKey {
    /// The refusal detail, operator-facing only.
    pub const REASON: &'static str = "refusing key (test fixture)";
}

#[cfg(any(test, feature = "test-signer"))]
impl PassKey for RefusingKey {
    fn ready(&self, _shard_id: u64, _anchor_height: BlockHeight) -> Result<(), SignRefused> {
        Err(SignRefused::new(Self::REASON))
    }

    fn sign_pass(
        &self,
        _message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        Err(SignRefused::new(Self::REASON))
    }
}

/// The [`PassSigner`] a [`PersonaServingHost`](crate::PersonaServingHost)
/// binds: height from the daemon tip cache, signature from the caller's key.
///
/// The cache is shared with the producer that stamps it — that producer
/// owns the transport and the cadence, both of which are facts about how
/// this wallet was opened rather than about serving, so neither is decided
/// here. What is decided here is that the gate reads *that* cache and
/// nothing else, and that a `None` from it refuses.
pub(crate) struct HostSigner {
    tip: Arc<DaemonTipCache>,
    key: Arc<dyn PassKey>,
}

impl HostSigner {
    pub(crate) fn new(tip: Arc<DaemonTipCache>, key: Arc<dyn PassKey>) -> Self {
        Self { tip, key }
    }
}

impl PassKey for HostSigner {
    /// The wrapped key's answer, forwarded: a keyless host must not send
    /// shards it cannot countersign.
    fn ready(&self, shard_id: u64, anchor_height: BlockHeight) -> Result<(), SignRefused> {
        self.key.ready(shard_id, anchor_height)
    }

    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        self.key.sign_pass(message)
    }
}

impl PassSigner for HostSigner {
    /// The daemon's top block height as of the last stamp within the
    /// cache's age bound.
    ///
    /// `None` when there is no usable tip — nothing stamped yet, the daemon
    /// stopped following the chain, or the last stamp has aged out. All three
    /// take the path the unreadable store took before them: the serve loop
    /// renders the 503 and counts a lookup failure, so a persona
    /// that has lost sight of the chain shows up in `ServeCounters` rather
    /// than refusing every anchor behind an indistinguishable sentinel.
    fn own_height(&self) -> Option<BlockHeight> {
        self.tip.height()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const MAX_AGE: Duration = Duration::from_secs(120);

    fn signer() -> (Arc<DaemonTipCache>, HostSigner) {
        let tip = Arc::new(DaemonTipCache::new(MAX_AGE));
        let signer = HostSigner::new(Arc::clone(&tip), Arc::new(RefusingKey));
        (tip, signer)
    }

    /// The refusal is the pre-flight's, so a keyless persona is a 503
    /// before the body rather than a shard that ends in the refusal
    /// trailer; the host signer passes the question through to its key.
    #[test]
    fn refusing_key_refuses_at_the_pre_flight_and_the_host_passes_it_through() {
        let err = RefusingKey
            .ready(7, BlockHeight::from_raw(9_280))
            .unwrap_err();
        assert_eq!(err.detail, RefusingKey::REASON);
        let (tip, signer) = signer();
        tip.stamp_synced(BlockHeight::from_raw(10_000));
        assert_eq!(
            signer
                .ready(7, BlockHeight::from_raw(9_280))
                .unwrap_err()
                .detail,
            RefusingKey::REASON,
            "the host signer's pre-flight is its key's"
        );
    }

    #[test]
    fn refusing_key_refuses_with_its_fixed_reason() {
        let err = RefusingKey
            .sign_pass(&[0u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN])
            .unwrap_err();
        assert_eq!(err.detail, RefusingKey::REASON);
    }

    /// WSS-24: the gate's height is the daemon's tip, not the principal's
    /// scan. Restoring the `ServingReader::sync_tip_height` read turns this
    /// red — a store the signer no longer holds cannot answer it.
    #[test]
    fn host_signer_height_is_the_stamped_daemon_tip() {
        let (tip, signer) = signer();
        assert_eq!(
            signer.own_height(),
            None,
            "before any stamp the persona cannot say where the chain is"
        );
        tip.stamp_synced(BlockHeight::from_raw(4_321));
        assert_eq!(
            signer.own_height(),
            Some(BlockHeight::from_raw(4_321)),
            "the gate reads the daemon tip the producer stamped"
        );
    }

    /// A daemon that has stopped following the chain refuses, even with a
    /// tip that is still well inside the age bound.
    #[test]
    fn a_daemon_that_stopped_following_refuses() {
        let (tip, signer) = signer();
        tip.stamp_synced(BlockHeight::from_raw(4_321));
        tip.stamp_not_following();
        assert_eq!(signer.own_height(), None);
    }

    /// The age bound reaches the gate: a tip past `max_age` is `None` at
    /// `own_height`, not a stale height the gate would centre on.
    #[test]
    fn a_tip_past_the_age_bound_refuses_at_the_gate() {
        let tip = Arc::new(DaemonTipCache::new(MAX_AGE));
        let signer = HostSigner::new(Arc::clone(&tip), Arc::new(RefusingKey));
        let long_ago = Instant::now()
            .checked_sub(MAX_AGE + Duration::from_secs(1))
            .expect("the test clock is past the age bound");
        tip.stamp_synced_at(BlockHeight::from_raw(4_321), long_ago);
        assert_eq!(signer.own_height(), None);
    }

    /// The key half is untouched by the height change: `RefusingKey`
    /// still refuses every transcript.
    #[test]
    fn the_key_still_refuses_independently_of_the_height() {
        let (tip, signer) = signer();
        tip.stamp_synced(BlockHeight::from_raw(4_321));
        assert!(signer
            .sign_pass(&[0u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN])
            .is_err());
    }
}
