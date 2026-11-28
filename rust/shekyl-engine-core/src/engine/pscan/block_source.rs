// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-0 — the per-`P` [`BlockSource`]: the firewall fetch-layer keystone (DQ1).
//!
//! The isolation property is the *shape* of this trait, not a convention: it
//! fetches a **whole block by height** and has **no** selective / output-filtered
//! method. A wallet-server-style "give me the outputs matching X" query is
//! therefore *uncallable* — the Monero light-wallet selective-request leak is
//! unrepresentable on the surface (`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` SP-0 / §4).
//!
//! The persona scan reads whole blocks through the wallet's operator-owned daemon.

use std::future::Future;

use shekyl_rpc_client::{DaemonFault, Rpc, RpcError};
use shekyl_scanner::ScannableBlock;
use shekyl_types::{BlockHeight, ChainCount};

use crate::engine::daemon::synced_chain_facts::fetch_synced_chain_facts;
use crate::engine::traits::DaemonEngine;

/// Error from a [`BlockSource`].
///
/// A failed read carries [`DaemonFault`], the remedy classified where the
/// RPC error was raised. The string is the log line. Syncing stays its own
/// variant: "the daemon did not answer" and "the daemon answered that it
/// does not know yet" are different faults (rule 82), and `R-B` makes only
/// the second one routine.
#[derive(Debug, Clone)]
pub(crate) enum BlockSourceError {
    /// The source failed. `fault` is the remedy. `detail` is the log line.
    Failed {
        /// What the operator does about this read.
        fault: DaemonFault,
        /// The failure's own rendering, including a channel's leg.
        detail: String,
    },
    /// The daemon reports it is still synchronizing, so it has no tip to
    /// claim.
    DaemonSyncing,
}

impl std::fmt::Display for BlockSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // A fault with its own sentence is that sentence. The log line
            // already carries the leg. Anything else is a source failure
            // whose text is the transport's.
            Self::Failed { fault, detail } if fault.has_own_remedy() => f.write_str(detail),
            Self::Failed { detail, .. } => write!(f, "block source failure: {detail}"),
            Self::DaemonSyncing => write!(
                f,
                "the daemon is still synchronizing, so it has no chain tip to claim"
            ),
        }
    }
}

impl std::error::Error for BlockSourceError {}

impl BlockSourceError {
    /// The daemon fault, when this is a failed read. Syncing has none.
    #[must_use]
    pub(crate) fn remedy(&self) -> Option<DaemonFault> {
        match self {
            Self::Failed { fault, .. } => Some(*fault),
            Self::DaemonSyncing => None,
        }
    }

    /// The remedy, when folding this into "the daemon did not answer" would
    /// name the wrong action. Empty for syncing and for a plain transport miss.
    #[must_use]
    pub(crate) fn own_remedy(&self) -> Option<DaemonFault> {
        self.remedy().filter(|fault| fault.has_own_remedy())
    }
}

impl From<RpcError> for BlockSourceError {
    fn from(err: RpcError) -> Self {
        let fault = err.fault();
        // The log line keeps a channel's leg. `Debug` would dump the enum.
        let detail = if fault.has_own_remedy() {
            err.log_line()
        } else {
            err.to_string()
        };
        Self::Failed { fault, detail }
    }
}

/// A per-`P`, fetch-everything source of scannable blocks — the DQ1 firewall
/// keystone.
///
/// There is deliberately **no** selective fetch on this surface (no
/// `outputs_matching`, no filter): the only way to reintroduce the
/// light-wallet leak is to add such a method, which is a visible, reviewable API
/// change rather than an accident a caller can make.
//
// Visibility: `pub(crate)` for SP-0 — the only implementors today are the local
// placeholder and tests. Bump to `pub` when 2d-2's transport needs to implement
// it from another crate (a one-word change behind a stable signature).
pub(crate) trait BlockSource {
    /// This source's **claimed** chain **count** — matching the daemon's
    /// `get_height` (a genesis-only chain reports `1`). So the highest
    /// existing block is `tip()`, and [`Self::block_at`] is valid for
    /// ordinals in `0 .. count` (half-open; exclusive end is
    /// [`ChainCount::next_height`]).
    ///
    /// The method name is the WI-3 named clock (`daemon_claimed_tip` /
    /// `BlockSource::tip_height`); the return type is the quantity. It is a
    /// *claimed* count, **not** a trusted-current one: a single source can
    /// withhold or truncate its tip for free (the SP-7 stale-tip residual)
    /// — forging a header chain is PoW-expensive, truncating it is not. Tip
    /// *currency* is resolved
    /// by **posture**, not multi-source machinery
    /// (`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` §4); this trait only reports
    /// what the source claims.
    fn tip_height(&self) -> impl Future<Output = Result<ChainCount, BlockSourceError>> + Send;

    /// Fetch the **whole** block at `height` (header + every transaction + the
    /// first global output index), in scannable form.
    ///
    /// `Ok(None)` means the source can *prove* there is no block at `height`
    /// (above tip / pruned) — a capability that requires header-chain anchoring
    /// and is therefore a 2d-2 transport property (withheld-body robustness; see
    /// the trust-anchor resolution — exhaustiveness is 2d-1, withheld-body / fork /
    /// tip robustness is 2d-2, not a wallet-side PoW/root-anchoring job). The 2d-1
    /// [`DaemonBlockSource`] surfaces a missing block as `Err`: it cannot *prove*
    /// absence, so it never fabricates a `None`.
    ///
    /// **P-SH — single-height-per-call is a *correctness* precondition, not an
    /// ergonomics choice** (`ARCHIVAL_BOND_2D2_SP_T2_FETCH.md` DQ-T2.5). This
    /// method takes **one** `height`, and that is load-bearing: a single-height
    /// read is atomic (store MVCC — no adversary needed), whereas a *multi*-height
    /// batch can straddle a reorg *between* its per-height reads (finding-b),
    /// returning an internally-inconsistent set the scanner would splice. The
    /// signature — one `height`, not a range/slice — makes that batch
    /// **unrepresentable**: reintroducing a multi-height fetch is a visible
    /// signature change here, and it reopens finding-b — it requires *either* a
    /// single-`txn` batch read on the daemon side *or* the scanner's cross-height
    /// coherence requirement established first. The type enforces; this note is
    /// the reopen condition it carries.
    fn block_at(
        &self,
        height: BlockHeight,
    ) -> impl Future<Output = Result<Option<ScannableBlock>, BlockSourceError>> + Send;
}

/// A source's claimed tip, **only if the daemon reports itself synchronized**.
///
/// Returns the [`SyncedChainFacts`](crate::engine::daemon::synced_chain_facts::SyncedChainFacts)
/// witness rather than a bare height
/// (`WALLET_SIDE_STORE.md` `WSS-Q14`). Every consumer below posts a
/// transaction stamped with this clock, and `R-B` says that while the daemon
/// reports syncing the answer is **unknown** — do not erase, post or sign. So
/// the clock is not derivable without the witness: a syncing daemon yields
/// [`BlockSourceError::DaemonSyncing`] and the caller declines, rather than
/// stamping a post with a resync height.
///
/// This is the choke point, which is why the gate sits here and not at six
/// call sites. **The witness is consumed here, not returned** — callers
/// receive a [`ChainCount`], the quantity this clock has always carried
/// (the type matches; the number does not move), and cannot inspect the
/// facts it was derived from. What the type buys is not an API for them:
/// it is that **there is no other way to obtain this clock**, so a future
/// consumer inherits the refusal instead of having to remember it —
/// adopt-on-next-touch is how `WSS-25` happened.
///
/// A consumer that needs to *reason* about the facts rather than take a
/// height — to reject a rolled-back record, say — must hold the witness
/// itself and reconcile it (`CoherentChainView`), which is what the claim
/// and exit lanes do. This function is for consumers that only need a clock.
///
/// One `daemon_status` read carries both the height and the sync state, so
/// the gate costs no extra round trip. The value returned is **numerically unchanged** — [`ChainCount`], not
/// `.tip()`. Flipping to `.tip()` would fire due one block late and skip
/// the last pscan block.
///
/// **Named daemon-claimed-tip clock (WI-2 F-2 / WI-3 R2-1).** This is the
/// single function both (a) a stake request's `requested_at` and the
/// signing-at-due tip check and (b) the pscan dispatch due-check tip read
/// through (`BlockSource::tip_height` → here). Explicitly **not**
/// `synced_height` or `ingested_tip_height` — those clocks have different
/// bases and must not feed a plan's due.
///
pub(crate) async fn daemon_claimed_tip<R: Rpc>(rpc: &R) -> Result<ChainCount, BlockSourceError> {
    let facts = fetch_synced_chain_facts(rpc)
        .await?
        .ok_or(BlockSourceError::DaemonSyncing)?;
    // Count, not tip ordinal — the number is frozen (Phase 1).
    // Flipping to `.tip()` would fire due one block late and skip the
    // last pscan block. A 3-block chain still reports 3.
    Ok(facts.chain_height())
}

/// A [`BlockHeight`] as the `usize` block **number** the fetch layer indexes by,
/// converted fail-closed. Shared by both `block_at` impls, which then differ only
/// in *which* single-height fetch they issue.
fn block_number(height: BlockHeight) -> Result<usize, BlockSourceError> {
    usize::try_from(height.to_raw()).map_err(|_| BlockSourceError::Failed {
        fault: DaemonFault::Internal,
        detail: format!("height {} exceeds the platform's usize", height.to_raw()),
    })
}

/// The 2d-1 local [`BlockSource`]: a firewall-shaped view over an existing
/// [`DaemonEngine`] connection.
///
/// It is generic over [`DaemonEngine`] (not the bare `Rpc` transport) on
/// purpose — it calls the high-level
/// [`DaemonEngine::fetch_scannable_block`], which the daemon actor and
/// the test double both override; routing through the low-level `Rpc`
/// transport instead would bypass those overrides.
///
/// This establishes the *interface* only. The per-`P` network **isolation**
/// (separate connection, no shared cache with the principal) is 2d-2's
/// transport, not this placeholder.
pub(crate) struct DaemonBlockSource<D: DaemonEngine> {
    daemon: D,
}

impl<D: DaemonEngine> DaemonBlockSource<D> {
    /// Wrap a daemon connection as a per-`P` block source.
    pub(crate) fn new(daemon: D) -> Self {
        Self { daemon }
    }
}

impl<D: DaemonEngine> BlockSource for DaemonBlockSource<D> {
    async fn tip_height(&self) -> Result<ChainCount, BlockSourceError> {
        // `DaemonEngine: Rpc`, so `get_height` is the inherited tip query.
        daemon_claimed_tip(&self.daemon).await
    }

    async fn block_at(
        &self,
        height: BlockHeight,
    ) -> Result<Option<ScannableBlock>, BlockSourceError> {
        let number = block_number(height)?;
        // High-level fetch: whole block, all transactions, no selectivity.
        // Every body arrives as a skeleton bound to its txid (`SB-Q2`), which
        // is what SP-6's exhaustiveness gate reads. Routes through
        // `DaemonEngine::fetch_scannable_block` (which the daemon actor and
        // the test double override) — not the bare `Rpc`, which would bypass
        // them.
        let block = self.daemon.fetch_scannable_block(number).await?;
        Ok(Some(block))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_support::{make_synthetic_block, TestDaemon, DEFAULT_TEST_SEED};

    /// A small synthetic chain. Parent linkage is irrelevant to fetch-by-height
    /// (the daemon serves `chain[height]`), so dummy parents suffice here.
    fn three_block_chain() -> Vec<ScannableBlock> {
        vec![
            make_synthetic_block(0, shekyl_types::BlockHash::NULL),
            make_synthetic_block(1, shekyl_types::BlockHash::NULL),
            make_synthetic_block(2, shekyl_types::BlockHash::NULL),
        ]
    }

    #[tokio::test]
    async fn local_source_reports_tip_and_fetches_whole_block_by_height() {
        let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, three_block_chain());
        let source = DaemonBlockSource::new(daemon);

        // tip_height reports the source's claimed height (chain length).
        assert_eq!(
            source.tip_height().await.expect("tip_height"),
            ChainCount::from_raw(3)
        );

        // block_at returns the WHOLE block at the requested height — fetch-everything,
        // no selectivity. `block.block.number()` is the coinbase `gen` height.
        let fetched = source
            .block_at(BlockHeight::from_raw(1))
            .await
            .expect("block_at transport")
            .expect("block 1 present");
        assert_eq!(fetched.block.number(), Some(1));
    }

    // ── WSS-Q14 class-A refusal bite ────────────────────────────────────
    //
    // `daemon_claimed_tip` is the choke point six consumers read their clock
    // through: a plan's `requested_at` (bond_orchestrator), the claim / drain / release
    // dispatch stamps, and both `BlockSource::tip_height` impls (whence the
    // pscan finality horizon). Every one of them stamps a transaction it then
    // posts, which is what `R-B` forbids on an unsynchronized view.
    //
    // One bite covers the class because there is exactly one derivation: the
    // consumers cannot obtain this clock any other way. The edit that turns
    // this red is deleting the `ok_or(DaemonSyncing)` — which is also the
    // edit that would silently restore `WSS-25`'s shape on the posting lanes.

    /// A syncing daemon has no tip to claim, so the clock is not derivable —
    /// and the refusal names the state rather than looking like a transport
    /// fault.
    ///
    /// This bites against every consumer stamping a post on a resync height;
    /// it does **not** cover a daemon that lies "synchronized" (the type
    /// carries the daemon's claim, not an independent measurement).
    #[tokio::test]
    async fn a_syncing_daemon_yields_no_claimed_tip() {
        let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, three_block_chain());
        daemon.set_daemon_syncing(true);

        let err = daemon_claimed_tip(&daemon)
            .await
            .expect_err("a syncing daemon has no tip to claim");
        assert!(
            matches!(err, BlockSourceError::DaemonSyncing),
            "the refusal must name the sync state, not read as a transport \
             failure an operator would chase at the network layer: {err:?}"
        );

        // And the same refusal reaches the consumers through the seam they
        // actually call, rather than only the free function.
        let source = DaemonBlockSource::new(daemon);
        assert!(
            matches!(
                source.tip_height().await,
                Err(BlockSourceError::DaemonSyncing)
            ),
            "BlockSource::tip_height must inherit the gate"
        );
    }

    /// The negative control, and the numeric pin: synchronized, the clock is
    /// the same value it was before the gate existed.
    ///
    /// Without this the test above would pass on a `daemon_claimed_tip` that
    /// had simply stopped working. It also pins the count-vs-tip reading
    /// deliberately left unchanged — a 3-block chain still reports 3, not 2.
    #[tokio::test]
    async fn a_synchronized_daemon_reports_the_unchanged_clock() {
        let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, three_block_chain());
        assert_eq!(
            daemon_claimed_tip(&daemon).await.expect("synced"),
            ChainCount::from_raw(3),
        );
    }

    /// A channel refusal stays a channel refusal on the read that every
    /// poster stamps from. Red edit: store only `err.to_string()` in
    /// `Failed`, and `own_remedy` is `None`.
    #[test]
    fn a_channel_fault_keeps_its_remedy_on_a_block_read() {
        let fingerprint = [7_u8; 32];
        let err = RpcError::Channel(
            shekyl_rpc_client::WalletChannelFault::NotEnrolled(fingerprint),
            "127.0.0.1:11029".into(),
        );
        let source = BlockSourceError::from(err);
        assert_eq!(
            source.own_remedy(),
            Some(DaemonFault::Channel(
                shekyl_rpc_client::WalletChannelFault::NotEnrolled(fingerprint)
            ))
        );
        let shown = source.to_string();
        assert!(
            shown.contains("shekyl-cli rpc client add"),
            "the enrollment command is the sentence: {shown}"
        );
        assert!(
            shown.contains("127.0.0.1:11029"),
            "the leg stays beside the sentence: {shown}"
        );
        assert!(
            !shown.contains("block source failure"),
            "a channel fault is not a generic source failure: {shown}"
        );
    }
}
