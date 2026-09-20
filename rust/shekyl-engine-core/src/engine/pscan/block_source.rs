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
//! 2d-1 ships [`DaemonBlockSource`], a thin firewall-shaped view over an existing
//! daemon connection that establishes the *interface*. 2d-2 implements the real
//! per-`P`-isolated transport behind the same trait — a bundled Tor-over-SOCKS
//! client, not Arti (`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` §3) — adding the network
//! **isolation** (separate connection, no shared cache with the principal) this
//! placeholder does not provide.
//!
//! ## Staging note
//!
//! SP-0 is the keystone; its non-test consumer is the **SP-5** scan loop (the
//! `P`-scan task that drives this source), live since the WI-1 lifecycle wiring
//! (`Engine::start_pscan`). [`PBlockSource`] still carries transient
//! `#[allow(dead_code)]`: its consumer is the 2d-2 posture selector (DQ-T2.3),
//! explicitly out of WI-1's scope.

use std::future::Future;

use shekyl_p_transport::PTorClient;
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_scanner::ScannableBlock;
use shekyl_types::{BlockHeight, ChainCount};

use crate::engine::block_fetch::default_fetch_scannable_block_full;
use crate::engine::daemon::synced_chain_facts::fetch_synced_chain_facts;
use crate::engine::prpc::PRpc;
use crate::engine::traits::DaemonEngine;

/// Error from a [`BlockSource`].
///
/// Transport-agnostic (it carries a rendered message, not a transport type) so
/// 2d-2's transport maps its own failures in without this type ever depending on
/// a specific transport's error enum.
#[derive(Debug, Clone)]
pub(crate) enum BlockSourceError {
    /// The underlying source (transport, parse, or daemon) failed.
    Source(String),
    /// The daemon reports it is still synchronizing, so it has no tip to
    /// claim.
    ///
    /// Deliberately **not** folded into [`Self::Source`]: "the daemon did not
    /// answer" and "the daemon answered that it does not know yet" are
    /// different faults with different operator remedies (rule 82), and
    /// `R-B` makes only the second one routine.
    DaemonSyncing,
}

impl std::fmt::Display for BlockSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source(msg) => write!(f, "block source failure: {msg}"),
            Self::DaemonSyncing => write!(
                f,
                "the daemon is still synchronizing, so it has no chain tip to claim"
            ),
        }
    }
}

impl std::error::Error for BlockSourceError {}

impl From<RpcError> for BlockSourceError {
    fn from(err: RpcError) -> Self {
        // `Display` (the `thiserror` `#[error(...)]` message), not `Debug` — this
        // is a rendered, human-facing message, not a structural dump.
        Self::Source(err.to_string())
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
    /// read is atomic (LMDB/MVCC — no adversary needed), whereas a *multi*-height
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

// Shared [`BlockSource`] conversion scaffolding: the `tip_height` body and the
// `block_at` height→number conversion are transport-agnostic, so both the local
// `DaemonBlockSource` and the remote `PBlockSource` route through these helpers
// rather than re-deriving the same checked conversions (and the same error
// strings) per impl, where the copies could drift.

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
/// One `get_info` read replaces the former `get_height` read: the same
/// response carries the height and the sync state, so the gate costs no extra
/// round trip, and the former `usize → u64` conversion is gone with it. The
/// value returned is **numerically unchanged** — [`ChainCount`], not
/// `.tip()`. Flipping to `.tip()` would fire due one block late and skip
/// the last pscan block.
///
/// **Named daemon-claimed-tip clock (WI-2 F-2 / WI-3 R2-1).** This is the
/// single function both (a) bond-assemble `anchor_t0` stamps and (b) the
/// pscan dispatch due-check tip read through (`BlockSource::tip_height` →
/// here). Explicitly **not** `synced_height` or `ingested_tip_height` —
/// those clocks have different bases and must not feed `anchor_t0`.
///
/// Generic over the transport so the local (`DaemonEngine: Rpc`) and remote
/// ([`PRpc`]) sources share one body; the returned future is `Send` because
/// `get_height`'s is.
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
    usize::try_from(height.to_raw()).map_err(|_| {
        BlockSourceError::Source(format!(
            "height {} exceeds the platform's usize",
            height.to_raw()
        ))
    })
}

/// The 2d-1 local [`BlockSource`]: a firewall-shaped view over an existing
/// [`DaemonEngine`] connection.
///
/// It is generic over [`DaemonEngine`] (not the bare `Rpc` transport) on
/// purpose — it calls the high-level
/// [`DaemonEngine::fetch_scannable_block_full`], which the daemon actor and
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
        // High-level fetch: whole block, all transactions, no selectivity. The
        // **full**-body variant, because SP-6's exhaustiveness gate recomputes
        // each body's committed hash — a pruned FCMP++ spend can never satisfy
        // it (`Transaction::hash()` substitutes the null prunable hash). Routes
        // through `DaemonEngine::fetch_scannable_block_full` (which the daemon
        // actor and the test double override) — not the bare `Rpc`, which
        // would bypass them.
        let block = self.daemon.fetch_scannable_block_full(number).await?;
        Ok(Some(block))
    }
}

/// The 2d-2 **remote-posture** [`BlockSource`]: fetches whole blocks over `P`'s
/// **own** Tor circuit via [`PRpc`] (a plain fetch shim — the Round-0
/// disposition attached no decorrelation duty, DQ-T2.5).
///
/// Constructed **only** from a [`PTorClient`] + the daemon base URL (DQ-T2.3,
/// §416): there is no principal-`DaemonClient` path and no `Default`, so a remote
/// source **cannot** be built over the shared principal connection — the posture
/// conflation the firewall forbids (`P` routing its fetch over a shared circuit)
/// is unrepresentable on the constructor, not merely discouraged.
//
// The posture selector at the SP-5 scan-loop wiring is the outstanding
// consumer. Note the split: the struct and its `BlockSource` impl need no
// suppression, while the `new` constructor below does — the module test is its
// only caller until that selector lands.
pub(crate) struct PBlockSource {
    rpc: PRpc,
}

#[allow(dead_code)]
impl PBlockSource {
    /// Build a remote-posture source dialing `base_url` over `client`'s circuit.
    pub(crate) fn new(client: PTorClient, base_url: String) -> Self {
        Self {
            rpc: PRpc::new(client, base_url),
        }
    }
}

impl BlockSource for PBlockSource {
    async fn tip_height(&self) -> Result<ChainCount, BlockSourceError> {
        // `PRpc: Rpc`, so `get_height` is the inherited tip query — over `P`'s
        // circuit, same claimed-not-trusted semantics as any single source.
        daemon_claimed_tip(&self.rpc).await
    }

    async fn block_at(
        &self,
        height: BlockHeight,
    ) -> Result<Option<ScannableBlock>, BlockSourceError> {
        let number = block_number(height)?;
        // P-SH: exactly one height per call — the fetch issues a single
        // `get_block` (+ its txs) for `number`. Full bodies, same as
        // `DaemonBlockSource`: the SP-6 per-body hash recompute requires the
        // prunable section. (The pruned-fetch bandwidth optimization over Tor
        // is the reopening candidate if 2d-2 posture profiling demands it —
        // it would need a daemon-claimed `prunable_hash` leg, which weakens
        // recompute-from-received; see `docs/FOLLOWUPS.md`.) Like
        // `DaemonBlockSource`, a missing block surfaces as `Err` (this source
        // cannot *prove* absence; `Ok(None)` is the withheld-body-robustness
        // slice, out of scope for SP-T2).
        let block = default_fetch_scannable_block_full(&self.rpc, number).await?;
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
    // through: `anchor_t0` (bond_orchestrator), the claim / drain / release
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

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_source_over_a_dead_proxy_errors_without_leaking_the_username() {
        use shekyl_p_transport::TorSocksEndpoint;
        use shekyl_types::PCanonicalId;

        // No Tor: a closed SOCKS port (`:1`) refuses immediately, so the remote
        // source's transport error path is exercised fast. `PBlockSource::new`
        // takes only a `PTorClient` — there is no principal path to construct it
        // over a shared connection (DQ-T2.3). The failure is a `Source` error and
        // must not render the SOCKS username (invariant (a)).
        let client = PTorClient::for_persona(
            &PCanonicalId::from_bytes([9u8; 32]),
            &TorSocksEndpoint::loopback(1),
        )
        .expect("proxy config is well-formed");
        let username = client.username().as_str().to_owned();
        let source = PBlockSource::new(client, "http://127.0.0.1:18081".to_string());

        let err = source
            .tip_height()
            .await
            .expect_err("a dead SOCKS proxy must fail the tip query");
        assert!(
            !format!("{err}").contains(&username),
            "invariant (a): a block-source error must never render the SOCKS username"
        );
    }
}
