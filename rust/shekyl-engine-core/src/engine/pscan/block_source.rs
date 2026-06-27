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
//! daemon connection that establishes the *interface*. 2d-2 swaps an Arti
//! transport behind the same trait and adds the per-`P` network **isolation**
//! (separate connection, no shared cache with the principal) this placeholder
//! does not provide.
//!
//! ## Staging note
//!
//! SP-0 is the keystone; its non-test consumer is the **SP-5** scan loop (the
//! `P`-scan task that drives this source), which is not yet built. Until it
//! lands, the trait and the local impl are exercised only by this module's tests,
//! so they carry `#[allow(dead_code)]` — transient scaffolding the SP-5 PR
//! removes when it wires the first real caller. The proving test below ships
//! *with* the enabler (it is not deferred).

use std::future::Future;

use shekyl_rpc_client::RpcError;
use shekyl_scanner::ScannableBlock;
use shekyl_types::BlockHeight;

use crate::engine::traits::DaemonEngine;

/// Error from a [`BlockSource`].
///
/// Transport-agnostic (it carries a rendered message, not a transport type) so
/// 2d-2's Arti transport maps its own failures in without this type ever
/// depending on a specific transport's error enum.
#[derive(Debug, Clone)]
pub(crate) enum BlockSourceError {
    /// The underlying source (transport, parse, or daemon) failed.
    Source(String),
}

impl std::fmt::Display for BlockSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source(msg) => write!(f, "block source failure: {msg}"),
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
//
// `allow(dead_code)`: transient — the non-test consumer is the SP-5 scan loop
// (module "Staging note"); removed when that PR wires the first real caller.
#[allow(dead_code)]
pub(crate) trait BlockSource {
    /// This source's **claimed** chain height — the *count* of blocks, matching
    /// the daemon's `get_height` (a genesis-only chain has height `1`). So the
    /// highest existing block is `tip_height - 1`, and [`Self::block_at`] is valid
    /// for heights in `0 .. tip_height` (half-open).
    ///
    /// It is a *claimed* height, **not** a trusted-current one: a single source
    /// can withhold or truncate its tip for free (the SP-7 stale-tip residual) —
    /// forging a header chain is PoW-expensive, truncating it is not. Establishing
    /// that a tip is *current* needs multiple `P`-isolated sources or an
    /// out-of-band sanity-check, which is a 2d-2 transport property; this trait
    /// only reports what the source claims.
    fn tip_height(&self) -> impl Future<Output = Result<BlockHeight, BlockSourceError>> + Send;

    /// Fetch the **whole** block at `height` (header + every transaction + the
    /// first global output index), in scannable form.
    ///
    /// `Ok(None)` means the source can *prove* there is no block at `height`
    /// (above tip / pruned) — a capability that requires header-chain anchoring
    /// and is therefore a 2d-2 transport property. The 2d-1 [`DaemonBlockSource`]
    /// surfaces a missing block as `Err`: it cannot *prove* absence (that is
    /// SP-7's root-anchored job), so it never fabricates a `None`.
    fn block_at(
        &self,
        height: BlockHeight,
    ) -> impl Future<Output = Result<Option<ScannableBlock>, BlockSourceError>> + Send;
}

/// The 2d-1 local [`BlockSource`]: a firewall-shaped view over an existing
/// [`DaemonEngine`] connection.
///
/// It is generic over [`DaemonEngine`] (not the bare `Rpc` transport) on
/// purpose — it calls the high-level [`DaemonEngine::fetch_scannable_block`],
/// which the daemon actor and the test double both override; routing through
/// the low-level `Rpc` transport instead would bypass those overrides.
///
/// This establishes the *interface* only. The per-`P` network **isolation**
/// (separate connection, no shared cache with the principal) is 2d-2's
/// transport, not this placeholder.
//
// `allow(dead_code)`: transient — see the module "Staging note" (SP-5 consumer).
#[allow(dead_code)]
pub(crate) struct DaemonBlockSource<D: DaemonEngine> {
    daemon: D,
}

#[allow(dead_code)]
impl<D: DaemonEngine> DaemonBlockSource<D> {
    /// Wrap a daemon connection as a per-`P` block source.
    pub(crate) fn new(daemon: D) -> Self {
        Self { daemon }
    }
}

impl<D: DaemonEngine> BlockSource for DaemonBlockSource<D> {
    async fn tip_height(&self) -> Result<BlockHeight, BlockSourceError> {
        // `DaemonEngine: Rpc`, so `get_height` is the inherited tip query.
        let height = self.daemon.get_height().await?;
        // Checked, fail-closed conversion — mirrors `block_at`'s discipline. The
        // 64-bit-only build gate already makes `usize <= u64` (so this never
        // errors), but the uniform checked form keeps the conversion honest.
        let raw = u64::try_from(height)
            .map_err(|_| BlockSourceError::Source(format!("chain height {height} exceeds u64")))?;
        Ok(BlockHeight::from_raw(raw))
    }

    async fn block_at(
        &self,
        height: BlockHeight,
    ) -> Result<Option<ScannableBlock>, BlockSourceError> {
        let number = usize::try_from(height.to_raw()).map_err(|_| {
            BlockSourceError::Source(format!(
                "height {} exceeds the platform's usize",
                height.to_raw()
            ))
        })?;
        // High-level fetch: whole block, all transactions, no selectivity.
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
            make_synthetic_block(0, [0u8; 32]),
            make_synthetic_block(1, [0u8; 32]),
            make_synthetic_block(2, [0u8; 32]),
        ]
    }

    #[tokio::test]
    async fn local_source_reports_tip_and_fetches_whole_block_by_height() {
        let daemon = TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, three_block_chain());
        let source = DaemonBlockSource::new(daemon);

        // tip_height reports the source's claimed height (chain length).
        assert_eq!(
            source.tip_height().await.expect("tip_height"),
            BlockHeight::from_raw(3)
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
}
