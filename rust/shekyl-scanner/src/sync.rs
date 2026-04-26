// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Background blockchain sync loop.
//!
//! Polls the daemon RPC for new blocks, feeds them through the scanner,
//! detects spent outputs via key-image matching, and updates the live
//! `(LedgerBlock, LedgerIndexes)` pair held behind a `tokio::sync::Mutex`.
//!
//! The loop is cancellation-safe: stopping the `CancellationToken` causes a
//! clean shutdown, after which the caller can persist `LedgerBlock` at the
//! last successfully processed height. (`LedgerIndexes` is rebuilt from
//! `LedgerBlock::transfers` + scanner replay on every wallet open and is
//! not persisted.)

#[cfg(feature = "rust-scanner")]
mod inner {
    use std::sync::Arc;

    use tokio::sync::Mutex;
    use tokio_util::sync::CancellationToken;
    use tracing::{debug, error, info, warn};

    use shekyl_oxide::transaction::Input;
    use shekyl_rpc::{Rpc, RpcError};
    use shekyl_wallet_state::{LedgerBlock, LedgerIndexes};

    use crate::{
        ledger_ext::LedgerIndexesExt,
        scan::{ScanError, Scanner},
    };

    /// Live wallet state under the sync loop's lock: the persisted ledger
    /// plus the runtime-only indexes maintained alongside it.
    pub type LiveLedger = (LedgerBlock, LedgerIndexes);

    /// Progress event emitted by the sync loop after each block.
    #[derive(Clone, Debug)]
    pub struct SyncProgress {
        /// Height just processed.
        pub height: u64,
        /// Current daemon tip height.
        pub daemon_height: u64,
        /// Number of new outputs found in the latest block.
        pub outputs_found: usize,
        /// Number of outputs detected as spent in the latest block.
        pub spends_detected: usize,
    }

    /// Errors specific to the sync loop.
    #[derive(Clone, Debug, thiserror::Error)]
    pub enum SyncError {
        #[error("rpc error: {0}")]
        Rpc(#[from] RpcError),
        #[error("scan error: {0}")]
        Scan(#[from] ScanError),
    }

    /// How often (in blocks) to call the flush callback on desktop.
    const DESKTOP_FLUSH_INTERVAL: u64 = 100;

    /// Maximum retries for transient per-block RPC failures.
    const MAX_BLOCK_FETCH_RETRIES: u32 = 5;
    /// Initial backoff for block fetch retries.
    const INITIAL_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

    /// Run the background sync loop.
    ///
    /// Fetches blocks from `ledger.height() + 1` up to the daemon tip, then
    /// polls every `poll_interval` for new blocks. Stops when `cancel` is
    /// triggered.
    ///
    /// Detects chain reorganizations by comparing each block's `previous` hash
    /// against the hash stored in `LedgerBlock` for the prior height. On
    /// reorg, [`LedgerIndexes::handle_reorg`] is called to roll back affected
    /// transfers before resuming.
    ///
    /// `on_progress` is called after every successfully processed block.
    /// `on_flush` is called every `DESKTOP_FLUSH_INTERVAL` blocks (or every
    /// block if `flush_every_block` is set — use this on mobile where the OS
    /// can kill the process without warning). Only the persisted half
    /// (`LedgerBlock`) is exposed to the flush callback; `LedgerIndexes` is
    /// always reconstructible from the persisted ledger and need not be
    /// snapshotted.
    pub async fn run_sync_loop<R, P, F>(
        rpc: R,
        scanner: Arc<Mutex<Scanner>>,
        state: Arc<Mutex<LiveLedger>>,
        cancel: CancellationToken,
        poll_interval: std::time::Duration,
        flush_every_block: bool,
        mut on_progress: P,
        mut on_flush: F,
    ) -> Result<(), SyncError>
    where
        R: Rpc + Send + 'static,
        P: FnMut(SyncProgress) + Send,
        F: FnMut(&LedgerBlock) + Send,
    {
        info!("sync loop started");

        loop {
            if cancel.is_cancelled() {
                info!("sync loop cancelled");
                break;
            }

            let daemon_height = match rpc.get_height().await {
                Ok(h) => h as u64,
                Err(e) => {
                    warn!(error = %e, "failed to get daemon height, retrying after poll interval");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(poll_interval) => continue,
                    }
                }
            };

            let wallet_height = state.lock().await.0.height();

            if wallet_height >= daemon_height {
                debug!(wallet_height, daemon_height, "wallet is synced, sleeping");
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(poll_interval) => continue,
                }
            }

            let start_height = wallet_height + 1;

            for h in start_height..=daemon_height {
                if cancel.is_cancelled() {
                    info!(height = h, "sync loop cancelled mid-batch");
                    break;
                }

                let scannable = fetch_block_with_retry(&rpc, h, &cancel).await?;

                // --- Reorg detection ---
                // Compare the block's `previous` hash with what we stored for (h-1).
                if h > 1 {
                    let parent_hash = scannable.block.header.previous;
                    let state_guard = state.lock().await;
                    let expected = state_guard.0.block_hash_at(h - 1).copied();
                    drop(state_guard);

                    if let Some(stored_hash) = expected {
                        if stored_hash != parent_hash {
                            warn!(
                                height = h,
                                expected = hex::encode(stored_hash),
                                actual_parent = hex::encode(parent_hash),
                                "chain reorg detected, rolling back"
                            );

                            let fork_height = find_fork_point(&rpc, &state, h - 1, &cancel).await?;

                            let mut state_guard = state.lock().await;
                            let (ledger, indexes) = &mut *state_guard;
                            indexes.handle_reorg(ledger, fork_height);
                            on_flush(ledger);
                            drop(state_guard);

                            info!(
                                fork_height,
                                "reorg handled, restarting scan from fork point"
                            );
                            break;
                        }
                    }
                }

                let block_hash = scannable.block.hash();

                let outputs = {
                    let mut scanner_guard = scanner.lock().await;
                    match scanner_guard.scan(scannable.clone()) {
                        Ok(t) => t,
                        Err(e) => {
                            error!(height = h, error = %e, "scan failed, aborting batch");
                            return Err(SyncError::Scan(e));
                        }
                    }
                };

                let mut block_key_images: Vec<[u8; 32]> = Vec::new();

                let miner_tx = scannable.block.miner_transaction();
                for input in &miner_tx.prefix().inputs {
                    if let Input::ToKey { key_image, .. } | Input::StakeClaim { key_image, .. } =
                        input
                    {
                        block_key_images.push(key_image.0);
                    }
                }

                for tx in &scannable.transactions {
                    for input in &tx.prefix().inputs {
                        if let Input::ToKey { key_image, .. }
                        | Input::StakeClaim { key_image, .. } = input
                        {
                            block_key_images.push(key_image.0);
                        }
                    }
                }

                let mut state_guard = state.lock().await;
                let (ledger, indexes) = &mut *state_guard;

                let outputs_found = indexes.process_scanned_outputs(ledger, h, block_hash, outputs);
                let spends_detected = indexes.detect_spends(ledger, h, &block_key_images);

                let progress = SyncProgress {
                    height: h,
                    daemon_height,
                    outputs_found,
                    spends_detected,
                };

                if outputs_found > 0 || spends_detected > 0 {
                    info!(
                        height = h,
                        outputs_found, spends_detected, "block processed with wallet activity"
                    );
                }

                let should_flush =
                    flush_every_block || (h % DESKTOP_FLUSH_INTERVAL == 0) || h == daemon_height;

                if should_flush {
                    on_flush(ledger);
                }

                drop(state_guard);
                on_progress(progress);
            }
        }

        let guard = state.lock().await;
        on_flush(&guard.0);
        info!(
            final_height = guard.0.height(),
            "sync loop stopped, final flush done"
        );

        Ok(())
    }

    /// Fetch a block with exponential backoff on transient failures.
    async fn fetch_block_with_retry<R: Rpc>(
        rpc: &R,
        height: u64,
        cancel: &CancellationToken,
    ) -> Result<shekyl_rpc::ScannableBlock, SyncError> {
        let mut delay = INITIAL_RETRY_DELAY;
        for attempt in 0..MAX_BLOCK_FETCH_RETRIES {
            match rpc.get_scannable_block_by_number(height as usize).await {
                Ok(b) => return Ok(b),
                Err(e) if attempt + 1 < MAX_BLOCK_FETCH_RETRIES => {
                    warn!(
                        height,
                        attempt = attempt + 1,
                        max = MAX_BLOCK_FETCH_RETRIES,
                        error = %e,
                        "block fetch failed, retrying after backoff"
                    );
                    tokio::select! {
                        _ = cancel.cancelled() => return Err(SyncError::Rpc(e)),
                        _ = tokio::time::sleep(delay) => {}
                    }
                    delay = std::cmp::min(delay * 2, std::time::Duration::from_secs(30));
                }
                Err(e) => {
                    error!(
                        height,
                        error = %e,
                        "block fetch failed after {} attempts, aborting",
                        MAX_BLOCK_FETCH_RETRIES,
                    );
                    return Err(SyncError::Rpc(e));
                }
            }
        }
        unreachable!()
    }

    /// Walk backwards from `from_height` to find the fork point where the
    /// wallet's stored block hash matches the daemon's chain.
    async fn find_fork_point<R: Rpc>(
        rpc: &R,
        state: &Arc<Mutex<LiveLedger>>,
        from_height: u64,
        cancel: &CancellationToken,
    ) -> Result<u64, SyncError> {
        let mut h = from_height;
        loop {
            if h == 0 {
                return Ok(1);
            }
            if cancel.is_cancelled() {
                return Ok(h + 1);
            }

            let state_guard = state.lock().await;
            let stored = state_guard.0.block_hash_at(h).copied();
            drop(state_guard);

            let Some(stored_hash) = stored else {
                return Ok(h + 1);
            };

            let daemon_block = fetch_block_with_retry(rpc, h, cancel).await?;
            let daemon_hash = daemon_block.block.hash();

            if daemon_hash == stored_hash {
                return Ok(h + 1);
            }

            debug!(height = h, "fork point search: mismatch, going back");
            h -= 1;
        }
    }
}

#[cfg(feature = "rust-scanner")]
pub use inner::*;
