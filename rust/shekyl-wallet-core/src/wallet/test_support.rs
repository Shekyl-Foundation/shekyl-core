// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Test scaffolding for the wallet refresh / scan-loop pipeline.
//!
//! Lives under `#[cfg(test)]` and is `pub(crate)` only — never
//! re-exported. Exists so the producer (`produce_scan_result`,
//! lands next commit), `Wallet::refresh` (commit 4), and the
//! `RefreshHandle` integration tests (Branch 2) all build their
//! synthetic chains and inject failures through one audited site
//! rather than each rolling its own.
//!
//! What this module ships:
//!
//! - [`MockRpc`]: deterministic in-memory `shekyl_rpc::Rpc`
//!   implementor. Models a daemon serving a single canonical
//!   linear chain with reorg simulation via
//!   [`MockRpc::replace_chain_from`]. Failure-injection APIs
//!   cover every transient and persistent error path the producer
//!   must distinguish.
//! - [`make_synthetic_block`]: minimal-valid `ScannableBlock`
//!   constructor (V2 miner transaction with `Input::Gen`, no
//!   regular outputs, no non-miner transactions). Tests that need
//!   a recoverable owned output build their own
//!   `ScannableBlock` rather than extending this helper, because
//!   real recovery requires real keys and a `ViewPair`-aligned
//!   shared secret — the helper would either lie about that or
//!   replicate the scanner's own test fixtures.
//!
//! What this module does *not* ship:
//!
//! - End-to-end "wallet recovers a transfer" fixtures. Those land
//!   alongside the `produce_scan_result` test suite in commit 3,
//!   built either on the existing `shekyl-scanner` `test-utils`
//!   path (which constructs `RecoveredWalletOutput`s directly,
//!   bypassing `Scanner::scan`) or on a small `ViewPair`-backed
//!   block builder. The choice is the producer's test suite to
//!   make; the MockRpc only needs to deliver whatever `ScannableBlock`
//!   the test author hands it.
//! - Branched chains as first-class state. The reorg simulation
//!   model is "the daemon's canonical chain shifts": the wallet
//!   refresh test snapshots, the test calls `replace_chain_from`
//!   while the snapshot is still active, then the merge runs.
//!   Modelling parallel branches as named state would let tests
//!   express "fork to branch X, sync, fork back," which no
//!   producer test in commit 3 needs. Adding that is reversible
//!   if a future test requires it; YAGNI for now.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use shekyl_oxide::block::{Block, BlockHeader};
use shekyl_oxide::transaction::{Input, Timelock, Transaction, TransactionPrefix};
use shekyl_rpc::{Rpc, RpcError, ScannableBlock};

/// In-memory `Rpc` implementor for refresh / scan-loop tests.
///
/// Cheaply cloneable (`Arc<Mutex<…>>` internally) so producer
/// futures can hold an owned copy while the test driver continues
/// to mutate the canonical chain or queue failures. Cloning shares
/// state with the original handle by design: a reorg injected on
/// one clone is observed by all clones.
///
/// Locking is `std::sync::Mutex` rather than `tokio::sync::Mutex`
/// because every guarded critical section is non-`await` (the
/// state transitions in `get_height` and
/// `get_scannable_block_by_number` are pure data lookups that
/// drop the guard before returning the future's result). Holding
/// a `std::sync::Mutex` across an `await` point would be a defect;
/// the implementation below does not.
#[derive(Clone)]
pub(crate) struct MockRpc {
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    /// Canonical chain. Index `i` is the block at height `i + 1`
    /// (height 0 is unused; the daemon protocol's first block is
    /// height 1).
    chain: Vec<ScannableBlock>,
    /// When `Some`, caps the height returned by `get_height` at
    /// `min(chain.len(), cap)`. Models a daemon whose reported
    /// height contracts mid-loop (e.g. the daemon was asked about
    /// a chain it has since pruned or rolled back).
    daemon_height_cap: Option<u64>,
    /// Errors queued for upcoming `get_height` calls (FIFO). Once
    /// drained, subsequent calls return the canonical height.
    height_errors: VecDeque<RpcError>,
    /// Per-height error queues for `get_scannable_block_by_number`.
    /// FIFO; once a height's queue is drained, subsequent fetches
    /// at that height return the canonical block.
    block_errors: HashMap<u64, VecDeque<RpcError>>,
    /// Heights for which every fetch returns a malformed-block
    /// error. Models persistent-failure scenarios distinct from
    /// transient retry-and-recover ones.
    malformed_at: HashSet<u64>,
}

impl MockRpc {
    /// Empty chain, daemon height 0. Tests typically use this with
    /// `push_block` or `replace_chain_from` to construct the chain
    /// incrementally.
    pub(crate) fn empty() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// Pre-fill the canonical chain. Equivalent to `empty` followed
    /// by repeated `push_block` calls.
    pub(crate) fn with_chain(chain: Vec<ScannableBlock>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                chain,
                ..State::default()
            })),
        }
    }

    /// Append a block to the canonical chain. The block at index
    /// `chain.len()` is served from height `chain.len() + 1`.
    pub(crate) fn push_block(&self, block: ScannableBlock) {
        self.state
            .lock()
            .expect("MockRpc state poisoned")
            .chain
            .push(block);
    }

    /// Replace the canonical chain at and above `fork_height` with
    /// `new_blocks` (1-indexed; `fork_height = 1` discards the entire
    /// chain). Models a daemon reorg from the test driver's view.
    ///
    /// Subsequent `get_scannable_block_by_number(h)` for
    /// `h >= fork_height` returns the corresponding entry of
    /// `new_blocks`; `h < fork_height` is unaffected. The reported
    /// daemon height (via `get_height`) becomes
    /// `(fork_height - 1) + new_blocks.len()`, modulo
    /// `daemon_height_cap`.
    ///
    /// # Panics
    ///
    /// Panics if `fork_height == 0` (heights are 1-indexed) or if
    /// `fork_height > chain.len() + 1` (the truncation point lies
    /// past the chain end).
    pub(crate) fn replace_chain_from(&self, fork_height: u64, new_blocks: Vec<ScannableBlock>) {
        assert!(
            fork_height >= 1,
            "MockRpc::replace_chain_from: fork_height must be 1-indexed (>= 1)"
        );
        let mut state = self.state.lock().expect("MockRpc state poisoned");
        let keep = usize::try_from(fork_height - 1)
            .expect("MockRpc::replace_chain_from: fork_height fits in usize");
        assert!(
            keep <= state.chain.len(),
            "MockRpc::replace_chain_from: fork_height {fork_height} exceeds chain length {}",
            state.chain.len() + 1
        );
        state.chain.truncate(keep);
        state.chain.extend(new_blocks);
    }

    /// Cap the height that `get_height` reports at `cap`. Useful
    /// for testing the daemon-height-shrinks-mid-loop path: build
    /// a chain of length N, then mid-test set the cap below N to
    /// simulate the daemon reporting a smaller height.
    pub(crate) fn set_daemon_height(&self, cap: u64) {
        self.state
            .lock()
            .expect("MockRpc state poisoned")
            .daemon_height_cap = Some(cap);
    }

    /// Queue `n` errors to be returned by the next `n`
    /// `get_height` calls (oldest first). After the queue drains,
    /// `get_height` returns the canonical height. Models
    /// transient daemon flakiness.
    pub(crate) fn set_height_error_for_next_n_calls(&self, n: u32, kind: &RpcError) {
        let mut state = self.state.lock().expect("MockRpc state poisoned");
        for _ in 0..n {
            state.height_errors.push_back(kind.clone());
        }
    }

    /// Inject a one-shot error for the next
    /// `get_scannable_block_by_number(height)` call. Multiple
    /// invocations queue multiple errors at the same height (FIFO).
    /// Once the height's queue drains, subsequent fetches at that
    /// height return the canonical block.
    pub(crate) fn inject_block_fetch_failure(&self, height: u64, kind: RpcError) {
        self.state
            .lock()
            .expect("MockRpc state poisoned")
            .block_errors
            .entry(height)
            .or_default()
            .push_back(kind);
    }

    /// Mark a height such that *every* fetch returns
    /// `RpcError::InvalidNode`. Models a persistently bad block
    /// from the daemon — the producer must surface this as a
    /// terminal error, not retry indefinitely.
    pub(crate) fn set_block_returns_malformed(&self, height: u64) {
        self.state
            .lock()
            .expect("MockRpc state poisoned")
            .malformed_at
            .insert(height);
    }

    /// Number of blocks in the canonical chain. Each block at
    /// index `i` lives at height `i + 1`.
    pub(crate) fn chain_len(&self) -> u64 {
        self.state
            .lock()
            .expect("MockRpc state poisoned")
            .chain
            .len() as u64
    }
}

impl Rpc for MockRpc {
    fn post(
        &self,
        _route: &str,
        _body: Vec<u8>,
    ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
        async move {
            panic!(
                "MockRpc::post is unreachable: tests override the high-level Rpc methods directly. \
                 If you reached here, you called a default-impl Rpc method that MockRpc does not yet override; \
                 add the override rather than implementing post()."
            )
        }
    }

    fn get_height(&self) -> impl Send + std::future::Future<Output = Result<usize, RpcError>> {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().expect("MockRpc state poisoned");
            if let Some(err) = state.height_errors.pop_front() {
                return Err(err);
            }
            let chain_len = state.chain.len() as u64;
            let height = state
                .daemon_height_cap
                .map(|cap| cap.min(chain_len))
                .unwrap_or(chain_len);
            usize::try_from(height)
                .map_err(|_| RpcError::InvalidNode("MockRpc height exceeded usize".to_string()))
        }
    }

    fn get_scannable_block_by_number(
        &self,
        number: usize,
    ) -> impl Send + std::future::Future<Output = Result<ScannableBlock, RpcError>> {
        let state = self.state.clone();
        async move {
            let height = number as u64;
            let mut state = state.lock().expect("MockRpc state poisoned");

            if state.malformed_at.contains(&height) {
                return Err(RpcError::InvalidNode(format!(
                    "MockRpc: malformed block at height {height}"
                )));
            }

            if let Some(queue) = state.block_errors.get_mut(&height) {
                if let Some(err) = queue.pop_front() {
                    return Err(err);
                }
            }

            if height == 0 {
                return Err(RpcError::InvalidNode(
                    "MockRpc: requested height 0 is invalid".to_string(),
                ));
            }
            let idx = usize::try_from(height - 1).map_err(|_| {
                RpcError::InvalidNode("MockRpc: height did not fit in usize".to_string())
            })?;

            state.chain.get(idx).cloned().ok_or_else(|| {
                RpcError::InvalidNode(format!("MockRpc: no block at height {height}"))
            })
        }
    }
}

/// Build a minimal-valid `ScannableBlock` for `height` with the
/// chosen `parent_hash`. The produced block has:
///
/// - V2 miner transaction with `Input::Gen(height)` (passes
///   [`Block::new`]'s coinbase check).
/// - No outputs in the miner transaction.
/// - No non-miner transactions.
///
/// `Scanner::scan` against this block returns zero recovered
/// outputs and `Block::hash` is well-defined. Tests that exercise
/// the producer's structural behaviour (linear scan, reorg
/// detection by parent-hash compare, retries) build their chains
/// from this helper. Tests that need owned-output recovery construct
/// their own `ScannableBlock` (see module docs).
pub(crate) fn make_synthetic_block(height: u64, parent_hash: [u8; 32]) -> ScannableBlock {
    let header = BlockHeader {
        hardfork_version: 1,
        hardfork_signal: 0,
        timestamp: height,
        previous: parent_hash,
        nonce: 0,
    };

    let miner_prefix = TransactionPrefix {
        additional_timelock: Timelock::None,
        inputs: vec![Input::Gen(
            usize::try_from(height).expect("synthetic block height fits in usize"),
        )],
        outputs: vec![],
        extra: vec![],
    };

    let miner_tx = Transaction::V2 {
        prefix: miner_prefix,
        proofs: None,
    };

    let block = Block::new(header, miner_tx, vec![]).expect(
        "Block::new accepts a V2 miner-tx-only block by construction; \
         the only failure mode is a non-Gen first input or wrong input count, \
         neither of which applies here",
    );

    ScannableBlock {
        block,
        transactions: vec![],
        output_index_for_first_ringct_output: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linear_chain(n: u64) -> Vec<ScannableBlock> {
        let mut chain =
            Vec::with_capacity(usize::try_from(n).expect("test linear_chain length fits in usize"));
        let mut parent = [0u8; 32];
        for h in 1..=n {
            let block = make_synthetic_block(h, parent);
            parent = block.block.hash();
            chain.push(block);
        }
        chain
    }

    #[tokio::test]
    async fn empty_chain_reports_zero_height() {
        let rpc = MockRpc::empty();
        assert_eq!(rpc.get_height().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn linear_chain_reports_canonical_height() {
        let rpc = MockRpc::with_chain(linear_chain(5));
        assert_eq!(rpc.get_height().await.unwrap(), 5);
    }

    #[tokio::test]
    async fn block_fetch_returns_correct_height() {
        let chain = linear_chain(3);
        let expected_h2 = chain[1].block.hash();
        let rpc = MockRpc::with_chain(chain);

        let block = rpc.get_scannable_block_by_number(2).await.unwrap();
        assert_eq!(block.block.hash(), expected_h2);
    }

    #[tokio::test]
    async fn parent_hash_chains_correctly() {
        let rpc = MockRpc::with_chain(linear_chain(3));
        let h2 = rpc.get_scannable_block_by_number(2).await.unwrap();
        let h3 = rpc.get_scannable_block_by_number(3).await.unwrap();
        assert_eq!(h3.block.header.previous, h2.block.hash());
    }

    #[tokio::test]
    async fn replace_chain_from_truncates_and_extends() {
        let rpc = MockRpc::with_chain(linear_chain(5));
        let parent_h2 = rpc
            .get_scannable_block_by_number(2)
            .await
            .unwrap()
            .block
            .hash();

        let mut alt = Vec::new();
        let mut p = parent_h2;
        for h in 3..=4 {
            let mut blk = make_synthetic_block(h, p);
            // Disambiguate from the original chain by perturbing the timestamp.
            blk.block.header.timestamp = 9_000 + h;
            p = blk.block.hash();
            alt.push(blk);
        }
        rpc.replace_chain_from(3, alt);

        assert_eq!(rpc.chain_len(), 4, "fork_height=3 + 2 new blocks => len 4");
        let h3 = rpc.get_scannable_block_by_number(3).await.unwrap();
        assert_eq!(h3.block.header.previous, parent_h2);
        assert_eq!(h3.block.header.timestamp, 9_003);
    }

    #[tokio::test]
    async fn daemon_height_cap_below_chain_len() {
        let rpc = MockRpc::with_chain(linear_chain(10));
        rpc.set_daemon_height(4);
        assert_eq!(rpc.get_height().await.unwrap(), 4);
    }

    #[tokio::test]
    async fn height_errors_drain_in_fifo_then_recover() {
        let rpc = MockRpc::with_chain(linear_chain(2));
        rpc.set_height_error_for_next_n_calls(2, &RpcError::ConnectionError("transient".into()));

        assert!(rpc.get_height().await.is_err());
        assert!(rpc.get_height().await.is_err());
        assert_eq!(rpc.get_height().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn block_fetch_failure_is_one_shot() {
        let rpc = MockRpc::with_chain(linear_chain(3));
        rpc.inject_block_fetch_failure(2, RpcError::ConnectionError("flaky".into()));

        assert!(rpc.get_scannable_block_by_number(2).await.is_err());
        assert!(rpc.get_scannable_block_by_number(2).await.is_ok());
    }

    #[tokio::test]
    async fn malformed_block_errors_persistently() {
        let rpc = MockRpc::with_chain(linear_chain(3));
        rpc.set_block_returns_malformed(2);

        for _ in 0..3 {
            let err = rpc.get_scannable_block_by_number(2).await.unwrap_err();
            assert!(matches!(err, RpcError::InvalidNode(_)));
        }
        assert!(rpc.get_scannable_block_by_number(1).await.is_ok());
        assert!(rpc.get_scannable_block_by_number(3).await.is_ok());
    }

    #[tokio::test]
    async fn clones_share_state() {
        let rpc = MockRpc::empty();
        let clone = rpc.clone();
        rpc.push_block(make_synthetic_block(1, [0u8; 32]));
        assert_eq!(clone.get_height().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn fetching_height_zero_is_an_error() {
        let rpc = MockRpc::with_chain(linear_chain(1));
        let err = rpc.get_scannable_block_by_number(0).await.unwrap_err();
        assert!(matches!(err, RpcError::InvalidNode(_)));
    }

    #[tokio::test]
    async fn fetching_past_chain_end_is_an_error() {
        let rpc = MockRpc::with_chain(linear_chain(2));
        let err = rpc.get_scannable_block_by_number(3).await.unwrap_err();
        assert!(matches!(err, RpcError::InvalidNode(_)));
    }
}
