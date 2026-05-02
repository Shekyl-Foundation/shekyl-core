// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Test scaffolding for the wallet refresh / scan-loop pipeline.
//!
//! Lives under `#[cfg(test)]` and is `pub(crate)` only — never
//! re-exported. Exists so the producer (`produce_scan_result`),
//! `Engine::refresh`, the `RefreshHandle` integration tests, and
//! the Stage 1 hybrid tests (`Engine<SoloSigner, MockDaemon>`) all
//! build their synthetic chains and inject failures through one
//! audited site rather than each rolling its own.
//!
//! What this module ships:
//!
//! - [`MockDaemon`]: deterministic in-memory implementor of both
//!   [`shekyl_rpc::Rpc`] (chain serving — height / block fetch
//!   with reorg simulation, failure injection per height) **and**
//!   the crate-internal `DaemonEngine` Stage 1 trait (transaction
//!   submission with daemon-faithful tx-hash dedup per the §5.2
//!   retry contract; configurable fee estimates per §2.5). One
//!   value drives both the producer-only refresh tests
//!   (consumed as `&MockDaemon: Rpc` by `produce_scan_result`)
//!   and the hybrid `Engine<SoloSigner, MockDaemon>` tests
//!   (consumed as the engine's `D: DaemonEngine` slot).
//! - [`make_synthetic_block`]: minimal-valid `ScannableBlock`
//!   constructor (V2 miner transaction with `Input::Gen`, no
//!   regular outputs, no non-miner transactions). Tests that need
//!   a recoverable owned output build their own
//!   `ScannableBlock` rather than extending this helper, because
//!   real recovery requires real keys and a `ViewPair`-aligned
//!   shared secret — the helper would either lie about that or
//!   replicate the scanner's own test fixtures.
//!
//! # Determinism contract
//!
//! Per `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §6.2, every `Mock*`
//! constructor takes an explicit 32-byte seed which initializes
//! a `ChaCha20Rng` internal to the mock. Tests that don't
//! exercise RNG-driven mock behavior (e.g. producer-only chain
//! serving) pass [`DEFAULT_TEST_SEED`]; tests that do (future
//! fee-jitter, synthetic-fork randomization) pass a recorded
//! literal seed and embed it in the test name so reproduction
//! across CI runs is unambiguous.
//!
//! What this module does *not* ship:
//!
//! - End-to-end "wallet recovers a transfer" fixtures. Those live
//!   alongside the `produce_scan_result` test suite, built either
//!   on the existing `shekyl-scanner` `test-utils` path (which
//!   constructs `RecoveredWalletOutput`s directly, bypassing
//!   `Scanner::scan`) or on a small `ViewPair`-backed block
//!   builder. The choice is the producer's test suite to make; the
//!   `MockDaemon` only needs to deliver whatever `ScannableBlock`
//!   the test author hands it.
//! - Branched chains as first-class state. The reorg simulation
//!   model is "the daemon's canonical chain shifts": the wallet
//!   refresh test snapshots, the test calls `replace_chain_from`
//!   while the snapshot is still active, then the merge runs.
//!   Modelling parallel branches as named state would let tests
//!   express "fork to branch X, sync, fork back," which no
//!   producer or refresh test currently needs. Adding that is
//!   reversible if a future test requires it; YAGNI for now.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use hkdf::Hkdf;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use shekyl_oxide::block::{Block, BlockHeader};
use shekyl_oxide::transaction::{Input, Timelock, Transaction, TransactionPrefix};
use shekyl_rpc::{FeeRate, Rpc, RpcError, ScannableBlock};

use crate::engine::pending::TxHash;
use crate::engine::traits::{DaemonEngine, FeeEstimates, TxSubmitOutcome};

/// Default 32-byte seed for tests that don't exercise the
/// `ChaCha20Rng`-driven paths of [`MockDaemon`].
///
/// Producer-only refresh tests (which use `MockDaemon` purely as
/// an `Rpc` chain server) pass this constant rather than a bespoke
/// literal so the §6.2 "every constructor takes a seed" contract
/// is honored without ceremony at every call site. Tests that do
/// exercise RNG-driven behavior pass a recorded literal seed
/// instead and embed the seed in their test name (e.g.
/// `_seed_0xdeadbeef`) for cross-run reproducibility.
pub(crate) const DEFAULT_TEST_SEED: [u8; 32] = [0u8; 32];

// ---- Role-tag registry for §6.2 master-seed derivation -------------------
//
// Each `Mock*` slot in a hybrid composition gets a stable byte string
// that names its role. Hybrid tests pass `(master_seed, ROLE_X)` to
// [`derive_seed`] to produce the per-component seed that goes into
// `MockX::with_seed(...)`. The registry pins the role-tag-to-component
// mapping in one audited site so reviewers can confirm hybrid tests
// don't re-bind a tag to a different component slot.
//
// PR 1 lands `ROLE_DAEMON` only (the only mock implementor that exists
// at this stage). Subsequent Stage 1 PRs add `ROLE_KEY`, `ROLE_LEDGER`,
// `ROLE_ECONOMICS`, `ROLE_PERSISTENCE`, `ROLE_REFRESH`, `ROLE_PENDING_TX`
// alongside their corresponding `Mock*` types.

/// Role tag for the [`MockDaemon`] slot in §6.2 master-seed derivation.
pub(crate) const ROLE_DAEMON: &[u8] = b"role/daemon";

/// Derive a per-component 32-byte seed from a master seed and a role
/// tag via HKDF-SHA256, per `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §6.2's
/// master-seed-derivation contract.
///
/// Hybrid tests own a single literal `master_seed` (recorded in the
/// test name or CI logs); each `Mock*` they construct gets its
/// `with_seed` argument from `derive_seed(&master, ROLE_X)`. This
/// keeps cross-run reproducibility a function of the master seed
/// alone — changing the master re-derives every component
/// consistently; per-component edits are unnecessary.
///
/// Construction: HKDF-SHA256 with `salt = None` (defaults to a
/// hash-block-length zero salt per RFC 5869), `ikm = master_seed`,
/// `info = role`, `OKM = 32 bytes`. The 32-byte output is well
/// within HKDF-SHA256's `255 * HashLen = 8160` byte OKM limit, so
/// the expand step is infallible.
pub(crate) fn derive_seed(master: &[u8; 32], role: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, master);
    let mut output = [0u8; 32];
    hkdf.expand(role, &mut output)
        .expect("32-byte OKM is well within HKDF-SHA256's 255 * HashLen limit");
    output
}

/// In-memory implementor of [`shekyl_rpc::Rpc`] **and** the
/// crate-internal `DaemonEngine` trait for refresh / scan-loop /
/// hybrid tests.
///
/// Cheaply cloneable (`Arc<Mutex<…>>` internally) so producer
/// futures can hold an owned copy while the test driver continues
/// to mutate the canonical chain or queue failures. Cloning shares
/// state with the original handle by design: a reorg injected on
/// one clone is observed by all clones, and a transaction
/// submitted via one clone is observed as `AlreadyKnown` by every
/// other.
///
/// Locking is `std::sync::Mutex` rather than `tokio::sync::Mutex`
/// because every guarded critical section is non-`await` (the
/// state transitions in `get_height`,
/// `get_scannable_block_by_number`, `submit_transaction`, and
/// `get_fee_estimates` are pure data lookups that drop the guard
/// before returning the future's result). Holding a
/// `std::sync::Mutex` across an `await` point would be a defect;
/// the implementation below does not.
///
/// # Contract fidelity (§6.1, Round 4b — Item 3)
///
/// `MockDaemon` honors the *contract* of `DaemonEngine`, not just
/// the syntactic surface:
///
/// - `submit_transaction` dedupes by tx hash exactly as the real
///   daemon does (first submission → `Submitted { hash }`; every
///   subsequent submission of the same `tx_bytes` →
///   `AlreadyKnown { hash }`). The hash is derived
///   deterministically via `shekyl_crypto_hash::cn_fast_hash` over
///   the submitted bytes — the real daemon hashes the tx prefix
///   plus signatures, but for `MockDaemon` the byte-keyed dedup
///   provides the §5.2 retry-safety semantics tests need without
///   parsing transaction structure (Phase 2a refines this once
///   the production stub parses `tx_bytes`).
/// - Failure injection (`inject_submit_failure`,
///   `inject_fee_failure`) preserves `RpcError` typed shape so
///   hybrid tests exercise real `Engine`-orchestration retry
///   logic against realistic error variants.
#[derive(Clone)]
pub(crate) struct MockDaemon {
    state: Arc<Mutex<State>>,
}

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

    /// Tx-hash set keyed by the byte-derived hash. `submit_transaction`
    /// inserts on first sight (returning `Submitted`) and observes
    /// the existing entry on retry (returning `AlreadyKnown`). The
    /// real daemon's mempool serves the same role; modelling it as
    /// a `HashSet` preserves the §5.2 idempotency guarantee tests
    /// rely on without modeling mempool eviction.
    submitted_hashes: HashSet<TxHash>,
    /// Errors queued for upcoming `submit_transaction` calls (FIFO).
    /// Drained before the dedup check, so a queued error preempts
    /// the dedup outcome — letting tests assert that the engine's
    /// retry contract handles a daemon that errors *before* having
    /// observed the tx.
    submit_errors: VecDeque<RpcError>,

    /// Snapshot returned by `get_fee_estimates` when no error is
    /// queued. Defaults to a monotonically-increasing
    /// economy / standard / priority triple so tests can observe
    /// distinct values per priority without configuring fees
    /// explicitly. Override via `set_fee_estimates`.
    fee_estimates: FeeEstimates,
    /// Errors queued for upcoming `get_fee_estimates` calls (FIFO).
    /// Models a daemon that transiently refuses to serve fee
    /// estimates (e.g. mid-startup, during fee-pool rotation).
    fee_errors: VecDeque<RpcError>,

    /// Deterministic RNG seeded from the constructor seed. Held
    /// for §6.2 compliance and reserved for future RNG-driven
    /// affordances (fee jitter, synthetic-fork randomization);
    /// the current Stage 1 PR 1 contract surface does not consume
    /// it. Wrapped in `Mutex` via `state` so the borrow rule is
    /// the same as every other field.
    #[allow(dead_code)]
    rng: ChaCha20Rng,
}

impl State {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            chain: Vec::new(),
            daemon_height_cap: None,
            height_errors: VecDeque::new(),
            block_errors: HashMap::new(),
            malformed_at: HashSet::new(),
            submitted_hashes: HashSet::new(),
            submit_errors: VecDeque::new(),
            fee_estimates: default_fee_estimates(),
            fee_errors: VecDeque::new(),
            rng: ChaCha20Rng::from_seed(seed),
        }
    }
}

/// Construct the default [`FeeEstimates`] that fresh `MockDaemon`s
/// return from `get_fee_estimates`. The three priorities scale
/// monotonically (economy < standard < priority) so tests that
/// observe per-priority resolution see distinct values without
/// configuring fees explicitly. Mask is `1` everywhere — the
/// rounding mask carries no signal in tests that don't exercise
/// fee-rounding code paths.
fn default_fee_estimates() -> FeeEstimates {
    FeeEstimates {
        economy: FeeRate::new(1, 1).expect("economy fee rate is non-zero"),
        standard: FeeRate::new(10, 1).expect("standard fee rate is non-zero"),
        priority: FeeRate::new(100, 1).expect("priority fee rate is non-zero"),
    }
}

impl MockDaemon {
    /// Construct a `MockDaemon` with an empty chain and the given
    /// 32-byte seed. The seed initializes the internal
    /// `ChaCha20Rng` per `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §6.2.
    /// Tests that don't care about RNG-driven affordances pass
    /// [`DEFAULT_TEST_SEED`].
    pub(crate) fn with_seed(seed: [u8; 32]) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::new(seed))),
        }
    }

    /// Construct a `MockDaemon` with a pre-filled canonical chain
    /// and the given seed. Equivalent to [`Self::with_seed`]
    /// followed by repeated `push_block` calls; provided as a
    /// constructor so common cases stay one-line.
    pub(crate) fn with_seed_and_chain(seed: [u8; 32], chain: Vec<ScannableBlock>) -> Self {
        let mut state = State::new(seed);
        state.chain = chain;
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Append a block to the canonical chain. The block at index
    /// `chain.len()` is served from height `chain.len() + 1`.
    pub(crate) fn push_block(&self, block: ScannableBlock) {
        self.state
            .lock()
            .expect("MockDaemon state poisoned")
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
            "MockDaemon::replace_chain_from: fork_height must be 1-indexed (>= 1)"
        );
        let mut state = self.state.lock().expect("MockDaemon state poisoned");
        let keep = usize::try_from(fork_height - 1)
            .expect("MockDaemon::replace_chain_from: fork_height fits in usize");
        assert!(
            keep <= state.chain.len(),
            "MockDaemon::replace_chain_from: fork_height {fork_height} exceeds chain length {}",
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
            .expect("MockDaemon state poisoned")
            .daemon_height_cap = Some(cap);
    }

    /// Queue `n` errors to be returned by the next `n`
    /// `get_height` calls (oldest first). After the queue drains,
    /// `get_height` returns the canonical height. Models
    /// transient daemon flakiness.
    pub(crate) fn set_height_error_for_next_n_calls(&self, n: u32, kind: &RpcError) {
        let mut state = self.state.lock().expect("MockDaemon state poisoned");
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
            .expect("MockDaemon state poisoned")
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
            .expect("MockDaemon state poisoned")
            .malformed_at
            .insert(height);
    }

    /// Number of blocks in the canonical chain. Each block at
    /// index `i` lives at height `i + 1`.
    pub(crate) fn chain_len(&self) -> u64 {
        self.state
            .lock()
            .expect("MockDaemon state poisoned")
            .chain
            .len() as u64
    }

    /// Override the [`FeeEstimates`] returned by future
    /// `get_fee_estimates` calls. Persists across subsequent
    /// queries until called again.
    pub(crate) fn set_fee_estimates(&self, fees: FeeEstimates) {
        self.state
            .lock()
            .expect("MockDaemon state poisoned")
            .fee_estimates = fees;
    }

    /// Queue a one-shot error for the next `submit_transaction`
    /// call. The error is returned *before* the dedup check, so
    /// tests can model "daemon errored mid-submit; engine retries;
    /// daemon now succeeds" without first having to admit the tx
    /// to the dedup set. Multiple invocations queue multiple
    /// errors (FIFO).
    pub(crate) fn inject_submit_failure(&self, err: RpcError) {
        self.state
            .lock()
            .expect("MockDaemon state poisoned")
            .submit_errors
            .push_back(err);
    }

    /// Queue a one-shot error for the next `get_fee_estimates`
    /// call. Multiple invocations queue multiple errors (FIFO).
    /// Once the queue drains, subsequent calls return the
    /// configured [`FeeEstimates`].
    pub(crate) fn inject_fee_failure(&self, err: RpcError) {
        self.state
            .lock()
            .expect("MockDaemon state poisoned")
            .fee_errors
            .push_back(err);
    }

    /// Number of distinct transactions that have entered the
    /// `submit_transaction` dedup set. Each call to
    /// `submit_transaction(bytes)` with previously-unseen `bytes`
    /// increments this; retries of the same `bytes` do not. Tests
    /// assert against this to confirm `Engine::submit_pending_tx`'s
    /// retry path re-submits the same bytes (dedup absorbs it)
    /// rather than constructing a different transaction (which
    /// would double-spend).
    pub(crate) fn submitted_count(&self) -> usize {
        self.state
            .lock()
            .expect("MockDaemon state poisoned")
            .submitted_hashes
            .len()
    }
}

impl Rpc for MockDaemon {
    fn post(
        &self,
        _route: &str,
        _body: Vec<u8>,
    ) -> impl Send + std::future::Future<Output = Result<Vec<u8>, RpcError>> {
        async move {
            panic!(
                "MockDaemon::post is unreachable: tests override the high-level Rpc methods directly. \
                 If you reached here, you called a default-impl Rpc method that MockDaemon does not yet override; \
                 add the override rather than implementing post()."
            )
        }
    }

    fn get_height(&self) -> impl Send + std::future::Future<Output = Result<usize, RpcError>> {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().expect("MockDaemon state poisoned");
            if let Some(err) = state.height_errors.pop_front() {
                return Err(err);
            }
            let chain_len = state.chain.len() as u64;
            let height = state
                .daemon_height_cap
                .map(|cap| cap.min(chain_len))
                .unwrap_or(chain_len);
            usize::try_from(height)
                .map_err(|_| RpcError::InvalidNode("MockDaemon height exceeded usize".to_string()))
        }
    }

    fn get_scannable_block_by_number(
        &self,
        number: usize,
    ) -> impl Send + std::future::Future<Output = Result<ScannableBlock, RpcError>> {
        let state = self.state.clone();
        async move {
            let height = number as u64;
            let mut state = state.lock().expect("MockDaemon state poisoned");

            if state.malformed_at.contains(&height) {
                return Err(RpcError::InvalidNode(format!(
                    "MockDaemon: malformed block at height {height}"
                )));
            }

            if let Some(queue) = state.block_errors.get_mut(&height) {
                if let Some(err) = queue.pop_front() {
                    return Err(err);
                }
            }

            if height == 0 {
                return Err(RpcError::InvalidNode(
                    "MockDaemon: requested height 0 is invalid".to_string(),
                ));
            }
            let idx = usize::try_from(height - 1).map_err(|_| {
                RpcError::InvalidNode("MockDaemon: height did not fit in usize".to_string())
            })?;

            state.chain.get(idx).cloned().ok_or_else(|| {
                RpcError::InvalidNode(format!("MockDaemon: no block at height {height}"))
            })
        }
    }
}

impl DaemonEngine for MockDaemon {
    type Error = RpcError;

    fn get_fee_estimates(
        &self,
    ) -> impl Send + std::future::Future<Output = Result<FeeEstimates, Self::Error>> {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().expect("MockDaemon state poisoned");
            if let Some(err) = state.fee_errors.pop_front() {
                return Err(err);
            }
            Ok(state.fee_estimates)
        }
    }

    fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> impl Send + std::future::Future<Output = Result<TxSubmitOutcome, Self::Error>> {
        let state = self.state.clone();
        async move {
            let hash = TxHash(shekyl_crypto_hash::cn_fast_hash(&tx_bytes));
            let mut state = state.lock().expect("MockDaemon state poisoned");
            if let Some(err) = state.submit_errors.pop_front() {
                return Err(err);
            }
            if state.submitted_hashes.insert(hash) {
                Ok(TxSubmitOutcome::Submitted { hash })
            } else {
                Ok(TxSubmitOutcome::AlreadyKnown { hash })
            }
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
        let rpc = MockDaemon::with_seed(DEFAULT_TEST_SEED);
        assert_eq!(rpc.get_height().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn linear_chain_reports_canonical_height() {
        let rpc = MockDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(5));
        assert_eq!(rpc.get_height().await.unwrap(), 5);
    }

    #[tokio::test]
    async fn block_fetch_returns_correct_height() {
        let chain = linear_chain(3);
        let expected_h2 = chain[1].block.hash();
        let rpc = MockDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, chain);

        let block = rpc.get_scannable_block_by_number(2).await.unwrap();
        assert_eq!(block.block.hash(), expected_h2);
    }

    #[tokio::test]
    async fn parent_hash_chains_correctly() {
        let rpc = MockDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(3));
        let h2 = rpc.get_scannable_block_by_number(2).await.unwrap();
        let h3 = rpc.get_scannable_block_by_number(3).await.unwrap();
        assert_eq!(h3.block.header.previous, h2.block.hash());
    }

    #[tokio::test]
    async fn replace_chain_from_truncates_and_extends() {
        let rpc = MockDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(5));
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
        let rpc = MockDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(10));
        rpc.set_daemon_height(4);
        assert_eq!(rpc.get_height().await.unwrap(), 4);
    }

    #[tokio::test]
    async fn height_errors_drain_in_fifo_then_recover() {
        let rpc = MockDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(2));
        rpc.set_height_error_for_next_n_calls(2, &RpcError::ConnectionError("transient".into()));

        assert!(rpc.get_height().await.is_err());
        assert!(rpc.get_height().await.is_err());
        assert_eq!(rpc.get_height().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn block_fetch_failure_is_one_shot() {
        let rpc = MockDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(3));
        rpc.inject_block_fetch_failure(2, RpcError::ConnectionError("flaky".into()));

        assert!(rpc.get_scannable_block_by_number(2).await.is_err());
        assert!(rpc.get_scannable_block_by_number(2).await.is_ok());
    }

    #[tokio::test]
    async fn malformed_block_errors_persistently() {
        let rpc = MockDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(3));
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
        let rpc = MockDaemon::with_seed(DEFAULT_TEST_SEED);
        let clone = rpc.clone();
        rpc.push_block(make_synthetic_block(1, [0u8; 32]));
        assert_eq!(clone.get_height().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn fetching_height_zero_is_an_error() {
        let rpc = MockDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(1));
        let err = rpc.get_scannable_block_by_number(0).await.unwrap_err();
        assert!(matches!(err, RpcError::InvalidNode(_)));
    }

    #[tokio::test]
    async fn fetching_past_chain_end_is_an_error() {
        let rpc = MockDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, linear_chain(2));
        let err = rpc.get_scannable_block_by_number(3).await.unwrap_err();
        assert!(matches!(err, RpcError::InvalidNode(_)));
    }

    // ---- DaemonEngine surface (§2.5 + §5.2 + §6.1 contract) ----

    #[tokio::test]
    async fn fee_estimates_default_is_monotonic_economy_standard_priority() {
        let daemon = MockDaemon::with_seed(DEFAULT_TEST_SEED);
        let fees = daemon.get_fee_estimates().await.unwrap();
        // FeeRate exposes no public per_weight accessor; verify
        // shape by round-tripping through equality against the
        // documented default constants.
        assert_eq!(fees.economy, FeeRate::new(1, 1).unwrap());
        assert_eq!(fees.standard, FeeRate::new(10, 1).unwrap());
        assert_eq!(fees.priority, FeeRate::new(100, 1).unwrap());
    }

    #[tokio::test]
    async fn fee_estimates_override_persists_across_calls() {
        let daemon = MockDaemon::with_seed(DEFAULT_TEST_SEED);
        let custom = FeeEstimates {
            economy: FeeRate::new(7, 1).unwrap(),
            standard: FeeRate::new(70, 1).unwrap(),
            priority: FeeRate::new(700, 1).unwrap(),
        };
        daemon.set_fee_estimates(custom);
        for _ in 0..3 {
            assert_eq!(daemon.get_fee_estimates().await.unwrap(), custom);
        }
    }

    #[tokio::test]
    async fn fee_failure_is_one_shot_then_recovers() {
        let daemon = MockDaemon::with_seed(DEFAULT_TEST_SEED);
        daemon.inject_fee_failure(RpcError::ConnectionError("fee-pool rotating".into()));
        assert!(daemon.get_fee_estimates().await.is_err());
        assert!(daemon.get_fee_estimates().await.is_ok());
    }

    #[tokio::test]
    async fn submit_transaction_first_sight_returns_submitted() {
        let daemon = MockDaemon::with_seed(DEFAULT_TEST_SEED);
        let bytes = b"tx-alpha".to_vec();
        let outcome = daemon.submit_transaction(bytes.clone()).await.unwrap();
        match outcome {
            TxSubmitOutcome::Submitted { hash } => {
                assert_eq!(hash, TxHash(shekyl_crypto_hash::cn_fast_hash(&bytes)));
            }
            other => panic!("expected Submitted, got {:?}", other),
        }
        assert_eq!(daemon.submitted_count(), 1);
    }

    #[tokio::test]
    async fn submit_transaction_dedupes_retry_returns_already_known() {
        // Models the §5.2 retry contract: engine submits, network
        // glitches between submit and ack, engine retries with the
        // same tx_bytes; the daemon (and MockDaemon) reports
        // AlreadyKnown rather than admitting a duplicate. Same hash
        // both times — caller correlates the two outcomes.
        let daemon = MockDaemon::with_seed(DEFAULT_TEST_SEED);
        let bytes = b"tx-beta".to_vec();
        let first = daemon.submit_transaction(bytes.clone()).await.unwrap();
        let second = daemon.submit_transaction(bytes.clone()).await.unwrap();
        let third = daemon.submit_transaction(bytes.clone()).await.unwrap();

        let expected = TxHash(shekyl_crypto_hash::cn_fast_hash(&bytes));
        assert!(matches!(first, TxSubmitOutcome::Submitted { hash } if hash == expected));
        assert!(matches!(second, TxSubmitOutcome::AlreadyKnown { hash } if hash == expected));
        assert!(matches!(third, TxSubmitOutcome::AlreadyKnown { hash } if hash == expected));
        assert_eq!(daemon.submitted_count(), 1, "dedup keeps the set size at 1");
    }

    #[tokio::test]
    async fn submit_transaction_distinct_bytes_get_distinct_hashes() {
        let daemon = MockDaemon::with_seed(DEFAULT_TEST_SEED);
        let alpha = daemon.submit_transaction(b"alpha".to_vec()).await.unwrap();
        let beta = daemon.submit_transaction(b"beta".to_vec()).await.unwrap();
        let alpha_hash = match alpha {
            TxSubmitOutcome::Submitted { hash } => hash,
            other => panic!("expected Submitted for alpha, got {:?}", other),
        };
        let beta_hash = match beta {
            TxSubmitOutcome::Submitted { hash } => hash,
            other => panic!("expected Submitted for beta, got {:?}", other),
        };
        assert_ne!(alpha_hash, beta_hash);
        assert_eq!(daemon.submitted_count(), 2);
    }

    #[tokio::test]
    async fn submit_failure_preempts_dedup_then_drains() {
        // The error queue drains *before* the dedup check so a
        // queued error returns even on first sight of the tx.
        // After the queue empties, the same tx_bytes admit
        // normally — exercising the engine's "retry after
        // transient error; dedup handles second-trip-after-success"
        // path.
        let daemon = MockDaemon::with_seed(DEFAULT_TEST_SEED);
        let bytes = b"tx-gamma".to_vec();

        daemon.inject_submit_failure(RpcError::ConnectionError("flaky".into()));
        assert!(daemon.submit_transaction(bytes.clone()).await.is_err());
        assert_eq!(
            daemon.submitted_count(),
            0,
            "errored submit did not enter dedup set"
        );

        let outcome = daemon.submit_transaction(bytes.clone()).await.unwrap();
        assert!(matches!(outcome, TxSubmitOutcome::Submitted { .. }));
        assert_eq!(daemon.submitted_count(), 1);
    }

    #[tokio::test]
    async fn submit_dedup_state_is_shared_across_clones() {
        let daemon = MockDaemon::with_seed(DEFAULT_TEST_SEED);
        let clone = daemon.clone();
        let bytes = b"tx-delta".to_vec();
        let first = daemon.submit_transaction(bytes.clone()).await.unwrap();
        let second_via_clone = clone.submit_transaction(bytes.clone()).await.unwrap();
        let expected = TxHash(shekyl_crypto_hash::cn_fast_hash(&bytes));
        assert!(matches!(first, TxSubmitOutcome::Submitted { hash } if hash == expected));
        assert!(
            matches!(second_via_clone, TxSubmitOutcome::AlreadyKnown { hash } if hash == expected)
        );
    }

    // ---- §6.2 derive_seed contract ----

    /// Master seed used in derive_seed contract tests. Recorded as a
    /// literal so a future failure can reproduce the exact derivation.
    const TEST_MASTER_SEED: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18,
    ];

    #[test]
    fn derive_seed_is_deterministic() {
        let seed_a = derive_seed(&TEST_MASTER_SEED, ROLE_DAEMON);
        let seed_b = derive_seed(&TEST_MASTER_SEED, ROLE_DAEMON);
        assert_eq!(
            seed_a, seed_b,
            "same (master, role) must derive the same seed across calls"
        );
    }

    #[test]
    fn derive_seed_distinct_roles_yield_distinct_seeds() {
        // The whole point of §6.2's role-tag separation: per-component
        // seeds are independent so a failure in one component's RNG
        // path can't masquerade as another's.
        let daemon_seed = derive_seed(&TEST_MASTER_SEED, ROLE_DAEMON);
        let probe_seed = derive_seed(&TEST_MASTER_SEED, b"role/probe-not-yet-bound");
        assert_ne!(
            daemon_seed, probe_seed,
            "distinct role tags must derive distinct seeds"
        );
    }

    #[test]
    fn derive_seed_distinct_masters_yield_distinct_seeds() {
        let alt_master = [0x42u8; 32];
        let from_test = derive_seed(&TEST_MASTER_SEED, ROLE_DAEMON);
        let from_alt = derive_seed(&alt_master, ROLE_DAEMON);
        assert_ne!(
            from_test, from_alt,
            "distinct master seeds must derive distinct per-role seeds"
        );
    }

    #[test]
    fn derive_seed_pinned_fixture_for_role_daemon() {
        // Defense against upstream `hkdf` / `sha2` library drift or
        // an accidental change to `ROLE_DAEMON`'s byte string. If
        // this fixture changes, hybrid-test reproducibility for
        // recorded master seeds breaks silently — the literal here
        // catches that at the helper boundary, before any hybrid
        // test sees the new derived seed.
        //
        // Computed on first run with the stable inputs above; a
        // future deliberate change to either the role tag or the
        // derivation primitive must update this fixture in the same
        // commit so the substitution is visible in review.
        let seed = derive_seed(&TEST_MASTER_SEED, ROLE_DAEMON);
        let expected: [u8; 32] = [
            0xc9, 0xf2, 0xb0, 0xa6, 0xa4, 0x1c, 0xf4, 0x8c, 0x43, 0x13, 0xdd, 0x74, 0x68, 0x3a,
            0xe0, 0x4c, 0xc2, 0x19, 0xcc, 0x67, 0xd3, 0x29, 0x41, 0x2b, 0x61, 0x90, 0x3b, 0x19,
            0x14, 0xda, 0x6b, 0x36,
        ];
        assert_eq!(
            seed, expected,
            "derive_seed(TEST_MASTER_SEED, ROLE_DAEMON) drifted from pinned fixture"
        );
    }
}
