// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The RPC's store-backed facts (`shekyl-daemon-rpc`'s `StoreFacts`;
//! `DRS_X_STORE_FLIP.md` DX-Q3) over real chains, through the handlers the
//! flip routes to them.
//!
//! Hosted here because this crate holds the two real chains a facts read
//! can be judged over: the scenario driver's (mined through the production
//! stack, with alt blocks a second driver offers) and the six captured
//! chains (replayed through the production pipeline, each with its E2
//! trace — the C++ daemon's own per-height values, harvested from its
//! LMDB). The second is the differential the brief asks for: what the
//! store-backed facts report against what the C++ facts were made of.
//!
//! Every expectation here is computed from something other than the
//! facts under test: the mined template, the producer's claims, a hash
//! recomputed through the substrate, the corpus bytes, the trace.

#![cfg(test)]

use std::path::Path;
use std::sync::Arc;

use shekyl_chain_rules::{relay_floor_at, AtHeight, Substrate};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::{ChainStore, SnapshotView};
use shekyl_daemon_rpc::chain_facts::{BlockLookup, ChainFacts, FactsFault};
use shekyl_daemon_rpc::info::{get_info, Disclosure};
use shekyl_daemon_rpc::info_facts::{
    InfoPeersFacts, PeerFacts, PoolCounts, PoolScope, SessionCounts,
};
use shekyl_daemon_rpc::methods::{
    get_block, get_block_count, get_block_hash, get_block_header_by_hash,
    get_block_header_by_height, get_block_headers_range, get_fee_estimate, get_height,
    get_last_block_header, RpcFault,
};
use shekyl_daemon_rpc::read_methods::{get_coinbase_tx_sum, get_curve_tree_checkpoint};
use shekyl_daemon_rpc::store_facts::{NodeFacts, NodeIdentity, StoreFacts, SyncFacts};
use shekyl_pow_randomx::CacheStore;
use shekyl_rpc_types::{
    GetBlockHeaderByHashRequest, GetBlockHeadersRangeRequest, GetBlockRequest,
    GetCoinbaseTxSumRequest, GetCurveTreeCheckpointRequest, GetFeeEstimateRequest, HashHex, Hidden,
};
use shekyl_types::{BlockHash, BlockHeight, ChainCount, PowHash};
use shekyl_wire::Block;

use crate::connector::Offered;
use crate::scenario::{Mined, Scenario, RULES};
use crate::schedule::ChainRules;
use crate::source::{IngestEvent, Source};
use crate::test_support::{cleanup, open_store, open_store_under, tmp};

mod reads;

// ---------------------------------------------------------------------------
// The inputs the store does not hold
// ---------------------------------------------------------------------------

/// The node's non-store state, fixed: what PR 2's sync owner, PR-b's pool
/// and the p2p layer will supply at the flip.
struct TestNode {
    sync: SyncFacts,
    pool: PoolCounts,
    /// The key images the pool's shown entries spend.
    pool_spends: Vec<shekyl_types::KeyImage>,
    /// The bodies the pool shows.
    pool_bodies: Vec<shekyl_wire::Transaction>,
    now: u64,
}

impl TestNode {
    fn synced() -> Self {
        Self {
            sync: SyncFacts {
                target: None,
                synchronized: true,
                busy_syncing: false,
                offline: false,
                following_degraded: false,
            },
            pool: PoolCounts {
                broadcast: 3,
                unbroadcast: Some(2),
            },
            pool_spends: Vec::new(),
            pool_bodies: Vec::new(),
            now: 1_800_000_000,
        }
    }
}

impl NodeFacts for TestNode {
    fn sync(&self) -> Result<SyncFacts, FactsFault> {
        Ok(self.sync)
    }
    fn pool_counts(&self, scope: PoolScope) -> Result<PoolCounts, FactsFault> {
        Ok(match scope {
            PoolScope::Broadcast => PoolCounts {
                broadcast: self.pool.broadcast,
                unbroadcast: None,
            },
            PoolScope::WithUnbroadcast => self.pool,
        })
    }
    fn pool_spends(&self, key_images: &[shekyl_types::KeyImage]) -> Result<Vec<bool>, FactsFault> {
        Ok(key_images
            .iter()
            .map(|image| self.pool_spends.contains(image))
            .collect())
    }
    fn pool_bodies(
        &self,
        ids: &[shekyl_types::TxHash],
        _scope: PoolScope,
    ) -> Result<Vec<Option<shekyl_daemon_rpc::store_facts::PoolBody>>, FactsFault> {
        Ok(ids
            .iter()
            .map(|id| {
                self.pool_bodies
                    .iter()
                    .find(|tx| tx.txid_parts().hash == *id)
                    .map(|tx| shekyl_daemon_rpc::store_facts::PoolBody {
                        tx: tx.serialize(),
                        shown: true,
                    })
            })
            .collect())
    }
    fn peers(&self) -> Result<PeerFacts, FactsFault> {
        // An online node has its peer lists; `Offline` belongs to a node
        // whose sync facts say so.
        Ok(PeerFacts::Running(InfoPeersFacts {
            public_incoming_sockets: 1,
            public_outgoing_sockets: 2,
            tor_incoming_sockets: 0,
            tor_outgoing_sockets: 0,
            white_peerlist_size: 5,
            grey_peerlist_size: 7,
        }))
    }
    fn sessions(&self) -> Result<SessionCounts, FactsFault> {
        Ok(SessionCounts {
            outbound: 2,
            inbound: 1,
        })
    }
    fn free_space(&self) -> Result<u64, FactsFault> {
        Ok(1 << 40)
    }
    fn now(&self) -> u64 {
        self.now
    }
}

fn identity() -> NodeIdentity {
    NodeIdentity {
        nettype: shekyl_rpc_types::DaemonNetwork::Mainnet,
        release_build: false,
        version: "3.1.0-test".to_owned(),
        start_time: 1_700_000_000,
        protocol_version: 3,
    }
}

/// The store-backed facts over the store at `path`, under `rules`.
pub(crate) fn facts_over(store: Arc<ChainStore>, path: &Path, rules: ChainRules) -> StoreFacts {
    facts_with_caches(store, path, rules, Arc::new(CacheStore::new()))
}

/// [`facts_over`], hashing `calc_pow` under the caches `caches` holds —
/// the store a test's production substrate derived into, or an empty one.
pub(crate) fn facts_with_caches(
    store: Arc<ChainStore>,
    path: &Path,
    rules: ChainRules,
    caches: Arc<CacheStore>,
) -> StoreFacts {
    facts_with_budget(
        store,
        path,
        rules,
        caches,
        shekyl_hash_budget::Budget::of_host(),
    )
}

/// [`facts_with_caches`], hashing `calc_pow` under permits from `budget`.
pub(crate) fn facts_with_budget(
    store: Arc<ChainStore>,
    path: &Path,
    rules: ChainRules,
    caches: Arc<CacheStore>,
    budget: shekyl_hash_budget::Budget,
) -> StoreFacts {
    StoreFacts::new(
        store,
        path.to_path_buf(),
        Arc::new(move |h| rules.in_force(h)),
        Arc::new(TestNode::synced()),
        identity(),
        caches,
        budget,
    )
}

/// A hash a refusal echoes, as the wire spells it.
pub(crate) fn hex(hash: BlockHash) -> HashHex {
    HashHex::from_bytes(hash.to_bytes())
}

// ---------------------------------------------------------------------------
// A scenario chain
// ---------------------------------------------------------------------------

/// A longhash a test can recompute: keccak over the blob and the seed. At
/// the scenario's fixed difficulty of one every hash satisfies the target,
/// so the chain mines as it would over the free hash — but a recorded PoW
/// that is not this block's own is visible, which an all-zero hash hides.
pub(crate) struct KeccakPow;

impl Substrate for KeccakPow {
    type Fault = std::convert::Infallible;
    type Held = ();

    fn local_clock(&self) -> Result<shekyl_types::Timestamp, Self::Fault> {
        crate::scenario::FreeHash.local_clock()
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, Self::Fault> {
        Ok(PowHash::from_bytes(keccak_pow(pow_blob, seed)))
    }
}

pub(crate) fn keccak_pow(pow_blob: &[u8], seed: &BlockHash) -> [u8; 32] {
    let mut preimage = pow_blob.to_vec();
    preimage.extend_from_slice(&seed.to_bytes());
    shekyl_crypto_hash::keccak256(&preimage)
}

/// The miner transaction's outputs summed: the reward, computed from the
/// mined template rather than read from the facts.
fn template_reward(block: &Block) -> u64 {
    block
        .miner_transaction
        .prefix
        .outputs
        .iter()
        .map(|o| o.amount)
        .sum()
}

/// Every header field the facts report for a main-chain block, held to the
/// block as mined and to the producer's own claims.
#[tokio::test]
async fn a_scenario_chains_headers_and_blocks_are_the_mined_blocks() {
    let mut s = Scenario::open_with("rpc-store-facts-main", KeccakPow);
    let mined = s.mine(8).await;
    let tip = mined.last().expect("eight blocks").height;
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_over(Arc::clone(&store), path, RULES);

        // The tip, the count and every hash.
        let height = get_height(&facts).expect("height");
        assert_eq!(height.height, tip.to_raw() + 1, "get_height is the count");
        assert_eq!(height.hash, hex(mined.last().expect("tip").hash));
        assert_eq!(
            get_block_count(&facts).expect("count").count,
            tip.to_raw() + 1
        );
        for m in &mined {
            assert_eq!(
                get_block_hash(&facts, m.height.to_raw()).expect("in range"),
                hex(m.hash),
                "block hash at {}",
                m.height.to_raw()
            );
        }

        // Every header field, by height, from the block as mined.
        for m in &mined {
            let header = get_block_header_by_height(&facts, m.height.to_raw(), true)
                .expect("in range")
                .block_header;
            let block = &m.template.block;
            assert_eq!(header.hash, hex(m.hash));
            assert_eq!(header.height, m.height.to_raw());
            assert_eq!(header.depth, tip.to_raw() - m.height.to_raw());
            assert_eq!(header.prev_hash, hex(block.header.previous));
            assert_eq!(
                header.miner_tx_hash,
                HashHex::from_bytes(block.miner_transaction.hash().to_bytes())
            );
            assert_eq!(header.timestamp, block.header.timestamp);
            assert_eq!(header.nonce, block.header.nonce);
            assert_eq!(header.major_version, block.header.major_version);
            assert_eq!(header.minor_version, block.header.minor_version);
            assert_eq!(
                header.num_txes,
                u64::try_from(block.transaction_hashes.len()).expect("fits")
            );
            assert_eq!(
                header.reward,
                template_reward(block),
                "reward at {}",
                m.height.to_raw()
            );
            assert_eq!(
                header.curve_tree_root,
                HashHex::from_bytes(block.header.curve_tree_root.to_bytes())
            );
            assert_eq!(
                header.attestation_root,
                HashHex::from_bytes(block.header.attestation_root.to_bytes())
            );
            assert_eq!(
                u128::from(header.difficulty),
                m.target.difficulty().to_raw(),
                "the block's own difficulty is the target its producer claimed"
            );
            assert!(!header.orphan_status);
            assert_eq!(
                header.block_weight,
                m.weights.weight.to_raw(),
                "weight at {}",
                m.height.to_raw()
            );
            assert_eq!(
                header.pow_hash,
                Some(HashHex::from_bytes(keccak_pow(&block.pow_blob(), &m.seed))),
                "the recorded PoW is this block's own hash under its seed"
            );
        }

        // The cumulative difficulty is the running sum of the claimed
        // targets.
        let mut sum = 0u128;
        for m in &mined {
            sum += m.target.difficulty().to_raw();
            let header = get_block_header_by_height(&facts, m.height.to_raw(), false)
                .expect("in range")
                .block_header;
            assert_eq!(
                (u128::from(header.cumulative_difficulty_top64) << 64)
                    | u128::from(header.cumulative_difficulty),
                sum
            );
            assert_eq!(header.pow_hash, None, "not requested, not filled");
        }

        // By hash, the same header.
        let last = mined.last().expect("tip");
        let by_hash = get_block_header_by_hash(
            &facts,
            &GetBlockHeaderByHashRequest {
                hashes: vec![hex(last.hash)],
                fill_pow_hash: false,
            },
            false,
        )
        .expect("by hash");
        assert_eq!(
            by_hash.block_headers[0].block_header,
            Some(
                get_block_header_by_height(&facts, last.height.to_raw(), false)
                    .expect("in range")
                    .block_header
            )
        );
        assert_eq!(
            get_last_block_header(&facts, false, false)
                .expect("tip")
                .block_header
                .hash,
            hex(last.hash)
        );

        // The range, and its refusal past the tip.
        let range = get_block_headers_range(
            &facts,
            &GetBlockHeadersRangeRequest {
                start_height: 2,
                end_height: 5,
                fill_pow_hash: false,
            },
            false,
        )
        .expect("in range");
        assert_eq!(
            range.headers.iter().map(|h| h.height).collect::<Vec<_>>(),
            vec![2, 3, 4, 5]
        );
        assert!(matches!(
            get_block_headers_range(
                &facts,
                &GetBlockHeadersRangeRequest {
                    start_height: 2,
                    end_height: tip.to_raw() + 1,
                    fill_pow_hash: false,
                },
                false,
            ),
            Err(RpcFault::Refused(_))
        ));

        // The whole block: its blob is the block as mined, its hashes its
        // listed bodies, and there is no epee rendering.
        for m in &mined {
            let reply = get_block(
                &facts,
                &GetBlockRequest {
                    hash: String::new(),
                    height: m.height.to_raw(),
                    fill_pow_hash: false,
                },
                false,
            )
            .expect("in range");
            assert_eq!(reply.blob, hex::encode(m.template.block.serialize()));
            assert_eq!(
                reply.tx_hashes,
                m.template
                    .block
                    .transaction_hashes
                    .iter()
                    .map(|h| HashHex::from_bytes(h.to_bytes()))
                    .collect::<Vec<_>>()
            );
            assert_eq!(reply.json, None, "the store has no epee renderer (RK-D11)");
        }

        // Past the tip: refused by height and by an unknown hash, each with
        // its own refusal.
        assert!(matches!(
            get_block_header_by_height(&facts, tip.to_raw() + 1, false),
            Err(RpcFault::Refused(_))
        ));
        assert!(matches!(
            get_block_hash(&facts, tip.to_raw() + 1),
            Err(RpcFault::Refused(_))
        ));
        let unknown = get_block_header_by_hash(
            &facts,
            &GetBlockHeaderByHashRequest {
                hashes: vec![HashHex::from_bytes([0x5a; 32])],
                fill_pow_hash: false,
            },
            false,
        )
        .expect("an unknown hash is a slot, not a refusal");
        assert_eq!(unknown.block_headers[0].block_header, None);

        // A restricted caller asking for the PoW is refused, not blanked.
        assert!(matches!(
            get_last_block_header(&facts, true, true),
            Err(RpcFault::Refused(_))
        ));
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// The fee estimate is the served ladder at the connecting height, and its
/// economy rung is the relay floor there (FL-R6) — the floor read through
/// its own path.
#[tokio::test]
async fn the_fee_estimate_is_the_ladder_at_the_connecting_height() {
    let mut s = Scenario::open("rpc-store-facts-fee");
    let mined = s.mine(6).await;
    let connecting = BlockHeight::from_raw(mined.last().expect("tip").height.to_raw() + 1);
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_over(Arc::clone(&store), path, RULES);
        let fees = get_fee_estimate(&facts, &GetFeeEstimateRequest {})
            .expect("fees")
            .fees
            .0;
        let snap = store.begin_read().expect("read");
        let floor = match relay_floor_at(&SnapshotView::new(&snap), connecting) {
            Ok(AtHeight::Recorded(floor)) => floor,
            other => panic!("the floor at the connecting height: {other:?}"),
        };
        assert_eq!(fees[0], floor, "the economy rung is the floor (FL-R6)");
        assert!(fees[0] <= fees[1] && fees[1] <= fees[2], "{fees:?}");
        drop(snap);
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// `get_info` over the store: the chain part from the snapshot and the
/// rules' derivations, everything else from the node's inputs.
#[tokio::test]
async fn get_info_reads_the_chain_from_the_store_and_the_rest_from_the_node() {
    let mut s = Scenario::open("rpc-store-facts-info");
    let mined = s.mine(5).await;
    let last = mined.last().expect("tip").clone();
    // The wire's `tx_count` excludes coinbases: every listed body, and
    // nothing else.
    let listed: u64 = mined
        .iter()
        .map(|m| u64::try_from(m.template.transactions.len()).expect("fits"))
        .sum();
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_over(Arc::clone(&store), path, RULES);
        let info = get_info(&facts, Disclosure::FULL, 0).expect("info");
        assert_eq!(info.health.height, last.height.to_raw() + 1);
        assert_eq!(info.health.top_block_hash, hex(last.hash));
        assert!(info.health.synchronized);
        assert!(!info.health.following_degraded);
        assert_eq!(
            info.chain.tx_count, listed,
            "every listed body, coinbases excluded"
        );
        assert_eq!(
            info.economics.already_generated_coins, last.emission.coins_generated,
            "the accumulator through the tip"
        );
        // The scenario's fixed difficulty is the next block's too.
        assert_eq!(info.chain.difficulty, 1);
        assert_eq!(
            info.chain.block_weight_limit,
            2 * info.chain.block_weight_median,
            "the limit is twice the effective median (CEN-G6b)"
        );
        assert_eq!(
            info.pool.tx_pool_size, 3,
            "the pool's broadcast count is the node's"
        );
        match &info.node {
            Hidden::Shown(status) => assert_eq!(status.alt_blocks_count, 0),
            Hidden::Withheld => panic!("a full disclosure shows Status"),
        }
        let restricted = get_info(&facts, Disclosure::VIEW, 0).expect("info");
        assert!(matches!(restricted.node, Hidden::Withheld));
        assert!(matches!(restricted.peers, Hidden::Withheld));
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// An alt block by hash: every value from its own row — its cumulative
/// difficulty, its weight, its recorded PoW — never the main chain's at
/// its height; no confirmations on the main chain; no long-term weight.
#[tokio::test]
async fn an_alt_block_by_hash_is_described_by_its_own_row() {
    let prefix = 4;
    let mut x = Scenario::open_with("rpc-store-facts-alt-x", KeccakPow);
    let mut y = Scenario::open_with("rpc-store-facts-alt-y", KeccakPow);
    x.mine(prefix).await;
    y.mine(prefix).await;
    let main = x.mine(3).await;
    y.idle();
    let branch: Vec<Mined> = y.mine(1).await;
    let alt = branch[0].clone();
    assert_ne!(alt.hash, main[0].hash, "the branches differ");
    match x.offer(&alt).await.expect("offer") {
        Offered::Held { height } => assert_eq!(height, alt.height),
        other => panic!("a lighter branch is held: {other:?}"),
    }
    x.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_over(Arc::clone(&store), path, RULES);
        let reply = get_block_header_by_hash(
            &facts,
            &GetBlockHeaderByHashRequest {
                hashes: vec![hex(alt.hash)],
                fill_pow_hash: true,
            },
            false,
        )
        .expect("by hash");
        let header = reply.block_headers[0]
            .block_header
            .clone()
            .expect("the alt block is held");
        assert!(header.orphan_status);
        assert_eq!(header.height, alt.height.to_raw());
        assert_eq!(header.depth, 0, "no confirmations on the main chain");
        assert_eq!(
            header.long_term_weight, 0,
            "omitted: no chain records its medians"
        );
        assert_eq!(
            u128::from(header.difficulty),
            alt.target.difficulty().to_raw()
        );
        assert_eq!(
            header.pow_hash,
            Some(HashHex::from_bytes(keccak_pow(
                &alt.template.block.pow_blob(),
                &alt.seed
            )))
        );
        assert_eq!(header.block_weight, alt.weights.weight.to_raw());
        // The main block at the same height is a different header.
        let main_header = get_block_header_by_height(&facts, alt.height.to_raw(), false)
            .expect("in range")
            .block_header;
        assert_ne!(main_header.hash, header.hash);
        let snap = store.begin_read().expect("read");
        assert_eq!(snap.alt_block_count().expect("count"), 1);
        drop(snap);
        drop(facts);
        drop(store);
    })
    .await;
    x.close().await;
    y.close().await;
}

/// An empty store has not connected genesis, so it has no tip to describe:
/// not ready, never a zero tip.
#[test]
fn an_empty_store_is_not_ready_and_never_a_zero_tip() {
    let path = tmp("rpc-store-facts-empty");
    let store = Arc::new(open_store(&path));
    let facts = facts_over(Arc::clone(&store), &path, RULES);
    assert_eq!(facts.chain_tip(), Err(FactsFault::NotReady));
    assert_eq!(facts.identity(), Err(FactsFault::NotReady));
    assert_eq!(
        facts.block_header_at(BlockLookup::Height(BlockHeight::ZERO), false),
        Err(FactsFault::NotReady)
    );
    drop(facts);
    drop(store);
    cleanup(&path);
}

// ---------------------------------------------------------------------------
// The captured chains: the differential against the C++'s own values
// ---------------------------------------------------------------------------

/// One field the store-backed facts and the C++ disagree on, at a height.
#[derive(Debug)]
struct Difference {
    shape: String,
    height: BlockHeight,
    field: &'static str,
    cxx: String,
    rust: String,
}

/// Replay every captured chain, then read it back through the store-backed
/// facts and hold each value the C++ facts were made of — the trace's
/// `block_info` columns and the corpus's block bytes — against what the
/// store-backed facts report. Every difference is collected, printed, and
/// then must be empty: a difference is a DX-Q8 row to place, and the PR
/// body places each one before this is allowed to be non-empty.
#[tokio::test]
async fn the_store_facts_report_what_the_cxx_facts_were_made_of_on_every_captured_chain() {
    let mut differences: Vec<Difference> = Vec::new();
    let mut heights_read = 0u64;
    let mut coinbase_figure_differs = 0u64;
    let mut coinbase_figure_wraps = 0u64;
    for (dir, manifest) in crate::vectors_tests::captured_chains() {
        let (report, path, rules) = crate::vectors_tests::replay_keeping_store(
            &dir,
            &manifest,
            crate::vectors_tests::mock_with_the_real_clock(),
            ApplyPolicy::Full,
            "rpc-facts",
        )
        .await;
        let report = report.unwrap_or_else(|e| panic!("{}: replays: {e}", manifest.shape));
        let trace = crate::trace::Trace::read(std::io::Cursor::new(
            std::fs::read(dir.join("trace.e2")).expect("read trace"),
        ))
        .expect("trace");
        // The corpus's blocks, as the C++ RPC served them — read as far as
        // the replay connected: past a chain's retired keyless join the
        // corpus holds bodies this tree no longer parses
        // (`retired_keyless_join`), and the replay stopped before them.
        let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus");
        let mut reader = crate::corpus::CorpusReader::open(std::io::Cursor::new(corpus.as_slice()))
            .expect("open corpus");
        let mut corpus_blocks: Vec<Block> = Vec::new();
        let mut corpus_fees: Vec<u128> = Vec::new();
        while corpus_blocks.len() < report.connected.len() {
            let item = reader
                .next()
                .expect("the corpus reads as far as the replay connected")
                .expect("the corpus holds every connected block");
            if let IngestEvent::Extend(candidate) = item.event {
                corpus_fees.push(
                    candidate
                        .transactions
                        .iter()
                        .map(|tx| match tx.ct {
                            shekyl_wire::Ct::Fcmp { fee, .. } => u128::from(fee),
                            shekyl_wire::Ct::Null(_) => 0,
                        })
                        .sum(),
                );
                corpus_blocks.push(candidate.block);
            }
        }

        let store = Arc::new(open_store_under(
            &path,
            &rules.in_force(BlockHeight::ZERO),
            ApplyPolicy::Full,
        ));
        let facts = facts_over(Arc::clone(&store), &path, rules);
        let mut push = |height: BlockHeight, field: &'static str, cxx: String, rust: String| {
            if cxx != rust {
                differences.push(Difference {
                    shape: manifest.shape.clone(),
                    height,
                    field,
                    cxx,
                    rust,
                });
            }
        };
        let mut previous_cumulative = 0u128;
        let mut previous_coins = 0u128;
        for (height, hash) in &report.connected {
            let h = height.to_raw();
            heights_read += 1;
            let Some(borrowed) = trace.borrow(*height) else {
                panic!(
                    "{}: the trace covers every connected height",
                    manifest.shape
                );
            };
            let cxx = borrowed.value();
            let at = facts
                .block_at(BlockLookup::Height(*height), false)
                .expect("facts")
                .block
                .expect("a connected height has a block");
            let header = &at.header;
            push(
                *height,
                "hash",
                format!("{hash:?}"),
                format!("{:?}", header.hash),
            );
            push(
                *height,
                "block_weight",
                cxx.weight.to_raw().to_string(),
                header.block_weight.to_string(),
            );
            push(
                *height,
                "long_term_weight",
                format!("{:?}", Some(cxx.long_term_weight.to_raw())),
                format!("{:?}", header.long_term_weight),
            );
            let cumulative = cxx.cumulative_difficulty.to_raw();
            push(
                *height,
                "cumulative_difficulty",
                cumulative.to_string(),
                header.cumulative_difficulty.to_string(),
            );
            push(
                *height,
                "difficulty",
                (cumulative - previous_cumulative).to_string(),
                header.difficulty.to_string(),
            );
            previous_cumulative = cumulative;
            let served = &corpus_blocks[usize::try_from(h).expect("fits")];
            push(
                *height,
                "blob",
                hex::encode(served.serialize()),
                hex::encode(&at.blob),
            );
            push(
                *height,
                "reward",
                template_reward(served).to_string(),
                header.reward.to_string(),
            );
            push(
                *height,
                "curve_tree_root",
                format!("{:?}", served.header.curve_tree_root),
                format!("{:?}", header.curve_tree_root),
            );

            // The read handlers' values at this height.
            // The tree after the block: the C++ recorded root after it.
            let checkpoint = get_curve_tree_checkpoint(
                &facts,
                &GetCurveTreeCheckpointRequest { block_height: h },
            )
            .expect("through the tip");
            push(
                *height,
                "checkpoint_root",
                hex::encode(cxx.root_after.to_bytes()),
                checkpoint.root,
            );
            // One block's coinbase sum: its fees are the corpus bodies'; its
            // emission is the C++ accumulator's growth at this height.
            let one = get_coinbase_tx_sum(
                &facts,
                &GetCoinbaseTxSumRequest {
                    height: h,
                    count: 1,
                },
            )
            .expect("coinbase sum");
            let fees = corpus_fees[usize::try_from(h).expect("fits")];
            push(
                *height,
                "coinbase_sum_fees",
                fees.to_string(),
                ((u128::from(one.fee_amount_top64) << 64) | u128::from(one.fee_amount)).to_string(),
            );
            let coins = u128::from(cxx.coins_generated.to_raw());
            let emission =
                (u128::from(one.emission_amount_top64) << 64) | u128::from(one.emission_amount);
            push(
                *height,
                "coinbase_sum_emission",
                (coins - previous_coins).to_string(),
                emission.to_string(),
            );
            previous_coins = coins;
            // The C++ handler's own figure, the coinbase less the fees —
            // the divergence register's C++-defect row, tallied apart: it
            // is placed, so it is not a difference this test refuses on.
            let cxx_figure =
                i128::from(template_reward(served)) - i128::try_from(fees).expect("fits");
            if cxx_figure != i128::try_from(emission).expect("fits") {
                coinbase_figure_differs += 1;
                if cxx_figure < 0 {
                    coinbase_figure_wraps += 1;
                }
            }
        }
        // At the tip: the accumulator and the burn total.
        if let Some((tip, _)) = report.connected.last() {
            let cxx = *trace.borrow(*tip).expect("covered").value();
            let info = shekyl_daemon_rpc::info_facts::InfoFacts::chain(&facts).expect("chain");
            push(
                *tip,
                "already_generated_coins",
                cxx.coins_generated.to_raw().to_string(),
                info.already_generated_coins.to_raw().to_string(),
            );
            let burned: u64 = report
                .connected
                .iter()
                .map(|(h, _)| trace.borrow(*h).expect("covered").value().burned.to_raw())
                .sum();
            push(
                *tip,
                "total_burned",
                burned.to_string(),
                info.total_burned.to_raw().to_string(),
            );
            push(
                *tip,
                "chain_height",
                ChainCount::from_raw(tip.to_raw() + 1).to_raw().to_string(),
                info.chain_height.to_raw().to_string(),
            );
        }
        drop(facts);
        drop(store);
        cleanup(&path);
    }
    assert!(heights_read > 0, "the captured chains were read (rule 47)");
    for d in &differences {
        eprintln!(
            "difference: {} h{} {}: C++ {} / Rust {}",
            d.shape,
            d.height.to_raw(),
            d.field,
            d.cxx,
            d.rust
        );
    }
    eprintln!(
        "store-facts differential: {heights_read} heights over the captured chains, {} differences",
        differences.len()
    );
    eprintln!(
        "get_coinbase_tx_sum: the C++ emission figure (coinbase less fees) differs from the coins \
         minted at {coinbase_figure_differs} of {heights_read} heights; it would wrap below zero at \
         {coinbase_figure_wraps}"
    );
    assert!(differences.is_empty(), "{} differences", differences.len());
}
