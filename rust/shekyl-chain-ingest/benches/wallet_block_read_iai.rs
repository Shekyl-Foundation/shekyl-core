// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A wallet's block read answered from the store (`BENCHMARK_ALIGNMENT.md`
//! BA-T47): `shekyl_daemon_rpc::reads::block_list` over the production
//! store facts (`StoreFacts`, whose `blocks_by_height` reads the bodies),
//! and the reply serialized as the handler serializes it.
//!
//! The request names the tail of a block-path fixture's chain with its
//! subject connected: seven coinbase-only blocks and the subject, which
//! lists [`SUBJECT_SPENDS`] spends, unpruned. For each height the
//! read takes the header facts, the block and each listed transaction's
//! body, and the miner transaction's first output index. The caller is
//! bounded, as a wallet's connection is; the request is inside the bound.
//!
//! The serialization is the handler's `framed` (`serde_json::to_value`)
//! and then the value written to bytes, which the server does with every
//! response.
//!
//! These reads consult nothing about the node beyond its store: the node
//! facts the bench supplies answer "not ready" to every question, and
//! setup asserts the whole reply, so a read that began asking the node
//! would fail there.
//!
//! The bench is this crate's for the store (`bench_support.rs`).
//! `shekyl-daemon-rpc` is a dev-dependency of this crate, so the ledger
//! row's path set names it (a dev edge is not in the capture's linked
//! closure).
//!
//! An instruction count on the CI runner's x86, never a floor figure
//! (rule 76).

use std::hint::black_box;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};

use gungraun::{library_benchmark, library_benchmark_group, main};
use shekyl_chain_ingest::bench_support::RULES;
use shekyl_daemon_rpc::chain_facts::FactsFault;
use shekyl_daemon_rpc::info_facts::{PeerFacts, PoolCounts, PoolScope, PoolState, SessionCounts};
use shekyl_daemon_rpc::reads::block_list;
use shekyl_daemon_rpc::store_facts::{NodeFacts, NodeIdentity, PoolBody, StoreFacts, SyncFacts};
use shekyl_daemon_rpc::sync_facts::SyncViewFacts;
use shekyl_hash_budget::Budget;
use shekyl_hasher::{Hasher, Owner};
use shekyl_rpc_types::kinds::Height;
use shekyl_rpc_types::wire::block::BlockListQuery;
use shekyl_rpc_types::wire::shared::Slot;
use shekyl_types::{KeyImage, TxHash};

#[path = "support/tail.rs"]
mod tail;
use tail::{RequestedTail, SUBJECT_SPENDS, TAIL_BLOCKS};

const SPEND_1IN_2OUT: &[u8] = include_bytes!("fixtures/block_path_spend_1in_2out_unit.corpus");

/// A node that answers nothing: a block read is the store's alone.
struct NoNode;

impl NodeFacts for NoNode {
    fn sync(&self) -> Result<SyncFacts, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn sync_view(&self) -> Result<SyncViewFacts, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn pool_counts(&self, _: PoolScope) -> Result<PoolState<PoolCounts>, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn pool_spends(&self, _: &[KeyImage]) -> Result<Vec<bool>, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn pool_bodies(
        &self,
        _: &[TxHash],
        _: PoolScope,
    ) -> Result<PoolState<Vec<Option<PoolBody>>>, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn peers(&self) -> Result<PeerFacts, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn sessions(&self) -> Result<SessionCounts, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn free_space(&self) -> Result<u64, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn now(&self) -> u64 {
        0
    }
}

/// The store facts over a prepared store, with what keeps the store's
/// directory alive.
struct Prepared {
    facts: StoreFacts,
    request: BlockListQuery,
    _dir: tempfile::TempDir,
}

/// A hasher nothing ranks. This read never hashes: `pow` is not on the
/// path, and a warm loan on an unranked hasher is declined. The owner
/// stays for the process, so the builder thread is not joined between
/// iterations.
fn idle_hasher() -> Hasher {
    static IDLE: OnceLock<(Hasher, Owner)> = OnceLock::new();
    IDLE.get_or_init(|| {
        Hasher::start(Budget::new(NonZeroUsize::MIN)).expect("the builder thread starts")
    })
    .0
    .clone()
}

fn prepared(corpus: &[u8]) -> Prepared {
    let tail = RequestedTail::connected(corpus);
    let tip = u64::try_from(tail.chain.hashes().len()).expect("a short chain") - 1;
    let requested = u64::try_from(tail.hashes.len()).expect("the tail fits");
    let request = BlockListQuery {
        height: (tip + 1 - requested..=tip).map(Height).collect(),
        prune: false,
    };
    let (store, file, dir) = tail.chain.into_shared();
    let facts = StoreFacts::new(
        store,
        file,
        Arc::new(|height| RULES.in_force(height)),
        Arc::new(NoNode),
        NodeIdentity {
            nettype: shekyl_rpc_types::Network::Mainnet,
            release_build: false,
            version: "bench".to_owned(),
            start_time: 0,
            protocol_version: 3,
        },
        idle_hasher(),
    );
    let prepared = Prepared {
        facts,
        request,
        _dir: dir,
    };
    let reply = block_list(&prepared.facts, &prepared.facts, &prepared.request, true)
        .unwrap_or_else(|fault| panic!("the read answers: {fault:?}"));
    assert_eq!(reply.len(), TAIL_BLOCKS);
    match reply.last() {
        Some(Slot::Item(block)) => {
            assert_eq!(block.tx.len(), SUBJECT_SPENDS, "the subject's spends")
        }
        other => panic!("the tip is a block: {other:?}"),
    }
    prepared
}

#[library_benchmark]
#[bench::tip_run(args = (SPEND_1IN_2OUT), setup = prepared)]
fn crypto_bench_rpc_block_list(prepared: Prepared) -> (Prepared, Vec<u8>) {
    let bytes = {
        let reply = block_list(
            &prepared.facts,
            &prepared.facts,
            black_box(&prepared.request),
            true,
        )
        .unwrap_or_else(|fault| panic!("the read answers: {fault:?}"));
        let value = serde_json::to_value(&reply).expect("the reply is a value");
        black_box(serde_json::to_vec(&value).expect("the value is bytes"))
    };
    (prepared, bytes)
}

library_benchmark_group!(
    name = wallet_block_read_group;
    benchmarks = crypto_bench_rpc_block_list
);

main!(library_benchmark_groups = wallet_block_read_group);
