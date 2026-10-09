// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The scheduler's moves against the production serve loop behind the
//! loopback SOCKS shim: a good read, the `SF-D6` moves across holders,
//! the open-shard refusal, and the view cache's key.
//!
//! The shim tunnels every CONNECT to one endpoint, so "several holders"
//! here are several ids over one serve; what the tests show is that the
//! scheduler drew each once, moved when the client said to, and stopped
//! at the budget.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shekyl_archival_fetch_sched::{
    BlockSpan, ClosedShard, DiscardTxs, FactsFault, FetchError, FetchScheduler, Holder,
    HolderSource, NeedBudget, PFetchClient, ReadFailure, ShardClose, ShardFacts, ShardStanding,
    Timeouts, ViewDesk, ViewRefusal,
};
use shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
use shekyl_p_loopback::{
    endpoint_and_client, fetch_target, fixture_body, fixture_expectation, FIXTURE_SHARD_ID,
};
use shekyl_p_serve::{PassSigner, TestKeySigner};
use shekyl_types::{ArchivalLength, BlockHash, BlockHeight, PCanonicalId, ShardId};
use tokio::net::TcpListener;

const OWN_HEIGHT: u64 = 10_000;
const CLOSE_HEIGHT: u64 = 9_000;
const SHARD: ShardId = ShardId::from_raw(FIXTURE_SHARD_ID);

fn ephemeral_timeouts() -> Timeouts {
    Timeouts {
        dial: Duration::from_millis(500),
        head: Duration::from_millis(1_000),
        body_stall: Duration::from_millis(400),
        body_total: Duration::from_millis(2_000),
    }
}

/// In-memory skeleton: one closed shard, a tip, hashes by height.
struct Facts {
    tip: Mutex<u64>,
    close_hash: Mutex<[u8; 32]>,
    /// The span's coinbase count: the skeleton-side field a reorg moves.
    coinbase_outputs: Mutex<u64>,
    closed: ShardId,
    shard_reads: Mutex<u32>,
    /// When set, the `n`th `shard()` read is answered from a reorged
    /// standing (new close hash, one more coinbase) and every read after
    /// it: a reorg landing between two readers of the skeleton.
    reorg_at_read: Mutex<Option<u32>>,
}

impl Facts {
    fn new() -> Self {
        Self {
            tip: Mutex::new(OWN_HEIGHT),
            close_hash: Mutex::new([0xc1; 32]),
            coinbase_outputs: Mutex::new(11),
            closed: SHARD,
            shard_reads: Mutex::new(0),
            reorg_at_read: Mutex::new(None),
        }
    }

    fn reorg(&self) {
        *self.close_hash.lock().unwrap() = [0xd2; 32];
        *self.coinbase_outputs.lock().unwrap() += 1;
    }

    fn span(&self) -> BlockSpan {
        BlockSpan {
            first: BlockHeight::from_raw(8_990),
            last: BlockHeight::from_raw(CLOSE_HEIGHT),
            first_timestamp: 1_700_000_000,
            last_timestamp: 1_700_001_200,
            coinbase_outputs: *self.coinbase_outputs.lock().unwrap(),
            tx_outputs: 2,
        }
    }
}

impl ShardFacts for Facts {
    fn tip_height(&self) -> Result<BlockHeight, FactsFault> {
        Ok(BlockHeight::from_raw(*self.tip.lock().unwrap()))
    }

    fn block_hash_at(&self, height: BlockHeight) -> Result<Option<BlockHash>, FactsFault> {
        if height.to_raw() > *self.tip.lock().unwrap() {
            return Ok(None);
        }
        if height.to_raw() == CLOSE_HEIGHT {
            return Ok(Some(BlockHash::from_bytes(
                *self.close_hash.lock().unwrap(),
            )));
        }
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&height.to_raw().to_le_bytes());
        Ok(Some(BlockHash::from_bytes(bytes)))
    }

    fn shard(&self, shard_id: ShardId) -> Result<ShardStanding, FactsFault> {
        let reads = {
            let mut reads = self.shard_reads.lock().unwrap();
            *reads += 1;
            *reads
        };
        if *self.reorg_at_read.lock().unwrap() == Some(reads) {
            self.reorg();
        }
        if shard_id == self.closed {
            return Ok(ShardStanding::Closed(Box::new(ClosedShard {
                expected: fixture_expectation(shard_id.to_raw()),
                span: self.span(),
                close: ShardClose {
                    height: BlockHeight::from_raw(CLOSE_HEIGHT),
                    hash: BlockHash::from_bytes(*self.close_hash.lock().unwrap()),
                },
            })));
        }
        Ok(ShardStanding::Open {
            open_shard: ShardId::from_raw(self.closed.to_raw() + 1),
            archival_through_tip: ArchivalLength::from_raw(
                shekyl_types::shard_start(ShardId::from_raw(self.closed.to_raw() + 1))
                    .unwrap()
                    .to_raw()
                    + 1_000,
            ),
        })
    }
}

/// `n` holder ids, all resolving (through the shim) to the one endpoint.
struct Holders {
    holders: Mutex<Vec<Holder>>,
}

impl Holders {
    fn new(n: u8, key: &shekyl_crypto_pq::signature::HybridPublicKey) -> Self {
        let holders = (1..=n)
            .map(|tag| Holder {
                id: PCanonicalId::from_bytes([tag; 32]),
                target: fetch_target(key.clone()),
            })
            .collect();
        Self {
            holders: Mutex::new(holders),
        }
    }

    fn clear(&self) {
        self.holders.lock().unwrap().clear();
    }
}

impl HolderSource for Holders {
    fn holders_of(&self, _shard_id: ShardId) -> Result<Vec<Holder>, FactsFault> {
        Ok(self.holders.lock().unwrap().clone())
    }
}

struct Stack {
    endpoint: shekyl_p_loopback::PServeEndpoint,
    facts: Arc<Facts>,
    holders: Arc<Holders>,
    scheduler: Arc<FetchScheduler<Facts, Holders>>,
}

/// A serve of `served_shard` behind `n` holder ids.
async fn stack(served_shard: u64, n: u8) -> Stack {
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let key = signer.public_key().clone();
    let (endpoint, client) = endpoint_and_client(
        served_shard,
        fixture_body(),
        Arc::clone(&signer) as Arc<dyn PassSigner>,
        ephemeral_timeouts(),
    )
    .await;
    let facts = Arc::new(Facts::new());
    let holders = Arc::new(Holders::new(n, &key));
    let scheduler = Arc::new(FetchScheduler::new(
        Arc::clone(&facts),
        Arc::clone(&holders),
        client,
    ));
    Stack {
        endpoint,
        facts,
        holders,
        scheduler,
    }
}

fn budget(holders: usize, stall_redials: u32) -> NeedBudget {
    NeedBudget {
        holders: holders.try_into().unwrap(),
        stall_redials,
    }
}

fn holder_tags(attempts: &[shekyl_archival_fetch_sched::Attempt]) -> Vec<u8> {
    attempts.iter().map(|a| a.holder.to_bytes()[0]).collect()
}

#[tokio::test]
async fn a_closed_shard_is_read_from_a_drawn_holder() {
    let s = stack(FIXTURE_SHARD_ID, 3).await;
    let read = s
        .scheduler
        .read(SHARD, Arc::new(DiscardTxs), NeedBudget::DEFAULT)
        .await
        .expect("one serve, one read");
    assert_eq!(read.shard.shard_id(), SHARD);
    assert_eq!(read.shard.tx_count(), 1);
    assert_eq!(
        read.header.anchor_height(),
        BlockHeight::from_raw(OWN_HEIGHT) - PASS_ANCHOR_DEPTH_BLOCKS
    );
    assert_eq!(read.close.height, BlockHeight::from_raw(CLOSE_HEIGHT));
    assert!((1..=3).contains(&read.holder.to_bytes()[0]));
}

#[tokio::test]
async fn a_miss_moves_to_the_next_holder_and_the_budget_ends_the_need() {
    // The serve holds a different shard: every holder answers 404, each is
    // drawn once, and the need stops at the budget, not at the urn.
    let s = stack(FIXTURE_SHARD_ID + 7, 5).await;
    let err = s
        .scheduler
        .read(SHARD, Arc::new(DiscardTxs), budget(3, 1))
        .await
        .unwrap_err();
    let ReadFailure::Exhausted { attempts } = err else {
        panic!("expected exhaustion, got {err:?}");
    };
    assert_eq!(attempts.len(), 3);
    assert!(attempts.iter().all(|a| matches!(a.error, FetchError::Miss)));
    let tags: BTreeSet<u8> = holder_tags(&attempts).into_iter().collect();
    assert_eq!(tags.len(), 3, "a holder was drawn twice: {attempts:?}");
}

#[tokio::test]
async fn a_rejection_earns_one_fresh_anchor_then_moves_on() {
    // The requester's tip is far below P's: every anchor is out of P's
    // gate. First 400 → fresh header, same P; second 400 → next holder.
    let s = stack(FIXTURE_SHARD_ID, 2).await;
    *s.facts.tip.lock().unwrap() = OWN_HEIGHT - 100;
    let err = s
        .scheduler
        .read(SHARD, Arc::new(DiscardTxs), budget(2, 1))
        .await
        .unwrap_err();
    let ReadFailure::Exhausted { attempts } = err else {
        panic!("expected exhaustion, got {err:?}");
    };
    assert!(attempts
        .iter()
        .all(|a| matches!(a.error, FetchError::Rejected)));
    let tags = holder_tags(&attempts);
    assert_eq!(tags.len(), 4, "{attempts:?}");
    assert_eq!(tags[0], tags[1], "the fresh-anchor retry is the same P");
    assert_eq!(tags[2], tags[3]);
    assert_ne!(tags[0], tags[2], "then the next holder");
}

#[tokio::test]
async fn a_stall_redials_the_same_holder_within_the_budget() {
    // A black hole in place of the proxy: accepts and never answers.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            held.push(socket);
        }
    });
    let client = PFetchClient::with_timeouts(proxy, ephemeral_timeouts());
    let facts = Arc::new(Facts::new());
    let key = shekyl_crypto_pq::signature::HybridPublicKey {
        ed25519: [1; 32],
        ml_dsa: Vec::new(),
    };
    let holders = Arc::new(Holders::new(2, &key));
    let scheduler = FetchScheduler::new(facts, holders, client);
    let err = scheduler
        .read(SHARD, Arc::new(DiscardTxs), budget(2, 2))
        .await
        .unwrap_err();
    let ReadFailure::Exhausted { attempts } = err else {
        panic!("expected exhaustion, got {err:?}");
    };
    assert!(attempts
        .iter()
        .all(|a| matches!(a.error, FetchError::Stall(_))));
    // Two holders × (one dial + two redials).
    let tags = holder_tags(&attempts);
    assert_eq!(tags.len(), 6, "{attempts:?}");
    assert_eq!(&tags[..3], &[tags[0]; 3]);
    assert_eq!(&tags[3..], &[tags[3]; 3]);
    assert_ne!(tags[0], tags[3]);
}

#[tokio::test]
async fn an_open_shard_is_refused_before_any_dial() {
    let s = stack(FIXTURE_SHARD_ID, 1).await;
    let open = ShardId::from_raw(FIXTURE_SHARD_ID + 1);
    let err = s
        .scheduler
        .read(open, Arc::new(DiscardTxs), NeedBudget::DEFAULT)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ReadFailure::Open { shard_id, open_shard, .. } if shard_id == open && open_shard == open),
        "{err:?}"
    );
    assert_eq!(s.endpoint.served_count(), 0);
}

#[tokio::test]
async fn no_bonded_holder_is_typed_and_dials_nothing() {
    let s = stack(FIXTURE_SHARD_ID, 1).await;
    s.holders.clear();
    let err = s
        .scheduler
        .read(SHARD, Arc::new(DiscardTxs), NeedBudget::DEFAULT)
        .await
        .unwrap_err();
    assert!(matches!(err, ReadFailure::NoHolders { shard_id } if shard_id == SHARD));
}

#[tokio::test]
async fn the_view_is_assembled_cached_and_rekeyed_on_the_close_hash() {
    let s = stack(FIXTURE_SHARD_ID, 2).await;
    let desk = ViewDesk::new(Arc::clone(&s.scheduler), NeedBudget::DEFAULT);

    let view = desk.view(SHARD).await.expect("first view fetches");
    assert_eq!(view.shard_id, SHARD);
    assert_eq!(view.tx_count, 1);
    assert_eq!(view.block_count.to_raw(), 11);
    assert_eq!(view.coinbase_output_count, 11);
    assert_eq!(view.output_count, 13);
    assert_eq!(view.time_range_seconds, 1_200);
    assert_eq!(view.close_height, BlockHeight::from_raw(CLOSE_HEIGHT));
    assert_eq!(s.endpoint.served_count(), 1);

    // Cached: no holder is needed for the second answer.
    s.holders.clear();
    let again = desk.view(SHARD).await.expect("cache hit");
    assert_eq!(again, view);
    assert_eq!(s.endpoint.served_count(), 1);
    assert_eq!(desk.cached_count(), 1);

    // The block that closed the shard changed hash: the entry is dropped
    // and the view goes back to the holders — of which there are now none.
    s.facts.reorg();
    let err = desk.view(SHARD).await.unwrap_err();
    assert!(
        matches!(err, ViewRefusal::Unavailable { shard_id, ref attempts } if shard_id == SHARD && attempts.is_empty()),
        "{err:?}"
    );
    assert_eq!(desk.cached_count(), 0);
}

/// A reorg between the desk's cache check and the scheduler's own read of
/// the skeleton. The view must describe one standing — the one the body
/// was verified against — and be cached under that standing's close hash,
/// so the cache keeps answering it and nothing retains a view with the old
/// span's counts under the new hash.
#[tokio::test]
async fn a_reorg_between_the_cache_check_and_the_read_yields_one_standing() {
    let s = stack(FIXTURE_SHARD_ID, 2).await;
    let desk = ViewDesk::new(Arc::clone(&s.scheduler), NeedBudget::DEFAULT);
    // Read 1 is the desk's cache check; read 2 is the scheduler's snapshot.
    *s.facts.reorg_at_read.lock().unwrap() = Some(2);

    let view = desk.view(SHARD).await.expect("the read's own standing");
    assert_eq!(*s.facts.shard_reads.lock().unwrap(), 2);
    assert_eq!(
        view.coinbase_output_count, 12,
        "the span is the read's snapshot, not the cache check's"
    );
    assert_eq!(view.output_count, 14);
    assert_eq!(s.endpoint.served_count(), 1);

    // Cached under the standing it describes: the post-reorg skeleton
    // answers it without a holder.
    s.holders.clear();
    assert_eq!(desk.view(SHARD).await.expect("cache hit"), view);
    assert_eq!(s.endpoint.served_count(), 1);
    assert_eq!(desk.cached_count(), 1);
}

#[tokio::test]
async fn the_view_refuses_the_open_shard_with_the_distance_to_close() {
    let s = stack(FIXTURE_SHARD_ID, 1).await;
    let desk = ViewDesk::new(Arc::clone(&s.scheduler), NeedBudget::DEFAULT);
    let open = ShardId::from_raw(FIXTURE_SHARD_ID + 1);
    let err = desk.view(open).await.unwrap_err();
    let ViewRefusal::Open {
        shard_id,
        open_shard,
        remaining_to_close,
    } = err
    else {
        panic!("{err:?}");
    };
    assert_eq!(shard_id, open);
    assert_eq!(open_shard, open);
    // The facts say the tip shard is 1,000 bytes in.
    assert_eq!(
        remaining_to_close,
        Some(ArchivalLength::from_raw(
            shekyl_types::SHARD_LENGTH.to_raw() - 1_000
        ))
    );
    // Past the open shard there is no distance to state.
    let beyond = ShardId::from_raw(FIXTURE_SHARD_ID + 5);
    let err = desk.view(beyond).await.unwrap_err();
    assert!(matches!(
        err,
        ViewRefusal::Open {
            remaining_to_close: None,
            ..
        }
    ));
}

#[tokio::test]
async fn concurrent_views_of_one_shard_share_one_fetch() {
    let s = stack(FIXTURE_SHARD_ID, 2).await;
    let desk = Arc::new(ViewDesk::new(Arc::clone(&s.scheduler), NeedBudget::DEFAULT));
    let a = {
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.view(SHARD).await })
    };
    let b = {
        let desk = Arc::clone(&desk);
        tokio::spawn(async move { desk.view(SHARD).await })
    };
    let (a, b) = (a.await.unwrap().unwrap(), b.await.unwrap().unwrap());
    assert_eq!(a, b);
    assert_eq!(s.endpoint.served_count(), 1);
    assert_eq!(*s.facts.shard_reads.lock().unwrap(), 3);
}
