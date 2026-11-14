// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The chains the loopback harness syncs: a captured corpus connected
//! through a real ingest service into a real store, and header chains
//! built on one.
//!
//! A corpus is connected the way `block_submit` connects a block: through
//! the door, from this node, one block at a time, each formed and judged.
//! That is the store an honest peer serves and the store a node starts
//! from. A header chain is a fork only a header path judges: each header
//! is a stored block's with its parent, timestamp and nonce rewritten, at
//! the corpus's fixed target, so its proof is one real hash and its body
//! is never offered.

use std::num::{NonZeroU128, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use shekyl_chain_ingest::service::{
    Arrival, ArrivalTag, Follow, Origin, Reply, Service, ServiceConfig,
};
use shekyl_chain_ingest::{ChainRules, CorpusReader, IngestEvent, ProductionPow, Source};
use shekyl_chain_rules::{AtHeight, CappedEpoch, SettlementEpochBlocks};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::{ChainStore, Horizons};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::Block;

/// One captured corpus: where it is and what it was mined under.
#[derive(Clone, Debug)]
pub struct Corpus {
    /// The corpus's shape, its directory name.
    pub shape: &'static str,
    dir: PathBuf,
    fixed_difficulty: u128,
    epoch: u64,
    cap: u64,
    /// The captured tip.
    pub tip_height: u64,
}

/// One step of a corpus: a block and its listed bodies.
#[derive(Clone, Debug)]
pub struct Step {
    /// The block blob.
    pub block: Vec<u8>,
    /// The listed bodies, in the block's order.
    pub bodies: Vec<Vec<u8>>,
}

impl Corpus {
    /// The corpus `shape` under `shekyl-chain-ingest/tests/vectors`.
    ///
    /// # Panics
    ///
    /// The manifest is missing or malformed: the harness cannot run.
    #[must_use]
    pub fn open(shape: &'static str) -> Self {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../shekyl-chain-ingest/tests/vectors")
            .join(shape);
        let text = std::fs::read_to_string(dir.join("manifest.json")).expect("the manifest");
        let manifest: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        let field = |name: &str| {
            manifest[name]
                .as_u64()
                .unwrap_or_else(|| panic!("{shape}: manifest field {name}"))
        };
        Self {
            shape,
            fixed_difficulty: u128::from(field("fixed_difficulty")),
            epoch: field("settlement_epoch_blocks"),
            cap: field("reorg_cap_blocks"),
            tip_height: field("tip_height"),
            dir,
        }
    }

    /// The corpus's rules with the reorg cap at `depth`: what a regtest
    /// node started with `--dev-archival-reorg-depth depth` runs (regtest's
    /// `ArchivalReorgDepth` permit, `NETWORK_IDENTITY.md` NI-R6). Only the
    /// constant moves; the switch, the cap check and the latch are the
    /// production ones.
    ///
    /// # Panics
    ///
    /// `depth` is not strictly inside the corpus's settlement epoch.
    #[must_use]
    pub fn rules_under_reorg_depth(&self, depth: u64) -> ChainRules {
        self.rules_with(self.fixed_difficulty, depth)
    }

    /// The corpus's epoch, at `difficulty` and reorg cap `cap`.
    fn rules_with(&self, difficulty: u128, cap: u64) -> ChainRules {
        let schedule = CappedEpoch::new(
            SettlementEpochBlocks::new(self.epoch).expect("a captured epoch"),
            BlockCount::from_raw(cap),
        )
        .expect("a reorg cap inside the epoch");
        ChainRules::new(
            shekyl_network::Network::Regtest,
            Some(NonZeroU128::new(difficulty).expect("non-zero")),
            schedule,
        )
        .expect("regtest's row permits its levers")
    }

    /// The rules the corpus was mined under.
    #[must_use]
    pub fn rules(&self) -> ChainRules {
        self.rules_at(self.fixed_difficulty)
    }

    /// The corpus's schedule at another fixed difficulty: a forgery's
    /// target (genesis is target 1 under every rule set).
    ///
    /// # Panics
    ///
    /// `difficulty` is zero, or the manifest's pair is not a schedule.
    #[must_use]
    pub fn rules_at(&self, difficulty: u128) -> ChainRules {
        self.rules_with(difficulty, self.cap)
    }

    /// Every step, in order.
    ///
    /// # Panics
    ///
    /// The corpus does not read, or a block carries bundle references:
    /// these steps offer none, so such a corpus is not connected this way.
    #[must_use]
    pub fn steps(&self) -> Vec<Step> {
        self.steps_through(self.tip_height)
    }

    /// The steps through the block at `last`.
    ///
    /// # Panics
    ///
    /// As [`Self::steps`].
    #[must_use]
    pub fn steps_through(&self, last: u64) -> Vec<Step> {
        let bytes = std::fs::read(self.dir.join("corpus.e2")).expect("the corpus");
        let mut reader = CorpusReader::open(std::io::Cursor::new(bytes)).expect("a corpus");
        let mut steps = Vec::new();
        let mut blocks = 0u64;
        while blocks <= last {
            let Some(event) = reader.next().expect("the corpus reads") else {
                break;
            };
            match event.event {
                IngestEvent::Extend(candidate) => {
                    blocks += 1;
                    assert!(
                        candidate.bundle_references.is_none(),
                        "{}: a block with bundle references",
                        self.shape
                    );
                    steps.push(Step {
                        block: candidate.block.serialize(),
                        bodies: candidate
                            .transactions
                            .iter()
                            .map(shekyl_wire::Transaction::serialize)
                            .collect(),
                    });
                }
                IngestEvent::Rewind { .. } => panic!("{}: a rewind in a corpus", self.shape),
            }
        }
        steps
    }
}

/// A store under the schedule `rules` names at genesis.
///
/// # Panics
///
/// The store cannot be created.
#[must_use]
pub fn open_store(path: &Path, rules: ChainRules) -> ChainStore {
    let horizons = Horizons::under(&rules.in_force(BlockHeight::ZERO)).expect("a schedule");
    ChainStore::with_horizons(path, ApplyPolicy::Full, horizons).expect("the store")
}

/// A hasher of a node's own, and the boundary over it.
pub struct OwnHasher {
    /// The boundary the service and the executor form and prove through.
    pub pow: ProductionPow,
    /// The hasher, for its `resident()` watch.
    pub hasher: shekyl_hasher::Hasher,
    /// The sink the boundary records into.
    pub metrics: Arc<shekyl_chain_ingest::Metrics>,
    _owner: shekyl_hasher::Owner,
}

/// Start a hasher over a budget of `permits`.
///
/// # Panics
///
/// `permits` is zero, or the builder thread does not start.
#[must_use]
pub fn own_hasher(permits: usize) -> OwnHasher {
    let budget =
        shekyl_hash_budget::Budget::new(NonZeroUsize::new(permits).expect("non-zero permits"));
    let (hasher, owner) = shekyl_hasher::Hasher::start(budget).expect("the builder thread starts");
    let metrics = Arc::new(shekyl_chain_ingest::Metrics::new());
    OwnHasher {
        pow: ProductionPow::new(hasher.clone(), Arc::clone(&metrics)),
        hasher,
        metrics,
        _owner: owner,
    }
}

/// The seeds a hasher's `resident` watch shows once it is quiet: every
/// cache warm, and nothing changing for a third of a second.
///
/// # Panics
///
/// The hasher did not settle within two minutes.
#[must_use]
pub fn quiet_seeds(
    resident: &tokio::sync::watch::Receiver<shekyl_hasher::Resident>,
) -> std::collections::BTreeSet<[u8; 32]> {
    use std::time::{Duration, Instant};
    let started = Instant::now();
    let mut stable: Option<(shekyl_hasher::Resident, Instant)> = None;
    loop {
        let now = resident.borrow().clone();
        let warm = now
            .caches
            .iter()
            .all(|(_, state)| *state == shekyl_hasher::Residency::Warm);
        match &stable {
            Some((held, since)) if warm && *held == now => {
                if since.elapsed() >= Duration::from_millis(300) {
                    return now
                        .caches
                        .iter()
                        .map(|(seed, _)| *seed.as_bytes())
                        .collect();
                }
            }
            _ => stable = warm.then(|| (now.clone(), Instant::now())),
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "the hasher never went quiet: {now:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// HA-R5 on a node's production path: once the hasher behind `resident`
/// is quiet it holds exactly the caches a fresh hasher fed `list` reaches.
/// The fresh one is started here and derives each listed seed. Blocking.
///
/// # Panics
///
/// The two differ.
pub fn assert_quiet_is_fresh(
    resident: &tokio::sync::watch::Receiver<shekyl_hasher::Resident>,
    list: Option<shekyl_hasher::Ranked>,
) {
    let fresh = own_hasher(2);
    if let Some(list) = list.clone() {
        fresh.hasher.rank(list);
    }
    let expected = quiet_seeds(&fresh.hasher.resident());
    let held = quiet_seeds(resident);
    assert_eq!(
        held, expected,
        "a quiet hasher holds what a fresh one fed the same list holds (HA-R5); the list: {list:?}"
    );
}

/// A real store with its ingest service running.
pub struct Chain {
    /// The store.
    pub store: Arc<ChainStore>,
    /// The service that alone writes it.
    pub service: Service<ProductionPow>,
    /// The rules it connects under.
    pub rules: ChainRules,
    /// This chain's own hasher, as each daemon has its own: its own cap
    /// and its own ranked list. After the service, so the service's jobs
    /// have ended before the hasher stops.
    pub own: OwnHasher,
    /// The header frontier a sync owner over this chain publishes, which
    /// the service's ranker reads. `None` is published by a chain with no
    /// owner.
    pub frontier: tokio::sync::watch::Sender<Option<shekyl_chain_ingest::service::Frontier>>,
    next_tag: AtomicU64,
    /// The store's directory: a fresh one under the system temp directory,
    /// removed with the store and the files beside it when this drops,
    /// after the service and the store above.
    _dir: tempfile::TempDir,
}

impl Chain {
    /// An empty store and its service. Call from inside a runtime.
    #[must_use]
    pub fn empty(tag: &str, rules: ChainRules, own: OwnHasher) -> Self {
        Self::empty_following(tag, rules, own, Follow::default())
    }

    /// An empty store and its service, with `follow` seated on the tip
    /// follower. Call from inside a runtime.
    #[must_use]
    pub fn empty_following(
        tag: &str,
        rules: ChainRules,
        own: OwnHasher,
        mut follow: Follow,
    ) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("shekyl-cs3-{tag}-"))
            .tempdir()
            .expect("the store's directory");
        let store = Arc::new(open_store(&dir.path().join("chain.redb"), rules));
        // The frontier channel exists before either service starts, as
        // the daemon's node makes it.
        let (frontier, listening) = tokio::sync::watch::channel(None);
        follow.frontier = Some(listening);
        // The boundary's sink, which the executor shares, as the daemon's
        // node wires it: the per-block profile's phases in one place.
        follow.metrics = Some(Arc::clone(&own.metrics));
        let service = Service::start(
            Arc::clone(&store),
            rules,
            Arc::new(own.pow.clone()),
            ServiceConfig {
                room: NonZeroUsize::new(64).expect("non-zero"),
            },
            follow,
        );
        Self {
            store,
            service,
            rules,
            own,
            frontier,
            next_tag: AtomicU64::new(1),
            _dir: dir,
        }
    }

    /// Connect `steps` from this node, in order.
    ///
    /// # Panics
    ///
    /// A block did not connect: the corpus is the chain these rules accept.
    pub async fn apply(&self, steps: &[Step]) {
        let door = self.service.door();
        for Step { block, bodies } in steps {
            let tag = ArrivalTag(self.next_tag.fetch_add(1, Ordering::Relaxed));
            let ticket = loop {
                match door.offer(Arrival {
                    tag,
                    origin: Origin::Local,
                    block: block.clone(),
                    bodies: bodies.clone(),
                    bundle_references: Vec::new(),
                    bundle_bodies: Vec::new(),
                }) {
                    Ok(ticket) => break ticket,
                    Err(_) => tokio::task::yield_now().await,
                }
            };
            let reply = ticket.reply().await.reply;
            assert!(
                matches!(reply, Reply::Connected { .. } | Reply::AlreadyHeld),
                "a corpus block did not connect: {reply:?}"
            );
        }
    }

    /// The main chain's block at `height`.
    ///
    /// # Panics
    ///
    /// The height is above the tip.
    #[must_use]
    pub fn block(&self, height: u64) -> Block {
        let snap = self.store.begin_read().expect("a read");
        match snap.block(BlockHeight::from_raw(height)).expect("a read") {
            AtHeight::Recorded(body) => body.block,
            AtHeight::AboveTip => panic!("height {height} is above the tip"),
        }
    }

    /// The main chain's tip: its block count and cumulative work.
    #[must_use]
    pub fn tip(&self) -> Option<(u64, u128, BlockHash)> {
        let snap = self.store.begin_read().expect("a read");
        let tip = snap.tip().expect("a read").recorded?;
        match snap.block_info(tip.height).expect("a read") {
            AtHeight::Recorded(info) => Some((
                tip.height.to_raw() + 1,
                info.cumulative_difficulty.to_raw(),
                tip.hash,
            )),
            AtHeight::AboveTip => None,
        }
    }

    /// Stop the service and remove the store.
    pub async fn stop(self) {
        let Self {
            store,
            service,
            own,
            frontier,
            rules,
            _dir: dir,
            ..
        } = self;
        // Whatever published the frontier has stopped: the service ranks
        // without one. Then HA-R5 on this node's production path
        // (`RANDOMX_CACHE_ACTOR.md` §8): once the hasher is quiet it holds
        // what a fresh one fed the store's list holds.
        drop(frontier);
        let list = {
            let snap = store.begin_read().expect("the store reads");
            shekyl_chain_ingest::service::ranked_on(&snap, rules, None).expect("the store ranks")
        };
        let resident = own.hasher.resident();
        tokio::task::spawn_blocking(move || assert_quiet_is_fresh(&resident, list))
            .await
            .expect("the quiet hasher holds what a fresh one holds (HA-R5)");
        let _stopped = service.stop().await;
        drop(store);
        drop(own);
        dir.close().expect("remove the store's directory");
    }
}

/// A header chain off `chain`'s block at `fork_at`, `count` headers long.
/// Each header is a stored block's with its parent, a timestamp one
/// second past its parent's, and a nonce of its own, so it is not that
/// block. At the corpus's target of 1 every nonce is a proof.
///
/// Returns the pow blobs and the hashes, in chain order.
#[must_use]
pub fn fork_headers(chain: &Chain, fork_at: u64, count: u64) -> Vec<(BlockHash, Vec<u8>)> {
    let (tip_count, _, _) = chain.tip().expect("a chain");
    let parent = chain.block(fork_at);
    let mut previous = parent.hash();
    let mut timestamp = parent.header.timestamp;
    let mut out = Vec::new();
    for offset in 1..=count {
        let template_height = (fork_at + offset).min(tip_count - 1);
        let mut block = chain.block(template_height);
        block.header.previous = previous;
        timestamp += 1;
        block.header.timestamp = timestamp;
        block.header.nonce = 0xF0F0_0000 | u32::try_from(offset).expect("a short fork");
        previous = block.hash();
        out.push((previous, block.pow_blob()));
    }
    out
}
