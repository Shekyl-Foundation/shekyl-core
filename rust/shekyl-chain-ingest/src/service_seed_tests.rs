// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Branches that pass their own seed point (B2, design review 2026-10-19).
//!
//! Heights through `SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG` hash under
//! genesis's id. The next height hashes under the block at
//! `SEEDHASH_EPOCH_BLOCKS` on its own chain (CEN-D3). A branch that forks
//! below that block and grows past it names a seed no main-chain window
//! holds. The service prepares that seed into the transient slot, never
//! pins it, and hashes with the cache the preparation returned, one branch
//! form at a time.
//!
//! The file is one test. It mines the chains once — three drivers in
//! parallel — and then runs each [`Case`] in order, each on its own
//! service. nextest gives every test its own process, so another test
//! here would mine the same chains again. A failure carries its [`Case`].

use std::sync::Arc;

use shekyl_difficulty::{seedheight, SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, ChainCount};

use super::service_tests::{arrival, offer_all, service, Gated, Running};
use super::{Reply, Service, ServiceConfig};
use crate::scenario::{Mined, Scenario};

/// The seed block. [`SEEDHASH_EPOCH_BLOCKS`] is the epoch length; the seed
/// is the block at that ordinal.
const SEED: BlockHeight = BlockHeight::from_raw(SEEDHASH_EPOCH_BLOCKS);
/// The schedule's seed lag, as a span.
const LAG: BlockCount = BlockCount::from_raw(SEEDHASH_EPOCH_LAG);
/// How far below the seed the fork sits. The seed block is then the
/// branch's own.
const LEAD_IN: BlockCount = BlockCount::from_raw(8);

/// The shared chain. Its next height is the first block of every branch,
/// and its tip is the fork root. The two differ by one: the count is not
/// the ordinal.
const PREFIX: ChainCount = {
    let Some(first_branch) = SEED.checked_sub_count(LEAD_IN) else {
        panic!("the lead-in fits under the seed");
    };
    ChainCount::from_next_height(first_branch)
};

/// The first height whose seed is [`SEED`]. [`seedheight`] still returns
/// genesis through the epoch length plus the lag.
const PAST_SEED: BlockHeight = first_own_seed_height();

/// Blocks of each branch offered together, past the seed.
const TOGETHER: BlockCount = BlockCount::from_raw(8);
/// Alternation steps once both branches have reached the seed. Step `i`
/// offers w at `PAST_SEED + i` and z one block later.
const ALTERNATION_STEPS: BlockCount = BlockCount::from_raw(4);
/// Blocks w keeps past the higher window, and blocks main keeps past w.
/// w stays lighter than main. z is one block longer than main, so it
/// becomes heavier only at its tip.
const W_MARGIN: BlockCount = BlockCount::from_raw(9);
const MAIN_MARGIN: BlockCount = BlockCount::from_raw(10);

/// w: long enough for every window, shorter than main.
const W: BlockCount = add_count(blocks_through(window_top()), W_MARGIN);
/// The main chain after the prefix. Its tip is past the seed.
const MAIN: BlockCount = add_count(W, MAIN_MARGIN);
/// z: one block longer than main.
const Z: BlockCount = add_count(MAIN, BlockCount::ONE);

/// The session that connected the prefix and the main chain.
const MAIN_SESSION: u64 = 1;
/// z's arrivals.
const Z_SESSION: u64 = 2;
/// w's arrivals.
const W_SESSION: u64 = 3;
/// Single-block offers while the branches alternate. Distinct from the
/// spans that filled each branch up to the seed.
const ALTERNATION_SESSION: u64 = 4;

/// Tags for those single-block offers. `offer_all` numbers a session's
/// span from `session * 1_000`, and the sessions above start at 2, so
/// these tags sit in a different range.
const FIRST_PAST_SEED_TAG: u64 = 500;
const W_STEP_TAG: u64 = 600;
const Z_STEP_TAG: u64 = 700;

const fn add_count(count: BlockCount, more: BlockCount) -> BlockCount {
    let Some(sum) = count.checked_add(more) else {
        panic!("a branch length fits");
    };
    sum
}

const fn first_own_seed_height() -> BlockHeight {
    let mut height = SEED.saturating_add(LAG);
    while seedheight(height.to_raw(), SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG) != SEED.to_raw() {
        height = height.saturating_add(BlockCount::ONE);
    }
    height
}

/// The later of the two windows' last heights: w's last alternation step,
/// or the last block of the joint offer.
const fn window_top() -> BlockHeight {
    let alternation = PAST_SEED
        .saturating_add(ALTERNATION_STEPS)
        .saturating_sub_count(BlockCount::ONE);
    let together = PAST_SEED
        .saturating_add(TOGETHER)
        .saturating_sub_count(BlockCount::ONE);
    if alternation.to_raw() > together.to_raw() {
        alternation
    } else {
        together
    }
}

/// Branch blocks from the first block after the fork through `height`,
/// inclusive.
const fn blocks_through(height: BlockHeight) -> BlockCount {
    let Some(before) = height.checked_sub(PREFIX.next_height()) else {
        panic!("the height is on the branch");
    };
    let Some(count) = before.checked_add(BlockCount::ONE) else {
        panic!("the span of the branch fits");
    };
    count
}

/// Tip height of a branch that mined `len` blocks after the prefix.
const fn branch_tip(len: BlockCount) -> BlockHeight {
    let Some(fork) = PREFIX.tip() else {
        panic!("the prefix holds a block");
    };
    fork.saturating_add(len)
}

const _: () = {
    assert!(!LEAD_IN.is_zero(), "the seed block belongs to the branch");
    assert!(!TOGETHER.is_zero(), "the joint offer is a span");
    assert!(!ALTERNATION_STEPS.is_zero(), "the alternation takes a step");
    assert!(!MAIN_MARGIN.is_zero(), "main stays ahead of w");
    assert!(
        window_top().to_raw() >= PREFIX.next_height().to_raw(),
        "the windows sit on the branch"
    );
    assert!(W.to_raw() < MAIN.to_raw(), "w stays lighter than main");
    assert!(
        Z.to_raw() == MAIN.to_raw() + 1,
        "z becomes heavier only at its tip"
    );
    assert!(
        branch_tip(MAIN).to_raw() >= PAST_SEED.to_raw(),
        "main passes the seed"
    );
    assert!(
        branch_tip(W).to_raw() >= window_top().to_raw(),
        "w covers the higher window"
    );
    assert!(
        branch_tip(Z).to_raw() >= PAST_SEED.saturating_add(ALTERNATION_STEPS).to_raw(),
        "z covers the height one past each alternation step"
    );
    assert!(
        branch_tip(Z).to_raw() >= window_top().to_raw(),
        "z covers the higher window"
    );
    assert!(
        seedheight(
            PAST_SEED.to_raw(),
            SEEDHASH_EPOCH_BLOCKS,
            SEEDHASH_EPOCH_LAG
        ) == SEED.to_raw(),
        "PAST_SEED hashes under the branch's own seed"
    );
    let Some(before_seed) = PAST_SEED.checked_sub_count(BlockCount::ONE) else {
        panic!("PAST_SEED is not genesis");
    };
    assert!(
        seedheight(
            before_seed.to_raw(),
            SEEDHASH_EPOCH_BLOCKS,
            SEEDHASH_EPOCH_LAG
        ) == 0,
        "the height before PAST_SEED still hashes under genesis"
    );
    // The measured fixture. A derivation that moves one of these has
    // changed which blocks the scenarios mine.
    assert!(PREFIX.to_raw() == 2040);
    assert!(PAST_SEED.to_raw() == 2113);
    assert!(W.to_raw() == 90);
    assert!(MAIN.to_raw() == 100);
    assert!(Z.to_raw() == 101);
    assert!(
        Z_STEP_TAG > W_STEP_TAG + ALTERNATION_STEPS.to_raw(),
        "alternation tags do not collide"
    );
    assert!(
        W_STEP_TAG > FIRST_PAST_SEED_TAG,
        "the first past-seed tag sits below the alternation tags"
    );
};

/// The chains: a prefix and three branches that differ from the fork on.
struct Branches {
    prefix: Vec<Mined>,
    main: Vec<Mined>,
    z: Vec<Mined>,
    w: Vec<Mined>,
}

/// One scenario. The label is the store directory and the name a failure
/// of this scenario carries, so the two cannot drift apart.
#[derive(Clone, Copy, Debug)]
enum Case {
    /// The lighter node follows the heavier branch past its own seed.
    Follow,
    /// Two branches alternate through the one transient slot.
    Alternate,
    /// Two branches past their seeds arrive together.
    Concurrent,
}

impl Case {
    const fn label(self) -> &'static str {
        match self {
            Self::Follow => "seed-point-follow",
            Self::Alternate => "seed-point-alternate",
            Self::Concurrent => "seed-point-concurrent",
        }
    }

    async fn run(self, chains: &Branches) {
        match self {
            Self::Follow => self.follow(chains).await,
            Self::Alternate => self.alternate(chains).await,
            Self::Concurrent => self.concurrent(chains).await,
        }
    }

    /// A service on the prefix and the main chain, and its substrate.
    async fn open_on_main(self, chains: &Branches) -> (Running, Arc<Gated>) {
        let substrate = Arc::new(Gated::new());
        let service = service(
            self.label(),
            Arc::clone(&substrate),
            ServiceConfig::default(),
        );
        offer_all(&service, MAIN_SESSION, &chains.prefix).await;
        let replies = offer_all(&service, MAIN_SESSION, &chains.main).await;
        assert!(
            replies.iter().all(|r| matches!(r, Reply::Connected { .. })),
            "{self}: the main branch connects"
        );
        (service, substrate)
    }

    /// The partition case: two nodes split across a seed point, and the
    /// heavier side passes the seed lag. The lighter node follows it: it
    /// stores the branch past its own seed point, switches when it is
    /// heavier, and once the follower has run the branch's seed block is
    /// canonical.
    async fn follow(self, chains: &Branches) {
        let (service, substrate) = self.open_on_main(chains).await;
        let replies = offer_all(&service, Z_SESSION, &chains.z).await;
        let past: Vec<_> = chains
            .z
            .iter()
            .zip(&replies)
            .filter(|(mined, _)| mined.height >= PAST_SEED)
            .collect();
        let Some(last_index) = past.len().checked_sub(1) else {
            panic!("{self}: z passes its seed point");
        };
        for (mined, reply) in &past[..last_index] {
            assert!(
                matches!(reply, Reply::Held { .. }),
                "{self}: {height} past its seed point is stored: {reply:?}",
                height = mined.height.to_raw(),
            );
        }
        let (last, switched) = &past[last_index];
        assert!(
            matches!(switched, Reply::Switched { .. }),
            "{self}: the heavier branch is followed at {height}: {switched:?}",
            height = last.height.to_raw(),
        );
        let mut tips = claimed(self, "watch", service.watch_tip().await);
        let seq = tips.borrow_and_update().seq;
        claimed(
            self,
            "following",
            service.followed().wait_for(|at| *at >= seq).await,
        );
        assert_eq!(
            substrate.canonical(),
            Some(seed_block(&chains.z)),
            "{self}: after the switch the branch's seed block is canonical"
        );
        claimed(self, "stops", service.stop().await);
    }

    /// Store z and w up to their seed points, where both still hash under
    /// genesis's id.
    async fn up_to_the_seed_point(self, service: &Service<Gated>, chains: &Branches) {
        for (session, branch) in [(Z_SESSION, &chains.z), (W_SESSION, &chains.w)] {
            let replies = offer_all(
                service,
                session,
                between(branch, PREFIX.next_height(), PAST_SEED),
            )
            .await;
            assert!(
                replies.iter().all(|r| matches!(r, Reply::Held { .. })),
                "{self}: up to the seed point: {replies:?}"
            );
        }
    }

    /// An in-cap block naming its own branch's seed costs one derivation,
    /// into the transient slot, with the chain's seed still canonical and
    /// nothing pinned. Two branches alternating cost one derivation per
    /// alternation: each evicts the other's seed from the one transient slot.
    async fn alternate(self, chains: &Branches) {
        let (service, substrate) = self.open_on_main(chains).await;
        self.up_to_the_seed_point(&service, chains).await;
        let canonical = substrate.canonical();
        assert_eq!(
            canonical,
            Some(seed_block(&chains.main)),
            "{self}: the main chain's seed"
        );
        let door = service.door();
        let (prepared, pins) = (substrate.prepared(), substrate.pins());
        let first = claimed(
            self,
            "room",
            door.offer(arrival(
                FIRST_PAST_SEED_TAG,
                Z_SESSION,
                block_at(&chains.z, PAST_SEED),
            )),
        )
        .reply()
        .await
        .reply;
        assert!(
            matches!(first, Reply::Held { .. }),
            "{self}: the first block past the seed is held: {first:?}"
        );
        assert_eq!(
            substrate.prepared(),
            prepared + 1,
            "{self}: exactly one derivation"
        );
        assert_eq!(substrate.pins(), pins, "{self}: nothing pinned");
        assert_eq!(
            substrate.canonical(),
            canonical,
            "{self}: the chain's seed stays canonical"
        );
        // Then w, z, w, z, … : each switch of branch evicts the other's seed.
        // The tag names w's height on both offers. z's block is the next one.
        let mut order = Vec::new();
        let steps_end = PAST_SEED + ALTERNATION_STEPS;
        for height in PAST_SEED.ordinals_until(steps_end) {
            order.push((W_STEP_TAG + height.to_raw(), &chains.w, height));
            order.push((
                Z_STEP_TAG + height.to_raw(),
                &chains.z,
                height + BlockCount::ONE,
            ));
        }
        let mut alternations = 0;
        for (tag, branch, height) in order {
            let reply = claimed(
                self,
                "room",
                door.offer(arrival(tag, ALTERNATION_SESSION, block_at(branch, height))),
            )
            .reply()
            .await
            .reply;
            assert!(
                matches!(reply, Reply::Held { .. }),
                "{self}: {height} held: {reply:?}"
            );
            alternations += 1;
        }
        assert_eq!(
            substrate.prepared(),
            prepared + 1 + alternations,
            "{self}: one derivation per alternation"
        );
        assert_eq!(
            substrate.pins(),
            pins,
            "{self}: branch seeds are never pinned"
        );
        claimed(self, "stops", service.stop().await);
    }

    /// Two branches past their seed points arriving at once: their forms
    /// run one at a time on the branch gate, so at most one cache beyond
    /// the two slots is ever held.
    async fn concurrent(self, chains: &Branches) {
        let (service, substrate) = self.open_on_main(chains).await;
        self.up_to_the_seed_point(&service, chains).await;
        let together_end = PAST_SEED + TOGETHER;
        let (z, w) = tokio::join!(
            offer_all(
                &service,
                Z_SESSION,
                between(&chains.z, PAST_SEED, together_end)
            ),
            offer_all(
                &service,
                W_SESSION,
                between(&chains.w, PAST_SEED, together_end)
            ),
        );
        assert!(
            z.iter()
                .chain(&w)
                .all(|reply| matches!(reply, Reply::Held { .. })),
            "{self}: both branches held: {z:?} {w:?}"
        );
        assert_eq!(
            substrate.branch_forms_max(),
            1,
            "{self}: one branch form at a time"
        );
        claimed(self, "stops", service.stop().await);
    }
}

impl std::fmt::Display for Case {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Mine the chains. `idle` ticks a driver's clock, so z and w build
/// blocks of their own from the first block after the prefix.
async fn branches() -> Branches {
    let mut main = Scenario::open("seed-point-main");
    let mut z = Scenario::open("seed-point-z");
    let mut w = Scenario::open("seed-point-w");
    let prefix_len = PREFIX.to_raw();
    let (prefix, _, _) = tokio::join!(
        main.mine(prefix_len),
        z.mine(prefix_len),
        w.mine(prefix_len)
    );
    z.idle();
    w.idle();
    w.idle();
    let (main_branch, z_branch, w_branch) = tokio::join!(
        main.mine(MAIN.to_raw()),
        z.mine(Z.to_raw()),
        w.mine(W.to_raw())
    );
    for driver in [main, z, w] {
        driver.close().await;
    }
    assert_ne!(
        seed_block(&main_branch),
        seed_block(&z_branch),
        "z is its own branch"
    );
    assert_ne!(
        seed_block(&z_branch),
        seed_block(&w_branch),
        "w is its own branch"
    );
    Branches {
        prefix,
        main: main_branch,
        z: z_branch,
        w: w_branch,
    }
}

/// The three cases over one mining, in order: one service at a time.
///
/// Four workers: the three drivers mine together, and the fourth runs
/// the join.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn branches_past_their_seed_points() {
    let chains = branches().await;
    Case::Follow.run(&chains).await;
    Case::Alternate.run(&chains).await;
    Case::Concurrent.run(&chains).await;
}

/// `result`, or a panic that names `case` and `what`.
fn claimed<T, E: std::fmt::Debug>(case: Case, what: &str, result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(fault) => panic!("{case}: {what}: {fault:?}"),
    }
}

/// Where `height` sits in a branch mined after [`PREFIX`]. Index 0 is the
/// prefix's next height: the count and that ordinal are different
/// quantities that share a number.
fn index_on_branch(height: BlockHeight) -> usize {
    let start = PREFIX.next_height();
    let Some(span) = height.checked_sub(start) else {
        panic!("{height} is before the branch, which starts at {start}");
    };
    usize::try_from(span.to_raw()).unwrap_or_else(|_| panic!("{height} does not fit an index"))
}

/// The blocks of `branch` from height `from` up to, not including, `to`.
fn between(branch: &[Mined], from: BlockHeight, to: BlockHeight) -> &[Mined] {
    &branch[index_on_branch(from)..index_on_branch(to)]
}

/// The block of `branch` at `height`.
fn block_at(branch: &[Mined], height: BlockHeight) -> &Mined {
    let Some(block) = between(branch, height, height + BlockCount::ONE).first() else {
        panic!("no block at {height}");
    };
    block
}

/// The seed block at [`SEED`] on `branch`.
fn seed_block(branch: &[Mined]) -> BlockHash {
    block_at(branch, SEED).hash
}
