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
use shekyl_types::BlockHash;

use super::service_tests::{arrival, offer_all, service, Gated, Running};
use super::{Reply, Service, ServiceConfig};
use crate::scenario::{Mined, Scenario};

/// Blocks the fork sits below the seed. Each branch then mines its own
/// seed block; the prefix stops on the shared fork root.
const LEAD_IN: u64 = 8;

/// Blocks `0..PREFIX`. The tip of this span is the fork root.
const PREFIX: u64 = SEEDHASH_EPOCH_BLOCKS - LEAD_IN;

/// The first height whose seed is the block at [`SEEDHASH_EPOCH_BLOCKS`].
/// [`seedheight`] still returns genesis through `blocks + lag`.
const PAST_SEED: u64 = first_own_seed_height();

/// Blocks of each branch offered together, past the seed.
const TOGETHER: u64 = 8;

/// Alternation steps once both branches have reached the seed. Step `i`
/// offers w at `PAST_SEED + i` and z at the next height.
const ALTERNATION_STEPS: u64 = 4;

/// Blocks w keeps past the higher window, and blocks main keeps past w.
/// w stays lighter than main. z is one block longer than main, so it
/// becomes heavier only at its tip.
const W_MARGIN: u64 = 9;
const MAIN_MARGIN: u64 = 10;

/// w: long enough for every window, shorter than main.
const W: u64 = blocks_through(window_top()) + W_MARGIN;
/// The main chain after the prefix. Its tip is past the seed.
const MAIN: u64 = W + MAIN_MARGIN;
/// z: one block longer than main.
const Z: u64 = MAIN + 1;

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

const fn first_own_seed_height() -> u64 {
    let mut height = SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG;
    while seedheight(height, SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG) != SEEDHASH_EPOCH_BLOCKS {
        height += 1;
    }
    height
}

/// The later of the two windows' last heights: w's last alternation step,
/// or the last block of the joint offer.
const fn window_top() -> u64 {
    let alternation = PAST_SEED + ALTERNATION_STEPS - 1;
    let together = PAST_SEED + TOGETHER - 1;
    if alternation > together {
        alternation
    } else {
        together
    }
}

/// How many branch blocks it takes to reach `height` inclusive. Branch
/// block 0 is at height [`PREFIX`].
const fn blocks_through(height: u64) -> u64 {
    height - PREFIX + 1
}

/// Tip height of a branch that mined `len` blocks after the prefix.
const fn branch_tip(len: u64) -> u64 {
    PREFIX - 1 + len
}

const _: () = {
    assert!(LEAD_IN > 0, "the seed block belongs to the branch");
    assert!(TOGETHER > 0, "the joint offer is a span");
    assert!(ALTERNATION_STEPS > 0, "the alternation takes a step");
    assert!(MAIN_MARGIN > 0, "main stays ahead of w");
    assert!(window_top() >= PREFIX, "the windows sit on the branch");
    assert!(W < MAIN, "w stays lighter than main");
    assert!(Z == MAIN + 1, "z becomes heavier only at its tip");
    assert!(branch_tip(MAIN) >= PAST_SEED, "main passes the seed");
    assert!(
        branch_tip(W) >= PAST_SEED + TOGETHER - 1,
        "w covers the joint offer"
    );
    assert!(
        branch_tip(W) >= PAST_SEED + ALTERNATION_STEPS - 1,
        "w covers its alternation steps"
    );
    assert!(
        branch_tip(Z) >= PAST_SEED + ALTERNATION_STEPS,
        "z covers the height one past each alternation step"
    );
    assert!(
        branch_tip(Z) >= PAST_SEED + TOGETHER - 1,
        "z covers the joint offer"
    );
    assert!(
        seedheight(PAST_SEED, SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG) == SEEDHASH_EPOCH_BLOCKS,
        "PAST_SEED hashes under the branch's own seed"
    );
    assert!(
        seedheight(PAST_SEED - 1, SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG) == 0,
        "the height before PAST_SEED still hashes under genesis"
    );
    assert!(
        Z_STEP_TAG > W_STEP_TAG + ALTERNATION_STEPS,
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
        let door = service.door();
        offer_all(&door, MAIN_SESSION, &chains.prefix).await;
        let replies = offer_all(&door, MAIN_SESSION, &chains.main).await;
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
        let replies = offer_all(&service.door(), Z_SESSION, &chains.z).await;
        let past: Vec<_> = chains
            .z
            .iter()
            .zip(&replies)
            .filter(|(mined, _)| mined.height.to_raw() >= PAST_SEED)
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
            let replies =
                offer_all(&service.door(), session, between(branch, PREFIX, PAST_SEED)).await;
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
        let mut order = Vec::new();
        for step in 0..ALTERNATION_STEPS {
            let height = PAST_SEED + step;
            order.push((W_STEP_TAG + height, &chains.w, height));
            order.push((Z_STEP_TAG + height, &chains.z, height + 1));
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
        let door = service.door();
        let (z, w) = tokio::join!(
            offer_all(
                &door,
                Z_SESSION,
                between(&chains.z, PAST_SEED, PAST_SEED + TOGETHER)
            ),
            offer_all(
                &door,
                W_SESSION,
                between(&chains.w, PAST_SEED, PAST_SEED + TOGETHER)
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
    let (prefix, _, _) = tokio::join!(main.mine(PREFIX), z.mine(PREFIX), w.mine(PREFIX));
    z.idle();
    w.idle();
    w.idle();
    let (main_branch, z_branch, w_branch) = tokio::join!(main.mine(MAIN), z.mine(Z), w.mine(W));
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

/// The blocks of `branch` from height `from` up to, not including, `to`.
fn between(branch: &[Mined], from: u64, to: u64) -> &[Mined] {
    let first = usize::try_from(from - PREFIX).expect("an index");
    let end = usize::try_from(to - PREFIX).expect("an index");
    &branch[first..end]
}

/// The block of `branch` at `height`.
fn block_at(branch: &[Mined], height: u64) -> &Mined {
    &between(branch, height, height + 1)[0]
}

/// The seed block at [`SEEDHASH_EPOCH_BLOCKS`] on `branch`.
fn seed_block(branch: &[Mined]) -> BlockHash {
    block_at(branch, SEEDHASH_EPOCH_BLOCKS).hash
}
