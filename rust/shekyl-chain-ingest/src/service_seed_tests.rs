// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Branches that pass their own seed point (B2, design review 2026-10-19).
//!
//! Heights 1..=2112 hash under genesis's id. From 2113 a block hashes under
//! the block at 2048 on its own chain (CEN-D3: epoch 2048, lag 64). A
//! branch that forks below 2048 and grows past 2113 names its own block at
//! 2048, a seed no main-chain window holds. The service prepares that seed
//! into the transient slot, never pins it, and hashes with the cache the
//! preparation returned, one branch form at a time.
//!
//! The chains are mined once per test binary (about four minutes, the
//! three drivers in parallel) and each test runs its own service over them.

use std::sync::Arc;

use super::service_tests::{arrival, offer_all, service, Gated};
use super::{Reply, ServiceConfig};
use crate::scenario::{Mined, Scenario};
use crate::test_support::cleanup;

/// The shared prefix: blocks 0..=2039. Every branch's fork root is 2039,
/// below the seed block at 2048.
const PREFIX: u64 = 2040;
/// The main chain's branch: 2040..=2139.
const MAIN: u64 = 100;
/// z: 2040..=2140, one block heavier than the main chain at its tip.
const Z: u64 = 101;
/// w: 2040..=2129.
const W: u64 = 90;
/// The first height that hashes under the block at 2048.
const PAST_SEED: u64 = 2113;

/// The chains: a prefix and three branches that differ from 2040 on.
struct Branches {
    prefix: Vec<Mined>,
    main: Vec<Mined>,
    z: Vec<Mined>,
    w: Vec<Mined>,
}

static BRANCHES: tokio::sync::OnceCell<Branches> = tokio::sync::OnceCell::const_new();

/// Mine the chains once. `idle` ticks a driver's clock, so z and w build
/// blocks of their own from the first block after the prefix.
async fn branches() -> &'static Branches {
    BRANCHES
        .get_or_init(|| async {
            let mut main = Scenario::open("seed-point-main");
            let mut z = Scenario::open("seed-point-z");
            let mut w = Scenario::open("seed-point-w");
            let (prefix, _, _) = tokio::join!(main.mine(PREFIX), z.mine(PREFIX), w.mine(PREFIX));
            z.idle();
            w.idle();
            w.idle();
            let (main_branch, z_branch, w_branch) =
                tokio::join!(main.mine(MAIN), z.mine(Z), w.mine(W));
            for s in [main, z, w] {
                s.close().await;
            }
            assert_ne!(main_branch[8].hash, z_branch[8].hash, "z is its own branch");
            assert_ne!(z_branch[8].hash, w_branch[8].hash, "w is its own branch");
            Branches {
                prefix,
                main: main_branch,
                z: z_branch,
                w: w_branch,
            }
        })
        .await
}

/// The blocks of `branch` from height `from` up to, not including, `to`.
fn between(branch: &[Mined], from: u64, to: u64) -> &[Mined] {
    let first = usize::try_from(from - PREFIX).expect("an index");
    let end = usize::try_from(to - PREFIX).expect("an index");
    &branch[first..end]
}

/// The seed block at 2048 on `branch`.
fn seed_block(branch: &[Mined]) -> shekyl_types::BlockHash {
    between(branch, 2048, 2049)[0].hash
}

/// A service holding the prefix and the main branch, and its substrate.
async fn on_main(
    name: &str,
    chains: &Branches,
) -> (super::Service<Gated>, std::path::PathBuf, Arc<Gated>) {
    let substrate = Arc::new(Gated::new());
    let (service, path) = service(name, Arc::clone(&substrate), ServiceConfig::default());
    let door = service.door();
    offer_all(&door, 1, &chains.prefix).await;
    let replies = offer_all(&door, 1, &chains.main).await;
    assert!(
        replies.iter().all(|r| matches!(r, Reply::Connected { .. })),
        "the main branch connects"
    );
    (service, path, substrate)
}

/// The partition case: two nodes split across a seed point, and the
/// heavier side passes `S + 64`. The lighter node follows it: it stores the
/// branch past its own seed point, switches when it is heavier, and once
/// the follower has run the branch's seed block is canonical.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_heavier_branch_past_its_own_seed_point_is_followed() {
    let chains = branches().await;
    let (service, path, substrate) = on_main("seed-point-follow", chains).await;
    let replies = offer_all(&service.door(), 2, &chains.z).await;
    let past: Vec<_> = chains
        .z
        .iter()
        .zip(&replies)
        .filter(|(m, _)| m.height.to_raw() >= PAST_SEED)
        .collect();
    for (mined, reply) in &past[..past.len() - 1] {
        assert!(
            matches!(reply, Reply::Held { .. }),
            "{} past its seed point is stored: {reply:?}",
            mined.height.to_raw()
        );
    }
    let (last, switched) = past.last().expect("z passes its seed point");
    assert!(
        matches!(switched, Reply::Switched { .. }),
        "the heavier branch is followed at {}: {switched:?}",
        last.height.to_raw()
    );
    let mut tips = service.watch_tip().await.expect("watch");
    let seq = tips.borrow_and_update().seq;
    service
        .followed()
        .wait_for(|at| *at >= seq)
        .await
        .expect("following");
    assert_eq!(
        substrate.canonical(),
        Some(seed_block(&chains.z)),
        "after the switch the branch's seed block is canonical"
    );
    service.stop().await.expect("stops");
    cleanup(&path);
}

/// Store z and w up to their seed points, where both still hash under
/// genesis's id.
async fn up_to_the_seed_point(service: &super::Service<Gated>, chains: &Branches) {
    for (session, branch) in [(2, &chains.z), (3, &chains.w)] {
        let replies = offer_all(&service.door(), session, between(branch, PREFIX, PAST_SEED)).await;
        assert!(
            replies.iter().all(|r| matches!(r, Reply::Held { .. })),
            "{replies:?}"
        );
    }
}

/// An in-cap block naming its own branch's seed costs one derivation, into
/// the transient slot, with the chain's seed still canonical and nothing
/// pinned. Two branches alternating cost one derivation per alternation:
/// each evicts the other's seed from the one transient slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_branches_alternating_derive_once_per_alternation() {
    let chains = branches().await;
    let (service, path, substrate) = on_main("seed-point-alternate", chains).await;
    up_to_the_seed_point(&service, chains).await;
    let canonical = substrate.canonical();
    assert_eq!(
        canonical,
        Some(seed_block(&chains.main)),
        "the main chain's seed"
    );
    let door = service.door();
    let (prepared, pins) = (substrate.prepared(), substrate.pins());
    let first = door
        .offer(arrival(
            500,
            2,
            &between(&chains.z, PAST_SEED, PAST_SEED + 1)[0],
        ))
        .expect("room")
        .reply()
        .await
        .reply;
    assert!(matches!(first, Reply::Held { .. }), "{first:?}");
    assert_eq!(substrate.prepared(), prepared + 1, "exactly one derivation");
    assert_eq!(substrate.pins(), pins, "nothing pinned");
    assert_eq!(
        substrate.canonical(),
        canonical,
        "the chain's seed stays canonical"
    );
    // Then w, z, w, … : each switch of branch evicts the other's seed.
    // w at 2113, z at 2114, w at 2114, z at 2115, …
    let mut order = Vec::new();
    for height in PAST_SEED..PAST_SEED + 4 {
        order.push((600 + height, &chains.w, height));
        order.push((700 + height, &chains.z, height + 1));
    }
    let mut alternations = 0;
    for (tag, branch, height) in order {
        {
            let block = &between(branch, height, height + 1)[0];
            let reply = door
                .offer(arrival(tag, 4, block))
                .expect("room")
                .reply()
                .await
                .reply;
            assert!(matches!(reply, Reply::Held { .. }), "{height}: {reply:?}");
            alternations += 1;
        }
    }
    assert_eq!(
        substrate.prepared(),
        prepared + 1 + alternations,
        "one derivation per alternation"
    );
    assert_eq!(substrate.pins(), pins, "branch seeds are never pinned");
    service.stop().await.expect("stops");
    cleanup(&path);
}

/// Two branches past their seed points arriving at once: their forms run
/// one at a time on the branch gate, so at most one cache beyond the two
/// slots is ever held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn branch_forms_run_one_at_a_time() {
    let chains = branches().await;
    let (service, path, substrate) = on_main("seed-point-one", chains).await;
    up_to_the_seed_point(&service, chains).await;
    let door = service.door();
    let (z, w) = tokio::join!(
        offer_all(&door, 2, between(&chains.z, PAST_SEED, PAST_SEED + 8)),
        offer_all(&door, 3, between(&chains.w, PAST_SEED, PAST_SEED + 8)),
    );
    assert!(
        z.iter().chain(&w).all(|r| matches!(r, Reply::Held { .. })),
        "{z:?} {w:?}"
    );
    assert_eq!(substrate.branch_forms_max(), 1, "one branch form at a time");
    service.stop().await.expect("stops");
    cleanup(&path);
}
