// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! When a hasher is quiet, and whether that is what a fresh one would hold
//! (`RANDOMX_CACHE_ACTOR.md` §8, HA-R5).
//!
//! The production path checks this after the writes that ranked it: the
//! scenario driver at close, and each loopback chain at stop. The check
//! does not rank. A caller that forgot to send the list fails it.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::thread;
use std::time::{Duration, Instant};

use shekyl_hash_budget::Budget;
use tokio::sync::watch::Receiver;

use crate::{Hasher, Ranked, Residency, Resident};

/// How long every cache must sit warm and unchanged before the watch is quiet.
const SETTLED_FOR: Duration = Duration::from_millis(300);

/// How often the check reads the watch while it waits for [`SETTLED_FOR`].
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// How long the check waits. Past this the hasher is not coming to rest,
/// and the check panics with what it holds.
const SETTLE_LIMIT: Duration = Duration::from_secs(120);

/// The seeds `resident` shows once it is quiet: every cache warm, and
/// nothing changing for [`SETTLED_FOR`]. A build or a lease in flight is
/// waited out.
///
/// # Panics
///
/// The watch does not settle within [`SETTLE_LIMIT`].
#[must_use]
pub fn seeds(resident: &Receiver<Resident>) -> BTreeSet<[u8; 32]> {
    let started = Instant::now();
    let mut stable: Option<(Resident, Instant)> = None;
    loop {
        let now = resident.borrow().clone();
        let warm = now
            .caches
            .iter()
            .all(|(_, state)| *state == Residency::Warm);
        match &stable {
            Some((held, since)) if warm && *held == now => {
                if since.elapsed() >= SETTLED_FOR {
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
            started.elapsed() < SETTLE_LIMIT,
            "the hasher never went quiet: {now:?}"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

/// Once `resident` is quiet it holds exactly the caches a fresh hasher fed
/// `list` reaches. The fresh one derives each listed seed and hashes
/// nothing, so it runs on the smallest budget. The permit count is not
/// what the check compares.
///
/// # Panics
///
/// The two differ, either side never settles, or the fresh hasher's
/// builder thread does not start.
pub fn assert_matches_fresh(resident: &Receiver<Resident>, list: Option<&Ranked>) {
    // Held to the end: dropping the owner stops the hasher, and the fresh
    // side is still settling while [`seeds`] reads it.
    let (fresh, _owner) =
        Hasher::start(Budget::new(NonZeroUsize::MIN)).expect("the builder thread starts");
    if let Some(list) = list {
        fresh.rank(list.clone());
    }
    let expected = seeds(&fresh.resident());
    let held = seeds(resident);
    assert_eq!(
        held, expected,
        "a quiet hasher holds what a fresh one fed the same list holds (HA-R5); the list: {list:?}"
    );
}
