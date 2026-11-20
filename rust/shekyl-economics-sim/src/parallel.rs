// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Independent folds on every core.
//!
//! A sweep's cells share nothing while they fold, so they run on a pool of
//! scoped threads, each taking the next unclaimed item until none is left.
//! The results come back in the items' order, so a report printed from them
//! is the same whatever the thread count.

use std::num::NonZero;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Threads a pool starts when the platform cannot say how many cores it
/// has.
const FALLBACK_THREADS: usize = 4;

/// `job` of every item, on every core, in `items`' order.
pub(crate) fn map<I: Sync, T: Send>(items: &[I], job: impl Fn(&I) -> T + Sync) -> Vec<T> {
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<T>>> = items.iter().map(|_| Mutex::new(None)).collect();
    let threads = std::thread::available_parallelism()
        .map_or(FALLBACK_THREADS, NonZero::get)
        .min(items.len().max(1));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(index) else {
                    break;
                };
                let result = job(item);
                *slots[index].lock().expect("a slot is written once") = Some(result);
            });
        }
    });
    slots
        .into_iter()
        .map(|slot| {
            slot.into_inner()
                .expect("a slot is written once")
                .expect("every item ran")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The results are in the items' order, whichever thread ran each.
    #[test]
    fn results_come_back_in_the_items_order() {
        let items: Vec<u64> = (0..257).collect();
        assert_eq!(
            map(&items, |&n| n * n),
            items.iter().map(|n| n * n).collect::<Vec<_>>()
        );
        assert!(map(&[] as &[u64], |&n| n).is_empty());
    }
}
