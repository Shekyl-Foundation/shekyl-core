// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one constructor for a daemon runtime (D5).
//!
//! Tokio's multi-thread builder, with no worker count, starts one worker
//! per core. That is the default this function exists to refuse. The
//! caller passes the measured budget. This crate does not contain a
//! count, a deadline, or a socket.
//!
//! `net` and `time` are enabled so the runtime can host sockets and
//! deadlines. The blocking-pool cap is still Tokio's default. D6's
//! measurement names that cap; this constructor does not invent it.
//!
//! The daemon-RPC and Tor-control call sites still build their own
//! runtimes. Moving them here is the follow-up. The clearnet connector
//! is the first caller that keeps one.

#![deny(unsafe_code)]

use std::io;
use std::num::NonZeroUsize;

use tokio::runtime::{Builder, Runtime};

/// Build one multi-thread runtime with exactly `workers` worker threads.
///
/// `thread_name` is how the pool is told apart from the others. An empty
/// name is a programming error: a pool with no name cannot be counted.
///
/// # Panics
///
/// Panics if `thread_name` is empty.
pub fn runtime(workers: NonZeroUsize, thread_name: &str) -> io::Result<Runtime> {
    assert!(!thread_name.is_empty(), "a runtime's threads carry a name");
    Builder::new_multi_thread()
        .worker_threads(workers.get())
        .thread_name(thread_name)
        .enable_all()
        .build()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::num::NonZeroUsize;

    use super::runtime;

    #[test]
    fn the_budget_is_the_worker_count() {
        let workers = NonZeroUsize::new(2).expect("2");
        let rt = runtime(workers, "sk-rt").expect("runtime");
        assert_eq!(rt.metrics().num_workers(), workers.get());
        let name = rt
            .block_on(async {
                tokio::spawn(async { std::thread::current().name().map(str::to_owned) }).await
            })
            .expect("worker");
        assert_eq!(name.as_deref(), Some("sk-rt"));
    }

    #[test]
    fn one_worker_is_one_thread() {
        let workers = NonZeroUsize::new(1).expect("1");
        let rt = runtime(workers, "sk-rt-1").expect("runtime");
        assert_eq!(rt.metrics().num_workers(), 1);
        let ids = rt.block_on(async {
            let mut tasks = Vec::new();
            for _ in 0..4 {
                tasks.push(tokio::spawn(async { std::thread::current().id() }));
            }
            let mut out = Vec::new();
            for task in tasks {
                out.push(task.await.expect("worker"));
            }
            out
        });
        let distinct: HashSet<_> = ids.iter().collect();
        assert_eq!(distinct.len(), 1);
    }

    #[test]
    #[should_panic(expected = "a runtime's threads carry a name")]
    fn a_runtime_without_a_name_is_not_built() {
        let workers = NonZeroUsize::new(1).expect("1");
        let _rt = runtime(workers, "");
    }
}
