// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The floor-device job's figure for the model (CS-Q11;
//! `.github/workflows/cs2-long-run.yml`): the owner's cost per header,
//! apart from RandomX, at the sizes the flat-cost test holds and at
//! 50,000 headers. `cargo test --lib` does not build it.
//!
//! The driver is the flat-cost test's (`scaling_tests`): a header sync
//! from one peer with every proof answered by a substrate whose hash
//! always passes, then a connect of every header, 64 at a time. Hashing is
//! the hash-rate figure's, in `shekyl-p2p-harness`'s long run.

// Whole-file test module. `lib.rs` gates it with
// `#[cfg(all(test, feature = "cs2-long-run"))]`, which the debug-macro
// lint cannot see, so the file declares the test half itself. The
// figures below are a test's output.
#![cfg(test)]

use crate::scaling_tests::{sync_then_connect, Cost};

fn line(phase: &str, cost: &Cost) -> String {
    let headers = u128::try_from(cost.headers).expect("a count");
    format!(
        "{phase} {}: {} reads and {} ns per header ({:?} in all)",
        cost.headers,
        u128::from(cost.reads) / headers,
        cost.handle.as_nanos() / headers,
        cost.handle
    )
}

#[test]
fn owner_cost_per_header() {
    for count in [5_000, 10_000, 20_000, 50_000] {
        let (headers, connect) = sync_then_connect(count);
        eprintln!("{}", line("headers", &headers));
        eprintln!("{}", line("connect", &connect));
    }
}
