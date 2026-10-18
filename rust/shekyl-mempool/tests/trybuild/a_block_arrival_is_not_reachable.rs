// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// S6 (the review of #1102): no caller outside the pool names a block
// arrival, so none can admit a peer's transaction as public and skip its
// embargo. `Arrival` is crate-private.
use shekyl_mempool::Arrival;

fn main() {
    let _ = Arrival::Carried;
}
