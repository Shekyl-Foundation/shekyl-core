// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// S6 (the review of #1102): the pool's every-entry reads — the stem phase
// included — are not the pool's own surface outside the crate; they are
// `RelayView`'s, named for the one reader that may hold them.
fn reads(pool: &shekyl_mempool::Pool, txid: &shekyl_types::TxHash) {
    let _ = pool.record(txid);
    let _ = pool.key_images();
    let _ = pool.len();
}

fn main() {}
