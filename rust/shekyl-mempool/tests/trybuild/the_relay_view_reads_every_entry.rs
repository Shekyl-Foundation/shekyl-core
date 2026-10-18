// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// The positive control: the same reads through `RelayView` compile.
fn reads(pool: &shekyl_mempool::Pool, txid: &shekyl_types::TxHash) {
    let view = pool.relay_view();
    let _ = view.record(txid);
    let _ = view.key_images();
    let _ = view.len();
}

fn main() {}
