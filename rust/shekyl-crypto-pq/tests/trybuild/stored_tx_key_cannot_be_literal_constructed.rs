// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Route 3 to a transaction key from chosen bytes: build its stored form
//! and open it (R-21). The stored form's field is private, so only
//! `TxKey::store` makes one in code; widening it turns this red.

use shekyl_crypto_pq::tx_key::StoredTxKey;

pub fn forge() -> StoredTxKey {
    StoredTxKey(todo!())
}

fn main() {}
