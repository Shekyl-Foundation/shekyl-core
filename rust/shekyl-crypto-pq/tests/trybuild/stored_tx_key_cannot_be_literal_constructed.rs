// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Route 3 to a transaction key from chosen bytes: build its stored form
//! and open it (R-21). The stored form's field is private, so only
//! `TxKey::store` makes one in code; widening it turns this red. The field
//! comes in as a parameter, so the only error is the one this fixture is
//! about.

use shekyl_crypto_pq::tx_key::{StoredTxKey, TX_KEY_LEN};
use shekyl_heap_secret::HeapSecret;

pub fn forge(secret: HeapSecret<TX_KEY_LEN>) -> StoredTxKey {
    StoredTxKey(secret)
}

fn main() {}
