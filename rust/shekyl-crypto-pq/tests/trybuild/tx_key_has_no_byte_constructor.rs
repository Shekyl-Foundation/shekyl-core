// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Route 1 to a transaction key from chosen bytes: an associated function
//! that takes them (R-21). There is none; the `.stderr` snapshot lists the
//! constructors there are, so a new one shows up here first.

use shekyl_crypto_pq::TxKey;

pub fn forge(bytes: [u8; 32]) -> TxKey {
    TxKey::from_bytes(bytes)
}

fn main() {}
