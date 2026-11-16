// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Route 2 to a transaction key from chosen bytes: a struct literal (R-21).
//! Its fields are private; widening one turns this red.

use shekyl_crypto_pq::TxKey;

pub fn forge() -> TxKey {
    TxKey {
        secret: todo!(),
        public: todo!(),
    }
}

fn main() {}
