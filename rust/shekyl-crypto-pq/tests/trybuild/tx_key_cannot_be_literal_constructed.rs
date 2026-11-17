// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Route 2 to a transaction key from chosen bytes: a struct literal (R-21).
//! Its fields are private; widening one turns this red. The fields come in
//! as parameters, so the only error is the one this fixture is about.

use curve25519_dalek::edwards::EdwardsPoint;
use shekyl_crypto_pq::tx_key::TX_KEY_LEN;
use shekyl_crypto_pq::TxKey;
use shekyl_heap_secret::HeapSecret;

pub fn forge(secret: HeapSecret<TX_KEY_LEN>, public: EdwardsPoint) -> TxKey {
    TxKey {
        secret,
        public,
    }
}

fn main() {}
