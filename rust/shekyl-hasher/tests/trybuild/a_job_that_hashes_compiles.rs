// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The positive control: a job that hashes and returns the hash compiles.

use std::sync::atomic::AtomicBool;

use shekyl_hasher::{Class, Hasher};

#[allow(dead_code)]
fn job(hasher: &Hasher, seed: [u8; 32], stop: &AtomicBool) -> Option<[u8; 32]> {
    let seed = shekyl_pow_randomx::Seedhash::from_bytes(seed);
    hasher.run(Class::Chain, seed, stop, |lent| lent.hash(b"blob"))
}

fn main() {}
