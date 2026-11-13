// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A `Lent` is not `Clone`: a copy would be a second handle on the cache.

use std::sync::atomic::AtomicBool;

use shekyl_hasher::{Class, Hasher, Lent};

#[allow(dead_code)]
fn job(hasher: &Hasher, seed: shekyl_pow_randomx::Seedhash, stop: &AtomicBool) {
    hasher.run(Class::Chain, seed, stop, |lent| {
        let _copy: Lent<'_> = Clone::clone(lent);
    });
}

fn main() {}
