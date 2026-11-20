// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A job cannot return its `Lent`: the `for<'job>` bound names no lifetime
//! the result could carry.

use std::sync::atomic::AtomicBool;

use shekyl_hasher::{Class, Hasher};

#[allow(dead_code)]
fn job(hasher: &Hasher, seed: shekyl_pow_randomx::Seedhash, stop: &AtomicBool) {
    let _escaped = hasher.run(Class::Chain, seed, stop, |lent| lent);
}

fn main() {}
