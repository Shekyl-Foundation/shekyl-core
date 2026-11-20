// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A job cannot store its `Loan` where it outlives the job.

use std::sync::atomic::AtomicBool;

use shekyl_hasher::{Class, Hasher, Loan};

#[allow(dead_code)]
fn job(hasher: &Hasher, seed: shekyl_pow_randomx::Seedhash, stop: &AtomicBool) {
    let mut kept: Option<&Loan<'_>> = None;
    hasher.lend(Class::Chain, seed, stop, |loan| {
        kept = Some(loan);
    });
    drop(kept);
}

fn main() {}
