// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Control: crypto-bigint 0.7.x `sub_mod` on U256, the entrypoint upstream's
// #1358 reported as a control-flow leak on x86_64 before the fix (0.7.5) and
// secure after it (0.7.6). If 0.7.5 does not come back insecure here, this
// setup cannot see the leak class and no other verdict in this run counts.
use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;
use crypto_bigint::{NonZero, U256};

fn inputs() -> (U256, U256, NonZero<U256>) {
    let mut private = PrivateRng::new();
    let mut public = PublicRng::new();
    let mut bytes = [0u8; 32];
    private.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    let a = U256::from_be_slice(&bytes);
    private.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    let b = U256::from_be_slice(&bytes);
    public.fill_bytes(&mut bytes);
    bytes[0] |= 0x80;
    let p = U256::from_be_slice(&bytes).to_nz().unwrap();
    (a, b, p)
}

#[checkct]
pub fn ctl_sub_mod_u256() {
    let (a, b, p) = inputs();
    black_box(a.sub_mod(&b, &p));
}

/// Positive control: a branch on a secret bit. If this does not come back
/// insecure, the pipeline is not seeing secret-dependent control flow at all.
#[inline(never)]
fn leaky(secret: u8) -> u32 {
    if secret & 1 == 1 {
        black_box(17)
    } else {
        black_box(23)
    }
}
#[checkct]
pub fn ctl_positive_leaky_branch() {
    let s = PrivateRng::new().next_u32() as u8;
    black_box(leaky(s));
}

/// Positive control, memory-access class: a table lookup indexed by a secret.
#[inline(never)]
fn leaky_lookup(secret: u8) -> u8 {
    static T: [u8; 256] = {
        let mut t = [0u8; 256];
        let mut i = 0;
        while i < 256 {
            t[i] = (i as u8).wrapping_mul(31);
            i += 1;
        }
        t
    };
    T[secret as usize]
}
#[checkct]
pub fn ctl_positive_leaky_lookup() {
    let s = PrivateRng::new().next_u32() as u8;
    black_box(leaky_lookup(s));
}
