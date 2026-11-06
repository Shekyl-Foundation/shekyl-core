// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The production draw source: OS entropy, never `SplitMix64`.

use shekyl_draw_rng::RelayRng;

/// A CSPRNG reading OS entropy each draw, as the C++
/// `crypto::random_device` the inherited timers and scheduling used. The
/// deterministic `SplitMix64` is the measurement suite's and the tests'.
#[derive(Debug, Default, Clone, Copy)]
pub struct SecureRelayRng;

impl RelayRng for SecureRelayRng {
    fn next_u64(&mut self) -> u64 {
        use rand::RngCore;
        rand::rngs::OsRng.next_u64()
    }
}
