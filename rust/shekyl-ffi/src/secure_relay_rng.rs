// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Production CSPRNG for relay FFI seams — OS entropy, never SplitMix64.

use shekyl_relay_privacy::rng::RelayRng;

/// Production RNG: a CSPRNG reading OS entropy each draw, matching the C++
/// `crypto::random_device` the inherited timers and scheduling used — never the
/// deterministic `SplitMix64` the measurement suite draws from.
pub(crate) struct SecureRelayRng;

impl RelayRng for SecureRelayRng {
    fn next_u64(&mut self) -> u64 {
        use rand::RngCore;
        rand::rngs::OsRng.next_u64()
    }
}
