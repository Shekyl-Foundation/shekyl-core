// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The seeded generator the cross-check draws from.

use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// What every role's stream is derived from, with the role's byte appended.
pub const RNG_LABEL: &[u8] = b"shekyl rt-w8 cross-check rng v1";

/// A deterministic byte stream: SHAKE256 over [`RNG_LABEL`] and one role
/// byte, read from the start.
///
/// clatter takes its generator as a *type* and builds it with `Default`
/// inside each handshake, so the seed has to live in the type. `ROLE` is that
/// seed: two roles are two types and two independent streams. Draws of any
/// size read the same stream, so a 64-byte draw and two 32-byte draws see the
/// same bytes.
#[derive(Clone)]
pub struct SeededRng<const ROLE: u8> {
    reader: <Shake256 as ExtendableOutput>::Reader,
}

impl<const ROLE: u8> Default for SeededRng<ROLE> {
    fn default() -> Self {
        let mut hasher = Shake256::default();
        hasher.update(RNG_LABEL);
        hasher.update(&[ROLE]);
        Self {
            reader: hasher.finalize_xof(),
        }
    }
}

impl<const ROLE: u8> RngCore for SeededRng<ROLE> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Test generator only. The marker is what clatter's bound asks for; nothing
/// here is random.
impl<const ROLE: u8> CryptoRng for SeededRng<ROLE> {}
