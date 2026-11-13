// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The scenario driver's persona (DRS-E4 commit 4,
//! `DRS_E4_ARCHIVAL_WRITER.md` §6 row 4), whose bond posts ride the
//! driver's real spend.
//!
//! The persona and its posts are [`shekyl_harness_spender::Persona`]'s
//! (that module's docs say what is real about them). They lived here until
//! CEN-J27 (`CHAIN_RULES_SLICE_6.md` §5 row 6) judged a bond post's funding
//! spend as CEN-I13/I15 judge a regular one: the store's tests then needed
//! a real join as much as the driver did, and the store cannot dev-depend
//! on the ingest. This module keeps the driver's [`Persona`] as a
//! [`Deref`] over the spender's, so every call site reads as before.

use core::ops::Deref;

pub use shekyl_harness_spender::{complete_tree, shard_set};

/// An archival persona: the keys a wallet derives for a slot, and the
/// posts and the credit it makes with them.
pub struct Persona(shekyl_harness_spender::Persona);

impl Deref for Persona {
    type Target = shekyl_harness_spender::Persona;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Persona {
    /// Derive the persona at `p_slot` from the harness's master seed.
    pub fn at(p_slot: u32) -> Self {
        Self(shekyl_harness_spender::Persona::at(p_slot))
    }
}
