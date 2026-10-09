// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Archival bodies for the scenario driver (DRS-E4 commit 4,
//! `DRS_E4_ARCHIVAL_WRITER.md` §6 row 4): a persona whose bond posts ride
//! the driver's real spend, and the serve credit it responds with.
//!
//! The persona and its posts are [`shekyl_harness_spender::Persona`]'s
//! (that module's docs say what is real about them). They lived here until
//! CEN-J27 (`CHAIN_RULES_SLICE_6.md` §5 row 6) judged a bond post's funding
//! spend as CEN-I13/I15 judge a regular one: the store's tests then needed
//! a real join as much as the driver did, and the store cannot dev-depend
//! on the ingest. This module keeps the driver's [`Persona`] as a
//! [`Deref`] over the spender's — every call site reads as before — and
//! adds the one body that is not a spend: the serve credit.
//!
//! What is not the subject: a serve credit's Ed25519 countersignature —
//! the vin's docs ([`shekyl_harness_spender::Persona::serve_credit_vin`])
//! say why its bytes are a marker, and the body around it is the rules
//! harness's H20 shape (`fixture::serve_credit_only_with`), whose pruned
//! record is likewise a marker until CEN-J10 lands.

use core::ops::Deref;

use shekyl_chain_rules::harness::fixture;
use shekyl_wire::Transaction;

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

    /// The serve-credit-only transaction (CEN-H20's shape, with its `RF-D1`
    /// prunable region) crediting this persona for `shard` in
    /// `settlement_epoch`: the spender's vin in the rules harness's body.
    pub fn serve_credit(&self, shard: u64, settlement_epoch: u64) -> Transaction {
        fixture::serve_credit_only_with(self.serve_credit_vin(shard, settlement_epoch))
    }
}
