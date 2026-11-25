// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A group wallet's ceremony records: the body of `.wallet.multisig`
//! (`PayloadKind` `0x04`; `docs/PQC_MULTISIG.md` §13; R-30).
//!
//! It holds only what changes as a member takes part in ceremonies, and
//! nothing a restore could misuse: no nonce (R-20) and no key (the member's
//! keys are in `.wallet.keys`, R-30). Each record tolerates rollback, and
//! what a lost record costs is stated beside it:
//!
//! - **Input reservations** — intent hash → the inputs it spends, with the
//!   intent's reference block height so the reservation can expire. A
//!   member reserves an intent's inputs before it makes a nonce for it, so
//!   two of its own ceremonies never spend one input. Lost, two ceremonies
//!   can share an input; consensus's key image lets only one land.
//! - **The responder's approvals** — the intents this member approved as
//!   their responder. Lost, the responder's second visit for that intent is
//!   refused and the ceremony starts again.
//! - **Seen-seed fingerprints** — the one-way fingerprint of every intent
//!   seed this member has seen, never the seed. Lost, a malicious proposer
//!   can reuse a seed, which links two attempts and loses nothing.
//!
//! [`MULTISIG_STATE_VERSION`] ↔ `schemas/multisig_state.snap` (rule 42).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use shekyl_crypto_pq::multisig_intent::IntentSeedFingerprint;
use shekyl_types::{BlockHeight, GlobalOutputIndex};

use crate::error::WalletLedgerError;

/// Version of [`MultisigState`]'s layout. Bumps with
/// `schemas/multisig_state.snap`; a file of another version is refused, not
/// migrated (pre-genesis, rule 15).
pub const MULTISIG_STATE_VERSION: u32 = 1;

/// The inputs one intent spends at this member, until the intent lands or
/// ages out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, postcard_schema::Schema)]
pub struct Reservation {
    intent_hash: [u8; 32],
    inputs: Vec<GlobalOutputIndex>,
    reference_height: BlockHeight,
}

impl Reservation {
    /// The intent's hash.
    #[must_use]
    pub fn intent_hash(&self) -> &[u8; 32] {
        &self.intent_hash
    }
    /// The inputs the intent spends.
    #[must_use]
    pub fn inputs(&self) -> &[GlobalOutputIndex] {
        &self.inputs
    }
    /// The intent's reference block height.
    #[must_use]
    pub fn reference_height(&self) -> BlockHeight {
        self.reference_height
    }
}

/// Why an intent's inputs were not reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReserveError {
    /// Another of this member's live ceremonies already spends `input`.
    #[error("input {input} is spent by another live ceremony at this member")]
    ReservedElsewhere {
        /// The input's global output index.
        input: GlobalOutputIndex,
    },
    /// This intent is already reserved, and the call names different inputs
    /// or a different reference height. The stored reservation is unchanged.
    #[error(
        "this intent is already reserved with different inputs or a different reference height"
    )]
    ReservationDiffers,
}

/// The body of `.wallet.multisig` (module docs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, postcard_schema::Schema)]
pub struct MultisigState {
    /// Always [`MULTISIG_STATE_VERSION`] on construction; refused on load if
    /// it does not match.
    pub version: u32,
    reservations: Vec<Reservation>,
    responder_approvals: Vec<[u8; 32]>,
    seen_seeds: Vec<[u8; 32]>,
}

impl MultisigState {
    /// A group wallet's records before its first ceremony.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            version: MULTISIG_STATE_VERSION,
            reservations: Vec::new(),
            responder_approvals: Vec::new(),
            seen_seeds: Vec::new(),
        }
    }

    /// Serialize to postcard bytes.
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from postcard bytes produced by
    /// [`Self::to_postcard_bytes`]. The version is read and gated before
    /// the body is decoded.
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        crate::version_gate::gate_leading_version(bytes, "multisig state", MULTISIG_STATE_VERSION)?;
        Ok(postcard::from_bytes(bytes)?)
    }

    /// Version gate.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        crate::version_gate::gate_version(self.version, "multisig state", MULTISIG_STATE_VERSION)
    }

    /// Reserve `inputs` for the intent `intent_hash`, whose reference block
    /// is at `reference_height`. The input list is the intent's own order.
    /// Reserving that same intent again, with the same list and the same
    /// height, changes nothing.
    ///
    /// # Errors
    ///
    /// [`ReserveError::ReservedElsewhere`] when another intent holds one of
    /// the inputs, and [`ReserveError::ReservationDiffers`] when this intent
    /// is already reserved with a different list or height. Nothing is
    /// reserved in either case.
    pub fn reserve(
        &mut self,
        intent_hash: &[u8; 32],
        inputs: &[GlobalOutputIndex],
        reference_height: BlockHeight,
    ) -> Result<(), ReserveError> {
        if let Some(held) = self
            .reservations
            .iter()
            .find(|reservation| &reservation.intent_hash == intent_hash)
        {
            if held.inputs.as_slice() == inputs && held.reference_height == reference_height {
                return Ok(());
            }
            return Err(ReserveError::ReservationDiffers);
        }
        for reservation in &self.reservations {
            if let Some(&input) = inputs.iter().find(|i| reservation.inputs.contains(i)) {
                return Err(ReserveError::ReservedElsewhere { input });
            }
        }
        self.reservations.push(Reservation {
            intent_hash: *intent_hash,
            inputs: inputs.to_vec(),
            reference_height,
        });
        Ok(())
    }

    /// Release the reservation of `intent_hash`: its transaction landed, or
    /// it was abandoned. Returns whether there was one.
    pub fn release(&mut self, intent_hash: &[u8; 32]) -> bool {
        let before = self.reservations.len();
        self.reservations
            .retain(|reservation| &reservation.intent_hash != intent_hash);
        self.reservations.len() != before
    }

    /// Release every reservation whose reference block is below
    /// `oldest_live`: its intent can no longer land. Returns the released
    /// intents' hashes.
    pub fn release_aged(&mut self, oldest_live: BlockHeight) -> Vec<[u8; 32]> {
        let mut released = Vec::new();
        self.reservations.retain(|reservation| {
            let live = reservation.reference_height >= oldest_live;
            if !live {
                released.push(reservation.intent_hash);
            }
            live
        });
        released
    }

    /// The live reservations.
    #[must_use]
    pub fn reservations(&self) -> &[Reservation] {
        &self.reservations
    }

    /// Record that this member approved `intent_hash` as its responder.
    pub fn record_responder_approval(&mut self, intent_hash: &[u8; 32]) {
        if !self.responder_approved(intent_hash) {
            self.responder_approvals.push(*intent_hash);
        }
    }

    /// Whether this member approved `intent_hash` as its responder.
    #[must_use]
    pub fn responder_approved(&self, intent_hash: &[u8; 32]) -> bool {
        self.responder_approvals.contains(intent_hash)
    }

    /// Record that this member saw an intent seed with `fingerprint`.
    pub fn record_seen_seed(&mut self, fingerprint: &IntentSeedFingerprint) {
        if !self.has_seen_seed(fingerprint) {
            self.seen_seeds.push(*fingerprint.as_bytes());
        }
    }

    /// Whether this member saw an intent seed with `fingerprint`.
    #[must_use]
    pub fn has_seen_seed(&self, fingerprint: &IntentSeedFingerprint) -> bool {
        self.seen_seeds.contains(fingerprint.as_bytes())
    }

    /// Every seed fingerprint this member has seen.
    #[must_use]
    pub fn seen_seeds(&self) -> HashSet<IntentSeedFingerprint> {
        self.seen_seeds
            .iter()
            .map(IntentSeedFingerprint::from_recorded)
            .collect()
    }
}

#[cfg(test)]
#[path = "multisig_state_tests.rs"]
mod tests;
