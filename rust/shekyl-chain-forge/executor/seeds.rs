// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Every seed a forged block draws, and the negative controls' swap.
//!
//! A [`Source`] is a row of `CHAIN_FORGE.md` §5.2 that draws randomness.
//! Each draws from `seed_for(plan_seed, role, index)`, its role its own and
//! its index a place the plan decides. A control names sources to swap: a
//! swapped source draws fresh bytes from the OS instead, every other source
//! as before, so a determinism check that stays green under a swap is a
//! check that never saw the source. A swapped draw is remembered by its
//! role and index for the rest of the run: one block's draw seed is read
//! twice (the coinbase commits to it, the bundle reveals it), and a seed
//! that changed between the two would break the chain rather than vary it.
//!
//! S6, the Ed25519 half of every hybrid signature, has no randomness of its
//! own (RFC 8032 signing is deterministic); it signs `inner ‖ σ_pq` and so
//! changes exactly when S5 does. It has no swap: S5's control shows it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use rand::RngCore as _;
use shekyl_archival_retention::{sign_bundle_commitment_seeded, BUNDLE_SIGNATURE_LEN};
use shekyl_chain_forge::{message_id, seed_for, seed_for_message, PlanSeed, Role};
use shekyl_chain_ingest::admitted_draws::WitnessDraws;
use shekyl_chain_ingest::emission_assembly::EmissionSeeds;
use shekyl_crypto_pq::fn_dsa_hybrid::{
    FnDsaHybridSecretKey, FnDsaHybridSignature, HybridEd25519FnDsa,
};
use shekyl_crypto_pq::CryptoError;
use shekyl_harness_spender::SpendSeeds;
use shekyl_network::envelope::Framed64;
use shekyl_types::BlockHeight;
use zeroize::Zeroizing;

/// A source of randomness that a forged block draws (`CHAIN_FORGE.md`
/// §5.2), by its row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// S1: the Bulletproofs+ range proof.
    S1,
    /// S2: a multi-input spend's pseudo-out blinds.
    S2,
    /// S3: the FCMP++ membership proof.
    S3,
    /// S4: the emission's backing proof.
    S4,
    /// S5: the ML-DSA half of every hybrid signature.
    S5,
    /// S7: the witness's draw commitment.
    S7,
    /// S8: the bundle's witness signature and its records' receipts.
    S8,
    /// S9: the shard fill's parallel spend building.
    S9,
}

impl Source {
    /// Every source a control can swap, in §5.2's order (S6 has nothing to
    /// swap; module docs).
    pub const ALL: [Self; 8] = [
        Self::S1,
        Self::S2,
        Self::S3,
        Self::S4,
        Self::S5,
        Self::S7,
        Self::S8,
        Self::S9,
    ];

    /// The row's name, `S1` … `S9`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::S1 => "S1",
            Self::S2 => "S2",
            Self::S3 => "S3",
            Self::S4 => "S4",
            Self::S5 => "S5",
            Self::S7 => "S7",
            Self::S8 => "S8",
            Self::S9 => "S9",
        }
    }

    /// The source named `name`.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|source| source.name() == name)
    }
}

/// A swapped index-bound draw, remembered by role and index.
type IndexDraws = BTreeMap<(Role, u64), [u8; 32]>;
/// A swapped message-bound draw, remembered by role and [`message_id`].
type MessageDraws = BTreeMap<(Role, [u8; 32]), [u8; 32]>;

/// The plan's seeds, with the sources a control swaps.
pub struct Seeds {
    plan: PlanSeed,
    swapped: BTreeSet<Source>,
    drawn: Mutex<IndexDraws>,
    /// A swapped message-bound draw, remembered by [`message_id`].
    drawn_message: Mutex<MessageDraws>,
}

impl Seeds {
    /// `plan`'s seeds, every source in `swapped` drawing from the OS.
    #[must_use]
    pub fn new(plan: PlanSeed, swapped: BTreeSet<Source>) -> Self {
        Self {
            plan,
            swapped,
            drawn: Mutex::new(BTreeMap::new()),
            drawn_message: Mutex::new(BTreeMap::new()),
        }
    }

    /// The seed `role` draws at `index` for `source`: the plan's, or once
    /// `source` is swapped, the OS's, the same for the rest of the run.
    pub fn pick(&self, source: Source, role: Role, index: u64) -> [u8; 32] {
        if !self.swapped.contains(&source) {
            return seed_for(&self.plan, role, index);
        }
        *self
            .drawn
            .lock()
            .expect("the swap's record is never poisoned")
            .entry((role, index))
            .or_insert_with(|| {
                let mut fresh = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut fresh);
                fresh
            })
    }

    /// [`pick`] for a draw [`seed_for_message`] names. A swapped source
    /// draws from the OS once per message, remembered by [`message_id`].
    pub fn pick_message(&self, source: Source, role: Role, message: &[u8]) -> [u8; 32] {
        if !self.swapped.contains(&source) {
            return seed_for_message(&self.plan, role, message);
        }
        let id = message_id(message);
        *self
            .drawn_message
            .lock()
            .expect("the swap's record is never poisoned")
            .entry((role, id))
            .or_insert_with(|| {
                let mut fresh = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut fresh);
                fresh
            })
    }

    /// A key the plan derives (no source: keys are derived, not drawn).
    pub fn key(&self, role: Role, index: u64) -> [u8; 32] {
        seed_for(&self.plan, role, index)
    }

    /// The seeds of the plan's `index`-th spend.
    #[must_use]
    pub fn spend(&self, index: u64) -> SpendSeeds {
        SpendSeeds::from_parts(
            self.pick(Source::S1, Role::Range, index),
            self.pick(Source::S2, Role::Blinds, index),
            self.pick(Source::S3, Role::Membership, index),
            self.pick(Source::S5, Role::Slots, index),
        )
    }

    /// A shard fill's `index`-th spend: the plan's seeds, or the OS's for
    /// all four draws when S9 is swapped (the fill's threads drawing for
    /// themselves, the hazard S9 names). Swapped or not it is a seeded
    /// spend, so its transaction key keeps the pin
    /// ([`SpendSeeds`]' presence selects it) and S9's control moves the
    /// chain only through the draws S9 names.
    #[must_use]
    pub fn fill_spend(&self, index: u64) -> SpendSeeds {
        if !self.swapped.contains(&Source::S9) {
            return self.spend(index);
        }
        SpendSeeds::from_parts(
            self.pick(Source::S9, Role::Range, index),
            self.pick(Source::S9, Role::Blinds, index),
            self.pick(Source::S9, Role::Membership, index),
            self.pick(Source::S9, Role::Slots, index),
        )
    }

    /// Persona `slot`'s master seed: 64 bytes, two derivations.
    #[must_use]
    pub fn persona_master(&self, slot: u32) -> [u8; 64] {
        let slot = u64::from(slot);
        let mut master = [0u8; 64];
        master[..32].copy_from_slice(&self.key(Role::PersonaKey, 2 * slot));
        master[32..].copy_from_slice(&self.key(Role::PersonaKey, 2 * slot + 1));
        master
    }

    /// Persona `slot`'s signing seed (S5).
    #[must_use]
    pub fn persona_signing(&self, slot: u32) -> [u8; 32] {
        self.pick(Source::S5, Role::PersonaSigning, u64::from(slot))
    }

    /// The witness key's two keygen seeds.
    #[must_use]
    pub fn witness_key(&self) -> ([u8; 32], [u8; 32]) {
        (self.key(Role::WitnessKey, 0), self.key(Role::WitnessKey, 1))
    }

    /// The `index`-th emission claim's transaction key.
    #[must_use]
    pub fn claim_tx_key(&self, index: u64) -> [u8; 32] {
        self.key(Role::TxKey, index)
    }

    /// The seeds of the plan's `index`-th emission claim, whose fee side is
    /// the plan's `spend`-th spend.
    #[must_use]
    pub fn claim(&self, index: u64, spend: u64) -> EmissionSeeds {
        EmissionSeeds {
            proofs: shekyl_tx_builder::ProofSeeds {
                range: Zeroizing::new(self.pick(Source::S1, Role::Range, spend)),
                blinds: Zeroizing::new(self.pick(Source::S2, Role::Blinds, spend)),
                membership: Zeroizing::new(self.pick(Source::S3, Role::Membership, spend)),
            },
            backing: Zeroizing::new(self.pick(Source::S4, Role::Backing, index)),
            backing_auth: Zeroizing::new(self.pick(Source::S5, Role::BackingAuth, index)),
            fee_slots: Zeroizing::new(self.pick(Source::S5, Role::Slots, spend)),
            claim_auth: Zeroizing::new(self.pick(Source::S5, Role::ClaimAuth, index)),
            emission_slot: Zeroizing::new(self.pick(Source::S5, Role::EmissionSlot, index)),
        }
    }
}

/// The witness's draws from the plan: a block's draw seed (S7), its
/// bundle's witness signature and its records' receipts (S8).
pub struct PlanDraws(pub std::sync::Arc<Seeds>);

impl WitnessDraws for PlanDraws {
    fn draw_seed(&self, h: BlockHeight) -> [u8; 32] {
        self.0.pick(Source::S7, Role::DrawSeed, h.to_raw())
    }

    fn sign_bundle(
        &self,
        h: BlockHeight,
        secret: &FnDsaHybridSecretKey,
        commitment: &Framed64,
    ) -> Result<[u8; BUNDLE_SIGNATURE_LEN], CryptoError> {
        let seed = self.0.pick(Source::S8, Role::BundleWitness, h.to_raw());
        sign_bundle_commitment_seeded(secret, commitment, &seed)
    }

    fn sign_receipt(
        &self,
        h: BlockHeight,
        record: usize,
        secret: &FnDsaHybridSecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<FnDsaHybridSignature, CryptoError> {
        let record = u64::try_from(record).expect("a bundle's records fit u64");
        // A block's receipts take a block of indices of their own: a bundle
        // holds far fewer than 2^20 records.
        let index = (h.to_raw() << 20) | record;
        let seed = self.0.pick(Source::S8, Role::Receipt, index);
        HybridEd25519FnDsa.sign_with_rng_seed(secret, domain, message, &seed)
    }
}
