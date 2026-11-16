// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The forge's one seed derivation (`CHAIN_FORGE.md` §5.1).
//!
//! Every seed a forged chain's randomness comes from is
//! `seed_for(plan_seed, role, index)`: cSHAKE256 under
//! [`SEED_CUSTOMIZATION`] over `plan_seed ‖ role ‖ index_le8`, 32 bytes.
//! `plan_seed` is fixed at 32 bytes and `index` at 8, so the role's string,
//! between them, is never ambiguous. One [`Role`] per consumer of
//! randomness: two roles never share a stream, and adding a role does not
//! move another role's bytes. `index` is a position the plan decides (a
//! spend's place in the plan, a block's height), never a thread or a
//! counter that depends on scheduling.
//!
//! Each source of `CHAIN_FORGE.md` §5.2 that draws randomness has a role of
//! its own, so the determinism check's negative controls can swap one
//! source to the OS's randomness and leave every other source's bytes as
//! they were. These seeds are public by design: a forged chain is a
//! regtest chain whose plan, seed included, is committed.

use shekyl_crypto_hash::cshake256_32;

/// cSHAKE256's customization for [`seed_for`]. Registered as a test-only
/// row of `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv`: the forge is a
/// test-kind target and no shipped build links this crate.
pub const SEED_CUSTOMIZATION: &[u8] = b"shekyl/chain-forge/seed-v1";

/// A plan's 32-byte seed, written in the plan as 64 hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanSeed([u8; 32]);

/// Why a plan's seed did not parse.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SeedFault {
    /// Not 64 hex digits.
    #[error("a plan seed is 64 hex digits, not {0:?}")]
    NotHex(String),
}

impl PlanSeed {
    /// Wrap raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The seed `hex` writes: exactly 64 hex digits.
    ///
    /// # Errors
    ///
    /// [`SeedFault::NotHex`] for anything else.
    pub fn from_hex(hex: &str) -> Result<Self, SeedFault> {
        let bytes = hex::decode(hex).map_err(|_| SeedFault::NotHex(hex.to_owned()))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SeedFault::NotHex(hex.to_owned()))?;
        Ok(Self(bytes))
    }

    /// The seed as 64 lower-case hex digits.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Who draws from a stream. Each role's [`Role::name`] is fixed for good:
/// renaming one moves every seed it derives, which is a regeneration of
/// every forged chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// S1: a transaction's Bulletproofs+ range proof.
    Range,
    /// S2: a multi-input spend's pseudo-out blinds.
    Blinds,
    /// S3: a spend's FCMP++ membership proof.
    Membership,
    /// S4: an emission claim's backing proof.
    Backing,
    /// S5: the ML-DSA half of a spend's (or a claim's fee side's) PQC
    /// authorization slots.
    Slots,
    /// S5: the ML-DSA half of a persona's own signatures (its posts' bond
    /// slot, its claim's identity authorization).
    PersonaSigning,
    /// A persona's master seed (two indices per persona, 64 bytes): which
    /// persona is which key is the plan's, not a fixed constant's.
    PersonaKey,
    /// S7: the witness the driver commits each block's draws to: its key.
    WitnessKey,
    /// S7: a block's draw seed, revealed by its bundle.
    DrawSeed,
    /// S8: a bundle record's receipt signature.
    Receipt,
    /// S8: a bundle's witness signature.
    BundleWitness,
}

impl Role {
    /// Every role, in declaration order.
    pub const ALL: [Self; 11] = [
        Self::Range,
        Self::Blinds,
        Self::Membership,
        Self::Backing,
        Self::Slots,
        Self::PersonaSigning,
        Self::PersonaKey,
        Self::WitnessKey,
        Self::DrawSeed,
        Self::Receipt,
        Self::BundleWitness,
    ];

    /// The role's string in the derivation.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Range => "range",
            Self::Blinds => "blinds",
            Self::Membership => "membership",
            Self::Backing => "backing",
            Self::Slots => "slots",
            Self::PersonaSigning => "persona-signing",
            Self::PersonaKey => "persona-key",
            Self::WitnessKey => "witness-key",
            Self::DrawSeed => "draw-seed",
            Self::Receipt => "receipt",
            Self::BundleWitness => "bundle-witness",
        }
    }
}

/// `seed_for(plan_seed, role, index)` (`CHAIN_FORGE.md` §5.1).
#[must_use]
pub fn seed_for(plan: &PlanSeed, role: Role, index: u64) -> [u8; 32] {
    let name = role.name().as_bytes();
    let mut input = Vec::with_capacity(plan.0.len() + name.len() + 8);
    input.extend_from_slice(&plan.0);
    input.extend_from_slice(name);
    input.extend_from_slice(&index.to_le_bytes());
    cshake256_32(SEED_CUSTOMIZATION, &input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation's known answer: cSHAKE256 under the registered
    /// customization over `0x00..=0x1f ‖ "range" ‖ 7_le8`, first 32 bytes.
    /// Computed outside this code, by a pure-Python Keccak-f[1600] and
    /// SP 800-185's `bytepad`/`encode_string`, which reproduces NIST's
    /// cSHAKE256 sample #3 (the one `shekyl-crypto-hash` pins), and pinned
    /// here: a change to the encoding, the customization or the width moves
    /// every forged chain, and this is where that shows first.
    #[test]
    fn seed_for_is_its_known_answer() {
        let plan =
            PlanSeed::from_bytes(core::array::from_fn(|i| u8::try_from(i).expect("below 32")));
        assert_eq!(hex::encode(seed_for(&plan, Role::Range, 7)), KNOWN_ANSWER,);
    }

    const KNOWN_ANSWER: &str = "5872d648b06c0b9212ce30acccc074ec9b91e405fa14a76ee38cc049d7481006";

    /// Two roles never share a stream, nor two indices of one role.
    #[test]
    fn every_role_and_index_is_its_own_stream() {
        let plan = PlanSeed::from_bytes([0x42; 32]);
        let mut seen = std::collections::BTreeSet::new();
        for role in Role::ALL {
            for index in 0..4 {
                assert!(
                    seen.insert(seed_for(&plan, role, index)),
                    "{role:?} {index} repeats a stream"
                );
            }
        }
        let names: std::collections::BTreeSet<&str> = Role::ALL.iter().map(|r| r.name()).collect();
        assert_eq!(names.len(), Role::ALL.len(), "every role has its own name");
    }

    /// A different plan seed moves every stream.
    #[test]
    fn the_plan_seed_moves_every_stream() {
        let a = PlanSeed::from_bytes([1; 32]);
        let b = PlanSeed::from_bytes([2; 32]);
        for role in Role::ALL {
            assert_ne!(seed_for(&a, role, 0), seed_for(&b, role, 0), "{role:?}");
        }
    }

    #[test]
    fn a_seed_is_64_hex_digits() {
        let seed = PlanSeed::from_bytes([0xab; 32]);
        assert_eq!(PlanSeed::from_hex(&seed.to_hex()), Ok(seed));
        assert!(PlanSeed::from_hex("ab").is_err());
        assert!(PlanSeed::from_hex(&"zz".repeat(32)).is_err());
    }
}
