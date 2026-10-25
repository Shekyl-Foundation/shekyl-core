// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The witness ring (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §4.2; ruling Q10).
//!
//! `commitment → (seed, witness secret key, drawn for)`, in memory only.
//!
//! - **Fill.** Every template the node builds draws a fresh witness key
//!   and a fresh seed from the OS ([`WitnessRing::draw`]), and the ring
//!   keeps them under the commitment it returns. Nothing is derived: two
//!   templates for one height commit to different keys and seeds.
//! - **Claim.** When a block connects whose `0x0C` is a candidate's, this
//!   daemon mined it, and the candidate becomes the in-flight entry for
//!   that height.
//! - **Evict.** A candidate whose height is [`crate::CANDIDATE_DEPTH`]
//!   below the tip lost its race; at [`crate::MAX_CANDIDATES`] the oldest
//!   goes first. An in-flight entry leaves when its bundle is filed, or
//!   when the [`crate::Producer`] gives up on its block (popped past the
//!   reorg cap, or its window closed).
//! - **Restart.** The ring is empty. Its in-flight blocks' draws expire in
//!   flight, and the producer logs each one it held when it stops.
//!
//! The witness key never leaves the ring. Filing signs inside it
//! ([`WitnessRing::file`]) and drops the entry in the same call, so the
//! secrets are wiped as the bundle is made. The seed leaves twice, each
//! time in a wiping cell: once to the connector, which derives the draws
//! where the drawable memo is, and once when the bundle reveals it.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rand::RngCore;
use shekyl_archival_retention::{
    assemble_bundle, draw_commit, sign_bundle_commitment, BundleBody, BundleKept, BundleRecord,
    BundleRef, BUNDLE_WITNESS_KEY_LEN,
};
use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridSecretKey, HybridEd25519FnDsa};
use shekyl_crypto_pq::CryptoError;
use shekyl_types::archival::DrawCommitment;
use shekyl_types::BlockHeight;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{CANDIDATE_DEPTH, MAX_CANDIDATES};

/// One template's secrets: the seed, the witness secret key, and the
/// public key the commitment was made over.
struct WitnessSecrets {
    seed: Zeroizing<[u8; 32]>,
    secret: FnDsaHybridSecretKey,
    public: Box<[u8; BUNDLE_WITNESS_KEY_LEN]>,
}

// A marker: the seed is a `Zeroizing` cell and the secret key's halves are
// heap secrets, so each wipes itself where it lies when it drops. The
// public key is not secret. Held by `ring_entries_wipe_themselves`.
impl ZeroizeOnDrop for WitnessSecrets {}

impl core::fmt::Debug for WitnessSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WitnessSecrets([REDACTED])")
    }
}

impl WitnessSecrets {
    fn drawn() -> Result<Self, DrawFailed> {
        let (public, secret) = HybridEd25519FnDsa::generate_keypair()
            .map_err(|e| DrawFailed::KeyGeneration(e.to_string()))?;
        let public: Box<[u8; BUNDLE_WITNESS_KEY_LEN]> = public
            .to_canonical_bytes()
            .into_boxed_slice()
            .try_into()
            .map_err(|_| DrawFailed::KeyGeneration("a scheme-3 key of another width".into()))?;
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|e| DrawFailed::Entropy(e.to_string()))?;
        Ok(Self {
            seed,
            secret,
            public,
        })
    }

    fn commitment(&self) -> DrawCommitment {
        DrawCommitment::from_bytes(draw_commit(self.public.as_slice(), &self.seed))
    }
}

struct Candidate {
    commitment: DrawCommitment,
    drawn_for: BlockHeight,
    secrets: WitnessSecrets,
}

#[derive(Default)]
struct RingState {
    /// Oldest first.
    candidates: VecDeque<Candidate>,
    in_flight: BTreeMap<BlockHeight, WitnessSecrets>,
}

/// Why a template could not draw. Nothing is committed: the template
/// builder refuses, as it did when the commitment was drawn and dropped.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DrawFailed {
    /// The OS random source failed.
    #[error("the OS random source failed: {0}")]
    Entropy(String),
    /// Scheme-3 key generation failed.
    #[error("witness key generation failed: {0}")]
    KeyGeneration(String),
}

/// The ring (module docs). Shared: the template producer draws, the
/// [`crate::Producer`] claims, files and forgets.
pub struct WitnessRing {
    state: Mutex<RingState>,
    /// [`MAX_CANDIDATES`], except in a test of the bound.
    bound: usize,
}

impl Default for WitnessRing {
    fn default() -> Self {
        Self {
            state: Mutex::default(),
            bound: MAX_CANDIDATES,
        }
    }
}

impl core::fmt::Debug for WitnessRing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = self.lock();
        f.debug_struct("WitnessRing")
            .field("candidates", &state.candidates.len())
            .field("in_flight", &state.in_flight.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl WitnessRing {
    /// An empty ring: every node starts with one, and a restart has one.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A ring holding at most `bound` candidates: the bound's test, which
    /// cannot afford [`MAX_CANDIDATES`] scheme-3 key generations.
    #[cfg(test)]
    pub(crate) fn bounded(bound: usize) -> Self {
        Self {
            state: Mutex::default(),
            bound,
        }
    }

    /// A poisoned lock is recovered: every mutation below leaves the state
    /// whole before it can panic, and a ring that refused to open would
    /// stop the template, not protect a secret.
    fn lock(&self) -> MutexGuard<'_, RingState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Draw a fresh witness key and seed from the OS for a template whose
    /// block connects at `connecting`, keep them, and return the `0x0C`
    /// commitment the template carries.
    ///
    /// # Errors
    ///
    /// [`DrawFailed`] when the OS random source or key generation fails.
    /// There is no fallback commitment.
    pub fn draw(&self, connecting: BlockHeight) -> Result<DrawCommitment, DrawFailed> {
        let secrets = WitnessSecrets::drawn()?;
        let commitment = secrets.commitment();
        let mut state = self.lock();
        while state.candidates.len() >= self.bound {
            state.candidates.pop_front();
        }
        state.candidates.push_back(Candidate {
            commitment,
            drawn_for: connecting,
            secrets,
        });
        Ok(commitment)
    }

    /// Drop every candidate drawn for a height [`CANDIDATE_DEPTH`] or more
    /// below `tip`. How many went.
    pub(crate) fn evict(&self, tip: BlockHeight) -> usize {
        let floor = tip.saturating_sub_count(CANDIDATE_DEPTH);
        let mut state = self.lock();
        let before = state.candidates.len();
        state
            .candidates
            .retain(|candidate| candidate.drawn_for > floor);
        before - state.candidates.len()
    }

    /// The block at `h` carries `commitment`. If a candidate drew it, this
    /// daemon mined `h`: the candidate becomes `h`'s in-flight entry, and
    /// the other candidates for `h` go (exactly one template's block is
    /// the block at `h`). An entry already in flight for `h` is a block a
    /// reorg popped, and it is replaced: only one block at `h` is on the
    /// chain. Whether it was ours.
    pub(crate) fn claim(&self, h: BlockHeight, commitment: &DrawCommitment) -> bool {
        let mut state = self.lock();
        let Some(at) = state
            .candidates
            .iter()
            .position(|candidate| candidate.drawn_for == h && candidate.commitment == *commitment)
        else {
            return false;
        };
        let Some(candidate) = state.candidates.remove(at) else {
            return false;
        };
        state.candidates.retain(|other| other.drawn_for != h);
        state.in_flight.insert(h, candidate.secrets);
        true
    }

    /// A copy of `h`'s seed, for the connector's derivation of its draws
    /// and for the read nonces. `None` when `h` is not in flight.
    pub(crate) fn seed(&self, h: BlockHeight) -> Option<Zeroizing<[u8; 32]>> {
        self.lock()
            .in_flight
            .get(&h)
            .map(|secrets| Zeroizing::new(*secrets.seed))
    }

    /// Assemble `h`'s bundle over `passes` and `support` with these
    /// records, sign it with `h`'s witness key, and drop the entry: its
    /// secrets are wiped before this returns. `None` when `h` is not in
    /// flight.
    pub(crate) fn file(
        &self,
        h: BlockHeight,
        passes: shekyl_archival_retention::PassBitmap,
        support: shekyl_archival_retention::PassBitmap,
        records: &[BundleRecord],
    ) -> Option<Result<(BundleRef, BundleBody), CryptoError>> {
        let secrets = self.lock().in_flight.remove(&h)?;
        let kept = BundleKept {
            h,
            seed: *secrets.seed,
            passes,
            support,
        };
        Some(assemble_bundle(
            &kept,
            records,
            &secrets.public,
            |commitment| sign_bundle_commitment(&secrets.secret, commitment),
        ))
    }

    /// Drop `h`'s entry without filing. Whether there was one.
    pub(crate) fn forget(&self, h: BlockHeight) -> bool {
        self.lock().in_flight.remove(&h).is_some()
    }

    /// How many candidates the ring holds.
    #[must_use]
    pub fn candidates(&self) -> usize {
        self.lock().candidates.len()
    }

    /// The heights in flight, ascending.
    #[must_use]
    pub fn in_flight(&self) -> Vec<BlockHeight> {
        self.lock().in_flight.keys().copied().collect()
    }
}

#[cfg(test)]
#[path = "ring_tests.rs"]
mod tests;
