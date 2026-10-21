// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The facts a header rule reads, and whether the proof has been computed.
//!
//! [`Unproven`] and [`Proven`] are the two states. A header without a
//! longhash is [`HeaderFacts<Unproven>`]; [`crate::rules::pow::D1`] accepts
//! only [`HeaderFacts<Proven>`]. There is no `Option` to unwrap and no
//! conversion from the unproven state, so the proof check cannot run on a
//! header that has not been hashed.
//!
//! [`StructurallyValid`](crate::block::StructurallyValid) carries the
//! proven facts of a formed block. [`FormedHeader`] carries them for a
//! header that [`crate::form_header`] has judged. [`OpenHeader`] is the
//! unproven state [`crate::judge_header_cheap`] reads.

use shekyl_types::{BlockHash, PowHash, Timestamp};
use shekyl_wire::{BlockHeader, PowBlob};

use crate::coverage::RuleCoverage;
use crate::fault::FormAttempt;
use crate::rules::difficulty::Target;
use crate::rules::pow::LonghashSeal;
use crate::substrate::Substrate;

/// The proof has not been computed. The cheap checks never read this.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Unproven;

/// The longhash under the claimed seed (CEN-D2). CEN-D1 is the only reader.
///
/// Constructed only by [`crate::rules::pow::D2::longhash`]. The seal is
/// what that function holds; a header is not proven by writing the hash in.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Proven {
    longhash: PowHash,
}

impl Proven {
    pub(crate) const fn from_longhash(longhash: PowHash, _seal: LonghashSeal) -> Self {
        Self { longhash }
    }

    /// The longhash CEN-D2 computed.
    #[must_use]
    pub(crate) const fn longhash(self) -> PowHash {
        self.longhash
    }
}

/// Header, identity, the clock the header was judged at, the seed and
/// target claims, and the attempt those claims were made on.
///
/// `P` is [`Unproven`] or [`Proven`]. The attempt rides here so a `Stale`
/// fault can name the retry the token allows; without it the header path
/// could not return the same fault `validate` returns.
#[derive(Clone, Debug)]
pub(crate) struct HeaderFacts<P> {
    pub(crate) header: BlockHeader,
    pub(crate) identity: BlockHash,
    pub(crate) judged_at: Timestamp,
    pub(crate) seed: BlockHash,
    pub(crate) target: Target,
    pub(crate) attempt: FormAttempt,
    pub(crate) proof: P,
}

/// A header whose proof has not been computed. Input to
/// [`crate::judge_header_cheap`]. Not convertible into a [`FormedHeader`]:
/// that token is what [`crate::form_header`] returns after CEN-D1.
#[derive(Clone, Debug)]
pub struct OpenHeader {
    pub(crate) facts: HeaderFacts<Unproven>,
}

impl OpenHeader {
    /// The facts the cheap checks read. The identity is
    /// [`PowBlob::identity`]; the attempt is [`FormAttempt::FIRST`]. The
    /// clock is the substrate's, read once here; [`crate::judge_header_cheap`]
    /// reads it again when it judges, so a caller cannot name the instant.
    ///
    /// # Errors
    ///
    /// The substrate's fault, from the clock.
    pub fn from_pow<S: Substrate>(
        pow: &PowBlob,
        substrate: &S,
        seed: BlockHash,
        target: Target,
    ) -> Result<Self, S::Fault> {
        let judged_at = substrate.local_clock()?;
        Ok(Self {
            facts: HeaderFacts {
                header: pow.header.clone(),
                identity: pow.identity(),
                judged_at,
                seed,
                target,
                attempt: FormAttempt::FIRST,
                proof: Unproven,
            },
        })
    }
}

/// A header [`crate::form_header`] has judged: B1, B2, the identity, the
/// longhash and CEN-D1 against the claimed target. Input to
/// [`crate::judge_header`].
#[derive(Clone, Debug)]
pub struct FormedHeader {
    pub(crate) facts: HeaderFacts<Proven>,
    /// The rows `form_header` ran and passed. Not a `validate` coverage,
    /// and this token mints no [`crate::ChainValid`].
    pub coverage: RuleCoverage,
}

impl FormedHeader {
    /// The block identity CEN-B6 derived from the PoW preimage.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.facts.identity
    }

    /// The wall clock `form_header` read, once, before the rules.
    #[must_use]
    pub const fn judged_at(&self) -> Timestamp {
        self.facts.judged_at
    }

    /// The seed the caller claimed. [`crate::judge_header`] checks it.
    #[must_use]
    pub const fn seed(&self) -> BlockHash {
        self.facts.seed
    }

    /// The target CEN-D1 was judged against. [`crate::judge_header`] checks it.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.facts.target
    }

    /// The longhash CEN-D2 computed and CEN-D1 accepted.
    #[must_use]
    pub const fn pow(&self) -> PowHash {
        self.facts.proof.longhash()
    }
}

/// A header that has not been proven cannot be passed where CEN-D1 runs.
///
/// The mismatch is the types (`E0308`). `todo!()` stands in for a value so
/// the failure is the argument, not a missing constructor.
///
/// ```compile_fail
/// fn d1_step(_: &shekyl_chain_rules::FormedHeader) {}
/// fn no(open: &shekyl_chain_rules::OpenHeader) {
///     d1_step(open);
/// }
/// ```
#[doc(hidden)]
pub fn _d1_requires_a_proven_header() {}
