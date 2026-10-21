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
//!
//! The fields are private. A proven header is assembled only from a
//! [`Proven`] value, and only [`crate::rules::pow::D2::longhash`] builds
//! that value, so a module cannot swap the header under a seal it did not
//! compute. [`prove_header`] is the production path: [`crate::form`] and
//! [`crate::form_header`] both call it, after their own cheap checks, so
//! B6, D2 and D1 cannot drift apart.

use shekyl_types::{BlockHash, PowHash, Timestamp};
use shekyl_wire::{BlockHeader, PowBlob};

use crate::coverage::RuleCoverage;
use crate::fault::FormAttempt;
use crate::rule_set::RuleSet;
use crate::rules::difficulty::Target;
use crate::rules::header::B6;
use crate::rules::pow::{LonghashSeal, D1, D2};
use crate::substrate::Substrate;
use crate::verdict::Verdict;

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
    header: BlockHeader,
    identity: BlockHash,
    judged_at: Timestamp,
    seed: BlockHash,
    target: Target,
    attempt: FormAttempt,
    proof: P,
}

impl<P> HeaderFacts<P> {
    /// The only assembler. `P` is the proof state: [`Unproven`] from
    /// [`OpenHeader::at`], [`Proven`] from a longhash [`D2`] computed.
    fn assemble(
        header: BlockHeader,
        identity: BlockHash,
        judged_at: Timestamp,
        seed: BlockHash,
        target: Target,
        attempt: FormAttempt,
        proof: P,
    ) -> Self {
        Self {
            header,
            identity,
            judged_at,
            seed,
            target,
            attempt,
            proof,
        }
    }

    /// The header under judgement.
    #[must_use]
    pub(crate) const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// The block identity (CEN-B6).
    #[must_use]
    pub(crate) const fn identity(&self) -> BlockHash {
        self.identity
    }

    /// The clock the header was judged at.
    #[must_use]
    pub(crate) const fn judged_at(&self) -> Timestamp {
        self.judged_at
    }

    /// The seed the caller claimed.
    #[must_use]
    pub(crate) const fn seed(&self) -> BlockHash {
        self.seed
    }

    /// The target the caller claimed.
    #[must_use]
    pub(crate) const fn target(&self) -> Target {
        self.target
    }

    /// Which attempt produced these facts.
    #[must_use]
    pub(crate) const fn attempt(&self) -> FormAttempt {
        self.attempt
    }

    /// The proof state. [`Proven::longhash`] is what CEN-D1 reads.
    #[must_use]
    pub(crate) const fn proof(&self) -> &P {
        &self.proof
    }
}

impl HeaderFacts<Proven> {
    /// Proven facts for a test that judges one view-bound rule and must
    /// not depend on every stateless row. The longhash is still
    /// [`Proven`]: only [`D2::longhash`] can build it. Coverage stays the
    /// caller's, and this is not a verdict.
    #[cfg(any(test, feature = "harness"))]
    pub(crate) fn for_harness(
        header: BlockHeader,
        identity: BlockHash,
        judged_at: Timestamp,
        seed: BlockHash,
        target: Target,
        attempt: FormAttempt,
        proof: Proven,
    ) -> Self {
        Self::assemble(header, identity, judged_at, seed, target, attempt, proof)
    }
}

/// What [`prove_header`] judges: the preimage, and the claims the caller
/// makes about it. [`crate::form`] fills this from a block;
/// [`crate::form_header`] fills it from a [`PowBlob`].
pub(crate) struct HeaderProof<'a, S: Substrate> {
    /// The header the facts carry. The caller parsed it from `pow_blob`.
    pub header: BlockHeader,
    /// The bytes B6 hashes and D2 longhashes.
    pub pow_blob: &'a [u8],
    /// The clock and the longhash.
    pub substrate: &'a S,
    /// The seed the caller claims (CEN-D3 verifies it later).
    pub seed: BlockHash,
    /// The target the caller claims (CEN-D4 verifies it later).
    pub target: Target,
    /// Which try this is.
    pub attempt: FormAttempt,
    /// The clock, already read. This function does not read it again.
    pub judged_at: Timestamp,
}

/// B6, then D2, then D1. [`crate::form`] and [`crate::form_header`] both
/// call this after their cheap checks, so the proof tail is one function
/// and the two paths cannot record it differently.
///
/// On a D1 refusal, B6 and D2 are already in `coverage`: those rows ran.
///
/// # Errors
///
/// The substrate's fault, from the longhash. A refusal is `Ok(Err(_))`.
pub(crate) fn prove_header<S: Substrate>(
    proof: HeaderProof<'_, S>,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<HeaderFacts<Proven>>, S::Fault> {
    let identity = B6::identity_of(proof.pow_blob, coverage);
    let proven = D2::longhash(proof.substrate, proof.pow_blob, proof.seed, coverage)?;
    let facts = HeaderFacts::assemble(
        proof.header,
        identity,
        proof.judged_at,
        proof.seed,
        proof.target,
        proof.attempt,
        proven,
    );
    if let Err(refused) = D1::judge(&facts, coverage) {
        return Ok(Err(refused));
    }
    Ok(Ok(facts))
}

/// A header whose proof has not been computed, and whose clock has not
/// been read. Input to [`crate::judge_header_cheap`]. Not convertible into
/// a [`FormedHeader`]: that token is what [`crate::form_header`] returns
/// after CEN-D1.
///
/// The time is absent. [`Self::at`] adds it when the cheap checks read the
/// substrate clock, so there is no stand-in for a reading that has not
/// happened.
#[derive(Clone, Debug)]
pub struct OpenHeader {
    header: BlockHeader,
    identity: BlockHash,
    seed: BlockHash,
    target: Target,
    attempt: FormAttempt,
}

impl OpenHeader {
    /// The identity is [`PowBlob::identity`]. `attempt` is which try this
    /// is, the same value [`crate::form`] takes. No clock is read.
    #[must_use]
    pub fn from_pow(pow: &PowBlob, seed: BlockHash, target: Target, attempt: FormAttempt) -> Self {
        Self {
            header: pow.header.clone(),
            identity: pow.identity(),
            seed,
            target,
            attempt,
        }
    }

    /// The facts the rules read, at the instant the cheap checks took the
    /// clock. The proof is still [`Unproven`].
    pub(crate) fn at(&self, judged_at: Timestamp) -> HeaderFacts<Unproven> {
        HeaderFacts::assemble(
            self.header.clone(),
            self.identity,
            judged_at,
            self.seed,
            self.target,
            self.attempt,
            Unproven,
        )
    }
}

/// A header [`crate::form_header`] has judged: B1, B2, the identity, the
/// longhash and CEN-D1 against the claimed target. Input to
/// [`crate::judge_header`].
///
/// Constructed only by `form_header`. The fields are private and there is
/// no public constructor, the same seal [`StructurallyValid`](crate::StructurallyValid)
/// carries:
///
/// ```compile_fail
/// let forged = shekyl_chain_rules::FormedHeader {
///     facts: todo!(),
///     coverage: todo!(),
///     rule_set: todo!(),
/// };
/// ```
///
/// `Clone`: [`crate::judge_header`] borrows the token against more than
/// one view. Dropping it discards the proof.
#[must_use = "a FormedHeader is the input to `judge_header`; dropping it discards the header proof"]
#[derive(Clone, Debug)]
pub struct FormedHeader {
    facts: HeaderFacts<Proven>,
    /// The rows `form_header` ran and passed. Not a `validate` coverage,
    /// and this token mints no [`crate::ChainValid`].
    coverage: RuleCoverage,
    /// The rules `form_header` was given. [`crate::judge_header`] faults
    /// when it is handed another, the same check `validate` makes.
    rule_set: RuleSet,
}

impl FormedHeader {
    /// Called by `form_header` once B1, B2 and [`prove_header`] have
    /// passed, and nowhere else.
    pub(crate) fn new(
        facts: HeaderFacts<Proven>,
        coverage: RuleCoverage,
        rule_set: RuleSet,
    ) -> Self {
        Self {
            facts,
            coverage,
            rule_set,
        }
    }

    /// The facts `form_header` established, including the longhash.
    #[must_use]
    pub(crate) const fn facts(&self) -> &HeaderFacts<Proven> {
        &self.facts
    }

    /// The rows `form_header` ran and passed.
    #[must_use]
    pub const fn coverage(&self) -> &RuleCoverage {
        &self.coverage
    }

    /// The rules `form_header` was given.
    #[must_use]
    pub const fn rule_set(&self) -> RuleSet {
        self.rule_set
    }

    /// Which attempt at `form_header` produced this.
    #[must_use]
    pub const fn attempt(&self) -> FormAttempt {
        self.facts.attempt()
    }

    /// The block identity CEN-B6 derived from the PoW preimage.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.facts.identity()
    }

    /// The wall clock `form_header` read, once, before the rules.
    #[must_use]
    pub const fn judged_at(&self) -> Timestamp {
        self.facts.judged_at()
    }

    /// The seed the caller claimed. [`crate::judge_header`] checks it.
    #[must_use]
    pub const fn seed(&self) -> BlockHash {
        self.facts.seed()
    }

    /// The target CEN-D1 was judged against. [`crate::judge_header`] checks it.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.facts.target()
    }

    /// The longhash CEN-D2 computed and CEN-D1 accepted.
    #[must_use]
    pub const fn pow(&self) -> PowHash {
        self.facts.proof().longhash()
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
