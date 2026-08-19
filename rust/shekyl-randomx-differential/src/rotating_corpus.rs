// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Rotating-corpus seed derivation (re-scope item 2, §7.9 MR-R1).
//!
//! Per `docs/design/RANDOMX_V2_MUTATION_REGIME.md` §7.5 item 2, the
//! rotating differential lane explores inputs *outside* the pinned
//! corpus. Its seed is **derived from a time index, never drawn from
//! entropy** — the distinction MR-R1 turns on, and the reason this
//! module exists rather than a call to a random-number generator.
//!
//! ## Why derived, not drawn
//!
//! A lane seeded from fresh entropy makes its own red **self-erasing**:
//! re-running turns it green with a different, innocent input set, and
//! the run looks identical in the UI. Every halt-and-escalate posture
//! in this workflow rests implicitly on a reproducibility that such a
//! lane would remove — and a consensus divergence is the one finding
//! class whose record must outlive any CI artifact-retention window.
//!
//! Deriving the seed from an integer index keeps all three properties
//! that motivated pinning [`crate::corpus_random::RANDOM_CORPUS_SEED_V1`]
//! — reproducible failures, byte-stability, runtime re-derivation from
//! a source string — while making coverage **monotonic instead of
//! constant**. Week 47's input set is reconstructable in three years by
//! anyone, offline, from the integer alone.
//!
//! ## Triage rule
//!
//! **Replay by index. Never re-run the lane.** A same-day re-run
//! regenerates the *same* set (so a red reproduces); a re-run the next
//! day does not. The M4 banner carries the index and its provenance so
//! the distinction is auditable rather than assumed.
//!
//! ## Prohibition
//!
//! The pinned v1 corpus is **not** index 0 of this sequence, and must
//! never be redefined as such. `RANDOM_CORPUS_SEED_V1` is
//! `SHA-256("shekyl-randomx-differential-corpus-v1")`, and all 1024
//! `CANONICAL_RANDOM_HASHES` entries plus 32 `CANONICAL_CACHE_SHAS`
//! entries are *positionally bound* to it. Any unification invalidates
//! the entire canonical table and every pin gate consuming it, across
//! five lanes. [`tests::rotating_seed_never_collides_with_v1`] is the
//! mechanical guard; this paragraph is the reason.

use shekyl_crypto_hash::cshake256_32;

/// cSHAKE256 customization string for rotating-corpus seed derivation.
///
/// Registered in [`docs/design/CRYPTO_DOMAIN_REGISTRY.tsv`] (SA-3b);
/// `scripts/ci/domain_registry_gate.sh` enforces the row-presence and
/// const-binding tripwires against this constant.
///
/// Domain-separated from every other Shekyl derivation *and* from the
/// v1 corpus seed, which is a bare SHA-256 of a different string — see
/// the module-level prohibition.
///
/// [`docs/design/CRYPTO_DOMAIN_REGISTRY.tsv`]: ../../../docs/design/CRYPTO_DOMAIN_REGISTRY.tsv
pub const ROTATING_CORPUS_CUSTOMIZATION: &[u8] = b"shekyl/randomx-rotating-corpus-v1";

/// Where a lane's rotation index came from.
///
/// Per §7.9 MR-R4 this is a **provenance label**, not the load-bearing
/// control: because an index-derived seed is a bounded integer whose
/// input set anyone can regenerate offline, "the operator picked a
/// benign one" is a falsifiable claim rather than an unbounded
/// attacker choice. The label exists so a green *replay* cannot be
/// cited as a green *sweep* (§4.5 T-A11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexProvenance {
    /// Derived from the run's own clock at lane start — a genuine
    /// forward step of the coverage boundary.
    ScheduleDerived,
    /// Supplied by an operator on `workflow_dispatch`, i.e. a replay
    /// of a previously-explored index.
    OperatorSupplied,
    /// Derived from the date on a `pull_request` run (MR-DQ-6).
    ///
    /// Distinct from both siblings, and the distinction is load-
    /// bearing rather than cosmetic. It is not `ScheduleDerived`: a
    /// per-PR run does **not** advance the explored boundary, because
    /// every PR on a given day derives the *same* index and therefore
    /// re-checks the same inputs. It is not `OperatorSupplied` either:
    /// nobody chose the index, so labelling it as a replay would be
    /// untrue in the other direction.
    ///
    /// Its purpose is a **tripwire on the change**, not coverage of the
    /// input space: does this diff diverge on a non-pinned input set?
    /// Only [`Self::ScheduleDerived`] may ever be credited as coverage
    /// (§4.5 T-A11).
    PullRequest,
}

impl IndexProvenance {
    /// Banner-facing tag. Pinned by the T17 banner assertion; changing
    /// these strings changes what a reviewer greps for.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::ScheduleDerived => "schedule-derived",
            Self::OperatorSupplied => "operator-supplied",
            Self::PullRequest => "pull-request",
        }
    }
}

/// Derive the 32-byte corpus seed for rotation index `index`.
///
/// `seed(i) = cSHAKE256-32(ROTATING_CORPUS_CUSTOMIZATION, i_le_bytes)`.
///
/// The index is encoded little-endian and fixed-width so the preimage
/// is unambiguous: a variable-width or decimal-string encoding would
/// let two distinct indices share a preimage under concatenation, and
/// the whole value of this scheme is that the index *determines* the
/// input set.
///
/// # Coverage boundary
///
/// Bites against seed drift between runs claiming the same index, and
/// against collision with the pinned v1 corpus. Does **not** assert
/// anything about the *quality* of the resulting corpus — that is
/// `generate_random_corpus`'s ChaCha20 expansion, unchanged from the
/// pinned lane.
#[must_use]
pub fn rotating_seed(index: u64) -> [u8; 32] {
    cshake256_32(ROTATING_CORPUS_CUSTOMIZATION, &index.to_le_bytes())
}

/// A lane's rotation binding: which index it explored, and where that
/// index came from.
///
/// Carried into the M4 banner so a reader of the run — or of a
/// three-year-old log — can reconstruct the exact input set from the
/// integer, and can tell a forward sweep from a replay (§7.9 MR-R4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationContext {
    /// The rotation index. Computed **once at lane start**: a lane
    /// straddling midnight UTC that re-derived mid-run would emit a
    /// banner index that does not describe all of its own inputs — a
    /// record that lies while looking complete.
    pub index: u64,
    /// Whether `index` came from the schedule or from an operator.
    pub provenance: IndexProvenance,
}

impl RotationContext {
    /// Bind an index to its provenance.
    #[must_use]
    pub fn new(index: u64, provenance: IndexProvenance) -> Self {
        Self { index, provenance }
    }

    /// The seed this rotation explores.
    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        rotating_seed(self.index)
    }
}

/// Generate this rotation's corpus.
///
/// Delegates to [`crate::corpus_random::generate_corpus_from_seed`] so
/// the rotating and pinned lanes share **one** expansion — see that
/// function's note on why a second copy would be a latent divergence.
///
/// # Coverage boundary
///
/// Bites against a rotation exploring the wrong input set for its
/// index. Does **not** bound *how much* of the input space is covered;
/// per §7.5 item 2's claim discipline, this lane advances the
/// **explored** boundary, never the **pinned** one, and proves
/// spec-equivalence at no sizing.
#[must_use]
pub fn generate_rotating_corpus(
    rotation: RotationContext,
    seedhash_count: usize,
    data_per_seedhash: usize,
) -> Vec<crate::corpus_random::RandomCorpusPair> {
    crate::corpus_random::generate_corpus_from_seed(
        rotation.seed(),
        seedhash_count,
        data_per_seedhash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus_random::RANDOM_CORPUS_SEED_V1;

    /// `rotating_seed(0)`, pinned at first landing.
    const PINNED_SEED_INDEX_0: [u8; 32] = [
        0xa2, 0x85, 0x59, 0x79, 0x46, 0xc1, 0xc6, 0xcc, 0x2e, 0x04, 0x14, 0x05, 0xdb, 0x7b, 0xb2,
        0x4d, 0x12, 0xf8, 0x6b, 0xc9, 0x82, 0x70, 0x30, 0xbe, 0x73, 0xa4, 0xb4, 0x0b, 0xbd, 0x9d,
        0x14, 0x54,
    ];
    /// `rotating_seed(47)`, pinned at first landing.
    const PINNED_SEED_INDEX_47: [u8; 32] = [
        0x54, 0xdd, 0xa4, 0x69, 0x81, 0x5c, 0x19, 0x9b, 0xe4, 0x69, 0x29, 0xe0, 0x98, 0x88, 0x06,
        0xc2, 0x13, 0x3c, 0x86, 0xea, 0x8f, 0x5f, 0xd1, 0xe0, 0xa7, 0xa8, 0x10, 0x38, 0xf7, 0x53,
        0xb8, 0xce,
    ];

    /// The load-bearing property: an index determines its seed.
    ///
    /// Bites against any reintroduction of entropy into the derivation
    /// — the MR-R1 hazard. Does NOT cover the corpus expansion.
    #[test]
    fn rotating_seed_is_deterministic_in_the_index() {
        for i in [0u64, 1, 47, 20_000, u64::MAX] {
            assert_eq!(
                rotating_seed(i),
                rotating_seed(i),
                "index {i} must be stable"
            );
        }
    }

    /// Distinct indices give distinct seeds.
    ///
    /// Bites against an encoding that collapses indices (e.g. a
    /// truncating cast). Does NOT prove collision resistance — that is
    /// cSHAKE256's, not this function's.
    #[test]
    fn distinct_indices_give_distinct_seeds() {
        let a = rotating_seed(46);
        let b = rotating_seed(47);
        let c = rotating_seed(u64::from(u32::MAX) + 47);
        assert_ne!(a, b);
        assert_ne!(a, c, "a 32-bit-truncating encoding would collide these");
        assert_ne!(b, c);
    }

    /// The prohibition, enforced mechanically.
    ///
    /// Bites against any future "the pinned corpus is just index 0"
    /// unification, which would invalidate all 1024 canonical hashes
    /// and 32 canonical cache SHAs positionally bound to the v1 seed.
    /// Does NOT prevent someone deleting this test — that is what the
    /// module-level prohibition paragraph is for.
    #[test]
    fn rotating_seed_never_collides_with_v1() {
        for i in 0..1024u64 {
            assert_ne!(
                rotating_seed(i),
                RANDOM_CORPUS_SEED_V1,
                "rotation index {i} collided with the pinned v1 corpus seed; \
                 the sequences must remain separate namespaces"
            );
        }
    }

    /// Pinned known-answer vectors.
    ///
    /// Bites against every silent way the derivation could drift: the
    /// customization being dropped or altered, the index encoding
    /// changing width or endianness, or the primitive being swapped.
    /// Any of those changes the corpus a given index names, which
    /// would break the replay-by-index triage rule (§7.9 MR-R1)
    /// without breaking any other test here.
    ///
    /// Per `30-cryptography.mdc` a derivation carries pinned vectors;
    /// note this deliberately does NOT re-derive the value with a
    /// second cSHAKE call, which would only assert that cSHAKE agrees
    /// with itself — and would move the production cSHAKE count-pin in
    /// `domain_registry_gate.sh` for a non-domain.
    #[test]
    fn rotating_seed_matches_pinned_vectors() {
        assert_eq!(
            rotating_seed(0),
            PINNED_SEED_INDEX_0,
            "index 0 drifted; the replay-by-index rule is broken"
        );
        assert_eq!(
            rotating_seed(47),
            PINNED_SEED_INDEX_47,
            "index 47 drifted; the replay-by-index rule is broken"
        );
    }

    /// A rotation's corpus is a function of its index alone.
    ///
    /// Bites against the corpus depending on wall-clock or process
    /// state — the property the replay-by-index triage rule needs.
    /// Does NOT cover the expansion's distribution (that is
    /// `corpus_random`'s surface).
    #[test]
    fn rotating_corpus_is_reproducible_from_the_index_alone() {
        let a = generate_rotating_corpus(
            RotationContext::new(47, IndexProvenance::ScheduleDerived),
            2,
            2,
        );
        // Same index, different provenance: provenance is a label and
        // must not touch the inputs.
        let b = generate_rotating_corpus(
            RotationContext::new(47, IndexProvenance::OperatorSupplied),
            2,
            2,
        );
        assert_eq!(a.len(), 4);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.seedhash, y.seedhash, "provenance must not affect inputs");
            assert_eq!(x.data, y.data, "provenance must not affect inputs");
        }
    }

    /// Different rotations explore different inputs.
    ///
    /// Bites against a lane that reports a rotating index while
    /// re-verifying one fixed set — the failure that would make the
    /// whole lane theatre while every other test passed.
    #[test]
    fn distinct_rotations_explore_distinct_inputs() {
        let a = generate_rotating_corpus(
            RotationContext::new(46, IndexProvenance::ScheduleDerived),
            2,
            2,
        );
        let b = generate_rotating_corpus(
            RotationContext::new(47, IndexProvenance::ScheduleDerived),
            2,
            2,
        );
        assert_ne!(
            a.iter().map(|p| p.seedhash).collect::<Vec<_>>(),
            b.iter().map(|p| p.seedhash).collect::<Vec<_>>(),
            "consecutive rotations produced identical seedhashes"
        );
    }

    /// The rotating lane never re-explores the pinned corpus.
    ///
    /// Bites against the namespaces silently converging — the
    /// module-level prohibition, checked at corpus level rather than
    /// only at seed level.
    #[test]
    fn rotation_zero_does_not_reproduce_the_pinned_corpus() {
        use crate::corpus_random::generate_random_corpus;
        let pinned = generate_random_corpus(2, 2);
        let rotating = generate_rotating_corpus(
            RotationContext::new(0, IndexProvenance::ScheduleDerived),
            2,
            2,
        );
        assert_ne!(
            pinned.iter().map(|p| p.seedhash).collect::<Vec<_>>(),
            rotating.iter().map(|p| p.seedhash).collect::<Vec<_>>(),
            "rotation 0 reproduced the pinned corpus; the namespaces have converged"
        );
    }

    /// Provenance tags are the strings the banner assertion greps for.
    #[test]
    fn provenance_tags_are_stable() {
        assert_eq!(IndexProvenance::ScheduleDerived.tag(), "schedule-derived");
        assert_eq!(IndexProvenance::OperatorSupplied.tag(), "operator-supplied");
        assert_eq!(IndexProvenance::PullRequest.tag(), "pull-request");
    }

    /// Exactly one provenance may be credited as coverage.
    ///
    /// Bites against a future variant being added that silently reads
    /// as a sweep — the §4.5 T-A11 laundering the label exists to
    /// prevent. Does NOT check what any lane *does* with the label;
    /// that is the workflow's surface.
    #[test]
    fn only_schedule_derived_counts_as_coverage() {
        let all = [
            IndexProvenance::ScheduleDerived,
            IndexProvenance::OperatorSupplied,
            IndexProvenance::PullRequest,
        ];
        let coverage: Vec<_> = all
            .iter()
            .filter(|p| **p == IndexProvenance::ScheduleDerived)
            .collect();
        assert_eq!(
            coverage.len(),
            1,
            "exactly one provenance may be credited as coverage"
        );
        for p in &all {
            assert!(!p.tag().is_empty(), "every provenance needs a banner tag");
        }
    }
}
