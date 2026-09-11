// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--mode=rotating` — the exploring differential lane (re-scope item 2).
//!
//! Per `docs/design/RANDOMX_V2_MUTATION_REGIME.md` §7.5 item 2, this is
//! the lane that moves the **explored** coverage boundary. Every other
//! differential lane re-verifies the same 1024 pinned pairs on every
//! run, on every branch, in five places; this one derives a fresh input
//! set per rotation index and runs the same rust-vs-C comparison over
//! inputs the project has never tested.
//!
//! ## Coverage-boundary rationale (`50-testing.mdc`)
//!
//! **Bites against** spec-non-equivalence between `shekyl-pow-randomx`
//! and the fork-pinned C reference on inputs **outside** the pinned
//! corpus — the §4.5 T-A9 residual the pinned lanes cannot reach by
//! construction.
//!
//! **Does NOT** grow the regression corpus absent a finding, and does
//! **not** prove spec-equivalence at any sizing. The pinned corpus
//! grows only through the MR-R3 promotion path, which runs after a
//! divergence is root-caused and fixed — never at discovery. A reader
//! who sees "corpus lane, weekly" and credits it with accumulation has
//! misread it, which is why this paragraph is here rather than only in
//! the plan doc.
//!
//! ## Why there is no canonical leg
//!
//! The three-leg comparison's leg 3 comes from
//! [`crate::canonical_outputs`], which is positionally bound to the
//! pinned corpus. Rotating inputs have no canonical by construction —
//! they are new. So this lane runs legs 1 and 2 (cache precondition +
//! `rust == c`) and passes `None` for the canonical, reusing
//! [`crate::mode_correctness::three_leg_verdict`] rather than a second
//! comparison written here. One verdict implementation, per MR-F10's
//! lesson: a comparison that exists in two places can be weakened in
//! one of them.
//!
//! ## Failure posture
//!
//! A divergence here is a **plausible real consensus finding** and
//! carries the same halt-and-escalate posture as the concurrent and
//! native-arm lanes: never rerun-until-green. Under a rotating seed
//! that posture needs stating twice over, because rerunning on a later
//! index *would* come back green — see §7.9 MR-R1 and the banner's
//! `Rotation-replay:` line.

use crate::c_oracle::COracleSession;
use crate::cache_precondition::assert_equivalent;
use crate::mode_correctness::{three_leg_verdict, CorrectnessError};
use crate::rotating_corpus::{generate_rotating_corpus, RotationContext};
use crate::rust_subject::RustSubjectSession;

/// Default rotation sizing: seedhashes per run.
///
/// Deliberately smaller than the pinned lane's nightly 32: a cache
/// derive dominates per-seedhash cost, and this lane's value is
/// *new* inputs per unit time rather than depth at one seedhash.
/// Re-derive against the runner class before treating as a budget.
pub const DEFAULT_ROTATION_SEEDHASHES: usize = 8;

/// Default rotation sizing: data values per seedhash.
pub const DEFAULT_ROTATION_DATA_PER_SEEDHASH: usize = 16;

/// What a completed rotation checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationReport {
    /// The index explored — echoed so a caller logging the report
    /// does not have to re-thread the context to say what was run.
    pub index: u64,
    /// Seedhashes whose cache precondition held.
    pub seedhashes_checked: usize,
    /// `(seedhash, data)` pairs whose `rust == c` held.
    pub pairs_checked: usize,
}

impl core::fmt::Display for RotationReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "rotation index {} clean: {} seedhashes, {} pairs (explored, not pinned)",
            self.index, self.seedhashes_checked, self.pairs_checked
        )
    }
}

/// Run one rotation.
///
/// Errors carry the same [`CorrectnessError`] taxonomy the pinned lane
/// uses, so the C9 failure-output schema and its triage path are
/// unchanged — a divergence found here is reported in the shape a
/// reviewer already knows how to read.
pub fn run(
    rotation: RotationContext,
    seedhash_count: usize,
    data_per_seedhash: usize,
) -> Result<RotationReport, CorrectnessError> {
    let corpus = generate_rotating_corpus(rotation, seedhash_count, data_per_seedhash);
    let mut seedhashes_checked = 0usize;
    let mut pairs_checked = 0usize;

    let mut index = 0usize;
    while index < corpus.len() {
        let seedhash = corpus[index].seedhash;
        let rust = RustSubjectSession::derive(seedhash);
        let c = COracleSession::new(seedhash).map_err(CorrectnessError::COracle)?;
        assert_equivalent(&rust, &c).map_err(CorrectnessError::Precondition)?;

        // Consume the contiguous run of pairs sharing this seedhash;
        // the generator emits them grouped, and re-deriving a cache
        // per data value would multiply this lane's cost by
        // `data_per_seedhash` for no additional coverage.
        while index < corpus.len() && corpus[index].seedhash == seedhash {
            let pair = &corpus[index];
            let rust_hash = rust.compute_hash(&pair.data);
            let c_hash = c.calculate_hash(&pair.data);
            three_leg_verdict(
                seedhash,
                usize::MAX,
                pair.data.len(),
                rust_hash,
                c_hash,
                // No canonical: rotating inputs are outside the pinned
                // corpus by construction (see module docs).
                None,
            )?;
            pairs_checked += 1;
            index += 1;
        }
        seedhashes_checked += 1;
    }

    Ok(RotationReport {
        index: rotation.index,
        seedhashes_checked,
        pairs_checked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotating_corpus::IndexProvenance;

    /// The report echoes the index it ran.
    ///
    /// Bites against a report that cannot be attributed to a rotation
    /// — a clean run whose log does not say what it explored is worth
    /// little more than no run.
    #[test]
    fn report_display_names_the_index_and_disclaims_pinning() {
        let r = RotationReport {
            index: 47,
            seedhashes_checked: 8,
            pairs_checked: 128,
        };
        let s = r.to_string();
        assert!(s.contains("rotation index 47"), "{s}");
        assert!(
            s.contains("explored, not pinned"),
            "the report must not read as corpus growth: {s}"
        );
    }

    /// Sizing defaults are the ones the CI lane budgets against.
    #[test]
    fn rotation_defaults_are_pinned() {
        assert_eq!(DEFAULT_ROTATION_SEEDHASHES, 8);
        assert_eq!(DEFAULT_ROTATION_DATA_PER_SEEDHASH, 16);
    }

    /// The lane's corpus is grouped by seedhash, which the run loop
    /// relies on to derive one cache per seedhash.
    ///
    /// Bites against a generator change that interleaves seedhashes:
    /// the loop would still be correct but would re-derive a 256-MiB
    /// cache per pair, turning an 8-seedhash rotation into a
    /// 128-derive run. A silent 16x cost regression with no failing
    /// assertion is exactly the kind of thing that goes unnoticed
    /// until a lane times out.
    #[test]
    fn rotating_corpus_is_grouped_by_seedhash() {
        let corpus = generate_rotating_corpus(
            RotationContext::new(47, IndexProvenance::ScheduleDerived),
            3,
            4,
        );
        let mut seen = Vec::new();
        let mut prev = None;
        for pair in &corpus {
            if Some(pair.seedhash) != prev {
                assert!(
                    !seen.contains(&pair.seedhash),
                    "seedhash group reopened; the run loop would re-derive its cache"
                );
                seen.push(pair.seedhash);
                prev = Some(pair.seedhash);
            }
        }
        assert_eq!(seen.len(), 3, "expected one group per requested seedhash");
    }
}
