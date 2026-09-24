// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.D, the proof-of-work half (slice 2; `CHAIN_RULES_SLICE_2.md`
//! §4.2 as ruled, Q8): the longhash (D2), the seed it is computed under
//! (D3), the comparison against the target (D1) and the comparison's form
//! (D1b). The difficulty half — D4, D6 — is `rules/difficulty.rs`.
//!
//! # Split across the two stages, by what each row reads
//!
//! The ruling sorted these rows into the stateless stage and then found two
//! of them read the chain: D3's seed is the identity of the block at the
//! seed height, and D1's target is D4's derivation. So the split is by
//! operand, and it is also the C++'s (`cryptonote_tx_utils.cpp:770`–`:780`
//! fetches the seed id; `blockchain.cpp:5535` compares in the connect path):
//!
//! | Row | Stage | Reads |
//! | --- | --- | --- |
//! | D2 | `form` | the candidate's PoW preimage, a seed the caller **claims**, `Substrate::longhash` |
//! | D3 | `validate` | the view: is the claimed seed the block id at `seedheight(connecting)`? |
//! | D1b | `validate` | the longhash and the target: `hash · difficulty < 2^256` |
//! | D1 | `validate` | D1b's answer |
//!
//! The expensive call stays outside the write transaction; every
//! chain-dependent judgement stays inside it.
//!
//! # Two definitions, one verification, one predicate
//!
//! **D2** is a definition: *what the longhash is* — RandomX v2 over
//! `Block::pow_blob` under the seed, computed by the substrate. Recorded at
//! [`D2::longhash`], where it is derived; a substrate that cannot compute
//! returns its fault and `form` returns no verdict (the block is unproven,
//! not disproven — CEN-D2's fail-closed gate is the `Result`, and the
//! `0xff…` sentinel the C++ needed cannot be written here).
//!
//! **D3** verifies a claim. `form` had no view, so the caller told it which
//! seed to use; [`D3::verify_seed`] reads the block at
//! `seedheight(connecting)` — `0` for the first `2048 + 64` heights, else
//! `(h − 65) & !2047` (`shekyl_difficulty::seed_epoch`, moved there so the
//! validator adopts it without the engine crate) — and compares. Below
//! height 1 there is no block 0 yet and the C++'s `get_block_id_by_height`
//! returns `null_hash` on `BLOCK_DNE` (`blockchain.cpp:897`–`:911`;
//! *"the all-zero hash is a valid RandomX genesis seed"*), so the expected
//! seed at genesis admission is [`BlockHash::NULL`]. A mismatch is
//! [`Stale::Seed`] — a **fault**, never a refusal: the seed height is at
//! least `SEEDHASH_EPOCH_LAG` blocks below the connecting height, so the
//! claim can only be wrong if the chain reorganised that deep between the
//! stages, and the remedy is to redo `form` (bounded; `fault.rs`).
//!
//! **D1b** is the comparison's *form*: `check_hash` — `hash · difficulty <
//! 2^256` over the hash read little-endian — the KAT-ported body
//! (`shekyl-difficulty/tests/check_hash_vectors.rs`, 116 C++-oracle vectors).
//! Bucket 4: sealed by vectors, not ratified; ported as-is with them. It is
//! a definition — *what "satisfies" means* — evaluated once at
//! [`D1b::satisfies`] and recorded there.
//!
//! **D1** is the predicate: the longhash must satisfy the target. It reads
//! D1b's answer from the context and refuses on `false`. Two rows, one
//! comparison, each recorded by the writer that owns it.
//!
//! # The seed-epoch env lever is not here
//!
//! `SEEDHASH_EPOCH_*` is read at the FFI boundary and clamped there for the
//! C++ daemon; the validator reads no environment (slice 2 F5; the CEN-D3
//! pass condition in `CONSENSUS_STORE_RECONCILIATION.md` §5.4.1). D3 uses
//! the two constants at every nettype.

use shekyl_difficulty::{seedheight, SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG};
use shekyl_types::{BlockHash, BlockHeight, PowHash};

use crate::block::{Candidate, StructurallyValid};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Fault, Stale, ViewRead};
#[cfg(test)]
use crate::rules::difficulty::Target;
use crate::rules::{recorded, BlockContext, BlockRule, Rule};
use crate::substrate::Substrate;
use crate::verdict::{refused, Locus, Verdict};
use crate::view::ChainView;

/// CEN-D2: the longhash is RandomX v2 over the PoW preimage under the
/// seed, unconditionally; a verifier that cannot compute is the fail-closed
/// gate.
///
/// A definition (module docs), recorded at [`D2::longhash`].
pub(crate) struct D2;

impl Rule for D2 {
    const ROW: CenRow = CenRow::D2;
}

impl D2 {
    /// The candidate's longhash under `seed`, from the substrate, recorded
    /// in `coverage` as this row. `Err` is the substrate's fault: no
    /// longhash, no verdict.
    pub(crate) fn longhash<S: Substrate>(
        substrate: &S,
        candidate: &Candidate,
        seed: BlockHash,
        coverage: &mut RuleCoverage,
    ) -> Result<PowHash, S::Fault> {
        coverage.insert(Self::ROW);
        substrate.longhash(&candidate.block.pow_blob(), &seed)
    }
}

/// CEN-D3's schedule, stated once for every consumer: the height whose block
/// id seeds the RandomX cache for a block connecting at `connecting`, or
/// `None` at genesis admission — no block exists yet, and the seed is
/// [`BlockHash::NULL`] (module docs). The mainnet constants at every
/// nettype; no environment is read (slice 2 F5). The validator (D3), the
/// harness and the ingest driver's seed claim all call this, so the claim
/// and the check cannot spell the schedule differently.
#[must_use]
pub const fn seed_height(connecting: BlockHeight) -> Option<BlockHeight> {
    if connecting.is_zero() {
        return None;
    }
    Some(BlockHeight::from_raw(seedheight(
        connecting.to_raw(),
        SEEDHASH_EPOCH_BLOCKS,
        SEEDHASH_EPOCH_LAG,
    )))
}

/// CEN-D3: the seed is the block id at [`seed_height`] — epoch 2048, lag
/// 64 — or the null hash before block 0 exists.
///
/// Verifies the claim `form` was given against the committing view
/// (module docs); recorded at [`D3::verify_seed`].
pub(crate) struct D3;

impl Rule for D3 {
    const ROW: CenRow = CenRow::D3;
}

impl D3 {
    /// The seed the chain expects for a block connecting at `connecting`.
    fn expected_seed<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
    ) -> Result<BlockHash, ViewRead<V::Fault>> {
        let Some(seed_height) = seed_height(connecting) else {
            return Ok(BlockHash::NULL);
        };
        // `seed_height ≤ connecting − 1 − SEEDHASH_EPOCH_LAG` (or 0) is
        // below the tip on a conforming view — the shared parent-side read,
        // whose hole arm is the halting fault, not a panic (`recorded`).
        Ok(recorded(view, seed_height)?.hash)
    }

    /// Check the claimed seed against the view, recording this row.
    /// A mismatch is [`Stale::Seed`] with the retry the token allows.
    pub(crate) fn verify_seed<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
        formed: &StructurallyValid,
        coverage: &mut RuleCoverage,
    ) -> Result<(), Fault<V::Fault>> {
        coverage.insert(Self::ROW);
        let expected = Self::expected_seed(view, connecting)?;
        let claimed = formed.seed();
        if claimed == expected {
            Ok(())
        } else {
            Err(Fault::Stale(Stale::Seed {
                claimed,
                expected,
                retry: formed.attempt().next(),
            }))
        }
    }
}

/// CEN-D1b: the acceptance comparison is `hash · difficulty < 2^256`, the
/// hash read as a 256-bit little-endian integer — `check_hash`, KAT-ported.
///
/// A definition of *satisfies*, evaluated once at [`D1b::satisfies`] and
/// recorded there; D1 acts on the answer.
pub(crate) struct D1b;

impl Rule for D1b {
    const ROW: CenRow = CenRow::D1b;
}

impl D1b {
    /// Record this row: the comparison form is [`Target::is_satisfied_by`]
    /// (`check_hash`). D1 acts on the answer; the definition records here
    /// so a forgotten predicate cannot mint without naming the form.
    pub(crate) fn record(coverage: &mut RuleCoverage) {
        coverage.insert(Self::ROW);
    }

    /// Whether `pow` satisfies `target` under the ported comparison,
    /// recorded in `coverage` as this row. Test surface for the definition;
    /// production records at [`Self::record`] and D1 acts on
    /// [`Target::is_satisfied_by`].
    #[cfg(test)]
    pub(crate) fn satisfies(pow: PowHash, target: Target, coverage: &mut RuleCoverage) -> bool {
        Self::record(coverage);
        target.is_satisfied_by(pow)
    }
}

/// CEN-D1: the block's longhash must satisfy the difficulty target.
pub(crate) struct D1;

impl Rule for D1 {
    const ROW: CenRow = CenRow::D1;
}

impl BlockRule for D1 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        if cx.target.is_satisfied_by(cx.formed.pow()) {
            Ok(Ok(()))
        } else {
            refused(Self::ROW, Locus::Block)
        }
    }
}

#[cfg(test)]
#[path = "pow_tests.rs"]
mod pow_tests;
