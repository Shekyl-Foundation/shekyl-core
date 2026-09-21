// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What flows between the stateless stage and the writer: a formed block
//! or a rewind, in source order.
//!
//! `form` is `shekyl-chain-rules`' — this module only names what a worker
//! produces so the sequencer, the connector and the tests speak one type.
//! A [`Staged::Extend`] carries `form`'s **verdict**: a refusal by a
//! stateless rule is a verdict too, and travels to the connector to be
//! recorded, never dropped on the worker's floor (§1.1's supervision
//! table: a verdict is not a fault).

use shekyl_chain_rules::{
    form, Candidate, FormAttempt, RuleSet, StructurallyValid, Substrate, Verdict,
};
use shekyl_types::{BlockHash, BlockHeight};

/// One event after the stateless stage.
#[derive(Debug)]
pub enum Staged {
    /// A block at `height`, judged by every stateless rule.
    Extend {
        /// Where it connects.
        height: BlockHeight,
        /// `form`'s verdict: structurally valid, or refused by a rule.
        /// Boxed: the token carries the block and its bodies, a `Rewind`
        /// carries a height.
        formed: Box<Verdict<StructurallyValid>>,
    },
    /// Pop until the tip is `to`.
    Rewind {
        /// The height that is the tip after the rewind.
        to: BlockHeight,
    },
}

/// Run the stateless stage on one corpus block under `rule_set`, claiming
/// `seed` (from the [`SeedLedger`](crate::seed::SeedLedger)).
///
/// # Errors
///
/// The substrate's fault — the verifier could not compute. Terminal for
/// the run (§1.1); never a verdict.
pub fn form_extend<S: Substrate>(
    height: BlockHeight,
    candidate: Candidate,
    rule_set: &RuleSet,
    substrate: &S,
    seed: BlockHash,
    attempt: FormAttempt,
) -> Result<Staged, S::Fault> {
    let formed = Box::new(form(candidate, rule_set, substrate, seed, attempt)?);
    Ok(Staged::Extend { height, formed })
}

/// Re-run the stateless stage on a candidate the connector handed back
/// with a corrected seed (the bounded `Stale::Seed` retry, RD-Q5).
///
/// # Errors
///
/// As [`form_extend`].
pub fn re_form<S: Substrate>(
    height: BlockHeight,
    candidate: Candidate,
    rule_set: &RuleSet,
    substrate: &S,
    seed: BlockHash,
    attempt: FormAttempt,
) -> Result<Staged, S::Fault> {
    let formed = Box::new(form(candidate, rule_set, substrate, seed, attempt)?);
    Ok(Staged::Extend { height, formed })
}
