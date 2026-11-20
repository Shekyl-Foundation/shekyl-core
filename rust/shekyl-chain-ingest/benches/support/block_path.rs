// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Setup shared by the two block-path bench targets (`block_path_iai.rs`,
//! `block_path_full_iai.rs`): a fixture replayed to each point a row
//! starts from. Everything here runs outside the measured region.

use shekyl_chain_ingest::bench_support::{BlockPath, Claimed};
use shekyl_chain_rules::{Candidate, StructurallyValid};

/// A chain replayed to the block below the subject, and the subject with
/// its claims read.
pub fn before_form(corpus: &[u8]) -> (BlockPath, Candidate, Claimed) {
    let (mut chain, subject) = BlockPath::replayed(corpus);
    let claimed = chain.claims(&subject);
    (chain, subject, claimed)
}

/// The same chain with the subject formed: what `connect` is handed.
pub fn before_connect(corpus: &[u8]) -> (BlockPath, StructurallyValid, Claimed) {
    let (chain, subject, claimed) = before_form(corpus);
    let formed = chain.form(subject, &claimed);
    (chain, formed, claimed)
}

/// The same chain with the subject connected: what `pop` removes and what
/// the read rows read.
pub fn connected(corpus: &[u8]) -> BlockPath {
    let (mut chain, formed, claimed) = before_connect(corpus);
    chain.connect(formed, &claimed);
    chain
}
