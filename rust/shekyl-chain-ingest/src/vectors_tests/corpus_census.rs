// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `Unmutable` census over the captured chains
//! (`CHAIN_RULES_SLICE_7.md` §3.7): for every mutation and every chain,
//! whether the mutation could apply at all. The replay that connects those
//! chains stays in the parent.

// Test-only by its parent (`vectors_tests`, gated at `lib.rs`). The inner
// attribute is this file's own declaration of that fact, for the
// debug-macro lint (`build.yml`), which scans each file for its own
// marker. The census prints its table; that line is a test report.
#![cfg(test)]

use std::path::Path;

use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::Candidate;

use crate::corpus::CorpusReader;
use crate::mutation::{ArchivalKind, Before, Environment, Mutation, Unmutable};
use crate::source::{IngestEvent, Source};
use crate::test_support::h;

use super::{captured_chains, shape_of, UntilRetiredJoin};

/// What one mutation can do on one captured chain: apply at some height,
/// or report why it cannot at every height.
#[derive(Debug, PartialEq, Eq)]
enum Reach {
    /// The first height the mutation applies at.
    Applies { first: u64 },
    /// Every distinct cause the corpus reported, over every height, in
    /// first-seen order.
    Unmutable(Vec<Unmutable>),
}

fn note(causes: &mut Vec<Unmutable>, cause: Unmutable) {
    if !causes.contains(&cause) {
        causes.push(cause);
    }
}
/// Every candidate of one captured chain in connect order, with what the
/// chain strictly below it established (`Before`: the key images spent,
/// the first listed body) — the operands `Mutation::apply` takes. A
/// `Rewind` truncates, as the pipeline would, and the state after it is
/// the retained tip's **post-block** state: its `before` plus its own
/// contribution (the first cut took `spent_before` alone, which would have
/// called a `DoubleSpend` of the retained tip's image `NothingSpentBefore`
/// — Copilot on #880; no captured chain rewinds, so the census's answer
/// did not move).
fn corpus_candidates(dir: &Path) -> Vec<(u64, Candidate, Before)> {
    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let mut reader = UntilRetiredJoin::new(
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus"),
    );
    let mut height = reader.first_height().to_raw();
    let mut chain: Vec<(u64, Candidate, Before)> = Vec::new();
    let mut below = Before::default();
    while let Some(event) = reader.next().expect("corpus reads") {
        match event.event {
            IngestEvent::Extend(candidate) => {
                let before = below.clone();
                below.remember(&candidate);
                chain.push((height, *candidate, before));
                height += 1;
            }
            IngestEvent::Rewind { to } => {
                chain.truncate(usize::try_from(to.to_raw() + 1).expect("small"));
                below = match chain.last() {
                    None => Before::default(),
                    Some((_, tip, before)) => {
                        let mut after = before.clone();
                        after.remember(tip);
                        after
                    }
                };
                height = to.to_raw() + 1;
            }
            // An inject occupies no height and lists no body: nothing a
            // block mutation could take as an operand.
            IngestEvent::Inject(_) => {}
        }
    }
    reader.finish(&shape_of(dir));
    chain
}

/// E6 slice 7 commit 2 (d): **the `Unmutable` census** (`CHAIN_RULES_SLICE_7.md`
/// §3.7). The E2 family is judged over the harness chain, never over these
/// captured chains; this test asks, for every mutation and every captured
/// chain, whether the mutation *could* apply there at all — and holds the
/// answer, so a mutation that is `Unmutable` on every chain in the corpus
/// is a recorded fact about the corpus's shape rather than a status a
/// reader mistakes for coverage.
///
/// Two causes are not the corpus's and are named apart: `PowUnderWrongSeed`
/// needs a PoW environment this census does not supply, and `DoubleSpend`
/// at a chain's first spend has nothing spent before it (it applies from
/// the second). Everything else that is `Unmutable` everywhere is a hole in
/// what the corpus carries.
#[test]
fn the_family_over_the_corpus_names_what_it_cannot_reach() {
    let chains = captured_chains();
    // A corpus chain brings no spare bodies, no twins and no wallet-made
    // spend bodies, and the bound is the validator's: the weight, the
    // signed-twin and the three spend mutations are `Unmutable` here by
    // construction, and the census says so below.
    let env = Environment {
        clock: MockSubstrate::CLOCK,
        pow: None,
        overweight: None,
        twins: &[],
        resigned: None,
    };
    // Per mutation (by its position in `Mutation::ALL`): `Some(causes)`
    // while it has been unreachable on every chain so far, `None` once one
    // chain carried it.
    let mut everywhere_unmutable: Vec<Option<Vec<Unmutable>>> =
        vec![Some(Vec::new()); Mutation::ALL.len()];
    let mut table = String::new();
    for (dir, manifest) in &chains {
        let candidates = corpus_candidates(dir);
        assert!(
            !candidates.is_empty(),
            "{}: the corpus has blocks",
            manifest.shape
        );
        for (i, mutation) in Mutation::ALL.into_iter().enumerate() {
            let mut causes = Vec::new();
            let mut reach = None;
            for (height, candidate, before) in &candidates {
                match mutation.apply(candidate.clone(), &env, before, h(*height)) {
                    Ok(_) => {
                        reach = Some(Reach::Applies { first: *height });
                        break;
                    }
                    Err(cause) => note(&mut causes, cause),
                }
            }
            let reach = reach.unwrap_or(Reach::Unmutable(causes));
            use std::fmt::Write as _;
            writeln!(
                table,
                "{:<16} {:<22} {reach:?}",
                manifest.shape,
                format!("{mutation:?}")
            )
            .expect("String write");
            match (reach, &mut everywhere_unmutable[i]) {
                (Reach::Unmutable(causes), Some(all)) => {
                    for cause in causes {
                        note(all, cause);
                    }
                }
                (Reach::Applies { .. }, slot) => *slot = None,
                (Reach::Unmutable(_), None) => {}
            }
        }
    }
    eprintln!(
        "Unmutable census over {} captured chains:\n{table}",
        chains.len()
    );

    let unreachable: Vec<(Mutation, Vec<Unmutable>)> = Mutation::ALL
        .into_iter()
        .zip(everywhere_unmutable)
        .filter_map(|(m, causes)| causes.map(|c| (m, c)))
        .collect();
    // Seven entries, and the census says whose — the environment's or the
    // corpus's, never the family's. `PowUnderWrongSeed`: this census
    // carries no PoW leg. `OverweightBlock`: no body supply — the corpus
    // census judges captured blocks as they are. `DoubleSpend`,
    // `UnknownReference`, `ReferenceTooRecent`: no wallet-made bodies
    // (`Environment::resigned`, 2026-10-16) — a captured chain's spends are
    // signed by a wallet this census does not hold; `DoubleSpend` at a
    // chain's first spend also has nothing spent before it. `DuplicateBondPost`: this
    // census supplies no twins, and the *other* cause —
    // `NoArchivalBodyToDuplicate` — is the heights that carry no post,
    // which is a reading of the corpus: *until 2026-10-12* the bond-post
    // capture did carry the body, so a twin supply would have reached it
    // (see the entry below). (`DuplicateClaim` was the
    // fifth until slice 8 row 9 retired it to the driver — `Mutation`
    // docs.) `DuplicateServeCredit` needs no supply (its
    // twin is the body itself) and is unreachable on the corpus alone: no
    // captured chain carries a serve credit. `ReorderedBodies` was the
    // corpus's until 2026-09-28 — every captured block listed at most one
    // body (slice 6 §5 row 8 measured it; slice 7 §3.7 names the class) —
    // and is reachable since the `median-full` capture (slice 7 commit
    // 4 (c)): its block 211 lists 23 bodies, so the mutations that need two
    // have a corpus witness there. A change here is a change in the
    // corpus's shape or in the family, and §3.7 moves with it.
    assert_eq!(
        unreachable,
        vec![
            (
                Mutation::PowUnderWrongSeed,
                vec![Unmutable::NoPowEnvironment]
            ),
            (
                Mutation::DuplicateServeCredit,
                vec![Unmutable::NoArchivalBodyToDuplicate {
                    kind: ArchivalKind::ServeCredit
                }]
            ),
            (
                Mutation::DuplicateBondPost,
                // *Moved 2026-10-12:* this also listed `NoTwinSupplied`
                // — the bond-post capture carried the body, so only the
                // twin was missing. That body is a keyless JoinMarket and
                // the chain is read only below it now
                // (`retired_keyless_join::RETIRED_KEYLESS_JOINS`), so no captured chain carries a
                // post at all and the one cause is the corpus's.
                vec![Unmutable::NoArchivalBodyToDuplicate {
                    kind: ArchivalKind::BondPost
                }]
            ),
            (Mutation::OverweightBlock, vec![Unmutable::NoBodySupply]),
            (
                Mutation::DoubleSpend,
                vec![
                    Unmutable::NothingSpentBefore,
                    Unmutable::NoResignedBody {
                        mutation: Mutation::DoubleSpend
                    }
                ]
            ),
            (
                Mutation::UnknownReference,
                vec![Unmutable::NoResignedBody {
                    mutation: Mutation::UnknownReference
                }]
            ),
            (
                Mutation::ReferenceTooRecent,
                vec![Unmutable::NoResignedBody {
                    mutation: Mutation::ReferenceTooRecent
                }]
            ),
        ],
        "the mutations no captured chain can carry, with why"
    );
}
