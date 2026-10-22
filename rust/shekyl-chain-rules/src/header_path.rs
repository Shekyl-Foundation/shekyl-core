// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The header path (CS-1, `P2P_3_CHAIN_SYNC_BRIEF.md` CS-Q2).
//!
//! A header chain is judged by the same rules `validate` runs, from the
//! header alone. [`form_header`] is `form`'s header rows: B1, B2, the
//! identity, the longhash, CEN-D1. [`judge_header_cheap`] is the view-bound
//! header rows over a header whose proof has not been computed.
//! [`judge_header`] is those rows over a header CEN-D1 has accepted, and
//! its verdict carries the height and the cumulative work. [`bind_body`]
//! checks a body against the header it claims, statelessly.
//!
//! None of these mint a [`ChainValid`](crate::ChainValid). The coverage
//! they record is their own.

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHash, BlockHeight, Timestamp, TxHash};
use shekyl_wire::{Block, BlockBody, PowBlob, Transaction, TxBody};

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Fault, FormAttempt, Stale};
use crate::header_facts::{prove_header, FormedHeader, HeaderFacts, HeaderProof, OpenHeader};
use crate::header_ladder::{self, Derived};
use crate::rule_set::RuleSet;
use crate::rules::attestation::B4;
use crate::rules::body::G2;
use crate::rules::difficulty::Target;
use crate::rules::header::{B1, B2};
use crate::rules::HeaderContext;
use crate::rules::Rule;
use crate::substrate::Substrate;
use crate::trust::Trust;
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::HeaderView;

/// What [`judge_header`] established. This is what a header tree records,
/// and the proof [`crate::form_judged`] takes instead of hashing again.
///
/// Constructed only by `judge_header`. The fields are private:
///
/// ```compile_fail
/// let forged = shekyl_chain_rules::HeaderJudged {
///     facts: todo!(),
///     proof_coverage: todo!(),
///     coverage: todo!(),
///     rule_set: todo!(),
///     connecting: todo!(),
///     cumulative_difficulty: todo!(),
/// };
/// ```
#[must_use = "a HeaderJudged is the proof of a header; dropping it discards that proof"]
#[derive(Clone, Debug)]
pub struct HeaderJudged {
    facts: crate::header_facts::HeaderFacts<crate::header_facts::Proven>,
    /// B1, B2, B6, D2 and D1, as `form_header` recorded them. [`crate::form_judged`]
    /// unions this and does not run those rows again.
    proof_coverage: RuleCoverage,
    /// The rows this judgement ran and passed, proof and view-bound.
    coverage: RuleCoverage,
    rule_set: RuleSet,
    connecting: BlockHeight,
    cumulative_difficulty: CumulativeDifficulty,
}

impl HeaderJudged {
    /// The height the view's tip derives.
    #[must_use]
    pub const fn connecting(&self) -> BlockHeight {
        self.connecting
    }

    /// The parent's cumulative difficulty plus the target the header met.
    #[must_use]
    pub const fn cumulative_difficulty(&self) -> CumulativeDifficulty {
        self.cumulative_difficulty
    }

    /// The rows this judgement ran and passed.
    #[must_use]
    pub const fn coverage(&self) -> &RuleCoverage {
        &self.coverage
    }

    /// The block identity CEN-B6 derived from the PoW preimage.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.facts.identity()
    }

    /// The parent this header names. The header tree's link.
    #[must_use]
    pub const fn previous(&self) -> BlockHash {
        self.facts.header().previous
    }

    /// The rules the header was formed under.
    #[must_use]
    pub const fn rule_set(&self) -> RuleSet {
        self.rule_set
    }

    /// The seed the header was proved under.
    #[must_use]
    pub const fn seed(&self) -> BlockHash {
        self.facts.seed()
    }

    /// The target CEN-D1 accepted.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.facts.target()
    }

    /// Which attempt produced the proof.
    #[must_use]
    pub const fn attempt(&self) -> FormAttempt {
        self.facts.attempt()
    }

    /// The clock the header was judged at. Earlier than a fresh reading
    /// would be, so an FTL check against it is never looser.
    #[must_use]
    pub const fn judged_at(&self) -> Timestamp {
        self.facts.judged_at()
    }

    /// The proof rows `form_header` recorded.
    #[must_use]
    pub(crate) const fn proof_coverage(&self) -> &RuleCoverage {
        &self.proof_coverage
    }

    /// The proven facts, including the longhash.
    #[must_use]
    pub(crate) const fn facts(
        &self,
    ) -> &crate::header_facts::HeaderFacts<crate::header_facts::Proven> {
        &self.facts
    }
}

/// What [`judge_header_cheap`] established, before the proof. The work is
/// the claim a later work test compares. It is not a [`HeaderJudged`]: a
/// header the proof has not accepted does not enter the tree.
#[derive(Clone, Copy, Debug)]
pub struct HeaderProspect {
    /// The height the view's tip derives.
    pub connecting: BlockHeight,
    /// The parent's cumulative difficulty plus the target the header claims.
    pub cumulative_difficulty: CumulativeDifficulty,
    /// The rows the cheap checks ran and passed.
    pub coverage: RuleCoverage,
}

/// Judge a PoW preimage the way `form` judges a block's header.
///
/// Order: the clock, once; B1; B2; the identity (B6); the longhash (D2);
/// CEN-D1 against `target`. A refusal is the row `form` would name.
/// `attempt` is which try this is, the same value `form` takes: a driver
/// starts at [`FormAttempt::FIRST`] and passes back only the attempt a
/// [`crate::Fault::Stale`] hands it. The rule set stays on the token.
///
/// # Errors
///
/// The substrate's fault, from the clock or the longhash. A refusal is
/// `Ok(Err(_))`.
pub fn form_header<S: Substrate>(
    pow: &PowBlob,
    rule_set: &RuleSet,
    substrate: &S,
    seed: BlockHash,
    target: Target,
    attempt: FormAttempt,
) -> Result<Verdict<FormedHeader>, S::Fault> {
    let clock = substrate.local_clock()?;
    let mut coverage = RuleCoverage::EMPTY;
    if let Err(refused) = B1::judge(&pow.header, rule_set) {
        return Ok(Err(refused));
    }
    coverage.insert(B1::ROW);
    if let Err(refused) = B2::judge(&pow.header) {
        return Ok(Err(refused));
    }
    coverage.insert(B2::ROW);

    let blob = pow.write();
    let facts = match prove_header(
        HeaderProof {
            header: pow.header.clone(),
            pow_blob: &blob,
            substrate,
            seed,
            target,
            attempt,
            judged_at: clock,
        },
        &mut coverage,
    )? {
        Ok(facts) => facts,
        Err(refused) => return Ok(Err(refused)),
    };
    Ok(Ok(FormedHeader::new(facts, coverage, *rule_set)))
}

/// Why [`judge_header_cheap`] stopped before a verdict: the substrate's
/// clock, or the view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProspectFault<S, V> {
    /// [`Substrate::local_clock`] failed. No row ran.
    Substrate(S),
    /// The view faulted, or the seed or target claim is not this view's.
    Chain(Fault<V>),
}

/// The view-bound header rows, over a header whose proof has not been
/// computed. Order: the substrate's clock, once; B1; B2; then
/// [`header_ladder::derive`], the parent link, the clock and the anchor.
/// CEN-D1 is not among them, and this function does not hash. F4, F5 and
/// F6 are not among them: those read the coinbase.
///
/// # Errors
///
/// [`ProspectFault::Substrate`] from the clock. [`ProspectFault::Chain`]
/// carries [`Fault::View`], [`Fault::Corrupt`] or [`Fault::Stale`].
pub fn judge_header_cheap<'id, S: Substrate, H: HeaderView<'id>>(
    header: &OpenHeader,
    view: &H,
    rule_set: &RuleSet,
    trust: &Trust,
    substrate: &S,
) -> Result<Verdict<HeaderProspect>, ProspectFault<S::Fault, H::Fault>> {
    let judged_at = substrate.local_clock().map_err(ProspectFault::Substrate)?;
    let facts = header.at(judged_at);
    let mut coverage = RuleCoverage::EMPTY;
    if let Err(refused) = B1::judge(facts.header(), rule_set) {
        return Ok(Err(refused));
    }
    coverage.insert(B1::ROW);
    if let Err(refused) = B2::judge(facts.header()) {
        return Ok(Err(refused));
    }
    coverage.insert(B2::ROW);
    let (derived, view_coverage) =
        match judge_rules(&facts, view, rule_set, trust).map_err(ProspectFault::Chain)? {
            Ok(judged) => judged,
            Err(refused) => return Ok(Err(refused)),
        };
    coverage.union(&view_coverage);
    Ok(Ok(HeaderProspect {
        connecting: derived.connecting,
        cumulative_difficulty: derived.cumulative_difficulty,
        coverage,
    }))
}

/// [`judge_header_cheap`] over a header CEN-D1 has accepted. The result is
/// what a header tree records.
///
/// # Errors
///
/// As [`judge_header_cheap`].
pub fn judge_header<'id, H: HeaderView<'id>>(
    header: &FormedHeader,
    view: &H,
    rule_set: &RuleSet,
    trust: &Trust,
) -> Result<Verdict<HeaderJudged>, Fault<H::Fault>> {
    if header.rule_set() != *rule_set {
        return Err(Fault::Stale(Stale::RuleSet {
            formed_under: Box::new(header.rule_set()),
            in_force: Box::new(*rule_set),
            retry: header.attempt().next(),
        }));
    }
    let (derived, mut coverage) = match judge_rules(header.facts(), view, rule_set, trust)? {
        Ok(judged) => judged,
        Err(refused) => return Ok(Err(refused)),
    };
    coverage.union(header.coverage());
    Ok(Ok(HeaderJudged {
        facts: header.facts().clone(),
        proof_coverage: *header.coverage(),
        coverage,
        rule_set: header.rule_set(),
        connecting: derived.connecting,
        cumulative_difficulty: derived.cumulative_difficulty,
    }))
}

fn judge_rules<'id, P, H: HeaderView<'id>>(
    facts: &HeaderFacts<P>,
    view: &H,
    rule_set: &RuleSet,
    trust: &Trust,
) -> Result<Verdict<(Derived, RuleCoverage)>, Fault<H::Fault>> {
    let mut coverage = RuleCoverage::EMPTY;
    let derived = match header_ladder::derive(
        facts.seed(),
        facts.target(),
        facts.attempt(),
        view,
        rule_set,
        &mut coverage,
    )? {
        Ok(derived) => derived,
        Err(refused) => return Ok(Err(refused)),
    };
    // The context borrows `derived`'s window. It ends before `derived` moves.
    {
        let cx = HeaderContext::from_derived(facts, &derived, trust);
        if let Err(refused) = header_ladder::parent_link(&cx, view, &mut coverage)? {
            return Ok(Err(refused));
        }
        if let Err(refused) = header_ladder::clock(&cx, view, &mut coverage)? {
            return Ok(Err(refused));
        }
        if let Err(refused) = header_ladder::anchor(&cx, view, &mut coverage)? {
            return Ok(Err(refused));
        }
    }
    Ok(Ok((derived, coverage)))
}

/// A body matches its header: the block's identity, every carried
/// transaction's txid (CEN-G2, a skeleton through
/// [`Transaction::hash_with_supplied_components`]), and the witness's root
/// (CEN-B4's stateless half). The countersignatures stay `validate`'s.
///
/// A mismatch is the row `validate` would name. What a session does with
/// it is the caller's.
pub fn bind_body(header: &HeaderJudged, body: &BlockBody) -> Verdict<()> {
    let Ok(block) = Block::from_bytes(&body.block) else {
        return Err(InvalidBlock::new(CenRow::B6, Locus::Block));
    };
    if block.hash() != header.hash() {
        return Err(InvalidBlock::new(CenRow::B6, Locus::Block));
    }
    let mut carried = Vec::with_capacity(body.txs.len());
    for tx in &body.txs {
        let Ok(hash) = txid_of(tx) else {
            return Err(InvalidBlock::new(CenRow::G2, Locus::Block));
        };
        carried.push(hash);
    }
    G2::listed_match(&block.transaction_hashes, &carried)?;
    let root = *block.header.attestation_root.as_bytes();
    B4::bind_root(
        &block.miner_transaction.prefix.extra,
        &body.attestation_witness,
        &root,
    )?;
    Ok(())
}

fn txid_of(tx: &TxBody) -> Result<TxHash, ()> {
    match tx {
        TxBody::Full(bytes) => Transaction::from_bytes(bytes)
            .map(|tx| tx.hash())
            .map_err(|_| ()),
        TxBody::Skeleton(skeleton) => skeleton.txid().map_err(|_| ()),
    }
}

#[cfg(test)]
mod tests {
    use shekyl_types::BlockHash;

    use super::*;
    use crate::block::ReferenceClaims;
    use crate::census::CenRow;
    use crate::fault::Retry;
    use shekyl_difficulty::{CumulativeDifficulty, N};

    use crate::harness::fixture::{candidate, candidate_on, chain_of, recorded_with_work, root};
    use crate::harness::{expected_seed, expected_target, MockChain, MockSubstrate};
    use crate::trust::Trust;
    use crate::{form, form_judged, validate};

    /// `judge_header` faults a rule set other than the one `form_header`
    /// kept, and the retry is the attempt that was formed, not a fresh one.
    #[test]
    fn a_header_formed_under_another_rule_set_is_stale() {
        let admits_two = RuleSet::admitting_for_tests(2);
        let mut input = candidate(Vec::new());
        input.block.header.major_version = 2;
        let chain = MockChain::default();
        let target = expected_target(&chain, &admits_two);
        let pow = PowBlob::read(&input.block.pow_blob()).expect("the preimage parses");
        let formed = form_header(
            &pow,
            &admits_two,
            &MockSubstrate::default(),
            BlockHash::NULL,
            target,
            FormAttempt::FIRST,
        )
        .expect("the mock answers")
        .expect("major 2 passes B1 under a set that admits 2");
        chain.with_view(|view| {
            let fault = judge_header(&formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED)
                .expect_err("a different rule set is a fault");
            let Fault::Stale(Stale::RuleSet {
                formed_under,
                in_force,
                retry,
            }) = fault
            else {
                panic!("expected Stale::RuleSet, got {fault:?}");
            };
            assert_eq!(*formed_under, admits_two);
            assert_eq!(*in_force, RuleSet::GENESIS);
            assert_eq!(retry, Retry::Again(FormAttempt::FIRST.next_for_tests()));
        });
    }

    #[test]
    fn the_last_header_attempt_does_not_restart() {
        let admits_two = RuleSet::admitting_for_tests(2);
        let mut input = candidate(Vec::new());
        input.block.header.major_version = 2;
        let chain = MockChain::default();
        let target = expected_target(&chain, &admits_two);
        let pow = PowBlob::read(&input.block.pow_blob()).expect("the preimage parses");
        let formed = form_header(
            &pow,
            &admits_two,
            &MockSubstrate::default(),
            BlockHash::NULL,
            target,
            FormAttempt::last_for_tests(),
        )
        .expect("the mock answers")
        .expect("the header forms");
        chain.with_view(|view| {
            let fault = judge_header(&formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED)
                .expect_err("a different rule set is a fault");
            match fault {
                Fault::Stale(Stale::RuleSet { retry, .. }) => {
                    assert_eq!(retry, Retry::Exhausted);
                }
                other => panic!("expected Stale::RuleSet, got {other:?}"),
            }
        });
    }

    /// The judged-header entry does not hash, matches `form` on the claims
    /// and the coverage, refuses a different identity as B6, and still
    /// leaves `validate` to fault a rule set the token does not carry.
    #[test]
    fn form_judged_reuses_the_proof() {
        let chain = MockChain::default();
        let rule_set = RuleSet::GENESIS;
        let target = expected_target(&chain, &rule_set);
        let input = candidate(Vec::new());
        let pow = PowBlob::read(&input.block.pow_blob()).expect("preimage");
        let substrate = MockSubstrate::default();
        let formed = form_header(
            &pow,
            &rule_set,
            &substrate,
            BlockHash::NULL,
            target,
            FormAttempt::FIRST,
        )
        .expect("mock")
        .expect("forms");
        chain.with_view(|view| {
            let judged =
                match judge_header(&formed, &view, &rule_set, &Trust::UNANCHORED).expect("view") {
                    Ok(judged) => judged,
                    Err(refused) => panic!("honest header refused: {refused:?}"),
                };
            let from_header = form_judged(input.clone(), &judged, &ReferenceClaims::EMPTY)
                .expect("the body forms");
            let from_bytes = form(
                input.clone(),
                &rule_set,
                &substrate,
                BlockHash::NULL,
                target,
                &ReferenceClaims::EMPTY,
                FormAttempt::FIRST,
            )
            .expect("mock")
            .expect("forms");
            assert_eq!(from_header.coverage(), from_bytes.coverage());
            assert_eq!(from_header.rule_set(), from_bytes.rule_set());
            assert_eq!(from_header.seed(), from_bytes.seed());
            assert_eq!(from_header.target(), from_bytes.target());
            assert_eq!(from_header.attempt(), from_bytes.attempt());
            assert_eq!(from_header.judged_at(), from_bytes.judged_at());
            assert_eq!(from_header.hash(), from_bytes.hash());
            assert_eq!(from_header.pow(), from_bytes.pow());
            let mut moved = input;
            moved.block.header.nonce = moved.block.header.nonce.wrapping_add(1);
            match form_judged(moved, &judged, &ReferenceClaims::EMPTY) {
                Err(refused) => assert_eq!(refused.rule, CenRow::B6),
                Ok(_) => panic!("a different preimage formed"),
            }
            let fault = validate(
                from_header,
                &view,
                &RuleSet::admitting_for_tests(2),
                &Trust::UNANCHORED,
            )
            .expect_err("a different rule set is a fault");
            assert!(matches!(fault, Fault::Stale(Stale::RuleSet { .. })));
        });
    }

    /// `N + 1` blocks, one timestamp series, `per_block` of work each. The
    /// seed is block 0's hash, which is the timestamp's, so two calls share
    /// a seed and, once the window is open, not a target.
    fn worked_chain(per_block: u128) -> MockChain {
        let mut chain = MockChain::default();
        let mut ts = 1_000u64;
        let mut cum = 0u128;
        for i in 0..=N {
            ts += 120;
            cum += per_block + u128::from(i);
            chain = chain.push(
                recorded_with_work(ts, CumulativeDifficulty::from_raw(cum)),
                root(1),
            );
        }
        chain
    }

    /// `validate` faults a seed the token carries that this view does not,
    /// and a target likewise. The token was judged where each claim held.
    #[test]
    fn validate_faults_a_token_seed_or_target_the_view_does_not_hold() {
        let deep = chain_of(2113);
        let deep_seed = expected_seed(&deep);
        let deep_target = expected_target(&deep, &RuleSet::GENESIS);
        let deep_candidate = candidate_on(&deep, Vec::new());
        let pow = PowBlob::read(&deep_candidate.block.pow_blob()).expect("preimage");
        let formed = form_header(
            &pow,
            &RuleSet::GENESIS,
            &MockSubstrate::default(),
            deep_seed,
            deep_target,
            FormAttempt::FIRST,
        )
        .expect("mock")
        .expect("the header forms");
        let judged = deep.with_view(|view| {
            match judge_header(&formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED).expect("view")
            {
                Ok(judged) => judged,
                Err(refused) => panic!("honest header refused: {refused:?}"),
            }
        });
        let from_header =
            form_judged(deep_candidate, &judged, &ReferenceClaims::EMPTY).expect("the body forms");
        MockChain::default().with_view(|view| {
            match validate(from_header, &view, &RuleSet::GENESIS, &Trust::UNANCHORED) {
                Err(Fault::Stale(Stale::Seed { claimed, .. })) => {
                    assert_eq!(claimed, deep_seed);
                }
                other => panic!("expected Stale::Seed, got {other:?}"),
            }
        });

        // Same timestamps, so the seed block is the same hash. Different
        // work, so once the window is open the targets diverge.
        let claimed_on = worked_chain(4_000);
        let judged_on = worked_chain(400);
        let long_target = expected_target(&claimed_on, &RuleSet::GENESIS);
        let short_target = expected_target(&judged_on, &RuleSet::GENESIS);
        assert_eq!(expected_seed(&claimed_on), expected_seed(&judged_on));
        assert_ne!(
            long_target, short_target,
            "the two chains derive different targets"
        );
        let long_candidate = candidate_on(&claimed_on, Vec::new());
        let long_seed = expected_seed(&claimed_on);
        let pow = PowBlob::read(&long_candidate.block.pow_blob()).expect("preimage");
        let formed = form_header(
            &pow,
            &RuleSet::GENESIS,
            &MockSubstrate::default(),
            long_seed,
            long_target,
            FormAttempt::FIRST,
        )
        .expect("mock")
        .expect("the header forms");
        let judged = claimed_on.with_view(|view| {
            match judge_header(&formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED).expect("view")
            {
                Ok(judged) => judged,
                Err(refused) => panic!("honest header refused: {refused:?}"),
            }
        });
        let from_header =
            form_judged(long_candidate, &judged, &ReferenceClaims::EMPTY).expect("the body forms");
        judged_on.with_view(|view| {
            match validate(from_header, &view, &RuleSet::GENESIS, &Trust::UNANCHORED) {
                Err(Fault::Stale(Stale::Target {
                    claimed, expected, ..
                })) => {
                    assert_eq!(claimed, long_target);
                    assert_eq!(expected, short_target);
                }
                other => panic!("expected Stale::Target, got {other:?}"),
            }
        });
    }
}
