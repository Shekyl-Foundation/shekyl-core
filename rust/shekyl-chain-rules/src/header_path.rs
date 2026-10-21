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
use shekyl_types::{BlockHash, BlockHeight, TxHash};
use shekyl_wire::{Block, BlockBody, PowBlob, Transaction, TxBody};

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Fault, FormAttempt};
use crate::header_facts::{FormedHeader, HeaderFacts, OpenHeader, Proven};
use crate::header_ladder::{self, Derived};
use crate::rule_set::RuleSet;
use crate::rules::attestation::B4;
use crate::rules::body::G2;
use crate::rules::difficulty::Target;
use crate::rules::header::{B1, B2, B6};
use crate::rules::pow::{D1, D2};
use crate::rules::HeaderContext;
use crate::rules::Rule;
use crate::substrate::Substrate;
use crate::trust::Trust;
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::HeaderView;

/// What [`judge_header`] established. This is what a header tree records:
/// the height the header connects at, and the cumulative work through it.
#[derive(Clone, Copy, Debug)]
pub struct HeaderJudged {
    /// The height the view's tip derives.
    pub connecting: BlockHeight,
    /// The parent's cumulative difficulty plus the target the header met.
    pub cumulative_difficulty: CumulativeDifficulty,
    /// The rows this judgement ran and passed. Not a `validate` coverage.
    pub coverage: RuleCoverage,
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
    let hash = B6::identity_of(&blob, &mut coverage);
    let longhash = D2::longhash(substrate, &blob, seed, &mut coverage)?;
    let facts = HeaderFacts {
        header: pow.header.clone(),
        identity: hash,
        judged_at: clock,
        seed,
        target,
        attempt: FormAttempt::FIRST,
        proof: Proven { longhash },
    };
    if let Err(refused) = D1::judge(&facts, &mut coverage) {
        return Ok(Err(refused));
    }
    Ok(Ok(FormedHeader { facts, coverage }))
}

/// The view-bound header rows, over a header whose proof has not been
/// computed: [`header_ladder::derive`], then the parent link, the clock
/// and the anchor. CEN-D1 is not among them. F4, F5 and F6 are not among
/// them: those read the coinbase.
///
/// # Errors
///
/// [`Fault::View`] on the view's fault, [`Fault::Corrupt`] on a hole,
/// [`Fault::Stale`] when the seed or target claim is not this view's.
pub fn judge_header_cheap<'id, H: HeaderView<'id>>(
    header: &OpenHeader,
    view: &H,
    rule_set: &RuleSet,
    trust: &Trust,
) -> Result<Verdict<HeaderProspect>, Fault<H::Fault>> {
    let (derived, coverage) = match judge_rules(&header.facts, view, rule_set, trust)? {
        Ok(judged) => judged,
        Err(refused) => return Ok(Err(refused)),
    };
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
    let (derived, mut coverage) = match judge_rules(&header.facts, view, rule_set, trust)? {
        Ok(judged) => judged,
        Err(refused) => return Ok(Err(refused)),
    };
    coverage.union(&header.coverage);
    Ok(Ok(HeaderJudged {
        connecting: derived.connecting,
        cumulative_difficulty: derived.cumulative_difficulty,
        coverage,
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
        facts.seed,
        facts.target,
        facts.attempt,
        view,
        rule_set,
        &mut coverage,
    )? {
        Ok(derived) => derived,
        Err(refused) => return Ok(Err(refused)),
    };
    let cx = HeaderContext {
        facts,
        connecting: derived.connecting,
        tip: derived.tip,
        mtp_window: derived.mtp_window.as_ref(),
        trust,
    };
    if let Err(refused) = header_ladder::parent_link(&cx, view, &mut coverage)? {
        return Ok(Err(refused));
    }
    if let Err(refused) = header_ladder::clock(&cx, view, &mut coverage)? {
        return Ok(Err(refused));
    }
    if let Err(refused) = header_ladder::anchor(&cx, view, &mut coverage)? {
        return Ok(Err(refused));
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
pub fn bind_body(header: &FormedHeader, body: &BlockBody) -> Verdict<()> {
    let Ok(block) = Block::from_bytes(&body.block) else {
        return Err(InvalidBlock::new(CenRow::B6, Locus::Block));
    };
    if block.hash() != header.facts.identity {
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
        TxBody::Full(bytes) => {
            let mut cursor = bytes.as_slice();
            Transaction::read(&mut cursor)
                .map(|tx| tx.hash())
                .map_err(|_| ())
        }
        TxBody::Skeleton(skeleton) => skeleton.txid().map_err(|_| ()),
    }
}
