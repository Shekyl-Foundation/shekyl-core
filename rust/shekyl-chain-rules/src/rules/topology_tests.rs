// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Negative fixtures for CEN-A2 (`CHAIN_RULES_SLICE_1.md` §7).

use super::*;
use crate::block::Candidate;
use crate::census::CenRow;
use crate::harness::fixture::{candidate_on, root};
use crate::harness::{assert_refused, formed_on, infallible, FaultingView, MockChain};
use crate::rules::BlockContext;
use crate::verdict::{Locus, Verdict};
use shekyl_types::BlockHash;

fn check_on(chain: &MockChain, candidate: &Candidate) -> Verdict<()> {
    let formed = formed_on(chain, candidate.clone());
    chain.with_view(|view| {
        infallible(A2::check(
            &BlockContext::for_tests(&formed, chain.tip(), None),
            &view,
        ))
    })
}

#[test]
fn cen_a2_previous_must_be_the_tip_hash() {
    let chain = MockChain::default().push(crate::harness::fixture::recorded(1_000), root(0xa0));
    let tip = chain.tip().expect("one block");
    // The fixture builds the candidate on the chain's tip: it passes.
    let good = candidate_on(&chain, Vec::new());
    assert_eq!(good.block.header.previous, tip.hash);
    check_on(&chain, &good).expect("previous == tip hash passes A2");

    // Any other parent — a bit flipped, the null hash, a hash one block
    // back — is refused on A2 at the block.
    let mut flipped = good.clone();
    flipped.block.header.previous = {
        let mut bytes = flipped.block.header.previous.to_bytes();
        bytes[0] ^= 1;
        BlockHash::from_bytes(bytes)
    };
    assert_refused(check_on(&chain, &flipped), CenRow::A2, Locus::Block);
    let mut zero = good.clone();
    zero.block.header.previous = BlockHash::NULL;
    assert_refused(check_on(&chain, &zero), CenRow::A2, Locus::Block);
}

#[test]
fn cen_a2_genesis_previous_is_the_null_hash() {
    // Empty chain: `top_block_hash` is `null_hash` in the C++, so the
    // genesis candidate's `previous` is all zeros — and only that.
    let chain = MockChain::default();
    assert_eq!(chain.tip(), None);
    let genesis = candidate_on(&chain, Vec::new());
    assert_eq!(genesis.block.header.previous, BlockHash::NULL);
    check_on(&chain, &genesis).expect("genesis with a null previous passes A2");

    let mut not_genesis = genesis;
    not_genesis.block.header.previous = BlockHash::from_bytes([0x11; 32]);
    assert_refused(check_on(&chain, &not_genesis), CenRow::A2, Locus::Block);
}

#[test]
fn cen_a2_reads_the_context_tip_not_the_view() {
    // The connecting tip is a shared connect fact, derived once. A2 does
    // not re-read `view.tip()`, so a view that cannot answer still yields
    // a verdict from the context.
    let chain = MockChain::default();
    let formed = formed_on(&chain, candidate_on(&chain, Vec::new()));
    let view = FaultingView::default();
    assert_eq!(
        A2::check(&BlockContext::for_tests(&formed, chain.tip(), None), &view),
        Ok(Ok(()))
    );
}
