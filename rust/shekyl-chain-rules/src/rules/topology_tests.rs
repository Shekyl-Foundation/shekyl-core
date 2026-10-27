// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Negative fixtures for CEN-A2 (`CHAIN_RULES_SLICE_1.md` §7), and the
//! falsifiers of the two 4.A rows the wire holds by construction (A6, A7).

use super::*;
use crate::block::Candidate;
use crate::census::CenRow;
use crate::harness::fixture::{candidate_on, chain_of, root};
use crate::harness::{assert_refused, defined, formed_on, FaultingView, MockChain};
use crate::rules::BlockContext;
use crate::verdict::{Locus, Verdict};
use shekyl_types::BlockHash;
use shekyl_wire::varint::write_varint;
use shekyl_wire::Block;
use std::io;

fn check_on(chain: &MockChain, candidate: &Candidate) -> Verdict<()> {
    let formed = formed_on(chain, candidate.clone());
    chain.with_view(|view| {
        defined(A2::check(
            &BlockContext::for_tests(&formed, chain.tip(), None).as_header(),
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
        A2::check(
            &BlockContext::for_tests(&formed, chain.tip(), None).as_header(),
            &view,
        ),
        Ok(Ok(()))
    );
}

// --- the wire invariants (A6, A7): held by `shekyl_wire::Block` ------------

/// CEN-A6's falsifier: a block blob the wire cannot parse is no block. A
/// fixture block round-trips through [`Block::from_bytes`]; every proper
/// prefix of its blob, and the blob with one trailing byte (§12 exact
/// consumption), is refused — so nothing malformed becomes a [`Candidate`].
#[test]
fn a6_a_block_blob_the_wire_cannot_parse_is_refused() {
    let block = candidate_on(&chain_of(3), Vec::new()).block;
    let blob = block.serialize();
    assert_eq!(Block::from_bytes(&blob).expect("round-trips"), block);
    for len in 0..blob.len() {
        assert!(
            Block::from_bytes(&blob[..len]).is_err(),
            "a {len}-byte prefix of a {}-byte block must not parse",
            blob.len()
        );
    }
    let mut trailing = blob;
    trailing.push(0);
    assert!(Block::from_bytes(&trailing).is_err());
}

/// CEN-A7's falsifier: a block claiming more than `2^28` transaction hashes
/// is refused at the count, before any hash is read. The wire's cap is
/// tighter than the census value — `READ_LEN_CAP`, `10^6`
/// (`shekyl-wire/src/lib.rs`) — so the census property holds a fortiori;
/// the two numbers are one field's two undocumented bounds (FOLLOWUPS,
/// *CEN-A7's per-block transaction-count bound*), and this test asserts
/// only the census value, not the provisional cap. The control count reaches
/// the hash read and fails there instead, so the assertion tells the cap
/// from a short blob.
#[test]
fn a7_a_transaction_hash_count_above_the_bound_is_refused_before_any_hash_is_read() {
    let blob = candidate_on(&chain_of(3), Vec::new()).block.serialize();
    // No listed transactions: the blob ends in the count, `varint(0)`.
    let (count, head) = blob.split_last().expect("non-empty");
    assert_eq!(*count, 0);
    let with_count = |n: u64| {
        let mut out = head.to_vec();
        write_varint(n, &mut out).expect("writing to a Vec is infallible");
        Block::from_bytes(&out).expect_err("no hash follows the count")
    };
    for n in [(1u64 << 28) + 1, u64::MAX] {
        let refused = with_count(n);
        assert_eq!(refused.kind(), io::ErrorKind::Other, "count {n}");
        assert!(
            refused.to_string().contains("transaction-hash count"),
            "count {n} is refused at the count: {refused}"
        );
    }
    assert_eq!(with_count(1).kind(), io::ErrorKind::UnexpectedEof);
}
