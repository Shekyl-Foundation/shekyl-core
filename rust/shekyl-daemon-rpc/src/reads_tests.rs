// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The chain's reads over in-memory facts: every method's rules, pinned
//! once for every caller (`reads.rs`'s module docs).

use super::*;
use crate::chain_facts::decode_target_count;
use crate::core::ArchivalGood;
use crate::methods::tests::{facts, patterned_hash, tagged_bytes, tagged_hash, FakeFacts};
use crate::read_facts::{
    AdmittedPow, AltChainFacts, BlockRead, BlocksAt, ClaimSource, CurveTreeFacts, ListedTx,
    ShardCoverage, TransactionsAt,
};
use serde_json::json;
use shekyl_types::{CurveTreeRoot, PowHash, ShardId};
use shekyl_wire::Transaction;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

// ── an in-memory chain read ─────────────────────────────────────────────

/// In-memory [`ChainReadFacts`]: canned answers for the reads these tests
/// drive, and `NotReady` for the rest. Records the pool scope it was asked
/// with, because the scope is the whole of the pool's privacy rule.
#[derive(Default)]
struct FakeRead {
    slots: Vec<TxSlot>,
    chain_height: u64,
    output_indices: Option<Vec<u64>>,
    blocks: Vec<BlockRead>,
    spent: Vec<SpentAt>,
    coinbase: Option<CoinbaseRange>,
    curve_after: Option<CurveTreeFacts>,
    alt: Vec<AltChainFacts>,
    scope: Mutex<Option<PoolScope>>,
}

impl ChainReadFacts for FakeRead {
    fn blocks_by_height(&self, heights: &[BlockHeight]) -> Result<BlocksAt, FactsFault> {
        Ok(BlocksAt {
            blocks: self.blocks.iter().take(heights.len()).cloned().collect(),
            failed: None,
        })
    }
    fn transactions(&self, ids: &[TxHash], scope: PoolScope) -> Result<TransactionsAt, FactsFault> {
        *self.scope.lock().expect("not poisoned") = Some(scope);
        assert_eq!(ids.len(), self.slots.len(), "one slot per id");
        Ok(TransactionsAt {
            slots: self.slots.clone(),
            chain_height: self.chain_height,
        })
    }
    fn output_indices(&self, _txid: &TxHash) -> Result<Option<Vec<u64>>, FactsFault> {
        Ok(self.output_indices.clone())
    }
    fn key_images_spent(&self, key_images: &[KeyImage]) -> Result<Vec<SpentAt>, FactsFault> {
        assert_eq!(key_images.len(), self.spent.len());
        Ok(self.spent.clone())
    }
    fn alt_block_hashes(&self) -> Result<Vec<BlockHash>, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn alternate_chains(&self) -> Result<Vec<AltChainFacts>, FactsFault> {
        Ok(self.alt.clone())
    }
    fn curve_tree(&self) -> Result<CurveTreeFacts, FactsFault> {
        self.curve_after.ok_or(FactsFault::NotReady)
    }
    fn curve_tree_after(&self, _height: BlockHeight) -> Result<Option<CurveTreeFacts>, FactsFault> {
        Ok(self.curve_after)
    }
    fn coinbase_sum(&self, _start: BlockHeight, _count: u64) -> Result<CoinbaseRange, FactsFault> {
        self.coinbase.ok_or(FactsFault::NotReady)
    }
    fn admit_pow(&self, _seed: PowSeed) -> Result<PowAdmission, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn hash_admitted(&self, _blob: &[u8], _admitted: &AdmittedPow) -> Result<PowHash, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn emission_claim_source(&self, _persona: &PCanonicalId) -> Result<ClaimSource, FactsFault> {
        Err(FactsFault::NotReady)
    }
    fn shard_coverage(&self) -> Result<ShardCoverage, FactsFault> {
        Err(FactsFault::NotReady)
    }
}

fn refusal(fault: RpcFault) -> RpcError {
    fault.into_error()
}

fn at_height(height: u64, pow: bool) -> block::HeaderSelect {
    block::HeaderSelect(block::BlockSelect {
        select: shared::Selector::Height(Height(height)),
        pow,
        prune: None,
    })
}

fn tip(pow: bool) -> block::HeaderSelect {
    block::HeaderSelect(block::BlockSelect {
        select: shared::Selector::Tip,
        pow,
        prune: None,
    })
}

fn by_hash(hash: BlockHash) -> block::HeaderSelect {
    block::HeaderSelect(block::BlockSelect {
        select: shared::Selector::Hash(block_hash(hash)),
        pow: false,
        prune: None,
    })
}

/// A chain whose tip is 42 blocks above the sample header's height.
fn header_facts() -> FakeFacts {
    let mut f = facts(true, 0);
    f.hash_chain_height = ChainCount::from_raw(1_234_610);
    f
}

// ── the tip and the version ─────────────────────────────────────────────

/// `chain_height` is the tip's height, an ordinal (IG-Q45): the count less
/// one, with the tip's hash and the writer's state (IG-Q92). The edit that
/// turns this red is answering the count.
#[test]
fn chain_height_is_the_tip_ordinal_with_its_hash_and_writer() {
    let out = chain_height(&facts(true, 0)).expect("a tip");
    assert_eq!(out.height, Height(1_234_566));
    assert_eq!(out.hash, block_hash(patterned_hash()));
    assert_eq!(out.writer, chain::Writer::Live(shared::Null));

    let mut halted = facts(true, 0);
    halted.tip.as_mut().expect("a tip").halt = Some((BlockHeight::from_raw(77), 12));
    assert_eq!(
        chain_height(&halted).expect("a tip").writer,
        chain::Writer::Halted(chain::Halt {
            height: Height(77),
            invariant: Integer(12),
        })
    );
}

/// The version read: this build's version and digest, the tip and target
/// as ordinals, and the identity the facts layer handed up, unaltered.
#[test]
fn version_carries_this_builds_constants_and_the_facts_identity() {
    let out = version(&facts(true, 999_999)).expect("a version");
    assert_eq!(
        out.version,
        Integer(u64::from(shekyl_rpc_types::CORE_RPC_VERSION))
    );
    assert_eq!(out.height, Height(1_234_566));
    assert_eq!(out.target_height, Nullable(Some(Height(999_998))));
    assert_eq!(
        out.consensus_digest,
        shekyl_rpc_types::CONSENSUS_CONSTANTS_DIGEST_HASH
    );
    assert_eq!(out.network, shekyl_rpc_types::Network::Mainnet);
    assert_eq!(out.genesis, HashHex::from_bytes([0x11; 32]));
}

/// **No target is `null`**, never `0` and never an omitted member, whether
/// or not the node is synchronized (RK-D23); a one-block chain's tip is `0`.
#[test]
fn no_target_is_null_and_a_genesis_tip_is_zero() {
    for synchronized in [true, false] {
        let mut f = facts(synchronized, 0);
        f.tip.as_mut().expect("a tip").chain_height = ChainCount::from_raw(1);
        let wire = serde_json::to_value(version(&f).expect("a version")).unwrap();
        assert_eq!(wire["target_height"], serde_json::Value::Null);
        assert_eq!(wire["height"], json!(0));
    }
    assert_eq!(decode_target_count(0), None);
}

/// A facts fault is a fault, never a fabricated reply.
#[test]
fn a_facts_fault_is_not_answered_with_zeros() {
    let mut f = facts(true, 0);
    f.tip = Err(FactsFault::NotReady);
    f.hash_fault = Some(FactsFault::NotReady);
    assert_eq!(chain_height(&f), Err(RpcFault::Facts(FactsFault::NotReady)));
    assert_eq!(version(&f), Err(RpcFault::Facts(FactsFault::NotReady)));
    assert_eq!(
        block_header_show(&f, &at_height(1, false)),
        Err(RpcFault::Facts(FactsFault::NotReady))
    );
}

// ── one header ─────────────────────────────────────────────────────────

/// The header projection carries every fact in its 4.0 name and kind: the
/// difficulties whole as `0x` hex, the reward as an amount, the pow hash
/// when it was asked for.
#[test]
fn a_header_carries_every_fact_in_its_wire_kind() {
    let f = header_facts();
    let out = block_header_show(&f, &at_height(1_234_567, true)).expect("a header");
    assert!(
        f.asked_pow.load(Ordering::Relaxed),
        "the caller's pow switch reaches the facts"
    );
    let wire = serde_json::to_value(&out).expect("serializes");
    assert_eq!(wire["height"], json!(1_234_567));
    assert_eq!(wire["depth"], json!(42));
    assert_eq!(wire["hash"], json!(tagged_hash(11).to_string()));
    assert_eq!(wire["parent"], json!(tagged_hash(3).to_string()));
    assert_eq!(wire["difficulty"], json!("0x400000000000003039"));
    assert_eq!(wire["difficulty_cumulative"], json!("0x800000000000000063"));
    assert_eq!(wire["reward"], json!("600000000000"));
    assert_eq!(wire["weight_longterm"], json!(87654));
    assert_eq!(wire["version_major"], json!(1));
    assert_eq!(wire["orphan"], json!(true));
    assert_eq!(wire["pow"], json!(hex::encode(tagged_bytes(23))));
    assert_eq!(
        f.asked_height.load(Ordering::Relaxed),
        1_234_567,
        "the handler asks the facts for the height it was given"
    );
}

/// Without `pow` the header carries no `pow` key at all (RW-Q4: a field
/// the request did not select is not in the reply), and the facts layer
/// is never asked to compute one.
#[test]
fn pow_is_absent_and_uncomputed_when_not_asked() {
    let f = header_facts();
    let out = block_header_show(&f, &at_height(1_234_567, false)).expect("a header");
    assert!(!f.asked_pow.load(Ordering::Relaxed));
    assert_eq!(out.pow, Asked::Unasked);
    let wire = serde_json::to_value(&out).expect("a header serializes");
    assert!(wire.get("pow").is_none(), "{wire}");
}

/// A height above the tip, and a hash this node does not hold, are
/// `block.missing`, naming the block and the tip. The edit that turns this
/// red is answering a default header.
#[test]
fn a_block_this_node_does_not_hold_is_block_missing_naming_the_tip() {
    let f = header_facts();
    let past = refusal(block_header_show(&f, &at_height(9_000_000, false)).unwrap_err());
    assert_eq!(past.class, ErrorClass::RefusedByMethod);
    assert_eq!(past.diagnostic.code, codes::BLOCK_MISSING);
    assert_eq!(past.diagnostic.parameter["tip"], "1234609");
    assert_eq!(past.diagnostic.parameter["block"], "at height 9000000");

    let unknown = refusal(block_header_show(&f, &by_hash(tagged_hash(200))).unwrap_err());
    assert_eq!(unknown.diagnostic.code, codes::BLOCK_MISSING);
    assert!(block_header_show(&f, &by_hash(patterned_hash())).is_ok());
}

/// A store that cannot produce an in-range block is the store's fault
/// (`chain.inconsistent`), never a claim about the caller's height; any
/// other facts fault stays its own.
#[test]
fn a_store_fault_is_the_stores_and_not_the_callers() {
    let mut f = header_facts();
    f.hash_fault = Some(FactsFault::Inconsistent);
    let err = refusal(block_header_show(&f, &at_height(5, false)).unwrap_err());
    assert_eq!(err.class, ErrorClass::StoreFault);
    assert_eq!(err.diagnostic.code, codes::CHAIN_INCONSISTENT);

    f.hash_fault = Some(FactsFault::NotReady);
    assert_eq!(
        block_header_show(&f, &at_height(5, false)),
        Err(RpcFault::Facts(FactsFault::NotReady))
    );
}

/// **The selector is exactly one of `height`, `hash`, `tip`** (IG-Q94): an
/// empty object is refused rather than read as genesis, and so is every
/// other shape. The edit that turns this red is a `#[serde(default)]`
/// selector.
#[test]
fn a_selector_is_exactly_one_key_and_nothing_else_reads_as_genesis() {
    let read = |v: serde_json::Value| serde_json::from_value::<block::HeaderSelect>(v);
    assert!(read(json!({"height": 7, "pow": true})).is_ok());
    assert!(read(json!({"tip": null})).is_ok());
    for bad in [
        json!({}),
        json!(null),
        json!({"height": "nope"}),
        json!({"height": -1}),
        json!({"height": 1.5}),
        json!({"height": 7, "pow": "yes"}),
        json!({"height": 7, "tip": null}),
        json!({"height": 7, "fill_pow_hash": true}),
        // A positional array never reaches the type: the envelope refuses
        // it as `rpc.envelope` (`handlers::rpc` tests).
        json!("0"),
        json!(0),
        json!(true),
    ] {
        assert!(read(bad.clone()).is_err(), "{bad} is not a selector");
    }
}

// ── the tip ─────────────────────────────────────────────────────────────

/// A block arriving between choosing the tip and reading it does not
/// produce a header labelled the tip that is not: the read repeats, and
/// the header returned is the new tip at depth 0.
#[test]
fn a_block_arriving_mid_read_does_not_yield_a_stale_tip() {
    let f = facts(true, 0);
    let before = f.tip.as_ref().expect("a tip").chain_height;
    f.tip_growth_remaining.store(1, Ordering::Relaxed);
    let out = block_header_show(&f, &tip(false)).expect("the tip, after one retry");
    assert_eq!(out.height, Height(before.next_height().to_raw()));
    assert_eq!(out.depth, Count(0));
    assert_eq!(f.header_reads.load(Ordering::Relaxed), 2);
}

/// A chain that moves on every attempt is refused `chain.moving`, at a
/// fixed number of reads, rather than spun on.
#[test]
fn a_chain_that_never_settles_is_refused_rather_than_spun_on() {
    let f = facts(true, 0);
    f.tip_growth_remaining.store(u64::MAX, Ordering::Relaxed);
    let err = refusal(block_header_show(&f, &tip(false)).unwrap_err());
    assert_eq!(err.class, ErrorClass::NotReady);
    assert_eq!(err.diagnostic.code, codes::CHAIN_MOVING);
    assert_eq!(
        f.header_reads.load(Ordering::Relaxed),
        TIP_READ_ATTEMPTS as u64
    );
}

/// An unsynchronized node refuses to name the tip (`chain.syncing`) before
/// reading any header; a height, a range and the fee need no tip.
#[test]
fn an_unsynchronized_node_refuses_to_report_a_tip() {
    let unsynced = facts(false, 900_000);
    let err = refusal(block_header_show(&unsynced, &tip(false)).unwrap_err());
    assert_eq!(err.class, ErrorClass::NotReady);
    assert_eq!(err.diagnostic.code, codes::CHAIN_SYNCING);
    assert_eq!(unsynced.header_reads.load(Ordering::Relaxed), 0);

    assert!(block_header_show(&unsynced, &at_height(0, false)).is_ok());
    assert!(block_header_list(&unsynced, &range(0, 0), false).is_ok());
    assert!(fee(&unsynced).is_ok());
}

// ── header lists ────────────────────────────────────────────────────────

fn range(from: u64, to: u64) -> block::HeaderRange {
    block::HeaderRange {
        select: block::HeaderRangeSelect::Range {
            from: Height(from),
            to: Height(to),
        },
        pow: false,
    }
}

/// One miss costs only its own slot, `{"missing": null}` (IG-Q73), and the
/// slots answer in request order.
#[test]
fn a_missing_hash_costs_only_its_own_slot() {
    let f = facts(false, 0);
    let known = block_hash(patterned_hash());
    let absent = block_hash(tagged_hash(200));
    let out = block_header_list(
        &f,
        &block::HeaderRange {
            select: block::HeaderRangeSelect::Hash(vec![known, absent, known]),
            pow: false,
        },
        false,
    )
    .expect("per element");
    assert_eq!(out.len(), 3);
    assert!(matches!(out[0], shared::Slot::Item(_)));
    assert_eq!(
        out[1],
        shared::Slot::State(shared::SlotState::Missing(shared::Null))
    );
    assert!(matches!(out[2], shared::Slot::Item(_)));
}

/// The cap counts headers, not the gap between the ends, and binds a
/// bounded caller only (`bound.header`); a hash list over its cap is
/// `bound.block`.
#[test]
fn the_header_caps_count_headers_and_bind_a_bounded_caller() {
    let f = facts(false, 0);
    assert!(block_header_list(&f, &range(0, 999), true).is_ok());
    let over = refusal(block_header_list(&f, &range(0, 1000), true).unwrap_err());
    assert_eq!(over.class, ErrorClass::OverResourceBound);
    assert_eq!(over.diagnostic.code, codes::BOUND_HEADER);
    assert!(block_header_list(&f, &range(0, 1000), false).is_ok());

    let hashes = block::HeaderRange {
        select: block::HeaderRangeSelect::Hash(vec![block_hash(patterned_hash()); 1001]),
        pow: false,
    };
    let over = refusal(block_header_list(&f, &hashes, true).unwrap_err());
    assert_eq!(over.diagnostic.code, codes::BOUND_BLOCK);
    assert!(block_header_list(&f, &hashes, false).is_ok());
}

/// An inverted range is `block.range` (BadParams), and a range past the
/// tip is `block.missing` **without reading a single header**: the count is
/// the only observable that tells an O(1) refusal from one that walked the
/// chain first. The last valid height still answers, in one read.
#[test]
fn a_range_past_the_tip_is_refused_before_any_header_is_read() {
    let f = facts(false, 0);
    let reads = || f.header_reads.load(Ordering::Relaxed);

    let inverted = refusal(block_header_list(&f, &range(5, 4), false).unwrap_err());
    assert_eq!(inverted.class, ErrorClass::BadParams);
    assert_eq!(inverted.diagnostic.code, codes::BLOCK_RANGE);

    let before = reads();
    let past = refusal(block_header_list(&f, &range(0, u64::MAX), false).unwrap_err());
    assert_eq!(past.diagnostic.code, codes::BLOCK_MISSING);
    assert_eq!(reads(), before, "an unbounded range costs no header reads");

    let chain = f.tip.as_ref().expect("a tip").chain_height;
    let next = chain.next_height().to_raw();
    let before = reads();
    assert!(block_header_list(&f, &range(next, next), false).is_err());
    assert_eq!(reads(), before, "the exclusive end is not readable");

    let last = chain.tip().expect("non-empty").to_raw();
    let before = reads();
    assert!(block_header_list(&f, &range(last, last), false).is_ok());
    assert_eq!(reads(), before + 1, "exactly one header for one height");
}

/// A height that vanishes between the bound and the read — the chain
/// shortened under the range — is `block.missing` naming the height and the
/// tip as it now stands, not a store fault.
#[test]
fn a_height_that_vanishes_under_the_bound_is_block_missing() {
    let mut f = facts(true, 0);
    f.hash_chain_height = ChainCount::from_raw(1_000);
    let err = refusal(block_header_list(&f, &range(999, 1_000), false).unwrap_err());
    assert_eq!(err.diagnostic.code, codes::BLOCK_MISSING);
    assert_eq!(err.diagnostic.parameter["block"], "at height 1000");
    assert_eq!(err.diagnostic.parameter["tip"], "999");
}

/// Every header in a bounded range carries its recorded pow hash when
/// asked.
#[test]
fn a_bounded_header_range_serves_the_recorded_hash() {
    let f = facts(false, 0);
    let mut asked = range(0, 2);
    asked.pow = true;
    let out = block_header_list(&f, &asked, true).expect("three headers");
    assert_eq!(out.len(), 3);
    assert!(out
        .iter()
        .all(|slot| matches!(slot, shared::Slot::Item(h) if matches!(h.pow, Asked::Present(_)))));
}

// ── the fee ─────────────────────────────────────────────────────────────

/// The tiers are named (IG-Q52), each an amount, and nothing else rides
/// beside them.
#[test]
fn the_fee_reply_names_its_tiers() {
    assert_eq!(
        serde_json::to_value(fee(&facts(false, 0)).expect("fees")).unwrap(),
        json!({"economy": "10", "standard": "20", "high": "40"})
    );
}

// ── transactions ────────────────────────────────────────────────────────

/// A real transaction as the store hands it over: its skeleton and its
/// archival good, cut by the wire crate's segmenter and bound by its own
/// `txid_parts`.
fn stored(full: &[u8]) -> TxBody {
    let tx = Transaction::from_bytes(full).expect("a real transaction");
    let segments = tx.write_segments().expect("segments");
    let parts = tx.txid_parts();
    TxBody {
        skeleton: shekyl_wire::SkeletonTx {
            unprunable: segments.pruned,
            prunable_hash: parts.prunable_hash,
            pqc_auth_hash: parts.pqc_auth_hash,
            archival_len: parts.archival_len,
        },
        good: ArchivalGood::Retained {
            pqc_auths: parts.pqc_auth_hash.map(|_| segments.pqc_auths),
            prunable: segments.prunable,
        },
    }
}

/// The pinned parity spend, with the archival length the fixture pins.
fn stored_spend() -> (TxBody, u64) {
    let pin: serde_json::Value = serde_json::from_str(include_str!(
        "../../shekyl-wire/tests/fixtures/pruned_tx_hash_parity_v1.json"
    ))
    .expect("parity fixture");
    let full = hex::decode(pin["tx_hex"].as_str().expect("tx_hex")).expect("hex");
    (
        stored(&full),
        pin["archival_len"].as_u64().expect("archival_len"),
    )
}

/// A real coinbase: no `pqc_auths`, an empty prunable region.
fn stored_coinbase() -> TxBody {
    let block = shekyl_wire::Block::from_bytes(include_bytes!(
        "../../shekyl-wire/tests/vectors/regtest_coinbase_h1.block"
    ))
    .expect("block vector");
    stored(&block.miner_transaction.serialize())
}

fn chain_slot(body: TxBody) -> TxSlot {
    TxSlot::Chain {
        body,
        block_height: 7,
        block_timestamp: 1_700_000_000,
        output_indices: vec![3, 4],
    }
}

fn archived(body: &TxBody, shard: u64) -> TxBody {
    TxBody {
        skeleton: body.skeleton.clone(),
        good: ArchivalGood::Discarded {
            shard: ShardId::from_raw(shard),
        },
    }
}

fn listing(slots: Vec<TxSlot>) -> FakeRead {
    FakeRead {
        slots,
        chain_height: 9,
        ..FakeRead::default()
    }
}

fn list(read: &FakeRead, prune: bool, host: bool) -> tx::TxList {
    let ids = (0..read.slots.len())
        .map(|i| hash([u8::try_from(i).expect("few") + 1; 32]))
        .collect();
    tx_list(read, &tx::TxListQuery { id: ids, prune }, host).expect("a list")
}

fn item(slot: &shared::Slot<tx::TxEntry>) -> &tx::TxEntry {
    match slot {
        shared::Slot::Item(entry) => entry,
        other => panic!("an entry, got {other:?}"),
    }
}

/// **The pruned form is the skeleton, and the full form is the whole
/// body** (`SB-Q2`): the three txid operands ride in both forms, identically.
#[test]
fn the_pruned_form_is_the_skeleton_and_the_full_form_the_whole_body() {
    let (body, pinned_len) = stored_spend();
    let ArchivalGood::Retained {
        pqc_auths,
        prunable,
    } = &body.good
    else {
        unreachable!("the fixture is retained");
    };
    let pqc_auths = pqc_auths.as_ref().expect("the pinned spend is 4-part");
    let mut whole = body.skeleton.unprunable.clone();
    whole.extend_from_slice(pqc_auths);
    whole.extend_from_slice(prunable);

    let read = listing(vec![chain_slot(body.clone())]);
    let pruned = list(&read, true, false);
    let full = list(&read, false, false);
    let (p, f) = (item(&pruned[0]), item(&full[0]));
    assert_eq!(
        p.body.0, body.skeleton.unprunable,
        "the pruned segment alone"
    );
    assert_eq!(f.body.0, whole, "pruned ‖ pqc_auths ‖ prunable");
    // The pruned entry is the skeleton, with the txid's operands; the
    // full entry is `{id, body}` and carries none (IG-Q55, RW-Q4).
    assert_eq!(p.archival_size, Asked::Present(Size(pinned_len)));
    assert_eq!(
        p.prunable_hash,
        Asked::Present(hash(body.skeleton.prunable_hash.to_bytes()))
    );
    assert_eq!(
        p.pqc_auth_hash,
        Asked::Present(Nullable(
            body.skeleton.pqc_auth_hash.map(|h| hash(h.to_bytes()))
        ))
    );
    assert_eq!(
        (f.prunable_hash, f.pqc_auth_hash, f.archival_size),
        (Asked::Unasked, Asked::Unasked, Asked::Unasked),
        "the full form carries no operands"
    );
}

/// **A discarded good is `{"archived": …}` in the full form, and the
/// skeleton under `prune`** (`PDM-Q10`), byte-identical before and after
/// the discard. The edit that turns this red is the archived state folded
/// into the unasked one (`null`).
#[test]
fn a_discarded_good_is_archived_in_the_full_form_and_a_skeleton_under_prune() {
    let (held, _) = stored_spend();
    let gone = archived(&held, 3);
    let full = list(&listing(vec![chain_slot(gone.clone())]), false, false);
    assert_eq!(
        full[0],
        shared::Slot::State(shared::SlotState::Archived(shared::Archived {
            id: hash([1; 32]),
            shard: Integer(3),
        }))
    );
    assert_eq!(
        serde_json::to_value(&full[0]).unwrap()["archived"]["shard"],
        json!(3),
        "the archived state is its own key on the wire"
    );
    let before = list(&listing(vec![chain_slot(held)]), true, false);
    let after = list(&listing(vec![chain_slot(gone)]), true, false);
    assert_eq!(before, after, "one shape under prune, whatever the good");
}

/// A coinbase, and a record that carries no good, answer the pruned
/// segment in both forms; neither is ever archived.
#[test]
fn a_body_with_no_good_answers_its_pruned_segment_in_both_forms() {
    let coinbase = stored_coinbase();
    let none = TxBody {
        skeleton: coinbase.skeleton.clone(),
        good: ArchivalGood::CarriesNone,
    };
    for body in [coinbase, none] {
        let segment = body.skeleton.unprunable.clone();
        let read = listing(vec![chain_slot(body)]);
        for prune in [false, true] {
            let out = list(&read, prune, false);
            let e = item(&out[0]);
            assert_eq!(e.body.0, segment);
            assert_eq!(e.pqc_auth_hash, Asked::when(prune, || Nullable(None)));
            assert_eq!(e.archival_size, Asked::when(prune, || Size(0)));
        }
    }
}

/// **The slot states** (IG-Q73): a mined entry carries its height, depth
/// and indices; a pooled one its one public bit; a miss is
/// `{"missing": null}`; a pool that cannot be asked is `null`. The edit
/// that turns this red is a miss or an unasked pool folded into the other.
#[test]
fn each_slot_answers_in_its_own_state() {
    let (body, pinned_len) = stored_spend();
    let read = listing(vec![
        chain_slot(body.clone()),
        TxSlot::Pool {
            body,
            double_spend_seen: true,
            relayed: false,
            received_timestamp: Some(1_700_000_001),
        },
        TxSlot::Missed,
        TxSlot::PoolUnavailable,
    ]);
    let out = list(&read, true, true);
    let mined = item(&out[0]);
    assert!(!mined.pooled);
    assert_eq!(mined.mined_height, Nullable(Some(Height(7))));
    assert_eq!(mined.confirmations, Nullable(Some(Count(2))), "9 - 7");
    assert_eq!(mined.output_index, vec![Integer(3), Integer(4)]);
    assert_eq!(mined.public, Nullable(None));
    let pooled = item(&out[1]);
    assert!(pooled.pooled);
    assert_eq!(pooled.mined_height, Nullable(None));
    assert_eq!(pooled.public, Nullable(Some(false)));
    assert_eq!(pooled.archival_size, Asked::Present(Size(pinned_len)));
    assert_eq!(
        out[2],
        shared::Slot::State(shared::SlotState::Missing(shared::Null))
    );
    assert_eq!(out[3], shared::Slot::Unasked);
    assert_eq!(
        serde_json::to_value(&out[3]).unwrap(),
        serde_json::Value::Null
    );
    assert_eq!(
        serde_json::to_value(&out[2]).unwrap(),
        json!({"missing": null})
    );
}

/// The pool a caller reads is its scope: the host sees what it has not
/// made public, everyone else only what it has (RT-O9.3). A bounded caller
/// over `bound.tx` is refused before any read.
#[test]
fn the_pool_scope_follows_the_caller_and_the_cap_binds_the_unbounded_not() {
    let read = listing(vec![TxSlot::Missed]);
    list(&read, true, true);
    assert_eq!(
        *read.scope.lock().unwrap(),
        Some(PoolScope::WithUnbroadcast)
    );
    list(&read, true, false);
    assert_eq!(*read.scope.lock().unwrap(), Some(PoolScope::Broadcast));

    let many = tx::TxListQuery {
        id: vec![hash([1; 32]); 101],
        prune: true,
    };
    let err = refusal(tx_list(&read, &many, false).unwrap_err());
    assert_eq!(err.class, ErrorClass::OverResourceBound);
    assert_eq!(err.diagnostic.code, codes::BOUND_TX);
}

/// `tx_show` refuses a miss as `tx.missing` and an unasked pool as
/// `txpool.retired` (NotReady), and answers an archived body as its state.
#[test]
fn tx_show_refuses_a_miss_and_an_unasked_pool_by_their_codes() {
    let show = |slot: TxSlot, prune: bool| {
        tx_show(
            &listing(vec![slot]),
            &tx::TxQuery {
                id: hash([1; 32]),
                prune,
            },
            false,
        )
    };
    let missing = refusal(show(TxSlot::Missed, true).unwrap_err());
    assert_eq!(missing.class, ErrorClass::RefusedByMethod);
    assert_eq!(missing.diagnostic.code, codes::TX_MISSING);
    let retired = refusal(show(TxSlot::PoolUnavailable, true).unwrap_err());
    assert_eq!(retired.class, ErrorClass::NotReady);
    assert_eq!(retired.diagnostic.code, codes::TXPOOL_RETIRED);
    let (held, _) = stored_spend();
    assert!(matches!(
        show(chain_slot(archived(&held, 4)), false).expect("an answer"),
        shared::OrArchived::Archived(_)
    ));
}

// ── blocks ──────────────────────────────────────────────────────────────

/// A whole block: its header, bytes, transactions in the form asked and the
/// first output's global index (RW-Q5). The hash selector asks the facts by
/// hash, and the height is not consulted.
#[test]
fn a_block_carries_its_header_bytes_transactions_and_first_index() {
    let f = header_facts();
    let (body, _) = stored_spend();
    let read = FakeRead {
        slots: vec![chain_slot(body.clone()), chain_slot(body)],
        chain_height: 9,
        output_indices: Some(vec![41, 42]),
        ..FakeRead::default()
    };
    let select = |s: shared::Selector, prune: bool| {
        block::BlockShowSelect(block::BlockSelect {
            select: s,
            pow: false,
            prune: Some(prune),
        })
    };
    let out = block_show(
        &f,
        &read,
        &select(shared::Selector::Height(Height(1_234_567)), true),
    )
    .expect("a block");
    assert_eq!(out.header.height, Height(1_234_567));
    assert_eq!(out.body.0, vec![0x01, 0x02, 0xab, 0xff]);
    assert_eq!(out.tx.len(), 2);
    assert_eq!(out.output_index, Integer(41));
    match &out.tx[0] {
        shared::OrArchived::Item(tx) => assert_eq!(tx.id, hash(tagged_bytes(61))),
        other => panic!("an item: {other:?}"),
    }

    let by = block_show(
        &f,
        &read,
        &select(shared::Selector::Hash(block_hash(patterned_hash())), true),
    )
    .expect("a block");
    assert_eq!(by.tx.len(), 2);
    assert_eq!(
        *f.asked_hash.lock().unwrap(),
        Some(patterned_hash().to_bytes())
    );

    let past = refusal(
        block_show(
            &f,
            &read,
            &select(shared::Selector::Height(Height(9_000_000)), true),
        )
        .unwrap_err(),
    );
    assert_eq!(past.diagnostic.code, codes::BLOCK_MISSING);
}

/// A block the store lists and whose coinbase has no indices, or whose
/// transaction the chain does not hold, is the store contradicting itself.
#[test]
fn a_block_the_store_contradicts_is_a_store_fault() {
    let f = header_facts();
    let read = FakeRead {
        slots: vec![TxSlot::Missed, TxSlot::Missed],
        output_indices: Some(vec![1]),
        ..FakeRead::default()
    };
    let select = block::BlockShowSelect(block::BlockSelect {
        select: shared::Selector::Height(Height(5)),
        pow: false,
        prune: Some(true),
    });
    assert_eq!(
        block_show(&f, &read, &select),
        Err(RpcFault::Facts(FactsFault::Inconsistent))
    );
}

/// `block_list`: heights in request order, a height above the tip
/// `{"missing": null}` (RW-Q5), and `bound.block` for a bounded caller
/// asking more than its cap. The edit that turns this red is refusing the
/// whole list for one height above the tip.
#[test]
fn block_list_answers_each_height_and_a_height_above_the_tip_is_missing() {
    let mut f = facts(true, 0);
    f.hash_chain_height = ChainCount::from_raw(3);
    let read = FakeRead {
        blocks: vec![
            BlockRead {
                block: vec![1],
                txs: Vec::new(),
            },
            BlockRead {
                block: vec![2],
                txs: vec![ListedTx {
                    hash: TxHash::from_bytes([9; 32]),
                    body: stored_coinbase(),
                }],
            },
        ],
        output_indices: Some(vec![7]),
        ..FakeRead::default()
    };
    let out = block_list(
        &f,
        &read,
        &block::BlockListQuery {
            height: vec![Height(0), Height(2), Height(50)],
            prune: true,
        },
        false,
    )
    .expect("a list");
    assert_eq!(out.len(), 3);
    let shared::Slot::Item(first) = &out[0] else {
        panic!("height 0 is held")
    };
    assert_eq!(first.body.0, vec![1]);
    let shared::Slot::Item(second) = &out[1] else {
        panic!("height 2 is held")
    };
    assert_eq!(second.tx.len(), 1);
    assert_eq!(second.output_index, Integer(7));
    assert_eq!(
        out[2],
        shared::Slot::State(shared::SlotState::Missing(shared::Null))
    );

    let err = refusal(
        block_list(
            &f,
            &read,
            &block::BlockListQuery {
                height: vec![Height(0); 1001],
                prune: true,
            },
            true,
        )
        .unwrap_err(),
    );
    assert_eq!(err.class, ErrorClass::OverResourceBound);
    assert_eq!(err.diagnostic.code, codes::BOUND_BLOCK);
}

// ── spent, coinbase sums, alt chains, the curve ─────────────────────────

/// `chain_spent` names where each image is spent, in order, and binds a
/// bounded caller at `bound.key-image`.
#[test]
fn chain_spent_names_each_place_and_binds_a_bounded_caller() {
    let read = FakeRead {
        spent: vec![SpentAt::Unspent, SpentAt::Chain, SpentAt::Pool],
        ..FakeRead::default()
    };
    let three = chain::SpentQuery {
        key_image: vec![hash([1; 32]); 3],
    };
    assert_eq!(
        chain_spent(&read, &three, false).expect("an answer"),
        vec![
            chain::Spent::Unspent,
            chain::Spent::Chain,
            chain::Spent::Txpool
        ]
    );
    let many = chain::SpentQuery {
        key_image: vec![hash([1; 32]); 5001],
    };
    let err = refusal(chain_spent(&read, &many, false).unwrap_err());
    assert_eq!(err.diagnostic.code, codes::BOUND_KEY_IMAGE);
}

/// An inverted coinbase range is `block.range` before any read; one that
/// leaves the chain is `block.missing`; a sum is two amounts.
#[test]
fn chain_coinbase_sum_refuses_by_its_codes_and_sums_in_amounts() {
    let sum = |coinbase: Option<CoinbaseRange>, from: u64, to: u64| {
        chain_coinbase_sum(
            &FakeRead {
                coinbase,
                ..FakeRead::default()
            },
            &chain::CoinbaseSumRange {
                from: Height(from),
                to: Height(to),
            },
        )
    };
    let inverted = refusal(sum(None, 5, 4).unwrap_err());
    assert_eq!(inverted.diagnostic.code, codes::BLOCK_RANGE);
    let past = refusal(sum(Some(CoinbaseRange::TooLarge), 0, 9).unwrap_err());
    assert_eq!(past.diagnostic.code, codes::BLOCK_MISSING);
    let summed = sum(
        Some(CoinbaseRange::Summed(crate::read_facts::CoinbaseSum {
            emission: 500,
            fees: 7,
        })),
        0,
        9,
    )
    .expect("a sum");
    assert_eq!(
        serde_json::to_value(summed).unwrap(),
        json!({"emission": "500", "fee": "7"})
    );
}

/// The curve tree above the tip is `curve.missing`, not the tip's tree.
#[test]
fn a_curve_above_the_tip_is_curve_missing() {
    let read = FakeRead::default();
    let err = refusal(
        curve_show(
            &read,
            &chain::CurveSelect(shared::Selector::Height(Height(9))),
        )
        .unwrap_err(),
    );
    assert_eq!(err.diagnostic.code, codes::CURVE_MISSING);
    let tree = CurveTreeFacts {
        after: BlockHeight::from_raw(9),
        root: CurveTreeRoot::from_bytes([3; 32]),
        depth: 4,
        leaf_count: 77,
    };
    let read = FakeRead {
        curve_after: Some(tree),
        ..FakeRead::default()
    };
    let out = curve_show(&read, &chain::CurveSelect(shared::Selector::Tip)).expect("a tree");
    assert_eq!(
        (out.layers, out.leaf_count, out.height),
        (Count(4), Count(77), Height(9))
    );
}

/// An alternative chain is named by its tip, tip first; one with no block
/// is the store contradicting itself.
#[test]
fn an_alt_chain_is_named_by_its_tip() {
    let read = FakeRead {
        alt: vec![AltChainFacts {
            blocks: vec![tagged_hash(5), tagged_hash(6)],
            tip_height: BlockHeight::from_raw(12),
            cumulative_difficulty: 255,
            parent: tagged_hash(7),
        }],
        ..FakeRead::default()
    };
    let out = chain_alt(&read).expect("alts");
    assert_eq!(out[0].hash, block_hash(tagged_hash(5)));
    assert_eq!(out[0].height, Height(12));
    assert_eq!(out[0].block.len(), 2);
    let empty = FakeRead {
        alt: vec![AltChainFacts {
            blocks: Vec::new(),
            tip_height: BlockHeight::from_raw(12),
            cumulative_difficulty: 0,
            parent: tagged_hash(7),
        }],
        ..FakeRead::default()
    };
    assert_eq!(
        chain_alt(&empty),
        Err(RpcFault::Facts(FactsFault::Inconsistent))
    );
}

/// A header asked for `pow` carries it as a hash, and one its facts cannot
/// supply it for is refused: the facts contradict the request, never a
/// blank (IG-Q56, RW-Q4 at 4.1). Not asked, `pow` is not in the header.
/// Red edit: answer an unsuppliable `pow` as unasked.
#[test]
fn a_header_asked_for_pow_carries_it_or_is_refused() {
    let mut facts = crate::methods::tests::sample_header();
    facts.pow_hash = Some([7; 32]);
    assert_eq!(
        header(&facts, true)
            .unwrap_or_else(|_| panic!("the hash is held"))
            .pow,
        shekyl_rpc_types::kinds::Asked::Present(HashHex::from_bytes([7; 32]))
    );
    assert!(header(&facts, false)
        .unwrap_or_else(|_| panic!("not asked"))
        .pow
        .is_unasked());
    facts.pow_hash = None;
    assert_eq!(
        header(&facts, true).map(|_| ()),
        Err(RpcFault::Facts(FactsFault::Inconsistent))
    );
}
