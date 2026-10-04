// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-6 increment 5 — capture, as the ingest writes it.
//!
//! The fold closes a chunk once, so capture happens there or not at all
//! ([`CurveTreeClient::register_owned`]). These passes grade what the fold
//! wrote against what [`CurveTreeClient::assemble_paths`] builds from the
//! whole tree: the same two values, reached from opposite directions. The
//! comparison is the point — a capture that agreed with its own encoder
//! would establish nothing.

use super::super::tests::ingest_outputs_at;
use super::super::{
    BlockLeaves, OwnedRegistration, RawOutput, TxLeafInputs, CAPTURED_IDENTITY_BYTES,
    CAPTURED_IDENTITY_CM_X_AT, CAPTURED_IDENTITY_COMMITMENT_AT, CAPTURED_IDENTITY_OUTPUT_KEY_AT,
    CURVE_ELEMENT_BYTES,
};
use super::{lock_count, reference_at};
use crate::store::CapturedChunk;
use crate::types::{
    AssembleInput, AssembledPath, BlockHeight, ChunkLeaf, CommitmentBytes, Gindex, OneTimePubkey,
    ReferenceBlock, TargetKind,
};
use crate::CurveTreeClient;
use crate::TreePosition;
use shekyl_fcmp::tree::{
    key_image_generator, selene_point_to_helios_scalar, HELIOS_CHUNK_WIDTH, SELENE_CHUNK_WIDTH,
};
use shekyl_types::BlockCount;

/// One output whose `O` is distinct per `seed` and distinct **from** its `C`.
///
/// The shared `coinbase_raw` fixture carries the Ed25519 basepoint as both
/// `O` and `C` for every output, which collapses the observable this file
/// needs: with every leaf identical, a capture that wrote `C` where `O`
/// belongs, or wrote the siblings in reverse, compares equal to the path.
/// The first version of this file used it, and both mutations passed — a
/// collapsed observable caps every assertion built on it, however exact the
/// assertion looks.
///
/// `key_image_generator` is a hash-to-point, so each seed gives a valid,
/// byte-distinct Ed25519 point, and 64 bits of seed outlast the fixture.
fn seeded_raw(seed: u64) -> RawOutput {
    let mut preimage = [0u8; 32];
    preimage[..8].copy_from_slice(&seed.to_le_bytes());
    RawOutput {
        output_key: OneTimePubkey::from_bytes(key_image_generator(&preimage)),
        commitment: Some(CommitmentBytes::from_bytes(ED25519_BASEPOINT)),
        target: TargetKind::TaggedKey,
    }
}

/// The output key the fixture gives the leaf at `gindex`.
///
/// Seeds start at 1 for gindex 0 ([`ingest_fixture`] increments before each
/// output), so this is the inverse of that schedule. Registration is bound
/// to `O`, not to the number, so a pass that registers before ingest has to
/// name the key the ingest will produce — which is also the only reason a
/// test can register early at all.
fn owned_key(gindex: u64) -> OneTimePubkey {
    // Saturating because the never-ingested gindex a pass registers is
    // `u64::MAX`; that key is never matched against anything, it only has
    // to exist.
    seeded_raw(gindex.saturating_add(1)).output_key
}

/// The Ed25519 basepoint, as every output's commitment. A valid point is
/// all `C` has to be here; `O` is what carries the per-leaf distinction.
const ED25519_BASEPOINT: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Ingest blocks 0..=`tip`, giving creation block `i` `counts[i]` outputs
/// with globally distinct output keys.
fn ingest_fixture(client: &mut CurveTreeClient, tip: BlockHeight, counts: &[usize]) {
    ingest_range(client, BlockHeight::ZERO, tip, counts);
}

/// Blocks of one full Selene chunk each, enough that the owned leaf's
/// layer-1 chunk closes **and** is not the root.
///
/// 19 chunks is `HELIOS_CHUNK_WIDTH + 1`, which is the smallest count that
/// makes layer-1 node 0 an interior node. At exactly 18 chunks that node is
/// the root, and a pass written there would be comparing the captured chunk
/// with the root's own child set — true, and silent about the interior case
/// every deeper tree is made of.
const CHUNKS: usize = HELIOS_CHUNK_WIDTH + 1;

/// Leaf position of the owned output: the **last** leaf of the chunk that
/// also closes layer-1 node 0.
///
/// `684 = 38 · 18` leaves close layer-0 chunk 17 and layer-1 node 0 on one
/// push, so both land under one key — the cascade §11.8 names, and the
/// reason a write must merge rather than replace.
const OWNED_POSITION: u64 = (SELENE_CHUNK_WIDTH as u64) * (HELIOS_CHUNK_WIDTH as u64) - 1;

/// Leaf position whose layer-0 chunk holds no owned leaf: the chunk after
/// the owned one, adjacent on purpose.
const FOREIGN_CHUNK_END: u64 = (SELENE_CHUNK_WIDTH as u64) * (CHUNKS as u64) - 1;

/// Output counts per creation block, sized so **no leaf chunk is aligned
/// with a block**.
///
/// This is load-bearing, not incidental. A chunk's siblings are split by
/// `captured_leaf_identities` between the rows the store has committed and
/// the leaves of the block being ingested, and a fixture whose chunks each
/// drained inside one block would exercise only the second half — the first
/// version of this file did exactly that, so the ranged store read it was
/// built on was never called. One fewer leaf per block than the chunk width
/// makes every chunk span at least two blocks, whatever the widths are.
fn counts() -> Vec<usize> {
    counts_for(CHUNKS)
}

/// [`counts`] for an arbitrary number of leaf chunks.
fn counts_for(chunks: usize) -> Vec<usize> {
    counts_totalling(chunks * SELENE_CHUNK_WIDTH)
}

/// [`counts`] for an arbitrary leaf total, which need not be a whole number
/// of chunks — the boundary passes need a count that is one short.
fn counts_totalling(target: usize) -> Vec<usize> {
    let per_block = SELENE_CHUNK_WIDTH - 1;
    let mut out = vec![per_block; target / per_block];
    let rest = target % per_block;
    if rest > 0 {
        out.push(rest);
    }
    assert_eq!(
        out.iter().sum::<usize>(),
        target,
        "counts must drain the fixture"
    );
    out
}

/// Ingest heights `from..=to`, continuing a fixture already ingested below
/// `from`. Seeds are a prefix sum over `counts`, so a continuation hands out
/// the same output keys the one-shot [`ingest_fixture`] would have.
fn ingest_range(
    client: &mut CurveTreeClient,
    from: BlockHeight,
    to: BlockHeight,
    counts: &[usize],
) {
    ingest_range_seeded(client, from, to, counts, 0);
}

/// [`ingest_range`] with a seed offset, so a post-reorg chain can hand the
/// *same* gindexes to **different** outputs — which is what a reorg past an
/// output's creation actually does.
fn ingest_range_seeded(
    client: &mut CurveTreeClient,
    from: BlockHeight,
    to: BlockHeight,
    counts: &[usize],
    seed_offset: u64,
) {
    let before = usize::try_from(from.to_raw()).expect("a height fits usize");
    let mut seed: u64 = seed_offset
        + counts
            .iter()
            .take(before)
            .map(|n| u64::try_from(*n).expect("a count fits u64"))
            .sum::<u64>();
    let end = to
        .checked_add(BlockCount::ONE)
        .expect("the ingested tip has a successor");
    for height in from.ordinals_until(end) {
        let n = usize::try_from(height.to_raw())
            .ok()
            .and_then(|i| counts.get(i).copied())
            .unwrap_or(0);
        if n == 0 {
            let txs: Vec<TxLeafInputs<'_>> = Vec::new();
            client
                .ingest_block(BlockLeaves { height, txs: &txs })
                .expect("an empty block ingests");
        } else {
            let outs: Vec<RawOutput> = (0..n)
                .map(|_| {
                    seed += 1;
                    seeded_raw(seed)
                })
                .collect();
            ingest_outputs_at(client, height.to_raw(), &outs);
        }
    }
}

/// The tip at which every leaf a `counts` fixture creates has drained.
fn tip_for(counts: &[usize]) -> BlockHeight {
    let last_creation = u64::try_from(counts.len() - 1).expect("block count fits u64");
    BlockHeight::from_raw(last_creation) + lock_count() + BlockCount::ONE
}

/// A client with `CHUNKS` full leaf chunks drained, and the gindexes that
/// drained with it.
///
/// Every output is a coinbase, so each block's outputs share a maturity and
/// the maturities rise with the creation height. Drain order is
/// `(maturity, gindex)` and both rise together here, so **position equals
/// gindex** — which is what lets a pass name a position and register the
/// matching output without resolving one from the other.
fn drained_chunks(register: &[u64]) -> (CurveTreeClient, BlockHeight) {
    let counts = counts();
    let mut client = CurveTreeClient::new();
    for gindex in register {
        assert_eq!(
            client
                .register_owned(Gindex::from_raw(*gindex), owned_key(*gindex))
                .expect("a live client registers"),
            OwnedRegistration::BeforeDrain,
            "an empty client has drained nothing"
        );
    }
    let tip = tip_for(&counts);
    ingest_fixture(&mut client, tip, &counts);
    let drained = client.drained_leaf_count(tip);
    assert_eq!(
        drained,
        CHUNKS * SELENE_CHUNK_WIDTH,
        "the fixture must drain exactly {CHUNKS} full leaf chunks"
    );
    // The split the capture depends on: the owned chunk's first leaf and its
    // last were drained by different blocks, so its identities came partly
    // from `read_drained_range` and partly from the block in hand.
    assert_ne!(
        creation_block_of(chunk_start(OWNED_POSITION)),
        creation_block_of(OWNED_POSITION),
        "the owned chunk must straddle a block or the store read is untested"
    );
    (client, tip)
}

/// First leaf position of the layer-0 chunk that `position` sits in.
fn chunk_start(position: u64) -> u64 {
    let width = SELENE_CHUNK_WIDTH as u64;
    position / width * width
}

/// Creation block of the leaf at `position`, from the fixture's counts.
///
/// Position equals gindex here (see [`drained_chunks`]), and gindexes are
/// handed out in creation order, so the counts are a prefix sum.
fn creation_block_of(position: u64) -> u64 {
    let mut seen = 0u64;
    for (block, n) in counts().iter().enumerate() {
        seen += u64::try_from(*n).expect("a block's count fits u64");
        if position < seen {
            return u64::try_from(block).expect("a block index fits u64");
        }
    }
    panic!("position {position} is past the fixture");
}

/// Decode a closed layer-0 capture body into the chunk leaves a path carries.
///
/// `I` is re-derived here, because it is not stored (§11.8). This is the
/// consumer's side of [`super::super::capture::push_captured_identity`],
/// written out rather than shared with it: a decoder that called the
/// encoder's inverse would agree with it by construction. The offsets are
/// the layout's names. A closed chunk is exactly one Selene width; a short
/// body is not a chunk this oracle accepts.
fn decode_identities(bytes: &[u8]) -> Vec<ChunkLeaf> {
    assert_eq!(
        bytes.len(),
        SELENE_CHUNK_WIDTH * CAPTURED_IDENTITY_BYTES,
        "a closed layer-0 chunk is one full width"
    );
    bytes
        .chunks_exact(CAPTURED_IDENTITY_BYTES)
        .map(|row| {
            let mut o = [0u8; CURVE_ELEMENT_BYTES];
            let mut c = [0u8; CURVE_ELEMENT_BYTES];
            let mut cm_x = [0u8; CURVE_ELEMENT_BYTES];
            o.copy_from_slice(
                &row[CAPTURED_IDENTITY_OUTPUT_KEY_AT..CAPTURED_IDENTITY_COMMITMENT_AT],
            );
            c.copy_from_slice(&row[CAPTURED_IDENTITY_COMMITMENT_AT..CAPTURED_IDENTITY_CM_X_AT]);
            cm_x.copy_from_slice(&row[CAPTURED_IDENTITY_CM_X_AT..CAPTURED_IDENTITY_BYTES]);
            ChunkLeaf {
                output_key: OneTimePubkey::from_bytes(o),
                key_image_gen: key_image_generator(&o),
                commitment: CommitmentBytes::from_bytes(c),
                cm_x,
            }
        })
        .collect()
}

fn held_at(client: &CurveTreeClient, end_leaf: u64) -> Vec<CapturedChunk> {
    client
        .store
        .captured_chunks(TreePosition::from_raw(end_leaf))
        .expect("the capture table reads")
}

fn body_at(chunks: &[CapturedChunk], layer: u8) -> Vec<u8> {
    chunks
        .iter()
        .find(|c| c.layer == layer)
        .unwrap_or_else(|| panic!("no layer-{layer} chunk in {chunks:?}"))
        .bytes
        .clone()
}

/// What the fold captured is what assembly builds from the whole tree.
///
/// Two independent derivations of one value. The capture is written at
/// ingest, leaf by leaf, from the store's rows and the block's own leaves.
/// The path below comes from an unregistered twin, so `assemble_paths`
/// rebuilds the tree at the reference height and slices it. Equality is the
/// claim capture rests on, and it is the only assertion that would notice an
/// off-by-one in the chunk span, a wrong `base` split between the store read
/// and the block, or identities written out of drain order.
#[test]
fn a_captured_chunk_equals_what_assembly_builds() {
    let (client, tip) = drained_chunks(&[OWNED_POSITION]);
    // The path comes from an UNREGISTERED twin over the same seeds, so it is
    // rebuilt from every drained leaf. On `client` itself assembly would now
    // read the capture this pass is grading, and compare it with itself.
    let (twin, _) = drained_chunks(&[]);
    let reference = reference_at(&twin, tip);

    let path = rebuilt_path(&twin, OWNED_POSITION, &reference);

    let held = held_at(&client, OWNED_POSITION);
    assert_eq!(
        held.iter().map(|c| c.layer).collect::<Vec<_>>(),
        vec![0, 1],
        "leaf chunk 17 and layer-1 node 0 both close at leaf {OWNED_POSITION}, \
         so one key holds both — a replace would have left one of them"
    );

    // Layer 0: the siblings as a path carries them.
    assert_eq!(
        decode_identities(&body_at(&held, 0)),
        path.leaf_chunk,
        "the captured leaf chunk must be the leaf chunk assembly builds"
    );

    // Layer 1 is Helios, so a path carries its children as Helios scalars
    // converted from the Selene points below. The capture holds those points
    // as the frontier folded them, so the comparison applies the conversion
    // — which is also what pins that the capture stored *points*, not the
    // already-converted scalars.
    let captured: Vec<[u8; 32]> = body_at(&held, 1)
        .chunks_exact(32)
        .map(|c| {
            let mut node = [0u8; 32];
            node.copy_from_slice(c);
            selene_point_to_helios_scalar(&node).expect("a folded node converts")
        })
        .collect();
    assert_eq!(
        captured, path.c2_layers[0],
        "the captured layer-1 chunk must be the branch assembly walks"
    );
    assert_eq!(
        path.c1_layers.len(),
        1,
        "the layer-2 branch is the root's child set, which never closes — it \
         comes from the ring snapshot, not from a capture"
    );
}

/// A chunk holding no owned leaf writes no row.
///
/// The filter has to exclude as well as include, and the chunk after the
/// owned one is the adjacent case: it closed in the same fixture, from the
/// same fold, and differs only in which leaves it covers.
#[test]
fn a_chunk_with_no_owned_leaf_is_not_captured() {
    let (client, _) = drained_chunks(&[OWNED_POSITION]);
    assert!(
        held_at(&client, FOREIGN_CHUNK_END).is_empty(),
        "leaf chunk {} holds positions {}..={FOREIGN_CHUNK_END}, none owned",
        CHUNKS - 1,
        FOREIGN_CHUNK_END + 1 - SELENE_CHUNK_WIDTH as u64
    );
    // The first chunk too, so the pass is not merely reading past the end.
    let first_chunk_end = SELENE_CHUNK_WIDTH as u64 - 1;
    assert!(
        held_at(&client, first_chunk_end).is_empty(),
        "leaf chunk 0 holds no owned leaf either"
    );
}

/// Registering nothing captures nothing.
///
/// The control on the pass above: the same fixture, the same fold, no
/// registration. A capture written for every chunk would pass every
/// equality assertion and quietly make the registry decorative.
#[test]
fn an_unregistered_fixture_captures_nothing() {
    let (client, _) = drained_chunks(&[]);
    for chunk in 0..CHUNKS {
        let end = (chunk as u64 + 1) * SELENE_CHUNK_WIDTH as u64 - 1;
        assert!(
            held_at(&client, end).is_empty(),
            "nothing is registered, so leaf chunk {chunk} must not be captured"
        );
    }
}

/// Registration after the drain says so.
///
/// The return value is the only thing that distinguishes a registration the
/// fold will serve from one reconciliation owes, and the distinction is what
/// keeps a late registration from reading as a working one.
#[test]
fn a_registration_after_the_drain_reports_itself() {
    let (mut client, _) = drained_chunks(&[]);
    assert_eq!(
        client
            .register_owned(Gindex::from_raw(0), owned_key(0))
            .expect("a live client registers"),
        OwnedRegistration::AfterDrain,
        "leaf 0 drained long before this call"
    );
    // A gindex this client has never seen is a future leaf, not an error.
    assert_eq!(
        client
            .register_owned(Gindex::from_raw(u64::MAX), owned_key(u64::MAX))
            .expect("a live client registers"),
        OwnedRegistration::BeforeDrain,
        "an unseen gindex has not drained"
    );
    // Re-offering a held pair whose leaf has drained but whose position is
    // NOT resolved is still a late registration: "held" and "served" have
    // diverged, and the captures are owed.
    assert_eq!(
        client
            .register_owned(Gindex::from_raw(0), owned_key(0))
            .expect("a live client registers"),
        OwnedRegistration::AfterDrain,
        "held, drained, unresolved: owed, not already served"
    );
    client
        .reconcile_captures()
        .expect("reconciliation resolves it");
    assert_eq!(
        client
            .register_owned(Gindex::from_raw(0), owned_key(0))
            .expect("a live client registers"),
        OwnedRegistration::AlreadyHeld,
        "held and resolved: nothing owed"
    );
    assert_eq!(
        client
            .register_owned(Gindex::from_raw(u64::MAX), owned_key(u64::MAX))
            .expect("a live client registers"),
        OwnedRegistration::AlreadyHeld,
        "held and not drained: the fold will serve it, nothing owed"
    );
}

/// `entries` is strictly increasing in `gindex`.
///
/// [`CurveTreeClient::register_owned`] binary-searches it, and
/// `rebuild_from_store` already reads `entries.last()` for `next_gindex` on
/// the same basis. Stated as a pass because an invariant two callers rely on
/// and nothing asserts is one an ingest change can quietly break.
#[test]
fn entries_stay_sorted_by_gindex() {
    let (client, _) = drained_chunks(&[]);
    assert!(
        client.entries.len() > SELENE_CHUNK_WIDTH,
        "fixture is non-trivial"
    );
    for pair in client.entries.windows(2) {
        assert!(
            pair[0].gindex < pair[1].gindex,
            "entries must rise in gindex: {:?} then {:?}",
            pair[0].gindex,
            pair[1].gindex
        );
    }
}

/// A rollback keeps the registry and drops the positions it cut.
///
/// Two halves of one invariant, and they fail in opposite directions. Losing
/// the **registry** stops capture for every held output after the first
/// reorg — silently, because the fold simply finds nothing registered.
/// Keeping a **position** past the cut leaves a coordinate that now names a
/// different leaf, so a chunk holding nothing of the wallet's reads as
/// owned. Only the end-to-end half is observable from outside, so the pass
/// asserts the state too, and then re-ingests to show the registry's
/// survival is load-bearing rather than decorative.
#[test]
fn a_rollback_keeps_the_registry_and_drops_cut_positions() {
    let (mut client, tip) = drained_chunks(&[OWNED_POSITION]);
    let owned = Gindex::from_raw(OWNED_POSITION);
    assert!(
        !held_at(&client, OWNED_POSITION).is_empty(),
        "the fixture must capture before it is rolled back"
    );

    // Fork one height below the one that drained the owned leaf, so its
    // chunk is un-finalized: it drains at `maturity + 1`, because the root
    // at `h` drains through `h - 1`.
    let cutoff = tip - BlockCount::ONE;
    let drained = crate::recon::drained_sorted(&client.entries, cutoff);
    let maturity = drained[usize::try_from(OWNED_POSITION).expect("position fits usize")].maturity;
    client
        .rollback_to_fork(maturity)
        .expect("the fork rolls back");

    assert!(
        client.owned_outputs.contains_key(&owned),
        "a registration is the wallet's statement about its own output; a \
         rollback is a statement about the chain, and cannot retract it"
    );
    assert!(
        !client.owned_positions.contains_key(&OWNED_POSITION),
        "position {OWNED_POSITION} is at or above the surviving leaf count, so \
         it no longer names the owned leaf"
    );
    assert!(
        held_at(&client, OWNED_POSITION).is_empty(),
        "the capture row is un-finalized by the same truncation as every other \
         position-keyed table"
    );

    // Forward again over the undone heights. Nothing is created there — the
    // fixture's creations are far below — so these blocks only re-drain, and
    // the capture must come back from the registry alone.
    let end = tip
        .checked_add(BlockCount::ONE)
        .expect("tip has a successor");
    for height in (maturity + BlockCount::ONE).ordinals_until(end) {
        let txs: Vec<TxLeafInputs<'_>> = Vec::new();
        client
            .ingest_block(BlockLeaves { height, txs: &txs })
            .expect("a re-drain ingests");
    }
    assert_eq!(
        held_at(&client, OWNED_POSITION)
            .iter()
            .map(|c| c.layer)
            .collect::<Vec<_>>(),
        vec![0, 1],
        "both cascade layers must be captured again after the re-drain"
    );
}

/// A leaf row missing under a closing chunk refuses the block.
///
/// `prune_frozen` is the only thing that produces this shape — a position
/// the store still counts whose leaf bytes are gone — and it has no
/// production caller, so without a standing pass this refusal would be
/// shown only by mutating the code it guards. Writing a short chunk instead
/// would be the worse outcome by far: the merge accepts it, and the defect
/// surfaces at spend time as a path that does not hash to its root.
#[test]
fn a_missing_leaf_row_refuses_rather_than_capturing_short() {
    let counts = counts();
    let owned_creation = creation_block_of(OWNED_POSITION);
    // The owned leaf drains at `maturity + 1`, because the root at `h`
    // drains through `h - 1`. Stop one short of that, so the chunk has not
    // closed and the rows below this block's drain are committed.
    let maturity = BlockHeight::from_raw(owned_creation) + lock_count();
    let mut client = CurveTreeClient::new();
    client
        .register_owned(Gindex::from_raw(OWNED_POSITION), owned_key(OWNED_POSITION))
        .expect("a live client registers");
    ingest_fixture(&mut client, maturity, &counts);
    assert!(
        held_at(&client, OWNED_POSITION).is_empty(),
        "the chunk must not have closed yet"
    );

    // Drop the chunk's first sibling — in the half that comes from the store,
    // and both of its rows, which is what `prune_frozen` removes. Dropping
    // the leaf row alone is a *different* state: `read_drained_range` refuses
    // leaf/meta asymmetry as corruption, so that path never reaches the
    // short-count refusal this pass is about.
    let start = chunk_start(OWNED_POSITION);
    let base = client.frontier.leaf_count();
    assert!(
        start < base,
        "the dropped row must be one the store has already committed"
    );
    client
        .store
        .drop_leaf_rows_for_test(TreePosition::from_raw(start), TreePosition::from_raw(start))
        .expect("the rows drop");

    let closing = maturity + BlockCount::ONE;
    let txs: Vec<TxLeafInputs<'_>> = Vec::new();
    let err = client
        .ingest_block(BlockLeaves {
            height: closing,
            txs: &txs,
        })
        .expect_err("a chunk whose siblings are short must refuse the block");
    match err {
        crate::ClientError::CaptureIdentitiesIncomplete {
            end_leaf,
            want,
            got,
        } => {
            assert_eq!(
                end_leaf, OWNED_POSITION,
                "the refusal names the chunk's key"
            );
            assert_eq!(want, SELENE_CHUNK_WIDTH);
            // Not `want - 1`, though one position was dropped.
            // `read_drained_range` cannot tell a hole from the end of the
            // table, so it stops at the first absent position — the whole
            // store-side half is lost, and only this block's own leaves
            // remain. That is the honest reading of a ranged read over a
            // table with a hole in it, and the reason the refusal is keyed
            // on the total rather than on a diff.
            let own_half = usize::try_from(OWNED_POSITION + 1 - base).expect("half fits usize");
            assert_eq!(
                got, own_half,
                "a hole stops the ranged read, so only the block's own leaves counted"
            );
        }
        other => panic!("expected CaptureIdentitiesIncomplete, got {other:?}"),
    }
    assert!(
        held_at(&client, OWNED_POSITION).is_empty(),
        "the refusal is ahead of the transaction, so nothing was written"
    );
}

/// A poisoned client refuses to answer.
///
/// The verdict reads `entries`, and a poisoned client's `entries` may
/// disagree with the store. The wrong answer that matters is `BeforeDrain`
/// for a leaf that has drained: it reports *nothing owed*, so reconciliation
/// is never told, and the captures are lost without a trace.
#[test]
fn a_poisoned_client_refuses_to_register() {
    let (mut client, _) = drained_chunks(&[]);
    client.poisoned = true;
    assert!(
        matches!(
            client.register_owned(Gindex::from_raw(0), owned_key(0)),
            Err(crate::ClientError::Poisoned)
        ),
        "registration must fail fast while memory is inconsistent"
    );
}

// ---------------------------------------------------------------------------
// Reconciliation: a capture that is due and missing is a late registration
// ---------------------------------------------------------------------------

/// Position whose layer-1 chunk ends at [`OWNED_POSITION`] but whose layer-0
/// chunk does **not**: leaf 0.
///
/// The pair `(0, OWNED_POSITION)` is the cascade-key hazard with two
/// different owners. Leaf 0's layer-1 node spans `0..=683` and so shares key
/// 683 with leaf 683's *layer-0* chunk, while leaf 0's own layer-0 chunk ends
/// at 37. One owner's chunk is written by the fold and the other's by
/// reconciliation, at one key.
const CASCADE_PARTNER: u64 = 0;

/// Every key a reconciliation of `register` would write at, and its chunks.
fn rows_for(client: &CurveTreeClient, keys: &[u64]) -> Vec<(u64, Vec<CapturedChunk>)> {
    keys.iter().map(|k| (*k, held_at(client, *k))).collect()
}

/// A reconciled row is **byte-equal** to the one the fold writes.
///
/// This is reconciliation's oracle, and it is deliberately not
/// `assemble_paths`: reconciliation and assembly both go through
/// `drained_sorted` + `build_layers`, so comparing them would compare a
/// function with itself. The fold is the independent producer — it writes
/// leaf by leaf, from the store's committed rows plus the block in hand,
/// while reconciliation rebuilds the layer stack from `entries`. Two
/// sources, one encoder, and the bytes must agree.
#[test]
fn a_reconciled_row_equals_the_folded_one() {
    // Early registration: the fold writes.
    let (folded, _) = drained_chunks(&[OWNED_POSITION]);

    // Late registration: reconciliation writes.
    let (mut rebuilt, _) = drained_chunks(&[]);
    assert_eq!(
        rebuilt
            .register_owned(Gindex::from_raw(OWNED_POSITION), owned_key(OWNED_POSITION))
            .expect("a live client registers"),
        OwnedRegistration::AfterDrain,
        "the fixture must have drained the leaf already, or there is nothing to backfill"
    );
    let report = rebuilt.reconcile_captures().expect("reconciliation runs");
    assert_eq!(report.positions_resolved, 1, "one late registration");
    assert_eq!(
        report.chunks_written, 2,
        "the cascade puts layer 0 and layer 1 under one key"
    );
    assert_eq!(
        report.rows_written, 1,
        "both chunks share key {OWNED_POSITION}"
    );

    let keys = [OWNED_POSITION];
    assert_eq!(
        rows_for(&rebuilt, &keys),
        rows_for(&folded, &keys),
        "a backfilled row must be byte-equal to the folded one; the fold reads \
         store rows and the block, reconciliation rebuilds from entries, so a \
         difference is a real disagreement about the same chunk"
    );
    assert!(
        !held_at(&rebuilt, OWNED_POSITION).is_empty(),
        "the comparison must not be two empty vectors"
    );
}

/// A late layer-0 capture does not erase a folded layer-1 chunk.
///
/// The end-to-end form of the merge-by-layer rule. Leaf 0 is registered
/// early, so the fold writes its layer-1 chunk at key 683. Leaf 683 is
/// registered late, and its *layer-0* chunk ends at the same key. A write
/// that replaced would drop leaf 0's branch — latent until the backfill
/// exists, which is exactly what triggers it.
#[test]
fn a_late_layer_zero_capture_does_not_erase_a_folded_layer_one() {
    let (mut client, _) = drained_chunks(&[CASCADE_PARTNER]);
    let folded = held_at(&client, OWNED_POSITION);
    assert_eq!(
        folded.iter().map(|c| c.layer).collect::<Vec<_>>(),
        vec![1],
        "leaf {CASCADE_PARTNER}'s layer-1 node ends at {OWNED_POSITION}, and its \
         own layer-0 chunk ends at {} — so the fold wrote layer 1 only here",
        SELENE_CHUNK_WIDTH - 1
    );
    let layer_one = body_at(&folded, 1);

    client
        .register_owned(Gindex::from_raw(OWNED_POSITION), owned_key(OWNED_POSITION))
        .expect("a live client registers");
    client.reconcile_captures().expect("reconciliation runs");

    let after = held_at(&client, OWNED_POSITION);
    assert_eq!(
        after.iter().map(|c| c.layer).collect::<Vec<_>>(),
        vec![0, 1],
        "the backfill must ADD layer 0 beside the folded layer 1, not replace it"
    );
    assert_eq!(
        body_at(&after, 1),
        layer_one,
        "the folded layer-1 bytes must be untouched"
    );
}

/// Reconciling twice writes nothing — and **hashes nothing** — the second
/// time.
///
/// `leaves_rebuilt == 0` is the load-bearing half. The first revision of
/// this mechanism rebuilt the whole tree before comparing anything, so a
/// resume with every capture already present still paid the full `O(chain)`
/// hash: the cost capture exists to remove, charged on wallet open, where it
/// hurts more than at spend. Nothing required it. Asserting only "wrote
/// nothing" would have passed that revision unchanged, which is exactly why
/// the cost is a reported field rather than an implementation detail.
#[test]
fn reconciling_twice_rebuilds_nothing_the_second_time() {
    let (mut client, _) = drained_chunks(&[]);
    client
        .register_owned(Gindex::from_raw(OWNED_POSITION), owned_key(OWNED_POSITION))
        .expect("a live client registers");
    let first = client.reconcile_captures().expect("the first pass runs");
    assert!(first.chunks_written > 0, "the first pass has work to do");
    // Exactly the missing chunks' own spans — leaf 683 is owed a layer-0
    // chunk (38 leaves) and a layer-1 node (38 x 18). Asserted as an
    // equality, not as "fewer than the chain": at this fixture's size the
    // layer-1 span is most of the tree, so an inequality would be measuring
    // the fixture rather than the bound. The bound is per chunk, and
    // `a_resume_with_nothing_owed_hashes_nothing` is where it reaches zero.
    let width = SELENE_CHUNK_WIDTH as u64;
    assert_eq!(
        first.leaves_rebuilt,
        width + width * HELIOS_CHUNK_WIDTH as u64,
        "the backfill must read each missing chunk's own span and nothing wider"
    );

    let second = client.reconcile_captures().expect("the second pass runs");
    assert_eq!(
        second,
        crate::CaptureReconciliation {
            positions_resolved: 0,
            rows_written: 0,
            chunks_written: 0,
            leaves_rebuilt: 0,
        },
        "nothing is due the second time, so nothing is read and nothing hashed"
    );
}

/// A resume with every capture present hashes nothing.
///
/// The normal case, stated on its own rather than as the tail of the
/// idempotence pass: a wallet opens, re-registers what it holds, and
/// reconciles. Every due chunk is already in the table, so the call costs a
/// table read per due coordinate and no hashing — `O(owned × depth)`, not
/// `O(chain)`.
#[test]
fn a_resume_with_nothing_owed_hashes_nothing() {
    // Early registration, so the fold wrote every due chunk.
    let (mut client, _) = drained_chunks(&[OWNED_POSITION]);
    // A resume loses the registry; the wallet re-registers what it holds.
    client.owned_outputs.clear();
    client.owned_positions.clear();
    assert_eq!(
        client
            .register_owned(Gindex::from_raw(OWNED_POSITION), owned_key(OWNED_POSITION))
            .expect("a live client registers"),
        OwnedRegistration::AfterDrain,
        "a re-registration after a resume is always a late one"
    );

    let report = client.reconcile_captures().expect("reconciliation runs");
    assert_eq!(
        report.positions_resolved, 1,
        "the position is resolved again, which is what lets the fold continue"
    );
    assert_eq!(
        report.leaves_rebuilt, 0,
        "every due capture is present, so a resume must not rebuild the tree"
    );
    assert_eq!(report.chunks_written, 0, "and must not write");
}

/// Reconciliation resolves the position, so the fold keeps capturing.
///
/// Without this the backfill would be a one-shot: the chunks that had already
/// closed get written, and every chunk that closes *after* the late
/// registration is missed, because the fold matches on `owned_positions`.
/// The leaf would be silently unprotected from the backfill onward.
///
/// Leaf 700's layer-0 chunk has closed by `CHUNKS`, but its layer-1 node —
/// spanning `684..=1367` — has not, so the fixture grows to the chunk count
/// that closes it and the pass reconciles in between.
#[test]
fn reconciliation_resolves_the_position_so_the_fold_continues() {
    let late = 700u64;
    let layer_one_end = 2 * (SELENE_CHUNK_WIDTH as u64) * (HELIOS_CHUNK_WIDTH as u64) - 1;
    let chunks = usize::try_from((layer_one_end + 1) / SELENE_CHUNK_WIDTH as u64)
        .expect("chunk count fits usize");
    let counts = counts_for(chunks);
    let full_tip = tip_for(&counts);

    // Ingest only far enough that leaf `late`'s layer-0 chunk has closed —
    // `chunk_start(late) + width` leaves must have drained — and no further.
    // Derived from this fixture's own counts: `creation_block_of` reads the
    // default fixture's, which is what the first version of this pass used
    // and why it did not land where it claimed.
    let needed = chunk_start(late) + SELENE_CHUNK_WIDTH as u64;
    let mut cumulative = 0u64;
    let mut creation = 0usize;
    while cumulative < needed {
        cumulative += u64::try_from(counts[creation]).expect("a count fits u64");
        creation += 1;
    }
    let mut client = CurveTreeClient::new();
    let partial_tip =
        BlockHeight::from_raw(u64::try_from(creation - 1).expect("a block index fits u64"))
            + lock_count()
            + BlockCount::ONE;
    ingest_fixture(&mut client, partial_tip, &counts);
    let drained = client.frontier.leaf_count();
    assert!(
        drained >= needed && drained <= layer_one_end,
        "the fixture must have closed leaf {late}'s layer-0 chunk ({needed} leaves)          and not its layer-1 node ({} leaves); drained {drained}",
        layer_one_end + 1
    );

    client
        .register_owned(Gindex::from_raw(late), owned_key(late))
        .expect("a live client registers");
    client.reconcile_captures().expect("reconciliation runs");
    assert!(
        held_at(&client, layer_one_end).is_empty(),
        "leaf {late}'s layer-1 chunk has not closed, so nothing is due at its key yet"
    );

    // Forward to where the layer-1 node closes. The fold must capture it.
    ingest_range(
        &mut client,
        partial_tip + BlockCount::ONE,
        full_tip,
        &counts,
    );
    assert_eq!(
        held_at(&client, layer_one_end)
            .iter()
            .map(|c| c.layer)
            .collect::<Vec<_>>(),
        vec![1],
        "the chunk closed after the backfill, so only a resolved position could \
         have captured it"
    );
}

/// A held position the canonical drain order does not produce is refused.
///
/// `owned_positions` is the fold's; the recomputation is `drained_sorted`'s.
/// Two orders over one field, so reconciliation compares them instead of
/// silently overwriting one with the other — a wrong coordinate means every
/// capture keyed on it is keyed on the wrong leaf.
/// A held position that names the **wrong** gindex is refused too.
///
/// The key-set comparison this replaces would have passed: swap two
/// registered outputs' positions and both keys are still present. The
/// mapping is what the captures are keyed on, so the mapping is what is
/// compared.
#[test]
fn a_held_position_naming_the_wrong_gindex_is_refused() {
    let (mut client, _) = drained_chunks(&[OWNED_POSITION, CASCADE_PARTNER]);
    let a = client.owned_positions[&OWNED_POSITION];
    let b = client.owned_positions[&CASCADE_PARTNER];
    assert_ne!(a, b);
    client.owned_positions.insert(OWNED_POSITION, b);
    client.owned_positions.insert(CASCADE_PARTNER, a);
    match client.reconcile_captures() {
        Err(crate::ClientError::OwnedPositionDrift { position }) => {
            assert!(
                position == OWNED_POSITION || position == CASCADE_PARTNER,
                "the refusal names one of the swapped positions, got {position}"
            );
        }
        other => panic!("expected OwnedPositionDrift for a swapped mapping, got {other:?}"),
    }
}

#[test]
fn a_drifted_owned_position_is_refused() {
    let (mut client, _) = drained_chunks(&[OWNED_POSITION]);
    // A position no registration can account for.
    client
        .owned_positions
        .insert(OWNED_POSITION - 1, Gindex::from_raw(OWNED_POSITION - 1));
    match client.reconcile_captures() {
        Err(crate::ClientError::OwnedPositionDrift { position }) => {
            assert_eq!(
                position,
                OWNED_POSITION - 1,
                "the refusal names the position"
            );
        }
        other => panic!("expected OwnedPositionDrift, got {other:?}"),
    }
}

/// Reconcile a fixture that is one leaf short of closing the chunk over
/// leaf 0 at `span`, and report what it wrote.
///
/// `span` is `outputs_per_node(layer)`, so the chunk over leaf 0 ends at
/// `span - 1` and the fixture drains `span - 1` leaves — putting the chunk's
/// end exactly **at** the drained count, which is the only place `<` and
/// `<=` differ.
fn reconcile_one_leaf_short(span: u64) -> crate::CaptureReconciliation {
    let short = counts_totalling(usize::try_from(span - 1).expect("a leaf total fits usize"));
    let mut client = CurveTreeClient::new();
    client
        .register_owned(Gindex::from_raw(0), owned_key(0))
        .expect("a live client registers");
    ingest_fixture(&mut client, tip_for(&short), &short);
    assert_eq!(
        client.frontier.leaf_count(),
        span - 1,
        "the fixture must be one leaf short of closing the chunk"
    );
    client
        .reconcile_captures()
        .expect("an unclosed chunk must be skipped, not read past")
}

/// An unclosed **layer-0** chunk is not due.
///
/// This is the fencepost the whole design rests on: `end_leaf <
/// drained_leaf_count`, the one comparison a rollback, the capture key and
/// the backfill all share. `<=` instead of `<` passed every other pass in
/// this file, because the default fixture drains a whole number of chunks
/// and so never puts a chunk's end *at* the drained count.
///
/// At this shape the mutated form reads **past the end** of the drained
/// entries.
#[test]
fn an_unclosed_leaf_chunk_is_not_due() {
    let report = reconcile_one_leaf_short(SELENE_CHUNK_WIDTH as u64);
    assert_eq!(
        report.chunks_written, 0,
        "the chunk over leaf 0 ends at exactly the drained count, and a chunk \
         is due only strictly below it"
    );
}

/// An unclosed **layer-1** node is not due.
///
/// Its own pass, not a second iteration of the one above, because the two
/// shapes fail differently and a loop would stop at the first. Here the
/// mutated form's node slice stays **in bounds** — `layers[0]` holds enough
/// rows — so it would write a *wrong* chunk silently rather than panic: the
/// children of a layer-0 row whose last node covers a partial chunk.
#[test]
fn an_unclosed_node_chunk_is_not_due() {
    let span = SELENE_CHUNK_WIDTH as u64 * HELIOS_CHUNK_WIDTH as u64;
    let report = reconcile_one_leaf_short(span);
    assert_eq!(
        report.chunks_written, 0,
        "leaf 0's layer-1 node ends at exactly the drained count, so nothing \
         is due at its key; its layer-0 chunk closed long ago and was already \
         written by the fold"
    );
}

/// A drained leaf's `gindex` can equal or exceed the drained leaf **count**.
///
/// The falsifier for a rule that has not been written yet, pinned before it
/// is. Dropping a stale registration on rollback invites the *same*
/// inequality the other two holders use — `gindex >= surviving_leaf_count` —
/// and that compares two different quantities. `surviving_leaf_count` counts
/// drained **positions**; a `gindex` is a global output index, and
/// [`TargetKind::Other`] consumes one without producing a leaf ("the output
/// still consumes a global output index", `types.rs`).
///
/// This fixture makes the gap one, which is enough: the last drained leaf's
/// `gindex` equals the drained count, so the inequality holds for a leaf that
/// is present, valid and must **not** be dropped. Every other fixture in this
/// file has `position == gindex`, so none of them could show this.
///
/// The honest discriminator is set membership on the rebuilt state — stale
/// iff `gindex < next_gindex` and absent from `entries` — and its red-bite
/// needs all three states of that comparison.
#[test]
fn a_gindex_is_not_a_position() {
    let mut client = CurveTreeClient::new();
    // A leaf-ineligible output first, then leaf-eligible ones. The first
    // consumes gindex 0 and produces no leaf, so every leaf below sits one
    // gindex above its position.
    let mut outs = vec![RawOutput {
        output_key: OneTimePubkey::from_bytes(key_image_generator(&[9u8; 32])),
        commitment: Some(CommitmentBytes::from_bytes(ED25519_BASEPOINT)),
        target: TargetKind::Other,
    }];
    outs.extend((1..=4u64).map(seeded_raw));
    ingest_outputs_at(&mut client, 0, &outs);
    let tip = BlockHeight::ZERO + lock_count() + BlockCount::ONE;
    ingest_range(&mut client, BlockHeight::from_raw(1), tip, &[]);

    let drained = crate::recon::drained_sorted(&client.entries, tip - BlockCount::ONE);
    let count = u64::try_from(drained.len()).expect("a drained count fits u64");
    assert_eq!(count, 4, "the leaf-ineligible output produced no leaf");
    for (position, entry) in drained.iter().enumerate() {
        let position = u64::try_from(position).expect("a position fits u64");
        assert_eq!(
            entry.gindex.to_raw(),
            position + 1,
            "the skipped gindex offsets every leaf below it"
        );
    }
    let last = drained.last().expect("the fixture drained leaves");
    assert!(
        last.gindex.to_raw() >= count,
        "gindex {} is at or above the drained count {count}, so \
         `gindex >= surviving_leaf_count` would discard a registration for a \
         leaf that is present and valid",
        last.gindex.to_raw()
    );
}

// ---------------------------------------------------------------------------
// A rollback trims two holders, in two units
// ---------------------------------------------------------------------------

/// A registered output created early enough to survive the forks below.
const SURVIVES: u64 = 100;
/// A registered output created late enough that those forks remove it.
const REMOVED: u64 = 500;

/// Fork height that keeps [`SURVIVES`]'s creation block and drops
/// [`REMOVED`]'s.
fn fork_between() -> BlockHeight {
    let keep = creation_block_of(SURVIVES);
    assert!(
        creation_block_of(REMOVED) > keep,
        "the fixture must create {REMOVED} after {SURVIVES}"
    );
    BlockHeight::from_raw(keep)
}

/// A rollback drops a registration exactly when its output is gone.
///
/// Three states, because the rule has to get all three right and two
/// candidate rules got one each wrong:
///
/// | registration | after the fork | verdict |
/// | --- | --- | --- |
/// | names a surviving output | still in `entries` | **keep** |
/// | names a removed output | gone from `entries` | **drop** |
/// | names an output never ingested | never in `entries` | **keep** |
///
/// The third is the early registration the scanner makes when it identifies
/// an output from a block this client has not reached. A rule that simply
/// retained what `entries` contains would discard it.
#[test]
fn a_rollback_drops_a_registration_only_when_its_output_is_gone() {
    let (mut client, _) = drained_chunks(&[SURVIVES, REMOVED]);
    let unseen = Gindex::from_raw(u64::MAX);
    assert_eq!(
        client
            .register_owned(unseen, owned_key(u64::MAX))
            .expect("a live client registers"),
        OwnedRegistration::BeforeDrain,
        "an unseen gindex is a future output"
    );

    client
        .rollback_to_fork(fork_between())
        .expect("the fork rolls back");

    assert!(
        client
            .owned_outputs
            .contains_key(&Gindex::from_raw(SURVIVES)),
        "the output survived the fork, so its registration must"
    );
    assert!(
        !client
            .owned_outputs
            .contains_key(&Gindex::from_raw(REMOVED)),
        "the output is gone from the new chain; the gindex will be re-derived \
         there and may name a different output, so the registration must go"
    );
    assert!(
        client.owned_outputs.contains_key(&unseen),
        "a registration for an output never ingested is an early one, not a \
         stale one"
    );
}

/// Every output a rollback removes holds a gindex **at or above** the
/// rebuilt `next_gindex`.
///
/// The falsifier for the second candidate rule, pinned the way
/// [`a_gindex_is_not_a_position`] pins the first. `gindex < next_gindex &&
/// !entries.contains(gindex)` typechecks, and its first clause was there to
/// protect a registration for a not-yet-ingested output. But a rollback
/// removes the chain's **tail**, and `rebuild_from_store` sets `next_gindex`
/// to `entries.last() + 1` over what survived — so every removed output
/// lands in exactly the band that clause protects, and the rule drops
/// nothing in the case it was written for.
///
/// That is why staleness is a set difference taken across the rollback
/// rather than a test on the state after it: the two are indistinguishable
/// from the new state alone.
#[test]
fn a_removed_gindex_sits_above_the_rebuilt_next_gindex() {
    let (mut client, _) = drained_chunks(&[]);
    client
        .rollback_to_fork(fork_between())
        .expect("the fork rolls back");
    assert!(
        REMOVED >= client.next_gindex,
        "removed gindex {REMOVED} is below the rebuilt next_gindex {}, which \
         would make the inequality rule look like it worked",
        client.next_gindex
    );
    assert!(
        SURVIVES < client.next_gindex,
        "the surviving gindex must be below it, or the fixture proves nothing"
    );
}

/// A reorg past an output's creation: the registration goes, and a
/// re-registration on the new chain captures the **new** output correctly.
///
/// The second half is the one that matters. After the fork the same gindex
/// names a different output, so the question is not only whether the stale
/// registration was dropped but whether what replaces it is right. The
/// capture written for the re-registered output is compared against the path
/// `assemble_paths` builds from the post-reorg tree — the same two-route
/// comparison as [`a_captured_chunk_equals_what_assembly_builds`], now over a
/// chain that forked.
#[test]
fn a_reorg_past_creation_retires_the_registration_and_rebinds_it() {
    let counts = counts();
    let (mut client, _) = drained_chunks(&[REMOVED]);
    let before = client
        .entries
        .iter()
        .find(|e| e.gindex.to_raw() == REMOVED)
        .expect("the fixture created it")
        .identity
        .output_key;

    let fork = fork_between();
    client.rollback_to_fork(fork).expect("the fork rolls back");
    assert!(
        !client
            .owned_outputs
            .contains_key(&Gindex::from_raw(REMOVED)),
        "the registration must not survive its output"
    );

    // A different chain from the fork: the same block shape, different
    // outputs, so `REMOVED` is handed to one the wallet never owned.
    ingest_range_seeded(
        &mut client,
        fork + BlockCount::ONE,
        tip_for(&counts),
        &counts,
        1_000_000,
    );
    let after = client
        .entries
        .iter()
        .find(|e| e.gindex.to_raw() == REMOVED)
        .expect("the new chain created one too")
        .identity
        .output_key;
    assert_ne!(
        before, after,
        "the fork must hand this gindex a different output or the pass is vacuous"
    );

    // Re-offering the OLD key is refused: the client's chain view has a
    // different output at that number now, and the registry is bound to
    // the pair.
    assert!(
        matches!(
            client.register_owned(Gindex::from_raw(REMOVED), before),
            Err(crate::ClientError::RegistrationIdentityMismatch { .. })
        ),
        "a registration naming the pre-reorg output must not be accepted"
    );

    // The wallet rescans, finds it owns the new output, and re-registers.
    // The insert rebinds the gindex; no separate retraction is needed.
    assert_eq!(
        client
            .register_owned(Gindex::from_raw(REMOVED), after)
            .expect("a live client registers"),
        OwnedRegistration::AfterDrain,
        "the new output has already drained by the post-reorg tip"
    );
    client.reconcile_captures().expect("reconciliation runs");

    // The oracle path is rebuilt on an unregistered twin that walked the
    // same fork, so it does not read the capture it is compared against.
    let mut twin = CurveTreeClient::new();
    ingest_fixture(&mut twin, fork, &counts);
    ingest_range_seeded(
        &mut twin,
        fork + BlockCount::ONE,
        tip_for(&counts),
        &counts,
        1_000_000,
    );
    let tip = twin
        .ingested_tip_height
        .expect("the twin has ingested the new chain");
    assert_eq!(tip, client.ingested_tip_height.expect("ingested"));
    let reference = reference_at(&twin, tip);
    let drained = crate::recon::drained_sorted(&twin.entries, tip - BlockCount::ONE);
    let position = drained
        .iter()
        .position(|e| e.gindex.to_raw() == REMOVED)
        .expect("the re-registered output drained");
    let path = rebuilt_path(
        &twin,
        u64::try_from(position).expect("a position fits u64"),
        &reference,
    );

    let end_leaf = chunk_start(u64::try_from(position).expect("a position fits u64"))
        + SELENE_CHUNK_WIDTH as u64
        - 1;
    assert_eq!(
        decode_identities(&body_at(&held_at(&client, end_leaf), 0)),
        path.leaf_chunk,
        "the capture at the new position must be the leaf chunk assembly builds \
         from the post-reorg tree"
    );
}

/// An **early** registration never claims a stranger's output.
///
/// This is the case identity binding exists for, and the one no rollback
/// rule could reach. A registration made before the client ingests the
/// output's creation block is not in the held set, so the rollback trim
/// correctly leaves it alone — it looks exactly like a legitimate
/// registration for a block not yet seen, because until the fork it was
/// one. If the reorg goes past that creation, the new chain can hand the
/// same `gindex` to a different output, and a registry keyed on the number
/// would then mark a stranger's leaf as owned and capture its chunks.
///
/// Nothing financial breaks — spending is driven by the wallet's ledger,
/// which never holds the stranger's output — but the registry and the
/// plaintext capture table would be wrong, and nothing would ever correct
/// them. Binding to `O` makes the case impossible by construction rather
/// than detectable after the fact.
#[test]
fn an_early_registration_does_not_claim_a_strangers_output() {
    let counts = counts();
    let fork = fork_between();

    // Ingest only as far as the fork, so `REMOVED`'s creation block is not
    // in `entries` yet. Registering here is the early case.
    let mut client = CurveTreeClient::new();
    ingest_fixture(&mut client, fork, &counts);
    assert!(
        CurveTreeClient::held_output(&client.entries, Gindex::from_raw(REMOVED)).is_none(),
        "the fixture must not have ingested {REMOVED}'s creation block yet"
    );
    assert_eq!(
        client
            .register_owned(Gindex::from_raw(REMOVED), owned_key(REMOVED))
            .expect("a live client registers"),
        OwnedRegistration::BeforeDrain,
        "an output whose creation block is not ingested has not drained"
    );

    // The chain that actually arrives is a different one, and it gives that
    // gindex to another output.
    ingest_range_seeded(
        &mut client,
        fork + BlockCount::ONE,
        tip_for(&counts),
        &counts,
        1_000_000,
    );
    let stranger = CurveTreeClient::held_output(&client.entries, Gindex::from_raw(REMOVED))
        .expect("the arriving chain created an output at that gindex");
    assert_ne!(
        stranger,
        owned_key(REMOVED),
        "the arriving chain must bind the gindex to a different output, or \
         this pass is vacuous"
    );

    // The registration survives — it is indistinguishable from a legitimate
    // early one — but it matches nothing, so nothing of the stranger's is
    // captured.
    assert!(
        client
            .owned_outputs
            .contains_key(&Gindex::from_raw(REMOVED)),
        "the trim cannot retire this and must not try: it never named a held \
         output"
    );
    let tip = client.ingested_tip_height.expect("the client ingested");
    let position = crate::recon::drained_sorted(&client.entries, tip - BlockCount::ONE)
        .iter()
        .position(|e| e.gindex.to_raw() == REMOVED)
        .expect("the stranger drained");
    let end_leaf = chunk_start(u64::try_from(position).expect("a position fits u64"))
        + SELENE_CHUNK_WIDTH as u64
        - 1;
    assert!(
        held_at(&client, end_leaf).is_empty(),
        "the stranger's chunk must not be captured: the registration names a \
         key this leaf does not carry"
    );

    // And reconciliation agrees — it must not resolve a position for it.
    let report = client.reconcile_captures().expect("reconciliation runs");
    assert_eq!(
        report.positions_resolved, 0,
        "no owned position exists; the registered key matches no drained leaf"
    );
    assert_eq!(report.chunks_written, 0, "so nothing is owed");
}

// ---------------------------------------------------------------------------
// State 3: a capture is load-bearing
// ---------------------------------------------------------------------------

/// The path at `position`, **rebuilt** from every drained leaf in `entries`
/// — the pre-capture derivation, kept here as the oracle after production
/// stopped doing it.
///
/// Written out with the tree primitives rather than through anything in
/// `assemble.rs`, so the comparison crosses mechanisms: production reads
/// captures and the snapshot; this builds the whole layer stack and slices
/// it. The `tree` context is the reference's, as production's is, so
/// equality asserts every branch and the leaf chunk and nothing cosmetic.
fn rebuilt_path(
    client: &CurveTreeClient,
    position: u64,
    reference: &ReferenceBlock,
) -> AssembledPath {
    use shekyl_fcmp::tree::{
        build_layers, chunk_width, helios_point_to_selene_scalar, layer_is_selene,
        selene_point_to_helios_scalar,
    };
    let cutoff = reference.height - BlockCount::ONE;
    let drained = crate::recon::drained_sorted(&client.entries, cutoff);
    let scalars = crate::recon::assemble_leaf_stream(&client.entries, cutoff);
    let layers = build_layers(&scalars);
    let depth = u8::try_from(layers.len()).expect("depth fits u8");
    let pos = usize::try_from(position).expect("position fits usize");

    let leaf_start = pos / SELENE_CHUNK_WIDTH * SELENE_CHUNK_WIDTH;
    let leaf_end = (leaf_start + SELENE_CHUNK_WIDTH).min(drained.len());
    let leaf_chunk: Vec<ChunkLeaf> = drained[leaf_start..leaf_end]
        .iter()
        .map(|e| ChunkLeaf {
            output_key: e.identity.output_key,
            key_image_gen: key_image_generator(e.identity.output_key.as_bytes()),
            commitment: e
                .identity
                .commitment
                .expect("a drained leaf carries a commitment"),
            cm_x: e.cm_x(),
        })
        .collect();

    let mut c1_layers = Vec::new();
    let mut c2_layers = Vec::new();
    let mut node = leaf_start / SELENE_CHUNK_WIDTH;
    for layer in 1..depth {
        let width = chunk_width(layer);
        let parent = node / width;
        let below = &layers[usize::from(layer) - 1];
        let start = parent * width;
        let end = (start + width).min(below.len());
        if layer_is_selene(layer) {
            c1_layers.push(
                below[start..end]
                    .iter()
                    .map(|p| helios_point_to_selene_scalar(p).expect("helios->selene"))
                    .collect::<Vec<_>>(),
            );
        } else {
            c2_layers.push(
                below[start..end]
                    .iter()
                    .map(|p| selene_point_to_helios_scalar(p).expect("selene->helios"))
                    .collect::<Vec<_>>(),
            );
        }
        node = parent;
    }
    AssembledPath {
        leaf_chunk,
        c1_layers,
        c2_layers,
        tree: crate::types::TreeContext {
            reference_block: reference.block_hash,
            tree_root: reference.curve_tree_root,
            tree_depth: depth,
        },
    }
}

/// The input for the leaf at `position` on `client`, read from its entries.
fn input_at(client: &CurveTreeClient, tip: BlockHeight, position: u64) -> AssembleInput {
    let drained = crate::recon::drained_sorted(&client.entries, tip - BlockCount::ONE);
    let e = drained[usize::try_from(position).expect("position fits usize")];
    AssembleInput {
        gindex: e.gindex,
        output_key: e.identity.output_key,
        commitment: e
            .identity
            .commitment
            .expect("a drained leaf carries a commitment"),
    }
}

/// Remove every entry but the one at `gindex`, leaving the store untouched.
fn keep_only(client: &mut CurveTreeClient, gindex: Gindex) {
    let before = client.entries.len();
    client.entries.retain(|entry| entry.gindex == gindex);
    assert_eq!(client.entries.len(), 1, "exactly the owned leaf remains");
    assert!(
        before > 1,
        "the fixture must hold foreign leaves for their absence to mean anything"
    );
}

/// With every foreign leaf removed, assembly succeeds and the path equals
/// the one rebuilt from the whole tree.
///
/// # Three states
///
/// Capture's claim is one comparison: a path assembled with every foreign
/// leaf absent equals the path assembled with the whole tree present.
///
/// | | with foreign leaves absent |
/// | --- | --- |
/// | before the §11.6 gate | succeeded, returning a wrong path under the real root |
/// | with the gate, before capture | refused with `PathRootFault::RootDisagrees` |
/// | **now** | succeeds, and the path equals `full` |
///
/// This pass replaced the state-2 one in the parent module, which asserted
/// the refusal. It is not a timing test: a cost curve only estimates the
/// property, while a slower implementation cannot pass this comparison —
/// and neither can one that keeps the rebuild as a fallback, because with
/// the foreign leaves gone the fallback has nothing to rebuild from and
/// refuses.
///
/// # Why `full` comes from a different client
///
/// On a client whose input is registered, assembly takes the capture path;
/// comparing that with itself proves nothing. `full` is rebuilt on an
/// **unregistered** twin over the same seeds, which is the pre-capture
/// derivation. Both registration orders are then graded against it: late
/// (register after ingest, reconcile) and early (register before ingest, the
/// fold writes), because they fill the table by different mechanisms.
#[test]
fn a_path_from_captures_equals_the_rebuilt_one_with_every_foreign_leaf_gone() {
    let (twin, tip) = drained_chunks(&[]);
    let reference = reference_at(&twin, tip);
    let input = input_at(&twin, tip, OWNED_POSITION);
    assert_eq!(
        twin.root_at(tip).expect("store root reads"),
        reference.curve_tree_root,
        "the anchor is the store tier's root over the whole tree"
    );
    let full = rebuilt_path(&twin, OWNED_POSITION, &reference);
    assert_eq!(
        crate::assemble::verify_path_against_its_branches(&full),
        Ok(()),
        "the test-side rebuild must fold to the reference root, or it is no oracle"
    );
    assert!(
        full.leaf_chunk.len() > 1,
        "the owned leaf's real chunk holds its siblings; a one-leaf chunk here would \
         mean the fixture, not the mechanism, is doing the work"
    );

    // Late registration: the table is filled by reconciliation.
    let (mut late, _) = drained_chunks(&[]);
    late.register_owned(input.gindex, input.output_key)
        .expect("a live client registers");
    late.reconcile_captures().expect("reconciliation runs");
    keep_only(&mut late, input.gindex);
    let sparse = late
        .assemble_path(&input, &reference)
        .expect("state 3: assembly succeeds with every foreign leaf gone");
    assert_eq!(
        sparse, full,
        "late registration: the captured path is the rebuilt path"
    );

    // Early registration: the table is filled by the fold.
    let (mut early, _) = drained_chunks(&[OWNED_POSITION]);
    keep_only(&mut early, input.gindex);
    let sparse = early
        .assemble_path(&input, &reference)
        .expect("state 3: assembly succeeds with every foreign leaf gone");
    assert_eq!(
        sparse, full,
        "early registration: the captured path is the rebuilt path"
    );
}

/// The closed chunks come from the capture table, not from the leaf rows.
///
/// The leaves table holds every closed chunk's identities too, so an
/// assembly that read it for a closed layer-0 chunk would pass the pass
/// above without touching a capture. Here every foreign leaf row in a
/// closed chunk is also dropped from the store, leaving only the owned
/// leaf's row; the root gate still answers from the ring, and the path must
/// still equal `full`. At this fixture's size every leaf chunk is closed, so
/// no row at all is read.
#[test]
fn captures_are_the_read_site_not_the_leaf_table() {
    let (twin, tip) = drained_chunks(&[]);
    let reference = reference_at(&twin, tip);
    let input = input_at(&twin, tip, OWNED_POSITION);
    let full = rebuilt_path(&twin, OWNED_POSITION, &reference);

    let (mut client, _) = drained_chunks(&[OWNED_POSITION]);
    keep_only(&mut client, input.gindex);
    let last = client.frontier.leaf_count() - 1;
    assert_eq!(
        (last + 1) % SELENE_CHUNK_WIDTH as u64,
        0,
        "every leaf chunk must be closed, or the tail read would legitimately touch rows"
    );
    if OWNED_POSITION > 0 {
        client
            .store
            .drop_leaf_rows_for_test(
                TreePosition::from_raw(0),
                TreePosition::from_raw(OWNED_POSITION - 1),
            )
            .expect("rows drop");
    }
    client
        .store
        .drop_leaf_rows_for_test(
            TreePosition::from_raw(OWNED_POSITION + 1),
            TreePosition::from_raw(last),
        )
        .expect("rows drop");

    let sparse = client
        .assemble_path(&input, &reference)
        .expect("assembly must not need a foreign leaf row for a closed chunk");
    assert_eq!(sparse, full, "the captured path is the rebuilt path");
}

/// An owned leaf in the **open** leaf chunk assembles from the tail rows and
/// the snapshot's open branches, and equals the rebuilt path.
///
/// The one place assembly still reads leaf rows: the rightmost leaf chunk
/// has not closed, the frontier holds its scalars and a path needs points,
/// so its identities come from a ranged read of at most
/// `SELENE_CHUNK_WIDTH - 1` rows. Above it every chunk is open too, so both
/// parities of [`Frontier::open_branches`] are consulted — layer 1 (Helios)
/// and layer 2 (Selene) — from the snapshot rather than from a capture.
/// Together with the pass above, which takes layer 1 from a capture, the
/// two sources are each graded at a layer ≥ 1.
#[test]
fn an_owned_leaf_in_the_open_leaf_chunk_assembles_from_the_tail() {
    let into_tail = 5usize;
    let counts = counts_totalling(CHUNKS * SELENE_CHUNK_WIDTH + into_tail);
    let tip = tip_for(&counts);
    let position = (CHUNKS * SELENE_CHUNK_WIDTH) as u64 + 2;

    let mut twin = CurveTreeClient::new();
    ingest_fixture(&mut twin, tip, &counts);
    assert_eq!(
        twin.frontier.leaf_count() % SELENE_CHUNK_WIDTH as u64,
        into_tail as u64,
        "the fixture must leave an open leaf chunk"
    );
    let reference = reference_at(&twin, tip);
    let input = input_at(&twin, tip, position);
    let full = rebuilt_path(&twin, position, &reference);
    assert_eq!(
        full.leaf_chunk.len(),
        into_tail,
        "the open chunk is the tail"
    );

    let mut client = CurveTreeClient::new();
    client
        .register_owned(input.gindex, input.output_key)
        .expect("a live client registers");
    ingest_fixture(&mut client, tip, &counts);
    let report = client.reconcile_captures().expect("reconciliation runs");
    assert_eq!(
        report.chunks_written, 0,
        "nothing over this leaf has closed"
    );
    keep_only(&mut client, input.gindex);
    let sparse = client
        .assemble_path(&input, &reference)
        .expect("the open chunk assembles from the tail and the snapshot");
    assert_eq!(sparse, full, "the open-tail path is the rebuilt path");
}

/// A reference height the ring no longer holds is refused by name.
///
/// Reachable only for a reference the daemon would reject as too old — the
/// ring keeps 720 blocks and the daemon accepts 100 — so the refusal is not
/// a limitation a spend can meet. The alternative was to rebuild the tree
/// from every drained leaf to serve a reference that cannot be submitted.
#[test]
fn a_reference_outside_the_ring_is_refused() {
    let (mut client, tip) = drained_chunks(&[OWNED_POSITION]);
    let input = input_at(&client, tip, OWNED_POSITION);
    let reference = reference_at(&client, tip);
    client
        .assemble_path(&input, &reference)
        .expect("inside the ring the capture path assembles");

    // Push the tip past the horizon with empty blocks, so `tip` falls out.
    let horizon = crate::segment::SEGMENT_FREEZE_REORG_MARGIN_BLOCKS;
    let far = tip + BlockCount::from_raw(horizon + 1);
    ingest_range(&mut client, tip + BlockCount::ONE, far, &[]);
    assert!(
        client.snapshot_at(tip).expect("ring reads").is_none(),
        "the fixture must have evicted the reference height's row"
    );

    match client.assemble_path(&input, &reference) {
        Err(crate::ClientError::ReferenceOutsideSnapshotRing { height }) => {
            assert_eq!(height, tip, "the refusal names the height");
        }
        other => panic!("expected ReferenceOutsideSnapshotRing, got {other:?}"),
    }
}

/// A closed chunk whose capture is absent refuses by name — it does not
/// quietly rebuild.
///
/// A resolved position means every chunk over it should be in the table. If
/// one is not, the remedy is reconciliation, and a silent fallback would
/// serve the spend while hiding that the mechanism it relies on has a hole.
#[test]
fn a_missing_capture_is_refused_not_rebuilt() {
    let (client, tip) = drained_chunks(&[OWNED_POSITION]);
    let input = input_at(&client, tip, OWNED_POSITION);
    let reference = reference_at(&client, tip);
    client
        .store
        .drop_capture_row_for_test(TreePosition::from_raw(OWNED_POSITION))
        .expect("row drops");

    match client.assemble_path(&input, &reference) {
        Err(crate::ClientError::CaptureMissing { end_leaf, layer }) => {
            assert_eq!(end_leaf, OWNED_POSITION, "the refusal names the key");
            assert_eq!(layer, 0, "the leaf chunk is read first");
        }
        other => panic!("expected CaptureMissing, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The batch: what the wallet and the actor actually call
// ---------------------------------------------------------------------------

/// A batch registers everything it can, reconciles once iff something is
/// owed, and reports the pairs it could not accept without failing.
#[test]
fn a_batch_registers_reconciles_once_and_reports_stale_pairs() {
    let (mut client, _) = drained_chunks(&[]);
    let early = Gindex::from_raw(u64::MAX - 1);
    let batch = [
        (Gindex::from_raw(OWNED_POSITION), owned_key(OWNED_POSITION)),
        (
            Gindex::from_raw(CASCADE_PARTNER),
            owned_key(CASCADE_PARTNER),
        ),
        (early, owned_key(u64::MAX - 1)),
        // A stale pair: the wrong key for a gindex the client holds.
        (Gindex::from_raw(SURVIVES), owned_key(SURVIVES + 1)),
    ];
    let sync = client.sync_owned(&batch).expect("a live client syncs");
    assert_eq!(sync.after_drain, 2, "two drained outputs were owed");
    assert_eq!(sync.before_drain, 1, "the unseen gindex is a future leaf");
    assert_eq!(sync.already_held, 0);
    assert_eq!(
        sync.stale,
        vec![Gindex::from_raw(SURVIVES)],
        "the wrong key is reported, not fatal"
    );
    let report = sync
        .reconciliation
        .expect("something was owed, so the batch reconciled");
    assert_eq!(report.positions_resolved, 2);
    assert!(report.chunks_written > 0);
    assert!(
        !client
            .owned_outputs
            .contains_key(&Gindex::from_raw(SURVIVES)),
        "a stale pair is not stored"
    );

    // The same batch again: nothing owed, nothing reconciled, still stale.
    let again = client.sync_owned(&batch).expect("a live client syncs");
    assert_eq!(
        again.already_held, 3,
        "every accepted pair is now held and served"
    );
    assert_eq!(again.after_drain, 0);
    assert_eq!(again.reconciliation, None, "a re-offer must not reconcile");
    assert_eq!(again.stale, vec![Gindex::from_raw(SURVIVES)]);

    // The caller's rescan reaches the chain the client is on and re-offers
    // the right key: accepted, owed, reconciled. Nothing was poisoned along
    // the way.
    let fixed = client
        .sync_owned(&[(Gindex::from_raw(SURVIVES), owned_key(SURVIVES))])
        .expect("a live client syncs");
    assert_eq!(fixed.after_drain, 1);
    assert!(fixed.stale.is_empty());
    assert!(fixed.reconciliation.is_some());
}

/// `AlreadyHeld` never suppresses an owed reconciliation across a rollback.
///
/// A rollback past the drain trims the position but keeps the surviving
/// pair. On re-ingest the fold re-resolves it — the pair is held — and
/// writes the chunks as they close, so by the time the wallet re-offers the
/// pair it is held *and* served: `AlreadyHeld`, with the captures present.
/// The pass asserts the captures, not only the verdict, because the verdict
/// alone would also be returned by a rule that simply never reconciled.
#[test]
fn a_re_offer_after_a_rollback_is_already_held_and_already_captured() {
    let (mut client, tip) = drained_chunks(&[OWNED_POSITION]);
    let cutoff = tip - BlockCount::ONE;
    let maturity = crate::recon::drained_sorted(&client.entries, cutoff)
        [usize::try_from(OWNED_POSITION).expect("fits")]
    .maturity;
    client
        .rollback_to_fork(maturity)
        .expect("the fork rolls back");
    assert!(
        held_at(&client, OWNED_POSITION).is_empty(),
        "the cut removed the row"
    );

    let end = tip.checked_add(BlockCount::ONE).expect("successor");
    for height in (maturity + BlockCount::ONE).ordinals_until(end) {
        let txs: Vec<TxLeafInputs<'_>> = Vec::new();
        client
            .ingest_block(BlockLeaves { height, txs: &txs })
            .expect("a re-drain ingests");
    }
    let sync = client
        .sync_owned(&[(Gindex::from_raw(OWNED_POSITION), owned_key(OWNED_POSITION))])
        .expect("a live client syncs");
    assert_eq!(
        sync.already_held, 1,
        "the pair survived the rollback and re-resolved"
    );
    assert_eq!(sync.reconciliation, None, "nothing was owed");
    assert_eq!(
        held_at(&client, OWNED_POSITION)
            .iter()
            .map(|c| c.layer)
            .collect::<Vec<_>>(),
        vec![0, 1],
        "the fold re-captured both cascade layers on the re-drain"
    );
}

/// A resumed client's mass re-registration reconciles once, then is free.
///
/// Resume is the mass late registration: the registry does not persist, so
/// every held output comes back owed on the first offer. The first sync
/// resolves every position and rebuilds nothing when the captures are
/// already in the store; the second sync is all `AlreadyHeld` and does not
/// touch the table.
#[test]
fn a_resumed_mass_registration_reconciles_once_then_is_already_held() {
    let (mut client, _) = drained_chunks(&[OWNED_POSITION, CASCADE_PARTNER]);
    // A resume loses the registry; the wallet re-offers what it holds.
    client.owned_outputs.clear();
    client.owned_positions.clear();
    let batch = [
        (Gindex::from_raw(OWNED_POSITION), owned_key(OWNED_POSITION)),
        (
            Gindex::from_raw(CASCADE_PARTNER),
            owned_key(CASCADE_PARTNER),
        ),
    ];
    let first = client.sync_owned(&batch).expect("a live client syncs");
    assert_eq!(first.after_drain, 2);
    let report = first.reconciliation.expect("owed, so reconciled");
    assert_eq!(report.positions_resolved, 2);
    assert_eq!(
        report.leaves_rebuilt, 0,
        "the fold had already captured everything"
    );

    let second = client.sync_owned(&batch).expect("a live client syncs");
    assert_eq!(second.already_held, 2);
    assert_eq!(second.reconciliation, None);
}

/// An unregistered input is refused by name — there is no rebuild to fall
/// back to.
#[test]
fn an_unregistered_input_is_refused_not_rebuilt() {
    let (client, tip) = drained_chunks(&[]);
    let input = input_at(&client, tip, OWNED_POSITION);
    let reference = reference_at(&client, tip);
    match client.assemble_path(&input, &reference) {
        Err(crate::ClientError::OutputNotRegistered { gindex, .. }) => {
            assert_eq!(gindex, input.gindex, "the refusal names the input");
        }
        other => panic!("expected OutputNotRegistered, got {other:?}"),
    }
}
