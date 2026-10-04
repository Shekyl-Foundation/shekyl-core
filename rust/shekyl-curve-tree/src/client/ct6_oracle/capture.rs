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
};
use super::{lock_count, reference_at};
use crate::store::CapturedChunk;
use crate::types::{
    AssembleInput, BlockHeight, ChunkLeaf, CommitmentBytes, Gindex, OneTimePubkey, TargetKind,
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

/// The Ed25519 basepoint, as every output's commitment. A valid point is
/// all `C` has to be here; `O` is what carries the per-leaf distinction.
const ED25519_BASEPOINT: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Ingest blocks 0..=`tip`, giving creation block `i` `counts[i]` outputs
/// with globally distinct output keys.
fn ingest_fixture(client: &mut CurveTreeClient, tip: BlockHeight, counts: &[usize]) {
    let mut seed = 0u64;
    let end = tip
        .checked_add(BlockCount::ONE)
        .expect("the ingested tip has a successor");
    for height in BlockHeight::ZERO.ordinals_until(end) {
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
    let target = CHUNKS * SELENE_CHUNK_WIDTH;
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
                .register_owned(Gindex::from_raw(*gindex))
                .expect("a live client registers"),
            OwnedRegistration::BeforeDrain,
            "an empty client has drained nothing"
        );
    }
    // The last creation is the last counted block; it drains at `+ lock`,
    // and the root at `h` drains through `h - 1`, so the tip is one past.
    let last_creation = u64::try_from(counts.len() - 1).expect("block count fits u64");
    let tip = BlockHeight::from_raw(last_creation) + lock_count() + BlockCount::ONE;
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

/// Decode a layer-0 capture body into the chunk leaves a path carries.
///
/// `I` is re-derived here, because it is not stored (§11.8). This is the
/// consumer's side of [`super::super::push_captured_identity`], written out
/// rather than shared with it: a decoder that called the encoder's inverse
/// would agree with it by construction.
fn decode_identities(bytes: &[u8]) -> Vec<ChunkLeaf> {
    assert_eq!(
        bytes.len() % CAPTURED_IDENTITY_BYTES,
        0,
        "a layer-0 body is whole identities"
    );
    bytes
        .chunks_exact(CAPTURED_IDENTITY_BYTES)
        .map(|row| {
            let mut o = [0u8; 32];
            let mut c = [0u8; 32];
            let mut cm_x = [0u8; 32];
            o.copy_from_slice(&row[0..32]);
            c.copy_from_slice(&row[32..64]);
            cm_x.copy_from_slice(&row[64..96]);
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

/// What the fold captured is what assembly would have built.
///
/// Two independent derivations of one value. The capture is written at
/// ingest, leaf by leaf, from the store's rows and the block's own leaves.
/// `assemble_paths` rebuilds the whole tree at the reference height and
/// slices it. Equality is the claim capture rests on, and it is the only
/// assertion that would notice an off-by-one in the chunk span, a wrong
/// `base` split between the store read and the block, or identities written
/// out of drain order.
#[test]
fn a_captured_chunk_equals_what_assembly_builds() {
    let (client, tip) = drained_chunks(&[OWNED_POSITION]);
    let reference = reference_at(&client, tip);

    let cutoff = tip - BlockCount::ONE;
    let drained = crate::recon::drained_sorted(&client.entries, cutoff);
    let owned = &drained[usize::try_from(OWNED_POSITION).expect("position fits usize")];
    let path = client
        .assemble_path(
            &AssembleInput {
                gindex: owned.gindex,
                output_key: owned.identity.output_key,
                commitment: owned
                    .identity
                    .commitment
                    .expect("a drained leaf carries a commitment"),
            },
            &reference,
        )
        .expect("the owned output's path assembles");

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
            .register_owned(Gindex::from_raw(0))
            .expect("a live client registers"),
        OwnedRegistration::AfterDrain,
        "leaf 0 drained long before this call"
    );
    // A gindex this client has never seen is a future leaf, not an error.
    assert_eq!(
        client
            .register_owned(Gindex::from_raw(u64::MAX))
            .expect("a live client registers"),
        OwnedRegistration::BeforeDrain,
        "an unseen gindex has not drained"
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
        client.owned_gindexes.contains(&owned),
        "a registration is the wallet's statement about its own output; a \
         rollback is a statement about the chain, and cannot retract it"
    );
    assert!(
        !client.owned_positions.contains(&OWNED_POSITION),
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
        .register_owned(Gindex::from_raw(OWNED_POSITION))
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
        .drop_leaf_rows_for_test(TreePosition::from_raw(start))
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
            client.register_owned(Gindex::from_raw(0)),
            Err(crate::ClientError::Poisoned)
        ),
        "registration must fail fast while memory is inconsistent"
    );
}
