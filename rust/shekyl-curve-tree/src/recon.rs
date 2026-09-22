// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Block-derived leaf reconstruction (CT-2 surfaces S1/S2).
//!
//! Pure, deterministic functions that replicate the daemon's leaf-stream
//! derivation bit-exactly, so the wallet's reconstructed curve-tree root
//! byte-equals the consensus header root. Each function mirrors a named
//! site in `src/blockchain_db/blockchain_db.cpp::collect_outputs` /
//! `extract_leaf_hashes` (now the `0x07` entry slice) and is pinned in
//! `docs/design/CT2_DRAIN_ORDER.md`.
//!
//! This module owns the *post-parse* `tx_extra 0x07` slicing
//! ([`extract_leaf_commitments`]); the raw `tx_extra` → blob *parse* is owned
//! by `shekyl_scanner::extra::Extra::pqc_leaf_entries()` and runs at the
//! decode boundary (`client`, CT-3). No second `tx_extra` parser exists.

use crate::types::{BlockHeight, Gindex, LeafEntry, OutputIdentity, TargetKind};
use shekyl_consensus::{COINBASE_LOCK_WINDOW, DEFAULT_LOCK_WINDOW};
use shekyl_fcmp::tree::{
    build_layers, construct_leaf, ed25519_point_to_selene_scalar, selene_hash_init,
    SCALARS_PER_LEAF,
};

/// Size in bytes of one per-output `0x07` entry: the leaf commitment point
/// `CM` (32) followed by the post-quantum record (32) — `PL-D3` / `PL-D3a`.
/// Single source: [`shekyl_fcmp::PQC_LEAF_ENTRY_LEN`].
pub const PQC_LEAF_ENTRY_BYTES: usize = shekyl_fcmp::PQC_LEAF_ENTRY_LEN;
/// Byte length of the commitment point at the front of each entry.
/// Single source: `shekyl-crypto-pq` owns the 32/32 split of the entry.
pub const PQC_LEAF_POINT_BYTES: usize = shekyl_crypto_pq::leaf_commitment::PQC_LEAF_POINT_LEN;

/// Why a transaction's `0x07` payload cannot yield its outputs' leaf
/// commitments. On an admitted chain none of these fires: the shape and
/// content rules (`shekyl_wire::tx_extra::check_pqc_field_shape_of`) refuse
/// such a transaction at relay and connect. The replica therefore has **no
/// fallback** — the zero-`h_pqc` placeholder the daemon retired (CEN-I19) is
/// gone here too; a block that reaches this code with a bad field is a bug
/// in the feed, surfaced as an error rather than stored as a leaf set the
/// daemon would never hold. These are the *shape* errors; the point-content
/// twin — a published point that fails decompression — is [`LeafPointError`],
/// raised by [`collect_block_leaves`] under the same no-fallback rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafEntryError {
    /// The `0x07` tag is absent on a transaction with outputs.
    Absent,
    /// The payload is not a whole number of entries.
    Length {
        /// Payload length in bytes.
        got: usize,
    },
    /// The entry count does not equal the output count.
    CountMismatch {
        /// Entries in the payload.
        entries: usize,
        /// Outputs in the transaction.
        outputs: usize,
    },
}

/// One transaction's outputs for leaf collection, in `vout` order.
#[derive(Clone, Copy, Debug)]
pub struct TxOutputs<'a> {
    /// Whether this is the block's coinbase (`is_miner`).
    pub is_miner: bool,
    /// Per-output identities in `vout` order, `h_pqc` (the published
    /// commitment point) already resolved.
    pub outputs: &'a [OutputIdentity],
}

/// Slice the `tx_extra 0x07` payload into per-output leaf commitment points
/// (the first 32 bytes of each 64-byte entry), one per output.
///
/// `blob` is the raw payload from
/// `shekyl_scanner::extra::Extra::pqc_leaf_entries()` (or `None` when the
/// tag is absent); `n_outputs` is the transaction's `vout` count. Errors
/// are the [`LeafEntryError`] cases; with `n_outputs == 0` an absent tag is
/// the conforming shape and yields an empty vector.
pub fn extract_leaf_commitments(
    blob: Option<&[u8]>,
    n_outputs: usize,
) -> Result<Vec<[u8; 32]>, LeafEntryError> {
    let Some(bytes) = blob else {
        return if n_outputs == 0 {
            Ok(Vec::new())
        } else {
            Err(LeafEntryError::Absent)
        };
    };
    if !bytes.len().is_multiple_of(PQC_LEAF_ENTRY_BYTES) {
        return Err(LeafEntryError::Length { got: bytes.len() });
    }
    let entries = bytes.len() / PQC_LEAF_ENTRY_BYTES;
    if entries != n_outputs {
        return Err(LeafEntryError::CountMismatch {
            entries,
            outputs: n_outputs,
        });
    }
    Ok(bytes
        .chunks_exact(PQC_LEAF_ENTRY_BYTES)
        .map(|entry| {
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&entry[..PQC_LEAF_POINT_BYTES]);
            cm
        })
        .collect())
}

/// Compute an output's maturity height, mirroring the per-target maturity
/// arithmetic in `collect_outputs`. Returns `None` for [`TargetKind::Other`]
/// (the C++ `else continue` — not a leaf candidate).
#[must_use]
pub fn maturity_height(
    block_height: shekyl_types::BlockHeight,
    is_miner: bool,
    target: TargetKind,
) -> Option<shekyl_types::BlockHeight> {
    let coinbase = shekyl_types::BlockCount::from_raw(COINBASE_LOCK_WINDOW as u64);
    let spendable = shekyl_types::BlockCount::from_raw(DEFAULT_LOCK_WINDOW as u64);
    match target {
        TargetKind::TaggedKey | TargetKind::Key => {
            let lock = if is_miner { coinbase } else { spendable };
            Some(block_height + lock)
        }
        TargetKind::Other => None,
    }
}

/// Which of an output's published Ed25519 points was refused while building
/// its leaf. These are the three point *inputs* of
/// [`shekyl_fcmp::tree::construct_leaf`]; the fourth leaf field, `I = Hp(O)`,
/// is derived by hash-to-point and is always a point, so it can never be the
/// failing input. `O` and `C` fail only on decompression (consensus imposes
/// nothing more on them); `CM` is held to the full admission content rule
/// (canonical, prime-order, non-identity — `pqc_leaf_point_valid`, CEN-I19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafPoint {
    /// The output's one-time key `O`.
    OutputKey,
    /// The output's amount commitment `C` (`outPk`).
    Commitment,
    /// The published `0x07` leaf commitment `CM` (`PL-D3`).
    LeafCommitment,
}

/// An output whose published point was refused during leaf collection —
/// failed decompression, or (for `CM`) failed the admission content rule.
/// `gindex` names the offending output in the global output
/// sequence (assigned to every vout, so it identifies the tx/vout position).
///
/// On an admitted chain this never fires: the daemon rejects such an output
/// at admission and **aborts** on the same input at store time
/// (`DB_ERROR`, `src/blockchain_db/blockchain_db.cpp:617`). The replica
/// mirrors that fail-closed behavior — the block is refused, never ingested
/// with the leaf silently omitted (which would consume the gindex and build
/// a silently divergent tree).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafPointError {
    /// Global output index of the offending output.
    pub gindex: Gindex,
    /// Which published point was refused.
    pub point: LeafPoint,
}

/// The leaf-skip predicate fused with leaf construction, mirroring the
/// body of the `collect_outputs` per-output loop.
///
/// Returns `Ok(Some(leaf))` iff the output is a tree-leaf candidate:
/// - (a) the target is a known key target (not [`TargetKind::Other`]);
/// - (b) the output has a commitment (`i < outPk.size()`);
/// - (c) the published `CM` passes the admission content rule
///   (`pqc_leaf_point_valid`: canonical, prime-order, non-identity); and
/// - (c2) [`shekyl_fcmp::tree::construct_leaf`] succeeds.
///
/// Returns `Ok(None)` on the *legitimate* skips (a) and (b) — the daemon
/// skips the same outputs, so the two leaf sets agree. The global output
/// index is assigned to *every* output by the caller regardless of this
/// result — the leaf set is a subset of the indexed set
/// (CT2_DRAIN_ORDER.md §2.2). This function decides leaf membership only.
///
/// Returns `Err` when (c) or (c2) fails: a published `CM` the admission
/// rule refuses, or a point that does not decompress. That is **not** a
/// skip — the daemon rejects the same input (admission at relay/connect,
/// `DB_ERROR` at store, `blockchain_db.cpp:617`), so treating it as one
/// would silently drop a leaf the daemon refuses to be without, and every
/// later leaf would sit at a shifted position. The error names the failing
/// point so the feed defect is diagnosable.
pub fn try_build_leaf(out: &OutputIdentity) -> Result<Option<[u8; 128]>, LeafPoint> {
    // (a) known target.
    if matches!(out.target, TargetKind::Other) {
        return Ok(None);
    }
    // (b) has commitment slot.
    let Some(commitment) = out.commitment else {
        return Ok(None);
    };
    // (c) the published `CM` passes the admission content rule the daemon
    // enforces at relay and connect (canonical, prime-order, non-identity;
    // CEN-I19): `construct_leaf` below only decompresses, so without this
    // check a non-conforming feed could hand the replica an
    // identity/torsion/non-canonical commitment the daemon would have
    // refused — the same fail-closed parity contract as (c2), through the
    // shared predicate rather than a re-statement of it.
    if shekyl_crypto_pq::leaf_commitment::pqc_leaf_point_valid(&out.cm).is_none() {
        return Err(LeafPoint::LeafCommitment);
    }
    // (c2) leaf construction succeeds (shared FFI primitive with the
    // daemon, so x-extraction of all four points — `CM.x` included —
    // cannot diverge; CT2_DRAIN_ORDER.md §3.2).
    match construct_leaf(out.output_key.as_bytes(), commitment.as_bytes(), &out.cm) {
        Some(leaf) => Ok(Some(leaf)),
        None => {
            // Name the failing input, in `construct_leaf`'s own probe
            // order. `I = Hp(O)` is derived (hash-to-point, infallible),
            // so if `O` and `C` decompress the failure is `CM`.
            let point = if ed25519_point_to_selene_scalar(out.output_key.as_bytes()).is_none() {
                LeafPoint::OutputKey
            } else if ed25519_point_to_selene_scalar(commitment.as_bytes()).is_none() {
                LeafPoint::Commitment
            } else {
                LeafPoint::LeafCommitment
            };
            Err(point)
        }
    }
}

/// Collect leaf entries from a block's transactions, assigning global
/// output indices in C++ drain order (S1).
///
/// `next_gindex` is the running global output sequence (`next_output_seq`
/// in the daemon). It is advanced for **every** output regardless of leaf
/// membership — the leaf-ineligible outputs still consume an index — and
/// the updated value is returned so the caller threads it across blocks.
/// Per the derive-don't-accumulate rule (CT2_DRAIN_ORDER.md §7.1), the
/// caller derives `next_gindex` from cumulative chain position rather than
/// persisting a stateful counter, which makes reorg handling free
/// (truncate-and-rebuild).
///
/// Pass `txs` in C++ order: the coinbase first, then block txs in
/// block-list order; outputs within each in `vout` order.
///
/// Errors with [`LeafPointError`] when an output's published point fails
/// decompression ([`try_build_leaf`] (c)): the daemon aborts on the same
/// input, so the replica refuses the block rather than omitting the leaf
/// and building a silently divergent tree. `out` may hold a partial batch
/// on `Err`; the caller discards it.
pub fn collect_block_leaves(
    block_height: shekyl_types::BlockHeight,
    txs: &[TxOutputs<'_>],
    next_gindex: u64,
    out: &mut Vec<LeafEntry>,
) -> Result<u64, LeafPointError> {
    let mut gindex = next_gindex;
    for tx in txs {
        for output in tx.outputs {
            let this_gindex = gindex;
            // Every vout consumes an index before any skip check
            // (`next_output_seq++` at blockchain_db.cpp:360).
            gindex += 1;
            let Some(maturity) = maturity_height(block_height, tx.is_miner, output.target) else {
                continue; // (a) unknown target; index already consumed.
            };
            match try_build_leaf(output) {
                Ok(Some(leaf)) => out.push(LeafEntry {
                    gindex: Gindex::from_raw(this_gindex),
                    maturity,
                    creation_height: block_height,
                    leaf,
                    identity: *output,
                }),
                // (b) no commitment slot; index already consumed.
                Ok(None) => {}
                Err(point) => {
                    return Err(LeafPointError {
                        gindex: Gindex::from_raw(this_gindex),
                        point,
                    });
                }
            }
        }
    }
    Ok(gindex)
}

/// The drained leaves at `drained_through`, in canonical drain order
/// `(maturity, gindex)` (S2) — the single definition of tree-leaf order.
///
/// Both the leaf-scalar stream ([`assemble_leaf_stream`]) and membership-path
/// assembly ([`crate::assemble`]) consume this ordering, so a leaf's position
/// in the stream and its position in the returned slice are the same index.
/// Keeping one ordering avoids the "two orderings must agree" trap
/// (`CURVE_TREE_CLIENT.md` §7.7).
///
/// `drained_through` is the inclusive maturity cutoff for the reference
/// height; the reference-height → cutoff mapping (the drain trigger's
/// inclusive/exclusive boundary) is pinned by the CT-2 KAT and owned by
/// `client` (CT-3).
#[must_use]
pub fn drained_sorted(entries: &[LeafEntry], drained_through: BlockHeight) -> Vec<&LeafEntry> {
    let mut drained: Vec<&LeafEntry> = entries
        .iter()
        .filter(|e| e.maturity <= drained_through)
        .collect();
    drained.sort_by_key(|e| (e.maturity, e.gindex));
    drained
}

/// Leaves that enter the drained set when the inclusive cutoff advances to
/// `drained_through`.
///
/// During monotonic block ingest, `drained_through` increases by at most one
/// per block; these are exactly the leaves with `maturity == drained_through`
/// (all lower maturities were persisted on prior blocks). Sorted by `gindex`
/// within the maturity class so append order matches canonical drain order.
#[must_use]
pub fn newly_drained_at_cutoff(
    entries: &[LeafEntry],
    drained_through: BlockHeight,
) -> Vec<LeafEntry> {
    let mut batch: Vec<&LeafEntry> = entries
        .iter()
        .filter(|e| e.maturity == drained_through)
        .collect();
    batch.sort_by_key(|e| e.gindex);
    batch.into_iter().copied().collect()
}

/// Assemble the flat leaf-scalar stream for all leaves drained by
/// `drained_through`, in canonical drain order `(maturity, gindex)` (S2).
/// The result feeds [`shekyl_fcmp::tree::build_layers`].
#[must_use]
pub fn assemble_leaf_stream(entries: &[LeafEntry], drained_through: BlockHeight) -> Vec<[u8; 32]> {
    let drained = drained_sorted(entries, drained_through);
    let mut scalars = Vec::with_capacity(drained.len() * SCALARS_PER_LEAF);
    for entry in drained {
        for i in 0..SCALARS_PER_LEAF {
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(&entry.leaf[i * 32..(i + 1) * 32]);
            scalars.push(scalar);
        }
    }
    scalars
}

/// Compute the curve-tree root from an assembled leaf-scalar stream.
///
/// The empty tree (no drained leaves) is `selene_hash_init()`, mirroring
/// the daemon's `leaf_count == 0` special case (`db_lmdb.cpp`) — it is
/// **not** `build_layers(&[])` (the empty-tree boundary,
/// CT2_DRAIN_ORDER.md §5). The Round-1 oracle rebuilds from leaves via
/// `build_layers`; the cached `R_k` hot path (`store`, via
/// `build_upper_layers`) is layered on later against this baseline.
#[must_use]
pub fn root_from_scalars(scalars: &[[u8; 32]]) -> [u8; 32] {
    if scalars.is_empty() {
        return selene_hash_init();
    }
    let layers = build_layers(scalars);
    let top = layers.last().expect("build_layers yields ≥1 layer");
    debug_assert_eq!(top.len(), 1, "root layer has exactly one node");
    top[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::OutputIdentity;

    /// Standard Ed25519 basepoint, compressed. A valid, torsion-free
    /// point that `construct_leaf` accepts for both `O` and `C` in tests.
    const ED25519_BASEPOINT: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    fn coinbase_output() -> OutputIdentity {
        OutputIdentity {
            output_key: crate::types::OneTimePubkey::from_bytes(ED25519_BASEPOINT),
            commitment: Some(crate::types::CommitmentBytes::from_bytes(ED25519_BASEPOINT)),
            cm: ED25519_BASEPOINT,
            target: TargetKind::TaggedKey,
        }
    }

    #[test]
    fn extract_leaf_commitments_absent() {
        assert_eq!(extract_leaf_commitments(None, 0), Ok(Vec::new()));
        assert_eq!(
            extract_leaf_commitments(None, 1),
            Err(LeafEntryError::Absent)
        );
    }

    #[test]
    fn extract_leaf_commitments_slices_per_output() {
        let mut blob = vec![0xABu8; 64];
        blob.extend_from_slice(&[0xCDu8; 64]);
        let cms = extract_leaf_commitments(Some(&blob), 2).unwrap();
        assert_eq!(cms, vec![[0xABu8; 32], [0xCDu8; 32]]);
    }

    #[test]
    fn extract_leaf_commitments_malformed_length_is_an_error() {
        let blob = vec![0x01u8; 65];
        assert_eq!(
            extract_leaf_commitments(Some(&blob), 1),
            Err(LeafEntryError::Length { got: 65 })
        );
    }

    #[test]
    fn extract_leaf_commitments_count_must_equal_outputs() {
        let blob = vec![0x01u8; 128];
        assert_eq!(
            extract_leaf_commitments(Some(&blob), 3),
            Err(LeafEntryError::CountMismatch {
                entries: 2,
                outputs: 3
            })
        );
        assert_eq!(
            extract_leaf_commitments(Some(&[]), 0),
            Ok(Vec::new()),
            "no outputs, empty payload: conforming"
        );
    }

    #[test]
    fn maturity_coinbase_is_plus_60() {
        let m = maturity_height(BlockHeight::from_raw(100), true, TargetKind::TaggedKey)
            .expect("coinbase matures");
        assert_eq!(
            m,
            BlockHeight::from_raw(100 + COINBASE_LOCK_WINDOW as u64)
        );
    }

    #[test]
    fn maturity_regular_is_plus_10() {
        let m = maturity_height(BlockHeight::from_raw(100), false, TargetKind::TaggedKey)
            .expect("regular matures");
        assert_eq!(m, BlockHeight::from_raw(100 + DEFAULT_LOCK_WINDOW as u64));
    }

    #[test]
    fn maturity_other_is_none() {
        assert!(maturity_height(BlockHeight::from_raw(100), true, TargetKind::Other).is_none());
    }

    #[test]
    fn try_build_leaf_other_target_skipped() {
        let mut out = coinbase_output();
        out.target = TargetKind::Other;
        assert_eq!(try_build_leaf(&out), Ok(None));
    }

    #[test]
    fn try_build_leaf_no_commitment_skipped() {
        let mut out = coinbase_output();
        out.commitment = None;
        assert_eq!(try_build_leaf(&out), Ok(None));
    }

    #[test]
    fn try_build_leaf_coinbase_included() {
        let leaf = try_build_leaf(&coinbase_output())
            .expect("no bad point")
            .expect("valid coinbase output builds a leaf");
        // The 4th scalar is the commitment point's x-coordinate (PL-D3).
        let cm_x = shekyl_fcmp::tree::ed25519_point_to_selene_scalar(&ED25519_BASEPOINT)
            .expect("basepoint decompresses");
        assert_eq!(&leaf[96..128], &cm_x);
    }

    /// A published value that is not a point is a *named error* on its axis,
    /// never a skip and never a zero placeholder: a skipped leaf would
    /// silently diverge from the daemon, which aborts on the same input
    /// (`DB_ERROR`, `blockchain_db.cpp:617`) — the two surfaces agree
    /// fail-closed. `[7u8; 32]` is a non-point (nothing decompresses
    /// from it).
    #[test]
    fn try_build_leaf_names_the_failing_point() {
        let mut bad_cm = coinbase_output();
        bad_cm.cm = [7u8; 32];
        assert_eq!(try_build_leaf(&bad_cm), Err(LeafPoint::LeafCommitment));

        let mut bad_o = coinbase_output();
        bad_o.output_key = crate::types::OneTimePubkey::from_bytes([7u8; 32]);
        assert_eq!(try_build_leaf(&bad_o), Err(LeafPoint::OutputKey));

        let mut bad_c = coinbase_output();
        bad_c.commitment = Some(crate::types::CommitmentBytes::from_bytes([7u8; 32]));
        assert_eq!(try_build_leaf(&bad_c), Err(LeafPoint::Commitment));
    }

    /// `CM` is held to the admission content rule, not just decompression:
    /// the identity (decompresses fine) and a torsion point (decompresses
    /// fine) are refused exactly as the daemon refuses them at relay and
    /// connect, and only for `CM` — `O`/`C` carry no such consensus rule.
    #[test]
    fn try_build_leaf_holds_cm_to_the_admission_rule() {
        // Compressed identity: y = 1.
        let mut identity = [0u8; 32];
        identity[0] = 0x01;
        // A small-order (torsion) point: canonical encoding, decompresses,
        // not in the prime-order subgroup.
        const TORSION: [u8; 32] = [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ];

        for bad in [identity, TORSION] {
            let mut out = coinbase_output();
            out.cm = bad;
            assert_eq!(try_build_leaf(&out), Err(LeafPoint::LeafCommitment));
        }

        // The identity as `O` or `C` is refused too, but by
        // `construct_leaf` itself (`to_xy` has no affine x for the
        // identity) — the same shared primitive the daemon runs, so parity
        // holds there without a CM-style admission check, and the error
        // still names the right arm.
        let mut id_o = coinbase_output();
        id_o.output_key = crate::types::OneTimePubkey::from_bytes(identity);
        assert_eq!(try_build_leaf(&id_o), Err(LeafPoint::OutputKey));
        let mut id_c = coinbase_output();
        id_c.commitment = Some(crate::types::CommitmentBytes::from_bytes(identity));
        assert_eq!(try_build_leaf(&id_c), Err(LeafPoint::Commitment));
    }

    /// `collect_block_leaves` refuses the block on a bad point and names the
    /// offending output by its true global index (the index every vout
    /// consumes), not by its position in the leaf subset.
    #[test]
    fn collect_refuses_block_on_bad_point_with_gindex() {
        let mut bad = coinbase_output();
        bad.cm = [7u8; 32];
        let outputs = [coinbase_output(), bad];
        let txs = [TxOutputs {
            is_miner: true,
            outputs: &outputs,
        }];
        let mut leaves = Vec::new();
        assert_eq!(
            collect_block_leaves(BlockHeight::from_raw(60), &txs, 0, &mut leaves),
            Err(LeafPointError {
                gindex: Gindex::from_raw(1),
                point: LeafPoint::LeafCommitment,
            })
        );
    }

    #[test]
    fn collect_assigns_gindex_to_every_vout() {
        // [Other, valid]: the Other output consumes index 0 but is not a
        // leaf; the valid output is a leaf at gindex 1. This is the
        // leaf-set ⊆ indexed-set rule (§2.2).
        let mut other = coinbase_output();
        other.target = TargetKind::Other;
        let outputs = [other, coinbase_output()];
        let txs = [TxOutputs {
            is_miner: true,
            outputs: &outputs,
        }];
        let mut leaves = Vec::new();
        let next = collect_block_leaves(BlockHeight::from_raw(60), &txs, 0, &mut leaves).expect("no bad point");
        assert_eq!(next, 2, "both vouts consume an index");
        assert_eq!(leaves.len(), 1, "only the valid output is a leaf");
        assert_eq!(
            leaves[0].gindex,
            Gindex::from_raw(1),
            "leaf carries its true global index"
        );
        assert_eq!(
            leaves[0].maturity,
            BlockHeight::from_raw(60 + COINBASE_LOCK_WINDOW as u64)
        );
        assert_eq!(
            leaves[0].creation_height,
            BlockHeight::from_raw(60),
            "leaf records the block it was created in"
        );
    }

    #[test]
    fn empty_tree_root_is_selene_hash_init() {
        assert_eq!(root_from_scalars(&[]), selene_hash_init());
    }

    #[test]
    fn non_empty_root_differs_from_empty() {
        let id = coinbase_output();
        let leaf = try_build_leaf(&id).expect("no bad point").expect("leaf");
        let entry = LeafEntry {
            gindex: Gindex::from_raw(0),
            maturity: BlockHeight::from_raw(120),
            creation_height: BlockHeight::from_raw(60),
            leaf,
            identity: id,
        };
        let scalars = assemble_leaf_stream(&[entry], BlockHeight::from_raw(120));
        assert_eq!(scalars.len(), SCALARS_PER_LEAF, "one leaf → 4 scalars");
        let root = root_from_scalars(&scalars);
        assert_ne!(root, selene_hash_init(), "a populated tree is not empty");
    }

    #[test]
    fn assemble_filters_undrained_and_sorts_by_maturity_then_gindex() {
        let id = coinbase_output();
        let leaf = try_build_leaf(&id).expect("no bad point").expect("leaf");
        let entries = [
            LeafEntry {
                gindex: Gindex::from_raw(5),
                maturity: BlockHeight::from_raw(70),
                creation_height: BlockHeight::from_raw(10),
                leaf,
                identity: id,
            },
            LeafEntry {
                gindex: Gindex::from_raw(2),
                maturity: BlockHeight::from_raw(70),
                creation_height: BlockHeight::from_raw(10),
                leaf,
                identity: id,
            },
            // Not yet drained at cutoff 70.
            LeafEntry {
                gindex: Gindex::from_raw(1),
                maturity: BlockHeight::from_raw(71),
                creation_height: BlockHeight::from_raw(11),
                leaf,
                identity: id,
            },
        ];
        let scalars = assemble_leaf_stream(&entries, BlockHeight::from_raw(70));
        // Two drained leaves → 8 scalars (the maturity-71 leaf excluded).
        assert_eq!(scalars.len(), 2 * SCALARS_PER_LEAF);
    }

    #[test]
    fn incremental_drain_batches_match_drained_sorted_prefix() {
        let id = coinbase_output();
        let leaf = try_build_leaf(&id)
            .expect("no bad point")
            .expect("valid leaf");
        let entries = vec![
            LeafEntry {
                gindex: Gindex::from_raw(0),
                maturity: BlockHeight::from_raw(60),
                creation_height: BlockHeight::from_raw(0),
                leaf,
                identity: id,
            },
            LeafEntry {
                gindex: Gindex::from_raw(1),
                maturity: BlockHeight::from_raw(10),
                creation_height: BlockHeight::from_raw(0),
                leaf,
                identity: id,
            },
        ];
        let mut incremental = Vec::new();
        for through in 0..=60u64 {
            incremental.extend(newly_drained_at_cutoff(
                &entries,
                BlockHeight::from_raw(through),
            ));
        }
        let oracle: Vec<LeafEntry> = drained_sorted(&entries, BlockHeight::from_raw(60))
            .into_iter()
            .copied()
            .collect();
        assert_eq!(incremental, oracle);
    }
}
