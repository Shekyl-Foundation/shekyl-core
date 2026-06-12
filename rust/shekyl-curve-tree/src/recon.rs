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
//! `extract_leaf_hashes` and is pinned in `docs/design/CT2_DRAIN_ORDER.md`.
//!
//! This module owns the *post-parse* `tx_extra 0x07` validation
//! ([`extract_leaf_hashes`]); the raw `tx_extra` → blob *parse* is owned
//! by `shekyl_scanner::extra::Extra::pqc_leaf_hashes()` and runs at the
//! decode boundary (`client`, CT-3). No second `tx_extra` parser exists.

use crate::types::{BlockHeight, Gindex, LeafEntry, OutputIdentity, TargetKind};
use shekyl_fcmp::tree::{build_layers, construct_leaf, selene_hash_init, SCALARS_PER_LEAF};
use shekyl_oxide::{COINBASE_LOCK_WINDOW, DEFAULT_LOCK_WINDOW};

/// Size in bytes of one per-output PQC leaf hash (`PQC_LEAF_HASH_BYTES`).
pub const PQC_LEAF_HASH_BYTES: usize = 32;

/// All-zero `h_pqc` sentinel for outputs with no on-chain leaf hash.
/// Mirrors the C++ `zero_pqc` fallback in `collect_outputs`.
const ZERO_PQC: [u8; 32] = [0u8; 32];

/// One transaction's outputs for leaf collection, in `vout` order.
#[derive(Clone, Copy, Debug)]
pub struct TxOutputs<'a> {
    /// Whether this is the block's coinbase (`is_miner`).
    pub is_miner: bool,
    /// Per-output identities in `vout` order, `h_pqc` already resolved.
    pub outputs: &'a [OutputIdentity],
}

/// Validate and slice the `tx_extra 0x07` leaf-hash blob into per-output
/// 32-byte hashes, mirroring the daemon's `extract_leaf_hashes` lambda.
///
/// `blob` is the raw payload from
/// `shekyl_scanner::extra::Extra::pqc_leaf_hashes()` (or `None` when the
/// tag is absent). Returns an empty vector when the tag is absent or the
/// blob length is not a multiple of [`PQC_LEAF_HASH_BYTES`] (the C++
/// `return {}` paths) — an empty result means every output falls back to
/// the zero `h_pqc`.
///
/// In a V3-from-genesis chain every output carries the tag, so the
/// absent/malformed fallbacks never fire on Tier-A fixtures; they are
/// matched for daemon parity. The malformed (present-but-wrong-length)
/// case is exercised in Tier B (CT2_DRAIN_ORDER.md §8.2).
#[must_use]
pub fn extract_leaf_hashes(blob: Option<&[u8]>) -> Vec<[u8; 32]> {
    let Some(bytes) = blob else {
        return Vec::new();
    };
    if !bytes.len().is_multiple_of(PQC_LEAF_HASH_BYTES) {
        return Vec::new();
    }
    bytes
        .chunks_exact(PQC_LEAF_HASH_BYTES)
        .map(|chunk| {
            let mut h = [0u8; 32];
            h.copy_from_slice(chunk);
            h
        })
        .collect()
}

/// Resolve the per-output `h_pqc`: the `i`-th leaf hash if present, else
/// the zero sentinel. Mirrors `(i < num_leaf_hashes) ? blob[i] : zero_pqc`.
#[must_use]
pub fn per_output_h_pqc(leaf_hashes: &[[u8; 32]], i: usize) -> [u8; 32] {
    leaf_hashes.get(i).copied().unwrap_or(ZERO_PQC)
}

/// Compute an output's maturity height, mirroring the per-target maturity
/// arithmetic in `collect_outputs`. Returns `None` for [`TargetKind::Other`]
/// (the C++ `else continue` — not a leaf candidate).
#[must_use]
pub fn maturity_height(block_height: u64, is_miner: bool, target: TargetKind) -> Option<u64> {
    let coinbase = COINBASE_LOCK_WINDOW as u64;
    let spendable = DEFAULT_LOCK_WINDOW as u64;
    match target {
        TargetKind::TaggedKey | TargetKind::Key => {
            let lock = if is_miner { coinbase } else { spendable };
            Some(block_height + lock)
        }
        TargetKind::StakedKey { lock_blocks } => {
            Some((block_height + lock_blocks).max(block_height + spendable))
        }
        TargetKind::Other => None,
    }
}

/// The leaf-skip predicate fused with leaf construction, mirroring the
/// body of the `collect_outputs` per-output loop.
///
/// Returns `Some(leaf)` iff the output is a tree-leaf candidate:
/// - (a) the target is a known key target (not [`TargetKind::Other`]);
/// - (b) the output has a commitment (`i < outPk.size()`); and
/// - (c) [`shekyl_fcmp::tree::construct_leaf`] succeeds.
///
/// Returns `None` otherwise. The global output index is assigned to
/// *every* output by the caller regardless of this result — the leaf set
/// is a subset of the indexed set (CT2_DRAIN_ORDER.md §2.2). This
/// function decides leaf membership only.
#[must_use]
pub fn try_build_leaf(out: &OutputIdentity) -> Option<[u8; 128]> {
    // (a) known target.
    if matches!(out.target, TargetKind::Other) {
        return None;
    }
    // (b) has commitment slot.
    let commitment = out.commitment?;
    // (c) leaf construction succeeds (shared FFI primitive with the
    // daemon, so x-extraction cannot diverge — CT2_DRAIN_ORDER.md §3.2).
    construct_leaf(&out.output_key, &commitment, &out.h_pqc)
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
pub fn collect_block_leaves(
    block_height: u64,
    txs: &[TxOutputs<'_>],
    next_gindex: u64,
    out: &mut Vec<LeafEntry>,
) -> u64 {
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
            if let Some(leaf) = try_build_leaf(output) {
                out.push(LeafEntry {
                    gindex: Gindex(this_gindex),
                    maturity: BlockHeight(maturity),
                    creation_height: BlockHeight(block_height),
                    leaf,
                    identity: *output,
                });
            }
        }
    }
    gindex
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
pub fn drained_sorted(entries: &[LeafEntry], drained_through: u64) -> Vec<&LeafEntry> {
    let mut drained: Vec<&LeafEntry> = entries
        .iter()
        .filter(|e| e.maturity <= BlockHeight(drained_through))
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
pub fn newly_drained_at_cutoff(entries: &[LeafEntry], drained_through: u64) -> Vec<LeafEntry> {
    let mut batch: Vec<&LeafEntry> = entries
        .iter()
        .filter(|e| e.maturity == BlockHeight(drained_through))
        .collect();
    batch.sort_by_key(|e| e.gindex);
    batch.into_iter().copied().collect()
}

/// Assemble the flat leaf-scalar stream for all leaves drained by
/// `drained_through`, in canonical drain order `(maturity, gindex)` (S2).
/// The result feeds [`shekyl_fcmp::tree::build_layers`].
#[must_use]
pub fn assemble_leaf_stream(entries: &[LeafEntry], drained_through: u64) -> Vec<[u8; 32]> {
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
            output_key: ED25519_BASEPOINT,
            commitment: Some(ED25519_BASEPOINT),
            h_pqc: [7u8; 32],
            target: TargetKind::TaggedKey,
        }
    }

    #[test]
    fn extract_leaf_hashes_absent_is_empty() {
        assert!(extract_leaf_hashes(None).is_empty());
        assert!(extract_leaf_hashes(Some(&[])).is_empty());
    }

    #[test]
    fn extract_leaf_hashes_slices_per_output() {
        let blob = vec![0xABu8; 64];
        let hashes = extract_leaf_hashes(Some(&blob));
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], [0xABu8; 32]);
        assert_eq!(hashes[1], [0xABu8; 32]);
    }

    #[test]
    fn extract_leaf_hashes_malformed_length_is_empty() {
        // 65 bytes: not a multiple of 32 — the daemon's `return {}` path.
        let blob = vec![0x01u8; 65];
        assert!(extract_leaf_hashes(Some(&blob)).is_empty());
    }

    #[test]
    fn per_output_h_pqc_zero_fallback() {
        let hashes = [[1u8; 32], [2u8; 32]];
        assert_eq!(per_output_h_pqc(&hashes, 0), [1u8; 32]);
        assert_eq!(per_output_h_pqc(&hashes, 1), [2u8; 32]);
        // Out of range → zero sentinel.
        assert_eq!(per_output_h_pqc(&hashes, 2), ZERO_PQC);
        assert_eq!(per_output_h_pqc(&[], 0), ZERO_PQC);
    }

    #[test]
    fn maturity_coinbase_is_plus_60() {
        let m = maturity_height(100, true, TargetKind::TaggedKey).expect("coinbase matures");
        assert_eq!(m, 100 + COINBASE_LOCK_WINDOW as u64);
    }

    #[test]
    fn maturity_regular_is_plus_10() {
        let m = maturity_height(100, false, TargetKind::TaggedKey).expect("regular matures");
        assert_eq!(m, 100 + DEFAULT_LOCK_WINDOW as u64);
    }

    #[test]
    fn maturity_staked_is_max_of_lock_and_spendable() {
        // Lock longer than spendable age → lock wins.
        let long = maturity_height(100, false, TargetKind::StakedKey { lock_blocks: 1000 })
            .expect("staked matures");
        assert_eq!(long, 100 + 1000);
        // Lock shorter than spendable age → spendable floor wins.
        let short = maturity_height(100, false, TargetKind::StakedKey { lock_blocks: 1 })
            .expect("staked matures");
        assert_eq!(short, 100 + DEFAULT_LOCK_WINDOW as u64);
    }

    #[test]
    fn maturity_other_is_none() {
        assert!(maturity_height(100, true, TargetKind::Other).is_none());
    }

    #[test]
    fn try_build_leaf_other_target_skipped() {
        let mut out = coinbase_output();
        out.target = TargetKind::Other;
        assert!(try_build_leaf(&out).is_none());
    }

    #[test]
    fn try_build_leaf_no_commitment_skipped() {
        let mut out = coinbase_output();
        out.commitment = None;
        assert!(try_build_leaf(&out).is_none());
    }

    #[test]
    fn try_build_leaf_coinbase_included() {
        let leaf = try_build_leaf(&coinbase_output()).expect("valid coinbase output builds a leaf");
        // h_pqc is the 4th scalar, copied verbatim.
        assert_eq!(&leaf[96..128], &[7u8; 32]);
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
        let next = collect_block_leaves(60, &txs, 0, &mut leaves);
        assert_eq!(next, 2, "both vouts consume an index");
        assert_eq!(leaves.len(), 1, "only the valid output is a leaf");
        assert_eq!(
            leaves[0].gindex,
            Gindex(1),
            "leaf carries its true global index"
        );
        assert_eq!(
            leaves[0].maturity,
            BlockHeight(60 + COINBASE_LOCK_WINDOW as u64)
        );
        assert_eq!(
            leaves[0].creation_height,
            BlockHeight(60),
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
        let leaf = try_build_leaf(&id).expect("leaf");
        let entry = LeafEntry {
            gindex: Gindex(0),
            maturity: BlockHeight(120),
            creation_height: BlockHeight(60),
            leaf,
            identity: id,
        };
        let scalars = assemble_leaf_stream(&[entry], 120);
        assert_eq!(scalars.len(), SCALARS_PER_LEAF, "one leaf → 4 scalars");
        let root = root_from_scalars(&scalars);
        assert_ne!(root, selene_hash_init(), "a populated tree is not empty");
    }

    #[test]
    fn assemble_filters_undrained_and_sorts_by_maturity_then_gindex() {
        let id = coinbase_output();
        let leaf = try_build_leaf(&id).expect("leaf");
        let entries = [
            LeafEntry {
                gindex: Gindex(5),
                maturity: BlockHeight(70),
                creation_height: BlockHeight(10),
                leaf,
                identity: id,
            },
            LeafEntry {
                gindex: Gindex(2),
                maturity: BlockHeight(70),
                creation_height: BlockHeight(10),
                leaf,
                identity: id,
            },
            // Not yet drained at cutoff 70.
            LeafEntry {
                gindex: Gindex(1),
                maturity: BlockHeight(71),
                creation_height: BlockHeight(11),
                leaf,
                identity: id,
            },
        ];
        let scalars = assemble_leaf_stream(&entries, 70);
        // Two drained leaves → 8 scalars (the maturity-71 leaf excluded).
        assert_eq!(scalars.len(), 2 * SCALARS_PER_LEAF);
    }

    #[test]
    fn incremental_drain_batches_match_drained_sorted_prefix() {
        let id = coinbase_output();
        let leaf = try_build_leaf(&id).expect("valid leaf");
        let entries = vec![
            LeafEntry {
                gindex: Gindex(0),
                maturity: BlockHeight(60),
                creation_height: BlockHeight(0),
                leaf,
                identity: id,
            },
            LeafEntry {
                gindex: Gindex(1),
                maturity: BlockHeight(10),
                creation_height: BlockHeight(0),
                leaf,
                identity: id,
            },
        ];
        let mut incremental = Vec::new();
        for through in 0..=60u64 {
            incremental.extend(newly_drained_at_cutoff(&entries, through));
        }
        let oracle: Vec<LeafEntry> = drained_sorted(&entries, 60).into_iter().copied().collect();
        assert_eq!(incremental, oracle);
    }
}
