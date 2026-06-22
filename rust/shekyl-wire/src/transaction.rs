// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Shekyl transaction (genesis `version = 3`) — coinbase + FCMP++ spend.
//!
//! Layout (GENESIS_TX_WIRE_FORMAT.md §9.3-§9.9), in the **genesis dense tag scheme**
//! (§2.0; matches the renumbered C++ oracle — landed via PR #168):
//!
//! ```text
//! Transaction := V(version=3) TxPrefix Ct
//! TxPrefix    := V(unlock_time) vec(Input) vec(Output) V(extra_len) extra[extra_len]
//! Input(gen)       := 0x00 V(height)
//! Input(spend)     := 0x01 V(amount) vec(V key_offset) key_image[32]   # txin_to_key / fcmp
//! Input(serve_cr.) := 0x02 ...                                         # archival serve_credit
//! Input(bond_post) := 0x03 ...                                         # archival bond_post
//! Output      := V(amount) 0x00 key[32] view_tag(1)                  # tagged_key (sole genesis output)
//! Ct(Null)    := 0x00 enc_amounts[nout×9] enc_labels[nout×9] outPk[nout×32]   # coinbase
//! Ct(Fcmp)    := 0x01 V(fee) referenceBlock[32]
//!                enc_amounts[nout×9] enc_labels[nout×9] outPk[nout×32]
//!                PqcAuths(nvin)  Prunable
//! PqcAuth     := auth_version(1) scheme_id(1) flags(u16 LE) V(pk_len) pk V(sig_len) sig
//! Prunable    := V(nbp) nbp×BpPlus V(tree_depth) V(proof_len) fcmp_proof[] pseudoOuts[nvin×32]
//! BpPlus      := A A1 B r1 s1 d1 (6×32) V(L_len) L[..×32] V(R_len) R[..×32]   # V restored from outPk
//! ```
//!
//! `pqc_auths` has **no length prefix** — its count is `nvin` (the C++
//! `PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), …)`); same for `pseudoOuts`.
//! Source: `src/fcmp/rctTypes.h` (`serialize_rctsig_base` / `serialize_rctsig_prunable`,
//! `BulletproofPlus`), `src/cryptonote_basic/cryptonote_basic.h` (`pqc_authentication`,
//! tx-level between base and prunable).

use std::io::{self, BufRead, Read, Write};

use shekyl_crypto_hash::cn_fast_hash;

use crate::bytes::{read_array, read_byte};
use crate::hash::hash_concat;
use crate::varint::{read_varint, write_varint};
use crate::READ_LEN_CAP;

/// Genesis transaction version (kept deliberately; `V4` = future lattice-only).
pub const TX_VERSION: u64 = 3;

// Genesis dense tag scheme (GENESIS_TX_WIRE_FORMAT.md §2.0 / §5 gate-(c)). Tags are
// numbered dense from 0x00; matches the renumbered C++ oracle VARIANT_TAGs and ct enum.
/// `txin_gen` tag — coinbase generation input.
pub const TAG_INPUT_GEN: u8 = 0x00;
/// `txin_to_key`/`txin_fcmp` tag — the FCMP++ spend input (the `key_offsets`-drop
/// reshape is a separate gate-(c) cut; the tag is dense here).
pub const TAG_INPUT_TO_KEY: u8 = 0x01;
/// `txout_to_tagged_key` tag — the sole genesis output type.
pub const TAG_OUTPUT_TAGGED_KEY: u8 = 0x00;
/// `Null` confidential-transaction type — the coinbase ct (carries a committed base).
pub const CT_TYPE_NULL: u8 = 0x00;
/// `FcmpPlusPlusPqc` confidential-transaction type — the spend ct.
pub const CT_TYPE_FCMP: u8 = 0x01;
/// `txin_archival_serve_credit_response` tag (gate-2, non-spending).
pub const TAG_INPUT_SERVE_CREDIT: u8 = 0x02;
/// `txin_archival_bond_post` tag (gate-4, JoinMarket-only at genesis).
pub const TAG_INPUT_BOND_POST: u8 = 0x03;

/// `post_kind` value for a JoinMarket bond post (the only kind valid at genesis).
/// `bond_spend_pk` is present on the wire iff `post_kind == JOINMARKET` (§9.11).
pub const BOND_POST_KIND_JOINMARKET: u8 = 0;
/// `holdings.kind` for a compact shard-set (carries an explicit shard list).
pub const HOLDINGS_SHARD_SET_COMPACT: u8 = 0;
/// `holdings.kind` for the complete tree (carries no shard list).
pub const HOLDINGS_COMPLETE_TREE: u8 = 1;

/// Consensus bound: max shards in a compact holdings set (`bond_wire.rs`).
const MAX_HOLDINGS_SHARDS: usize = 4096;
/// Consensus bound: max branch scalars per path layer (`wire.rs`).
const MAX_BRANCH_SCALARS: usize = 256;
/// Consensus bound: max path layers per curve (`wire.rs`).
const MAX_PATH_LAYERS: usize = 64;

// §10 resource bounds (structural; the chain-context rules of §13 — double-spend,
// CT balance, referenceBlock window, per-arm pqc_auths semantics — are the
// consensus layer's job, not the wire serializer's).
/// Max key-image (fcmp) inputs per tx (`FCMP_MAX_INPUTS_PER_TX`).
pub const MAX_FCMP_INPUTS: usize = 8;
/// Max outputs per tx (`BULLETPROOF_PLUS_MAX_OUTPUTS`).
pub const MAX_OUTPUTS: usize = 16;
/// Max `tx_extra` bytes for a non-coinbase tx (`MAX_TX_EXTRA_SIZE`).
pub const MAX_TX_EXTRA: usize = 24_576;
/// Max serialized transaction size (`CRYPTONOTE_MAX_TX_SIZE`).
pub const MAX_TX_SIZE: usize = 1_000_000;
/// `unlock_time` block-height sentinel: `>=` this is the (rejected) timestamp form.
pub const UNLOCK_TIME_BLOCK_SENTINEL: u64 = 500_000_000;

// PQC blob bounds — consensus accept/reject parity with the C++ oracle
// (`src/cryptonote_config.h`). A hybrid public key / signature is `x25519 ‖ ML-DSA-65`;
// the tx-level `pqc_auths` blobs may aggregate up to `MAX_MULTISIG_PARTICIPANTS` of
// them. These are tighter than `READ_LEN_CAP` and are the values the daemon rejects
// above, so the parser must match.
/// Single hybrid public-key length (`PQC_HYBRID_SINGLE_KEY_LEN`).
pub const PQC_HYBRID_SINGLE_KEY_LEN: usize = 1996;
/// Single hybrid signature length (`PQC_HYBRID_SINGLE_SIG_LEN`).
pub const PQC_HYBRID_SINGLE_SIG_LEN: usize = 3385;
/// Max multisig participants (`MAX_MULTISIG_PARTICIPANTS`).
const MAX_MULTISIG_PARTICIPANTS: usize = 7;
/// Max tx-level `pqc_auths` public-key blob (`PQC_MAX_PUBLIC_KEY_BLOB`).
pub const PQC_MAX_PUBLIC_KEY_BLOB: usize =
    2 + MAX_MULTISIG_PARTICIPANTS * PQC_HYBRID_SINGLE_KEY_LEN;
/// Max tx-level `pqc_auths` signature blob (`PQC_MAX_SIGNATURE_BLOB`).
pub const PQC_MAX_SIGNATURE_BLOB: usize = 2 + MAX_MULTISIG_PARTICIPANTS * PQC_HYBRID_SINGLE_SIG_LEN;

/// Read a varint-length-prefixed opaque byte blob, capped against `READ_LEN_CAP`.
fn read_len_prefixed<R: Read>(r: &mut R, what: &str) -> io::Result<Vec<u8>> {
    read_len_prefixed_bounded(r, what, READ_LEN_CAP)
}

/// Read a varint-length-prefixed opaque byte blob, rejecting (before allocating) any
/// declared length above `max`. Use a consensus-specific `max` for fields the C++
/// oracle bounds tighter than `READ_LEN_CAP` — e.g. the PQC key/sig blobs.
fn read_len_prefixed_bounded<R: Read>(r: &mut R, what: &str, max: usize) -> io::Result<Vec<u8>> {
    let len: usize = read_varint(r)?;
    if len > max {
        return Err(io::Error::other(format!(
            "shekyl-wire: {what} length {len} exceeds cap {max}"
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read `count` fixed 32-byte points (no per-element length prefix).
///
/// The speculative pre-allocation is **clamped**: `count` reaches here validated only
/// loosely on some paths (Bp+ `L`/`R` are capped at `READ_LEN_CAP`, not their exact
/// log-sized length), so reserving `count` up front would be a hostile-input
/// pre-alloc DoS (~32 MiB for a declared 1M). Every legitimate point vector is
/// `<= MAX_BRANCH_SCALARS`, so the clamp right-sizes real inputs while bounding the
/// reserve; the loop still pushes from a finite reader, so an oversized `count` fails
/// on the missing bytes rather than on allocation.
fn read_points<R: Read>(r: &mut R, count: usize) -> io::Result<Vec<[u8; 32]>> {
    let mut v = Vec::with_capacity(count.min(MAX_BRANCH_SCALARS));
    for _ in 0..count {
        v.push(read_array::<32, _>(r)?);
    }
    Ok(v)
}

/// A `Write` sink that discards its input and only tallies the byte count — lets
/// [`Transaction::serialized_len`] measure the wire size without materializing the
/// blob (the `MAX_TX_SIZE` check would otherwise allocate up to ~1 MiB per call).
#[derive(Default)]
struct CountingWriter {
    bytes: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Write segment-path branch layers: `V(n_layers) · per-layer[ V(width) · scalar[32]… ]`
/// (matches `shekyl-archival-retention::wire::write_branch_layers`).
fn write_branch_layers<W: Write>(w: &mut W, layers: &[Vec<[u8; 32]>]) -> io::Result<()> {
    write_varint(layers.len(), w)?;
    for branch in layers {
        write_varint(branch.len(), w)?;
        for scalar in branch {
            w.write_all(scalar)?;
        }
    }
    Ok(())
}

/// Read segment-path branch layers (bounds match the source reader).
fn read_branch_layers<R: Read>(r: &mut R, kind: &str) -> io::Result<Vec<Vec<[u8; 32]>>> {
    let n_layers: usize = read_varint(r)?;
    if n_layers > MAX_PATH_LAYERS {
        return Err(io::Error::other(format!(
            "shekyl-wire: {kind} layer count {n_layers} exceeds {MAX_PATH_LAYERS}"
        )));
    }
    let mut layers = Vec::new();
    for _ in 0..n_layers {
        let width: usize = read_varint(r)?;
        if width > MAX_BRANCH_SCALARS {
            return Err(io::Error::other(format!(
                "shekyl-wire: {kind} branch width {width} exceeds {MAX_BRANCH_SCALARS}"
            )));
        }
        layers.push(read_points(r, width)?);
    }
    Ok(layers)
}

/// A transaction input.
///
/// Genesis arms modelled here: the coinbase `gen` input and the FCMP++ spend
/// (`txin_to_key`). The archival arms (`serve_credit`, `bond_post`) and the
/// deferred emission/membership-only arms land in later slices.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
    /// Coinbase generation input: the block height.
    Gen(u64),
    /// FCMP++ spend input (`txin_to_key`, dense tag `0x01`). At genesis `amount == 0`
    /// and `key_offsets` is empty (membership is via the curve tree, not a ring), but
    /// the wire still serializes both — round-tripped faithfully (the §5 item-3
    /// `txin_fcmp` reshape that drops them is a deferred gate-(c) cut).
    ToKey {
        /// Cleartext amount (`0` for FCMP++).
        amount: u64,
        /// Ring offsets (empty for FCMP++).
        key_offsets: Vec<u64>,
        /// Key image (linking tag / nullifier).
        key_image: [u8; 32],
    },
    /// Archival serve-credit response (dense tag `0x02`, gate-2) — non-spending.
    ServeCredit(Box<ServeCredit>),
    /// Archival bond-post (dense tag `0x03`, gate-4) — JoinMarket-only at genesis.
    BondPost(Box<BondPost>),
}

impl Input {
    /// Write the input.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            Input::Gen(height) => {
                w.write_all(&[TAG_INPUT_GEN])?;
                write_varint(*height, w)
            }
            Input::ToKey {
                amount,
                key_offsets,
                key_image,
            } => {
                w.write_all(&[TAG_INPUT_TO_KEY])?;
                write_varint(*amount, w)?;
                write_varint(key_offsets.len(), w)?;
                for offset in key_offsets {
                    write_varint(*offset, w)?;
                }
                w.write_all(key_image)
            }
            Input::ServeCredit(sc) => {
                w.write_all(&[TAG_INPUT_SERVE_CREDIT])?;
                sc.write(w)
            }
            Input::BondPost(bp) => {
                w.write_all(&[TAG_INPUT_BOND_POST])?;
                bp.write(w)
            }
        }
    }

    /// Read an input.
    pub fn read<R: Read>(r: &mut R) -> io::Result<Input> {
        let tag = read_byte(r)?;
        match tag {
            TAG_INPUT_GEN => Ok(Input::Gen(read_varint(r)?)),
            TAG_INPUT_TO_KEY => {
                let amount = read_varint(r)?;
                let n_offsets: usize = read_varint(r)?;
                if n_offsets > READ_LEN_CAP {
                    return Err(io::Error::other(format!(
                        "shekyl-wire: key_offsets count {n_offsets} exceeds parse cap {READ_LEN_CAP}"
                    )));
                }
                let mut key_offsets = Vec::new();
                for _ in 0..n_offsets {
                    key_offsets.push(read_varint(r)?);
                }
                Ok(Input::ToKey {
                    amount,
                    key_offsets,
                    key_image: read_array(r)?,
                })
            }
            TAG_INPUT_SERVE_CREDIT => Ok(Input::ServeCredit(Box::new(ServeCredit::read(r)?))),
            TAG_INPUT_BOND_POST => Ok(Input::BondPost(Box::new(BondPost::read(r)?))),
            other => Err(io::Error::other(format!(
                "shekyl-wire: unsupported input tag {other:#04x}"
            ))),
        }
    }
}

/// Holdings descriptor for a bond post (`bond_wire.rs` `HoldingsDescriptor`).
///
/// The `kind` byte and the shard-id list are coupled on the wire — only the compact
/// form carries a list — so they are one enum, not a `{ kind, shard_ids }` pair. That
/// makes the `kind`/list mismatch the wire cannot represent (a complete-tree holding
/// with a stray shard list, which the old `write` silently dropped) unconstructable.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Holdings {
    /// Compact shard set (`kind` `0x00`) — carries an explicit shard-id list.
    ShardSetCompact(Vec<u64>),
    /// Complete tree (`kind` `0x01`) — no shard list on the wire.
    CompleteTree,
}

impl Holdings {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            Holdings::ShardSetCompact(shard_ids) => {
                w.write_all(&[HOLDINGS_SHARD_SET_COMPACT])?;
                write_varint(shard_ids.len(), w)?;
                for shard in shard_ids {
                    write_varint(*shard, w)?;
                }
            }
            Holdings::CompleteTree => w.write_all(&[HOLDINGS_COMPLETE_TREE])?,
        }
        Ok(())
    }

    fn read<R: Read>(r: &mut R) -> io::Result<Holdings> {
        match read_byte(r)? {
            HOLDINGS_SHARD_SET_COMPACT => {
                let count: usize = read_varint(r)?;
                if count > MAX_HOLDINGS_SHARDS {
                    return Err(io::Error::other(format!(
                        "shekyl-wire: holdings shard count {count} exceeds {MAX_HOLDINGS_SHARDS}"
                    )));
                }
                let mut shard_ids = Vec::new();
                for _ in 0..count {
                    shard_ids.push(read_varint(r)?);
                }
                Ok(Holdings::ShardSetCompact(shard_ids))
            }
            HOLDINGS_COMPLETE_TREE => Ok(Holdings::CompleteTree),
            other => Err(io::Error::other(format!(
                "shekyl-wire: invalid holdings kind {other}"
            ))),
        }
    }
}

/// Archival serve-credit response payload (dense tag `0x02`, gate-2 §5.1.1).
///
/// Non-spending: no key image; the `hybrid_signature` is on the vin and the tx
/// carries empty `pqc_auths`. Layout per
/// `shekyl-archival-retention::wire::ArchivalServeCreditResponse`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ServeCredit {
    /// The serving `P`'s canonical id.
    pub p_canonical_id: [u8; 32],
    /// Shard being served.
    pub shard_id: u64,
    /// Settlement epoch this response covers.
    pub settlement_epoch: u64,
    /// Frozen segment sub-root `R_k`.
    pub segment_subroot_rk: [u8; 32],
    /// Leaf index within the segment.
    pub leaf_index_in_segment: u32,
    /// Challenged leaf bytes (4 scalars × 32).
    pub leaf_bytes: [u8; 128],
    /// Selene (`c1`) branch layers, bottom-to-top.
    pub c1_layers: Vec<Vec<[u8; 32]>>,
    /// Helios (`c2`) branch layers, bottom-to-top.
    pub c2_layers: Vec<Vec<[u8; 32]>>,
    /// Canonical hybrid signature bytes.
    pub hybrid_signature: Vec<u8>,
}

impl ServeCredit {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.p_canonical_id)?;
        write_varint(self.shard_id, w)?;
        write_varint(self.settlement_epoch, w)?;
        w.write_all(&self.segment_subroot_rk)?;
        w.write_all(&self.leaf_index_in_segment.to_le_bytes())?;
        w.write_all(&self.leaf_bytes)?;
        write_branch_layers(w, &self.c1_layers)?;
        write_branch_layers(w, &self.c2_layers)?;
        write_varint(self.hybrid_signature.len(), w)?;
        w.write_all(&self.hybrid_signature)
    }

    fn read<R: Read>(r: &mut R) -> io::Result<ServeCredit> {
        let p_canonical_id = read_array(r)?;
        let shard_id = read_varint(r)?;
        let settlement_epoch = read_varint(r)?;
        let segment_subroot_rk = read_array(r)?;
        let leaf_index_in_segment = u32::from_le_bytes(read_array::<4, _>(r)?);
        let leaf_bytes = read_array::<128, _>(r)?;
        let c1_layers = read_branch_layers(r, "c1")?;
        let c2_layers = read_branch_layers(r, "c2")?;
        let hybrid_signature = read_len_prefixed_bounded(
            r,
            "serve_credit hybrid_signature",
            PQC_HYBRID_SINGLE_SIG_LEN,
        )?;
        Ok(ServeCredit {
            p_canonical_id,
            shard_id,
            settlement_epoch,
            segment_subroot_rk,
            leaf_index_in_segment,
            leaf_bytes,
            c1_layers,
            c2_layers,
            hybrid_signature,
        })
    }

    /// In-memory consensus-bound check — mirrors the per-field `read` caps so a
    /// hand-built arm passes [`Transaction::validate`] iff it would re-parse (`write`
    /// is faithful, not a gate).
    fn validate(&self) -> io::Result<()> {
        for (which, layers) in [("c1", &self.c1_layers), ("c2", &self.c2_layers)] {
            if layers.len() > MAX_PATH_LAYERS {
                return Err(io::Error::other(format!(
                    "shekyl-wire: serve_credit {which} path layers {} exceed {MAX_PATH_LAYERS}",
                    layers.len()
                )));
            }
            for layer in layers {
                if layer.len() > MAX_BRANCH_SCALARS {
                    return Err(io::Error::other(format!(
                        "shekyl-wire: serve_credit {which} branch scalars {} exceed {MAX_BRANCH_SCALARS}",
                        layer.len()
                    )));
                }
            }
        }
        if self.hybrid_signature.len() > PQC_HYBRID_SINGLE_SIG_LEN {
            return Err(io::Error::other(format!(
                "shekyl-wire: serve_credit hybrid_signature {} exceeds {PQC_HYBRID_SINGLE_SIG_LEN}",
                self.hybrid_signature.len()
            )));
        }
        Ok(())
    }
}

/// The `post_kind` discriminant of a [`BondPost`], with its coupled payload.
///
/// Only the JoinMarket post carries `bond_spend_pk` on the wire (§9.11), so the
/// coupling lives in the type: `JoinMarket` *always* has the key and `Other` *never*
/// does. That makes both silent round-trip hazards of the old `{ post_kind: u8,
/// bond_spend_pk: Option<_> }` shape — a non-JoinMarket post whose `Some` key `write`
/// dropped, and a JoinMarket post whose missing key `write` errored on — impossible
/// to construct.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BondPostKind {
    /// JoinMarket post (`post_kind` `0x00`, the only kind valid at genesis) — carries
    /// `bond_spend_pk`, the GF-1 debit authorizer (§9.11).
    JoinMarket {
        /// The GF-1 debit authorizer hybrid public key.
        bond_spend_pk: Vec<u8>,
    },
    /// Any non-JoinMarket post kind — no `bond_spend_pk` on the wire. The byte must
    /// not be the JoinMarket tag (`Other` is non-JoinMarket by construction; `write`
    /// rejects `Other(JOINMARKET)`).
    Other(u8),
}

/// Archival bond-post payload (dense tag `0x03`, gate-4 §3.4.1). JoinMarket-only at
/// genesis. The `post_kind`/`bond_spend_pk` coupling (§9.11) — which the current
/// `shekyl-archival-retention::bond_wire` omits and the impl must add — is carried in
/// [`BondPostKind`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BondPost {
    /// `P`'s canonical hybrid public key.
    pub hybrid_public_key: Vec<u8>,
    /// `P`'s canonical id.
    pub p_canonical_id: [u8; 32],
    /// The post kind and its coupled `bond_spend_pk` (§9.11).
    pub kind: BondPostKind,
    /// Holdings served.
    pub holdings: Holdings,
    /// Public bonded total (== `bond_credit` == `bond_floor` for JoinMarket).
    pub bonded_total_atomic: u64,
    /// Public bond credit.
    pub bond_credit: u64,
    /// Public bond debit (`0` for JoinMarket).
    pub bond_debit: u64,
}

impl BondPost {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(self.hybrid_public_key.len(), w)?;
        w.write_all(&self.hybrid_public_key)?;
        w.write_all(&self.p_canonical_id)?;
        match &self.kind {
            BondPostKind::JoinMarket { bond_spend_pk } => {
                w.write_all(&[BOND_POST_KIND_JOINMARKET])?;
                write_varint(bond_spend_pk.len(), w)?;
                w.write_all(bond_spend_pk)?;
            }
            BondPostKind::Other(post_kind) => {
                // `Other` is non-JoinMarket by contract; reusing the JoinMarket tag
                // would make `write` emit a `bond_spend_pk`-less blob that `read`
                // would then try to parse as JoinMarket (consuming the holdings bytes
                // as the key). Reject the misconstruction rather than emit it.
                if *post_kind == BOND_POST_KIND_JOINMARKET {
                    return Err(io::Error::other(
                        "shekyl-wire: BondPostKind::Other must not use the JoinMarket tag \
                         (use BondPostKind::JoinMarket)",
                    ));
                }
                w.write_all(&[*post_kind])?;
            }
        }
        self.holdings.write(w)?;
        write_varint(self.bonded_total_atomic, w)?;
        write_varint(self.bond_credit, w)?;
        write_varint(self.bond_debit, w)
    }

    fn read<R: Read>(r: &mut R) -> io::Result<BondPost> {
        let hybrid_public_key =
            read_len_prefixed_bounded(r, "bond_post hybrid_public_key", PQC_HYBRID_SINGLE_KEY_LEN)?;
        let p_canonical_id = read_array(r)?;
        let post_kind = read_byte(r)?;
        // `read` never yields `Other(JOINMARKET)`: the JoinMarket tag always takes the
        // first arm, so the `write` guard above only fires on a hand-built value.
        let kind = if post_kind == BOND_POST_KIND_JOINMARKET {
            BondPostKind::JoinMarket {
                bond_spend_pk: read_len_prefixed_bounded(
                    r,
                    "bond_spend_pk",
                    PQC_HYBRID_SINGLE_KEY_LEN,
                )?,
            }
        } else {
            BondPostKind::Other(post_kind)
        };
        let holdings = Holdings::read(r)?;
        Ok(BondPost {
            hybrid_public_key,
            p_canonical_id,
            kind,
            holdings,
            bonded_total_atomic: read_varint(r)?,
            bond_credit: read_varint(r)?,
            bond_debit: read_varint(r)?,
        })
    }

    /// In-memory consensus-bound check — mirrors the per-field `read` caps and the
    /// `write` JoinMarket-tag guard, so a hand-built arm passes
    /// [`Transaction::validate`] iff it would serialize-and-re-parse intact.
    fn validate(&self) -> io::Result<()> {
        if self.hybrid_public_key.len() > PQC_HYBRID_SINGLE_KEY_LEN {
            return Err(io::Error::other(format!(
                "shekyl-wire: bond_post hybrid_public_key {} exceeds {PQC_HYBRID_SINGLE_KEY_LEN}",
                self.hybrid_public_key.len()
            )));
        }
        match &self.kind {
            BondPostKind::JoinMarket { bond_spend_pk } => {
                if bond_spend_pk.len() > PQC_HYBRID_SINGLE_KEY_LEN {
                    return Err(io::Error::other(format!(
                        "shekyl-wire: bond_post bond_spend_pk {} exceeds {PQC_HYBRID_SINGLE_KEY_LEN}",
                        bond_spend_pk.len()
                    )));
                }
            }
            // `Other` must not reuse the JoinMarket tag — `write` would emit a
            // bond_spend_pk-less blob that re-parses as JoinMarket (a mis-parse).
            BondPostKind::Other(post_kind) => {
                if *post_kind == BOND_POST_KIND_JOINMARKET {
                    return Err(io::Error::other(
                        "shekyl-wire: BondPostKind::Other must not use the JoinMarket tag",
                    ));
                }
            }
        }
        if let Holdings::ShardSetCompact(shard_ids) = &self.holdings {
            if shard_ids.len() > MAX_HOLDINGS_SHARDS {
                return Err(io::Error::other(format!(
                    "shekyl-wire: bond_post holdings shard count {} exceeds {MAX_HOLDINGS_SHARDS}",
                    shard_ids.len()
                )));
            }
        }
        Ok(())
    }
}

/// A transaction output (`tagged_key`).
///
/// `view_tag` is mandatory — `tagged_key` is the sole genesis output type
/// (GENESIS_TX_WIRE_FORMAT.md §2.2), so a view-tag-less output is unrepresentable
/// (no `Option`). `amount` is cleartext for the coinbase output and `0` for a
/// confidential spend output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
    /// Cleartext amount for the coinbase output; `0` for confidential outputs.
    pub amount: u64,
    /// The one-time output key.
    pub key: [u8; 32],
    /// Scan fast-reject prefilter byte.
    pub view_tag: u8,
}

impl Output {
    /// Write the output.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(self.amount, w)?;
        w.write_all(&[TAG_OUTPUT_TAGGED_KEY])?;
        w.write_all(&self.key)?;
        w.write_all(&[self.view_tag])
    }

    /// Read an output.
    pub fn read<R: Read>(r: &mut R) -> io::Result<Output> {
        let amount = read_varint(r)?;
        let tag = read_byte(r)?;
        match tag {
            TAG_OUTPUT_TAGGED_KEY => Ok(Output {
                amount,
                key: read_array(r)?,
                view_tag: read_byte(r)?,
            }),
            other => Err(io::Error::other(format!(
                "shekyl-wire: unsupported output tag {other:#04x} (only tagged_key)"
            ))),
        }
    }
}

/// The committed confidential-transaction base arrays, sized by output count.
///
/// Present for **both** the coinbase `Null` type and the `Fcmp` spend — the C++
/// `serialize_rctsig_base` writes `enc_amounts` / `enc_labels` / `outPk` for both
/// so every output gets a tree-leaf commitment (rctTypes.h:209-280).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CtBase {
    /// Per-output encrypted amounts (8-byte value + 1-byte tag).
    pub enc_amounts: Vec<[u8; 9]>,
    /// Per-output encrypted labels (fixed-size, real-or-zero, never elided; §2.3).
    pub enc_labels: Vec<[u8; 9]>,
    /// Per-output commitments.
    pub commitments: Vec<[u8; 32]>,
}

impl CtBase {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for amount in &self.enc_amounts {
            w.write_all(amount)?;
        }
        for label in &self.enc_labels {
            w.write_all(label)?;
        }
        for commitment in &self.commitments {
            w.write_all(commitment)?;
        }
        Ok(())
    }

    fn read<R: Read>(outputs: usize, r: &mut R) -> io::Result<CtBase> {
        let mut enc_amounts = Vec::new();
        let mut enc_labels = Vec::new();
        for _ in 0..outputs {
            enc_amounts.push(read_array::<9, _>(r)?);
        }
        for _ in 0..outputs {
            enc_labels.push(read_array::<9, _>(r)?);
        }
        Ok(CtBase {
            enc_amounts,
            enc_labels,
            commitments: read_points(r, outputs)?,
        })
    }
}

/// Per-input PQC authentication (`cryptonote_basic.h` `pqc_authentication`),
/// serialized at **tx level** between the ct base and the prunable section.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PqcAuth {
    /// Authentication version (consensus requires `1`).
    pub auth_version: u8,
    /// Scheme id (`1` single, `2` multisig).
    pub scheme_id: u8,
    /// Flags (consensus requires `0`; unknown bits rejected).
    pub flags: u16,
    /// Canonical `HybridPublicKey` blob.
    pub hybrid_public_key: Vec<u8>,
    /// Canonical `HybridSignature` blob.
    pub hybrid_signature: Vec<u8>,
}

impl PqcAuth {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&[self.auth_version, self.scheme_id])?;
        w.write_all(&self.flags.to_le_bytes())?;
        write_varint(self.hybrid_public_key.len(), w)?;
        w.write_all(&self.hybrid_public_key)?;
        write_varint(self.hybrid_signature.len(), w)?;
        w.write_all(&self.hybrid_signature)
    }

    fn read<R: Read>(r: &mut R) -> io::Result<PqcAuth> {
        let auth_version = read_byte(r)?;
        let scheme_id = read_byte(r)?;
        let flags = u16::from_le_bytes(read_array::<2, _>(r)?);
        let hybrid_public_key =
            read_len_prefixed_bounded(r, "pqc hybrid_public_key", PQC_MAX_PUBLIC_KEY_BLOB)?;
        let hybrid_signature =
            read_len_prefixed_bounded(r, "pqc hybrid_signature", PQC_MAX_SIGNATURE_BLOB)?;
        Ok(PqcAuth {
            auth_version,
            scheme_id,
            flags,
            hybrid_public_key,
            hybrid_signature,
        })
    }
}

/// An aggregated Bulletproof+ (`rctTypes.h` `BulletproofPlus`). `V` is not
/// serialized (restored from `outPk`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BpPlus {
    /// `A`.
    pub a: [u8; 32],
    /// `A1`.
    pub a1: [u8; 32],
    /// `B`.
    pub b: [u8; 32],
    /// `r1`.
    pub r1: [u8; 32],
    /// `s1`.
    pub s1: [u8; 32],
    /// `d1`.
    pub d1: [u8; 32],
    /// `L` vector.
    pub l: Vec<[u8; 32]>,
    /// `R` vector.
    pub r: Vec<[u8; 32]>,
}

impl BpPlus {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.a)?;
        w.write_all(&self.a1)?;
        w.write_all(&self.b)?;
        w.write_all(&self.r1)?;
        w.write_all(&self.s1)?;
        w.write_all(&self.d1)?;
        write_varint(self.l.len(), w)?;
        for point in &self.l {
            w.write_all(point)?;
        }
        write_varint(self.r.len(), w)?;
        for point in &self.r {
            w.write_all(point)?;
        }
        Ok(())
    }

    fn read<R: Read>(r: &mut R) -> io::Result<BpPlus> {
        let a = read_array(r)?;
        let a1 = read_array(r)?;
        let b = read_array(r)?;
        let r1 = read_array(r)?;
        let s1 = read_array(r)?;
        let d1 = read_array(r)?;
        let l_len: usize = read_varint(r)?;
        if l_len > READ_LEN_CAP {
            return Err(io::Error::other(format!(
                "shekyl-wire: Bp+ L length {l_len} exceeds parse cap {READ_LEN_CAP}"
            )));
        }
        let l = read_points(r, l_len)?;
        let r_len: usize = read_varint(r)?;
        if r_len > READ_LEN_CAP {
            return Err(io::Error::other(format!(
                "shekyl-wire: Bp+ R length {r_len} exceeds parse cap {READ_LEN_CAP}"
            )));
        }
        let r_points = read_points(r, r_len)?;
        Ok(BpPlus {
            a,
            a1,
            b,
            r1,
            s1,
            d1,
            l,
            r: r_points,
        })
    }
}

/// FCMP++ prunable proof data (`rctTypes.h` `serialize_rctsig_prunable`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Prunable {
    /// Bulletproof+ proofs (genesis: exactly one — `nbp == 1`).
    pub bulletproofs: Vec<BpPlus>,
    /// Curve-tree depth the FCMP++ proof is relative to.
    pub tree_depth: u64,
    /// Opaque FCMP++ membership+SAL proof bytes (interior frozen by reference, §6 Q6).
    pub fcmp_proof: Vec<u8>,
    /// Re-blinded pseudo-out commitments, one per input.
    pub pseudo_outs: Vec<[u8; 32]>,
}

impl Prunable {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(self.bulletproofs.len(), w)?;
        for bp in &self.bulletproofs {
            bp.write(w)?;
        }
        write_varint(self.tree_depth, w)?;
        write_varint(self.fcmp_proof.len(), w)?;
        w.write_all(&self.fcmp_proof)?;
        for pseudo_out in &self.pseudo_outs {
            w.write_all(pseudo_out)?;
        }
        Ok(())
    }

    fn read<R: Read>(inputs: usize, r: &mut R) -> io::Result<Prunable> {
        let nbp: usize = read_varint(r)?;
        if nbp > READ_LEN_CAP {
            return Err(io::Error::other(format!(
                "shekyl-wire: nbp {nbp} exceeds parse cap {READ_LEN_CAP}"
            )));
        }
        let mut bulletproofs = Vec::new();
        for _ in 0..nbp {
            bulletproofs.push(BpPlus::read(r)?);
        }
        let tree_depth = read_varint(r)?;
        let fcmp_proof = read_len_prefixed(r, "fcmp_proof")?;
        // pseudoOuts: one per input, no length prefix.
        let pseudo_outs = read_points(r, inputs)?;
        Ok(Prunable {
            bulletproofs,
            tree_depth,
            fcmp_proof,
            pseudo_outs,
        })
    }
}

/// The confidential-transaction section.
#[derive(Clone, PartialEq, Eq, Debug)]
// The Fcmp variant is intrinsically larger than Null (it carries the proofs);
// boxing would only move the bytes behind a pointer for no consumer benefit.
#[allow(clippy::large_enum_variant)]
pub enum Ct {
    /// Coinbase confidential section (type 0x00): committed base only.
    Null(CtBase),
    /// FCMP++ confidential section (dense ct type `0x01`). Covers the full spend
    /// (per-input `pqc_auths` + a `prunable` proof) **and** the non-spend fee-only
    /// shapes (`serve_credit_only`: empty `pqc_auths`, no prunable, §2.5). `pqc_auths`
    /// is EOF-tolerant on read and `prunable` is [`Option`] — both absent in the
    /// fee-only form (GENESIS_TX_WIRE_FORMAT.md §9.8 / §4).
    Fcmp {
        /// Transaction fee.
        fee: u64,
        /// Block hash anchoring the curve-tree root the proof is against.
        reference_block: [u8; 32],
        /// Committed base arrays (per output).
        base: CtBase,
        /// Per-input PQC authentication (count == `nvin`, no length prefix; empty in
        /// the fee-only / serve-credit form).
        pqc_auths: Vec<PqcAuth>,
        /// Prunable proof data — `None` in the fee-only / serve-credit form (no
        /// bulletproof / fcmp proof / pseudoOuts).
        prunable: Option<Prunable>,
    },
}

impl Ct {
    /// Write the ct section.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            Ct::Null(base) => {
                w.write_all(&[CT_TYPE_NULL])?;
                base.write(w)
            }
            Ct::Fcmp {
                fee,
                reference_block,
                base,
                pqc_auths,
                prunable,
            } => {
                w.write_all(&[CT_TYPE_FCMP])?;
                write_varint(*fee, w)?;
                w.write_all(reference_block)?;
                base.write(w)?;
                // tx-level pqc_auths: count == nvin, no length prefix (empty in the
                // fee-only / serve-credit form).
                for auth in pqc_auths {
                    auth.write(w)?;
                }
                // prunable follows iff present (absent in the fee-only form).
                if let Some(prunable) = prunable {
                    prunable.write(w)?;
                }
                Ok(())
            }
        }
    }

    /// Read the ct section. `inputs`/`outputs` (the vin/vout counts) size the
    /// per-input/per-output arrays that carry no length prefix. Takes a [`BufRead`]
    /// so the EOF-tolerant tail (§9.8) can be detected without consuming bytes.
    pub fn read<R: BufRead>(inputs: usize, outputs: usize, r: &mut R) -> io::Result<Ct> {
        let ct_type = read_byte(r)?;
        match ct_type {
            CT_TYPE_NULL => Ok(Ct::Null(CtBase::read(outputs, r)?)),
            CT_TYPE_FCMP => {
                let fee = read_varint(r)?;
                let reference_block = read_array(r)?;
                let base = CtBase::read(outputs, r)?;
                // EOF-tolerant tail (§9.8 / §4). The full spend carries `nvin`
                // pqc_auths then a prunable proof; the **fee-only / serve-credit**
                // form ends right after the base — empty pqc_auths, no prunable
                // (cryptonote_basic.h:491-530; tx_verification_utils.cpp:122-141).
                // The ct is the last field of a transaction, so no remaining bytes
                // here means the fee-only form. NOTE: the live-oracle byte/hash
                // parity for the fee-only/serve-credit shape (and the bond_post
                // pseudoOuts coupling, a §13 F1/F3 forward obligation) is validated
                // when those post-genesis blobs are capturable; the round-trip here
                // proves internal consistency.
                if r.fill_buf()?.is_empty() {
                    return Ok(Ct::Fcmp {
                        fee,
                        reference_block,
                        base,
                        pqc_auths: Vec::new(),
                        prunable: None,
                    });
                }
                let mut pqc_auths = Vec::new();
                for _ in 0..inputs {
                    pqc_auths.push(PqcAuth::read(r)?);
                }
                let prunable = Some(Prunable::read(inputs, r)?);
                Ok(Ct::Fcmp {
                    fee,
                    reference_block,
                    base,
                    pqc_auths,
                    prunable,
                })
            }
            other => Err(io::Error::other(format!(
                "shekyl-wire: unsupported ct type {other:#04x}"
            ))),
        }
    }
}

/// The transaction prefix (everything hashed into the prefix hash).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxPrefix {
    /// Additional timelock (block height; `0` = none). A varint on the wire.
    pub unlock_time: u64,
    /// Transaction inputs.
    pub inputs: Vec<Input>,
    /// Transaction outputs.
    pub outputs: Vec<Output>,
    /// Opaque extra blob (the PQC `tx_extra` internal structure is a later slice).
    pub extra: Vec<u8>,
}

impl TxPrefix {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(self.unlock_time, w)?;
        write_varint(self.inputs.len(), w)?;
        for input in &self.inputs {
            input.write(w)?;
        }
        write_varint(self.outputs.len(), w)?;
        for output in &self.outputs {
            output.write(w)?;
        }
        write_varint(self.extra.len(), w)?;
        w.write_all(&self.extra)
    }

    fn read<R: Read>(r: &mut R) -> io::Result<TxPrefix> {
        let unlock_time = read_varint(r)?;

        let n_inputs: usize = read_varint(r)?;
        if n_inputs > READ_LEN_CAP {
            return Err(io::Error::other(format!(
                "shekyl-wire: input count {n_inputs} exceeds parse cap {READ_LEN_CAP}"
            )));
        }
        let mut inputs = Vec::new();
        for _ in 0..n_inputs {
            inputs.push(Input::read(r)?);
        }

        // Outputs are capped at the structural maximum (not the loose `READ_LEN_CAP`):
        // no valid tx exceeds `MAX_OUTPUTS`, and rejecting here bounds the per-output
        // `CtBase` allocation (`enc_amounts`/`enc_labels`/`commitments`) that follows,
        // so a hostile count can't drive ~50 B/output of allocation before `validate`.
        let n_outputs: usize = read_varint(r)?;
        if n_outputs > MAX_OUTPUTS {
            return Err(io::Error::other(format!(
                "shekyl-wire: output count {n_outputs} exceeds {MAX_OUTPUTS}"
            )));
        }
        let mut outputs = Vec::new();
        for _ in 0..n_outputs {
            outputs.push(Output::read(r)?);
        }

        let extra = read_len_prefixed(r, "extra")?;

        Ok(TxPrefix {
            unlock_time,
            inputs,
            outputs,
            extra,
        })
    }

    /// Parse the opaque `extra` blob into structured `tx_extra` fields (§9.6a).
    /// `extra` is kept opaque for round-trip; this is the additive structured view.
    pub fn parse_extra(&self) -> io::Result<Vec<crate::tx_extra::TxExtraField>> {
        crate::tx_extra::parse(&self.extra)
    }
}

/// A Shekyl transaction (version 3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    /// The transaction prefix.
    pub prefix: TxPrefix,
    /// The confidential-transaction section.
    pub ct: Ct,
}

impl Transaction {
    /// Write the transaction.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(TX_VERSION, w)?;
        self.prefix.write(w)?;
        self.ct.write(w)
    }

    /// Read the transaction.
    pub fn read<R: BufRead>(r: &mut R) -> io::Result<Transaction> {
        let version: u64 = read_varint(r)?;
        if version != TX_VERSION {
            return Err(io::Error::other(format!(
                "shekyl-wire: transaction version {version} != {TX_VERSION}"
            )));
        }
        let prefix = TxPrefix::read(r)?;
        let ct = Ct::read(prefix.inputs.len(), prefix.outputs.len(), r)?;
        Ok(Transaction { prefix, ct })
    }

    /// Serialize the transaction to a fresh `Vec<u8>`.
    ///
    /// This is a **faithful** encoding of the in-memory value, not a validity gate:
    /// the I/O is infallible, but a hand-built tx with out-of-range fields (counts
    /// past the parse caps, oversized PQC blobs, a fee-only/spend shape mismatch) can
    /// serialize to bytes [`Self::from_bytes`] would then reject. Call
    /// [`Self::validate`] first when you need a guaranteed-round-trippable blob;
    /// values obtained from `from_bytes` are already in range and always round-trip.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out)
            .expect("writing to a Vec is infallible");
        out
    }

    /// The serialized byte length, measured **without allocating** the blob (writes
    /// into a counting sink). Used for the `MAX_TX_SIZE` bound in [`Self::validate`].
    pub fn serialized_len(&self) -> usize {
        let mut counter = CountingWriter::default();
        self.write(&mut counter)
            .expect("counting write is infallible");
        counter.bytes
    }

    /// Parse a transaction from a complete blob, requiring **exact consumption**
    /// (GENESIS_TX_WIRE_FORMAT.md §12 — trailing bytes are rejected).
    pub fn from_bytes(blob: &[u8]) -> io::Result<Transaction> {
        let mut cursor = blob;
        let tx = Transaction::read(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(io::Error::other(format!(
                "shekyl-wire: {} trailing byte(s) after transaction (§12 exact-consumption)",
                cursor.len()
            )));
        }
        Ok(tx)
    }

    /// The consensus transaction hash (`cn_fast_hash` over component hashes,
    /// GENESIS_TX_WIRE_FORMAT.md §11): **3-part** for the coinbase (`Null`) —
    /// `H(prefix) · H(base) · null_hash`; **4-part** for an FCMP++ spend —
    /// `H(prefix) · H(base) · H(pqc_auths) · H(prunable)`. `H(prefix)` includes
    /// the version varint (the first field of the C++ `transaction_prefix`).
    pub fn hash(&self) -> [u8; 32] {
        let mut prefix_buf = Vec::new();
        write_varint(TX_VERSION, &mut prefix_buf).expect("Vec write is infallible");
        self.prefix
            .write(&mut prefix_buf)
            .expect("Vec write is infallible");
        let h_prefix = cn_fast_hash(&prefix_buf);

        match &self.ct {
            Ct::Null(base) => {
                let mut base_buf = vec![CT_TYPE_NULL];
                base.write(&mut base_buf).expect("Vec write is infallible");
                hash_concat(&[h_prefix, cn_fast_hash(&base_buf), [0u8; 32]])
            }
            Ct::Fcmp {
                fee,
                reference_block,
                base,
                pqc_auths,
                prunable,
            } => {
                let mut base_buf = vec![CT_TYPE_FCMP];
                write_varint(*fee, &mut base_buf).expect("Vec write is infallible");
                base_buf.extend_from_slice(reference_block);
                base.write(&mut base_buf).expect("Vec write is infallible");
                let h_base = cn_fast_hash(&base_buf);

                // Per the C++ oracle (format_utils.cpp:1137/1163-1182): **4-part**
                // `{prefix, base, pqc_auths, prunable}` iff `has_pqc && !pqc_auths
                // .empty()`, where `has_pqc = version>=3 && vin[0] != gen`; otherwise
                // **3-part** `{prefix, base, prunable}`. The prunable component is
                // `H(prunable)` when present, else the null hash (the fee-only /
                // serve-credit form — its live-oracle hash parity is pending a captured
                // blob, as for the spend KAT).
                let h_prunable = match prunable {
                    Some(prunable) => {
                        let mut prunable_buf = Vec::new();
                        prunable
                            .write(&mut prunable_buf)
                            .expect("Vec write is infallible");
                        cn_fast_hash(&prunable_buf)
                    }
                    None => [0u8; 32],
                };

                // `has_pqc` excludes the (malformed) gen-first shape, exactly as the
                // oracle does — so a `gen` input + `Fcmp` ct hashes 3-part like a
                // coinbase rather than misclassifying as a spend.
                let first_is_gen = matches!(self.prefix.inputs.first(), Some(Input::Gen(_)));
                if pqc_auths.is_empty() || first_is_gen {
                    hash_concat(&[h_prefix, h_base, h_prunable])
                } else {
                    // The pqc component mirrors the oracle's generic `std::vector`
                    // serializer (format_utils.cpp:1169), whose `begin_array(cnt)`
                    // writes the element **count as a leading varint** before the
                    // entries — unlike the tx *body*, where the count is implicit
                    // (`vin.size()`, no prefix). Both must match their respective C++
                    // paths; they legitimately differ.
                    let mut auth_buf = Vec::new();
                    write_varint(pqc_auths.len(), &mut auth_buf).expect("Vec write is infallible");
                    for auth in pqc_auths {
                        auth.write(&mut auth_buf).expect("Vec write is infallible");
                    }
                    hash_concat(&[h_prefix, h_base, cn_fast_hash(&auth_buf), h_prunable])
                }
            }
        }
    }

    /// Structural / canonical-form validation (GENESIS_TX_WIRE_FORMAT.md §10 + the
    /// context-free parts of §12): resource bounds, key-image ordering, the
    /// `unlock_time` block-height form, and `nbp == 1`. **Out of scope** (the
    /// consensus layer's job — needs arm-context or chain state): per-arm
    /// `pqc_auths` semantics (§13), coinbase domain rules, CT balance,
    /// double-spend, and the referenceBlock window.
    pub fn validate(&self) -> io::Result<()> {
        if self.prefix.inputs.is_empty() {
            return Err(io::Error::other("shekyl-wire: transaction has no inputs"));
        }
        let n_out = self.prefix.outputs.len();
        // Upper bound is structural; the lower bound is shape-aware (a spend/coinbase
        // has >=1 output, the fee-only serve-credit form has 0) — enforced per-ct below.
        if n_out > MAX_OUTPUTS {
            return Err(io::Error::other(format!(
                "shekyl-wire: output count {n_out} exceeds {MAX_OUTPUTS}"
            )));
        }
        // §2.5 coinbase shape: a `gen` input is coinbase-only and must be the sole
        // input. Reject `gen` mixed with any other input — otherwise a tx like
        // `[Gen, ToKey, …]` would be misclassified as coinbase and skip the
        // non-coinbase tx_extra cap below.
        let gen_count = self
            .prefix
            .inputs
            .iter()
            .filter(|input| matches!(input, Input::Gen(_)))
            .count();
        if gen_count > 0 && self.prefix.inputs.len() != 1 {
            return Err(io::Error::other(
                "shekyl-wire: gen input must be the sole input (coinbase shape, §2.5)",
            ));
        }
        let is_coinbase = gen_count == 1;
        // §2.5 Serve-credit shape (settled): a `serve_credit` is non-spending and is
        // the *entire* tx — a sole serve_credit input, no outputs, and a fee-only
        // `Fcmp` ct (empty pqc_auths, no prunable). The settled mixing table has no row
        // combining serve_credit with any other arm, so reject every mixed form here.
        // (Without this, a serve_credit beside a spend slips through the spend branch's
        // intentionally-lenient pseudoOuts coupling below.)
        if self
            .prefix
            .inputs
            .iter()
            .any(|input| matches!(input, Input::ServeCredit(_)))
        {
            let is_serve_credit_shape =
                matches!(self.prefix.inputs.as_slice(), [Input::ServeCredit(_)])
                    && self.prefix.outputs.is_empty()
                    && matches!(
                        &self.ct,
                        Ct::Fcmp { pqc_auths, prunable, .. }
                            if pqc_auths.is_empty() && prunable.is_none()
                    );
            if !is_serve_credit_shape {
                return Err(io::Error::other(
                    "shekyl-wire: a serve_credit input requires the fee-only Serve-credit \
                     shape — a sole non-spending input, no outputs, empty pqc_auths, no \
                     prunable (§2.5); it does not mix with any other arm",
                ));
            }
        }
        // tx_extra bound (the coinbase extra is unbounded in C++; cap non-coinbase).
        if !is_coinbase && self.prefix.extra.len() > MAX_TX_EXTRA {
            return Err(io::Error::other(format!(
                "shekyl-wire: tx_extra {} exceeds {MAX_TX_EXTRA}",
                self.prefix.extra.len()
            )));
        }
        let size = self.serialized_len();
        if size > MAX_TX_SIZE {
            return Err(io::Error::other(format!(
                "shekyl-wire: tx size {size} exceeds {MAX_TX_SIZE}"
            )));
        }
        if self.prefix.unlock_time >= UNLOCK_TIME_BLOCK_SENTINEL {
            return Err(io::Error::other(format!(
                "shekyl-wire: unlock_time {} is the timestamp form (block-height only)",
                self.prefix.unlock_time
            )));
        }
        // §12: key-image-bearing inputs strictly ascending — rejects both unsorted
        // and in-tx duplicate key images. Also enforces the fcmp input cap.
        let key_images: Vec<&[u8; 32]> = self
            .prefix
            .inputs
            .iter()
            .filter_map(|input| match input {
                Input::ToKey { key_image, .. } => Some(key_image),
                _ => None,
            })
            .collect();
        if key_images.len() > MAX_FCMP_INPUTS {
            return Err(io::Error::other(format!(
                "shekyl-wire: {} fcmp inputs exceed {MAX_FCMP_INPUTS}",
                key_images.len()
            )));
        }
        for pair in key_images.windows(2) {
            if pair[0] >= pair[1] {
                return Err(io::Error::other(
                    "shekyl-wire: key images not strictly ascending (§12)",
                ));
            }
        }
        // Per-arm in-memory bound checks for the archival inputs — the consensus caps
        // that `read` enforces inline (path layers, branch scalars, hybrid blobs,
        // holdings shard count, the JoinMarket-tag coupling). Without these a hand-built
        // arm could pass `validate` yet serialize to bytes `from_bytes` rejects.
        for input in &self.prefix.inputs {
            match input {
                Input::ServeCredit(sc) => sc.validate()?,
                Input::BondPost(bp) => bp.validate()?,
                _ => {}
            }
        }
        // Structural length-coupling: these vectors carry no independent length prefix
        // on the wire — their counts are tied to vin/vout — so an in-memory tx with
        // mismatched lengths would not round-trip and would be consensus-invalid.
        // Shape-aware per §2.5 (full spend / bond-post / fee-only-serve-credit).
        let n_in = self.prefix.inputs.len();
        let n_ki = key_images.len(); // key-image (spend) inputs
        let base = match &self.ct {
            Ct::Null(base) => {
                // §2.5: a `Null` ct carries no proof material and is **coinbase-only**;
                // a non-coinbase tx must be `Fcmp`. Without this, a tx with `ToKey`
                // (spend) inputs + a `Null` ct would pass structural validation while
                // being consensus-invalid.
                if !is_coinbase {
                    return Err(io::Error::other(
                        "shekyl-wire: Null ct is coinbase-only; a non-coinbase tx must be Fcmp (§2.5)",
                    ));
                }
                if n_out == 0 {
                    return Err(io::Error::other("shekyl-wire: coinbase has no outputs"));
                }
                base
            }
            Ct::Fcmp {
                base,
                pqc_auths,
                prunable,
                ..
            } => {
                // §2.5: the coinbase is `Null`-only — an `Fcmp` ct on a coinbase (a
                // `gen` input) is the dual of the check above.
                if is_coinbase {
                    return Err(io::Error::other(
                        "shekyl-wire: coinbase must carry a Null ct, not Fcmp (§2.5)",
                    ));
                }
                // Per-auth blob bounds — consensus accept-parity with the C++
                // deserialization caps (`PqcAuth::read` rejects oversized blobs on the
                // wire; `PqcAuth::write` is faithful, so `validate` is the in-memory
                // gate that keeps a constructed tx from later failing parse). Empty for
                // the fee-only form, so this is a no-op there.
                for auth in pqc_auths {
                    if auth.hybrid_public_key.len() > PQC_MAX_PUBLIC_KEY_BLOB {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: pqc_auth public key {} exceeds {PQC_MAX_PUBLIC_KEY_BLOB}",
                            auth.hybrid_public_key.len()
                        )));
                    }
                    if auth.hybrid_signature.len() > PQC_MAX_SIGNATURE_BLOB {
                        return Err(io::Error::other(format!(
                            "shekyl-wire: pqc_auth signature {} exceeds {PQC_MAX_SIGNATURE_BLOB}",
                            auth.hybrid_signature.len()
                        )));
                    }
                }
                match prunable {
                    // Spend / bond-post: a prunable proof is present.
                    Some(prunable) => {
                        if n_out == 0 {
                            return Err(io::Error::other("shekyl-wire: spend has no outputs"));
                        }
                        // pqc_auths are per-input (count == nvin): one slot per input,
                        // including the bond_post slot (§2.5 / §13).
                        if pqc_auths.len() != n_in {
                            return Err(io::Error::other(format!(
                                "shekyl-wire: pqc_auths {} != input count {n_in}",
                                pqc_auths.len()
                            )));
                        }
                        // §10: exactly one aggregated Bp+.
                        if prunable.bulletproofs.len() != 1 {
                            return Err(io::Error::other(format!(
                                "shekyl-wire: nbp {} != 1",
                                prunable.bulletproofs.len()
                            )));
                        }
                        // pseudoOuts are per key-image (spend) input. For an all-fcmp
                        // spend that is exactly nvin; for a mixed bond-post tx the exact
                        // spend-subset coupling is a §13 (F1/F3) forward obligation
                        // owned by the emission / membership-only PRs, so it is bounded
                        // here (<= the spend subset), not pinned.
                        if n_ki == n_in {
                            if prunable.pseudo_outs.len() != n_ki {
                                return Err(io::Error::other(format!(
                                    "shekyl-wire: pseudoOuts {} != spend input count {n_ki}",
                                    prunable.pseudo_outs.len()
                                )));
                            }
                        } else if prunable.pseudo_outs.len() > n_ki {
                            return Err(io::Error::other(format!(
                                "shekyl-wire: pseudoOuts {} exceed spend input count {n_ki}",
                                prunable.pseudo_outs.len()
                            )));
                        }
                    }
                    // Fee-only / serve-credit: no prunable proof, no outputs, and
                    // pqc_auths empty (the hybrid signature rides the vin, §9.10).
                    None => {
                        if n_out != 0 {
                            return Err(io::Error::other(format!(
                                "shekyl-wire: fee-only ct (no prunable) must have no \
                                 outputs, found {n_out}"
                            )));
                        }
                        if !pqc_auths.is_empty() {
                            return Err(io::Error::other(format!(
                                "shekyl-wire: fee-only ct (no prunable) must carry empty \
                                 pqc_auths, found {}",
                                pqc_auths.len()
                            )));
                        }
                        // No prunable proof ⇒ no key-image (spend) inputs: a spend
                        // requires a prunable. (The storage-pruned full-spend form —
                        // ki inputs, prunable dropped, external prunable hash — is
                        // post-genesis, handled by §4 `into_full`, not the wire parser.)
                        if n_ki != 0 {
                            return Err(io::Error::other(format!(
                                "shekyl-wire: {n_ki} key-image input(s) but no prunable proof"
                            )));
                        }
                    }
                }
                base
            }
        };
        // The committed base arrays are per-output (count == nvout).
        if base.enc_amounts.len() != n_out
            || base.enc_labels.len() != n_out
            || base.commitments.len() != n_out
        {
            return Err(io::Error::other(format!(
                "shekyl-wire: ct base arrays (enc_amounts={}, enc_labels={}, \
                 commitments={}) must each equal output count {n_out}",
                base.enc_amounts.len(),
                base.enc_labels.len(),
                base.commitments.len()
            )));
        }
        Ok(())
    }
}
