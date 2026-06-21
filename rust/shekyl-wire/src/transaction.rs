// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Shekyl transaction (genesis `version = 3`) — coinbase + FCMP++ spend.
//!
//! Layout (GENESIS_TX_WIRE_FORMAT.md §9.3-§9.9), in the **genesis dense tag
//! scheme** (the gate-(c) renumber — these match the renumbered C++ oracle
//! `VARIANT_TAG`s and the ct enum, and the constants below):
//!
//! ```text
//! Transaction := V(version=3) TxPrefix Ct
//! TxPrefix    := V(unlock_time) vec(Input) vec(Output) V(extra_len) extra[extra_len]
//! Input(gen)  := 0x00 V(height)                                     # txin_gen
//! Input(spend):= 0x01 V(amount) vec(V key_offset) key_image[32]     # txin_to_key
//! Output      := V(amount) 0x00 key[32] view_tag(1)                 # tagged_key
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

use std::io::{self, Read, Write};

use shekyl_crypto_hash::cn_fast_hash;

use crate::bytes::{read_array, read_byte};
use crate::hash::hash_concat;
use crate::varint::{read_varint, write_varint};

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

/// Parse-safety bound on length-prefixed reads: a declared length drives an
/// allocation, so it is capped before reading. Coincides with
/// `CRYPTONOTE_MAX_TX_SIZE`; the full consensus bounds are the validation slice.
const READ_LEN_CAP: usize = 1_000_000;

/// Read a varint-length-prefixed opaque byte blob, capped against `READ_LEN_CAP`.
fn read_len_prefixed<R: Read>(r: &mut R, what: &str) -> io::Result<Vec<u8>> {
    let len: usize = read_varint(r)?;
    if len > READ_LEN_CAP {
        return Err(io::Error::other(format!(
            "shekyl-wire: {what} length {len} exceeds parse cap {READ_LEN_CAP}"
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read `count` fixed 32-byte points (no per-element length prefix).
fn read_points<R: Read>(r: &mut R, count: usize) -> io::Result<Vec<[u8; 32]>> {
    let mut v = Vec::new();
    for _ in 0..count {
        v.push(read_array::<32, _>(r)?);
    }
    Ok(v)
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
/// All four genesis arms are modelled: the coinbase `gen` input, the FCMP++
/// spend (`txin_to_key`), and the archival `serve_credit` / `bond_post` arms.
/// Tag bytes are the genesis dense scheme (the `TAG_INPUT_*` constants above).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
    /// Coinbase generation input (`txin_gen`, tag 0x00): the block height.
    Gen(u64),
    /// FCMP++ spend input (`txin_to_key`, tag 0x01). At genesis `amount == 0` and
    /// `key_offsets` is empty (membership is via the curve tree, not a ring), but
    /// the current C++ wire still serializes both — round-tripped faithfully.
    ToKey {
        /// Cleartext amount (`0` for FCMP++).
        amount: u64,
        /// Ring offsets (empty for FCMP++).
        key_offsets: Vec<u64>,
        /// Key image (linking tag / nullifier).
        key_image: [u8; 32],
    },
    /// Archival serve-credit response (`tag 0x02`, gate-2) — non-spending.
    ServeCredit(Box<ServeCredit>),
    /// Archival bond-post (`tag 0x03`, gate-4) — JoinMarket-only at genesis.
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
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Holdings {
    /// Holdings kind byte (`HOLDINGS_SHARD_SET_COMPACT` or `HOLDINGS_COMPLETE_TREE`).
    pub kind: u8,
    /// Shard ids (present only for `ShardSetCompact`; empty for `CompleteTree`).
    pub shard_ids: Vec<u64>,
}

impl Holdings {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&[self.kind])?;
        if self.kind == HOLDINGS_SHARD_SET_COMPACT {
            write_varint(self.shard_ids.len(), w)?;
            for shard in &self.shard_ids {
                write_varint(*shard, w)?;
            }
        }
        Ok(())
    }

    fn read<R: Read>(r: &mut R) -> io::Result<Holdings> {
        let kind = read_byte(r)?;
        if kind != HOLDINGS_SHARD_SET_COMPACT && kind != HOLDINGS_COMPLETE_TREE {
            return Err(io::Error::other(format!(
                "shekyl-wire: invalid holdings kind {kind}"
            )));
        }
        let shard_ids = if kind == HOLDINGS_SHARD_SET_COMPACT {
            let count: usize = read_varint(r)?;
            if count > MAX_HOLDINGS_SHARDS {
                return Err(io::Error::other(format!(
                    "shekyl-wire: holdings shard count {count} exceeds {MAX_HOLDINGS_SHARDS}"
                )));
            }
            let mut ids = Vec::new();
            for _ in 0..count {
                ids.push(read_varint(r)?);
            }
            ids
        } else {
            Vec::new()
        };
        Ok(Holdings { kind, shard_ids })
    }
}

/// Archival serve-credit response payload (`tag 0x04`, gate-2 §5.1.1).
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
        let hybrid_signature = read_len_prefixed(r, "serve_credit hybrid_signature")?;
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
}

/// Archival bond-post payload (`tag 0x05`, gate-4 §3.4.1). JoinMarket-only at
/// genesis. Includes **`bond_spend_pk`** (the GF-1 debit authorizer, §9.11),
/// present on the wire iff `post_kind == JOINMARKET` — which the current
/// `shekyl-archival-retention::bond_wire` omits and the impl must add.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BondPost {
    /// `P`'s canonical hybrid public key.
    pub hybrid_public_key: Vec<u8>,
    /// `P`'s canonical id.
    pub p_canonical_id: [u8; 32],
    /// Post kind byte (`BOND_POST_KIND_JOINMARKET` at genesis).
    pub post_kind: u8,
    /// GF-1 debit authorizer; `Some` iff `post_kind == JOINMARKET`.
    pub bond_spend_pk: Option<Vec<u8>>,
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
        w.write_all(&[self.post_kind])?;
        if self.post_kind == BOND_POST_KIND_JOINMARKET {
            let bspk = self.bond_spend_pk.as_deref().ok_or_else(|| {
                io::Error::other("shekyl-wire: JoinMarket bond_post requires bond_spend_pk")
            })?;
            write_varint(bspk.len(), w)?;
            w.write_all(bspk)?;
        }
        self.holdings.write(w)?;
        write_varint(self.bonded_total_atomic, w)?;
        write_varint(self.bond_credit, w)?;
        write_varint(self.bond_debit, w)
    }

    fn read<R: Read>(r: &mut R) -> io::Result<BondPost> {
        let hybrid_public_key = read_len_prefixed(r, "bond_post hybrid_public_key")?;
        let p_canonical_id = read_array(r)?;
        let post_kind = read_byte(r)?;
        let bond_spend_pk = if post_kind == BOND_POST_KIND_JOINMARKET {
            Some(read_len_prefixed(r, "bond_spend_pk")?)
        } else {
            None
        };
        let holdings = Holdings::read(r)?;
        Ok(BondPost {
            hybrid_public_key,
            p_canonical_id,
            post_kind,
            bond_spend_pk,
            holdings,
            bonded_total_atomic: read_varint(r)?,
            bond_credit: read_varint(r)?,
            bond_debit: read_varint(r)?,
        })
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
        let hybrid_public_key = read_len_prefixed(r, "pqc hybrid_public_key")?;
        let hybrid_signature = read_len_prefixed(r, "pqc hybrid_signature")?;
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
    /// FCMP++ spend confidential section (type 0x01).
    Fcmp {
        /// Transaction fee.
        fee: u64,
        /// Block hash anchoring the curve-tree root the proof is against.
        reference_block: [u8; 32],
        /// Committed base arrays (per output).
        base: CtBase,
        /// Per-input PQC authentication (count == `nvin`, no length prefix).
        pqc_auths: Vec<PqcAuth>,
        /// Prunable proof data.
        prunable: Prunable,
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
                // tx-level pqc_auths: count == nvin, no length prefix.
                for auth in pqc_auths {
                    auth.write(w)?;
                }
                prunable.write(w)
            }
        }
    }

    /// Read the ct section. `inputs`/`outputs` (the vin/vout counts) size the
    /// per-input/per-output arrays that carry no length prefix.
    pub fn read<R: Read>(inputs: usize, outputs: usize, r: &mut R) -> io::Result<Ct> {
        let ct_type = read_byte(r)?;
        match ct_type {
            CT_TYPE_NULL => Ok(Ct::Null(CtBase::read(outputs, r)?)),
            CT_TYPE_FCMP => {
                let fee = read_varint(r)?;
                let reference_block = read_array(r)?;
                let base = CtBase::read(outputs, r)?;
                let mut pqc_auths = Vec::new();
                for _ in 0..inputs {
                    pqc_auths.push(PqcAuth::read(r)?);
                }
                let prunable = Prunable::read(inputs, r)?;
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

        // Parse-time DoS guard: a declared count drives per-element reads, so it
        // is bounded before the loop (the `read_len_prefixed` / `key_offsets`
        // pattern). This is the loose parse-safety cap; the tight consensus
        // structural maxima (`MAX_FCMP_INPUTS` / `MAX_OUTPUTS`) — which depend on
        // the tx type read *after* the prefix — are enforced in `validate()`.
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

        let n_outputs: usize = read_varint(r)?;
        if n_outputs > READ_LEN_CAP {
            return Err(io::Error::other(format!(
                "shekyl-wire: output count {n_outputs} exceeds parse cap {READ_LEN_CAP}"
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
    pub fn read<R: Read>(r: &mut R) -> io::Result<Transaction> {
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
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out)
            .expect("writing to a Vec is infallible");
        out
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

                let mut auth_buf = Vec::new();
                for auth in pqc_auths {
                    auth.write(&mut auth_buf).expect("Vec write is infallible");
                }

                let mut prunable_buf = Vec::new();
                prunable
                    .write(&mut prunable_buf)
                    .expect("Vec write is infallible");

                hash_concat(&[
                    h_prefix,
                    cn_fast_hash(&base_buf),
                    cn_fast_hash(&auth_buf),
                    cn_fast_hash(&prunable_buf),
                ])
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
        if n_out == 0 || n_out > MAX_OUTPUTS {
            return Err(io::Error::other(format!(
                "shekyl-wire: output count {n_out} not in 1..={MAX_OUTPUTS}"
            )));
        }
        // tx_extra bound (the coinbase extra is unbounded in C++; cap non-coinbase).
        // A genuine coinbase is *exactly one* `gen` input; matching only the first
        // input would let a spend tx prepend a `gen` to dodge the cap.
        let is_coinbase = self.prefix.inputs.len() == 1
            && matches!(self.prefix.inputs.first(), Some(Input::Gen(_)));
        if !is_coinbase && self.prefix.extra.len() > MAX_TX_EXTRA {
            return Err(io::Error::other(format!(
                "shekyl-wire: tx_extra {} exceeds {MAX_TX_EXTRA}",
                self.prefix.extra.len()
            )));
        }
        let size = self.serialize().len();
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
        // §10: exactly one Bp+ for an Fcmp spend.
        if let Ct::Fcmp { prunable, .. } = &self.ct {
            if prunable.bulletproofs.len() != 1 {
                return Err(io::Error::other(format!(
                    "shekyl-wire: nbp {} != 1",
                    prunable.bulletproofs.len()
                )));
            }
        }
        Ok(())
    }
}
