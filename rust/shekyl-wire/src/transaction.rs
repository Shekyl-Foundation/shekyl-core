// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Shekyl transaction (genesis `version = 3`) — coinbase + FCMP++ spend.
//!
//! Layout (GENESIS_TX_WIRE_FORMAT.md §9.3-§9.9), in the **current C++ tag values**
//! (the dense renumber is a later gate-(c) cut):
//!
//! ```text
//! Transaction := V(version=3) TxPrefix Ct
//! TxPrefix    := V(unlock_time) vec(Input) vec(Output) V(extra_len) extra[extra_len]
//! Input(gen)  := 0xff V(height)
//! Input(spend):= 0x02 V(amount) vec(V key_offset) key_image[32]      # txin_to_key
//! Output      := V(amount) 0x03 key[32] view_tag(1)                  # tagged_key
//! Ct(Null)    := 0x00 enc_amounts[nout×9] enc_labels[nout×9] outPk[nout×32]   # coinbase
//! Ct(Fcmp)    := 0x07 V(fee) referenceBlock[32]
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

use crate::bytes::{read_array, read_byte};
use crate::varint::{read_varint, write_varint};

/// Genesis transaction version (kept deliberately; `V4` = future lattice-only).
pub const TX_VERSION: u64 = 3;

/// `txin_gen` tag — coinbase generation input (current C++ value).
pub const TAG_INPUT_GEN: u8 = 0xff;
/// `txin_to_key` tag — the FCMP++ spend input (current C++ value; the dense
/// `txin_fcmp` reshape is a later gate-(c) cut).
pub const TAG_INPUT_TO_KEY: u8 = 0x02;
/// `txout_to_tagged_key` tag — the sole genesis output type (current C++ value).
pub const TAG_OUTPUT_TAGGED_KEY: u8 = 0x03;
/// `Null` confidential-transaction type — the coinbase ct (carries a committed base).
pub const CT_TYPE_NULL: u8 = 0x00;
/// `FcmpPlusPlusPqc` confidential-transaction type — the spend ct (current C++ value).
pub const CT_TYPE_FCMP: u8 = 0x07;

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

/// A transaction input.
///
/// Genesis arms modelled here: the coinbase `gen` input and the FCMP++ spend
/// (`txin_to_key`). The archival arms (`serve_credit`, `bond_post`) and the
/// deferred emission/membership-only arms land in later slices.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
    /// Coinbase generation input: the block height.
    Gen(u64),
    /// FCMP++ spend input (`txin_to_key`, tag 0x02). At genesis `amount == 0` and
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
            other => Err(io::Error::other(format!(
                "shekyl-wire: unsupported input tag {other:#04x}"
            ))),
        }
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
    /// FCMP++ spend confidential section (type 0x07).
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

        let n_inputs: usize = read_varint(r)?;
        let mut inputs = Vec::new();
        for _ in 0..n_inputs {
            inputs.push(Input::read(r)?);
        }

        let n_outputs: usize = read_varint(r)?;
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
}
