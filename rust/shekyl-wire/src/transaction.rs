//! The Shekyl transaction (genesis `version = 3`) — coinbase-shaped slice.
//!
//! Layout (GENESIS_TX_WIRE_FORMAT.md §9.3-§9.7):
//!
//! ```text
//! Transaction := V(version=3) TxPrefix Ct
//! TxPrefix    := V(unlock_time) vec(Input) vec(Output) V(extra_len) extra[extra_len]
//! Input(gen)  := 0xff V(height)
//! Output      := V(amount) 0x03 key[32] view_tag(1)        # tagged_key
//! Ct(Null)    := 0x00 enc_amounts[nout×9] enc_labels[nout×9] outPk[nout×32]
//! ```
//!
//! Spend (`Fcmp`) inputs/ct, the archival arms, and the dense tag renumber are
//! later slices; see the crate docs.

use std::io::{self, Read, Write};

use crate::bytes::{read_array, read_byte};
use crate::varint::{read_varint, write_varint};

/// Genesis transaction version (kept deliberately; `V4` = future lattice-only).
pub const TX_VERSION: u64 = 3;

/// `txin_gen` tag — coinbase generation input (current C++ value).
pub const TAG_INPUT_GEN: u8 = 0xff;
/// `txout_to_tagged_key` tag — the sole genesis output type (current C++ value).
pub const TAG_OUTPUT_TAGGED_KEY: u8 = 0x03;
/// `Null` confidential-transaction type — the coinbase ct (carries a committed base).
pub const CT_TYPE_NULL: u8 = 0x00;

/// Parse-safety bound on `extra` length: the length prefix drives an allocation,
/// so it is capped before reading. Coincides with `CRYPTONOTE_MAX_TX_SIZE` (§10);
/// the full consensus bounds are enforced in the validation slice.
const READ_EXTRA_CAP: usize = 1_000_000;

/// A transaction input.
///
/// This slice models only the coinbase `gen` input; the `fcmp` spend and the
/// archival arms land in later slices (the enum stays open for them).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
    /// Coinbase generation input: the block height.
    Gen(u64),
}

impl Input {
    /// Write the input.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            Input::Gen(height) => {
                w.write_all(&[TAG_INPUT_GEN])?;
                write_varint(*height, w)
            }
        }
    }

    /// Read an input.
    pub fn read<R: Read>(r: &mut R) -> io::Result<Input> {
        let tag = read_byte(r)?;
        match tag {
            TAG_INPUT_GEN => Ok(Input::Gen(read_varint(r)?)),
            other => Err(io::Error::other(format!(
                "shekyl-wire: unsupported input tag {other:#04x} (coinbase slice handles gen only)"
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
/// Present even for the coinbase `Null` type — the C++ `serialize_rctsig_base`
/// writes `enc_amounts` / `enc_labels` / `outPk` for `RCTTypeNull` so every
/// output gets a tree-leaf commitment (rctTypes.h:209-280). This is the field the
/// pre-fix `shekyl-oxide` reader skipped (it returned `None` on the `Null` type
/// byte), causing `Block::read` to mis-align and fail `UnexpectedEof`.
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
        let mut commitments = Vec::new();
        for _ in 0..outputs {
            enc_amounts.push(read_array::<9, _>(r)?);
        }
        for _ in 0..outputs {
            enc_labels.push(read_array::<9, _>(r)?);
        }
        for _ in 0..outputs {
            commitments.push(read_array::<32, _>(r)?);
        }
        Ok(CtBase {
            enc_amounts,
            enc_labels,
            commitments,
        })
    }
}

/// The confidential-transaction section.
///
/// This slice models the coinbase `Null` type only; the `Fcmp` spend section
/// (fee, referenceBlock, pqc_auths, prunable) lands in a later slice.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Ct {
    /// Coinbase confidential section: committed base only.
    Null(CtBase),
}

impl Ct {
    /// Write the ct section.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            Ct::Null(base) => {
                w.write_all(&[CT_TYPE_NULL])?;
                base.write(w)
            }
        }
    }

    /// Read the ct section. `outputs` (the vout count) sizes the base arrays.
    pub fn read<R: Read>(outputs: usize, r: &mut R) -> io::Result<Ct> {
        let ct_type = read_byte(r)?;
        match ct_type {
            CT_TYPE_NULL => Ok(Ct::Null(CtBase::read(outputs, r)?)),
            other => Err(io::Error::other(format!(
                "shekyl-wire: unsupported ct type {other:#04x} (coinbase slice handles Null only)"
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

        let extra_len: usize = read_varint(r)?;
        if extra_len > READ_EXTRA_CAP {
            return Err(io::Error::other(format!(
                "shekyl-wire: extra_len {extra_len} exceeds parse cap {READ_EXTRA_CAP}"
            )));
        }
        let mut extra = vec![0u8; extra_len];
        r.read_exact(&mut extra)?;

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
        let ct = Ct::read(prefix.outputs.len(), r)?;
        Ok(Transaction { prefix, ct })
    }
}
