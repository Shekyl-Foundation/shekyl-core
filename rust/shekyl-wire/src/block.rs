// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Shekyl block and block header.
//!
//! Layout (GENESIS_TX_WIRE_FORMAT.md §9.1-§9.2):
//!
//! ```text
//! Block       := BlockHeader Transaction(miner) V(n_tx) n_tx×Hash[32]
//! BlockHeader := V(major) V(minor) V(timestamp) prev[32] nonce(u32 LE) curve_tree_root[32] attestation_root[32]
//! ```
//!
//! The miner transaction is embedded inline; `n_tx` counts the *other*
//! transactions, carried as 32-byte hashes (a coinbase-only block has `n_tx = 0`).

use std::io::{self, BufRead, Read, Write};

use shekyl_crypto_hash::keccak256;

use shekyl_types::{AttestationRoot, BlockHash, CurveTreeRoot, TxHash, TxTreeHash};

use crate::bytes::read_array;
use crate::hash::merkle_root;
use crate::transaction::{Ct, Input, Transaction, MAX_TX_SIZE};
use crate::varint::{read_varint, write_varint};
use crate::READ_LEN_CAP;

/// Defense-in-depth upper bound on a serialized block blob, mirroring
/// [`MAX_TX_SIZE`]'s role for a transaction.
///
/// A block blob is the header + the embedded coinbase + the non-miner
/// transaction-*hash* list (the full non-miner txs are fetched separately, as
/// their own blobs), so its largest parseable form is the sum of what
/// [`Block::read`]'s caps already accept:
///
/// * header — fixed fields with varint slack ([`MAX_BLOCK_HEADER_SIZE`]);
/// * the coinbase [`Transaction`] — `≤ MAX_TX_SIZE` (a vast over-estimate: a
///   coinbase is one `gen` input, `≤ MAX_OUTPUTS` outputs, an extra the
///   coinbase grammar fixes at `1184·n` bytes of payload plus the pubkey,
///   nonce and draw-commitment fields for `n` outputs (19 027 at `n = 16`) —
///   `MAX_TX_EXTRA` is the *non-coinbase* relay cap and does not apply to a
///   coinbase, CEN-M4 — and a `Null` base, i.e. tens of KiB; `MAX_TX_SIZE`
///   is the simplest safe ceiling and `Block::read` does not separately
///   bound it);
/// * the `n_tx` varint + `n_tx × 32`-byte hashes — `≤ READ_LEN_CAP × 32`.
///
/// Because the sum is `≥` the largest blob `Block::read` can accept, the guard
/// never rejects a parseable block; it only stops an unbounded pre-allocation
/// from a hostile/oversized blob *before* the structured count-caps run (the
/// same role the up-front `MAX_TX_SIZE` check plays in
/// [`Transaction::from_bytes`]). It is a DoS bound, **not** a consensus bound.
pub const MAX_BLOCK_BLOB_SIZE: usize = MAX_TX_SIZE + READ_LEN_CAP * 32 + MAX_BLOCK_HEADER_SIZE;

/// The largest serialized [`BlockHeader`]: its fixed fields with varint
/// slack. The header part of [`MAX_BLOCK_BLOB_SIZE`], and of the ingest
/// door's size bound before parse (`shekyl_chain_ingest::admission`).
pub const MAX_BLOCK_HEADER_SIZE: usize = 128;

/// The value every valid header's `minor_version` carries (CEN-B2).
///
/// The byte was Monero's hard-fork vote. Shekyl has no vote, so the byte
/// means nothing, and a byte that means nothing and may hold anything is a
/// channel the block's producer controls. It is reserved
/// at zero, which is what genesis carries. The parser reads any value; the
/// consensus validator refuses every one but this.
pub const HEADER_MINOR_VERSION: u8 = 0;

/// A Shekyl block header.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockHeader {
    /// Block version; `1` (CEN-B1).
    pub major_version: u8,
    /// Reserved; [`HEADER_MINOR_VERSION`] on every valid block (CEN-B2).
    pub minor_version: u8,
    /// Seconds since the epoch.
    pub timestamp: u64,
    /// The previous block's hash (CEN-A2 compares it to the tip's).
    pub previous: BlockHash,
    /// The PoW nonce.
    pub nonce: u32,
    /// The FCMP++ curve-tree root **at this block's own height**: the tree
    /// grown with every leaf that matured through the parent, before any of
    /// this block's outputs (CEN-B5, wording corrected 2026-09-05). The root
    /// *after* this block is the next header's.
    pub curve_tree_root: CurveTreeRoot,
    /// The archival credit-wire attestation root over this block's pass records
    /// (`ARCHIVAL_CREDIT_WIRE.md` §3). A `block_header` field alongside
    /// `curve_tree_root`, mined via the header being the PoW preimage.
    pub attestation_root: AttestationRoot,
}

impl BlockHeader {
    /// Write the header.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(self.major_version, w)?;
        write_varint(self.minor_version, w)?;
        write_varint(self.timestamp, w)?;
        w.write_all(self.previous.as_bytes())?;
        w.write_all(&self.nonce.to_le_bytes())?;
        w.write_all(self.curve_tree_root.as_bytes())?;
        w.write_all(self.attestation_root.as_bytes())
    }

    /// Where [`nonce`](Self::nonce)'s four little-endian bytes sit in
    /// [`write`](Self::write)'s output — after the three varints and
    /// `previous` — and so in [`Block::pow_blob`], which begins with the
    /// header. A miner writes each attempt's nonce there instead of
    /// re-serializing the header and re-hashing the transaction tree. The
    /// offset depends on the varints' lengths, so it is this header's, not
    /// a constant.
    #[must_use]
    pub fn nonce_offset(&self) -> usize {
        let mut prefix = Vec::with_capacity(32);
        write_varint(self.major_version, &mut prefix).expect("Vec write is infallible");
        write_varint(self.minor_version, &mut prefix).expect("Vec write is infallible");
        write_varint(self.timestamp, &mut prefix).expect("Vec write is infallible");
        prefix.len() + self.previous.as_bytes().len()
    }

    /// Read the header.
    pub fn read<R: Read>(r: &mut R) -> io::Result<BlockHeader> {
        Ok(BlockHeader {
            major_version: read_varint(r)?,
            minor_version: read_varint(r)?,
            timestamp: read_varint(r)?,
            previous: BlockHash::from_bytes(read_array(r)?),
            nonce: u32::from_le_bytes(read_array::<4, _>(r)?),
            curve_tree_root: CurveTreeRoot::from_bytes(read_array(r)?),
            attestation_root: AttestationRoot::from_bytes(read_array(r)?),
        })
    }
}

/// A Shekyl block.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    /// The block header.
    pub header: BlockHeader,
    /// The miner (coinbase) transaction, embedded inline.
    pub miner_transaction: Transaction,
    /// Hashes of the block's non-miner transactions.
    pub transaction_hashes: Vec<TxHash>,
}

impl Block {
    /// Write the block.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.header.write(w)?;
        self.miner_transaction.write(w)?;
        write_varint(self.transaction_hashes.len(), w)?;
        for hash in &self.transaction_hashes {
            w.write_all(hash.as_bytes())?;
        }
        Ok(())
    }

    /// Serialize the block to a fresh `Vec<u8>`.
    ///
    /// A faithful encoding of the in-memory value, not a validity gate: a block whose
    /// miner tx is not coinbase-shaped serializes fine but [`Self::from_bytes`] would
    /// reject it (the embedded-tx read requires a `Null` coinbase). A block read via
    /// `from_bytes` always round-trips.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out)
            .expect("writing to a Vec is infallible");
        out
    }

    /// Read a block from a reader.
    ///
    /// Use [`Block::from_bytes`] for the common case of a complete in-memory
    /// blob, which additionally enforces exact consumption (§12).
    pub fn read<R: BufRead>(r: &mut R) -> io::Result<Block> {
        let header = BlockHeader::read(r)?;
        let miner_transaction = Transaction::read(r)?;
        // The miner tx is the coinbase (§2.5): a sole `gen` input and a `Null` ct.
        // Enforce it here because the embedded read must be unambiguous —
        // `Ct::read` discriminates the fee-only / full FCMP++ shapes by end-of-input,
        // which is only meaningful for a *terminal* field. A `Null` coinbase has no
        // EOF-tolerant tail, so embedding it before the `n_tx`/hash array is
        // well-defined; an embedded `Fcmp` tx would instead consume the trailing block
        // bytes as `pqc_auths`/`prunable`. Rejecting a non-coinbase miner tx closes
        // that mis-parse and keeps `number()`/`pow_blob()`'s coinbase assumption sound.
        if !matches!(miner_transaction.prefix.inputs.as_slice(), [Input::Gen(_)]) {
            return Err(io::Error::other(
                "shekyl-wire: block miner tx must have a sole gen input (coinbase, §2.5)",
            ));
        }
        if !matches!(miner_transaction.ct, Ct::Null(_)) {
            return Err(io::Error::other(
                "shekyl-wire: block miner tx must carry a Null ct (coinbase, §2.5)",
            ));
        }

        let n_tx: usize = read_varint(r)?;
        if n_tx > READ_LEN_CAP {
            return Err(io::Error::other(format!(
                "shekyl-wire: transaction-hash count {n_tx} exceeds parse cap {READ_LEN_CAP}"
            )));
        }
        // No pre-allocation against `n_tx`: push from empty so an oversized count
        // against a finite reader fails on the missing bytes, not on allocation.
        let mut transaction_hashes = Vec::new();
        for _ in 0..n_tx {
            transaction_hashes.push(TxHash::from_bytes(read_array::<32, _>(r)?));
        }

        Ok(Block {
            header,
            miner_transaction,
            transaction_hashes,
        })
    }

    /// Parse a block from a complete blob, requiring **exact consumption**:
    /// trailing bytes are rejected (GENESIS_TX_WIRE_FORMAT.md §12 — the canonical
    /// encoding invariant; the genesis serializer closes the C++ oracle's
    /// trailing-byte malleability gap).
    pub fn from_bytes(blob: &[u8]) -> io::Result<Block> {
        // Up-front DoS bound, parity with `Transaction::from_bytes`'s
        // `MAX_TX_SIZE` check: reject an over-large blob before parsing. The
        // bound is `≥` any blob `read` can accept, so it cannot reject a
        // parseable block (see `MAX_BLOCK_BLOB_SIZE`).
        if blob.len() > MAX_BLOCK_BLOB_SIZE {
            return Err(io::Error::other(format!(
                "shekyl-wire: block blob {} exceeds {MAX_BLOCK_BLOB_SIZE}",
                blob.len()
            )));
        }
        let mut cursor = blob;
        let block = Block::read(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(io::Error::other(format!(
                "shekyl-wire: {} trailing byte(s) after block (§12 exact-consumption)",
                cursor.len()
            )));
        }
        Ok(block)
    }

    /// The block's height, read from the coinbase `gen` input.
    pub fn number(&self) -> Option<u64> {
        match self.miner_transaction.prefix.inputs.first()? {
            Input::Gen(height) => Some(*height),
            // A well-formed coinbase's first input is always Gen; anything else
            // is not a block number.
            _ => None,
        }
    }

    /// The block-hash / PoW preimage (without the leading length varint):
    /// `BlockHeader · tx_tree_hash · V(tx_count + 1)`, where `tx_tree_hash` is the
    /// Merkle tree-hash over `[miner_tx_hash, transaction_hashes…]` (§11). This is
    /// exactly the **PoW** preimage; the block hash adds a length prefix (below).
    ///
    /// One encoder: the bytes are [`PowBlob::write`].
    pub fn pow_blob(&self) -> Vec<u8> {
        self.pow().write()
    }

    /// The PoW preimage as the parsed value [`PowBlob::read`] accepts.
    fn pow(&self) -> PowBlob {
        let mut leaves = Vec::with_capacity(1 + self.transaction_hashes.len());
        leaves.push(self.miner_transaction.hash().to_bytes());
        leaves.extend(self.transaction_hashes.iter().map(|h| h.to_bytes()));
        let tx_tree_hash =
            TxTreeHash::from_bytes(merkle_root(leaves).expect("the miner tx is always present"));
        PowBlob {
            header: self.header.clone(),
            tx_tree_hash,
            tx_count: u64::try_from(self.transaction_hashes.len() + 1)
                .expect("a transaction count fits u64"),
        }
    }

    /// The consensus block hash: `keccak256(V(len) · pow_blob)` (§11). The
    /// length-varint prefix is what distinguishes the block-hash preimage from the
    /// PoW preimage (which omits it). The Monero block-202612 special case is shed
    /// (dead pre-genesis chain history).
    pub fn hash(&self) -> BlockHash {
        identity_of_pow_blob(&self.pow_blob())
    }
}

/// The block identity (CEN-B6) of the block whose [`Block::pow_blob`] is
/// `blob`: one keccak over the blob's length and the blob. The identity is
/// a function of the PoW preimage, so a holder of the preimage alone — the
/// `Substrate::longhash` caller — can name the block it hashes.
#[must_use]
pub fn identity_of_pow_blob(blob: &[u8]) -> BlockHash {
    let mut preimage = Vec::new();
    write_varint(blob.len(), &mut preimage).expect("Vec write is infallible");
    preimage.extend_from_slice(blob);
    BlockHash::from_bytes(keccak256(&preimage))
}

/// The PoW preimage, parsed: the header, the transaction-tree hash, and the
/// count the trailing varint carries (`tx_count = n_tx + 1`, the miner
/// included). [`Block::pow_blob`] writes this and nothing else.
///
/// A header chain carries these bytes and no body. The identity is
/// [`Self::identity`], the same keccak [`identity_of_pow_blob`] applies to
/// [`Block::hash`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PowBlob {
    /// The block header, the prefix of the preimage.
    pub header: BlockHeader,
    /// Merkle root over `[miner_tx_hash, transaction_hashes…]`.
    pub tx_tree_hash: TxTreeHash,
    /// The value of the trailing varint: one more than the number of
    /// non-miner transaction hashes.
    pub tx_count: u64,
}

impl PowBlob {
    /// Parse exactly the bytes [`Block::pow_blob`] writes.
    ///
    /// The transaction-hash count (`tx_count - 1`) is held to
    /// [`READ_LEN_CAP`], the same cap [`Block::read`] puts on `n_tx`. A
    /// trailing byte is refused: the preimage has no slack.
    ///
    /// # Errors
    ///
    /// A short read, a count outside the cap, or bytes after the varint.
    pub fn read(bytes: &[u8]) -> io::Result<Self> {
        let mut cursor = bytes;
        let header = BlockHeader::read(&mut cursor)?;
        let tx_tree_hash = TxTreeHash::from_bytes(read_array::<32, _>(&mut cursor)?);
        let tx_count: u64 = read_varint(&mut cursor)?;
        let listed = tx_count.checked_sub(1).ok_or_else(|| {
            io::Error::other("shekyl-wire: PoW preimage tx_count is 0; the miner is always counted")
        })?;
        if listed > u64::try_from(READ_LEN_CAP).expect("READ_LEN_CAP fits u64") {
            return Err(io::Error::other(format!(
                "shekyl-wire: PoW preimage transaction count {listed} exceeds parse cap {READ_LEN_CAP}"
            )));
        }
        if !cursor.is_empty() {
            return Err(io::Error::other(format!(
                "shekyl-wire: {} trailing byte(s) after the PoW preimage",
                cursor.len()
            )));
        }
        Ok(Self {
            header,
            tx_tree_hash,
            tx_count,
        })
    }

    /// The bytes [`Block::pow_blob`] emits. The one encoder.
    #[must_use]
    pub fn write(&self) -> Vec<u8> {
        let mut blob = Vec::new();
        self.header
            .write(&mut blob)
            .expect("Vec write is infallible");
        blob.extend_from_slice(self.tx_tree_hash.as_bytes());
        write_varint(self.tx_count, &mut blob).expect("Vec write is infallible");
        blob
    }

    /// The block identity of this preimage: [`identity_of_pow_blob`] over
    /// [`Self::write`].
    #[must_use]
    pub fn identity(&self) -> BlockHash {
        identity_of_pow_blob(&self.write())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_archival_retention::empty_attestation_root;

    fn header(attestation_root: [u8; 32]) -> BlockHeader {
        BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_700_000_000,
            previous: BlockHash::from_bytes([0x11; 32]),
            nonce: 0xDEAD_BEEF,
            curve_tree_root: CurveTreeRoot::from_bytes([0x22; 32]),
            attestation_root: AttestationRoot::from_bytes(attestation_root),
        }
    }

    #[test]
    fn attestation_root_roundtrips_and_is_the_final_header_field() {
        let empty = empty_attestation_root();
        let h = header(empty);
        let mut bytes = Vec::new();
        h.write(&mut bytes).unwrap();
        // It is the LAST 32 bytes of the serialized header (after curve_tree_root),
        // so appending it never shifts the nonce/curve_tree_root offsets.
        assert_eq!(&bytes[bytes.len() - 32..], &empty);
        let back = BlockHeader::read(&mut &bytes[..]).unwrap();
        assert_eq!(back, h);
        assert_eq!(back.attestation_root, AttestationRoot::from_bytes(empty));
    }

    /// The four bytes at `nonce_offset` in the PoW preimage are the nonce:
    /// writing a nonce there gives the preimage of the header carrying it.
    /// The timestamps cover a one-byte and a five-byte varint, so the
    /// offset's arithmetic is exercised beyond a fixed layout.
    #[test]
    fn the_nonce_offset_is_where_the_pow_preimage_carries_the_nonce() {
        for timestamp in [1u64, 1_700_000_000] {
            let mut block = Block {
                header: BlockHeader {
                    timestamp,
                    ..header(empty_attestation_root())
                },
                miner_transaction: Transaction {
                    prefix: crate::transaction::TxPrefix {
                        unlock_time: 0,
                        inputs: vec![Input::Gen(7)],
                        outputs: Vec::new(),
                        extra: Vec::new(),
                    },
                    ct: Ct::Null(crate::transaction::CtBase {
                        enc_amounts: Vec::new(),
                        enc_labels: Vec::new(),
                        commitments: Vec::new(),
                    }),
                },
                transaction_hashes: vec![TxHash::from_bytes([0x33; 32])],
            };
            let offset = block.header.nonce_offset();
            let mut patched = block.pow_blob();
            patched[offset..offset + 4].copy_from_slice(&0x0102_0304u32.to_le_bytes());
            block.header.nonce = 0x0102_0304;
            assert_eq!(patched, block.pow_blob(), "timestamp {timestamp}");
        }
    }

    #[test]
    fn attestation_root_is_committed_by_the_wire() {
        // Two headers differing ONLY in attestation_root serialize differently and
        // to equal length — the field is on the wire (hence in the PoW/block-hash
        // preimage, since the header is the preimage prefix), never dropped.
        let mut a = Vec::new();
        let mut b = Vec::new();
        header([0u8; 32]).write(&mut a).unwrap();
        header(empty_attestation_root()).write(&mut b).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), b.len());
    }
}
