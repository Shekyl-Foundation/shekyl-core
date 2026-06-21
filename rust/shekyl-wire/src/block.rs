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
//! BlockHeader := V(major) V(minor) V(timestamp) prev[32] nonce(u32 LE) curve_tree_root[32]
//! ```
//!
//! The miner transaction is embedded inline; `n_tx` counts the *other*
//! transactions, carried as 32-byte hashes (a coinbase-only block has `n_tx = 0`).

use std::io::{self, Read, Write};

use shekyl_crypto_hash::cn_fast_hash;

use crate::bytes::read_array;
use crate::hash::merkle_root;
use crate::transaction::{Input, Transaction};
use crate::varint::{read_varint, write_varint};
use crate::READ_LEN_CAP;

/// A Shekyl block header.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockHeader {
    /// Hard-fork (major) version; genesis `1`.
    pub major_version: u8,
    /// Hard-fork signal (minor) version; genesis `0`.
    pub minor_version: u8,
    /// Seconds since the epoch.
    pub timestamp: u64,
    /// The previous block's hash.
    pub previous: [u8; 32],
    /// The PoW nonce.
    pub nonce: u32,
    /// The FCMP++ curve-tree root committing to the chain's outputs after this block.
    pub curve_tree_root: [u8; 32],
}

impl BlockHeader {
    /// Write the header.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write_varint(self.major_version, w)?;
        write_varint(self.minor_version, w)?;
        write_varint(self.timestamp, w)?;
        w.write_all(&self.previous)?;
        w.write_all(&self.nonce.to_le_bytes())?;
        w.write_all(&self.curve_tree_root)
    }

    /// Read the header.
    pub fn read<R: Read>(r: &mut R) -> io::Result<BlockHeader> {
        Ok(BlockHeader {
            major_version: read_varint(r)?,
            minor_version: read_varint(r)?,
            timestamp: read_varint(r)?,
            previous: read_array(r)?,
            nonce: u32::from_le_bytes(read_array::<4, _>(r)?),
            curve_tree_root: read_array(r)?,
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
    pub transaction_hashes: Vec<[u8; 32]>,
}

impl Block {
    /// Write the block.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.header.write(w)?;
        self.miner_transaction.write(w)?;
        write_varint(self.transaction_hashes.len(), w)?;
        for hash in &self.transaction_hashes {
            w.write_all(hash)?;
        }
        Ok(())
    }

    /// Serialize the block to a fresh `Vec<u8>`.
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
    pub fn read<R: Read>(r: &mut R) -> io::Result<Block> {
        let header = BlockHeader::read(r)?;
        let miner_transaction = Transaction::read(r)?;

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
            transaction_hashes.push(read_array::<32, _>(r)?);
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
    pub fn pow_blob(&self) -> Vec<u8> {
        let mut blob = Vec::new();
        self.header
            .write(&mut blob)
            .expect("Vec write is infallible");
        let mut leaves = Vec::with_capacity(1 + self.transaction_hashes.len());
        leaves.push(self.miner_transaction.hash());
        leaves.extend_from_slice(&self.transaction_hashes);
        let tree_hash = merkle_root(leaves).expect("the miner tx is always present");
        blob.extend_from_slice(&tree_hash);
        write_varint(self.transaction_hashes.len() + 1, &mut blob)
            .expect("Vec write is infallible");
        blob
    }

    /// The consensus block hash: `cn_fast_hash(V(len) · pow_blob)` (§11). The
    /// length-varint prefix is what distinguishes the block-hash preimage from the
    /// PoW preimage (which omits it). The Monero block-202612 special case is shed
    /// (dead pre-genesis chain history).
    pub fn hash(&self) -> [u8; 32] {
        let blob = self.pow_blob();
        let mut preimage = Vec::new();
        write_varint(blob.len(), &mut preimage).expect("Vec write is infallible");
        preimage.extend_from_slice(&blob);
        cn_fast_hash(&preimage)
    }
}
