// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A chain of real spends, built once and checked in: the shard fill
//! (Rick's shard-fill ruling, option A, 2026-11-11).
//!
//! The store's prune tests and the ingest's long scenarios need shards
//! closed by bytes every landed rule verifies. Proving those spends costs
//! minutes; verifying them costs seconds. So the chain is built once by the
//! store's builder (`shekyl-chain-store`, `store/shard_fill.rs`), written
//! here, and every consumer connects the prefix it needs. The store's
//! `#[ignore]`d real-spends test rebuilds it nightly and fails if a fresh
//! build's archival lengths differ from these: proving draws fresh
//! randomness, so the bytes move between builds and the lengths do not.
//!
//! # Format
//!
//! Little-endian throughout.
//!
//! ```text
//! magic[8] = "SKLSHFIL"
//! format: u32 = FORMAT
//! capture_rev_len: u32, capture_rev[capture_rev_len]   (utf-8: the sha built from)
//! blocks: u32
//! per block:
//!   block_len: u32, block[block_len]                    (Block::serialize, priced)
//!   listed: u32
//!   per listed transaction: tx_len: u32, tx[tx_len]     (Transaction::serialize)
//! ```

use std::io;
use std::path::PathBuf;

use shekyl_wire::{Block, Transaction};

/// The file's magic.
const MAGIC: &[u8; 8] = b"SKLSHFIL";

/// The format this module reads and writes. A change to the layout bumps it.
pub const FORMAT: u32 = 1;

/// Coinbases the shard-fill chain never spends: a consumer's own bond
/// posts spend these (the ingest's `FILL_FROM_COINBASE` names the same
/// count).
pub const SHARD_FILL_RESERVED_COINBASES: u64 = 10;

/// One connected block and the bodies it lists.
#[derive(Clone, Debug)]
pub struct CapturedBlock {
    /// The block as connected (its coinbase priced).
    pub block: Block,
    /// The listed bodies, in listing order.
    pub listed: Vec<Transaction>,
}

/// The checked-in chain.
#[derive(Clone, Debug)]
pub struct CapturedChain {
    /// The commit the chain was built from.
    pub capture_rev: String,
    /// Every block from genesis, in height order.
    pub blocks: Vec<CapturedBlock>,
}

/// Where the shard-fill chain is checked in.
#[must_use]
pub fn shard_fill_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors/shard-fill.bin")
}

impl CapturedChain {
    /// The chain's bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT.to_le_bytes());
        put(&mut out, self.capture_rev.as_bytes());
        out.extend_from_slice(&len32(self.blocks.len()).to_le_bytes());
        for captured in &self.blocks {
            put(&mut out, &captured.block.serialize());
            out.extend_from_slice(&len32(captured.listed.len()).to_le_bytes());
            for tx in &captured.listed {
                put(&mut out, &tx.serialize());
            }
        }
        out
    }

    /// A chain from its bytes.
    ///
    /// # Errors
    ///
    /// `InvalidData` for a wrong magic or format, a short read, trailing
    /// bytes, or a block or body that does not parse.
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let mut at = Reader { bytes, at: 0 };
        if at.take(MAGIC.len())? != MAGIC {
            return Err(bad("not a shard-fill chain"));
        }
        let format = at.u32()?;
        if format != FORMAT {
            return Err(bad(&format!("format {format}, this reader reads {FORMAT}")));
        }
        let capture_rev = String::from_utf8(at.field()?.to_vec())
            .map_err(|_| bad("the capture revision is not utf-8"))?;
        let count = at.u32()?;
        let mut blocks = Vec::new();
        for _ in 0..count {
            let block = Block::from_bytes(at.field()?)?;
            let listed_count = at.u32()?;
            let mut listed = Vec::new();
            for _ in 0..listed_count {
                listed.push(Transaction::from_bytes(at.field()?)?);
            }
            blocks.push(CapturedBlock { block, listed });
        }
        if at.at != bytes.len() {
            return Err(bad("trailing bytes after the last block"));
        }
        Ok(Self {
            capture_rev,
            blocks,
        })
    }

    /// The checked-in shard-fill chain ([`shard_fill_path`]).
    ///
    /// # Panics
    ///
    /// When the file is missing or does not decode: a consumer cannot run
    /// without it.
    #[must_use]
    pub fn shard_fill() -> Self {
        let path = shard_fill_path();
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|err| panic!("the shard-fill chain at {}: {err}", path.display()));
        Self::decode(&bytes)
            .unwrap_or_else(|err| panic!("the shard-fill chain at {}: {err}", path.display()))
    }

    /// Each block's listed archival length, by height: what a consumer's
    /// model of the shards reads.
    #[must_use]
    pub fn archival_lengths(&self) -> Vec<Vec<u64>> {
        self.blocks
            .iter()
            .map(|captured| {
                captured
                    .listed
                    .iter()
                    .map(|tx| tx.archival_len().to_raw())
                    .collect()
            })
            .collect()
    }
}

impl CapturedChain {
    /// How many blocks, from genesis, close shard `k`: the prefix through
    /// the first block whose cumulative listed archival length reaches
    /// `(k + 1)·W`. `None` when the chain does not close it.
    #[must_use]
    pub fn blocks_closing(&self, k: u64) -> Option<usize> {
        let w = shekyl_types::SHARD_LENGTH.to_raw();
        let mut total = 0u64;
        for (h, lens) in self.archival_lengths().iter().enumerate() {
            total += lens.iter().sum::<u64>();
            if total >= (k + 1) * w {
                return Some(h + 1);
            }
        }
        None
    }
}

fn put(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&len32(field.len()).to_le_bytes());
    out.extend_from_slice(field);
}

fn len32(n: usize) -> u32 {
    u32::try_from(n).expect("a captured length fits a u32")
}

fn bad(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.to_owned())
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| bad("the chain ends inside a field"))?;
        let field = &self.bytes[self.at..end];
        self.at = end;
        Ok(field)
    }

    fn u32(&mut self) -> io::Result<u32> {
        let raw: [u8; 4] = self.take(4)?.try_into().expect("four bytes");
        Ok(u32::from_le_bytes(raw))
    }

    fn field(&mut self) -> io::Result<&'a [u8]> {
        let n = usize::try_from(self.u32()?).map_err(|_| bad("a length past usize"))?;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chain round-trips, and every malformed shape is refused rather
    /// than half-read. Red edit: drop the trailing-bytes check.
    #[test]
    fn a_captured_chain_round_trips_and_a_malformed_one_is_refused() {
        let block = Block {
            header: shekyl_wire::BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: 1_000,
                previous: shekyl_types::BlockHash::NULL,
                nonce: 7,
                curve_tree_root: shekyl_types::CurveTreeRoot::EMPTY,
                bundle_root: shekyl_types::BundleRoot::from_bytes([0; 32]),
            },
            miner_transaction: shekyl_harness_wallet::coinbase::paying(
                crate::MinerWallet::harness().recipient(),
                0,
                60,
                0,
            ),
            transaction_hashes: Vec::new(),
        };
        let chain = CapturedChain {
            capture_rev: "0123abcd".to_owned(),
            blocks: vec![CapturedBlock {
                block,
                listed: Vec::new(),
            }],
        };
        let bytes = chain.encode();
        let back = CapturedChain::decode(&bytes).expect("round trip");
        assert_eq!(back.capture_rev, "0123abcd");
        assert_eq!(back.blocks.len(), 1);
        assert_eq!(back.blocks[0].block, chain.blocks[0].block);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(CapturedChain::decode(&trailing).is_err(), "trailing bytes");
        assert!(
            CapturedChain::decode(&bytes[..bytes.len() - 1]).is_err(),
            "short"
        );
        let mut magic = bytes.clone();
        magic[0] ^= 1;
        assert!(CapturedChain::decode(&magic).is_err(), "magic");
        let mut format = bytes;
        format[8] ^= 1;
        assert!(CapturedChain::decode(&format).is_err(), "format");
    }
}
