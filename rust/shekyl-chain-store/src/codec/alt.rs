// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The alternative-chain store's record (DRS-E1 S-ALT, `DRS_E1_SALT.md`
//! §3.4): `alt_blocks[hash] → Coded<AltBlock>`.
//!
//! The C++ `alt_block_data_t` (`blockchain_db.h:206`) is five `u64` words
//! followed by the block blob in one LMDB value, with the reorg-survival
//! attestation witness in a **second** table keyed by the same hash
//! (`archival_alt_attestation_witness`, `ARCHIVAL_CREDIT_WIRE.md` §3 CW-2).
//! This record re-specifies that along its seams rather than porting it:
//!
//! - `cumulative_difficulty` is **one** `u128`, the encoding the chain
//!   codec already uses for `block_info` (`chain.rs`), not the two `u64`
//!   halves the C++ splits by hand at three sites (SAL-5);
//! - `block_weight` is `Option` — the C++ stores `0` for "could not be
//!   determined at admission" (`blockchain.cpp:2345`), and no block weighs
//!   zero, so the sentinel is `None` (`SAL-Q4`); the field is named for what
//!   it holds — the block's own weight, not a cumulative one (SAL-11);
//! - the block and the witness are **fields**, so an alt record without
//!   its block, or a witness outliving its block, is not a value
//!   (`SAL-Q2`; CW-2's lifetime clause made structural, SAL-6).
//!
//! # Construction and decoding refuse the same things
//!
//! [`AltBlock::checked`] is the constructor; the fields are private so it
//! is the *only* constructor. It refuses block bytes that are not a block
//! ([`BlockBody::parse`] — the `blocks` table's own rule), a witness that
//! is present and empty or over its bound
//! ([`AttestationWitnessBytes::well_formed`] — the height-keyed twin's own
//! rule; "empty stores no row" is `None`), and a weight of zero (the
//! sentinel re-minted). [`Canonical::decode`] refuses the same three, so a
//! row that decodes is a row `checked` would have built (SI-14's shape).
//!
//! # The value is the block
//!
//! Construction and decode each call [`BlockBody::parse`] once and store
//! the [`Block`]. [`AltBlock::block`] returns that value; nothing parses
//! again, and there is no raw-bytes accessor. Encode writes
//! [`Block::serialize`]: a blob `from_bytes` accepted re-encodes to itself,
//! so the row's bytes are the canonical encoding without a second copy of
//! them sitting beside the block. The chain read surface keeps its
//! unverified-bytes shape (`RawBlockBytes`) for the relay path that
//! forwards without parsing; no alt consumer forwards, so no raw shape is
//! offered.
//!
//! What the record does not carry is its own hash: the key is the identity.
//! AL1 refuses a caller-supplied key that is not `block.hash()`
//! (`AltCannot::IdentityMismatch`). AL4 and AL7 refuse a row already on
//! disk whose block does not hash to its key, as SI-7 — the belt
//! `chain_reads::block_body` applies to a blob against `block_info.hash`,
//! verification of an identity rather than computation of a consensus
//! value (C2-R8 Q4). The C++ trusted the caller (`blockchain.cpp:2359`).

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_store_codec::{BlobKind, Canonical, CodecError};
use shekyl_types::{BlockHeight, BlockWeight};
use shekyl_units::AtomicUnits;
use shekyl_wire::Block;

use super::archival::AttestationWitnessBytes;
use super::chain::BlockBody;
use super::reader::{put_bytes, Reader};

/// Why [`AltBlock::checked`] refused to build a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AltBlockError {
    /// The block bytes do not parse as a block. An alt block is a block.
    BlockMalformed,
    /// A witness was given and is not a well-formed witness — empty, or over
    /// its bound. Absence is `None`, never an empty `Some`.
    WitnessMalformed,
    /// A weight of zero was given. Zero is the C++ sentinel for "not
    /// determined"; here that is `None`.
    ZeroWeight,
}

impl core::fmt::Display for AltBlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::BlockMalformed => "alt block bytes do not parse as a block",
            Self::WitnessMalformed => {
                "attestation witness is present and empty or over its bound; absence is None"
            }
            Self::ZeroWeight => "a block weight of zero is the sentinel; undetermined is None",
        })
    }
}

impl core::error::Error for AltBlockError {}

/// One alternative-chain block: its bookkeeping, its bytes, and the
/// attestation witness it carries across a reorg.
///
/// Built only through [`AltBlock::checked`]; read through the accessors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AltBlock {
    height: BlockHeight,
    block_weight: Option<BlockWeight>,
    cumulative_difficulty: CumulativeDifficulty,
    coins_generated: AtomicUnits,
    /// Parsed once, at construction or decode. The wire form is
    /// [`Block::serialize`] of this value.
    block: Block,
    attestation_witness: Option<Vec<u8>>,
}

/// The bookkeeping half of an [`AltBlock`] — what the C++ `alt_block_data_t`
/// carried, typed. Passed to [`AltBlock::checked`] as one argument so the
/// four scalars cannot be transposed at a call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AltBlockFacts {
    /// The block's height on its alternative chain.
    pub height: BlockHeight,
    /// The block's own weight, `None` if admission could not determine it.
    pub block_weight: Option<BlockWeight>,
    /// Cumulative difficulty at this block along its chain.
    pub cumulative_difficulty: CumulativeDifficulty,
    /// Coins generated through this block along its chain.
    pub coins_generated: AtomicUnits,
}

impl AltBlock {
    /// Presence byte for an absent optional field.
    const ABSENT: u8 = 0;
    /// Presence byte for a present optional field.
    const PRESENT: u8 = 1;

    /// Build a record, refusing what the codec would refuse.
    ///
    /// # Errors
    ///
    /// [`AltBlockError::BlockMalformed`] if `block` does not parse;
    /// [`AltBlockError::WitnessMalformed`] if `attestation_witness` is
    /// `Some` and not a well-formed witness; [`AltBlockError::ZeroWeight`]
    /// if `facts.block_weight` is `Some(0)`.
    pub fn checked(
        facts: AltBlockFacts,
        block: &[u8],
        attestation_witness: Option<Vec<u8>>,
    ) -> Result<Self, AltBlockError> {
        if facts.block_weight.is_some_and(|w| w.to_raw() == 0) {
            return Err(AltBlockError::ZeroWeight);
        }
        let block = BlockBody::parse(block).map_err(|_| AltBlockError::BlockMalformed)?;
        if let Some(witness) = attestation_witness.as_deref() {
            AttestationWitnessBytes::well_formed(witness)
                .map_err(|_| AltBlockError::WitnessMalformed)?;
        }
        Ok(Self {
            height: facts.height,
            block_weight: facts.block_weight,
            cumulative_difficulty: facts.cumulative_difficulty,
            coins_generated: facts.coins_generated,
            block,
            attestation_witness,
        })
    }

    /// The bookkeeping half.
    #[must_use]
    pub const fn facts(&self) -> AltBlockFacts {
        AltBlockFacts {
            height: self.height,
            block_weight: self.block_weight,
            cumulative_difficulty: self.cumulative_difficulty,
            coins_generated: self.coins_generated,
        }
    }

    /// The block's height on its alternative chain.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.height
    }

    /// The block's own weight, `None` if admission could not determine it.
    #[must_use]
    pub const fn block_weight(&self) -> Option<BlockWeight> {
        self.block_weight
    }

    /// Cumulative difficulty at this block along its chain.
    #[must_use]
    pub const fn cumulative_difficulty(&self) -> CumulativeDifficulty {
        self.cumulative_difficulty
    }

    /// Coins generated through this block along its chain.
    #[must_use]
    pub const fn coins_generated(&self) -> AtomicUnits {
        self.coins_generated
    }

    /// The block. Parsed once, at construction or decode
    /// ([`BlockBody::parse`]); this returns that value.
    #[must_use]
    pub const fn block(&self) -> &Block {
        &self.block
    }

    /// The reorg-survival attestation witness, if the block carries one.
    #[must_use]
    pub fn attestation_witness(&self) -> Option<&[u8]> {
        self.attestation_witness.as_deref()
    }
}

impl Canonical for AltBlock {
    const NAME: &'static str = "alt_block";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.height.to_raw().to_le_bytes());
        match self.block_weight {
            None => out.push(Self::ABSENT),
            Some(w) => {
                out.push(Self::PRESENT);
                out.extend_from_slice(&w.to_raw().to_le_bytes());
            }
        }
        out.extend_from_slice(&self.cumulative_difficulty.to_raw().to_le_bytes());
        self.coins_generated.encode_into(out);
        put_bytes(out, &self.block.serialize());
        match &self.attestation_witness {
            None => out.push(Self::ABSENT),
            Some(w) => {
                out.push(Self::PRESENT);
                put_bytes(out, w);
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(Self::NAME, bytes);
        let height = BlockHeight::from_raw(r.u64()?);
        let block_weight = match r.u8()? {
            Self::ABSENT => None,
            Self::PRESENT => Some(BlockWeight::from_raw(r.u64()?)),
            _ => return Err(r.invalid("block_weight presence byte is not 0 or 1")),
        };
        let cumulative_difficulty = CumulativeDifficulty::from_raw(u128::from_le_bytes(
            r.array::<16>("buffer ends inside the cumulative difficulty")?,
        ));
        let coins_generated = AtomicUnits::from_raw(r.u64()?);
        // Copied out so the witness can be read before the parse. The
        // `Block` is what is kept.
        let block_bytes = r.bytes()?.to_vec();
        let attestation_witness = match r.u8()? {
            Self::ABSENT => None,
            Self::PRESENT => Some(r.bytes()?.to_vec()),
            _ => return Err(r.invalid("attestation_witness presence byte is not 0 or 1")),
        };
        if !r.is_empty() {
            return Err(r.invalid("trailing bytes after the alt block record"));
        }
        if block_weight.is_some_and(|w| w.to_raw() == 0) {
            return Err(r.invalid("block weight is zero; undetermined is a missing option"));
        }
        let block = BlockBody::parse(&block_bytes)
            .map_err(|_| r.invalid("alt block bytes do not parse as a block"))?;
        if let Some(witness) = attestation_witness.as_deref() {
            AttestationWitnessBytes::well_formed(witness).map_err(|_| {
                r.invalid(
                    "attestation witness is empty or over its bound; absence is a missing option",
                )
            })?;
        }
        Ok(Self {
            height,
            block_weight,
            cumulative_difficulty,
            coins_generated,
            block,
            attestation_witness,
        })
    }
}

/// A parseable block for this crate's tests and snapshot fixtures: a
/// header at `height` over a coinbase, no listed transactions. Lives here so
/// the codec test and the snapshot fixture build **the same** bytes.
///
/// The coinbase is built **inline, from literals alone — no rules-harness
/// fixture, no consensus constant** (rule 42: a codec snapshot's input is
/// constructed inline, never a shared value). This codec carries the block
/// as a blob; its snapshot pins the blob's bytes, and `schema-snapshot.yml`
/// demands a `SCHEMA_VERSION` bump for any snapshot change. Anything read
/// from elsewhere is another lane's to move — the harness coinbase did (E6
/// slice 6 commit 3 gave every fixture coinbase its `extra`), and a
/// consensus window or a fixture point could — and a codec whose layout had
/// not changed would then be asked for a schema bump it did not earn. The
/// bytes here are the ones the snapshot has always held: a coinbase no rule
/// reads, only the codec, so its `unlock_time` offset and its points are
/// this snapshot's own literals and nothing else's.
#[cfg(test)]
pub(crate) fn test_block_bytes(height: u64) -> Vec<u8> {
    use shekyl_types::{AttestationRoot, BlockHash, CurveTreeRoot};
    use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};
    // The snapshot's own bytes. `UNLOCK_OFFSET` happens to equal the genesis
    // unlock window and `KEY` / `MASK` the harness's `G` / `2·G` at the pin;
    // that is where the bytes came from, not what they are bound to.
    const UNLOCK_OFFSET: u64 = 60;
    const KEY: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];
    const MASK: [u8; 32] = [
        0xc9, 0xa3, 0xf8, 0x6a, 0xae, 0x46, 0x5f, 0x0e, 0x56, 0x51, 0x38, 0x64, 0x51, 0x0f, 0x39,
        0x97, 0x56, 0x1f, 0xa2, 0xc9, 0xe8, 0x5e, 0xa2, 0x1d, 0xc2, 0x29, 0x23, 0x09, 0xf3, 0xcd,
        0x60, 0x22,
    ];
    let unlock_time = height.saturating_add(UNLOCK_OFFSET);
    Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_000 + height * 60,
            previous: BlockHash::from_bytes([0x11; 32]),
            nonce: 7,
            curve_tree_root: CurveTreeRoot::EMPTY,
            attestation_root: AttestationRoot::from_bytes([0x33; 32]),
        },
        miner_transaction: Transaction {
            prefix: TxPrefix {
                unlock_time,
                inputs: vec![Input::Gen(height)],
                outputs: vec![Output {
                    amount: 0,
                    key: KEY,
                    view_tag: 1,
                }],
                extra: Vec::new(),
            },
            ct: Ct::Null(CtBase {
                enc_amounts: vec![[0x55; 9]],
                enc_labels: vec![[0x66; 9]],
                commitments: vec![MASK],
            }),
        },
        transaction_hashes: Vec::new(),
    }
    .serialize()
}
