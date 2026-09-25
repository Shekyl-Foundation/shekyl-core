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
//! - the block bytes and the witness are **fields**, so an alt record
//!   without its block, or a witness outliving its block, is not a value
//!   (`SAL-Q2`; CW-2's lifetime clause made structural, SAL-6).
//!
//! # Construction and decoding refuse the same things
//!
//! [`AltBlock::checked`] is the constructor; the fields are private so it
//! is the *only* constructor. It refuses block bytes that are not a block
//! ([`BlockBody::well_formed`] — the `blocks` table's own rule), a witness
//! that is present and empty or over its bound
//! ([`AttestationWitnessBytes::well_formed`] — the height-keyed twin's own
//! rule; "empty stores no row" is `None`), and a weight of zero (the
//! sentinel re-minted). [`Canonical::decode`] refuses the same three, so a
//! row that decodes is a row `checked` would have built (SI-14's shape).
//!
//! # The parse boundary is here, not at the consumer
//!
//! The record stores the block's wire bytes (the one canonical encoding),
//! but it hands out a **parsed** [`Block`] — [`AltBlock::block`] — never the
//! bytes. Every C++ consumer parsed (`blockchain.cpp:937`, `:2023`,
//! `:2590`, `:6749`) and `MERROR`-skipped a blob that would not; here a row
//! that decodes *is* a block, because decoding ran the same parse. The
//! chain read surface keeps its unverified-bytes shape (`RawBlockBytes`)
//! for the relay path that forwards without parsing; no alt consumer
//! forwards, so no raw shape is offered (Copilot, PR #856).
//!
//! What the record does not carry is its own hash: the key is the identity,
//! and the store verifies at AL1 that the key hashes the block
//! (`AltCannot::IdentityMismatch`) — the belt class `chain_reads::block_body`
//! already applies to a blob against `block_info.hash`, verification of a
//! caller-supplied identity rather than computation of a consensus value
//! (C2-R8 Q4). The C++ trusted the caller (`blockchain.cpp:2359`).

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
    block: Vec<u8>,
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
        block: Vec<u8>,
        attestation_witness: Option<Vec<u8>>,
    ) -> Result<Self, AltBlockError> {
        validate(facts.block_weight, &block, attestation_witness.as_deref())?;
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

    /// The block, parsed. The bytes parsed at construction or at decode (the
    /// same [`BlockBody::well_formed`]), so this cannot fail; there is no
    /// raw-bytes accessor (module docs, *The parse boundary is here*).
    #[must_use]
    pub fn block(&self) -> Block {
        Block::from_bytes(&self.block)
            .expect("an AltBlock's bytes parsed at construction or decode; nothing mutates them")
    }

    /// The block's wire bytes, for the tests that pin the row's layout.
    /// Test-only: the block is [`block`](Self::block), parsed.
    #[cfg(test)]
    pub(crate) fn block_bytes(&self) -> &[u8] {
        &self.block
    }

    /// The reorg-survival attestation witness, if the block carries one.
    #[must_use]
    pub fn attestation_witness(&self) -> Option<&[u8]> {
        self.attestation_witness.as_deref()
    }
}

/// The three refusals, shared by construction and decoding.
fn validate(
    block_weight: Option<BlockWeight>,
    block: &[u8],
    witness: Option<&[u8]>,
) -> Result<(), AltBlockError> {
    if block_weight.is_some_and(|w| w.to_raw() == 0) {
        return Err(AltBlockError::ZeroWeight);
    }
    BlockBody::well_formed(block).map_err(|_| AltBlockError::BlockMalformed)?;
    if let Some(w) = witness {
        AttestationWitnessBytes::well_formed(w).map_err(|_| AltBlockError::WitnessMalformed)?;
    }
    Ok(())
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
        put_bytes(out, &self.block);
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
        let block = r.bytes()?.to_vec();
        let attestation_witness = match r.u8()? {
            Self::ABSENT => None,
            Self::PRESENT => Some(r.bytes()?.to_vec()),
            _ => return Err(r.invalid("attestation_witness presence byte is not 0 or 1")),
        };
        if !r.is_empty() {
            return Err(r.invalid("trailing bytes after the alt block record"));
        }
        validate(block_weight, &block, attestation_witness.as_deref()).map_err(|e| {
            r.invalid(match e {
                AltBlockError::BlockMalformed => "alt block bytes do not parse as a block",
                AltBlockError::WitnessMalformed => {
                    "attestation witness is empty or over its bound; absence is a missing option"
                }
                AltBlockError::ZeroWeight => {
                    "block weight is zero; undetermined is a missing option"
                }
            })
        })?;
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
#[cfg(test)]
pub(crate) fn test_block_bytes(height: u64) -> Vec<u8> {
    use shekyl_chain_rules::harness::fixture;
    use shekyl_types::{AttestationRoot, BlockHash, CurveTreeRoot};
    use shekyl_wire::{Block, BlockHeader};
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
        miner_transaction: fixture::coinbase(height),
        transaction_hashes: Vec::new(),
    }
    .serialize()
}
