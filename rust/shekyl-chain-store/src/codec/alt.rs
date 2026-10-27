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
//! - `block_weight` is a [`BlockWeight`] — the block's own weight, not a
//!   cumulative one (SAL-11). The C++ stored `0` for "could not be
//!   determined" (`blockchain.cpp:2345`). Nothing writes an undetermined
//!   weight: the cheap tier measures one, and zero is a codec refusal
//!   ([`AltBlockError::ZeroWeight`]), not an absence. This layout stores
//!   the eight bytes with no presence byte;
//! - the block and the witness are **fields**, so an alt record without
//!   its block, or a witness outliving its block, is not a value
//!   (`SAL-Q2`; CW-2's lifetime clause made structural, SAL-6);
//! - there is **no supply word** (CEN-K8, `DRS_E5_POOL_ALT_PRUNE.md`
//!   §2.1). The C++ carried `already_generated_coins` per alt block as a
//!   coinbase-paid approximation nothing consensus-bearing read; the Rust
//!   tier that admits an alt block reads no executed-chain fact and
//!   derives none, and promotion re-derives supply by executing the chain.
//!   A field with no reader is not stored, so "nothing reads it" is the
//!   type, not a grep. Deleted at `SCHEMA_VERSION` 24 (rule 42);
//! - the **proof-of-work hash** the tier computed, under its seed
//!   ([`RecordedPow`], 64 bytes after the cumulative difficulty;
//!   `SCHEMA_VERSION` 26): its reader is the switch, which re-forms the
//!   block through it instead of hashing it again
//!   (`DRS_E5_POOL_ALT_PRUNE.md`, 2026-10-15 ruling 3).
//!
//! # The row is built from the verdict
//!
//! [`AltBlock::admitted`] is the constructor: it takes the cheap tier's
//! verdict, [`AltValid`], and nothing else (DRS-E5 a4, `AltValid → AL1`).
//! The verdict carries the block, its witness, and the three facts the tier
//! derived over the stitched chain — the height, the cumulative difficulty,
//! the measured weight — so there is no call site at which a fact is typed
//! by hand, and no row the store holds that no tier admitted. The
//! constructor is infallible: the block is a parsed [`Block`] already, the
//! witness is a typed [`AttestationWitness`](shekyl_types::archival::AttestationWitness)
//! (non-empty, within the bound the codec checks), and a measured weight is
//! never zero (a block weighs at least its coinbase's bytes).
//!
//! [`AltBlock::checked`] builds a *value* from bare facts and bytes,
//! refusing what the codec would refuse: block bytes that are not a block
//! ([`BlockBody::parse`] — the `blocks` table's own rule), a witness that
//! is present and empty or over its bound
//! ([`AttestationWitnessBytes::well_formed`] — the height-keyed twin's own
//! rule; "empty stores no row" is `None`), and a weight of zero. The
//! codec's own tests, the schema snapshot and the store's planted-row
//! fixtures build rows this way; AL1 does not take one — the write
//! boundary is the verdict's type, not this constructor's visibility.
//! [`Canonical::decode`] refuses the same three, so a row that decodes is
//! a row `checked` would have built (SI-14's shape).
//!
//! The weight is mandatory in this layout. [`AltBlock::admitted`] always
//! measured one, and no other writer produced an absence, so a presence
//! byte is not a case the type can name. A later writer that needs an
//! absent weight bumps the layout. The switch's demotion re-entry is a5's
//! (`DRS_E5_POOL_ALT_PRUNE.md` §5); it does not inherit an absence arm.
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
//! AL1 takes the key from the verdict ([`AltValid::hash`], CEN-B6's one
//! keccak over the block it stores), so no caller supplies one and there is
//! no mismatch to refuse. AL4 and AL7 refuse a row already on disk whose
//! block does not hash to its key, as SI-7 — the belt
//! `chain_reads::block_body` applies to a blob against `block_info.hash`,
//! verification of an identity rather than computation of a consensus
//! value (C2-R8 Q4). The C++ trusted the caller (`blockchain.cpp:2359`).

use shekyl_chain_rules::AltValid;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_store_codec::{BlobKind, Canonical, CodecError};
use shekyl_types::{BlockHeight, BlockWeight};
use shekyl_wire::{Block, Transaction};

use super::archival::AttestationWitnessBytes;
use super::chain::{BlockBody, RecordedPow};
use shekyl_store_codec::reader::{put_bytes, put_count, Reader};

/// Why [`AltBlock::checked`] refused to build a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AltBlockError {
    /// The block bytes do not parse as a block. An alt block is a block.
    BlockMalformed,
    /// A witness was given and is not a well-formed witness — empty, or over
    /// its bound. Absence is `None`, never an empty `Some`.
    WitnessMalformed,
    /// A weight of zero was given. A block weighs at least its coinbase;
    /// zero is not a weight this record stores.
    ZeroWeight,
}

impl core::fmt::Display for AltBlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::BlockMalformed => "alt block bytes do not parse as a block",
            Self::WitnessMalformed => {
                "attestation witness is present and empty or over its bound; absence is None"
            }
            Self::ZeroWeight => "a block weight of zero is refused",
        })
    }
}

impl core::error::Error for AltBlockError {}

/// One alternative-chain block: its bookkeeping, its bytes, and the
/// attestation witness it carries across a reorg.
///
/// Built from the cheap tier's verdict through [`AltBlock::admitted`]
/// (inside the crate, from bare facts through [`AltBlock::checked`]); read
/// through the accessors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AltBlock {
    height: BlockHeight,
    block_weight: BlockWeight,
    cumulative_difficulty: CumulativeDifficulty,
    /// The PoW the cheap tier computed and accepted, under its seed — the
    /// switch re-forms this block through it rather than hashing again
    /// (ruling 3, 2026-10-15).
    pow: RecordedPow,
    /// Parsed once, at construction or decode. The wire form is
    /// [`Block::serialize`] of this value.
    block: Block,
    attestation_witness: Option<Vec<u8>>,
}

/// The bookkeeping half of an [`AltBlock`] — what the C++ `alt_block_data_t`
/// carried, typed — less its supply word (module doc). Passed to
/// [`AltBlock::checked`] as one argument so the scalars cannot be
/// transposed at a call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AltBlockFacts {
    /// The block's height on its alternative chain.
    pub height: BlockHeight,
    /// The block's own weight. Zero is refused.
    pub block_weight: BlockWeight,
    /// Cumulative difficulty at this block along its chain.
    pub cumulative_difficulty: CumulativeDifficulty,
    /// The PoW the tier computed under its seed.
    pub pow: RecordedPow,
}

impl AltBlock {
    /// Presence byte for an absent witness.
    const ABSENT: u8 = 0;
    /// Presence byte for a present witness.
    const PRESENT: u8 = 1;

    /// **AL1's input.** The row for a block the cheap tier admitted: the
    /// block and witness the verdict carries, under the height, cumulative
    /// difficulty and weight it derived over the stitched chain
    /// (`DRS_E5_POOL_ALT_PRUNE.md` §2.1). Infallible — module docs, *The row
    /// is built from the verdict*. `V` is the view the tier judged over;
    /// the row does not keep it.
    ///
    /// The second value is the block's listed bodies, which AL1 writes to
    /// `alt_block_bodies` under the same key ([`AltBodies`]).
    #[must_use]
    pub fn admitted<V>(valid: AltValid<'_, V>) -> (Self, AltBodies) {
        let height = valid.height();
        let cumulative_difficulty = valid.cumulative_difficulty();
        let block_weight = valid.block_weight();
        let pow = RecordedPow::of(valid.pow());
        debug_assert!(
            block_weight.to_raw() != 0,
            "a measured block weight is at least its coinbase's bytes"
        );
        let candidate = valid.into_candidate();
        (
            Self {
                height,
                block_weight,
                cumulative_difficulty,
                pow,
                block: candidate.block,
                attestation_witness: candidate
                    .attestation_witness
                    .map(|witness| witness.as_bytes().to_vec()),
            },
            AltBodies(candidate.transactions),
        )
    }

    /// Build a value from bare facts and bytes, refusing what the codec
    /// would refuse. Not AL1's input — that is [`AltBlock::admitted`]; this
    /// is how the codec's tests, the schema snapshot and the store's
    /// planted-row fixtures build a row.
    ///
    /// # Errors
    ///
    /// [`AltBlockError::BlockMalformed`] if `block` does not parse;
    /// [`AltBlockError::WitnessMalformed`] if `attestation_witness` is
    /// `Some` and not a well-formed witness; [`AltBlockError::ZeroWeight`]
    /// if `facts.block_weight` is zero.
    pub fn checked(
        facts: AltBlockFacts,
        block: &[u8],
        attestation_witness: Option<Vec<u8>>,
    ) -> Result<Self, AltBlockError> {
        if facts.block_weight.to_raw() == 0 {
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
            pow: facts.pow,
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
            pow: self.pow,
        }
    }

    /// The block's height on its alternative chain.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.height
    }

    /// The block's own weight.
    #[must_use]
    pub const fn block_weight(&self) -> BlockWeight {
        self.block_weight
    }

    /// Cumulative difficulty at this block along its chain.
    #[must_use]
    pub const fn cumulative_difficulty(&self) -> CumulativeDifficulty {
        self.cumulative_difficulty
    }

    /// The PoW the cheap tier computed under its seed.
    #[must_use]
    pub const fn pow(&self) -> RecordedPow {
        self.pow
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
        out.extend_from_slice(&self.block_weight.to_raw().to_le_bytes());
        out.extend_from_slice(&self.cumulative_difficulty.to_raw().to_le_bytes());
        self.pow.encode_into(out);
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
        let block_weight = BlockWeight::from_raw(r.u64()?);
        if block_weight.to_raw() == 0 {
            return Err(r.invalid("block weight is zero"));
        }
        let cumulative_difficulty = CumulativeDifficulty::from_raw(u128::from_le_bytes(
            r.array::<16>("buffer ends inside the cumulative difficulty")?,
        ));
        let pow = RecordedPow::decode(&r.array::<64>("buffer ends inside the recorded PoW")?)?;
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
            pow,
            block,
            attestation_witness,
        })
    }
}

/// An alternative block's listed bodies, in the order its header lists
/// them — `alt_block_bodies[hash] → Coded<AltBodies>` (DRS-E5 PR-b, the
/// review of #1102's B1).
///
/// **The bodies are consensus data.** A switch promoting an alternative
/// connects these bodies; a store that did not hold them could not follow a
/// heavier valid chain, and a pool refuses, evicts and discards by local
/// policy, so they are not the pool's to hold. AL1 writes them from
/// the cheap tier's verdict, whose candidate `form` paired with the header
/// (CEN-G2) before the tier ran, and AL2 and AL3 remove them with the row.
///
/// **A table of its own, not a field of [`AltBlock`].** Every switch plan
/// and every connect's dead-row sweep walks the alt rows for their heights
/// and headers; a field would make each of those walks parse every listed
/// transaction. The bodies are read only when a block is promoted. The
/// pairing the field would have made structural is a read belt instead:
/// AL8 holds the bodies to the row's listed hashes, and a row without its
/// bodies, or the converse, is SI-7.
///
/// # Layout
///
/// ```text
/// count u32 ‖ count × (len u32 ‖ transaction bytes)
/// ```
///
/// Each transaction is parsed at decode and must re-encode to its own
/// bytes: one value, one encoding. Trailing bytes are a codec error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AltBodies(Vec<Transaction>);

impl AltBodies {
    /// Bodies for this crate's fixtures and tests; AL1 builds its value
    /// from the verdict ([`AltBlock::admitted`]).
    #[cfg(test)]
    pub(crate) const fn of(transactions: Vec<Transaction>) -> Self {
        Self(transactions)
    }

    /// The bodies, in listed order.
    #[must_use]
    pub fn transactions(&self) -> &[Transaction] {
        &self.0
    }

    /// The bodies, owned.
    #[must_use]
    pub fn into_transactions(self) -> Vec<Transaction> {
        self.0
    }
}

impl Canonical for AltBodies {
    const NAME: &'static str = "alt_bodies";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        put_count(out, self.0.len());
        for tx in &self.0 {
            put_bytes(out, &tx.serialize());
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(Self::NAME, bytes);
        // Each body is at least its four-byte length.
        let count = r.count_bounded(4, usize::MAX, "unreachable: usize::MAX cap")?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let raw = r.bytes()?;
            let tx = Transaction::from_bytes(raw)
                .map_err(|_| r.invalid("a listed body does not parse as a transaction"))?;
            if tx.serialize() != raw {
                return Err(r.invalid("a listed body does not re-encode to its own bytes"));
            }
            out.push(tx);
        }
        if !r.is_empty() {
            return Err(r.invalid("trailing bytes after the alt block's bodies"));
        }
        Ok(Self(out))
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
