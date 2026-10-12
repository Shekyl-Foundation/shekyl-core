// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve-credit bundle: its bytes, its commitment, and the header root
//! over a block's references.
//!
//! Design: [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](../../../docs/design/ARCHIVAL_SERVE_CREDIT_SPEC.md)
//! §7 (the bundle), §9.6 (the kept projection). One bundle per block `h`
//! carries the producer's reveal and every pass record it holds:
//!
//! | Part | Field | Width |
//! | --- | --- | --- |
//! | Kept | seed | 32 |
//! | Kept | `h` | 8, little-endian |
//! | Kept | pass bitmap | `⌈count(h) / 8⌉` |
//! | Prunable, once | witness public key | [`BUNDLE_WITNESS_KEY_LEN`] |
//! | Prunable, once | witness signature | [`BUNDLE_SIGNATURE_LEN`] |
//! | Prunable, per record | `attempt` | 1 |
//! | Prunable, per record | `anchor_height` | 8, little-endian |
//! | Prunable, per record | `delivery_digest` | 32 |
//! | Prunable, per record | receipt signature | [`BUNDLE_SIGNATURE_LEN`] |
//!
//! # Nothing is framed, and that rests on one fact
//!
//! Every record is the same width, [`BUNDLE_RECORD_LEN`]. `count(h)` fixes
//! the bitmap's length, the bitmap's set bits fix the number of records, and
//! the width fixes where each ends. The width is fixed because FN-DSA-1024's
//! signature is padded to a fixed length and the canonical hybrid encoding
//! is fixed-length ([`FnDsaHybridSignature::CANONICAL_LEN`]). **A scheme
//! whose signature is not fixed-width breaks this construction**: it needs
//! frames or a different commitment along with its version bump (§7.3,
//! `SCS-P35`). The widths below are derived from the scheme's own constants
//! and then asserted equal to the specification's numbers, so a scheme
//! change meets that statement at compile time, here.
//!
//! # Three hashes, three labels
//!
//! - [`bundle_commitment`] — what the witness signs.
//! - [`bundle_prunable_hash`] — what a reference carries of the prunable
//!   part, and the key a body is fetched and accepted by.
//! - [`bundle_root`] — what the block header commits to.
//!
//! All three are consensus: every node must compute the same bytes.
//!
//! # Disposition: STAGED
//!
//! Nothing on a block path builds or reads a bundle yet. The one consumer
//! is the pure verifier in `shekyl-chain-rules` (`archival::bundle`), which
//! `SO-D12`'s cutover increment calls at admission
//! ([`ARCHIVAL_SERVE_CREDIT_SPEC.md`](../../../docs/design/ARCHIVAL_SERVE_CREDIT_SPEC.md)
//! §9.6, §11). The carrier's set commitment
//! ([`serve_credit_batch_commitment`](crate::secret_draw::serve_credit_batch_commitment))
//! is what this replaces; it stays beside it until that lane deletes it.
//!
//! # No secrets
//!
//! A bundle is public from the moment it is filed: the seed it carries is
//! the reveal. The seed and the witness key *before* the reveal are the
//! challenger's, held in its ring, and never pass through these types.

use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridPublicKey, FnDsaHybridSignature};
use shekyl_types::archival::SettlementEpochBlocks;
use shekyl_types::BlockHeight;

use crate::hash::cshake256_32;

/// cSHAKE256 customization for [`bundle_commitment`] (rule 30: one label,
/// one message, versioned).
pub const BUNDLE_COMMITMENT_CUSTOMIZATION: &[u8] = b"shekyl/archival-serve-credit-bundle-v1";

/// cSHAKE256 customization for [`bundle_prunable_hash`].
pub const BUNDLE_PRUNABLE_CUSTOMIZATION: &[u8] = b"shekyl/archival-bundle-prunable-v1";

/// cSHAKE256 customization for [`bundle_root`].
pub const BUNDLE_ROOT_CUSTOMIZATION: &[u8] = b"shekyl/archival-bundle-root-v1";

/// The draw seed's length.
pub const BUNDLE_SEED_LEN: usize = 32;

/// The witness public key's length: the canonical Ed25519 + FN-DSA-1024
/// public key.
pub const BUNDLE_WITNESS_KEY_LEN: usize = FnDsaHybridPublicKey::CANONICAL_LEN;

/// The length of the witness signature and of each receipt: the canonical
/// Ed25519 + FN-DSA-1024 signature. **Fixed-width, and the bundle's
/// unframed layout depends on that** (module docs).
pub const BUNDLE_SIGNATURE_LEN: usize = FnDsaHybridSignature::CANONICAL_LEN;

/// One record: `attempt[1] ‖ anchor_height_le[8] ‖ delivery_digest[32] ‖
/// receipt[BUNDLE_SIGNATURE_LEN]`.
pub const BUNDLE_RECORD_LEN: usize = 1 + 8 + 32 + BUNDLE_SIGNATURE_LEN;

/// The prunable part before its records: the witness key and signature.
pub const BUNDLE_WITNESS_LEN: usize = BUNDLE_WITNESS_KEY_LEN + BUNDLE_SIGNATURE_LEN;

/// The kept part before its bitmap: the seed and `h`.
pub const BUNDLE_KEPT_FIXED_LEN: usize = BUNDLE_SEED_LEN + 8;

/// A reference before its bitmap: the kept part's fixed bytes and the
/// 32-byte hash of the prunable part.
pub const BUNDLE_REF_FIXED_LEN: usize = BUNDLE_KEPT_FIXED_LEN + 32;

/// The section budget's multiple of the count cap, `c`.
///
/// **PROVISIONAL** (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §13.2 V6, `SCS-P20`).
/// Reopen when it binds on the first build, or when section bytes,
/// propagation to Tor peers, the orphan rate or `BA-T33` say otherwise.
pub const BUNDLE_SECTION_BUDGET_MULTIPLE: u64 = 2;

// The specification's widths (§6.2, §7.2, §7.4), as numbers, against the
// widths derived from the scheme. A scheme whose key or signature has a
// different length — or no fixed length — fails here, which is where the
// unframed layout has to be redesigned.
const _: () = assert!(BUNDLE_WITNESS_KEY_LEN == 1_837);
const _: () = assert!(BUNDLE_SIGNATURE_LEN == 1_356);
const _: () = assert!(BUNDLE_RECORD_LEN == 1_397);
const _: () = assert!(BUNDLE_WITNESS_LEN == 3_193);
const _: () = assert!(BUNDLE_KEPT_FIXED_LEN == 40);
const _: () = assert!(BUNDLE_REF_FIXED_LEN == 72);

/// Bytes of a bundle that are not the bytes of a bundle.
///
/// A parse refusal, not a verdict: the verifier that reads these types
/// names the census row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BundleWireError {
    /// A bitmap of `count` bits is exactly `⌈count / 8⌉` bytes.
    #[error("a pass bitmap of {count} bits is {expected} bytes, not {found}")]
    BitmapLength {
        /// The bit count the bitmap was read against.
        count: u32,
        /// `⌈count / 8⌉`.
        expected: usize,
        /// The bytes offered.
        found: usize,
    },
    /// A bit at or beyond `count` is set. Padding bits are zero (`SCS-P35`).
    #[error("a pass bitmap of {count} bits has a padding bit set")]
    BitmapPadding {
        /// The bit count the bitmap was read against.
        count: u32,
    },
    /// A pass was named for a draw the block does not have.
    #[error("draw {draw} is not below the count {count}")]
    PassOutOfRange {
        /// The draw named.
        draw: u32,
        /// The block's draw count.
        count: u32,
    },
    /// The kept part is the seed, `h`, and a bitmap of exactly `count` bits.
    #[error("the kept part is {expected} bytes for this count, not {found}")]
    KeptLength {
        /// `40 + ⌈count / 8⌉`.
        expected: usize,
        /// The bytes offered.
        found: usize,
    },
    /// A reference is at least its fixed bytes, and its bitmap is no longer
    /// than a bitmap of `u32::MAX` bits.
    #[error("a reference is 72 bytes and a bitmap, not {found} bytes")]
    ReferenceLength {
        /// The bytes offered.
        found: usize,
    },
    /// The prunable part is the witness key, the witness signature, and a
    /// whole number of fixed-width records.
    #[error("the prunable part is 3193 bytes and whole 1397-byte records, not {found} bytes")]
    BodyLength {
        /// The bytes offered.
        found: usize,
    },
}

/// Which of a block's draws passed: exactly `count(h)` bits.
///
/// Draw `j` is bit `j mod 8` of byte `⌊j / 8⌋`, least significant bit
/// first. Padding bits are zero; a value of this type has none set
/// (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.2, `SCS-P35`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PassBitmap {
    count: u32,
    bytes: Vec<u8>,
}

impl PassBitmap {
    /// `⌈count / 8⌉`: the bytes a bitmap of `count` bits occupies.
    #[must_use]
    pub const fn byte_len(count: u32) -> usize {
        // `u32 / 8` is at most 2^29, so the `usize` holds it on every
        // target the workspace builds for.
        (count / 8) as usize + if count.is_multiple_of(8) { 0 } else { 1 }
    }

    /// The bitmap of `count` bits these bytes are.
    ///
    /// # Errors
    ///
    /// [`BundleWireError::BitmapLength`] unless `bytes` is exactly
    /// `⌈count / 8⌉` long; [`BundleWireError::BitmapPadding`] if a bit at
    /// or beyond `count` is set.
    pub fn new(count: u32, bytes: &[u8]) -> Result<Self, BundleWireError> {
        let expected = Self::byte_len(count);
        if bytes.len() != expected {
            return Err(BundleWireError::BitmapLength {
                count,
                expected,
                found: bytes.len(),
            });
        }
        let used = count % 8;
        if used != 0 {
            let last = bytes[expected - 1];
            if last >> used != 0 {
                return Err(BundleWireError::BitmapPadding { count });
            }
        }
        Ok(Self {
            count,
            bytes: bytes.to_vec(),
        })
    }

    /// The bitmap of `count` bits with exactly `passes` set — the
    /// challenger's side of [`Self::new`].
    ///
    /// # Errors
    ///
    /// [`BundleWireError::PassOutOfRange`] for a pass at or beyond `count`.
    pub fn from_passes(
        count: u32,
        passes: impl IntoIterator<Item = u32>,
    ) -> Result<Self, BundleWireError> {
        let mut bytes = vec![0u8; Self::byte_len(count)];
        for draw in passes {
            if draw >= count {
                return Err(BundleWireError::PassOutOfRange { draw, count });
            }
            bytes[(draw / 8) as usize] |= 1 << (draw % 8);
        }
        Ok(Self { count, bytes })
    }

    /// The number of draws the bitmap covers: `count(h)`.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Whether draw `j` passed. `false` at or beyond [`Self::count`].
    #[must_use]
    pub fn get(&self, draw: u32) -> bool {
        draw < self.count && self.bytes[(draw / 8) as usize] & (1 << (draw % 8)) != 0
    }

    /// The number of passes: the number of records the bundle carries.
    #[must_use]
    pub fn popcount(&self) -> u32 {
        self.bytes.iter().map(|byte| byte.count_ones()).sum()
    }

    /// The passed draws, ascending — the order the records follow in.
    pub fn iter_set(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.count).filter(|draw| self.get(*draw))
    }

    /// The bitmap's bytes, as the kept part and the commitment carry them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The kept part of a bundle and nothing more: what the header root covers,
/// what a pruned node retains, and what settlement reads
/// (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.2, §9.6).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BundleKept {
    /// The block whose producer drew.
    pub h: BlockHeight,
    /// The revealed draw seed.
    pub seed: [u8; BUNDLE_SEED_LEN],
    /// Exactly `count(h)` bits.
    pub passes: PassBitmap,
}

impl BundleKept {
    /// `seed[32] ‖ h_le[8] ‖ bitmap`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BUNDLE_KEPT_FIXED_LEN + self.passes.as_bytes().len());
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.h.to_raw().to_le_bytes());
        out.extend_from_slice(self.passes.as_bytes());
        out
    }

    /// The kept part these bytes are, for a block of `count` draws. The
    /// count is not in the bytes: it is `count(h)`, which the chain holds.
    ///
    /// # Errors
    ///
    /// [`BundleWireError::KeptLength`] unless `bytes` is exactly
    /// `40 + ⌈count / 8⌉` long; [`BundleWireError::BitmapPadding`] for a
    /// set padding bit.
    pub fn decode(bytes: &[u8], count: u32) -> Result<Self, BundleWireError> {
        let expected = BUNDLE_KEPT_FIXED_LEN + PassBitmap::byte_len(count);
        if bytes.len() != expected {
            return Err(BundleWireError::KeptLength {
                expected,
                found: bytes.len(),
            });
        }
        let (seed, rest) = bytes.split_at(BUNDLE_SEED_LEN);
        let (h, bitmap) = rest.split_at(8);
        Ok(Self {
            h: BlockHeight::from_raw(u64::from_le_bytes(h.try_into().expect("8 bytes"))),
            seed: seed.try_into().expect("32 bytes"),
            passes: PassBitmap::new(count, bitmap)?,
        })
    }

    /// The bundle commitment over this kept part and `records`, the
    /// records' bytes in order ([`BundleBody::records_bytes`]).
    #[must_use]
    pub fn commitment(&self, records: &[u8]) -> [u8; 32] {
        bundle_commitment(
            &self.seed,
            self.h,
            self.passes.count(),
            self.passes.as_bytes(),
            records,
        )
    }
}

/// What a block carries of a bundle: its kept bytes and the hash of its
/// prunable bytes (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.5).
///
/// The bitmap is held as bytes, not as a [`PassBitmap`]: a reference does
/// not carry `count(h)`, and the stateless section check runs where the
/// chain that holds it may not be known (`SCS-P23`). [`Self::kept`] reads
/// the bitmap against the count once the chain supplies it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BundleRef {
    seed: [u8; BUNDLE_SEED_LEN],
    h: BlockHeight,
    bitmap: Vec<u8>,
    prunable_hash: [u8; 32],
}

impl BundleRef {
    /// The longest bitmap a reference can carry: a bitmap of `u32::MAX`
    /// bits. A draw index is 32 bits (§3), so no block has more.
    pub const MAX_BITMAP_LEN: usize = PassBitmap::byte_len(u32::MAX);

    /// The reference to `body` under `kept`.
    #[must_use]
    pub fn of(kept: &BundleKept, body: &BundleBody) -> Self {
        Self {
            seed: kept.seed,
            h: kept.h,
            bitmap: kept.passes.as_bytes().to_vec(),
            prunable_hash: body.prunable_hash(),
        }
    }

    /// A reference from its fields.
    ///
    /// # Errors
    ///
    /// [`BundleWireError::ReferenceLength`] for a bitmap longer than
    /// [`Self::MAX_BITMAP_LEN`].
    pub fn new(
        seed: [u8; BUNDLE_SEED_LEN],
        h: BlockHeight,
        bitmap: &[u8],
        prunable_hash: [u8; 32],
    ) -> Result<Self, BundleWireError> {
        if bitmap.len() > Self::MAX_BITMAP_LEN {
            return Err(BundleWireError::ReferenceLength {
                found: BUNDLE_REF_FIXED_LEN.saturating_add(bitmap.len()),
            });
        }
        Ok(Self {
            seed,
            h,
            bitmap: bitmap.to_vec(),
            prunable_hash,
        })
    }

    /// `seed[32] ‖ h_le[8] ‖ bitmap ‖ prunable_hash[32]`: the kept bytes,
    /// then the hash.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BUNDLE_REF_FIXED_LEN + self.bitmap.len());
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.h.to_raw().to_le_bytes());
        out.extend_from_slice(&self.bitmap);
        out.extend_from_slice(&self.prunable_hash);
        out
    }

    /// The reference these bytes are. Whatever lies between the fixed
    /// leading 40 bytes and the trailing 32 is the bitmap.
    ///
    /// # Errors
    ///
    /// [`BundleWireError::ReferenceLength`] for fewer than
    /// [`BUNDLE_REF_FIXED_LEN`] bytes or a bitmap longer than
    /// [`Self::MAX_BITMAP_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleWireError> {
        let short = BundleWireError::ReferenceLength { found: bytes.len() };
        let Some(bitmap_len) = bytes.len().checked_sub(BUNDLE_REF_FIXED_LEN) else {
            return Err(short);
        };
        if bitmap_len > Self::MAX_BITMAP_LEN {
            return Err(short);
        }
        let (seed, rest) = bytes.split_at(BUNDLE_SEED_LEN);
        let (h, rest) = rest.split_at(8);
        let (bitmap, prunable_hash) = rest.split_at(bitmap_len);
        Ok(Self {
            seed: seed.try_into().expect("32 bytes"),
            h: BlockHeight::from_raw(u64::from_le_bytes(h.try_into().expect("8 bytes"))),
            bitmap: bitmap.to_vec(),
            prunable_hash: prunable_hash.try_into().expect("32 bytes"),
        })
    }

    /// The block whose producer drew.
    #[must_use]
    pub const fn h(&self) -> BlockHeight {
        self.h
    }

    /// The revealed draw seed.
    #[must_use]
    pub const fn seed(&self) -> &[u8; BUNDLE_SEED_LEN] {
        &self.seed
    }

    /// The bitmap's bytes, not yet read against a count.
    #[must_use]
    pub fn bitmap_bytes(&self) -> &[u8] {
        &self.bitmap
    }

    /// The hash of the prunable part ([`bundle_prunable_hash`]).
    #[must_use]
    pub const fn prunable_hash(&self) -> &[u8; 32] {
        &self.prunable_hash
    }

    /// The kept part, read against `count(h)`.
    ///
    /// # Errors
    ///
    /// [`BundleWireError::BitmapLength`] unless the bitmap is exactly
    /// `count` bits long; [`BundleWireError::BitmapPadding`] for a set
    /// padding bit.
    pub fn kept(&self, count: u32) -> Result<BundleKept, BundleWireError> {
        Ok(BundleKept {
            h: self.h,
            seed: self.seed,
            passes: PassBitmap::new(count, &self.bitmap)?,
        })
    }

    /// The length of the body this reference names: the witness key and
    /// signature, and one record per set bit. The reference fixes it, so a
    /// longer fetch is refused before it completes (§7.5).
    #[must_use]
    pub fn body_len(&self) -> u64 {
        let set: u64 = self
            .bitmap
            .iter()
            .map(|byte| u64::from(byte.count_ones()))
            .sum();
        // At most 2^32 set bits of 1,397 bytes each: no overflow in `u64`.
        BUNDLE_WITNESS_LEN as u64 + set * BUNDLE_RECORD_LEN as u64
    }
}

/// One pass record. It names nothing: its draw is the position of its bit,
/// its pair is derived from that draw, and its nonce is recomputed from the
/// seed, the draw and `attempt` (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.2).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BundleRecord {
    /// Which read of the draw produced this record, from 0. Admission
    /// refuses `attempt ≥ K`.
    pub attempt: u8,
    /// The anchor the read's request carried. Admission refuses an anchor
    /// at or above `h` (`SCS-P32`).
    pub anchor_height: BlockHeight,
    /// The digest of the response the persona delivered (`SF-D8`).
    pub delivery_digest: [u8; 32],
    /// The persona's receipt: a canonical scheme-3 signature.
    pub receipt: [u8; BUNDLE_SIGNATURE_LEN],
}

impl core::fmt::Debug for BundleRecord {
    /// The receipt is 1,356 bytes; a log line does not carry it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BundleRecord")
            .field("attempt", &self.attempt)
            .field("anchor_height", &self.anchor_height)
            .finish_non_exhaustive()
    }
}

impl BundleRecord {
    /// `attempt[1] ‖ anchor_height_le[8] ‖ delivery_digest[32] ‖ receipt`.
    #[must_use]
    pub fn encode(&self) -> [u8; BUNDLE_RECORD_LEN] {
        let mut out = [0u8; BUNDLE_RECORD_LEN];
        out[0] = self.attempt;
        out[1..9].copy_from_slice(&self.anchor_height.to_raw().to_le_bytes());
        out[9..41].copy_from_slice(&self.delivery_digest);
        out[41..].copy_from_slice(&self.receipt);
        out
    }

    /// The record these bytes are. Every byte string of the width is a
    /// record; whether its receipt verifies is the verifier's question.
    #[must_use]
    pub fn decode(bytes: &[u8; BUNDLE_RECORD_LEN]) -> Self {
        Self {
            attempt: bytes[0],
            anchor_height: BlockHeight::from_raw(u64::from_le_bytes(
                bytes[1..9].try_into().expect("8 bytes"),
            )),
            delivery_digest: bytes[9..41].try_into().expect("32 bytes"),
            receipt: bytes[41..].try_into().expect("the receipt's width"),
        }
    }
}

/// The prunable part of a bundle: the witness key, the witness signature,
/// and the records in ascending `j` over the set bits.
///
/// Held as its canonical bytes. Decoding establishes the length and
/// nothing else: whether the key and the signatures are a key and
/// signatures is the verifier's question, asked in the order admission
/// rules (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §9.1).
#[derive(Clone, PartialEq, Eq)]
pub struct BundleBody {
    bytes: Vec<u8>,
}

impl core::fmt::Debug for BundleBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BundleBody")
            .field("records", &self.record_count())
            .finish_non_exhaustive()
    }
}

impl BundleBody {
    /// The body with this witness key, witness signature and records.
    #[must_use]
    pub fn new(
        witness_public_key: &[u8; BUNDLE_WITNESS_KEY_LEN],
        witness_signature: &[u8; BUNDLE_SIGNATURE_LEN],
        records: &[BundleRecord],
    ) -> Self {
        let mut bytes = Vec::with_capacity(BUNDLE_WITNESS_LEN + records.len() * BUNDLE_RECORD_LEN);
        bytes.extend_from_slice(witness_public_key);
        bytes.extend_from_slice(witness_signature);
        for record in records {
            bytes.extend_from_slice(&record.encode());
        }
        Self { bytes }
    }

    /// The body these bytes are.
    ///
    /// # Errors
    ///
    /// [`BundleWireError::BodyLength`] unless `bytes` is the witness key,
    /// the witness signature, and a whole number of records.
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleWireError> {
        match bytes.len().checked_sub(BUNDLE_WITNESS_LEN) {
            Some(records) if records.is_multiple_of(BUNDLE_RECORD_LEN) => Ok(Self {
                bytes: bytes.to_vec(),
            }),
            _ => Err(BundleWireError::BodyLength { found: bytes.len() }),
        }
    }

    /// The canonical bytes: `witness_pk ‖ witness_sig ‖ r₁ ‖ … ‖ rₙ`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The witness public key's canonical bytes.
    #[must_use]
    pub fn witness_public_key(&self) -> &[u8; BUNDLE_WITNESS_KEY_LEN] {
        self.bytes[..BUNDLE_WITNESS_KEY_LEN]
            .try_into()
            .expect("the length was established at construction")
    }

    /// The witness signature's canonical bytes.
    #[must_use]
    pub fn witness_signature(&self) -> &[u8; BUNDLE_SIGNATURE_LEN] {
        self.bytes[BUNDLE_WITNESS_KEY_LEN..BUNDLE_WITNESS_LEN]
            .try_into()
            .expect("the length was established at construction")
    }

    /// The records' bytes, in order: `r₁ ‖ … ‖ rₙ`, as the commitment
    /// takes them.
    #[must_use]
    pub fn records_bytes(&self) -> &[u8] {
        &self.bytes[BUNDLE_WITNESS_LEN..]
    }

    /// The number of records.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records_bytes().len() / BUNDLE_RECORD_LEN
    }

    /// The records, in the order they were filed: ascending `j` over the
    /// set bits.
    pub fn records(&self) -> impl Iterator<Item = BundleRecord> + '_ {
        self.records_bytes()
            .chunks_exact(BUNDLE_RECORD_LEN)
            .map(|chunk| BundleRecord::decode(chunk.try_into().expect("an exact chunk")))
    }

    /// [`bundle_prunable_hash`] of these bytes.
    #[must_use]
    pub fn prunable_hash(&self) -> [u8; 32] {
        bundle_prunable_hash(&self.bytes)
    }
}

/// The bundle commitment: what the witness signs, under
/// `SCHEME_DOMAIN_WITNESS_BUNDLE` (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.3,
/// `SCS-P35`).
///
/// ```text
/// cSHAKE256_32("shekyl/archival-serve-credit-bundle-v1",
///              seed[32] ‖ h_le[8] ‖ count_le[4] ‖ bitmap ‖ r₁ ‖ … ‖ rₙ)
/// ```
///
/// `count` is `count(h)`, `bitmap` its `⌈count / 8⌉` bytes, and `records`
/// the records' bytes in order, each [`BUNDLE_RECORD_LEN`] wide. The hash
/// checks none of those lengths: it is a function of the bytes it is
/// given, and the verifier establishes them before it signs or compares.
/// Nothing is framed because nothing needs to be (module docs).
#[must_use]
pub fn bundle_commitment(
    seed: &[u8; BUNDLE_SEED_LEN],
    h: BlockHeight,
    count: u32,
    bitmap: &[u8],
    records: &[u8],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(BUNDLE_SEED_LEN + 8 + 4 + bitmap.len() + records.len());
    input.extend_from_slice(seed);
    input.extend_from_slice(&h.to_raw().to_le_bytes());
    input.extend_from_slice(&count.to_le_bytes());
    input.extend_from_slice(bitmap);
    input.extend_from_slice(records);
    cshake256_32(BUNDLE_COMMITMENT_CUSTOMIZATION, &input)
}

/// The hash of a bundle's prunable bytes: what its reference carries, and
/// the key its body is stored, fetched and accepted by
/// (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.3, §7.5, `SCS-P36`).
///
/// ```text
/// cSHAKE256_32("shekyl/archival-bundle-prunable-v1",
///              witness_pk[1837] ‖ witness_sig[1356] ‖ r₁ ‖ … ‖ rₙ)
/// ```
///
/// The input is the prunable part verbatim ([`BundleBody::as_bytes`]).
#[must_use]
pub fn bundle_prunable_hash(prunable: &[u8]) -> [u8; 32] {
    cshake256_32(BUNDLE_PRUNABLE_CUSTOMIZATION, prunable)
}

/// The header root over a block's bundle references, in the order given
/// (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.3, §9.1).
///
/// ```text
/// cSHAKE256_32("shekyl/archival-bundle-root-v1",
///              n_le[4] ‖ len₁_le[4] ‖ ref₁ ‖ … ‖ lenₙ_le[4] ‖ refₙ)
/// refᵢ = seed[32] ‖ h_le[8] ‖ bitmap ‖ prunable_hash[32]
/// ```
///
/// Each bundle contributes its kept bytes and the hash of its prunable
/// bytes, which is its reference ([`BundleRef::encode`]). `lenᵢ` is that
/// reference's length in bytes. The frame is by **bytes, not by
/// `count(h)`**: a reference does not carry the count, and the root must
/// recompute from the references alone where the chain that holds the
/// count is not known (`SCS-P23`). With `n` and each length in the
/// preimage, two different sections cannot produce one preimage.
///
/// The caller supplies ascending `h`; the order is part of what is hashed,
/// and the verifier's section check refuses any other.
///
/// # Panics
///
/// If the section holds 2³² references or more. A reference is at least
/// 72 bytes and at most 2²⁹ + 72, so its own length always fits.
#[must_use]
pub fn bundle_root(refs: &[BundleRef]) -> [u8; 32] {
    let frame = |len: usize| -> [u8; 4] {
        u32::try_from(len)
            .expect("a section's reference count and each reference's length fit 32 bits")
            .to_le_bytes()
    };
    let mut input = Vec::new();
    input.extend_from_slice(&frame(refs.len()));
    for reference in refs {
        let bytes = reference.encode();
        input.extend_from_slice(&frame(bytes.len()));
        input.extend_from_slice(&bytes);
    }
    cshake256_32(BUNDLE_ROOT_CUSTOMIZATION, &input)
}

/// The section budget, in draws: the most the `count(h)` of the bundles
/// one block admits may sum to (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.4,
/// `SCS-P20`, `SCS-P33`).
///
/// ```text
/// c · (⌊9·D / SEB⌋ + 1)
/// ```
///
/// `d_max` is the largest `D` among the epochs of the bundles in the
/// section, and `c` is [`BUNDLE_SECTION_BUDGET_MULTIPLE`] in production.
/// `⌊9·D / SEB⌋ + 1` is the count cap: the per-block target is at most
/// `9·D / SEB` and the carry adds less than one. The `+ 1` is what lets a
/// network below `SEB / 9` pairs admit a bundle at all.
///
/// Computed in 128 bits and saturated: a budget above `u64::MAX` binds
/// nothing a `u64` sum can reach.
#[must_use]
pub fn section_budget(c: u64, d_max: u64, seb: SettlementEpochBlocks) -> u64 {
    let cap = u128::from(d_max) * 9 / u128::from(seb.get()) + 1;
    u64::try_from(u128::from(c).saturating_mul(cap)).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod bundle_tests;
