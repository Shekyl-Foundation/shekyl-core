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
//! | Kept | `count` | 4, little-endian |
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
//! Every record is the same width, [`BUNDLE_RECORD_LEN`]. The kept part
//! states its own `count` (`SCS-P39`), which fixes
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
use shekyl_types::{BlockHeight, SettlementEpoch};

use crate::hash::cshake256_32;
use crate::SettlementSchedule;

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

/// The kept part before its bitmap: the seed, `h` and `count` (`SCS-P39`).
pub const BUNDLE_KEPT_FIXED_LEN: usize = BUNDLE_SEED_LEN + 8 + 4;

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
const _: () = assert!(BUNDLE_KEPT_FIXED_LEN == 44);
const _: () = assert!(BUNDLE_REF_FIXED_LEN == 76);

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
    /// The kept part is the seed, `h`, `count`, and a bitmap of exactly
    /// `count` bits. `expected` is the length the stated count implies, or
    /// the 44 fixed bytes when there are too few to state one.
    #[error("the kept part is {expected} bytes for the count it states, not {found}")]
    KeptLength {
        /// `44 + ⌈count / 8⌉`.
        expected: usize,
        /// The bytes offered.
        found: usize,
    },
    /// A reference is its kept part and a 32-byte hash: exactly
    /// `76 + ⌈count / 8⌉` bytes for the count it states.
    #[error("a reference is 76 bytes and the bitmap its count implies, not {found} bytes")]
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
///
/// It states its own `count` (`SCS-P39`): [`PassBitmap::count`]. A
/// bitmap's bytes do not say how many bits it has — 13 bytes fit any count
/// from 97 to 104 — so the count is on the wire beside them, and the kept
/// part parses, and its padding is checked, with no chain. Admission holds
/// the stated count to `count(h)`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BundleKept {
    /// The block whose producer drew.
    pub h: BlockHeight,
    /// The revealed draw seed.
    pub seed: [u8; BUNDLE_SEED_LEN],
    /// The stated count and its bits.
    pub passes: PassBitmap,
}

impl BundleKept {
    /// The bytes [`Self::encode`] returns: `44 + ⌈count / 8⌉`.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        BUNDLE_KEPT_FIXED_LEN + self.passes.as_bytes().len()
    }

    /// `seed[32] ‖ h_le[8] ‖ count_le[4] ‖ bitmap[⌈count / 8⌉]`.
    ///
    /// The one encoding of the kept part. The reference opens with these
    /// bytes, the header root hashes them inside each reference, and the
    /// bundle commitment is the hash of these bytes followed by the
    /// records: all three call this.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.h.to_raw().to_le_bytes());
        out.extend_from_slice(&self.passes.count().to_le_bytes());
        out.extend_from_slice(self.passes.as_bytes());
    }

    /// The kept part these bytes are. The count is read from the bytes.
    ///
    /// # Errors
    ///
    /// [`BundleWireError::KeptLength`] unless `bytes` is exactly
    /// `44 + ⌈count / 8⌉` long for the count it states;
    /// [`BundleWireError::BitmapPadding`] for a set padding bit.
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleWireError> {
        let Some((fixed, bitmap)) = bytes.split_at_checked(BUNDLE_KEPT_FIXED_LEN) else {
            return Err(BundleWireError::KeptLength {
                expected: BUNDLE_KEPT_FIXED_LEN,
                found: bytes.len(),
            });
        };
        let (seed, rest) = fixed.split_at(BUNDLE_SEED_LEN);
        let (h, count) = rest.split_at(8);
        let count = u32::from_le_bytes(count.try_into().expect("4 bytes"));
        let passes = PassBitmap::new(count, bitmap).map_err(|refusal| match refusal {
            BundleWireError::BitmapLength { expected, .. } => BundleWireError::KeptLength {
                expected: BUNDLE_KEPT_FIXED_LEN.saturating_add(expected),
                found: bytes.len(),
            },
            other => other,
        })?;
        Ok(Self {
            h: BlockHeight::from_raw(u64::from_le_bytes(h.try_into().expect("8 bytes"))),
            seed: seed.try_into().expect("32 bytes"),
            passes,
        })
    }

    /// [`bundle_commitment`] over this kept part and `records`, the
    /// records' bytes in order ([`BundleBody::records_bytes`]).
    #[must_use]
    pub fn commitment(&self, records: &[u8]) -> [u8; 32] {
        bundle_commitment(self, records)
    }

    /// [`bundle_charge`] of this bundle's stated count.
    #[must_use]
    pub const fn charge(&self) -> u64 {
        bundle_charge(self.passes.count())
    }
}

/// What a block carries of a bundle: its kept part and the hash of its
/// prunable bytes (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.5).
///
/// A decoded reference **is** its kept part and that hash. The kept part
/// states its count (`SCS-P39`), so a reference is self-delimiting: it
/// parses on its own, its bitmap's length and padding are checked at
/// decode, and a section's draws are summed from its references with no
/// chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BundleRef {
    kept: BundleKept,
    prunable_hash: [u8; 32],
}

impl BundleRef {
    /// The reference to `body` under `kept`.
    #[must_use]
    pub fn of(kept: &BundleKept, body: &BundleBody) -> Self {
        Self::new(kept.clone(), body.prunable_hash())
    }

    /// A reference from its kept part and the hash of its prunable part.
    #[must_use]
    pub const fn new(kept: BundleKept, prunable_hash: [u8; 32]) -> Self {
        Self {
            kept,
            prunable_hash,
        }
    }

    /// `seed[32] ‖ h_le[8] ‖ count_le[4] ‖ bitmap ‖ prunable_hash[32]`: the
    /// kept part ([`BundleKept::encode`]), then the hash. `76 + ⌈count /
    /// 8⌉` bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.kept.encoded_len() + 32);
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        self.kept.encode_into(out);
        out.extend_from_slice(&self.prunable_hash);
    }

    /// The reference these bytes are.
    ///
    /// # Errors
    ///
    /// [`BundleWireError::ReferenceLength`] unless `bytes` is exactly
    /// `76 + ⌈count / 8⌉` long for the count it states;
    /// [`BundleWireError::BitmapPadding`] for a set padding bit.
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleWireError> {
        let length = BundleWireError::ReferenceLength { found: bytes.len() };
        let Some(kept_len) = bytes.len().checked_sub(32) else {
            return Err(length);
        };
        let (kept, prunable_hash) = bytes.split_at(kept_len);
        let kept = BundleKept::decode(kept).map_err(|refusal| match refusal {
            BundleWireError::KeptLength { .. } => length,
            other => other,
        })?;
        Ok(Self {
            kept,
            prunable_hash: prunable_hash.try_into().expect("32 bytes"),
        })
    }

    /// The kept part.
    #[must_use]
    pub const fn kept(&self) -> &BundleKept {
        &self.kept
    }

    /// The block whose producer drew.
    #[must_use]
    pub const fn h(&self) -> BlockHeight {
        self.kept.h
    }

    /// The revealed draw seed.
    #[must_use]
    pub const fn seed(&self) -> &[u8; BUNDLE_SEED_LEN] {
        &self.kept.seed
    }

    /// The count the reference states. Admission holds it to `count(h)`.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.kept.passes.count()
    }

    /// The pass bitmap.
    #[must_use]
    pub const fn passes(&self) -> &PassBitmap {
        &self.kept.passes
    }

    /// The hash of the prunable part ([`bundle_prunable_hash`]).
    #[must_use]
    pub const fn prunable_hash(&self) -> &[u8; 32] {
        &self.prunable_hash
    }

    /// [`bundle_charge`] of the count the reference states: what the
    /// bundle costs its section.
    #[must_use]
    pub const fn charge(&self) -> u64 {
        self.kept.charge()
    }

    /// The length of the body this reference names: the witness key and
    /// signature, and one record per set bit. The reference fixes it, so a
    /// longer fetch is refused before it completes (§7.5).
    #[must_use]
    pub fn body_len(&self) -> u64 {
        // At most 2^32 set bits of 1,397 bytes each: no overflow in `u64`.
        BUNDLE_WITNESS_LEN as u64
            + u64::from(self.kept.passes.popcount()) * BUNDLE_RECORD_LEN as u64
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
/// That is **the kept part followed by the records**: the preimage opens
/// with [`BundleKept::encode`], the same bytes a reference opens with, and
/// `records` follows — the records' bytes in order, each
/// [`BUNDLE_RECORD_LEN`] wide. The hash does not check the records'
/// length: the verifier holds their number to the bitmap's set bits before
/// it compares. Nothing is framed because nothing needs to be (module
/// docs).
#[must_use]
pub fn bundle_commitment(kept: &BundleKept, records: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(kept.encoded_len() + records.len());
    kept.encode_into(&mut input);
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
/// cSHAKE256_32("shekyl/archival-bundle-root-v1", n_le[4] ‖ ref₁ ‖ … ‖ refₙ)
/// refᵢ = seed[32] ‖ h_le[8] ‖ count_le[4] ‖ bitmap[⌈count / 8⌉] ‖ prunable_hash[32]
/// ```
///
/// Each bundle contributes its kept bytes and the hash of its prunable
/// bytes, which is its reference ([`BundleRef::encode`]). **No reference
/// is length-framed**: each states its `count` (`SCS-P39`), which fixes
/// where its bitmap ends and so where it ends. With `n` in front, two
/// different sections cannot produce one preimage, and the root recomputes
/// from the references alone, on an alternative block with no chain
/// (`SCS-P23`).
///
/// The caller supplies ascending `h`; the order is part of what is hashed,
/// and the verifier's section check refuses any other.
///
/// # Errors
///
/// [`TooManyReferences`] if the section holds 2³² references or more: the
/// root's preimage counts them in four bytes, so such a section has no
/// root. A consensus caller refuses the section for it; nothing here
/// panics.
pub fn bundle_root(refs: &[BundleRef]) -> Result<[u8; 32], TooManyReferences> {
    let n = section_reference_count(refs.len())?;
    let mut input = Vec::new();
    input.extend_from_slice(&n.to_le_bytes());
    for reference in refs {
        reference.encode_into(&mut input);
    }
    Ok(cshake256_32(BUNDLE_ROOT_CUSTOMIZATION, &input))
}

/// A section holds more references than the root's `n_le[4]` can count.
///
/// The wire's condition, owned here: §7.3 fixes the count's width at four
/// bytes, so a section of 2³² or more references has no root preimage at
/// all — it is not a section the format can commit to. The verifier's
/// section check turns it into its own refusal of the block (CEN-J29).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("a section of {found} references has no root: the root counts them in 32 bits")]
pub struct TooManyReferences {
    /// The references offered.
    pub found: usize,
}

/// `n` as the root's preimage carries it: the section's reference count in
/// 32 bits, checked, never truncated.
///
/// Crate-private. [`bundle_root`] is the caller. The bound is tested on
/// this function because a section of 2³² references is not something a
/// test allocates. The verifier maps [`bundle_root`]'s error and does not
/// call this.
///
/// # Errors
///
/// [`TooManyReferences`] if `len` is 2³² or more.
fn section_reference_count(len: usize) -> Result<u32, TooManyReferences> {
    u32::try_from(len).map_err(|_| TooManyReferences { found: len })
}

/// What one bundle costs its section, in draws: `max(count, 1)`
/// (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.4, `SCS-P40`).
///
/// A bundle with draws is charged its draws. A zero-draw bundle is
/// admissible (`SCS-P33`) and is charged one: charged nothing, a block
/// could carry one for every zero-draw block of the last `W₂` under a
/// budget meant to hold a section to `c` bundles at the count cap. This is
/// the one place the charge is computed; the section check sums it.
#[must_use]
pub const fn bundle_charge(count: u32) -> u64 {
    if count == 0 {
        1
    } else {
        count as u64
    }
}

/// The section budget, in draws: the most the charges ([`bundle_charge`],
/// `max(count, 1)`) of the bundles one block admits may sum to (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.4,
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

/// The `D` a section's budget is computed from: [`section_budget`]'s
/// `d_max` (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.4, `SCS-P20`, `SCS-P33`).
///
/// > with `c = 2` (PROVISIONAL, §13.2) and **`D` the largest `D` among the
/// > epochs of the bundles in the section**
///
/// Each reference's `h` names an epoch under `schedule`; `d_of_epoch` is
/// asked for that epoch's `D` — the drawable epoch's length at `h_open(E)`
/// — once per distinct epoch, in the section's order. The maximum is what
/// lets one budget hold bundles of two epochs: a section spans at most two,
/// because `W₂ < SEB`, and a bundle of the larger-`D` epoch is charged
/// against a cap its own epoch set. Taking the including block's `D`, or
/// the first reference's, under-budgets a section whose later epoch is
/// larger and over-budgets one whose earlier epoch is.
///
/// The answer is three-valued, as the view's reads are:
///
/// - `Ok(Some(d_max))` — every epoch's `D` is known.
/// - `Ok(None)` — some epoch's `D` is not known, or the section names no
///   epoch. **Never a partial maximum** over the epochs that did answer.
///   The bundle verifier does not use this for an empty section: an empty
///   section is admitted without a call, because it has no `D` to wait
///   for. A non-empty section with `Ok(None)` waits (`SCS-P23`).
/// - `Err(fault)` — `d_of_epoch` faulted. Not an unknown `D`, and not a
///   verdict: the view's own failure, returned as itself.
///
/// # Errors
///
/// The first fault `d_of_epoch` returns.
pub fn section_d_max<E>(
    refs: &[BundleRef],
    schedule: SettlementSchedule,
    mut d_of_epoch: impl FnMut(SettlementEpoch) -> Result<Option<u64>, E>,
) -> Result<Option<u64>, E> {
    let mut d_max: Option<u64> = None;
    let mut asked: Option<SettlementEpoch> = None;
    for reference in refs {
        let epoch = schedule.epoch_at(reference.h());
        if asked == Some(epoch) {
            continue;
        }
        asked = Some(epoch);
        let Some(d) = d_of_epoch(epoch)? else {
            return Ok(None);
        };
        d_max = Some(d_max.map_or(d, |known| known.max(d)));
    }
    Ok(d_max)
}

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod bundle_tests;
