// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Attestation wire + admission verify — the §3 record format and the §4
//! *admission* half of the seam (block-validation time, pre-prune).
//!
//! Design of record: [`ARCHIVAL_CREDIT_WIRE.md`](../../../docs/design/ARCHIVAL_CREDIT_WIRE.md)
//! (TJ-B step 3, shape 4), amended by
//! [`ARCHIVAL_SHARD_FETCH.md`](../../../docs/design/ARCHIVAL_SHARD_FETCH.md)
//! `SF-D8` (ruled 2026-09-13, landed here as that round's §9.1 step (a0)).
//! This module owns the parts admission touches — the kept **header** bytes
//! (`p_id, shard_id, E, kind`), the requester-random **nonce** and
//! **anchor height** each pass carries, the **`attestation_root`** over the
//! **pass-record** set, and the **countersignature verify**. Its sibling
//! [`crate::attestation`] owns the settlement fold; the two never share a
//! signature, which is the §4 seam.
//!
//! # What `P` countersigns — the decoded request header ‖ `shard_id` (v2)
//!
//! [`pass_countersignature_message`] is the single statement of the signed
//! transcript, `header[72] ‖ shard_id_le[8]`, under
//! [`SCHEME_DOMAIN_ATTESTATION`](shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION)
//! (the `-v2` domain; the nonce-only `-v1` domain is retired and never reused),
//! where the header is the fetching client's one required request header
//! (`SF-D5`) **decoded to its 72 canonical binary bytes**
//! ([`pass_request_header_bytes`]):
//!
//! ```text
//! nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]
//! ```
//!
//! `P` signs the **decoded** value, never the header's textual form. `RF-R1`
//! gives the header one canonical textual encoding, but the transcript has to
//! be the binary or Rust and C++ disagree the first time a case or padding
//! variant is accepted on the wire.
//!
//! - **`nonce`** is 32 requester-random bytes. `P` sees them only as bytes to
//!   sign; they are **not** derivable from chain terms, so the pass record
//!   carries them ([`PassRecord::nonce`]) and the witness transports them
//!   alongside the signature ([`PassWitness`]). Every caller draws its nonce
//!   fresh per request — witness and organic reader alike; `P` cannot tell
//!   which, which is what keeps *the test IS a read* true.
//! - **`anchor_height` / `anchor_hash`** bind the read to a block that had to
//!   **exist** when `P` signed: the requester anchors at
//!   `tip − `[`PASS_ANCHOR_DEPTH_BLOCKS`] and supplies that block's hash. The
//!   record carries the **height** ([`PassRecord::anchor_height`]); admission
//!   looks the **hash** up from the connecting chain
//!   ([`PassAnchorWindow`]) — a fabricated hash fails against the real one,
//!   which is what makes the term unforgeable by the requester. The depth is
//!   the archival freeze margin, so the anchored hash is identical on every
//!   honest node's chain and tip races cannot touch it; the accepted **residue**
//!   is that a colluding `P` gains `depth` blocks of pre-signing lead, which
//!   the 2-of-3 quadratic already prices. Admission accepts
//!   `anchor_height ∈ [h − depth − L, h − depth]` for a block whose predecessor
//!   is `h` ([`PassAnchorHeights::for_predecessor`]); `L` =
//!   [`PASS_ANCHOR_LAG_BLOCKS`] covers fetch span and `P`/requester skew, so
//!   one record is valid across `L + 1` heights (the replay window, accepted
//!   by ruling). `P`'s own pre-sign gate is `±L` around its own
//!   `height − depth` with the **same** `L` (`RF-R1`), so no `P` gates
//!   distinctively.
//! - **`shard_id`** is the `u64` `P` parsed from the `/shard/{id}` route it
//!   actually served. Signing it server-side is what makes the countersignature
//!   a *shard* binding: a caller-supplied header alone would let a dishonest
//!   witness replay a valid signature over any shard's terms.
//!
//! Below `depth + L` (predecessor height < [`PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT`])
//! no window exists and **any** pass record is refused; the first settlement
//! is at 10 000, so nothing is lost.
//!
//! The v1 message (`H(block_hash(h−1) ‖ cb_out_key ‖ P ‖ s ‖ E)`, every term
//! recomputable) is **retired**, not gated: `cb_out_key` and the rest of the
//! challenge tuple leave the signed message, `attestation_nonce()` is deleted,
//! and the verifier takes the anchor window where it took the predecessor
//! hash and coinbase key. Pre-genesis, no chain carried a v1 record.
//!
//! # Pass is a type, not a kind check
//!
//! Root and verify take [`PassRecord`] — identity + terms + nonce + anchor
//! height + signature, with **no `kind` field**. Wire encode materializes
//! `kind = Pass`. A miss is a kept header alone and cannot enter these APIs.
//! That is the admission half of the same make-bad-states-unrepresentable seam
//! settlement already uses (`settle_epoch(passes, issued)` — absolute-2, §7.1
//! ratification).

use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
};
use shekyl_crypto_pq::CryptoError;

use crate::attestation::AttestationKind;
use crate::bond_floor::{ARCHIVAL_ATTESTATION_ANCHOR_LAG_BLOCKS, ARCHIVAL_REORG_DEPTH_BLOCKS};
use crate::hash::cshake256_32;
use crate::id::p_canonical_id_from_hybrid_pubkey;

/// cSHAKE customization for `attestation_root` over the ordered pass-record set.
///
/// Unchanged by the `SF-D8` layout amendment: the record layout it hashes gained
/// the nonce and anchor height (see [`attestation_root`]), which the two-record
/// KAT pins, and the genesis-frozen empty root (`count = 0`, no records) is
/// byte-identical before and after. There was never a chain carrying the
/// pre-amendment layout, so there is no second layout under this string to
/// separate from.
pub const ATTESTATION_ROOT_CUSTOMIZATION: &[u8] = b"shekyl/archival-attestation-root-v1";

/// Canonical kept-header length: `p_id(32) + shard_id(8) + settlement_epoch(8) +
/// kind(1)` (§3.1). The `kind` byte is the sole prune-surviving *discriminant*
/// on the full kept header (`p_id ‖ s ‖ E ‖ kind` all ride `prefix_hash`).
pub const ATTESTATION_HEADER_LEN: usize = 32 + 8 + 8 + 1;

/// Length of the requester-random nonce a pass record carries and `P` signs
/// over (`SF-D5`: exactly 32 bytes, one encoding, refused otherwise).
pub const PASS_NONCE_LEN: usize = 32;

/// Length of the little-endian anchor height in the request header, the
/// transcript, the pass record, and the witness entry.
pub const PASS_ANCHOR_HEIGHT_LEN: usize = 8;

/// Length of the anchor block hash in the request header and the transcript.
/// It is **not** carried by the record or the witness — admission derives it
/// from the connecting chain at `anchor_height`.
pub const PASS_ANCHOR_HASH_LEN: usize = 32;

/// Length of the **decoded** request header `P` signs
/// ([`pass_request_header_bytes`]): `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`.
pub const PASS_REQUEST_HEADER_LEN: usize =
    PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN + PASS_ANCHOR_HASH_LEN;

/// Length of the signed transcript `header[72] ‖ shard_id_le[8]`
/// ([`pass_countersignature_message`]).
pub const PASS_COUNTERSIGNATURE_MESSAGE_LEN: usize = PASS_REQUEST_HEADER_LEN + 8;

/// Anchor burial depth: the requester anchors at `tip − depth`, admission at
/// `h − depth` (upper bound). This **is** `archival_reorg_depth_blocks` (720),
/// consumed from the generated constant — the same freeze margin segment
/// freeze already relies on never being replaced, so the anchored hash is
/// canonical on every honest node. Both directions are dangerous
/// (`config/consensus_constants.json`): lower makes the anchor
/// reorg-sensitive; higher lengthens collusive pre-signing lead.
pub const PASS_ANCHOR_DEPTH_BLOCKS: u64 = ARCHIVAL_REORG_DEPTH_BLOCKS;

/// Anchor lag `L` (PROVISIONAL 4, `SF-D8`): the window below the upper bound
/// admission accepts, and the half-width of `P`'s pre-sign gate. Consumed from
/// the generated constant; the falsifier and re-pin rule live on the JSON key.
pub const PASS_ANCHOR_LAG_BLOCKS: u64 = ARCHIVAL_ATTESTATION_ANCHOR_LAG_BLOCKS;

/// Lowest predecessor height with an anchor window: `depth + L`. Below it
/// ([`PassAnchorHeights::for_predecessor`] is `None`) every pass record is
/// refused — the genesis boundary, KAT-pinned at the threshold and one below.
pub const PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT: u64 =
    PASS_ANCHOR_DEPTH_BLOCKS + PASS_ANCHOR_LAG_BLOCKS;

/// Number of heights (and hashes) in one anchor window: `L + 1`.
///
/// `L` is a small block count (PROVISIONAL 4, re-pin band `[2, …]`), so the
/// cast cannot truncate on any target; the assertion makes that a build
/// failure rather than a comment if the JSON key is ever set absurdly.
pub const PASS_ANCHOR_WINDOW_LEN: usize = {
    assert!(PASS_ANCHOR_LAG_BLOCKS <= u32::MAX as u64);
    #[allow(clippy::cast_possible_truncation)]
    let lag = PASS_ANCHOR_LAG_BLOCKS as usize;
    lag + 1
};

/// Genesis-frozen consensus cap on attestation records per block. It must equal
/// C++ `config::ARCHIVAL_MAX_ATTESTATION_RECORDS` (the cross-language witness KAT
/// pins the equality). It bounds both the admission record count and the witness
/// decode's up-front allocation, so a hostile `count` field cannot force an
/// unbounded reservation before the length is validated.
pub const MAX_ATTESTATION_RECORDS: usize = 256;

/// Fixed framing prefix of a canonical witness: `count_le(8)`.
pub const WITNESS_PREFIX_LEN: usize = 8;

/// One witness entry: `nonce(32) ‖ anchor_height_le(8) ‖ signature_canonical`
/// ([`PassWitness`]).
pub const WITNESS_ENTRY_LEN: usize =
    PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN + HybridSignature::CANONICAL_LEN;

/// The EXACT maximum canonical byte length of a [`BlockAttestationWitness`]:
/// `count(8) ‖ MAX_ATTESTATION_RECORDS × (nonce ‖ anchor_height ‖ HybridSignature)`.
/// This is the authority the C++ transport cap must respect: the coarse
/// `config::ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES` must **over-bound** this value
/// (`cpp_cap ≥ this`), never under-bound it — a C++ cap below this maximum would
/// reject on the wire a witness that Rust admits, i.e. a consensus split. The
/// direction is gated cross-language by the FFI bound test; this const is the
/// single Rust-side authority for that check.
pub const MAX_ATTESTATION_WITNESS_BYTES: usize =
    WITNESS_PREFIX_LEN + MAX_ATTESTATION_RECORDS * WITNESS_ENTRY_LEN;

/// `kind` byte encodings — fixed, not a bit in a status field, so a decoder
/// rejects anything that is neither (no silent third state).
const KIND_MISS: u8 = 0;
const KIND_PASS: u8 = 1;

/// The kept per-record header (§3.1), permanent in the coinbase `tx_extra` and
/// committed via `prefix_hash`. The full header (`p_id, shard_id, E, kind`)
/// survives the signature prune; settlement folds the gathered `kind` values
/// after the scan has already keyed by `(P, s, E)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationHeader {
    pub p_id: [u8; 32],
    pub shard_id: u64,
    pub settlement_epoch: u64,
    pub kind: AttestationKind,
}

/// A header failed to decode from its canonical bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationHeaderError {
    /// Byte length is not [`ATTESTATION_HEADER_LEN`].
    #[error("attestation header wrong length: expected {ATTESTATION_HEADER_LEN}, got {0}")]
    WrongLength(usize),
    /// The `kind` byte is neither [`KIND_MISS`] nor [`KIND_PASS`].
    #[error("attestation header kind byte {0} is neither miss (0) nor pass (1)")]
    BadKind(u8),
}

impl AttestationHeader {
    /// Canonical bytes: `p_id ‖ shard_id_le ‖ settlement_epoch_le ‖ kind`.
    /// Little-endian for the counters, matching the archival lineage
    /// (`challenge.rs` uses `to_le_bytes`); fixed-width so the layout is
    /// position-addressable and never ambiguous.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> [u8; ATTESTATION_HEADER_LEN] {
        let mut out = [0u8; ATTESTATION_HEADER_LEN];
        out[0..32].copy_from_slice(&self.p_id);
        out[32..40].copy_from_slice(&self.shard_id.to_le_bytes());
        out[40..48].copy_from_slice(&self.settlement_epoch.to_le_bytes());
        out[48] = match self.kind {
            AttestationKind::Miss => KIND_MISS,
            AttestationKind::Pass => KIND_PASS,
        };
        out
    }

    /// Decode; rejects a wrong length or an out-of-range `kind` byte (loud, not
    /// a silent default — a malformed header is a block-validity failure).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AttestationHeaderError> {
        if bytes.len() != ATTESTATION_HEADER_LEN {
            return Err(AttestationHeaderError::WrongLength(bytes.len()));
        }
        let mut p_id = [0u8; 32];
        p_id.copy_from_slice(&bytes[0..32]);
        let shard_id = u64::from_le_bytes(bytes[32..40].try_into().expect("8 bytes"));
        let settlement_epoch = u64::from_le_bytes(bytes[40..48].try_into().expect("8 bytes"));
        let kind = match bytes[48] {
            KIND_MISS => AttestationKind::Miss,
            KIND_PASS => AttestationKind::Pass,
            other => return Err(AttestationHeaderError::BadKind(other)),
        };
        Ok(Self {
            p_id,
            shard_id,
            settlement_epoch,
            kind,
        })
    }
}

/// The anchor **heights** admission accepts for a block whose validated
/// predecessor is `h`: `[h − depth − L, h − depth]`, inclusive, `L + 1` wide.
///
/// The upper bound carries freshness (`P` could not have signed a hash of a
/// block that did not exist; the depth is the accepted lead); the lower bound
/// is hygiene against a stale anchor. `h` is the **predecessor** of the block
/// carrying the record — the value C++ already passes — so a fetch that spans
/// one block boundary (anchored for `h`, mined into `h + 1`) is still inside
/// the window; that is why `L ≥ 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassAnchorHeights {
    first: u64,
    last: u64,
}

impl PassAnchorHeights {
    /// The window for a block connecting to predecessor height
    /// `predecessor_height`, or `None` below
    /// [`PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT`] (no window exists; every pass
    /// record is refused there).
    #[must_use]
    pub fn for_predecessor(predecessor_height: u64) -> Option<Self> {
        if predecessor_height < PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT {
            return None;
        }
        let last = predecessor_height - PASS_ANCHOR_DEPTH_BLOCKS;
        Some(Self {
            first: last - PASS_ANCHOR_LAG_BLOCKS,
            last,
        })
    }

    /// Lowest accepted anchor height (`h − depth − L`).
    #[must_use]
    pub const fn first(&self) -> u64 {
        self.first
    }

    /// Highest accepted anchor height (`h − depth`).
    #[must_use]
    pub const fn last(&self) -> u64 {
        self.last
    }

    /// Number of heights in the window — always [`PASS_ANCHOR_WINDOW_LEN`].
    #[must_use]
    pub const fn len(&self) -> usize {
        PASS_ANCHOR_WINDOW_LEN
    }

    /// A window is never empty (`L + 1 ≥ 1`); provided for the `len`/`is_empty`
    /// pairing lint, it is always `false`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Table index of `anchor_height` within the window (`anchor − first`), or
    /// `None` when it lies outside — the **one indexed lookup** the verifier
    /// performs against the C++-filled hash table.
    #[must_use]
    pub fn index_of(&self, anchor_height: u64) -> Option<usize> {
        if anchor_height < self.first || anchor_height > self.last {
            return None;
        }
        // ≤ L, so this narrowing is infallible on every target width.
        Some(usize::try_from(anchor_height - self.first).expect("index ≤ L fits usize"))
    }
}

/// An anchor window could not be built from the caller's hash table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PassAnchorWindowError {
    /// The predecessor height is below [`PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT`]:
    /// no window exists, so no table can be right.
    #[error(
        "no pass anchor window below predecessor height {PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT} \
         (got {predecessor_height})"
    )]
    BelowThreshold { predecessor_height: u64 },
    /// The hash table is not exactly [`PASS_ANCHOR_WINDOW_LEN`] entries — a
    /// marshaling slip on the caller's side, distinct from any record verdict.
    #[error("pass anchor hash table has {got} entries, expected {expected}")]
    WrongLength { expected: usize, got: usize },
}

/// The anchor window with its **hashes**: the connecting chain's block hash at
/// each height of [`PassAnchorHeights`], `hashes[i]` for height `first + i`.
///
/// The caller (C++ admission, through the FFI ctx) fills the table from the
/// chain the block is being connected to — the main chain, or an alt chain
/// **above the fork point** — so a block validated on an alt chain sees that
/// chain's anchor hashes, not the main chain's. Nothing caps reorg depth, so an
/// anchor inside a deep alt chain is a live case, not a corner. Rust does one
/// indexed lookup per record and never reads chain state itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassAnchorWindow {
    heights: PassAnchorHeights,
    hashes: Vec<[u8; PASS_ANCHOR_HASH_LEN]>,
}

impl PassAnchorWindow {
    /// Build the window for `predecessor_height` from the caller's hash table,
    /// which must hold exactly [`PASS_ANCHOR_WINDOW_LEN`] hashes for heights
    /// `first..=last` in ascending order.
    pub fn new(
        predecessor_height: u64,
        hashes: Vec<[u8; PASS_ANCHOR_HASH_LEN]>,
    ) -> Result<Self, PassAnchorWindowError> {
        let heights = PassAnchorHeights::for_predecessor(predecessor_height)
            .ok_or(PassAnchorWindowError::BelowThreshold { predecessor_height })?;
        if hashes.len() != heights.len() {
            return Err(PassAnchorWindowError::WrongLength {
                expected: heights.len(),
                got: hashes.len(),
            });
        }
        Ok(Self { heights, hashes })
    }

    /// The heights this window covers.
    #[must_use]
    pub const fn heights(&self) -> PassAnchorHeights {
        self.heights
    }

    /// The connecting chain's hash at `anchor_height`, or `None` when the height
    /// is outside the window.
    #[must_use]
    pub fn hash_at(&self, anchor_height: u64) -> Option<&[u8; PASS_ANCHOR_HASH_LEN]> {
        self.heights
            .index_of(anchor_height)
            .map(|i| &self.hashes[i])
    }
}

/// One **pass** attestation: identity + terms + the carried nonce and anchor
/// height + countersignature.
///
/// `nonce` and `anchor_height` are the requester-supplied header terms `P`
/// signed over (with the anchor hash and the served `shard_id`). They are
/// carried because they cannot be recomputed: no chain term determines a
/// caller's nonce, and the anchor height is the caller's choice within the
/// window (`SF-D8`). The anchor **hash** is not carried — admission derives it
/// from the connecting chain, which is what makes it unforgeable.
///
/// There is no `kind` field — Pass is the type. [`Self::to_header`] materializes
/// the kept wire header with `kind = Pass`. Miss records never carry a
/// signature and never appear here, so root/verify cannot represent
/// miss-with-signature.
#[derive(Debug, Clone)]
pub struct PassRecord {
    pub p_id: [u8; 32],
    pub shard_id: u64,
    pub settlement_epoch: u64,
    pub nonce: [u8; PASS_NONCE_LEN],
    pub anchor_height: u64,
    pub signature: HybridSignature,
}

impl PassRecord {
    /// Kept header for this pass (`kind = Pass`).
    #[must_use]
    pub fn to_header(&self) -> AttestationHeader {
        AttestationHeader {
            p_id: self.p_id,
            shard_id: self.shard_id,
            settlement_epoch: self.settlement_epoch,
            kind: AttestationKind::Pass,
        }
    }

    /// The transcript `P` must have signed for this record to verify when the
    /// connecting chain's hash at `anchor_height` is `anchor_hash`:
    /// [`pass_countersignature_message`] over the carried nonce and anchor
    /// height, that hash, and this record's `shard_id`. Prefer this at call
    /// sites that hold a record so the terms cannot drift from it.
    #[must_use]
    pub fn countersignature_message(
        &self,
        anchor_hash: &[u8; PASS_ANCHOR_HASH_LEN],
    ) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
        pass_countersignature_message(&self.nonce, self.anchor_height, anchor_hash, self.shard_id)
    }
}

/// The **decoded** request header (`SF-D5`) — the 72 canonical binary bytes
/// `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]` the fetching client
/// sends and `P` signs. `RF-R1` owns the textual header encoding; this is the
/// value it decodes to, and the only form that enters the transcript.
#[must_use]
pub fn pass_request_header_bytes(
    nonce: &[u8; PASS_NONCE_LEN],
    anchor_height: u64,
    anchor_hash: &[u8; PASS_ANCHOR_HASH_LEN],
) -> [u8; PASS_REQUEST_HEADER_LEN] {
    const HEIGHT_END: usize = PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN;
    let mut out = [0u8; PASS_REQUEST_HEADER_LEN];
    out[0..PASS_NONCE_LEN].copy_from_slice(nonce);
    out[PASS_NONCE_LEN..HEIGHT_END].copy_from_slice(&anchor_height.to_le_bytes());
    out[HEIGHT_END..].copy_from_slice(anchor_hash);
    out
}

/// The signed transcript of a pass countersignature (`SF-D8`):
/// `header[72] ‖ shard_id_le[8]`, the header being
/// [`pass_request_header_bytes`] — `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`.
///
/// This is the **only** statement of the layout; `P`'s serve path and every
/// verifier (admission here, the fetching client in `shekyl-p-fetch`) build the
/// message through it, so the three cannot drift. The signature itself is made
/// under [`SCHEME_DOMAIN_ATTESTATION`](shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION).
/// A plain concatenation, **not** a hash — a verifier that hashed it would
/// fail the byte-pinned KAT.
///
/// - `nonce`: the caller's 32 random bytes, opaque to `P`.
/// - `anchor_height`: the caller's anchor, `tip − depth` at request time; at
///   admission the record's carried value, accepted only inside
///   [`PassAnchorHeights`].
/// - `anchor_hash`: at `P`, the caller's header bytes (gated on height only —
///   `P` is chain-blind); at admission the connecting chain's hash at
///   `anchor_height` ([`PassAnchorWindow::hash_at`]), so a caller who lied
///   about the hash produced a signature that verifies nowhere.
/// - `shard_id`: the `u64` `P` parsed from the route it served — the
///   server-enforced shard binding.
#[must_use]
pub fn pass_countersignature_message(
    nonce: &[u8; PASS_NONCE_LEN],
    anchor_height: u64,
    anchor_hash: &[u8; PASS_ANCHOR_HASH_LEN],
    shard_id: u64,
) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
    let mut out = [0u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN];
    out[..PASS_REQUEST_HEADER_LEN].copy_from_slice(&pass_request_header_bytes(
        nonce,
        anchor_height,
        anchor_hash,
    ));
    out[PASS_REQUEST_HEADER_LEN..].copy_from_slice(&shard_id.to_le_bytes());
    out
}

/// `attestation_root` over the block's **pass-records** (§3.2) — the value
/// stored in the block field and mined over as a merkle leaf.
///
/// Each record contributes
/// `header_canonical ‖ nonce ‖ anchor_height_le ‖ signature_canonical`, so the
/// root commits the header↔nonce↔anchor↔signature **tuple** — not signatures
/// alone, and not in an unstated positional order. The nonce and anchor height
/// are committed because they are signed-over yet not chain-derivable: a root
/// over header‖signature alone would let the witness transport different
/// header terms than the ones the root was mined over. Records are **sorted by
/// these canonical bytes** before hashing, giving one defined order every
/// producer and every re-validating node (reading nonce+anchor+signature from
/// the **prunable** side table at admission / pre-prune) reproduces
/// identically. Post-prune the **stored** root is trusted (mined into the
/// block hash); settlement never recomputes it.
///
/// The input type is [`PassRecord`]: miss-with-signature is unrepresentable.
/// Each signature is in its authoritative fixed-length canonical encoding
/// ([`HybridSignature::to_canonical_bytes`]), so a malformed (wrong-length)
/// signature is a loud [`CryptoError`], not a silent truncation.
///
/// **Defined-empty** (§3.2 invariant): an empty set hashes to the customization
/// over the bare count prefix, a fixed constant, so the leaf is never omitted
/// and the count never desyncs. That constant is genesis-frozen and did not
/// move when the record layout gained the nonce and anchor height.
pub fn attestation_root(records: &[PassRecord]) -> Result<[u8; 32], CryptoError> {
    const NONCE_END: usize = ATTESTATION_HEADER_LEN + PASS_NONCE_LEN;
    const ANCHOR_END: usize = NONCE_END + PASS_ANCHOR_HEIGHT_LEN;
    const RECORD_LEN: usize = ANCHOR_END + HybridSignature::CANONICAL_LEN;
    let mut record_bytes: Vec<[u8; RECORD_LEN]> = Vec::with_capacity(records.len());
    for record in records {
        let mut rec = [0u8; RECORD_LEN];
        rec[..ATTESTATION_HEADER_LEN].copy_from_slice(&record.to_header().to_canonical_bytes());
        rec[ATTESTATION_HEADER_LEN..NONCE_END].copy_from_slice(&record.nonce);
        rec[NONCE_END..ANCHOR_END].copy_from_slice(&record.anchor_height.to_le_bytes());
        rec[ANCHOR_END..].copy_from_slice(&record.signature.to_canonical_bytes()?);
        record_bytes.push(rec);
    }
    record_bytes.sort_unstable();

    let mut input = Vec::with_capacity(8 + records.len() * RECORD_LEN);
    input.extend_from_slice(&(records.len() as u64).to_le_bytes());
    for rec in &record_bytes {
        input.extend_from_slice(rec);
    }
    Ok(cshake256_32(ATTESTATION_ROOT_CUSTOMIZATION, &input))
}

/// Empty-set root: `attestation_root(&[])`. Infallibly the defined-empty
/// commitment a block header carries with no pass records (not the all-zero
/// hash). Prefer this over re-hexing the KAT pin at call sites.
#[inline]
pub fn empty_attestation_root() -> [u8; 32] {
    // No signatures to canonicalize; the empty path cannot fail.
    attestation_root(&[]).expect("empty attestation_root is infallible")
}

/// One witness entry: the nonce and anchor height a pass was signed over and
/// the signature. All three are prunable — none is in the block hash directly;
/// the mined [`attestation_root`] commits them paired with the kept header.
#[derive(Debug, Clone)]
pub struct PassWitness {
    pub nonce: [u8; PASS_NONCE_LEN],
    pub anchor_height: u64,
    pub signature: HybridSignature,
}

impl PassWitness {
    fn canonical_bytes_eq(&self, other: &Self) -> bool {
        self.nonce == other.nonce
            && self.anchor_height == other.anchor_height
            && self.signature.ed25519 == other.signature.ed25519
            && self.signature.ml_dsa == other.signature.ml_dsa
    }
}

/// The prunable, admission-only **attestation witness** for one block
/// (§3.2/§4, transport shape B2). It carries exactly the data the block *hash*
/// does not commit directly — each pass's carried nonce, anchor height, and
/// [`HybridSignature`] — transported **alongside** the block, stored only in
/// the height-keyed side table, and dropped after the retention horizon. It is
/// never in the block blob (which rides the never-pruned `blocks` store, so
/// blob-resident bytes cannot prune — the reason shape 1 was rejected). Its
/// integrity does not need the blob: [`attestation_root`] (the mined header
/// field) commits the header↔nonce↔anchor↔signature set, and admission
/// recomputes it over these entries paired with the kept `tx_extra` headers.
///
/// # The pairing rule (consensus — pinned here because the block-hash
/// differential is structurally blind to it)
///
/// The block-hash / C++↔Rust differential cannot see this witness (it is not in
/// the hash), so the entry↔header pairing must be stated, not inferred:
/// `passes[i]` is the nonce+anchor+countersignature for the **i-th pass
/// header** — the kept `tx_extra` headers filtered to `kind = Pass`, in
/// `tx_extra` order. Miss headers consume no entry.
/// [`pass_records_from_headers_and_witness`] is the single executable statement
/// of this zip; both producer and validator go through it so the rule cannot
/// drift between call sites. A pass-header / entry **count** mismatch is a loud
/// error (a block-validity failure at admission); any *content* pairing
/// disagreement instead surfaces as an `attestation_root` mismatch
/// (self-enforcing).
#[derive(Debug, Clone)]
pub struct BlockAttestationWitness {
    /// One entry per pass header, in `tx_extra` pass order.
    pub passes: Vec<PassWitness>,
}

// HybridSignature is not `PartialEq`; compare canonical field bytes. Two
// witnesses are equal iff every paired entry's nonce, anchor height, and
// `(ed25519, ml_dsa)` bytes match — enough for round-trip assertions without
// widening the crypto type's derives.
impl PartialEq for BlockAttestationWitness {
    fn eq(&self, other: &Self) -> bool {
        self.passes.len() == other.passes.len()
            && self
                .passes
                .iter()
                .zip(&other.passes)
                .all(|(a, b)| a.canonical_bytes_eq(b))
    }
}
impl Eq for BlockAttestationWitness {}

/// A witness blob failed to decode/encode, or declared a record count out of range.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    /// Shorter than the fixed `count(8)` prefix ([`WITNESS_PREFIX_LEN`]).
    #[error(
        "attestation witness shorter than the {WITNESS_PREFIX_LEN}-byte count prefix: got {0}"
    )]
    TooShort(usize),
    /// The declared (or encode-side) count exceeds [`MAX_ATTESTATION_RECORDS`].
    /// Checked **before** any length arithmetic on decode, so it also caps the
    /// allocation and rules out a `count · WITNESS_ENTRY_LEN` overflow. Held as
    /// the raw wire `u64` — the value may not fit `usize` on a 32-bit target,
    /// which is itself a reason to reject.
    #[error("attestation witness count {0} exceeds cap {MAX_ATTESTATION_RECORDS}")]
    CountExceedsCap(u64),
    /// Total length is not exactly
    /// `WITNESS_PREFIX_LEN + count · WITNESS_ENTRY_LEN`.
    #[error("attestation witness length {got}, expected {expected} for {count} entry(ies)")]
    LengthMismatch {
        count: usize,
        expected: usize,
        got: usize,
    },
    /// The `index`-th entry's signature failed canonical encode/decode.
    #[error("attestation witness signature {index} invalid: {source}")]
    Signature {
        index: usize,
        #[source]
        source: CryptoError,
    },
}

impl BlockAttestationWitness {
    /// Canonical bytes:
    /// `count_le(8) ‖ (nonce(32) ‖ anchor_height_le(8) ‖ signature)[0..count]`,
    /// each signature in [`HybridSignature::to_canonical_bytes`] (fixed
    /// [`HybridSignature::CANONICAL_LEN`]), so every entry is exactly
    /// [`WITNESS_ENTRY_LEN`]. This is the exact byte stream carried alongside
    /// the block and pinned by the cross-language witness KAT — the `count`
    /// prefix mirrors [`attestation_root`]'s `u64`-LE length prefix so the two
    /// encodings share one integer convention.
    ///
    /// Rejects an entry count above [`MAX_ATTESTATION_RECORDS`] (same cap as
    /// decode) so an over-cap producer cannot emit a blob the decoder would
    /// refuse — encode and decode share one validity surface.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, WitnessError> {
        let count = self.passes.len();
        if count > MAX_ATTESTATION_RECORDS {
            return Err(WitnessError::CountExceedsCap(count as u64));
        }
        let mut out = Vec::with_capacity(WITNESS_PREFIX_LEN + count * WITNESS_ENTRY_LEN);
        out.extend_from_slice(&(count as u64).to_le_bytes());
        for (index, entry) in self.passes.iter().enumerate() {
            let sig = entry
                .signature
                .to_canonical_bytes()
                .map_err(|source| WitnessError::Signature { index, source })?;
            debug_assert_eq!(sig.len(), HybridSignature::CANONICAL_LEN);
            out.extend_from_slice(&entry.nonce);
            out.extend_from_slice(&entry.anchor_height.to_le_bytes());
            out.extend_from_slice(&sig);
        }
        Ok(out)
    }

    /// Decode a witness blob. Rejects a short prefix, an over-cap count (before
    /// allocating), a total length that is not an exact `count`-many entries,
    /// and any malformed signature — all loud, because a malformed witness is a
    /// block-validity failure at admission, never a silent default.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() < WITNESS_PREFIX_LEN {
            return Err(WitnessError::TooShort(bytes.len()));
        }
        let count_u64 =
            u64::from_le_bytes(bytes[0..WITNESS_PREFIX_LEN].try_into().expect("8 bytes"));
        // Cap BEFORE the length multiply: bounds the allocation and forecloses a
        // `count · WITNESS_ENTRY_LEN` overflow on a hostile count. Compared in
        // u64 so the check itself never truncates on a 32-bit target.
        if count_u64 > MAX_ATTESTATION_RECORDS as u64 {
            return Err(WitnessError::CountExceedsCap(count_u64));
        }
        // ≤ MAX_ATTESTATION_RECORDS now, so this narrowing is infallible on every
        // target width (the cap fits every usize).
        let count = usize::try_from(count_u64).expect("count ≤ cap fits usize");
        let expected = WITNESS_PREFIX_LEN + count * WITNESS_ENTRY_LEN;
        if bytes.len() != expected {
            return Err(WitnessError::LengthMismatch {
                count,
                expected,
                got: bytes.len(),
            });
        }
        let mut passes = Vec::with_capacity(count);
        for index in 0..count {
            let start = WITNESS_PREFIX_LEN + index * WITNESS_ENTRY_LEN;
            let nonce_end = start + PASS_NONCE_LEN;
            let anchor_end = nonce_end + PASS_ANCHOR_HEIGHT_LEN;
            let end = start + WITNESS_ENTRY_LEN;
            let mut nonce = [0u8; PASS_NONCE_LEN];
            nonce.copy_from_slice(&bytes[start..nonce_end]);
            let anchor_height =
                u64::from_le_bytes(bytes[nonce_end..anchor_end].try_into().expect("8 bytes"));
            let signature = HybridSignature::from_canonical_bytes(&bytes[anchor_end..end])
                .map_err(|source| WitnessError::Signature { index, source })?;
            passes.push(PassWitness {
                nonce,
                anchor_height,
                signature,
            });
        }
        Ok(Self { passes })
    }
}

/// The kept pass headers and the witness entries disagreed on count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("attestation pairing count mismatch: {pass_headers} pass header(s) vs {signatures} witness entry(ies)")]
pub struct WitnessPairingError {
    pub pass_headers: usize,
    pub signatures: usize,
}

/// Reconstruct the block's [`PassRecord`] set by zipping the kept **pass**
/// headers with the witness entries — the single executable statement of the
/// §3.2 pairing rule. `headers` is the full kept set (pass **and** miss, in
/// `tx_extra` order); it is filtered to `kind = Pass` and zipped positionally
/// with `witness.passes`. Both admission's `attestation_root` recompute and any
/// later re-check call this, so the pairing cannot drift between sites. A
/// pass-header / entry count mismatch is a [`WitnessPairingError`] (a
/// block-validity failure).
pub fn pass_records_from_headers_and_witness(
    headers: &[AttestationHeader],
    witness: &BlockAttestationWitness,
) -> Result<Vec<PassRecord>, WitnessPairingError> {
    let pass: Vec<&AttestationHeader> = headers
        .iter()
        .filter(|h| h.kind == AttestationKind::Pass)
        .collect();
    if pass.len() != witness.passes.len() {
        return Err(WitnessPairingError {
            pass_headers: pass.len(),
            signatures: witness.passes.len(),
        });
    }
    Ok(pass
        .into_iter()
        .zip(&witness.passes)
        .map(|(h, entry)| PassRecord {
            p_id: h.p_id,
            shard_id: h.shard_id,
            settlement_epoch: h.settlement_epoch,
            nonce: entry.nonce,
            anchor_height: entry.anchor_height,
            signature: entry.signature.clone(),
        })
        .collect())
}

/// Why one pass record's countersignature was refused at admission — three
/// typed classes, because the FFI reports each as a distinct verdict and the
/// diagnostics differ: a wrong `p_id` and a bad signature are forgery signals,
/// an out-of-window anchor is a stale or pre-fetched read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PassCountersignatureError {
    /// The record's `p_id` is not the supplied pubkey's canonical id.
    #[error("pass record p_id is not the supplied pubkey's canonical id")]
    PIdMismatch,
    /// The carried `anchor_height` lies outside the block's window
    /// `[first, last]` — no hash to check against, so no signature is
    /// evaluated.
    #[error("pass anchor height {anchor_height} outside admission window [{first}, {last}]")]
    AnchorOutOfWindow {
        anchor_height: u64,
        first: u64,
        last: u64,
    },
    /// `P`'s hybrid signature does not verify over the transcript built from
    /// the record and the connecting chain's hash at its anchor height.
    #[error("pass countersignature does not verify")]
    InvalidSignature,
}

/// Verify one **pass** record's countersignature at admission (§3.3 step b).
///
/// Three bindings, all self-contained so no correctness rides on the caller:
///
/// 1. **`p_id` binds the key.** The record's `p_id` must be *this pubkey's*
///    canonical id ([`p_canonical_id_from_hybrid_pubkey`]).
/// 2. **The anchor is in the window.** The record's `anchor_height` must lie in
///    `window.heights()` — `[h − depth − L, h − depth]` for the connecting
///    block's predecessor `h`. Outside it there is no chain hash to check
///    against; the record is refused before any signature work.
/// 3. **The signature covers `header ‖ shard_id`.** Build
///    [`PassRecord::countersignature_message`] from the carried nonce and
///    anchor height, the **connecting chain's** hash at that height
///    ([`PassAnchorWindow::hash_at`]), and the record's `shard_id`, and check
///    `P`'s hybrid countersignature over it under the v2 domain. A signature
///    `P` made over a different anchor hash (a fabricated one, or a fork's),
///    or over a different shard, or over a nonce other than the one carried,
///    fails here.
///
/// `window` must be filled from the chain the block is actually being
/// connected to (alt chain above the fork point included), from its
/// **validated** predecessor height — never from a header-claimed value.
///
/// Kind is not checked: a miss cannot be a [`PassRecord`].
pub fn verify_pass_countersignature(
    window: &PassAnchorWindow,
    p_pubkey: &HybridPublicKey,
    record: &PassRecord,
) -> Result<(), PassCountersignatureError> {
    // Binding 1: the record's p_id must be this pubkey's canonical id.
    let pubkey_bytes = p_pubkey
        .to_canonical_bytes()
        .map_err(|_| PassCountersignatureError::PIdMismatch)?;
    if p_canonical_id_from_hybrid_pubkey(&pubkey_bytes).as_bytes() != &record.p_id {
        return Err(PassCountersignatureError::PIdMismatch);
    }
    // Binding 2: the anchor height must be one the window holds a hash for.
    let heights = window.heights();
    let anchor_hash = window.hash_at(record.anchor_height).ok_or(
        PassCountersignatureError::AnchorOutOfWindow {
            anchor_height: record.anchor_height,
            first: heights.first(),
            last: heights.last(),
        },
    )?;
    // Binding 3: P's countersignature over the SF-D8 transcript with the
    // chain's hash, not any caller's.
    let message = record.countersignature_message(anchor_hash);
    HybridEd25519MlDsa
        .verify(
            p_pubkey,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION,
            &message,
            &record.signature,
        )
        .map_err(|_| PassCountersignatureError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_crypto_pq::signature::HybridSecretKey;

    /// A predecessor height comfortably above the genesis threshold; its
    /// window is `[H − 724, H − 720]` = `[4276, 4280]` at the pinned constants.
    const H: u64 = 5000;

    fn keypair() -> (HybridPublicKey, HybridSecretKey) {
        HybridEd25519MlDsa
            .generate_ephemeral_keypair_for_tests()
            .expect("keypair generates")
    }

    /// Sign under the attestation surface domain (SA-R-2) — one place so
    /// the domain cannot drift across the many structural tests below.
    fn att_sign(sk: &HybridSecretKey, msg: &[u8]) -> HybridSignature {
        HybridEd25519MlDsa
            .sign(
                sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION,
                msg,
            )
            .expect("attestation sign")
    }

    /// This pubkey's canonical id — the value the record's `p_id` must equal.
    fn p_id_of(pubkey: &HybridPublicKey) -> [u8; 32] {
        let bytes = pubkey.to_canonical_bytes().expect("canonical pubkey");
        *p_canonical_id_from_hybrid_pubkey(&bytes).as_bytes()
    }

    /// A deterministic stand-in for "the chain's hash at `height`" so every
    /// window in these tests agrees on what each height hashes to.
    fn chain_hash(height: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&height.to_le_bytes());
        h[8] = 0xC4;
        h
    }

    /// The window a block connecting to predecessor `predecessor_height` sees,
    /// filled from `chain_hash`.
    fn window_at(predecessor_height: u64) -> PassAnchorWindow {
        let heights = PassAnchorHeights::for_predecessor(predecessor_height).expect("window");
        PassAnchorWindow::new(
            predecessor_height,
            (heights.first()..=heights.last()).map(chain_hash).collect(),
        )
        .expect("table sized to the window")
    }

    fn pass_record(
        p_id: [u8; 32],
        shard_id: u64,
        settlement_epoch: u64,
        nonce: [u8; PASS_NONCE_LEN],
        anchor_height: u64,
        signature: HybridSignature,
    ) -> PassRecord {
        PassRecord {
            p_id,
            shard_id,
            settlement_epoch,
            nonce,
            anchor_height,
            signature,
        }
    }

    /// A pass record signed correctly by `sk` for `(nonce, anchor, shard)` with
    /// the anchor hash the chain holds at `anchor_height`.
    fn signed_pass(
        sk: &HybridSecretKey,
        p_id: [u8; 32],
        nonce: [u8; PASS_NONCE_LEN],
        anchor_height: u64,
        shard_id: u64,
        settlement_epoch: u64,
    ) -> PassRecord {
        let sig = att_sign(
            sk,
            &pass_countersignature_message(
                &nonce,
                anchor_height,
                &chain_hash(anchor_height),
                shard_id,
            ),
        );
        pass_record(p_id, shard_id, settlement_epoch, nonce, anchor_height, sig)
    }

    #[test]
    fn header_bytes_roundtrip_and_reject_malformed() {
        for kind in [AttestationKind::Pass, AttestationKind::Miss] {
            let h = AttestationHeader {
                p_id: [7u8; 32],
                shard_id: 42,
                settlement_epoch: 1000,
                kind,
            };
            let bytes = h.to_canonical_bytes();
            assert_eq!(bytes.len(), ATTESTATION_HEADER_LEN);
            assert_eq!(AttestationHeader::from_canonical_bytes(&bytes), Ok(h));
        }
        // Wrong length and a bad kind byte are loud errors, not silent defaults.
        assert_eq!(
            AttestationHeader::from_canonical_bytes(&[0u8; 10]),
            Err(AttestationHeaderError::WrongLength(10))
        );
        let mut bad = AttestationHeader {
            p_id: [7u8; 32],
            shard_id: 42,
            settlement_epoch: 1000,
            kind: AttestationKind::Pass,
        }
        .to_canonical_bytes();
        bad[48] = 2;
        assert_eq!(
            AttestationHeader::from_canonical_bytes(&bad),
            Err(AttestationHeaderError::BadKind(2))
        );
    }

    #[test]
    fn pass_record_to_header_is_always_pass() {
        // Structural seam: PassRecord cannot carry Miss; wire kind is Pass.
        let (_pk, sk) = keypair();
        let sig = att_sign(&sk, b"x");
        let rec = pass_record([1u8; 32], 2, 3, [0u8; 32], 4, sig);
        assert_eq!(rec.to_header().kind, AttestationKind::Pass);
    }

    #[test]
    fn request_header_and_message_are_the_pinned_concatenation() {
        // nonce ‖ anchor_height_le ‖ anchor_hash, then ‖ shard_le — every term
        // at its position, no hashing.
        let nonce = [0xAAu8; 32];
        let hash = [0xBBu8; 32];
        let header = pass_request_header_bytes(&nonce, 0x0102_0304_0506_0708, &hash);
        assert_eq!(header.len(), PASS_REQUEST_HEADER_LEN);
        assert_eq!(&header[..32], &nonce);
        assert_eq!(
            &header[32..40],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&header[40..72], &hash);

        let msg = pass_countersignature_message(
            &nonce,
            0x0102_0304_0506_0708,
            &hash,
            0x1112_1314_1516_1718,
        );
        assert_eq!(msg.len(), PASS_COUNTERSIGNATURE_MESSAGE_LEN);
        assert_eq!(
            &msg[..72],
            &header,
            "the transcript starts with the decoded header"
        );
        assert_eq!(
            &msg[72..80],
            &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
        // Every term is live: changing any one changes the message.
        assert_ne!(
            msg,
            pass_countersignature_message(
                &[0xABu8; 32],
                0x0102_0304_0506_0708,
                &hash,
                0x1112_1314_1516_1718
            )
        );
        assert_ne!(
            msg,
            pass_countersignature_message(&nonce, 1, &hash, 0x1112_1314_1516_1718)
        );
        assert_ne!(
            msg,
            pass_countersignature_message(
                &nonce,
                0x0102_0304_0506_0708,
                &[0xBCu8; 32],
                0x1112_1314_1516_1718
            )
        );
        assert_ne!(
            msg,
            pass_countersignature_message(&nonce, 0x0102_0304_0506_0708, &hash, 1)
        );
    }

    #[test]
    fn pass_record_message_matches_free_function() {
        let (_pk, sk) = keypair();
        let sig = att_sign(&sk, b"n");
        let rec = pass_record([3u8; 32], 4, 5, [9u8; 32], 77, sig);
        let hash = [0xDDu8; 32];
        assert_eq!(
            rec.countersignature_message(&hash),
            pass_countersignature_message(&rec.nonce, 77, &hash, rec.shard_id)
        );
    }

    #[test]
    fn anchor_window_heights_are_depth_and_lag_below_the_predecessor() {
        assert_eq!(PASS_ANCHOR_DEPTH_BLOCKS, 720);
        assert_eq!(PASS_ANCHOR_LAG_BLOCKS, 4);
        assert_eq!(PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT, 724);
        assert_eq!(PASS_ANCHOR_WINDOW_LEN, 5);

        let w = PassAnchorHeights::for_predecessor(H).unwrap();
        assert_eq!((w.first(), w.last()), (H - 724, H - 720));
        assert_eq!(w.len(), 5);
        assert!(!w.is_empty());
        // The one indexed lookup: anchor − first, None outside.
        assert_eq!(w.index_of(H - 724), Some(0));
        assert_eq!(w.index_of(H - 720), Some(4));
        assert_eq!(w.index_of(H - 725), None);
        assert_eq!(w.index_of(H - 719), None);

        // Genesis boundary: 723 has no window; 724 is the first with one, and
        // it bottoms out at height 0.
        assert_eq!(PassAnchorHeights::for_predecessor(723), None);
        let first = PassAnchorHeights::for_predecessor(724).unwrap();
        assert_eq!((first.first(), first.last()), (0, 4));
        assert_eq!(PassAnchorHeights::for_predecessor(0), None);
    }

    #[test]
    fn anchor_window_table_must_match_the_window_exactly() {
        assert_eq!(
            PassAnchorWindow::new(723, vec![[0u8; 32]; 5]).unwrap_err(),
            PassAnchorWindowError::BelowThreshold {
                predecessor_height: 723
            }
        );
        assert_eq!(
            PassAnchorWindow::new(H, vec![[0u8; 32]; 4]).unwrap_err(),
            PassAnchorWindowError::WrongLength {
                expected: 5,
                got: 4
            }
        );
        assert_eq!(
            PassAnchorWindow::new(H, vec![[0u8; 32]; 6]).unwrap_err(),
            PassAnchorWindowError::WrongLength {
                expected: 5,
                got: 6
            }
        );
        let w = window_at(H);
        assert_eq!(w.hash_at(H - 724), Some(&chain_hash(H - 724)));
        assert_eq!(w.hash_at(H - 720), Some(&chain_hash(H - 720)));
        assert_eq!(w.hash_at(H - 719), None);
    }

    #[test]
    fn a_valid_countersignature_verifies_and_a_wrong_key_or_term_fails() {
        let (pubkey, secret) = keypair();
        let p_id = p_id_of(&pubkey);
        let nonce = [0x11u8; 32];
        let anchor = H - 720; // the requester's tip − depth for a block at H + 1
        let rec = signed_pass(&secret, p_id, nonce, anchor, 42, 1000);
        let w = window_at(H);

        assert_eq!(verify_pass_countersignature(&w, &pubkey, &rec), Ok(()));

        // A different shard term: the server-side shard binding.
        let mut other = rec.clone();
        other.shard_id = 43;
        assert_eq!(
            verify_pass_countersignature(&w, &pubkey, &other),
            Err(PassCountersignatureError::InvalidSignature)
        );
        // A different carried nonce than the one signed over.
        let mut swapped_nonce = rec.clone();
        swapped_nonce.nonce = [0x22u8; 32];
        assert_eq!(
            verify_pass_countersignature(&w, &pubkey, &swapped_nonce),
            Err(PassCountersignatureError::InvalidSignature)
        );
        // A different carried anchor height INSIDE the window: the chain's hash
        // at that height is not the one signed over, so the signature fails —
        // the height is bound through the hash the verifier supplies.
        let mut moved_anchor = rec.clone();
        moved_anchor.anchor_height = anchor - 1;
        assert_eq!(
            verify_pass_countersignature(&w, &pubkey, &moved_anchor),
            Err(PassCountersignatureError::InvalidSignature)
        );
        // Settlement epoch is NOT in the signed message (it is a kept-header
        // term the root commits); changing it does not touch the signature.
        let mut other_epoch = rec.clone();
        other_epoch.settlement_epoch = 1001;
        assert_eq!(
            verify_pass_countersignature(&w, &pubkey, &other_epoch),
            Ok(())
        );

        // Binding 1 in isolation: a record whose p_id is NOT this key's id fails
        // even when the signature covers that record's own message.
        let foreign = signed_pass(&secret, [0xABu8; 32], nonce, anchor, 42, 1000);
        assert_eq!(
            verify_pass_countersignature(&w, &pubkey, &foreign),
            Err(PassCountersignatureError::PIdMismatch)
        );
    }

    /// The requester supplies the anchor hash to `P`, so a requester who lies
    /// about it gets a signature over a hash the chain never had — refused
    /// against the real one. This is what makes the hash term unforgeable
    /// while `P` stays chain-blind.
    #[test]
    fn a_fabricated_anchor_hash_fails_against_the_chains_hash() {
        let (pubkey, secret) = keypair();
        let p_id = p_id_of(&pubkey);
        let anchor = H - 722;
        let lied = att_sign(
            &secret,
            &pass_countersignature_message(&[0x55u8; 32], anchor, &[0xFFu8; 32], 42),
        );
        let rec = pass_record(p_id, 42, 1000, [0x55u8; 32], anchor, lied);
        assert_eq!(
            verify_pass_countersignature(&window_at(H), &pubkey, &rec),
            Err(PassCountersignatureError::InvalidSignature)
        );
    }

    /// The window is `[h − depth − L, h − depth]`, both ends inclusive: an
    /// anchor at either bound verifies, one past either bound is refused
    /// before any signature is evaluated. The same record is therefore valid
    /// at `L + 1` consecutive predecessor heights — the accepted replay
    /// window — and at none outside them.
    #[test]
    fn anchor_window_bounds_are_inclusive_and_out_of_window_is_typed() {
        let (pubkey, secret) = keypair();
        let p_id = p_id_of(&pubkey);
        let w = window_at(H);
        let heights = w.heights();

        for anchor in [heights.first(), heights.last()] {
            let rec = signed_pass(&secret, p_id, [0x66u8; 32], anchor, 7, 1000);
            assert_eq!(verify_pass_countersignature(&w, &pubkey, &rec), Ok(()));
        }
        for anchor in [heights.first() - 1, heights.last() + 1] {
            let rec = signed_pass(&secret, p_id, [0x66u8; 32], anchor, 7, 1000);
            assert_eq!(
                verify_pass_countersignature(&w, &pubkey, &rec),
                Err(PassCountersignatureError::AnchorOutOfWindow {
                    anchor_height: anchor,
                    first: heights.first(),
                    last: heights.last(),
                })
            );
        }

        // One record, anchored at A = H − 720, across connecting heights: valid
        // for predecessors H ..= H + L (A stays inside the sliding window),
        // refused at H − 1 (A above the upper bound — a pre-fetched read) and
        // at H + L + 1 (A below the lower bound — stale).
        let anchor = H - 720;
        let rec = signed_pass(&secret, p_id, [0x77u8; 32], anchor, 7, 1000);
        for h in H..=H + PASS_ANCHOR_LAG_BLOCKS {
            assert_eq!(
                verify_pass_countersignature(&window_at(h), &pubkey, &rec),
                Ok(()),
                "anchor {anchor} must verify at predecessor {h}"
            );
        }
        assert!(matches!(
            verify_pass_countersignature(&window_at(H - 1), &pubkey, &rec),
            Err(PassCountersignatureError::AnchorOutOfWindow { .. })
        ));
        assert!(matches!(
            verify_pass_countersignature(&window_at(H + PASS_ANCHOR_LAG_BLOCKS + 1), &pubkey, &rec),
            Err(PassCountersignatureError::AnchorOutOfWindow { .. })
        ));
    }

    /// The dishonest-witness replay the shard term exists to close: a valid
    /// countersignature `P` made for shard 42 must not verify as a pass over
    /// shard 43 even with the same header terms carried.
    #[test]
    fn a_signature_over_one_shard_cannot_be_replayed_against_another() {
        let (pubkey, secret) = keypair();
        let p_id = p_id_of(&pubkey);
        let nonce = [0x33u8; 32];
        let anchor = H - 721;
        let served = signed_pass(&secret, p_id, nonce, anchor, 42, 1000);
        let replayed = pass_record(p_id, 43, 1000, nonce, anchor, served.signature.clone());
        let w = window_at(H);
        assert_eq!(verify_pass_countersignature(&w, &pubkey, &served), Ok(()));
        assert_eq!(
            verify_pass_countersignature(&w, &pubkey, &replayed),
            Err(PassCountersignatureError::InvalidSignature)
        );
    }

    /// The v1 domain is retired, not aliased: a signature under the v1 string
    /// over the v2 message must not verify.
    #[test]
    fn v1_domain_signature_does_not_verify_under_v2() {
        let (pubkey, secret) = keypair();
        let p_id = p_id_of(&pubkey);
        let nonce = [0x44u8; 32];
        let anchor = H - 720;
        let msg = pass_countersignature_message(&nonce, anchor, &chain_hash(anchor), 42);
        let v1_sig = HybridEd25519MlDsa
            .sign(&secret, b"shekyl/archival-attestation-scheme-v1", &msg)
            .expect("sign");
        let rec = pass_record(p_id, 42, 1000, nonce, anchor, v1_sig);
        assert_eq!(
            verify_pass_countersignature(&window_at(H), &pubkey, &rec),
            Err(PassCountersignatureError::InvalidSignature)
        );
        assert_eq!(
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION,
            b"shekyl/archival-attestation-scheme-v2"
        );
    }

    #[test]
    fn attestation_root_is_defined_empty_order_independent_and_pairing_committed() {
        // Defined-empty (§3.2 invariant): the empty set has a fixed root, never
        // omitted, so the merkle leaf and count never desync.
        let empty = attestation_root(&[]).unwrap();
        assert_eq!(empty, attestation_root(&[]).unwrap());

        let (_pk, sk) = keypair();
        let s1 = att_sign(&sk, b"a");
        let s2 = att_sign(&sk, b"b");
        let (n1, n2) = ([1u8; 32], [2u8; 32]);
        let (a1, a2) = (4276u64, 4277u64);
        let r1 = pass_record([7u8; 32], 42, 1000, n1, a1, s1.clone());
        let r2 = pass_record([7u8; 32], 43, 1000, n2, a2, s2.clone());

        // A non-empty set differs from empty.
        assert_ne!(attestation_root(std::slice::from_ref(&r1)).unwrap(), empty);

        // ORDER-INDEPENDENT: the internal sort yields one canonical order.
        let ab = attestation_root(&[r1.clone(), r2.clone()]).unwrap();
        let ba = attestation_root(&[r2.clone(), r1.clone()]).unwrap();
        assert_eq!(ab, ba);

        // PAIRING IS COMMITTED: swapping which signature rides which terms
        // changes the root.
        let swapped = attestation_root(&[
            pass_record(
                r1.p_id,
                r1.shard_id,
                r1.settlement_epoch,
                n1,
                a1,
                s2.clone(),
            ),
            pass_record(
                r2.p_id,
                r2.shard_id,
                r2.settlement_epoch,
                n2,
                a2,
                s1.clone(),
            ),
        ])
        .unwrap();
        assert_ne!(ab, swapped);

        // THE NONCE IS COMMITTED: the same header+anchor+signature set with the
        // nonces swapped is a different root, so a witness cannot transport a
        // nonce other than the one the root was mined over.
        let nonce_swapped = attestation_root(&[
            pass_record(
                r1.p_id,
                r1.shard_id,
                r1.settlement_epoch,
                n2,
                a1,
                s1.clone(),
            ),
            pass_record(
                r2.p_id,
                r2.shard_id,
                r2.settlement_epoch,
                n1,
                a2,
                s2.clone(),
            ),
        ])
        .unwrap();
        assert_ne!(ab, nonce_swapped);

        // THE ANCHOR HEIGHT IS COMMITTED, for the same reason.
        let anchor_swapped = attestation_root(&[
            pass_record(r1.p_id, r1.shard_id, r1.settlement_epoch, n1, a2, s1),
            pass_record(r2.p_id, r2.shard_id, r2.settlement_epoch, n2, a1, s2),
        ])
        .unwrap();
        assert_ne!(ab, anchor_swapped);
    }

    #[test]
    fn witness_roundtrips_including_empty() {
        let (_pk, sk) = keypair();
        let s0 = att_sign(&sk, b"w0");
        let s1 = att_sign(&sk, b"w1");
        let w = BlockAttestationWitness {
            passes: vec![
                PassWitness {
                    nonce: [5u8; 32],
                    anchor_height: 0x0102_0304_0506_0708,
                    signature: s0,
                },
                PassWitness {
                    nonce: [6u8; 32],
                    anchor_height: 4277,
                    signature: s1,
                },
            ],
        };
        let bytes = w.to_canonical_bytes().unwrap();
        // Layout: count_le(8) ‖ 2 × (nonce(32) ‖ anchor_le(8) ‖ CANONICAL_LEN).
        assert_eq!(bytes.len(), WITNESS_PREFIX_LEN + 2 * WITNESS_ENTRY_LEN);
        assert_eq!(&bytes[0..WITNESS_PREFIX_LEN], &2u64.to_le_bytes());
        assert_eq!(
            &bytes[WITNESS_PREFIX_LEN..WITNESS_PREFIX_LEN + PASS_NONCE_LEN],
            &[5u8; 32]
        );
        assert_eq!(
            &bytes[WITNESS_PREFIX_LEN + PASS_NONCE_LEN..WITNESS_PREFIX_LEN + PASS_NONCE_LEN + 8],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            "anchor height is little-endian after the nonce"
        );
        assert_eq!(
            BlockAttestationWitness::from_canonical_bytes(&bytes).unwrap(),
            w
        );

        // Codec-defined-empty: a zero-entry witness is still a valid
        // `count=0` encoding. That is distinct from the C++ side-table
        // convention, which skips writing a row for empty/absent witnesses
        // (interim / all-miss blocks store nothing; absent key ≡ no witness).
        let empty = BlockAttestationWitness { passes: vec![] };
        let eb = empty.to_canonical_bytes().unwrap();
        assert_eq!(eb.len(), WITNESS_PREFIX_LEN);
        assert_eq!(
            BlockAttestationWitness::from_canonical_bytes(&eb).unwrap(),
            empty
        );
    }

    #[test]
    fn witness_decode_rejects_malformed() {
        let (_pk, sk) = keypair();
        let s0 = att_sign(&sk, b"w");
        let good = BlockAttestationWitness {
            passes: vec![PassWitness {
                nonce: [0u8; 32],
                anchor_height: 1,
                signature: s0,
            }],
        }
        .to_canonical_bytes()
        .unwrap();
        const SIG_START: usize = WITNESS_PREFIX_LEN + PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN;

        // Short prefix.
        assert!(matches!(
            BlockAttestationWitness::from_canonical_bytes(&[0u8; WITNESS_PREFIX_LEN - 1]),
            Err(WitnessError::TooShort(n)) if n == WITNESS_PREFIX_LEN - 1
        ));

        // Declares one entry, carries none.
        let mut short_body = Vec::new();
        short_body.extend_from_slice(&1u64.to_le_bytes());
        assert!(matches!(
            BlockAttestationWitness::from_canonical_bytes(&short_body),
            Err(WitnessError::LengthMismatch {
                count: 1,
                got: WITNESS_PREFIX_LEN,
                ..
            })
        ));

        // The two superseded entry shapes — signature alone (pre-SF-D8) and
        // nonce ‖ signature (the withdrawn #734 cut) — are length mismatches,
        // not silently re-framed entries.
        for skip in [
            PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN,
            PASS_ANCHOR_HEIGHT_LEN,
        ] {
            let mut stale = Vec::new();
            stale.extend_from_slice(&1u64.to_le_bytes());
            stale.extend_from_slice(&good[WITNESS_PREFIX_LEN + skip..]);
            assert!(matches!(
                BlockAttestationWitness::from_canonical_bytes(&stale),
                Err(WitnessError::LengthMismatch { count: 1, .. })
            ));
        }

        // Over-cap count is rejected before allocating — a hostile u64 cannot
        // trigger a `count · WITNESS_ENTRY_LEN` reservation.
        let mut over = Vec::new();
        over.extend_from_slice(&((MAX_ATTESTATION_RECORDS as u64) + 1).to_le_bytes());
        assert!(matches!(
            BlockAttestationWitness::from_canonical_bytes(&over),
            Err(WitnessError::CountExceedsCap(n)) if n == MAX_ATTESTATION_RECORDS as u64 + 1
        ));

        // Corrupt the first signature's leading version byte (after the nonce
        // and anchor height).
        let mut corrupt = good.clone();
        corrupt[SIG_START] ^= 0xFF;
        assert!(matches!(
            BlockAttestationWitness::from_canonical_bytes(&corrupt),
            Err(WitnessError::Signature { index: 0, .. })
        ));
    }

    #[test]
    fn witness_encode_rejects_over_cap() {
        let (_pk, sk) = keypair();
        let sig = att_sign(&sk, b"x");
        let over = BlockAttestationWitness {
            passes: vec![
                PassWitness {
                    nonce: [0u8; 32],
                    anchor_height: 0,
                    signature: sig,
                };
                MAX_ATTESTATION_RECORDS + 1
            ],
        };
        assert!(matches!(
            over.to_canonical_bytes(),
            Err(WitnessError::CountExceedsCap(n)) if n == (MAX_ATTESTATION_RECORDS as u64) + 1
        ));
    }

    #[test]
    fn pairing_zips_pass_headers_and_reproduces_the_root() {
        // Two pass records with a MISS interleaved: the witness holds only the
        // two pass entries, and the zip must skip the miss.
        let (pk, sk) = keypair();
        let p_id = p_id_of(&pk);
        let w = window_at(H);
        let (n_a, n_b) = ([0xA0u8; 32], [0xB0u8; 32]);
        let (a_a, a_b) = (H - 720, H - 723);
        let rec_a = signed_pass(&sk, p_id, n_a, a_a, 10, 1000);
        let rec_b = signed_pass(&sk, p_id, n_b, a_b, 20, 1000);

        let headers = vec![
            AttestationHeader {
                p_id,
                shard_id: 10,
                settlement_epoch: 1000,
                kind: AttestationKind::Pass,
            },
            AttestationHeader {
                p_id,
                shard_id: 99,
                settlement_epoch: 1000,
                kind: AttestationKind::Miss,
            },
            AttestationHeader {
                p_id,
                shard_id: 20,
                settlement_epoch: 1000,
                kind: AttestationKind::Pass,
            },
        ];
        let entry = |r: &PassRecord| PassWitness {
            nonce: r.nonce,
            anchor_height: r.anchor_height,
            signature: r.signature.clone(),
        };
        let witness = BlockAttestationWitness {
            passes: vec![entry(&rec_a), entry(&rec_b)],
        };

        let records = pass_records_from_headers_and_witness(&headers, &witness).unwrap();
        assert_eq!(records.len(), 2);
        // The reconstructed records carry the header terms and verify against
        // P (pairing landed correctly).
        assert_eq!((records[0].nonce, records[0].anchor_height), (n_a, a_a));
        assert_eq!((records[1].nonce, records[1].anchor_height), (n_b, a_b));
        for rec in &records {
            assert_eq!(verify_pass_countersignature(&w, &pk, rec), Ok(()));
        }
        // And their root matches the direct construction from the same tuples.
        let direct = attestation_root(&[rec_a.clone(), rec_b.clone()]).unwrap();
        assert_eq!(attestation_root(&records).unwrap(), direct);

        // A count mismatch (one pass header dropped from the witness) is loud.
        let short_witness = BlockAttestationWitness {
            passes: vec![entry(&rec_a)],
        };
        assert_eq!(
            pass_records_from_headers_and_witness(&headers, &short_witness).unwrap_err(),
            WitnessPairingError {
                pass_headers: 2,
                signatures: 1
            }
        );

        // PAIRING-SWAP NEGATIVE CONTROL: feeding the two entries in the wrong
        // order mis-binds each to the other's terms, so the recomputed root
        // differs — the property the cross-language KAT extends over the FFI.
        let swapped_witness = BlockAttestationWitness {
            passes: vec![entry(&rec_b), entry(&rec_a)],
        };
        let swapped = pass_records_from_headers_and_witness(&headers, &swapped_witness).unwrap();
        assert_ne!(attestation_root(&swapped).unwrap(), direct);
        // …and the mis-bound records no longer verify (shard term differs).
        assert!(swapped
            .iter()
            .all(|rec| verify_pass_countersignature(&w, &pk, rec).is_err()));
    }
}
