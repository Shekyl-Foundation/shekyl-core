// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Byte-exact `txin_archival_bond_post` wire (gate-4 §3.4.1).

use core::fmt;
use std::io::{self, Read, Write};

use shekyl_crypto_pq::multisig::SINGLE_KEY_CANONICAL_LEN;
use shekyl_curve_io::{read_byte, read_bytes, read_varint, write_varint};

/// Vin type tag: `txin_archival_bond_post` (gate-4 §3.4.1).
///
/// Dense genesis tag scheme (§2.0, PR #168): `0x03`. Must equal the C++ oracle's
/// `VARIANT_TAG(txin_archival_bond_post)` and shekyl-wire's `TAG_INPUT_BOND_POST`
/// — the same consensus discriminant.
pub const VIN_TYPE_ARCHIVAL_BOND_POST: u8 = 0x03;

/// Exact canonical single [`HybridPublicKey`] encoding length; matches
/// `config::PQC_HYBRID_SINGLE_KEY_LEN` in `cryptonote_config.h` (not multisig
/// blob). Stays 1996 even when multisig admits N>1: **pseudonym uniformity**
/// — all `bond_spend_pk` (P) values are the same shape; a bond commits
/// exactly one hybrid key so no bond is distinguishable by its controller's
/// structure. Anonymity constraint, not a bounds check. Rule-21 reopen:
/// only if P-set uniformity is abandoned. (Truncation ≠ shorter-valid is
/// also true — PR #229 — and incidental to that load-bearing reason.)
pub const HYBRID_PUBKEY_CANONICAL_BYTES: usize = SINGLE_KEY_CANONICAL_LEN;
pub const MAX_HOLDINGS_SHARDS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BondPostKind {
    JoinMarket = 0,
    Rebond = 1,
    Unbond = 2,
    HoldingsUpdate = 3,
}

impl BondPostKind {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            0 => Ok(Self::JoinMarket),
            1 => Ok(Self::Rebond),
            2 => Ok(Self::Unbond),
            3 => Ok(Self::HoldingsUpdate),
            _ => Err(WireError::InvalidPostKind(v)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HoldingsKind {
    ShardSetCompact = 0,
    CompleteTree = 1,
}

impl HoldingsKind {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            0 => Ok(Self::ShardSetCompact),
            1 => Ok(Self::CompleteTree),
            _ => Err(WireError::InvalidHoldingsKind(v)),
        }
    }
}

/// A bounded, duplicate-free list of held shard ids — the validated form of a
/// `ShardSetCompact` holdings' shard list (gate-4 §3.4.1).
///
/// Parse-don't-validate: the two structural invariants that were previously
/// carried by convention — each verify re-guarding, and `bond_floor` signalling
/// an invalid set with an in-band `0` (the same value the legitimate empty exit
/// shape returns) — are enforced once, at construction, so an invalid set is
/// unrepresentable past any decoder:
///
/// - **bounded**: `len <= MAX_HOLDINGS_SHARDS` (the codec cap);
/// - **duplicate-free**: a shard id appears at most once ("a set on the wire" —
///   previously rejected only inside the `HoldingsUpdate`/`Rebond` diffs and
///   silently tolerated by `JoinMarket`, which let `[7, 7]` bond `2·FLOOR` for
///   one shard).
///
/// **Insertion order is preserved** (ratified 2026-07-15): the §3.4.1 encoding
/// writes the ids in slice order, so a valid `ShardSet` encodes byte-identically
/// to the pre-newtype `Vec` — this change tightens *validity* (dupe-carrying
/// byte strings now reject at decode) without re-encoding any accepted tx. So
/// `[7, 42]` and `[42, 7]` remain distinct valid encodings of the same set;
/// benign, since holdings feed the signature preimage (only the signer produces
/// either, and only one connects).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ShardSet(Vec<u64>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardSetError {
    /// `len > MAX_HOLDINGS_SHARDS`.
    CountExceeded { got: usize },
    /// A shard id appears more than once.
    Duplicate { shard_id: u64 },
}

impl fmt::Display for ShardSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CountExceeded { got } => {
                write!(
                    f,
                    "shard count {got} exceeds the bound ({MAX_HOLDINGS_SHARDS})"
                )
            }
            Self::Duplicate { shard_id } => {
                write!(f, "shard id {shard_id} appears more than once")
            }
        }
    }
}

impl std::error::Error for ShardSetError {}

impl ShardSet {
    /// The one fallible constructor — every decoder / FFI marshal / builder
    /// routes through it. Enforces the bound and duplicate-freeness; preserves
    /// insertion order.
    pub fn new(ids: Vec<u64>) -> Result<Self, ShardSetError> {
        if ids.len() > MAX_HOLDINGS_SHARDS {
            return Err(ShardSetError::CountExceeded { got: ids.len() });
        }
        // Duplicate check on a sorted scratch copy — do NOT perturb the caller's
        // insertion order (that is the wire form). Bounded above, so the sort is
        // at most MAX_HOLDINGS_SHARDS elements.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        if let Some(pair) = sorted.windows(2).find(|w| w[0] == w[1]) {
            return Err(ShardSetError::Duplicate { shard_id: pair[0] });
        }
        Ok(Self(ids))
    }

    /// The empty set (`CompleteTree` carries none; the `Unbond` exit shape). The
    /// empty set is trivially bounded and duplicate-free.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Borrow the ids as a slice (also available through `Deref`).
    #[must_use]
    pub fn as_slice(&self) -> &[u64] {
        &self.0
    }

    /// Consume into the raw id vec — the `shekyl-wire` handoff (an independent
    /// oracle that owns its own bound/dupe checks).
    #[must_use]
    pub fn into_vec(self) -> Vec<u64> {
        self.0
    }
}

impl core::ops::Deref for ShardSet {
    type Target = [u64];
    fn deref(&self) -> &[u64] {
        &self.0
    }
}

impl TryFrom<Vec<u64>> for ShardSet {
    type Error = ShardSetError;
    fn try_from(ids: Vec<u64>) -> Result<Self, ShardSetError> {
        Self::new(ids)
    }
}

// Order-sensitive comparison against raw id lists — matches the wire form, for
// call sites and tests that assert a set equals expected ids.
impl PartialEq<[u64]> for ShardSet {
    fn eq(&self, other: &[u64]) -> bool {
        self.0 == other
    }
}

impl<const N: usize> PartialEq<[u64; N]> for ShardSet {
    fn eq(&self, other: &[u64; N]) -> bool {
        self.0.as_slice() == other.as_slice()
    }
}

impl PartialEq<Vec<u64>> for ShardSet {
    fn eq(&self, other: &Vec<u64>) -> bool {
        &self.0 == other
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldingsDescriptor {
    pub kind: HoldingsKind,
    pub shard_ids: ShardSet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivalBondPostVin {
    pub hybrid_public_key: Vec<u8>,
    pub p_canonical_id: [u8; 32],
    pub post_kind: BondPostKind,
    /// The GF-1 debit authorizer (gate-4 §4.1 `bond_spend_pk`, gate-6 §9.6),
    /// **JoinMarket-coupled on the wire** (§9.11, mirroring the `shekyl-wire`
    /// `BondPostKind::JoinMarket { bond_spend_pk }` oracle): present with the
    /// exact canonical single-key length iff `post_kind == JoinMarket` —
    /// committed once into the record at connect, immutable for the record's
    /// life, and the key every later `bond_debit` verifies against. `write`
    /// and `read_payload` enforce the coupling (a non-JoinMarket vin carrying
    /// one, or a JoinMarket vin without one, is unrepresentable on the wire).
    pub bond_spend_pk: Vec<u8>,
    pub holdings: HoldingsDescriptor,
    pub bonded_total_atomic: u64,
    pub bond_credit: u64,
    pub bond_debit: u64,
}

#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    UnknownVinType(u8),
    HybridPubkeyLenNotCanonical { got: usize },
    BondSpendPkLenNotCanonical { got: usize },
    BondSpendPkForbidden,
    HoldingsCountExceeded { got: usize },
    HoldingsDuplicateShard { shard_id: u64 },
    ShardListForbiddenForCompleteTree,
    InvalidPostKind(u8),
    InvalidHoldingsKind(u8),
    TrailingBytes,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::UnknownVinType(t) => write!(f, "unknown archival vin type {t}"),
            Self::HybridPubkeyLenNotCanonical { got } => {
                write!(
                    f,
                    "hybrid pubkey length {got} != canonical single-key length"
                )
            }
            Self::BondSpendPkLenNotCanonical { got } => {
                write!(
                    f,
                    "bond_spend_pk length {got} != canonical single-key length"
                )
            }
            Self::BondSpendPkForbidden => {
                write!(
                    f,
                    "bond_spend_pk is JoinMarket-coupled; other post kinds must not carry one"
                )
            }
            Self::HoldingsCountExceeded { got } => {
                write!(f, "holdings shard count {got} exceeds bound")
            }
            Self::HoldingsDuplicateShard { shard_id } => {
                write!(f, "holdings shard id {shard_id} appears more than once")
            }
            Self::ShardListForbiddenForCompleteTree => {
                write!(f, "CompleteTree must not carry shard ids on wire")
            }
            Self::InvalidPostKind(v) => write!(f, "invalid bond post_kind {v}"),
            Self::InvalidHoldingsKind(v) => write!(f, "invalid holdings kind {v}"),
            Self::TrailingBytes => write!(f, "trailing bytes after bond-post payload"),
        }
    }
}

impl std::error::Error for WireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ShardSetError> for WireError {
    fn from(e: ShardSetError) -> Self {
        match e {
            ShardSetError::CountExceeded { got } => Self::HoldingsCountExceeded { got },
            ShardSetError::Duplicate { shard_id } => Self::HoldingsDuplicateShard { shard_id },
        }
    }
}

/// Stream the §3.4.1 holdings encoding straight to a sink (no intermediate Vec).
/// Shared with the emission wire's `write()`; `encode_holdings_descriptor` wraps
/// this for callers that need the bytes (signature preimages / auth digests).
pub(crate) fn write_holdings_descriptor<W: Write>(
    w: &mut W,
    h: &HoldingsDescriptor,
) -> io::Result<()> {
    w.write_all(&[h.kind as u8])?;
    match h.kind {
        HoldingsKind::ShardSetCompact => {
            write_varint(&h.shard_ids.len(), w)?;
            for shard_id in h.shard_ids.iter() {
                write_varint(shard_id, w)?;
            }
        }
        HoldingsKind::CompleteTree => {}
    }
    Ok(())
}

/// Holdings section bytes for §3.4.1 signature preimage (kind byte + optional shard list).
pub fn encode_holdings_descriptor(h: &HoldingsDescriptor) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();
    write_holdings_descriptor(&mut out, h)?;
    Ok(out)
}

/// Read a [`HoldingsDescriptor`] (kind byte + optional shard list) — the §3.4.1
/// canonical holdings encoding. Shared with the emission vin
/// ([`crate::emission_wire`], §5.3 "must match bond record"), so the two wires
/// cannot drift on the holdings fragment.
pub fn read_holdings_descriptor<R: Read>(r: &mut R) -> Result<HoldingsDescriptor, WireError> {
    let kind = HoldingsKind::from_u8(read_byte(r)?)?;
    let shard_ids = match kind {
        HoldingsKind::ShardSetCompact => {
            let count: usize = read_varint(r)?;
            // Early bound-reject before allocating: a malicious count must not
            // drive a huge `with_capacity`. `ShardSet::new` re-checks the bound
            // (cheap once built) and adds the duplicate rejection.
            if count > MAX_HOLDINGS_SHARDS {
                return Err(WireError::HoldingsCountExceeded { got: count });
            }
            let mut ids = Vec::with_capacity(count);
            for _ in 0..count {
                ids.push(read_varint(r)?);
            }
            ShardSet::new(ids).map_err(WireError::from)?
        }
        HoldingsKind::CompleteTree => ShardSet::empty(),
    };
    Ok(HoldingsDescriptor { kind, shard_ids })
}

impl ArchivalBondPostVin {
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), WireError> {
        if self.hybrid_public_key.len() != HYBRID_PUBKEY_CANONICAL_BYTES {
            return Err(WireError::HybridPubkeyLenNotCanonical {
                got: self.hybrid_public_key.len(),
            });
        }
        // §9.11 coupling: JoinMarket carries the exact-canonical-length key;
        // every other kind must not carry one. Enforced at write so a
        // misconstruction is loud rather than silently dropped or emitted.
        match self.post_kind {
            BondPostKind::JoinMarket => {
                if self.bond_spend_pk.len() != HYBRID_PUBKEY_CANONICAL_BYTES {
                    return Err(WireError::BondSpendPkLenNotCanonical {
                        got: self.bond_spend_pk.len(),
                    });
                }
            }
            _ => {
                if !self.bond_spend_pk.is_empty() {
                    return Err(WireError::BondSpendPkForbidden);
                }
            }
        }
        if self.holdings.kind == HoldingsKind::ShardSetCompact
            && self.holdings.shard_ids.len() > MAX_HOLDINGS_SHARDS
        {
            return Err(WireError::HoldingsCountExceeded {
                got: self.holdings.shard_ids.len(),
            });
        }
        if self.holdings.kind == HoldingsKind::CompleteTree && !self.holdings.shard_ids.is_empty() {
            return Err(WireError::ShardListForbiddenForCompleteTree);
        }

        w.write_all(&[VIN_TYPE_ARCHIVAL_BOND_POST])?;
        write_varint(&self.hybrid_public_key.len(), w)?;
        w.write_all(&self.hybrid_public_key)?;
        w.write_all(&self.p_canonical_id)?;
        w.write_all(&[self.post_kind as u8])?;
        if self.post_kind == BondPostKind::JoinMarket {
            write_varint(&self.bond_spend_pk.len(), w)?;
            w.write_all(&self.bond_spend_pk)?;
        }
        write_holdings_descriptor(w, &self.holdings)?;
        write_varint(&self.bonded_total_atomic, w)?;
        write_varint(&self.bond_credit, w)?;
        write_varint(&self.bond_debit, w)?;
        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    pub fn read_payload<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let pk_len: usize = read_varint(r)?;
        if pk_len != HYBRID_PUBKEY_CANONICAL_BYTES {
            return Err(WireError::HybridPubkeyLenNotCanonical { got: pk_len });
        }
        let mut hybrid_public_key = vec![0u8; pk_len];
        r.read_exact(&mut hybrid_public_key)?;
        let p_canonical_id = read_bytes(r)?;
        let post_kind = BondPostKind::from_u8(read_byte(r)?)?;
        // §9.11 coupling: the key bytes exist on the wire iff JoinMarket, so
        // `read` can never yield a non-JoinMarket vin carrying one.
        let bond_spend_pk = if post_kind == BondPostKind::JoinMarket {
            let spk_len: usize = read_varint(r)?;
            if spk_len != HYBRID_PUBKEY_CANONICAL_BYTES {
                return Err(WireError::BondSpendPkLenNotCanonical { got: spk_len });
            }
            let mut spk = vec![0u8; spk_len];
            r.read_exact(&mut spk)?;
            spk
        } else {
            Vec::new()
        };
        let holdings = read_holdings_descriptor(r)?;
        let bonded_total_atomic = read_varint(r)?;
        let bond_credit = read_varint(r)?;
        let bond_debit = read_varint(r)?;
        Ok(Self {
            hybrid_public_key,
            p_canonical_id,
            post_kind,
            bond_spend_pk,
            holdings,
            bonded_total_atomic,
            bond_credit,
            bond_debit,
        })
    }

    /// Length-delimited parse: reject unread trailing bytes.
    pub fn read_payload_exact<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let vin = Self::read_payload(r)?;
        crate::wire::ensure_payload_fully_consumed(r).map_err(|e| match e {
            crate::wire::ExactParseError::TrailingBytes => WireError::TrailingBytes,
            crate::wire::ExactParseError::Io(err) => WireError::Io(err),
        })?;
        Ok(vin)
    }

    pub fn read<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let tag = read_byte(r)?;
        if tag != VIN_TYPE_ARCHIVAL_BOND_POST {
            return Err(WireError::UnknownVinType(tag));
        }
        Self::read_payload(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::p_canonical_id_from_hybrid_pubkey;

    #[test]
    fn bond_post_roundtrip_shard_set() {
        let hybrid_pk = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES];
        let vin = ArchivalBondPostVin {
            hybrid_public_key: hybrid_pk.clone(),
            p_canonical_id: p_canonical_id_from_hybrid_pubkey(&hybrid_pk).to_bytes(),
            post_kind: BondPostKind::JoinMarket,
            bond_spend_pk: vec![0xE5; HYBRID_PUBKEY_CANONICAL_BYTES],
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
            },
            bonded_total_atomic: 1_500_000_000,
            bond_credit: 1_500_000_000,
            bond_debit: 0,
        };
        let wire = vin.serialize().unwrap();
        assert_eq!(wire[0], VIN_TYPE_ARCHIVAL_BOND_POST);
        let decoded = ArchivalBondPostVin::read(&mut wire.as_slice()).unwrap();
        assert_eq!(decoded, vin);
    }

    #[test]
    fn bond_post_complete_tree_has_no_shard_list_on_wire() {
        let hybrid_pk = vec![0x01; HYBRID_PUBKEY_CANONICAL_BYTES];
        let vin = ArchivalBondPostVin {
            hybrid_public_key: hybrid_pk.clone(),
            p_canonical_id: p_canonical_id_from_hybrid_pubkey(&hybrid_pk).to_bytes(),
            post_kind: BondPostKind::JoinMarket,
            bond_spend_pk: vec![0xE5; HYBRID_PUBKEY_CANONICAL_BYTES],
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::CompleteTree,
                shard_ids: ShardSet::empty(),
            },
            bonded_total_atomic: 750_000_000,
            bond_credit: 750_000_000,
            bond_debit: 0,
        };
        let wire = vin.serialize().unwrap();
        let decoded = ArchivalBondPostVin::read(&mut wire.as_slice()).unwrap();
        assert_eq!(decoded.holdings.kind, HoldingsKind::CompleteTree);
        assert!(decoded.holdings.shard_ids.is_empty());
    }

    /// A truncated (or over-long) hybrid pubkey is malformed, not a shorter
    /// valid key — both write and read demand the exact canonical length
    /// (mirrors the emission wire; the C++ oracle enforces the same equality).
    #[test]
    fn bond_post_rejects_non_canonical_pubkey_length() {
        let mut vin = ArchivalBondPostVin {
            hybrid_public_key: vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES - 1],
            p_canonical_id: [0x11; 32],
            post_kind: BondPostKind::JoinMarket,
            bond_spend_pk: vec![0xE5; HYBRID_PUBKEY_CANONICAL_BYTES],
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::CompleteTree,
                shard_ids: ShardSet::empty(),
            },
            bonded_total_atomic: 750_000_000,
            bond_credit: 750_000_000,
            bond_debit: 0,
        };
        assert!(matches!(
            vin.serialize(),
            Err(WireError::HybridPubkeyLenNotCanonical { .. })
        ));
        vin.hybrid_public_key = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES + 1];
        assert!(matches!(
            vin.serialize(),
            Err(WireError::HybridPubkeyLenNotCanonical { .. })
        ));

        // Read side: craft a payload with a truncated pk_len.
        let mut wire = Vec::new();
        write_varint(&(HYBRID_PUBKEY_CANONICAL_BYTES - 1), &mut wire).unwrap();
        wire.extend_from_slice(&vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES - 1]);
        assert!(matches!(
            ArchivalBondPostVin::read_payload(&mut wire.as_slice()),
            Err(WireError::HybridPubkeyLenNotCanonical { .. })
        ));
    }

    /// §9.11 coupling: `bond_spend_pk` is present with the exact canonical
    /// length iff JoinMarket. Both directions of the misconstruction are
    /// unrepresentable — write refuses to emit them, read refuses to parse
    /// them — mirroring the shekyl-wire `BondPostKind` enum coupling.
    #[test]
    fn bond_spend_pk_is_join_market_coupled() {
        let hybrid_pk = vec![0xAB; HYBRID_PUBKEY_CANONICAL_BYTES];
        let base = ArchivalBondPostVin {
            hybrid_public_key: hybrid_pk.clone(),
            p_canonical_id: p_canonical_id_from_hybrid_pubkey(&hybrid_pk).to_bytes(),
            post_kind: BondPostKind::JoinMarket,
            bond_spend_pk: vec![0xE5; HYBRID_PUBKEY_CANONICAL_BYTES],
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![7]).unwrap(),
            },
            bonded_total_atomic: 750_000_000,
            bond_credit: 750_000_000,
            bond_debit: 0,
        };

        // JoinMarket with a non-canonical key length refuses to write.
        let mut vin = base.clone();
        vin.bond_spend_pk = vec![0xE5; HYBRID_PUBKEY_CANONICAL_BYTES - 1];
        assert!(matches!(
            vin.serialize(),
            Err(WireError::BondSpendPkLenNotCanonical { .. })
        ));
        let mut vin = base.clone();
        vin.bond_spend_pk = Vec::new();
        assert!(matches!(
            vin.serialize(),
            Err(WireError::BondSpendPkLenNotCanonical { .. })
        ));

        // A non-JoinMarket vin carrying a key refuses to write (it would be
        // silently dropped otherwise — the coupling means the wire has no
        // place for it).
        let mut vin = base.clone();
        vin.post_kind = BondPostKind::Unbond;
        vin.holdings.shard_ids = ShardSet::empty();
        vin.bonded_total_atomic = 0;
        vin.bond_credit = 0;
        vin.bond_debit = 750_000_000;
        assert!(matches!(
            vin.serialize(),
            Err(WireError::BondSpendPkForbidden)
        ));
        // The same vin without the key round-trips, key-less.
        vin.bond_spend_pk = Vec::new();
        let wire = vin.serialize().unwrap();
        let decoded = ArchivalBondPostVin::read(&mut wire.as_slice()).unwrap();
        assert_eq!(decoded, vin);
        assert!(decoded.bond_spend_pk.is_empty());

        // Read side: a JoinMarket payload with a truncated key length refuses.
        let mut wire = Vec::new();
        write_varint(&HYBRID_PUBKEY_CANONICAL_BYTES, &mut wire).unwrap();
        wire.extend_from_slice(&hybrid_pk);
        wire.extend_from_slice(&base.p_canonical_id);
        wire.push(BondPostKind::JoinMarket as u8);
        write_varint(&(HYBRID_PUBKEY_CANONICAL_BYTES - 1), &mut wire).unwrap();
        wire.extend_from_slice(&vec![0xE5; HYBRID_PUBKEY_CANONICAL_BYTES - 1]);
        assert!(matches!(
            ArchivalBondPostVin::read_payload(&mut wire.as_slice()),
            Err(WireError::BondSpendPkLenNotCanonical { .. })
        ));
    }

    /// Golden byte vector for the shared holdings codec.
    ///
    /// **Blast radius: TWO consensus wires.** This fragment is byte-identical on
    /// the bond-post wire (`0x03`, this module) **and** the reward-emission wire
    /// (`0x04`, [`crate::emission_wire`], which mirrors this exact pin in
    /// `emission_wire::tests::holdings_codec_golden_vector_shared_with_bond_wire`).
    /// A change that moves these bytes is a consensus change to both surfaces and
    /// must fail both suites loudly — do not "fix" this test by updating the pin
    /// without a genesis-format decision covering both wires.
    #[test]
    fn holdings_codec_golden_vector_shared_with_emission_wire() {
        let shard_set = HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
        };
        assert_eq!(
            encode_holdings_descriptor(&shard_set).unwrap(),
            [0x00, 0x02, 0x07, 0x2A],
            "ShardSetCompact golden bytes moved — consensus change to BOTH wires"
        );
        let complete = HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: ShardSet::empty(),
        };
        assert_eq!(
            encode_holdings_descriptor(&complete).unwrap(),
            [0x01],
            "CompleteTree golden byte moved — consensus change to BOTH wires"
        );
        // Read side of the same pin: the golden bytes decode back exactly.
        assert_eq!(
            read_holdings_descriptor(&mut [0x00u8, 0x02, 0x07, 0x2A].as_slice()).unwrap(),
            shard_set
        );
        assert_eq!(
            read_holdings_descriptor(&mut [0x01u8].as_slice()).unwrap(),
            complete
        );
    }

    #[test]
    fn shard_set_rejects_oversize_at_construction() {
        // MAX + 1 DISTINCT ids — fails the bound (count is checked before dupes).
        let ids: Vec<u64> = (0..=MAX_HOLDINGS_SHARDS as u64).collect();
        assert_eq!(ids.len(), MAX_HOLDINGS_SHARDS + 1);
        assert_eq!(
            ShardSet::new(ids),
            Err(ShardSetError::CountExceeded {
                got: MAX_HOLDINGS_SHARDS + 1
            })
        );
        // The bound holds exactly at the cap.
        assert!(ShardSet::new((0..MAX_HOLDINGS_SHARDS as u64).collect()).is_ok());
    }

    #[test]
    fn shard_set_rejects_duplicate_at_construction() {
        // "A set on the wire": the constructor rejects a repeated id, naming it.
        assert_eq!(
            ShardSet::new(vec![7, 42, 7]),
            Err(ShardSetError::Duplicate { shard_id: 7 })
        );
        assert!(ShardSet::new(vec![7, 42, 9]).is_ok());
        assert!(ShardSet::empty().is_empty());
    }

    #[test]
    fn shard_set_preserves_insertion_order_byte_identically() {
        // Q2 (2026-07-15): order is NOT canonicalized — `[42, 7]` stays `[42, 7]`
        // and encodes in that order, so the type change re-encodes no accepted tx.
        let unsorted = ShardSet::new(vec![42, 7]).unwrap();
        assert_eq!(unsorted.as_slice(), &[42, 7]);
        let holdings = HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: unsorted,
        };
        assert_eq!(
            encode_holdings_descriptor(&holdings).unwrap(),
            [0x00, 0x02, 0x2A, 0x07],
            "insertion order must survive encoding (no canonical sort)"
        );
        // Round-trip: decode preserves the same order.
        assert_eq!(
            read_holdings_descriptor(&mut [0x00u8, 0x02, 0x2A, 0x07].as_slice()).unwrap(),
            holdings
        );
    }

    #[test]
    fn decode_rejects_duplicate_carrying_wire_bytes() {
        // The validity tightening at the wire boundary: a byte string carrying a
        // duplicate id (count 2, ids [7, 7]) is rejected at decode — it was
        // silently accepted before the newtype. Valid txs are unaffected (the
        // golden-vector test above pins their bytes unchanged).
        let dupe_bytes = [0x00u8, 0x02, 0x07, 0x07];
        assert!(matches!(
            read_holdings_descriptor(&mut dupe_bytes.as_slice()),
            Err(WireError::HoldingsDuplicateShard { shard_id: 7 })
        ));
        // And an oversize count is still rejected (count varint past the cap).
        let mut oversize = vec![0x00u8];
        // varint(4097) then no ids needed — the count guard fires first.
        oversize.extend_from_slice(&[0x81, 0x20]); // LEB128 for 4097
        assert!(matches!(
            read_holdings_descriptor(&mut oversize.as_slice()),
            Err(WireError::HoldingsCountExceeded { got: 4097 })
        ));
    }
}
