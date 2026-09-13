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

/// The serving endpoint on the wire: the raw 32-byte Ed25519 public key of
/// the persona's v3 onion service (`EU-D3`). The `.onion` address is a display
/// form; the wire never carries it.
pub const ENDPOINT_BYTES: usize = 32;

/// Wire discriminant of a bond-post vin (gate-4 §3.4.1). Copy so FFI, debit-auth,
/// and `as u8` sites can name the byte without carrying JoinMarket's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BondPostKind {
    JoinMarket = 0,
    Rebond = 1,
    Release = 2,
    HoldingsUpdate = 3,
}

impl BondPostKind {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            0 => Ok(Self::JoinMarket),
            1 => Ok(Self::Rebond),
            2 => Ok(Self::Release),
            3 => Ok(Self::HoldingsUpdate),
            _ => Err(WireError::InvalidPostKind(v)),
        }
    }

    /// Unit kinds: Rebond / Release / HoldingsUpdate. `None` for JoinMarket,
    /// which needs `bond_spend_pk` and the endpoint before it is a [`BondKind`].
    pub const fn unit_kind(self) -> Option<BondKind> {
        match self {
            Self::Rebond => Some(BondKind::Rebond),
            Self::Release => Some(BondKind::Release),
            Self::HoldingsUpdate => Some(BondKind::HoldingsUpdate),
            Self::JoinMarket => None,
        }
    }
}

/// Kind of a decoded [`ArchivalBondPostVin`]. JoinMarket is the only variant
/// that carries extra data (`bond_spend_pk` + serving endpoint). Holdings and
/// the amount terms live on the vin — every kind has them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BondKind {
    JoinMarket {
        bond_spend_pk: Vec<u8>,
        endpoint: [u8; ENDPOINT_BYTES],
    },
    Rebond,
    Release,
    HoldingsUpdate,
}

impl BondKind {
    pub const fn tag(&self) -> BondPostKind {
        match self {
            Self::JoinMarket { .. } => BondPostKind::JoinMarket,
            Self::Rebond => BondPostKind::Rebond,
            Self::Release => BondPostKind::Release,
            Self::HoldingsUpdate => BondPostKind::HoldingsUpdate,
        }
    }

    pub fn bond_spend_pk(&self) -> Option<&[u8]> {
        match self {
            Self::JoinMarket { bond_spend_pk, .. } => Some(bond_spend_pk.as_slice()),
            _ => None,
        }
    }

    pub fn endpoint(&self) -> Option<&[u8; ENDPOINT_BYTES]> {
        match self {
            Self::JoinMarket { endpoint, .. } => Some(endpoint),
            _ => None,
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

    /// Which LMDB scan produces the per-shard last-served slice that
    /// [`crate::whole_record_last_served`] folds into the release-cooldown
    /// anchor.
    ///
    /// Exhaustive on this enum: a third holdings kind fails to compile until
    /// its scan is written. That is the gate the two C++ gather sites cannot
    /// provide — they used to branch on `is_complete_tree()` independently,
    /// coupled only by comments. Compact holdings store a shard list; a
    /// complete-tree record stores none, so folding that empty list reports
    /// "never served" (the permissive cooldown branch) for a record that has.
    pub const fn last_served_scan(self) -> LastServedScan {
        match self {
            Self::ShardSetCompact => LastServedScan::HeldShards,
            Self::CompleteTree => LastServedScan::AllShards,
        }
    }
}

/// The gather the Release cooldown-anchor fold consumes, decided by
/// [`HoldingsKind::last_served_scan`].
///
/// C++ marshals this discriminant and calls the matching DB accessor; it does
/// not re-derive the kind→scan decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LastServedScan {
    /// Fold the record's held shards (`archival_bond_last_served_epochs`).
    HeldShards = 0,
    /// Complete-tree records store no shard list: scan every served shard
    /// (`archival_bond_all_last_served_epochs`).
    AllShards = 1,
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

    /// The empty set (`CompleteTree` carries none; the `Release` exit shape). The
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

/// Byte-exact `txin_archival_bond_post` (gate-4 §3.4.1). JoinMarket-coupled
/// fields live on [`BondKind`]; holdings and the amount terms are on the
/// struct, matching `shekyl-wire::BondPost`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivalBondPostVin {
    pub hybrid_public_key: Vec<u8>,
    pub p_canonical_id: [u8; 32],
    pub kind: BondKind,
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
    pub fn join_market(
        hybrid_public_key: Vec<u8>,
        p_canonical_id: [u8; 32],
        bond_spend_pk: Vec<u8>,
        endpoint: [u8; ENDPOINT_BYTES],
        holdings: HoldingsDescriptor,
        bonded_total_atomic: u64,
        bond_credit: u64,
    ) -> Self {
        Self {
            hybrid_public_key,
            p_canonical_id,
            kind: BondKind::JoinMarket {
                bond_spend_pk,
                endpoint,
            },
            holdings,
            bonded_total_atomic,
            bond_credit,
            bond_debit: 0,
        }
    }

    pub fn release(
        hybrid_public_key: Vec<u8>,
        p_canonical_id: [u8; 32],
        holdings: HoldingsDescriptor,
        bonded_total_atomic: u64,
        bond_credit: u64,
        bond_debit: u64,
    ) -> Self {
        Self {
            hybrid_public_key,
            p_canonical_id,
            kind: BondKind::Release,
            holdings,
            bonded_total_atomic,
            bond_credit,
            bond_debit,
        }
    }

    pub fn rebond(
        hybrid_public_key: Vec<u8>,
        p_canonical_id: [u8; 32],
        holdings: HoldingsDescriptor,
        bonded_total_atomic: u64,
        bond_credit: u64,
        bond_debit: u64,
    ) -> Self {
        Self {
            hybrid_public_key,
            p_canonical_id,
            kind: BondKind::Rebond,
            holdings,
            bonded_total_atomic,
            bond_credit,
            bond_debit,
        }
    }

    pub fn holdings_update(
        hybrid_public_key: Vec<u8>,
        p_canonical_id: [u8; 32],
        holdings: HoldingsDescriptor,
        bonded_total_atomic: u64,
        bond_credit: u64,
        bond_debit: u64,
    ) -> Self {
        Self {
            hybrid_public_key,
            p_canonical_id,
            kind: BondKind::HoldingsUpdate,
            holdings,
            bonded_total_atomic,
            bond_credit,
            bond_debit,
        }
    }

    pub const fn post_kind(&self) -> BondPostKind {
        self.kind.tag()
    }

    pub fn bond_spend_pk(&self) -> Option<&[u8]> {
        self.kind.bond_spend_pk()
    }

    pub fn endpoint(&self) -> Option<&[u8; ENDPOINT_BYTES]> {
        self.kind.endpoint()
    }

    /// Write-time checks the kind type cannot hold: hybrid-key length,
    /// JoinMarket `bond_spend_pk` length, holdings bounds. Presence couplings
    /// are the variant — they are not checked here.
    pub fn check_couplings(&self) -> Result<(), WireError> {
        if self.hybrid_public_key.len() != HYBRID_PUBKEY_CANONICAL_BYTES {
            return Err(WireError::HybridPubkeyLenNotCanonical {
                got: self.hybrid_public_key.len(),
            });
        }
        if let BondKind::JoinMarket { bond_spend_pk, .. } = &self.kind {
            if bond_spend_pk.len() != HYBRID_PUBKEY_CANONICAL_BYTES {
                return Err(WireError::BondSpendPkLenNotCanonical {
                    got: bond_spend_pk.len(),
                });
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
        Ok(())
    }

    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), WireError> {
        self.check_couplings()?;
        w.write_all(&[VIN_TYPE_ARCHIVAL_BOND_POST])?;
        write_varint(&self.hybrid_public_key.len(), w)?;
        w.write_all(&self.hybrid_public_key)?;
        w.write_all(&self.p_canonical_id)?;
        w.write_all(&[self.post_kind() as u8])?;
        if let BondKind::JoinMarket {
            bond_spend_pk,
            endpoint,
        } = &self.kind
        {
            write_varint(&bond_spend_pk.len(), w)?;
            w.write_all(bond_spend_pk)?;
            w.write_all(endpoint)?;
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
        let tag = BondPostKind::from_u8(read_byte(r)?)?;
        let kind = match tag {
            BondPostKind::JoinMarket => {
                let spk_len: usize = read_varint(r)?;
                if spk_len != HYBRID_PUBKEY_CANONICAL_BYTES {
                    return Err(WireError::BondSpendPkLenNotCanonical { got: spk_len });
                }
                let mut bond_spend_pk = vec![0u8; spk_len];
                r.read_exact(&mut bond_spend_pk)?;
                let endpoint = read_bytes(r)?;
                BondKind::JoinMarket {
                    bond_spend_pk,
                    endpoint,
                }
            }
            BondPostKind::Rebond => BondKind::Rebond,
            BondPostKind::Release => BondKind::Release,
            BondPostKind::HoldingsUpdate => BondKind::HoldingsUpdate,
        };
        let holdings = read_holdings_descriptor(r)?;
        let bonded_total_atomic = read_varint(r)?;
        let bond_credit = read_varint(r)?;
        let bond_debit = read_varint(r)?;
        Ok(Self {
            hybrid_public_key,
            p_canonical_id,
            kind,
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
impl ArchivalBondPostVin {
    pub(crate) fn set_bond_spend_pk(&mut self, pk: Vec<u8>) {
        match &mut self.kind {
            BondKind::JoinMarket { bond_spend_pk, .. } => *bond_spend_pk = pk,
            _ => panic!("bond_spend_pk exists only on JoinMarket"),
        }
    }

    pub(crate) fn set_endpoint(&mut self, ep: [u8; ENDPOINT_BYTES]) {
        match &mut self.kind {
            BondKind::JoinMarket { endpoint, .. } => *endpoint = ep,
            _ => panic!("endpoint exists only on JoinMarket"),
        }
    }
}

#[cfg(test)]
#[path = "bond_wire_tests.rs"]
mod tests;
