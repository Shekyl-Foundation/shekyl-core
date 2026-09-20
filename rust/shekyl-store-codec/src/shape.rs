// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How a value is stored: the four value shapes a table may declare
//! (`DAEMON_REDB_STORE.md` §11.1(f)).
//!
//! The shapes are the contract; the write boundary that makes the
//! `fixed_width` assertion unreachable (below) is each store's own.
//!
//! # The value side gets the key side's discipline
//!
//! Keys were typed from the first increment: `lmdb_order` carries LMDB's
//! orderings into redb, and redb refuses at `open_table` to open a table
//! whose stored key `TypeName` disagrees with the definition's — so a
//! height and a hash cannot index each other's tables. Values were `&[u8]`,
//! and `&[u8]` is what every table inherits when nothing states otherwise:
//! two tables of identical `(u64, &[u8])` shape are indistinguishable to
//! the engine however different their meanings, and a definition that
//! drifted onto the wrong name would open cleanly. This module is the
//! value side's statement, made once, so that the increments still ahead
//! (S-ARCH, E3, E5) do not each answer it locally.
//!
//! A **map** table's value is one of exactly four shapes:
//!
//! - [`Coded<V>`] — a value with a [`Canonical`] codec. The stored bytes
//!   **are** `V::encode`, the digest's fold input (§11.1(b)); the
//!   `TypeName` is `shekyl::Coded<{V::NAME}>` — the wrapper's name carrying
//!   the codec's, which the codec contract already forbids reusing for a
//!   different layout (`tables.snap` pins the exact string).
//! - [`Blob<K>`] — wire bytes the chain itself encodes and that the store
//!   does not re-codec: a block body, a transaction segment. [`BlobKind`]
//!   names the kind; the bytes are verified where they are read (a block
//!   blob against the identity `block_info` records,
//!   `shekyl-chain-store`'s `store/chain_reads.rs`).
//! - [`Present`] — a set-table's value: the key is the fact, the value is
//!   a zero-width witness that the key is a member. The daemon store's
//!   `spent_keys` is the one catalogued instance at this pin. Named, so
//!   two set-tables cannot silently share redb's `()` `TypeName`.
//! - [`Unshaped`] — a table the LMDB census declares and no Rust writer
//!   has reached. Its value type is uninhabited: the table is catalogued
//!   (it has an ordinal) and dispatched to by the journal replay, which
//!   refuses it; it is **not** created by the seal (`shekyl-chain-store`'s
//!   `Restorable::SEALED` is `false` for exactly this shape) and cannot be
//!   inserted into. "No writer yet" is a fact of the type, not of the
//!   code; the increment that first writes the table replaces this shape
//!   with the table's codec and bumps `SCHEMA_VERSION`.
//!
//! `&[u8]` is not a value type, and there is no multimap in the catalogue
//! (S-OUT-KI SOK-1): every value is one of the four shapes above.
//!
//! # Two guards, stated exactly
//!
//! The `TypeName` check is redb's, at `open_table`, and it covers **table
//! confusion**: a definition opened against a table whose stored value
//! type is named differently is refused before any row is read. It does
//! not see inside a correctly opened table. **Codec confusion** — decoding
//! a row under the wrong codec, or inserting bytes of the wrong codec — is
//! closed by the Rust type instead: a `Coded<V>` table yields
//! [`Encoded<'_, V>`] from every read and accepts only `Encoded<'_, V>` on
//! every write. [`Canonical::encoded`] is the constructor this crate
//! offers; the guarantee is the store's insertion boundary, below.
//! The two guards are different mechanisms with different reach; neither
//! is "the name guards the type."
//!
//! # `from_bytes` is not a decoder, so the decode path does not move
//!
//! `redb::Value::from_bytes` is infallible: every typed value impl in this
//! tree panics on malformed input (`&[u8; N]` unwraps, `Hash32` expects).
//! A store whose row decode ran *inside* redb would turn a corrupt cell
//! into a panic where today it is `CodecError` → SI-7 and a halted writer.
//! So `Coded<V>` does not decode in `from_bytes`. It hands back the bytes,
//! tagged; [`Encoded::decode`] is where `V::decode` runs, strict and
//! fallible, exactly where the daemon store's `chain_reads::cell` ran it
//! before. The open-time
//! guard is gained without touching the decode path.
//!
//! # `fixed_width` is a layout choice, made deliberately
//!
//! redb stores a fixed-width value without the per-entry offset it keeps
//! for variable-width ones, locates row *n* as `key_end + width × (n+1)`,
//! and **asserts** the width in `LeafBuilder::append` (4.1.0
//! `btree_base.rs:884`): a wrong-width value is a panic, and the panic
//! poisons the transaction lock — a process-level failure, not a `Result`.
//! `Coded<V>` reports [`Canonical::FIXED_WIDTH`] anyway, for two reasons.
//! The codec has already declared its width and the snapshot gate already
//! holds every fixture to it; reporting `None` to the engine would be a
//! second declaration that could drift from the first, which is what
//! §11.1(b) exists to prevent. And the assertion is kept unreachable by
//! two boundaries, stated exactly. `Canonical::encoded` cannot produce the
//! wrong width. But `redb::Value::from_bytes` is a **public trait method**,
//! so a caller can construct an `Encoded<V>` over any bytes — constructor
//! visibility alone is not the guarantee. So every write through a
//! store's own table handles checks the row first
//! (`shekyl-chain-store`'s `store::keyed::check_row`)
//! and refuses as `StoreCannot::RowWidth` or `StoreCannot::RowIllFormed`,
//! and the journal replay runs
//! `V::decode` — exact width — as `Restorable::well_formed` before
//! `from_bytes`. Reporting the width is a layout change from `&[u8]` (which
//! is variable-width), not pure metadata; it rides the `SCHEMA_VERSION` bump
//! of the commit that lands it, as any layout change does.
//!

use core::fmt;
use core::marker::PhantomData;

use redb::{TypeName, Value};

use crate::{Canonical, CodecError};

// ---------------------------------------------------------------------------
// Coded<V>
// ---------------------------------------------------------------------------

/// The value shape of a table whose rows are `V::encode` (module docs).
///
/// A marker: never constructed. Appears only as the `V` of a
/// `TableDefinition<K, Coded<V>>`.
pub struct Coded<V>(PhantomData<fn() -> V>);

impl<V> fmt::Debug for Coded<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Coded")
    }
}

/// One row of a [`Coded<V>`] table, as redb holds it: `V`'s canonical
/// bytes, borrowed from the transaction, **not yet decoded**.
///
/// This is `Coded<V>`'s `SelfType` — what a read hands back and what a
/// write accepts. The constructor this crate offers is
/// [`Canonical::encoded`] (via [`EncodedBuf::as_encoded`]);
/// `redb::Value::from_bytes` is public and produces one over any bytes,
/// which is why a `Coded<V>` table's rows are held to `V::encode` at each
/// store's insertion boundary (module docs, *Two guards*) rather than
/// here. The exits are [`decode`](Self::decode) — strict, fallible,
/// `V::decode` — and the raw [`bytes`](Self::bytes) for the journal's
/// post-image digest.
#[derive(Clone, Copy)]
pub struct Encoded<'a, V> {
    bytes: &'a [u8],
    _codec: PhantomData<fn() -> V>,
}

impl<'a, V: Canonical> Encoded<'a, V> {
    /// Decode the row under its codec.
    ///
    /// # Errors
    ///
    /// [`CodecError`] if the bytes are not exactly one encoding of a `V` —
    /// the read path's SI-7, unchanged from when the table was `&[u8]`.
    pub fn decode(self) -> Result<V, CodecError> {
        V::decode(self.bytes)
    }

    /// The stored bytes, for the journal's post-image digest.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

impl<V> fmt::Debug for Encoded<'_, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Encoded").field(&self.bytes).finish()
    }
}

/// An owned `V::encode`, the write side's half of [`Encoded`].
///
/// Made only by [`Canonical::encoded`]; borrowed into the `Encoded` a
/// `Coded<V>` table's `insert` takes by [`as_encoded`](Self::as_encoded).
pub struct EncodedBuf<V> {
    bytes: Vec<u8>,
    _codec: PhantomData<fn() -> V>,
}

impl<V: Canonical> EncodedBuf<V> {
    pub(super) fn of(value: &V) -> Self {
        // `pub(super)`: reachable from `Canonical::encoded` and nowhere else.
        Self {
            bytes: value.encode(),
            _codec: PhantomData,
        }
    }

    /// Borrow as the row a `Coded<V>` table inserts.
    #[must_use]
    pub fn as_encoded(&self) -> Encoded<'_, V> {
        Encoded {
            bytes: &self.bytes,
            _codec: PhantomData,
        }
    }
}

impl<V> fmt::Debug for EncodedBuf<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EncodedBuf").field(&self.bytes).finish()
    }
}

impl<V: Canonical + 'static> Value for Coded<V> {
    type SelfType<'a>
        = Encoded<'a, V>
    where
        Self: 'a;
    type AsBytes<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        V::FIXED_WIDTH
    }

    /// The engine's constructor: bytes it stored come back tagged, not
    /// decoded (module docs). Reached from a read, and from the journal
    /// replay after `Restorable::well_formed` has run `V::decode`.
    ///
    fn from_bytes<'a>(data: &'a [u8]) -> Encoded<'a, V>
    where
        Self: 'a,
    {
        Encoded {
            bytes: data,
            _codec: PhantomData,
        }
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Encoded<'b, V>) -> &'a [u8]
    where
        Self: 'b,
    {
        value.bytes
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!("shekyl::Coded<{}>", V::NAME))
    }
}

// ---------------------------------------------------------------------------
// Blob<K>
// ---------------------------------------------------------------------------

/// A kind of wire blob a table stores (module docs, [`Blob`]).
///
/// The kind names the bytes and says what a well-formed row is, so the
/// journal replay can refuse a damaged pre-image before `from_bytes`. It
/// does **not** re-codec the bytes: the chain's own encoding is the
/// encoding, and verification against recorded identity happens at the
/// read site that has that identity.
pub trait BlobKind: 'static {
    /// Stable name; becomes the table's value `TypeName`. Never reused
    /// for a different kind of bytes.
    const NAME: &'static str;

    /// `Err(reason)` if `bytes` cannot be a row of this kind.
    ///
    /// The default accepts anything: a segment or a property cell is
    /// opaque to the store and checked by its consumer. A kind whose bytes
    /// have a parse (a block body) overrides this.
    fn well_formed(bytes: &[u8]) -> Result<(), &'static str> {
        let _ = bytes;
        Ok(())
    }
}

/// The value shape of a table whose rows are wire bytes of kind `K`
/// (module docs). A marker, like [`Coded`].
pub struct Blob<K>(PhantomData<fn() -> K>);

impl<K> fmt::Debug for Blob<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Blob")
    }
}

/// One row of a [`Blob<K>`] table: the bytes, borrowed, named by kind.
///
/// Constructible from any bytes by [`Raw::new`] — a blob's bytes are made
/// elsewhere (`Block::serialize`, `Transaction::write_segments`) and the
/// store does not own their encoding. The kind must still be **named** at
/// the write site, so a pruned segment cannot land in `blocks` without the
/// author writing `Raw::<BlockBody>::new(segment)` and a reviewer reading
/// it.
#[derive(Clone, Copy)]
pub struct Raw<'a, K> {
    bytes: &'a [u8],
    _kind: PhantomData<fn() -> K>,
}

impl<'a, K: BlobKind> Raw<'a, K> {
    /// Name `bytes` as a row of kind `K`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            _kind: PhantomData,
        }
    }

    /// The bytes.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

impl<K> fmt::Debug for Raw<'_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Raw").field(&self.bytes).finish()
    }
}

impl<K: BlobKind> Value for Blob<K> {
    type SelfType<'a>
        = Raw<'a, K>
    where
        Self: 'a;
    type AsBytes<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Raw<'a, K>
    where
        Self: 'a,
    {
        Raw::new(data)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Raw<'b, K>) -> &'a [u8]
    where
        Self: 'b,
    {
        value.bytes
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!("shekyl::Blob<{}>", K::NAME))
    }
}

// ---------------------------------------------------------------------------
// Present
// ---------------------------------------------------------------------------

/// The value shape of a set-table: the key is the member, the value is a
/// zero-width witness (module docs).
///
/// Constructible only as the unit [`Present`]. `insert(key, Present)` is
/// the write; a `()` would have been redb's untyped unit, sharing a
/// `TypeName` with any other table that inherited it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Present;

impl Value for Present {
    type SelfType<'a> = Present;
    type AsBytes<'a> = [u8; 0];

    fn fixed_width() -> Option<usize> {
        Some(0)
    }

    fn from_bytes<'a>(_data: &'a [u8]) -> Present
    where
        Self: 'a,
    {
        // Width is the engine's and the store's write boundary; replay
        // runs `Restorable::well_formed` (the width check) first.
        Present
    }

    fn as_bytes<'a, 'b: 'a>(_value: &'a Present) -> [u8; 0]
    where
        Self: 'b,
    {
        []
    }

    fn type_name() -> TypeName {
        TypeName::new("shekyl::Present")
    }
}

// ---------------------------------------------------------------------------
// Unshaped
// ---------------------------------------------------------------------------

/// The value shape of a censused table no Rust writer has reached
/// (module docs).
///
/// Its `SelfType` is [`NoRow`], which has no values: `insert` on an
/// `Unshaped` table does not type-check, and `from_bytes` — reachable only
/// if a file somehow held a row — is unreachable by construction and says
/// so. The journal replay refuses first (`Restorable::well_formed`), so
/// a damaged journal naming an unshaped table is SI-7, not a panic.
///
/// One `TypeName` for every unshaped table is deliberate: the guard has
/// nothing to distinguish while there are no rows, and it resumes — with
/// the table's own codec name — in the commit that gives the table a
/// writer.
///
#[derive(Debug)]
pub struct Unshaped;

/// A row of an [`Unshaped`] table. There are none.
#[derive(Debug, Clone, Copy)]
pub enum NoRow {}

impl Value for Unshaped {
    type SelfType<'a> = NoRow;
    type AsBytes<'a> = &'a [u8];

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(_data: &'a [u8]) -> NoRow
    where
        Self: 'a,
    {
        unreachable!("an Unshaped table has no rows; the journal replay refuses before this")
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a NoRow) -> &'a [u8]
    where
        Self: 'b,
    {
        match *value {}
    }

    fn type_name() -> TypeName {
        TypeName::new("shekyl::Unshaped")
    }
}

#[cfg(test)]
mod tests {
    use shekyl_types::BlockHeight;

    use super::*;

    // `BlockHeight` is a codec this crate owns (`vocabulary`), so the shape
    // tests do not reach into a store for a subject. Each store's own
    // codecs are exercised through these shapes in that store's tests.
    fn height() -> BlockHeight {
        BlockHeight::from_raw(0x0102_0304_0506_0708)
    }

    #[test]
    fn coded_round_trips_through_the_engine_constructor() {
        let buf = height().encoded();
        let stored = <Coded<BlockHeight> as Value>::as_bytes(&buf.as_encoded()).to_vec();
        assert_eq!(stored, height().encode(), "stored bytes are V::encode");
        let back = <Coded<BlockHeight> as Value>::from_bytes(&stored);
        assert_eq!(back.decode().expect("decodes"), height());
    }

    #[test]
    fn coded_reports_the_codecs_declared_width_and_name() {
        assert_eq!(
            <Coded<BlockHeight> as Value>::fixed_width(),
            BlockHeight::FIXED_WIDTH
        );
        assert_eq!(
            <Coded<BlockHeight> as Value>::type_name(),
            TypeName::new("shekyl::Coded<block_height>")
        );
    }

    #[test]
    fn coded_decode_is_the_strict_codec_not_the_engine() {
        let short = [0u8; 3];
        let row = <Coded<BlockHeight> as Value>::from_bytes(&short);
        assert!(
            row.decode().is_err(),
            "a malformed row is CodecError, never a panic"
        );
    }

    struct Opaque;
    impl BlobKind for Opaque {
        const NAME: &'static str = "opaque";
    }

    #[test]
    fn blob_is_variable_width_and_named_by_kind() {
        assert_eq!(<Blob<Opaque> as Value>::fixed_width(), None);
        assert_eq!(
            <Blob<Opaque> as Value>::type_name(),
            TypeName::new("shekyl::Blob<opaque>")
        );
        let row = <Blob<Opaque> as Value>::from_bytes(b"xyz");
        assert_eq!(<Blob<Opaque> as Value>::as_bytes(&row), b"xyz");
        assert_eq!(row.bytes(), b"xyz");
    }

    #[test]
    fn unshaped_has_one_name_and_no_width() {
        assert_eq!(<Unshaped as Value>::fixed_width(), None);
        assert_eq!(
            <Unshaped as Value>::type_name(),
            TypeName::new("shekyl::Unshaped")
        );
    }

    #[test]
    fn present_is_zero_width_and_named() {
        assert_eq!(<Present as Value>::fixed_width(), Some(0));
        assert_eq!(
            <Present as Value>::type_name(),
            TypeName::new("shekyl::Present")
        );
        assert_eq!(<Present as Value>::as_bytes(&Present), [0u8; 0]);
        assert_eq!(<Present as Value>::from_bytes(&[]), Present);
    }
}
