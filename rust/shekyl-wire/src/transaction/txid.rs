// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Consensus txid construction (`GENESIS_TX_WIRE_FORMAT.md` §11).
//!
//! One mixer, one prefix predicate, four public entries:
//! [`Transaction::txid_parts`] (body in hand),
//! [`Transaction::hash_with_supplied_prunable`] (prunable digest and
//! archival length supplied),
//! [`Transaction::hash_with_supplied_components`] (both discardable
//! components and the length supplied), and [`TxidSegments::txid`] (a full
//! body's bytes, unparsed — the C++ daemon's entry). [`Transaction::hash`] is
//! the `hash` field of `txid_parts`. Every txid leaves this module as a
//! [`TxHash`] (RTN-7).
//!
//! # The archival length is a mixer operand (`SHT-Q2`)
//!
//! An FCMP++ transaction's txid folds in its **archival length** — the bytes
//! of its prunable region plus its `pqc_auths` segment
//! (`ARCHIVAL_SHARD_T_DERIVATION.md` §8.6, RULED 2026-09-29). Shards are cut by
//! that length, so it has to be a value the skeleton binds: a node that keeps
//! only digests must not be able to hold a length the chain did not commit to.
//! Nothing declares it. A full body's length is measured from its own bytes
//! while the txid is computed, so a wrong one cannot exist; a pruned or
//! skeleton form **supplies** it beside the digests it already supplies, and a
//! supplied length that is not the body's yields a txid the block does not
//! list. A coinbase is outside the domain and keeps its 3-part form.
//!
//! **"3-part" and "4-part" count component digests, not preimage words.** A
//! body is 4-part when it carries the `pqc_auths` component (prefix, base,
//! `pqc_auths`, prunable) and 3-part when it does not. The length is one more
//! word after the digests of an FCMP++ body, so the preimages are three words
//! for a coinbase, four for a 3-part FCMP++ body (the serve-credit form) and
//! five for a spend. The three word counts are distinct, so no body of one
//! shape shares a preimage with a body of another.

use shekyl_crypto_hash::keccak256;
use shekyl_types::{ArchivalLength, PqcAuthHash, PrunableHash, TxHash};

use super::{archival_len_of, Ct, Input, Transaction, CT_TYPE_NULL, TX_VERSION};
use crate::hash::hash_concat;
use crate::varint::write_varint;

/// The txid's prunable component for a body with no prunable region to hash:
/// a coinbase, always.
const NULL_COMPONENT: [u8; 32] = [0u8; 32];

/// This **body's** consensus txid, with the two store-row digests and the
/// archival length it was mixed from.
///
/// One construction: [`Transaction::txid_parts`] serializes and hashes each
/// discardable region once, measures the same bytes, and mixes the txid from
/// those values, so the four fields cannot disagree. [`Transaction::hash`] is the `hash` field.
/// `TxIdentity::of` is this value, not three independent accessors — and
/// `validate` only calls it on the candidate as received, which still
/// holds the regions it is judged against.
///
/// `pqc_auth_hash: None` means **this body** hashes 3-part, not "the
/// accepted txid of some other body is 3-part." A skeleton of a 4-part
/// spend (auths cleared) hashes 3-part as a body; the accepted txid is
/// [`Transaction::hash_with_supplied_components`] with the stored digest.
/// A second `Transaction` type for "regions discarded" would leak store
/// retention into the wire crate; the two functions are the two contracts.
///
/// [`Self::prunable_hash`] is the store row (`keccak256` of the region,
/// `keccak256("")` when empty) — not always the txid's prunable *component*,
/// which is the null hash for a coinbase or a body whose region is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxidParts {
    /// This body's consensus transaction hash.
    pub hash: TxHash,
    /// This body's third component, or `None` when this body hashes 3-part.
    pub pqc_auth_hash: Option<PqcAuthHash>,
    /// `keccak256` of the prunable byte region (the store row).
    pub prunable_hash: PrunableHash,
    /// This body's archival length, measured on the two regions hashed above
    /// (the store row, `txs_archival_len`). Zero for a coinbase, and for a
    /// body whose regions have been discarded — which, like the digests, is
    /// then this body's value and not the accepted transaction's.
    pub archival_len: ArchivalLength,
}

/// `keccak256("")` — the `prunable_hash` row of a body with **no prunable byte
/// region**: a coinbase, or a storage-pruned spend whose region is absent.
///
/// This is the value [`Transaction::prunable_hash`] returns for such a body, and
/// it is **not** the null hash. The txid's prunable *component* substitutes the
/// null hash there; the store row does not. A predicate written against
/// "non-null prunable hash" would therefore read **every** coinbase as carrying
/// archival good, which is why [`carries_archival_good`] compares against this
/// value instead. Pinned by `the_empty_region_digest_is_the_coinbases_row`.
#[must_use]
pub fn empty_region_prunable_hash() -> PrunableHash {
    PrunableHash::from_bytes(keccak256(&[]))
}

/// Whether a transaction is in the **archival shard partition's domain** —
/// `SHT-Q1` RULED (Rick, 2026-09-27, design-owner lane).
///
/// A transaction is in the domain **iff it carries archival good**: a non-empty
/// prunable region, or a `pqc_auths` component. Both operands are skeleton data
/// — the two digests every node retains after the bodies are discarded — so
/// membership is decidable **without reading a body**, which is what lets bond
/// admission check it on a pruned node. That is why this function takes the two
/// row values and not a [`Transaction`].
///
/// - `pqc_auth_hash.is_some()` ⇔ the txid is **4-part** ⇔ the body carried a
///   non-empty `pqc_auths` ([`Transaction::pqc_auth_hash`]).
/// - `prunable_hash != empty_region_prunable_hash()` ⇔ the prunable region held
///   bytes. The comparison is against `keccak256("")`, **not** the null hash —
///   see [`empty_region_prunable_hash`].
///
/// **Feed it the rows as recorded at ingest — never digests recomputed from a
/// body.** There is deliberately **no** `TxidParts` convenience method, because
/// [`Transaction::txid_parts`] *recomputes* both digests from the object in hand:
/// on a body whose prunable region and `pqc_auths` have been discarded (`PDM-Q6`
/// retires them atomically) that yields `keccak256("")` and `None`, so a pruned
/// node would read its own discarded spends as carrying **no** good and drop them
/// from the domain — while an archival node keeps them. The two would then
/// disagree on shard boundaries, which is a consensus split.
/// [`Transaction::prunable_hash`] states the recomputation's behaviour for
/// exactly these cases. The store reads
/// the permanent rows instead (`txs_prunable_hash`, `txs_pqc_auth_hash`), which a
/// prune never deletes, and `shekyl-chain-store`'s `tx_carries_archival_good` is
/// the production path.
///
/// The coinbase is outside the domain **by this definition, not by exclusion**:
/// `Ct::Null` writes no prunable region and has no `pqc_auths`, so both legs are
/// false however large its `extra` grows. Every other transaction class carries
/// good; `shekyl-chain-rules`' `the_domain_is_every_non_coinbase_class` pins that
/// class by class, exhaustively, so a new class cannot be added without deciding
/// where it sits.
#[must_use]
pub fn carries_archival_good(
    pqc_auth_hash: Option<PqcAuthHash>,
    prunable_hash: PrunableHash,
) -> bool {
    pqc_auth_hash.is_some() || prunable_hash != empty_region_prunable_hash()
}

impl Transaction {
    /// The consensus transaction hash (`keccak256` over 32-byte words,
    /// GENESIS_TX_WIRE_FORMAT.md §11): for the coinbase (`Null`),
    /// `H(prefix) · H(base) · null_hash`; for an FCMP++ spend,
    /// `H(prefix) · H(base) · H(pqc_auths) · H(prunable) · L`; for an FCMP++
    /// body with no `pqc_auths` component, the same without that digest. `L`
    /// is the archival length word. `H(prefix)` includes the version varint
    /// (the first field of the C++ `transaction_prefix`).
    ///
    /// The `hash` field of [`Self::txid_parts`]. Reconstruction of a body that
    /// no longer holds a discardable region is
    /// [`Self::hash_with_supplied_components`].
    pub fn hash(&self) -> TxHash {
        self.txid_parts().hash
    }

    /// This body's consensus txid and the two store-row digests, hashed
    /// once each.
    ///
    /// [`Self::hash`], [`Self::pqc_auth_hash`] and [`Self::prunable_hash`]
    /// are the fields of this value. Call this when more than one is needed
    /// — `TxIdentity::of` — so a spend's ~16 KB of discardable bytes is not
    /// serialised and Keccak'd twice. Do not call it on a skeleton expecting
    /// the accepted 4-part txid: that is
    /// [`Self::hash_with_supplied_components`].
    #[must_use]
    pub fn txid_parts(&self) -> TxidParts {
        let (pqc_auths, prunable) = self.discardable_regions();
        let pqc_auth_hash = self.pqc_auth_component(&pqc_auths);
        let prunable_hash = PrunableHash::from_bytes(keccak256(&prunable));
        let archival_len = archival_len_of(&pqc_auths, &prunable);
        TxidParts {
            hash: self.hash_from_components(
                pqc_auth_hash,
                self.body_prunable_component(prunable_hash),
                archival_len,
            ),
            pqc_auth_hash,
            prunable_hash,
            archival_len,
        }
    }

    /// The two regions a prune discards, serialized once: the tx-level
    /// `pqc_auths` segment (no count prefix) and the prunable region. Each
    /// is empty when this body does not hold it.
    fn discardable_regions(&self) -> (Vec<u8>, Vec<u8>) {
        let mut pqc_auths = Vec::new();
        self.ct
            .write_pqc_auths(&mut pqc_auths)
            .expect("Vec write is infallible");
        let mut prunable = Vec::new();
        self.ct
            .write_prunable(&mut prunable)
            .expect("Vec write is infallible");
        (pqc_auths, prunable)
    }

    /// `keccak256` of the **prunable byte region** — exactly the bytes
    /// [`Self::write_segments`] puts in `prunable`, which is what the C++
    /// `calculate_transaction_prunable_hash` hashes
    /// (`blob[unprunable_size..]`) and what the chain store records in
    /// `txs_prunable_hash`.
    ///
    /// This is **not** the txid's prunable component in every case: when the
    /// region is absent (a coinbase, or a storage-pruned spend) the txid
    /// substitutes the null hash, while this is `keccak256("")` — the C++
    /// store's row for a coinbase is the latter. When the region is present
    /// the two coincide, and [`Self::hash`] is built from this value.
    #[must_use]
    pub fn prunable_hash(&self) -> PrunableHash {
        let mut prunable = Vec::new();
        self.ct
            .write_prunable(&mut prunable)
            .expect("Vec write is infallible");
        PrunableHash::from_bytes(keccak256(&prunable))
    }

    /// The txid's **third component** — `keccak256(varint(count) ‖ auths)`
    /// over the per-input `pqc_auths` — or `None` when the txid has no such
    /// component and is **3-part** (`PDM-Q-F26`; `DAEMON_REDB_STORE.md` §7.7
    /// item 2).
    ///
    /// `None` means **this body** hashes 3-part: the coinbase (`Null` ct),
    /// the serve-credit form (empty `pqc_auths`), the malformed gen-first and
    /// no-input shapes, **and** a skeleton whose auths have been cleared.
    /// That last case is not "the accepted txid is 3-part" — the accepted
    /// identity of a discarded-auths spend is reconstructed with
    /// [`Self::hash_with_supplied_components`]. The arity of this body is
    /// [`Self::prefix_carries_pqc_component`] together with whether auths are
    /// present on it — never per input arm: a bond-post carries its identity
    /// signature in a tx-level `pqc_auths` slot and so is 4-part like any
    /// spend; an emission takes whatever arity its auth count yields.
    ///
    /// **Not** `keccak256` of the stored `txs_pqc_auths` segment, which has no
    /// count prefix and so verifies nothing the chain signed: the count
    /// varint mirrors the C++ generic `std::vector` serializer the oracle
    /// hashes with (`cryptonote_format_utils.cpp:1169`, `begin_array(cnt)`),
    /// unlike the tx *body*, where the count is implicit in `vin.size()`.
    #[must_use]
    pub fn pqc_auth_hash(&self) -> Option<PqcAuthHash> {
        let mut pqc_auths = Vec::new();
        self.ct
            .write_pqc_auths(&mut pqc_auths)
            .expect("Vec write is infallible");
        self.pqc_auth_component(&pqc_auths)
    }

    /// [`Self::pqc_auth_hash`] over this body's already-serialized `pqc_auths`
    /// segment, so a caller that needs the segment's bytes for something else
    /// (its length) serializes it once.
    fn pqc_auth_component(&self, pqc_auths: &[u8]) -> Option<PqcAuthHash> {
        let Ct::Fcmp {
            pqc_auths: auths, ..
        } = &self.ct
        else {
            return None;
        };
        (self.prefix_carries_pqc_component() && !auths.is_empty())
            .then(|| pqc_auth_hash_of(auths.len(), pqc_auths))
    }

    /// The consensus transaction hash of a **pruned** body, with the prunable
    /// digest and the archival length supplied instead of computed.
    ///
    /// It exists because a pruned body has no prunable section to hash or
    /// measure: [`Self::hash`] would substitute the null hash and a short
    /// length, and return an identity no transaction has.
    ///
    /// This is what lets a caller **bind** a pruned body served by an untrusted
    /// daemon to the hash it asked for. The reply's `tx_hash` label proves
    /// nothing — the daemon chooses it — and so do `prunable_hash` and
    /// `archival_len` on their own; what the daemon cannot choose is a body, a
    /// digest and a length that mix to a txid someone else named first, which
    /// is a keccak preimage.
    ///
    /// The `pqc_auths` component is still computed from the body: this is the
    /// storage-pruned *spend* form, which keeps them. The length is supplied
    /// **whole** — the store's row and the reply's field are the transaction's
    /// archival length, not the absent region's share of it — so the three
    /// supplied-form callers pass one value with one definition. A body holding
    /// neither region is [`Self::hash_with_supplied_components`]'s case. The
    /// operands are typed: a txid or a `PqcAuthHash` passed as the digest, or
    /// a count passed as the length, is a compile error rather than a wrong
    /// identity.
    pub fn hash_with_supplied_prunable(
        &self,
        prunable_hash: PrunableHash,
        archival_len: ArchivalLength,
    ) -> TxHash {
        self.hash_from_components(
            self.pqc_auth_hash(),
            self.supplied_prunable_component(prunable_hash),
            archival_len,
        )
    }

    /// The consensus transaction hash of a **skeleton** — prefix and base
    /// only — with **every** discardable operand supplied (`PDM-Q-F26`,
    /// `DAEMON_REDB_STORE.md` §7.7 item 2; `SHT-Q2`): the txid's third
    /// component as [`Self::pqc_auth_hash`] would have computed it (`None` ⇔
    /// the txid has no such component), the prunable digest as
    /// [`Self::prunable_hash`] would have, and the archival length as
    /// [`Self::archival_len`] would have measured it.
    ///
    /// Reconstruct-from-stored-rows. A node that has discarded `pqc_auths`
    /// under `PDM-Q6` item 2, or that holds a band-1 skeleton (`PDM-Q-F28`)
    /// with neither region, cannot derive the txid's arity from
    /// `pqc_auths.is_empty()` on a body that is not there — so the arity is
    /// the supplied `Option` after [`Self::prefix_carries_pqc_component`]
    /// drops a `Some` the prefix cannot carry. [`Self::hash`] (all computed)
    /// and [`Self::hash_with_supplied_prunable`] (two supplied) are the special
    /// cases of this one mixer, so no two paths can hash one transaction two
    /// ways.
    ///
    /// For a coinbase (`Null` ct) the third component is the null hash and no
    /// length is mixed, whatever is supplied — pruning cannot give a coinbase
    /// a prunable region, and its `pqc_auth` is necessarily `None`.
    pub fn hash_with_supplied_components(
        &self,
        pqc_auth: Option<PqcAuthHash>,
        prunable_hash: PrunableHash,
        archival_len: ArchivalLength,
    ) -> TxHash {
        let pqc_auth = pqc_auth.filter(|_| self.prefix_carries_pqc_component());
        self.hash_from_components(
            pqc_auth,
            self.supplied_prunable_component(prunable_hash),
            archival_len,
        )
    }

    /// Whether this prefix can carry a third txid component (C++ oracle,
    /// `cryptonote_format_utils.cpp`, `has_pqc`): `version >= 3 &&
    /// !vin.empty() && vin[0] != gen`. Here: the ct is `Fcmp` (version 3) and
    /// the first input **exists and is not `gen`**. Auth presence is a
    /// separate fact — on a body, `!pqc_auths.is_empty()`; when supplied,
    /// `pqc_auth.is_some()` — so this predicate has no boolean "auths
    /// present" argument. Both malformed shapes the oracle hashes without the
    /// component, gen-first-with-auths and no-inputs-with-auths, fail it
    /// rather than misclassifying as a spend. A malformed body's identity is
    /// still consensus-visible (relay dedup, the `already known` arm) before
    /// `validate` refuses it, so the predicate matches the oracle on every
    /// input, not only valid ones. The prefix is part of every form, skeleton
    /// included, so this half is always computable.
    fn prefix_carries_pqc_component(&self) -> bool {
        let first_is_spend = matches!(
            self.prefix.inputs.first(),
            Some(first) if !matches!(first, Input::Gen(_))
        );
        matches!(self.ct, Ct::Fcmp { .. }) && first_is_spend
    }

    /// The txid's prunable component for a **body in hand**: the region's
    /// digest when the body holds the region (the same bytes
    /// [`Self::prunable_hash`] hashes — one construction), else the null
    /// hash — a coinbase, which has no such region, or a body it was
    /// discarded from.
    fn body_prunable_component(&self, prunable_hash: PrunableHash) -> [u8; 32] {
        match &self.ct {
            Ct::Fcmp {
                prunable: Some(_), ..
            } => prunable_hash.to_bytes(),
            Ct::Null(_) | Ct::Fcmp { prunable: None, .. } => NULL_COMPONENT,
        }
    }

    /// The txid's prunable component when the digest is **supplied**: the
    /// supplied digest for `Fcmp` (the region is absent and its hash is the
    /// caller's operand); for `Null`, the null hash regardless — a coinbase
    /// has no prunable region at all, so its component is fixed whatever was
    /// supplied.
    fn supplied_prunable_component(&self, prunable_hash: PrunableHash) -> [u8; 32] {
        match &self.ct {
            Ct::Fcmp { .. } => prunable_hash.to_bytes(),
            Ct::Null(_) => NULL_COMPONENT,
        }
    }

    /// `H(prefix)` and `H(base)` from the parts every form carries, handed to
    /// the one mixer ([`mix`]) with the discardable operands. Callers that can
    /// supply a lying `Some` (the skeleton form) filter through
    /// [`Self::prefix_carries_pqc_component`] first; [`Self::pqc_auth_hash`]
    /// already returns `None` unless the body carries the component. Both
    /// arities carry struct-derived cross-language hash parity
    /// (`pruned_tx_hash_parity` and `serve_credit_tx_parity`, each with a C++
    /// leg asserting the same pin through the daemon's FFI entry); the
    /// live-oracle pin (`live_oracle_spend_v1.json`) binds a real spend's
    /// bytes to the same value.
    fn hash_from_components(
        &self,
        pqc_auth: Option<PqcAuthHash>,
        prunable: [u8; 32],
        archival_len: ArchivalLength,
    ) -> TxHash {
        let mut prefix_buf = Vec::new();
        write_varint(TX_VERSION, &mut prefix_buf).expect("Vec write is infallible");
        self.prefix
            .write(&mut prefix_buf)
            .expect("Vec write is infallible");
        let mut base_buf = Vec::new();
        self.ct
            .write_base(&mut base_buf)
            .expect("Vec write is infallible");
        let discardable = match &self.ct {
            Ct::Null(_) => Discardable::Coinbase,
            Ct::Fcmp { .. } => Discardable::Fcmp {
                pqc_auth,
                prunable,
                archival_len,
            },
        };
        mix(keccak256(&prefix_buf), keccak256(&base_buf), discardable)
    }
}

/// What a txid mixes after `H(prefix)` and `H(base)`.
#[derive(Clone, Copy)]
enum Discardable {
    /// A coinbase (`Null` ct): the null hash and nothing else. It carries no
    /// archival good, so it has no length to bind.
    Coinbase,
    /// An FCMP++ transaction: the `pqc_auths` component when the txid has
    /// one, the prunable component, and the archival length.
    Fcmp {
        pqc_auth: Option<PqcAuthHash>,
        prunable: [u8; 32],
        archival_len: ArchivalLength,
    },
}

/// The one mixer (`GENESIS_TX_WIRE_FORMAT.md` §11). `keccak256` over 32-byte
/// words:
///
/// - coinbase: `H(prefix) · H(base) · null`;
/// - FCMP++ without a `pqc_auths` component (the serve-credit form):
///   `H(prefix) · H(base) · H(prunable) · len`;
/// - FCMP++ with one: `H(prefix) · H(base) · H(pqc_auths) · H(prunable) · len`.
///
/// `len` is [`length_word`]. The three shapes are three word counts, so no
/// two can be confused, and the concat stays raw (`hash_concat`).
fn mix(h_prefix: [u8; 32], h_base: [u8; 32], discardable: Discardable) -> TxHash {
    let mixed = match discardable {
        Discardable::Coinbase => hash_concat(&[h_prefix, h_base, NULL_COMPONENT]),
        Discardable::Fcmp {
            pqc_auth: None,
            prunable,
            archival_len,
        } => hash_concat(&[h_prefix, h_base, prunable, length_word(archival_len)]),
        Discardable::Fcmp {
            pqc_auth: Some(pqc_auth),
            prunable,
            archival_len,
        } => hash_concat(&[
            h_prefix,
            h_base,
            pqc_auth.to_bytes(),
            prunable,
            length_word(archival_len),
        ]),
    };
    TxHash::from_bytes(mixed)
}

/// Bytes of a [`length_word`] that carry the length; the rest are zero.
const LENGTH_WORD_VALUE_BYTES: usize = 8;

/// The archival length as a mixer word: the `u64` little-endian in the low
/// [`LENGTH_WORD_VALUE_BYTES`], zero above. A full word rather than eight
/// bytes so every mixer operand has one width.
fn length_word(archival_len: ArchivalLength) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[..LENGTH_WORD_VALUE_BYTES].copy_from_slice(&archival_len.to_raw().to_le_bytes());
    word
}

/// The txid's `pqc_auths` component: `keccak256(varint(count) ‖ segment)`.
/// The count prefix is in the hash and not in the stored segment (see
/// [`Transaction::pqc_auth_hash`]).
fn pqc_auth_hash_of(count: usize, pqc_auths_segment: &[u8]) -> PqcAuthHash {
    let mut buf = Vec::with_capacity(pqc_auths_segment.len() + 9);
    write_varint(count, &mut buf).expect("Vec write is infallible");
    buf.extend_from_slice(pqc_auths_segment);
    PqcAuthHash::from_bytes(keccak256(&buf))
}

/// A **full** transaction's bytes, cut where the txid reads them and not
/// parsed: the entry for a caller that holds a serialized body and its segment
/// offsets rather than a [`Transaction`] — the C++ daemon, whose one txid
/// computation is this (`SHT-Q2`: one mixer, in Rust).
///
/// The caller hands over bytes and two facts about the prefix it parsed; this
/// hashes each segment, **measures** the archival length from the two
/// discardable segments, and mixes. There is deliberately no length field:
/// a caller that could supply one could supply a wrong one, and a full body
/// leaves nothing to supply.
///
/// It agrees with [`Transaction::hash`] on every body both can read
/// (`segments_entry_agrees_with_the_parsed_body`), and it cannot fail: C++
/// names a transaction's id in its refusal paths, for bodies no validator
/// would accept, so an id has to exist for any bytes it can serialize.
#[derive(Clone, Copy, Debug)]
pub struct TxidSegments<'a> {
    /// The version varint and the prefix.
    pub prefix: &'a [u8],
    /// The ct type byte and everything up to the tx-level `pqc_auths`.
    pub ct_base: &'a [u8],
    /// The tx-level `pqc_auths` segment as the body carries it — no count
    /// prefix. Empty when the body has none.
    pub pqc_auths: &'a [u8],
    /// How many authorizations [`Self::pqc_auths`] holds.
    pub pqc_auth_count: usize,
    /// Whether the first input exists and is not `gen` — the half of the
    /// arity predicate that needs the prefix parsed
    /// (`Transaction::prefix_carries_pqc_component`).
    pub first_input_is_spend: bool,
    /// The prunable region. Empty when the body has none.
    pub prunable: &'a [u8],
}

impl TxidSegments<'_> {
    /// The consensus txid of the body these segments were cut from.
    #[must_use]
    pub fn txid(&self) -> TxHash {
        let discardable = if self.ct_base.first() == Some(&CT_TYPE_NULL) {
            Discardable::Coinbase
        } else {
            let carries_pqc_component = self.first_input_is_spend && self.pqc_auth_count > 0;
            Discardable::Fcmp {
                pqc_auth: carries_pqc_component
                    .then(|| pqc_auth_hash_of(self.pqc_auth_count, self.pqc_auths)),
                // An absent region mixes the null hash, as a parsed body
                // without one does (`body_prunable_component`).
                prunable: if self.prunable.is_empty() {
                    NULL_COMPONENT
                } else {
                    keccak256(self.prunable)
                },
                archival_len: archival_len_of(self.pqc_auths, self.prunable),
            }
        };
        mix(keccak256(self.prefix), keccak256(self.ct_base), discardable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Block;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// The `tx_hex` body of a pinned fixture.
    fn pinned(fixture: &str) -> Transaction {
        let doc: serde_json::Value = serde_json::from_str(fixture).expect("fixture json");
        Transaction::from_bytes(&unhex(doc["tx_hex"].as_str().expect("tx_hex"))).expect("parse")
    }

    /// The txid of `tx` through [`TxidSegments`]: the body's bytes cut as the
    /// C++ caller cuts them, with the two prefix facts read off the parsed
    /// prefix the way that caller reads them — not through the predicate
    /// under test.
    fn via_segments(tx: &Transaction) -> TxHash {
        let mut prefix = Vec::new();
        write_varint(TX_VERSION, &mut prefix).unwrap();
        tx.prefix.write(&mut prefix).unwrap();
        let mut ct_base = Vec::new();
        tx.ct.write_base(&mut ct_base).unwrap();
        let (pqc_auths, prunable) = tx.discardable_regions();
        let pqc_auth_count = match &tx.ct {
            Ct::Fcmp { pqc_auths, .. } => pqc_auths.len(),
            Ct::Null(_) => 0,
        };
        let first_input_is_spend =
            matches!(tx.prefix.inputs.first(), Some(first) if !matches!(first, Input::Gen(_)));
        TxidSegments {
            prefix: &prefix,
            ct_base: &ct_base,
            pqc_auths: &pqc_auths,
            pqc_auth_count,
            first_input_is_spend,
            prunable: &prunable,
        }
        .txid()
    }

    /// The unparsed entry and the parsed one are the same function of a body:
    /// every class, the storage-pruned and skeleton forms, and the two
    /// malformed shapes whose identity is consensus-visible before `validate`
    /// refuses them. C++ computes every txid through the first, so a
    /// disagreement here is a daemon and a wallet naming one transaction two
    /// ways.
    #[test]
    fn segments_entry_agrees_with_the_parsed_body() {
        let spend = pinned(include_str!(
            "../../tests/fixtures/pruned_tx_hash_parity_v1.json"
        ));
        let live_spend = pinned(include_str!(
            "../../tests/fixtures/live_oracle_spend_v1.json"
        ));
        let serve_credit = pinned(include_str!(
            "../../tests/fixtures/serve_credit_tx_parity_v1.json"
        ));
        let coinbase = Block::from_bytes(include_bytes!(
            "../../tests/vectors/regtest_coinbase_h1.block"
        ))
        .expect("block")
        .miner_transaction;

        let mut storage_pruned = spend.clone();
        let mut skeleton = spend.clone();
        let mut no_inputs = spend.clone();
        let mut gen_first = spend.clone();
        if let Ct::Fcmp { prunable, .. } = &mut storage_pruned.ct {
            *prunable = None;
        }
        if let Ct::Fcmp {
            pqc_auths,
            prunable,
            ..
        } = &mut skeleton.ct
        {
            pqc_auths.clear();
            *prunable = None;
        }
        no_inputs.prefix.inputs.clear();
        gen_first.prefix.inputs.insert(0, Input::Gen(7));

        let bodies = [
            ("spend", &spend),
            ("daemon-accepted spend", &live_spend),
            ("serve-credit", &serve_credit),
            ("coinbase", &coinbase),
            ("storage-pruned spend", &storage_pruned),
            ("skeleton", &skeleton),
            ("no inputs, with an auth", &no_inputs),
            ("gen first, with an auth", &gen_first),
        ];
        for (name, tx) in bodies {
            assert_eq!(via_segments(tx), tx.hash(), "{name}");
        }
        // The cases are distinct identities, so agreement is not eight
        // bodies collapsing onto one value.
        let ids: std::collections::BTreeSet<_> = bodies.iter().map(|(_, tx)| tx.hash()).collect();
        assert_eq!(ids.len(), bodies.len());
    }

    /// The length is an operand: the same digests under another length are
    /// another identity, in both arities, and a coinbase mixes none.
    #[test]
    fn the_archival_length_is_bound_for_fcmp_and_absent_for_a_coinbase() {
        let h = |b: u8| [b; 32];
        let at = |pqc_auth, len| {
            mix(
                h(1),
                h(2),
                Discardable::Fcmp {
                    pqc_auth,
                    prunable: h(4),
                    archival_len: ArchivalLength::from_raw(len),
                },
            )
        };
        for pqc_auth in [None, Some(PqcAuthHash::from_bytes(h(3)))] {
            assert_ne!(at(pqc_auth, 100), at(pqc_auth, 101));
            assert_ne!(at(pqc_auth, 0), at(pqc_auth, 1));
        }
        // A component and no component are different identities at one
        // length, and neither is the coinbase form.
        assert_ne!(at(None, 100), at(Some(PqcAuthHash::from_bytes(h(3))), 100));
        assert_ne!(mix(h(1), h(2), Discardable::Coinbase), at(None, 0));
    }

    /// The length word is the `u64` little-endian in the low bytes and zero
    /// above — written out, so the encoding is pinned by value and not by the
    /// function that produces it.
    #[test]
    fn the_length_word_is_the_u64_little_endian_then_zeros() {
        let mut expected = [0u8; 32];
        expected[0] = 0x02;
        expected[1] = 0x01;
        assert_eq!(length_word(ArchivalLength::from_raw(0x0102)), expected);
        assert_eq!(length_word(ArchivalLength::ZERO), [0u8; 32]);
        let mut max = [0u8; 32];
        max[..8].copy_from_slice(&[0xFF; 8]);
        assert_eq!(length_word(ArchivalLength::from_raw(u64::MAX)), max);
    }
}
