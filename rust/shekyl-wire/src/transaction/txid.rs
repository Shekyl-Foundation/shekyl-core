// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Consensus txid construction (`GENESIS_TX_WIRE_FORMAT.md` §11).
//!
//! One mixer, one prefix predicate, three public entries:
//! [`Transaction::txid_parts`] (body in hand),
//! [`Transaction::hash_with_supplied_prunable`] (prunable digest supplied),
//! [`Transaction::hash_with_supplied_components`] (both discardable
//! components supplied). [`Transaction::hash`] is the `hash` field of
//! `txid_parts`. Every txid leaves this module as a [`TxHash`] (RTN-7).

use shekyl_crypto_hash::keccak256;
use shekyl_types::{PqcAuthHash, PrunableHash, TxHash};

use super::{Ct, Input, Transaction, CT_TYPE_FCMP, CT_TYPE_NULL, TX_VERSION};
use crate::hash::hash_concat;
use crate::varint::write_varint;

/// This **body's** consensus txid and the two store-row digests computed
/// from it.
///
/// One construction: [`Transaction::txid_parts`] hashes each discardable
/// region once and mixes the txid from those values, so the three fields
/// cannot disagree. [`Transaction::hash`] is the `hash` field.
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
}

impl Transaction {
    /// The consensus transaction hash (`keccak256` over component hashes,
    /// GENESIS_TX_WIRE_FORMAT.md §11): **3-part** for the coinbase (`Null`) —
    /// `H(prefix) · H(base) · null_hash`; **4-part** for an FCMP++ spend —
    /// `H(prefix) · H(base) · H(pqc_auths) · H(prunable)`. `H(prefix)` includes
    /// the version varint (the first field of the C++ `transaction_prefix`).
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
        let pqc_auth_hash = self.pqc_auth_hash();
        let prunable_hash = self.prunable_hash();
        let mix_prunable = match &self.ct {
            Ct::Fcmp {
                prunable: Some(_), ..
            } => prunable_hash.to_bytes(),
            Ct::Null(_) | Ct::Fcmp { prunable: None, .. } => [0u8; 32],
        };
        TxidParts {
            hash: self.hash_from_components(pqc_auth_hash, mix_prunable),
            pqc_auth_hash,
            prunable_hash,
        }
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
        let Ct::Fcmp { pqc_auths, .. } = &self.ct else {
            return None;
        };
        if !self.prefix_carries_pqc_component() || pqc_auths.is_empty() {
            return None;
        }
        let mut auth_buf = Vec::new();
        write_varint(pqc_auths.len(), &mut auth_buf).expect("Vec write is infallible");
        for auth in pqc_auths {
            auth.write(&mut auth_buf).expect("Vec write is infallible");
        }
        Some(PqcAuthHash::from_bytes(keccak256(&auth_buf)))
    }

    /// The consensus transaction hash of a **pruned** body, with the prunable
    /// digest supplied instead of computed.
    ///
    /// The C++ equivalent is `get_pruned_transaction_hash`. It exists because a
    /// pruned body has no prunable section to hash: [`Self::hash`] would
    /// substitute the null hash and return an identity no transaction has.
    ///
    /// This is what lets a caller **bind** a pruned body served by an untrusted
    /// daemon to the hash it asked for. The reply's `tx_hash` label proves
    /// nothing — the daemon chooses it — and so does `prunable_hash` on its
    /// own; what the daemon cannot choose is a body and a digest that mix to a
    /// txid someone else named first, which is a keccak preimage.
    ///
    /// The `pqc_auths` component is still computed from the body: this is the
    /// storage-pruned *spend* form, which keeps them. A body holding neither
    /// region is [`Self::hash_with_supplied_components`]'s case. The operand
    /// is a [`PrunableHash`], not a bare `[u8; 32]`: what the store hands
    /// back is typed at the row, and a txid or a `PqcAuthHash` passed here is
    /// a compile error rather than a wrong identity.
    pub fn hash_with_supplied_prunable(&self, prunable_hash: PrunableHash) -> TxHash {
        self.hash_from_components(
            self.pqc_auth_hash(),
            self.prunable_component(Some(prunable_hash)),
        )
    }

    /// The consensus transaction hash of a **skeleton** — prefix and base
    /// only — with **both** discardable components supplied (`PDM-Q-F26`,
    /// `DAEMON_REDB_STORE.md` §7.7 item 2): the txid's third component as
    /// [`Self::pqc_auth_hash`] would have computed it (`None` ⇔ the txid is
    /// 3-part), and the prunable digest as [`Self::prunable_hash`] would have.
    ///
    /// Reconstruct-from-stored-digest, applied a second time. A node that has
    /// discarded `pqc_auths` under `PDM-Q6` item 2, or that holds a band-1
    /// skeleton (`PDM-Q-F28`) with neither region, cannot derive the txid's
    /// arity from `pqc_auths.is_empty()` on a body that is not there — so the
    /// arity is the supplied `Option` after [`Self::prefix_carries_pqc_component`]
    /// drops a `Some` the prefix cannot carry. [`Self::hash`] (both computed)
    /// and [`Self::hash_with_supplied_prunable`] (one supplied) are the special
    /// cases of this one mixer, so no two paths can hash one transaction two
    /// ways.
    ///
    /// For a coinbase (`Null` ct) the third component is the null hash
    /// whatever is supplied — pruning cannot give a coinbase a prunable
    /// region, and its `pqc_auth` is necessarily `None`.
    pub fn hash_with_supplied_components(
        &self,
        pqc_auth: Option<PqcAuthHash>,
        prunable_hash: PrunableHash,
    ) -> TxHash {
        let pqc_auth = pqc_auth.filter(|_| self.prefix_carries_pqc_component());
        self.hash_from_components(pqc_auth, self.prunable_component(Some(prunable_hash)))
    }

    /// Whether this prefix can carry a third txid component (C++ oracle,
    /// `cryptonote_format_utils.cpp:1290` and `:1359`, applied at `:1316` /
    /// `:1386`): `version >= 3 && !vin.empty() && vin[0] != gen`. Here: the
    /// ct is `Fcmp` (version 3) and the first input **exists and is not
    /// `gen`**. Auth presence is a separate fact — on a body,
    /// `!pqc_auths.is_empty()`; when supplied, `pqc_auth.is_some()` — so this
    /// predicate has no boolean "auths present" argument. Both malformed
    /// shapes the oracle hashes 3-part, gen-first-with-auths and
    /// no-inputs-with-auths, fail it rather than misclassifying as a spend.
    /// A malformed body's identity is still consensus-visible (relay dedup,
    /// the `already known` arm) before `validate` refuses it, so the
    /// predicate matches the oracle on every input, not only valid ones.
    /// The prefix is part of every form, skeleton included, so this half is
    /// always computable.
    fn prefix_carries_pqc_component(&self) -> bool {
        let first_is_spend = matches!(
            self.prefix.inputs.first(),
            Some(first) if !matches!(first, Input::Gen(_))
        );
        matches!(self.ct, Ct::Fcmp { .. }) && first_is_spend
    }

    /// The txid's prunable component: for `Fcmp`, a supplied digest wins (the
    /// pruned case, where the region is absent and its hash is the caller's
    /// operand), else the region's digest when present (the same bytes
    /// [`Self::prunable_hash`] hashes — one construction), else the null hash;
    /// for `Null`, the null hash regardless — a coinbase has no prunable
    /// region at all, so its component is fixed whether or not a digest was
    /// supplied.
    fn prunable_component(&self, supplied: Option<PrunableHash>) -> [u8; 32] {
        match (&self.ct, supplied) {
            (Ct::Fcmp { .. }, Some(h)) => h.to_bytes(),
            (
                Ct::Fcmp {
                    prunable: Some(_), ..
                },
                None,
            ) => self.prunable_hash().to_bytes(),
            (Ct::Null(_), _) | (Ct::Fcmp { prunable: None, .. }, None) => [0u8; 32],
        }
    }

    /// Shared mixer of every txid path: `H(prefix)` and `H(base)` from the
    /// parts every form carries, then 3-part or 4-part by whether
    /// `pqc_auth` is `Some`. The concat stays raw (`hash_concat`); the
    /// identity leaves here as a [`TxHash`] so no public path re-wraps.
    /// Callers that can supply a lying `Some` (the skeleton form) filter
    /// through [`Self::prefix_carries_pqc_component`] first;
    /// [`Self::pqc_auth_hash`] already returns `None` unless the body is
    /// 4-part. Both arms carry struct-derived cross-language hash parity
    /// (`pruned_tx_hash_parity` and `serve_credit_tx_parity`, each with a
    /// C++ leg asserting the same pin); the live-oracle pin
    /// (`live_oracle_spend_v1.json`) binds both languages to a
    /// daemon-accepted spend.
    fn hash_from_components(&self, pqc_auth: Option<PqcAuthHash>, prunable: [u8; 32]) -> TxHash {
        let mut prefix_buf = Vec::new();
        write_varint(TX_VERSION, &mut prefix_buf).expect("Vec write is infallible");
        self.prefix
            .write(&mut prefix_buf)
            .expect("Vec write is infallible");
        let h_prefix = keccak256(&prefix_buf);

        let mixed = match &self.ct {
            Ct::Null(base) => {
                let mut base_buf = vec![CT_TYPE_NULL];
                base.write(&mut base_buf).expect("Vec write is infallible");
                hash_concat(&[h_prefix, keccak256(&base_buf), prunable])
            }
            Ct::Fcmp {
                fee,
                reference_block,
                base,
                ..
            } => {
                let mut base_buf = vec![CT_TYPE_FCMP];
                write_varint(*fee, &mut base_buf).expect("Vec write is infallible");
                base_buf.extend_from_slice(reference_block.as_bytes());
                base.write(&mut base_buf).expect("Vec write is infallible");
                let h_base = keccak256(&base_buf);
                match pqc_auth {
                    Some(h_auths) => hash_concat(&[h_prefix, h_base, h_auths.to_bytes(), prunable]),
                    None => hash_concat(&[h_prefix, h_base, prunable]),
                }
            }
        };
        TxHash::from_bytes(mixed)
    }
}
