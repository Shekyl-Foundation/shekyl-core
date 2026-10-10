// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a fetch is *for* — the typed target the scheduler supplies, the
//! shard it expects, the sink the verified transactions are handed to, and
//! the verified result.

use std::fmt;

use shekyl_archival_retention::PASS_DELIVERY_DIGEST_LEN;
use shekyl_crypto_pq::signature::{HybridPublicKey, HybridSignature};
use shekyl_types::{shard_of, shard_start, ArchivalLength, ShardId, ShardViewHash};
use shekyl_wire::shard_frame::frame_len_ceiling;
use shekyl_wire::{carries_archival_good, TxidParts};

use crate::client::SIGNATURE_ENVELOPE_LEN;

/// The raw 32-byte Ed25519 public key of a persona's v3 onion service, as
/// the bond record carries it (`EU-D3`: the `.onion` is display form; the
/// wire never carries it).
///
/// This is the **daemon's** typed dial target. The wallet serving path
/// publishes through `OnionIdentity` (expanded credential, `ADD_ONION`).
/// Those stay different types (`PWD-E9`): mixing them would let a fetch
/// client hold serving-key material, or a serving host dial through the
/// daemon's SOCKS. The hostname both derive is one function in
/// `shekyl-onion-v3`.
///
/// The provenance obligation: build this from the **record** read (the
/// `ArchivalBondValue` endpoint column at the drawable snapshot, `EU-D4`),
/// never from a vin and never from a response. The crate cannot check
/// where the bytes came from; the type is what the review checks. The
/// bond wire itself stays a bare array (rule 42).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ServingEndpoint([u8; 32]);

impl ServingEndpoint {
    /// Wrap the endpoint column of an authorized bond record. Consensus has
    /// already refused the all-zero endpoint on both sides of the record,
    /// so there is nothing left for this constructor to validate — the
    /// name is the provenance statement.
    #[must_use]
    pub const fn from_record_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw key, as the record holds it.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The v3 `.onion` hostname this endpoint is dialled at.
    #[must_use]
    pub fn onion_address(&self) -> String {
        shekyl_onion_v3::v3_onion_hostname(&self.0)
    }
}

/// Whom to dial and whose signature to accept.
///
/// Both fields are read from **local chain state** — the bond record's
/// endpoint column and identity key — and never from a response (`SF-D7`
/// amendment). The types carry that obligation: a [`ServingEndpoint`] is
/// minted from record bytes, a [`HybridPublicKey`] parses only its
/// canonical encoding. A call site constructing either from wire or
/// response bytes is the review's rule-19 catch, not this crate's.
///
/// *Which* shard is named, and what it must hold, is the
/// [`ExpectedShard`] passed beside the target: one `P` serves many shards,
/// and the expectation is the scheduler's per-need object while the target
/// is the persona's.
#[derive(Clone, Debug)]
pub struct FetchTarget {
    /// The persona's onion, from the bond record.
    pub endpoint: ServingEndpoint,
    /// The persona's stable hybrid identity key, from the bond record
    /// (`SF-D13`). The envelope's countersignature must verify under it.
    pub verifying_key: HybridPublicKey,
}

/// The shard a fetch names and what the requester already knows it must
/// hold: the in-domain transactions of shard `k`, in chain order, each as
/// its retained `txid_parts` row (`SF-D8` amendment 2026-10-08).
///
/// Every requester — a validating daemon, a pruned one, a wallet's view
/// through its daemon — holds the skeleton rows (`txid_parts`:
/// `txs_pqc_auth_hash`, `txs_prunable_hash`, `txs_archival_len`) for every
/// transaction, so the expectation is derivable before the dial and the
/// body is checked per transaction as it streams: declared lengths against
/// `archival_len` before a segment byte is read, then the two segments'
/// hashes against the two rows. The body's exact size follows from the rows
/// too, which is what bounds `content-length` from the head
/// ([`Self::max_response_len`]).
///
/// The constructor refuses a range that cannot be a shard — empty, a
/// transaction without archival good (a coinbase, a body whose regions are
/// gone: not in the domain), a cumulative-before outside shard `k`
/// ([`shard_of`]), or a range that does not close the shard (its last
/// transaction's cumulative-after still inside `k`). What the range alone
/// cannot check — that the transaction *before* it ends shard `k − 1`
/// (`PDM-Q-F32`'s boundary pair) — is the caller's fold, which produced
/// `cum_before` in the first place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedShard {
    shard_id: ShardId,
    txs: Vec<TxidParts>,
    archival_len: ArchivalLength,
    max_response_len: u64,
}

impl ExpectedShard {
    /// The expectation for shard `shard_id` over `txs`, where `cum_before`
    /// is the cumulative archival length of every transaction ahead of
    /// `txs[0]`.
    ///
    /// # Errors
    ///
    /// [`ExpectationError`]: the range is not a closed shard `shard_id`.
    pub fn new(
        shard_id: ShardId,
        cum_before: ArchivalLength,
        txs: Vec<TxidParts>,
    ) -> Result<Self, ExpectationError> {
        if txs.is_empty() {
            return Err(ExpectationError::Empty);
        }
        let mut cum = cum_before;
        let mut archival_len = ArchivalLength::ZERO;
        for (i, tx) in txs.iter().enumerate() {
            let index = u64::try_from(i).expect("a range index fits u64");
            if !carries_archival_good(tx.pqc_auth_hash, tx.prunable_hash) {
                return Err(ExpectationError::NoArchivalGood { index });
            }
            if shard_of(cum) != shard_id {
                return Err(ExpectationError::OutsideShard {
                    index,
                    cum_before: cum,
                });
            }
            cum = cum
                .checked_add(tx.archival_len)
                .ok_or(ExpectationError::Overflow)?;
            archival_len = archival_len
                .checked_add(tx.archival_len)
                .ok_or(ExpectationError::Overflow)?;
        }
        // Closed: the next transaction, whatever it is, starts in a later
        // shard. `shard_start(k + 1)` overflowing means no `cum` reaches it.
        let next = ShardId::from_raw(
            shard_id
                .to_raw()
                .checked_add(1)
                .ok_or(ExpectationError::Overflow)?,
        );
        match shard_start(next) {
            Some(start) if cum.to_raw() >= start.to_raw() => {}
            _ => return Err(ExpectationError::Open { cum_after: cum }),
        }
        let tx_count = u64::try_from(txs.len()).expect("a range length fits u64");
        let max_response_len = frame_len_ceiling(tx_count, archival_len)
            .and_then(|frame| {
                frame.checked_add(u64::try_from(SIGNATURE_ENVELOPE_LEN).expect("envelope fits"))
            })
            .ok_or(ExpectationError::Overflow)?;
        Ok(Self {
            shard_id,
            txs,
            archival_len,
            max_response_len,
        })
    }

    /// The shard this expectation names.
    #[must_use]
    pub fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// The retained rows, in chain order.
    #[must_use]
    pub fn txs(&self) -> &[TxidParts] {
        &self.txs
    }

    /// In-domain transactions in the range. Never zero.
    #[must_use]
    pub fn tx_count(&self) -> u64 {
        u64::try_from(self.txs.len()).expect("a range length fits u64")
    }

    /// The shard's archival length: the sum of the rows' `archival_len`.
    /// At least `W` by construction (the range closes the shard), and
    /// exactly the bytes the body's segments carry.
    #[must_use]
    pub fn archival_len(&self) -> ArchivalLength {
        self.archival_len
    }

    /// The most bytes a conforming response to this expectation can declare
    /// in `content-length`: the frame's ceiling over this range
    /// ([`frame_len_ceiling`]) plus the countersignature envelope. The
    /// client refuses a larger declaration from the head, before a body
    /// byte is read (`SF-D6`); a declaration under it is read and the frame
    /// is held to end exactly where the envelope begins.
    #[must_use]
    pub fn max_response_len(&self) -> u64 {
        self.max_response_len
    }
}

/// Why a range is not a closed shard ([`ExpectedShard::new`]). A caller's
/// error, not `P`'s: nothing was dialled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectationError {
    /// No transactions. Every shard is non-empty (`SHT-Q2`).
    Empty,
    /// A row with neither archival digest: a coinbase or a discarded body,
    /// which is not in the domain and belongs to no shard.
    NoArchivalGood {
        /// Position in the range.
        index: u64,
    },
    /// The transaction's cumulative-before places it in another shard.
    OutsideShard {
        /// Position in the range.
        index: u64,
        /// Its cumulative archival length before.
        cum_before: ArchivalLength,
    },
    /// The last transaction's cumulative-after is still inside the shard:
    /// the range does not close it. An open shard is not fetchable.
    Open {
        /// Cumulative archival length after the last transaction.
        cum_after: ArchivalLength,
    },
    /// A length sum overflowed `u64`. Not reachable from retained rows.
    Overflow,
}

impl fmt::Display for ExpectationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("expected range is empty"),
            Self::NoArchivalGood { index } => {
                write!(f, "entry {index} carries no archival good")
            }
            Self::OutsideShard { index, cum_before } => write!(
                f,
                "entry {index} at cumulative length {} lies outside the shard",
                cum_before.to_raw()
            ),
            Self::Open { cum_after } => write!(
                f,
                "range ends at cumulative length {} without closing the shard",
                cum_after.to_raw()
            ),
            Self::Overflow => f.write_str("archival length sum overflows"),
        }
    }
}

impl std::error::Error for ExpectationError {}

/// One transaction of the body, after its segments hashed to the
/// requester's own retained rows — handed to the [`TxSink`] and then
/// dropped, so one transaction is resident at a time.
///
/// Content-correct by the rows, not by `P`: `check_components` compared the
/// segments against `txs_pqc_auth_hash` / `txs_prunable_hash`, which the
/// requester holds. `P`'s countersignature — which is about *crediting*
/// `P`, not about these bytes — arrives after the last transaction and is
/// verified then; a sink writing to a body store has written bytes the
/// chain already committed to, whatever the envelope turns out to be.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedTx<'a> {
    /// Position in the range.
    pub index: u64,
    /// The retained row this transaction matched.
    pub parts: &'a TxidParts,
    /// `pqc_auths` entry count, as framed.
    pub pqc_auth_count: u64,
    /// The `pqc_auths` bytes, exactly as serialized; empty when the row has
    /// no `pqc_auth_hash`.
    pub pqc_auths: &'a [u8],
    /// The prunable region's bytes, exactly as serialized.
    pub prunable: &'a [u8],
}

/// Where the body's transactions go as they verify (`SF-D8` amendment:
/// the body streams; it is never resident whole). The organic caller's
/// sink writes to its body store; the challenge and view callers discard
/// ([`DiscardTxs`]) — the fetch's [`VerifiedShard`] already carries the
/// view hash and the pass record's inputs.
///
/// Called on the blocking pool, in chain order, once per transaction, and
/// never after a refusal: a sink sees a prefix of the shard on a failed
/// fetch, which is why a store-writing sink keys on `(shard_id, index)`
/// rather than appending.
pub trait TxSink: Send + Sync {
    /// Take one verified transaction. The borrow ends when this returns;
    /// a sink that keeps the bytes copies them.
    fn accept(&self, tx: &VerifiedTx<'_>);
}

/// A [`TxSink`] that keeps nothing: the challenge and view callers' sink.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscardTxs;

impl TxSink for DiscardTxs {
    fn accept(&self, _tx: &VerifiedTx<'_>) {}
}

/// A shard whose body matched the requester's expectation transaction by
/// transaction **and** whose countersignature verified under the target's
/// key.
///
/// There is no unverified variant of this type: the only way to obtain one
/// is through [`PFetchClient::fetch`](crate::PFetchClient::fetch), after
/// both checks (`SF-D8`: verified-or-refused). The signature and the
/// delivery digest are kept because the pass record the requester goes on
/// to build carries both; the view hash is kept because the view caller's
/// aggregate carries it. The body itself is not here — it went to the
/// [`TxSink`] one transaction at a time.
#[derive(Clone, Debug)]
pub struct VerifiedShard {
    shard_id: ShardId,
    delivery_digest: [u8; PASS_DELIVERY_DIGEST_LEN],
    signature: HybridSignature,
    view_hash: ShardViewHash,
    tx_count: u64,
    archival_len: ArchivalLength,
}

impl VerifiedShard {
    pub(crate) fn new(
        shard_id: ShardId,
        delivery_digest: [u8; PASS_DELIVERY_DIGEST_LEN],
        signature: HybridSignature,
        view_hash: ShardViewHash,
        tx_count: u64,
        archival_len: ArchivalLength,
    ) -> Self {
        Self {
            shard_id,
            delivery_digest,
            signature,
            view_hash,
            tx_count,
            archival_len,
        }
    }

    /// The digest of the body this client received, salted by its request's
    /// nonce — recomputed here over every body byte, frame included, never
    /// read from the response. `P`'s signature verified over it, so it is
    /// the pass record's digest.
    #[must_use]
    pub fn delivery_digest(&self) -> &[u8; PASS_DELIVERY_DIGEST_LEN] {
        &self.delivery_digest
    }

    /// The shard the path named.
    #[must_use]
    pub fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// `P`'s countersignature over the request transcript — the pass
    /// record's payload.
    #[must_use]
    pub fn signature(&self) -> &HybridSignature {
        &self.signature
    }

    /// The shard's view hash (`SV-D`): the `ShardViewHasher` fold over the
    /// verified transactions, in order. What the view caller renders and
    /// what two daemons fetching the same shard agree on.
    #[must_use]
    pub fn view_hash(&self) -> ShardViewHash {
        self.view_hash
    }

    /// Transactions the body carried — the expectation's count.
    #[must_use]
    pub fn tx_count(&self) -> u64 {
        self.tx_count
    }

    /// Archival bytes the body's segments carried — the expectation's sum.
    #[must_use]
    pub fn archival_len(&self) -> ArchivalLength {
        self.archival_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_types::{TxHash, SHARD_LENGTH};
    use shekyl_wire::shard_frame::MAX_VARINT_LEN;
    use shekyl_wire::{empty_region_prunable_hash, prunable_hash_of};

    #[test]
    fn onion_address_matches_the_publish_side_golden_kat() {
        let pubkey: [u8; 32] = [
            0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e,
            0xab, 0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06,
            0x98, 0x81, 0xdb, 0x12,
        ];
        let endpoint = ServingEndpoint::from_record_bytes(pubkey);
        assert_eq!(
            endpoint.onion_address(),
            "efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad.onion"
        );
        assert_eq!(endpoint.as_bytes(), &pubkey);
    }

    /// A row with `len` prunable bytes and no `pqc_auths`.
    fn row(seed: u8, len: u64) -> TxidParts {
        TxidParts {
            hash: TxHash::from_bytes([seed; 32]),
            pqc_auth_hash: None,
            prunable_hash: prunable_hash_of(&[seed]),
            archival_len: ArchivalLength::from_raw(len),
        }
    }

    fn w() -> u64 {
        SHARD_LENGTH.to_raw()
    }

    #[test]
    fn a_closed_shard_is_accepted_and_its_ceiling_is_the_frames_plus_the_envelope() {
        // Shard 2: starts at 2W; three rows that reach 3W exactly.
        let rows = vec![row(1, w() / 2), row(2, w() / 4), row(3, w() / 4)];
        let shard = ExpectedShard::new(
            ShardId::from_raw(2),
            ArchivalLength::from_raw(2 * w()),
            rows.clone(),
        )
        .expect("closed");
        assert_eq!(shard.shard_id(), ShardId::from_raw(2));
        assert_eq!(shard.txs(), rows.as_slice());
        assert_eq!(shard.tx_count(), 3);
        assert_eq!(shard.archival_len(), SHARD_LENGTH);
        let varint = u64::try_from(MAX_VARINT_LEN).unwrap();
        assert_eq!(
            shard.max_response_len(),
            1 + varint + 3 * 3 * varint + w() + u64::try_from(SIGNATURE_ENVELOPE_LEN).unwrap()
        );
    }

    #[test]
    fn the_overshooting_last_transaction_closes_the_shard_too() {
        // One row starting inside shard 0 and running past W: shard 0's
        // whole range is that one transaction (SHT-Q2: a transaction is in
        // the shard its cumulative-before falls in).
        let shard = ExpectedShard::new(ShardId::ZERO, ArchivalLength::ZERO, vec![row(1, w() + 5)])
            .expect("closed by overshoot");
        assert_eq!(shard.archival_len().to_raw(), w() + 5);
    }

    #[test]
    fn every_range_that_is_not_a_closed_shard_is_refused_by_name() {
        assert_eq!(
            ExpectedShard::new(ShardId::ZERO, ArchivalLength::ZERO, vec![]),
            Err(ExpectationError::Empty)
        );
        // A coinbase row: no pqc_auth_hash, empty-region prunable hash.
        let coinbase = TxidParts {
            hash: TxHash::from_bytes([9; 32]),
            pqc_auth_hash: None,
            prunable_hash: empty_region_prunable_hash(),
            archival_len: ArchivalLength::ZERO,
        };
        assert_eq!(
            ExpectedShard::new(
                ShardId::ZERO,
                ArchivalLength::ZERO,
                vec![row(1, w() / 2), coinbase, row(2, w() / 2)]
            ),
            Err(ExpectationError::NoArchivalGood { index: 1 })
        );
        // Cumulative-before in shard 1, named as shard 0.
        assert_eq!(
            ExpectedShard::new(
                ShardId::ZERO,
                ArchivalLength::from_raw(w()),
                vec![row(1, w())]
            ),
            Err(ExpectationError::OutsideShard {
                index: 0,
                cum_before: ArchivalLength::from_raw(w())
            })
        );
        // The second row has already crossed into shard 1.
        assert_eq!(
            ExpectedShard::new(
                ShardId::ZERO,
                ArchivalLength::ZERO,
                vec![row(1, w()), row(2, 1)]
            ),
            Err(ExpectationError::OutsideShard {
                index: 1,
                cum_before: ArchivalLength::from_raw(w())
            })
        );
        // Stops one byte short of closing.
        assert_eq!(
            ExpectedShard::new(ShardId::ZERO, ArchivalLength::ZERO, vec![row(1, w() - 1)]),
            Err(ExpectationError::Open {
                cum_after: ArchivalLength::from_raw(w() - 1)
            })
        );
        // A row whose length runs the cumulative sum off `u64`.
        let last = u64::MAX / w();
        let start = last * w();
        assert_eq!(
            ExpectedShard::new(
                ShardId::from_raw(last),
                ArchivalLength::from_raw(start),
                vec![row(1, u64::MAX - start + 1)]
            ),
            Err(ExpectationError::Overflow)
        );
    }
}
