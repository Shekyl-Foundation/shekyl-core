// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Nonces, and the durable writes the ceremony needs but does not own
//! (brief §4, §3A).
//!
//! - A proposer or holder **holds** its round-1 state across the wait for
//!   the other members: a [`HeldNonce`], one `frost_sal::HeldSession` per
//!   input, each owning the cached seed together with the parameters and
//!   keys it was made under. The ceremony puts it into a [`HeldNonceStore`]
//!   the caller injects and keeps no copy.
//! - To sign, the ceremony moves the nonce **out** of the store
//!   ([`HeldNonceStore::take`]), then durably advances the member's nonce
//!   counter ([`NonceCounterSink`]). Only a successful persist wraps the
//!   nonce in a [`ConsumedNonce`], and only a `ConsumedNonce` signs; signing
//!   consumes it. If the persist fails, the nonce is dropped (wiped) and the
//!   ceremony is forfeit: a new intent is needed.
//! - The responder never holds: it preprocesses and signs inside one call.
//! - A member commits to at most one live intent per input
//!   ([`LiveCeremonies`]).
//!
//! What types cannot do: a disk restored from a backup can hand a consumed
//! `HeldNonce` back, or a store whose `take` returned before its delete was
//! durable can. Both are the store's contract (slice 4a: held nonces are
//! excluded from backups, a restore cancels every open ceremony, and
//! `take` deletes durably before it returns).

use shekyl_fcmp::frost_sal::HeldSession;

/// One member's held round-1 state for one intent: a session per input,
/// in the intent's input order. Not `Clone`; each session wipes on drop.
pub struct HeldNonce {
    intent_hash: [u8; 32],
    sessions: Vec<HeldSession>,
}

impl std::fmt::Debug for HeldNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldNonce")
            .field("intent_hash", &self.intent_hash)
            .field("inputs", &self.sessions.len())
            .finish_non_exhaustive()
    }
}

impl HeldNonce {
    pub(crate) fn new(intent_hash: [u8; 32], sessions: Vec<HeldSession>) -> Self {
        Self {
            intent_hash,
            sessions,
        }
    }

    /// The intent this nonce was made for.
    #[must_use]
    pub fn intent_hash(&self) -> &[u8; 32] {
        &self.intent_hash
    }
}

/// Why the store refused.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A nonce for this intent is already held.
    #[error("a nonce for this intent is already held")]
    AlreadyHeld,
    /// The durable write or delete failed.
    #[error("the held-nonce store failed: {0}")]
    Durable(String),
}

/// Where held nonces live between a member's two visits. Slice 4a puts it
/// in the same protected container as the member's `y_group` share.
pub trait HeldNonceStore {
    /// Store `nonce`, keyed by its intent hash.
    ///
    /// # Errors
    ///
    /// [`StoreError::AlreadyHeld`] when a nonce for that intent is held:
    /// a second round 1 for one intent is refused, never overwritten.
    fn put(&mut self, nonce: HeldNonce) -> Result<(), StoreError>;

    /// Move the nonce for `intent_hash` out of the store. The store's
    /// copy is deleted durably before this returns.
    ///
    /// # Errors
    ///
    /// [`StoreError::Durable`] when the delete is not durable.
    fn take(&mut self, intent_hash: &[u8; 32]) -> Result<Option<HeldNonce>, StoreError>;
}

/// The member's durable, monotonic nonce counter.
pub trait NonceCounterSink {
    /// The value the next persist must write: one past the last durable
    /// value.
    fn next_nonce_counter(&self) -> u64;

    /// Durably record that the nonce for `intent_hash` is used, at
    /// `counter`. Returns only once the write is durable.
    ///
    /// # Errors
    ///
    /// [`NonceCounterError`] when the write is not durable.
    fn persist_nonce_counter(
        &mut self,
        intent_hash: &[u8; 32],
        counter: u64,
    ) -> Result<(), NonceCounterError>;
}

/// The nonce counter's durable write failed.
#[derive(Debug, thiserror::Error)]
#[error("the durable nonce-counter persist failed: {0}")]
pub struct NonceCounterError(pub String);

/// A held nonce whose use is durably recorded: the only thing that signs.
/// Made only by [`consume`], after the store has given the nonce up and
/// the counter persist has returned `Ok`.
pub struct ConsumedNonce {
    nonce: HeldNonce,
    counter: u64,
}

impl ConsumedNonce {
    /// The counter value its use was recorded at.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The intent it was made for.
    #[must_use]
    pub fn intent_hash(&self) -> &[u8; 32] {
        &self.nonce.intent_hash
    }

    pub(crate) fn into_sessions(self) -> Vec<HeldSession> {
        self.nonce.sessions
    }
}

/// Why a held nonce could not be consumed.
#[derive(Debug, thiserror::Error)]
pub enum ConsumeError {
    /// No nonce is held for this intent: it was never committed, or it
    /// was already used.
    #[error("no nonce is held for this intent")]
    NotHeld,
    /// The store refused.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The counter persist failed; the nonce is dropped and the ceremony
    /// is forfeit.
    #[error(transparent)]
    Persist(#[from] NonceCounterError),
}

/// Take the nonce held for `intent_hash` out of `store`, persist its use,
/// and wrap it. The order is the rule: out of the store, then the durable
/// counter, then usable.
pub(crate) fn consume(
    intent_hash: &[u8; 32],
    store: &mut impl HeldNonceStore,
    sink: &mut impl NonceCounterSink,
) -> Result<ConsumedNonce, ConsumeError> {
    let nonce = store.take(intent_hash)?.ok_or(ConsumeError::NotHeld)?;
    let counter = sink.next_nonce_counter();
    sink.persist_nonce_counter(intent_hash, counter)?;
    Ok(ConsumedNonce { nonce, counter })
}

/// A member's live ceremonies, by the inputs they spend. Slice 4a keeps
/// it in the wallet ledger.
pub trait LiveCeremonies {
    /// Record that `intent_hash` spends `inputs` (global output indices).
    ///
    /// # Errors
    ///
    /// [`InputInUse`] when another live ceremony at this member spends
    /// one of them.
    fn reserve(&mut self, intent_hash: &[u8; 32], inputs: &[u64]) -> Result<(), InputInUse>;
}

/// Another live ceremony at this member already spends this input.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("input {input} is spent by another live ceremony at this member")]
pub struct InputInUse {
    /// The input's global output index.
    pub input: u64,
}
