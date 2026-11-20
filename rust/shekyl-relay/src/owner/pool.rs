// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool as relay reads it: four verbs, implemented by the node over
//! its mempool. Relay never sees a transaction's fields; it sees whether
//! the pool took the bytes, and under which id.

use crate::stem_watch::TxId;

/// What the pool did with one received blob.
///
/// The ids of every blob that parsed, admitted or not, are the arrivals
/// the zone records: a transaction already in the pool still tells the
/// stem watch that it propagated (`DAEMON_RELAY_PRIVACY.md` §46). The
/// two refusals differ in what they say about the peer: a blob that is
/// not a well-formed transaction, or fails a stateless rule, is the
/// peer's fault and severs the session; a blob the current chain state
/// refuses is nobody's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Taken into the pool: the transaction relays.
    Admitted(TxId),
    /// Already held, in the pool or on the chain: nothing to relay.
    Held(TxId),
    /// Parsed and refused on chain state (a spent input, a full pool):
    /// nothing to relay, the session stays.
    RefusedState(TxId),
    /// Not a transaction this chain can read, or one that fails a rule no
    /// state could change. The session closes.
    RefusedForm,
    /// The pool could not answer (the store was unreadable). Logged;
    /// the session stays, the blob is dropped.
    Fault,
}

/// The pool, as the relay owner reaches it.
///
/// Every method is called from a session's task (admission and the
/// complement, while that session's `Taken` is held) or from the relay
/// task. None takes a lock the caller holds.
pub trait PoolDoor: Send + Sync {
    /// Offer a received blob to the pool.
    fn admit(&self, blob: &[u8]) -> Admit;

    /// Whether the pool still holds `tx`, in any relay state.
    fn holds(&self, tx: &TxId) -> bool;

    /// `tx` has been shown to the network: fluffed by this node, or seen
    /// circulating. The pool's relay state moves to shown (Q9) and the tip
    /// follower may rebuild its job.
    fn shown(&self, tx: &TxId);

    /// The pool's transactions whose ids are not in `known`, serialized:
    /// the 2010 answer.
    fn complement(&self, known: &[TxId]) -> Vec<Vec<u8>>;
}
