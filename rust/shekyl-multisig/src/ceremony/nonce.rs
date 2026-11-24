// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Nonces, held in memory only (`PQC_MULTISIG.md` §11.3, §11.4; R-20).
//!
//! - A proposer or holder **holds** its round-1 state across the wait for
//!   the other members: a [`HeldNonce`], one `frost_sal::HeldSession` per
//!   input, each owning the cached seed together with the parameters and
//!   keys it was made under. The ceremony puts it into the member's
//!   [`HeldNonceStore`] and keeps no copy.
//! - To sign, the ceremony moves the nonce **out** of the store; only a
//!   nonce taken out is a [`ConsumedNonce`], and only a `ConsumedNonce`
//!   signs. Signing consumes it.
//! - The responder never holds: it preprocesses and signs inside one call.
//! - A member commits to at most one live intent per input
//!   ([`LiveCeremonies`]).
//!
//! **A held nonce never leaves the process (R-20).** The store is an
//! in-memory map the ceremony alone puts into and takes from, and no
//! encoding of a [`HeldNonce`] or a `HeldSession` exists. A nonce on disk
//! would come back on any restore, together with every record of what it
//! had signed, and no type or on-disk counter can detect a rollback of its
//! own disk: a responder that withheld its post-quantum signature could
//! then draw a second share under the same nonce, and a few such replays
//! solve for the member's `y_group` share. Closing the wallet between a
//! member's commit and its share drops (wipes) its nonce, and its part of
//! the ceremony is forfeit: a new intent completes the spend, and no funds
//! are at stake.

use shekyl_engine_state::MultisigState;
use shekyl_types::{BlockHeight, GlobalOutputIndex};

use crate::invariants::ValidatedIntent;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use shekyl_fcmp::frost_sal::HeldSession;

/// One member's held round-1 state for one intent: a session per input,
/// in the transaction's input order. Not `Clone`; each session wipes on
/// drop.
///
/// A held session owns the parameters and keys it was made under, and
/// resumes only with them:
///
/// ```
/// use shekyl_fcmp::frost_sal::HeldSession;
///
/// fn resume(held: HeldSession) {
///     let _ = held.resume();
/// }
/// ```
///
/// There is no resume with other parameters:
///
/// ```compile_fail,E0061
/// use shekyl_fcmp::frost_sal::{HeldSession, SalSigningParams};
///
/// fn resume(held: HeldSession, foreign: SalSigningParams) {
///     let _ = held.resume(foreign);
/// }
/// ```
///
/// and the sign machine has no `cache` and no `from_cache`, so the seed
/// cannot be copied out and resumed under other parameters:
///
/// ```compile_fail,E0599
/// use shekyl_fcmp::frost_sal::SalSignMachine;
/// fn leak(machine: SalSignMachine) {
///     let _ = machine.cache();
/// }
/// ```
///
/// ```compile_fail,E0599
/// use shekyl_fcmp::frost_sal::SalSignMachine;
/// fn rebuild() {
///     let _ = SalSignMachine::from_cache();
/// }
/// ```
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

/// A nonce for this intent is already held: a second round 1 for one
/// intent is refused, never overwritten.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("a nonce for this intent is already held")]
pub struct AlreadyHeld;

/// No nonce is held for this intent: it was never committed, it was
/// already used, or the wallet closed in between (R-20).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("no nonce is held for this intent")]
pub struct NotHeld;

/// A member's held nonces, by intent hash, in memory (R-20). The engine
/// owns one per open wallet; dropping it wipes every nonce it holds.
///
/// Only the ceremony puts a nonce in and takes one out, so no caller can
/// copy a nonce anywhere, a disk included:
///
/// ```compile_fail,E0624
/// use shekyl_multisig::HeldNonceStore;
///
/// fn leak(store: &mut HeldNonceStore, intent_hash: &[u8; 32]) {
///     let _ = store.take(intent_hash);
/// }
/// ```
#[derive(Default)]
pub struct HeldNonceStore {
    held: HashMap<[u8; 32], HeldNonce>,
}

impl std::fmt::Debug for HeldNonceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldNonceStore")
            .field("held", &self.held.len())
            .finish()
    }
}

impl HeldNonceStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a nonce is held for `intent_hash`: the ceremony this wallet
    /// would forfeit by closing.
    #[must_use]
    pub fn holds(&self, intent_hash: &[u8; 32]) -> bool {
        self.held.contains_key(intent_hash)
    }

    /// Store `nonce`, keyed by its intent hash.
    pub(crate) fn put(&mut self, nonce: HeldNonce) -> Result<(), AlreadyHeld> {
        match self.held.entry(nonce.intent_hash) {
            Entry::Occupied(_) => Err(AlreadyHeld),
            Entry::Vacant(slot) => {
                slot.insert(nonce);
                Ok(())
            }
        }
    }

    /// Move the nonce for `intent_hash` out of the store.
    fn take(&mut self, intent_hash: &[u8; 32]) -> Option<HeldNonce> {
        self.held.remove(intent_hash)
    }
}

/// A held nonce taken out of the store: the only thing that signs. Made
/// only by `consume`, so a nonce signs once.
///
/// A holder signs only through its store, which is how it gets its
/// `ConsumedNonce`:
///
/// ```
/// use rand_core::OsRng;
/// use shekyl_multisig::ceremony::files::SigningSet;
/// use shekyl_multisig::ceremony::roles::Committed;
/// use shekyl_multisig::{Authenticated, HeldNonceStore, Holder};
///
/// fn sign(
///     holder: Holder<'_, Committed>,
///     set: &Authenticated<SigningSet>,
///     store: &mut HeldNonceStore,
/// ) {
///     let _ = holder.sign(set, store, &mut OsRng);
/// }
/// ```
///
/// and a `ConsumedNonce` cannot be made from a nonce by hand:
///
/// ```compile_fail,E0423
/// use shekyl_multisig::{ConsumedNonce, HeldNonce};
///
/// fn forge(nonce: HeldNonce) -> ConsumedNonce {
///     ConsumedNonce(nonce)
/// }
/// ```
pub struct ConsumedNonce(HeldNonce);

impl ConsumedNonce {
    /// The intent it was made for.
    #[must_use]
    pub fn intent_hash(&self) -> &[u8; 32] {
        &self.0.intent_hash
    }

    pub(crate) fn into_sessions(self) -> Vec<HeldSession> {
        self.0.sessions
    }
}

/// Take the nonce held for `intent_hash` out of `store` and wrap it.
pub(crate) fn consume(
    intent_hash: &[u8; 32],
    store: &mut HeldNonceStore,
) -> Result<ConsumedNonce, NotHeld> {
    store.take(intent_hash).map(ConsumedNonce).ok_or(NotHeld)
}

/// A member's live ceremonies, by the inputs they spend. A group wallet
/// keeps them in `.wallet.multisig`
/// ([`shekyl_engine_state::MultisigState`]).
pub trait LiveCeremonies {
    /// Record that `intent` spends its inputs, until it lands or its
    /// reference block ages out. The reservation is read from the
    /// validated intent: its hash, its inputs and its reference height. No
    /// caller hands in a list.
    ///
    /// # Errors
    ///
    /// [`ReserveFault::InputInUse`] when another live ceremony at this
    /// member spends one of them, and
    /// [`ReserveFault::ReservationDiffers`] when the stored reservation of
    /// this intent's hash names different inputs or a different reference
    /// height.
    fn reserve(&mut self, intent: &ValidatedIntent) -> Result<(), ReserveFault>;
}

impl LiveCeremonies for MultisigState {
    fn reserve(&mut self, intent: &ValidatedIntent) -> Result<(), ReserveFault> {
        let inputs: Vec<GlobalOutputIndex> = intent
            .intent()
            .input_global_indices
            .iter()
            .map(|&index| GlobalOutputIndex::from_raw(index))
            .collect();
        match MultisigState::reserve(
            self,
            intent.hash(),
            &inputs,
            BlockHeight::from_raw(intent.intent().reference_block_height),
        ) {
            Ok(()) => Ok(()),
            Err(shekyl_engine_state::ReserveError::ReservedElsewhere { input }) => {
                Err(ReserveFault::InputInUse(InputInUse {
                    input: input.to_raw(),
                }))
            }
            Err(shekyl_engine_state::ReserveError::ReservationDiffers) => {
                Err(ReserveFault::ReservationDiffers(ReservationDiffers))
            }
        }
    }
}

/// Another live ceremony at this member already spends this input.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("input {input} is spent by another live ceremony at this member")]
pub struct InputInUse {
    /// The input's global output index.
    pub input: u64,
}

/// The member's records already reserve this intent's hash, and the stored
/// inputs or reference height are not this intent's. The hash commits to
/// both, so the records disagree with the intent.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("this intent is already reserved with different inputs or a different reference height")]
pub struct ReservationDiffers;

/// Why a ceremony did not reserve its intent's inputs.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReserveFault {
    /// Another live ceremony spends one of the inputs.
    #[error(transparent)]
    InputInUse(#[from] InputInUse),
    /// The stored reservation of this intent's hash disagrees with the intent.
    #[error(transparent)]
    ReservationDiffers(#[from] ReservationDiffers),
}

#[cfg(test)]
mod tests {
    use shekyl_fcmp::frost_sal::HeldSession;

    use super::HeldNonce;

    /// Whether `$ty` implements `$trait`, decided at compile time: the
    /// inherent constant exists only when the bound holds, and shadows the
    /// blanket trait's `false`.
    macro_rules! implements {
        ($ty:ty: $($trait:tt)+) => {{
            #[allow(dead_code)]
            trait Fallback {
                const IMPLEMENTS: bool = false;
            }
            impl<T: ?Sized> Fallback for T {}
            struct Probe<T: ?Sized>(core::marker::PhantomData<T>);
            #[allow(dead_code)]
            impl<T: ?Sized + $($trait)+> Probe<T> {
                const IMPLEMENTS: bool = true;
            }
            <Probe<$ty>>::IMPLEMENTS
        }};
    }

    /// A held nonce has no encoding (R-20): neither `HeldNonce` nor
    /// `HeldSession` implements a serialization trait the workspace uses,
    /// so a nonce cannot be written anywhere a restore could bring it
    /// back. The probe is checked on a type that does implement each
    /// trait, so its `false` means what it says (rule 47).
    #[test]
    fn a_held_nonce_has_no_encoding() {
        assert!(implements!(String: serde::Serialize));
        assert!(implements!(String: serde::de::DeserializeOwned));
        assert!(!implements!(HeldNonce: serde::Serialize));
        assert!(!implements!(HeldNonce: serde::de::DeserializeOwned));
        assert!(!implements!(HeldSession: serde::Serialize));
        assert!(!implements!(HeldSession: serde::de::DeserializeOwned));
    }
}
