// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl V3.1 multisig — Option E′ (`PQC_MULTISIG.md` §15.4a).
//!
//! Coordinator-less, equal-participants multisig with deterministic
//! transaction construction and per-output forward privacy. This crate is
//! **pure ceremony logic**: it takes a spend intent + outputs and returns
//! bytes. It owns no ledger, no I/O, and **no transport** — the dependency
//! list is the structural "no transport" ban (MS-1(a)); engine-core wires the
//! returned bytes to the wallet ledger.
//!
//! # Why every output carries per-member keys
//!
//! A fixed group PQC key in plaintext `pqc_auth` would be a ~1996-byte
//! on-chain fingerprint that collapses FCMP++ anonymity. So every output
//! to a group carries a fresh key per member, committed by hash in its
//! leaf (`PQC_MULTISIG.md` §7), and a spend reveals only its `m` signers'
//! keys; the threshold spend secret is a FROST split
//! (`shekyl_fcmp::frost_sal`).
//!
//! The E′ signing ceremony is [`ceremony`]: the roles, the ceremony files, the
//! nonce and proof types that make each honest-signer check a type, over the
//! format modules below.
#![deny(unsafe_code)]

pub mod ceremony;
pub mod envelope;
pub mod group_descriptor;
pub mod intent;
pub mod invariants;
pub mod member_file;
pub mod messages;

pub use ceremony::{
    import, AlreadyHeld, Authenticated, CeremonyError, ConsumedNonce, Cosigner, DeriveError,
    DerivedSpend, GroupOutput, HeldNonce, HeldNonceStore, Holder, ImportError, Incoming,
    InputContext, InputPath, LiveCeremonies, NotHeld, Proposer, ProposerInputs, Responder,
    ResponderInput, Role, SigningContext, UnsignedSpend,
};
pub use envelope::{
    open_envelope, seal_envelope, ImportRefusal, OpenedEnvelope, SealError, MAX_BODY_LEN,
    SENDER_SIG_LEN,
};
pub use group_descriptor::{GroupDescriptor, GroupDescriptorError};
pub use intent::{
    ChainStateFingerprint, SpendIntent, SpendIntentError, MAX_ADDRESS_LEN, MAX_INPUTS,
    MAX_RECIPIENTS,
};
pub use invariants::{IntentRefusal, LedgerView, ValidatedIntent};
pub use member_file::{MemberFile, MemberFileError, MemberSecrets};
pub use messages::MessageType;

#[cfg(test)]
mod tests;
