// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Option E′ signing ceremony (`PQC_MULTISIG.md` §11, §13).
//!
//! # Roles and files
//!
//! The intent names the roles (R-5): the proposer **A**, the responder
//! **B** (`responder_index`), and the holders **H**, every other signer
//! (none when M = 2).
//!
//! | Step | File | From → to | Body |
//! | --- | --- | --- | --- |
//! | 1 | `Proposal` | A → each H (M ≥ 3); A → B (M = 2) | the intent; per input A's preprocess and per-output key |
//! | 2 | `Commitment` | H → A | per input H's preprocess and per-output key |
//! | 3 | `SigningSet` | A → B (M ≥ 3) | the `Proposal` and every `Commitment`, sealed as received |
//! | 4 | `ResponderShare` | B → A | per input B's preprocess, share and per-output key |
//! | 5 | `SigningSet` | A → each H | the `Proposal`, every `Commitment`, B's `ResponderShare` |
//! | 6 | `SignatureShare` | H → A | per input H's share |
//! | 7 | — | A | the SALs, the FCMP++ proof, the range proof, the transaction |
//! | 8 | `FinalTx` | A → B and each H | the proofs, every signer's keys, the `Proposal` |
//! | 9 | `HybridSig` | B, H → A | per input the hybrid signature |
//! | 10 | — | A | the signature containers; `verify_multisig` on every input |
//!
//! M = 2 is files 1, 4, 8 and 9.
//!
//! # The guards are types
//!
//! Every rule is a type whose only constructor runs the check, so the code
//! that signs cannot be reached with an unchecked value:
//!
//! - a file from the member it names is an [`files::Authenticated`], made
//!   only by [`files::import`], and each step takes the one body it
//!   expects;
//! - the intent is a [`crate::invariants::ValidatedIntent`]; the member's
//!   spend is a [`DerivedSpend`], made only by deriving it from that intent
//!   and the member's own ledger, and its [`SigningContext`] is built from
//!   that;
//! - a per-output key that matches its committed hash is a
//!   [`proofs::CommittedMemberKey`];
//! - a held nonce owns its parameters ([`nonce::HeldNonce`]) and lives in
//!   memory only, in a store only the ceremony reaches (R-20); only a
//!   [`nonce::ConsumedNonce`], made by taking the nonce out of the store,
//!   signs;
//! - the responder has one step, which preprocesses and signs in one call
//!   and holds nothing;
//! - each role's state offers only the steps legal from it;
//! - a member signs only a [`proofs::SignableTransaction`], which it
//!   assembled from its own context, the verified proofs and the checked
//!   keys.
//!
//! A proposer's or holder's state across a wait for another member lives
//! in the open wallet only, its held nonce in memory (R-20): closing the
//! wallet between its commit and its share forfeits its part of the
//! ceremony, and a new intent completes the spend. The second round holds
//! no nonce, so a proposer that has finished is rebuilt from the
//! `FinalTx` it sent ([`Proposer::resume_after_finish`]), and a cosigner
//! signs from its context and the `FinalTx` alone.

pub mod context;
pub mod derivation;
pub mod files;
pub mod nonce;
pub mod proofs;
pub mod roles;

pub use context::{ContextError, SigningContext};
pub use derivation::{
    DeriveError, DerivedSpend, GroupOutput, GroupOutputs, InputContext, UnsignedSpend,
};
pub use files::{import, Authenticated, BodyError, ImportError, Incoming};
pub use nonce::{
    AlreadyHeld, ConsumedNonce, HeldNonce, HeldNonceStore, InputInUse, LiveCeremonies, NotHeld,
};
pub use proofs::{CommittedMemberKey, SignableTransaction};
pub use roles::{
    AwaitingSignatures, Collecting, Committed, Cosigner, Holder, Proposer, Responder,
    ResponderInput, SharesPending,
};

use shekyl_bulletproofs::BulletproofError;
use shekyl_crypto_pq::error::PqcVerifyError;
use shekyl_crypto_pq::multisig_output::MultisigSignError;
use shekyl_fcmp::frost_sal::{FrostError, FrostSalError};
use shekyl_fcmp::proof::ProveError;

use crate::envelope::SealError;
use crate::intent::SpendIntent;

/// A member's role in one intent's ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The proposer, A.
    Proposer,
    /// The responder, B.
    Responder,
    /// A holder, H.
    Holder,
}

impl Role {
    /// `member`'s role in `intent` (R-5), or `None` if it does not sign.
    #[must_use]
    pub fn of(intent: &SpendIntent, member: u8) -> Option<Self> {
        if !intent.signers.contains(&member) {
            None
        } else if member == intent.proposer_index {
            Some(Self::Proposer)
        } else if member == intent.responder_index {
            Some(Self::Responder)
        } else {
            Some(Self::Holder)
        }
    }

    /// The roles that run the second round as a cosigner.
    pub const COSIGNERS: &'static [Role] = &[Role::Responder, Role::Holder];
}

/// Why a ceremony step refused. Each names one check.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    /// This member's role in the intent is not one the step is for.
    #[error("this step is for {allowed:?}; this member is the {actual:?}")]
    WrongRole {
        /// The roles the step is for.
        allowed: &'static [Role],
        /// This member's role.
        actual: Role,
    },
    /// The file is for another intent than this member's context.
    #[error("the file is for another intent")]
    IntentMismatch,
    /// The file's sender is not the role that sends this type.
    #[error("member {sender} does not send this file in this intent")]
    Sender {
        /// The sender.
        sender: u8,
    },
    /// A second file of this type from one member.
    #[error("member {member} already sent this file")]
    Duplicate {
        /// The sender.
        member: u8,
    },
    /// Not every signer's file for this step has arrived yet.
    #[error("not every signer's file for this step has arrived")]
    Incomplete,
    /// A per-input list's length is not the intent's input count.
    #[error("a per-input list does not have one entry per input")]
    InputCount,
    /// A forwarded set is not exactly the files this step needs.
    #[error("the signing set is not the signer set's files")]
    SigningSetContents,
    /// A file inside another, or a file a step rebuilds from, is not the
    /// type the step needs.
    #[error("the file is not the type this step needs")]
    FileType,
    /// A per-output key does not hash to its committed hash.
    #[error("member {member}'s key for input {input} does not match its committed hash")]
    KeyHash {
        /// The member.
        member: u8,
        /// The input.
        input: usize,
    },
    /// An input's key blob does not assemble.
    #[error("input {input}'s key blob does not assemble")]
    KeyBlob {
        /// The input.
        input: usize,
    },
    /// The FCMP++ proof does not verify against this member's context.
    #[error("the FCMP++ proof does not verify against this member's context")]
    MembershipProof,
    /// The range proof does not verify against this member's outputs.
    #[error("the range proof does not verify against this member's outputs")]
    RangeProof,
    /// A signer's hybrid signature does not verify.
    #[error("member {member}'s hybrid signature on input {input} does not verify")]
    HybridSignature {
        /// The member.
        member: u8,
        /// The input.
        input: usize,
    },
    /// The assembled authorization does not verify.
    #[error("input {input}'s multisig authorization does not verify: {source}")]
    Authorization {
        /// The input.
        input: usize,
        /// `verify_multisig`'s refusal.
        source: PqcVerifyError,
    },
    /// The held nonce rebuilt a preprocess other than the one sent.
    #[error("the held nonce does not rebuild the preprocess this member sent")]
    HeldNonceMismatch,
    /// A FROST layer refusal for one input.
    #[error("input {input}: {source}")]
    Frost {
        /// The input.
        input: usize,
        /// The refusal.
        source: FrostSalError,
    },
    /// `modular_frost` refused a signing step; for a bad share it names the
    /// signer.
    #[error("input {input}: {source}")]
    Signing {
        /// The input.
        input: usize,
        /// The refusal.
        source: FrostError,
    },
    /// The assembled transaction is not well formed (the wire's
    /// structural rules, which the pool applies before any proof).
    #[error("the assembled transaction is not well formed: {0}")]
    Structure(#[source] std::io::Error),
    /// The FCMP++ prover refused.
    #[error(transparent)]
    Prove(#[from] ProveError),
    /// The range prover refused.
    #[error("the range prover refused: {0}")]
    RangeProve(#[source] BulletproofError),
    /// The member's own hybrid signer refused.
    #[error(transparent)]
    MemberSign(#[from] MultisigSignError),
    /// Import of a forwarded file.
    #[error(transparent)]
    Import(#[from] files::ImportError),
    /// Sealing a file.
    #[error(transparent)]
    Seal(#[from] SealError),
    /// A nonce for this intent is already held.
    #[error(transparent)]
    AlreadyHeld(#[from] nonce::AlreadyHeld),
    /// No nonce is held for this intent.
    #[error(transparent)]
    NotHeld(#[from] nonce::NotHeld),
    /// Another live ceremony spends one of the intent's inputs.
    #[error(transparent)]
    InputInUse(#[from] nonce::InputInUse),
}
