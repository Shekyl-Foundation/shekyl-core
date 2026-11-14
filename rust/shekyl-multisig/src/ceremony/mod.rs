// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Option E′ signing ceremony (`PQC_MULTISIG.md` §11;
//! `claude/MULTISIG_SLICE3_PRC_CEREMONY_BRIEF.md`).
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
//! - the intent is a [`crate::invariants::ValidatedIntent`], and the
//!   member's [`SigningContext`] is built from it;
//! - a per-output key that matches its committed hash is a
//!   [`proofs::CommittedMemberKey`];
//! - a held nonce owns its parameters ([`nonce::HeldNonce`]); only a
//!   [`nonce::ConsumedNonce`], made after the store gave the nonce up and
//!   the counter persist returned `Ok`, signs;
//! - the responder has one step, which preprocesses and signs in one call
//!   and holds nothing;
//! - each role's state offers only the steps legal from it;
//! - a member signs only a [`proofs::SignableTransaction`], which it
//!   assembled from its own context, the verified proofs and the checked
//!   keys.
//!
//! Every state that spans a wait for another member is rebuilt from what
//! survives a restart: the context, the held-nonce store and the files the
//! member received.

pub mod context;
pub mod files;
pub mod nonce;
pub mod proofs;
pub mod roles;

pub use context::{ContextError, InputContext, ProposerInputs, SigningContext, UnsignedSpend};
pub use files::{import, Authenticated, BodyError, ImportError, Incoming};
pub use nonce::{
    ConsumeError, ConsumedNonce, HeldNonce, HeldNonceStore, InputInUse, LiveCeremonies,
    NonceCounterError, NonceCounterSink, StoreError,
};
pub use proofs::{CommittedMemberKey, SignableTransaction};
pub use roles::{Cosigner, Holder, Proposer, Responder, ResponderInput};

use shekyl_crypto_pq::error::PqcVerifyError;
use shekyl_crypto_pq::multisig_output::MultisigSignError;
use shekyl_fcmp::frost_sal::{FrostError, FrostSalError};

use crate::envelope::SealError;

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
    /// `member`'s role in an intent proposed by `proposer` with responder
    /// `responder`, or `None` if `member` is not among `signers`.
    #[must_use]
    pub fn of(member: u8, proposer: u8, responder: u8, signers: &[u8]) -> Option<Self> {
        if !signers.contains(&member) {
            None
        } else if member == proposer {
            Some(Self::Proposer)
        } else if member == responder {
            Some(Self::Responder)
        } else {
            Some(Self::Holder)
        }
    }
}

/// Why a ceremony step refused. Each names one check.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    /// This member's role in the intent is not the one the step is for.
    #[error("this step is for the {expected:?}; this member is the {actual:?}")]
    WrongRole {
        /// The step's role.
        expected: Role,
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
    /// The FCMP++ prover refused.
    #[error("the FCMP++ prover refused: {0}")]
    Prove(String),
    /// The range prover refused.
    #[error("the range prover refused")]
    RangeProve,
    /// The member's own hybrid signer refused.
    #[error(transparent)]
    MemberSign(#[from] MultisigSignError),
    /// Import of a forwarded file.
    #[error(transparent)]
    Import(#[from] files::ImportError),
    /// Sealing a file.
    #[error(transparent)]
    Seal(#[from] SealError),
    /// The held-nonce store.
    #[error(transparent)]
    Store(#[from] nonce::StoreError),
    /// Consuming the held nonce.
    #[error(transparent)]
    Consume(#[from] nonce::ConsumeError),
    /// Another live ceremony spends one of the intent's inputs.
    #[error(transparent)]
    InputInUse(#[from] nonce::InputInUse),
}
