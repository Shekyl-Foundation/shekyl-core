// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The roles: [`Proposer`], [`Holder`], [`Responder`], and [`Cosigner`]
//! for the second round every signer but the proposer runs
//! (`PQC_MULTISIG.md` §11.1).
//!
//! Each state is a type with only the steps legal from it, and each step
//! takes the one [`Authenticated`] body that phase expects, so a file out
//! of phase cannot be passed. Every state that spans a wait for another
//! member is rebuilt after a restart from what survives it
//! (`PQC_MULTISIG.md` §13.1): the proposer from the last file it sent (its
//! `Proposal`, then its `FinalTx`) and the files it received; a holder as
//! [`Holder::committed`], its held nonce being the durable fact; the second
//! round is stateless.
//!
//! This module holds the steps the roles share: who may send what, the
//! round-1 contributions and their keys, the preprocess set, signing from a
//! held nonce, opening a forwarded set, and the check of a `FinalTx`.

mod cosigner;
mod holder;
mod proposer;
mod responder;

pub use cosigner::Cosigner;
pub use holder::{Committed, Holder};
pub use proposer::{AwaitingSignatures, Collecting, Proposer, SharesPending};
pub use responder::{Responder, ResponderInput};

use std::collections::{BTreeMap, HashMap};

use rand::{CryptoRng, RngCore};
use shekyl_crypto_pq::multisig_output::multisig_member_public_key;
use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_fcmp::frost_sal::{
    hold, participant, preprocess_bytes, read_preprocess, sign, Participant, SalPreprocess,
    SalShare, SalSignMachine, SalSignatureMachine, SAL_PREPROCESS_LEN,
};

use super::context::SigningContext;
use super::files::{
    open_forwarded, seal, Authenticated, Body, FinalTx, Incoming, ResponderRound, RoundOne,
    SigningSet,
};
use super::nonce::{ConsumedNonce, HeldNonce, HeldNonceStore};
use super::proofs::{
    CommittedMemberKey, SignableTransaction, SignerKeys, VerifiedMembershipProof,
    VerifiedRangeProof,
};
use super::{CeremonyError, Role};

// ---------------------------------------------------------------------------
// Who may send what
// ---------------------------------------------------------------------------

/// This member's role is one of `allowed`.
fn expect_role(ctx: &SigningContext<'_>, allowed: &'static [Role]) -> Result<(), CeremonyError> {
    let actual = ctx.role();
    if allowed.contains(&actual) {
        Ok(())
    } else {
        Err(CeremonyError::WrongRole { allowed, actual })
    }
}

/// The file is for this context's intent, and from a member with `role`.
fn from_role<B>(
    ctx: &SigningContext<'_>,
    file: &Authenticated<B>,
    role: Role,
) -> Result<(), CeremonyError> {
    if file.intent_hash() != ctx.intent.hash() {
        return Err(CeremonyError::IntentMismatch);
    }
    if ctx.role_of(file.sender()) != Some(role) {
        return Err(CeremonyError::Sender {
            sender: file.sender(),
        });
    }
    Ok(())
}

/// Seal `body` as this member's file for its intent.
fn seal_as<B: Body>(
    ctx: &SigningContext<'_>,
    body: &B,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>, CeremonyError> {
    Ok(seal(
        ctx.member,
        &ctx.network_id,
        ctx.intent.hash(),
        body,
        rng,
    )?)
}

// ---------------------------------------------------------------------------
// Round 1
// ---------------------------------------------------------------------------

/// This member's per-output key for every input.
fn own_keys(ctx: &SigningContext<'_>) -> Result<Vec<HybridPublicKey>, CeremonyError> {
    let view = ctx.signing_view();
    (0..ctx.inputs.len())
        .map(|input| {
            multisig_member_public_key(&view, &ctx.own_ciphertext(input))
                .map_err(CeremonyError::MemberSign)
        })
        .collect()
}

/// Check `member`'s first rounds on receipt: one per input, each key
/// matching its committed hash.
fn check_rounds<'r>(
    ctx: &SigningContext<'_>,
    member: u8,
    rounds: impl ExactSizeIterator<Item = &'r RoundOne>,
) -> Result<(), CeremonyError> {
    if rounds.len() != ctx.inputs.len() {
        return Err(CeremonyError::InputCount);
    }
    for (input, round) in rounds.enumerate() {
        CommittedMemberKey::check(ctx, input, member, round.key.clone())?;
    }
    Ok(())
}

/// Hold a nonce for every input, put it in `store`, and return this
/// member's first rounds.
fn hold_all(
    ctx: &SigningContext<'_>,
    store: &mut impl HeldNonceStore,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<RoundOne>, CeremonyError> {
    let keys = own_keys(ctx)?;
    let mut sessions = Vec::with_capacity(keys.len());
    let mut rounds = Vec::with_capacity(keys.len());
    for (input, key) in keys.into_iter().enumerate() {
        let (session, preprocess) = hold(ctx.params(input), ctx.keys.clone(), rng)
            .map_err(|source| CeremonyError::Frost { input, source })?;
        sessions.push(session);
        rounds.push(RoundOne {
            preprocess: preprocess_bytes(&preprocess),
            key,
        });
    }
    store.put(HeldNonce::new(*ctx.intent.hash(), sessions))?;
    Ok(rounds)
}

/// One member's preprocess per input.
type Preprocesses = Vec<[u8; SAL_PREPROCESS_LEN]>;

/// The preprocesses of `rounds`, in input order.
fn preprocesses<'r>(rounds: impl IntoIterator<Item = &'r RoundOne>) -> Preprocesses {
    rounds.into_iter().map(|round| round.preprocess).collect()
}

/// The preprocesses of the responder's rounds, in input order.
fn responder_preprocesses(rounds: &[ResponderRound]) -> Preprocesses {
    preprocesses(rounds.iter().map(|r| &r.round))
}

/// The other signers' preprocesses, per member, per input: exactly the
/// intent's signers but this member, once each, each read from a file its
/// sender signed whose keys were checked on receipt. Made only by
/// [`PreprocessSet::new`], and signing takes one, never a bare map. This
/// member's own preprocess is the one its machine produces, so "mine is
/// the one I sent" holds by construction.
struct PreprocessSet(BTreeMap<u8, Preprocesses>);

impl PreprocessSet {
    fn new(
        ctx: &SigningContext<'_>,
        others: impl IntoIterator<Item = (u8, Preprocesses)>,
    ) -> Result<Self, CeremonyError> {
        let mut set = BTreeMap::new();
        for (member, preprocesses) in others {
            if set.insert(member, preprocesses).is_some() {
                return Err(CeremonyError::Duplicate { member });
            }
        }
        let me = ctx.member.member_index();
        let expected = ctx.intent.intent().signers.iter().filter(|&&m| m != me);
        if !set.keys().eq(expected) {
            return Err(CeremonyError::SigningSetContents);
        }
        Ok(Self(set))
    }

    /// The set for one input, read by `machine`.
    fn read(
        &self,
        machine: &SalSignMachine,
        input: usize,
    ) -> Result<HashMap<Participant, SalPreprocess>, CeremonyError> {
        self.0
            .iter()
            .map(|(&member, per_input)| {
                read_preprocess(machine, &per_input[input])
                    .map(|preprocess| (participant(member), preprocess))
                    .map_err(|source| CeremonyError::Frost { input, source })
            })
            .collect()
    }
}

/// Resume a consumed nonce and sign every input over `set`; each rebuilt
/// preprocess must be the one this member `sent`.
fn sign_held(
    consumed: ConsumedNonce,
    sent: &[RoundOne],
    set: &PreprocessSet,
) -> Result<Vec<(SalSignatureMachine, SalShare)>, CeremonyError> {
    consumed
        .into_sessions()
        .into_iter()
        .enumerate()
        .map(|(input, session)| {
            let (machine, rebuilt) = session
                .resume()
                .map_err(|source| CeremonyError::Frost { input, source })?;
            if sent.get(input).map(|round| round.preprocess) != Some(preprocess_bytes(&rebuilt)) {
                return Err(CeremonyError::HeldNonceMismatch);
            }
            let preprocesses = set.read(&machine, input)?;
            sign(machine, preprocesses).map_err(|source| CeremonyError::Signing { input, source })
        })
        .collect()
}

/// A forwarded set, opened: each file under its own sender's signature,
/// for this intent, every key checked. The round-1 contributions by
/// member, and the responder's rounds if the set carries them.
#[derive(Default)]
struct OpenedSet {
    proposal: Option<Vec<RoundOne>>,
    commitments: BTreeMap<u8, Vec<RoundOne>>,
    responder: Option<(u8, Vec<ResponderRound>)>,
}

impl OpenedSet {
    fn open(
        ctx: &SigningContext<'_>,
        set: &Authenticated<SigningSet>,
    ) -> Result<Self, CeremonyError> {
        from_role(ctx, set, Role::Proposer)?;
        let mut opened = Self::default();
        for file in &set.body().files {
            match open_forwarded(ctx.member, &ctx.network_id, ctx.intent.hash(), file)? {
                Incoming::Proposal(p) => {
                    from_role(ctx, &p, Role::Proposer)?;
                    check_rounds(ctx, p.sender(), p.body().rounds.iter())?;
                    if opened.proposal.replace(p.into_body().rounds).is_some() {
                        return Err(CeremonyError::Duplicate {
                            member: ctx.intent.intent().proposer_index,
                        });
                    }
                }
                Incoming::Commitment(c) => {
                    from_role(ctx, &c, Role::Holder)?;
                    check_rounds(ctx, c.sender(), c.body().rounds.iter())?;
                    let sender = c.sender();
                    if opened
                        .commitments
                        .insert(sender, c.into_body().rounds)
                        .is_some()
                    {
                        return Err(CeremonyError::Duplicate { member: sender });
                    }
                }
                Incoming::ResponderShare(r) => {
                    from_role(ctx, &r, Role::Responder)?;
                    check_rounds(ctx, r.sender(), r.body().inputs.iter().map(|i| &i.round))?;
                    let sender = r.sender();
                    if opened
                        .responder
                        .replace((sender, r.into_body().inputs))
                        .is_some()
                    {
                        return Err(CeremonyError::Duplicate { member: sender });
                    }
                }
                _ => return Err(CeremonyError::SigningSetContents),
            }
        }
        Ok(opened)
    }
}

// ---------------------------------------------------------------------------
// Round 2
// ---------------------------------------------------------------------------

/// Check a `FinalTx` from the proposer and assemble, from this member's own
/// context, the transaction it describes: the `Proposal` inside opens for
/// this intent from the proposer, every signer's key matches its committed
/// hash, and both proofs verify against this member's own spend.
fn check_final_tx(
    ctx: &SigningContext<'_>,
    final_tx: &Authenticated<FinalTx>,
) -> Result<(SignerKeys, SignableTransaction), CeremonyError> {
    from_role(ctx, final_tx, Role::Proposer)?;
    let body = final_tx.body();
    let Incoming::Proposal(proposal) = open_forwarded(
        ctx.member,
        &ctx.network_id,
        ctx.intent.hash(),
        &body.proposal_file,
    )?
    else {
        return Err(CeremonyError::FileType);
    };
    from_role(ctx, &proposal, Role::Proposer)?;
    let keys = SignerKeys::check(ctx, body.keys.clone())?;
    let membership = VerifiedMembershipProof::verify(ctx, body.fcmp_proof.clone())?;
    let range = VerifiedRangeProof::verify(ctx, &body.range_proof)?;
    let signable = SignableTransaction::assemble(ctx, &membership, &range, &keys)?;
    Ok((keys, signable))
}
