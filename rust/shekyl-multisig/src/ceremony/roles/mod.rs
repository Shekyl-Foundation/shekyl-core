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
    open_forwarded, seal, Authenticated, Body, FinalTx, Incoming, RoundOne, SigningSet,
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

/// Hold a nonce for every input and return this member's first rounds.
///
/// The rounds are checked against the committed hashes before the nonce
/// goes into `store`. A key that does not match drops the sessions, wiped,
/// and leaves the store unchanged.
fn hold_all(
    ctx: &SigningContext<'_>,
    store: &mut impl HeldNonceStore,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CheckedRounds, CeremonyError> {
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
    let rounds = CheckedRounds::new(ctx, ctx.member.member_index(), rounds)?;
    store.put(HeldNonce::new(*ctx.intent.hash(), sessions))?;
    Ok(rounds)
}

/// One member's preprocess per input, in the transaction's input order.
type Preprocesses = Vec<[u8; SAL_PREPROCESS_LEN]>;

/// A member's first round for every input of one context.
///
/// The length is the context's input count, and each key matches its
/// committed hash. [`CheckedRounds::new`] is the only constructor, so a
/// later step indexes a list that has already been refused if it was short
/// or long.
struct CheckedRounds {
    rounds: Vec<RoundOne>,
}

impl CheckedRounds {
    /// Check `rounds` as `member`'s first round for every input of `ctx`.
    fn new(
        ctx: &SigningContext<'_>,
        member: u8,
        rounds: Vec<RoundOne>,
    ) -> Result<Self, CeremonyError> {
        check_rounds(ctx, member, rounds.iter())?;
        Ok(Self { rounds })
    }

    fn len(&self) -> usize {
        self.rounds.len()
    }

    fn rounds(&self) -> &[RoundOne] {
        &self.rounds
    }

    /// The preprocess for `input`.
    fn preprocess(&self, input: usize) -> Result<[u8; SAL_PREPROCESS_LEN], CeremonyError> {
        self.rounds
            .get(input)
            .map(|round| round.preprocess)
            .ok_or(CeremonyError::InputCount)
    }

    /// The per-output key for `input`.
    fn key(&self, input: usize) -> Result<&HybridPublicKey, CeremonyError> {
        self.rounds
            .get(input)
            .map(|round| &round.key)
            .ok_or(CeremonyError::InputCount)
    }

    fn preprocesses(&self) -> Preprocesses {
        self.rounds.iter().map(|round| round.preprocess).collect()
    }
}

/// The other signers' preprocesses, per member, per input: exactly the
/// intent's signers but this member, once each, each a [`CheckedRounds`].
/// Made only by [`PreprocessSet::new`], and signing takes one, never a
/// bare map. This member's own preprocess is the one its machine produces,
/// so "mine is the one I sent" holds by construction.
struct PreprocessSet(BTreeMap<u8, Preprocesses>);

impl PreprocessSet {
    fn new(
        ctx: &SigningContext<'_>,
        others: impl IntoIterator<Item = (u8, CheckedRounds)>,
    ) -> Result<Self, CeremonyError> {
        let mut set = BTreeMap::new();
        let inputs = ctx.inputs.len();
        for (member, rounds) in others {
            if rounds.len() != inputs {
                return Err(CeremonyError::InputCount);
            }
            if set.insert(member, rounds.preprocesses()).is_some() {
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
                let bytes = per_input.get(input).ok_or(CeremonyError::InputCount)?;
                read_preprocess(machine, bytes)
                    .map(|preprocess| (participant(member), preprocess))
                    .map_err(|source| CeremonyError::Frost { input, source })
            })
            .collect()
    }
}

/// Resume a consumed nonce and sign every input over `set`. The session
/// count is `sent`'s length, and each rebuilt preprocess is the one this
/// member sent. A short or long nonce signs nothing.
fn sign_held(
    consumed: ConsumedNonce,
    sent: &CheckedRounds,
    set: &PreprocessSet,
) -> Result<Vec<(SalSignatureMachine, SalShare)>, CeremonyError> {
    let sessions = consumed.into_sessions();
    if sessions.len() != sent.len() {
        return Err(CeremonyError::HeldNonceMismatch);
    }
    sessions
        .into_iter()
        .enumerate()
        .map(|(input, session)| {
            let (machine, rebuilt) = session
                .resume()
                .map_err(|source| CeremonyError::Frost { input, source })?;
            if sent.preprocess(input)? != preprocess_bytes(&rebuilt) {
                return Err(CeremonyError::HeldNonceMismatch);
            }
            let preprocesses = set.read(&machine, input)?;
            sign(machine, preprocesses).map_err(|source| CeremonyError::Signing { input, source })
        })
        .collect()
}

/// A forwarded set, opened: each file under its own sender's signature,
/// for this intent, every first round a [`CheckedRounds`]. A responder's
/// shares are not kept: the holder signs from the rounds, and the proposer
/// reads the shares from the file it stored.
#[derive(Default)]
struct OpenedSet {
    proposal: Option<CheckedRounds>,
    commitments: BTreeMap<u8, CheckedRounds>,
    responder: Option<(u8, CheckedRounds)>,
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
                    let sender = p.sender();
                    let rounds = CheckedRounds::new(ctx, sender, p.into_body().rounds)?;
                    if opened.proposal.replace(rounds).is_some() {
                        return Err(CeremonyError::Duplicate { member: sender });
                    }
                }
                Incoming::Commitment(c) => {
                    from_role(ctx, &c, Role::Holder)?;
                    let sender = c.sender();
                    let rounds = CheckedRounds::new(ctx, sender, c.into_body().rounds)?;
                    if opened.commitments.insert(sender, rounds).is_some() {
                        return Err(CeremonyError::Duplicate { member: sender });
                    }
                }
                Incoming::ResponderShare(r) => {
                    from_role(ctx, &r, Role::Responder)?;
                    let sender = r.sender();
                    let rounds = CheckedRounds::new(
                        ctx,
                        sender,
                        r.into_body()
                            .inputs
                            .into_iter()
                            .map(|input| input.round)
                            .collect(),
                    )?;
                    if opened.responder.replace((sender, rounds)).is_some() {
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
