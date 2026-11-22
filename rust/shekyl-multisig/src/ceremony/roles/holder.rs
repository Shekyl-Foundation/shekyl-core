// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A holder, H: every signer but the proposer and the responder. It holds
//! a nonce between the rounds (`PQC_MULTISIG.md` §11.1, steps 2 and 6;
//! §11.4).

use std::marker::PhantomData;

use rand::{CryptoRng, RngCore};
use shekyl_fcmp::frost_sal::share_bytes;

use super::super::context::SigningContext;
use super::super::files::{Authenticated, Commitment, Proposal, SignatureShare, SigningSet};
use super::super::nonce::{consume, HeldNonceStore, LiveCeremonies};
use super::super::{CeremonyError, Role};
use super::{
    check_rounds, expect_role, from_role, hold_all, seal_as, sign_held, OpenedSet, PreprocessSet,
};

/// A holder, H, in state `S`.
pub struct Holder<'a, S> {
    ctx: SigningContext<'a>,
    state: PhantomData<S>,
}

/// Committed: this member's nonce is held; waiting for the `SigningSet`.
pub struct Committed;

impl<'a> Holder<'a, Committed> {
    /// Step 1 received, step 2 sent: check the proposer's keys, reserve the
    /// inputs, hold a nonce per input, and write the `Commitment`.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: this member is not a holder, the `Proposal` is
    /// for another intent, a key does not match, an input is in another
    /// live ceremony, or a nonce for this intent is already held.
    pub fn commit(
        ctx: SigningContext<'a>,
        proposal: &Authenticated<Proposal>,
        store: &mut HeldNonceStore,
        live: &mut impl LiveCeremonies,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Self, Vec<u8>), CeremonyError> {
        expect_role(&ctx, &[Role::Holder])?;
        from_role(&ctx, proposal, Role::Proposer)?;
        check_rounds(&ctx, proposal.sender(), proposal.body().rounds.iter())?;
        live.reserve(&ctx.intent)?;
        let rounds = hold_all(&ctx, store, rng)?;
        let file = seal_as(
            &ctx,
            &Commitment {
                rounds: rounds.rounds().to_vec(),
            },
            rng,
        )?;
        Ok((
            Self {
                ctx,
                state: PhantomData,
            },
            file,
        ))
    }

    /// Step 5 received, step 6 sent: open every forwarded file under its
    /// own sender's signature, check the set is exactly the other signers',
    /// consume the held nonce, sign every input, and write the
    /// `SignatureShare`.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: the set is not from the proposer, a forwarded
    /// file does not open or is not this intent's, the set is not exactly
    /// the other signers', the nonce is not held (it was used, or the
    /// wallet closed since the commit: R-20), or a FROST or seal refusal.
    pub fn sign(
        self,
        set: &Authenticated<SigningSet>,
        store: &mut HeldNonceStore,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, CeremonyError> {
        let ctx = &self.ctx;
        let OpenedSet {
            proposal: Some(proposal),
            mut commitments,
            responder: Some((responder, responder_rounds)),
        } = OpenedSet::open(ctx, set)?
        else {
            return Err(CeremonyError::SigningSetContents);
        };
        // This member's own Commitment, forwarded back: the preprocess its
        // held nonce must rebuild.
        let own = commitments
            .remove(&ctx.member.member_index())
            .ok_or(CeremonyError::SigningSetContents)?;
        let set = PreprocessSet::new(
            ctx,
            commitments.into_iter().chain([
                (ctx.intent.intent().proposer_index, proposal),
                (responder, responder_rounds),
            ]),
        )?;
        let consumed = consume(ctx.intent.hash(), store)?;
        let shares = sign_held(consumed, &own, &set)?
            .iter()
            .map(|(_, share)| share_bytes(share))
            .collect();
        seal_as(ctx, &SignatureShare { shares }, rng)
    }
}
