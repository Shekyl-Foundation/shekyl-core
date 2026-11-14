// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The responder, B: often the device kept in a safe. Its round 1 is one
//! call that preprocesses and signs, so it never holds a nonce
//! (`PQC_MULTISIG.md` §11.1, step 4; §11.4).

use rand::{CryptoRng, RngCore};
use shekyl_fcmp::frost_sal::{preprocess, preprocess_bytes, share_bytes, sign};

use super::super::context::SigningContext;
use super::super::files::{
    Authenticated, Proposal, ResponderRound, ResponderShare, RoundOne, SigningSet,
};
use super::super::nonce::LiveCeremonies;
use super::super::{CeremonyError, Role};
use super::{
    check_rounds, expect_role, from_role, own_keys, preprocesses, seal_as, OpenedSet,
    PreprocessSet, Preprocesses,
};

/// What the responder receives: the `Proposal` when M = 2, the proposer's
/// `SigningSet` otherwise.
#[derive(Clone, Copy)]
pub enum ResponderInput<'f> {
    /// M = 2.
    Proposal(&'f Authenticated<Proposal>),
    /// M ≥ 3.
    SigningSet(&'f Authenticated<SigningSet>),
}

/// The responder, B: one step, which preprocesses and signs inside one
/// call. It holds no nonce and has no way to cache one.
///
/// Its one transition takes no nonce store and returns only its share
/// file:
///
/// ```
/// use rand_core::OsRng;
/// use shekyl_multisig::{LiveCeremonies, Responder, ResponderInput, SigningContext};
///
/// fn respond(ctx: &SigningContext<'_>, received: ResponderInput<'_>, live: &mut impl LiveCeremonies) {
///     let _: Result<Vec<u8>, _> = Responder::respond(ctx, received, live, &mut OsRng);
/// }
/// ```
///
/// so a responder cannot put a nonce away:
///
/// ```compile_fail,E0061
/// use rand_core::OsRng;
/// use shekyl_multisig::{
///     HeldNonceStore, LiveCeremonies, Responder, ResponderInput, SigningContext,
/// };
///
/// fn respond(
///     ctx: &SigningContext<'_>,
///     received: ResponderInput<'_>,
///     store: &mut impl HeldNonceStore,
///     live: &mut impl LiveCeremonies,
/// ) {
///     let _ = Responder::respond(ctx, received, store, live, &mut OsRng);
/// }
/// ```
pub struct Responder;

impl Responder {
    /// Step 4: check every other signer's round 1, reserve the inputs,
    /// preprocess and sign every input in one call, and write the
    /// `ResponderShare`.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: this member is not the responder, the file is the
    /// wrong one for the group's size or not from the proposer, the set is
    /// not exactly the other signers', a key does not match, an input is in
    /// another live ceremony, or a FROST or seal refusal.
    pub fn respond(
        ctx: &SigningContext<'_>,
        received: ResponderInput<'_>,
        live: &mut impl LiveCeremonies,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, CeremonyError> {
        expect_role(ctx, &[Role::Responder])?;
        let set = PreprocessSet::new(ctx, Self::others(ctx, received)?)?;
        live.reserve(ctx.intent.hash(), &ctx.intent.intent().input_global_indices)?;
        let inputs = own_keys(ctx)?
            .into_iter()
            .enumerate()
            .map(|(input, key)| {
                let (machine, own) = preprocess(&ctx.params(input), ctx.keys.clone(), rng)
                    .map_err(|source| CeremonyError::Frost { input, source })?;
                let preprocesses = set.read(&machine, input)?;
                let (_, share) = sign(machine, preprocesses)
                    .map_err(|source| CeremonyError::Signing { input, source })?;
                Ok(ResponderRound {
                    round: RoundOne {
                        preprocess: preprocess_bytes(&own),
                        key,
                    },
                    share: share_bytes(&share),
                })
            })
            .collect::<Result<_, CeremonyError>>()?;
        seal_as(ctx, &ResponderShare { inputs }, rng)
    }

    /// Every other signer's preprocesses, from what the responder received:
    /// with no holders the `Proposal`; otherwise the `SigningSet`, which
    /// carries the `Proposal` and every `Commitment` and no responder's
    /// rounds.
    fn others(
        ctx: &SigningContext<'_>,
        received: ResponderInput<'_>,
    ) -> Result<Vec<(u8, Preprocesses)>, CeremonyError> {
        let proposer = ctx.intent.intent().proposer_index;
        let has_holders = ctx.holders().next().is_some();
        match received {
            ResponderInput::Proposal(p) if !has_holders => {
                from_role(ctx, p, Role::Proposer)?;
                check_rounds(ctx, p.sender(), p.body().rounds.iter())?;
                Ok(vec![(proposer, preprocesses(&p.body().rounds))])
            }
            ResponderInput::SigningSet(set) if has_holders => {
                let OpenedSet {
                    proposal: Some(proposal),
                    commitments,
                    responder: None,
                } = OpenedSet::open(ctx, set)?
                else {
                    return Err(CeremonyError::SigningSetContents);
                };
                Ok(std::iter::once((proposer, preprocesses(&proposal)))
                    .chain(
                        commitments
                            .iter()
                            .map(|(&holder, rounds)| (holder, preprocesses(rounds))),
                    )
                    .collect())
            }
            _ => Err(CeremonyError::SigningSetContents),
        }
    }
}
