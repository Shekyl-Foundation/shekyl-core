// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The proposer, A: it proposes, collects every other signer's round 1 and
//! shares, completes the SALs, proves, and assembles and releases the
//! transaction (`PQC_MULTISIG.md` §11.1, steps 1, 3, 5, 7 and 10).
//!
//! Each state carries only what its steps need. The inputs' tree paths and
//! the outputs' openings are the context's own, derived from the intent
//! and the proposer's ledger; the prover's leaf chunks are made from them
//! at [`Proposer::finish`] and wiped when the proof is made. Until [`Proposer::finish`] the proposer's
//! nonce is held in memory only (R-20): a restart forfeits its ceremony. A
//! proposer that has finished holds no nonce and is rebuilt from the
//! `FinalTx` it sent ([`Proposer::resume_after_finish`]).

use std::collections::{BTreeMap, HashMap};

use rand::{CryptoRng, RngCore};
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::multisig::{
    verify_multisig, MultisigSigContainer, HYBRID_SCHEME_ID_MULTISIG,
};
use shekyl_crypto_pq::signature::{HybridPublicKey, HybridSignature};
use shekyl_curve_primitives::Commitment as Opening;
use shekyl_fcmp::frost_sal::{
    complete, participant, read_share, SalShare, SalSignatureMachine, SalSigningParams,
};
use shekyl_fcmp::proof::{prove_with_sal, ProveInputLeafChunk};
use shekyl_wire::{Ct, Transaction};

use super::super::context::SigningContext;
use super::super::derivation::InputContext;
use super::super::files::{
    open_forwarded, Authenticated, Commitment, FinalTx, HybridSig, Incoming, Proposal,
    ResponderShare, SignatureShare, SigningSet,
};
use super::super::nonce::{consume, HeldNonceStore, LiveCeremonies};
use super::super::proofs::{
    SignableTransaction, SignerKeys, VerifiedMembershipProof, VerifiedRangeProof,
};
use super::super::{CeremonyError, Role};
use super::{
    check_final_tx, check_rounds, expect_role, from_role, hold_all, seal_as, sign_held,
    CheckedRounds, PreprocessSet,
};

/// The proposer, A, in state `S`.
pub struct Proposer<'a, S> {
    ctx: SigningContext<'a>,
    proposal_file: Vec<u8>,
    state: S,
}

/// Waiting for every holder's `Commitment`, then the responder's share.
pub struct Collecting {
    own: CheckedRounds,
    commitments: BTreeMap<u8, Authenticated<Commitment>>,
}

/// The responder's share is in; waiting for every holder's share.
pub struct SharesPending {
    own: CheckedRounds,
    commitments: BTreeMap<u8, Authenticated<Commitment>>,
    responder: Authenticated<ResponderShare>,
    holder_shares: BTreeMap<u8, Authenticated<SignatureShare>>,
}

/// The transaction is assembled and the `FinalTx` written; waiting for
/// every other signer's hybrid signatures.
pub struct AwaitingSignatures {
    keys: SignerKeys,
    signable: SignableTransaction,
    signatures: BTreeMap<u8, Vec<HybridSignature>>,
}

impl<'a, S> Proposer<'a, S> {
    /// The file every forwarded set and the `FinalTx` carry.
    fn proposal_file(&self) -> Vec<u8> {
        self.proposal_file.clone()
    }
}

impl<'a> Proposer<'a, Collecting> {
    /// Step 1: reserve the inputs, hold a nonce per input, and write the
    /// `Proposal`.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: this member is not the proposer, an input is in
    /// another live ceremony, a nonce for this intent is already held, or a
    /// FROST or seal refusal.
    pub fn propose(
        ctx: SigningContext<'a>,
        store: &mut HeldNonceStore,
        live: &mut impl LiveCeremonies,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Self, Vec<u8>), CeremonyError> {
        expect_role(&ctx, &[Role::Proposer])?;
        live.reserve(ctx.intent.hash(), &ctx.intent.intent().input_global_indices)?;
        let own = hold_all(&ctx, store, rng)?;
        let file = seal_as(
            &ctx,
            &Proposal {
                intent: ctx.intent.intent().clone(),
                rounds: own.rounds().to_vec(),
            },
            rng,
        )?;
        Ok((Self::collecting(ctx, own, file.clone()), file))
    }

    fn collecting(ctx: SigningContext<'a>, own: CheckedRounds, proposal_file: Vec<u8>) -> Self {
        Self {
            ctx,
            proposal_file,
            state: Collecting {
                own,
                commitments: BTreeMap::new(),
            },
        }
    }

    /// Step 2 received: a holder's `Commitment`, its keys checked.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: another intent, not a holder, a second file from
    /// one holder, or a key that does not match its committed hash.
    pub fn commitment(mut self, file: Authenticated<Commitment>) -> Result<Self, CeremonyError> {
        from_role(&self.ctx, &file, Role::Holder)?;
        check_rounds(&self.ctx, file.sender(), file.body().rounds.iter())?;
        let sender = file.sender();
        if self.state.commitments.insert(sender, file).is_some() {
            return Err(CeremonyError::Duplicate { member: sender });
        }
        Ok(self)
    }

    fn all_committed(&self) -> Result<(), CeremonyError> {
        if self
            .state
            .commitments
            .keys()
            .copied()
            .eq(self.ctx.holders())
        {
            Ok(())
        } else {
            Err(CeremonyError::Incomplete)
        }
    }

    /// The file for the responder: with no holders the `Proposal` itself
    /// (step 1); otherwise a `SigningSet` of the `Proposal` and every
    /// holder's `Commitment`, sealed as received (step 3).
    ///
    /// # Errors
    ///
    /// [`CeremonyError::Incomplete`] before every holder has committed;
    /// a seal refusal.
    pub fn responder_file(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, CeremonyError> {
        self.all_committed()?;
        if self.state.commitments.is_empty() {
            return Ok(self.proposal_file());
        }
        let files = std::iter::once(self.proposal_file())
            .chain(self.state.commitments.values().map(|c| c.file().to_vec()))
            .collect();
        seal_as(&self.ctx, &SigningSet { files }, rng)
    }

    /// Step 4 received: the responder's `ResponderShare`.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: before every holder has committed, another
    /// intent, not the responder, or a key that does not match.
    pub fn responder_share(
        self,
        file: Authenticated<ResponderShare>,
    ) -> Result<Proposer<'a, SharesPending>, CeremonyError> {
        self.all_committed()?;
        from_role(&self.ctx, &file, Role::Responder)?;
        check_rounds(
            &self.ctx,
            file.sender(),
            file.body().inputs.iter().map(|i| &i.round),
        )?;
        let Collecting { own, commitments } = self.state;
        Ok(Proposer {
            ctx: self.ctx,
            proposal_file: self.proposal_file,
            state: SharesPending {
                own,
                commitments,
                responder: file,
                holder_shares: BTreeMap::new(),
            },
        })
    }
}

impl<'a> Proposer<'a, SharesPending> {
    /// Step 5: the file for every holder: a `SigningSet` of the `Proposal`,
    /// every `Commitment` and the responder's `ResponderShare`, sealed as
    /// received. `None` when there are no holders (M = 2).
    ///
    /// # Errors
    ///
    /// A seal refusal.
    pub fn holders_file(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Option<Vec<u8>>, CeremonyError> {
        if self.state.commitments.is_empty() {
            return Ok(None);
        }
        let files = std::iter::once(self.proposal_file())
            .chain(self.state.commitments.values().map(|c| c.file().to_vec()))
            .chain(std::iter::once(self.state.responder.file().to_vec()))
            .collect();
        seal_as(&self.ctx, &SigningSet { files }, rng).map(Some)
    }

    /// Step 6 received: a holder's `SignatureShare`.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: another intent, not a holder, a second share
    /// from one holder, or a per-input count that is not the intent's.
    pub fn holder_share(
        mut self,
        file: Authenticated<SignatureShare>,
    ) -> Result<Self, CeremonyError> {
        from_role(&self.ctx, &file, Role::Holder)?;
        if file.body().shares.len() != self.ctx.inputs.len() {
            return Err(CeremonyError::InputCount);
        }
        let sender = file.sender();
        if self.state.holder_shares.insert(sender, file).is_some() {
            return Err(CeremonyError::Duplicate { member: sender });
        }
        Ok(self)
    }

    /// Step 7: consume the held nonce and sign; complete one SAL per input
    /// (a bad share is named by its signer); prove membership and range;
    /// assemble the transaction this member signs and sign it; and write
    /// the `FinalTx`. The outputs' openings are dropped here.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: a holder's share is missing, the nonce is not
    /// held (the wallet closed since the proposal: R-20), or a FROST,
    /// prover, structure or seal refusal.
    pub fn finish(
        self,
        store: &mut HeldNonceStore,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Proposer<'a, AwaitingSignatures>, Vec<u8>), CeremonyError> {
        let ctx = &self.ctx;
        if !self.state.holder_shares.keys().copied().eq(ctx.holders()) {
            return Err(CeremonyError::Incomplete);
        }
        let SharesPending {
            own,
            commitments,
            responder,
            holder_shares,
        } = self.state;

        let mut others = Vec::with_capacity(commitments.len() + 1);
        for (&holder, file) in &commitments {
            others.push((
                holder,
                CheckedRounds::new(ctx, holder, file.body().rounds.clone())?,
            ));
        }
        let responder_index = responder.sender();
        others.push((
            responder_index,
            CheckedRounds::new(
                ctx,
                responder_index,
                responder
                    .body()
                    .inputs
                    .iter()
                    .map(|input| input.round.clone())
                    .collect(),
            )?,
        ));
        let set = PreprocessSet::new(ctx, others)?;
        let consumed = consume(ctx.intent.hash(), store)?;
        let signed = sign_held(consumed, &own, &set)?;
        let sals = complete_sals(signed, &responder, &holder_shares)?;

        let leaf_chunks: Vec<ProveInputLeafChunk> =
            ctx.inputs.iter().map(InputContext::leaf_chunk).collect();
        let membership = prove_membership(ctx, sals, &leaf_chunks)?;
        let range = prove_range(ctx, ctx.output_openings().to_vec(), rng)?;
        let keys = SignerKeys::check(ctx, signer_keys(ctx, &own, &commitments, &responder)?)?;
        let signable = SignableTransaction::assemble(ctx, &membership, &range, &keys)?;

        let file = seal_as(
            ctx,
            &FinalTx {
                proposal_file: self.proposal_file.clone(),
                keys: keys.keys(),
                fcmp_proof: membership.data().to_vec(),
                range_proof: range.bytes().to_vec(),
            },
            rng,
        )?;
        let proposer = Proposer::awaiting(self.ctx, self.proposal_file, keys, signable)?;
        Ok((proposer, file))
    }
}

/// Every input's SAL: this member's share with the responder's and every
/// holder's, read by its machine. A bad share is named by its signer.
fn complete_sals(
    signed: Vec<(SalSignatureMachine, SalShare)>,
    responder: &Authenticated<ResponderShare>,
    holder_shares: &BTreeMap<u8, Authenticated<SignatureShare>>,
) -> Result<Vec<shekyl_fcmp::SpendAuthAndLinkability>, CeremonyError> {
    signed
        .into_iter()
        .enumerate()
        .map(|(input, (machine, _own))| {
            let mut shares = HashMap::new();
            let responder_share = per_input(&responder.body().inputs, input)?.share;
            shares.insert(
                participant(responder.sender()),
                read_share(&machine, &responder_share)
                    .map_err(|source| CeremonyError::Frost { input, source })?,
            );
            for (&holder, file) in holder_shares {
                let share = per_input(&file.body().shares, input)?;
                shares.insert(
                    participant(holder),
                    read_share(&machine, share)
                        .map_err(|source| CeremonyError::Frost { input, source })?,
                );
            }
            complete(machine, shares).map_err(|source| CeremonyError::Signing { input, source })
        })
        .collect()
}

/// `items[input]`, or [`CeremonyError::InputCount`] when the list is short.
fn per_input<T>(items: &[T], input: usize) -> Result<&T, CeremonyError> {
    items.get(input).ok_or(CeremonyError::InputCount)
}

/// The FCMP++ proof with every input's SAL, verified as every signer will
/// verify it.
fn prove_membership(
    ctx: &SigningContext<'_>,
    sals: Vec<shekyl_fcmp::SpendAuthAndLinkability>,
    leaf_chunks: &[ProveInputLeafChunk],
) -> Result<VerifiedMembershipProof, CeremonyError> {
    let params: Vec<_> = (0..ctx.inputs.len())
        .map(|input| ctx.params(input))
        .collect();
    let proved = prove_with_sal(
        params
            .iter()
            .map(|p| p.rerandomized().input())
            .zip(sals)
            .collect(),
        &params
            .iter()
            .map(SalSigningParams::output)
            .collect::<Vec<_>>(),
        &params
            .iter()
            .map(|p| p.rerandomized().clone())
            .collect::<Vec<_>>(),
        leaf_chunks,
        ctx.fcmp_layers,
    )?;
    VerifiedMembershipProof::verify(ctx, proved.proof.data)
}

/// The range proof over the outputs' openings, verified as every signer
/// will verify it. The openings are consumed and wiped.
fn prove_range(
    ctx: &SigningContext<'_>,
    openings: Vec<Opening>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<VerifiedRangeProof, CeremonyError> {
    let proof = Bulletproof::prove_plus(rng, openings).map_err(CeremonyError::RangeProve)?;
    VerifiedRangeProof::verify(ctx, &proof.serialize())
}

/// Every signer's per-output key per input, in the intent's signer order.
fn signer_keys(
    ctx: &SigningContext<'_>,
    own: &CheckedRounds,
    commitments: &BTreeMap<u8, Authenticated<Commitment>>,
    responder: &Authenticated<ResponderShare>,
) -> Result<Vec<Vec<HybridPublicKey>>, CeremonyError> {
    let me = ctx.member.member_index();
    (0..ctx.inputs.len())
        .map(|input| {
            ctx.intent
                .intent()
                .signers
                .iter()
                .map(|&member| {
                    if member == me {
                        Ok(own.key(input)?.clone())
                    } else if member == responder.sender() {
                        Ok(per_input(&responder.body().inputs, input)?
                            .round
                            .key
                            .clone())
                    } else {
                        let commitment =
                            commitments.get(&member).ok_or(CeremonyError::Incomplete)?;
                        Ok(per_input(&commitment.body().rounds, input)?.key.clone())
                    }
                })
                .collect()
        })
        .collect()
}

impl<'a> Proposer<'a, AwaitingSignatures> {
    /// Rebuild the proposer after a restart, after [`Proposer::finish`],
    /// from its context and the `FinalTx` file it sent: the transaction is
    /// re-assembled and re-checked exactly as a cosigner checks it, and
    /// this member signs it again (its hybrid signature holds no nonce).
    /// Then replay the `HybridSig` files it received.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: this member is not the proposer, the file is not
    /// its own `FinalTx` for this intent, or a check of it fails.
    pub fn resume_after_finish(
        ctx: SigningContext<'a>,
        final_tx_file: &[u8],
    ) -> Result<Self, CeremonyError> {
        expect_role(&ctx, &[Role::Proposer])?;
        let Incoming::FinalTx(sent) = open_forwarded(
            ctx.member,
            &ctx.network_id,
            ctx.intent.hash(),
            final_tx_file,
        )?
        else {
            return Err(CeremonyError::FileType);
        };
        let (keys, signable) = check_final_tx(&ctx, &sent)?;
        let proposal_file = sent.into_body().proposal_file;
        Self::awaiting(ctx, proposal_file, keys, signable)
    }

    /// The state after the transaction is assembled, with this member's
    /// own signatures in.
    fn awaiting(
        ctx: SigningContext<'a>,
        proposal_file: Vec<u8>,
        keys: SignerKeys,
        signable: SignableTransaction,
    ) -> Result<Self, CeremonyError> {
        let own = signable.sign_as_member(&ctx)?;
        let signatures = BTreeMap::from([(ctx.member.member_index(), own)]);
        Ok(Self {
            ctx,
            proposal_file,
            state: AwaitingSignatures {
                keys,
                signable,
                signatures,
            },
        })
    }

    /// Step 9 received: a cosigner's hybrid signatures, each verified on
    /// receipt under that signer's checked key.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: another intent, not a cosigner of this intent, a
    /// second file from one signer, a count that is not the intent's, or a
    /// signature that does not verify (named by signer and input).
    pub fn hybrid_sig(mut self, file: Authenticated<HybridSig>) -> Result<Self, CeremonyError> {
        let ctx = &self.ctx;
        if file.intent_hash() != ctx.intent.hash() {
            return Err(CeremonyError::IntentMismatch);
        }
        let sender = file.sender();
        if !ctx
            .role_of(sender)
            .is_some_and(|role| Role::COSIGNERS.contains(&role))
        {
            return Err(CeremonyError::Sender { sender });
        }
        let signatures = file.into_body().signatures;
        self.state
            .keys
            .verify_signatures(sender, self.state.signable.hashes(), &signatures)?;
        if self.state.signatures.insert(sender, signatures).is_some() {
            return Err(CeremonyError::Duplicate { member: sender });
        }
        Ok(self)
    }

    /// Step 10: every signer's signatures into each input's container,
    /// `verify_multisig` on every input, the structural check on the final
    /// bytes, and the transaction.
    ///
    /// # Errors
    ///
    /// [`CeremonyError::Incomplete`] before every signer has signed;
    /// [`CeremonyError::Authorization`] for an input that does not verify;
    /// [`CeremonyError::Structure`] if the signed transaction is not well
    /// formed.
    pub fn release(self) -> Result<Transaction, CeremonyError> {
        let ctx = &self.ctx;
        let signers = &ctx.intent.intent().signers;
        if !self.state.signatures.keys().eq(signers.iter()) {
            return Err(CeremonyError::Incomplete);
        }
        let hashes = self.state.signable.hashes().to_vec();
        let sig_count = u8::try_from(signers.len()).expect("m is at most the participant cap");
        let mut tx = self.state.signable.into_transaction();
        let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct else {
            unreachable!("SignableTransaction is an FCMP++ spend");
        };
        for (input, (auth, hash)) in pqc_auths.iter_mut().zip(&hashes).enumerate() {
            let container = MultisigSigContainer {
                sig_count,
                sigs: signers
                    .iter()
                    .map(|member| {
                        self.state
                            .signatures
                            .get(member)
                            .and_then(|sigs| sigs.get(input))
                            .cloned()
                            .ok_or(CeremonyError::InputCount)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                signer_indices: signers.clone(),
            };
            auth.hybrid_signature = container
                .to_canonical_bytes()
                .map_err(|source| CeremonyError::Authorization { input, source })?;
            verify_multisig(
                HYBRID_SCHEME_ID_MULTISIG,
                &auth.hybrid_public_key,
                &auth.hybrid_signature,
                hash,
                &ctx.network_id,
            )
            .map_err(|source| CeremonyError::Authorization { input, source })?;
        }
        tx.validate().map_err(CeremonyError::Structure)?;
        Ok(tx)
    }
}
