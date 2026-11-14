// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The roles: [`Proposer`], [`Holder`], [`Responder`], and [`Cosigner`]
//! for the second round every non-proposer signer runs.
//!
//! Each state is a type with only the steps legal from it, and each step
//! takes the one [`Authenticated`] body that phase expects, so a file out
//! of phase cannot be passed. Every state that spans a wait for another
//! member is rebuilt after a restart from the context, the held-nonce store
//! and the files received: a proposer replays the files it received, a
//! holder resumes as [`Holder::committed`] (its held nonce is the durable
//! fact), and the second round is stateless.

use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;

use rand::{CryptoRng, RngCore};
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::multisig::{
    verify_multisig, MultisigSigContainer, HYBRID_SCHEME_ID_MULTISIG,
};
use shekyl_crypto_pq::multisig_output::{
    multisig_member_public_key, MemberOwnCiphertext, MultisigMemberView,
};
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
    SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG,
};
use shekyl_curve_primitives::Commitment as PedersenCommitment;
use shekyl_fcmp::frost_sal::{
    complete, hold, participant, preprocess, preprocess_bytes, read_preprocess, read_share,
    share_bytes, sign, SalPreprocess, SalShare, SalSignMachine, SAL_PREPROCESS_LEN, SAL_SHARE_LEN,
};
use shekyl_fcmp::proof::prove_with_sal;
use shekyl_wire::{Ct, Transaction};

use super::context::{ProposerInputs, SigningContext};
use super::files::{
    open_forwarded, seal, Authenticated, Commitment, FinalTx, HybridSig, Incoming, Proposal,
    ResponderShare, RoundOne, SignatureShare, SigningSet,
};
use super::nonce::{consume, HeldNonce, HeldNonceStore, LiveCeremonies, NonceCounterSink};
use super::proofs::{SignableTransaction, SignerKeys, VerifiedMembershipProof, VerifiedRangeProof};
use super::{CeremonyError, Role};

// ---------------------------------------------------------------------------
// Shared steps
// ---------------------------------------------------------------------------

fn role(ctx: &SigningContext<'_>) -> Role {
    let intent = ctx.intent.intent();
    Role::of(
        ctx.member.member_index(),
        intent.proposer_index,
        intent.responder_index,
        &intent.signers,
    )
    .expect("SigningContext::new refused a member that is not a signer")
}

fn expect_role(ctx: &SigningContext<'_>, expected: Role) -> Result<(), CeremonyError> {
    let actual = role(ctx);
    if actual == expected {
        Ok(())
    } else {
        Err(CeremonyError::WrongRole { expected, actual })
    }
}

/// `member`'s role in `ctx`'s intent.
fn role_of(ctx: &SigningContext<'_>, member: u8) -> Option<Role> {
    let intent = ctx.intent.intent();
    Role::of(
        member,
        intent.proposer_index,
        intent.responder_index,
        &intent.signers,
    )
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
    if role_of(ctx, file.sender()) != Some(role) {
        return Err(CeremonyError::Sender {
            sender: file.sender(),
        });
    }
    Ok(())
}

/// The holders, in signer order.
fn holders(ctx: &SigningContext<'_>) -> Vec<u8> {
    ctx.intent
        .intent()
        .signers
        .iter()
        .copied()
        .filter(|&m| role_of(ctx, m) == Some(Role::Holder))
        .collect()
}

/// This member's per-output key for every input.
fn own_keys(ctx: &SigningContext<'_>) -> Result<Vec<HybridPublicKey>, CeremonyError> {
    let member = ctx.member;
    let address = member.address();
    let (x25519, ml_kem) = member.member_kem_secret().split_at(32);
    let x25519: &[u8; 32] = x25519
        .try_into()
        .expect("a hybrid KEM secret starts with X25519");
    let view = MultisigMemberView {
        member_index: member.member_index(),
        n_total: address.n_total(),
        m_required: address.m_required(),
        member_x25519_sk: x25519,
        member_ml_kem_dk: ml_kem,
        network: &ctx.network_id,
    };
    ctx.inputs
        .iter()
        .map(|input| {
            multisig_member_public_key(
                &view,
                &MemberOwnCiphertext {
                    n: address.n_total(),
                    own_x25519_ct: &input.own_x25519_ct,
                    own_ml_kem_ct: &input.own_ml_kem_ct,
                },
            )
            .map_err(CeremonyError::MemberSign)
        })
        .collect()
}

/// Check another member's first rounds: one per input, each key matching
/// its committed hash. Done on receipt, in round 1.
fn check_rounds(
    ctx: &SigningContext<'_>,
    member: u8,
    rounds: &[RoundOne],
) -> Result<(), CeremonyError> {
    if rounds.len() != ctx.inputs.len() {
        return Err(CeremonyError::InputCount);
    }
    for (input, round) in rounds.iter().enumerate() {
        super::proofs::CommittedMemberKey::check(ctx, input, member, round.key.clone())?;
    }
    Ok(())
}

/// This member's round-1 state for every input, held for later.
fn hold_all(
    ctx: &SigningContext<'_>,
    store: &mut impl HeldNonceStore,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<RoundOne>, CeremonyError> {
    let keys = own_keys(ctx)?;
    let mut sessions = Vec::with_capacity(ctx.inputs.len());
    let mut rounds = Vec::with_capacity(ctx.inputs.len());
    for (input, key) in keys.into_iter().enumerate() {
        let (session, pre) = hold(ctx.params(input), ctx.keys.clone(), rng)
            .map_err(|source| CeremonyError::Frost { input, source })?;
        sessions.push(session);
        rounds.push(RoundOne {
            preprocess: preprocess_bytes(&pre),
            key,
        });
    }
    store.put(HeldNonce::new(*ctx.intent.hash(), sessions))?;
    Ok(rounds)
}

/// The other signers' preprocesses for one input, read by `machine`.
type OthersPreprocesses = BTreeMap<u8, Vec<[u8; SAL_PREPROCESS_LEN]>>;

fn read_others(
    machine: &SalSignMachine,
    input: usize,
    others: &OthersPreprocesses,
) -> Result<HashMap<shekyl_fcmp::frost_sal::Participant, SalPreprocess>, CeremonyError> {
    others
        .iter()
        .map(|(&member, per_input)| {
            read_preprocess(machine, &per_input[input])
                .map(|pre| (participant(member), pre))
                .map_err(|source| CeremonyError::Frost { input, source })
        })
        .collect()
}

/// The preprocess set every signer other than this member contributed:
/// exactly the signer set minus this member, each from a file its sender
/// signed. This member's own preprocess is the one its machine produces,
/// so "mine is the one I sent" holds by construction.
fn check_set(ctx: &SigningContext<'_>, others: &OthersPreprocesses) -> Result<(), CeremonyError> {
    let me = ctx.member.member_index();
    let expected: Vec<u8> = ctx
        .intent
        .intent()
        .signers
        .iter()
        .copied()
        .filter(|&m| m != me)
        .collect();
    if others.keys().copied().collect::<Vec<_>>() != expected {
        return Err(CeremonyError::SigningSetContents);
    }
    Ok(())
}

/// Resume a held nonce and sign every input over the other signers'
/// preprocesses; check each rebuilt preprocess is the one this member sent.
fn sign_held(
    ctx: &SigningContext<'_>,
    consumed: super::nonce::ConsumedNonce,
    sent: &[RoundOne],
    others: &OthersPreprocesses,
) -> Result<Vec<(shekyl_fcmp::frost_sal::SalSignatureMachine, SalShare)>, CeremonyError> {
    check_set(ctx, others)?;
    consumed
        .into_sessions()
        .into_iter()
        .enumerate()
        .map(|(input, session)| {
            let (machine, rebuilt) = session
                .resume()
                .map_err(|source| CeremonyError::Frost { input, source })?;
            if sent.get(input).map(|r| r.preprocess) != Some(preprocess_bytes(&rebuilt)) {
                return Err(CeremonyError::HeldNonceMismatch);
            }
            let preprocesses = read_others(&machine, input, others)?;
            sign(machine, preprocesses).map_err(|source| CeremonyError::Signing { input, source })
        })
        .collect()
}

/// The responder's first round and share, per input.
type ResponderRounds = Vec<(RoundOne, [u8; SAL_SHARE_LEN])>;

/// Open a forwarded set: each file under its own sender's signature, for
/// this intent. Returns the round-1 contributions by member, every key
/// checked, and the responder's shares if the set carries them.
struct OpenedSet {
    proposal_rounds: Option<Vec<RoundOne>>,
    commitments: BTreeMap<u8, Vec<RoundOne>>,
    responder: Option<(u8, ResponderRounds)>,
}

fn open_set(
    ctx: &SigningContext<'_>,
    set: &Authenticated<SigningSet>,
) -> Result<OpenedSet, CeremonyError> {
    from_role(ctx, set, Role::Proposer)?;
    let mut opened = OpenedSet {
        proposal_rounds: None,
        commitments: BTreeMap::new(),
        responder: None,
    };
    for file in &set.body().files {
        match open_forwarded(ctx.member, &ctx.network_id, ctx.intent.hash(), file)? {
            Incoming::Proposal(p) => {
                if opened.proposal_rounds.is_some() {
                    return Err(CeremonyError::Duplicate { member: p.sender() });
                }
                check_rounds(ctx, p.sender(), &p.body().rounds)?;
                opened.proposal_rounds = Some(p.body().rounds.clone());
            }
            Incoming::Commitment(c) => {
                from_role(ctx, &c, Role::Holder)?;
                check_rounds(ctx, c.sender(), &c.body().rounds)?;
                if opened
                    .commitments
                    .insert(c.sender(), c.body().rounds.clone())
                    .is_some()
                {
                    return Err(CeremonyError::Duplicate { member: c.sender() });
                }
            }
            Incoming::ResponderShare(r) => {
                from_role(ctx, &r, Role::Responder)?;
                let rounds: Vec<RoundOne> =
                    r.body().inputs.iter().map(|(ro, _)| ro.clone()).collect();
                check_rounds(ctx, r.sender(), &rounds)?;
                if opened.responder.is_some() {
                    return Err(CeremonyError::Duplicate { member: r.sender() });
                }
                opened.responder = Some((r.sender(), r.body().inputs.clone()));
            }
            _ => return Err(CeremonyError::SigningSetContents),
        }
    }
    Ok(opened)
}

// ---------------------------------------------------------------------------
// Proposer
// ---------------------------------------------------------------------------

/// The proposer, A, in state `S`.
pub struct Proposer<'a, S> {
    ctx: SigningContext<'a>,
    inputs: ProposerInputs,
    own: Vec<RoundOne>,
    proposal_file: Vec<u8>,
    state: S,
}

/// Waiting for every holder's `Commitment`, then the responder's share.
pub struct Collecting {
    commitments: BTreeMap<u8, Authenticated<Commitment>>,
}

/// The responder's share is in; waiting for every holder's share.
pub struct SharesPending {
    commitments: BTreeMap<u8, Authenticated<Commitment>>,
    responder: Authenticated<ResponderShare>,
    holder_shares: BTreeMap<u8, Authenticated<SignatureShare>>,
}

/// The transaction is assembled; waiting for every signer's hybrid
/// signatures.
pub struct AwaitingSignatures {
    signable: SignableTransaction,
    keys: Vec<Vec<HybridPublicKey>>,
    signatures: BTreeMap<u8, Vec<HybridSignature>>,
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
        inputs: ProposerInputs,
        store: &mut impl HeldNonceStore,
        live: &mut impl LiveCeremonies,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Self, Vec<u8>), CeremonyError> {
        expect_role(&ctx, Role::Proposer)?;
        if inputs.leaf_chunks.len() != ctx.inputs.len()
            || inputs.outputs.len() != ctx.unsigned.base.commitments.len()
        {
            return Err(CeremonyError::InputCount);
        }
        live.reserve(ctx.intent.hash(), &ctx.intent.intent().input_global_indices)?;
        let own = hold_all(&ctx, store, rng)?;
        let body = Proposal {
            intent: ctx.intent.intent().clone(),
            rounds: own.clone(),
        };
        let file = seal(ctx.member, &ctx.network_id, ctx.intent.hash(), &body, rng)?;
        Ok((
            Self {
                ctx,
                inputs,
                own,
                proposal_file: file.clone(),
                state: Collecting {
                    commitments: BTreeMap::new(),
                },
            },
            file,
        ))
    }

    /// Rebuild the proposer after a restart from its context and the
    /// `Proposal` file it sent, then replay the files it received. Its
    /// held nonce stays in the store.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: the file is not this member's `Proposal` for this
    /// intent.
    pub fn resume(
        ctx: SigningContext<'a>,
        inputs: ProposerInputs,
        proposal_file: Vec<u8>,
    ) -> Result<Self, CeremonyError> {
        expect_role(&ctx, Role::Proposer)?;
        let Incoming::Proposal(sent) = open_forwarded(
            ctx.member,
            &ctx.network_id,
            ctx.intent.hash(),
            &proposal_file,
        )?
        else {
            return Err(CeremonyError::SigningSetContents);
        };
        if sent.sender() != ctx.member.member_index() {
            return Err(CeremonyError::Sender {
                sender: sent.sender(),
            });
        }
        Ok(Self {
            own: sent.body().rounds.clone(),
            ctx,
            inputs,
            proposal_file,
            state: Collecting {
                commitments: BTreeMap::new(),
            },
        })
    }

    /// Step 2 received: a holder's `Commitment`, its keys checked.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: another intent, not a holder, a second file from
    /// one holder, or a key that does not match its committed hash.
    pub fn commitment(mut self, file: Authenticated<Commitment>) -> Result<Self, CeremonyError> {
        from_role(&self.ctx, &file, Role::Holder)?;
        check_rounds(&self.ctx, file.sender(), &file.body().rounds)?;
        let sender = file.sender();
        if self.state.commitments.insert(sender, file).is_some() {
            return Err(CeremonyError::Duplicate { member: sender });
        }
        Ok(self)
    }

    fn all_committed(&self) -> Result<(), CeremonyError> {
        if self.state.commitments.keys().copied().collect::<Vec<_>>() == holders(&self.ctx) {
            Ok(())
        } else {
            Err(CeremonyError::Incomplete)
        }
    }

    /// The file for the responder: for M = 2 the `Proposal` itself (step
    /// 1); otherwise a `SigningSet` of the `Proposal` and every holder's
    /// `Commitment`, sealed as received (step 3).
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
            return Ok(self.proposal_file.clone());
        }
        let mut files = vec![self.proposal_file.clone()];
        files.extend(self.state.commitments.values().map(|c| c.file().to_vec()));
        Ok(seal(
            self.ctx.member,
            &self.ctx.network_id,
            self.ctx.intent.hash(),
            &SigningSet { files },
            rng,
        )?)
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
        let rounds: Vec<RoundOne> = file.body().inputs.iter().map(|(r, _)| r.clone()).collect();
        check_rounds(&self.ctx, file.sender(), &rounds)?;
        Ok(Proposer {
            ctx: self.ctx,
            inputs: self.inputs,
            own: self.own,
            proposal_file: self.proposal_file,
            state: SharesPending {
                commitments: self.state.commitments,
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
        let mut files = vec![self.proposal_file.clone()];
        files.extend(self.state.commitments.values().map(|c| c.file().to_vec()));
        files.push(self.state.responder.file().to_vec());
        Ok(Some(seal(
            self.ctx.member,
            &self.ctx.network_id,
            self.ctx.intent.hash(),
            &SigningSet { files },
            rng,
        )?))
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

    /// Step 7: consume the held nonce, sign, complete one SAL per input
    /// (a bad share is named by its signer), prove membership, prove the
    /// range, assemble the transaction this member signs, sign it, and
    /// write the `FinalTx`.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: a holder's share is missing, the nonce is not
    /// held or its use cannot be persisted, or a FROST, prover or seal
    /// refusal.
    pub fn finish(
        self,
        store: &mut impl HeldNonceStore,
        sink: &mut impl NonceCounterSink,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Proposer<'a, AwaitingSignatures>, Vec<u8>), CeremonyError> {
        let ctx = &self.ctx;
        if self.state.holder_shares.keys().copied().collect::<Vec<_>>() != holders(ctx) {
            return Err(CeremonyError::Incomplete);
        }
        let responder = &self.state.responder;
        let mut others: OthersPreprocesses = self
            .state
            .commitments
            .iter()
            .map(|(&m, c)| (m, c.body().rounds.iter().map(|r| r.preprocess).collect()))
            .collect();
        others.insert(
            responder.sender(),
            responder
                .body()
                .inputs
                .iter()
                .map(|(r, _)| r.preprocess)
                .collect(),
        );

        let consumed = consume(ctx.intent.hash(), store, sink)?;
        let signed = sign_held(ctx, consumed, &self.own, &others)?;

        let mut sals = Vec::with_capacity(ctx.inputs.len());
        for (input, (machine, _own_share)) in signed.into_iter().enumerate() {
            let mut shares = HashMap::new();
            let responder_share = responder.body().inputs[input].1;
            shares.insert(
                participant(responder.sender()),
                read_share(&machine, &responder_share)
                    .map_err(|source| CeremonyError::Frost { input, source })?,
            );
            for (&holder, file) in &self.state.holder_shares {
                shares.insert(
                    participant(holder),
                    read_share(&machine, &file.body().shares[input])
                        .map_err(|source| CeremonyError::Frost { input, source })?,
                );
            }
            sals.push(
                complete(machine, shares)
                    .map_err(|source| CeremonyError::Signing { input, source })?,
            );
        }

        let params: Vec<_> = (0..ctx.inputs.len()).map(|i| ctx.params(i)).collect();
        let proved = prove_with_sal(
            params
                .iter()
                .map(|p| p.rerandomized().input())
                .zip(sals)
                .collect(),
            &params
                .iter()
                .map(shekyl_fcmp::frost_sal::SalSigningParams::output)
                .collect::<Vec<_>>(),
            &params
                .iter()
                .map(|p| p.rerandomized().clone())
                .collect::<Vec<_>>(),
            &self.inputs.leaf_chunks,
            ctx.fcmp_layers,
        )
        .map_err(|e| CeremonyError::Prove(e.to_string()))?;

        let commitments: Vec<PedersenCommitment> = self
            .inputs
            .outputs
            .iter()
            .map(|(amount, mask)| {
                let mask = curve25519_dalek::Scalar::from_canonical_bytes(**mask);
                Option::<curve25519_dalek::Scalar>::from(mask)
                    .map(|mask| PedersenCommitment::new(mask, *amount))
                    .ok_or(CeremonyError::RangeProve)
            })
            .collect::<Result<_, _>>()?;
        let bulletproof =
            Bulletproof::prove_plus(rng, commitments).map_err(|_| CeremonyError::RangeProve)?;

        let membership = VerifiedMembershipProof::verify(ctx, proved.proof.data)?;
        let range = VerifiedRangeProof::verify(ctx, &bulletproof.serialize())?;

        let keys = all_keys(ctx, &self.own, &self.state.commitments, responder)?;
        let checked = SignerKeys::check(ctx, keys)?;
        let signable = SignableTransaction::assemble(ctx, &membership, &range, &checked)?;
        let own_signatures = signable.sign_as_member(ctx)?;

        let body = FinalTx {
            proposal_file: self.proposal_file.clone(),
            keys: checked.keys(),
            fcmp_proof: membership.data().to_vec(),
            range_proof: range.bytes().to_vec(),
        };
        let file = seal(ctx.member, &ctx.network_id, ctx.intent.hash(), &body, rng)?;
        let mut signatures = BTreeMap::new();
        signatures.insert(ctx.member.member_index(), own_signatures);
        Ok((
            Proposer {
                state: AwaitingSignatures {
                    signable,
                    keys: checked.keys(),
                    signatures,
                },
                ctx: self.ctx,
                inputs: self.inputs,
                own: self.own,
                proposal_file: self.proposal_file,
            },
            file,
        ))
    }
}

/// Every signer's key per input, in the intent's signer order.
fn all_keys(
    ctx: &SigningContext<'_>,
    own: &[RoundOne],
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
                        Ok(own[input].key.clone())
                    } else if member == responder.sender() {
                        Ok(responder.body().inputs[input].0.key.clone())
                    } else {
                        commitments
                            .get(&member)
                            .map(|c| c.body().rounds[input].key.clone())
                            .ok_or(CeremonyError::Incomplete)
                    }
                })
                .collect()
        })
        .collect()
}

impl<'a> Proposer<'a, AwaitingSignatures> {
    /// Step 9 received: a signer's hybrid signatures, each verified on
    /// receipt under that signer's checked key.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: another intent, not a signer, a second file from
    /// one signer, a count that is not the intent's, or a signature that
    /// does not verify (named by signer and input).
    pub fn hybrid_sig(mut self, file: &Authenticated<HybridSig>) -> Result<Self, CeremonyError> {
        let ctx = &self.ctx;
        if file.intent_hash() != ctx.intent.hash() {
            return Err(CeremonyError::IntentMismatch);
        }
        let sender = file.sender();
        let Some(position) = ctx
            .intent
            .intent()
            .signers
            .iter()
            .position(|&m| m == sender)
        else {
            return Err(CeremonyError::Sender { sender });
        };
        if sender == ctx.member.member_index() {
            return Err(CeremonyError::Sender { sender });
        }
        let signatures = &file.body().signatures;
        if signatures.len() != ctx.inputs.len() {
            return Err(CeremonyError::InputCount);
        }
        for (input, (sig, hash)) in signatures
            .iter()
            .zip(self.state.signable.hashes())
            .enumerate()
        {
            HybridEd25519MlDsa
                .verify(
                    &self.state.keys[input][position],
                    SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG,
                    hash.as_bytes(),
                    sig,
                )
                .map_err(|_| CeremonyError::HybridSignature {
                    member: sender,
                    input,
                })?;
        }
        if self
            .state
            .signatures
            .insert(sender, signatures.clone())
            .is_some()
        {
            return Err(CeremonyError::Duplicate { member: sender });
        }
        Ok(self)
    }

    /// Step 10: every signer's signatures into each input's container,
    /// `verify_multisig` on every input, and the transaction.
    ///
    /// # Errors
    ///
    /// [`CeremonyError::Incomplete`] before every signer has signed;
    /// [`CeremonyError::Authorization`] for an input that does not verify.
    pub fn release(self) -> Result<Transaction, CeremonyError> {
        let ctx = &self.ctx;
        let signers = &ctx.intent.intent().signers;
        if self.state.signatures.keys().copied().collect::<Vec<_>>() != *signers {
            return Err(CeremonyError::Incomplete);
        }
        let hashes = self.state.signable.hashes().to_vec();
        let m = u8::try_from(signers.len()).expect("m is at most the participant cap");
        let mut tx = self.state.signable.into_transaction();
        let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct else {
            unreachable!("SignableTransaction is an FCMP++ spend");
        };
        for (input, auth) in pqc_auths.iter_mut().enumerate() {
            let container = MultisigSigContainer {
                sig_count: m,
                sigs: signers
                    .iter()
                    .map(|member| self.state.signatures[member][input].clone())
                    .collect(),
                signer_indices: signers.clone(),
            };
            auth.hybrid_signature = container
                .to_canonical_bytes()
                .map_err(|source| CeremonyError::Authorization { input, source })?;
            verify_multisig(
                HYBRID_SCHEME_ID_MULTISIG,
                &auth.hybrid_public_key,
                &auth.hybrid_signature,
                &hashes[input],
                &ctx.network_id,
            )
            .map_err(|source| CeremonyError::Authorization { input, source })?;
        }
        Ok(tx)
    }
}

// ---------------------------------------------------------------------------
// Holder
// ---------------------------------------------------------------------------

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
        store: &mut impl HeldNonceStore,
        live: &mut impl LiveCeremonies,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Self, Vec<u8>), CeremonyError> {
        expect_role(&ctx, Role::Holder)?;
        from_role(&ctx, proposal, Role::Proposer)?;
        check_rounds(&ctx, proposal.sender(), &proposal.body().rounds)?;
        live.reserve(ctx.intent.hash(), &ctx.intent.intent().input_global_indices)?;
        let rounds = hold_all(&ctx, store, rng)?;
        let file = seal(
            ctx.member,
            &ctx.network_id,
            ctx.intent.hash(),
            &Commitment { rounds },
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

    /// Rebuild a committed holder after a restart. Its held nonce in the
    /// store is the durable fact: signing without one is refused.
    ///
    /// # Errors
    ///
    /// [`CeremonyError::WrongRole`] if this member is not a holder.
    pub fn committed(ctx: SigningContext<'a>) -> Result<Self, CeremonyError> {
        expect_role(&ctx, Role::Holder)?;
        Ok(Self {
            ctx,
            state: PhantomData,
        })
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
    /// the other signers', the nonce is not held or its use cannot be
    /// persisted, or a FROST or seal refusal.
    pub fn sign(
        self,
        set: &Authenticated<SigningSet>,
        store: &mut impl HeldNonceStore,
        sink: &mut impl NonceCounterSink,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, CeremonyError> {
        let ctx = &self.ctx;
        let opened = open_set(ctx, set)?;
        let me = ctx.member.member_index();
        let proposer = ctx.intent.intent().proposer_index;
        let Some(proposal_rounds) = opened.proposal_rounds else {
            return Err(CeremonyError::SigningSetContents);
        };
        let Some((responder, responder_inputs)) = opened.responder else {
            return Err(CeremonyError::SigningSetContents);
        };
        // This member's own Commitment, forwarded back: the preprocess its
        // held nonce must rebuild.
        let Some(own) = opened.commitments.get(&me).cloned() else {
            return Err(CeremonyError::SigningSetContents);
        };
        let mut others: OthersPreprocesses = opened
            .commitments
            .into_iter()
            .filter(|(m, _)| *m != me)
            .map(|(m, rounds)| (m, rounds.iter().map(|r| r.preprocess).collect()))
            .collect();
        others.insert(
            proposer,
            proposal_rounds.iter().map(|r| r.preprocess).collect(),
        );
        others.insert(
            responder,
            responder_inputs.iter().map(|(r, _)| r.preprocess).collect(),
        );
        let consumed = consume(ctx.intent.hash(), store, sink)?;
        let signed = sign_held(ctx, consumed, &own, &others)?;
        let shares = signed.iter().map(|(_, share)| share_bytes(share)).collect();
        Ok(seal(
            ctx.member,
            &ctx.network_id,
            ctx.intent.hash(),
            &SignatureShare { shares },
            rng,
        )?)
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

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
        expect_role(ctx, Role::Responder)?;
        let proposer = ctx.intent.intent().proposer_index;
        let has_holders = !holders(ctx).is_empty();
        let mut others: OthersPreprocesses = BTreeMap::new();
        match received {
            ResponderInput::Proposal(p) if !has_holders => {
                from_role(ctx, p, Role::Proposer)?;
                check_rounds(ctx, p.sender(), &p.body().rounds)?;
                others.insert(
                    proposer,
                    p.body().rounds.iter().map(|r| r.preprocess).collect(),
                );
            }
            ResponderInput::SigningSet(set) if has_holders => {
                let opened = open_set(ctx, set)?;
                if opened.responder.is_some() {
                    return Err(CeremonyError::SigningSetContents);
                }
                let Some(proposal_rounds) = opened.proposal_rounds else {
                    return Err(CeremonyError::SigningSetContents);
                };
                others.insert(
                    proposer,
                    proposal_rounds.iter().map(|r| r.preprocess).collect(),
                );
                for (m, rounds) in opened.commitments {
                    others.insert(m, rounds.iter().map(|r| r.preprocess).collect());
                }
            }
            _ => return Err(CeremonyError::SigningSetContents),
        }
        check_set(ctx, &others)?;
        live.reserve(ctx.intent.hash(), &ctx.intent.intent().input_global_indices)?;
        let keys = own_keys(ctx)?;
        let mut inputs = Vec::with_capacity(ctx.inputs.len());
        for (input, key) in keys.into_iter().enumerate() {
            let (machine, pre) = preprocess(&ctx.params(input), ctx.keys.clone(), rng)
                .map_err(|source| CeremonyError::Frost { input, source })?;
            let preprocesses = read_others(&machine, input, &others)?;
            let (_, share) = sign(machine, preprocesses)
                .map_err(|source| CeremonyError::Signing { input, source })?;
            inputs.push((
                RoundOne {
                    preprocess: preprocess_bytes(&pre),
                    key,
                },
                share_bytes(&share),
            ));
        }
        Ok(seal(
            ctx.member,
            &ctx.network_id,
            ctx.intent.hash(),
            &ResponderShare { inputs },
            rng,
        )?)
    }
}

// ---------------------------------------------------------------------------
// The second round, for every signer but the proposer
// ---------------------------------------------------------------------------

/// The responder or a holder, in the second round: stateless, so a member
/// that kept nothing since the first round signs from its rebuilt context
/// (brief P-3).
pub struct Cosigner;

impl Cosigner {
    /// Step 8 received, step 9 sent: check every signer's keys, verify the
    /// FCMP++ proof and the range proof against this member's own context,
    /// assemble the transaction from this member's own values, sign every
    /// input, and write the `HybridSig`.
    ///
    /// # Errors
    ///
    /// [`CeremonyError`]: this member is the proposer, the file is not from
    /// the proposer or is for another intent, its `Proposal` does not open,
    /// a key does not match, a proof does not verify, or a signer or seal
    /// refusal.
    pub fn sign_final_tx(
        ctx: &SigningContext<'_>,
        file: &Authenticated<FinalTx>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, CeremonyError> {
        let actual = role(ctx);
        if actual == Role::Proposer {
            return Err(CeremonyError::WrongRole {
                expected: Role::Holder,
                actual,
            });
        }
        from_role(ctx, file, Role::Proposer)?;
        let Incoming::Proposal(_) = open_forwarded(
            ctx.member,
            &ctx.network_id,
            ctx.intent.hash(),
            &file.body().proposal_file,
        )?
        else {
            return Err(CeremonyError::SigningSetContents);
        };
        let keys = SignerKeys::check(ctx, file.body().keys.clone())?;
        let membership = VerifiedMembershipProof::verify(ctx, file.body().fcmp_proof.clone())?;
        let range = VerifiedRangeProof::verify(ctx, &file.body().range_proof)?;
        let signable = SignableTransaction::assemble(ctx, &membership, &range, &keys)?;
        let signatures = signable.sign_as_member(ctx)?;
        Ok(seal(
            ctx.member,
            &ctx.network_id,
            ctx.intent.hash(),
            &HybridSig { signatures },
            rng,
        )?)
    }
}
