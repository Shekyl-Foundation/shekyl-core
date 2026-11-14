// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The checks between "a member received it" and "a member signs over
//! it", each a type whose only constructor runs the check (brief §3A):
//!
//! - [`CommittedMemberKey`]: a per-output key that hashes to `h_i` at its
//!   member's index of the input's committed form.
//! - [`VerifiedMembershipProof`]: the FCMP++ proof, SALs included, verified
//!   against this member's own key images, pseudo-outs, committed forms,
//!   tree root, depth and `tx_signable`.
//! - [`VerifiedRangeProof`]: the range proof, verified against the
//!   outputs' commitments in this member's own base.
//! - [`SignableTransaction`]: assembled by this member from its own
//!   context, the two verified proofs and the checked keys. The hybrid
//!   signer is called only on it, so a byte the member neither built nor
//!   verified has no way into its signature.
//!
//! The SALs travel inside the FCMP++ proof (`prove_with_sal` writes them
//! there), so one verifier covers both: there is no separate verified SAL.
//! The proof's rerandomized tuples are read from its bytes, with the
//! pseudo-out (`C~`) from this member's own context. The SAL challenge
//! hashes `tx_signable`, `O~`, `I~`, `C~` and `R`, and every signer's share
//! was made over its own context's tuple, so a proof over any other tuple
//! has no valid SAL.

use shekyl_crypto_pq::multisig::{multisig_key_hash, MultisigKeyBlob, HYBRID_SCHEME_ID_MULTISIG};
use shekyl_crypto_pq::multisig_output::{
    sign_multisig_member_auth, MemberOwnCiphertext, MultisigMemberView,
};
use shekyl_crypto_pq::signature::{HybridPublicKey, HybridSignature};
use shekyl_curve_io::CompressedPoint;
use shekyl_fcmp::proof::{verify, ShekylFcmpProof};
use shekyl_fcmp::PqcKeyScalar;
use shekyl_types::SigningPayloadHash;
use shekyl_wire::{BpPlus, Ct, PqcAuth, Prunable, Transaction};

use super::context::SigningContext;
use super::CeremonyError;

/// `pqc_auth.auth_version` (CEN-I16 requires 1).
const PQC_AUTH_VERSION: u8 = 1;

/// A per-output key that hashes, under this network, to the committed
/// hash at its member's index of one input's committed form.
#[derive(Clone)]
pub struct CommittedMemberKey {
    member_index: u8,
    key: HybridPublicKey,
}

impl CommittedMemberKey {
    /// Check `key` as member `member_index`'s key for input `input`.
    pub(crate) fn check(
        ctx: &SigningContext<'_>,
        input: usize,
        member_index: u8,
        key: HybridPublicKey,
    ) -> Result<Self, CeremonyError> {
        let committed = &ctx.inputs[input].committed_form;
        let expected = committed
            .key_hashes()
            .get(usize::from(member_index))
            .ok_or(CeremonyError::KeyHash {
                member: member_index,
                input,
            })?;
        if multisig_key_hash(&ctx.network_id, &key) != *expected {
            return Err(CeremonyError::KeyHash {
                member: member_index,
                input,
            });
        }
        Ok(Self { member_index, key })
    }

    /// The key.
    #[must_use]
    pub fn key(&self) -> &HybridPublicKey {
        &self.key
    }
}

/// Every signer's checked key for every input, in the intent's signer
/// order: the key blobs are built from nothing else.
pub(crate) struct SignerKeys {
    per_input: Vec<Vec<CommittedMemberKey>>,
}

impl SignerKeys {
    /// Check `keys` (per input, per signer in the intent's order).
    pub(crate) fn check(
        ctx: &SigningContext<'_>,
        keys: Vec<Vec<HybridPublicKey>>,
    ) -> Result<Self, CeremonyError> {
        let signers = &ctx.intent.intent().signers;
        if keys.len() != ctx.inputs.len() || keys.iter().any(|k| k.len() != signers.len()) {
            return Err(CeremonyError::InputCount);
        }
        let per_input = keys
            .into_iter()
            .enumerate()
            .map(|(input, keys)| {
                signers
                    .iter()
                    .zip(keys)
                    .map(|(&member, key)| CommittedMemberKey::check(ctx, input, member, key))
                    .collect::<Result<_, _>>()
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { per_input })
    }

    /// The keys, per input, signer order, as `FinalTx` carries them.
    pub(crate) fn keys(&self) -> Vec<Vec<HybridPublicKey>> {
        self.per_input
            .iter()
            .map(|keys| keys.iter().map(|k| k.key.clone()).collect())
            .collect()
    }

    fn key_blob(&self, ctx: &SigningContext<'_>, input: usize) -> Result<Vec<u8>, CeremonyError> {
        MultisigKeyBlob::assemble(
            ctx.inputs[input].committed_form.clone(),
            self.per_input[input]
                .iter()
                .map(|k| (k.member_index, k.key.clone()))
                .collect(),
        )
        .and_then(|blob| blob.to_canonical_bytes())
        .map_err(|_| CeremonyError::KeyBlob { input })
    }
}

/// The FCMP++ proof, SALs included, verified against this member's own
/// context.
pub(crate) struct VerifiedMembershipProof {
    data: Vec<u8>,
    pseudo_outs: Vec<[u8; 32]>,
}

impl VerifiedMembershipProof {
    pub(crate) fn verify(ctx: &SigningContext<'_>, data: Vec<u8>) -> Result<Self, CeremonyError> {
        let n = ctx.inputs.len();
        let pseudo_outs: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                ctx.params(i)
                    .rerandomized()
                    .input()
                    .C_tilde()
                    .compress()
                    .to_bytes()
            })
            .collect();
        let key_images: Vec<_> = ctx.inputs.iter().map(|i| i.key_image).collect();
        let pqc_keys: Vec<PqcKeyScalar> = ctx
            .inputs
            .iter()
            .map(|i| PqcKeyScalar::from_pqc_public_key(&i.committed_form.to_bytes()))
            .collect();
        let proof = ShekylFcmpProof {
            data,
            num_inputs: u32::try_from(n).expect("an intent spends at most MAX_INPUTS"),
            tree_depth: ctx.fcmp_layers,
        };
        let verified = verify(
            &proof,
            &key_images,
            &pseudo_outs,
            &pqc_keys,
            &ctx.tree_root,
            ctx.fcmp_layers,
            ctx.tx_signable,
        );
        if !matches!(verified, Ok(true)) {
            return Err(CeremonyError::MembershipProof);
        }
        Ok(Self {
            data: proof.data,
            pseudo_outs,
        })
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }
}

/// The range proof, verified over the outputs' commitments in this
/// member's own base, as CEN-H19 verifies it.
pub(crate) struct VerifiedRangeProof {
    proof: BpPlus,
    bytes: Vec<u8>,
}

impl VerifiedRangeProof {
    pub(crate) fn verify(ctx: &SigningContext<'_>, bytes: &[u8]) -> Result<Self, CeremonyError> {
        let proof = BpPlus::from_bytes(bytes).map_err(|_| CeremonyError::RangeProof)?;
        let bulletproof = proof.to_bulletproof().ok_or(CeremonyError::RangeProof)?;
        let commitments: Vec<CompressedPoint> = ctx
            .unsigned
            .base
            .commitments
            .iter()
            .map(|c| CompressedPoint::from(*c))
            .collect();
        let entry = shekyl_bulletproofs::BatchEntry {
            proof: &bulletproof,
            commitments: &commitments,
        };
        if !shekyl_bulletproofs::verify_batch(&[entry]) {
            return Err(CeremonyError::RangeProof);
        }
        Ok(Self {
            proof,
            bytes: bytes.to_vec(),
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The transaction this member signs: its own unsigned spend, the two
/// verified proofs, and a key blob per input built from checked keys.
///
/// A cosigner signs the `FinalTx` it received, from which it assembles
/// this type itself:
///
/// ```
/// use rand_core::OsRng;
/// use shekyl_multisig::ceremony::files::FinalTx;
/// use shekyl_multisig::{Authenticated, Cosigner, SigningContext};
///
/// fn sign(ctx: &SigningContext<'_>, received: &Authenticated<FinalTx>) {
///     let _ = Cosigner::sign_final_tx(ctx, received, &mut OsRng);
/// }
/// ```
///
/// It cannot sign a transaction it did not assemble:
///
/// ```compile_fail,E0308
/// use rand_core::OsRng;
/// use shekyl_multisig::{Cosigner, SigningContext};
/// use shekyl_wire::Transaction;
///
/// fn sign(ctx: &SigningContext<'_>, received: &Transaction) {
///     let _ = Cosigner::sign_final_tx(ctx, received, &mut OsRng);
/// }
/// ```
///
/// and nothing outside the assembly makes one:
///
/// ```compile_fail,E0451
/// use shekyl_multisig::ceremony::SignableTransaction;
/// use shekyl_wire::Transaction;
///
/// fn forge(tx: Transaction) -> SignableTransaction {
///     SignableTransaction { tx, hashes: Vec::new() }
/// }
/// ```
pub struct SignableTransaction {
    tx: Transaction,
    hashes: Vec<SigningPayloadHash>,
}

impl SignableTransaction {
    pub(crate) fn assemble(
        ctx: &SigningContext<'_>,
        membership: &VerifiedMembershipProof,
        range: &VerifiedRangeProof,
        keys: &SignerKeys,
    ) -> Result<Self, CeremonyError> {
        let pqc_auths = (0..ctx.inputs.len())
            .map(|input| {
                Ok(PqcAuth {
                    auth_version: PQC_AUTH_VERSION,
                    scheme_id: HYBRID_SCHEME_ID_MULTISIG,
                    flags: 0,
                    hybrid_public_key: keys.key_blob(ctx, input)?,
                    hybrid_signature: Vec::new(),
                })
            })
            .collect::<Result<_, CeremonyError>>()?;
        let tx = Transaction {
            prefix: ctx.unsigned.prefix.clone(),
            ct: Ct::Fcmp {
                fee: ctx.unsigned.fee,
                reference_block: ctx.unsigned.reference_block,
                base: ctx.unsigned.base.clone(),
                pqc_auths,
                prunable: Some(Prunable {
                    bulletproofs: vec![range.proof.clone()],
                    tree_depth: u64::from(ctx.fcmp_layers) - 1,
                    fcmp_proof: membership.data.clone(),
                    pseudo_outs: membership.pseudo_outs.clone(),
                }),
            },
        };
        debug_assert_eq!(tx.tx_signable(&ctx.network_id), ctx.tx_signable);
        let hashes = tx.pqc_signing_payload_hashes(&ctx.network_id);
        Ok(Self { tx, hashes })
    }

    /// This member's hybrid signature on every input: the one call site of
    /// the member signer in this crate.
    pub(crate) fn sign_as_member(
        &self,
        ctx: &SigningContext<'_>,
    ) -> Result<Vec<HybridSignature>, CeremonyError> {
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
            .zip(&self.hashes)
            .map(|(input, hash)| {
                sign_multisig_member_auth(
                    &view,
                    &MemberOwnCiphertext {
                        n: address.n_total(),
                        own_x25519_ct: &input.own_x25519_ct,
                        own_ml_kem_ct: &input.own_ml_kem_ct,
                    },
                    hash,
                )
                .map(|signed| signed.signature)
                .map_err(CeremonyError::MemberSign)
            })
            .collect()
    }

    pub(crate) fn hashes(&self) -> &[SigningPayloadHash] {
        &self.hashes
    }

    pub(crate) fn into_transaction(self) -> Transaction {
        self.tx
    }
}
