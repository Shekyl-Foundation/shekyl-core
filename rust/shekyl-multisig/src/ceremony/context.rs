// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What one member brings to a ceremony: [`SigningContext`], everything it
//! derives from the intent and its own ledger (R-7), and, for the proposer
//! alone, [`ProposerInputs`].
//!
//! The intent is the only input a signer trusts. Every value here is the
//! member's own: the spent outputs as its scan recovered them, the
//! rerandomization seeds and pseudo-out blinds derived from the intent's
//! `kem_randomness_seed` (slice 4a derives them under the reserved labels,
//! `PQC_MULTISIG.md` §9.5; this slice's tests build them directly), and
//! the outputs its own construction yields. Nothing another member sends
//! enters this type.
//!
//! What the intent fixes is never carried twice: the fee and the reference
//! block are read from the intent, and the inputs are the context's own key
//! images. [`UnsignedSpend`] carries only what the construction adds, so an
//! unsigned spend that disagrees with its intent cannot be written down.
//!
//! The ceremony's input order is the transaction's: key images strictly
//! descending (CEN-I5). Every member computes the same key images, so every
//! member orders its inputs alike, and every per-input list in a ceremony
//! file is in this order.

use shekyl_crypto_pq::kem::X25519_KEM_CT_LEN;
use shekyl_crypto_pq::multisig::MultisigCommittedForm;
use shekyl_crypto_pq::multisig_output::{MemberOwnCiphertext, MultisigMemberView};
use shekyl_curve_primitives::Commitment;
use shekyl_fcmp::frost_sal::{
    check_keys_open, threshold_keys, Ed25519T, FrostKeyError, FrostSalError, SalSigningParams,
    SpentOutput, ThresholdKeys, RERANDOMIZATION_SEED_LEN,
};
use shekyl_fcmp::proof::ProveInputLeafChunk;
use shekyl_network::NetworkId;
use shekyl_types::{BlockHash, CurveTreeRoot, KeyImage, TxSignableHash};
use shekyl_wire::{Ct, CtBase, Input, Output, PqcAuth, Prunable, Transaction, TxPrefix};
use zeroize::Zeroizing;

use super::{CeremonyError, Role};
use crate::invariants::ValidatedIntent;
use crate::member_file::MemberFile;

/// One spent input, as this member knows it.
pub struct InputContext {
    /// The output's key `O`.
    pub output_key: [u8; 32],
    /// The output's commitment `C`.
    pub commitment: [u8; 32],
    /// `x = ho + b`, group-plaintext.
    pub spend_scalar: Zeroizing<[u8; 32]>,
    /// The output's `y_kem`.
    pub y_kem: Zeroizing<[u8; 32]>,
    /// The output's commitment mask `z`.
    pub commitment_mask: Zeroizing<[u8; 32]>,
    /// The input's pseudo-out blind `a`, derived from the intent.
    pub pseudo_out_blind: Zeroizing<[u8; 32]>,
    /// The input's rerandomization seed, derived from the intent.
    pub rerandomization_seed: Zeroizing<[u8; RERANDOMIZATION_SEED_LEN]>,
    /// The input's key image.
    pub key_image: KeyImage,
    /// The committed form the output's leaf binds (`0x02 ‖ n ‖ m ‖ h_1 … h_n`).
    pub committed_form: MultisigCommittedForm,
    /// This member's own `0x0D` X25519 ciphertext for the output.
    pub own_x25519_ct: [u8; X25519_KEM_CT_LEN],
    /// This member's own `0x0D` ML-KEM-768 ciphertext for the output.
    pub own_ml_kem_ct: Vec<u8>,
}

impl InputContext {
    /// The input's signing parameters, built from this member's own values.
    /// Every signer builds the same value from the same intent.
    fn params(&self, signable: TxSignableHash) -> Result<SalSigningParams, FrostSalError> {
        SalSigningParams::new(
            &self.rerandomization_seed,
            &SpentOutput {
                output_key: &self.output_key,
                commitment: &self.commitment,
                spend_scalar: &self.spend_scalar,
                y_kem: &self.y_kem,
                commitment_mask: &self.commitment_mask,
            },
            &self.pseudo_out_blind,
            signable,
        )
    }
}

/// What this member's construction adds to the intent: the outputs, their
/// `tx_extra` fields and the committed base. The inputs, the fee and the
/// reference block are the intent's, so they are not here.
#[derive(Clone, Debug)]
pub struct UnsignedSpend {
    /// The outputs, in output order.
    pub outputs: Vec<Output>,
    /// `tx_extra`: every output's PQC fields.
    pub extra: Vec<u8>,
    /// The committed base: output commitments and encrypted fields.
    pub base: CtBase,
}

/// Why a member's context cannot be built.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    /// This member is not one of the intent's signers.
    #[error("this member is not a signer of the intent")]
    NotASigner,
    /// The context's inputs are not the intent's.
    #[error("the context has {got} inputs; the intent spends {expected}")]
    InputCount { expected: usize, got: usize },
    /// Two inputs have one key image: one output spent twice.
    #[error("two inputs have one key image")]
    DuplicateKeyImage,
    /// An input's committed form is not for this group.
    #[error("input {input}'s committed form is not for this group")]
    CommittedForm { input: usize },
    /// No spend proves under this many FCMP++ layers.
    #[error("no spend proves under {layers} FCMP++ layers")]
    TreeLayers { layers: u8 },
    /// This member's key share does not load.
    #[error("this member's key share does not load: {0}")]
    Keys(FrostKeyError),
    /// An input's parameters do not build, or the keys do not open it.
    #[error("input {input}'s signing parameters do not build: {source}")]
    Params { input: usize, source: FrostSalError },
}

/// What one member signs from.
pub struct SigningContext<'a> {
    pub(crate) member: &'a MemberFile,
    pub(crate) network_id: NetworkId,
    pub(crate) keys: ThresholdKeys<Ed25519T>,
    pub(crate) intent: ValidatedIntent,
    pub(crate) inputs: Vec<InputContext>,
    unsigned: UnsignedSpend,
    pub(crate) tree_root: CurveTreeRoot,
    pub(crate) fcmp_layers: u8,
    tree_depth: u64,
    pub(crate) tx_signable: TxSignableHash,
}

impl<'a> SigningContext<'a> {
    /// Build `member`'s context for `intent`.
    ///
    /// Puts `inputs` in the transaction's order, and checks what can be
    /// checked without the derivation itself (slice 4a's): this member
    /// signs the intent; one input context per intent input, each spending
    /// its own output; every committed form is for this group's size; a
    /// spend proves under `fcmp_layers`; this member's share loads; and
    /// every input's parameters build and are opened by this member's keys.
    ///
    /// # Errors
    ///
    /// The first [`ContextError`] that holds.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is a distinct part of the member's own view"
    )]
    pub fn new(
        member: &'a MemberFile,
        network_id: NetworkId,
        intent: ValidatedIntent,
        mut inputs: Vec<InputContext>,
        unsigned: UnsignedSpend,
        tree_root: CurveTreeRoot,
        fcmp_layers: u8,
    ) -> Result<Self, ContextError> {
        if !intent.intent().signers.contains(&member.member_index()) {
            return Err(ContextError::NotASigner);
        }
        let expected = intent.intent().input_global_indices.len();
        if inputs.len() != expected {
            return Err(ContextError::InputCount {
                expected,
                got: inputs.len(),
            });
        }
        inputs.sort_unstable_by(|a, b| b.key_image.as_bytes().cmp(a.key_image.as_bytes()));
        if inputs
            .windows(2)
            .any(|pair| pair[0].key_image == pair[1].key_image)
        {
            return Err(ContextError::DuplicateKeyImage);
        }
        let address = member.address();
        for (input, ctx) in inputs.iter().enumerate() {
            if ctx.committed_form.n_total() != address.n_total()
                || ctx.committed_form.m_required() != address.m_required()
            {
                return Err(ContextError::CommittedForm { input });
            }
        }
        let tree_depth =
            shekyl_fcmp::curve_trees_tree_depth(fcmp_layers).ok_or(ContextError::TreeLayers {
                layers: fcmp_layers,
            })?;
        let keys = threshold_keys(
            address.n_total(),
            address.m_required(),
            member.member_index(),
            member.y_share(),
            member.verification_shares(),
            address.y_group(),
        )
        .map_err(ContextError::Keys)?;
        let tx_signable =
            spend(&intent, &inputs, &unsigned, Vec::new(), None).tx_signable(&network_id);
        for (input, spent) in inputs.iter().enumerate() {
            let params = spent
                .params(tx_signable)
                .map_err(|source| ContextError::Params { input, source })?;
            check_keys_open(&params, &keys)
                .map_err(|source| ContextError::Params { input, source })?;
        }
        Ok(Self {
            member,
            network_id,
            keys,
            intent,
            inputs,
            unsigned,
            tree_root,
            fcmp_layers,
            tree_depth,
            tx_signable,
        })
    }

    /// The intent this context signs.
    #[must_use]
    pub fn intent(&self) -> &ValidatedIntent {
        &self.intent
    }

    /// The message every proof and signature of this spend is over.
    #[must_use]
    pub fn tx_signable(&self) -> TxSignableHash {
        self.tx_signable
    }

    /// The member whose context this is.
    #[must_use]
    pub fn member(&self) -> &MemberFile {
        self.member
    }

    /// This member's role in the intent.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role_of(self.member.member_index())
            .expect("new() refused a member that is not a signer")
    }

    /// `member`'s role in the intent, or `None` if it does not sign.
    #[must_use]
    pub fn role_of(&self, member: u8) -> Option<Role> {
        Role::of(self.intent.intent(), member)
    }

    /// The intent's holders, in signer order.
    pub(crate) fn holders(&self) -> impl Iterator<Item = u8> + '_ {
        self.intent
            .intent()
            .signers
            .iter()
            .copied()
            .filter(|&member| self.role_of(member) == Some(Role::Holder))
    }

    /// The input's signing parameters. Each signer derives them from the
    /// input's seed; a held session takes its own copy.
    pub(crate) fn params(&self, input: usize) -> SalSigningParams {
        self.inputs[input]
            .params(self.tx_signable)
            .expect("new() built every input's params")
    }

    /// This member as its multisig signer sees it.
    pub(crate) fn signing_view(&self) -> MultisigMemberView<'_> {
        self.member.signing_view(&self.network_id)
    }

    /// This member's own `0x0D` ciphertext for `input`.
    pub(crate) fn own_ciphertext(&self, input: usize) -> MemberOwnCiphertext<'_> {
        let spent = &self.inputs[input];
        MemberOwnCiphertext {
            n: self.member.address().n_total(),
            own_x25519_ct: &spent.own_x25519_ct,
            own_ml_kem_ct: &spent.own_ml_kem_ct,
        }
    }

    /// The output commitments this member's construction yields.
    pub(crate) fn output_commitments(&self) -> &[[u8; 32]] {
        &self.unsigned.base.commitments
    }

    /// The on-chain tree depth of a spend proving under this context's
    /// layers.
    pub(crate) fn tree_depth(&self) -> u64 {
        self.tree_depth
    }

    /// This member's spend with `pqc_auths` and `prunable`: the inputs are
    /// its own key images in the intent's order, the fee and the reference
    /// block are the intent's, and the rest is its own construction. Every
    /// transaction this member hashes or signs is built here.
    pub(crate) fn transaction(
        &self,
        pqc_auths: Vec<PqcAuth>,
        prunable: Option<Prunable>,
    ) -> Transaction {
        spend(
            &self.intent,
            &self.inputs,
            &self.unsigned,
            pqc_auths,
            prunable,
        )
    }
}

/// The one layout of a member's spend: its own key images in the intent's
/// order, the intent's fee and reference block, and its own construction.
fn spend(
    intent: &ValidatedIntent,
    inputs: &[InputContext],
    unsigned: &UnsignedSpend,
    pqc_auths: Vec<PqcAuth>,
    prunable: Option<Prunable>,
) -> Transaction {
    let intent = intent.intent();
    Transaction {
        prefix: TxPrefix {
            unlock_time: TxPrefix::NO_UNLOCK_TIME,
            inputs: inputs
                .iter()
                .map(|spent| Input::fcmp_spend(spent.key_image))
                .collect(),
            outputs: unsigned.outputs.clone(),
            extra: unsigned.extra.clone(),
        },
        ct: Ct::Fcmp {
            fee: intent.fee.to_raw(),
            reference_block: BlockHash::from_bytes(intent.reference_block_hash),
            base: unsigned.base.clone(),
            pqc_auths,
            prunable,
        },
    }
}

/// One input's path to the reference root, named by the input it proves.
pub struct InputPath {
    /// The key image of the input the path proves.
    pub key_image: KeyImage,
    /// The leaf chunk holding the input's output, and the branch above it.
    pub leaf_chunk: ProveInputLeafChunk,
}

/// What the proposer alone needs to finish the transaction: each output's
/// opening (the range proof covers them) and each input's path to the
/// reference root (the membership proof).
pub struct ProposerInputs {
    /// Per output, in output order: its amount and mask, wiped on drop.
    pub output_openings: Vec<Commitment>,
    /// One per input, in any order: each names its input.
    pub input_paths: Vec<InputPath>,
}

impl ProposerInputs {
    /// These inputs for `ctx`: an opening per output, and a path per input
    /// put in the context's input order.
    ///
    /// # Errors
    ///
    /// [`CeremonyError::InputCount`] when an output has no opening or an
    /// input no path, or one has two.
    pub(crate) fn for_context(mut self, ctx: &SigningContext<'_>) -> Result<Self, CeremonyError> {
        self.input_paths
            .sort_unstable_by(|a, b| b.key_image.as_bytes().cmp(a.key_image.as_bytes()));
        let paths_match = self
            .input_paths
            .iter()
            .map(|path| path.key_image)
            .eq(ctx.inputs.iter().map(|spent| spent.key_image));
        if !paths_match || self.output_openings.len() != ctx.output_commitments().len() {
            return Err(CeremonyError::InputCount);
        }
        Ok(self)
    }
}
