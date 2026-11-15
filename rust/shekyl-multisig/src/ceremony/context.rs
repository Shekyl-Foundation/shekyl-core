// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What one member brings to a ceremony: [`SigningContext`], its derived
//! spend (`super::derivation`) with its keys and its view of the tree,
//! and, for the proposer alone, [`ProposerInputs`].
//!
//! The intent is the only input a signer trusts. Every value here is the
//! member's own: the spent outputs as its ledger records them, and what
//! the intent derives from them (R-7, R-14). Nothing another member sends
//! enters this type.
//!
//! What the intent fixes is never carried twice: the fee and the reference
//! block are read from the intent, and the inputs are the context's own key
//! images. [`UnsignedSpend`] carries only what the derivation adds, so an
//! unsigned spend that disagrees with its intent cannot be written down.
//!
//! The ceremony's input order is the transaction's: key images strictly
//! descending (CEN-I5). Every member computes the same key images, so every
//! member orders its inputs alike, and every per-input list in a ceremony
//! file is in this order.

use shekyl_crypto_pq::multisig_output::{MemberOwnCiphertext, MultisigMemberView};
use shekyl_curve_primitives::Commitment;
use shekyl_fcmp::frost_sal::{
    check_keys_open, threshold_keys, Ed25519T, FrostKeyError, FrostSalError, SalSigningParams,
    ThresholdKeys,
};
use shekyl_fcmp::proof::ProveInputLeafChunk;
use shekyl_network::NetworkId;
use shekyl_types::{BlockHash, CurveTreeRoot, KeyImage, TxSignableHash};
use shekyl_wire::{Ct, Input, PqcAuth, Prunable, Transaction, TxPrefix};

use super::derivation::{DerivedSpend, InputContext, UnsignedSpend};
use super::{CeremonyError, Role};
use crate::invariants::ValidatedIntent;
use crate::member_file::MemberFile;

/// Why a member's context cannot be built.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    /// This member is not one of the intent's signers.
    #[error("this member is not a signer of the intent")]
    NotASigner,
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
    output_openings: Vec<Commitment>,
    pub(crate) tree_root: CurveTreeRoot,
    pub(crate) fcmp_layers: u8,
    tree_depth: u64,
    pub(crate) tx_signable: TxSignableHash,
}

impl<'a> SigningContext<'a> {
    /// Build `member`'s context for its derived spend `derived`, under a
    /// tree whose root is `tree_root` and whose layer count is
    /// `fcmp_layers`.
    ///
    /// Checks this member signs the intent; every committed form is for
    /// this group's size; a spend proves under `fcmp_layers`; this
    /// member's share loads; and every input's parameters build and are
    /// opened by this member's keys.
    ///
    /// # Errors
    ///
    /// The first [`ContextError`] that holds.
    pub fn new(
        member: &'a MemberFile,
        derived: DerivedSpend,
        tree_root: CurveTreeRoot,
        fcmp_layers: u8,
    ) -> Result<Self, ContextError> {
        let DerivedSpend {
            network_id,
            intent,
            inputs,
            unsigned,
            output_openings,
        } = derived;
        if !intent.intent().signers.contains(&member.member_index()) {
            return Err(ContextError::NotASigner);
        }
        let address = member.address();
        for (input, spent) in inputs.iter().enumerate() {
            let form = spent.committed_form();
            if form.n_total() != address.n_total() || form.m_required() != address.m_required() {
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
            output_openings,
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
        self.inputs[input].own_ciphertext(self.member.address().n_total())
    }

    /// The output commitments this member's derivation yields.
    pub(crate) fn output_commitments(&self) -> &[[u8; 32]] {
        &self.unsigned.base().commitments
    }

    /// Each output's opening, in output order: what the range proof
    /// covers.
    pub(crate) fn output_openings(&self) -> &[Commitment] {
        &self.output_openings
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
                .map(|spent| Input::fcmp_spend(spent.key_image()))
                .collect(),
            outputs: unsigned.outputs().to_vec(),
            extra: unsigned.extra().to_vec(),
        },
        ct: Ct::Fcmp {
            fee: intent.fee.to_raw(),
            reference_block: BlockHash::from_bytes(intent.reference_block_hash),
            base: unsigned.base().clone(),
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

/// What the proposer alone needs to finish the transaction, beyond what
/// it derives: each input's path to the reference root (the membership
/// proof).
pub struct ProposerInputs {
    /// One per input, in any order: each names its input.
    pub input_paths: Vec<InputPath>,
}

impl ProposerInputs {
    /// These inputs for `ctx`: a path per input, put in the context's
    /// input order.
    ///
    /// # Errors
    ///
    /// [`CeremonyError::InputCount`] when an input has no path, or one has
    /// two.
    pub(crate) fn for_context(mut self, ctx: &SigningContext<'_>) -> Result<Self, CeremonyError> {
        self.input_paths
            .sort_unstable_by(|a, b| b.key_image.as_bytes().cmp(a.key_image.as_bytes()));
        let paths_match = self
            .input_paths
            .iter()
            .map(|path| path.key_image)
            .eq(ctx.inputs.iter().map(InputContext::key_image));
        if !paths_match {
            return Err(CeremonyError::InputCount);
        }
        Ok(self)
    }
}
