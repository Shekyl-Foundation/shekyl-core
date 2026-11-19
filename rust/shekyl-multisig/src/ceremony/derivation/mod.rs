// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a member signs from, derived from the intent alone (R-7, R-14,
//! `PQC_MULTISIG.md` §9.5): [`DerivedSpend`].
//!
//! A member builds the group's transaction from the validated intent, its
//! own ledger's records of the outputs the intent spends
//! ([`GroupOutputRecord`], looked up through [`GroupOutputs`]), and the
//! membership paths its own curve tree assembled, matched to the intent
//! once ([`SpendPaths`], R-26). A record holds public values and the
//! output's `0x06` ciphertext only; the spend secrets are
//! re-derived from that ciphertext under the group's key
//! (`shekyl_crypto_pq::multisig_output::recover_group_spend`) and checked
//! against the record's key image and leaf point. The outputs, their `tx_extra` and the committed base
//! come from the builder every spend uses (`shekyl_tx_builder::outputs`),
//! under the transaction key the intent's seed derives; each input's
//! pseudo-out blind and rerandomization seed come from the same seed
//! ([`IntentSeed`](shekyl_crypto_pq::multisig_intent::IntentSeed)). Every member holding the intent derives the same
//! transaction, so no member sends another anything it must trust.
//!
//! [`DerivedSpend::derive`] is the only constructor of [`InputContext`],
//! [`UnsignedSpend`] and [`DerivedSpend`], and it takes the intent only
//! from the [`SpendPaths`] it consumes: a caller cannot hand the ceremony a
//! blind, a seed or an output the intent does not determine, nor pair one
//! intent with another's paths or spend. A member
//! that is handed none of these by hand cannot build them:
//!
//! ```compile_fail,E0451
//! use shekyl_multisig::ceremony::UnsignedSpend;
//! use shekyl_tx_builder::outputs::SpendOutputs;
//!
//! fn forge(outputs: SpendOutputs) -> UnsignedSpend {
//!     UnsignedSpend { outputs }
//! }
//! ```
//!
//! ```compile_fail,E0451
//! use shekyl_crypto_pq::multisig_intent::RerandomizationSeed;
//! use shekyl_crypto_pq::multisig_output::GroupSpendSecrets;
//! use shekyl_curve_tree::AssembledPath;
//! use shekyl_multisig::ceremony::{GroupOutputRecord, InputContext};
//! use zeroize::Zeroizing;
//!
//! fn forge(
//!     record: GroupOutputRecord,
//!     path: AssembledPath,
//!     secrets: GroupSpendSecrets,
//!     blind: [u8; 32],
//!     rerandomization_seed: RerandomizationSeed,
//! ) -> InputContext {
//!     InputContext {
//!         record,
//!         path,
//!         secrets,
//!         pseudo_out_blind: Zeroizing::new(blind),
//!         rerandomization_seed,
//!     }
//! }
//! ```

use shekyl_address::multisig_address::MultisigAddressPayload;
use shekyl_crypto_pq::kem::X25519_KEM_CT_LEN;
use shekyl_crypto_pq::leaf_commitment::PQC_LEAF_POINT_LEN;
use shekyl_crypto_pq::multisig::MultisigCommittedForm;
use shekyl_crypto_pq::multisig_intent::RerandomizationSeed;
use shekyl_crypto_pq::multisig_output::{
    recover_group_spend, GroupOutputSource, GroupSpendError, GroupSpendSecrets,
    MemberOwnCiphertext, MultisigGroupKey,
};
use shekyl_crypto_pq::{CryptoError, TxKey};
use shekyl_ct_balance::PseudoOutBlinds;
use shekyl_curve_primitives::Commitment;
use shekyl_curve_tree::{AssembledPath, TreeContext};
use shekyl_fcmp::frost_sal::{FrostSalError, SalSigningParams, SpentOutput};
use shekyl_fcmp::proof::{BranchLayer, ProveInputLeafChunk};
use shekyl_fcmp::PqcLeafScalar;
use shekyl_network::NetworkId;
use shekyl_tx_builder::outputs::{
    BuildSpendError, BuiltSpend, Payee, Recipient, RecipientKeys, SpendOutputs,
};
use shekyl_types::{KeyImage, TxSignableHash};
use shekyl_units::AtomicUnits;
use shekyl_wire::{CtBase, Output};
use zeroize::Zeroizing;

use super::spend_paths::SpendPaths;
use crate::intent::ResolvedPayee;
use crate::invariants::ValidatedIntent;

/// A spendable output paid to the group, as this member's ledger stores
/// it: public values, the `0x06` ciphertext its secrets are re-derived
/// from, and this member's own `0x0D` ciphertexts. No path and nothing
/// secret (R-26): the paths arrive as one batch from the curve tree when
/// the output is spent ([`SpendPaths`]).
#[derive(Clone)]
pub struct GroupOutputRecord {
    /// The output's global index, by which an intent names it.
    pub global_index: u64,
    /// The output's index in its transaction (the derivations bind it).
    pub output_index: u64,
    /// The output's key `O`.
    pub output_key: [u8; 32],
    /// The output's commitment `C`.
    pub commitment: [u8; 32],
    /// The output's `0x06` X25519 ciphertext, to the group's KEM key.
    pub source_x25519_ct: [u8; X25519_KEM_CT_LEN],
    /// The output's `0x06` ML-KEM-768 ciphertext, to the group's KEM key.
    pub source_ml_kem_ct: Vec<u8>,
    /// The output's key image, as the scan derived it.
    pub key_image: KeyImage,
    /// The output's PQC leaf commitment point `CM`, as published.
    pub leaf_point: [u8; PQC_LEAF_POINT_LEN],
    /// The committed form the output's leaf binds (`0x02 ‖ n ‖ m ‖ h_1 … h_n`).
    pub committed_form: MultisigCommittedForm,
    /// This member's own `0x0D` X25519 ciphertext for the output.
    pub own_x25519_ct: [u8; X25519_KEM_CT_LEN],
    /// This member's own `0x0D` ML-KEM-768 ciphertext for the output.
    pub own_ml_kem_ct: Vec<u8>,
}

impl GroupOutputRecord {
    fn source(&self) -> GroupOutputSource<'_> {
        GroupOutputSource {
            output_index: self.output_index,
            output_key: &self.output_key,
            x25519_ct: &self.source_x25519_ct,
            ml_kem_ct: &self.source_ml_kem_ct,
            committed_form: &self.committed_form,
        }
    }
}

/// A member's ledger of the group's spendable outputs, as
/// [`DerivedSpend::derive`] reads it: one record per global index (R-26).
/// It holds no path: those come from the curve tree, matched to the intent
/// as [`SpendPaths`].
pub trait GroupOutputs {
    /// The record of the output at `global_index`, or `None` when the group
    /// does not hold that output spendable.
    fn record(&self, global_index: u64) -> Option<GroupOutputRecord>;
}

/// One spent input, as this member signs it: its ledger record, its
/// membership path, the secrets re-derived from the record, and the
/// pseudo-out blind and rerandomization seed the intent derives for it.
pub struct InputContext {
    record: GroupOutputRecord,
    path: AssembledPath,
    secrets: GroupSpendSecrets,
    pseudo_out_blind: Zeroizing<[u8; 32]>,
    rerandomization_seed: RerandomizationSeed,
}

impl InputContext {
    /// The input's key image.
    #[must_use]
    pub fn key_image(&self) -> KeyImage {
        self.record.key_image
    }

    /// The committed form the spent output's leaf binds.
    pub(crate) fn committed_form(&self) -> &MultisigCommittedForm {
        &self.record.committed_form
    }

    /// The input's signing parameters over `signable`. Every signer builds
    /// the same value from the same intent.
    pub(crate) fn params(
        &self,
        signable: TxSignableHash,
    ) -> Result<SalSigningParams, FrostSalError> {
        SalSigningParams::new(
            &self.rerandomization_seed,
            &SpentOutput {
                output_key: &self.record.output_key,
                commitment: &self.record.commitment,
                spend_scalar: self.secrets.spend_scalar(),
                y_kem: self.secrets.y_kem(),
                commitment_mask: self.secrets.commitment_mask(),
            },
            &self.pseudo_out_blind,
            signable,
        )
    }

    /// The prover's leaf chunk for this input: the record's public path
    /// joined to the leaf point and the blind its secrets derive.
    pub(crate) fn leaf_chunk(&self) -> ProveInputLeafChunk {
        let path = &self.path;
        let branch = |layers: &[Vec<[u8; 32]>]| -> Vec<BranchLayer> {
            layers
                .iter()
                .map(|siblings| BranchLayer {
                    siblings: siblings.clone(),
                })
                .collect()
        };
        ProveInputLeafChunk {
            pqc_leaf_commitment: self.record.leaf_point,
            pqc_leaf_blind: *self.secrets.leaf_blind(),
            leaf_outputs: path
                .leaf_chunk()
                .iter()
                .map(|leaf| {
                    (
                        leaf.output_key.to_bytes(),
                        leaf.key_image_gen,
                        leaf.commitment.to_bytes(),
                    )
                })
                .collect(),
            leaf_cm_x: path.leaf_chunk().iter().map(|leaf| leaf.cm_x).collect(),
            c1_branch_layers: branch(path.c1_layers()),
            c2_branch_layers: branch(path.c2_layers()),
        }
    }

    /// This member's own `0x0D` ciphertext for the spent output, in a
    /// group of `n`.
    pub(crate) fn own_ciphertext(&self, n: u8) -> MemberOwnCiphertext<'_> {
        MemberOwnCiphertext {
            n,
            own_x25519_ct: &self.record.own_x25519_ct,
            own_ml_kem_ct: &self.record.own_ml_kem_ct,
        }
    }
}

/// What the derivation adds to the intent: the outputs, their `tx_extra`
/// and the committed base. The inputs, the fee and the reference block are
/// the intent's, so they are not here.
#[derive(Clone, Debug)]
pub struct UnsignedSpend {
    outputs: SpendOutputs,
}

impl UnsignedSpend {
    /// The prefix's outputs, in position order (R-24: recipient `i` at
    /// `π(i)`).
    #[must_use]
    pub fn outputs(&self) -> &[Output] {
        self.outputs.outputs()
    }

    /// `tx_extra`.
    #[must_use]
    pub fn extra(&self) -> &[u8] {
        self.outputs.extra()
    }

    /// The committed base: each output's commitment and encrypted fields.
    #[must_use]
    pub fn base(&self) -> &CtBase {
        self.outputs.base()
    }
}

/// Why a member cannot derive its spend from an intent.
#[derive(Debug, thiserror::Error)]
pub enum DeriveError {
    /// An input of the intent is not in this member's ledger.
    #[error("input {global_index} is not in this member's ledger")]
    MissingInput { global_index: u64 },
    /// An input's secrets do not re-derive from its record.
    #[error("input {global_index}'s secrets do not derive: {source}")]
    Secrets {
        global_index: u64,
        #[source]
        source: GroupSpendError,
    },
    /// An input's record names a key image its secrets do not derive: the
    /// record is not this group's output, or is damaged.
    #[error("input {global_index}'s recorded key image is not the one its secrets derive")]
    KeyImage { global_index: u64 },
    /// An input's record names a leaf point its secrets do not derive.
    #[error("input {global_index}'s recorded leaf is not the one its secrets derive")]
    Leaf { global_index: u64 },
    /// An input's commitment on the chain does not open to the mask its
    /// secrets derive and the amount the validated intent pairs with it
    /// (R-27): the stated amount is not this coin's.
    #[error("input {global_index}'s commitment does not open at its stated amount")]
    InputCommitment { global_index: u64 },
    /// An input's path does not hold its output's leaf.
    #[error("input {global_index}'s path does not hold its output")]
    Path { global_index: u64 },
    /// Two inputs have one key image: one output spent twice.
    #[error("two inputs have one key image")]
    DuplicateKeyImage,
    /// A single-signer recipient's address keys do not map to the keys its
    /// output is built to.
    #[error("recipient {recipient}'s keys do not map: {source}")]
    Recipient {
        recipient: usize,
        #[source]
        source: CryptoError,
    },
    /// The builder refused the outputs.
    #[error("the outputs do not build: {0}")]
    Outputs(#[source] BuildSpendError),
}

/// One recipient, ready to build. A single-signer recipient holds the keys
/// its output is built to, the view key mapped once. A group recipient
/// borrows its address. [`DerivedSpend::derive`] builds this list in one
/// pass and then borrows a [`Payee`] from each entry, so every output is
/// built from the recipient it was mapped with.
enum PreparedPayee<'a> {
    Single {
        keys: RecipientKeys<'a>,
        label_plaintext: &'a [u8; 8],
    },
    Group {
        address: &'a MultisigAddressPayload,
    },
}

impl<'a> PreparedPayee<'a> {
    fn prepare(recipient: usize, payee: &'a ResolvedPayee) -> Result<Self, DeriveError> {
        match payee {
            ResolvedPayee::Single {
                address,
                label_plaintext,
            } => {
                let keys = RecipientKeys::of_address(address.as_address())
                    .map_err(|source| DeriveError::Recipient { recipient, source })?;
                Ok(Self::Single {
                    keys,
                    label_plaintext,
                })
            }
            ResolvedPayee::Group(address) => Ok(Self::Group { address }),
        }
    }

    fn payee<'p>(&'p self, network: &'p NetworkId) -> Payee<'p> {
        match self {
            Self::Single {
                keys,
                label_plaintext,
            } => keys.payee(label_plaintext),
            Self::Group { address } => Payee::Group { address, network },
        }
    }
}

/// A member's spend, derived from a validated intent and its own ledger:
/// the intent, the network its outputs are built for, the curve tree at
/// the intent's reference block, the inputs in the transaction's order
/// (key images strictly descending, CEN-I5), the unsigned spend, and each
/// output's opening.
pub struct DerivedSpend {
    pub(super) network_id: NetworkId,
    pub(super) intent: ValidatedIntent,
    pub(super) tree: TreeContext,
    pub(super) inputs: Vec<InputContext>,
    pub(super) unsigned: UnsignedSpend,
    pub(super) output_openings: Vec<Commitment>,
}

impl DerivedSpend {
    /// Derive the spend the intent of `paths` describes on the chain whose
    /// id is `network_id`: each input's record looked up in `ledger` by the
    /// intent's own global indices, its secrets re-derived under `key` (the
    /// group's key from this member's file), and its path the one `paths`
    /// matched to it. The paths were matched to the intent's reference block
    /// and inputs once, by [`SpendPaths::new`], and are to one tree, so
    /// nothing here compares blocks or trees.
    ///
    /// Recipient `i` is the output at position `π(i)`, the order the
    /// intent's transaction key derives (R-24), so every member places the
    /// outputs alike; each is built to its resolved payee under that key.
    /// Input `j` of the intent
    /// takes the `j`-th derived pseudo-out blind and rerandomization seed;
    /// the last blind balances the outputs' masks. The inputs are then put
    /// in the transaction's order.
    ///
    /// # Errors
    ///
    /// The first [`DeriveError`] that holds.
    pub fn derive(
        paths: SpendPaths,
        ledger: &impl GroupOutputs,
        key: &MultisigGroupKey<'_>,
        network_id: NetworkId,
    ) -> Result<Self, DeriveError> {
        let (intent, tree, paths) = paths.into_parts();
        // Allocated once, at the input count: each record carries the
        // secrets re-derived for it, and a vector that grew would free its
        // earlier buffers, secrets in them, without wiping them.
        let mut records = Vec::with_capacity(intent.input_count().get());
        for ((&global_index, amount), path) in intent
            .intent()
            .input_global_indices
            .iter()
            .zip(intent.input_amounts())
            .zip(paths)
        {
            records.push(spendable(ledger, key, global_index, *amount, path)?);
        }
        let seed = &intent.intent().kem_randomness_seed;
        let tx_key = TxKey::from_intent_seed(seed);
        // Each recipient's keys mapped once, in recipient order. The outputs
        // borrow those keys; recipient `i` is not yet an output position.
        let prepared = intent
            .recipients()
            .iter()
            .enumerate()
            .map(|(recipient, r)| PreparedPayee::prepare(recipient, &r.payee))
            .collect::<Result<Vec<_>, _>>()?;
        let recipients: Vec<Recipient<'_>> = prepared
            .iter()
            .zip(intent.recipients())
            .map(|(prepared, r)| Recipient {
                payee: prepared.payee(&network_id),
                amount: r.amount.to_raw(),
            })
            .collect();
        // Recipient `i` lands at `π(i)`, the order the intent's key derives,
        // alike for every member (R-24).
        let built = BuiltSpend::build(&tx_key, &recipients).map_err(DeriveError::Outputs)?;
        let output_openings: Vec<Commitment> = built
            .outputs()
            .iter()
            .map(|b| b.commitment_mask().opening(b.info.amount.to_raw()))
            .collect();
        // Every input's blind but the last from the intent's seed, in the
        // intent's input order; the last balances the outputs' masks.
        let blinds =
            PseudoOutBlinds::from_intent(seed, intent.input_count(), &output_openings).into_bytes();
        let mut inputs: Vec<InputContext> = records
            .into_iter()
            .zip(blinds)
            .enumerate()
            .map(
                |(position, ((record, path, secrets), pseudo_out_blind))| InputContext {
                    record,
                    path,
                    secrets,
                    pseudo_out_blind,
                    rerandomization_seed: seed.rerandomization_seed(position),
                },
            )
            .collect();
        inputs.sort_unstable_by(|a, b| b.key_image().as_bytes().cmp(a.key_image().as_bytes()));
        if inputs
            .windows(2)
            .any(|pair| pair[0].key_image() == pair[1].key_image())
        {
            return Err(DeriveError::DuplicateKeyImage);
        }
        let unsigned = UnsignedSpend {
            outputs: built.wire().clone(),
        };
        Ok(Self {
            network_id,
            intent,
            tree,
            inputs,
            unsigned,
            output_openings,
        })
    }

    /// The intent this spend is derived from.
    #[must_use]
    pub fn intent(&self) -> &ValidatedIntent {
        &self.intent
    }

    /// The unsigned spend.
    #[must_use]
    pub fn unsigned(&self) -> &UnsignedSpend {
        &self.unsigned
    }

    /// The inputs, in the transaction's order.
    #[must_use]
    pub fn inputs(&self) -> &[InputContext] {
        &self.inputs
    }
}

/// Input `global_index`'s record from the ledger, beside `path`, its path
/// in the batch matched to the intent, and the secrets `key` re-derives
/// from the record: checked against the record's key image and leaf,
/// against its commitment at `amount` (R-27), and against the path's leaf
/// chunk.
fn spendable(
    ledger: &impl GroupOutputs,
    key: &MultisigGroupKey<'_>,
    global_index: u64,
    amount: AtomicUnits,
    path: AssembledPath,
) -> Result<(GroupOutputRecord, AssembledPath, GroupSpendSecrets), DeriveError> {
    let record = ledger
        .record(global_index)
        .ok_or(DeriveError::MissingInput { global_index })?;
    let secrets =
        recover_group_spend(key, &record.source()).map_err(|source| DeriveError::Secrets {
            global_index,
            source,
        })?;
    if secrets.key_image() != record.key_image {
        return Err(DeriveError::KeyImage { global_index });
    }
    if secrets.leaf_point() != &record.leaf_point {
        return Err(DeriveError::Leaf { global_index });
    }
    let cm_x = PqcLeafScalar::from_commitment_point(&record.leaf_point)
        .ok_or(DeriveError::Leaf { global_index })?;
    if !secrets.commitment_opens(&record.commitment, amount.to_raw()) {
        return Err(DeriveError::InputCommitment { global_index });
    }
    // Consensus does not forbid two leaves with one `(O, C)` in a chunk;
    // `CM.x` names the spent one.
    if !path.leaf_chunk().iter().any(|leaf| {
        leaf.output_key.to_bytes() == record.output_key
            && leaf.commitment.to_bytes() == record.commitment
            && leaf.cm_x == cm_x.0
    }) {
        return Err(DeriveError::Path { global_index });
    }
    Ok((record, path, secrets))
}

#[cfg(test)]
mod tests;
