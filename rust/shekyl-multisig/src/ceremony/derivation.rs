// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a member signs from, derived from the intent alone (R-7, R-14,
//! `PQC_MULTISIG.md` §9.5): [`DerivedSpend`].
//!
//! A member builds the group's transaction from the validated intent and
//! its own ledger's records of the outputs the intent spends
//! ([`GroupOutput`], looked up through [`GroupOutputs`]). A record holds
//! public values and the output's `0x06` ciphertext only; the spend
//! secrets are re-derived from that ciphertext under the group's key
//! (`shekyl_crypto_pq::multisig_output::recover_group_spend`) and checked
//! against the record's key image and leaf point. The outputs, their `tx_extra` and the committed base
//! come from the builder every spend uses (`shekyl_tx_builder::outputs`),
//! under the transaction key the intent's seed derives; each input's
//! pseudo-out blind and rerandomization seed come from the same seed
//! ([`IntentSeed`](shekyl_crypto_pq::multisig_intent::IntentSeed)). Every member holding the intent derives the same
//! transaction, so no member sends another anything it must trust.
//!
//! [`DerivedSpend::derive`] is the only constructor of [`InputContext`],
//! [`UnsignedSpend`] and [`DerivedSpend`], and it consumes the intent: a
//! caller cannot hand the ceremony a blind, a seed or an output the intent
//! does not determine, nor pair one intent with another's spend. A member
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
//! use shekyl_multisig::ceremony::{GroupOutput, InputContext};
//! use zeroize::Zeroizing;
//!
//! fn forge(
//!     output: GroupOutput,
//!     secrets: GroupSpendSecrets,
//!     blind: [u8; 32],
//!     rerandomization_seed: RerandomizationSeed,
//! ) -> InputContext {
//!     InputContext {
//!         output,
//!         secrets,
//!         pseudo_out_blind: Zeroizing::new(blind),
//!         rerandomization_seed,
//!     }
//! }
//! ```

use shekyl_crypto_pq::kem::X25519_KEM_CT_LEN;
use shekyl_crypto_pq::leaf_commitment::PQC_LEAF_POINT_LEN;
use shekyl_crypto_pq::multisig::MultisigCommittedForm;
use shekyl_crypto_pq::multisig_intent::RerandomizationSeed;
use shekyl_crypto_pq::multisig_output::{
    recover_group_spend, GroupOutputSource, GroupSpendError, GroupSpendSecrets,
    MemberOwnCiphertext, MultisigGroupKey,
};
use shekyl_crypto_pq::{CryptoError, TxKey};
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
use shekyl_wire::{CtBase, Output};
use zeroize::Zeroizing;

use crate::intent::ResolvedPayee;
use crate::invariants::ValidatedIntent;

/// A spendable output paid to the group, as this member's ledger records
/// it: public values, the `0x06` ciphertext its secrets are re-derived
/// from, and this member's own `0x0D` ciphertexts. Nothing secret.
#[derive(Clone)]
pub struct GroupOutput {
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
    /// The output's membership path to the curve tree at the intent's
    /// reference block, public material only, with that tree's context.
    pub path: AssembledPath,
}

impl GroupOutput {
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

/// A member's ledger of the group's spendable outputs, as [`DerivedSpend::derive`]
/// reads it: one record per global index, its path assembled to the
/// intent's reference block.
///
/// `derive` checks that every path names the intent's reference block hash
/// and one tree. That the tree's root is the one the block's header
/// commits to is the implementor's to hold, as the solo wallet's curve
/// tree client holds it (`shekyl_curve_tree::ReferenceBlock`): a ledger
/// assembles its paths against the header root of the block it has synced
/// under that hash. A path to another root makes a context the proposer's
/// honest proof does not verify under.
pub trait GroupOutputs {
    /// The record of the output at `global_index`, if the group holds it
    /// spendable.
    fn output(&self, global_index: u64) -> Option<&GroupOutput>;
}

/// One spent input, as this member signs it: its ledger record, the
/// secrets re-derived from it, and the pseudo-out blind and
/// rerandomization seed the intent derives for it.
pub struct InputContext {
    output: GroupOutput,
    secrets: GroupSpendSecrets,
    pseudo_out_blind: Zeroizing<[u8; 32]>,
    rerandomization_seed: RerandomizationSeed,
}

impl InputContext {
    /// The input's key image.
    #[must_use]
    pub fn key_image(&self) -> KeyImage {
        self.output.key_image
    }

    /// The committed form the spent output's leaf binds.
    pub(crate) fn committed_form(&self) -> &MultisigCommittedForm {
        &self.output.committed_form
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
                output_key: &self.output.output_key,
                commitment: &self.output.commitment,
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
        let path = &self.output.path;
        let branch = |layers: &[Vec<[u8; 32]>]| -> Vec<BranchLayer> {
            layers
                .iter()
                .map(|siblings| BranchLayer {
                    siblings: siblings.clone(),
                })
                .collect()
        };
        ProveInputLeafChunk {
            pqc_leaf_commitment: self.output.leaf_point,
            pqc_leaf_blind: *self.secrets.leaf_blind(),
            leaf_outputs: path
                .leaf_chunk
                .iter()
                .map(|leaf| {
                    (
                        leaf.output_key.to_bytes(),
                        leaf.key_image_gen,
                        leaf.commitment.to_bytes(),
                    )
                })
                .collect(),
            leaf_cm_x: path.leaf_chunk.iter().map(|leaf| leaf.cm_x).collect(),
            c1_branch_layers: branch(&path.c1_layers),
            c2_branch_layers: branch(&path.c2_layers),
        }
    }

    /// This member's own `0x0D` ciphertext for the spent output, in a
    /// group of `n`.
    pub(crate) fn own_ciphertext(&self, n: u8) -> MemberOwnCiphertext<'_> {
        MemberOwnCiphertext {
            n,
            own_x25519_ct: &self.output.own_x25519_ct,
            own_ml_kem_ct: &self.output.own_ml_kem_ct,
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
    /// An input's path is not to the tree at the intent's reference block.
    #[error("input {global_index}'s path is not to the intent's reference block")]
    Reference { global_index: u64 },
    /// Two inputs' paths name different trees at the reference block.
    #[error("input {global_index}'s path names another tree than the other inputs'")]
    Tree { global_index: u64 },
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
    /// The output at `position` does not open at its amount: its mask is
    /// not a canonical scalar.
    #[error("the output at position {position} does not open")]
    Opening { position: usize },
    /// The pseudo-out blinds do not derive.
    #[error("the pseudo-out blinds do not derive: {0}")]
    Blinds(CryptoError),
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
    /// Derive the spend `intent` describes on the chain whose id is
    /// `network_id`, looking each input up in `ledger` by the intent's own
    /// global indices and re-deriving its secrets under `key`, the group's
    /// key from this member's file.
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
        intent: ValidatedIntent,
        ledger: &impl GroupOutputs,
        key: &MultisigGroupKey<'_>,
        network_id: NetworkId,
    ) -> Result<Self, DeriveError> {
        let records = intent
            .intent()
            .input_global_indices
            .iter()
            .map(|&global_index| spendable(ledger, key, global_index))
            .collect::<Result<Vec<_>, _>>()?;
        let tree = one_tree(&intent, &records)?;
        let seed = &intent.intent().kem_randomness_seed;
        let tx_key = TxKey::from_intent_seed(seed);
        // A single-signer recipient's keys, mapped once; the payees borrow
        // them.
        let single_keys = intent
            .recipients()
            .iter()
            .enumerate()
            .filter_map(|(recipient, r)| match &r.payee {
                ResolvedPayee::Single { address, .. } => Some(
                    RecipientKeys::of_address(address.as_address())
                        .map_err(|source| DeriveError::Recipient { recipient, source }),
                ),
                ResolvedPayee::Group(_) => None,
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut keys = single_keys.iter();
        let recipients: Vec<Recipient<'_>> = intent
            .recipients()
            .iter()
            .map(|r| Recipient {
                payee: match &r.payee {
                    ResolvedPayee::Single {
                        label_plaintext, ..
                    } => keys
                        .next()
                        .expect("one mapped key per single-signer recipient")
                        .payee(label_plaintext),
                    ResolvedPayee::Group(address) => Payee::Group {
                        address,
                        network: &network_id,
                    },
                },
                amount: r.amount.to_raw(),
            })
            .collect();
        // Recipient `i` lands at `π(i)`, the order the intent's key derives,
        // alike for every member (R-24).
        let built = BuiltSpend::build(&tx_key, &recipients).map_err(DeriveError::Outputs)?;
        let output_masks: Zeroizing<Vec<[u8; 32]>> = Zeroizing::new(
            built
                .outputs()
                .iter()
                .map(|b| b.info.commitment_mask)
                .collect(),
        );
        let output_openings = built
            .outputs()
            .iter()
            .enumerate()
            .map(|(position, b)| {
                Commitment::from_canonical_mask(&b.info.commitment_mask, b.info.amount.to_raw())
                    .ok_or(DeriveError::Opening { position })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let blinds = seed
            .pseudo_out_blinds(records.len(), &output_masks)
            .map_err(DeriveError::Blinds)?;
        let mut inputs: Vec<InputContext> = records
            .into_iter()
            .zip(blinds)
            .enumerate()
            .map(
                |(position, ((output, secrets), pseudo_out_blind))| InputContext {
                    output,
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

/// The ledger's record of input `global_index` and the secrets `key`
/// re-derives from it, checked against the record's key image and leaf.
fn spendable(
    ledger: &impl GroupOutputs,
    key: &MultisigGroupKey<'_>,
    global_index: u64,
) -> Result<(GroupOutput, GroupSpendSecrets), DeriveError> {
    let output = ledger
        .output(global_index)
        .ok_or(DeriveError::MissingInput { global_index })?;
    let secrets =
        recover_group_spend(key, &output.source()).map_err(|source| DeriveError::Secrets {
            global_index,
            source,
        })?;
    if secrets.key_image() != output.key_image {
        return Err(DeriveError::KeyImage { global_index });
    }
    if secrets.leaf_point() != &output.leaf_point {
        return Err(DeriveError::Leaf { global_index });
    }
    let cm_x = PqcLeafScalar::from_commitment_point(&output.leaf_point)
        .ok_or(DeriveError::Leaf { global_index })?;
    // Consensus does not forbid two leaves with one `(O, C)` in a chunk;
    // `CM.x` names the spent one.
    if !output.path.leaf_chunk.iter().any(|leaf| {
        leaf.output_key.to_bytes() == output.output_key
            && leaf.commitment.to_bytes() == output.commitment
            && leaf.cm_x == cm_x.0
    }) {
        return Err(DeriveError::Path { global_index });
    }
    Ok((output.clone(), secrets))
}

/// The one tree every input's path is to: the intent's reference block's.
fn one_tree(
    intent: &ValidatedIntent,
    records: &[(GroupOutput, GroupSpendSecrets)],
) -> Result<TreeContext, DeriveError> {
    let reference = intent.intent().reference_block_hash;
    let mut tree = None;
    for (output, _) in records {
        let global_index = output.global_index;
        let this = output.path.tree;
        if *this.reference_block.as_bytes() != reference {
            return Err(DeriveError::Reference { global_index });
        }
        if *tree.get_or_insert(this) != this {
            return Err(DeriveError::Tree { global_index });
        }
    }
    Ok(tree.expect("a validated intent spends at least one input"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::Scalar;
    use rand_core::{OsRng, RngCore};
    use shekyl_address::multisig_address::{address_fingerprint, MultisigAddressPayload};
    use shekyl_address::{Network, ShekylAddress, MSG_SIGN_PK_LEN};
    use shekyl_crypto_pq::kem::{HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation};
    use shekyl_crypto_pq::label::SENTINEL_PLAINTEXT;
    use shekyl_crypto_pq::multisig_intent::IntentSeed;
    use shekyl_crypto_pq::multisig_output::{
        construct_multisig_output, open_multisig_entry, MultisigEntryView, MultisigMemberView,
        MultisigOutputData,
    };
    use shekyl_crypto_pq::output::recover_combined_ss;
    use shekyl_curve_tree::ChunkLeaf;
    use shekyl_fcmp::tree::key_image_generator;
    use shekyl_types::{BlockHash, CommitmentBytes, CurveTreeRoot, OneTimePubkey};
    use shekyl_units::AtomicUnits;

    use super::*;
    use crate::intent::{
        ChainStateFingerprint, IntentPayee, IntentRecipient, SpendIntent, SPEND_INTENT_VERSION,
    };
    use crate::invariants::LedgerView;

    const NETWORK: Network = Network::Testnet;
    const NET_ID: NetworkId = [0x4E; 16];
    const INPUTS: [(u64, u64); 3] = [(70, 400), (71, 300), (72, 500)];
    /// Each paid output's index in its own transaction.
    const PAID_OUTPUT_INDEX: u64 = 1;
    /// The group's members.
    const MEMBERS: u8 = 2;
    /// The intents' reference block, and the tree at it every path is to.
    const REFERENCE_HASH: [u8; 32] = [0x77; 32];
    const TREE_ROOT: [u8; 32] = [0x52; 32];
    /// The reference tree's layer count. The derivation reads it and the
    /// context checks it; these tests prove nothing under it.
    const TREE_LAYERS: u8 = 2;
    const OUTPUTS: [u64; 2] = [900, 250];
    const FEE: u64 = 50;
    const SIGNERS: [u8; 2] = [0, 1];
    /// How many random intents and ledgers the properties are checked on.
    const CASES: usize = 4;

    fn bytes32() -> [u8; 32] {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        b
    }

    fn point() -> [u8; 32] {
        (&Scalar::from_bytes_mod_order(bytes32()) * ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes()
    }

    fn kem_bytes(pk: &shekyl_crypto_pq::kem::HybridKemPublicKey) -> Vec<u8> {
        [pk.x25519.as_slice(), &pk.ml_kem].concat()
    }

    /// A 2-of-2 group on [`NETWORK`] with real keys, as its members'
    /// files hold them.
    struct Group {
        payload: MultisigAddressPayload,
        b: [u8; 32],
        group_sk: HybridKemSecretKey,
        member_sks: Vec<HybridKemSecretKey>,
    }

    impl Group {
        fn key(&self) -> MultisigGroupKey<'_> {
            MultisigGroupKey::new(&self.group_sk, &self.b)
        }
    }

    fn group() -> Group {
        let b = Scalar::from_bytes_mod_order(bytes32());
        let (group_pk, group_sk) = HybridX25519MlKem.keypair_generate().unwrap();
        let (member_pks, member_sks): (Vec<_>, Vec<_>) = (0..MEMBERS)
            .map(|_| HybridX25519MlKem.keypair_generate().unwrap())
            .unzip();
        let payload = MultisigAddressPayload::new(
            NETWORK,
            MEMBERS,
            MEMBERS,
            (&b * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
            point(),
            kem_bytes(&group_pk),
            member_pks.iter().map(kem_bytes).collect(),
        )
        .unwrap();
        Group {
            payload,
            b: b.to_bytes(),
            group_sk,
            member_sks,
        }
    }

    /// An intent paying a single-signer address and the group's change,
    /// spending [`INPUTS`], validated against the ledger that holds them.
    fn validated(g: &Group, seed: [u8; 32]) -> ValidatedIntent {
        let payload = &g.payload;
        let (kem, _) = HybridX25519MlKem.keypair_generate().unwrap();
        let single =
            ShekylAddress::new(NETWORK, point(), point(), [0; MSG_SIGN_PK_LEN], kem.ml_kem);
        let amounts: Vec<AtomicUnits> = INPUTS
            .iter()
            .map(|&(_, amount)| AtomicUnits::from_raw(amount))
            .collect();
        let indices: Vec<u64> = INPUTS.iter().map(|&(index, _)| index).collect();
        let reference_block_hash = REFERENCE_HASH;
        let fingerprint = ChainStateFingerprint {
            reference_block_hash,
            input_global_indices: indices.clone(),
            input_eligible_heights: vec![0; INPUTS.len()],
            input_amounts: amounts.clone(),
        }
        .compute();
        let intent = SpendIntent {
            version: SPEND_INTENT_VERSION,
            intent_id: bytes32(),
            address_fingerprint: address_fingerprint(payload),
            proposer_index: SIGNERS[0],
            signers: SIGNERS.to_vec(),
            responder_index: SIGNERS[1],
            created_at: 0,
            reference_block_height: 100,
            reference_block_hash,
            recipients: vec![
                IntentRecipient {
                    payee: IntentPayee::Single {
                        address: single.encode().unwrap(),
                        label_plaintext: SENTINEL_PLAINTEXT,
                    },
                    amount: AtomicUnits::from_raw(OUTPUTS[0]),
                },
                IntentRecipient {
                    payee: IntentPayee::Group {
                        address: payload.to_canonical_bytes(),
                    },
                    amount: AtomicUnits::from_raw(OUTPUTS[1]),
                },
            ],
            fee: AtomicUnits::from_raw(FEE),
            input_global_indices: indices,
            kem_randomness_seed: IntentSeed::new(&seed),
            chain_state_fingerprint: fingerprint,
        };
        ValidatedIntent::validate(
            intent,
            &LedgerView {
                our_address_fingerprint: &address_fingerprint(payload),
                n_total: MEMBERS,
                m_required: MEMBERS,
                network: NETWORK,
                chain_tip_height: 105,
                local_ref_block_hash: &reference_block_hash,
                local_chain_state_fingerprint: &fingerprint,
                input_amounts: &amounts,
                seen_seeds: &HashSet::new(),
            },
        )
        .unwrap()
    }

    /// One of [`INPUTS`] as the sender built it, and what every member's
    /// scan reads from it.
    struct Paid {
        global_index: u64,
        output: MultisigOutputData,
        committed_form: MultisigCommittedForm,
        key_image: KeyImage,
    }

    /// The group paid [`INPUTS`], each in its own transaction.
    fn pay(g: &Group) -> Vec<Paid> {
        INPUTS
            .iter()
            .map(|&(global_index, amount)| {
                let output = construct_multisig_output(
                    &TxKey::random().expect("the OS draws a key"),
                    &g.payload,
                    amount,
                    PAID_OUTPUT_INDEX,
                    &NET_ID,
                )
                .unwrap();
                let ss = recover_combined_ss(
                    &g.group_sk.x25519,
                    &g.group_sk.ml_kem,
                    &output.kem_ciphertext_x25519,
                    &output.kem_ciphertext_ml_kem,
                )
                .unwrap();
                let (own_x25519, own_ml_kem) = own_ciphertexts(&output, 0);
                let committed_form = open_multisig_entry(
                    &ss.0,
                    PAID_OUTPUT_INDEX,
                    &MultisigMemberView {
                        member_index: 0,
                        n_total: MEMBERS,
                        m_required: MEMBERS,
                        member_kem_secret: &g.member_sks[0],
                        network: &NET_ID,
                    },
                    &MultisigEntryView {
                        out_idx: u8::try_from(PAID_OUTPUT_INDEX).unwrap(),
                        n: MEMBERS,
                        own_x25519_ct: &own_x25519,
                        own_ml_kem_ct: &own_ml_kem,
                        enc_key_hashes: &output.enc_key_hashes,
                    },
                    &output.pqc_leaf.entry_bytes(),
                )
                .unwrap();
                let mut paid = Paid {
                    global_index,
                    output,
                    committed_form,
                    key_image: KeyImage::from_bytes([0; 32]),
                };
                paid.key_image =
                    recover_group_spend(&g.key(), &record(&paid, 0, &path(&[])).source())
                        .unwrap()
                        .key_image();
                paid
            })
            .collect()
    }

    fn own_ciphertexts(output: &MultisigOutputData, member: u8) -> ([u8; 32], Vec<u8>) {
        let (x25519, ml_kem) =
            output.member_kem_ciphertexts[usize::from(member)].split_at(X25519_KEM_CT_LEN);
        (x25519.try_into().unwrap(), ml_kem.to_vec())
    }

    /// The path every paid output's record holds: one leaf chunk holding
    /// all of them, in the tree at [`REFERENCE_HASH`].
    fn path(paid: &[Paid]) -> AssembledPath {
        AssembledPath {
            leaf_chunk: paid
                .iter()
                .map(|p| ChunkLeaf {
                    output_key: OneTimePubkey::from_bytes(p.output.output_key),
                    key_image_gen: key_image_generator(&p.output.output_key),
                    commitment: CommitmentBytes::from_bytes(p.output.commitment),
                    cm_x: PqcLeafScalar::from_commitment_point(&p.output.pqc_leaf.point)
                        .unwrap()
                        .0,
                })
                .collect(),
            c1_layers: vec![],
            c2_layers: vec![],
            tree: TreeContext {
                reference_block: BlockHash::from_bytes(REFERENCE_HASH),
                tree_root: CurveTreeRoot::from_bytes(TREE_ROOT),
                tree_depth: TREE_LAYERS,
            },
        }
    }

    /// `member`'s ledger record of `paid`, its path `path`.
    fn record(paid: &Paid, member: u8, path: &AssembledPath) -> GroupOutput {
        let (own_x25519_ct, own_ml_kem_ct) = own_ciphertexts(&paid.output, member);
        GroupOutput {
            global_index: paid.global_index,
            output_index: PAID_OUTPUT_INDEX,
            output_key: paid.output.output_key,
            commitment: paid.output.commitment,
            source_x25519_ct: paid.output.kem_ciphertext_x25519,
            source_ml_kem_ct: paid.output.kem_ciphertext_ml_kem.clone(),
            key_image: paid.key_image,
            leaf_point: paid.output.pqc_leaf.point,
            committed_form: paid.committed_form.clone(),
            own_x25519_ct,
            own_ml_kem_ct,
            path: path.clone(),
        }
    }

    /// A member's ledger, looked up by global index.
    struct Ledger(Vec<GroupOutput>);

    impl GroupOutputs for Ledger {
        fn output(&self, global_index: u64) -> Option<&GroupOutput> {
            self.0.iter().find(|out| out.global_index == global_index)
        }
    }

    /// `member`'s ledger of `paid`: its own ciphertexts differ from every
    /// other member's.
    fn ledger(paid: &[Paid], member: u8) -> Ledger {
        let path = path(paid);
        Ledger(paid.iter().map(|p| record(p, member, &path)).collect())
    }

    /// Two members holding one intent derive one spend from their own
    /// ledgers: the same outputs, `tx_extra` and base, the same inputs in
    /// the same order, the same blinds, seeds and openings. Only their own
    /// ciphertexts differ. A spend derived from another seed shares none
    /// of the derived values.
    #[test]
    fn members_holding_one_intent_derive_one_spend() {
        for _ in 0..CASES {
            let g = group();
            let intent = validated(&g, bytes32());
            let paid = pay(&g);
            let [a, b] = [0, 1].map(|member| {
                DerivedSpend::derive(intent.clone(), &ledger(&paid, member), &g.key(), NET_ID)
                    .unwrap()
            });
            assert_eq!(a.unsigned.outputs(), b.unsigned.outputs());
            assert_eq!(a.unsigned.extra(), b.unsigned.extra());
            assert_eq!(a.unsigned.base(), b.unsigned.base());
            assert!(a.output_openings == b.output_openings);
            assert_eq!(a.inputs.len(), INPUTS.len());
            for (x, y) in a.inputs.iter().zip(&b.inputs) {
                assert_eq!(x.key_image(), y.key_image());
                assert!(*x.pseudo_out_blind == *y.pseudo_out_blind);
                assert_eq!(rerandomized(x), rerandomized(y));
                assert_ne!(x.output.own_x25519_ct, y.output.own_x25519_ct);
            }
            assert!(a
                .inputs
                .windows(2)
                .all(|pair| pair[0].key_image().as_bytes() > pair[1].key_image().as_bytes()));

            let other = DerivedSpend::derive(
                validated(&g, bytes32()),
                &ledger(&paid, 0),
                &g.key(),
                NET_ID,
            )
            .unwrap();
            assert_ne!(other.unsigned.extra(), a.unsigned.extra());
            assert!(other
                .inputs
                .iter()
                .zip(&a.inputs)
                .all(|(x, y)| rerandomized(x).R() != rerandomized(y).R()));
        }
    }

    /// The message the tests' signing parameters sign; an input's
    /// rerandomization does not read it.
    const SIGNABLE: TxSignableHash = TxSignableHash::from_bytes([0xC3; 32]);

    /// Input `input`'s rerandomization, as its signing parameters build it.
    fn rerandomized(input: &InputContext) -> shekyl_fcmp::Input {
        input
            .params(SIGNABLE)
            .expect("a derived input's parameters decode")
            .rerandomized()
            .input()
    }

    /// Two inputs of one intent never share rerandomization blinds: inputs
    /// that did would link to each other. `R` is drawn from the blinds
    /// alone and `Õ − O = r_o·T`, so each differs between any two inputs.
    #[test]
    fn two_inputs_of_one_intent_never_share_blinds() {
        for _ in 0..CASES {
            let g = group();
            let derived = DerivedSpend::derive(
                validated(&g, bytes32()),
                &ledger(&pay(&g), 0),
                &g.key(),
                NET_ID,
            )
            .unwrap();
            assert_eq!(derived.inputs.len(), INPUTS.len());
            let blinds: Vec<_> = derived
                .inputs
                .iter()
                .map(|input| {
                    let params = input.params(SIGNABLE).unwrap();
                    let rerandomized = params.rerandomized().input();
                    (
                        rerandomized.R(),
                        rerandomized.O_tilde() - params.output().O(),
                    )
                })
                .collect();
            for (i, a) in blinds.iter().enumerate() {
                for b in &blinds[i + 1..] {
                    assert_ne!(a.0, b.0, "two inputs share r_i and r_r_i");
                    assert_ne!(a.1, b.1, "two inputs share r_o");
                }
            }
        }
    }

    /// Recipient `i` is the output at position `π(i)`, the order the
    /// intent's key derives (R-24), opened at its amount; the blinds
    /// balance the outputs' masks.
    #[test]
    fn recipient_i_is_the_output_at_its_position_in_the_intents_order() {
        let g = group();
        let seed = bytes32();
        let derived =
            DerivedSpend::derive(validated(&g, seed), &ledger(&pay(&g), 0), &g.key(), NET_ID)
                .unwrap();
        let order = TxKey::from_intent_seed(&IntentSeed::new(&seed)).output_order(OUTPUTS.len());
        let amounts: Vec<u64> = derived.output_openings.iter().map(|o| o.amount).collect();
        let expected: Vec<u64> = order.recipients().map(|r| OUTPUTS[r]).collect();
        assert_eq!(amounts, expected);
        assert_eq!(derived.unsigned.outputs().len(), OUTPUTS.len());
        let blinds: Scalar = derived
            .inputs
            .iter()
            .map(|i| Scalar::from_canonical_bytes(*i.pseudo_out_blind).unwrap())
            .sum();
        let masks: Scalar = derived.output_openings.iter().map(|o| o.mask).sum();
        assert_eq!(blinds, masks);
    }
}
