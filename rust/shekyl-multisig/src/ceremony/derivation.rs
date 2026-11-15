// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a member signs from, derived from the intent alone (R-7, R-14,
//! `PQC_MULTISIG.md` §9.5): [`DerivedSpend`].
//!
//! A member builds the group's transaction from the validated intent and
//! its own ledger's records of the outputs the intent spends
//! ([`GroupOutput`]). The outputs, their `tx_extra` and the committed base
//! come from the builder every spend uses (`shekyl_tx_builder::outputs`),
//! under the transaction key the intent's seed derives; each input's
//! pseudo-out blind and rerandomization seed come from the same seed
//! ([`IntentSeed`]). Every member holding the intent derives the same
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
//! use shekyl_multisig::ceremony::{GroupOutput, InputContext};
//! use zeroize::Zeroizing;
//!
//! fn forge(output: GroupOutput, blind: [u8; 32], seed: [u8; 32]) -> InputContext {
//!     InputContext {
//!         output,
//!         pseudo_out_blind: Zeroizing::new(blind),
//!         rerandomization_seed: Zeroizing::new(seed),
//!     }
//! }
//! ```

use std::collections::HashMap;

use shekyl_crypto_pq::kem::X25519_KEM_CT_LEN;
use shekyl_crypto_pq::multisig::MultisigCommittedForm;
use shekyl_crypto_pq::multisig_intent::IntentSeed;
use shekyl_crypto_pq::multisig_output::MemberOwnCiphertext;
use shekyl_crypto_pq::CryptoError;
use shekyl_curve_primitives::Commitment;
use shekyl_fcmp::frost_sal::{
    FrostSalError, SalSigningParams, SpentOutput, RERANDOMIZATION_SEED_LEN,
};
use shekyl_network::NetworkId;
use shekyl_tx_builder::outputs::{build_output, BuiltOutput, Payee, RecipientKeys, SpendOutputs};
use shekyl_tx_builder::TxBuilderError;
use shekyl_types::{KeyImage, TxSignableHash};
use shekyl_wire::{CtBase, Output};
use zeroize::Zeroizing;

use crate::intent::{ResolvedPayee, ResolvedRecipient};
use crate::invariants::ValidatedIntent;

/// A spendable output paid to the group, as this member's ledger records
/// it: what its scan recovered, and its own `0x0D` ciphertexts.
pub struct GroupOutput {
    /// The output's global index, by which an intent names it.
    pub global_index: u64,
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
    /// The output's key image.
    pub key_image: KeyImage,
    /// The committed form the output's leaf binds (`0x02 ‖ n ‖ m ‖ h_1 … h_n`).
    pub committed_form: MultisigCommittedForm,
    /// This member's own `0x0D` X25519 ciphertext for the output.
    pub own_x25519_ct: [u8; X25519_KEM_CT_LEN],
    /// This member's own `0x0D` ML-KEM-768 ciphertext for the output.
    pub own_ml_kem_ct: Vec<u8>,
}

/// One spent input, as this member signs it: its ledger record, and the
/// pseudo-out blind and rerandomization seed the intent derives for it.
pub struct InputContext {
    output: GroupOutput,
    pseudo_out_blind: Zeroizing<[u8; 32]>,
    rerandomization_seed: Zeroizing<[u8; RERANDOMIZATION_SEED_LEN]>,
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
                spend_scalar: &self.output.spend_scalar,
                y_kem: &self.output.y_kem,
                commitment_mask: &self.output.commitment_mask,
            },
            &self.pseudo_out_blind,
            signable,
        )
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
    /// The prefix's outputs, in output order.
    #[must_use]
    pub fn outputs(&self) -> &[Output] {
        &self.outputs.outputs
    }

    /// `tx_extra`.
    #[must_use]
    pub fn extra(&self) -> &[u8] {
        &self.outputs.extra
    }

    /// The committed base: each output's commitment and encrypted fields.
    #[must_use]
    pub fn base(&self) -> &CtBase {
        &self.outputs.base
    }
}

/// Why a member cannot derive its spend from an intent.
#[derive(Debug, thiserror::Error)]
pub enum DeriveError {
    /// The ledger records one output twice.
    #[error("the ledger records output {global_index} twice")]
    DuplicateRecord { global_index: u64 },
    /// An input of the intent is not in this member's ledger.
    #[error("input {global_index} is not in this member's ledger")]
    MissingInput { global_index: u64 },
    /// The ledger handed records for outputs the intent does not spend.
    #[error("the intent spends {expected} outputs; the ledger handed {got}")]
    InputCount { expected: usize, got: usize },
    /// Two inputs have one key image: one output spent twice.
    #[error("two inputs have one key image")]
    DuplicateKeyImage,
    /// An output cannot be built to its recipient.
    #[error("output {index} does not build: {source}")]
    Output {
        index: usize,
        #[source]
        source: CryptoError,
    },
    /// The outputs' `tx_extra` does not encode.
    #[error("the outputs' tx_extra does not encode: {0}")]
    Extra(TxBuilderError),
    /// The pseudo-out blinds do not derive.
    #[error("the pseudo-out blinds do not derive: {0}")]
    Blinds(CryptoError),
}

/// A member's spend, derived from a validated intent and its own ledger:
/// the intent, the network its outputs are built for, the inputs in the
/// transaction's order (key images strictly descending, CEN-I5), the
/// unsigned spend, and each output's opening.
pub struct DerivedSpend {
    pub(super) network_id: NetworkId,
    pub(super) intent: ValidatedIntent,
    pub(super) inputs: Vec<InputContext>,
    pub(super) unsigned: UnsignedSpend,
    pub(super) output_openings: Vec<Commitment>,
}

impl DerivedSpend {
    /// Derive the spend `intent` describes on the chain whose id is
    /// `network_id`, from `spent`, this member's records of the outputs it
    /// spends, in any order.
    ///
    /// Recipient `i` is output `i`; each output is built to its resolved
    /// payee under the intent's transaction key. Input `j` of the intent
    /// takes the `j`-th derived pseudo-out blind and rerandomization seed;
    /// the last blind balances the outputs' masks. The inputs are then put
    /// in the transaction's order.
    ///
    /// # Errors
    ///
    /// The first [`DeriveError`] that holds.
    pub fn derive(
        intent: ValidatedIntent,
        spent: Vec<GroupOutput>,
        network_id: NetworkId,
    ) -> Result<Self, DeriveError> {
        let records = in_intent_order(&intent, spent)?;
        let seed = IntentSeed::new(&intent.intent().kem_randomness_seed);
        let tx_key = seed.tx_key();
        let built = intent
            .recipients()
            .iter()
            .zip(0u64..)
            .enumerate()
            .map(|(index, (recipient, output_index))| {
                build_recipient_output(&tx_key.secret, recipient, output_index, &network_id)
                    .map_err(|source| DeriveError::Output { index, source })
            })
            .collect::<Result<Vec<BuiltOutput>, _>>()?;
        let output_masks: Zeroizing<Vec<[u8; 32]>> =
            Zeroizing::new(built.iter().map(|b| b.info.commitment_mask).collect());
        let output_openings = built
            .iter()
            .enumerate()
            .map(|(index, b)| {
                Commitment::from_canonical_mask(&b.info.commitment_mask, b.info.amount.to_raw())
                    .ok_or(DeriveError::Output {
                        index,
                        source: CryptoError::InvalidKeyMaterial,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let blinds = seed
            .pseudo_out_blinds(records.len(), &output_masks)
            .map_err(DeriveError::Blinds)?;
        let mut inputs: Vec<InputContext> = records
            .into_iter()
            .zip(blinds)
            .enumerate()
            .map(|(position, (output, pseudo_out_blind))| InputContext {
                output,
                pseudo_out_blind,
                rerandomization_seed: seed.rerandomization_seed(position),
            })
            .collect();
        inputs.sort_unstable_by(|a, b| b.key_image().as_bytes().cmp(a.key_image().as_bytes()));
        if inputs
            .windows(2)
            .any(|pair| pair[0].key_image() == pair[1].key_image())
        {
            return Err(DeriveError::DuplicateKeyImage);
        }
        let unsigned = UnsignedSpend {
            outputs: SpendOutputs::of(&tx_key.public, &built).map_err(DeriveError::Extra)?,
        };
        Ok(Self {
            network_id,
            intent,
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

/// `spent`, one record per intent input, in the intent's input order.
fn in_intent_order(
    intent: &ValidatedIntent,
    spent: Vec<GroupOutput>,
) -> Result<Vec<GroupOutput>, DeriveError> {
    let wanted = &intent.intent().input_global_indices;
    let handed = spent.len();
    let mut by_index: HashMap<u64, GroupOutput> = HashMap::with_capacity(handed);
    for output in spent {
        let global_index = output.global_index;
        if by_index.insert(global_index, output).is_some() {
            return Err(DeriveError::DuplicateRecord { global_index });
        }
    }
    let records = wanted
        .iter()
        .map(|&global_index| {
            by_index
                .remove(&global_index)
                .ok_or(DeriveError::MissingInput { global_index })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !by_index.is_empty() {
        return Err(DeriveError::InputCount {
            expected: wanted.len(),
            got: handed,
        });
    }
    Ok(records)
}

/// The output paying `recipient` at `output_index`, under `tx_key_secret`.
fn build_recipient_output(
    tx_key_secret: &[u8; 32],
    recipient: &ResolvedRecipient,
    output_index: u64,
    network_id: &NetworkId,
) -> Result<BuiltOutput, CryptoError> {
    let amount = recipient.amount.to_raw();
    match &recipient.payee {
        ResolvedPayee::Single {
            address,
            label_plaintext,
        } => {
            let keys = RecipientKeys::of_address(address.as_address())?;
            build_output(
                tx_key_secret,
                keys.payee(label_plaintext),
                amount,
                output_index,
            )
        }
        ResolvedPayee::Group(address) => build_output(
            tx_key_secret,
            Payee::Group {
                address,
                network: network_id,
            },
            amount,
            output_index,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::Scalar;
    use rand_core::{OsRng, RngCore};
    use shekyl_address::multisig_address::{address_fingerprint, MultisigAddressPayload};
    use shekyl_address::{Network, ShekylAddress, MSG_SIGN_PK_LEN};
    use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};
    use shekyl_crypto_pq::label::SENTINEL_PLAINTEXT;
    use shekyl_crypto_pq::multisig::MultisigCommittedForm;
    use shekyl_units::AtomicUnits;

    use super::*;
    use crate::intent::{
        ChainStateFingerprint, IntentPayee, IntentRecipient, SpendIntent, SPEND_INTENT_VERSION,
    };
    use crate::invariants::LedgerView;

    const NETWORK: Network = Network::Testnet;
    const NET_ID: NetworkId = [0x4E; 16];
    const INPUTS: [(u64, u64); 3] = [(70, 400), (71, 300), (72, 500)];
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

    fn kem_bytes() -> Vec<u8> {
        let (pk, _) = HybridX25519MlKem.keypair_generate().unwrap();
        [pk.x25519.as_slice(), &pk.ml_kem].concat()
    }

    /// A 2-of-2 group on [`NETWORK`] with real KEM keys.
    fn group() -> MultisigAddressPayload {
        MultisigAddressPayload::new(
            NETWORK,
            2,
            2,
            point(),
            point(),
            kem_bytes(),
            vec![kem_bytes(), kem_bytes()],
        )
        .unwrap()
    }

    /// An intent paying a single-signer address and the group's change,
    /// spending [`INPUTS`], validated against the ledger that holds them.
    fn validated(seed: [u8; 32]) -> ValidatedIntent {
        let payload = group();
        let (kem, _) = HybridX25519MlKem.keypair_generate().unwrap();
        let single =
            ShekylAddress::new(NETWORK, point(), point(), [0; MSG_SIGN_PK_LEN], kem.ml_kem);
        let amounts: Vec<AtomicUnits> = INPUTS
            .iter()
            .map(|&(_, amount)| AtomicUnits::from_raw(amount))
            .collect();
        let indices: Vec<u64> = INPUTS.iter().map(|&(index, _)| index).collect();
        let reference_block_hash = bytes32();
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
            address_fingerprint: address_fingerprint(&payload),
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
            kem_randomness_seed: seed,
            chain_state_fingerprint: fingerprint,
        };
        ValidatedIntent::validate(
            intent,
            &LedgerView {
                our_address_fingerprint: &address_fingerprint(&payload),
                n_total: 2,
                m_required: 2,
                network: NETWORK,
                chain_tip_height: 105,
                local_ref_block_hash: &reference_block_hash,
                local_chain_state_fingerprint: &fingerprint,
                input_amounts: &amounts,
                seen_kem_seeds: &HashSet::new(),
            },
        )
        .unwrap()
    }

    /// The group's records of [`INPUTS`], shared by every member: the
    /// derivation reads them, and checks none of them.
    struct SharedRecord {
        global_index: u64,
        output_key: [u8; 32],
        commitment: [u8; 32],
        secrets: [[u8; 32]; 3],
        key_image: [u8; 32],
        key_hashes: [[u8; 32]; 2],
    }

    fn shared_records() -> Vec<SharedRecord> {
        INPUTS
            .iter()
            .map(|&(global_index, _)| SharedRecord {
                global_index,
                output_key: point(),
                commitment: point(),
                secrets: [bytes32(), bytes32(), bytes32()],
                key_image: bytes32(),
                key_hashes: [bytes32(), bytes32()],
            })
            .collect()
    }

    /// A member's ledger: the shared records with its own ciphertexts,
    /// which differ from every other member's.
    fn ledger(shared: &[SharedRecord]) -> Vec<GroupOutput> {
        shared
            .iter()
            .map(|r| GroupOutput {
                global_index: r.global_index,
                output_key: r.output_key,
                commitment: r.commitment,
                spend_scalar: Zeroizing::new(r.secrets[0]),
                y_kem: Zeroizing::new(r.secrets[1]),
                commitment_mask: Zeroizing::new(r.secrets[2]),
                key_image: KeyImage::from_bytes(r.key_image),
                committed_form: MultisigCommittedForm::new(2, r.key_hashes.to_vec()).unwrap(),
                own_x25519_ct: bytes32(),
                own_ml_kem_ct: bytes32().to_vec(),
            })
            .collect()
    }

    /// Two members holding one intent derive one spend from their own
    /// ledgers: the same outputs, `tx_extra` and base, the same inputs in
    /// the same order, the same blinds, seeds and openings. Only their own
    /// ciphertexts differ. A spend derived from another seed shares none
    /// of the derived values.
    #[test]
    fn members_holding_one_intent_derive_one_spend() {
        for _ in 0..CASES {
            let seed = bytes32();
            let intent = validated(seed);
            let shared = shared_records();
            let [a, b] = [0, 1]
                .map(|_| DerivedSpend::derive(intent.clone(), ledger(&shared), NET_ID).unwrap());
            assert_eq!(a.unsigned.outputs(), b.unsigned.outputs());
            assert_eq!(a.unsigned.extra(), b.unsigned.extra());
            assert_eq!(a.unsigned.base(), b.unsigned.base());
            assert!(a.output_openings == b.output_openings);
            assert_eq!(a.inputs.len(), INPUTS.len());
            for (x, y) in a.inputs.iter().zip(&b.inputs) {
                assert_eq!(x.key_image(), y.key_image());
                assert!(*x.pseudo_out_blind == *y.pseudo_out_blind);
                assert!(*x.rerandomization_seed == *y.rerandomization_seed);
                assert_ne!(x.output.own_x25519_ct, y.output.own_x25519_ct);
            }
            assert!(a
                .inputs
                .windows(2)
                .all(|pair| pair[0].key_image().as_bytes() > pair[1].key_image().as_bytes()));

            let other =
                DerivedSpend::derive(validated(bytes32()), ledger(&shared), NET_ID).unwrap();
            assert_ne!(other.unsigned.extra(), a.unsigned.extra());
            assert!(other
                .inputs
                .iter()
                .zip(&a.inputs)
                .all(|(x, y)| *x.rerandomization_seed != *y.rerandomization_seed));
        }
    }

    /// Recipient `i` is output `i`, opened at its amount; the blinds
    /// balance the outputs' masks.
    #[test]
    fn the_outputs_are_the_recipients_in_order() {
        let derived =
            DerivedSpend::derive(validated(bytes32()), ledger(&shared_records()), NET_ID).unwrap();
        let amounts: Vec<u64> = derived.output_openings.iter().map(|o| o.amount).collect();
        assert_eq!(amounts, OUTPUTS);
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
