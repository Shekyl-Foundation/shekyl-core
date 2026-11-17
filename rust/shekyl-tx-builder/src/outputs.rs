// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A spend's outputs and the `tx_extra` that carries them: the one builder
//! every spend path uses (the transfer, the drain, the bond post and the
//! emission claim in the wallet, and the multisig spend).
//!
//! Output construction is deterministic given the transaction key: the
//! key, the payee and the output's index fix its one-time key, its KEM
//! ciphertexts, its commitment mask and its encrypted fields (the
//! deterministic encapsulation, `PQC_MULTISIG.md` §7.3). A solo spend draws
//! its key from the OS; a multisig spend derives it from the intent. Both
//! then run this code, so a group's transaction is built exactly as a solo
//! one is.
//!
//! **Order (R-24).** A caller hands [`BuiltSpend::build`] its recipients
//! and never a position: the builder places recipient `i` at position
//! `π(i)`, the order the transaction key derives
//! ([`TxKey::output_order`]), and builds the output at position `p` with
//! derivation index `p`. Nothing else in this crate builds an output, so
//! no wallet-built transaction says by its layout which output is the
//! change. A caller that needs one recipient's output asks for it by
//! recipient ([`BuiltSpend::output_for`]).
//!
//! ```compile_fail,E0603
//! use shekyl_crypto_pq::TxKey;
//! use shekyl_tx_builder::outputs::{build_output, BuiltOutput, Payee};
//!
//! // An output at a position of the caller's choosing.
//! fn place(key: &TxKey, payee: Payee<'_>) -> BuiltOutput {
//!     build_output(key, payee, 1, 0).unwrap()
//! }
//! ```
//!
//! `tx_extra` carries the transaction public key, every output's hybrid
//! KEM ciphertext in one `0x06` field, every output's `0x07` leaf entry,
//! and, when an output pays a group, the `0x0D` member entries (CEN-I19),
//! written by the wire crate's own codec.

use std::borrow::Cow;

use shekyl_address::multisig_address::MultisigAddressPayload;
use shekyl_address::ShekylAddress;
use shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk;
use shekyl_crypto_pq::multisig_output::{construct_multisig_output, MultisigOutputData};
use shekyl_crypto_pq::output::construct_output_with_label_plaintext;
use shekyl_crypto_pq::output_mask::OutputMask;
use shekyl_crypto_pq::output_order::OutputOrder;
use shekyl_crypto_pq::{CryptoError, TxKey};
use shekyl_network::NetworkId;
use shekyl_units::AtomicUnits;
use shekyl_wire::tx_extra::{self, KemCiphertext, MultisigEntry, TxExtraField};
use shekyl_wire::{CtBase, Output};

use crate::types::OutputInfo;
use crate::wire::committed_base;
use crate::{TxBuilderError, MAX_OUTPUTS};

/// Who an output pays.
#[derive(Clone, Copy)]
pub enum Payee<'a> {
    /// A single-signer address.
    Single {
        /// The address's spend key (a compressed point).
        spend_key: &'a [u8; 32],
        /// The address's view key as an X25519 public key.
        view_x25519: &'a [u8; 32],
        /// The address's ML-KEM-768 encapsulation key.
        ml_kem_ek: &'a [u8],
        /// The 8-byte block the output's label encrypts: a payment
        /// request's echo, or the sentinel.
        label_plaintext: &'a [u8; 8],
    },
    /// A multisig group, on the chain whose id is `network` (its members'
    /// key hashes bind it).
    Group {
        /// The group's address.
        address: &'a MultisigAddressPayload,
        /// The chain's network id.
        network: &'a NetworkId,
    },
}

/// A single-signer recipient's keys as its output is built to them.
///
/// An address carries its **Edwards** view key; the KEM's X25519 half
/// encapsulates to `montgomery(view_pk)`, the parameter-free birational
/// map the recipient's scanner inverts by using its view scalar as the
/// Montgomery secret. Passing the Edwards bytes straight through would
/// encapsulate to a wrong point: the daemon still accepts the transaction
/// (the sender's own proofs re-derive consistently), but the recipient's
/// decapsulation fails silently and the output is lost. This type is the
/// one place a spend maps the key, so no path can skip it.
pub struct RecipientKeys<'a> {
    spend_key: [u8; 32],
    view_x25519: [u8; 32],
    ml_kem_ek: Cow<'a, [u8]>,
}

impl<'a> RecipientKeys<'a> {
    /// A recipient with spend key `spend_key`, Edwards view key `view_key`
    /// and ML-KEM-768 encapsulation key `ml_kem_ek`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKeyMaterial`] for a view key that is not a
    /// canonical point other than the identity.
    pub fn from_edwards(
        spend_key: [u8; 32],
        view_key: &[u8; 32],
        ml_kem_ek: Cow<'a, [u8]>,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            spend_key,
            view_x25519: ed25519_pk_to_x25519_pk(view_key)?,
            ml_kem_ek,
        })
    }

    /// The keys `address` names.
    ///
    /// # Errors
    ///
    /// As [`Self::from_edwards`].
    pub fn of_address(address: &'a ShekylAddress) -> Result<Self, CryptoError> {
        Self::from_edwards(
            address.spend_key,
            &address.view_key,
            Cow::Borrowed(&address.ml_kem_encap_key),
        )
    }

    /// The recipient's spend key.
    #[must_use]
    pub fn spend_key(&self) -> &[u8; 32] {
        &self.spend_key
    }

    /// The recipient's view key, mapped to X25519.
    #[must_use]
    pub fn view_x25519(&self) -> &[u8; 32] {
        &self.view_x25519
    }

    /// The recipient's ML-KEM-768 encapsulation key.
    #[must_use]
    pub fn ml_kem_ek(&self) -> &[u8] {
        &self.ml_kem_ek
    }

    /// This recipient as the payee of an output whose label encrypts
    /// `label_plaintext`.
    #[must_use]
    pub fn payee<'p>(&'p self, label_plaintext: &'p [u8; 8]) -> Payee<'p> {
        Payee::Single {
            spend_key: &self.spend_key,
            view_x25519: &self.view_x25519,
            ml_kem_ek: &self.ml_kem_ek,
            label_plaintext,
        }
    }
}

/// One output, built: what the transaction's prefix, base and `tx_extra`
/// carry for it. Made only by [`BuiltSpend::build`].
#[derive(Clone)]
pub struct BuiltOutput {
    /// What the signer needs: the one-time key, the amount, the commitment
    /// mask and the encrypted fields.
    pub info: OutputInfo,
    /// The one-time output key `O`.
    pub output_key: [u8; 32],
    /// The output's commitment `C = z·G + amount·H`.
    pub commitment: [u8; 32],
    /// The output's view tag.
    pub view_tag: u8,
    /// The output's hybrid KEM ciphertext (`X25519 ‖ ML-KEM-768`).
    pub kem_blob: Vec<u8>,
    /// The output's `0x07` entry, `CM ‖ record`.
    pub pqc_leaf: [u8; 64],
    /// The output's `0x0D` entry, when it pays a group.
    multisig_entry: Option<MultisigEntry>,
    /// The output's commitment mask `z`, as the scalar it was derived as.
    mask: OutputMask,
}

impl BuiltOutput {
    /// The output's commitment mask `z`, as the scalar it was derived as:
    /// its opening at the output's amount cannot fail.
    #[must_use]
    pub fn commitment_mask(&self) -> &OutputMask {
        &self.mask
    }
}

/// A [`BuiltOutput`] from a constructed output of either kind: the two
/// constructors' outputs share every field this reads.
macro_rules! built_output {
    ($constructed:expr, $amount:expr, $multisig_entry:expr) => {{
        let constructed = $constructed;
        BuiltOutput {
            info: OutputInfo {
                dest_key: constructed.output_key,
                amount: AtomicUnits::from_raw($amount),
                commitment_mask: constructed.z,
                enc_amount: constructed.enc_amount_wire(),
                enc_label: constructed.enc_label_wire(),
            },
            output_key: constructed.output_key,
            commitment: constructed.commitment,
            view_tag: constructed.view_tag_prefilter,
            kem_blob: [
                constructed.kem_ciphertext_x25519.as_slice(),
                &constructed.kem_ciphertext_ml_kem,
            ]
            .concat(),
            pqc_leaf: constructed.pqc_leaf.entry_bytes(),
            multisig_entry: $multisig_entry,
            mask: constructed.commitment_mask(),
        }
    }};
}

/// The `0x0D` entry of a group output at `out_idx`.
fn multisig_entry(
    constructed: &MultisigOutputData,
    out_idx: u8,
) -> Result<MultisigEntry, CryptoError> {
    let member_cts = constructed
        .member_kem_ciphertexts
        .iter()
        .map(|ct| {
            ct.as_slice()
                .try_into()
                .map(KemCiphertext::from_bytes)
                .map_err(|_| CryptoError::InvalidKeyMaterial)
        })
        .collect::<Result<_, _>>()?;
    MultisigEntry::new(out_idx, member_cts, constructed.enc_key_hashes.clone())
        .map_err(|e| CryptoError::InvalidInput(e.to_string()))
}

/// Build the output at `output_index` paying `amount` to `payee`, under the
/// transaction key `tx_key`. Private: the index is a position, and only
/// [`BuiltSpend::build`] chooses positions.
///
/// # Errors
///
/// The crypto crate's refusal: a payee key that is not a valid point, an
/// output index a group entry cannot name, or a member entry that does not
/// assemble.
fn build_output(
    tx_key: &TxKey,
    payee: Payee<'_>,
    amount: u64,
    output_index: u64,
) -> Result<BuiltOutput, CryptoError> {
    match payee {
        Payee::Single {
            spend_key,
            view_x25519,
            ml_kem_ek,
            label_plaintext,
        } => construct_output_with_label_plaintext(
            tx_key,
            view_x25519,
            ml_kem_ek,
            spend_key,
            amount,
            output_index,
            label_plaintext,
        )
        .map(|constructed| built_output!(&constructed, amount, None)),
        Payee::Group { address, network } => {
            let constructed =
                construct_multisig_output(tx_key, address, amount, output_index, network)?;
            let out_idx = u8::try_from(output_index).map_err(|_| {
                CryptoError::InvalidInput("a group output's index is one byte".into())
            })?;
            let entry = multisig_entry(&constructed, out_idx)?;
            Ok(built_output!(&constructed, amount, Some(entry)))
        }
    }
}

/// `tx_extra` for a spend whose outputs are `outputs`, in output order,
/// built under `tx_key`: its public key `R`, one `0x06` field
/// of every output's KEM ciphertext, the `0x07` leaf entries, and the
/// `0x0D` entries of the outputs that pay a group, if any.
///
/// # Errors
///
/// [`TxBuilderError::WireError`] if the wire codec refuses the fields.
fn build_tx_extra(tx_key: &TxKey, outputs: &[BuiltOutput]) -> Result<Vec<u8>, TxBuilderError> {
    let mut fields = vec![TxExtraField::PubKey(tx_key.public_bytes())];
    if !outputs.is_empty() {
        fields.push(TxExtraField::PqcKemCiphertext(
            outputs
                .iter()
                .flat_map(|o| o.kem_blob.iter().copied())
                .collect(),
        ));
        fields.push(TxExtraField::PqcLeafEntries(
            outputs.iter().flat_map(|o| o.pqc_leaf).collect(),
        ));
    }
    let entries: Vec<MultisigEntry> = outputs
        .iter()
        .filter_map(|o| o.multisig_entry.clone())
        .collect();
    if !entries.is_empty() {
        fields.push(TxExtraField::PqcMultisig(entries));
    }
    tx_extra::serialize(&fields).map_err(|e| TxBuilderError::WireError(e.to_string()))
}

/// One output a spend pays: who, and how much.
#[derive(Clone, Copy)]
pub struct Recipient<'a> {
    /// Who the output pays.
    pub payee: Payee<'a>,
    /// What it pays, in atomic units.
    pub amount: u64,
}

/// Why a spend's outputs were not built ([`BuiltSpend::build`]).
#[derive(Debug, thiserror::Error)]
pub enum BuildSpendError {
    /// A spend pays at least one output.
    #[error("a spend pays no output")]
    NoOutputs,
    /// More recipients than a transaction carries outputs.
    #[error("{count} outputs exceed the transaction's {MAX_OUTPUTS}")]
    TooManyOutputs {
        /// The recipients handed in.
        count: usize,
    },
    /// The crypto crate refused recipient `recipient`'s output.
    #[error("recipient {recipient}'s output: {source}")]
    Output {
        /// The recipient's place in the list handed in.
        recipient: usize,
        /// The crypto crate's refusal.
        source: CryptoError,
    },
    /// The wire codec refused `tx_extra`.
    #[error("tx_extra: {0}")]
    Extra(TxBuilderError),
}

/// A spend's outputs, built and placed in the order its transaction key
/// derives (module docs): what the signer takes, and the transaction's
/// outputs, `tx_extra` and committed base.
#[derive(Clone)]
pub struct BuiltSpend {
    /// The outputs in position order.
    outputs: Vec<BuiltOutput>,
    /// Which recipient each position holds.
    order: OutputOrder,
    /// The outputs as the transaction carries them.
    wire: SpendOutputs,
}

impl BuiltSpend {
    /// Build an output for each of `recipients` under `tx_key`, recipient
    /// `i` at position `π(i)` ([`TxKey::output_order`]) with derivation
    /// index `π(i)`, and the `tx_extra` that carries them.
    ///
    /// # Errors
    ///
    /// [`BuildSpendError`]: no recipient or more than [`MAX_OUTPUTS`], a
    /// recipient's output the crypto crate refuses, or `tx_extra` the wire
    /// codec refuses.
    pub fn build(tx_key: &TxKey, recipients: &[Recipient<'_>]) -> Result<Self, BuildSpendError> {
        let count = recipients.len();
        if count == 0 {
            return Err(BuildSpendError::NoOutputs);
        }
        if count > MAX_OUTPUTS {
            return Err(BuildSpendError::TooManyOutputs { count });
        }
        let order = tx_key.output_order(count);
        let outputs = order
            .recipients()
            .zip(0u64..)
            .map(|(recipient, position)| {
                let Recipient { payee, amount } = recipients[recipient];
                build_output(tx_key, payee, amount, position)
                    .map_err(|source| BuildSpendError::Output { recipient, source })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let wire = SpendOutputs::of(tx_key, &outputs).map_err(BuildSpendError::Extra)?;
        Ok(Self {
            outputs,
            order,
            wire,
        })
    }

    /// The outputs in position order: the first is the transaction's
    /// output 0.
    #[must_use]
    pub fn outputs(&self) -> &[BuiltOutput] {
        &self.outputs
    }

    /// The position of `recipient`'s output, or `None` for a recipient the
    /// spend does not pay.
    #[must_use]
    pub fn position_of(&self, recipient: usize) -> Option<usize> {
        self.order.position_of(recipient)
    }

    /// `recipient`'s output, or `None` for a recipient the spend does not
    /// pay.
    #[must_use]
    pub fn output_for(&self, recipient: usize) -> Option<&BuiltOutput> {
        self.position_of(recipient).map(|p| &self.outputs[p])
    }

    /// The outputs as the transaction carries them.
    #[must_use]
    pub fn wire(&self) -> &SpendOutputs {
        &self.wire
    }

    /// `tx_extra`: the transaction public key and every output's PQC
    /// fields, in position order.
    #[must_use]
    pub fn extra(&self) -> &[u8] {
        &self.wire.extra
    }
}

/// A confidential spend's outputs as its transaction carries them: the
/// prefix's outputs, `tx_extra`, and the committed base, in position
/// order. A spend whose transaction is assembled in phases (a multisig
/// spend's) takes its outputs from here; the one-shot encoder writes the
/// same base through the same mapping. Made only by [`BuiltSpend::build`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendOutputs {
    outputs: Vec<Output>,
    extra: Vec<u8>,
    base: CtBase,
}

impl SpendOutputs {
    /// The outputs `built`, in position order, built under `tx_key`.
    fn of(tx_key: &TxKey, built: &[BuiltOutput]) -> Result<Self, TxBuilderError> {
        let enc_amounts: Vec<_> = built.iter().map(|b| b.info.enc_amount).collect();
        let enc_labels: Vec<_> = built.iter().map(|b| b.info.enc_label).collect();
        Ok(Self {
            outputs: built
                .iter()
                .map(|b| Output::confidential(b.output_key, b.view_tag))
                .collect(),
            extra: build_tx_extra(tx_key, built)?,
            base: committed_base(
                &enc_amounts,
                &enc_labels,
                built.iter().map(|b| b.commitment).collect(),
            ),
        })
    }

    /// The prefix's outputs, in position order.
    #[must_use]
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// `tx_extra`: the transaction public key and every output's PQC
    /// fields.
    #[must_use]
    pub fn extra(&self) -> &[u8] {
        &self.extra
    }

    /// The committed base: each output's commitment and encrypted fields.
    #[must_use]
    pub fn base(&self) -> &CtBase {
        &self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::Scalar;
    use rand::rngs::OsRng;
    use shekyl_address::Network;
    use shekyl_crypto_pq::kem::{HybridKemPublicKey, HybridX25519MlKem, KeyEncapsulation};
    use shekyl_crypto_pq::label::sentinel_plaintext;
    use shekyl_wire::tx_extra::{check_tx_extra_shape, parse, ExtraSubject};

    const NET: NetworkId = [0x4E; 16];

    fn kem_bytes(pk: &HybridKemPublicKey) -> Vec<u8> {
        [pk.x25519.as_slice(), &pk.ml_kem].concat()
    }

    fn group(n: u8, m: u8) -> MultisigAddressPayload {
        let kem = HybridX25519MlKem;
        let point = |base: curve25519_dalek::EdwardsPoint| {
            (base * Scalar::random(&mut OsRng)).compress().to_bytes()
        };
        MultisigAddressPayload::new(
            Network::Testnet,
            n,
            m,
            point(ED25519_BASEPOINT_POINT),
            point(*shekyl_curve_generators::T),
            kem_bytes(&kem.keypair_generate().unwrap().0),
            (0..n)
                .map(|_| kem_bytes(&kem.keypair_generate().unwrap().0))
                .collect(),
        )
        .unwrap()
    }

    /// A spend paying one address and one group: the group output carries
    /// its `0x0D` entry, named by the position it landed at, and the
    /// `tx_extra` the builder writes is the shape consensus admits
    /// (CEN-I19).
    #[test]
    fn a_spend_paying_a_group_carries_its_member_entries() {
        let tx_key = TxKey::random().unwrap();
        let (single_pk, _) = HybridX25519MlKem.keypair_generate().unwrap();
        let label = sentinel_plaintext();
        let spend_key = ED25519_BASEPOINT_POINT.compress().to_bytes();
        let address = group(3, 2);
        let spend = BuiltSpend::build(
            &tx_key,
            &[
                Recipient {
                    payee: Payee::Single {
                        spend_key: &spend_key,
                        view_x25519: &single_pk.x25519,
                        ml_kem_ek: &single_pk.ml_kem,
                        label_plaintext: &label,
                    },
                    amount: 500,
                },
                Recipient {
                    payee: Payee::Group {
                        address: &address,
                        network: &NET,
                    },
                    amount: 700,
                },
            ],
        )
        .unwrap();
        let group_position = spend.position_of(1).unwrap();
        assert!(spend.output_for(0).unwrap().multisig_entry.is_none());
        assert_eq!(
            usize::from(
                spend
                    .output_for(1)
                    .unwrap()
                    .multisig_entry
                    .as_ref()
                    .unwrap()
                    .out_idx()
            ),
            group_position
        );

        let fields = parse(spend.extra()).unwrap();
        check_tx_extra_shape(&fields, spend.outputs().len(), ExtraSubject::General).unwrap();
        assert!(fields
            .iter()
            .any(|f| matches!(f, TxExtraField::PqcMultisig(entries) if entries.len() == 1)));
    }

    /// The outputs as the transaction carries them: each prefix output is
    /// confidential under its built key and tag, the base holds each
    /// output's commitment and encrypted fields in position order, and
    /// `tx_extra` is the builder's.
    #[test]
    fn a_spends_outputs_are_its_built_outputs_in_order() {
        let tx_key = TxKey::random().unwrap();
        let address = group(3, 2);
        let payee = Payee::Group {
            address: &address,
            network: &NET,
        };
        let recipients = [400, 600, 800].map(|amount| Recipient { payee, amount });
        let spend = BuiltSpend::build(&tx_key, &recipients).unwrap();
        let wire = spend.wire();
        for ((output, built), i) in wire.outputs().iter().zip(spend.outputs()).zip(0..) {
            assert_eq!(
                output,
                &Output::confidential(built.output_key, built.view_tag)
            );
            assert_eq!(wire.base().commitments[i], built.commitment);
            assert_eq!(wire.base().enc_amounts[i], built.info.enc_amount.to_bytes());
            assert_eq!(wire.base().enc_labels[i], built.info.enc_label.to_bytes());
        }
        assert_eq!(wire.outputs().len(), recipients.len());
        assert_eq!(
            wire.extra(),
            build_tx_extra(&tx_key, spend.outputs()).unwrap()
        );
    }

    /// Recipient `i` sits at position `π(i)`, the key's order, and is built
    /// with derivation index `π(i)`: the output a caller asks for by
    /// recipient is the one the order puts there, and building it alone at
    /// that index gives the same bytes.
    #[test]
    fn recipient_i_is_the_output_at_its_position_in_the_keys_order() {
        let tx_key = TxKey::random().unwrap();
        let address = group(3, 2);
        let payee = Payee::Group {
            address: &address,
            network: &NET,
        };
        let recipients: Vec<Recipient<'_>> = (1..=5)
            .map(|n| Recipient {
                payee,
                amount: 100 * n,
            })
            .collect();
        let spend = BuiltSpend::build(&tx_key, &recipients).unwrap();
        let order = tx_key.output_order(recipients.len());
        for (recipient, r) in recipients.iter().enumerate() {
            let position = order.position_of(recipient).unwrap();
            assert_eq!(spend.position_of(recipient), Some(position));
            let built = spend.output_for(recipient).unwrap();
            assert_eq!(built.info.amount.to_raw(), r.amount);
            let alone = build_output(&tx_key, payee, r.amount, position as u64).unwrap();
            assert_eq!(built.output_key, alone.output_key);
            assert_eq!(built.commitment, alone.commitment);
        }
        assert_eq!(spend.position_of(recipients.len()), None);
    }

    /// No recipient, or more than a transaction carries, builds nothing.
    #[test]
    fn a_spend_pays_one_to_max_outputs() {
        let tx_key = TxKey::random().unwrap();
        assert!(matches!(
            BuiltSpend::build(&tx_key, &[]),
            Err(BuildSpendError::NoOutputs)
        ));
        let address = group(3, 2);
        let payee = Payee::Group {
            address: &address,
            network: &NET,
        };
        let over = vec![Recipient { payee, amount: 1 }; MAX_OUTPUTS + 1];
        assert!(matches!(
            BuiltSpend::build(&tx_key, &over),
            Err(BuildSpendError::TooManyOutputs { count }) if count == MAX_OUTPUTS + 1
        ));
    }

    /// The same transaction key, payee and index build the same output:
    /// the property a multisig spend's members rely on to build one
    /// transaction apart.
    #[test]
    fn an_output_is_a_function_of_its_transaction_key() {
        let tx_key = TxKey::random().unwrap();
        let address = group(3, 2);
        let payee = Payee::Group {
            address: &address,
            network: &NET,
        };
        let [a, b] = [0, 1].map(|_| build_output(&tx_key, payee, 900, 0).unwrap());
        assert_eq!(a.output_key, b.output_key);
        assert_eq!(a.commitment, b.commitment);
        assert_eq!(a.kem_blob, b.kem_blob);
        assert_eq!(a.pqc_leaf, b.pqc_leaf);
    }
}
