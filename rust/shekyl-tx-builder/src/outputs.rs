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
//! `tx_extra` carries the transaction public key, every output's hybrid
//! KEM ciphertext in one `0x06` field, every output's `0x07` leaf entry,
//! and, when an output pays a group, the `0x0D` member entries (CEN-I19),
//! written by the wire crate's own codec.

use shekyl_address::multisig_address::MultisigAddressPayload;
use shekyl_crypto_pq::multisig_output::{construct_multisig_output, MultisigOutputData};
use shekyl_crypto_pq::output::construct_output_with_label_plaintext;
use shekyl_crypto_pq::CryptoError;
use shekyl_network::NetworkId;
use shekyl_units::AtomicUnits;
use shekyl_wire::tx_extra::{self, KemCiphertext, MultisigEntry, TxExtraField};

use crate::types::OutputInfo;
use crate::TxBuilderError;

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

/// One output, built: what the transaction's prefix, base and `tx_extra`
/// carry for it.
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
/// transaction key `tx_key_secret`.
///
/// # Errors
///
/// The crypto crate's refusal: a payee key that is not a valid point, an
/// output index a group entry cannot name, or a member entry that does not
/// assemble.
pub fn build_output(
    tx_key_secret: &[u8; 32],
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
            tx_key_secret,
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
                construct_multisig_output(tx_key_secret, address, amount, output_index, network)?;
            let out_idx = u8::try_from(output_index).map_err(|_| {
                CryptoError::InvalidInput("a group output's index is one byte".into())
            })?;
            let entry = multisig_entry(&constructed, out_idx)?;
            Ok(built_output!(&constructed, amount, Some(entry)))
        }
    }
}

/// `tx_extra` for a spend whose outputs are `outputs`, in output order,
/// under the transaction public key `tx_pubkey`: the key, one `0x06` field
/// of every output's KEM ciphertext, the `0x07` leaf entries, and the
/// `0x0D` entries of the outputs that pay a group, if any.
///
/// # Errors
///
/// [`TxBuilderError::WireError`] if the wire codec refuses the fields.
pub fn build_tx_extra(
    tx_pubkey: &[u8; 32],
    outputs: &[BuiltOutput],
) -> Result<Vec<u8>, TxBuilderError> {
    let mut fields = vec![TxExtraField::PubKey(*tx_pubkey)];
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
    /// its `0x0D` entry, named by its own index, and the `tx_extra` the
    /// builder writes is the shape consensus admits (CEN-I19).
    #[test]
    fn a_spend_paying_a_group_carries_its_member_entries() {
        let tx_key = Scalar::random(&mut OsRng);
        let (single_pk, _) = HybridX25519MlKem.keypair_generate().unwrap();
        let label = sentinel_plaintext();
        let spend_key = ED25519_BASEPOINT_POINT.compress().to_bytes();
        let payee = Payee::Single {
            spend_key: &spend_key,
            view_x25519: &single_pk.x25519,
            ml_kem_ek: &single_pk.ml_kem,
            label_plaintext: &label,
        };
        let address = group(3, 2);
        let outputs = [
            build_output(&tx_key.to_bytes(), payee, 500, 0).unwrap(),
            build_output(
                &tx_key.to_bytes(),
                Payee::Group {
                    address: &address,
                    network: &NET,
                },
                700,
                1,
            )
            .unwrap(),
        ];
        assert!(outputs[0].multisig_entry.is_none());
        assert_eq!(outputs[1].multisig_entry.as_ref().unwrap().out_idx(), 1);

        let pubkey = (ED25519_BASEPOINT_POINT * tx_key).compress().to_bytes();
        let extra = build_tx_extra(&pubkey, &outputs).unwrap();
        let fields = parse(&extra).unwrap();
        check_tx_extra_shape(&fields, outputs.len(), ExtraSubject::General).unwrap();
        assert!(fields
            .iter()
            .any(|f| matches!(f, TxExtraField::PqcMultisig(entries) if entries.len() == 1)));
    }

    /// The same transaction key, payee and index build the same output:
    /// the property a multisig spend's members rely on to build one
    /// transaction apart.
    #[test]
    fn an_output_is_a_function_of_its_transaction_key() {
        let tx_key = Scalar::random(&mut OsRng).to_bytes();
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
