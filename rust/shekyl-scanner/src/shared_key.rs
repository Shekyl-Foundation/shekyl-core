// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Adapted from monero-oxide (shekyl-wallet), MIT license.
// All rights reserved.
// BSD-3-Clause

//! Shared key derivation for the Shekyl scanning pipeline.
//!
//! Implements the ECDH-based shared-secret derivation used to match outputs,
//! derive view tags, decrypt amounts, and XOR payment IDs.

use zeroize::{Zeroize, Zeroizing};

use curve25519_dalek::{Scalar, EdwardsPoint};

use shekyl_oxide::{
    io::write_varint,
    primitives::{Commitment, keccak256, keccak256_to_scalar},
    fcmp::EncryptedAmount,
    transaction::Input,
};

#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct SharedKeyDerivations {
    pub(crate) view_tag: u8,
    pub(crate) shared_key: Scalar,
}

impl SharedKeyDerivations {
    /// Compute the uniqueness bytes for a set of inputs (guaranteed-mode scanning).
    pub fn uniqueness(inputs: &[Input]) -> [u8; 32] {
        let mut u = b"uniqueness".to_vec();
        for input in inputs {
            match input {
                Input::Gen(height) => {
                    write_varint(height, &mut u)
                        .expect("write failed but <Vec as io::Write> doesn't fail");
                }
                Input::ToKey { key_image, .. } => u.extend(key_image.to_bytes()),
            }
        }
        keccak256(u)
    }

    /// Derive the view tag and shared key for an output.
    #[allow(clippy::needless_pass_by_value)]
    pub fn output_derivations(
        uniqueness: Option<[u8; 32]>,
        ecdh: Zeroizing<EdwardsPoint>,
        o: usize,
    ) -> Zeroizing<SharedKeyDerivations> {
        let mut output_derivation = Zeroizing::new(
            Zeroizing::new(
                Zeroizing::new(ecdh.mul_by_cofactor()).compress().to_bytes(),
            )
            .to_vec(),
        );

        {
            let output_derivation: &mut Vec<u8> = output_derivation.as_mut();
            write_varint(&o, output_derivation)
                .expect("write failed but <Vec as io::Write> doesn't fail");
        }

        let view_tag = keccak256([b"view_tag".as_slice(), &output_derivation].concat())[0];

        let output_derivation = if let Some(uniqueness) = uniqueness {
            Zeroizing::new([uniqueness.as_slice(), &output_derivation].concat())
        } else {
            output_derivation
        };

        Zeroizing::new(SharedKeyDerivations {
            view_tag,
            shared_key: keccak256_to_scalar(&output_derivation),
        })
    }

    /// Derive the payment ID XOR mask from ECDH.
    #[allow(clippy::needless_pass_by_value)]
    pub fn payment_id_xor(ecdh: Zeroizing<EdwardsPoint>) -> [u8; 8] {
        let output_derivation = Zeroizing::new(
            Zeroizing::new(
                Zeroizing::new(ecdh.mul_by_cofactor()).compress().to_bytes(),
            )
            .to_vec(),
        );

        let mut payment_id_xor = [0; 8];
        payment_id_xor
            .copy_from_slice(&keccak256([output_derivation.as_slice(), &[0x8d]].concat())[..8]);
        payment_id_xor
    }

    pub(crate) fn commitment_mask(&self) -> Scalar {
        let mut mask = b"commitment_mask".to_vec();
        mask.extend(self.shared_key.as_bytes());
        let res = keccak256_to_scalar(&mask);
        mask.zeroize();
        res
    }

    pub(crate) fn compact_amount_encryption(&self, amount: u64) -> [u8; 8] {
        let mut amount_mask = Zeroizing::new(b"amount".to_vec());
        amount_mask.extend(self.shared_key.to_bytes());
        let mut amount_mask = keccak256(&amount_mask);

        let mut amount_mask_8 = [0; 8];
        amount_mask_8.copy_from_slice(&amount_mask[..8]);
        amount_mask.zeroize();

        (amount ^ u64::from_le_bytes(amount_mask_8)).to_le_bytes()
    }

    pub(crate) fn decrypt(&self, enc_amount: &EncryptedAmount) -> Commitment {
        Commitment::new(
            self.commitment_mask(),
            u64::from_le_bytes(
                self.compact_amount_encryption(u64::from_le_bytes(enc_amount.amount)),
            ),
        )
    }
}
