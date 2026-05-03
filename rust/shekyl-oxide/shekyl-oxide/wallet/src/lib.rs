#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

use std_shims::vec::Vec;

use zeroize::{Zeroize, Zeroizing};

use curve25519_dalek::{Scalar, EdwardsPoint};

use shekyl_oxide::{
  io::write_varint,
  primitives::{Commitment, keccak256, keccak256_to_scalar},
  fcmp::EncryptedAmount,
  transaction::Input,
};

pub use shekyl_oxide::*;

pub use shekyl_rpc as rpc;

pub use shekyl_address as address;

mod view_pair;
pub use view_pair::{ViewPairError, ViewPair, GuaranteedViewPair};

/// Structures and functionality for working with transactions' extra fields.
pub mod extra;
pub(crate) use extra::{PaymentId, Extra};

pub(crate) mod output;
pub use output::WalletOutput;

mod scan;
pub use scan::{Timelocked, ScanError, Scanner, GuaranteedScanner};

mod decoys;
pub use decoys::OutputWithDecoys;

/// Structs and functionality for sending transactions.
pub mod send;

#[cfg(test)]
mod tests;

#[derive(Clone, PartialEq, Eq, Zeroize)]
struct SharedKeyDerivations {
  // Hs("view_tag" || 8Ra || o)
  view_tag: u8,
  // Hs(uniqueness || 8Ra || o) where uniqueness may be empty
  shared_key: Scalar,
}

impl SharedKeyDerivations {
  // https://gist.github.com/kayabaNerve/8066c13f1fe1573286ba7a2fd79f6100
  fn uniqueness(inputs: &[Input]) -> [u8; 32] {
    let mut u = b"uniqueness".to_vec();
    for input in inputs {
      match input {
        // If Gen, this should be the only input, making this loop somewhat pointless
        // This works and even if there were somehow multiple inputs, it'd be a false negative
        Input::Gen(height) => {
          write_varint(height, &mut u).expect("write failed but <Vec as io::Write> doesn't fail");
        }
        // StakeClaim carries a key image (linking tag) just like ToKey; treat identically
        // for uniqueness derivation.
        Input::ToKey { key_image, .. } | Input::StakeClaim { key_image, .. } => {
          u.extend(key_image.to_bytes())
        }
      }
    }
    keccak256(u)
  }

  #[allow(clippy::needless_pass_by_value)]
  fn output_derivations(
    uniqueness: Option<[u8; 32]>,
    ecdh: Zeroizing<EdwardsPoint>,
    o: usize,
  ) -> Zeroizing<SharedKeyDerivations> {
    // 8Ra
    let mut output_derivation = Zeroizing::new(
      Zeroizing::new(Zeroizing::new(ecdh.mul_by_cofactor()).compress().to_bytes()).to_vec(),
    );

    // || o
    {
      let output_derivation: &mut Vec<u8> = output_derivation.as_mut();
      write_varint(&o, output_derivation)
        .expect("write failed but <Vec as io::Write> doesn't fail");
    }

    let view_tag = keccak256([b"view_tag".as_slice(), &output_derivation].concat())[0];

    // uniqueness ||
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

  // H(8Ra || 0x8d)
  #[allow(clippy::needless_pass_by_value)]
  fn payment_id_xor(ecdh: Zeroizing<EdwardsPoint>) -> [u8; 8] {
    // 8Ra
    let output_derivation = Zeroizing::new(
      Zeroizing::new(Zeroizing::new(ecdh.mul_by_cofactor()).compress().to_bytes()).to_vec(),
    );

    let mut payment_id_xor = [0; 8];
    payment_id_xor
      .copy_from_slice(&keccak256([output_derivation.as_slice(), &[0x8d]].concat())[.. 8]);
    payment_id_xor
  }

  fn commitment_mask(&self) -> Scalar {
    let mut mask = b"commitment_mask".to_vec();
    mask.extend(self.shared_key.as_bytes());
    let res = keccak256_to_scalar(&mask);
    mask.zeroize();
    res
  }

  fn compact_amount_encryption(&self, amount: u64) -> [u8; 8] {
    let mut amount_mask = Zeroizing::new(b"amount".to_vec());
    amount_mask.extend(self.shared_key.to_bytes());
    let mut amount_mask = keccak256(&amount_mask);

    let mut amount_mask_8 = [0; 8];
    amount_mask_8.copy_from_slice(&amount_mask[.. 8]);
    amount_mask.zeroize();

    (amount ^ u64::from_le_bytes(amount_mask_8)).to_le_bytes()
  }

  /// Decrypt the encrypted amount and produce a commitment for it.
  ///
  /// The fork's wallet has no PQC layer, so it does not verify `enc_amount.amount_tag`
  /// against an HKDF-derived expected value — the tag is carried through the codec but
  /// not checked here. Shekyl's verifier (`shekyl-crypto-pq::output::scan_output` in
  /// `shekyl-core`) does verify the tag, returning `CryptoError::DecapsulationFailed` on
  /// mismatch. See `EncryptedAmount`'s struct-level docs in `fcmp.rs`.
  fn decrypt(&self, enc_amount: &EncryptedAmount) -> Commitment {
    Commitment::new(
      self.commitment_mask(),
      u64::from_le_bytes(self.compact_amount_encryption(u64::from_le_bytes(enc_amount.amount))),
    )
  }
}
