use std_shims::{vec, vec::Vec};

use curve25519_dalek::constants::{ED25519_BASEPOINT_COMPRESSED, ED25519_BASEPOINT_TABLE};

use crate::{
  io::{varint_len, write_varint, CompressedPoint},
  fcmp::{bulletproofs::Bulletproof, EncryptedAmount, ProofBase, PrunableProof, Proofs},
  transaction::{Input, Output, Timelock, TransactionPrefix, Transaction},
  extra::{ARBITRARY_DATA_MARKER, PaymentId, Extra},
  send::{InternalPayment, SignableTransaction, SignableTransactionWithKeyImages},
};

impl SignableTransaction {
  pub(crate) fn inputs(&self, key_images: &[CompressedPoint]) -> Vec<Input> {
    debug_assert_eq!(self.inputs.len(), key_images.len());

    let mut res = Vec::with_capacity(self.inputs.len());
    for (input, key_image) in self.inputs.iter().zip(key_images) {
      res.push(Input::ToKey {
        amount: None,
        key_offsets: input.decoys().offsets().to_vec(),
        key_image: *key_image,
      });
    }
    res
  }

  pub(crate) fn outputs(&self, key_images: &[CompressedPoint]) -> Vec<Output> {
    let shared_key_derivations = self.shared_key_derivations(key_images);
    debug_assert_eq!(self.payments.len(), shared_key_derivations.len());

    let mut res = Vec::with_capacity(self.payments.len());
    for (payment, shared_key_derivations) in self.payments.iter().zip(&shared_key_derivations) {
      let key =
        (&shared_key_derivations.shared_key * ED25519_BASEPOINT_TABLE) + payment.address().spend();
      // The fork's wallet does not construct staked outputs (no PQC/staking layer);
      // staking metadata always None here. Shekyl-core constructs txout_to_staked_key.
      res.push(Output {
        key: CompressedPoint::from(key.compress()),
        amount: None,
        view_tag: Some(shared_key_derivations.view_tag),
        staking: None,
      });
    }
    res
  }

  pub(crate) fn extra(&self) -> Vec<u8> {
    let (tx_key, additional_keys) = self.transaction_keys_pub();
    debug_assert!(additional_keys.is_empty() || (additional_keys.len() == self.payments.len()));
    let payment_id_xors = self.payment_id_xors();
    debug_assert_eq!(self.payments.len(), payment_id_xors.len());

    let amount_of_keys = 1 + additional_keys.len();
    let mut extra = Extra::new(tx_key, additional_keys);

    if let Some((id, id_xor)) =
      self.payments.iter().zip(&payment_id_xors).find_map(|(payment, payment_id_xor)| {
        payment.address().payment_id().map(|id| (id, payment_id_xor))
      })
    {
      let id = (u64::from_le_bytes(id) ^ u64::from_le_bytes(*id_xor)).to_le_bytes();
      let mut id_vec = Vec::with_capacity(1 + 8);
      PaymentId::Encrypted(id)
        .write(&mut id_vec)
        .expect("write failed but <Vec as io::Write> doesn't fail");
      extra.push_nonce(id_vec);
    } else if self.payments.len() == 2 {
      let (_, payment_id_xor) = self
        .payments
        .iter()
        .zip(&payment_id_xors)
        .find(|(payment, _)| matches!(payment, InternalPayment::Payment(_, _)))
        .expect("multiple change outputs?");
      let mut id_vec = Vec::with_capacity(1 + 8);
      PaymentId::Encrypted(*payment_id_xor)
        .write(&mut id_vec)
        .expect("write failed but <Vec as io::Write> doesn't fail");
      extra.push_nonce(id_vec);
    }

    for part in &self.data {
      let mut arb = vec![ARBITRARY_DATA_MARKER];
      arb.extend(part);
      extra.push_nonce(arb);
    }

    let mut serialized = Vec::with_capacity(32 * amount_of_keys);
    extra.write(&mut serialized).expect("write failed but <Vec as io::Write> doesn't fail");
    serialized
  }

  pub(crate) fn weight_and_necessary_fee(&self) -> (usize, u64) {
    let base_weight = {
      let mut key_images = Vec::with_capacity(self.inputs.len());
      let mut pseudo_outs = Vec::with_capacity(self.inputs.len());
      for _ in &self.inputs {
        key_images.push(CompressedPoint::from(ED25519_BASEPOINT_COMPRESSED));
        pseudo_outs.push(CompressedPoint::from(ED25519_BASEPOINT_COMPRESSED));
      }
      let mut encrypted_amounts = Vec::with_capacity(self.payments.len());
      let mut commitments = Vec::with_capacity(self.payments.len());
      for _ in &self.payments {
        // amount_tag is a placeholder here (fork wallet has no PQC layer); Shekyl-consensus
        // values are produced by shekyl-crypto-pq in shekyl-core. See EncryptedAmount docs.
        encrypted_amounts.push(EncryptedAmount { amount: [0; 8], amount_tag: 0 });
        commitments.push(CompressedPoint::from(ED25519_BASEPOINT_COMPRESSED));
      }

      let padded_log2 = {
        let mut log2_find = 0;
        while (1 << log2_find) < self.payments.len() {
          log2_find += 1;
        }
        log2_find
      };
      let lr_len = 6 + padded_log2;

      let bulletproof = {
        let mut bp = Vec::with_capacity(((6 + (2 * lr_len)) * 32) + 2);
        let push_point = |bp: &mut Vec<u8>| {
          bp.push(1);
          bp.extend([0; 31]);
        };
        let push_scalar = |bp: &mut Vec<u8>| bp.extend([0; 32]);
        for _ in 0 .. 3 {
          push_point(&mut bp);
        }
        for _ in 0 .. 3 {
          push_scalar(&mut bp);
        }
        for _ in 0 .. 2 {
          write_varint(&lr_len, &mut bp)
            .expect("write failed but <Vec as io::Write> doesn't fail");
          for _ in 0 .. lr_len {
            push_point(&mut bp);
          }
        }
        Bulletproof::read_plus(&mut bp.as_slice()).expect("made an invalid dummy BP+")
      };

      // Estimated sizes for FCMP++ proof weight calculation
      const ESTIMATED_FCMP_BASE_PROOF_BYTES: usize = 2000;
      const ESTIMATED_FCMP_PROOF_BYTES_PER_INPUT: usize = 500;
      const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;
      let n_inputs = self.inputs.len();

      // `- 1` to remove the one byte for the 0 fee
      Transaction::V2 {
        prefix: TransactionPrefix {
          additional_timelock: Timelock::None,
          inputs: self.inputs(&key_images),
          outputs: self.outputs(&key_images),
          extra: self.extra(),
        },
        proofs: Some(Proofs {
          base: ProofBase { fee: 0, encrypted_amounts, commitments },
          prunable: PrunableProof {
            pseudo_outs,
            bulletproof,
            reference_block: 0,
            fcmp_proof: vec![
              0u8;
              ESTIMATED_FCMP_BASE_PROOF_BYTES +
                ESTIMATED_FCMP_PROOF_BYTES_PER_INPUT * n_inputs
            ],
            pqc_auths: (0 .. n_inputs)
              .map(|_| vec![0u8; ML_DSA_65_SIGNATURE_SIZE])
              .collect(),
          },
        }),
      }
      .weight() -
        1
    };

    let mut possible_weights = Vec::with_capacity(9);
    for i in 1 ..= 9 {
      possible_weights.push(base_weight + i);
    }
    debug_assert_eq!(possible_weights.len(), 9);

    let mut possible_fees = Vec::with_capacity(9);
    for weight in possible_weights {
      possible_fees.push(self.fee_rate.calculate_fee_from_weight(weight));
    }

    let mut weight_and_fee = None;
    for (fee_len, possible_fee) in possible_fees.into_iter().enumerate() {
      let fee_len = 1 + fee_len;
      debug_assert!(1 <= fee_len);
      debug_assert!(fee_len <= 9);

      if varint_len(possible_fee) <= fee_len {
        weight_and_fee = Some((base_weight + fee_len, possible_fee));
        break;
      }
    }
    weight_and_fee
      .expect("length of highest possible fee was greater than highest possible fee length")
  }
}

#[allow(dead_code)]
impl SignableTransactionWithKeyImages {
  pub(crate) fn transaction_without_signatures(&self) -> Transaction {
    let commitments_and_encrypted_amounts =
      self.intent.commitments_and_encrypted_amounts(&self.key_images);
    let mut commitments = Vec::with_capacity(self.intent.payments.len());
    let mut bp_commitments = Vec::with_capacity(self.intent.payments.len());
    let mut encrypted_amounts = Vec::with_capacity(self.intent.payments.len());
    for (commitment, encrypted_amount) in commitments_and_encrypted_amounts {
      commitments.push(CompressedPoint::from(commitment.calculate().compress()));
      bp_commitments.push(commitment);
      encrypted_amounts.push(encrypted_amount);
    }
    let bulletproof = {
      let mut bp_rng = self.intent.seeded_rng(b"bulletproof");
      Bulletproof::prove_plus(&mut bp_rng, bp_commitments)
        .expect("couldn't prove BP+s for this many payments despite checking in constructor?")
    };

    let fee = if self
      .intent
      .payments
      .iter()
      .any(|payment| matches!(payment, InternalPayment::Change(_)))
    {
      self.intent.weight_and_necessary_fee().1
    } else {
      let inputs =
        self.intent.inputs.iter().map(|input| input.commitment().amount).sum::<u64>();
      let payments = self
        .intent
        .payments
        .iter()
        .filter_map(|payment| match payment {
          InternalPayment::Payment(_, amount) => Some(amount),
          InternalPayment::Change(_) => None,
        })
        .sum::<u64>();
      inputs - payments
    };

    Transaction::V2 {
      prefix: TransactionPrefix {
        additional_timelock: Timelock::None,
        inputs: self.intent.inputs(&self.key_images),
        outputs: self.intent.outputs(&self.key_images),
        extra: self.intent.extra(),
      },
      proofs: Some(Proofs {
        base: ProofBase { fee, encrypted_amounts, commitments },
        prunable: PrunableProof {
          pseudo_outs: vec![],
          bulletproof,
          reference_block: 0,
          fcmp_proof: vec![],
          pqc_auths: vec![],
        },
      }),
    }
  }
}
