use shekyl_oxide::{
  io::CompressedPoint,
  fcmp::{
    EncryptedAmount, ProofType, ProofBase, PrunableProof, Proofs,
    bulletproofs::Bulletproof,
  },
  transaction::{Input, Output, StakingMeta, Timelock, TransactionPrefix, Transaction, NotPruned},
};

fn dummy_compressed_point() -> CompressedPoint {
  CompressedPoint([
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0,
  ])
}

fn make_dummy_bp_plus() -> Bulletproof {
  let lr_len: usize = 6;
  let push_point = |bp: &mut Vec<u8>| {
    bp.push(1);
    bp.extend([0; 31]);
  };
  let push_scalar = |bp: &mut Vec<u8>| bp.extend([0; 32]);
  let mut bp = Vec::with_capacity(((6 + (2 * lr_len)) * 32) + 2);
  for _ in 0 .. 3 {
    push_point(&mut bp);
  }
  for _ in 0 .. 3 {
    push_scalar(&mut bp);
  }
  for _ in 0 .. 2 {
    shekyl_oxide::io::write_varint(&lr_len, &mut bp).unwrap();
    for _ in 0 .. lr_len {
      push_point(&mut bp);
    }
  }
  Bulletproof::read_plus(&mut bp.as_slice()).unwrap()
}

// -- ProofType tests --

#[test]
fn only_fcmp_pp_type_accepted() {
  assert_eq!(u8::from(ProofType::FcmpPlusPlusPqc), 7);
  assert_eq!(ProofType::try_from(7u8).unwrap(), ProofType::FcmpPlusPlusPqc);
}

#[test]
fn proof_type_rejects_legacy_wire_values() {
  for byte in [0u8, 1, 2, 3, 4, 5, 6, 8, 255] {
    assert!(ProofType::try_from(byte).is_err(), "wire value {byte} should be rejected");
  }
}

// -- PrunableProof round-trip --

#[test]
fn fcmp_pp_prunable_round_trip() {
  let bulletproof = make_dummy_bp_plus();
  let prunable = PrunableProof {
    pseudo_outs: vec![dummy_compressed_point(); 2],
    bulletproof,
    reference_block: 42_000,
    fcmp_proof: vec![0xAA; 256],
    pqc_auths: vec![vec![0xBB; 128], vec![0xCC; 128]],
  };

  let mut serialized = vec![];
  prunable.write(&mut serialized).unwrap();
  assert!(!serialized.is_empty());

  let deserialized = PrunableProof::read(2, &mut serialized.as_slice()).unwrap();
  assert_eq!(prunable, deserialized);
}

// -- Full Proofs round-trip --

#[test]
fn fcmp_pp_proofs_round_trip() {
  let bulletproof = make_dummy_bp_plus();
  let proofs = Proofs {
    base: ProofBase {
      fee: 1_000_000,
      encrypted_amounts: vec![EncryptedAmount { amount: [1; 8], amount_tag: 0xA1 }],
      commitments: vec![dummy_compressed_point()],
    },
    prunable: PrunableProof {
      pseudo_outs: vec![dummy_compressed_point()],
      bulletproof,
      reference_block: 100,
      fcmp_proof: vec![0xDE; 512],
      pqc_auths: vec![vec![0xAD; 3309]],
    },
  };

  assert_eq!(proofs.proof_type(), ProofType::FcmpPlusPlusPqc);
  let serialized = proofs.serialize();

  let deserialized = Proofs::read(1, 1, &mut serialized.as_slice()).unwrap().unwrap();
  assert_eq!(proofs, deserialized);
}

// -- Transaction V2 FCMP++ round-trip --

#[test]
fn fcmp_pp_transaction_round_trip() {
  let bulletproof = make_dummy_bp_plus();
  let tx = Transaction::V2 {
    prefix: TransactionPrefix {
      additional_timelock: Timelock::None,
      inputs: vec![Input::ToKey {
        amount: None,
        key_offsets: vec![],
        key_image: dummy_compressed_point(),
      }],
      outputs: vec![Output {
        amount: None,
        key: dummy_compressed_point(),
        view_tag: Some(0x42),
        staking: None,
      }],
      extra: vec![],
    },
    proofs: Some(Proofs {
      base: ProofBase {
        fee: 500_000,
        encrypted_amounts: vec![EncryptedAmount { amount: [7; 8], amount_tag: 0xB2 }],
        commitments: vec![dummy_compressed_point()],
      },
      prunable: PrunableProof {
        pseudo_outs: vec![dummy_compressed_point()],
        bulletproof,
        reference_block: 99,
        fcmp_proof: vec![0xFF; 64],
        pqc_auths: vec![vec![0xEE; 64]],
      },
    }),
  };

  let serialized = tx.serialize();
  let deserialized = Transaction::read(&mut serialized.as_slice()).unwrap();
  assert_eq!(tx, deserialized);
  assert_eq!(tx.hash(), deserialized.hash());
}

// -- Coinbase transaction round-trip --

#[test]
fn coinbase_transaction_round_trip() {
  let tx = Transaction::V2 {
    prefix: TransactionPrefix {
      additional_timelock: Timelock::None,
      inputs: vec![Input::Gen(1000)],
      outputs: vec![Output {
        amount: Some(1_000_000_000),
        key: dummy_compressed_point(),
        view_tag: None,
        staking: None,
      }],
      extra: vec![1, 2, 3, 4],
    },
    proofs: None,
  };

  let serialized = tx.serialize();
  let deserialized = Transaction::read(&mut serialized.as_slice()).unwrap();
  assert_eq!(tx, deserialized);
  assert!(deserialized.signature_hash().is_none());
}

// -- V1 transactions are rejected --

#[test]
fn v1_transaction_rejected() {
  let mut data: Vec<u8> = vec![];
  shekyl_oxide::io::write_varint(&1u64, &mut data).unwrap();
  shekyl_oxide::io::write_varint(&0u64, &mut data).unwrap(); // timelock
  shekyl_oxide::io::write_varint(&1u64, &mut data).unwrap(); // 1 input
  data.push(255); // Gen
  shekyl_oxide::io::write_varint(&0u64, &mut data).unwrap(); // height 0
  shekyl_oxide::io::write_varint(&1u64, &mut data).unwrap(); // 1 output
  shekyl_oxide::io::write_varint(&100u64, &mut data).unwrap(); // amount
  data.push(2); // output type
  data.extend([0u8; 32]); // key
  shekyl_oxide::io::write_varint(&0u64, &mut data).unwrap(); // extra len

  let result = Transaction::<NotPruned>::read(&mut data.as_slice());
  assert!(result.is_err(), "v1 transaction should be rejected");
}

// -- Edge cases --

#[test]
fn fcmp_pp_empty_proof_round_trip() {
  let bulletproof = make_dummy_bp_plus();
  let prunable = PrunableProof {
    pseudo_outs: vec![dummy_compressed_point()],
    bulletproof,
    reference_block: 0,
    fcmp_proof: vec![],
    pqc_auths: vec![vec![]],
  };
  let serialized = prunable.serialize();
  let deserialized = PrunableProof::read(1, &mut serialized.as_slice()).unwrap();
  assert_eq!(prunable, deserialized);
}

#[test]
fn fcmp_pp_pqc_auth_count_mismatch_rejected() {
  let bulletproof = make_dummy_bp_plus();
  let prunable = PrunableProof {
    pseudo_outs: vec![dummy_compressed_point(); 2],
    bulletproof,
    reference_block: 0,
    fcmp_proof: vec![],
    pqc_auths: vec![vec![0u8; 16]],
  };
  let serialized = prunable.serialize();
  let result = PrunableProof::read(2, &mut serialized.as_slice());
  assert!(result.is_err(), "mismatched pqc_auths count should be rejected");
}

#[test]
fn proof_base_type_zero_is_none() {
  let result = ProofBase::read(1, &mut [0u8].as_slice()).unwrap();
  assert!(result.is_none());
}

#[test]
fn proof_base_legacy_type_bytes_rejected() {
  for byte in [1u8, 2, 3, 4, 5, 6] {
    let result = ProofBase::read(1, &mut [byte].as_slice());
    assert!(result.is_err(), "legacy type byte {byte} should be rejected by ProofBase::read");
  }
}

#[test]
fn transaction_version_always_2() {
  let tx: Transaction<NotPruned> = Transaction::V2 {
    prefix: TransactionPrefix {
      additional_timelock: Timelock::None,
      inputs: vec![Input::Gen(0)],
      outputs: vec![],
      extra: vec![],
    },
    proofs: None,
  };
  assert_eq!(tx.version(), 2);
}

// -- Commit B: Input::StakeClaim codec --

#[test]
fn input_stake_claim_round_trip() {
  let cases = [
    Input::StakeClaim {
      amount: 0,
      staked_output_index: 0,
      from_height: 0,
      to_height: 0,
      key_image: dummy_compressed_point(),
    },
    Input::StakeClaim {
      amount: 1,
      staked_output_index: 1,
      from_height: 1,
      to_height: 2,
      key_image: dummy_compressed_point(),
    },
    Input::StakeClaim {
      amount: u64::MAX,
      staked_output_index: u64::MAX,
      from_height: u64::MAX - 1,
      to_height: u64::MAX,
      key_image: CompressedPoint([0xFF; 32]),
    },
  ];
  for input in cases {
    let serialized = input.serialize();
    assert_eq!(serialized[0], 3, "StakeClaim binary tag is 0x03");
    let deserialized = Input::read(&mut serialized.as_slice()).unwrap();
    assert_eq!(input, deserialized, "StakeClaim round-trip is byte-equal");
  }
}

#[test]
fn input_stake_claim_truncated_rejected() {
  // Tag 0x03 + 4 varints (each 1 byte for value 0) but no key_image -> EOF on read.
  let truncated: Vec<u8> = vec![3, 0, 0, 0, 0];
  let err = Input::read(&mut truncated.as_slice()).unwrap_err();
  assert_eq!(
    err.kind(),
    std_shims::io::ErrorKind::UnexpectedEof,
    "truncated StakeClaim must fail with UnexpectedEof"
  );
}

#[test]
fn input_unknown_tag_rejected() {
  // Tag 0x05 is not assigned (0x02=ToKey, 0x03=StakeClaim, 0xFF=Gen).
  for unknown in [0u8, 1, 4, 5, 6, 100, 254] {
    let buf = [unknown, 0, 0, 0, 0];
    let result = Input::read(&mut buf.as_slice());
    assert!(result.is_err(), "Input tag {unknown:#04x} must be rejected");
  }
}

// -- Commit B: Staked Output codec (tag 0x04) --

#[test]
fn staked_output_round_trip_explicit_amount() {
  // Staked outputs always carry an explicit (non-zero) amount; rct flag must not zero it.
  let output = Output {
    amount: Some(500_000_000),
    key: dummy_compressed_point(),
    view_tag: Some(0x42),
    staking: Some(StakingMeta { lock_tier: 1 }),
  };
  let serialized = output.serialize();
  // Expected on-wire: varint(amount) + 0x04 + key(32) + view_tag(1) + lock_tier(1).
  let tag_position = {
    let mut probe = vec![];
    shekyl_oxide::io::write_varint(&500_000_000u64, &mut probe).unwrap();
    probe.len()
  };
  assert_eq!(serialized[tag_position], 4, "staked output emits tag 0x04");

  // rct=true must still preserve the amount on staked outputs.
  let deserialized = Output::read(true, &mut serialized.as_slice()).unwrap();
  assert_eq!(deserialized, output);

  // rct=false also round-trips identically.
  let deserialized = Output::read(false, &mut serialized.as_slice()).unwrap();
  assert_eq!(deserialized, output);
}

#[test]
fn staked_output_round_trip_all_tiers() {
  for tier in [0u8, 1, 2, 0xFE, 0xFF] {
    let output = Output {
      amount: Some(1),
      key: dummy_compressed_point(),
      view_tag: Some(0x99),
      staking: Some(StakingMeta { lock_tier: tier }),
    };
    let serialized = output.serialize();
    let deserialized = Output::read(true, &mut serialized.as_slice()).unwrap();
    assert_eq!(deserialized, output, "staked output round-trip for lock_tier = {tier}");
  }
}

#[test]
fn staked_output_view_tag_none_emits_zero_byte() {
  // The codec serializes view_tag = None as 0x00 to preserve the fixed wire shape for
  // tag 0x04. On read, this comes back as Some(0) — semantically equivalent to "no
  // distinguishing view tag set" but explicitly carried on the wire.
  let original = Output {
    amount: Some(1_000),
    key: dummy_compressed_point(),
    view_tag: None,
    staking: Some(StakingMeta { lock_tier: 0 }),
  };
  let serialized = original.serialize();
  let deserialized = Output::read(true, &mut serialized.as_slice()).unwrap();
  assert_eq!(
    deserialized,
    Output {
      amount: Some(1_000),
      key: dummy_compressed_point(),
      view_tag: Some(0),
      staking: Some(StakingMeta { lock_tier: 0 }),
    },
    "view_tag = None on a staked output round-trips to Some(0)"
  );
}

#[test]
fn output_unknown_tag_rejected() {
  // Tags 0x02, 0x03 (legacy view-tag), and 0x04 (staked) are valid. Anything else fails.
  for unknown in [0u8, 1, 5, 6, 7, 100, 255] {
    let mut buf: Vec<u8> = vec![];
    shekyl_oxide::io::write_varint(&0u64, &mut buf).unwrap();
    buf.push(unknown);
    buf.extend([0; 32]);
    let result = Output::read(true, &mut buf.as_slice());
    assert!(result.is_err(), "Output tag {unknown:#04x} must be rejected");
  }
}

// -- Commit B: PQC auth length bounds --
//
// MAX_PQC_AUTH_SIZE is 4096 internal to fcmp.rs. These tests probe the boundary
// without importing the constant: we drive the public PrunableProof::read API.

#[test]
fn pqc_auth_at_ml_dsa_65_size_accepted() {
  // ML-DSA-65 signatures are exactly 3309 bytes; the bound must accept them.
  let bulletproof = make_dummy_bp_plus();
  let prunable = PrunableProof {
    pseudo_outs: vec![dummy_compressed_point()],
    bulletproof,
    reference_block: 1,
    fcmp_proof: vec![],
    pqc_auths: vec![vec![0xCD; 3309]],
  };
  let serialized = prunable.serialize();
  let deserialized = PrunableProof::read(1, &mut serialized.as_slice()).unwrap();
  assert_eq!(prunable, deserialized);
}

#[test]
fn pqc_auth_at_max_boundary_accepted() {
  // 4096 is the upper bound; equal-to-bound must be accepted.
  let bulletproof = make_dummy_bp_plus();
  let prunable = PrunableProof {
    pseudo_outs: vec![dummy_compressed_point()],
    bulletproof,
    reference_block: 1,
    fcmp_proof: vec![],
    pqc_auths: vec![vec![0xCD; 4096]],
  };
  let serialized = prunable.serialize();
  let deserialized = PrunableProof::read(1, &mut serialized.as_slice()).unwrap();
  assert_eq!(prunable, deserialized);
}

#[test]
fn pqc_auth_above_max_boundary_rejected() {
  // 4097 must fail. Construct the payload manually to bypass write-side checks.
  let bulletproof = make_dummy_bp_plus();
  let prunable = PrunableProof {
    pseudo_outs: vec![dummy_compressed_point()],
    bulletproof,
    reference_block: 1,
    fcmp_proof: vec![],
    pqc_auths: vec![vec![0xEE; 4097]],
  };
  let serialized = prunable.serialize();
  let result = PrunableProof::read(1, &mut serialized.as_slice());
  assert!(result.is_err(), "auth_len = 4097 must exceed MAX_PQC_AUTH_SIZE and be rejected");
}

#[test]
fn pqc_auth_dos_size_rejected() {
  // A claimed length of u32::MAX would allocate ~4 GiB if the bound were missing.
  // The codec must reject this via the bound, not by attempting the allocation.
  //
  // Strategy: serialize a valid PrunableProof with a uniquely-sized pqc_auth blob,
  // then surgically replace the auth-length varint with u32::MAX. The unique size
  // (513 bytes — picked to be > 256 so the varint is 2 bytes, distinct from any
  // single-byte varint elsewhere) makes the patch unambiguous.
  let bulletproof = make_dummy_bp_plus();
  const SENTINEL_LEN: usize = 513;
  let prunable = PrunableProof {
    pseudo_outs: vec![dummy_compressed_point()],
    bulletproof,
    reference_block: 0,
    fcmp_proof: vec![],
    pqc_auths: vec![vec![0xAB; SENTINEL_LEN]],
  };
  let serialized = prunable.serialize();

  let mut sentinel_varint = vec![];
  shekyl_oxide::io::write_varint(&u64::try_from(SENTINEL_LEN).unwrap(), &mut sentinel_varint)
    .unwrap();
  let dos_varint = {
    let mut v = vec![];
    shekyl_oxide::io::write_varint(&u64::from(u32::MAX), &mut v).unwrap();
    v
  };

  // The sentinel varint precedes the SENTINEL_LEN bytes of 0xAB.
  let mut auth_blob_marker = sentinel_varint.clone();
  auth_blob_marker.extend([0xAB; 4]);
  let pos = serialized
    .windows(auth_blob_marker.len())
    .position(|w| w == auth_blob_marker.as_slice())
    .expect("locate auth-length varint via sentinel pattern");
  let varint_end = pos + sentinel_varint.len();

  let mut tampered = serialized[.. pos].to_vec();
  tampered.extend(&dos_varint);
  tampered.extend(&serialized[varint_end ..]);

  let result = PrunableProof::read(1, &mut tampered.as_slice());
  assert!(
    result.is_err(),
    "auth_len = u32::MAX must be rejected by MAX_PQC_AUTH_SIZE without allocating"
  );
}

#[test]
fn pqc_auth_zero_length_accepted() {
  // Empty signatures are syntactically permitted at the codec layer (any consensus
  // requirement that the signature be non-empty lives elsewhere, in shekyl-crypto-pq).
  let bulletproof = make_dummy_bp_plus();
  let prunable = PrunableProof {
    pseudo_outs: vec![dummy_compressed_point()],
    bulletproof,
    reference_block: 0,
    fcmp_proof: vec![],
    pqc_auths: vec![vec![]],
  };
  let serialized = prunable.serialize();
  let deserialized = PrunableProof::read(1, &mut serialized.as_slice()).unwrap();
  assert_eq!(prunable, deserialized);
}
