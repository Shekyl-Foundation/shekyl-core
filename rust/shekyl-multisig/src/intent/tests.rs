use super::*;
use crate::tests::single_address;
use shekyl_crypto_pq::label::{LABEL_PLAINTEXT_LEN, SENTINEL_PLAINTEXT};

/// A group payee named by `bytes`, which structural checks do not parse.
fn group_payee(bytes: &[u8]) -> IntentPayee {
    IntentPayee::Group {
        address: bytes.to_vec(),
    }
}

/// A 2-of-3 intent: member 0 proposes, members 0 and 2 sign, member 2
/// responds. Reference block 900.
fn make_test_intent() -> SpendIntent {
    SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id: [0xAA; 32],
        address_fingerprint: [0xBB; 32],
        proposer_index: 0,
        signers: vec![0, 2],
        responder_index: 2,
        created_at: 1000,
        reference_block_height: 900,
        reference_block_hash: [0xCC; 32],
        recipients: vec![
            IntentRecipient {
                payee: IntentPayee::Single {
                    address: single_address(Network::Testnet),
                    label_plaintext: SENTINEL_PLAINTEXT,
                },
                amount: AtomicUnits::from_raw(100),
            },
            IntentRecipient {
                payee: group_payee(&[4, 5, 6]),
                amount: AtomicUnits::from_raw(200),
            },
        ],
        fee: AtomicUnits::from_raw(10),
        input_global_indices: vec![42, 99],
        kem_randomness_seed: IntentSeed::new(&[0xDD; 32]),
        chain_state_fingerprint: [0; 32],
    }
}

#[test]
fn intent_hash_deterministic() {
    let intent = make_test_intent();
    let h1 = intent.intent_hash().unwrap();
    let h2 = intent.intent_hash().unwrap();
    assert_eq!(h1, h2);
    assert_ne!(h1, [0; 32]);
}

/// The signer set and the responder are in the hash, so every file of
/// the ceremony binds them (R-5); so is every other field.
#[test]
fn intent_hash_binds_the_signer_set_and_the_responder() {
    let base = make_test_intent().intent_hash().unwrap();
    let edits: [&dyn Fn(&mut SpendIntent); 4] = [
        &|i| i.fee = AtomicUnits::from_raw(20),
        &|i| i.signers = vec![0, 1],
        &|i| i.responder_index = 1,
        &|i| i.created_at = 1001,
    ];
    for edit in edits {
        let mut intent = make_test_intent();
        edit(&mut intent);
        assert_ne!(intent.intent_hash().unwrap(), base);
    }
}

/// The decoder is the encoder's inverse, and refuses a truncation, a
/// trailing byte and a count past its bound by the field's name.
#[test]
fn canonical_bytes_round_trip_and_refuse_by_field() {
    let intent = make_test_intent();
    let bytes = intent.to_canonical_bytes().unwrap();
    let back = SpendIntent::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(back.to_canonical_bytes().unwrap(), bytes);
    assert_eq!(back.intent_hash().unwrap(), intent.intent_hash().unwrap());
    for cut in [0, 1, 66, bytes.len() - 1] {
        assert!(
            matches!(
                SpendIntent::from_canonical_bytes(&bytes[..cut]),
                Err(SpendIntentError::Malformed(_))
            ),
            "cut at {cut}"
        );
    }
    let mut long = bytes.clone();
    long.push(0);
    assert!(matches!(
        SpendIntent::from_canonical_bytes(&long),
        Err(SpendIntentError::Malformed("trailing bytes"))
    ));
    let mut many_signers = bytes;
    many_signers[66..70].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        SpendIntent::from_canonical_bytes(&many_signers),
        Err(SpendIntentError::Malformed("signers"))
    ));
}

/// A recipient's kind leads its record, a single-signer payee's label
/// block follows its address, and the decoder refuses a kind it does
/// not know and an address that is not a string.
#[test]
fn a_recipient_is_written_by_its_kind() {
    let intent = make_test_intent();
    let bytes = intent.to_canonical_bytes().unwrap();
    let single = intent.recipients[0].payee.address();
    // version ‖ id ‖ fingerprint ‖ proposer ‖ u32 ‖ 2 signers ‖ responder
    // ‖ created_at ‖ height ‖ hash ‖ u32 recipient count.
    let first = 1 + 32 + 32 + 1 + 4 + 2 + 1 + 8 + 8 + 32 + 4;
    assert_eq!(bytes[first], IntentPayee::KIND_SINGLE);
    let label_at = first + 1 + 4 + single.len();
    assert_eq!(
        bytes[label_at..label_at + LABEL_PLAINTEXT_LEN],
        SENTINEL_PLAINTEXT
    );
    let second = label_at + LABEL_PLAINTEXT_LEN + 8;
    assert_eq!(bytes[second], IntentPayee::KIND_GROUP);

    let mut unknown = bytes.clone();
    unknown[first] = 0x7F;
    assert!(matches!(
        SpendIntent::from_canonical_bytes(&unknown),
        Err(SpendIntentError::Malformed("recipient kind"))
    ));
    let mut not_a_string = bytes;
    not_a_string[first + 1 + 4] = 0xFF;
    assert!(matches!(
        SpendIntent::from_canonical_bytes(&not_a_string),
        Err(SpendIntentError::Malformed("recipient address"))
    ));
}

#[test]
fn validate_structural_passes() {
    make_test_intent().validate_structural(3, 2).unwrap();
}

/// Every structural refusal, by name. Nothing here reads a clock: an
/// intent written years ago with a far-off `created_at` still passes
/// (R-13).
#[test]
fn validate_structural_refuses_each_defect_by_name() {
    let refused = |n: u8, m: u8, edit: &dyn Fn(&mut SpendIntent)| {
        let mut intent = make_test_intent();
        edit(&mut intent);
        intent.validate_structural(n, m).err()
    };
    let keep = |_: &mut SpendIntent| {};
    assert!(matches!(
        refused(3, 2, &|i| i.version = 1),
        Some(SpendIntentError::WrongVersion(1))
    ));
    // R-11: a 1-of-N group, and a threshold above n.
    assert!(matches!(
        refused(3, 1, &keep),
        Some(SpendIntentError::GroupShape { n: 3, m: 1 })
    ));
    assert!(matches!(
        refused(3, 4, &keep),
        Some(SpendIntentError::GroupShape { n: 3, m: 4 })
    ));
    assert!(matches!(
        refused(3, 2, &|i| i.proposer_index = 5),
        Some(SpendIntentError::ProposerOutOfRange(5))
    ));
    assert!(matches!(
        refused(3, 2, &|i| i.signers = vec![0, 1, 2]),
        Some(SpendIntentError::SignerCount {
            expected: 2,
            got: 3
        })
    ));
    assert!(matches!(
        refused(3, 2, &|i| i.signers = vec![2, 0]),
        Some(SpendIntentError::SignersNotAscending)
    ));
    assert!(matches!(
        refused(3, 2, &|i| i.signers = vec![2, 2]),
        Some(SpendIntentError::SignersNotAscending)
    ));
    assert!(matches!(
        refused(3, 2, &|i| i.signers = vec![0, 3]),
        Some(SpendIntentError::SignerOutOfRange(3))
    ));
    assert!(matches!(
        refused(3, 2, &|i| {
            i.signers = vec![1, 2];
        }),
        Some(SpendIntentError::ProposerNotSigner)
    ));
    assert!(matches!(
        refused(3, 2, &|i| i.responder_index = 1),
        Some(SpendIntentError::ResponderNotSigner)
    ));
    assert!(matches!(
        refused(3, 2, &|i| i.responder_index = 0),
        Some(SpendIntentError::ResponderIsProposer)
    ));
    assert!(matches!(
        refused(3, 2, &|i| i.recipients.reverse()),
        Some(SpendIntentError::RecipientsNotSorted)
    ));
    assert!(matches!(
        refused(3, 2, &|i| {
            i.recipients.push(i.recipients[0].clone());
            i.recipients.sort();
        }),
        Some(SpendIntentError::RecipientsNotSorted)
    ));
    assert!(refused(3, 2, &|i| i.created_at = u64::MAX).is_none());
}

#[test]
fn validate_structural_refuses_each_size_bound_by_name() {
    let refused = |edit: &dyn Fn(&mut SpendIntent)| {
        let mut intent = make_test_intent();
        edit(&mut intent);
        intent.validate_structural(3, 2).err()
    };
    assert!(matches!(
        refused(&|i| i.input_global_indices.clear()),
        Some(SpendIntentError::InputCount(0))
    ));
    assert!(matches!(
        refused(&|i| i.input_global_indices = vec![42, 99, 42]),
        Some(SpendIntentError::DuplicateInput(42))
    ));
    assert!(matches!(
        refused(&|i| i.input_global_indices = (0..=u64::from(MAX_INPUTS)).collect()),
        Some(SpendIntentError::InputCount(n)) if n == MAX_INPUTS as usize + 1
    ));
    assert!(matches!(
        refused(&|i| {
            i.recipients = (0..=MAX_RECIPIENTS)
                .map(|k| IntentRecipient {
                    payee: group_payee(&[u8::try_from(k).unwrap()]),
                    amount: AtomicUnits::from_raw(1),
                })
                .collect();
        }),
        Some(SpendIntentError::RecipientCount(n)) if n == MAX_RECIPIENTS as usize + 1
    ));
    assert!(matches!(
        refused(&|i| {
            i.recipients[0].payee = IntentPayee::Group {
                address: vec![0; MAX_ADDRESS_LEN as usize + 1],
            };
        }),
        Some(SpendIntentError::AddressTooLong(n)) if n == MAX_ADDRESS_LEN as usize + 1
    ));
}

#[test]
fn validate_temporal_passes() {
    make_test_intent()
        .validate_temporal(950, &[0xCC; 32])
        .unwrap();
}

/// The window is CEN-I11's, from the connecting height `tip + 1`: with
/// the reference at 900, tips 904 through 999 pass. 903 is too fresh;
/// 1000 is the deadline passed, since no block above 1000 can list the
/// spend. A reference above the tip is "not yet", never "expired".
#[test]
fn validate_temporal_is_the_consensus_window() {
    let intent = make_test_intent();
    let at = |tip: u64| intent.validate_temporal(tip, &[0xCC; 32]);
    let min = shekyl_curve_tree::REFERENCE_BLOCK_MIN_AGE.to_raw();
    let max = shekyl_curve_tree::REFERENCE_BLOCK_MAX_AGE.to_raw();
    let newest_tip = 900 + min - 1;
    let last_tip = 900 + max - 1;
    assert!(matches!(
        at(newest_tip - 1),
        Err(SpendIntentError::RefBlockTooFresh { .. })
    ));
    for tip in newest_tip..=last_tip {
        assert!(at(tip).is_ok(), "tip {tip}");
    }
    assert!(matches!(
        at(last_tip + 1),
        Err(SpendIntentError::RefBlockTooStale { .. })
    ));
    assert!(matches!(
        at(899),
        Err(SpendIntentError::RefBlockTooFresh { .. })
    ));
    assert!(matches!(
        at(0),
        Err(SpendIntentError::RefBlockTooFresh { .. })
    ));
}

#[test]
fn validate_temporal_rejects_ref_block_hash_mismatch() {
    assert!(matches!(
        make_test_intent().validate_temporal(950, &[0xFF; 32]),
        Err(SpendIntentError::RefBlockHashMismatch { .. })
    ));
}

#[test]
fn consensus_constants_match_baselines() {
    assert_eq!(CT_TYPE_FCMP_PLUS_PLUS_PQC, 1);
}

#[test]
fn max_inputs_is_the_consensus_cap() {
    assert_eq!(
        MAX_INPUTS as usize,
        shekyl_wire::transaction::MAX_FCMP_INPUTS,
        "an intent's input cap drifted from the consensus cap (CEN-I4)"
    );
}

/// CEN-I1's minimum is refused at the intent, before anyone signs; change
/// is a recipient, so a sweep to one address with no change is one output.
#[test]
fn an_intent_below_the_consensus_output_minimum_is_refused() {
    let min = shekyl_wire::transaction::MIN_NON_COINBASE_OUTPUTS;
    for count in 0..min {
        let mut intent = make_test_intent();
        intent.recipients.truncate(count);
        assert!(
            matches!(
                intent.validate_structural(3, 2),
                Err(SpendIntentError::TooFewRecipients(n)) if n == count
            ),
            "{count} recipients"
        );
    }
    let mut at_minimum = make_test_intent();
    at_minimum.recipients.truncate(min);
    assert_eq!(at_minimum.recipients.len(), min);
    at_minimum.validate_structural(3, 2).unwrap();
}

#[test]
fn max_recipients_is_the_output_cap() {
    assert_eq!(
        MAX_RECIPIENTS as usize,
        shekyl_wire::transaction::MAX_OUTPUTS,
        "an intent's recipient cap drifted from the consensus output cap"
    );
}

#[test]
fn wire_ct_type_matches_consensus_authority() {
    // Tripwire on the canonical FCMP++ ct-type wire value: if anyone edits
    // `shekyl_wire::transaction::CT_TYPE_FCMP` (the genesis dense ct tag, `1`)
    // without also updating `config/consensus_constants.json`, this test fires.
    assert_eq!(
        shekyl_wire::transaction::CT_TYPE_FCMP,
        CT_TYPE_FCMP_PLUS_PLUS_PQC,
        "shekyl-wire CT_TYPE_FCMP wire value drifted from \
         config/consensus_constants.json"
    );
}

#[test]
fn validate_balance_passes() {
    make_test_intent()
        .validate_balance(&[AtomicUnits::from_raw(210), AtomicUnits::from_raw(100)])
        .unwrap();
}

#[test]
fn validate_balance_rejects_mismatch() {
    assert!(matches!(
        make_test_intent()
            .validate_balance(&[AtomicUnits::from_raw(100), AtomicUnits::from_raw(100)]),
        Err(SpendIntentError::BalanceMismatch { .. })
    ));
}

#[test]
fn chain_state_fingerprint_deterministic() {
    let fp = ChainStateFingerprint {
        reference_block_hash: [0xAA; 32],
        input_global_indices: vec![42, 99],
        input_eligible_heights: vec![800, 850],
        input_amounts: vec![AtomicUnits::from_raw(100), AtomicUnits::from_raw(200)],
    };
    assert_eq!(fp.compute(), fp.compute());
}
