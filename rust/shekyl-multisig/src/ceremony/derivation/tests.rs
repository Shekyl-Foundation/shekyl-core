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
use shekyl_curve_tree::{
    AssembleInput, AssembledPaths, BlockHeight, ChunkLeaf, Gindex, PathParts, ReferenceBlock,
};
use shekyl_fcmp::tree::key_image_generator;
use shekyl_types::{BlockHash, CommitmentBytes, CurveTreeRoot, OneTimePubkey};

use super::*;
use crate::ceremony::spend_paths::SpendPathsError;
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
const REFERENCE_HEIGHT: u64 = 100;
const REFERENCE_HASH: [u8; 32] = [0x77; 32];
/// The chain's tip, a few blocks past the reference block.
const TIP_HEIGHT: u64 = 105;
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
    let amounts: Vec<AtomicUnits> = INPUTS
        .iter()
        .map(|&(_, amount)| AtomicUnits::from_raw(amount))
        .collect();
    validated_with(g, seed, &INPUTS, &amounts)
}

/// The intent spending `inputs` (global index and amount), validated
/// against a ledger that names `ledger_amounts` for them.
fn validated_with(
    g: &Group,
    seed: [u8; 32],
    inputs: &[(u64, u64)],
    ledger_amounts: &[AtomicUnits],
) -> ValidatedIntent {
    let payload = &g.payload;
    let (kem, _) = HybridX25519MlKem.keypair_generate().unwrap();
    let single = ShekylAddress::new(NETWORK, point(), point(), [0; MSG_SIGN_PK_LEN], kem.ml_kem);
    let amounts: Vec<AtomicUnits> = inputs
        .iter()
        .map(|&(_, amount)| AtomicUnits::from_raw(amount))
        .collect();
    let indices: Vec<u64> = inputs.iter().map(|&(index, _)| index).collect();
    let reference_block_hash = REFERENCE_HASH;
    let fingerprint = ChainStateFingerprint {
        reference_block_hash,
        input_global_indices: indices.clone(),
        input_eligible_heights: vec![0; inputs.len()],
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
        reference_block_height: REFERENCE_HEIGHT,
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
            chain_tip_height: TIP_HEIGHT,
            local_ref_block_hash: &reference_block_hash,
            local_chain_state_fingerprint: &fingerprint,
            input_amounts: ledger_amounts,
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
    pay_inputs(g, &INPUTS)
}

/// The group paid `inputs` (global index and amount), each in its own
/// transaction.
fn pay_inputs(g: &Group, inputs: &[(u64, u64)]) -> Vec<Paid> {
    inputs
        .iter()
        .map(|&(global_index, amount)| {
            let output = construct_multisig_output(
                TxKey::random()
                    .expect("the OS draws a key")
                    .output_positions(usize::try_from(PAID_OUTPUT_INDEX).unwrap() + 1)
                    .at(PAID_OUTPUT_INDEX)
                    .unwrap(),
                &g.payload,
                amount,
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
            paid.key_image = recover_group_spend(&g.key(), &record(&paid, 0).source())
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

/// The path every paid output has: one leaf chunk holding all of them.
fn chunk(paid: &[Paid]) -> PathParts {
    PathParts {
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
    }
}

/// What a wallet asks its tree for, for `paid`.
fn asked(paid: &Paid) -> AssembleInput {
    AssembleInput {
        gindex: Gindex::from_raw(paid.global_index),
        output_key: OneTimePubkey::from_bytes(paid.output.output_key),
        commitment: CommitmentBytes::from_bytes(paid.output.commitment),
    }
}

/// A batch assembled against the block whose hash is `block_hash`, in
/// the tree at [`TREE_ROOT`]: a path for each of `inputs`, each the
/// leaf chunk holding every one of `paid`.
fn batch_at(
    block_hash: [u8; 32],
    paid: &[Paid],
    inputs: impl IntoIterator<Item = AssembleInput>,
) -> AssembledPaths {
    AssembledPaths::from_parts_unchecked(
        ReferenceBlock {
            height: BlockHeight::from_raw(REFERENCE_HEIGHT),
            curve_tree_root: CurveTreeRoot::from_bytes(TREE_ROOT),
            block_hash: BlockHash::from_bytes(block_hash),
        },
        TREE_LAYERS,
        inputs
            .into_iter()
            .map(|input| (input, chunk(paid)))
            .collect(),
    )
}

/// `intent` matched to the paths of `paid`, assembled against its own
/// reference block.
fn spend(intent: &ValidatedIntent, paid: &[Paid]) -> SpendPaths {
    SpendPaths::new(
        intent,
        batch_at(REFERENCE_HASH, paid, paid.iter().map(asked)),
    )
    .expect("a batch of the intent's own inputs at its reference block matches")
}

/// `member`'s ledger record of `paid`.
fn record(paid: &Paid, member: u8) -> GroupOutputRecord {
    let (own_x25519_ct, own_ml_kem_ct) = own_ciphertexts(&paid.output, member);
    GroupOutputRecord {
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
    }
}

/// A member's ledger, looked up by global index: records only.
struct Ledger {
    records: Vec<GroupOutputRecord>,
}

impl GroupOutputs for Ledger {
    fn record(&self, global_index: u64) -> Option<GroupOutputRecord> {
        self.records
            .iter()
            .find(|r| r.global_index == global_index)
            .cloned()
    }
}

/// `member`'s ledger of `paid`: its own ciphertexts differ from every
/// other member's.
fn ledger(paid: &[Paid], member: u8) -> Ledger {
    Ledger {
        records: paid.iter().map(|p| record(p, member)).collect(),
    }
}

/// Two inputs' amounts swapped    /// Two inputs' amounts swapped in this member's ledger still balance
/// and still match the chain-state fingerprint, which sorts them; only
/// the coins' commitments tell. The derivation refuses the first input
/// paired with the other's amount, before any nonce exists (R-27).
#[test]
fn an_amount_paired_with_another_input_is_refused() {
    let g = group();
    let mut amounts: Vec<AtomicUnits> = INPUTS
        .iter()
        .map(|&(_, amount)| AtomicUnits::from_raw(amount))
        .collect();
    amounts.swap(0, 1);
    let intent = validated_with(&g, bytes32(), &INPUTS, &amounts);
    let paid = pay(&g);
    let refused =
        DerivedSpend::derive(spend(&intent, &paid), &ledger(&paid, 0), &g.key(), NET_ID).err();
    assert!(
        matches!(
            refused,
            Some(DeriveError::InputCommitment { global_index }) if global_index == INPUTS[0].0
        ),
        "{refused:?}"
    );
}

/// One coin recorded at both of an intent's global indices, where the
/// two inputs' amounts are equal: each record derives, opens at its
/// paired amount and sits in the tree, so only the shared key image
/// tells. The derivation refuses the spend of one output twice.
#[test]
fn one_coin_recorded_at_two_inputs_of_equal_amount_is_refused() {
    /// Two inputs of one amount that balance [`OUTPUTS`] and [`FEE`].
    const EQUAL_INPUTS: [(u64, u64); 2] = [(80, 600), (81, 600)];
    let g = group();
    let amounts = EQUAL_INPUTS.map(|(_, amount)| AtomicUnits::from_raw(amount));
    let intent = validated_with(&g, bytes32(), &EQUAL_INPUTS, &amounts);
    let paid = pay_inputs(&g, &EQUAL_INPUTS);
    let mut held = ledger(&paid, 0);
    held.records[1] = GroupOutputRecord {
        global_index: EQUAL_INPUTS[1].0,
        ..held.records[0].clone()
    };
    let refused = DerivedSpend::derive(spend(&intent, &paid), &held, &g.key(), NET_ID).err();
    assert!(
        matches!(refused, Some(DeriveError::DuplicateKeyImage)),
        "{refused:?}"
    );
}

/// Paths assembled against another block than the intent's reference
/// block are refused when they are matched to it (R-26), for a spend of
/// one input as for a spend of several: the comparison is made once,
/// here, and no input count skips it.
#[test]
fn a_batch_for_another_block_is_refused() {
    /// One input that alone balances [`OUTPUTS`] and [`FEE`].
    const ONE_INPUT: [(u64, u64); 1] = [(70, 1_200)];
    const OTHER_BLOCK: [u8; 32] = [0x78; 32];
    let g = group();
    for inputs in [&ONE_INPUT[..], &INPUTS[..]] {
        let amounts: Vec<AtomicUnits> = inputs
            .iter()
            .map(|&(_, amount)| AtomicUnits::from_raw(amount))
            .collect();
        let intent = validated_with(&g, bytes32(), inputs, &amounts);
        let paid = pay_inputs(&g, inputs);
        let refused = SpendPaths::new(
            &intent,
            batch_at(OTHER_BLOCK, &paid, paid.iter().map(asked)),
        )
        .err();
        assert_eq!(
            refused,
            Some(SpendPathsError::OtherBlock {
                intent: BlockHash::from_bytes(REFERENCE_HASH),
                batch: BlockHash::from_bytes(OTHER_BLOCK),
            }),
            "{} input(s)",
            inputs.len()
        );
    }
}

/// A batch with no path for one of the intent's inputs is refused,
/// naming the input.
#[test]
fn a_batch_missing_an_input_is_refused() {
    let g = group();
    let intent = validated(&g, bytes32());
    let paid = pay(&g);
    let refused = SpendPaths::new(
        &intent,
        batch_at(REFERENCE_HASH, &paid, paid[..2].iter().map(asked)),
    )
    .err();
    assert_eq!(
        refused,
        Some(SpendPathsError::MissingInput {
            global_index: INPUTS[2].0
        })
    );
}

/// A batch holding a path for an input the intent does not spend, or a
/// second path for one it does, is refused, naming the input.
#[test]
fn a_batch_with_an_extra_input_is_refused() {
    const NOT_SPENT: u64 = 99;
    let g = group();
    let intent = validated(&g, bytes32());
    let paid = pay(&g);
    let stranger = AssembleInput {
        gindex: Gindex::from_raw(NOT_SPENT),
        ..asked(&paid[0])
    };
    let added = paid.iter().map(asked).chain(std::iter::once(stranger));
    assert_eq!(
        SpendPaths::new(&intent, batch_at(REFERENCE_HASH, &paid, added)).err(),
        Some(SpendPathsError::ExtraInput {
            global_index: NOT_SPENT
        })
    );
    let twice = std::iter::once(asked(&paid[0])).chain(paid.iter().map(asked));
    assert_eq!(
        SpendPaths::new(&intent, batch_at(REFERENCE_HASH, &paid, twice)).err(),
        Some(SpendPathsError::ExtraInput {
            global_index: INPUTS[0].0
        })
    );
}

/// A batch asked for in another order than the intent lists its inputs
/// is matched to the intent's order: the spend derived from it is the
/// spend derived from a batch in the intent's own order.
#[test]
fn a_batch_in_another_order_is_matched_to_the_intents_inputs() {
    let g = group();
    let intent = validated(&g, bytes32());
    let paid = pay(&g);
    let reversed = SpendPaths::new(
        &intent,
        batch_at(REFERENCE_HASH, &paid, paid.iter().rev().map(asked)),
    )
    .expect("the same inputs, in another order, match");
    let [a, b] = [reversed, spend(&intent, &paid)]
        .map(|paths| DerivedSpend::derive(paths, &ledger(&paid, 0), &g.key(), NET_ID).unwrap());
    assert_eq!(a.unsigned.outputs(), b.unsigned.outputs());
    assert!(a
        .inputs
        .iter()
        .zip(&b.inputs)
        .all(|(x, y)| x.key_image() == y.key_image() && x.path == y.path));
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
            DerivedSpend::derive(
                spend(&intent, &paid),
                &ledger(&paid, member),
                &g.key(),
                NET_ID,
            )
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
            assert_ne!(x.record.own_x25519_ct, y.record.own_x25519_ct);
        }
        assert!(a
            .inputs
            .windows(2)
            .all(|pair| pair[0].key_image().as_bytes() > pair[1].key_image().as_bytes()));

        let other = DerivedSpend::derive(
            spend(&validated(&g, bytes32()), &paid),
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
        let paid = pay(&g);
        let derived = DerivedSpend::derive(
            spend(&validated(&g, bytes32()), &paid),
            &ledger(&paid, 0),
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
    let paid = pay(&g);
    let derived = DerivedSpend::derive(
        spend(&validated(&g, seed), &paid),
        &ledger(&paid, 0),
        &g.key(),
        NET_ID,
    )
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
