// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Slice 3's gate (R-8): from member files and slice 1's outputs, an
//! in-process ceremony for 2-of-3 (no holder) and 3-of-5 (one holder),
//! each spending two group outputs, produces a transaction whose every
//! input passes `verify_multisig`, whose FCMP++ proof (SALs included)
//! verifies, and which survives the wire: serialized, parsed back, and
//! verified from the parsed bytes.
//!
//! Each member signs from its own context; files move only as bytes, and
//! every file is imported by the member that receives it.

mod common;

use std::collections::{HashMap, HashSet};

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use common::{found_group, pay_group_twice, random_scalar, GroupOutputs, NET};
use shekyl_address::multisig_address::{address_fingerprint, MultisigAddressPayload};
use shekyl_crypto_pq::multisig::MultisigCommittedForm;
use shekyl_crypto_pq::signature::verify_pqc_auth;
use shekyl_curve_primitives::Commitment;
use shekyl_fcmp::proof::{verify, ShekylFcmpProof};
use shekyl_fcmp::PqcKeyScalar;
use shekyl_multisig::ceremony::nonce::{InputInUse, StoreError};
use shekyl_multisig::intent::{
    ChainStateFingerprint, IntentRecipient, SpendIntent, SPEND_INTENT_VERSION,
};
use shekyl_multisig::{
    import, Cosigner, HeldNonce, HeldNonceStore, Holder, Incoming, InputContext, LedgerView,
    LiveCeremonies, MemberFile, NonceCounterError, NonceCounterSink, Proposer, ProposerInputs,
    Responder, ResponderInput, SigningContext, UnsignedSpend, ValidatedIntent,
};
use shekyl_types::BlockHash;
use shekyl_units::AtomicUnits;
use shekyl_wire::{Ct, CtBase, Input, Output, Transaction, TxPrefix};

// ---------------------------------------------------------------------------
// The capabilities a wallet injects, in memory
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Store(HashMap<[u8; 32], HeldNonce>);

impl HeldNonceStore for Store {
    fn put(&mut self, nonce: HeldNonce) -> Result<(), StoreError> {
        if self.0.contains_key(nonce.intent_hash()) {
            return Err(StoreError::AlreadyHeld);
        }
        self.0.insert(*nonce.intent_hash(), nonce);
        Ok(())
    }

    fn take(&mut self, intent_hash: &[u8; 32]) -> Result<Option<HeldNonce>, StoreError> {
        Ok(self.0.remove(intent_hash))
    }
}

#[derive(Default)]
struct Sink {
    persisted: Vec<([u8; 32], u64)>,
}

impl NonceCounterSink for Sink {
    fn next_nonce_counter(&self) -> u64 {
        self.persisted.last().map_or(0, |(_, c)| c + 1)
    }

    fn persist_nonce_counter(
        &mut self,
        intent_hash: &[u8; 32],
        counter: u64,
    ) -> Result<(), NonceCounterError> {
        self.persisted.push((*intent_hash, counter));
        Ok(())
    }
}

#[derive(Default)]
struct Live(HashMap<u64, [u8; 32]>);

impl LiveCeremonies for Live {
    fn reserve(&mut self, intent_hash: &[u8; 32], inputs: &[u64]) -> Result<(), InputInUse> {
        if let Some(&input) = inputs
            .iter()
            .find(|i| self.0.get(i).is_some_and(|h| h != intent_hash))
        {
            return Err(InputInUse { input });
        }
        for &input in inputs {
            self.0.insert(input, *intent_hash);
        }
        Ok(())
    }
}

/// One member's wallet: its file and its injected capabilities.
struct Wallet {
    file: MemberFile,
    store: Store,
    sink: Sink,
    live: Live,
}

// ---------------------------------------------------------------------------
// The spend every member derives from the intent
// ---------------------------------------------------------------------------

const REFERENCE_HEIGHT: u64 = 1_000;
const TIP: u64 = 1_005;
const REFERENCE_HASH: [u8; 32] = [0x77; 32];
const FEE: u64 = 100;
const PAID: u64 = 1_100;
const GLOBAL_INDICES: [u64; 2] = [10, 11];

/// What slice 4a derives from the intent and every member derives alike:
/// the unsigned transaction, each input's pseudo-out blind and
/// rerandomization seed, and the output's mask.
struct Derived {
    unsigned: UnsignedSpend,
    blinds: [[u8; 32]; 2],
    seeds: [[u8; 32]; 2],
    out_mask: [u8; 32],
}

fn derive(paid: &GroupOutputs) -> Derived {
    let out_mask = random_scalar();
    let a0 = random_scalar();
    let a1 = out_mask - a0;
    let mut seeds = [[0u8; 32]; 2];
    for seed in &mut seeds {
        OsRng.fill_bytes(seed);
    }
    let mut output_key = [0u8; 32];
    output_key.copy_from_slice(
        &(curve25519_dalek::constants::ED25519_BASEPOINT_POINT * random_scalar())
            .compress()
            .to_bytes(),
    );
    let commitment = Commitment::new(out_mask, PAID)
        .calculate()
        .compress()
        .to_bytes();
    let unsigned = UnsignedSpend {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: paid
                .scans
                .iter()
                .map(|s| Input::ToKey {
                    amount: 0,
                    key_offsets: Vec::new(),
                    key_image: *s.key_image.as_bytes(),
                })
                .collect(),
            outputs: vec![Output {
                amount: 0,
                key: output_key,
                view_tag: 0,
            }],
            extra: Vec::new(),
        },
        fee: FEE,
        reference_block: BlockHash::from_bytes(REFERENCE_HASH),
        base: CtBase {
            enc_amounts: vec![[0x11; 9]],
            enc_labels: vec![[0x22; 9]],
            commitments: vec![commitment],
        },
    };
    Derived {
        unsigned,
        blinds: [a0.to_bytes(), a1.to_bytes()],
        seeds,
        out_mask: out_mask.to_bytes(),
    }
}

fn chain_fingerprint() -> [u8; 32] {
    ChainStateFingerprint {
        reference_block_hash: REFERENCE_HASH,
        input_global_indices: GLOBAL_INDICES.to_vec(),
        input_eligible_heights: vec![900, 900],
        input_amounts: vec![AtomicUnits::from_raw(500), AtomicUnits::from_raw(700)],
    }
    .compute()
}

fn intent(
    address: &MultisigAddressPayload,
    proposer: u8,
    signers: &[u8],
    responder: u8,
) -> SpendIntent {
    let mut intent_id = [0u8; 32];
    OsRng.fill_bytes(&mut intent_id);
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    SpendIntent {
        version: SPEND_INTENT_VERSION,
        intent_id,
        address_fingerprint: address_fingerprint(address),
        proposer_index: proposer,
        signers: signers.to_vec(),
        responder_index: responder,
        created_at: 0,
        reference_block_height: REFERENCE_HEIGHT,
        reference_block_hash: REFERENCE_HASH,
        recipients: vec![IntentRecipient {
            address: vec![0x5A; 8],
            amount: AtomicUnits::from_raw(PAID),
        }],
        fee: AtomicUnits::from_raw(FEE),
        input_global_indices: GLOBAL_INDICES.to_vec(),
        kem_randomness_seed: seed,
        chain_state_fingerprint: chain_fingerprint(),
    }
}

/// `file`'s check of `intent` against its own ledger.
fn validate(file: &MemberFile, intent: SpendIntent) -> ValidatedIntent {
    let address = file.address();
    ValidatedIntent::validate(
        intent,
        &LedgerView {
            our_address_fingerprint: &address_fingerprint(address),
            n_total: address.n_total(),
            m_required: address.m_required(),
            chain_tip_height: TIP,
            local_ref_block_hash: &REFERENCE_HASH,
            local_chain_state_fingerprint: &chain_fingerprint(),
            input_amounts: &[AtomicUnits::from_raw(500), AtomicUnits::from_raw(700)],
            seen_kem_seeds: &HashSet::new(),
        },
    )
    .expect("the intent is valid for every member")
}

/// `file`'s context: its own scans and ciphertexts, the shared derivation.
fn context<'a>(
    file: &'a MemberFile,
    intent: ValidatedIntent,
    paid: &GroupOutputs,
    derived: &Derived,
) -> SigningContext<'a> {
    let me = usize::from(file.member_index());
    let inputs = paid
        .outputs
        .iter()
        .zip(&paid.scans)
        .enumerate()
        .map(|(i, ((out, _, _), s))| {
            let (x25519, ml_kem) = out.member_kem_ciphertexts[me].split_at(32);
            InputContext {
                output_key: out.output_key,
                commitment: out.commitment,
                spend_scalar: s.x.clone(),
                y_kem: s.y_kem.clone(),
                commitment_mask: s.z.clone(),
                pseudo_out_blind: Zeroizing::new(derived.blinds[i]),
                rerandomization_seed: Zeroizing::new(derived.seeds[i]),
                key_image: s.key_image,
                committed_form: MultisigCommittedForm::from_bytes(&s.committed_form).unwrap(),
                own_x25519_ct: x25519.try_into().unwrap(),
                own_ml_kem_ct: ml_kem.to_vec(),
            }
        })
        .collect();
    SigningContext::new(
        file,
        NET,
        intent,
        inputs,
        derived.unsigned.clone(),
        paid.root,
        paid.layers,
    )
    .expect("every member's context builds")
}

/// The proposer's own inputs. The leaf chunks are taken: the prover is
/// their only reader.
fn proposer_inputs(paid: &mut GroupOutputs, derived: &Derived) -> ProposerInputs {
    ProposerInputs {
        outputs: vec![(PAID, Zeroizing::new(derived.out_mask))],
        leaf_chunks: std::mem::take(&mut paid.chunks),
    }
}

fn import_into(wallet: &Wallet, file: &[u8]) -> Incoming {
    import(&[&wallet.file], &NET, file)
        .expect("the file opens for its group")
        .1
}

macro_rules! expect {
    ($incoming:expr, $variant:ident) => {
        match $incoming {
            Incoming::$variant(a) => a,
            _ => panic!(concat!("expected a ", stringify!($variant))),
        }
    };
}

// ---------------------------------------------------------------------------
// The checks a node runs, from the wire
// ---------------------------------------------------------------------------

/// Serialize, parse back, and verify every input's authorization and the
/// FCMP++ proof from the parsed bytes alone.
fn verify_from_the_wire(tx: &Transaction, paid: &GroupOutputs) {
    let parsed = Transaction::from_bytes(&tx.serialize()).expect("the transaction parses");
    assert_eq!(parsed, *tx);
    let hashes = parsed.pqc_signing_payload_hashes(&NET);
    let Ct::Fcmp {
        pqc_auths,
        prunable: Some(prunable),
        ..
    } = &parsed.ct
    else {
        panic!("an FCMP++ spend");
    };
    assert_eq!(hashes.len(), pqc_auths.len());
    for (auth, hash) in pqc_auths.iter().zip(&hashes) {
        assert_eq!(auth.scheme_id, 2);
        verify_pqc_auth(
            auth.scheme_id,
            &auth.hybrid_public_key,
            &auth.hybrid_signature,
            hash,
            &NET,
        )
        .expect("every input's multisig authorization verifies");
    }
    let key_images: Vec<_> = paid.scans.iter().map(|s| s.key_image).collect();
    let pqc_keys: Vec<PqcKeyScalar> = pqc_auths
        .iter()
        .map(|a| PqcKeyScalar::from_pqc_auth(a.scheme_id, &a.hybrid_public_key).unwrap())
        .collect();
    let verified = verify(
        &ShekylFcmpProof {
            data: prunable.fcmp_proof.clone(),
            num_inputs: 2,
            tree_depth: paid.layers,
        },
        &key_images,
        &prunable.pseudo_outs,
        &pqc_keys,
        &paid.root,
        paid.layers,
        parsed.tx_signable(&NET),
    );
    assert!(matches!(verified, Ok(true)), "{verified:?}");
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// 2-of-3, no holder: files 1, 4, 8, 9.
#[test]
fn two_of_three_spends_two_group_outputs() {
    let (address, files) = found_group(3, 2);
    let mut paid = pay_group_twice(&address, &files);
    let derived = derive(&paid);
    let [a, _, b]: [MemberFile; 3] = files.try_into().ok().unwrap();
    let mut a = Wallet {
        file: a,
        store: Store::default(),
        sink: Sink::default(),
        live: Live::default(),
    };
    let mut b = Wallet {
        file: b,
        store: Store::default(),
        sink: Sink::default(),
        live: Live::default(),
    };
    let intent = intent(&address, 0, &[0, 2], 2);

    // 1: A proposes.
    let ctx_a = context(&a.file, validate(&a.file, intent.clone()), &paid, &derived);
    let (proposer, proposal) = Proposer::propose(
        ctx_a,
        proposer_inputs(&mut paid, &derived),
        &mut a.store,
        &mut a.live,
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(proposer.responder_file(&mut OsRng).unwrap(), proposal);

    // 4: B approves the intent it received, and responds in one call.
    let at_b = expect!(import_into(&b, &proposal), Proposal);
    let ctx_b = context(
        &b.file,
        validate(&b.file, at_b.body().intent.clone()),
        &paid,
        &derived,
    );
    let response = Responder::respond(
        &ctx_b,
        ResponderInput::Proposal(&at_b),
        &mut b.live,
        &mut OsRng,
    )
    .unwrap();
    assert!(b.store.0.is_empty(), "the responder holds no nonce");

    // 7, 8: A completes, proves and sends the FinalTx.
    let proposer = proposer
        .responder_share(expect!(import_into(&a, &response), ResponderShare))
        .unwrap();
    assert!(proposer.holders_file(&mut OsRng).unwrap().is_none());
    let (proposer, final_tx) = proposer
        .finish(&mut a.store, &mut a.sink, &mut OsRng)
        .unwrap();
    assert!(a.store.0.is_empty(), "the proposer's nonce is consumed");
    assert_eq!(a.sink.persisted.len(), 1);

    // 9: B builds the transaction itself and signs it.
    let hybrid = Cosigner::sign_final_tx(
        &ctx_b,
        &expect!(import_into(&b, &final_tx), FinalTx),
        &mut OsRng,
    )
    .unwrap();

    // 10: A assembles, verifies and releases.
    let tx = proposer
        .hybrid_sig(&expect!(import_into(&a, &hybrid), HybridSig))
        .unwrap()
        .release()
        .unwrap();
    verify_from_the_wire(&tx, &paid);
}

/// 3-of-5, one holder: every file of the table.
#[test]
fn three_of_five_spends_two_group_outputs() {
    let (address, files) = found_group(5, 3);
    let mut paid = pay_group_twice(&address, &files);
    let derived = derive(&paid);
    let mut files: Vec<Option<MemberFile>> = files.into_iter().map(Some).collect();
    let mut wallet = |i: usize| Wallet {
        file: files[i].take().unwrap(),
        store: Store::default(),
        sink: Sink::default(),
        live: Live::default(),
    };
    let (mut a, mut h, mut b) = (wallet(1), wallet(3), wallet(4));
    let intent = intent(&address, 1, &[1, 3, 4], 4);

    // 1: A proposes; the holder receives it.
    let ctx_a = context(&a.file, validate(&a.file, intent.clone()), &paid, &derived);
    let (proposer, proposal) = Proposer::propose(
        ctx_a,
        proposer_inputs(&mut paid, &derived),
        &mut a.store,
        &mut a.live,
        &mut OsRng,
    )
    .unwrap();

    // 2: the holder commits.
    let at_h = expect!(import_into(&h, &proposal), Proposal);
    let ctx_h = context(
        &h.file,
        validate(&h.file, at_h.body().intent.clone()),
        &paid,
        &derived,
    );
    let (holder, commitment) =
        Holder::commit(ctx_h, &at_h, &mut h.store, &mut h.live, &mut OsRng).unwrap();
    assert_eq!(h.store.0.len(), 1, "the holder holds its nonce");

    // 3: A forwards the proposal and the commitment to B.
    let proposer = proposer
        .commitment(expect!(import_into(&a, &commitment), Commitment))
        .unwrap();
    let to_b = proposer.responder_file(&mut OsRng).unwrap();

    // 4: B responds.
    let at_b = expect!(import_into(&b, &to_b), SigningSet);
    let proposal_at_b = expect!(import_into(&b, &at_b.body().files[0]), Proposal);
    let ctx_b = context(
        &b.file,
        validate(&b.file, proposal_at_b.body().intent.clone()),
        &paid,
        &derived,
    );
    let response = Responder::respond(
        &ctx_b,
        ResponderInput::SigningSet(&at_b),
        &mut b.live,
        &mut OsRng,
    )
    .unwrap();

    // 5: A forwards everything to the holder.
    let proposer = proposer
        .responder_share(expect!(import_into(&a, &response), ResponderShare))
        .unwrap();
    let to_h = proposer.holders_file(&mut OsRng).unwrap().unwrap();

    // 6: the holder signs.
    let share = holder
        .sign(
            &expect!(import_into(&h, &to_h), SigningSet),
            &mut h.store,
            &mut h.sink,
            &mut OsRng,
        )
        .unwrap();
    assert!(h.store.0.is_empty(), "the holder's nonce is consumed");

    // 7, 8: A completes and sends the FinalTx.
    let (proposer, final_tx) = proposer
        .holder_share(expect!(import_into(&a, &share), SignatureShare))
        .unwrap()
        .finish(&mut a.store, &mut a.sink, &mut OsRng)
        .unwrap();

    // 9: B and the holder each build the transaction and sign.
    let ctx_h2 = context(&h.file, validate(&h.file, intent.clone()), &paid, &derived);
    let from_h = Cosigner::sign_final_tx(
        &ctx_h2,
        &expect!(import_into(&h, &final_tx), FinalTx),
        &mut OsRng,
    )
    .unwrap();
    let from_b = Cosigner::sign_final_tx(
        &ctx_b,
        &expect!(import_into(&b, &final_tx), FinalTx),
        &mut OsRng,
    )
    .unwrap();

    // 10: A releases.
    let tx = proposer
        .hybrid_sig(&expect!(import_into(&a, &from_h), HybridSig))
        .unwrap()
        .hybrid_sig(&expect!(import_into(&a, &from_b), HybridSig))
        .unwrap()
        .release()
        .unwrap();
    verify_from_the_wire(&tx, &paid);
}
