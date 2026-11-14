// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A member's wallet for the ceremony tests: the capabilities it injects,
//! in memory, the spend every member derives from one intent, and the
//! checks a node runs on the result, from the wire.

use std::collections::{HashMap, HashSet};

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use super::{found_group, paths, random_scalar, GroupOutputs, AMOUNTS, NET};
use curve25519_dalek::Scalar as DalekScalar;
use shekyl_address::multisig_address::{address_fingerprint, MultisigAddressPayload};
use shekyl_crypto_pq::kem::X25519_KEM_CT_LEN;
use shekyl_crypto_pq::multisig::MultisigCommittedForm;
use shekyl_crypto_pq::multisig_output::{construct_multisig_output, MultisigOutputData};
use shekyl_crypto_pq::signature::verify_pqc_auth;
use shekyl_curve_primitives::Commitment;
use shekyl_fcmp::proof::{verify, ShekylFcmpProof};
use shekyl_fcmp::PqcKeyScalar;
use shekyl_multisig::ceremony::context::ContextError;
use shekyl_multisig::ceremony::nonce::{InputInUse, StoreError};
use shekyl_multisig::intent::{
    ChainStateFingerprint, IntentRecipient, SpendIntent, SPEND_INTENT_VERSION,
};
use shekyl_multisig::{
    import, HeldNonce, HeldNonceStore, Incoming, InputContext, LedgerView, LiveCeremonies,
    MemberFile, NonceCounterError, NonceCounterSink, ProposerInputs, SigningContext, UnsignedSpend,
    ValidatedIntent,
};
use shekyl_types::{BlockHash, KeyImage};
use shekyl_units::AtomicUnits;
use shekyl_wire::tx_extra::{self, KemCiphertext, MultisigEntry, TxExtraField};
use shekyl_wire::{Ct, CtBase, Input, Output, Transaction};

// ---------------------------------------------------------------------------
// The capabilities a wallet injects, in memory
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Store(pub HashMap<[u8; 32], HeldNonce>);

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

/// The durable nonce counter. A failing sink refuses every persist, as a
/// full disk or a failed fsync does.
#[derive(Default)]
pub struct Sink {
    pub persisted: Vec<([u8; 32], u64)>,
    pub failing: bool,
}

impl Sink {
    /// A sink whose every persist fails.
    pub fn failing() -> Self {
        Self {
            failing: true,
            ..Self::default()
        }
    }
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
        if self.failing {
            return Err(NonceCounterError("the counter write failed".into()));
        }
        self.persisted.push((*intent_hash, counter));
        Ok(())
    }
}

#[derive(Default)]
pub struct Live(pub HashMap<u64, [u8; 32]>);

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
pub struct Wallet {
    pub file: MemberFile,
    pub store: Store,
    pub sink: Sink,
    pub live: Live,
}

// ---------------------------------------------------------------------------
// The spend every member derives from the intent
// ---------------------------------------------------------------------------

pub const REFERENCE_HEIGHT: u64 = 1_000;
pub const TIP: u64 = 1_005;
pub const REFERENCE_HASH: [u8; 32] = [0x77; 32];
pub const FEE: u64 = 100;
pub const GLOBAL_INDICES: [u64; 2] = [10, 11];

/// The spend's outputs, in output order: a payment to another group, and
/// the change back to the paying group. With the fee they balance the
/// group's two inputs ([`AMOUNTS`]).
pub const PAYMENT: u64 = 800;
pub const CHANGE: u64 = 300;
pub const OUTPUT_AMOUNTS: [u64; 2] = [PAYMENT, CHANGE];
/// The intent's recipients for them, in the intent's sort order.
pub const PAYEE_ADDRESS: [u8; 8] = [0x5A; 8];
pub const CHANGE_ADDRESS: [u8; 8] = [0x6B; 8];

/// What slice 4a derives from the intent and every member derives alike:
/// the outputs and their fields, each input's pseudo-out blind and
/// rerandomization seed, and each output's mask.
pub struct Derived {
    pub unsigned: UnsignedSpend,
    pub blinds: [[u8; 32]; 2],
    pub seeds: [[u8; 32]; 2],
    pub out_masks: Vec<[u8; 32]>,
}

/// A spend of `group`'s two outputs: its outputs built by the production
/// constructor and carried in `tx_extra` as the chain carries them, its
/// pseudo-out blinds balancing the outputs' masks.
pub fn derive(group: &MultisigAddressPayload) -> Derived {
    let (payee, _) = found_group(2, 2);
    let tx_key = random_scalar().to_bytes();
    let outputs: Vec<MultisigOutputData> = [&payee, group]
        .into_iter()
        .zip(OUTPUT_AMOUNTS)
        .zip(0u64..)
        .map(|((address, amount), index)| {
            construct_multisig_output(&tx_key, address, amount, index, &NET).unwrap()
        })
        .collect();
    let out_masks: Vec<[u8; 32]> = outputs.iter().map(|out| out.z).collect();
    let mask_sum: DalekScalar = out_masks
        .iter()
        .map(|z| DalekScalar::from_canonical_bytes(*z).unwrap())
        .sum();
    let a0 = random_scalar();
    let a1 = mask_sum - a0;
    let mut seeds = [[0u8; 32]; 2];
    for seed in &mut seeds {
        OsRng.fill_bytes(seed);
    }
    let unsigned = UnsignedSpend {
        outputs: outputs
            .iter()
            .map(|out| Output {
                amount: 0,
                key: out.output_key,
                view_tag: out.view_tag_prefilter,
            })
            .collect(),
        extra: extra_of(&outputs),
        base: CtBase {
            enc_amounts: outputs
                .iter()
                .map(|o| o.enc_amount_wire().to_bytes())
                .collect(),
            enc_labels: outputs
                .iter()
                .map(|o| o.enc_label_wire().to_bytes())
                .collect(),
            commitments: outputs.iter().map(|o| o.commitment).collect(),
        },
    };
    Derived {
        unsigned,
        blinds: [a0.to_bytes(), a1.to_bytes()],
        seeds,
        out_masks,
    }
}

/// `tx_extra` for `outputs`, each paying a group: the `0x06` ciphertexts,
/// the `0x07` leaf entries and the `0x0D` member entries.
fn extra_of(outputs: &[MultisigOutputData]) -> Vec<u8> {
    let kem = outputs
        .iter()
        .flat_map(|o| [o.kem_ciphertext_x25519.as_slice(), &o.kem_ciphertext_ml_kem])
        .flatten()
        .copied()
        .collect();
    let leaf = outputs
        .iter()
        .flat_map(|o| o.pqc_leaf.entry_bytes())
        .collect();
    let entries = outputs
        .iter()
        .zip(0u8..)
        .map(|(o, out_idx)| {
            MultisigEntry::new(
                out_idx,
                o.member_kem_ciphertexts
                    .iter()
                    .map(|ct| KemCiphertext::from_bytes(ct.as_slice().try_into().unwrap()))
                    .collect(),
                o.enc_key_hashes.clone(),
            )
            .unwrap()
        })
        .collect();
    tx_extra::serialize(&[
        TxExtraField::PqcKemCiphertext(kem),
        TxExtraField::PqcLeafEntries(leaf),
        TxExtraField::PqcMultisig(entries),
    ])
    .unwrap()
}

pub fn chain_fingerprint() -> [u8; 32] {
    ChainStateFingerprint {
        reference_block_hash: REFERENCE_HASH,
        input_global_indices: GLOBAL_INDICES.to_vec(),
        input_eligible_heights: vec![900, 900],
        input_amounts: AMOUNTS.map(AtomicUnits::from_raw).to_vec(),
    }
    .compute()
}

pub fn intent(
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
        recipients: vec![
            IntentRecipient {
                address: PAYEE_ADDRESS.to_vec(),
                amount: AtomicUnits::from_raw(PAYMENT),
            },
            IntentRecipient {
                address: CHANGE_ADDRESS.to_vec(),
                amount: AtomicUnits::from_raw(CHANGE),
            },
        ],
        fee: AtomicUnits::from_raw(FEE),
        input_global_indices: GLOBAL_INDICES.to_vec(),
        kem_randomness_seed: seed,
        chain_state_fingerprint: chain_fingerprint(),
    }
}

/// `file`'s check of `intent` against its own ledger.
pub fn validate(file: &MemberFile, intent: SpendIntent) -> ValidatedIntent {
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
            input_amounts: &AMOUNTS.map(AtomicUnits::from_raw),
            seen_kem_seeds: &HashSet::new(),
        },
    )
    .expect("the intent is valid for every member")
}

/// `file`'s context: its own scans and ciphertexts, the shared derivation.
pub fn context<'a>(
    file: &'a MemberFile,
    intent: ValidatedIntent,
    paid: &GroupOutputs,
    derived: &Derived,
) -> SigningContext<'a> {
    try_context(file, intent, paid, derived, paid.layers).expect("every member's context builds")
}

/// [`context`] under `layers` FCMP++ layers, refusals returned.
pub fn try_context<'a>(
    file: &'a MemberFile,
    intent: ValidatedIntent,
    paid: &GroupOutputs,
    derived: &Derived,
    layers: u8,
) -> Result<SigningContext<'a>, ContextError> {
    SigningContext::new(
        file,
        NET,
        intent,
        input_contexts(file, paid, derived),
        derived.unsigned.clone(),
        paid.root,
        layers,
    )
}

/// `file`'s view of each input, in payment order: its own scans and
/// ciphertexts, and the shared derivation.
pub fn input_contexts(
    file: &MemberFile,
    paid: &GroupOutputs,
    derived: &Derived,
) -> Vec<InputContext> {
    let me = usize::from(file.member_index());
    paid.outputs
        .iter()
        .zip(&paid.scans)
        .enumerate()
        .map(|(i, ((out, _, _), s))| {
            let (x25519, ml_kem) = out.member_kem_ciphertexts[me].split_at(X25519_KEM_CT_LEN);
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
        .collect()
}

/// The proposer's own inputs. The leaf chunks are taken: the prover is
/// their only reader.
pub fn proposer_inputs(paid: &mut GroupOutputs, derived: &Derived) -> ProposerInputs {
    let chunks = std::mem::take(&mut paid.chunks);
    ProposerInputs {
        output_openings: openings(derived),
        input_paths: paths(paid, chunks),
    }
}

/// Each output's opening, in output order.
pub fn openings(derived: &Derived) -> Vec<Commitment> {
    derived
        .out_masks
        .iter()
        .zip(OUTPUT_AMOUNTS)
        .map(|(mask, amount)| Commitment::from_canonical_mask(mask, amount).unwrap())
        .collect()
}

pub fn import_into(wallet: &Wallet, file: &[u8]) -> Incoming {
    import_for(&wallet.file, file)
}

/// `bytes`, imported by the member whose file is `member`.
pub fn import_for(member: &MemberFile, bytes: &[u8]) -> Incoming {
    import(&[member], &NET, bytes)
        .expect("the file opens for its group")
        .1
}

#[macro_export]
macro_rules! expect {
    ($incoming:expr, $variant:ident) => {
        match $incoming {
            shekyl_multisig::Incoming::$variant(a) => a,
            _ => panic!(concat!("expected a ", stringify!($variant))),
        }
    };
}

// ---------------------------------------------------------------------------
// The checks a node runs, from the wire
// ---------------------------------------------------------------------------

/// Serialize, parse back, and check from the parsed bytes alone: the
/// structural rules the pool applies first, the intent's fee and reference
/// block, every input's authorization, and the FCMP++ proof.
pub fn verify_from_the_wire(tx: &Transaction, paid: &GroupOutputs) {
    let parsed = Transaction::from_bytes(&tx.serialize()).expect("the transaction parses");
    assert_eq!(parsed, *tx);
    parsed.validate().expect("the transaction is well formed");
    let hashes = parsed.pqc_signing_payload_hashes(&NET);
    let Ct::Fcmp {
        fee,
        reference_block,
        pqc_auths,
        prunable: Some(prunable),
        ..
    } = &parsed.ct
    else {
        panic!("an FCMP++ spend");
    };
    assert_eq!(*fee, FEE);
    assert_eq!(*reference_block, BlockHash::from_bytes(REFERENCE_HASH));
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
    let key_images: Vec<KeyImage> = parsed
        .prefix
        .inputs
        .iter()
        .map(|input| match input {
            Input::ToKey { key_image, .. } => KeyImage::from_bytes(*key_image),
            _ => panic!("a spend's inputs are key-imaged"),
        })
        .collect();
    let pqc_keys: Vec<PqcKeyScalar> = pqc_auths
        .iter()
        .map(|a| PqcKeyScalar::from_pqc_auth(a.scheme_id, &a.hybrid_public_key).unwrap())
        .collect();
    let verified = verify(
        &ShekylFcmpProof {
            data: prunable.fcmp_proof.clone(),
            num_inputs: u32::try_from(key_images.len()).unwrap(),
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

impl Wallet {
    /// A wallet over `file`, with empty stores.
    pub fn new(file: MemberFile) -> Self {
        Self {
            file,
            store: Store::default(),
            sink: Sink::default(),
            live: Live::default(),
        }
    }
}
