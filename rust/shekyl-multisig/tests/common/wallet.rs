// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A member's wallet for the ceremony tests: the capabilities it injects,
//! in memory, the spend every member derives from one intent, and the
//! checks a node runs on the result, from the wire.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use rand_core::{OsRng, RngCore};

use super::{paths, random_scalar, GroupOutputs, AMOUNTS, NET};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use shekyl_address::multisig_address::{address_fingerprint, MultisigAddressPayload};
use shekyl_address::{Network, ShekylAddress, MSG_SIGN_PK_LEN};
use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation, X25519_KEM_CT_LEN};
use shekyl_crypto_pq::label::SENTINEL_PLAINTEXT;
use shekyl_crypto_pq::multisig::MultisigCommittedForm;
use shekyl_crypto_pq::signature::verify_pqc_auth;
use shekyl_fcmp::proof::{verify, ShekylFcmpProof};
use shekyl_fcmp::PqcKeyScalar;
use shekyl_multisig::ceremony::context::ContextError;
use shekyl_multisig::ceremony::nonce::{InputInUse, StoreError};
use shekyl_multisig::intent::{
    ChainStateFingerprint, IntentPayee, IntentRecipient, SpendIntent, SPEND_INTENT_VERSION,
};
use shekyl_multisig::{
    import, DerivedSpend, GroupOutput, HeldNonce, HeldNonceStore, Incoming, LedgerView,
    LiveCeremonies, MemberFile, NonceCounterError, NonceCounterSink, ProposerInputs,
    SigningContext, ValidatedIntent,
};
use shekyl_tx_weight::{predict_group_weight, GroupSize, GroupSpendShape, InputCount, OutputCount};
use shekyl_types::{BlockHash, KeyImage};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Ct, Input, Transaction};

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

/// The spend's outputs, in output order: a payment to a single-signer
/// address, and the change back to the paying group, the intent's sort
/// order (a single-signer recipient sorts first). With the fee they
/// balance the group's two inputs ([`AMOUNTS`]).
pub const PAYMENT: u64 = 800;
pub const CHANGE: u64 = 300;
pub const OUTPUT_AMOUNTS: [u64; 2] = [PAYMENT, CHANGE];

/// The single-signer address the spend pays: one per test binary, on the
/// group's network.
pub fn payee() -> &'static ShekylAddress {
    static PAYEE: OnceLock<ShekylAddress> = OnceLock::new();
    PAYEE.get_or_init(|| {
        let point = || {
            (&random_scalar() * ED25519_BASEPOINT_TABLE)
                .compress()
                .to_bytes()
        };
        let (kem, _) = HybridX25519MlKem.keypair_generate().unwrap();
        ShekylAddress::new(
            Network::Testnet,
            point(),
            point(),
            [0; MSG_SIGN_PK_LEN],
            kem.ml_kem,
        )
    })
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
                payee: IntentPayee::Single {
                    address: payee().encode().unwrap(),
                    label_plaintext: SENTINEL_PLAINTEXT,
                },
                amount: AtomicUnits::from_raw(PAYMENT),
            },
            IntentRecipient {
                payee: IntentPayee::Group {
                    address: address.to_canonical_bytes(),
                },
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
            network: address.network(),
            chain_tip_height: TIP,
            local_ref_block_hash: &REFERENCE_HASH,
            local_chain_state_fingerprint: &chain_fingerprint(),
            input_amounts: &AMOUNTS.map(AtomicUnits::from_raw),
            seen_kem_seeds: &HashSet::new(),
        },
    )
    .expect("the intent is valid for every member")
}

/// `file`'s ledger records of `paid`'s outputs, in payment order: the
/// scan every member shares, its own ciphertexts, and each output's global
/// index ([`GLOBAL_INDICES`]).
pub fn group_outputs(file: &MemberFile, paid: &GroupOutputs) -> Vec<GroupOutput> {
    let me = usize::from(file.member_index());
    paid.outputs
        .iter()
        .zip(&paid.scans)
        .zip(GLOBAL_INDICES)
        .map(|(((out, _, _), s), global_index)| {
            let (x25519, ml_kem) = out.member_kem_ciphertexts[me].split_at(X25519_KEM_CT_LEN);
            GroupOutput {
                global_index,
                output_key: out.output_key,
                commitment: out.commitment,
                spend_scalar: s.x.clone(),
                y_kem: s.y_kem.clone(),
                commitment_mask: s.z.clone(),
                key_image: s.key_image,
                committed_form: MultisigCommittedForm::from_bytes(&s.committed_form).unwrap(),
                own_x25519_ct: x25519.try_into().unwrap(),
                own_ml_kem_ct: ml_kem.to_vec(),
            }
        })
        .collect()
}

/// `file`'s spend of `intent`, derived from its own ledger.
pub fn derive(file: &MemberFile, intent: ValidatedIntent, paid: &GroupOutputs) -> DerivedSpend {
    DerivedSpend::derive(intent, group_outputs(file, paid), NET)
        .expect("every member derives the spend")
}

/// `file`'s context: its own derivation of the intent from its own ledger.
pub fn context<'a>(
    file: &'a MemberFile,
    intent: ValidatedIntent,
    paid: &GroupOutputs,
) -> SigningContext<'a> {
    try_context(file, intent, paid, paid.layers).expect("every member's context builds")
}

/// [`context`] under `layers` FCMP++ layers, refusals returned.
pub fn try_context<'a>(
    file: &'a MemberFile,
    intent: ValidatedIntent,
    paid: &GroupOutputs,
    layers: u8,
) -> Result<SigningContext<'a>, ContextError> {
    SigningContext::new(file, derive(file, intent, paid), paid.root, layers)
}

/// The proposer's own inputs. The leaf chunks are taken: the prover is
/// their only reader.
pub fn proposer_inputs(paid: &mut GroupOutputs) -> ProposerInputs {
    let chunks = std::mem::take(&mut paid.chunks);
    ProposerInputs {
        input_paths: paths(paid, chunks),
    }
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

/// The weight the wallet predicts for `group`'s spend of `paid` paying
/// the intent's recipients (a single-signer address and the group's
/// change) equals the signed spend's own `weight()`: the scheme-2 auths and
/// the change's `0x0D` entry are priced exactly (slice 4a §2.4).
pub fn assert_weight_predicted(
    tx: &Transaction,
    group: &MultisigAddressPayload,
    paid: &GroupOutputs,
) {
    let Ct::Fcmp { fee, .. } = &tx.ct else {
        panic!("an FCMP++ spend");
    };
    let signers = GroupSize::new(group.n_total(), group.m_required()).unwrap();
    let predicted = predict_group_weight(
        &GroupSpendShape {
            n_in: InputCount::clamped(tx.prefix.inputs.len()),
            n_out: OutputCount::clamped(tx.prefix.outputs.len()),
            tree_depth: paid.layers,
            signers,
            group_payees: &[signers],
        },
        *fee,
    );
    assert_eq!(predicted, Some(tx.weight()));
}

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
