// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared fixtures for the submit-engine test suites: synthetic
//! transactions with **valid key images** (real prime-order points, unlike
//! `shekyl-wire`'s serializer fixtures), admitting fact snapshots, and the
//! deterministic [`SubmitStateShim`] / [`TxVerifier`] mocks the design doc
//! names as the race suite's substrate
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md` §10 item 2).

#![allow(dead_code)] // each test binary uses a subset

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use shekyl_daemon_rpc::submit::{
    CommitOutcome, KeyImageConflict, ParsedSubmission, ReferenceFacts, ShimFault, SubmitFacts,
    SubmitStateShim, TxMeta, TxVerifier, VerificationCertificate, VerifyFailure,
};
use shekyl_types::{BlockHash, BlockHeight, ChainCount, TxHash};
use shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN;
use shekyl_wire::{
    BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, ServeCredit, Transaction, TxPrefix,
};

/// The curve-tree root the fixture facts report at the reference height.
pub const FIXTURE_ROOT: [u8; 32] = [0xAA; 32];
/// The fixture reference-block hash carried by the synthetic spends.
pub const FIXTURE_REF_BLOCK: [u8; 32] = [0x44; 32];

/// `n` valid key images — distinct prime-order, non-identity points
/// (basepoint multiples), ordered **strictly descending** by compressed
/// bytes as `Transaction::validate` requires (§12).
pub fn valid_key_images(n: usize) -> Vec<[u8; 32]> {
    let mut images = Vec::with_capacity(n);
    let mut point = ED25519_BASEPOINT_POINT;
    for _ in 0..n {
        images.push(point.compress().to_bytes());
        point += ED25519_BASEPOINT_POINT;
    }
    images.sort_unstable();
    images.reverse();
    images
}

fn pqc_auth() -> PqcAuth {
    PqcAuth {
        auth_version: 1,
        scheme_id: 1,
        flags: 0,
        hybrid_public_key: vec![0xAB; PQC_HYBRID_SINGLE_KEY_LEN],
        hybrid_signature: vec![0xCD; 3385],
    }
}

fn bp_plus() -> BpPlus {
    BpPlus {
        a: [0x10; 32],
        a1: [0x11; 32],
        b: [0x12; 32],
        r1: [0x13; 32],
        s1: [0x14; 32],
        d1: [0x15; 32],
        l: vec![[0x20; 32]; 7],
        r: vec![[0x21; 32]; 7],
    }
}

fn two_outputs_base() -> (Vec<Output>, CtBase) {
    let outputs = vec![
        Output {
            amount: 0,
            key: [0x22; 32],
            view_tag: 7,
        },
        Output {
            amount: 0,
            key: [0x33; 32],
            view_tag: 9,
        },
    ];
    let base = CtBase {
        enc_amounts: vec![[1u8; 9], [2u8; 9]],
        enc_labels: vec![[3u8; 9], [4u8; 9]],
        commitments: vec![[5u8; 32], [6u8; 32]],
    };
    (outputs, base)
}

/// A structurally valid FCMP++ spend over the given key images (vin
/// order): per-input pqc_auths and pseudo-outs, one Bp+, two outputs,
/// non-empty proof bytes. Passes `Transaction::validate()` and every
/// Phase-A static.
pub fn spend_tx_with_kis(key_images: &[[u8; 32]], fee: u64) -> Transaction {
    let (outputs, base) = two_outputs_base();
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: key_images
                .iter()
                .map(|ki| Input::ToKey {
                    amount: 0,
                    key_offsets: vec![],
                    key_image: *ki,
                })
                .collect(),
            outputs,
            extra: vec![0x06, 0xAA, 0xBB, 0xCC],
        },
        ct: Ct::Fcmp {
            fee,
            reference_block: FIXTURE_REF_BLOCK,
            base,
            pqc_auths: key_images.iter().map(|_| pqc_auth()).collect(),
            prunable: Some(Prunable {
                bulletproofs: vec![bp_plus()],
                tree_depth: 3,
                fcmp_proof: vec![0xEF; 2500],
                pseudo_outs: key_images.iter().map(|_| [0x30; 32]).collect(),
            }),
        },
    }
}

/// The default 2-input spend fixture.
pub fn spend_tx(fee: u64) -> Transaction {
    spend_tx_with_kis(&valid_key_images(2), fee)
}

/// A fee-only serve-credit tx (all-serve-credit vin, no outputs, empty
/// pqc_auths, no prunable) — `fee` is parameterized so the zero-fee
/// consensus static can be exercised from both sides.
pub fn serve_credit_tx(fee: u64) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ServeCredit(Box::new(ServeCredit {
                p_canonical_id: [0x11; 32],
                shard_id: 7,
                settlement_epoch: 42,
                segment_subroot_rk: [0x22; 32],
                leaf_index_in_segment: 0x0403_0201,
                leaf_bytes: [0x33; 128],
                c1_layers: vec![vec![[0x44; 32], [0x45; 32]], vec![[0x46; 32]]],
                c2_layers: vec![vec![[0x55; 32]]],
                hybrid_signature: vec![0x66; 3385],
            }))],
            outputs: vec![],
            extra: vec![],
        },
        ct: Ct::Fcmp {
            fee,
            reference_block: [0u8; 32],
            base: CtBase {
                enc_amounts: vec![],
                enc_labels: vec![],
                commitments: vec![],
            },
            pqc_auths: vec![],
            prunable: None,
        },
    }
}

/// A synthetic-but-decodable emission vin (the retention `emission_wire`
/// sample-vin shape: canonical key/sig lengths, strictly increasing epochs,
/// aligned per-epoch claims) serialized to `canonical_bytes`.
pub fn emission_vin_bytes() -> Vec<u8> {
    use shekyl_archival_retention::{
        ArchivalRewardEmissionVin, HoldingsDescriptor, HoldingsKind, MembershipOnlyBacking,
        ShardSet, ShardWorkEntry, WorkEpochClaim,
    };
    use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};
    let vin = ArchivalRewardEmissionVin {
        p_pubkey: vec![0xA1; SINGLE_KEY_CANONICAL_LEN],
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
        },
        settlement_epochs: vec![11, 12],
        work_claim: vec![
            WorkEpochClaim {
                epoch: 11,
                shard_entries: vec![ShardWorkEntry {
                    shard_id: 7,
                    serve_credit_bit: true,
                    scarcity_micro: 850_000,
                }],
            },
            WorkEpochClaim {
                epoch: 12,
                shard_entries: vec![],
            },
        ],
        backing: MembershipOnlyBacking {
            proof: vec![0xEE; 512],
            pseudo_out: [0x22; 32],
            pqc_pk_hash: [0x33; 32],
            backing_pubkey: vec![0xB2; SINGLE_KEY_CANONICAL_LEN],
            tree_depth: 3,
        },
        reward_amount_plain: vec![1_000_000, 2_000_000],
        auth_backing: vec![0xC3; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0xD4; SINGLE_SIG_CANONICAL_LEN],
    };
    vin.serialize().expect("sample emission vin serializes")
}

/// An emission-shaped tx that clears Phase A: the decodable emission vin,
/// one `ToKey` fee input, one loud reward vout + one confidential change
/// vout, per-slot pqc_auths, `pseudoOuts == ToKey subset`, non-empty
/// FCMP++ proof.
pub fn emission_tx(fee: u64) -> Transaction {
    let ki = valid_key_images(1);
    let (mut outputs, base) = two_outputs_base();
    // One loud reward vout (EV3's non-zero sum static).
    outputs[0].amount = 3_000_000;
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![
                Input::ToKey {
                    amount: 0,
                    key_offsets: vec![],
                    key_image: ki[0],
                },
                Input::ArchivalRewardEmission {
                    canonical_bytes: emission_vin_bytes(),
                },
            ],
            outputs,
            extra: vec![],
        },
        ct: Ct::Fcmp {
            fee,
            reference_block: FIXTURE_REF_BLOCK,
            base,
            pqc_auths: vec![pqc_auth(), pqc_auth()],
            prunable: Some(Prunable {
                bulletproofs: vec![bp_plus()],
                tree_depth: 3,
                fcmp_proof: vec![0xEF; 2500],
                pseudo_outs: vec![[0x30; 32]],
            }),
        },
    }
}

/// Hex-encode a transaction for `parse_submission` / `SubmitEngine::submit`.
pub fn hexify(tx: &Transaction) -> String {
    hex::encode(tx.serialize())
}

/// A fact snapshot under which the spend fixture is fully admissible:
/// no identity hit, all key images free, reference known at an in-window
/// height, floor of 1/byte, the real Shekyl weight limit.
pub fn admitting_facts(parsed: &ParsedSubmission) -> SubmitFacts {
    SubmitFacts {
        in_pool: false,
        in_pool_broadcast: false,
        in_chain: None,
        key_image_conflicts: vec![KeyImageConflict::Free; parsed.key_images.len()],
        reference: Some(ReferenceFacts {
            height: BlockHeight::from_raw(150),
            root: FIXTURE_ROOT,
            tree_depth: 8,
        }),
        fee_per_byte: 1,
        fee_quantization_mask: 1,
        weight_limit: 149_400,
        chain_height: ChainCount::from_raw(200),
        bond_record_exists: None,
        emission: None,
        emission_claim_conflict: None,
    }
}

/// One recorded `commit` call — the mock's evidence for the §3.3/§3.5
/// binding assertions (certificate facts, blob identity, meta passthrough).
#[derive(Debug, Clone)]
pub struct CommitRecord {
    pub blob: Vec<u8>,
    pub txid: TxHash,
    pub meta: TxMeta,
    pub cert_txid: TxHash,
    pub cert_reference_block: BlockHash,
    pub cert_ref_height: BlockHeight,
    pub cert_root: [u8; 32],
    pub expected: SubmitFacts,
}

/// One recorded `snapshot_facts` call.
#[derive(Debug, Clone)]
pub struct SnapshotRecord {
    pub txid: TxHash,
    pub key_images: Vec<[u8; 32]>,
    pub reference_block: BlockHash,
    /// The §8.7.1 BP3 probe key the engine passed (bond-post submissions
    /// only).
    pub bond_p_canonical_id: Option<[u8; 32]>,
    /// The §8.7.2 E6/E7 probe the engine passed (emission submissions
    /// only): the vin-derived claimant id + claimed epochs.
    pub emission_probe: Option<([u8; 32], Vec<u64>)>,
}

/// Deterministic [`SubmitStateShim`]: serves a fixed snapshot, replays a
/// scripted commit outcome, and records every interaction. Wrap in [`Arc`]
/// and hand a clone to the engine; assert on the other.
#[derive(Debug)]
pub struct MockShim {
    pub facts: SubmitFacts,
    pub commit_outcome: Mutex<Option<CommitOutcome>>,
    pub snapshots: Mutex<Vec<SnapshotRecord>>,
    pub commits: Mutex<Vec<CommitRecord>>,
    pub relays: Mutex<Vec<TxHash>>,
}

impl MockShim {
    pub fn new(facts: SubmitFacts, commit_outcome: CommitOutcome) -> Arc<Self> {
        Arc::new(Self {
            facts,
            commit_outcome: Mutex::new(Some(commit_outcome)),
            snapshots: Mutex::new(Vec::new()),
            commits: Mutex::new(Vec::new()),
            relays: Mutex::new(Vec::new()),
        })
    }

    pub fn snapshot_count(&self) -> usize {
        self.snapshots.lock().unwrap().len()
    }

    pub fn commit_count(&self) -> usize {
        self.commits.lock().unwrap().len()
    }

    pub fn relay_count(&self) -> usize {
        self.relays.lock().unwrap().len()
    }
}

impl SubmitStateShim for MockShim {
    fn snapshot_facts(
        &self,
        txid: &TxHash,
        key_images: &[[u8; 32]],
        reference_block: &BlockHash,
        bond_p_canonical_id: Option<&[u8; 32]>,
        emission_probe: Option<(&[u8; 32], &[u64])>,
    ) -> Result<SubmitFacts, ShimFault> {
        self.snapshots.lock().unwrap().push(SnapshotRecord {
            txid: *txid,
            key_images: key_images.to_vec(),
            reference_block: *reference_block,
            bond_p_canonical_id: bond_p_canonical_id.copied(),
            emission_probe: emission_probe.map(|(id, epochs)| (*id, epochs.to_vec())),
        });
        Ok(self.facts.clone())
    }

    fn commit(
        &self,
        blob: &[u8],
        txid: &TxHash,
        meta: &TxMeta,
        cert: &VerificationCertificate,
        expected: &SubmitFacts,
    ) -> CommitOutcome {
        self.commits.lock().unwrap().push(CommitRecord {
            blob: blob.to_vec(),
            txid: *txid,
            meta: *meta,
            cert_txid: *cert.txid(),
            cert_reference_block: *cert.reference_block(),
            cert_ref_height: cert.ref_height(),
            cert_root: *cert.root(),
            expected: expected.clone(),
        });
        self.commit_outcome
            .lock()
            .unwrap()
            .take()
            .expect("commit called more than once (or unscripted)")
    }

    fn relay(&self, txid: &TxHash) {
        self.relays.lock().unwrap().push(*txid);
    }
}

/// Deterministic [`TxVerifier`]: scripted pass/fail, call-counted.
#[derive(Debug)]
pub struct MockVerifier {
    pub result: Result<(), VerifyFailure>,
    pub calls: AtomicUsize,
}

impl MockVerifier {
    pub fn passing() -> Arc<Self> {
        Arc::new(Self {
            result: Ok(()),
            calls: AtomicUsize::new(0),
        })
    }

    pub fn failing(failure: VerifyFailure) -> Arc<Self> {
        Arc::new(Self {
            result: Err(failure),
            calls: AtomicUsize::new(0),
        })
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl TxVerifier for MockVerifier {
    fn verify(
        &self,
        _parsed: &ParsedSubmission,
        _facts: &SubmitFacts,
    ) -> Result<(), VerifyFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result
    }
}
