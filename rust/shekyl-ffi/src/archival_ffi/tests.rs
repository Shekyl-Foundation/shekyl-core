// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the archival FFI edge (extracted from the former monofile).

use super::*;
use shekyl_archival_retention::{
    as_of_e_served_work, epoch_close_height, ArchivalRewardEmissionVin, CreditPair,
    EmissionVerifyError, EpochCloseBond, EpochCloseInputs, EpochCloseShard, HoldingsDescriptor,
    HoldingsKind, RewardCommit, ShardClose, ShardSet, ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
    SETTLEMENT_EPOCH_BLOCKS,
};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme};
use shekyl_peer_policy::DropVerdict;
use shekyl_types::BlockHeight;
use std::ptr;

/// The serving endpoint every JoinMarket call site passes (EU-D3: mandatory).

#[test]
fn emission_vin_drop_verdict_classifies_form_and_does_not_sever_on_our_state() {
    assert!(DropVerdict::from_byte(shekyl_emission_vin_drop_verdict(
        SHEKYL_EMISSION_VIN_ERR_WIRE
    ))
    .severs());
    assert!(DropVerdict::from_byte(shekyl_emission_vin_drop_verdict(
        SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED
    ))
    .severs());
    assert!(!DropVerdict::from_byte(shekyl_emission_vin_drop_verdict(
        SHEKYL_EMISSION_VIN_ERR_BOND_MISSING
    ))
    .severs());
    assert!(DropVerdict::from_byte(shekyl_emission_vin_drop_verdict(
        SHEKYL_EMISSION_VIN_ERR_MARSHAL
    ))
    .is_internal_failure());
    assert!(!DropVerdict::from_byte(shekyl_emission_vin_drop_verdict(255)).severs());
}

#[test]
fn extract_empty_slice_is_wire_not_null() {
    // A Rust empty slice has a non-null `as_ptr()`; length 0 is a parse
    // failure, not a call-site pointer bug.
    let empty: [u8; 0] = [];
    let mut p_id = [0u8; 32];
    let mut shard = 0u64;
    let mut epoch = 0u64;
    let code = unsafe {
        shekyl_archival_serve_credit_extract(
            empty.as_ptr(),
            0,
            p_id.as_mut_ptr(),
            &raw mut shard,
            &raw mut epoch,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_VERIFY_ERR_WIRE);
}

#[test]
fn extract_null_ptr_is_null() {
    let mut p_id = [0u8; 32];
    let mut shard = 0u64;
    let mut epoch = 0u64;
    let code = unsafe {
        shekyl_archival_serve_credit_extract(
            ptr::null(),
            0,
            p_id.as_mut_ptr(),
            &raw mut shard,
            &raw mut epoch,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR);
}

#[test]
fn checked_sum_amounts_sums_overflows_and_guards() {
    // Empty set (null allowed iff len == 0) sums to 0.
    let mut out: u64 = 7;
    assert_eq!(
        unsafe { shekyl_checked_sum_amounts(ptr::null(), 0, &raw mut out) },
        0
    );
    assert_eq!(out, 0);

    // Normal sum.
    let amounts = [1u64, 2, 3, 4];
    let mut sum: u64 = 0;
    assert_eq!(
        unsafe { shekyl_checked_sum_amounts(amounts.as_ptr(), amounts.len(), &raw mut sum) },
        0
    );
    assert_eq!(sum, 10);

    // Overflow rejects (non-zero return, caller must reject the tx).
    let overflow = [u64::MAX, 1];
    let mut bad: u64 = 0;
    assert_eq!(
        unsafe { shekyl_checked_sum_amounts(overflow.as_ptr(), overflow.len(), &raw mut bad) },
        1
    );

    // Null out pointer and null data with non-zero len both reject.
    assert_eq!(
        unsafe { shekyl_checked_sum_amounts(amounts.as_ptr(), amounts.len(), ptr::null_mut()) },
        1
    );
    let mut o: u64 = 0;
    assert_eq!(
        unsafe { shekyl_checked_sum_amounts(ptr::null(), 3, &raw mut o) },
        1
    );
}

#[test]
fn bond_ct_balance_ffi_rejects_null_with_nonzero_count() {
    let code = unsafe {
        shekyl_archival_verify_bond_post_ct_balance(ptr::null(), 1, ptr::null(), 0, 0, 0, 0)
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NULL_PTR);
}

#[test]
fn bond_ct_balance_ffi_rejects_count_overflow() {
    let buf = [0u8; 32];
    let code = unsafe {
        shekyl_archival_verify_bond_post_ct_balance(
            buf.as_ptr(),
            usize::MAX,
            ptr::null(),
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT);
}

// Both-terms is unrepresentable inside `BondTerm`; zero/zero is Unmoved.
// The FFI conversion is `BondTerm::from_credit_debit` — tested here at the
// untrusted u64 edge.
#[test]
fn bond_ct_balance_ffi_unmoved_closes_empty() {
    // credit = debit = 0, empty commitments, fee 0 → Unmoved, OK.
    let code = unsafe {
        shekyl_archival_verify_bond_post_ct_balance(ptr::null(), 0, ptr::null(), 0, 0, 0, 0)
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_OK);
    // Retired-assigned: zero-money used to return this. Number 5 stays.
    assert_eq!(SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NO_BOND_TERM, 5);
}

#[test]
fn bond_ct_balance_ffi_rejects_both_bond_terms() {
    // credit and debit both non-zero → BOTH_TERMS.
    let code = unsafe {
        shekyl_archival_verify_bond_post_ct_balance(ptr::null(), 0, ptr::null(), 0, 0, 1, 1)
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_BOTH_TERMS);
}

// -----------------------------------------------------------------------
// C-1 emission-vin FFI (`shekyl_archival_emission_vin_extract`,
// `shekyl_emission_vin_verify`). The honest fixture mirrors the crate KAT
// (`emission_verify_kat.rs`) but is recomputed with the FFI's own pinned
// consensus constants (plateau curve), so the test
// exercises the exact operand plumbing the C++ dispatch will use.
// -----------------------------------------------------------------------

use shekyl_archival_retention::{
    reward_share_floor, sigma_work_milli, EmissionAuthRole, MembershipOnlyBacking, ShardWorkEntry,
    WorkEpochClaim,
};
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};

const EM_EPOCH: u64 = 5;
const EM_BUDGET: u64 = 1_000_000;
const EM_SHARD_A: u64 = 7;
const EM_SHARD_B: u64 = 9;

/// Owned honest-emission scenario: two bonds (idx 0 = claimant on shard A
/// only; idx 1 on A and B, so `R_market(A) = 2`), real hybrid keypairs and
/// signatures over the vin's own Q1 role messages, work/reward derived
/// through the same sourcing functions the FFI verify recomputes with.
/// The backing proof is garbage bytes — step 6 is pinned positive in
/// `shekyl-fcmp`'s KATs; here it is the terminal rejection that proves
/// steps 1–5 and 8 already passed through the marshaling.
struct EmissionFfiFixture {
    vin_bytes: Vec<u8>,
    commits_flat: Vec<u8>,
    tx_hash: [u8; 32],
    reward: u64,
    sigma: u64,
    close: u64,
    ffi_bonds: Vec<ShekylArchivalEpochCloseBond>,
    ffi_shards: Vec<ShekylArchivalEpochCloseShard>,
    ffi_pairs: Vec<ShekylArchivalCreditPair>,
}

impl EmissionFfiFixture {
    fn build() -> Self {
        let close = epoch_close_height(EM_EPOCH).expect("fixture epoch closes");
        let bonds = [
            EpochCloseBond {
                join_settlement_epoch: 1,
                is_support_complete_tree: false,
                bad_intervals: &[],
            },
            EpochCloseBond {
                join_settlement_epoch: 1,
                is_support_complete_tree: false,
                bad_intervals: &[],
            },
        ];
        let shards = [
            EpochCloseShard {
                shard_id: EM_SHARD_A,
                close: ShardClose::ClosedAt(BlockHeight::from_raw(close - 5_000)),
            },
            EpochCloseShard {
                shard_id: EM_SHARD_B,
                close: ShardClose::ClosedAt(BlockHeight::from_raw(close - 8_000)),
            },
        ];
        let pairs = [
            CreditPair {
                bond_idx: 0,
                shard_idx: 0,
            },
            CreditPair {
                bond_idx: 1,
                shard_idx: 0,
            },
            CreditPair {
                bond_idx: 1,
                shard_idx: 1,
            },
        ];
        let inputs = EpochCloseInputs {
            settlement_epoch: EM_EPOCH,
            close_block_height: close,
            settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
            age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
            bonds: &bonds,
            shards: &shards,
            credit_pairs: &pairs,
        };
        let served = as_of_e_served_work(&inputs).expect("well-formed fixture");
        let work = served.work_by_bond[0];
        // Single-shard fixture ⇒ the sole entry's micro scarcity is the whole
        // per-bond micro sum; the wire carries micro, so verify's micro-space
        // aggregate compare demands this exact value (D1 fix).
        let work_micro = served.work_micro_by_bond[0];
        assert!(served.member[0] && work > 0, "fixture claimant must earn");
        let sigma = sigma_work_milli(&served.work_by_bond, &served.member);
        // D3/R2: no plateau in the reward path — the credited term is the work.
        let reward = reward_share_floor(EM_BUDGET, work, sigma);
        assert!(reward > 0, "fixture reward must be wire-encodable (>0)");

        let scheme = HybridEd25519MlDsa;
        let (p_pk, p_sk) = scheme
            .generate_ephemeral_keypair_for_tests()
            .expect("P keypair");
        let (b_pk, b_sk) = scheme
            .generate_ephemeral_keypair_for_tests()
            .expect("backing keypair");
        let mut vin = ArchivalRewardEmissionVin {
            p_pubkey: p_pk.to_canonical_bytes().expect("canonical P pubkey"),
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![EM_SHARD_A]).unwrap(),
            },
            settlement_epochs: vec![EM_EPOCH],
            work_claim: vec![WorkEpochClaim {
                epoch: EM_EPOCH,
                shard_entries: vec![ShardWorkEntry {
                    shard_id: EM_SHARD_A,
                    serve_credit_bit: true,
                    scarcity_micro: u32::try_from(work_micro).expect("fixture scarcity fits u32"),
                }],
            }],
            backing: MembershipOnlyBacking {
                proof: vec![0xAB; 64],
                pseudo_out: [0x22; 32],
                backing_pubkey: b_pk.to_canonical_bytes().expect("canonical backing pubkey"),
                tree_depth: 3,
            },
            reward_amount_plain: vec![reward],
            auth_backing: vec![0x55; SINGLE_SIG_CANONICAL_LEN],
            auth_claim: vec![0x66; SINGLE_SIG_CANONICAL_LEN],
        };
        assert_eq!(vin.p_pubkey.len(), SINGLE_KEY_CANONICAL_LEN);

        let commits = [RewardCommit {
            commitment: [0x71; 32],
            amount_plain: reward,
            one_time_key: [0x72; 32],
        }];
        let tx_hash = [0x5F; 32];
        let msgs = vin.auth_msgs(&commits, &tx_hash).expect("role messages");
        vin.auth_backing = scheme
            .sign(
                &b_sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_EMISSION_BACKING,
                &msgs.backing,
            )
            .expect("backing sign")
            .to_canonical_bytes()
            .expect("canonical backing sig");
        vin.auth_claim = scheme
            .sign(
                &p_sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_EMISSION_CLAIM,
                &msgs.claim,
            )
            .expect("claim sign")
            .to_canonical_bytes()
            .expect("canonical claim sig");

        let mut commits_flat = Vec::with_capacity(72);
        commits_flat.extend_from_slice(&commits[0].commitment);
        commits_flat.extend_from_slice(&commits[0].amount_plain.to_le_bytes());
        commits_flat.extend_from_slice(&commits[0].one_time_key);

        Self {
            vin_bytes: vin.serialize().expect("canonical wire"),
            commits_flat,
            tx_hash,
            reward,
            sigma,
            close,
            ffi_bonds: bonds
                .iter()
                .map(|b| ShekylArchivalEpochCloseBond {
                    join_settlement_epoch: b.join_settlement_epoch,
                    bad_intervals_ptr: ptr::null(),
                    bad_intervals_len: 0,
                    is_support_complete_tree: 0,
                })
                .collect(),
            ffi_shards: shards
                .iter()
                .map(|s| {
                    let wire = s.close.to_wire();
                    ShekylArchivalEpochCloseShard {
                        shard_id: s.shard_id,
                        freeze_height: wire.freeze_height,
                        has_segment: u8::from(wire.has_segment),
                    }
                })
                .collect(),
            ffi_pairs: pairs
                .iter()
                .map(|p| ShekylArchivalCreditPair {
                    bond_idx: p.bond_idx,
                    shard_idx: p.shard_idx,
                })
                .collect(),
        }
    }

    fn snapshot(&self) -> ShekylArchivalEmissionEpochSnapshot {
        ShekylArchivalEmissionEpochSnapshot {
            settlement_epoch: EM_EPOCH,
            close_block_height: self.close,
            sigma_work_milli: self.sigma,
            budget_atomic: EM_BUDGET,
            bonds_ptr: self.ffi_bonds.as_ptr(),
            bonds_len: self.ffi_bonds.len(),
            shards_ptr: self.ffi_shards.as_ptr(),
            shards_len: self.ffi_shards.len(),
            credit_pairs_ptr: self.ffi_pairs.as_ptr(),
            credit_pairs_len: self.ffi_pairs.len(),
            claimant_bond_idx: 0,
        }
    }

    /// One coarse verify crossing with the honest operands, with the two
    /// knobs the negatives vary. Returns `(code, total_reward, epochs)`.
    fn verify(&self, bond_present: u8, tx_hash: &[u8; 32]) -> (u8, u64, Vec<u64>) {
        let snapshots = [self.snapshot()];
        let bond_shard_ids = [EM_SHARD_A];
        let tree_root = [0u8; 32];
        let mut out_total = u64::MAX;
        let mut out_epochs = [u64::MAX; 4];
        let mut out_len = usize::MAX;
        let code = unsafe {
            shekyl_emission_vin_verify(
                self.vin_bytes.as_ptr(),
                self.vin_bytes.len(),
                self.close + 1,
                self.reward,
                bond_present,
                1,
                HoldingsKind::ShardSetCompact as u8,
                bond_shard_ids.as_ptr(),
                bond_shard_ids.len(),
                ptr::null(),
                0,
                snapshots.as_ptr(),
                snapshots.len(),
                tree_root.as_ptr(),
                3,
                tx_hash.as_ptr(),
                self.commits_flat.as_ptr(),
                1,
                ptr::from_mut(&mut out_total),
                out_epochs.as_mut_ptr(),
                out_epochs.len(),
                ptr::from_mut(&mut out_len),
            )
        };
        assert!(
            out_len <= out_epochs.len(),
            "out_epochs_len must be written"
        );
        (code, out_total, out_epochs[..out_len].to_vec())
    }
}

/// Block-level (P,E) uniqueness FFI over flattened 40-byte pairs — the
/// §6.4 KAT-1 shape (same-block double-claim) through the marshaling
/// boundary, plus the fail-closed null case.
#[test]
fn emission_block_claims_unique_ffi() {
    let flat = |pairs: &[([u8; 32], u64)]| -> Vec<u8> {
        let mut out = Vec::with_capacity(pairs.len() * 40);
        for (pid, epoch) in pairs {
            out.extend_from_slice(pid);
            out.extend_from_slice(&epoch.to_le_bytes());
        }
        out
    };
    let p = [0xaa; 32];
    let q = [0xbb; 32];

    // Distinct pairs (same P different E; different P same E) pass.
    let ok = flat(&[(p, 7), (p, 8), (q, 7)]);
    assert_eq!(
        unsafe { shekyl_emission_block_claims_unique(ok.as_ptr(), 3) },
        1
    );

    // Same-block duplicate (P, E) — non-adjacent — rejects.
    let dup = flat(&[(p, 7), (q, 3), (p, 7)]);
    assert_eq!(
        unsafe { shekyl_emission_block_claims_unique(dup.as_ptr(), 3) },
        0
    );

    // Empty block trivially unique; null with non-zero count fails closed.
    assert_eq!(
        unsafe { shekyl_emission_block_claims_unique(ptr::null(), 0) },
        1
    );
    assert_eq!(
        unsafe { shekyl_emission_block_claims_unique(ptr::null(), 1) },
        0
    );
}

/// End-to-end coarse verify over the honest fixture: claims (steps 1–5)
/// and the hybrid auth gate (step 8) pass through the full FFI
/// marshaling — snapshots, bond record, flattened reward commits — and
/// the call terminates at step 6 rejecting the garbage backing proof.
/// Reaching `BACKING_REJECTED` (not any earlier code) is the assertion:
/// it proves the DoS ordering (auth before backing) and that every
/// marshaled operand reproduced the crate-level honest fixture.
#[test]
fn emission_vin_verify_ffi_marshals_honest_operands_to_step_6() {
    let fx = EmissionFfiFixture::build();

    let (code, total, epochs) = fx.verify(1, &fx.tx_hash);
    assert_eq!(
        code, SHEKYL_EMISSION_VIN_ERR_BACKING_REJECTED,
        "honest claims + auths must reach (and stop at) the garbage proof"
    );
    assert_eq!(total, 0, "rejection must zero the mint output");
    assert!(epochs.is_empty(), "rejection must zero the commit set");

    // Auth-before-backing ordering: a tampered tx context breaks the Q1
    // binding messages, so the same vin now rejects at step 8 — earlier
    // than the backing proof it rejected at above.
    let mut wrong_hash = fx.tx_hash;
    wrong_hash[0] ^= 0x01;
    let (code, total, epochs) = fx.verify(1, &wrong_hash);
    assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED);
    assert_eq!(total, 0);
    assert!(epochs.is_empty());

    // Step 2: no bond record marshaled (`bond_present == 0`).
    let (code, total, epochs) = fx.verify(0, &fx.tx_hash);
    assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_BOND_MISSING);
    assert_eq!(total, 0);
    assert!(epochs.is_empty());
}

/// Marshaling negatives for the coarse verify: truncated wire, null
/// pointers, and the diagnostic error-code map for the auth variants the
/// C ABI collapses.
#[test]
fn emission_vin_verify_ffi_rejects_bad_marshaling() {
    let fx = EmissionFfiFixture::build();
    let snapshots = [fx.snapshot()];
    let tree_root = [0u8; 32];
    let mut out_total = u64::MAX;
    let mut out_epochs = [u64::MAX; 4];
    let mut out_len = usize::MAX;

    // Truncated vin bytes fail the length-exact parse.
    let code = unsafe {
        shekyl_emission_vin_verify(
            fx.vin_bytes.as_ptr(),
            fx.vin_bytes.len() - 1,
            fx.close + 1,
            fx.reward,
            0,
            0,
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            snapshots.as_ptr(),
            snapshots.len(),
            tree_root.as_ptr(),
            3,
            fx.tx_hash.as_ptr(),
            fx.commits_flat.as_ptr(),
            1,
            ptr::from_mut(&mut out_total),
            out_epochs.as_mut_ptr(),
            out_epochs.len(),
            ptr::from_mut(&mut out_len),
        )
    };
    assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_WIRE);
    assert_eq!(out_total, 0, "failure path must not leave stale outputs");
    assert_eq!(out_len, 0);

    // Null vin pointer rejects before any parse.
    let code = unsafe {
        shekyl_emission_vin_verify(
            ptr::null(),
            0,
            fx.close + 1,
            fx.reward,
            0,
            0,
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            snapshots.as_ptr(),
            snapshots.len(),
            tree_root.as_ptr(),
            3,
            fx.tx_hash.as_ptr(),
            fx.commits_flat.as_ptr(),
            1,
            ptr::from_mut(&mut out_total),
            out_epochs.as_mut_ptr(),
            out_epochs.len(),
            ptr::from_mut(&mut out_len),
        )
    };
    assert_eq!(code, SHEKYL_EMISSION_VIN_ERR_NULL_PTR);

    // The C ABI's collapsed diagnostic map, pinned per auth variant.
    assert_eq!(
        map_emission_vin_error(&EmissionVerifyError::AuthMalformed {
            role: EmissionAuthRole::Claim
        }),
        SHEKYL_EMISSION_VIN_ERR_AUTH_MALFORMED
    );
    assert_eq!(
        map_emission_vin_error(&EmissionVerifyError::AuthRejected {
            role: EmissionAuthRole::Backing
        }),
        SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED
    );
}
