// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The production [`TxVerifier`] — the Phase-C cryptographic battery over
//! the native Rust consensus crates
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3.1 Phase C; §8 rows O6, N8,
//! K12, K13).
//!
//! Every check here is the same Rust code the C++ oracle itself dispatches
//! to (`shekyl_verify_ct_balance`, `shekyl_fcmp_verify`, `shekyl_pqc_verify`
//! in `shekyl-ffi`) or a pinned thin-port of a C++-native check
//! (`check_commitment_mask_valid`; the Bp+ layout statics of
//! `n_bulletproof_plus_amounts`). Calling the crates natively removes the
//! FFI hop without changing the consensus arithmetic — the oracle and the
//! engine literally share the verifying functions.
//!
//! Check order mirrors the C++ submit path where it is observable in logs
//! (never in the verdict — every failure here is one of the three
//! [`VerifyFailure`] arms): `ver_non_input_consensus`'s battery first
//! (O6 mask non-triviality, N8 CT balance + Bp+ range proof), then
//! `check_tx_inputs`'s (K12 FCMP++ membership, K13 PQC hybrid auth).
//!
//! ## The bond-post batteries (§8.7.1 BP rows, §8.7.1.1 UB rows)
//!
//! [`SubmitTxKind::BondPost`] runs `verify_bond_post`, which dispatches on
//! the post kind after the legs both arms share: the spend legs (O6 masks,
//! the **bond** CT balance
//! `Σ pseudoOuts + bond_debit = Σ out_masks + fee + bond_credit`, Bp+, K12
//! FCMP++ over the `ToKey` funding subset, K13 PQC over every input) and
//! BP2's canonical-id recomputation. Every semantic leg is a native call
//! into `shekyl-archival-retention` — the same crate the C++ oracle's own
//! `check_archival_bond_post_input` dispatches to over FFI, so the two paths
//! share the verifying functions and cannot diverge semantically.
//!
//! - **JoinMarket — the credit arm** (`verify_credit_arm`): BP5 pins the
//!   bond slot's auth key to `P`'s **identity** key, then BP3's record-absent
//!   fact and BP4's economic battery.
//! - **Unbond — the debit arm** (`verify_debit_arm`): UB3 pins it to the
//!   **record's committed `bond_spend_pk`** instead, then UB2/UB4–UB9 over
//!   the §8.7.1.1 fact bundle. BP5's rule is *wrong* here: the identity key
//!   is the one a serving host holds, so an identity-authorized value-out
//!   would turn a host compromise into a collateral drain.
//!
//! There is **no wire contradiction**: since the §13 (F1/F3) coupling
//! closure (2026-07-05, `GENESIS_TX_WIRE_FORMAT.md` §1.1) `shekyl-wire`
//! sizes `pseudoOuts` by the `ToKey` **spend subset** for every shape —
//! a bond-post input carries no pseudo-out; its cleartext `bond_credit`
//! rides the balance equation — and `phase_a.rs` classifies and passes
//! bond-posts. (An earlier revision of these docs claimed the C++ wire
//! pinned `pseudoOuts == vin.size()` and bond-posts could not clear
//! Phase A; the PR-4a staker harness disproved that live — an
//! underfunded bond-post drew `FeeTooLow`, a Phase-C-only verdict.)
//!
//! ## Reachability honesty (the remaining refusal arms)
//!
//! - **Serve-credit-only** carries `fee == 0` by consensus (Phase A pins
//!   it), and the engine's Phase-C fee floor rejects zero fee before the
//!   crypto battery runs — the SP-T4a contradiction, reproduced for parity
//!   (`docs/FOLLOWUPS.md`). Reopening criterion (rule 21): the SP-T4a
//!   fee-floor resolution lands; re-evaluation shape: extend
//!   [`SubmitFacts`] with the §8.7.1 SC-row archival facts and implement
//!   the serve-credit battery (SC1–SC8) in this match arm.
//! - **HoldingsUpdate / Rebond** (wire `BondPostKind::Other`): the semantic
//!   verifies exist in `shekyl-archival-retention` and the block path runs
//!   them today, but **no wallet constructs either kind**. Building their
//!   submit-side fact sets now would be pre-provisioned flexibility (rule
//!   21) whose Phase-D race classification could not be verified against
//!   any real submission, so `verify_bond_post` refuses them at the kind
//!   dispatch. Reopening criterion: a producer. Re-evaluation shape: the
//!   §8.7.1.1 pattern — matrix rows, a `SubmitFacts` bundle carrying the
//!   kind's operands, a Phase-D disposition per fact.
//!
//! Until a criterion fires, these arms refuse loudly-but-safely
//! (`Malformed`, the §7.6 non-panicking posture) rather than carrying an
//! untested, unreachable battery.

use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
use rand_core::OsRng;

use shekyl_archival_retention::{
    debit_auth_pin, emission_vin_verify_auth, emission_vin_verify_backing,
    emission_vin_verify_claims, p_canonical_id_from_hybrid_pubkey, settlement_epoch_at_height,
    unbond_pre_cooldown_guards, unbond_vin_statics, verify_bond_post_ct_balance,
    verify_join_market_bond_post, verify_unbond_bond_post, whole_record_last_served,
    ArchivalBondPostVin, BondPostError, BondPostKind as RetentionBondPostKind, BondTerm,
    ClaimantBondRecord, CreditPair, EmissionEpochSource, EmissionVerifyContext,
    EmissionVerifyError, EpochCloseBond, EpochCloseInputs, EpochCloseShard, HoldingsDescriptor,
    HoldingsKind, RewardCommit, ShardSet,
};
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::multisig::verify_multisig;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
};
use shekyl_ct_balance::verify_ct_balance;
use shekyl_curve_io::CompressedPoint;
use shekyl_fcmp::proof::{self, KeyImage, ShekylFcmpProof, VerifyError};
use shekyl_fcmp::PqcLeafScalar;
use shekyl_units::{AtomicUnits, NonZeroAtomicUnits};
use shekyl_wire::transaction::{
    BondPost as WireBondPost, BondPostKind as WireBondPostKind, BpPlus, Ct, CtBase, Holdings,
    Input, PqcAuth, Prunable, PQC_HYBRID_SINGLE_KEY_LEN, PQC_MAX_PUBLIC_KEY_BLOB,
};
use shekyl_wire::varint::write_varint;

use crate::submit::facts::SubmitFacts;
use crate::submit::phase_a::{ParsedSubmission, SubmitTxKind};
use crate::submit::verify::{TxVerifier, VerifyFailure};

/// PQC scheme ids (`tx_pqc_verify.cpp:47-48`): single hybrid signer /
/// M-of-N multisig container. The closed set — anything else is
/// `Malformed`, exactly as the C++ battery rejects it.
const PQC_SCHEME_SINGLE: u8 = 1;
const PQC_SCHEME_MULTISIG: u8 = 2;

/// Multisig key-blob header (`n_total ‖ m_required`,
/// `tx_pqc_verify.cpp:50`).
const MULTISIG_KEY_HEADER_LEN: usize = 2;

/// Compressed identity — `ct::identity()` byte-for-byte; the O6
/// comparison is over compressed encodings, exactly as the C++
/// `operator==(ct::key)` compares.
const IDENTITY_COMPRESSED: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    bytes
};

/// The production Phase-C verifier over the native consensus crates.
///
/// Stateless: every input comes from the [`ParsedSubmission`] (bytes) and
/// the [`SubmitFacts`] snapshot (root, tree depth), so one instance serves
/// every submission concurrently under the engine's Phase-C gate.
#[derive(Debug, Default, Clone, Copy)]
pub struct DaemonTxVerifier;

impl TxVerifier for DaemonTxVerifier {
    fn verify(&self, parsed: &ParsedSubmission, facts: &SubmitFacts) -> Result<(), VerifyFailure> {
        match parsed.kind {
            SubmitTxKind::Spend => verify_spend(parsed, facts),
            SubmitTxKind::BondPost => verify_bond_post(parsed, facts),
            SubmitTxKind::Emission => verify_emission(parsed, facts),
            // Unreachable today (the engine's Phase-C fee floor rejects the
            // zero-fee consensus shape first) — see the module docs'
            // reachability section for the SP-T4a reopening criterion
            // (rule 21).
            SubmitTxKind::ServeCreditOnly => {
                tracing::error!(
                    kind = ?parsed.kind,
                    "TxVerifier reached by the serve-credit arm the engine's \
                     fee floor rejects today (SP-T4a); refusing (no battery \
                     is implemented for this arm)"
                );
                Err(VerifyFailure::Malformed)
            }
        }
    }
}

/// The regular FCMP++ spend battery: O6 → CT balance → Bp+ → FCMP++ → PQC.
fn verify_spend(parsed: &ParsedSubmission, facts: &SubmitFacts) -> Result<(), VerifyFailure> {
    // Phase A guarantees a spend is `Ct::Fcmp` with a prunable proof;
    // stay non-panicking per the §7.6 posture.
    let Ct::Fcmp {
        fee,
        base,
        pqc_auths,
        prunable: Some(prunable),
        ..
    } = &parsed.tx.ct
    else {
        return Err(VerifyFailure::Malformed);
    };

    // ── O6: commitment mask non-triviality ──────────────────────────────
    check_commitment_masks(base)?;

    // ── N8 leg 1: CT cleartext balance ──────────────────────────────────
    // `sum(pseudoOuts) == sum(outPk) + fee·H` via the single-sourced
    // equation (`shekyl-ct-balance`) — the same crate the C++
    // `verCtSemanticsSimple` dispatches to through
    // `shekyl_verify_ct_balance` (ct_semantics.cpp:226-241). The arity
    // pre-checks around it (`outPk == enc_amounts == enc_labels`,
    // `pseudoOuts == ToKey subset` — every spend input for this shape —
    // and base pseudoOuts empty) are structural in `shekyl-wire`'s
    // reader/validator and cannot fail here.
    // `as_flattened()` views `Vec<[u8; 32]>` as `&[u8]` with no per-submission
    // reallocation (the CT crate takes a flat byte slice).
    if verify_ct_balance(
        prunable.pseudo_outs.as_flattened(),
        base.commitments.as_flattened(),
        AtomicUnits::from_raw(*fee),
        &[],
        &[],
    )
    .is_err()
    {
        return Err(VerifyFailure::Malformed);
    }

    // ── N8 leg 2: Bp+ aggregate range proof ─────────────────────────────
    verify_bpplus_leg(base, prunable)?;

    // ── K12: FCMP++ membership + SAL ────────────────────────────────────
    // Native call to the exact consensus function the C++ oracle reaches
    // through `shekyl_fcmp_verify` (blockchain.cpp:3835-3850). Every input
    // of a spend is `ToKey`, so the leaf set is all auths.
    let (tree_root, layers) = fcmp_reference_layers(facts, prunable)?;
    let leaf_auths: Vec<&PqcAuth> = pqc_auths.iter().collect();
    verify_fcmp(parsed, prunable, &leaf_auths, &tree_root, layers)?;

    // ── K13: PQC hybrid auth (per-input scheme validity; MSW-6 dropped the
    // former tx-wide scheme-id agreement — see verify_pqc_auths) ─────────
    verify_pqc_auths(parsed, pqc_auths)
}

/// The §8.7.1 bond-post battery: the spend legs over the bond-post shape
/// (O6 → bond CT balance → Bp+ → funding-subset K12 → all-input K13), then
/// the archival BP legs (BP2 canonical id, BP5 identity-key auth pin,
/// BP3 record fact + BP4 economic battery), every semantic leg a native
/// call into `shekyl-archival-retention` — the same functions the C++
/// oracle's `check_archival_bond_post_input` reaches over FFI.
///
/// BP1 (hybrid pubkey length == `PQC_HYBRID_SINGLE_KEY_LEN`) and the
/// JoinMarket `bond_spend_pk` length pin are structural in `shekyl-wire`
/// (`BondPost::read`/`validate` enforce the exact canonical lengths), so a
/// `ParsedSubmission` cannot carry a violation — the §8.7.1 BP1 ⚠ resolves
/// to "wire-covered", recorded there.
fn verify_bond_post(parsed: &ParsedSubmission, facts: &SubmitFacts) -> Result<(), VerifyFailure> {
    // Phase A guarantees the bond-post shape is `Ct::Fcmp` with a prunable
    // proof and exactly one bond-post input; stay non-panicking (§7.6).
    let Ct::Fcmp {
        fee,
        base,
        pqc_auths,
        prunable: Some(prunable),
        ..
    } = &parsed.tx.ct
    else {
        return Err(VerifyFailure::Malformed);
    };
    let Some((bond_index, bond)) = parsed.bond_post() else {
        return Err(VerifyFailure::Malformed);
    };

    // Kind dispatch: the credit arm (JoinMarket, §8.7.1 BP rows) and the
    // debit arm (Unbond, §8.7.1.1 UB rows) are the two kinds whose
    // submit-side fact sets are pinned. HoldingsUpdate and Rebond have no
    // producer, so their fact sets are deliberately unbuilt and they refuse
    // loudly under their named rule-21 reopening criterion (module docs).
    let arm = match &bond.kind {
        WireBondPostKind::JoinMarket { bond_spend_pk } => BondArm::Credit(bond_spend_pk),
        WireBondPostKind::Other(tag) if *tag == RetentionBondPostKind::Unbond as u8 => {
            BondArm::Debit
        }
        kind => {
            tracing::error!(
                ?kind,
                "bond-post submit battery covers JoinMarket (§8.7.1) and \
                 Unbond (§8.7.1.1); HoldingsUpdate and Rebond refuse until \
                 a producer exists and their fact set + Phase-D re-check \
                 semantics are specified (rule-21 reopening criterion in \
                 the module docs)"
            );
            return Err(VerifyFailure::Malformed);
        }
    };

    // ── O6: commitment mask non-triviality (blockchain.cpp:3380 runs the
    // same check for every non-coinbase shape) ──────────────────────────
    check_commitment_masks(base)?;

    // ── N7 balance leg: the bond CT balance ─────────────────────────────
    // `Σ pseudoOuts + bond_debit = Σ out_masks + fee + bond_credit` via the
    // single-sourced `shekyl-archival-retention` equation — the same crate
    // the C++ `verCtSemanticsBondPost` dispatches to through
    // `shekyl_archival_verify_bond_post_ct_balance` (ct_semantics.cpp:325-340).
    // The `(credit, debit) → BondTerm` conversion — rejecting the both /
    // neither / zero states — happens here at the untrusted-input edge,
    // mirroring the FFI boundary's identical conversion, so the total core
    // function stays total. `pseudoOuts == ToKey subset` arity is
    // `validate()`'s coupling and cannot fail here.
    let term = match (
        NonZeroAtomicUnits::new(AtomicUnits::from_raw(bond.bond_credit)),
        NonZeroAtomicUnits::new(AtomicUnits::from_raw(bond.bond_debit)),
    ) {
        (None, None) | (Some(_), Some(_)) => return Err(VerifyFailure::Malformed),
        (Some(credit), None) => BondTerm::Credit(credit),
        (None, Some(debit)) => BondTerm::Debit(debit),
    };
    if verify_bond_post_ct_balance(
        prunable.pseudo_outs.as_flattened(),
        base.commitments.as_flattened(),
        *fee,
        term,
    )
    .is_err()
    {
        return Err(VerifyFailure::Malformed);
    }

    // ── BP2: canonical-id recomputation from the vin's pubkey ───────────
    // Native twin of `shekyl_archival_p_canonical_id_from_pubkey`
    // (blockchain.cpp:4739-4751): the claimed id must derive from the
    // claimed identity key, so the BP3 record probe (keyed on the claim)
    // and the BP5 auth pin (keyed on the pubkey) bind the same P. The
    // deterministic archival legs run before the expensive proofs — the
    // check *set* is the C++ oracle's (which also probes the record before
    // its FCMP/PQC legs); only the balance/Bp+ placement differs, and the
    // BP3 conflict deliberately outranks the proof legs: a consumed claim
    // slot is terminal for this P regardless of proof validity (a
    // resubmission with repaired proofs fails BP3 again), so
    // `DoubleSpendConflict` is the more actionable verdict even when later
    // legs would also have refused — the engine's most-terminal-first
    // doctrine, applied inside the battery.
    if p_canonical_id_from_hybrid_pubkey(&bond.hybrid_public_key).as_bytes() != &bond.p_canonical_id
    {
        return Err(VerifyFailure::Malformed);
    }

    // ── Authorization + the economic battery, per arm ───────────────────
    let Some(bond_auth) = pqc_auths.get(bond_index) else {
        return Err(VerifyFailure::Malformed);
    };
    match arm {
        BondArm::Credit(bond_spend_pk) => {
            verify_credit_arm(bond, bond_spend_pk, bond_auth, facts)?;
        }
        BondArm::Debit => verify_debit_arm(bond, bond_auth, facts)?,
    }

    // ── N8 leg 2: Bp+ aggregate range proof over the output commitments ─
    verify_bpplus_leg(base, prunable)?;

    // ── Funding-arm K12: FCMP++ membership + SAL over the ToKey subset ──
    // The C++ caller assembles key images / pseudo-outs / leaf hashes from
    // `spend_indices` only (blockchain.cpp:3698-3800) — the bond-post input
    // contributes no leaf. `parsed.key_images` and `pseudo_outs` are
    // already ToKey-subset by construction; the auth subset is selected by
    // vin arm here.
    let (tree_root, layers) = fcmp_reference_layers(facts, prunable)?;
    let funding_auths: Vec<&PqcAuth> = parsed
        .tx
        .prefix
        .inputs
        .iter()
        .zip(pqc_auths.iter())
        .filter_map(|(input, auth)| matches!(input, Input::ToKey { .. }).then_some(auth))
        .collect();
    verify_fcmp(parsed, prunable, &funding_auths, &tree_root, layers)?;

    // ── K13: PQC hybrid auth over EVERY input, the bond-post slot
    // included — exactly the C++ `verify_transaction_pqc_auth` battery ───
    verify_pqc_auths(parsed, pqc_auths)
}

/// The §8.7.2 emission battery: EV4's mint-balance + Bp+ legs, the E2/E5
/// structural bindings, the E6–E10 archival legs (native
/// `shekyl-archival-retention::emission_verify` minters — the same
/// functions the C++ oracle reaches through `shekyl_emission_vin_verify`),
/// then the shared funding-subset K12 and whole-tx K13.
///
/// EV1/EV2 are structural in `shekyl-wire`; EV3, E1 (parse+validate) and
/// the E11 proof-presence coupling are Phase-A statics. The Q11
/// zero-fee-input form is representable (a prunable with an EMPTY proof
/// and empty pseudo-outs — the prunable itself must be present, since a
/// prunable-less ct cannot carry outputs) and consensus-valid; the wallet
/// never builds it (`ClaimFeeInputsRequired`), but the battery admits it:
/// the fee-subset K12 leg is skipped when there are no fee inputs, exactly
/// as the C++ oracle skips it — §8.7.2 row E11's note.
fn verify_emission(parsed: &ParsedSubmission, facts: &SubmitFacts) -> Result<(), VerifyFailure> {
    let Ct::Fcmp {
        fee,
        base,
        pqc_auths,
        prunable: Some(prunable),
        ..
    } = &parsed.tx.ct
    else {
        return Err(VerifyFailure::Malformed);
    };
    // Phase A parsed + validated the vin (E1) and stored it.
    let Some(vin) = parsed.emission_vin.as_deref() else {
        return Err(VerifyFailure::Malformed);
    };
    let Some((emission_index, _)) = parsed
        .tx
        .prefix
        .inputs
        .iter()
        .enumerate()
        .find(|(_, input)| matches!(input, Input::ArchivalRewardEmission { .. }))
    else {
        return Err(VerifyFailure::Malformed);
    };

    // ── O6 over every output commitment (blockchain.cpp:3380 runs the
    // same check for the emission shape) ────────────────────────────────
    check_commitment_masks(base)?;

    // ── EV4: the mint-side CT balance ───────────────────────────────────
    // `Σ pseudoOuts + total_reward = Σ out_masks + fee` — the mint rides
    // the debit slot of the single-sourced archival balance
    // (`verCtSemanticsBondPost`'s sibling, ct_semantics.cpp:348-370). The loud
    // vout sum is non-zero by Phase A's EV3 static, so the `BondTerm`
    // conversion below is total for an admitted submission.
    let vout_reward_sum: u64 = {
        let mut sum: u64 = 0;
        for output in &parsed.tx.prefix.outputs {
            // Overflow-free by wire validate()'s check_money_overflow
            // parity; stay non-panicking anyway (§7.6).
            sum = sum
                .checked_add(output.amount)
                .ok_or(VerifyFailure::Malformed)?;
        }
        sum
    };
    let Some(mint) = NonZeroAtomicUnits::new(AtomicUnits::from_raw(vout_reward_sum)) else {
        return Err(VerifyFailure::Malformed);
    };
    if verify_bond_post_ct_balance(
        prunable.pseudo_outs.as_flattened(),
        base.commitments.as_flattened(),
        *fee,
        BondTerm::Debit(mint),
    )
    .is_err()
    {
        return Err(VerifyFailure::Malformed);
    }

    // ── N8 leg 2: Bp+ over the output commitments ───────────────────────
    verify_bpplus_leg(base, prunable)?;

    // ── E2: the emission slot's PQC auth key IS the vin's claim key ─────
    // (blockchain.cpp:3830-3845 compares the derived canonical ids — an
    // FFI necessity there; byte equality of the keys implies id equality
    // and is the direct form here.)
    let Some(emission_auth) = pqc_auths.get(emission_index) else {
        return Err(VerifyFailure::Malformed);
    };
    if emission_auth.hybrid_public_key != vin.p_pubkey {
        return Err(VerifyFailure::Malformed);
    }

    // ── E5: the F-C1c signable hash — the prefix hash with the emission
    // vin removed wholesale (blockchain.cpp:3907-3919) ──────────────────
    let signable_tx_hash = {
        let mut pruned = parsed.tx.clone();
        pruned.prefix.inputs.remove(emission_index);
        pruned.prefix_hash()
    };

    // ── E6 + E7 facts → the verify context and per-epoch sources ────────
    // The engine pre-checked presence (ShimContract); the `None` arm is
    // the seam's non-panicking refusal for direct callers.
    let Some(emission_facts) = facts.emission.as_ref() else {
        tracing::error!(
            "emission verifier called without the E6/E7 fact bundle \
             (the engine's ShimContract pre-check makes this unreachable \
             through the pipeline)"
        );
        return Err(VerifyFailure::Malformed);
    };
    // E7: every claimed epoch must carry a frozen budget row.
    if emission_facts.snapshots.iter().any(|s| !s.has_budget_row) {
        return Err(VerifyFailure::Malformed);
    }
    let ctx = EmissionVerifyContext {
        current_block_height: facts.chain_height.to_raw(),
        bond: emission_facts.bond.as_ref().map(|b| ClaimantBondRecord {
            join_settlement_epoch: b.join_settlement_epoch,
            holdings: &b.holdings,
            claimed_settlement_epochs: &b.claimed_settlement_epochs,
        }),
        vout_reward_sum,
    };
    // Borrow-anchored view construction, the archival_ffi shape: owned
    // rows first, then the borrowing `verify_view` sources (the single
    // constructor the C++ oracle's shim also uses, so the two paths build
    // byte-identical views).
    let bonds_per: Vec<Vec<EpochCloseBond<'_>>> = emission_facts
        .snapshots
        .iter()
        .map(|snap| {
            snap.bonds
                .iter()
                .map(|b| EpochCloseBond {
                    join_settlement_epoch: b.join_settlement_epoch,
                    is_foundation_complete_tree: b.is_foundation_complete_tree,
                    bad_intervals: &b.bad_intervals,
                })
                .collect()
        })
        .collect();
    let shards_per: Vec<Vec<EpochCloseShard>> = emission_facts
        .snapshots
        .iter()
        .map(|snap| {
            snap.shards
                .iter()
                .map(|sh| EpochCloseShard {
                    shard_id: sh.shard_id,
                    has_segment: sh.has_segment,
                    freeze_height: sh.freeze_height,
                })
                .collect()
        })
        .collect();
    let pairs_per: Vec<Vec<CreditPair>> = emission_facts
        .snapshots
        .iter()
        .map(|snap| {
            snap.credit_pairs
                .iter()
                .map(|cp| CreditPair {
                    bond_idx: cp.bond_idx,
                    shard_idx: cp.shard_idx,
                })
                .collect()
        })
        .collect();
    let sources: Vec<EmissionEpochSource<'_>> = emission_facts
        .snapshots
        .iter()
        .zip(&bonds_per)
        .zip(&shards_per)
        .zip(&pairs_per)
        .map(|(((snap, bonds), shards), pairs)| EmissionEpochSource {
            inputs: EpochCloseInputs::verify_view(
                snap.settlement_epoch,
                snap.close_block_height,
                bonds,
                shards,
                pairs,
            ),
            persisted_sigma_work_milli: snap.sigma_work_milli,
            claimant_bond_idx: snap.claimant_bond_idx,
            budget: snap.budget_atomic,
        })
        .collect();

    // ── E8: claims battery (§7.1 steps 1–5) ─────────────────────────────
    let claims =
        emission_vin_verify_claims(vin, &ctx, &sources).map_err(|e| emission_reject(&e))?;

    // ── E9 + E10: backing membership proof + the dual hybrid auths ──────
    let reference = facts.reference.ok_or(VerifyFailure::StaleRoot)?;
    let layers = u8::try_from(prunable.tree_depth)
        .ok()
        .and_then(|depth| depth.checked_add(1))
        .ok_or(VerifyFailure::StaleRoot)?;
    let backing = emission_vin_verify_backing(vin, &reference.root, layers, signable_tx_hash)
        .map_err(|e| emission_reject(&e))?;
    let reward_commits: Vec<RewardCommit> = parsed
        .tx
        .prefix
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, output)| output.amount != 0)
        .map(|(i, output)| {
            Some(RewardCommit {
                commitment: *base.commitments.get(i)?,
                amount_plain: output.amount,
                one_time_key: output.key,
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(VerifyFailure::Malformed)?;
    let auth = emission_vin_verify_auth(vin, &reward_commits, &signable_tx_hash)
        .map_err(|e| emission_reject(&e))?;
    // The witness assembly is infallible once the three minters passed —
    // mirroring the C++ oracle's single `shekyl_emission_vin_verify`
    // crossing; the outputs (total reward, epochs to commit) are the
    // connect arm's operands and unused at submit.
    drop(shekyl_archival_retention::emission_vin_verify(
        claims, backing, auth,
    ));

    // ── E11: fee-input FCMP++ over the ToKey subset (blockchain.cpp:
    // 4046-4108 — the bond-arm funding shape; the full prefix hash, not
    // the vin-less signable). With zero fee inputs the proof is EMPTY by
    // Phase A's coupling and the leg is skipped exactly as the C++ oracle
    // skips it (`if (num_spend == 0)`, blockchain.cpp:4050) — the Q11
    // mint-pays-fee form is consensus-valid even though the wallet never
    // builds it (`ClaimFeeInputsRequired`).
    if !parsed.key_images.is_empty() {
        let fee_auths: Vec<&PqcAuth> = parsed
            .tx
            .prefix
            .inputs
            .iter()
            .zip(pqc_auths.iter())
            .filter_map(|(input, auth)| matches!(input, Input::ToKey { .. }).then_some(auth))
            .collect();
        verify_fcmp(parsed, prunable, &fee_auths, &reference.root, layers)?;
    }

    // ── E12 / K13: PQC hybrid auth over EVERY slot, emission included ───
    verify_pqc_auths(parsed, pqc_auths)
}

/// §8.7.2 classification rule: the consumed/moved claim slot — record gone
/// or epoch already claimed — is the `DoubleSpendConflict` claim-slot leg;
/// every other violation is a window/shape/proof failure → `Malformed`.
fn emission_reject(e: &EmissionVerifyError) -> VerifyFailure {
    match e {
        EmissionVerifyError::BondMissing | EmissionVerifyError::EpochAlreadyClaimed { .. } => {
            VerifyFailure::DoubleSpendConflict
        }
        _ => VerifyFailure::Malformed,
    }
}

/// Which bond-post arm a submission is on — and, with it, which key
/// authorizes the slot.
///
/// The distinction is the whole reason the two arms cannot share one code
/// path: a **credit** proves control of `P_canonical_id` and moves no bonded
/// value out, so the identity key is the right authorizer; a **debit** takes
/// collateral out, and the identity key is exactly the key a compromised
/// serving host holds. See `verify_debit_arm`.
enum BondArm<'a> {
    /// JoinMarket (§8.7.1) — carries the `bond_spend_pk` the record will
    /// commit; authorized by the identity key (row BP5).
    Credit(&'a [u8]),
    /// Unbond (§8.7.1.1) — carries no `bond_spend_pk` on the wire;
    /// authorized by the record's committed key (row UB3).
    Debit,
}

/// The credit arm: row BP5's identity-key pin, then the BP3 record fact and
/// the BP4 economic battery.
///
/// `verify_join_market_bond_post` (`shekyl-archival-retention`) is the single
/// verdict source both paths share: post-kind, holdings-shape consistency,
/// credit/debit exclusivity, debit == 0, the bond-floor equality, and the
/// record-absent claim slot.
fn verify_credit_arm(
    bond: &WireBondPost,
    bond_spend_pk: &[u8],
    bond_auth: &PqcAuth,
    facts: &SubmitFacts,
) -> Result<(), VerifyFailure> {
    // ── BP5: credit-path authorization pins the IDENTITY key ────────────
    // (gate-4 §3.5 step 5; `blockchain.cpp`'s JoinMarket/Rebond arms): the
    // bond slot's PQC auth key — whose signature over the whole-tx payload
    // the K13 leg verifies — must be P's identity key `P_pubkey`.
    if bond_auth.hybrid_public_key != bond.hybrid_public_key {
        return Err(VerifyFailure::Malformed);
    }

    // The engine pre-checked the fact's presence (ShimContract); the `None`
    // arm here is the seam's non-panicking refusal for direct callers.
    let Some(record_exists) = facts.bond_record_exists else {
        tracing::error!(
            "bond-post verifier called without the BP3 record fact \
             (the engine's ShimContract pre-check makes this unreachable \
             through the pipeline)"
        );
        return Err(VerifyFailure::Malformed);
    };
    let Some(vin) = retention_vin(bond, RetentionBondPostKind::JoinMarket, bond_spend_pk) else {
        return Err(VerifyFailure::Malformed);
    };
    match verify_join_market_bond_post(&vin, record_exists) {
        Ok(()) => Ok(()),
        // §8.7.1 classification rule: the consumed claim slot is a state
        // conflict — the DoubleSpendConflict claim-slot leg; every other
        // violation is a window/shape failure → Malformed.
        Err(BondPostError::RecordExists) => Err(VerifyFailure::DoubleSpendConflict),
        Err(_) => Err(VerifyFailure::Malformed),
    }
}

/// The debit arm (§8.7.1.1 rows UB2–UB9): the record's committed authorizer,
/// then the Unbond economic battery over the Phase-B fact bundle.
///
/// **UB3 replaces BP5 here, and the substitution is the point.** A debit
/// takes bonded collateral out of the system. `P`'s identity key is held by
/// the serving host (it produces Auth-P for every response), so authorizing a
/// value-out against it would turn a host compromise into a collateral drain.
/// The record's `bond_spend_pk` is cold, and `debit_auth_pin` — the same
/// function the C++ block path calls over FFI — is what makes that coldness
/// load-bearing. A record committing no canonical key authorizes nothing;
/// there is no identity-key fallback.
fn verify_debit_arm(
    bond: &WireBondPost,
    bond_auth: &PqcAuth,
    facts: &SubmitFacts,
) -> Result<(), VerifyFailure> {
    let Some(unbond) = facts.unbond.as_ref() else {
        tracing::error!(
            "unbond verifier called without the §8.7.1.1 fact bundle \
             (the engine's ShimContract pre-check makes this unreachable \
             through the pipeline)"
        );
        return Err(VerifyFailure::Malformed);
    };

    // ── UB2: the record must exist ──────────────────────────────────────
    // Absent *here*, at Phase B/C, is a submitter error — `Malformed`,
    // whose remedy is rebuild, not retry. (Terminal on remedy rather than on
    // impossibility: a later JoinMarket could re-create the row at a floor
    // equal to this vin's fixed `bond_debit`. §8.7.1.1's UB2 note carries the
    // argument and the bound.) Absent at the Phase-D re-check after
    // being present at B is a competing debit that connected during Phase
    // C, and the engine classifies that `DoubleSpendConflict` from the
    // fresh facts. Same fact value, different verdict by when it was
    // observed — the `reference` field's asymmetry.
    let Some(record) = unbond.record.as_ref() else {
        return Err(VerifyFailure::Malformed);
    };

    // ── UB3: the record's COMMITTED authorizer, never the identity key ──
    if debit_auth_pin(record.bond_spend_pk(), &bond_auth.hybrid_public_key).is_err() {
        return Err(VerifyFailure::Malformed);
    }

    // ── The record-only UB9 guards, ahead of the skipped-scan belt ─────
    // These are the states the gather deliberately skips its scan for, and
    // they must be refused HERE, by name, rather than by the belt below. The
    // belt cannot tell an expected skip from a broken shim, so letting an
    // ordinary malformed Unbond reach it produced an `error!` claiming an
    // internal inconsistency for what is simply an invalid transaction.
    //
    // The shared consensus function, never a restatement: `verify_unbond_bond_post`
    // runs the identical guards, so the block path and this arm cannot drift.
    let Some(vin) = retention_vin(bond, RetentionBondPostKind::Unbond, &[]) else {
        return Err(VerifyFailure::Malformed);
    };
    if unbond_pre_cooldown_guards(
        &vin,
        record.bonded_total_atomic(),
        record.bad_interval_count(),
    )
    .is_err()
    {
        return Err(VerifyFailure::Malformed);
    }

    // ── The gather refused to scan, so there is nothing to fold ────────
    // An unread slice folds to "never served", which ELAPSES the cooldown —
    // the permissive direction — so a skipped scan is refused, never folded.
    //
    // Every skip the gather performs is now accounted for ABOVE this line:
    //   * identity (txid already known) — the engine returned AlreadyInPool /
    //     AlreadyInChain long before Phase C;
    //   * the debit pin failed — UB3 refused;
    //   * zero balance, a debit the balance no longer matches, or a full
    //     interval log — the record statics just refused, by name.
    // So reaching here means a skip NOTHING explains: a shim that skipped
    // without cause. That is a contract violation, not an invalid
    // transaction, and it is worth the loud log.
    if record.last_served_scan_skipped() {
        tracing::error!(
            "unbond gather skipped the last-served scan but the Phase-C pin \
             passed — refusing rather than folding an unread slice"
        );
        return Err(VerifyFailure::Malformed);
    }

    // ── UB4/UB5: fold the gathered slice into the cooldown anchor ───────
    // The shim already pinned the gather's scan discriminant against the
    // record's holdings kind (a mismatch is a ShimContract fault, not a
    // fold), so the slice here is the one this record's kind selects.
    let last_served_epoch = whole_record_last_served(record.per_shard_last_served());

    // ── UB8: the current settlement epoch ───────────────────────────────
    // The consensus shape deliberately feeds the chain *count*
    // (`m_db->height()`, "the height the next block will occupy") to an
    // "at height" helper; mirror it rather than correcting it, or the
    // engine and the oracle disagree at every epoch boundary. The helper
    // reads `effective_settlement_epoch_blocks`, so a regtest chain running
    // the shortened schedule stays consistent across both paths.
    let current_settlement_epoch = settlement_epoch_at_height(facts.chain_height.to_raw());

    // ── UB9: the economic battery, the same function the block path calls ─
    // `vin` was built above, for the record statics.
    match verify_unbond_bond_post(
        &vin,
        Some(record.bonded_total_atomic()),
        record.bad_interval_count(),
        last_served_epoch,
        unbond.last_settled_slash_epoch,
        current_settlement_epoch,
    ) {
        Ok(()) => Ok(()),
        // The record went missing between the fact snapshot and here — not
        // reachable through this arm (the `record` binding above proves
        // presence), but the battery owns the verdict, so map it the same
        // way the claim-slot leg is mapped rather than silently widening.
        Err(BondPostError::RecordMissing) => Err(VerifyFailure::DoubleSpendConflict),
        Err(_) => Err(VerifyFailure::Malformed),
    }
}

/// Marshal the wire bond-post vin into the retention crate's verify view.
///
/// Total for a `validate()`d JoinMarket vin (the wire read already enforced
/// the shard-set bound + duplicate-freeness this re-checks); `None` only
/// for a hand-built inconsistent value — the seam's non-panicking refusal.
fn retention_vin(
    bond: &WireBondPost,
    post_kind: RetentionBondPostKind,
    bond_spend_pk: &[u8],
) -> Option<ArchivalBondPostVin> {
    let (kind, shard_ids) = match &bond.holdings {
        Holdings::ShardSetCompact(ids) => (
            HoldingsKind::ShardSetCompact,
            ShardSet::new(ids.clone()).ok()?,
        ),
        Holdings::CompleteTree => (HoldingsKind::CompleteTree, ShardSet::empty()),
    };
    Some(ArchivalBondPostVin {
        hybrid_public_key: bond.hybrid_public_key.clone(),
        p_canonical_id: bond.p_canonical_id,
        post_kind,
        bond_spend_pk: bond_spend_pk.to_vec(),
        holdings: HoldingsDescriptor { kind, shard_ids },
        bonded_total_atomic: bond.bonded_total_atomic,
        bond_credit: bond.bond_credit,
        bond_debit: bond.bond_debit,
    })
}

/// Resolve the FCMP++ reference root + library layer count for a K12 leg,
/// shared by the spend and bond-post arms so the layer convention and the
/// StaleRoot mapping are single-sourced — a future change to either cannot
/// split the two arms into disagreeing accept/reject behaviour on the submit
/// surface. `facts.reference` is the pinned tree snapshot the engine bounded
/// against (absent ⇒ `StaleRoot`); the `tree_depth + 1` conversion matches
/// the C++ caller's `fcmp_layers = curve_trees_tree_depth + 1`, and a depth
/// that cannot be represented as a layer count is a snapshot inconsistency a
/// rebuild against a fresh root fixes (the `StaleRoot` contract), not a
/// malformed-bytes reject.
fn fcmp_reference_layers(
    facts: &SubmitFacts,
    prunable: &Prunable,
) -> Result<([u8; 32], u8), VerifyFailure> {
    let reference = facts.reference.ok_or(VerifyFailure::StaleRoot)?;
    let layers = u8::try_from(prunable.tree_depth)
        .ok()
        .and_then(|depth| depth.checked_add(1))
        .ok_or(VerifyFailure::StaleRoot)?;
    Ok((reference.root, layers))
}

/// O6: commitment mask non-triviality, shared by the spend and bond-post
/// arms. Thin-port of `check_commitment_mask_valid`
/// (blockchain.cpp:3284-3320), non-coinbase legs: reject `C == identity`
/// (mask 0, amount 0) and `C == G` (mask 1, amount 0). Byte-compare over
/// the compressed encoding, as the C++ compares `ct::key`s. The coinbase
/// zeroCommit leg does not apply — Phase A rejects coinbase submissions.
fn check_commitment_masks(base: &CtBase) -> Result<(), VerifyFailure> {
    for commitment in &base.commitments {
        if *commitment == IDENTITY_COMPRESSED
            || *commitment == ED25519_BASEPOINT_COMPRESSED.to_bytes()
        {
            return Err(VerifyFailure::Malformed);
        }
    }
    Ok(())
}

/// N8 leg 2: the Bp+ aggregate range proof, shared by the spend and
/// bond-post arms. `nbp == 1` is `validate()`'s §10 rule; the single-proof
/// destructure is therefore total, but stay non-panicking. The commitments
/// are the outPk masks exactly as transmitted: the statement multiplies by
/// `INV_EIGHT` for the transcript and clears the cofactor for evaluation —
/// matching the C++ path, which reconstructs `V = outPk·(1/8)` at
/// deserialization (cryptonote_format_utils.cpp:176) and evaluates `8·V`
/// (bulletproofs_plus.cc). L/R round-count statics
/// (`n_bulletproof_plus_amounts`) are enforced structurally by the WIP
/// verifier's round check; unreduced-scalar rejection (`is_reduced`) by
/// `read_scalar` in the wire conversion.
fn verify_bpplus_leg(base: &CtBase, prunable: &Prunable) -> Result<(), VerifyFailure> {
    let [bp_wire] = prunable.bulletproofs.as_slice() else {
        return Err(VerifyFailure::Malformed);
    };
    let Some(bp) = bulletproof_from_wire(bp_wire) else {
        return Err(VerifyFailure::Malformed);
    };
    let bp_commitments: Vec<CompressedPoint> = base
        .commitments
        .iter()
        .map(|c| CompressedPoint::from(*c))
        .collect();
    if !bp.verify(&mut OsRng, &bp_commitments) {
        return Err(VerifyFailure::Malformed);
    }
    Ok(())
}

/// Reassemble a [`Bulletproof`] from the wire [`BpPlus`].
///
/// The two layouts are byte-identical
/// (`A‖A1‖B‖r1‖s1‖d1‖vec(L)‖vec(R)`; the round-trip is pinned by
/// shekyl-tx-builder's mapping test), so the conversion is
/// serialize-then-`read_plus`. `read_plus` enforces reduced scalars —
/// the C++ `is_reduced(r1/s1/d1)` parity — and caps L/R at the maximal
/// round count, so a `None` here is the C++ battery's reject, not a
/// marshalling loss.
fn bulletproof_from_wire(bp: &BpPlus) -> Option<Bulletproof> {
    let mut bytes = Vec::with_capacity((6 + bp.l.len() + bp.r.len()) * 32 + 4);
    bytes.extend_from_slice(&bp.a);
    bytes.extend_from_slice(&bp.a1);
    bytes.extend_from_slice(&bp.b);
    bytes.extend_from_slice(&bp.r1);
    bytes.extend_from_slice(&bp.s1);
    bytes.extend_from_slice(&bp.d1);
    write_varint(bp.l.len(), &mut bytes).ok()?;
    for point in &bp.l {
        bytes.extend_from_slice(point);
    }
    write_varint(bp.r.len(), &mut bytes).ok()?;
    for point in &bp.r {
        bytes.extend_from_slice(point);
    }
    Bulletproof::read_plus(&mut bytes.as_slice()).ok()
}

/// K12 proper: marshal the parsed submission into [`proof::verify`]'s
/// inputs and map its error surface onto the [`VerifyFailure`] arms.
///
/// `leaf_auths` selects which vin slots contribute membership leaves: every
/// auth for a spend; the `ToKey` funding subset for a bond-post (the C++
/// caller's `spend_indices` loop, blockchain.cpp:3762-3775). It must be
/// index-aligned with `parsed.key_images` (both in vin order over the same
/// subset).
fn verify_fcmp(
    parsed: &ParsedSubmission,
    prunable: &Prunable,
    leaf_auths: &[&PqcAuth],
    tree_root: &[u8; 32],
    layers: u8,
) -> Result<(), VerifyFailure> {
    // One leaf hash per spending input, submission order — the same
    // `H_blake2b(dst ‖ hybrid_public_key)` Selene scalar the C++ caller
    // computes per input via `shekyl_fcmp_pqc_leaf_hash`
    // (blockchain.cpp:3810-3820). The caller passes `leaf_auths` already
    // narrowed to the leaf-contributing subset (every auth for a spend, the
    // `ToKey` funding subset for a bond-post), and `parsed.key_images` is the
    // matching subset by construction; the count check below enforces that
    // index alignment as a loud refusal, not an assumption. (`validate()`'s
    // arity rule covers the full `pqc_auths.len() == vin.len()`; the subset
    // alignment it does not, so it is checked here.)
    let key_images: Vec<KeyImage> = parsed
        .key_images
        .iter()
        .map(|ki| KeyImage::from_canonical_bytes(*ki))
        .collect();
    let pqc_hashes: Vec<PqcLeafScalar> = leaf_auths
        .iter()
        .map(|auth| PqcLeafScalar::from_pqc_public_key(&auth.hybrid_public_key))
        .collect();
    if pqc_hashes.len() != key_images.len() {
        return Err(VerifyFailure::Malformed);
    }
    let Ok(num_inputs) = u32::try_from(key_images.len()) else {
        return Err(VerifyFailure::Malformed);
    };

    let fcmp_proof = ShekylFcmpProof {
        data: prunable.fcmp_proof.clone(),
        num_inputs,
        tree_depth: layers,
    };

    // The signable hash is the canonical prefix hash — the C++ caller's
    // `get_transaction_prefix_hash(tx)` (blockchain.cpp:3372, threaded to
    // the verify at :3849).
    match proof::verify(
        &fcmp_proof,
        &key_images,
        &prunable.pseudo_outs,
        &pqc_hashes,
        tree_root,
        layers,
        parsed.tx.prefix_hash(),
    ) {
        Ok(true) => Ok(()),
        // `verify` never returns `Ok(false)` today (failures are `Err`);
        // treat it as the deterministic-reject arm if it ever does.
        Ok(false) => Err(VerifyFailure::Malformed),
        // Snapshot-tree inconsistencies a rebuild against a fresh root
        // fixes (the VerifyFailure::StaleRoot contract): the depth cap and
        // a root the tree codec cannot deserialize at the claimed layer
        // count. Everything else — proof bytes, counts, batch failure —
        // is deterministic for these bytes against this root.
        Err(VerifyError::TreeDepthTooLarge(_) | VerifyError::InvalidTreeRoot) => {
            Err(VerifyFailure::StaleRoot)
        }
        Err(e) => {
            // Operator-facing diagnostic only (§2.2 wire minimalism: the
            // verdict stays cause-coarse); enable the crate's debug level
            // to see which proof-system arm refused.
            tracing::debug!(error = ?e, "FCMP++ proof verification refused the submission");
            Err(VerifyFailure::Malformed)
        }
    }
}

/// K13 proper: the `verify_transaction_pqc_auth` battery
/// (`tx_pqc_verify.cpp`), natively.
///
/// Per auth: version pin, zero flags, known scheme id ∈ {1,2}, per-scheme
/// key-blob length bounds, then the hybrid Ed25519+ML-DSA (or M-of-N multisig
/// container) verification over the per-input signing-preimage hash — computed
/// by `shekyl-wire`'s [`pqc_signing_payload_hashes`], the pinned Rust twin of
/// C++ `get_transaction_signed_payload`.
///
/// MSW-6 (PQC_MULTISIG.md §16.3) withdrew the former tx-wide scheme-id
/// agreement (every input matching `pqc_auths[0]`). Its stated scheme-downgrade
/// purpose was vacuous — self-referential, and per-output binding is the leaf
/// hash `h_pqc = H(hybrid_public_key)`; its actual effect, foreclosing a
/// solo/multisig cross-model linkage, has no externality (one-time keys, FCMP++
/// proof over the whole tree — no other set shrinks) and mirrors the opt-in
/// scheme_id=2 self-marking cost, so it is a wallet coin-selection invariant —
/// a blocking E′/MS-5 ship gate, not merely tracked — not a consensus rule (and
/// not TM-1, whose disposition rests on the linkage being unmechanizable).
/// Dropped here in lockstep with the C++ battery so the K13 differential holds.
///
/// [`pqc_signing_payload_hashes`]: shekyl_wire::transaction::Transaction::pqc_signing_payload_hashes
fn verify_pqc_auths(parsed: &ParsedSubmission, pqc_auths: &[PqcAuth]) -> Result<(), VerifyFailure> {
    // Arity (`:159-163`): one auth per input, non-empty. Structural for a
    // validate()d spend; kept as a loud refusal, not an assumption.
    if pqc_auths.is_empty() || pqc_auths.len() != parsed.tx.prefix.inputs.len() {
        return Err(VerifyFailure::Malformed);
    }
    let payload_hashes = parsed.tx.pqc_signing_payload_hashes();
    if payload_hashes.len() != pqc_auths.len() {
        return Err(VerifyFailure::Malformed);
    }
    for (auth, payload_hash) in pqc_auths.iter().zip(&payload_hashes) {
        verify_pqc_auth_slot(auth, payload_hash)?;
    }
    Ok(())
}

/// One `pqc_auths` slot, verified in isolation: version pin, zero flags,
/// known scheme id, per-scheme key-blob bounds, then the hybrid
/// Ed25519+ML-DSA or multisig verification over that input's
/// signing-preimage hash.
///
/// Split out of [`verify_pqc_auths`] so the debit arm's **possession
/// pre-gate** ([`verify_debit_slot_possession`]) and K13 proper run the
/// *same* verification rather than a pair free to drift. The pre-gate
/// exists to keep an unauthenticated caller out of the §8.7.1.1 gather's
/// lock-held per-shard scan; a slot the pre-gate accepted and K13 later
/// rejected would hand back exactly the work the gate denies.
///
/// **Facts-free by construction** — every operand is the auth blob and the
/// payload hash, neither of which comes from the snapshot. That is what
/// makes it legal to run *before* the fact gather, and it is the property
/// to preserve: a daemon fact reaching this function would put a DB read
/// back in front of the authorization it is ordered to follow.
fn verify_pqc_auth_slot(auth: &PqcAuth, payload_hash: &[u8; 32]) -> Result<(), VerifyFailure> {
    if auth.auth_version != 1 || auth.flags != 0 {
        return Err(VerifyFailure::Malformed);
    }
    if auth.scheme_id != PQC_SCHEME_SINGLE && auth.scheme_id != PQC_SCHEME_MULTISIG {
        return Err(VerifyFailure::Malformed);
    }
    if auth.hybrid_public_key.is_empty() {
        return Err(VerifyFailure::Malformed);
    }
    match auth.scheme_id {
        PQC_SCHEME_SINGLE => {
            if auth.hybrid_public_key.len() != PQC_HYBRID_SINGLE_KEY_LEN {
                return Err(VerifyFailure::Malformed);
            }
            let Ok(public_key) = HybridPublicKey::from_canonical_bytes(&auth.hybrid_public_key)
            else {
                return Err(VerifyFailure::Malformed);
            };
            let Ok(signature) = HybridSignature::from_canonical_bytes(&auth.hybrid_signature)
            else {
                return Err(VerifyFailure::Malformed);
            };
            if HybridEd25519MlDsa
                .verify(
                    &public_key,
                    shekyl_crypto_pq::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
                    payload_hash,
                    &signature,
                )
                .is_err()
            {
                return Err(VerifyFailure::Malformed);
            }
        }
        PQC_SCHEME_MULTISIG => {
            if auth.hybrid_public_key.len() < MULTISIG_KEY_HEADER_LEN
                || auth.hybrid_public_key.len() > PQC_MAX_PUBLIC_KEY_BLOB
            {
                return Err(VerifyFailure::Malformed);
            }
            // Group-id binding no longer exists (Option E′ deleted
            // `group_id`; identity is the address fingerprint). This is
            // the single `verify_multisig` entry point.
            if verify_multisig(
                auth.scheme_id,
                &auth.hybrid_public_key,
                &auth.hybrid_signature,
                payload_hash,
            )
            .is_err()
            {
                return Err(VerifyFailure::Malformed);
            }
        }
        // Excluded by the closed-set check above.
        _ => return Err(VerifyFailure::Malformed),
    }
    Ok(())
}

/// The debit arm's **possession pre-gate**: prove the submitter holds the
/// private key for the bond slot's presented authorizer, *before* the
/// §8.7.1.1 fact gather takes the pool→blockchain locks.
///
/// **Why this exists, stated as the attack it closes.** The gather's cheap
/// pin (`debit_auth_pin`, run C++-side at `daemon_submit_ffi.cpp`) compares
/// the presented key to the record's committed `bond_spend_pk`. Both are
/// **public**: `bond_spend_pk` rides the JoinMarket bond post on the wire
/// and is therefore readable by anyone who syncs the chain. Equality of two
/// public values authenticates nobody — an attacker copies the record's key
/// into `pqc_auths`, signs with garbage, passes the pin, and buys the
/// per-shard last-served scan — two LMDB seeks per served shard, with both
/// locks held, on every submit, unauthenticated. That is not a constant: a
/// `HeldShards` record is capped by the codec (`MAX_HOLDINGS_SHARDS` = 4096,
/// so ≤ 8192 seeks), but a `CompleteTree` record's all-shards form walks
/// every shard carrying a serve-credit row under that persona, which tracks
/// the frozen-segment count and therefore **grows with the chain**.
/// CompleteTree is the shape an attacker would pick. K13 does reject the
/// signature — but only after the gather has already run.
///
/// So the two checks compose, and neither is redundant:
///
/// * this one proves possession of the **presented** key (signature), and
/// * the gather's pin ties the presented key to the **record's** key.
///
/// A possession-proven caller presenting their *own* key still gets no scan
/// (the pin refuses); a caller presenting the record's key without its
/// private half never reaches the gather (this refuses). Only the holder of
/// the cold `bond_spend_pk` — the party actually entitled to exit — buys the
/// scan.
///
/// It also narrows an oracle: the pre-gate runs before *any* record read, so
/// an unauthenticated caller can no longer time submit-response latency to
/// learn whether a bond record exists.
///
/// Cost, stated exactly rather than flatteringly: the honest debit path pays
/// **one extra hybrid verify**, because K13 re-verifies this slot with all the
/// others afterwards. Deduplicating that would mean carrying "slot N is
/// already verified" state into K13 — a drift pair on the battery's most
/// safety-critical loop, to save one verify against a transaction that is
/// about to run an FCMP++ membership proof. Not worth it. For the attack case
/// the change is strictly negative work: one verify instead of the gather.
pub(crate) fn verify_debit_slot_possession(parsed: &ParsedSubmission) -> Result<(), VerifyFailure> {
    let Ct::Fcmp { pqc_auths, .. } = &parsed.tx.ct else {
        return Err(VerifyFailure::Malformed);
    };
    // The same arity pin K13 applies. Checked here too rather than assumed:
    // the pre-gate indexes `pqc_auths` by the vin's position, so a mismatched
    // arity would let it verify a slot belonging to a different input.
    if pqc_auths.is_empty() || pqc_auths.len() != parsed.tx.prefix.inputs.len() {
        return Err(VerifyFailure::Malformed);
    }
    let Some((index, bond)) = parsed.bond_post() else {
        return Err(VerifyFailure::Malformed);
    };
    let payload_hashes = parsed.tx.pqc_signing_payload_hashes();
    if payload_hashes.len() != pqc_auths.len() {
        return Err(VerifyFailure::Malformed);
    }
    let (Some(auth), Some(payload_hash)) = (pqc_auths.get(index), payload_hashes.get(index)) else {
        return Err(VerifyFailure::Malformed);
    };
    verify_pqc_auth_slot(auth, payload_hash)?;

    // The vin-only half of UB9, run here for the same reason possession is:
    // it needs no daemon fact, and the gather it precedes performs a
    // lock-held per-shard scan. Possession alone does not stop a cold-key
    // holder minting fresh signatures over a vin these guards already doom —
    // each forged txid is unknown, so the gather's identity clause never
    // fires for it. The shared consensus function, never a local restatement:
    // the block path runs the identical checks inside
    // `verify_unbond_bond_post`, in the same order.
    let Some(vin) = retention_vin(bond, RetentionBondPostKind::Unbond, &[]) else {
        return Err(VerifyFailure::Malformed);
    };
    if unbond_vin_statics(&vin).is_err() {
        return Err(VerifyFailure::Malformed);
    }
    Ok(())
}
