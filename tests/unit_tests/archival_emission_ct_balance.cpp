// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Q11 balance-exclusion guard — the reopen clause's armed trigger
// (REWARD_EMISSION_E3_GATING_ROUND.md §7 Q11, ratified ACCEPT with this KAT
// named as the regression guard).
//
// The ratified property: the emission vin's backing pseudo-out (the
// membership proof's re-randomized commitment) moves NO value — it is
// structurally excluded from the CT balance. The mint is the only created
// value: sum(pseudoOuts) + total_reward*H = sum(out masks) + fee*H, where
// pseudoOuts covers exactly the fee inputs.
//
// The guard is STRUCTURAL and has three parts (EMISSION_CLAIM_BUILDER.md §3
// CB-4). Routing the backing into the balance is not a line-removal — it is
// a coordinated change across all three:
//
//   (i)   blob boundary — the backing lives in the vin's opaque
//         `canonical_bytes`; the balance path reads only `rv.p.pseudoOuts`
//         and NOTHING deserializes the blob into pseudoOuts;
//   (ii)  dispatch size check — `tx_verification_utils.cpp:175`
//         (`rv.p.pseudoOuts.size() != spend_input_count`); and
//   (iii) leaf size check — `rctSigs.cpp:362`
//         (`rv.p.pseudoOuts.size() == fee_input_count`).
//
// This KAT is the TRIPWIRE on the guard, not the guard itself. It is
// necessary-not-sufficient, and its coverage boundary is stated per arm so
// the next reviewer reads what each arm does and does NOT exercise:
//
//  1. backing_identity_O_vs_O_prime — BITES against a refactor that parsed
//     the blob into the balance OPERANDS (leg i, operand side): it derives
//     `spend_input_count`/`total_reward` through the SAME production
//     functions the dispatch uses (classify_archival_tx +
//     shekyl_checked_sum_amounts), on two txs differing ONLY in the
//     backing bytes, and asserts the operands do not move. Also pins leg
//     (iii): `EXPECT_TRUE(verdict_O)` fails if the leaf size check is
//     bumped to `+ 1`. Does NOT cover: the `verdict_O == verdict_O_prime`
//     identity is green-by-construction — `verCtSemanticsEmission`'s
//     signature `(rv, total_reward, fee_input_count)` has no parameter the
//     blob-resident backing can enter, so equal verdicts document the
//     signature-level exclusion, they are not the coordinated-regression
//     catch.
//
//  2. backing_inclusion_shape_rejects_in_production — BITES against
//     weakening the balance EQUATION (leg iii, value side): a fixture whose
//     balance closes ONLY with the backing summed must reject through the
//     production leaf, and the same fixture with the backing appended must
//     pass the single-sourced balance FFI — proving the rejection is the
//     exclusion working, not an unrelated malformation. Does NOT cover:
//     the blob boundary (leg i, pseudoOuts side) or the dispatch check
//     (leg ii).
//
//  NOT COVERED by any arm here: driving the full production dispatch
//  (`ver_non_input_consensus_templated`) with a valid FCMP++ emission tx
//  and asserting the CT-balance verdict is INVARIANT under `canonical_bytes`
//  variation — the arm that would fail if a future deserialization change
//  parsed the backing out of the blob into `pseudoOuts` (leg i, pseudoOuts
//  side + leg ii). That arm is harness-gated on a valid-proof emission-tx
//  builder; it rides the claim-builder PR (CB-4 follow-up (a)).
//
// A future edit that routes the backing into the balance MUST flip the
// biting assertions here; per the Q11 reversion clause that edit is a
// consensus change requiring a design-round reopen, not a "completeness"
// cleanup.

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <vector>

extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_basic/cryptonote_basic.h"
#include "fcmp/bulletproofs_plus.h"
#include "fcmp/rctOps.h"
#include "fcmp/rctSigs.h"
#include "shekyl/shekyl_ffi.h"

using namespace cryptonote;

namespace {

constexpr uint64_t kFee = 7;
constexpr uint64_t kReward = 100;

// Production reward-total derivation: the SAME overflow-checked FFI the
// dispatch emission branch uses (tx_verification_utils.cpp), fed the
// plaintext vout amounts. The vin blob is never an input, so the mint
// credit cannot be perturbed by the backing bytes. Calling the production
// FFI (not a test-local sum) is the point — a mirror would verify the
// mirror, not the code the dispatch runs (50-testing.mdc "Test the
// production code, not a local re-implementation").
uint64_t checked_reward_sum(const transaction& tx)
{
  std::vector<uint64_t> vout_amounts;
  vout_amounts.reserve(tx.vout.size());
  for (const auto& o : tx.vout)
    vout_amounts.push_back(o.amount);
  uint64_t total = 0;
  const uint8_t overflow = shekyl_checked_sum_amounts(
    vout_amounts.empty() ? nullptr : vout_amounts.data(),
    vout_amounts.size(), &total);
  EXPECT_EQ(overflow, 0u);
  return total;
}

rct::key add_scalars(const rct::key& a, const rct::key& b)
{
  rct::key out;
  sc_add(out.bytes, a.bytes, b.bytes);
  return out;
}

// Balanced emission rct set for one fee input and two outputs (CT values
// 100 reward-mirror + 3 change): pseudo(10) + 100*H = (100 + 3)*H + 7*H,
// blinding closed by g_pseudo = g0 + g1. Canonical single aggregate BP+.
rct::rctSig make_balanced_emission_rv()
{
  const rct::key g0 = rct::skGen();
  const rct::key g1 = rct::skGen();
  const rct::key g_pseudo = add_scalars(g0, g1);

  rct::rctSig rv{};
  rv.type = rct::RCTTypeFcmpPlusPlusPqc;
  rv.txnFee = kFee;
  rv.p.fcmp_pp_proof = {0x01};
  rv.p.pseudoOuts.push_back(rct::commit(10, g_pseudo));
  rv.outPk.resize(2);
  rv.outPk[0].mask = rct::commit(kReward, g0);
  rv.outPk[1].mask = rct::commit(3, g1);
  rv.enc_amounts.resize(2);
  rv.enc_labels.resize(2);
  rv.p.bulletproofs_plus.push_back(rct::bulletproof_plus_PROVE(
    std::vector<uint64_t>{kReward, 3}, rct::keyV{g0, g1}));
  return rv;
}

// Emission tx around a given rct set. The vin's backing pseudo-out is a
// 32-byte field inside the opaque canonical blob (emission_wire.rs
// MembershipOnlyBacking.pseudo_out); this stage never parses the blob, so
// the backing commitment's serialized bytes stand in at a fixed offset.
transaction make_emission_tx(const rct::rctSig& rv, const rct::key& backing_pseudo_out)
{
  transaction tx{};
  // Real emission txs are version 3 (min accepted version, blockchain.cpp);
  // the CT-balance / dispatch surface under test doesn't branch on it, but
  // the fixture matches the production surface so it cannot drift from it.
  tx.version = 3;

  txin_archival_reward_emission vin{};
  vin.canonical_bytes.assign(128, 0x5a);
  vin.canonical_bytes[0] = 0x04;
  std::memcpy(vin.canonical_bytes.data() + 32, backing_pseudo_out.bytes, 32);
  tx.vin.push_back(vin);
  tx.vin.push_back(txin_to_key{});

  const uint64_t amounts[2] = {kReward, 0};
  for (size_t i = 0; i < 2; ++i)
  {
    tx_out vout{};
    vout.amount = amounts[i];
    txout_to_tagged_key tagged{};
    memset(&tagged.key, 0x30 + static_cast<int>(i), sizeof(tagged.key));
    tagged.view_tag.data = 0;
    vout.target = tagged;
    tx.vout.push_back(vout);
  }
  tx.rct_signatures = rv;
  return tx;
}

std::vector<uint8_t> flatten(const rct::keyV& ks)
{
  std::vector<uint8_t> out;
  out.reserve(ks.size() * 32);
  for (const auto& k : ks)
    out.insert(out.end(), k.bytes, k.bytes + 32);
  return out;
}

} // namespace

// Arm 1: backing-on-O and backing-on-O' (different committed values, the
// only delta between the two transactions). The balance operands, derived
// through the PRODUCTION operand functions, are invariant under the
// backing bytes (leg i operand side); the balanced tx verifies (leg iii);
// the verdict identity documents the signature-level exclusion.
TEST(archival_emission_ct_balance, backing_identity_O_vs_O_prime)
{
  const rct::rctSig rv = make_balanced_emission_rv();

  const rct::key backing_O = rct::commit(500, rct::skGen());
  const rct::key backing_O_prime = rct::commit(9999, rct::skGen());
  const transaction tx_O = make_emission_tx(rv, backing_O);
  const transaction tx_O_prime = make_emission_tx(rv, backing_O_prime);

  // Operand derivation through the PRODUCTION single-source classifier
  // (classify_archival_tx, cryptonote_basic.h) — the same call the
  // dispatch emission branch makes. It inspects only the vin variant
  // TYPE, never `canonical_bytes`, so the fee-input-count operand cannot
  // move when the backing bytes change. A future refactor that parsed the
  // blob into the operand derivation (leg i, operand side) flips these.
  const archival_tx_classification cls_O = classify_archival_tx(tx_O.vin);
  const archival_tx_classification cls_O_prime = classify_archival_tx(tx_O_prime.vin);
  ASSERT_EQ(cls_O.kind, archival_tx_kind::emission);
  ASSERT_EQ(cls_O_prime.kind, archival_tx_kind::emission);
  EXPECT_EQ(cls_O.spend_input_count, cls_O_prime.spend_input_count);
  EXPECT_EQ(cls_O.special_index, cls_O_prime.special_index);

  const uint64_t total_reward = checked_reward_sum(tx_O);
  EXPECT_EQ(total_reward, checked_reward_sum(tx_O_prime));

  // verCtSemanticsEmission's signature (rv, total_reward, fee_input_count)
  // has NO parameter through which the blob-resident backing could enter,
  // so verdict_O == verdict_O_prime is green-by-construction and documents
  // that signature-level exclusion — it is NOT the coordinated-regression
  // catch. The biting assertion is EXPECT_TRUE(verdict_O): the balanced
  // 1-pseudo-out tx passes only while pseudoOuts covers exactly the fee
  // inputs (leaf size check rctSigs.cpp:362); bumping that check to `+ 1`
  // breaks it. The dispatch check (:175) and the blob→pseudoOuts boundary
  // are the harness-gated follow-up (see header).
  const bool verdict_O = rct::verCtSemanticsEmission(
    tx_O.rct_signatures, total_reward, cls_O.spend_input_count);
  const bool verdict_O_prime = rct::verCtSemanticsEmission(
    tx_O_prime.rct_signatures, total_reward, cls_O_prime.spend_input_count);
  EXPECT_TRUE(verdict_O);
  EXPECT_EQ(verdict_O, verdict_O_prime);
}

// Arm 2: a fixture balanced ONLY with the backing in the sum. Production
// must reject; the manually-included shape must pass the underlying FFI,
// proving the fixture is exactly the coordinated regression's accepting
// case (backing appended to pseudoOuts, size check bumped in lockstep).
TEST(archival_emission_ct_balance, backing_inclusion_shape_rejects_in_production)
{
  const rct::key m1 = rct::skGen();
  const rct::key m2 = rct::skGen();

  // pseudo(10, m1) + backing(50, m2) + 100*H = out(153, m1+m2) + 7*H
  // holds iff the backing is summed; without it the balance is short by
  // commit(50, m2).
  const rct::key backing = rct::commit(50, m2);
  const rct::key g_out = add_scalars(m1, m2);

  rct::rctSig rv{};
  rv.type = rct::RCTTypeFcmpPlusPlusPqc;
  rv.txnFee = kFee;
  rv.p.fcmp_pp_proof = {0x01};
  rv.p.pseudoOuts.push_back(rct::commit(10, m1));
  rv.outPk.resize(1);
  rv.outPk[0].mask = rct::commit(153, g_out);
  rv.enc_amounts.resize(1);
  rv.enc_labels.resize(1);
  rv.p.bulletproofs_plus.push_back(rct::bulletproof_plus_PROVE(
    std::vector<uint64_t>{153}, rct::keyV{g_out}));

  // Production: backing excluded → balance short → reject.
  EXPECT_FALSE(rct::verCtSemanticsEmission(rv, kReward, /*fee_input_count=*/1));

  // The coordinated-regression shape: backing appended to the pseudo side
  // (pseudo count 2 = fee_input_count + 1). The single-sourced balance
  // FFI accepts it — so the production rejection above is the Q11
  // exclusion doing the work, not an unrelated malformation.
  const std::vector<uint8_t> pseudo_flat =
    flatten(rct::keyV{rv.p.pseudoOuts[0], backing});
  const std::vector<uint8_t> mask_flat = flatten(rct::keyV{rv.outPk[0].mask});
  const uint8_t included_rc = shekyl_archival_verify_bond_post_ct_balance(
    pseudo_flat.data(), 2, mask_flat.data(), 1, kFee,
    /*bond_credit=*/0, /*bond_debit=*/kReward);
  EXPECT_EQ(included_rc, SHEKYL_ARCHIVAL_BOND_CT_BALANCE_OK);
}
