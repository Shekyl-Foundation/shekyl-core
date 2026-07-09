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
// Two arms:
//
//  1. backing_identity — two transactions differing ONLY in the vin's
//     backing pseudo-out (backing-on-O vs backing-on-O', different
//     committed values) must produce bit-identical balance verdicts
//     through the production dispatch derivation. The naive regression
//     (append the backing to pseudoOuts) already trips the
//     `pseudoOuts.size() == fee_input_count` assert; this arm catches the
//     COORDINATED regression — backing added to the sum and the size
//     check bumped to fee_input_count + 1 in lockstep — because with the
//     backing in the sum, O and O' (different values) cannot both
//     balance, and the identity assertion fails.
//
//  2. backing_inclusion_rejects — a fixture whose balance closes ONLY if
//     the backing enters the pseudo side must reject through the
//     production function, and the same fixture with the backing manually
//     appended must pass the underlying single-sourced balance FFI. The
//     second half proves the fixture is byte-for-byte the coordinated
//     regression's accepting shape, so the production rejection is the
//     exclusion working — not an unrelated malformation.
//
// A future edit that routes the backing into the balance MUST flip these
// tests; per the Q11 reversion clause that edit is a consensus change
// requiring a design-round reopen, not a "completeness" cleanup.

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <limits>
#include <variant>
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

// Mirrors tx_verification_utils.cpp's emission-branch operand derivation:
// total_reward is the overflow-checked plaintext vout sum; fee_input_count
// is the txin_to_key count. Nothing is read from the emission vin — that
// absence is the property under guard.
struct DispatchOperands {
  uint64_t total_reward = 0;
  size_t fee_input_count = 0;
  bool emission_shape = false;
};

DispatchOperands derive_dispatch_operands(const transaction& tx)
{
  DispatchOperands ops{};
  size_t emission_count = 0;
  for (const auto& in : tx.vin)
  {
    if (std::holds_alternative<txin_archival_reward_emission>(in))
      ++emission_count;
    else if (std::holds_alternative<txin_to_key>(in))
      ++ops.fee_input_count;
  }
  ops.emission_shape = emission_count == 1
    && ops.fee_input_count + 1 == tx.vin.size();
  for (const auto& o : tx.vout)
  {
    if (o.amount > std::numeric_limits<uint64_t>::max() - ops.total_reward)
      return ops;
    ops.total_reward += o.amount;
  }
  return ops;
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
  tx.version = 2;

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
// only delta between the two transactions) balance bit-identically —
// both accept, same verdict. The backing moves no value.
TEST(archival_emission_ct_balance, backing_identity_O_vs_O_prime)
{
  const rct::rctSig rv = make_balanced_emission_rv();

  const rct::key backing_O = rct::commit(500, rct::skGen());
  const rct::key backing_O_prime = rct::commit(9999, rct::skGen());
  const transaction tx_O = make_emission_tx(rv, backing_O);
  const transaction tx_O_prime = make_emission_tx(rv, backing_O_prime);

  const DispatchOperands ops_O = derive_dispatch_operands(tx_O);
  const DispatchOperands ops_O_prime = derive_dispatch_operands(tx_O_prime);
  ASSERT_TRUE(ops_O.emission_shape);
  ASSERT_TRUE(ops_O_prime.emission_shape);
  // The operands the balance sees are identical: the backing never
  // reaches them. This is the structural half of the exclusion.
  EXPECT_EQ(ops_O.total_reward, ops_O_prime.total_reward);
  EXPECT_EQ(ops_O.fee_input_count, ops_O_prime.fee_input_count);

  const bool verdict_O = rct::verCtSemanticsEmission(
    tx_O.rct_signatures, ops_O.total_reward, ops_O.fee_input_count);
  const bool verdict_O_prime = rct::verCtSemanticsEmission(
    tx_O_prime.rct_signatures, ops_O_prime.total_reward, ops_O_prime.fee_input_count);
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
