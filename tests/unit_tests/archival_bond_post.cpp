// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "gtest/gtest.h"

#include <cstring>
#include <sstream>
#include <variant>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "fcmp/bulletproofs_plus.h"
#include "fcmp/rctOps.h"
#include "fcmp/rctSigs.h"
#include "serialization/binary_archive.h"
#include "shekyl/consensus_constants_generated.h"

using namespace cryptonote;

namespace {

txin_archival_bond_post make_join_market_vin()
{
  txin_archival_bond_post bond{};
  bond.hybrid_public_key.assign(64, 0xAB);
  memset(&bond.p_canonical_id, 0x11, sizeof(bond.p_canonical_id));
  bond.post_kind = static_cast<uint8_t>(archival_bond_post_kind::JoinMarket);
  bond.holdings.kind = archival_holdings_kind::ShardSetCompact;
  bond.holdings.shard_ids = {7, 42};
  bond.bonded_total_atomic = 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;
  bond.bond_credit = bond.bonded_total_atomic;
  bond.bond_debit = 0;
  return bond;
}

} // namespace

TEST(archival_bond_post, vin_deserializes_with_tag_0x03)
{
  txin_v vin = make_join_market_vin();

  std::ostringstream oss;
  binary_archive<true> oar(oss);
  ASSERT_TRUE(::do_serialize(oar, vin));
  const std::string wire = oss.str();
  ASSERT_FALSE(wire.empty());
  EXPECT_EQ(static_cast<uint8_t>(wire[0]), 0x03u);

  txin_v decoded;
  binary_archive<false> iar({reinterpret_cast<const uint8_t*>(wire.data()), wire.size()});
  ASSERT_TRUE(::do_serialize(iar, decoded));
  ASSERT_TRUE(std::holds_alternative<txin_archival_bond_post>(decoded));

  const auto& out = std::get<txin_archival_bond_post>(decoded);
  EXPECT_EQ(out.holdings.shard_ids.size(), 2u);
  EXPECT_EQ(out.holdings.shard_ids[0], 7u);
  EXPECT_EQ(out.holdings.shard_ids[1], 42u);
  EXPECT_EQ(out.bond_credit, 2 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC);
  EXPECT_EQ(out.post_kind, static_cast<uint8_t>(archival_bond_post_kind::JoinMarket));
}

TEST(archival_bond_post, bond_floor_matches_shard_count)
{
  archival_holdings_descriptor holdings{};
  holdings.kind = archival_holdings_kind::ShardSetCompact;
  holdings.shard_ids = {1, 2, 3};
  EXPECT_EQ(archival_bond_floor(holdings), 3 * SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC);

  holdings.kind = archival_holdings_kind::CompleteTree;
  holdings.shard_ids.clear();
  EXPECT_EQ(archival_bond_floor(holdings), SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC);
}

TEST(archival_bond_post, tx_input_mixing_rejects_bond_with_serve_credit)
{
  transaction tx{};
  tx.vin.push_back(make_join_market_vin());
  tx.vin.push_back(txin_archival_serve_credit_response{});
  EXPECT_FALSE(check_inputs_types_supported(tx));
}

TEST(archival_bond_post, rct_balance_rejects_zero_bond_terms)
{
  constexpr uint64_t amount = 750'000'000;

  rct::rctSig rv{};
  rv.type = rct::RCTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  rv.p.pseudoOuts.push_back(rct::scalarmultH(rct::d2h(amount)));

  EXPECT_FALSE(rct::verRctSemanticsBondPost(rv, 0, 0));
}

TEST(archival_bond_post, rct_balance_includes_bond_credit_term)
{
  constexpr uint64_t bond_credit = 750'000'000;

  rct::rctSig rv{};
  rv.type = rct::RCTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  rv.p.pseudoOuts.push_back(rct::scalarmultH(rct::d2h(bond_credit)));

  EXPECT_FALSE(rct::verRctSemanticsSimple(rv));
  EXPECT_TRUE(rct::verRctSemanticsBondPost(rv, bond_credit, 0));
  EXPECT_FALSE(rct::verRctSemanticsBondPost(rv, bond_credit - 1, 0));
  EXPECT_FALSE(rct::verRctSemanticsBondPost(rv, 0, bond_credit));
}

TEST(archival_bond_post, rct_balance_rejects_noncanonical_bulletproof_layout)
{
  constexpr uint64_t bond_debit = 500'000'000;

  rct::rctSig rv{};
  rv.type = rct::RCTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  const rct::key mask_scalar = rct::skGen();
  rv.outPk.resize(2);
  rv.outPk[0].mask = rct::commit(bond_debit / 2, mask_scalar);
  rv.outPk[1].mask = rct::commit(bond_debit / 2, mask_scalar);
  rv.enc_amounts.resize(2);
  rv.enc_labels.resize(2);
  // Two outputs share one blinding scalar → pseudo must carry 2× that blinding so the
  // bond balance equation holds; failure is then only the non-canonical two-proof layout.
  const rct::key zero_mask = rct::commit(0, mask_scalar);
  rv.p.pseudoOuts.push_back(rct::addKeys(zero_mask, zero_mask));
  rv.p.bulletproofs_plus.push_back(rct::bulletproof_plus_PROVE(bond_debit / 2, mask_scalar));
  rv.p.bulletproofs_plus.push_back(rct::bulletproof_plus_PROVE(bond_debit / 2, mask_scalar));

  EXPECT_FALSE(rct::verRctSemanticsBondPost(rv, 0, bond_debit));
}

TEST(archival_bond_post, rct_balance_includes_bond_debit_term)
{
  constexpr uint64_t bond_debit = 500'000'000;

  rct::rctSig rv{};
  rv.type = rct::RCTTypeFcmpPlusPlusPqc;
  rv.txnFee = 0;
  rv.p.fcmp_pp_proof = {0x01};
  const rct::key mask_scalar = rct::skGen();
  rv.outPk.resize(1);
  rv.outPk[0].mask = rct::commit(bond_debit, mask_scalar);
  rv.enc_amounts.resize(1);
  rv.enc_labels.resize(1);
  // Funding input contributes only blinding; bond_debit is the cleartext source term.
  rv.p.pseudoOuts.push_back(rct::commit(0, mask_scalar));
  rv.p.bulletproofs_plus.push_back(rct::bulletproof_plus_PROVE(bond_debit, mask_scalar));

  EXPECT_FALSE(rct::verRctSemanticsSimple(rv));
  EXPECT_TRUE(rct::verRctSemanticsBondPost(rv, 0, bond_debit));
  EXPECT_FALSE(rct::verRctSemanticsBondPost(rv, bond_debit, 0));
}
