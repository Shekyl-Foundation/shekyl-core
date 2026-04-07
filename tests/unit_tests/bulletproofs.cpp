// Copyright (c) 2017-2022, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "gtest/gtest.h"

#include "string_tools.h"
#include "fcmp/rctOps.h"
#include "fcmp/rctSigs.h"
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "misc_log_ex.h"

// These tests previously used hardcoded Monero v2 BP+ transaction hex blobs.
// Shekyl's rctSigBase serialization now rejects any type other than
// RCTTypeFcmpPlusPlusPqc (type 7), so v2 blobs with RCTTypeBulletproofPlus
// (type 6) fail to deserialize.  The underlying weight calculation logic is
// still exercised for FCMP++ transactions in the FCMP unit tests.
//
// TODO: Replace these blobs with serialized RCTTypeFcmpPlusPlusPqc transactions
// once a test-blob generator is available.

TEST(bulletproof, DISABLED_weight_equal)
{
  static const char *tx_hex = "";
  cryptonote::blobdata bd;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(std::string(tx_hex), bd));
  cryptonote::transaction tx;
  crypto::hash tx_hash, tx_prefix_hash;
  ASSERT_TRUE(parse_and_validate_tx_from_blob(bd, tx, tx_hash, tx_prefix_hash));
  ASSERT_TRUE(tx.version == 2);
  ASSERT_TRUE(rct::is_rct_bulletproof_plus(tx.rct_signatures.type));
  const uint64_t tx_size = bd.size();
  const uint64_t tx_weight = cryptonote::get_transaction_weight(tx);
  ASSERT_TRUE(tx_weight == tx_size); // it has two outputs, <= 2 makes weight == size
}

TEST(bulletproof, DISABLED_weight_more)
{
  static const char *tx_hex = "";
  cryptonote::blobdata bd;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(std::string(tx_hex), bd));
  cryptonote::transaction tx;
  crypto::hash tx_hash, tx_prefix_hash;
  ASSERT_TRUE(parse_and_validate_tx_from_blob(bd, tx, tx_hash, tx_prefix_hash));
  ASSERT_TRUE(tx.version == 2);
  ASSERT_TRUE(rct::is_rct_bulletproof_plus(tx.rct_signatures.type));
  const uint64_t tx_size = bd.size();
  const uint64_t tx_weight = cryptonote::get_transaction_weight(tx);
  ASSERT_TRUE(tx_weight > tx_size); // it has four outputs, > 2 makes weight > size
}

TEST(bulletproof, DISABLED_weight_pruned)
{
  static const char * const txs_hex[] = { "" };
  for (const char *tx_hex: txs_hex)
  {
    cryptonote::blobdata bd;
    ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(std::string(tx_hex), bd));
    cryptonote::transaction tx, pruned_tx;
    crypto::hash tx_hash, tx_prefix_hash;
    ASSERT_TRUE(parse_and_validate_tx_from_blob(bd, tx, tx_hash, tx_prefix_hash));
    ASSERT_TRUE(tx.version == 2);
    ASSERT_FALSE(tx.pruned);
    ASSERT_TRUE(rct::is_rct_bulletproof_plus(tx.rct_signatures.type));
    const uint64_t tx_weight = cryptonote::get_transaction_weight(tx);
    ASSERT_TRUE(parse_and_validate_tx_base_from_blob(bd, pruned_tx));
    ASSERT_TRUE(pruned_tx.version == 2);
    ASSERT_TRUE(pruned_tx.pruned);
    const uint64_t pruned_tx_weight = cryptonote::get_pruned_transaction_weight(pruned_tx);
    ASSERT_EQ(tx_weight, pruned_tx_weight);
  }
}
