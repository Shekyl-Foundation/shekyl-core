// Copyright (c) 2014-2022, The Monero Project
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

#include "include_base_utils.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "storages/portable_storage_template_helper.h"

TEST(protocol_pack, protocol_pack_command)
{
  epee::byte_slice buff;
  cryptonote::NOTIFY_RESPONSE_CHAIN_ENTRY::request r;
  r.start_height = 1;
  r.total_height = 3;
  for(int i = 1; i < 10000; i += i*10)
  {
    r.m_block_ids.resize(i, crypto::hash{});
    bool res = epee::serialization::store_t_to_binary(r, buff);
    ASSERT_TRUE(res);

    cryptonote::NOTIFY_RESPONSE_CHAIN_ENTRY::request r2;
    res = epee::serialization::load_t_from_binary(r2, epee::to_span(buff));
    ASSERT_TRUE(res);
    ASSERT_TRUE(r.m_block_ids.size() == i);
    ASSERT_TRUE(r.start_height == 1);
    ASSERT_TRUE(r.total_height == 3);
  }
}

namespace
{
  cryptonote::block_complete_entry make_bce(bool pruned, const cryptonote::blobdata& witness)
  {
    cryptonote::block_complete_entry bce;
    bce.pruned = pruned;
    bce.block = cryptonote::blobdata("\x01\x02\x03\x04", 4); // opaque block blob; the codec never parses it
    bce.block_weight = pruned ? 1234u : 0u;
    // one tx blob entry; a pruned entry is signalled by a non-null prunable_hash
    crypto::hash prunable_hash = crypto::null_hash;
    if (pruned)
      prunable_hash.data[0] = 0x11;
    bce.txs.push_back(cryptonote::tx_blob_entry(cryptonote::blobdata("\x0a\x0b\x0c", 3), prunable_hash));
    bce.attestation_witness = witness;
    return bce;
  }
}

// Credit-wire attestation witness (ARCHIVAL_CREDIT_WIRE.md §3; PR-B2): the block_complete_entry
// epee KV codec must carry the witness across the p2p wire independent of the pruned/txs branch
// (the field sits OUTSIDE the if(pruned)/else), and an absent field — an old peer, or the empty
// default that KV_SERIALIZE_OPT omits — must deserialize to empty rather than fail the load.
TEST(protocol_pack, block_complete_entry_attestation_witness_roundtrip)
{
  // Non-empty and clearly not tied to a crypto constant, so this is not vacuous-by-input.
  const cryptonote::blobdata witness(1000, '\x5a');

  for (bool pruned : {false, true})
  {
    // present -> survives, both branches
    {
      epee::byte_slice buff;
      const cryptonote::block_complete_entry in = make_bce(pruned, witness);
      ASSERT_TRUE(epee::serialization::store_t_to_binary(in, buff)) << "pruned=" << pruned;
      cryptonote::block_complete_entry out;
      ASSERT_TRUE(epee::serialization::load_t_from_binary(out, epee::to_span(buff))) << "pruned=" << pruned;
      EXPECT_EQ(out.pruned, pruned);
      EXPECT_EQ(out.attestation_witness, witness) << "pruned=" << pruned;
    }
    // absent (empty witness is omitted on the wire by KV_SERIALIZE_OPT, exactly like an old peer)
    // -> deserializes to empty, not a load failure
    {
      epee::byte_slice buff;
      const cryptonote::block_complete_entry in = make_bce(pruned, cryptonote::blobdata{});
      ASSERT_TRUE(epee::serialization::store_t_to_binary(in, buff)) << "pruned=" << pruned;
      cryptonote::block_complete_entry out;
      ASSERT_TRUE(epee::serialization::load_t_from_binary(out, epee::to_span(buff))) << "pruned=" << pruned;
      EXPECT_TRUE(out.attestation_witness.empty()) << "pruned=" << pruned;
    }
  }
}
