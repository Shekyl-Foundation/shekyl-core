// Copyright (c) 2014-2026, The Monero Project
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

#pragma once

#include "cryptonote_basic/cryptonote_format_utils.h"
#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>
#include "fcmp/ct_ops.h"
#include "shekyl/economics.h"

namespace cryptonote
{
  //---------------------------------------------------------------
  // frozen_segment_count is the D2 escalation operand n and is deliberately
  // REQUIRED (not defaulted, unlike the economics tail): a defaulted n is a
  // silently-wrong split the moment the asymptote is non-neutral, priced at
  // template build and refused at connect — a chain halt. Every call site must
  // state its n; production reads it via Blockchain::parent_frozen_segment_count.
  bool construct_miner_tx(size_t height, size_t median_weight, uint64_t already_generated_coins, size_t current_block_weight, uint64_t fee, uint64_t frozen_segment_count, const account_public_address &miner_address, transaction& tx, const blobdata& extra_nonce = blobdata(), size_t max_outs = 999, uint8_t hard_fork_version = 1, shekyl::tx_volume_window tx_volume = {}, shekyl::supply_facts supply = {}, uint64_t genesis_ng_height = 0);

  struct tx_block_template_backlog_entry
  {
    crypto::hash id;
    uint64_t weight;
    uint64_t fee;
  };

  //---------------------------------------------------------------
  bool generate_genesis_block(
      block& bl
    , std::string const & genesis_tx
    , uint32_t nonce
    );

  class Blockchain;
  // seed_hash nullptr = look up from `pb` (or zeros at genesis). The
  // all-zero hash is a valid RandomX seed, so this stays nullable.
  bool get_block_longhash(const Blockchain *pb, const blobdata& bd, crypto::hash& res, const uint64_t height, const crypto::hash *seed_hash = nullptr);
  bool get_block_longhash(const Blockchain *pb, const block& b, crypto::hash& res, const uint64_t height, const crypto::hash *seed_hash = nullptr);
  crypto::hash get_block_longhash(const Blockchain *pb, const block& b, const uint64_t height, const crypto::hash *seed_hash = nullptr);
  bool get_altblock_longhash(const block& b, crypto::hash& res, const crypto::hash& seed_hash);

}
