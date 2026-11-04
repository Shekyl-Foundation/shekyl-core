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

#pragma once

#include <list>
#include "serialization/keyvalue_serialization.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_config.h"

namespace cryptonote
{


#define BC_COMMANDS_POOL_BASE 2000


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_NEW_TRANSACTIONS
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 2;

    struct request_t
    {
      std::vector<blobdata>   txs;
      std::string _; // padding
      bool dandelionpp_fluff; //zero initialization defaults to stem mode

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txs)
        KV_SERIALIZE(_)
        KV_SERIALIZE_OPT(dandelionpp_fluff, true) // backwards compatible mode is fluff
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
  };

  struct CORE_SYNC_DATA
  {
    uint64_t current_height;
    uint64_t cumulative_difficulty;
    uint64_t cumulative_difficulty_top64;
    crypto::hash  top_id;
    // No stripe seed (PDM-Q7, 2026-09-21): the stripe engine is deleted and
    // the handshake carries no self-asserted storage posture. An unknown
    // key is read with the key ignored.

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(current_height)
      KV_SERIALIZE(cumulative_difficulty)
      if (is_store)
        KV_SERIALIZE(cumulative_difficulty_top64)
      else
        KV_SERIALIZE_OPT(cumulative_difficulty_top64, (uint64_t)0)
      KV_SERIALIZE_VAL_POD_AS_BLOB(top_id)
    END_KV_SERIALIZE_MAP()
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_GET_TXPOOL_COMPLEMENT
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 10;

    struct request_t
    {
      std::vector<crypto::hash> hashes;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(hashes)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
  };
    
}
