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

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"

#include <cstring>

#include "cryptonote_basic/account.h"

class test_ge_frombytes_vartime
{
public:
  static const size_t loop_count = 10000;

  bool init()
  {
    // A canonical point to decompress: a fresh account's spend key. (This
    // used to build a whole C++ transaction to read a key image out of it;
    // that builder left with the C++ tx_extra codec, TXE-Q1, and the
    // benchmark's subject was never the transaction.)
    cryptonote::account_base alice;
    alice.generate(crypto::secret_key{}, false, false, cryptonote::FAKECHAIN);
    const crypto::public_key& pk = alice.get_keys().m_account_address.m_spend_public_key;
    memcpy(m_key.bytes, &pk, 32);
    ge_p3 check;
    return ge_frombytes_vartime(&check, (const unsigned char*) &pk) == 0;
  }

  bool test()
  {
    ge_p3 unp;
    return ge_frombytes_vartime(&unp, (const unsigned char*) &m_key) == 0;
  }

private:
  ct::key m_key;
};
