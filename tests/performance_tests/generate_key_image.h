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

#include "single_tx_test_base.h"

class test_generate_key_image : public single_tx_test_base
{
public:
  static const size_t loop_count = 1000;

  bool init()
  {
    using namespace cryptonote;

    if (!single_tx_test_base::init())
      return false;

    account_keys bob_keys = m_bob.get_keys();

    crypto::key_derivation recv_derivation;
    crypto::generate_key_derivation(m_tx_pub_key, bob_keys.m_view_secret_key, recv_derivation);

    // Inline derivation_to_scalar: Hs(derivation || varint(0))
    crypto::ec_scalar hs_scalar;
    {
      struct { crypto::key_derivation d; uint8_t vi; } buf;
      buf.d = recv_derivation;
      buf.vi = 0;
      crypto::hash_to_scalar(&buf, sizeof(crypto::key_derivation) + 1, hs_scalar);
    }

    // derive_public_key: hs_scalar * G + spend_public_key
    ge_p3 point1;
    ge_scalarmult_base(&point1, reinterpret_cast<const unsigned char*>(&hs_scalar));
    ge_p3 point2;
    ge_frombytes_vartime(&point2, reinterpret_cast<const unsigned char*>(&bob_keys.m_account_address.m_spend_public_key));
    ge_cached point2c;
    ge_p3_to_cached(&point2c, &point2);
    ge_p1p1 sum;
    ge_add(&sum, &point1, &point2c);
    ge_p3 result;
    ge_p1p1_to_p3(&result, &sum);
    ge_p3_tobytes(reinterpret_cast<unsigned char*>(&m_in_ephemeral.pub), &result);

    // derive_secret_key: hs_scalar + spend_secret_key
    sc_add(reinterpret_cast<unsigned char*>(&m_in_ephemeral.sec),
           reinterpret_cast<const unsigned char*>(&hs_scalar),
           reinterpret_cast<const unsigned char*>(&bob_keys.m_spend_secret_key));

    return true;
  }

  bool test()
  {
    crypto::key_image ki;
    crypto::generate_key_image(m_in_ephemeral.pub, m_in_ephemeral.sec, ki);
    return true;
  }

private:
  cryptonote::keypair m_in_ephemeral;
};
