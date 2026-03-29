// Copyright (c) 2022-2024, The Monero Project
// Copyright (c) 2024-2026, The Shekyl Project
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

#include <cassert>
#include <cstdint>
#include <cstring>
#include <mutex>

#include "generators.h"
#include "hash.h"

namespace crypto
{

// ed25519 generator G: {x, 4/5} (positive x when decompressing y = 4/5)
static const unsigned char G_bytes[32] = {
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

// Pedersen commitment generator H: toPoint(cn_fast_hash(G))
static const unsigned char H_bytes[32] = {
  0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
  0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
  0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
  0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94
};

static ge_p3 G_p3_val;
static ge_p3 H_p3_val;
static ge_cached G_cached_val;
static ge_cached H_cached_val;
static std::once_flag init_gens_once_flag;

static void init_gens()
{
  std::call_once(init_gens_once_flag, []() {
    const int G_ok = ge_frombytes_vartime(&G_p3_val, G_bytes);
    const int H_ok = ge_frombytes_vartime(&H_p3_val, H_bytes);
    (void)G_ok; assert(G_ok == 0);
    (void)H_ok; assert(H_ok == 0);

    ge_p3_to_cached(&G_cached_val, &G_p3_val);
    ge_p3_to_cached(&H_cached_val, &H_p3_val);
  });
}

public_key get_G()
{
  public_key pk;
  static_assert(sizeof(pk.data) == sizeof(G_bytes), "");
  memcpy(pk.data, G_bytes, 32);
  return pk;
}

public_key get_H()
{
  public_key pk;
  static_assert(sizeof(pk.data) == sizeof(H_bytes), "");
  memcpy(pk.data, H_bytes, 32);
  return pk;
}

ge_p3 get_G_p3()
{
  init_gens();
  return G_p3_val;
}

ge_p3 get_H_p3()
{
  init_gens();
  return H_p3_val;
}

ge_cached get_G_cached()
{
  init_gens();
  return G_cached_val;
}

ge_cached get_H_cached()
{
  init_gens();
  return H_cached_val;
}

} //namespace crypto
