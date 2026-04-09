// Copyright (c) 2014-2022, The Monero Project
// Copyright (c) 2024-2026, The Shekyl Foundation
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

#include <cstring>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "crypto/chacha.h"
#include "crypto/crypto.h"

TEST(xchacha20, round_trip_64_bytes)
{
  const uint8_t key[CHACHA_KEY_SIZE] = {
    0x0f, 0x62, 0xb5, 0x08, 0x5b, 0xae, 0x01, 0x54,
    0xa7, 0xfa, 0x4d, 0xa0, 0xf3, 0x46, 0x99, 0xec,
    0x3f, 0x92, 0xe5, 0x38, 0x8b, 0xde, 0x31, 0x84,
    0xd7, 0x2a, 0x7d, 0xd0, 0x23, 0x76, 0xc9, 0x1c
  };
  const uint8_t nonce[CHACHA_IV_SIZE] = {
    0x28, 0x8f, 0xf6, 0x5d, 0xc4, 0x2b, 0x92, 0xf9,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
  };

  const std::string plaintext(64, '\x42');
  std::string ciphertext(64, '\0');
  std::string recovered(64, '\0');

  crypto::xchacha20(plaintext.data(), plaintext.size(), key, nonce, &ciphertext[0]);
  ASSERT_NE(ciphertext, plaintext);

  crypto::xchacha20(ciphertext.data(), ciphertext.size(), key, nonce, &recovered[0]);
  ASSERT_EQ(recovered, plaintext);
}

TEST(xchacha20, round_trip_1_byte)
{
  const uint8_t key[CHACHA_KEY_SIZE] = {0};
  const uint8_t nonce[CHACHA_IV_SIZE] = {0};
  const char plain = 0xAB;
  char cipher = 0;
  char back = 0;

  crypto::xchacha20(&plain, 1, key, nonce, &cipher);
  ASSERT_NE(cipher, plain);

  crypto::xchacha20(&cipher, 1, key, nonce, &back);
  ASSERT_EQ(back, plain);
}

TEST(xchacha20, empty_data)
{
  const uint8_t key[CHACHA_KEY_SIZE] = {0};
  const uint8_t nonce[CHACHA_IV_SIZE] = {0};
  crypto::xchacha20(nullptr, 0, key, nonce, nullptr);
}

TEST(xchacha20, different_nonces_produce_different_output)
{
  const uint8_t key[CHACHA_KEY_SIZE] = {1};
  uint8_t nonce_a[CHACHA_IV_SIZE] = {0};
  uint8_t nonce_b[CHACHA_IV_SIZE] = {0};
  nonce_a[0] = 0x0A;
  nonce_b[0] = 0x0B;

  const std::string plaintext(32, '\x00');
  std::string ct_a(32, '\0');
  std::string ct_b(32, '\0');

  crypto::xchacha20(plaintext.data(), plaintext.size(), key, nonce_a, &ct_a[0]);
  crypto::xchacha20(plaintext.data(), plaintext.size(), key, nonce_b, &ct_b[0]);
  ASSERT_NE(ct_a, ct_b);
}

TEST(xchacha20, cpp_overload_round_trip)
{
  crypto::chacha_key key;
  memset(key.data(), 0x42, CHACHA_KEY_SIZE);
  crypto::chacha_iv iv;
  memset(iv.data, 0x24, CHACHA_IV_SIZE);

  const std::string plaintext = "Shekyl wallet encryption test";
  std::string ciphertext(plaintext.size(), '\0');
  std::string recovered(plaintext.size(), '\0');

  crypto::xchacha20(plaintext.data(), plaintext.size(), key, iv, &ciphertext[0]);
  ASSERT_NE(ciphertext, plaintext);

  crypto::xchacha20(ciphertext.data(), ciphertext.size(), key, iv, &recovered[0]);
  ASSERT_EQ(recovered, plaintext);
}

TEST(xchacha20, nonce_size_is_24)
{
  static_assert(CHACHA_IV_SIZE == 24, "XChaCha20 requires 24-byte nonce");
  static_assert(sizeof(crypto::chacha_iv) == 24, "chacha_iv struct must be 24 bytes");
}
