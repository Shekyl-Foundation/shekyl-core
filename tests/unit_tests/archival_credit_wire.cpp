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

// Credit-wire block-header carrier tests (ARCHIVAL_CREDIT_WIRE.md §3).

#include "gtest/gtest.h"

#include <cstring>
#include <sstream>
#include <string>

#include <boost/archive/portable_binary_iarchive.hpp>
#include <boost/archive/portable_binary_oarchive.hpp>

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_config.h"
#include "serialization/binary_archive.h"

// ARCHIVAL_CREDIT_WIRE.md §3: empty is attestation_root(&[]), never null_hash.
TEST(archival_credit_wire, attestation_root_defaults_to_empty_set_root)
{
  cryptonote::block_header hdr;
  ASSERT_EQ(hdr.attestation_root, cryptonote::empty_attestation_root());
  ASSERT_NE(hdr.attestation_root, crypto::null_hash);

  crypto::hash test_root;
  memset(&test_root, 0xAD, sizeof(test_root));
  hdr.attestation_root = test_root;

  std::string blob;
  {
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    ASSERT_TRUE(do_serialize(ar, hdr));
    blob = oss.str();
  }

  cryptonote::block_header hdr2;
  {
    binary_archive<false> ar({reinterpret_cast<const uint8_t*>(blob.data()), blob.size()});
    ASSERT_TRUE(do_serialize(ar, hdr2));
  }
  ASSERT_EQ(hdr2.attestation_root, test_root);
  // Final field on the wire: last 32 bytes of the serialized header.
  ASSERT_GE(blob.size(), sizeof(crypto::hash));
  ASSERT_EQ(0, memcmp(blob.data() + blob.size() - sizeof(crypto::hash), &test_root, sizeof(test_root)));
}

// The boost block serializer's class-version gate
// (BOOST_CLASS_VERSION(cryptonote::block, 1), cryptonote_boost_serialization.h):
// a current archive stores class version 1, so loading it must NOT trip the
// pre-V9 rejection, and attestation_root must ride the archive. (The stored
// version is delivered to serialize() at load — the wallet cache's
// `assert(ver == 4)` in wallet2.h relies on the same mechanism.)
TEST(archival_credit_wire, block_boost_archive_round_trips_attestation_root)
{
  cryptonote::block bl{};
  bl.miner_tx.version = 1;
  bl.timestamp = 42;
  memset(&bl.attestation_root, 0xAD, sizeof(bl.attestation_root));

  std::stringstream ss;
  boost::archive::portable_binary_oarchive a(ss);
  a << bl;

  cryptonote::block bl2{};
  boost::archive::portable_binary_iarchive a2(ss);
  a2 >> bl2;

  ASSERT_EQ(bl2.timestamp, bl.timestamp);
  ASSERT_EQ(bl2.attestation_root, bl.attestation_root);
}

// Phase 1 wire: the coinbase tx_extra attestation carrier round-trips, and
// sort_tx_extra handles the new tag (the pick<> exhaustiveness trap at
// format_utils.cpp — a missing case makes every coinbase carrying it fail to sort).
TEST(archival_credit_wire, tx_extra_attestation_round_trips_and_sorts)
{
  // 3 canonical headers (ARCHIVAL_ATTESTATION_HEADER_BYTES each), distinct per record.
  std::string blob;
  for (uint8_t i = 0; i < 3; ++i)
    blob.append(config::ARCHIVAL_ATTESTATION_HEADER_BYTES, static_cast<char>(0x10 + i));
  ASSERT_EQ(blob.size(), 3 * config::ARCHIVAL_ATTESTATION_HEADER_BYTES);

  // A mixed extra (pubkey + attestation) so the sort has to order the new tag.
  std::vector<uint8_t> extra;
  crypto::public_key pk;
  memset(&pk, 0x22, sizeof(pk));
  ASSERT_TRUE(cryptonote::add_tx_pub_key_to_extra(extra, pk));
  ASSERT_TRUE(cryptonote::add_archival_attestation_to_tx_extra(extra, blob));

  // parse recognizes the new field.
  std::vector<cryptonote::tx_extra_field> fields;
  ASSERT_TRUE(cryptonote::parse_tx_extra(extra, fields));

  // get round-trips the blob byte-identically.
  std::string got;
  ASSERT_TRUE(cryptonote::get_archival_attestation_from_extra(extra, got));
  ASSERT_EQ(got, blob);

  // sort must NOT hit "someone forgot to add a case", and the sorted extra still
  // round-trips the blob.
  std::vector<uint8_t> sorted;
  ASSERT_TRUE(cryptonote::sort_tx_extra(extra, sorted));
  std::string got_sorted;
  ASSERT_TRUE(cryptonote::get_archival_attestation_from_extra(sorted, got_sorted));
  ASSERT_EQ(got_sorted, blob);
}

// The header length matches the Rust canonical record; the record cap is pinned.
TEST(archival_credit_wire, attestation_cap_constants)
{
  static_assert(config::ARCHIVAL_ATTESTATION_HEADER_BYTES == 49,
                "must match shekyl-archival-retention ATTESTATION_HEADER_LEN");
  ASSERT_EQ(config::ARCHIVAL_MAX_ATTESTATION_RECORDS, 256u);
}
