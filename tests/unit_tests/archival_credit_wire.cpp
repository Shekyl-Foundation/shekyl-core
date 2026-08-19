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
#include "blockchain_utilities/bootstrap_serialization.h"
#include "serialization/binary_archive.h"
#include "serialization/binary_utils.h"
#include "shekyl/shekyl_ffi.h"

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
// `assert(ver == 4)` in the deleted wallet2.h relied on the same one.)
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
  ASSERT_TRUE(cryptonote::parse_archival_attestation_from_extra(extra, got));
  ASSERT_EQ(got, blob);

  // sort must NOT hit "someone forgot to add a case", and the sorted extra still
  // round-trips the blob.
  std::vector<uint8_t> sorted;
  ASSERT_TRUE(cryptonote::sort_tx_extra(extra, sorted));
  std::string got_sorted;
  ASSERT_TRUE(cryptonote::parse_archival_attestation_from_extra(sorted, got_sorted));
  ASSERT_EQ(got_sorted, blob);
}

// The reader's tri-state contract: "parsed, tag absent" is true with an EMPTY blob (the committed
// empty set) and "tx_extra unparseable" is false (headers UNREADABLE). Collapsing the two is the
// admission bug the verify's HEADERS_UNREADABLE verdict exists to prevent -- a malformed coinbase
// extra must never pass for the empty attestation set.
TEST(archival_credit_wire, attestation_reader_splits_absent_from_unreadable)
{
  // Parsed extra with no attestation tag -> true, empty blob.
  std::vector<uint8_t> extra;
  crypto::public_key pk;
  memset(&pk, 0x22, sizeof(pk));
  ASSERT_TRUE(cryptonote::add_tx_pub_key_to_extra(extra, pk));
  std::string blob{"sentinel"};  // must be cleared, not left stale
  ASSERT_TRUE(cryptonote::parse_archival_attestation_from_extra(extra, blob));
  ASSERT_TRUE(blob.empty());

  // An attestation tag followed by an unparseable tail -> false: the tag's bytes must NOT be
  // returned as if the extra were well-formed.
  std::string records(config::ARCHIVAL_ATTESTATION_HEADER_BYTES, '\x10');
  std::vector<uint8_t> malformed;
  ASSERT_TRUE(cryptonote::add_archival_attestation_to_tx_extra(malformed, records));
  malformed.push_back(0xFE);  // truncated/unknown trailing field -> parse_tx_extra fails
  blob = "sentinel";
  ASSERT_FALSE(cryptonote::parse_archival_attestation_from_extra(malformed, blob));
  ASSERT_TRUE(blob.empty());
}

// The header length matches the Rust canonical record; the record cap is pinned.
TEST(archival_credit_wire, attestation_cap_constants)
{
  static_assert(config::ARCHIVAL_ATTESTATION_HEADER_BYTES == 49,
                "must match shekyl-archival-retention ATTESTATION_HEADER_LEN");
  ASSERT_EQ(config::ARCHIVAL_MAX_ATTESTATION_RECORDS, 256u);
}

// Credit-wire CW-1b-iv cross-language gate. The block-hash differential is structurally blind to the attestation
// witness (it is not in the block blob), so the real check on this surface is that C++ config
// agrees with the Rust authority exposed via FFI. Constant equality catches C++-side drift from
// the genesis-frozen Rust values; the >= catches a coarse cap that would reject what Rust admits.
TEST(archival_credit_wire, attestation_constants_match_rust_ffi_authority)
{
  EXPECT_EQ(static_cast<uint64_t>(config::ARCHIVAL_MAX_ATTESTATION_RECORDS),
            shekyl_archival_max_attestation_records());
  EXPECT_EQ(static_cast<uint64_t>(config::ARCHIVAL_ATTESTATION_HEADER_BYTES),
            shekyl_archival_attestation_header_bytes());
  // LOAD-BEARING, and equality is the point. BELOW Rust's exact maximum, C++ would reject on the
  // wire a witness Rust admits — a consensus split. ABOVE it, the surplus is free padding an
  // attacker may send on every block. C++ derives its cap from the same operands, so this asserts
  // both directions at once against the Rust authority, never a C++ mirror of it.
  EXPECT_EQ(static_cast<uint64_t>(config::ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES),
            shekyl_archival_attestation_witness_max_bytes())
      << "the C++ witness cap must be exactly Rust's canonical maximum: below it C++ rejects a "
         "witness Rust admits, above it every block carries free attacker padding";
}

// Bootstrap export/import must carry the witness, or a node built from blocks.dat
// holds none for any block it imported: it can serve no witness to its IBD peers
// and, after the cutover, cannot re-drive their admission. The field is exercised
// through the real bootstrap::block_package codec — the one blockchain_export
// writes and blockchain_import reads — not a stand-in.
TEST(archival_credit_wire, bootstrap_block_package_round_trips_the_attestation_witness)
{
  const std::string witness(1000, '\x5a');

  cryptonote::bootstrap::block_package in{};
  in.block = cryptonote::block{};
  in.block_weight = 1234;
  in.cumulative_difficulty = 5678;
  in.coins_generated = 91011;
  in.attestation_witness = witness;

  const std::string blob = cryptonote::t_serializable_object_to_blob(in);

  cryptonote::bootstrap::block_package out{};
  ASSERT_TRUE(::serialization::parse_binary(blob, out));
  EXPECT_EQ(out.attestation_witness, witness);
  // Not vacuous: the surrounding fields survived too, so this is the real record
  // shape and not a partially-parsed one.
  EXPECT_EQ(out.block_weight, 1234u);
  EXPECT_EQ(out.coins_generated, 91011u);

  // An empty witness (interim / all-miss block, or one past the retention horizon)
  // round-trips as empty rather than failing the parse.
  cryptonote::bootstrap::block_package empty_in = in;
  empty_in.attestation_witness.clear();
  cryptonote::bootstrap::block_package empty_out{};
  ASSERT_TRUE(::serialization::parse_binary(cryptonote::t_serializable_object_to_blob(empty_in), empty_out));
  EXPECT_TRUE(empty_out.attestation_witness.empty());
}

// A bootstrap file is an untrusted input too, so block_package bounds its own blob
// the way block_complete_entry's KV map does — the importer is not the guard.
TEST(archival_credit_wire, bootstrap_block_package_refuses_an_oversized_attestation_witness)
{
  cryptonote::bootstrap::block_package in{};
  in.block = cryptonote::block{};
  in.attestation_witness.assign(config::ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES + 1, '\x5a');

  std::string blob;
  cryptonote::bootstrap::block_package out{};
  const bool stored = ::serialization::dump_binary(in, blob);
  const bool parsed = stored && ::serialization::parse_binary(blob, out);
  EXPECT_FALSE(parsed) << "an oversized witness parsed out of a bootstrap chunk";

  // Control: exactly at the cap is admitted, so the refusal above is the bound and
  // not a blanket failure of the codec on large blobs.
  cryptonote::bootstrap::block_package at_cap_in = in;
  at_cap_in.attestation_witness.assign(config::ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES, '\x5a');
  cryptonote::bootstrap::block_package at_cap_out{};
  ASSERT_TRUE(::serialization::parse_binary(cryptonote::t_serializable_object_to_blob(at_cap_in), at_cap_out));
  EXPECT_EQ(at_cap_out.attestation_witness.size(),
            config::ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES);
}
