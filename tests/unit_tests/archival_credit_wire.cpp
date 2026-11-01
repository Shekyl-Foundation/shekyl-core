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
#include "cryptonote_config.h"
#include "serialization/binary_archive.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
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

namespace
{
// One length-prefixed tx_extra field, laid out by hand: tag, varint length,
// payload. The wire grammar's one encoder is shekyl-wire's; these tests are
// about the C++ *reader* (parse_archival_attestation_from_extra over the
// codec), so the bytes it reads are written here, where the bytes are the
// subject.
void raw_field(std::vector<uint8_t>& extra, uint8_t tag, const std::string& payload)
{
  extra.push_back(tag);
  size_t n = payload.size();
  while (n >= 0x80)
  {
    extra.push_back(static_cast<uint8_t>((n & 0x7f) | 0x80));
    n >>= 7;
  }
  extra.push_back(static_cast<uint8_t>(n));
  extra.insert(extra.end(), payload.begin(), payload.end());
}

// One kept attestation header's length (shekyl-archival-retention's
// `ATTESTATION_HEADER_LEN`): a payload size for the codec reads below.
constexpr std::size_t kRecordBytes = 49;

void pubkey_field(std::vector<uint8_t>& extra, uint8_t fill)
{
  extra.push_back(SHEKYL_TX_EXTRA_TAG_PUBKEY);
  extra.insert(extra.end(), 32, fill);
}
} // namespace

// Phase 1 wire: the coinbase tx_extra attestation carrier reads back through
// the codec byte-identically, wherever in the extra it sits (there is no
// sorter any more; the coinbase grammar fixes the order and 0x0B's place in
// it is the amendment its producer will bring).
TEST(archival_credit_wire, tx_extra_attestation_reads_back_through_the_codec)
{
  // 3 header-sized records, distinct per record. The codec reads the field
  // by tag and does not parse the records.
  std::string blob;
  for (uint8_t i = 0; i < 3; ++i)
    blob.append(kRecordBytes, static_cast<char>(0x10 + i));
  ASSERT_EQ(blob.size(), 3 * kRecordBytes);

  // pubkey then attestation, and attestation then pubkey: the read is by tag.
  for (bool attestation_first : {false, true})
  {
    std::vector<uint8_t> extra;
    if (attestation_first)
      raw_field(extra, SHEKYL_TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, blob);
    pubkey_field(extra, 0x22);
    if (!attestation_first)
      raw_field(extra, SHEKYL_TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, blob);

    std::string got;
    ASSERT_TRUE(cryptonote::parse_archival_attestation_from_extra(extra, got));
    ASSERT_EQ(got, blob);
    // And the codec read it came from, with its own code.
    ShekylOwnedBuffer field;
    ASSERT_EQ(SHEKYL_TX_EXTRA_OK, shekyl_tx_extra_field(extra.data(), extra.size(),
        SHEKYL_TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, 0, &field.buf));
    ASSERT_EQ(std::string(reinterpret_cast<const char*>(field.data()), field.size()), blob);
  }
}

// The reader's tri-state contract: "parsed, tag absent" is true with an EMPTY blob (the committed
// empty set) and "tx_extra unparseable" is false (headers UNREADABLE). Collapsing the two is the
// admission bug the verify's HEADERS_UNREADABLE verdict exists to prevent -- a malformed coinbase
// extra must never pass for the empty attestation set. The codec carries the split as two codes
// (SHEKYL_TX_EXTRA_ABSENT / SHEKYL_TX_EXTRA_MALFORMED); the reader is the adapter.
TEST(archival_credit_wire, attestation_reader_splits_absent_from_unreadable)
{
  // Parsed extra with no attestation tag -> true, empty blob.
  std::vector<uint8_t> extra;
  pubkey_field(extra, 0x22);
  std::string blob{"sentinel"};  // must be cleared, not left stale
  ASSERT_TRUE(cryptonote::parse_archival_attestation_from_extra(extra, blob));
  ASSERT_TRUE(blob.empty());
  ShekylOwnedBuffer field;
  ASSERT_EQ(SHEKYL_TX_EXTRA_ABSENT, shekyl_tx_extra_field(extra.data(), extra.size(),
      SHEKYL_TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, 0, &field.buf));

  // An attestation tag followed by an unparseable tail -> false: the tag's bytes must NOT be
  // returned as if the extra were well-formed.
  std::string records(kRecordBytes, '\x10');
  std::vector<uint8_t> malformed;
  raw_field(malformed, SHEKYL_TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, records);
  malformed.push_back(0xFE);  // truncated/unknown trailing field -> the extra does not parse
  blob = "sentinel";
  ASSERT_FALSE(cryptonote::parse_archival_attestation_from_extra(malformed, blob));
  ASSERT_TRUE(blob.empty());
  ASSERT_EQ(SHEKYL_TX_EXTRA_MALFORMED, shekyl_tx_extra_field(malformed.data(), malformed.size(),
      SHEKYL_TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, 0, &field.buf));
}

// ── Cross-language grammar parity for the 0x0B tag ──────────────────────────
//
// The C++ variant and shekyl-wire now admit the same tx_extra tag set, which is
// what lets the port's validator refuse an unparseable `extra` outright rather
// than skipping the field-shape rule. That equality is a claim about two
// encoders agreeing on bytes, and only a shared literal can test it: the
// round-trip tests on each side prove each is self-consistent, which a pair of
// mutually wrong encoders would also satisfy.
//
// The Rust leg asserts the same two literals in
// rust/shekyl-wire/tests/tx_extra_roundtrip.rs. If either side's grammar moves,
// exactly one of the two goes red.
TEST(archival_credit_wire, attestation_field_bytes_match_the_port)
{
  // Non-empty: tag 0x0B, varint length 3, then the blob. The C++ side no
  // longer encodes 0x0B (the one encoder is shekyl-wire's, pinned to these
  // same literals in tx_extra_roundtrip.rs); this leg pins that the daemon
  // *reads* the pinned bytes back as that blob.
  const std::vector<uint8_t> extra{0x0B, 0x03, 0x01, 0x02, 0x03};
  std::string got;
  ASSERT_TRUE(cryptonote::parse_archival_attestation_from_extra(extra, got));
  ASSERT_EQ(got, std::string("\x01\x02\x03", 3))
      << "the 0x0B encoding must be read back byte for byte";

  // Empty blob: a present tag with a zero-length payload encodes as two bytes.
  // That is a codec fact, not the reader's committed-empty-set — which is a
  // successful parse with the tag absent (see
  // attestation_reader_splits_absent_from_unreadable). Present-empty and absent
  // both yield an empty blob at that API; they differ only on the wire, and
  // the codec's own read tells them apart (OK with len 0 vs ABSENT).
  const std::vector<uint8_t> empty_extra{0x0B, 0x00};
  got = "sentinel";
  ASSERT_TRUE(cryptonote::parse_archival_attestation_from_extra(empty_extra, got));
  ASSERT_TRUE(got.empty());
  ShekylOwnedBuffer field;
  ASSERT_EQ(SHEKYL_TX_EXTRA_OK, shekyl_tx_extra_field(empty_extra.data(), empty_extra.size(),
      SHEKYL_TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, 0, &field.buf));
  ASSERT_EQ(0u, field.size()) << "a present-but-empty attestation is two bytes, not absent";
}
