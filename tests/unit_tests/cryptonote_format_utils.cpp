// Copyright (c) 2025, The Monero Project
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

#include "gtest/gtest.h"

#include "crypto/generators.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"

TEST(cn_format_utils, add_extra_nonce_to_tx_extra)
{
    static constexpr std::size_t max_nonce_size = TX_EXTRA_NONCE_MAX_COUNT + 1; // we *can* test higher if desired

    for (int empty_prefix = 0; empty_prefix < 2; ++empty_prefix)
    {
        std::vector<std::uint8_t> extra_prefix;
        if (!empty_prefix)
            cryptonote::add_tx_pub_key_to_extra(extra_prefix, crypto::get_H());

        std::vector<std::uint8_t> extra;
        std::string nonce;
        std::vector<cryptonote::tx_extra_field> tx_extra_fields;
        extra.reserve(extra_prefix.size() + max_nonce_size + 1 + 10);
        nonce.reserve(max_nonce_size);
        tx_extra_fields.reserve(2);
        for (std::size_t nonce_size = 0; nonce_size <= max_nonce_size; ++nonce_size)
        {
            extra = extra_prefix;
            nonce.resize(nonce_size);
            if (nonce.size())
                memset(&nonce[0], '%', nonce.size());
            tx_extra_fields.clear();

            const std::size_t expected_extra_size = extra_prefix.size() + 1
                + tools::get_varint_byte_size(nonce_size) + nonce_size;
            const bool expected_success = nonce_size <= TX_EXTRA_NONCE_MAX_COUNT;

            // add nonce and do detailed test
            const bool add_success = cryptonote::add_extra_nonce_to_tx_extra(extra, nonce);
            ASSERT_EQ(expected_success, add_success);
            if (!expected_success)
                continue;
            ASSERT_EQ(expected_extra_size, extra.size());
            ASSERT_EQ(0, memcmp(extra_prefix.data(), extra.data(), extra_prefix.size()));
            const std::uint8_t *p = extra.data() + extra_prefix.size();
            ASSERT_EQ(TX_EXTRA_NONCE, *p);
            ++p;
            std::size_t read_nonce_size = 0;
            const int varint_size = tools::read_varint((const uint8_t*)(p), // copy p
                (const uint8_t*) extra.data() + extra.size(),
                read_nonce_size);
            ASSERT_EQ(tools::get_varint_byte_size(nonce_size), varint_size);
            p += varint_size;
            for (std::size_t i = 0; i < nonce_size; ++i)
            {
                ASSERT_EQ('%', *p);
                ++p;
            }
            ASSERT_EQ(extra.data() + extra.size(), p);

            // do integration test with higher-level tx_extra parsing code
            ASSERT_TRUE(cryptonote::parse_tx_extra(extra, tx_extra_fields));
            if (empty_prefix)
            {
                ASSERT_EQ(1, tx_extra_fields.size());
                const auto &nonce_field = std::get<cryptonote::tx_extra_nonce>(tx_extra_fields.at(0));
                ASSERT_EQ(nonce, nonce_field.nonce);
            }
            else
            {
                ASSERT_EQ(2, tx_extra_fields.size());
                const auto &pk_field = std::get<cryptonote::tx_extra_pub_key>(tx_extra_fields.at(0));
                ASSERT_EQ(crypto::get_H(), pk_field.pub_key);
                const auto &nonce_field = std::get<cryptonote::tx_extra_nonce>(tx_extra_fields.at(1));
                ASSERT_EQ(nonce, nonce_field.nonce);
            }
        }
    }
}

// The Rust grammar in rust/shekyl-wire/src/tx_extra.rs states that merge-mining
// (0x03) and "mysterious minergate" (0xDE) are not part of the genesis tx_extra
// grammar. These two tests hold the C++ parser to the same tag set, so the two
// parsers cannot disagree about which transactions exist (rule 60).
namespace
{
    // Builds a tx_extra carrying a single raw tag. Written in bytes rather than
    // through an add_* helper on purpose: the helpers for these tags are deleted,
    // and a test that could only be written while the producer existed would not
    // outlive it.
    std::vector<std::uint8_t> raw_tagged_extra(std::uint8_t tag, const std::vector<std::uint8_t>& body)
    {
        std::vector<std::uint8_t> extra;
        extra.push_back(tag);
        extra.insert(extra.end(), body.begin(), body.end());
        return extra;
    }
}

TEST(cn_format_utils, rejects_the_inherited_merge_mining_tag)
{
    // The 0x03 body is a length-prefixed blob holding (varint depth || 32-byte
    // merkle root), so the field is V(33) || 0x00 || 32 bytes. Without the length
    // prefix the parser fails on trailing garbage instead of on the tag, which
    // would make this test pass for the wrong reason.
    std::vector<std::uint8_t> body{0x21, 0x00};
    body.insert(body.end(), 32, 0xAB);

    const std::vector<std::uint8_t> extra = raw_tagged_extra(0x03, body);

    std::vector<cryptonote::tx_extra_field> fields;
    EXPECT_FALSE(cryptonote::parse_tx_extra(extra, fields))
        << "the merge-mining tag is not in the genesis grammar and must not parse";
}

TEST(cn_format_utils, rejects_the_inherited_minergate_tag)
{
    // A string field: varint length 4, then the bytes.
    const std::vector<std::uint8_t> body{0x04, 0xDE, 0xAD, 0xBE, 0xEF};

    const std::vector<std::uint8_t> extra = raw_tagged_extra(0xDE, body);

    std::vector<cryptonote::tx_extra_field> fields;
    EXPECT_FALSE(cryptonote::parse_tx_extra(extra, fields))
        << "the minergate tag is not in the genesis grammar and must not parse";
}

// Positive limb: shedding those two arms must not narrow the grammar that is
// still in use. A tag adjacent to the deleted ones on both sides still parses.
TEST(cn_format_utils, still_accepts_the_tags_that_remain)
{
    std::vector<std::uint8_t> extra;
    ASSERT_TRUE(cryptonote::add_tx_pub_key_to_extra(extra, crypto::get_H()));

    ASSERT_TRUE(cryptonote::add_extra_nonce_to_tx_extra(extra, std::string(8, 'x')));

    std::vector<cryptonote::tx_extra_field> fields;
    ASSERT_TRUE(cryptonote::parse_tx_extra(extra, fields));
    EXPECT_EQ(2u, fields.size());
    EXPECT_TRUE(std::holds_alternative<cryptonote::tx_extra_pub_key>(fields.at(0)));
    EXPECT_TRUE(std::holds_alternative<cryptonote::tx_extra_nonce>(fields.at(1)));
}
