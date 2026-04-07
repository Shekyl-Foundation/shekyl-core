// Copyright (c) 2016-2022, The Monero Project
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
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "wallet/wallet2.h"

class uri : public ::testing::Test
{
protected:
  void SetUp() override
  {
    acc.generate();
    test_address = cryptonote::get_account_address_as_str(cryptonote::MAINNET, false, acc.get_keys().m_account_address);
  }

  cryptonote::account_base acc;
  std::string test_address;
};

#define PARSE_URI(uri, expected) \
  std::string address, payment_id, recipient_name, description, error; \
  uint64_t amount; \
  std::vector<std::string> unknown_parameters; \
  tools::wallet2 w(cryptonote::MAINNET); \
  bool ret = w.parse_uri(uri, address, payment_id, amount, description, recipient_name, unknown_parameters, error); \
  ASSERT_EQ(ret, expected);

TEST_F(uri, empty_string)
{
  PARSE_URI("", false);
}

TEST_F(uri, no_scheme)
{
  PARSE_URI("shekyl", false);
}

TEST_F(uri, bad_scheme)
{
  PARSE_URI("http://foo", false);
}

TEST_F(uri, scheme_not_first)
{
  PARSE_URI(" shekyl:", false);
}

TEST_F(uri, no_body)
{
  PARSE_URI("shekyl:", false);
}

TEST_F(uri, no_address)
{
  PARSE_URI("shekyl:?", false);
}

TEST_F(uri, bad_address)
{
  PARSE_URI("shekyl:44444", false);
}

TEST_F(uri, good_address)
{
  const std::string uri_str = "shekyl:" + test_address;
  PARSE_URI(uri_str, true);
  ASSERT_EQ(address, test_address);
}

TEST_F(uri, good_integrated_address)
{
  const std::string uri_str = "shekyl:" + test_address;
  PARSE_URI(uri_str, true);
}

TEST_F(uri, parameter_without_inter)
{
  PARSE_URI("shekyl:" + test_address + "&amount=1", false);
}

TEST_F(uri, parameter_without_equals)
{
  PARSE_URI("shekyl:" + test_address + "?amount", false);
}

TEST_F(uri, parameter_without_value)
{
  PARSE_URI("shekyl:" + test_address + "?tx_amount=", false);
}

TEST_F(uri, negative_amount)
{
  PARSE_URI("shekyl:" + test_address + "?tx_amount=-1", false);
}

TEST_F(uri, bad_amount)
{
  PARSE_URI("shekyl:" + test_address + "?tx_amount=alphanumeric", false);
}

TEST_F(uri, duplicate_parameter)
{
  PARSE_URI("shekyl:" + test_address + "?tx_amount=1&tx_amount=1", false);
}

TEST_F(uri, unknown_parameter)
{
  PARSE_URI("shekyl:" + test_address + "?unknown=1", true);
  ASSERT_EQ(unknown_parameters.size(), 1u);
  ASSERT_EQ(unknown_parameters[0], "unknown=1");
}

TEST_F(uri, unknown_parameters)
{
  PARSE_URI("shekyl:" + test_address + "?tx_amount=1&unknown=1&tx_description=desc&foo=bar", true);
  ASSERT_EQ(unknown_parameters.size(), 2u);
  ASSERT_EQ(unknown_parameters[0], "unknown=1");
  ASSERT_EQ(unknown_parameters[1], "foo=bar");
}

TEST_F(uri, empty_payment_id)
{
  PARSE_URI("shekyl:" + test_address + "?tx_payment_id=", false);
}

TEST_F(uri, bad_payment_id)
{
  PARSE_URI("shekyl:" + test_address + "?tx_payment_id=1234567890", false);
}

TEST_F(uri, short_payment_id)
{
  PARSE_URI("shekyl:" + test_address + "?tx_payment_id=1234567890123456", false);
}

TEST_F(uri, long_payment_id)
{
  PARSE_URI("shekyl:" + test_address + "?tx_payment_id=1234567890123456789012345678901234567890123456789012345678901234", true);
  ASSERT_EQ(address, test_address);
  ASSERT_EQ(payment_id, "1234567890123456789012345678901234567890123456789012345678901234");
}

TEST_F(uri, payment_id_with_integrated_address)
{
  PARSE_URI("shekyl:" + test_address + "?tx_payment_id=1234567890123456", false);
}

TEST_F(uri, empty_description)
{
  PARSE_URI("shekyl:" + test_address + "?tx_description=", true);
  ASSERT_EQ(description, "");
}

TEST_F(uri, empty_recipient_name)
{
  PARSE_URI("shekyl:" + test_address + "?recipient_name=", true);
  ASSERT_EQ(recipient_name, "");
}

TEST_F(uri, non_empty_description)
{
  PARSE_URI("shekyl:" + test_address + "?tx_description=foo", true);
  ASSERT_EQ(description, "foo");
}

TEST_F(uri, non_empty_recipient_name)
{
  PARSE_URI("shekyl:" + test_address + "?recipient_name=foo", true);
  ASSERT_EQ(recipient_name, "foo");
}

TEST_F(uri, url_encoding)
{
  PARSE_URI("shekyl:" + test_address + "?tx_description=foo%20bar", true);
  ASSERT_EQ(description, "foo bar");
}

TEST_F(uri, non_alphanumeric_url_encoding)
{
  PARSE_URI("shekyl:" + test_address + "?tx_description=foo%2x", true);
  ASSERT_EQ(description, "foo%2x");
}

TEST_F(uri, truncated_url_encoding)
{
  PARSE_URI("shekyl:" + test_address + "?tx_description=foo%2", true);
  ASSERT_EQ(description, "foo%2");
}

TEST_F(uri, percent_without_url_encoding)
{
  PARSE_URI("shekyl:" + test_address + "?tx_description=foo%", true);
  ASSERT_EQ(description, "foo%");
}

TEST_F(uri, url_encoded_once)
{
  PARSE_URI("shekyl:" + test_address + "?tx_description=foo%2020", true);
  ASSERT_EQ(description, "foo 20");
}
