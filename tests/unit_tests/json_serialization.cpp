
#include <optional>
#include <boost/range/adaptor/indexed.hpp>
#include <gtest/gtest.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <vector>

#include "byte_stream.h"
#include "crypto/hash.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "serialization/json_object.h"


namespace test
{
    cryptonote::transaction
    make_miner_transaction(cryptonote::account_public_address const& to)
    {
        cryptonote::transaction tx{};
        if (!cryptonote::construct_miner_tx(0, 0, 5000, 500, 500, to, tx))
            throw std::runtime_error{"transaction construction error"};

        crypto::hash id{0};
        if (!cryptonote::get_transaction_hash(tx, id))
            throw std::runtime_error{"could not get transaction hash"};

        return tx;
    }

    cryptonote::transaction
    make_transaction(
        cryptonote::account_keys const& from,
        std::vector<cryptonote::transaction> const& sources,
        std::vector<cryptonote::account_public_address> const& destinations,
        bool rct)
    {
        std::uint64_t source_amount = 0;
        std::vector<cryptonote::tx_source_entry> actual_sources;
        for (auto const& source : sources)
        {
            std::vector<cryptonote::tx_extra_field> extra_fields;
            if (!cryptonote::parse_tx_extra(source.extra, extra_fields))
                throw std::runtime_error{"invalid transaction"};

            cryptonote::tx_extra_pub_key key_field{};
            if (!cryptonote::find_tx_extra_field_by_type(extra_fields, key_field))
                throw std::runtime_error{"invalid transaction"};

            for (auto const input : boost::adaptors::index(source.vout))
            {
                source_amount += input.value().amount;
                crypto::public_key out_key{};
                std::visit([&out_key](auto const& t) {
                    using T = std::decay_t<decltype(t)>;
                    if constexpr (std::is_same_v<T, cryptonote::txout_to_key>)
                        out_key = t.key;
                    else if constexpr (std::is_same_v<T, cryptonote::txout_to_tagged_key>)
                        out_key = t.key;
                }, input.value().target);

                {
                    cryptonote::tx_source_entry src{};
                    src.real_output = 0;
                    src.real_out_tx_key = key_field.pub_key;
                    src.real_output_in_tx_index = std::size_t(input.index());
                    src.amount = input.value().amount;
                    src.rct = rct;
                    src.mask = rct::identity();
                    actual_sources.push_back(std::move(src));
                }

                for (unsigned ring = 0; ring < 10; ++ring)
                    actual_sources.back().push_output(input.index(), out_key, input.value().amount);
                actual_sources.back().mask =
                    actual_sources.back().outputs[actual_sources.back().real_output].second.mask;
            }
        }

        std::vector<cryptonote::tx_destination_entry> to;
        for (auto const& destination : destinations)
            to.push_back({(source_amount / destinations.size()), destination, false});

        cryptonote::transaction tx{};

        crypto::secret_key tx_key{};

        std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
        subaddresses[from.m_account_address.m_spend_public_key] = {0,0};

        if (!cryptonote::construct_tx_and_get_tx_key(from, subaddresses, actual_sources, to, std::nullopt, {}, tx, tx_key, rct, true, 1))
            throw std::runtime_error{"transaction construction error"};

        return tx;
    }
}

namespace
{
    template<typename T>
    T test_json(const T& value)
    {
      epee::byte_stream buffer;
      {
        rapidjson::Writer<epee::byte_stream> dest{buffer};
        cryptonote::json::toJsonValue(dest, value);
      }

      rapidjson::Document doc;
      doc.Parse(reinterpret_cast<const char*>(buffer.data()), buffer.size());
      if (doc.HasParseError())
      {
        throw cryptonote::json::PARSE_FAIL();
      }

      T out{};
      cryptonote::json::fromJsonValue(doc, out);
      return out;
    }
} // anonymous

TEST(JsonSerialization, VectorBytes)
{
    EXPECT_EQ(std::vector<std::uint8_t>{}, test_json(std::vector<std::uint8_t>{}));
    EXPECT_EQ(std::vector<std::uint8_t>{0x00}, test_json(std::vector<std::uint8_t>{0x00}));
}

TEST(JsonSerialization, InvalidVectorBytes)
{
    rapidjson::Document doc;
    doc.SetString("1");

    std::vector<std::uint8_t> out;
    EXPECT_THROW(cryptonote::json::fromJsonValue(doc, out), cryptonote::json::BAD_INPUT);
}

TEST(JsonSerialization, MinerTransaction)
{
    cryptonote::account_base acct;
    acct.generate();
    const auto miner_tx = test::make_miner_transaction(acct.get_keys().m_account_address);

    crypto::hash tx_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(miner_tx, tx_hash));

    cryptonote::transaction miner_tx_copy = test_json(miner_tx);

    crypto::hash tx_copy_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(miner_tx_copy, tx_copy_hash));
    EXPECT_EQ(tx_hash, tx_copy_hash);

    cryptonote::blobdata tx_bytes{};
    cryptonote::blobdata tx_copy_bytes{};

    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(miner_tx, tx_bytes));
    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(miner_tx_copy, tx_copy_bytes));

    EXPECT_EQ(tx_bytes, tx_copy_bytes);
}

TEST(JsonSerialization, BulletproofPlusTransaction)
{
    GTEST_SKIP() << "Requires FCMP++ transaction construction infrastructure. "
                    "make_transaction builds ring-style sources incompatible with v3/FCMP++. "
                    "See docs/FOLLOWUPS.md for tracking.";
}

