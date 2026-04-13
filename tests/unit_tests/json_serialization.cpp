
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
#include "string_tools.h"


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
    make_v3_transaction_stub()
    {
        cryptonote::transaction tx{};
        tx.version = 3;
        tx.unlock_time = 0;
        tx.pruned = false;

        // One input: txin_to_key with a dummy key image
        cryptonote::txin_to_key in{};
        in.amount = 0;
        crypto::key_image ki;
        memset(&ki, 0x42, sizeof(ki));
        in.k_image = ki;
        in.key_offsets.push_back(12345);
        tx.vin.push_back(in);

        // Two outputs: tagged keys with dummy public keys
        for (int i = 0; i < 2; ++i)
        {
            cryptonote::tx_out out{};
            out.amount = 0;
            cryptonote::txout_to_tagged_key tagged{};
            memset(&tagged.key, 0x10 + i, sizeof(tagged.key));
            tagged.view_tag = static_cast<uint8_t>(i);
            out.target = tagged;
            tx.vout.push_back(out);
        }

        // Minimal extra (tx pubkey)
        crypto::public_key dummy_tx_pub;
        memset(&dummy_tx_pub, 0xAA, sizeof(dummy_tx_pub));
        cryptonote::add_tx_pub_key_to_extra(tx, dummy_tx_pub);

        // RCT signatures: BulletproofPlus type with minimal valid structure
        tx.rct_signatures.type = rct::RCTTypeBulletproofPlus;
        tx.rct_signatures.txnFee = 1000;
        tx.rct_signatures.ecdhInfo.resize(2);
        for (auto& info : tx.rct_signatures.ecdhInfo)
        {
            memset(info.amount.bytes, 0xCC, 8);
            memset(info.amount.bytes + 8, 0, 24);
        }
        tx.rct_signatures.outPk.resize(2);
        for (auto& pk : tx.rct_signatures.outPk)
            memset(pk.mask.bytes, 0xDD, 32);

        // PQC auth stub (one per input)
        cryptonote::pqc_authentication auth{};
        auth.auth_version = 1;
        auth.scheme_id = 1;
        auth.flags = 0;
        auth.hybrid_public_key.resize(32, 0xEE);
        auth.hybrid_signature.resize(64, 0xFF);
        tx.pqc_auths.push_back(auth);

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
    const auto tx = test::make_v3_transaction_stub();

    crypto::hash tx_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash))
        << "DEBUG: Failed to hash v3 tx stub";

    cryptonote::transaction tx_copy = test_json(tx);

    crypto::hash tx_copy_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash))
        << "DEBUG: Failed to hash round-tripped v3 tx";
    EXPECT_EQ(tx_hash, tx_copy_hash)
        << "DEBUG: tx hash mismatch after JSON round-trip. "
        << "Original: " << epee::string_tools::pod_to_hex(tx_hash)
        << " Copy: " << epee::string_tools::pod_to_hex(tx_copy_hash);

    EXPECT_EQ(tx_copy.version, 3u)
        << "DEBUG: version mismatch";
    EXPECT_EQ(tx_copy.vout.size(), 2u)
        << "DEBUG: output count mismatch";
    EXPECT_EQ(tx_copy.vin.size(), 1u)
        << "DEBUG: input count mismatch";
    EXPECT_EQ(tx_copy.rct_signatures.type, rct::RCTTypeBulletproofPlus)
        << "DEBUG: rct type mismatch";
    EXPECT_EQ(tx_copy.pqc_auths.size(), 1u)
        << "DEBUG: pqc_auths count mismatch";

    cryptonote::blobdata tx_bytes{};
    cryptonote::blobdata tx_copy_bytes{};
    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes))
        << "DEBUG: Failed to serialize original tx to blob";
    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes))
        << "DEBUG: Failed to serialize round-tripped tx to blob";
    EXPECT_EQ(tx_bytes, tx_copy_bytes)
        << "DEBUG: blob mismatch. Original size=" << tx_bytes.size()
        << " Copy size=" << tx_copy_bytes.size();
}

