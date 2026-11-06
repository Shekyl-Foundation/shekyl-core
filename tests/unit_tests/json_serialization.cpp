
#include <gtest/gtest.h>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/writer.h>
#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>

#include "byte_stream.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "serialization/json_object.h"
#include "string_tools.h"
#include "fcmp/ct_ops.h"

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
            throw cryptonote::json::PARSE_FAIL();

        T out{};
        cryptonote::json::fromJsonValue(doc, out);
        return out;
    }
} // anonymous

// The network table's mainnet genesis transaction (`shekyl_network`,
// `rust/shekyl-network/genesis/mainnet.tx.hex`): a production coinbase the
// Rust genesis tool writes. The path is CMake's.
#ifndef MAINNET_GENESIS_TX_HEX_PATH
#define MAINNET_GENESIS_TX_HEX_PATH "rust/shekyl-network/genesis/mainnet.tx.hex"
#endif
static std::string mainnet_genesis_tx_hex()
{
  std::ifstream ifs(MAINNET_GENESIS_TX_HEX_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing the network table's genesis at ") + MAINNET_GENESIS_TX_HEX_PATH);
  std::string hex;
  ifs >> hex;
  return hex;
}

// A spend a running daemon accepted and connected
// (`rust/shekyl-wire/tests/fixtures/live_oracle_spend_v1.json`, which
// `pruned_tx_hash_parity.cpp` also reads): an FCMP++ spend with real proofs
// and hybrid signatures, built by the Rust wallet. It replaced a fixture this
// file built through the wallet's C++ signing exports, deleted with them: the
// wallet is Rust (`.cursor/rules/20-rust-vs-cpp-policy.mdc`). The path is
// CMake's.
#ifndef LIVE_ORACLE_SPEND_FIXTURE_PATH
#define LIVE_ORACLE_SPEND_FIXTURE_PATH "rust/shekyl-wire/tests/fixtures/live_oracle_spend_v1.json"
#endif
static std::string live_oracle_spend_tx_hex()
{
  std::ifstream ifs(LIVE_ORACLE_SPEND_FIXTURE_PATH);
  if (!ifs.good())
    throw std::runtime_error(std::string("missing the live-oracle spend fixture at ") + LIVE_ORACLE_SPEND_FIXTURE_PATH);
  rapidjson::IStreamWrapper wrapper(ifs);
  rapidjson::Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError() || !doc.HasMember("tx_hex") || !doc["tx_hex"].IsString())
    throw std::runtime_error("invalid live-oracle spend fixture");
  return doc["tx_hex"].GetString();
}

namespace test
{
    // The network table's mainnet genesis: a production coinbase written by
    // the Rust writer. The C++ `construct_miner_tx` that built this fixture
    // was deleted with the C++ chain.
    cryptonote::transaction
    make_miner_transaction()
    {
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(
                mainnet_genesis_tx_hex(), blob))
            throw std::runtime_error{"the genesis transaction is not hex"};
        cryptonote::transaction tx{};
        if (!cryptonote::parse_and_validate_tx_from_blob(blob, tx))
            throw std::runtime_error{"the genesis transaction does not parse"};

        crypto::hash id{0};
        if (!cryptonote::get_transaction_hash(tx, id))
            throw std::runtime_error{"could not get transaction hash"};

        return tx;
    }

    // The live-oracle spend: six inputs, two outputs.
    cryptonote::transaction
    make_fcmp_transaction()
    {
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(
                live_oracle_spend_tx_hex(), blob))
            throw std::runtime_error{"the live-oracle spend is not hex"};
        cryptonote::transaction tx{};
        if (!cryptonote::parse_and_validate_tx_from_blob(blob, tx))
            throw std::runtime_error{"the live-oracle spend does not parse"};
        return tx;
    }
}

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
    const auto miner_tx = test::make_miner_transaction();

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

TEST(JsonSerialization, FcmpPlusPlusTransaction)
{
    const auto tx = test::make_fcmp_transaction();

    EXPECT_EQ(tx.version, 3u) << "DEBUG: version mismatch";
    EXPECT_EQ(tx.vin.size(), 6u) << "DEBUG: input count mismatch";
    EXPECT_EQ(tx.vout.size(), 2u) << "DEBUG: output count mismatch";
    EXPECT_EQ(tx.ct_signatures.type, ct::CTTypeFcmpPlusPlusPqc)
        << "DEBUG: rct type mismatch, got " << (int)tx.ct_signatures.type;
    EXPECT_FALSE(tx.ct_signatures.p.fcmp_pp_proof.empty())
        << "DEBUG: FCMP++ proof blob is empty";
    EXPECT_EQ(tx.pqc_auths.size(), tx.vin.size()) << "DEBUG: pqc_auths count mismatch";
    EXPECT_FALSE(tx.pqc_auths[0].hybrid_public_key.empty())
        << "DEBUG: pqc_auth hybrid_public_key is empty";
    EXPECT_FALSE(tx.pqc_auths[0].hybrid_signature.empty())
        << "DEBUG: pqc_auth hybrid_signature is empty";

    crypto::hash tx_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash))
        << "DEBUG: failed to hash FCMP++ tx";

    cryptonote::transaction tx_copy = test_json(tx);

    crypto::hash tx_copy_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash))
        << "DEBUG: failed to hash round-tripped FCMP++ tx";
    EXPECT_EQ(tx_hash, tx_copy_hash)
        << "DEBUG: tx hash mismatch after JSON round-trip. "
        << "Original: " << epee::string_tools::pod_to_hex(tx_hash)
        << " Copy: " << epee::string_tools::pod_to_hex(tx_copy_hash);

    EXPECT_EQ(tx_copy.version, 3u);
    EXPECT_EQ(tx_copy.ct_signatures.type, ct::CTTypeFcmpPlusPlusPqc);
    EXPECT_EQ(tx_copy.ct_signatures.p.fcmp_pp_proof.size(),
              tx.ct_signatures.p.fcmp_pp_proof.size())
        << "DEBUG: FCMP++ proof blob size changed after round-trip: "
        << tx.ct_signatures.p.fcmp_pp_proof.size() << " -> "
        << tx_copy.ct_signatures.p.fcmp_pp_proof.size();
    EXPECT_EQ(tx_copy.pqc_auths.size(), tx.pqc_auths.size());
    EXPECT_EQ(tx_copy.pqc_auths[0].hybrid_public_key.size(),
              tx.pqc_auths[0].hybrid_public_key.size())
        << "DEBUG: PQC pubkey size changed after round-trip";
    EXPECT_EQ(tx_copy.pqc_auths[0].hybrid_signature.size(),
              tx.pqc_auths[0].hybrid_signature.size())
        << "DEBUG: PQC signature size changed after round-trip";
    EXPECT_EQ(tx_copy.ct_signatures.outPk.size(),
              tx.ct_signatures.outPk.size());
    EXPECT_EQ(tx_copy.ct_signatures.p.pseudoOuts.size(),
              tx.ct_signatures.p.pseudoOuts.size());
    EXPECT_EQ(tx_copy.ct_signatures.enc_amounts.size(),
              tx.ct_signatures.enc_amounts.size());
    EXPECT_EQ(tx_copy.ct_signatures.enc_labels.size(),
              tx.ct_signatures.enc_labels.size());

    cryptonote::blobdata tx_bytes{};
    cryptonote::blobdata tx_copy_bytes{};
    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes))
        << "DEBUG: failed to serialize original FCMP++ tx to blob";
    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes))
        << "DEBUG: failed to serialize round-tripped FCMP++ tx to blob";
    EXPECT_EQ(tx_bytes, tx_copy_bytes)
        << "DEBUG: blob mismatch. Original size=" << tx_bytes.size()
        << " Copy size=" << tx_copy_bytes.size();
}
