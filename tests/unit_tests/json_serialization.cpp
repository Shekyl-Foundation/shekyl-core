
#include <gtest/gtest.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <vector>
#include <string>
#include <cstring>
#include <array>

#include "byte_stream.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "serialization/json_object.h"
#include "string_tools.h"
#include "memwipe.h"
#include "common/varint.h"
#include "shekyl/shekyl_ffi.h"
#include "fcmp/rctOps.h"

namespace
{
    std::string hex_encode(const uint8_t* data, size_t len)
    {
        static const char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(len * 2);
        for (size_t i = 0; i < len; ++i)
        {
            result.push_back(hex_chars[data[i] >> 4]);
            result.push_back(hex_chars[data[i] & 0x0F]);
        }
        return result;
    }

    std::vector<uint8_t> hex_decode(const std::string& hex)
    {
        std::vector<uint8_t> bytes;
        bytes.reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            uint8_t hi = (hex[i] >= 'a') ? (hex[i] - 'a' + 10) : (hex[i] - '0');
            uint8_t lo = (hex[i+1] >= 'a') ? (hex[i+1] - 'a' + 10) : (hex[i+1] - '0');
            bytes.push_back((hi << 4) | lo);
        }
        return bytes;
    }

    struct WalletKeys {
        uint8_t spend_secret[32];
        uint8_t spend_public[32];
        uint8_t x25519_pk[32];
        uint8_t x25519_sk[32];
        std::vector<uint8_t> ml_kem_ek;
        std::vector<uint8_t> ml_kem_dk;

        ~WalletKeys() { memwipe(spend_secret, 32); memwipe(x25519_sk, 32); }
    };

    WalletKeys generate_wallet_keys()
    {
        WalletKeys w{};
        crypto::public_key pk;
        crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        memcpy(w.spend_secret, &sk, 32);
        memcpy(w.spend_public, &pk, 32);

        ShekylPqcKeypair kem = shekyl_kem_keypair_generate();
        EXPECT_TRUE(kem.success) << "DEBUG: KEM keypair generation failed";

        EXPECT_EQ(kem.public_key.len, 1216u)
            << "DEBUG: KEM pk expected 1216 bytes, got " << kem.public_key.len;
        EXPECT_EQ(kem.secret_key.len, 2432u)
            << "DEBUG: KEM sk expected 2432 bytes, got " << kem.secret_key.len;

        memcpy(w.x25519_pk, kem.public_key.ptr, 32);
        w.ml_kem_ek.assign(kem.public_key.ptr + 32, kem.public_key.ptr + kem.public_key.len);

        memcpy(w.x25519_sk, kem.secret_key.ptr, 32);
        w.ml_kem_dk.assign(kem.secret_key.ptr + 32, kem.secret_key.ptr + kem.secret_key.len);

        shekyl_buffer_free(kem.public_key.ptr, kem.public_key.len);
        shekyl_buffer_free(kem.secret_key.ptr, kem.secret_key.len);
        return w;
    }

    struct ConstructedOutput {
        uint8_t output_key[32];
        uint8_t commitment[32];
        uint8_t enc_amount[8];
        uint8_t amount_tag;
        uint8_t view_tag;
        uint8_t kem_ct_x25519[32];
        std::vector<uint8_t> kem_ct_ml_kem;
        uint8_t h_pqc[32];
        uint8_t y[32];
        uint8_t z[32];
    };

    ConstructedOutput construct_output_ffi(
        const uint8_t* tx_secret,
        const WalletKeys& recipient,
        uint64_t amount,
        uint64_t output_index)
    {
        ShekylOutputData data = shekyl_construct_output(
            tx_secret,
            recipient.x25519_pk,
            recipient.ml_kem_ek.data(),
            recipient.ml_kem_ek.size(),
            recipient.spend_public,
            amount,
            output_index);

        ConstructedOutput out{};
        EXPECT_TRUE(data.success) << "DEBUG: shekyl_construct_output failed";

        memcpy(out.output_key, data.output_key, 32);
        memcpy(out.commitment, data.commitment, 32);
        memcpy(out.enc_amount, data.enc_amount, 8);
        out.amount_tag = data.amount_tag;
        out.view_tag = data.view_tag_x25519;
        memcpy(out.kem_ct_x25519, data.kem_ciphertext_x25519, 32);
        out.kem_ct_ml_kem.assign(
            data.kem_ciphertext_ml_kem.ptr,
            data.kem_ciphertext_ml_kem.ptr + data.kem_ciphertext_ml_kem.len);
        memcpy(out.h_pqc, data.h_pqc, 32);
        memcpy(out.y, data.y, 32);
        memcpy(out.z, data.z, 32);

        shekyl_output_data_free(&data);
        return out;
    }

    struct ScannedSecrets {
        uint8_t ho[32];
        uint8_t y[32];
        uint8_t z[32];
        uint64_t amount;
        uint8_t key_image[32];
        uint8_t combined_ss[64];
        uint8_t h_pqc[32];
        std::vector<uint8_t> pqc_pk;
        std::vector<uint8_t> pqc_sk;

        ~ScannedSecrets() { memwipe(ho, 32); memwipe(combined_ss, 64); }
    };

    ScannedSecrets scan_output_ffi(
        const WalletKeys& wallet,
        const ConstructedOutput& out,
        uint64_t output_index)
    {
        ge_p3 hp;
        rct::key od_rct;
        memcpy(od_rct.bytes, out.output_key, 32);
        rct::hash_to_p3(hp, od_rct);
        uint8_t hp_of_o[32];
        ge_p3_tobytes(hp_of_o, &hp);

        ScannedSecrets s{};
        uint8_t k_amount[32];
        uint8_t recovered_spend_key[32];
        ShekylBuffer pqc_pk_buf{nullptr, 0};
        ShekylBuffer pqc_sk_buf{nullptr, 0};

        bool ok = shekyl_scan_and_recover(
            wallet.x25519_sk,
            wallet.ml_kem_dk.data(),
            wallet.ml_kem_dk.size(),
            out.kem_ct_x25519,
            out.kem_ct_ml_kem.data(),
            out.kem_ct_ml_kem.size(),
            out.output_key,
            out.commitment,
            out.enc_amount,
            out.amount_tag,
            out.view_tag,
            output_index,
            wallet.spend_secret,
            hp_of_o,
            true,
            s.ho, s.y, s.z,
            k_amount,
            &s.amount,
            recovered_spend_key,
            s.key_image,
            s.combined_ss,
            &pqc_pk_buf,
            &pqc_sk_buf,
            s.h_pqc);

        EXPECT_TRUE(ok) << "DEBUG: shekyl_scan_and_recover failed";

        if (pqc_pk_buf.ptr && pqc_pk_buf.len > 0)
            s.pqc_pk.assign(pqc_pk_buf.ptr, pqc_pk_buf.ptr + pqc_pk_buf.len);
        if (pqc_sk_buf.ptr && pqc_sk_buf.len > 0)
            s.pqc_sk.assign(pqc_sk_buf.ptr, pqc_sk_buf.ptr + pqc_sk_buf.len);

        shekyl_buffer_free(pqc_pk_buf.ptr, pqc_pk_buf.len);
        shekyl_buffer_free(pqc_sk_buf.ptr, pqc_sk_buf.len);
        memwipe(k_amount, 32);
        return s;
    }

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
    make_fcmp_transaction()
    {
        // --- 1. Generate wallet keys ---
        WalletKeys wallet = generate_wallet_keys();

        crypto::secret_key tx_sk;
        crypto::public_key tx_pk;
        crypto::generate_keys(tx_pk, tx_sk);
        uint8_t tx_secret[32];
        memcpy(tx_secret, &tx_sk, 32);

        const uint64_t input_amount  = 1000000000; // 1 SKL
        const uint64_t fee           = 1000000;
        const uint64_t output_amount = input_amount - fee;
        const uint64_t input_output_index = 0;

        // --- 2. Construct the "existing" output that we'll spend ---
        ConstructedOutput input_out = construct_output_ffi(
            tx_secret, wallet, input_amount, input_output_index);

        // --- 3. Scan and recover secrets ---
        ScannedSecrets scanned = scan_output_ffi(wallet, input_out, input_output_index);
        EXPECT_EQ(scanned.amount, input_amount)
            << "DEBUG: scanned amount mismatch: expected " << input_amount
            << " got " << scanned.amount;

        // --- 4. Build curve tree leaf + depth-1 root ---
        uint8_t leaf[128];
        bool leaf_ok = shekyl_construct_curve_tree_leaf(
            input_out.output_key, input_out.commitment, scanned.h_pqc, leaf);
        EXPECT_TRUE(leaf_ok) << "DEBUG: shekyl_construct_curve_tree_leaf failed";

        uint8_t selene_init[32];
        EXPECT_TRUE(shekyl_curve_tree_selene_hash_init(selene_init))
            << "DEBUG: shekyl_curve_tree_selene_hash_init failed";

        uint8_t zero_scalar[32] = {};
        uint8_t tree_root[32];
        bool root_ok = shekyl_curve_tree_hash_grow_selene(
            selene_init, 0, zero_scalar, leaf, 4, tree_root);
        EXPECT_TRUE(root_ok) << "DEBUG: shekyl_curve_tree_hash_grow_selene failed";

        // --- 5. Construct change output ---
        WalletKeys change_wallet = generate_wallet_keys();
        crypto::secret_key change_tx_sk;
        crypto::public_key change_tx_pk;
        crypto::generate_keys(change_tx_pk, change_tx_sk);
        uint8_t change_tx_secret[32];
        memcpy(change_tx_secret, &change_tx_sk, 32);

        ConstructedOutput change_out = construct_output_ffi(
            change_tx_secret, change_wallet, output_amount, 0);

        // --- 6. Build Hp(O) for leaf entry ---
        ge_p3 hp;
        rct::key od_rct;
        memcpy(od_rct.bytes, input_out.output_key, 32);
        rct::hash_to_p3(hp, od_rct);
        uint8_t hp_of_o[32];
        ge_p3_tobytes(hp_of_o, &hp);

        // --- 7. Build JSON blobs for signer ---
        std::string inputs_json = "[{"
            "\"ki\":\"" + hex_encode(scanned.key_image, 32) + "\","
            "\"combined_ss\":\"" + hex_encode(scanned.combined_ss, 64) + "\","
            "\"output_index\":" + std::to_string(input_output_index) + ","
            "\"hp_of_O\":\"" + hex_encode(scanned.h_pqc, 32) + "\","
            "\"amount\":" + std::to_string(input_amount) + ","
            "\"commitment_mask\":\"" + hex_encode(scanned.z, 32) + "\","
            "\"commitment\":\"" + hex_encode(input_out.commitment, 32) + "\","
            "\"output_key\":\"" + hex_encode(input_out.output_key, 32) + "\","
            "\"h_pqc\":\"" + hex_encode(scanned.h_pqc, 32) + "\","
            "\"leaf_chunk\":[{"
                "\"output_key\":\"" + hex_encode(input_out.output_key, 32) + "\","
                "\"key_image_gen\":\"" + hex_encode(hp_of_o, 32) + "\","
                "\"commitment\":\"" + hex_encode(input_out.commitment, 32) + "\","
                "\"h_pqc\":\"" + hex_encode(scanned.h_pqc, 32) + "\""
            "}],"
            "\"c1_layers\":[],"
            "\"c2_layers\":[]"
        "}]";

        uint8_t enc_amount_9[9];
        memcpy(enc_amount_9, change_out.enc_amount, 8);
        enc_amount_9[8] = change_out.amount_tag;

        std::string outputs_json = "[{"
            "\"dest_key\":\"" + hex_encode(change_out.output_key, 32) + "\","
            "\"amount\":" + std::to_string(output_amount) + ","
            "\"commitment_mask\":\"" + hex_encode(change_out.z, 32) + "\","
            "\"enc_amount\":\"" + hex_encode(enc_amount_9, 9) + "\""
        "}]";

        // --- 8. Sign ---
        uint8_t tx_prefix_hash[32] = {};
        tx_prefix_hash[0] = 0xAA;
        tx_prefix_hash[31] = 0xBB;

        uint8_t reference_block[32] = {};
        reference_block[0] = 0xCC;
        reference_block[31] = 0xDD;

        const uint8_t tree_depth = 1;

        ShekylSignResult result = shekyl_sign_fcmp_transaction(
            wallet.spend_secret,
            tx_prefix_hash,
            reinterpret_cast<const uint8_t*>(inputs_json.data()),
            inputs_json.size(),
            reinterpret_cast<const uint8_t*>(outputs_json.data()),
            outputs_json.size(),
            fee,
            reference_block,
            tree_root,
            tree_depth);

        if (!result.success)
        {
            std::string err_msg = "(no message)";
            if (result.error_message.ptr && result.error_message.len > 0)
                err_msg.assign(reinterpret_cast<const char*>(result.error_message.ptr),
                               result.error_message.len);
            shekyl_buffer_free(result.error_message.ptr, result.error_message.len);
            shekyl_buffer_free(result.proofs_json.ptr, result.proofs_json.len);
            throw std::runtime_error{
                "shekyl_sign_fcmp_transaction failed (code="
                + std::to_string(result.error_code) + "): " + err_msg};
        }

        EXPECT_TRUE(result.proofs_json.ptr != nullptr && result.proofs_json.len > 0)
            << "DEBUG: proofs_json is empty on success";

        // --- 9. Parse SignedProofs JSON (mirrors wallet2.cpp pattern) ---
        std::string proofs_str(
            reinterpret_cast<const char*>(result.proofs_json.ptr),
            result.proofs_json.len);

        rapidjson::Document proofs_doc;
        proofs_doc.Parse(proofs_str.c_str(), proofs_str.size());
        EXPECT_FALSE(proofs_doc.HasParseError())
            << "DEBUG: proofs_json parse error at offset " << proofs_doc.GetErrorOffset();

        std::vector<uint8_t> fcmp_proof = hex_decode(proofs_doc["fcmp_proof"].GetString());

        const auto& pseudo_outs_arr = proofs_doc["pseudo_outs"].GetArray();
        EXPECT_EQ(pseudo_outs_arr.Size(), 1u) << "DEBUG: expected 1 pseudo_out";
        std::vector<uint8_t> pseudo_out = hex_decode(pseudo_outs_arr[0].GetString());
        EXPECT_EQ(pseudo_out.size(), 32u) << "DEBUG: pseudo_out should be 32 bytes";

        shekyl_buffer_free(result.proofs_json.ptr, result.proofs_json.len);
        shekyl_buffer_free(result.error_message.ptr, result.error_message.len);

        // --- 10. Verify the proof ---
        bool verified = shekyl_fcmp_verify(
            fcmp_proof.data(), fcmp_proof.size(),
            scanned.key_image, 1,
            pseudo_out.data(), 1,
            scanned.h_pqc, 1,
            tree_root, tree_depth,
            tx_prefix_hash);
        EXPECT_TRUE(verified) << "DEBUG: shekyl_fcmp_verify returned false for valid proof";

        // --- 11. Build transaction struct from SignedProofs ---
        cryptonote::transaction tx{};
        tx.version = 3;
        tx.unlock_time = 0;
        tx.pruned = false;

        // Input: real key image
        cryptonote::txin_to_key txin{};
        txin.amount = 0;
        memcpy(&txin.k_image, scanned.key_image, 32);
        txin.key_offsets.push_back(input_output_index);
        tx.vin.push_back(txin);

        // Output: real output key from change output
        {
            cryptonote::tx_out txout{};
            txout.amount = 0;
            cryptonote::txout_to_tagged_key tagged{};
            memcpy(&tagged.key, change_out.output_key, 32);
            tagged.view_tag.data = static_cast<char>(change_out.view_tag);
            txout.target = tagged;
            tx.vout.push_back(txout);
        }

        // Extra: tx public key
        cryptonote::add_tx_pub_key_to_extra(tx, tx_pk);

        // RCT base fields
        tx.rct_signatures.type = rct::RCTTypeFcmpPlusPlusPqc;
        tx.rct_signatures.txnFee = fee;
        memcpy(tx.rct_signatures.message.bytes, tx_prefix_hash, 32);
        memcpy(tx.rct_signatures.referenceBlock.data, reference_block, 32);
        tx.rct_signatures.p.curve_trees_tree_depth = proofs_doc["tree_depth"].GetUint();

        // outPk from commitments
        {
            const auto& comms = proofs_doc["commitments"].GetArray();
            tx.rct_signatures.outPk.resize(comms.Size());
            for (rapidjson::SizeType i = 0; i < comms.Size(); ++i)
            {
                std::vector<uint8_t> bin = hex_decode(comms[i].GetString());
                EXPECT_EQ(bin.size(), 32u) << "DEBUG: commitment size mismatch at " << i;
                memcpy(tx.rct_signatures.outPk[i].mask.bytes, bin.data(), 32);
            }
        }

        // BP+ range proof: deserialize Rust blob -> C++ BulletproofPlus
        // (mirrors wallet2.cpp deserialization pattern exactly)
        {
            std::string bp_bin;
            epee::string_tools::parse_hexstr_to_binbuff(
                proofs_doc["bulletproof_plus"].GetString(), bp_bin);
            const uint8_t* bp_data = reinterpret_cast<const uint8_t*>(bp_bin.data());
            size_t bp_len = bp_bin.size();
            size_t bp_off = 0;

            rct::BulletproofPlus bpp{};
            bpp.V.resize(tx.rct_signatures.outPk.size());
            for (size_t vi = 0; vi < tx.rct_signatures.outPk.size(); ++vi)
                bpp.V[vi] = tx.rct_signatures.outPk[vi].mask;

            EXPECT_GE(bp_len, bp_off + 192u) << "DEBUG: BP+ blob too short for fixed fields";
            memcpy(bpp.A.bytes,  bp_data + bp_off, 32); bp_off += 32;
            memcpy(bpp.A1.bytes, bp_data + bp_off, 32); bp_off += 32;
            memcpy(bpp.B.bytes,  bp_data + bp_off, 32); bp_off += 32;
            memcpy(bpp.r1.bytes, bp_data + bp_off, 32); bp_off += 32;
            memcpy(bpp.s1.bytes, bp_data + bp_off, 32); bp_off += 32;
            memcpy(bpp.d1.bytes, bp_data + bp_off, 32); bp_off += 32;

            uint64_t l_len = 0;
            {
                auto it = bp_bin.cbegin() + static_cast<ptrdiff_t>(bp_off);
                auto end = bp_bin.cend();
                int rd = tools::read_varint(it, end, l_len);
                EXPECT_GT(rd, 0) << "DEBUG: BP+ L varint read failed";
                bp_off += rd;
            }
            bpp.L.resize(l_len);
            for (uint64_t li = 0; li < l_len; ++li)
            {
                EXPECT_LE(bp_off + 32, bp_len) << "DEBUG: BP+ blob underflow in L at " << li;
                memcpy(bpp.L[li].bytes, bp_data + bp_off, 32);
                bp_off += 32;
            }

            uint64_t r_len = 0;
            {
                auto it = bp_bin.cbegin() + static_cast<ptrdiff_t>(bp_off);
                auto end = bp_bin.cend();
                int rd = tools::read_varint(it, end, r_len);
                EXPECT_GT(rd, 0) << "DEBUG: BP+ R varint read failed";
                bp_off += rd;
            }
            bpp.R.resize(r_len);
            for (uint64_t ri = 0; ri < r_len; ++ri)
            {
                EXPECT_LE(bp_off + 32, bp_len) << "DEBUG: BP+ blob underflow in R at " << ri;
                memcpy(bpp.R[ri].bytes, bp_data + bp_off, 32);
                bp_off += 32;
            }

            tx.rct_signatures.p.bulletproofs_plus.clear();
            tx.rct_signatures.p.bulletproofs_plus.push_back(std::move(bpp));
        }

        // enc_amounts (9 bytes each)
        {
            const auto& ea_arr = proofs_doc["enc_amounts"].GetArray();
            tx.rct_signatures.enc_amounts.resize(ea_arr.Size());
            for (rapidjson::SizeType i = 0; i < ea_arr.Size(); ++i)
            {
                std::vector<uint8_t> bin = hex_decode(ea_arr[i].GetString());
                tx.rct_signatures.enc_amounts[i].fill(0);
                memcpy(tx.rct_signatures.enc_amounts[i].data(), bin.data(),
                       std::min<size_t>(bin.size(), 9));
            }
        }

        // pseudoOuts (prunable section for RCTTypeFcmpPlusPlusPqc)
        {
            tx.rct_signatures.p.pseudoOuts.resize(pseudo_outs_arr.Size());
            for (rapidjson::SizeType i = 0; i < pseudo_outs_arr.Size(); ++i)
            {
                std::vector<uint8_t> bin = hex_decode(pseudo_outs_arr[i].GetString());
                memcpy(tx.rct_signatures.p.pseudoOuts[i].bytes, bin.data(), 32);
            }
        }

        // FCMP++ proof blob
        tx.rct_signatures.p.fcmp_pp_proof.assign(fcmp_proof.begin(), fcmp_proof.end());

        // PQC auth via FFI
        {
            ShekylPqcAuthResult pqc_auth_result = shekyl_sign_pqc_auth(
                scanned.combined_ss,
                input_output_index,
                tx_prefix_hash, 32);
            EXPECT_TRUE(pqc_auth_result.success)
                << "DEBUG: shekyl_sign_pqc_auth failed";

            cryptonote::pqc_authentication auth{};
            auth.auth_version = 1;
            auth.scheme_id = 0;
            auth.flags = 0;
            auth.hybrid_public_key.assign(
                pqc_auth_result.hybrid_public_key.ptr,
                pqc_auth_result.hybrid_public_key.ptr + pqc_auth_result.hybrid_public_key.len);
            auth.hybrid_signature.assign(
                pqc_auth_result.signature.ptr,
                pqc_auth_result.signature.ptr + pqc_auth_result.signature.len);
            shekyl_pqc_auth_result_free(&pqc_auth_result);
            tx.pqc_auths.push_back(std::move(auth));
        }

        memwipe(tx_secret, 32);
        memwipe(change_tx_secret, 32);
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

TEST(JsonSerialization, FcmpPlusPlusTransaction)
{
    const auto tx = test::make_fcmp_transaction();

    EXPECT_EQ(tx.version, 3u) << "DEBUG: version mismatch";
    EXPECT_EQ(tx.vin.size(), 1u) << "DEBUG: input count mismatch";
    EXPECT_EQ(tx.vout.size(), 1u) << "DEBUG: output count mismatch";
    EXPECT_EQ(tx.rct_signatures.type, rct::RCTTypeFcmpPlusPlusPqc)
        << "DEBUG: rct type mismatch, got " << (int)tx.rct_signatures.type;
    EXPECT_FALSE(tx.rct_signatures.p.fcmp_pp_proof.empty())
        << "DEBUG: FCMP++ proof blob is empty";
    EXPECT_EQ(tx.pqc_auths.size(), 1u) << "DEBUG: pqc_auths count mismatch";
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
    EXPECT_EQ(tx_copy.rct_signatures.type, rct::RCTTypeFcmpPlusPlusPqc);
    EXPECT_EQ(tx_copy.rct_signatures.p.fcmp_pp_proof.size(),
              tx.rct_signatures.p.fcmp_pp_proof.size())
        << "DEBUG: FCMP++ proof blob size changed after round-trip: "
        << tx.rct_signatures.p.fcmp_pp_proof.size() << " -> "
        << tx_copy.rct_signatures.p.fcmp_pp_proof.size();
    EXPECT_EQ(tx_copy.pqc_auths.size(), tx.pqc_auths.size());
    EXPECT_EQ(tx_copy.pqc_auths[0].hybrid_public_key.size(),
              tx.pqc_auths[0].hybrid_public_key.size())
        << "DEBUG: PQC pubkey size changed after round-trip";
    EXPECT_EQ(tx_copy.pqc_auths[0].hybrid_signature.size(),
              tx.pqc_auths[0].hybrid_signature.size())
        << "DEBUG: PQC signature size changed after round-trip";
    EXPECT_EQ(tx_copy.rct_signatures.outPk.size(),
              tx.rct_signatures.outPk.size());
    EXPECT_EQ(tx_copy.rct_signatures.p.pseudoOuts.size(),
              tx.rct_signatures.p.pseudoOuts.size());
    EXPECT_EQ(tx_copy.rct_signatures.enc_amounts.size(),
              tx.rct_signatures.enc_amounts.size());

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
