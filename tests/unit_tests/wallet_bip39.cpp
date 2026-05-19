// Copyright (c) 2026, The Shekyl Project
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

// Phase-1 Electrum-words-removal BIP-39 round-trip tests per
// `docs/design/ELECTRUM_WORDS_REMOVAL.md` §7.3 + Phase 1 work-item 8
// (`docs/design/ELECTRUM_WORDS_REMOVAL_PLAN.md`).
//
// Scope:
//
//   1. `shekyl_bip39_mnemonic_to_entropy` ↔ `shekyl_bip39_mnemonic_from_entropy`
//      FFI round-trip — the new 5th-FFI surface added in Phase 1 per
//      substrate §3.1. Round-trips a known BIP-39 entropy through both
//      directions and asserts byte-identity.
//
//   2. `tools::generate_from_json` BIP-39 restore path — drives the
//      inlined orchestration (§4.10.1) through the JSON-restore entry
//      point. Builds a temporary JSON file with a known mnemonic +
//      filename + scan_from_height (set to 1 to skip the daemon call in
//      `estimate_blockchain_height`), invokes `wallet2::make_from_json`,
//      and asserts:
//        - the orchestration succeeds and produces a wallet;
//        - the persisted `m_bip39_entropy` matches the canonical
//          BIP-39 entropy decoded from the phrase via direct FFI
//          (the substrate §4.10 entropy-persistence claim);
//        - the persisted entropy survives a `store_to` + reload cycle
//          (the §4.10 + §V4 keyfile-encryption-envelope claim).
//
//   3. V6 25-word-restore UX-hint negative — drives `make_from_json`
//      with a 25-word phrase and asserts the resulting exception
//      message contains the substrate-prescribed hint string
//      ("Shekyl uses 24-word BIP-39 mnemonics") rather than a bare
//      BIP-39 validation error.
//
// Out-of-scope (deferred to follow-up commits with explicit
// FOLLOWUPS.md tracking):
//
//   - V3 hardware-wallet negative test (substrate §V3): requires
//     device-restore scaffolding the unit-test harness does not
//     currently provide.
//   - Surface-A passphrase positive round-trip and Surface-B
//     passphrase hard-error negative for `query_key("mnemonic")`:
//     these exercise the `wallet2_ffi_query_key` C ABI rather than
//     `wallet2.cpp`'s C++ surface; the existing wallet_storage tests
//     don't cover the FFI surface either, and adding FFI-driven
//     tests requires constructing a `ShekylWallet*` handle. Tracked
//     for a Phase 1-adjacent follow-up commit.

#include "unit_tests_utils.h"
#include "gtest/gtest.h"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

#include "file_io_utils.h"
#include "wallet/wallet2.h"
#include "common/util.h"
#include "shekyl/shekyl_ffi.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>

using namespace boost::filesystem;
using namespace epee::file_io_utils;

namespace
{
// BIP-39 official test vector #1 (entropy = 32 × 0x00, no passphrase).
// The canonical 24-word phrase that encodes 32 bytes of zero entropy is
// 23 × "abandon" + "art". See
// `rust/shekyl-crypto-pq/src/bip39.rs::bip39_official_vector_zero_entropy_words_match`
// for the Rust-side pin of the same vector.
constexpr const char kBip39ZeroEntropyPhrase[] =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon art";

constexpr std::array<uint8_t, 32> kBip39ZeroEntropyBytes{};

// A second 32-byte entropy pattern to defend against the all-zero
// entropy being a degenerate vector that happens to round-trip via
// either direction. The corresponding 24-word phrase is derived
// programmatically from this byte pattern via
// `shekyl_bip39_mnemonic_from_entropy` so the test never depends on a
// hand-transcribed mnemonic. Matches the Rust-side
// `entropy_roundtrip_24_words` fixture in `bip39.rs`.
constexpr std::array<uint8_t, 32> kBip39NonZeroEntropyBytes{
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
};

// Derive the canonical 24-word phrase for the given 32-byte entropy
// via the FFI. Returns the phrase as a `std::string` so tests can
// embed it in restore JSON and reason about its length.
std::string phrase_from_entropy(const std::array<uint8_t, 32> &entropy)
{
    std::array<uint8_t, 256> buf{};
    size_t out_len = 0;
    const bool ok = shekyl_bip39_mnemonic_from_entropy(
        entropy.data(), buf.data(), buf.size(), &out_len);
    if (!ok)
        return {};
    return std::string(reinterpret_cast<const char *>(buf.data()), out_len);
}

// Write a JSON restore descriptor to the given file path, with the
// minimum field set Phase 1's inlined `tools::generate_from_json`
// orchestration requires for the BIP-39 path. `scan_from_height` is
// set to 1 so the orchestration's `estimate_blockchain_height()` call
// (which would otherwise perform a daemon HTTP request) is skipped.
void write_bip39_restore_json(const path &json_path,
                              const std::string &filename,
                              const std::string &password,
                              const std::string &mnemonic,
                              const std::string &seed_passphrase)
{
    std::ofstream out(json_path.string(), std::ios::out | std::ios::trunc);
    out << "{\n";
    out << "  \"version\": 1,\n";
    out << "  \"filename\": \"" << filename << "\",\n";
    out << "  \"scan_from_height\": 1,\n";
    out << "  \"password\": \"" << password << "\",\n";
    out << "  \"seed\": \"" << mnemonic << "\",\n";
    out << "  \"seed_passphrase\": \"" << seed_passphrase << "\"\n";
    out << "}\n";
}

// Build a minimal `boost::program_options::variables_map` populated
// with `wallet2::init_options` defaults. The orchestration's
// `make_basic` reads option values out of this vm; the default values
// suffice for the in-memory test wallet (no daemon, no proxy, no SSL).
boost::program_options::variables_map build_default_wallet_vm()
{
    boost::program_options::options_description desc;
    tools::wallet2::init_options(desc);
    boost::program_options::variables_map vm;
    const char *argv[] = {"unit_tests"};
    boost::program_options::store(
        boost::program_options::parse_command_line(
            1, const_cast<char **>(argv), desc),
        vm);
    boost::program_options::notify(vm);
    return vm;
}

// Always-fail password prompter: `tools::generate_from_json` only
// invokes the prompter when the JSON's `password` field is absent;
// the tests above always supply `password`, so the prompter must not
// be called. Failing loudly catches regressions.
std::optional<tools::password_container>
fail_password_prompter(const char *, bool)
{
    ADD_FAILURE() << "password prompter unexpectedly invoked";
    return std::nullopt;
}
} // namespace

TEST(wallet_bip39, ffi_entropy_roundtrip_zero_vector)
{
    std::array<uint8_t, 32> recovered{};
    const bool ok = shekyl_bip39_mnemonic_to_entropy(
        reinterpret_cast<const uint8_t *>(kBip39ZeroEntropyPhrase),
        std::strlen(kBip39ZeroEntropyPhrase),
        recovered.data());
    ASSERT_TRUE(ok) << "shekyl_bip39_mnemonic_to_entropy rejected the "
                       "BIP-39 official-vector zero-entropy phrase";
    EXPECT_EQ(recovered, kBip39ZeroEntropyBytes);
}

TEST(wallet_bip39, ffi_entropy_roundtrip_nonzero_vector)
{
    const std::string phrase = phrase_from_entropy(kBip39NonZeroEntropyBytes);
    ASSERT_FALSE(phrase.empty())
        << "shekyl_bip39_mnemonic_from_entropy failed for non-zero entropy";

    std::array<uint8_t, 32> recovered{};
    const bool ok = shekyl_bip39_mnemonic_to_entropy(
        reinterpret_cast<const uint8_t *>(phrase.data()),
        phrase.size(),
        recovered.data());
    ASSERT_TRUE(ok) << "shekyl_bip39_mnemonic_to_entropy rejected the "
                       "phrase derived from non-zero entropy";
    EXPECT_EQ(recovered, kBip39NonZeroEntropyBytes);
}

TEST(wallet_bip39, ffi_rejects_25_word_phrase)
{
    // Twenty-five "abandon" tokens — a syntactically-25-word input.
    // The substrate's §4.6 disposition is that 25-word phrases always
    // produce a BIP-39 validation error; the V6 25-word UX hint at
    // `tools::generate_from_json` is a wrapper around this error, not
    // a separate code path.
    std::string twenty_five_words;
    for (int i = 0; i < 25; ++i)
    {
        if (i)
            twenty_five_words += ' ';
        twenty_five_words += "abandon";
    }
    std::array<uint8_t, 32> recovered{};
    const bool ok = shekyl_bip39_mnemonic_to_entropy(
        reinterpret_cast<const uint8_t *>(twenty_five_words.data()),
        twenty_five_words.size(),
        recovered.data());
    EXPECT_FALSE(ok)
        << "shekyl_bip39_mnemonic_to_entropy unexpectedly accepted a "
           "25-word phrase";
}

TEST(wallet_bip39, generate_from_json_persists_bip39_entropy)
{
    const path data_dir = unit_test::data_dir / "wallet_bip39_persist";
    boost::filesystem::create_directories(data_dir);
    const path json_path = data_dir / "restore.json";
    const path wallet_path = data_dir / "wallet";

    if (is_file_exist(wallet_path.string()))
        boost::filesystem::remove(wallet_path);
    if (is_file_exist(wallet_path.string() + ".keys"))
        boost::filesystem::remove(wallet_path.string() + ".keys");

    const std::string password = "test-bip39-password";
    const std::string phrase = phrase_from_entropy(kBip39NonZeroEntropyBytes);
    ASSERT_FALSE(phrase.empty());
    write_bip39_restore_json(json_path,
                             wallet_path.string(),
                             password,
                             phrase,
                             /*seed_passphrase=*/"");

    const auto vm = build_default_wallet_vm();
    auto result = tools::wallet2::make_from_json(
        vm, /*unattended=*/true, json_path.string(),
        &fail_password_prompter);

    ASSERT_NE(result.first, nullptr)
        << "make_from_json returned null wallet for valid BIP-39 phrase";

    const auto &entropy_opt = result.first->bip39_entropy();
    ASSERT_TRUE(entropy_opt.has_value())
        << "m_bip39_entropy was not populated by the inlined orchestration "
           "for a JSON-restore-from-phrase wallet";
    EXPECT_EQ(0, std::memcmp(entropy_opt->data(),
                             kBip39NonZeroEntropyBytes.data(),
                             kBip39NonZeroEntropyBytes.size()))
        << "persisted entropy does not match the canonical BIP-39 entropy "
           "decoded from the source phrase";
}

TEST(wallet_bip39, keyfile_roundtrip_preserves_bip39_entropy)
{
    const path data_dir = unit_test::data_dir / "wallet_bip39_keyfile";
    boost::filesystem::create_directories(data_dir);
    const path json_path = data_dir / "restore.json";
    const path wallet_path = data_dir / "wallet";

    if (is_file_exist(wallet_path.string()))
        boost::filesystem::remove(wallet_path);
    if (is_file_exist(wallet_path.string() + ".keys"))
        boost::filesystem::remove(wallet_path.string() + ".keys");

    const std::string password = "test-bip39-keyfile-password";
    const std::string phrase = phrase_from_entropy(kBip39NonZeroEntropyBytes);
    ASSERT_FALSE(phrase.empty());
    write_bip39_restore_json(json_path,
                             wallet_path.string(),
                             password,
                             phrase,
                             /*seed_passphrase=*/"");

    const auto vm = build_default_wallet_vm();

    std::string primary_address_create;
    {
        auto created = tools::wallet2::make_from_json(
            vm, /*unattended=*/true, json_path.string(),
            &fail_password_prompter);
        ASSERT_NE(created.first, nullptr);
        primary_address_create = created.first->get_address_as_str();
        ASSERT_TRUE(created.first->bip39_entropy().has_value());
        created.first->store();
        ASSERT_TRUE(is_file_exist(wallet_path.string() + ".keys"));
    }

    // Reload the wallet from disk; the substrate §4.10 + §V4 claim is
    // that `m_bip39_entropy` round-trips through the encrypted keyfile
    // envelope ser/de path.
    tools::wallet2 w(cryptonote::MAINNET, 1, /*unattended=*/true);
    w.set_refresh_from_block_height(1);
    w.load(wallet_path.string(), epee::wipeable_string(password));

    const auto &entropy_opt = w.bip39_entropy();
    ASSERT_TRUE(entropy_opt.has_value())
        << "m_bip39_entropy did not survive the keyfile save/load cycle";
    EXPECT_EQ(0, std::memcmp(entropy_opt->data(),
                             kBip39NonZeroEntropyBytes.data(),
                             kBip39NonZeroEntropyBytes.size()));
    EXPECT_EQ(primary_address_create, w.get_address_as_str())
        << "reloaded wallet address differs from initial creation address";
}

TEST(wallet_bip39, keyfile_on_disk_is_encrypted_no_plaintext_entropy)
{
    // V4 keyfile-encryption-envelope on-disk inspection per
    // `docs/design/ELECTRUM_WORDS_REMOVAL.md` §V4. The keyfile's
    // `bip39_entropy` field is JSON-hex inside an xchacha20-encrypted
    // envelope; on-disk the only surface is ciphertext. This test
    // creates a wallet, persists it, reads the .keys file byte-for-
    // byte, and asserts:
    //   - the canonical entropy byte sequence does not appear on disk;
    //   - the hex-encoded entropy string does not appear on disk;
    //   - the JSON field name "bip39_entropy" does not appear on disk
    //     (would-be plaintext-JSON sentinel).
    const path data_dir = unit_test::data_dir / "wallet_bip39_envelope";
    boost::filesystem::create_directories(data_dir);
    const path json_path = data_dir / "restore.json";
    const path wallet_path = data_dir / "wallet";

    if (is_file_exist(wallet_path.string()))
        boost::filesystem::remove(wallet_path);
    if (is_file_exist(wallet_path.string() + ".keys"))
        boost::filesystem::remove(wallet_path.string() + ".keys");

    const std::string password = "test-bip39-envelope-password";
    const std::string phrase = phrase_from_entropy(kBip39NonZeroEntropyBytes);
    ASSERT_FALSE(phrase.empty());
    write_bip39_restore_json(json_path,
                             wallet_path.string(),
                             password,
                             phrase,
                             /*seed_passphrase=*/"");

    const auto vm = build_default_wallet_vm();
    {
        auto created = tools::wallet2::make_from_json(
            vm, /*unattended=*/true, json_path.string(),
            &fail_password_prompter);
        ASSERT_NE(created.first, nullptr);
        ASSERT_TRUE(created.first->bip39_entropy().has_value());
        created.first->store();
        ASSERT_TRUE(is_file_exist(wallet_path.string() + ".keys"));
    }

    std::ifstream keys_in(wallet_path.string() + ".keys",
                          std::ios::in | std::ios::binary);
    ASSERT_TRUE(keys_in.good());
    std::string on_disk((std::istreambuf_iterator<char>(keys_in)),
                        std::istreambuf_iterator<char>());
    ASSERT_FALSE(on_disk.empty());

    // 1. Canonical entropy bytes must not appear in the on-disk
    //    keyfile (the keyfile envelope is xchacha20-encrypted; the
    //    plaintext bytes are inside the envelope, not on disk).
    const std::string entropy_bytes(
        reinterpret_cast<const char *>(kBip39NonZeroEntropyBytes.data()),
        kBip39NonZeroEntropyBytes.size());
    EXPECT_EQ(on_disk.find(entropy_bytes), std::string::npos)
        << "raw entropy bytes found on disk — encryption envelope failed";

    // 2. Hex-encoded entropy string must not appear on disk either.
    std::string entropy_hex;
    entropy_hex.reserve(64);
    static const char kHex[] = "0123456789abcdef";
    for (uint8_t b : kBip39NonZeroEntropyBytes)
    {
        entropy_hex += kHex[(b >> 4) & 0xF];
        entropy_hex += kHex[b & 0xF];
    }
    EXPECT_EQ(on_disk.find(entropy_hex), std::string::npos)
        << "hex-encoded entropy found on disk — plaintext JSON written "
           "outside the encryption envelope";

    // 3. The JSON field name itself must not appear on disk; if it
    //    did, the JSON wasn't encrypted.
    EXPECT_EQ(on_disk.find("bip39_entropy"), std::string::npos)
        << "plaintext JSON field name \"bip39_entropy\" found on disk — "
           "the keyfile-encryption envelope is not protecting the field";
}

TEST(wallet_bip39, generate_from_json_rejects_25_word_phrase_with_v6_hint)
{
    const path data_dir = unit_test::data_dir / "wallet_bip39_v6_hint";
    boost::filesystem::create_directories(data_dir);
    const path json_path = data_dir / "restore.json";
    const path wallet_path = data_dir / "wallet";

    if (is_file_exist(wallet_path.string()))
        boost::filesystem::remove(wallet_path);
    if (is_file_exist(wallet_path.string() + ".keys"))
        boost::filesystem::remove(wallet_path.string() + ".keys");

    std::string twenty_five_words;
    for (int i = 0; i < 25; ++i)
    {
        if (i)
            twenty_five_words += ' ';
        twenty_five_words += "abandon";
    }
    write_bip39_restore_json(json_path,
                             wallet_path.string(),
                             "anything",
                             twenty_five_words,
                             /*seed_passphrase=*/"");

    const auto vm = build_default_wallet_vm();
    bool caught = false;
    try
    {
        (void)tools::wallet2::make_from_json(
            vm, /*unattended=*/true, json_path.string(),
            &fail_password_prompter);
    }
    catch (const std::exception &e)
    {
        caught = true;
        const std::string what = e.what();
        EXPECT_NE(what.find("24-word BIP-39 mnemonics"), std::string::npos)
            << "expected V6 25-word UX hint in exception message; got: "
            << what;
    }
    EXPECT_TRUE(caught) << "25-word phrase did not produce an exception";
}
