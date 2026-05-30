// Copyright (c) 2014-2022, The Monero Project
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

#include <cstring>

#include "cryptonote_basic/account.h"
#include "shekyl/shekyl_ffi.h"

TEST(account, encrypt_keys)
{
  cryptonote::keypair recovery_key = cryptonote::keypair::generate(hw::get_device("default"));
  cryptonote::account_base account;
  crypto::secret_key key = account.generate(
      recovery_key.sec, /*recover=*/false, /*two_random=*/false, cryptonote::FAKECHAIN);
  const cryptonote::account_keys keys = account.get_keys();

  ASSERT_EQ(account.get_keys().m_account_address, keys.m_account_address);
  ASSERT_EQ(account.get_keys().m_spend_secret_key, keys.m_spend_secret_key);
  ASSERT_EQ(account.get_keys().m_view_secret_key, keys.m_view_secret_key);

  crypto::chacha_key chacha_key;
  crypto::generate_chacha_key(&recovery_key, sizeof(recovery_key), chacha_key, 1);

  account.encrypt_keys(chacha_key);

  ASSERT_EQ(account.get_keys().m_account_address, keys.m_account_address);
  ASSERT_NE(account.get_keys().m_spend_secret_key, keys.m_spend_secret_key);
  ASSERT_NE(account.get_keys().m_view_secret_key, keys.m_view_secret_key);

  account.decrypt_viewkey(chacha_key);

  ASSERT_EQ(account.get_keys().m_account_address, keys.m_account_address);
  ASSERT_NE(account.get_keys().m_spend_secret_key, keys.m_spend_secret_key);
  ASSERT_EQ(account.get_keys().m_view_secret_key, keys.m_view_secret_key);

  account.encrypt_viewkey(chacha_key);

  ASSERT_EQ(account.get_keys().m_account_address, keys.m_account_address);
  ASSERT_NE(account.get_keys().m_spend_secret_key, keys.m_spend_secret_key);
  ASSERT_NE(account.get_keys().m_view_secret_key, keys.m_view_secret_key);

  account.decrypt_keys(chacha_key);

  ASSERT_EQ(account.get_keys().m_account_address, keys.m_account_address);
  ASSERT_EQ(account.get_keys().m_spend_secret_key, keys.m_spend_secret_key);
  ASSERT_EQ(account.get_keys().m_view_secret_key, keys.m_view_secret_key);
}

// The legacy `generate_pqc_for_restored_address` helper has been removed
// because it produced non-reproducible ML-KEM decap keys. Its replacement is
// the raw-seed / BIP-39 restore path, which runs the whole derivation through
// Rust; the test below exercises the "restore-from-raw-seed yields the same
// account as the original generate-from-raw-seed call" invariant that this
// new path is meant to provide.
TEST(account, rederive_from_raw_seed_reproduces_account)
{
  uint8_t raw_seed[SHEKYL_RAW_SEED_BYTES] = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
      0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
  };

  cryptonote::account_base first;
  first.generate_from_raw_seed(raw_seed, cryptonote::FAKECHAIN);
  const auto first_keys = first.get_keys();

  cryptonote::account_base second;
  second.generate_from_raw_seed(raw_seed, cryptonote::FAKECHAIN);
  const auto second_keys = second.get_keys();

  ASSERT_EQ(first_keys.m_account_address, second_keys.m_account_address);
  ASSERT_EQ(first_keys.m_spend_secret_key, second_keys.m_spend_secret_key);
  ASSERT_EQ(first_keys.m_view_secret_key,  second_keys.m_view_secret_key);
  ASSERT_EQ(first_keys.m_ml_kem_decap_key, second_keys.m_ml_kem_decap_key);
  ASSERT_EQ(first_keys.m_master_seed_64,   second_keys.m_master_seed_64);
  ASSERT_EQ(first_keys.m_seed_format,      second_keys.m_seed_format);
  ASSERT_EQ(first_keys.m_account_address.m_pqc_public_key.size(),
            static_cast<size_t>(SHEKYL_PQC_PUBLIC_KEY_BYTES));
}

// BIP-39 + MAINNET coverage. The constants the wallet_storage failure surfaced
// (SHEKYL_CLASSICAL_ADDRESS_BYTES off-by-one and the SHEKYL_SEED_FORMAT_*
// disagreement) bit the (Fakechain, Raw32) path in production; the (Mainnet,
// BIP-39) path was equally broken under the same constants but had zero test
// coverage at the C++/FFI layer, so the audit had no signal there. This test
// closes that gap end-to-end through the lower-level account_base API. See
// docs/audit_trail/2026-05-ffi-constant-drift-audit.md.
//
// Note: there is intentionally no `wallet2`-level wrapper exercised here.
// `wallet2` exposes no `generate_from_bip39` entry point **by design**: the
// wallet2 layer is being deleted at Phase 5 of the Rust wallet rewrite, and
// new BIP-39 wallet creation will live in the Rust wallet path post-
// migration. A `static_assert` tripwire in
// `tests/unit_tests/wallet_storage.cpp` defends the absence against drift;
// the architectural decision is recorded in `docs/FOLLOWUPS.md`
// §"V3.1+ Legacy C++ → Rust rewrite scope". This account_base-layer test
// is the deepest C++ surface that still exercises the BIP-39 + MAINNET
// FFI round-trip; the primary functional guarantee is the Rust test
// `shekyl-crypto-pq::tests::generate_from_bip39_mainnet_roundtrips_to_rederive`.
TEST(account, rederive_from_bip39_reproduces_account_mainnet)
{
  // BIP-39 §A.1 canonical test vector: 32-byte all-zero entropy → 24-word
  // English mnemonic ending in "art". Hardcoding rather than generating
  // through the FFI keeps the test self-describing for future readers.
  static constexpr const char *kZeroEntropyMnemonic =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon art";

  cryptonote::account_base first;
  first.generate_from_bip39(kZeroEntropyMnemonic, std::string{}, cryptonote::MAINNET);
  const auto first_keys = first.get_keys();

  // Every BIP-39 account must populate the same fields raw-seed accounts do.
  ASSERT_EQ(first_keys.m_master_seed_64.size(),
            static_cast<size_t>(SHEKYL_MASTER_SEED_BYTES));
  ASSERT_EQ(first_keys.m_seed_format,
            static_cast<uint8_t>(SHEKYL_SEED_FORMAT_BIP39));
  ASSERT_EQ(first_keys.m_account_address.m_pqc_public_key.size(),
            static_cast<size_t>(SHEKYL_PQC_PUBLIC_KEY_BYTES));

  // Same mnemonic + same passphrase on the same network must produce a
  // bit-identical account. Determinism check.
  cryptonote::account_base second;
  second.generate_from_bip39(kZeroEntropyMnemonic, std::string{}, cryptonote::MAINNET);
  const auto second_keys = second.get_keys();
  ASSERT_EQ(first_keys.m_account_address, second_keys.m_account_address);
  ASSERT_EQ(first_keys.m_spend_secret_key, second_keys.m_spend_secret_key);
  ASSERT_EQ(first_keys.m_view_secret_key,  second_keys.m_view_secret_key);
  ASSERT_EQ(first_keys.m_ml_kem_decap_key, second_keys.m_ml_kem_decap_key);
  ASSERT_EQ(first_keys.m_master_seed_64,   second_keys.m_master_seed_64);

  // Round-trip via rederive_from_master_seed: simulate the wallet-open hot
  // path. This is the exact call site that Bug 2 broke — wallet2::load
  // reads m_master_seed_64 / m_seed_format from the encrypted keys file and
  // calls rederive_from_master_seed(m_nettype). For Mainnet+BIP39, the
  // (Mainnet, Bip39) pair is permitted; the rederive must succeed and
  // reproduce every key bit-for-bit.
  cryptonote::account_base rederived = first;
  rederived.rederive_from_master_seed(cryptonote::MAINNET);
  const auto rederived_keys = rederived.get_keys();

  ASSERT_EQ(first_keys.m_account_address, rederived_keys.m_account_address);
  ASSERT_EQ(first_keys.m_spend_secret_key, rederived_keys.m_spend_secret_key);
  ASSERT_EQ(first_keys.m_view_secret_key,  rederived_keys.m_view_secret_key);
  ASSERT_EQ(first_keys.m_ml_kem_decap_key, rederived_keys.m_ml_kem_decap_key);
}

// Same passphrase-vs-no-passphrase isolation as BIP-39 §C: a non-empty
// passphrase must produce a different account from the empty passphrase.
// (Cheap to add and protects against a future "passphrase ignored" bug
// in the FFI plumbing.)
TEST(account, bip39_passphrase_changes_account_mainnet)
{
  static constexpr const char *kZeroEntropyMnemonic =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon art";

  cryptonote::account_base no_pass;
  no_pass.generate_from_bip39(kZeroEntropyMnemonic, std::string{}, cryptonote::MAINNET);

  cryptonote::account_base with_pass;
  with_pass.generate_from_bip39(kZeroEntropyMnemonic, "TREZOR", cryptonote::MAINNET);

  ASSERT_NE(no_pass.get_keys().m_master_seed_64,
            with_pass.get_keys().m_master_seed_64);
  ASSERT_NE(no_pass.get_keys().m_account_address,
            with_pass.get_keys().m_account_address);
}

// Cover the other two permitted (network, format) pairs end-to-end:
// (Stagenet, Bip39) and (Testnet, Raw32). Together with
// `rederive_from_bip39_reproduces_account_mainnet` and
// `rederive_from_raw_seed_reproduces_account` (Fakechain), these four
// tests exercise every cell of `permitted_seed_format()`'s positive
// matrix and pin the C++ `derivation_network_from_nettype()` mapping
// (`src/cryptonote_basic/account.cpp:66-75`) for all four networks at
// the FFI boundary. Without these two cases, a regression in the
// STAGENET- or TESTNET-byte mapping would only surface via the
// rejection paths, which can pass for the wrong reason. Surfaced by
// Copilot's PR #27 round-2 review.
TEST(account, rederive_from_bip39_reproduces_account_stagenet)
{
  static constexpr const char *kZeroEntropyMnemonic =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon art";

  cryptonote::account_base first;
  first.generate_from_bip39(kZeroEntropyMnemonic, std::string{}, cryptonote::STAGENET);
  const auto first_keys = first.get_keys();

  ASSERT_EQ(first_keys.m_seed_format,
            static_cast<uint8_t>(SHEKYL_SEED_FORMAT_BIP39));
  ASSERT_EQ(first_keys.m_master_seed_64.size(),
            static_cast<size_t>(SHEKYL_MASTER_SEED_BYTES));

  cryptonote::account_base rederived = first;
  rederived.rederive_from_master_seed(cryptonote::STAGENET);
  const auto rederived_keys = rederived.get_keys();

  ASSERT_EQ(first_keys.m_account_address, rederived_keys.m_account_address);
  ASSERT_EQ(first_keys.m_spend_secret_key, rederived_keys.m_spend_secret_key);
  ASSERT_EQ(first_keys.m_view_secret_key,  rederived_keys.m_view_secret_key);
  ASSERT_EQ(first_keys.m_ml_kem_decap_key, rederived_keys.m_ml_kem_decap_key);

  // Cross-network HKDF-salt invariant: the same mnemonic on MAINNET vs
  // STAGENET must derive different accounts. This is the property that
  // protects against a stagenet-test-fixture key colliding with a real
  // mainnet key (per the comment on `derivation_network_from_nettype`).
  cryptonote::account_base mainnet;
  mainnet.generate_from_bip39(kZeroEntropyMnemonic, std::string{}, cryptonote::MAINNET);
  ASSERT_NE(first_keys.m_account_address, mainnet.get_keys().m_account_address);
}

TEST(account, rederive_from_raw_seed_reproduces_account_testnet)
{
  uint8_t raw_seed[SHEKYL_RAW_SEED_BYTES] = {
      0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
      0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
      0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
  };

  cryptonote::account_base first;
  first.generate_from_raw_seed(raw_seed, cryptonote::TESTNET);
  const auto first_keys = first.get_keys();

  ASSERT_EQ(first_keys.m_seed_format,
            static_cast<uint8_t>(SHEKYL_SEED_FORMAT_RAW32));

  cryptonote::account_base rederived = first;
  rederived.rederive_from_master_seed(cryptonote::TESTNET);
  const auto rederived_keys = rederived.get_keys();

  ASSERT_EQ(first_keys.m_account_address, rederived_keys.m_account_address);
  ASSERT_EQ(first_keys.m_spend_secret_key, rederived_keys.m_spend_secret_key);
  ASSERT_EQ(first_keys.m_view_secret_key,  rederived_keys.m_view_secret_key);
  ASSERT_EQ(first_keys.m_ml_kem_decap_key, rederived_keys.m_ml_kem_decap_key);

  // Cross-network HKDF-salt invariant: same raw seed on TESTNET vs
  // FAKECHAIN must derive different accounts.
  cryptonote::account_base fakechain;
  fakechain.generate_from_raw_seed(raw_seed, cryptonote::FAKECHAIN);
  ASSERT_NE(first_keys.m_account_address, fakechain.get_keys().m_account_address);
}

// (Network, format) matrix: FAKECHAIN/TESTNET refuse BIP-39, MAINNET/STAGENET
// refuse RAW32. The FFI returns false on a disallowed pair; account_base
// throws. This test pins the consensus-level acceptance matrix at the C++
// boundary so a future "loosen the matrix" change has to update the test.
TEST(account, generate_from_bip39_rejects_fakechain_and_testnet)
{
  static constexpr const char *kZeroEntropyMnemonic =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon art";

  cryptonote::account_base account;
  EXPECT_ANY_THROW(account.generate_from_bip39(
      kZeroEntropyMnemonic, std::string{}, cryptonote::FAKECHAIN));
  EXPECT_ANY_THROW(account.generate_from_bip39(
      kZeroEntropyMnemonic, std::string{}, cryptonote::TESTNET));
}

TEST(account, generate_from_raw_seed_rejects_mainnet_and_stagenet)
{
  uint8_t raw_seed[SHEKYL_RAW_SEED_BYTES] = {};
  cryptonote::account_base account;
  EXPECT_ANY_THROW(account.generate_from_raw_seed(raw_seed, cryptonote::MAINNET));
  EXPECT_ANY_THROW(account.generate_from_raw_seed(raw_seed, cryptonote::STAGENET));
}

// Bug 4-adjacent regression test (audit 2026-05-05).
//
// Pre-fix, the legacy 3-arg `account_base::generate(recovery, recover,
// two_random)` hardcoded `FAKECHAIN` for the derivation salt regardless of
// the wallet's actual network. `wallet2::generate` and
// `wallet_rpc_server::on_stop_background_sync` both called this overload,
// silently producing FAKECHAIN-salted accounts on non-FAKECHAIN wallets,
// which then failed to round-trip through `wallet2::load`'s rederive
// (rederive uses `m_nettype`, not FAKECHAIN).
//
// Fix: a single `generate(recovery, recover, two_random, nettype)` overload
// that requires every caller — production and test — to spell its network
// out explicitly. The default-FAKECHAIN overload is deleted entirely so
// the footgun cannot be reintroduced by omitting an argument.
//
// This test pins:
//   1. `generate(..., nettype)` is wired through to `generate_from_raw_seed`
//      with the provided `nettype` (TESTNET-derived account matches the
//      lower-level API's output, and differs from FAKECHAIN-derived
//      account for the same raw seed — distinct HKDF salt).
//   2. `generate(..., MAINNET)` and `generate(..., STAGENET)` throw at the
//      FFI's `permitted_seed_format` check. This is the failure mode that
//      replaces the pre-fix silent miscompile: production paths
//      (`wallet2::generate`, `on_create_wallet` RPC, `on_stop_background_sync`)
//      now fail loudly on (MAINNET, RAW32) / (STAGENET, RAW32) rather than
//      silently producing FAKECHAIN-salted unspendable wallets.
// See `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`.
TEST(account, generate_uses_explicit_nettype_argument)
{
  uint8_t raw_seed[SHEKYL_RAW_SEED_BYTES] = {
      0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
      0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
      0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
      0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
  };
  crypto::secret_key recovery;
  std::memcpy(recovery.data, raw_seed, sizeof(recovery.data));

  // generate(..., TESTNET) produces a TESTNET-salted account.
  cryptonote::account_base testnet_account;
  testnet_account.generate(recovery, /*recover=*/true, /*two_random=*/false,
                           cryptonote::TESTNET);

  // Reference TESTNET account from the lower-level `generate_from_raw_seed`
  // API; the high-level `generate(..., TESTNET)` must produce identical keys.
  cryptonote::account_base testnet_reference;
  testnet_reference.generate_from_raw_seed(raw_seed, cryptonote::TESTNET);
  ASSERT_EQ(testnet_account.get_keys().m_account_address,
            testnet_reference.get_keys().m_account_address);
  ASSERT_EQ(testnet_account.get_keys().m_spend_secret_key,
            testnet_reference.get_keys().m_spend_secret_key);
  ASSERT_EQ(testnet_account.get_keys().m_view_secret_key,
            testnet_reference.get_keys().m_view_secret_key);

  // generate(..., FAKECHAIN) produces a FAKECHAIN-salted account distinct
  // from the TESTNET one — the HKDF salt is per-network so the same raw
  // seed cannot produce the same address across networks. This is the
  // invariant that protects against a fakechain-regression test
  // accidentally publishing a real mainnet-or-testnet key.
  cryptonote::account_base fakechain_account;
  fakechain_account.generate(recovery, /*recover=*/true, /*two_random=*/false,
                             cryptonote::FAKECHAIN);
  ASSERT_NE(testnet_account.get_keys().m_account_address,
            fakechain_account.get_keys().m_account_address);
  ASSERT_NE(testnet_account.get_keys().m_spend_secret_key,
            fakechain_account.get_keys().m_spend_secret_key);

  // generate(..., MAINNET / STAGENET) throws (RAW32 not permitted on those
  // networks; the throw happens inside `generate_from_raw_seed`'s FFI
  // `permitted_seed_format` check). Both `recover=true` (restoring from a
  // user-supplied seed) and `recover=false` (fresh-CSPRNG seed) reject —
  // i.e. there is no production path through this overload that produces
  // a MAINNET / STAGENET wallet, by design. MAINNET / STAGENET wallets
  // must be created via `generate_from_bip39`.
  cryptonote::account_base mainnet_recover;
  EXPECT_ANY_THROW(mainnet_recover.generate(
      recovery, /*recover=*/true, /*two_random=*/false, cryptonote::MAINNET));
  cryptonote::account_base mainnet_fresh;
  EXPECT_ANY_THROW(mainnet_fresh.generate(
      crypto::secret_key{}, /*recover=*/false, /*two_random=*/false,
      cryptonote::MAINNET));
  cryptonote::account_base stagenet_recover;
  EXPECT_ANY_THROW(stagenet_recover.generate(
      recovery, /*recover=*/true, /*two_random=*/false, cryptonote::STAGENET));
  cryptonote::account_base stagenet_fresh;
  EXPECT_ANY_THROW(stagenet_fresh.generate(
      crypto::secret_key{}, /*recover=*/false, /*two_random=*/false,
      cryptonote::STAGENET));
}
