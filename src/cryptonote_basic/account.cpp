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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <array>
#include <cstring>
#include <fstream>

#include "include_base_utils.h"
#include "account.h"
#include "warnings.h"
#include "crypto/crypto.h"
#include "cryptonote_basic_impl.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"
#include "shekyl/shekyl_secure_mem.h"
#include "memwipe.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "account"

using namespace std;

DISABLE_VS_WARNINGS(4244 4345)

  namespace cryptonote
{
  namespace
  {
    // Map a wallet-level network enum to the u8 that every
    // shekyl_account_* FFI expects as its `network` argument. Distinct from
    // nettype_to_ffi_network in cryptonote_basic_impl.cpp, which encodes
    // *bech32m* network prefixes — there MAINNET and FAKECHAIN share a byte
    // so fakechain wallets can round-trip a real mainnet address in tests.
    // Derivation, by contrast, requires FAKECHAIN to have its own HKDF salt
    // so a mainnet seed and a fakechain seed of the same bytes produce
    // different addresses. This is the invariant that protects against a
    // fakechain-regression test accidentally publishing a real mainnet key.
    uint8_t derivation_network_from_nettype(network_type nettype)
    {
      switch (nettype)
      {
        case MAINNET:   return SHEKYL_DERIVATION_NETWORK_MAINNET;
        case TESTNET:   return SHEKYL_DERIVATION_NETWORK_TESTNET;
        case STAGENET:  return SHEKYL_DERIVATION_NETWORK_STAGENET;
        case FAKECHAIN: return SHEKYL_DERIVATION_NETWORK_FAKECHAIN;
        default:        return SHEKYL_DERIVATION_NETWORK_FAKECHAIN;
      }
    }

    // Copy the public half of a blob into the caller's account_public_address
    // and the secret half into the caller's account_keys. On entry the blob
    // has already been populated by a successful FFI call; on exit the blob
    // is zeroized so that no stray secret bytes remain on the C++ stack.
    //
    // The view-prefixed legacy m_pqc_secret_key buffer is maintained as a
    // courtesy for unmigrated consumers (see the account.h field comment);
    // commit 3 of this branch will delete both the field and this fill-in.
    void populate_account_from_blob(account_keys &keys, ShekylAllKeysBlob &blob)
    {
      // --- public side ------------------------------------------------------
      std::memcpy(&keys.m_account_address.m_spend_public_key, blob.spend_pk, 32);
      std::memcpy(&keys.m_account_address.m_view_public_key,  blob.view_pk,  32);

      keys.m_account_address.m_pqc_public_key.assign(
          blob.pqc_public_key,
          blob.pqc_public_key + SHEKYL_PQC_PUBLIC_KEY_BYTES);

      // --- classical scalar secrets ----------------------------------------
      // Write through the `data` array rather than the mlocked wrapper so we
      // don't trip -Wclass-memaccess; this matches the xor_with_key_stream
      // access pattern above.
      std::memcpy(keys.m_spend_secret_key.data, blob.spend_sk, 32);
      std::memcpy(keys.m_view_secret_key.data,  blob.view_sk,  32);

      // --- ML-KEM decap key (rederived, never persisted) -------------------
      keys.m_ml_kem_decap_key.assign(
          blob.ml_kem_dk,
          blob.ml_kem_dk + SHEKYL_ML_KEM_768_DK_BYTES);
      if (!keys.m_ml_kem_decap_key.empty())
      {
        shekyl_mlock(keys.m_ml_kem_decap_key.data(), keys.m_ml_kem_decap_key.size());
        shekyl_madvise_dontdump(keys.m_ml_kem_decap_key.data(), keys.m_ml_kem_decap_key.size());
      }

      // --- LEGACY view-prefixed PQC secret buffer --------------------------
      // view_secret[32] || ML-KEM_dk[2400]. Every consumer that still reads
      // this field is flagged in the summary attached to commit 1 of
      // feat/wallet-account-rewire; commit 2 of the same branch migrates
      // them; commit 3 deletes the field altogether.
      keys.m_pqc_secret_key.clear();
      keys.m_pqc_secret_key.reserve(32 + SHEKYL_ML_KEM_768_DK_BYTES);
      keys.m_pqc_secret_key.insert(
          keys.m_pqc_secret_key.end(),
          blob.view_sk, blob.view_sk + 32);
      keys.m_pqc_secret_key.insert(
          keys.m_pqc_secret_key.end(),
          blob.ml_kem_dk, blob.ml_kem_dk + SHEKYL_ML_KEM_768_DK_BYTES);
      shekyl_mlock(keys.m_pqc_secret_key.data(), keys.m_pqc_secret_key.size());
      shekyl_madvise_dontdump(keys.m_pqc_secret_key.data(), keys.m_pqc_secret_key.size());

      // The caller is expected to set m_master_seed_64, m_seed_format, and
      // m_master_seed_present itself, because those values are the *input*
      // to derivation rather than an output of it. We wipe the blob now to
      // minimize the window during which a second copy of the secret
      // material lives in caller-controlled stack memory.
      shekyl_memwipe(&blob, sizeof(blob));
    }

    // Helper used by every path that populates m_master_seed_64 + flags.
    void install_master_seed(
        account_keys &keys,
        const uint8_t *seed64,
        uint8_t seed_format)
    {
      keys.m_master_seed_64.assign(seed64, seed64 + SHEKYL_MASTER_SEED_BYTES);
      shekyl_mlock(keys.m_master_seed_64.data(), keys.m_master_seed_64.size());
      shekyl_madvise_dontdump(keys.m_master_seed_64.data(), keys.m_master_seed_64.size());
      keys.m_seed_format = seed_format;
      keys.m_master_seed_present = true;
    }
  }

  //-----------------------------------------------------------------
  account_keys::~account_keys()
  {
    memwipe(&m_spend_secret_key, sizeof(m_spend_secret_key));
    memwipe(&m_view_secret_key, sizeof(m_view_secret_key));
    if (!m_pqc_secret_key.empty()) {
      shekyl_memwipe(m_pqc_secret_key.data(), m_pqc_secret_key.size());
      shekyl_munlock(m_pqc_secret_key.data(), m_pqc_secret_key.size());
    }
    if (!m_ml_kem_decap_key.empty()) {
      shekyl_memwipe(m_ml_kem_decap_key.data(), m_ml_kem_decap_key.size());
      shekyl_munlock(m_ml_kem_decap_key.data(), m_ml_kem_decap_key.size());
    }
    if (!m_master_seed_64.empty()) {
      shekyl_memwipe(m_master_seed_64.data(), m_master_seed_64.size());
      shekyl_munlock(m_master_seed_64.data(), m_master_seed_64.size());
    }
    m_master_seed_present = false;
  }
  //-----------------------------------------------------------------
  hw::device& account_keys::get_device() const  {
    return *m_device;
  }
  //-----------------------------------------------------------------
  void account_keys::set_device( hw::device &hwdev)  {
    m_device = &hwdev;
    MCDEBUG("device", "account_keys::set_device device type: "<<typeid(hwdev).name());
  }
  //-----------------------------------------------------------------
  static void derive_key(const crypto::chacha_key &base_key, crypto::chacha_key &key)
  {
    static_assert(sizeof(base_key) == sizeof(crypto::hash), "chacha key and hash should be the same size");
    epee::mlocked<tools::scrubbed_arr<char, sizeof(base_key)+1>> data;
    memcpy(data.data(), &base_key, sizeof(base_key));
    data[sizeof(base_key)] = config::HASH_KEY_MEMORY;
    crypto::generate_chacha_key(data.data(), sizeof(data), key, 1);
  }
  //-----------------------------------------------------------------
  static epee::wipeable_string get_key_stream(const crypto::chacha_key &base_key, const crypto::chacha_iv &iv, size_t bytes)
  {
    // derive a new key
    crypto::chacha_key key;
    derive_key(base_key, key);

    // chacha
    epee::wipeable_string buffer0(std::string(bytes, '\0'));
    epee::wipeable_string buffer1 = buffer0;
    crypto::xchacha20(buffer0.data(), buffer0.size(), key, iv, buffer1.data());
    return buffer1;
  }
  //-----------------------------------------------------------------
  void account_keys::xor_with_key_stream(const crypto::chacha_key &key)
  {
    // Encrypt both the legacy pqc-secret buffer AND the master seed in-place.
    // Each contributes its own byte span to the keystream length so that
    // zero-length fields (e.g. a pre-v1 wallet without m_master_seed_64, or a
    // device wallet without m_pqc_secret_key) don't shift the byte offsets of
    // the other fields. Ordering here is load-bearing: it is the on-disk XOR
    // layout for every wallet that has ever been written with this code.
    //   spend_sk[32] || view_sk[32] || pqc_sk[0 or 2432] || master_seed[0 or 64]
    const size_t pq_bytes = m_pqc_secret_key.size();
    const size_t ms_bytes = m_master_seed_64.size();
    epee::wipeable_string key_stream = get_key_stream(
        key, m_encryption_iv,
        sizeof(crypto::secret_key) * 2 + pq_bytes + ms_bytes);
    const char *ptr = key_stream.data();
    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
      m_spend_secret_key.data[i] ^= *ptr++;
    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
      m_view_secret_key.data[i] ^= *ptr++;
    for (size_t i = 0; i < pq_bytes; ++i)
      m_pqc_secret_key[i] ^= static_cast<uint8_t>(*ptr++);
    for (size_t i = 0; i < ms_bytes; ++i)
      m_master_seed_64[i] ^= static_cast<uint8_t>(*ptr++);
  }
  //-----------------------------------------------------------------
  void account_keys::encrypt(const crypto::chacha_key &key)
  {
    m_encryption_iv = crypto::rand<crypto::chacha_iv>();
    xor_with_key_stream(key);
  }
  //-----------------------------------------------------------------
  void account_keys::decrypt(const crypto::chacha_key &key)
  {
    xor_with_key_stream(key);
    if (!m_pqc_secret_key.empty()) {
      shekyl_mlock(m_pqc_secret_key.data(), m_pqc_secret_key.size());
      shekyl_madvise_dontdump(m_pqc_secret_key.data(), m_pqc_secret_key.size());
    }
    if (!m_master_seed_64.empty()) {
      shekyl_mlock(m_master_seed_64.data(), m_master_seed_64.size());
      shekyl_madvise_dontdump(m_master_seed_64.data(), m_master_seed_64.size());
      m_master_seed_present = true;
    }
  }
  //-----------------------------------------------------------------
  void account_keys::encrypt_viewkey(const crypto::chacha_key &key)
  {
    epee::wipeable_string key_stream = get_key_stream(key, m_encryption_iv, sizeof(crypto::secret_key) * 2);
    const char *ptr = key_stream.data();
    ptr += sizeof(crypto::secret_key);
    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
      m_view_secret_key.data[i] ^= *ptr++;
  }
  //-----------------------------------------------------------------
  void account_keys::decrypt_viewkey(const crypto::chacha_key &key)
  {
    encrypt_viewkey(key);
  }
  //-----------------------------------------------------------------
  account_base::account_base()
  {
    set_null();
  }
  //-----------------------------------------------------------------
  void account_base::set_null()
  {
    memwipe(&m_keys.m_spend_secret_key, sizeof(m_keys.m_spend_secret_key));
    memwipe(&m_keys.m_view_secret_key, sizeof(m_keys.m_view_secret_key));
    if (!m_keys.m_pqc_secret_key.empty()) {
      shekyl_memwipe(m_keys.m_pqc_secret_key.data(), m_keys.m_pqc_secret_key.size());
      shekyl_munlock(m_keys.m_pqc_secret_key.data(), m_keys.m_pqc_secret_key.size());
    }
    if (!m_keys.m_ml_kem_decap_key.empty()) {
      shekyl_memwipe(m_keys.m_ml_kem_decap_key.data(), m_keys.m_ml_kem_decap_key.size());
      shekyl_munlock(m_keys.m_ml_kem_decap_key.data(), m_keys.m_ml_kem_decap_key.size());
    }
    if (!m_keys.m_master_seed_64.empty()) {
      shekyl_memwipe(m_keys.m_master_seed_64.data(), m_keys.m_master_seed_64.size());
      shekyl_munlock(m_keys.m_master_seed_64.data(), m_keys.m_master_seed_64.size());
    }
    m_keys = account_keys();
    m_creation_timestamp = 0;
  }
  //-----------------------------------------------------------------
  void account_base::deinit()
  {
    try{
      m_keys.get_device().disconnect();
    } catch (const std::exception &e){
      MERROR("Device disconnect exception: " << e.what());
    }
  }
  //-----------------------------------------------------------------
  void account_base::forget_spend_key()
  {
    // Forgetting the spend key is only honest if we also destroy every byte
    // from which the spend key could be rederived. In v1 that is the entire
    // master seed; without it the wallet becomes a genuine view-only wallet
    // that retains m_view_secret_key + m_ml_kem_decap_key for incoming-tx
    // decapsulation but cannot sign outgoing transactions. m_pqc_secret_key
    // is cleared because its view_secret prefix is useless in isolation and
    // its ML-KEM decap suffix is preserved in m_ml_kem_decap_key.
    m_keys.m_spend_secret_key = crypto::secret_key();
    if (!m_keys.m_pqc_secret_key.empty()) {
      shekyl_memwipe(m_keys.m_pqc_secret_key.data(), m_keys.m_pqc_secret_key.size());
      shekyl_munlock(m_keys.m_pqc_secret_key.data(), m_keys.m_pqc_secret_key.size());
    }
    m_keys.m_pqc_secret_key.clear();
    if (!m_keys.m_master_seed_64.empty()) {
      shekyl_memwipe(m_keys.m_master_seed_64.data(), m_keys.m_master_seed_64.size());
      shekyl_munlock(m_keys.m_master_seed_64.data(), m_keys.m_master_seed_64.size());
    }
    m_keys.m_master_seed_64.clear();
    m_keys.m_master_seed_present = false;
  }
  //-----------------------------------------------------------------
  void account_base::set_spend_key(const crypto::secret_key& spend_secret_key)
  {
    // make sure derived spend public key matches saved public spend key
    crypto::public_key spend_public_key;
    crypto::secret_key_to_public_key(spend_secret_key, spend_public_key);
    CHECK_AND_ASSERT_THROW_MES(m_keys.m_account_address.m_spend_public_key == spend_public_key,
        "Unexpected derived public spend key");

    m_keys.m_spend_secret_key = spend_secret_key;
  }
  //-----------------------------------------------------------------
  void account_base::generate_from_raw_seed(
      const uint8_t raw_seed[SHEKYL_RAW_SEED_BYTES],
      network_type nettype)
  {
    set_null();

    uint8_t master_seed_out[SHEKYL_MASTER_SEED_BYTES];
    ShekylAllKeysBlob blob{};
    const bool ok = shekyl_account_generate_from_raw_seed(
        raw_seed,
        derivation_network_from_nettype(nettype),
        master_seed_out,
        &blob);
    CHECK_AND_ASSERT_THROW_MES(
        ok,
        "shekyl_account_generate_from_raw_seed rejected input "
        "(disallowed (network, raw) pair or FFI failure)");

    populate_account_from_blob(m_keys, blob);
    install_master_seed(m_keys, master_seed_out, SHEKYL_SEED_FORMAT_RAW32);
    // We are done with the stack-resident copy of the master seed; wipe it.
    shekyl_memwipe(master_seed_out, sizeof(master_seed_out));

    m_creation_timestamp = time(NULL);
  }
  //-----------------------------------------------------------------
  void account_base::generate_from_bip39(
      const std::string &mnemonic_words,
      const std::string &passphrase,
      network_type nettype)
  {
    set_null();

    uint8_t master_seed_out[SHEKYL_MASTER_SEED_BYTES];
    ShekylAllKeysBlob blob{};
    const bool ok = shekyl_account_generate_from_bip39(
        reinterpret_cast<const uint8_t*>(mnemonic_words.data()),
        mnemonic_words.size(),
        passphrase.empty() ? nullptr : reinterpret_cast<const uint8_t*>(passphrase.data()),
        passphrase.size(),
        derivation_network_from_nettype(nettype),
        master_seed_out,
        &blob);
    CHECK_AND_ASSERT_THROW_MES(
        ok,
        "shekyl_account_generate_from_bip39 rejected input "
        "(invalid mnemonic or disallowed (network, BIP-39) pair)");

    populate_account_from_blob(m_keys, blob);
    install_master_seed(m_keys, master_seed_out, SHEKYL_SEED_FORMAT_BIP39);
    shekyl_memwipe(master_seed_out, sizeof(master_seed_out));

    m_creation_timestamp = time(NULL);
  }
  //-----------------------------------------------------------------
  void account_base::rederive_from_master_seed(network_type nettype)
  {
    CHECK_AND_ASSERT_THROW_MES(
        m_keys.m_master_seed_present &&
            m_keys.m_master_seed_64.size() == SHEKYL_MASTER_SEED_BYTES,
        "account_base::rederive_from_master_seed: no master seed in memory "
        "(v1 wallet not yet opened or legacy wallet with no seed)");
    CHECK_AND_ASSERT_THROW_MES(
        m_keys.m_seed_format == SHEKYL_SEED_FORMAT_BIP39 ||
            m_keys.m_seed_format == SHEKYL_SEED_FORMAT_RAW32,
        "account_base::rederive_from_master_seed: unknown seed format "
            << static_cast<int>(m_keys.m_seed_format));

    ShekylAllKeysBlob blob{};
    const bool ok = shekyl_account_rederive(
        m_keys.m_master_seed_64.data(),
        derivation_network_from_nettype(nettype),
        m_keys.m_seed_format,
        &blob);
    CHECK_AND_ASSERT_THROW_MES(
        ok,
        "shekyl_account_rederive failed: (network, seed_format) pair "
        "disallowed or derivation inconsistent");

    populate_account_from_blob(m_keys, blob);
    // m_master_seed_64 / m_seed_format / m_master_seed_present stay as they
    // were — rederivation is a read-only operation on the seed.
  }
  //-----------------------------------------------------------------
  crypto::secret_key account_base::generate(
      const crypto::secret_key& recovery_key,
      bool recover,
      bool two_random)
  {
    // The Electrum-style 25-word / keccak-chain recovery path is gone; see
    // .cursor/rules/36-secret-locality.mdc and the wallet-account-rewire
    // commit on feat/wallet-account-rewire. This wrapper exists only so
    // unit / integration tests that historically called
    //   account.generate()
    //   account.generate(recovery_key, true, false)
    // keep building. It treats `recovery_key.data` as a 32-byte raw seed
    // on DerivationNetwork::Fakechain (not mainnet, not testnet). The bool
    // `two_random` is ignored; it was never true in the wallet path.
    (void)two_random;

    std::array<uint8_t, SHEKYL_RAW_SEED_BYTES> raw_seed{};
    if (recover)
    {
      std::memcpy(raw_seed.data(), recovery_key.data, SHEKYL_RAW_SEED_BYTES);
    }
    else
    {
      CHECK_AND_ASSERT_THROW_MES(
          shekyl_raw_seed_generate(raw_seed.data()),
          "shekyl_raw_seed_generate failed (OS CSPRNG unavailable)");
    }

    generate_from_raw_seed(raw_seed.data(), FAKECHAIN);
    // Wipe the local copy of the seed before returning; the authoritative
    // copy lives in m_keys.m_master_seed_64 under mlock.
    shekyl_memwipe(raw_seed.data(), raw_seed.size());

    // Legacy callers expect the spend secret key back so they can re-encode
    // it as a "recovery key" elsewhere. In the v1 model this is a degraded
    // capability (it can reconstruct the spend side of the account but not
    // the ML-KEM decap key), but returning it keeps the existing test
    // expectations meaningful.
    crypto::secret_key first = m_keys.m_spend_secret_key;
    return first;
  }
  //-----------------------------------------------------------------
  void account_base::create_from_keys(const cryptonote::account_public_address& address, const crypto::secret_key& spendkey, const crypto::secret_key& viewkey)
  {
    m_keys.m_account_address = address;
    m_keys.m_spend_secret_key = spendkey;
    m_keys.m_view_secret_key = viewkey;
    // Restoring from spend+view keys in v1 is a genuine view-only / limited
    // capability: there is no way to recover the ML-KEM decap key from the
    // Ed25519 scalars alone. We therefore leave every PQC-related buffer
    // empty. wallet2.cpp will surface the "cannot sign v3" state to the user.
    if (!m_keys.m_pqc_secret_key.empty()) {
      shekyl_memwipe(m_keys.m_pqc_secret_key.data(), m_keys.m_pqc_secret_key.size());
      shekyl_munlock(m_keys.m_pqc_secret_key.data(), m_keys.m_pqc_secret_key.size());
    }
    m_keys.m_pqc_secret_key.clear();
    if (!m_keys.m_ml_kem_decap_key.empty()) {
      shekyl_memwipe(m_keys.m_ml_kem_decap_key.data(), m_keys.m_ml_kem_decap_key.size());
      shekyl_munlock(m_keys.m_ml_kem_decap_key.data(), m_keys.m_ml_kem_decap_key.size());
    }
    m_keys.m_ml_kem_decap_key.clear();
    if (!m_keys.m_master_seed_64.empty()) {
      shekyl_memwipe(m_keys.m_master_seed_64.data(), m_keys.m_master_seed_64.size());
      shekyl_munlock(m_keys.m_master_seed_64.data(), m_keys.m_master_seed_64.size());
    }
    m_keys.m_master_seed_64.clear();
    m_keys.m_master_seed_present = false;

    struct tm timestamp = {0};
    timestamp.tm_year = 2014 - 1900;  // year 2014
    timestamp.tm_mon = 4 - 1;  // month april
    timestamp.tm_mday = 15;  // 15th of april
    timestamp.tm_hour = 0;
    timestamp.tm_min = 0;
    timestamp.tm_sec = 0;

    m_creation_timestamp = mktime(&timestamp);
    if (m_creation_timestamp == (uint64_t)-1) // failure
      m_creation_timestamp = 0; // lowest value
  }

  //-----------------------------------------------------------------
  void account_base::create_from_device(const std::string &device_name)
  {
    hw::device &hwdev =  hw::get_device(device_name);
    hwdev.set_name(device_name);
    create_from_device(hwdev);
  }

  void account_base::create_from_device(hw::device &hwdev)
  {
    m_keys.set_device(hwdev);
    MCDEBUG("device", "device type: "<<typeid(hwdev).name());
    CHECK_AND_ASSERT_THROW_MES(hwdev.init(), "Device init failed");
    CHECK_AND_ASSERT_THROW_MES(hwdev.connect(), "Device connect failed");
    try {
      CHECK_AND_ASSERT_THROW_MES(hwdev.get_public_address(m_keys.m_account_address), "Cannot get a device address");
      CHECK_AND_ASSERT_THROW_MES(hwdev.get_secret_keys(m_keys.m_view_secret_key, m_keys.m_spend_secret_key), "Cannot get device secret");
      // Hardware-wallet integration for PQC is tracked separately; the
      // device FFI currently returns only Ed25519 scalars so we can't
      // materialize an ML-KEM keypair deterministically without the seed.
      // For v1 we ship with device wallets as "classical signing only" and
      // will teach device_ledger.cpp the master-seed export path in a
      // follow-up (see docs/POST_QUANTUM_CRYPTOGRAPHY.md §Hardware).
    } catch (const std::exception &e){
      hwdev.disconnect();
      throw;
    }
    struct tm timestamp = {0};
    timestamp.tm_year = 2014 - 1900;  // year 2014
    timestamp.tm_mon = 4 - 1;  // month april
    timestamp.tm_mday = 15;  // 15th of april
    timestamp.tm_hour = 0;
    timestamp.tm_min = 0;
    timestamp.tm_sec = 0;

    m_creation_timestamp = mktime(&timestamp);
    if (m_creation_timestamp == (uint64_t)-1) // failure
      m_creation_timestamp = 0; // lowest value
  }
  //-----------------------------------------------------------------
  void account_base::create_from_viewkey(const cryptonote::account_public_address& address, const crypto::secret_key& viewkey)
  {
    crypto::secret_key fake{};
    create_from_keys(address, fake, viewkey);
  }
  //-----------------------------------------------------------------
  const account_keys& account_base::get_keys() const
  {
    return m_keys;
  }
  //-----------------------------------------------------------------
  std::string account_base::get_public_address_str(network_type nettype) const
  {
    return get_account_address_as_str(nettype, false, m_keys.m_account_address);
  }
  //-----------------------------------------------------------------
  std::string account_base::get_public_integrated_address_str(const crypto::hash8 &payment_id, network_type nettype) const
  {
    return get_account_integrated_address_as_str(nettype, m_keys.m_account_address, payment_id);
  }
  //-----------------------------------------------------------------
}
