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

#pragma once

#include "cryptonote_basic.h"
#include "crypto/crypto.h"
#include "serialization/keyvalue_serialization.h"
#include "shekyl/shekyl_ffi.h"

namespace epee { class wipeable_string; }

namespace cryptonote
{

  struct account_keys
  {
    account_public_address m_account_address;
    crypto::secret_key   m_spend_secret_key;
    crypto::secret_key   m_view_secret_key;

    // --- v1 stabilized state (see rust/shekyl-crypto-pq/src/account.rs) -----
    //
    // m_master_seed_64 is the only byte sequence that is *persisted* as a
    // secret; every other secret below is rederived on wallet open via
    // shekyl_account_rederive. Its in-memory copy is XOR-encrypted at rest
    // with the same chacha keystream as m_spend_secret_key / m_view_secret_key
    // and is wiped on destruction.
    //
    // m_seed_format records whether the master seed originated from a
    // BIP-39 mnemonic (mainnet/stagenet) or from a 32-byte raw seed
    // (testnet/fakechain); it is *not* encrypted because its value is
    // bound into the HKDF salt and therefore must survive a keyfile
    // decryption failure so the wallet can tell the user whether the
    // mismatch was password vs network.
    //
    // m_ml_kem_decap_key is never persisted. It is recomputed on every
    // open; see POST_QUANTUM_CRYPTOGRAPHY.md for the rationale (ML-KEM-768
    // decap key size > 2 KiB and the underlying library's encoding can
    // change without breaking FIPS-203 consumers).
    //
    // m_master_seed_present distinguishes "v1 wallet, seed in memory"
    // from "legacy / view-only wallet, no seed available" at runtime.
    std::vector<uint8_t> m_master_seed_64;
    uint8_t              m_seed_format = SHEKYL_SEED_FORMAT_RAW32;
    bool                 m_master_seed_present = false;
    std::vector<uint8_t> m_ml_kem_decap_key;

    hw::device *m_device = &hw::get_device("default");
    crypto::chacha_iv m_encryption_iv;

    account_keys() = default;
    ~account_keys();
    account_keys(const account_keys&) = default;
    account_keys& operator=(const account_keys&) = default;
    account_keys(account_keys&&) = default;
    account_keys& operator=(account_keys&&) = default;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(m_account_address)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_spend_secret_key)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_view_secret_key)
      KV_SERIALIZE_OPT(m_master_seed_64, std::vector<uint8_t>())
      KV_SERIALIZE_OPT(m_seed_format, (uint8_t)SHEKYL_SEED_FORMAT_RAW32)
      const crypto::chacha_iv default_iv{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
      KV_SERIALIZE_VAL_POD_AS_BLOB_OPT(m_encryption_iv, default_iv)
    END_KV_SERIALIZE_MAP()

    void encrypt(const crypto::chacha_key &key);
    void decrypt(const crypto::chacha_key &key);
    void encrypt_viewkey(const crypto::chacha_key &key);
    void decrypt_viewkey(const crypto::chacha_key &key);

    hw::device& get_device()  const ;
    void set_device( hw::device &hwdev) ;

  private:
    void xor_with_key_stream(const crypto::chacha_key &key);
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class account_base
  {
  public:
    account_base();

    // --- v1 canonical entry points ------------------------------------------
    //
    // Every production code path should go through one of these three calls.
    // They dispatch to the Rust `shekyl_account_*` FFIs, which own all secret
    // material; this class only receives a fully-formed `ShekylAllKeysBlob`
    // whose public side is copied into `m_account_address`, and whose secret
    // side is copied into the mlock'd region owned by `account_keys`.
    //
    // The `nettype` argument is required because the HKDF salt is network-
    // bound; calling generate_from_raw_seed with the wrong network does not
    // produce the right addresses.

    /// Mainnet / stagenet production path. 24 English BIP-39 words + optional
    /// passphrase. Throws on invalid mnemonic or disallowed (nettype,format)
    /// pair. `passphrase` may be empty.
    ///
    /// Inputs are taken as `epee::wipeable_string` so the BIP-39 phrase and
    /// passphrase remain inside the wipe-on-drop discipline end-to-end:
    /// the underlying FFI consumes them via `data()` / `size()` for a
    /// single immediate call and does not persist them, and no
    /// `std::string` intermediate is materialized at the call site.
    /// (`std::string`'s SSO and libstdc++ COW paths can leave plaintext
    /// residue across reallocations that subsequent `memwipe` cannot
    /// reach; `epee::wipeable_string` is backed by `std::vector<char>`
    /// without those concerns and zeroes its buffer on destruction.)
    void generate_from_bip39(
        const epee::wipeable_string &mnemonic_words,
        const epee::wipeable_string &passphrase,
        cryptonote::network_type nettype);

    /// Testnet / fakechain path. 32 bytes of input entropy that are also the
    /// wallet's source of truth on restore. Throws on disallowed
    /// (nettype,format) pair.
    void generate_from_raw_seed(
        const uint8_t raw_seed[SHEKYL_RAW_SEED_BYTES],
        cryptonote::network_type nettype);

    /// Rederive every in-memory key from an already-populated
    /// `m_master_seed_64` + `m_seed_format` (wallet-open hot path). Throws on
    /// FFI failure.
    void rederive_from_master_seed(cryptonote::network_type nettype);

    /// SHKW1 wallet-open hot path (transitional 2k.a -> 2m-keys).
    ///
    /// Atomic populate from the 64-byte master seed extracted out of a
    /// `ShekylWallet` handle via `shekyl_wallet_extract_rederivation_inputs`:
    /// clears prior state (set_null), installs the master seed under
    /// mlock, then drives `shekyl_account_rederive` to rebuild
    /// `m_spend_secret_key`, `m_view_secret_key`, `m_ml_kem_decap_key`,
    /// and `m_account_address`. The caller is expected to scrub its
    /// copy of the master seed bytes immediately after return, and to
    /// call `forget_master_seed()` once the ML-KEM decap key has been
    /// built (see 2k.a design pin 12 -- Option β) so the
    /// `ShekylWallet` handle remains the single in-memory source of
    /// truth for the master seed.
    ///
    /// Does NOT set `m_creation_timestamp`; the SHKW1 envelope carries
    /// its own authoritative creation timestamp in the AAD, and the
    /// caller threads it through `set_createtime()`.
    ///
    /// Throws on disallowed (nettype, seed_format) pair or FFI failure.
    void load_from_shkw1(
        const uint8_t master_seed_64[SHEKYL_MASTER_SEED_BYTES],
        uint8_t seed_format,
        cryptonote::network_type nettype);

    /// Scrub the in-memory master seed while keeping every derived key
    /// (spend_sk, view_sk, ml_kem_dk, account_address) intact.
    ///
    /// Called by `wallet2::load_keys` immediately after
    /// `load_from_shkw1` has populated the account, so the master seed
    /// exists in memory for exactly the interval needed to rebuild
    /// `m_ml_kem_decap_key`. Once the decap key is built the seed is
    /// dormant for the remainder of the wallet's lifetime (audit of
    /// `src/wallet/wallet2.cpp` confirms no post-rederive read), and
    /// scrubbing it here halves the memory-disclosure surface (Option
    /// β, 2k.a design pin 12).
    ///
    /// Distinct from `forget_spend_key()` which also scrubs the spend
    /// scalar -- this function preserves every signing capability and
    /// only wipes the pre-derivation input.
    void forget_master_seed();

    // --- raw-seed generation entry point ------------------------------------
    //
    // Routes through `generate_from_raw_seed`. RAW32 is only permitted on
    // `Testnet` and `Fakechain`; for `Mainnet`/`Stagenet` callers must use
    // `generate_from_bip39` instead. There is no longer a default-nettype
    // overload: every caller — production and test — must spell its
    // network out explicitly. The previous default-FAKECHAIN overload
    // existed only as a transitional bridge during the Bug 4-adjacent
    // fix and was deleted at V3.0 along with its ~28 test callers, all
    // of which now pass `cryptonote::FAKECHAIN` explicitly.
    // See `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`.

    /// Raw-seed account generation. The `nettype` argument selects the
    /// derivation salt and is the consensus-level network for the
    /// resulting account. Must be `TESTNET` or `FAKECHAIN`; `MAINNET`
    /// and `STAGENET` throw at the FFI's `permitted_seed_format` check
    /// because RAW32 isn't a permitted seed format on those networks
    /// (use `generate_from_bip39` instead).
    ///
    /// Failure modes:
    /// - `(MAINNET, *)` and `(STAGENET, *)` — throws (programming error).
    /// - `(TESTNET, *)` and `(FAKECHAIN, *)` with `recover=true` — derives
    ///   from `recovery_key.data` as 32 raw bytes.
    /// - `(TESTNET, *)` and `(FAKECHAIN, *)` with `recover=false` —
    ///   generates a fresh seed via the OS CSPRNG.
    ///
    /// `two_random` is unused; it remains in the signature for legacy-API
    /// compatibility with the v0 Electrum-style flow that has been
    /// removed (.cursor/rules/36-secret-locality.mdc).
    crypto::secret_key generate(
        const crypto::secret_key& recovery_key,
        bool recover,
        bool two_random,
        network_type nettype);

    void create_from_device(const std::string &device_name);
    void create_from_device(hw::device &hwdev);
    void create_from_keys(const cryptonote::account_public_address& address, const crypto::secret_key& spendkey, const crypto::secret_key& viewkey);
    void create_from_viewkey(const cryptonote::account_public_address& address, const crypto::secret_key& viewkey);
    const account_keys& get_keys() const;
    std::string get_public_address_str(network_type nettype) const;
    std::string get_public_integrated_address_str(const crypto::hash8 &payment_id, network_type nettype) const;

    hw::device& get_device() const  {return m_keys.get_device();}
    void set_device( hw::device &hwdev) {m_keys.set_device(hwdev);}
    void deinit();

    uint64_t get_createtime() const { return m_creation_timestamp; }
    void set_createtime(uint64_t val) { m_creation_timestamp = val; }

    bool load(const std::string& file_path);
    bool store(const std::string& file_path);

    void forget_spend_key();
    void set_spend_key(const crypto::secret_key& spend_secret_key);

    void encrypt_keys(const crypto::chacha_key &key) { m_keys.encrypt(key); }
    void decrypt_keys(const crypto::chacha_key &key) { m_keys.decrypt(key); }
    void encrypt_viewkey(const crypto::chacha_key &key) { m_keys.encrypt_viewkey(key); }
    void decrypt_viewkey(const crypto::chacha_key &key) { m_keys.decrypt_viewkey(key); }

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int /*ver*/)
    {
      a & m_keys;
      a & m_creation_timestamp;
    }

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(m_keys)
      KV_SERIALIZE(m_creation_timestamp)
    END_KV_SERIALIZE_MAP()

  private:
    void set_null();
    account_keys m_keys;
    uint64_t m_creation_timestamp;
  };
}
