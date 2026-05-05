// Copyright (c) 2023, The Monero Project
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

#include "unit_tests_utils.h"
#include "gtest/gtest.h"

#include "file_io_utils.h"
#include "wallet/wallet2.h"
#include "common/util.h"

#include <type_traits>
#include <string>

using namespace boost::filesystem;
using namespace epee::file_io_utils;

// ===========================================================================
// CI tripwire: wallet2 must NOT have a `generate_from_bip39` member.
// ===========================================================================
//
// Bug 4 (audit 2026-05-05): wallet2 has no BIP-39 entry point by design.
// The Rust derivation path (shekyl-crypto-pq::generate_account_from_bip39)
// and the FFI (shekyl_account_generate_from_bip39) and the lower-level C++
// glue (account_base::generate_from_bip39) all exist and are tested. The
// wallet2-level wrapper is intentionally absent because:
//
//   - wallet2.cpp is scheduled for wholesale deletion at Phase 5 of the
//     Rust wallet rewrite; any wrapper added now would be deleted by that
//     phase as a removal-as-breaking-change rather than removal-as-no-op.
//   - The Rust derivation path is the actual functional guarantee
//     (shekyl-crypto-pq::tests::generate_from_bip39_mainnet_roundtrips_to_rederive).
//   - No mainnet wallets exist yet; the next beta ships before the Rust
//     rewrite lands, so any "transitional" wrapper would have a lifespan
//     shorter than its review burden.
//
// If the static_assert below starts failing, either:
//
//   (a) The Rust wallet rewrite Phase 5 has landed and wallet2.cpp is
//       being deleted — in which case this entire file is being removed
//       and this tripwire goes with it. Action: just delete the assert
//       along with the rest of wallet2.cpp test scaffolding.
//
//   (b) Someone added wallet2::generate_from_bip39 without first reading
//       docs/FOLLOWUPS.md §"V3.1+ Legacy C++ → Rust rewrite scope"
//       entry on this exact decision. Action: remove the wrapper, read
//       the FOLLOWUPS entry, and reopen the architectural question
//       there if you still think the wrapper should exist.
//
// See docs/audit_trail/2026-05-ffi-constant-drift-audit.md for the
// Bug 4 framing and the discovery pattern that surfaced it.
//
// SFINAE detector: `has_generate_from_bip39<T>` is `true_type` iff
// `T::generate_from_bip39(const std::string&, const std::string&,
// cryptonote::network_type)` is callable. The mnemonic + passphrase +
// nettype signature mirrors `account_base::generate_from_bip39`; if a
// future wrapper uses a different signature, the detector misses it
// and a fresh detector overload is the right response.

template <typename, typename = void>
struct has_generate_from_bip39_wallet2_member : std::false_type {};

template <typename T>
struct has_generate_from_bip39_wallet2_member<
    T,
    std::void_t<decltype(std::declval<T &>().generate_from_bip39(
        std::declval<const std::string &>(),
        std::declval<const std::string &>(),
        std::declval<cryptonote::network_type>()))>> : std::true_type {};

static_assert(
    !has_generate_from_bip39_wallet2_member<tools::wallet2>::value,
    "wallet2::generate_from_bip39 must not exist; BIP-39 wallet creation "
    "lives in the Rust wallet path post-migration. See "
    "docs/FOLLOWUPS.md §\"V3.1+ Legacy C++ → Rust rewrite scope\" entry "
    "on `wallet2 has no generate_from_bip39 entry point` before adding it.");

// Compile-time positive control for the SFINAE detector itself. Without
// this, a refactor that breaks the detector (e.g. typo in the SFINAE
// signature, missing #include) would silently make the static_assert
// above pass for the wrong reason. The synthetic type below has the
// member, so the detector must report `true`; any failure here is a
// detector bug, not a wallet2 bug.
namespace tripwire_self_test {
struct synthetic_has_member {
    void generate_from_bip39(
        const std::string &, const std::string &, cryptonote::network_type) {}
};
struct synthetic_lacks_member {};
static_assert(
    has_generate_from_bip39_wallet2_member<synthetic_has_member>::value,
    "SFINAE detector is broken: must report `true` for a type that "
    "actually has the member. Fix the detector before trusting the "
    "negative assertion above.");
static_assert(
    !has_generate_from_bip39_wallet2_member<synthetic_lacks_member>::value,
    "SFINAE detector is broken: must report `false` for a type that "
    "lacks the member. Fix the detector before trusting the negative "
    "assertion above.");
} // namespace tripwire_self_test

// Three Monero-era keys-file round-trip tests (`store_to_file2file`,
// `change_password_same_file`, `change_password_different_file`) and their
// `wallet_00fd416a` / `wallet_9svHk1` fixtures were removed in this commit.
// Rationale (per `.cursor/rules/15-deletion-and-debt.mdc`'s "default: delete"):
// the fixtures are pre-master-seed Monero v0/v1 keys files inherited from
// upstream; v3-from-genesis Shekyl reads SHKW1 envelopes only, so these
// fixtures cannot be loaded under any version of the current keystore. The
// tests had been gated behind `GTEST_SKIP()` for that reason and were
// providing zero coverage.
//
// **Residual coverage gap (acknowledged, not closed by this branch):** the
// deleted tests were the only coverage for two `wallet2::store_to`
// branches, even gated/skipped:
//
//   - `store_to_file2file` exercised `store_to(target, password, false)`
//     with `target != m_wallet_file` on a wallet that had been *loaded*
//     from disk (not just generated in-memory). This is the
//     `!same_file && force_rewrite_keys == false` save-as-from-loaded
//     branch, which the surviving `store_to_mem2file` test does not
//     reach — that test uses a wallet that was just `generate()`'d.
//   - `change_password_same_file` exercised `store_to(m_wallet_file,
//     new_password, true)` on a loaded wallet — the
//     `same_file && force_rewrite_keys == true` rewrite-keys-in-place
//     branch. The surviving `change_password_mem2file` is also from a
//     freshly-generated wallet, not a loaded one.
//
// Both branches still execute on the production load→re-store path; they
// are simply uncovered by direct unit test. Filed as a V3.0 entry under
// FOLLOWUPS.md ("wallet_storage: cover loaded-wallet save-as branches"),
// targeted to land before the wallet2 → Rust cutover deletes wallet2.cpp
// outright (V3.2). At that point the residual gap retires with the
// surrounding code.

TEST(wallet_storage, store_to_mem2file)
{
    const path target_wallet_file = unit_test::data_dir / "wallet_mem2file";

    if (is_file_exist(target_wallet_file.string()))
        remove(target_wallet_file);
    if (is_file_exist(target_wallet_file.string() + ".keys"))
        remove(target_wallet_file.string() + ".keys");
    ASSERT_FALSE(is_file_exist(target_wallet_file.string()));
    ASSERT_FALSE(is_file_exist(target_wallet_file.string() + ".keys"));

    epee::wipeable_string password("beepbeep2");

    // FAKECHAIN nettype must match the network the legacy `account_base::generate()`
    // wrapper hardcodes for raw-seed derivation. A default-constructed wallet2
    // inherits MAINNET, which doesn't permit RAW32, so the rederive on `load`
    // would fail with "(network, seed_format) pair disallowed". The hardcoded
    // FAKECHAIN inside `account_base::generate()` is itself a footgun on the
    // raw-seed path used by `wallet2::generate("", password)` test code and by
    // `wallet_rpc_server::stop_background_sync`; it is fixed in sibling branch
    // `fix/legacy-account-generate-network-guard` (the "Bug 4-adjacent"
    // finding in `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`).
    // Bug 4 itself — the absent `wallet2::generate_from_bip39` wrapper — is
    // resolved by an architectural decision NOT to add the wrapper pre-
    // migration, defended by a static_assert tripwire at the top of this
    // file; see the corresponding FOLLOWUPS.md entry.
    {
        tools::wallet2 w(cryptonote::FAKECHAIN, 1, false);
        w.generate("", password);
        w.store_to(target_wallet_file.string(), password);

        EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
        EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));
    }

    EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));

    {
        tools::wallet2 w(cryptonote::FAKECHAIN, 1, false);
        w.load(target_wallet_file.string(), password);

        EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
        EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));
    }

    EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));
}

TEST(wallet_storage, change_password_in_memory)
{
    const epee::wipeable_string password1("monero");
    const epee::wipeable_string password2("means money");
    const epee::wipeable_string password_wrong("is traceable");

    tools::wallet2 w;
    w.generate("", password1);
    const std::string primary_address_1 = w.get_address_as_str();
    w.change_password("", password1, password2);
    const std::string primary_address_2 = w.get_address_as_str();
    EXPECT_EQ(primary_address_1, primary_address_2);

    EXPECT_THROW(w.change_password("", password_wrong, password1), tools::error::invalid_password);
}

TEST(wallet_storage, change_password_mem2file)
{
    const path target_wallet_file = unit_test::data_dir / "wallet_change_password_mem2file";

    if (is_file_exist(target_wallet_file.string()))
        remove(target_wallet_file);
    if (is_file_exist(target_wallet_file.string() + ".keys"))
        remove(target_wallet_file.string() + ".keys");
    ASSERT_FALSE(is_file_exist(target_wallet_file.string()));
    ASSERT_FALSE(is_file_exist(target_wallet_file.string() + ".keys"));

    const epee::wipeable_string password1("https://safecurves.cr.yp.to/rigid.html");
    const epee::wipeable_string password2(
        "https://csrc.nist.gov/csrc/media/projects/crypto-standards-development-process/documents/dualec_in_x982_and_sp800-90.pdf");
    
    std::string primary_address_1, primary_address_2;
    // FAKECHAIN nettype must match the network the legacy
    // `account_base::generate()` wrapper hardcodes for raw-seed derivation
    // (see the comment on `wallet_storage.store_to_mem2file` above).
    //
    // `unattended = false` is load-bearing here: with `unattended = true`,
    // `wallet2::change_password()` skips the `decrypt_keys(original_password)`
    // call (`src/wallet/wallet2.cpp` ~line 5046) and the test would no longer
    // verify that the old password is actually checked before the rotation.
    {
        tools::wallet2 w(cryptonote::FAKECHAIN, 1, false);
        w.generate("", password1);
        primary_address_1 = w.get_address_as_str();
        w.change_password(target_wallet_file.string(), password1, password2);
    }

    EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));

    {
        tools::wallet2 w(cryptonote::FAKECHAIN, 1, false);
        w.load(target_wallet_file.string(), password2);
        primary_address_2 = w.get_address_as_str();
    }

    EXPECT_EQ(primary_address_1, primary_address_2);
}
