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

// Phase-1 Electrum-words-removal cross-boundary zeroization residency
// invariant tests per `docs/design/ELECTRUM_WORDS_REMOVAL.md` §7.4 +
// Phase 1 work-item 9 (`docs/design/ELECTRUM_WORDS_REMOVAL_PLAN.md`).
//
// Test discipline boundary
// ------------------------
//
// The substrate §7.4 is explicit: "The test must demonstrate that no
// plaintext mnemonic word, no PBKDF2 intermediate, and no decoded
// entropy byte survives in either side's allocator arena after the
// calls return." An exhaustive proof of this property is not
// achievable in a unit test — the OS-level allocator's free-list
// residency, the kernel page cache, and the swap path are all out of
// the test harness's reach. What this test *can* do is catch the
// failure mode where the discipline collapses: where the FFI's
// documented zeroization contract on the validation-failure path is
// silently lost, or where the `m_bip39_entropy` field's mlocked
// allocation is replaced with a non-locking allocator, or where the
// bounded-region scan pattern surfaces an obvious leak.
//
// The test is intentionally narrow:
//
//   1. `shekyl_bip39_mnemonic_to_entropy` zero-fills the output buffer
//      when validation fails — the FFI's documented post-condition per
//      `rust/shekyl-ffi/src/account_ffi.rs` §"Recover entropy".
//      Verifies the contract directly by pre-filling the output with a
//      recognizable marker, calling the FFI with an invalid phrase,
//      and asserting the marker is gone.
//
//   2. `shekyl_bip39_mnemonic_from_entropy` zero-fills the output
//      buffer when given a too-small capacity — the symmetric
//      post-condition for the inverse direction.
//
//   3. Bounded-region heap-scan: a fresh, isolated 4 MiB buffer
//      allocated *after* the BIP-39 FFI calls return is scanned for
//      the canonical zero-entropy phrase's distinctive byte sequence
//      ("abandon "). The buffer is not zero-initialized (we use
//      `new uint8_t[N]` rather than `std::vector`'s value-init) so it
//      contains whatever the heap allocator handed us — typically
//      previously-freed memory. A match would indicate the BIP-39
//      orchestration freed a phrase buffer without wiping. The scan
//      is bounded (single buffer, single search) and probabilistic;
//      its purpose is to catch obvious regressions, not to prove the
//      negative. Per `21-reversion-clause-discipline.mdc` this test
//      is reopen-on-failure rather than removed: failures reflect a
//      real residency event worth investigating, even if absence of
//      a failure does not prove absence of residency.

#include "gtest/gtest.h"

#include "shekyl/shekyl_ffi.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

namespace
{
// The BIP-39 official-vector zero-entropy phrase begins with eight
// consecutive "abandon " tokens. The residency scan looks for the
// literal byte sequence "abandon abandon abandon abandon abandon ",
// which is highly unlikely to occur by chance in an uninitialized
// heap region (probability bound: a random 40-byte region matching
// is ~1/256^40) but trivial to spot if the orchestration leaks the
// phrase buffer.
constexpr const char kPhraseProbe[] =
    "abandon abandon abandon abandon abandon ";
constexpr size_t kPhraseProbeLen = sizeof(kPhraseProbe) - 1;

constexpr const char kZeroEntropyPhrase[] =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon art";
} // namespace

TEST(wallet_bip39_residency, ffi_to_entropy_zerofills_on_failure)
{
    // Pre-fill output buffer with a recognizable marker so we can
    // detect the FFI's documented zero-fill on validation failure.
    std::array<uint8_t, 32> out;
    out.fill(0xA5);

    const std::string invalid_phrase = "not a valid bip39 phrase";
    const bool ok = shekyl_bip39_mnemonic_to_entropy(
        reinterpret_cast<const uint8_t *>(invalid_phrase.data()),
        invalid_phrase.size(),
        out.data());

    ASSERT_FALSE(ok) << "FFI accepted an obviously-invalid phrase";
    for (size_t i = 0; i < out.size(); ++i)
    {
        EXPECT_EQ(out[i], 0u)
            << "FFI did not zero-fill output[" << i
            << "] on validation failure (residency contract violation)";
    }
}

TEST(wallet_bip39_residency, ffi_from_entropy_zerofills_on_capacity_overflow)
{
    std::array<uint8_t, 32> entropy{};
    // Capacity intentionally smaller than any valid 24-word phrase.
    std::array<uint8_t, 16> out;
    out.fill(0xA5);
    size_t written = 0xDEADBEEF;

    const bool ok = shekyl_bip39_mnemonic_from_entropy(
        entropy.data(), out.data(), out.size(), &written);

    ASSERT_FALSE(ok)
        << "FFI accepted an undersized output capacity";
    for (size_t i = 0; i < out.size(); ++i)
    {
        EXPECT_EQ(out[i], 0u)
            << "FFI did not zero-fill output[" << i
            << "] on capacity overflow (residency contract violation)";
    }
}

TEST(wallet_bip39_residency, bounded_heap_scan_after_ffi_calls)
{
    // First, drive both BIP-39 FFI directions with the zero-entropy
    // vector. This exercises the orchestration's transient buffers
    // (phrase byte slice, Rust-side `Zeroizing<[u8; 32]>` entropy,
    // PBKDF2 intermediates) and exits them. Any heap allocations made
    // for those transients are now in the allocator's free list and
    // available for re-use by the buffer we allocate next.
    {
        std::array<uint8_t, 32> recovered{};
        const bool ok = shekyl_bip39_mnemonic_to_entropy(
            reinterpret_cast<const uint8_t *>(kZeroEntropyPhrase),
            std::strlen(kZeroEntropyPhrase),
            recovered.data());
        ASSERT_TRUE(ok);

        std::array<uint8_t, 256> derived{};
        size_t written = 0;
        const bool ok2 = shekyl_bip39_mnemonic_from_entropy(
            recovered.data(), derived.data(), derived.size(), &written);
        ASSERT_TRUE(ok2);
        EXPECT_GT(written, 0u);
    }

    // Allocate a 4 MiB buffer without value-initialization so it
    // exposes whatever residual state the heap allocator hands back.
    constexpr size_t kScanBytes = 4u * 1024u * 1024u;
    std::unique_ptr<uint8_t[]> scan(new uint8_t[kScanBytes]);

    // Search for the phrase-probe byte sequence.
    bool found = false;
    if (kScanBytes >= kPhraseProbeLen)
    {
        const uint8_t *needle =
            reinterpret_cast<const uint8_t *>(kPhraseProbe);
        const uint8_t *haystack_end =
            scan.get() + (kScanBytes - kPhraseProbeLen);
        for (const uint8_t *p = scan.get(); p <= haystack_end; ++p)
        {
            if (std::memcmp(p, needle, kPhraseProbeLen) == 0)
            {
                found = true;
                break;
            }
        }
    }

    // Failure of this assertion indicates a probabilistic but
    // material residency signal. Per the file-header discipline note,
    // the test is reopen-on-failure: investigate before disabling.
    EXPECT_FALSE(found)
        << "BIP-39 mnemonic-phrase prefix found in a freshly-allocated "
        << "heap region after FFI calls returned — likely residency leak "
        << "from a non-zeroized transit buffer.";
}
