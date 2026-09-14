// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// Cross-language pinned-vector test for the credit-wire attestation verify (CW-3,
// ARCHIVAL_CREDIT_WIRE.md §3-§4; SF-D8 v2 countersignature, ARCHIVAL_SHARD_FETCH.md).
// The verify LOGIC is exhaustively tested in Rust (shekyl-ffi
// archival_ffi/attestation_verify_tests.rs); what only C++ can prove is that the C-side
// structs in shekyl/shekyl_ffi.h (shekyl_archival_attestation_verify_ctx,
// shekyl_archival_pid_pubkey) marshal byte-identically to the Rust #[repr(C)]
// definitions across the real ABI boundary -- the "byte-identical-or-split" surface.
//
// The vector is the SHARED deterministic fixture
// rust/shekyl-archival-retention/tests/fixtures/attestation_pass_countersignature_v2_pinned.json,
// consumed unchanged by the retention crate's attestation_wire_kat.rs and shekyl-ffi's
// `pinned_v2_fixture_verifies_through_ffi`. Rule-50 oracle tier: the signature bytes are
// SELF-PINNED (tier 3) -- a drift tripwire, not a KAT; only the hand-computed header and
// transcript pins in the Rust file carry the KAT name. Reading the same file on all three sides means
// the three cannot drift apart silently; it is regenerated only by the armed regenerator in
// attestation_wire_kat.rs under a rule-50 decision-log citation (there is no C++-side paste).
// A passing verdict proves the layout agrees end to end, and each negative control moves
// exactly one field to prove that field is read where the C header says it is.

#include "gtest/gtest.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include "cryptonote_config.h"
#include "shekyl/shekyl_ffi.h"

namespace
{
std::vector<uint8_t> from_hex(const std::string& h)
{
  if (h.size() % 2 != 0)
    throw std::logic_error("attestation fixture hex has odd length");
  std::vector<uint8_t> out;
  out.reserve(h.size() / 2);
  for (size_t i = 0; i + 1 < h.size(); i += 2)
    out.push_back(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
  return out;
}

using hash32 = std::array<uint8_t, 32>;

struct V2Pinned
{
  std::vector<uint8_t> headers;
  std::vector<uint8_t> witness;
  std::vector<uint8_t> pubkey;
  std::vector<uint8_t> p_id;
  std::vector<uint8_t> root;
  uint64_t predecessor_height = 0;
  uint64_t anchor_height = 0;
  uint64_t anchor_window_first_height = 0;
  /// The connecting chain's hash at `anchor_window_first_height + i` -- the table C++ fills.
  std::vector<hash32> anchor_window;
};

const V2Pinned& pinned()
{
  static const V2Pinned loaded = [] {
    std::ifstream ifs(ATTESTATION_V2_PINNED_FIXTURE_PATH);
    if (!ifs.good())
      throw std::runtime_error(std::string("missing SF-D8 v2 attestation fixture at ")
        + ATTESTATION_V2_PINNED_FIXTURE_PATH);
    rapidjson::IStreamWrapper wrapper(ifs);
    rapidjson::Document doc;
    doc.ParseStream(wrapper);
    if (doc.HasParseError() || !doc.IsObject())
      throw std::runtime_error("invalid SF-D8 v2 attestation fixture");
    auto hex_field = [&doc](const char* key) {
      if (!doc.HasMember(key) || !doc[key].IsString())
        throw std::runtime_error(std::string("fixture missing string field ") + key);
      return from_hex(doc[key].GetString());
    };
    V2Pinned k{};
    k.headers = hex_field("header_hex");
    k.witness = hex_field("witness_hex");
    k.pubkey = hex_field("hybrid_public_key_hex");
    k.p_id = hex_field("p_id_hex");
    k.root = hex_field("attestation_root_hex");
    auto u64_field = [&doc](const char* key) {
      if (!doc.HasMember(key) || !doc[key].IsUint64())
        throw std::runtime_error(std::string("fixture missing u64 field ") + key);
      return doc[key].GetUint64();
    };
    k.predecessor_height = u64_field("predecessor_height");
    k.anchor_height = u64_field("anchor_height");
    k.anchor_window_first_height = u64_field("anchor_window_first_height");
    if (!doc.HasMember("anchor_window_hashes_hex") || !doc["anchor_window_hashes_hex"].IsArray())
      throw std::runtime_error("fixture missing anchor_window_hashes_hex");
    for (const auto& v : doc["anchor_window_hashes_hex"].GetArray())
    {
      if (!v.IsString())
        throw std::runtime_error("anchor_window_hashes_hex entry is not a string");
      const std::vector<uint8_t> bytes = from_hex(v.GetString());
      if (bytes.size() != 32)
        throw std::runtime_error("anchor_window_hashes_hex entry is not 32 bytes");
      hash32 h{};
      std::memcpy(h.data(), bytes.data(), 32);
      k.anchor_window.push_back(h);
    }
    return k;
  }();
  return loaded;
}

// Copy exactly 32 bytes out of a fixture field, or fail loudly.
//
// from_hex() validates only evenness, so a mis-edited vector would otherwise memcpy past
// the end of a short buffer -- silent UB in a test whose entire job is pinning bytes.
// Applied to EVERY 32-byte source here: they all share the property, and guarding one would
// leave the class open while looking closed. Throwing is caught by gtest and reported as a
// test failure, which is what a mis-edited vector should produce.
void copy32(uint8_t (&dst)[32], const std::vector<uint8_t>& src, const char* what)
{
  if (src.size() != 32)
    throw std::logic_error(std::string("attestation test vector '") + what
      + "' is " + std::to_string(src.size()) + " bytes, expected 32");
  std::memcpy(dst, src.data(), 32);
}

// Step 0 as blockchain.cpp performs it: ask Rust which heights the window covers. Returns the
// verdict; on OK `first`/`len` are the table C++ must fill. C++ holds no copy of depth or L.
uint8_t anchor_window(uint64_t predecessor_height, uint64_t& first, size_t& len)
{
  first = 0;
  len = 0;
  return shekyl_archival_pass_anchor_window(predecessor_height, &first, &len);
}

// Verify the pinned vector with one (pair_pid, pair_pubkey) pair, a chosen root, a chosen
// predecessor height and a chosen anchor table. Every buffer lives for the synchronous FFI call.
uint8_t run_verify(const std::vector<uint8_t>& root, uint64_t predecessor_height,
  const std::vector<hash32>& table, const std::vector<uint8_t>& pair_pid,
  const std::vector<uint8_t>& pair_pubkey)
{
  const V2Pinned& k = pinned();

  shekyl_archival_pid_pubkey pair{};
  copy32(pair.p_id, pair_pid, "pair_pid");
  pair.pubkey_ptr = pair_pubkey.empty() ? nullptr : pair_pubkey.data();
  pair.pubkey_len = pair_pubkey.size();

  static_assert(sizeof(hash32) == 32, "anchor table entries are 32 bytes");
  shekyl_archival_attestation_verify_ctx ctx{};
  copy32(ctx.attestation_root, root, "attestation_root");
  ctx.predecessor_height = predecessor_height;
  ctx.anchor_hashes_ptr = table.empty() ? nullptr
    : reinterpret_cast<const uint8_t (*)[32]>(table.data());
  ctx.anchor_hashes_len = table.size();
  ctx.headers_readable = 1;
  ctx.headers_ptr = k.headers.data();
  ctx.headers_len = k.headers.size();
  ctx.pairs_ptr = &pair;
  ctx.pairs_len = 1;
  return shekyl_archival_verify_attestation(k.witness.data(), k.witness.size(), &ctx);
}
}  // namespace

// Step 0 across the ABI: the fixture's table is exactly the one Rust asks C++ to fill for the
// fixture's predecessor height, and the genesis threshold is pinned at both sides (723 has no
// window, 724 has one starting at height 0 -- the same pair the retention crate pins).
TEST(archival_attestation_verify, step0_window_matches_fixture_and_pins_threshold)
{
  const V2Pinned& k = pinned();
  uint64_t first = 0;
  size_t len = 0;
  EXPECT_EQ(anchor_window(k.predecessor_height, first, len), SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
  EXPECT_EQ(first, k.anchor_window_first_height);
  EXPECT_EQ(len, k.anchor_window.size());
  // The fixture's anchor is the window's top: h - depth.
  EXPECT_EQ(k.anchor_height, first + len - 1);

  EXPECT_EQ(anchor_window(723, first, len), SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
  EXPECT_EQ(first, 0u);
  EXPECT_EQ(len, 0u);
  EXPECT_EQ(anchor_window(724, first, len), SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
  EXPECT_EQ(first, 0u);
  EXPECT_EQ(len, k.anchor_window.size());

  EXPECT_EQ(shekyl_archival_pass_anchor_window(724, nullptr, &len),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR);
}

// The layout agrees end to end: the shared fixture, marshaled through the C structs, verifies OK.
TEST(archival_attestation_verify, pinned_valid_vector_verifies_ok)
{
  const V2Pinned& k = pinned();
  EXPECT_EQ(run_verify(k.root, k.predecessor_height, k.anchor_window, k.p_id, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
}

// attestation_root field offset: flip one byte -> ROOT_MISMATCH.
TEST(archival_attestation_verify, flipped_root_is_root_mismatch)
{
  const V2Pinned& k = pinned();
  std::vector<uint8_t> root = k.root;
  root[0] ^= 0x01;
  EXPECT_EQ(run_verify(root, k.predecessor_height, k.anchor_window, k.p_id, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH);
}

// anchor_hashes_ptr offset AND the SF-D8 binding: the same signature against a connecting chain
// whose hash at the ANCHOR height differs (a fork above the fork point, or a fabricated header
// hash) is a countersignature failure -- the record carries no hash, so only the signature can
// disagree. Perturbing a different height's entry changes nothing: one indexed lookup.
TEST(archival_attestation_verify, forked_anchor_hash_is_countersig_invalid)
{
  const V2Pinned& k = pinned();
  std::vector<hash32> forked = k.anchor_window;
  forked.at(k.anchor_height - k.anchor_window_first_height)[0] ^= 0x01;
  EXPECT_EQ(run_verify(k.root, k.predecessor_height, forked, k.p_id, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_COUNTERSIG_INVALID);

  std::vector<hash32> other = k.anchor_window;
  other.at(0)[0] ^= 0x01;
  EXPECT_EQ(run_verify(k.root, k.predecessor_height, other, k.p_id, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
}

// predecessor_height field offset AND the window: the same record presented under a connecting
// height whose window no longer contains the anchor is ANCHOR_OUT_OF_WINDOW (stale anchor, L + 1
// blocks later; and a future anchor, one block earlier); under a forgotten (zero) height it is
// BELOW_ANCHOR_THRESHOLD -- both fail closed, the reason v2 has no sentinel. This is also the
// C-side proof that the uint64_t lands where Rust reads it: the field is LIVE, not merely
// ignored. The tables are the ones step 0 sizes for each height (content is irrelevant to these
// verdicts, which precede the hash lookup).
TEST(archival_attestation_verify, wrong_predecessor_height_moves_the_window)
{
  const V2Pinned& k = pinned();
  const size_t lag = k.anchor_window.size() - 1; // L, learned from step 0 -- C++ holds no copy
  EXPECT_EQ(run_verify(k.root, k.predecessor_height + lag + 1, k.anchor_window, k.p_id, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ANCHOR_OUT_OF_WINDOW);
  EXPECT_EQ(run_verify(k.root, k.predecessor_height - 1, k.anchor_window, k.p_id, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ANCHOR_OUT_OF_WINDOW);
  EXPECT_EQ(run_verify(k.root, 0, std::vector<hash32>{}, k.p_id, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BELOW_ANCHOR_THRESHOLD);
}

// anchor_hashes_len offset: a table of the wrong shape for the height is MALFORMED_ANCHOR_TABLE
// -- the marshaling-drift verdict, distinct from every forgery verdict, and checked on every
// block (here with the pinned record present; the record-less form is pinned in Rust).
TEST(archival_attestation_verify, wrong_shape_anchor_table_is_malformed_anchor_table)
{
  const V2Pinned& k = pinned();
  std::vector<hash32> shorter(k.anchor_window.begin(), k.anchor_window.end() - 1);
  EXPECT_EQ(run_verify(k.root, k.predecessor_height, shorter, k.p_id, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_ANCHOR_TABLE);
  std::vector<hash32> longer = k.anchor_window;
  longer.push_back(hash32{});
  EXPECT_EQ(run_verify(k.root, k.predecessor_height, longer, k.p_id, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_ANCHOR_TABLE);
  EXPECT_EQ(run_verify(k.root, k.predecessor_height, std::vector<hash32>{}, k.p_id, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_ANCHOR_TABLE);
  // Below the threshold the only right shape is empty.
  EXPECT_EQ(run_verify(k.root, 0, k.anchor_window, k.p_id, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_ANCHOR_TABLE);
}

// pubkey_len == 0 is the bond-absent marker (a missing LMDB bond), not a bad signature.
TEST(archival_attestation_verify, absent_bond_is_bond_absent)
{
  const V2Pinned& k = pinned();
  EXPECT_EQ(run_verify(k.root, k.predecessor_height, k.anchor_window, k.p_id, std::vector<uint8_t>{}),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BOND_ABSENT);
}

// pair p_id offset + coverage: a pair that names no pass record (and a pass record with no
// pair) is a set mismatch, the loud verdict that makes the pairs-not-positional design safe.
TEST(archival_attestation_verify, wrong_pair_pid_is_set_mismatch)
{
  const V2Pinned& k = pinned();
  const std::vector<uint8_t> wrong_pid(32, 0xAB);
  EXPECT_EQ(run_verify(k.root, k.predecessor_height, k.anchor_window, wrong_pid, k.pubkey),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH);
}

// headers_readable flag offset: 0 means C++ could not parse the coinbase tx_extra -> the verify
// refuses rather than misreading a malformed extra as the committed empty attestation set.
TEST(archival_attestation_verify, unreadable_headers_is_headers_unreadable)
{
  uint8_t empty_root[32];
  ASSERT_TRUE(shekyl_attestation_root_empty(empty_root));

  shekyl_archival_attestation_verify_ctx ctx{};
  std::memcpy(ctx.attestation_root, empty_root, 32);
  ctx.predecessor_height = 7; // below the anchor threshold: the empty table is the right shape
  ctx.anchor_hashes_ptr = nullptr;
  ctx.anchor_hashes_len = 0;
  ctx.headers_readable = 0;
  EXPECT_EQ(shekyl_archival_verify_attestation(nullptr, 0, &ctx),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_HEADERS_UNREADABLE);
}

// The empty (pre-cutover / genesis) shape across the FFI: the C++ empty root
// (shekyl_attestation_root_empty) agrees with the Rust verify's recompute over zero records
// -> OK; a non-empty root -> reject. predecessor_height is 0 here deliberately: genesis
// passes 0 (no predecessor), which is below the anchor threshold, so the empty table is the
// required shape and with zero records nothing else is read -- there is no unpopulated
// sentinel to trip (the v1 all-zero-hash sentinel is gone with SF-D8).
TEST(archival_attestation_verify, empty_shape_across_ffi)
{
  uint8_t empty_root[32];
  ASSERT_TRUE(shekyl_attestation_root_empty(empty_root));

  shekyl_archival_attestation_verify_ctx ctx{};
  std::memcpy(ctx.attestation_root, empty_root, 32);
  ctx.predecessor_height = 0;
  ctx.anchor_hashes_ptr = nullptr;
  ctx.anchor_hashes_len = 0;
  ctx.headers_readable = 1;     // parsed extra, no attestation tag -> the committed empty set
  ctx.headers_ptr = nullptr;
  ctx.headers_len = 0;
  ctx.pairs_ptr = nullptr;
  ctx.pairs_len = 0;
  EXPECT_EQ(shekyl_archival_verify_attestation(nullptr, 0, &ctx),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);

  ctx.attestation_root[0] ^= 0x01;
  EXPECT_EQ(shekyl_archival_verify_attestation(nullptr, 0, &ctx),
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH);
}

// Step 1 marshaling: C++ hands the same header blob to shekyl_archival_attestation_pass_p_ids and
// gets back exactly the fixture's pass p_id the ctx above pairs against.
TEST(archival_attestation_verify, step1_names_the_pinned_pass_pid)
{
  const V2Pinned& k = pinned();
  uint8_t out[config::ARCHIVAL_MAX_ATTESTATION_RECORDS][32];
  size_t n = 0;
  const uint8_t code = shekyl_archival_attestation_pass_p_ids(
    k.headers.data(), k.headers.size(), out, config::ARCHIVAL_MAX_ATTESTATION_RECORDS, &n);
  EXPECT_EQ(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
  ASSERT_EQ(n, 1u);
  ASSERT_EQ(k.p_id.size(), 32u);
  EXPECT_EQ(std::memcmp(out[0], k.p_id.data(), 32), 0);
}
