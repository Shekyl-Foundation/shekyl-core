// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

/// @file
/// @brief PWD-B7: the header's verdict constants, pinned to the Rust rule.
///
/// The header is hand-written, so nothing mechanically checks
/// `SHEKYL_DROP_VERDICT_*` against `shekyl-peer-policy`'s discriminants. These
/// tests pin them **without restating a number**: they search the whole byte
/// domain for the value that severs and assert it is the constant C++ writes
/// for an attributable form failure. A drift in either direction — the header
/// renumbered, or the Rust discriminants reordered — makes the severing byte
/// and the constant disagree, and that is the failure.
///
/// The other half of the unit lives in `tx_verification_context`: these tests
/// also assert that a value-initialised context does not sever, which is what
/// makes an unclassified rejection path safe by construction.

#include "gtest/gtest.h"

#include <cstdint>
#include <vector>

#include "cryptonote_basic/verification_context.h"
#include "shekyl/shekyl_ffi.h"

namespace
{
  /// Every byte the ABI can carry, which is the domain the C++ side can
  /// actually produce — including bytes no constant names.
  std::vector<uint8_t> all_bytes()
  {
    std::vector<uint8_t> bytes;
    bytes.reserve(256);
    for (int b = 0; b <= 0xff; ++b)
      bytes.push_back(static_cast<uint8_t>(b));
    return bytes;
  }
}

/// The rule, and the pin: exactly one byte severs, and it is the one C++
/// assigns for "the sender chose to send these bytes".
TEST(peer_policy_drop_verdict, exactly_one_byte_severs_and_it_is_attributable_form)
{
  std::vector<uint8_t> severing;
  for (const uint8_t byte : all_bytes())
    if (shekyl_drop_verdict_severs(byte))
      severing.push_back(byte);

  ASSERT_EQ(1u, severing.size());
  EXPECT_EQ(SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM, severing.front());
}

/// The three no-drop constants are distinct from the severing one and from
/// each other — a header that collapsed two of them would still pass the test
/// above.
TEST(peer_policy_drop_verdict, the_no_drop_constants_are_distinct_and_none_severs)
{
  const uint8_t no_drop[] = {
    SHEKYL_DROP_VERDICT_UNCLASSIFIED,
    SHEKYL_DROP_VERDICT_POLICY_OR_STATE,
    SHEKYL_DROP_VERDICT_INTERNAL_FAILURE,
  };
  for (const uint8_t verdict : no_drop)
  {
    EXPECT_FALSE(shekyl_drop_verdict_severs(verdict));
    EXPECT_NE(SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM, verdict);
  }
  EXPECT_NE(no_drop[0], no_drop[1]);
  EXPECT_NE(no_drop[1], no_drop[2]);
  EXPECT_NE(no_drop[0], no_drop[2]);
}

/// The loud arm is exactly one byte, it is the constant named for it, and it
/// does not sever — the log is a second question, not a disposition.
TEST(peer_policy_drop_verdict, exactly_one_byte_is_an_internal_failure_and_it_never_severs)
{
  std::vector<uint8_t> loud;
  for (const uint8_t byte : all_bytes())
    if (shekyl_drop_verdict_is_internal_failure(byte))
      loud.push_back(byte);

  ASSERT_EQ(1u, loud.size());
  EXPECT_EQ(SHEKYL_DROP_VERDICT_INTERNAL_FAILURE, loud.front());
  EXPECT_FALSE(shekyl_drop_verdict_severs(loud.front()));
}

/// A value-initialised verification context does not sever. This is the
/// property that makes a rejection path added later safe: it classifies
/// nothing, so it cannot drop a peer.
TEST(peer_policy_drop_verdict, a_value_initialised_context_does_not_sever)
{
  cryptonote::tx_verification_context tvc{};
  EXPECT_EQ(SHEKYL_DROP_VERDICT_UNCLASSIFIED, tvc.m_drop_verdict);
  EXPECT_FALSE(shekyl_drop_verdict_severs(tvc.m_drop_verdict));
}

/// The same, without the braces — the in-class initialiser must carry it, so
/// that a declaration someone forgets to value-initialise still cannot sever.
TEST(peer_policy_drop_verdict, a_default_constructed_context_does_not_sever_either)
{
  cryptonote::tx_verification_context tvc;
  EXPECT_EQ(SHEKYL_DROP_VERDICT_UNCLASSIFIED, tvc.m_drop_verdict);
  EXPECT_FALSE(shekyl_drop_verdict_severs(tvc.m_drop_verdict));
}

/// Folding never manufactures a drop. Over all 65536 ordered pairs: if the
/// fold severs, one of its inputs already did. Nothing a C++ caller can write
/// -- an unrecognised byte, uninitialised memory, a value from a future
/// revision -- produces a drop that neither input asked for, which is what
/// lets a classification site be coarse without over-severing.
TEST(peer_policy_drop_verdict, folding_can_only_sever_if_an_input_severs)
{
  for (const uint8_t current : all_bytes())
  {
    for (const uint8_t incoming : all_bytes())
    {
      if (!shekyl_drop_verdict_severs(shekyl_drop_verdict_combine(current, incoming)))
        continue;

      EXPECT_TRUE(shekyl_drop_verdict_severs(current) || shekyl_drop_verdict_severs(incoming))
        << "combine(" << unsigned(current) << ", " << unsigned(incoming)
        << ") severs though neither input does";
    }
  }
}

/// The concrete ordering `Blockchain::check_tx_inputs` produces: a precise
/// "spent in our chain" recorded deep in the call, then its caller's coarse
/// "wrong inputs". The precise reading must win, or an honest peer whose
/// transaction merely conflicts with our view is severed.
TEST(peer_policy_drop_verdict, a_state_verdict_survives_a_later_form_verdict)
{
  const uint8_t after_check_tx_inputs = shekyl_drop_verdict_combine(
      SHEKYL_DROP_VERDICT_UNCLASSIFIED, SHEKYL_DROP_VERDICT_POLICY_OR_STATE);
  const uint8_t after_add_tx = shekyl_drop_verdict_combine(
      after_check_tx_inputs, SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM);

  EXPECT_EQ(SHEKYL_DROP_VERDICT_POLICY_OR_STATE, after_add_tx);
  EXPECT_FALSE(shekyl_drop_verdict_severs(after_add_tx));
}

/// An internal failure likewise cannot be promoted, which is the case that
/// motivated the whole unit: our storage throwing must not sever the sender.
TEST(peer_policy_drop_verdict, an_internal_failure_survives_a_later_form_verdict)
{
  const uint8_t folded = shekyl_drop_verdict_combine(
      SHEKYL_DROP_VERDICT_INTERNAL_FAILURE, SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM);

  EXPECT_EQ(SHEKYL_DROP_VERDICT_INTERNAL_FAILURE, folded);
  EXPECT_FALSE(shekyl_drop_verdict_severs(folded));
  EXPECT_TRUE(shekyl_drop_verdict_is_internal_failure(folded));
}

/// The 5-arg wrapper's leftover arm starts unclassified (the macro this
/// replaced wrote nothing), then classifies INTERNAL_FAILURE, then add_tx
/// folds ATTRIBUTABLE_FORM. Absence must not win (PWD-B7 / Bugbot on #674).
TEST(peer_policy_drop_verdict, the_wrapper_internal_error_survives_add_tx_form_fold)
{
  const uint8_t after_wrapper = shekyl_drop_verdict_combine(
      SHEKYL_DROP_VERDICT_UNCLASSIFIED, SHEKYL_DROP_VERDICT_INTERNAL_FAILURE);
  const uint8_t after_add_tx = shekyl_drop_verdict_combine(
      after_wrapper, SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM);

  EXPECT_EQ(SHEKYL_DROP_VERDICT_INTERNAL_FAILURE, after_add_tx);
  EXPECT_FALSE(shekyl_drop_verdict_severs(after_add_tx));
}

/// And a form verdict still reaches the gate when nothing contradicts it —
/// the positive limb, without which every test above would pass on a rule
/// that never severs anything.
TEST(peer_policy_drop_verdict, a_form_verdict_alone_still_severs)
{
  const uint8_t folded = shekyl_drop_verdict_combine(
      SHEKYL_DROP_VERDICT_UNCLASSIFIED, SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM);

  EXPECT_EQ(SHEKYL_DROP_VERDICT_ATTRIBUTABLE_FORM, folded);
  EXPECT_TRUE(shekyl_drop_verdict_severs(folded));
}
