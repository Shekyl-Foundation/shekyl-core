// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// The relay method -> relay category table, pinned exhaustively.
//
// `relay_category::legacy` was deleted here: it was `broadcasted` plus
// `relay_method::none`, a union of the most public class with the most
// private one, justified by its own doc as "rpc relay requests or historical
// reasons". The history was Monero's pre-Dandelion++ RPC, which Shekyl
// (v3-from-genesis, rule 60) has no client for. All ten of its call sites
// were asking "is this publicly known" -- `broadcasted` -- and one of them,
// `fill_block_template`, would have mined a do-not-relay transaction.
//
// This file is what stops the union coming back by accident, and every row
// can fail:
//
//   * put `relay_method::none` in `matches_category`'s `true` arm -- the old
//     `legacy` behaviour -- and `none_is_not_broadcast` goes red.
//   * drop the `method != none` test from the `relayable` arm and
//     `only_none_separates_relayable_from_all` goes red.
//   * let `local` or `stem` match `broadcasted` (the pre-Dandelion++ posture)
//     and `pre_fluff_methods_are_not_broadcast` goes red.
//   * re-add a category to the enum and the namespace-scope `static_assert`s
//     below fail the BUILD -- the value `legacy` vacated is what pins `all`.
//     That one is deliberately not a `TEST`: a compile-time invariant dressed
//     as a runtime case can never go red at run time, so presenting it as one
//     would be a check that cannot fail.
//
// The categories are not tested as a black box against each other: a table
// that only asserted `broadcasted` is a subset of `all` would pass with every
// method broadcast, which is the direction that leaks.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <array>

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_protocol/enums.h"

namespace
{
  using cryptonote::relay_category;
  using cryptonote::relay_method;

  //! Every method the enum has. A new one must be given a row here.
  constexpr std::array<relay_method, 5> k_methods{
    relay_method::none,
    relay_method::local,
    relay_method::stem,
    relay_method::fluff,
    relay_method::block};

  static_assert(unsigned(relay_method::block) == k_methods.size() - 1,
    "relay_method gained a member; add its row to every table below");

  /* The enum's shape. `all` is last, and it sits at the value the deleted
     `legacy` used to occupy, so inserting a category anywhere before it is a
     build failure rather than a silent renumbering. */
  static_assert(unsigned(relay_category::broadcasted) == 0,
    "relay_category::broadcasted must stay first; a category was inserted before it");
  static_assert(unsigned(relay_category::relayable) == 1,
    "relay_category::relayable moved; a category was inserted before it");
  static_assert(unsigned(relay_category::all) == 2,
    "relay_category::all moved; a category was added -- give it a row in every table below");
}

TEST(relay_category, all_admits_every_method)
{
  for (const relay_method method : k_methods)
    EXPECT_TRUE(cryptonote::matches_category(method, relay_category::all))
      << "method " << unsigned(method) << " must be in `all`";
}

// `broadcasted` means the network already has it: block or fluff, nothing
// earlier. This is the disclosure boundary -- the foreign `in_pool_broadcast`
// fact, the pool-inspection RPC's non-sensitive view, and the block template
// all read it. (`core::pool_has_tx` reads it too and should not; see the note
// at its definition.)
TEST(relay_category, none_is_not_broadcast)
{
  EXPECT_FALSE(cryptonote::matches_category(relay_method::none, relay_category::broadcasted))
    << "do-not-relay is the most private class; `legacy` admitted it here";
}

TEST(relay_category, pre_fluff_methods_are_not_broadcast)
{
  EXPECT_FALSE(cryptonote::matches_category(relay_method::local, relay_category::broadcasted));
  EXPECT_FALSE(cryptonote::matches_category(relay_method::stem, relay_category::broadcasted));
}

TEST(relay_category, fluff_and_block_are_broadcast)
{
  EXPECT_TRUE(cryptonote::matches_category(relay_method::fluff, relay_category::broadcasted));
  EXPECT_TRUE(cryptonote::matches_category(relay_method::block, relay_category::broadcasted));
}

// `relayable` survives the `legacy` deletion because `none` is the ZERO of
// `relay_method`: a zeroed or short-read pool record decodes to it, and this
// category is what keeps such an entry out of `get_relayable_transactions`.
// So it must differ from `all` at exactly one method, and no other.
TEST(relay_category, only_none_separates_relayable_from_all)
{
  for (const relay_method method : k_methods)
  {
    const bool relayable = cryptonote::matches_category(method, relay_category::relayable);
    EXPECT_EQ(relayable, method != relay_method::none)
      << "method " << unsigned(method) << " misclassified by `relayable`";
  }
}

// The negative control for the two above: the categories must not have
// collapsed into one predicate. `local` and `stem` separate them.
TEST(relay_category, relayable_is_wider_than_broadcasted)
{
  for (const relay_method method : {relay_method::local, relay_method::stem})
  {
    EXPECT_TRUE(cryptonote::matches_category(method, relay_category::relayable));
    EXPECT_FALSE(cryptonote::matches_category(method, relay_category::broadcasted));
  }
}
