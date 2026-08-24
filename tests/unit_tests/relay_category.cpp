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
//   * add a `relay_category` or a `relay_method` and `matches_category` fails
//     to COMPILE -- neither of its switches carries a `default:`, and
//     `-Werror=switch` is a project-wide flag, so that one is enforced in
//     every build rather than only where these tests are built. It lives at
//     the definition for that reason; a numeric pin here would have been a
//     weaker copy of it, and `relay_category`'s values have no contract to
//     pin -- they are never cast, serialized, or sent over the FFI.
//
// The categories are not tested as a black box against each other: a table
// that only asserted `broadcasted` is a subset of `all` would pass with every
// method broadcast, which is the direction that leaks.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <array>
#include <cstddef>

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

  /* The one guard that belongs HERE rather than at the definition: it proves
     `k_methods` is the whole domain, which the production classifier cannot.
     A new `relay_method` is already a compile error in `matches_category`;
     what that cannot catch is a member handled there and then missing from
     `k_methods`, leaving every loop below silently short a row.

     The `switch` is what makes it hold, not the return values. An ordinal
     assert (`block == k_methods.size() - 1`) passes for a member appended
     AFTER `block` and for explicitly assigned values -- exactly the cases
     that drop a row -- whereas `-Werror=switch` fails the build on any new
     member however it is numbered. */
  constexpr std::size_t k_methods_slot(const relay_method method)
  {
    switch (method)
    {
      case relay_method::none:  return 0;
      case relay_method::local: return 1;
      case relay_method::stem:  return 2;
      case relay_method::fluff: return 3;
      case relay_method::block: return 4;
    }
    return k_methods.size(); // out-of-domain byte; never an enumerator
  }

  static_assert(k_methods_slot(k_methods[0]) == 0
             && k_methods_slot(k_methods[1]) == 1
             && k_methods_slot(k_methods[2]) == 2
             && k_methods_slot(k_methods[3]) == 3
             && k_methods_slot(k_methods[4]) == 4,
    "k_methods must list every relay_method exactly once, in enum order");
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

// `relayable` must differ from `all` at exactly one method and no other.
//
// What this pins and what it does NOT: it pins the classifier row, and that
// is all it can pin. It is not evidence that a do-not-relay entry cannot be
// relayed -- `get_relayable_transactions` tests `!meta.do_not_relay` in its
// loop body as well as passing this category to `for_all_txpool_txes`, so the
// production guarantee has a second layer this test does not touch. Nor is
// `relayable` a zero-decode guard: a zeroed record decodes to `fluff`, not
// `none`. Stated because "the category keeps it out of the relay loop" is the
// credit this row would otherwise be given, and it would be over-credit.
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
// collapsed into one predicate. `local` and `stem` separate them -- and both
// sides matter, because `core::pool_has_tx` asks `all` precisely so that a
// held `local`/`stem` entry answers true, while the disclosure sites ask
// `broadcasted` so that it answers false.
TEST(relay_category, relayable_is_wider_than_broadcasted)
{
  for (const relay_method method : {relay_method::local, relay_method::stem})
  {
    EXPECT_TRUE(cryptonote::matches_category(method, relay_category::relayable));
    EXPECT_FALSE(cryptonote::matches_category(method, relay_category::broadcasted));
  }
}
