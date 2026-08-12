// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Q12-U1: the txpool origin-zone field.
//
// The field records the zone a transaction ARRIVED over, so the pool can route
// by origin instead of inferring it. `relay_method::forward` used to carry that
// meaning -- it meant "arrived somewhere other than clearnet" and threw away
// WHICH somewhere -- which is why the fact now has its own storage separate
// from the routing decision. Q12-U2 deleted that class outright, so the
// aliasing matrix below no longer has a `forward` column.
//
// What these tests are actually defending is the NO-MIGRATION claim. It rests
// on `zone::invalid == 0` plus every pre-existing record carrying zero in the
// two bits this field took over. Both halves are asserted here, because if
// either fails the failure is silent: old records would decode as some real
// transport, and anonymity-arrived traffic would become indistinguishable from
// clearnet in exactly the direction that loses privacy.

#include "gtest/gtest.h"

#include <cstring>

#include "blockchain_db/blockchain_db.h"
#include "net/enums.h"

namespace
{
  using zone = epee::net_utils::zone;

  TEST(txpool_origin_zone, round_trips_every_zone)
  {
    for (const zone z : {zone::invalid, zone::public_, zone::i2p, zone::tor})
    {
      cryptonote::txpool_tx_meta_t meta{};
      meta.set_origin_zone(z);
      EXPECT_EQ(z, meta.get_origin_zone())
        << "zone " << unsigned(static_cast<uint8_t>(z)) << " did not survive the two-bit field";
    }
  }

  // The migration claim, stated as an executable fact rather than a comment: a
  // record whose bytes are all zero -- which is what every pre-upgrade record
  // is in these bits -- reads as "origin unknown".
  TEST(txpool_origin_zone, a_zeroed_record_reads_as_origin_unknown)
  {
    cryptonote::txpool_tx_meta_t meta;
    std::memset(&meta, 0, sizeof(meta));
    EXPECT_EQ(zone::invalid, meta.get_origin_zone());
    EXPECT_EQ(0u, static_cast<uint8_t>(zone::invalid))
      << "invalid must be 0 or pre-upgrade records decode as a real transport";
  }

  // The record is a fixed 192 bytes and the field came out of reserved space,
  // so adding it must not have grown anything. A size change here is a
  // persisted-layout change wearing the clothes of a local edit.
  TEST(txpool_origin_zone, the_record_is_still_192_bytes)
  {
    EXPECT_EQ(192u, sizeof(cryptonote::txpool_tx_meta_t));
  }

  // Origin and routing are independent axes. Setting one must not disturb the
  // other -- they share a byte, and a bitfield is exactly where that kind of
  // aliasing hides.
  TEST(txpool_origin_zone, origin_and_relay_method_do_not_alias)
  {
    for (const zone z : {zone::invalid, zone::public_, zone::i2p, zone::tor})
    {
      for (const cryptonote::relay_method m : {
             cryptonote::relay_method::none, cryptonote::relay_method::local,
             cryptonote::relay_method::stem, cryptonote::relay_method::fluff,
             cryptonote::relay_method::block})
      {
        cryptonote::txpool_tx_meta_t a{};
        a.set_origin_zone(z);
        a.set_relay_method(m);
        EXPECT_EQ(z, a.get_origin_zone()) << "set_relay_method clobbered the origin zone";
        EXPECT_EQ(m, a.get_relay_method());

        // And in the other order, because `set_relay_method` clears several
        // sibling bits and could plausibly clear this one too.
        cryptonote::txpool_tx_meta_t b{};
        b.set_relay_method(m);
        b.set_origin_zone(z);
        EXPECT_EQ(z, b.get_origin_zone());
        EXPECT_EQ(m, b.get_relay_method()) << "set_origin_zone disturbed the relay method";
      }
    }
  }

  // Q12-U2 freed the bit that held `is_forwarding` and kept it as reserved
  // padding rather than removing it, so that the members after it do not shift
  // position in a persisted record. `fcmp_verified` is the neighbour that would
  // move, and it is the one where a misread costs something: reading 1 where 0
  // was written skips a proof re-verification. `set_relay_method` clears the
  // reserved bit, so this also pins that it clears the RESERVED bit and not a
  // live one next to it.
  TEST(txpool_origin_zone, the_reclaimed_bit_does_not_disturb_its_neighbours)
  {
    for (const cryptonote::relay_method m : {
           cryptonote::relay_method::none, cryptonote::relay_method::local,
           cryptonote::relay_method::stem, cryptonote::relay_method::fluff,
           cryptonote::relay_method::block})
    {
      cryptonote::txpool_tx_meta_t meta{};
      meta.fcmp_verified = 1;
      meta.double_spend_seen = 1;
      meta.pruned = 1;
      meta.set_origin_zone(zone::tor);
      meta.set_relay_method(m);

      EXPECT_EQ(1u, meta.fcmp_verified) << "set_relay_method cleared fcmp_verified";
      EXPECT_EQ(1u, meta.double_spend_seen);
      EXPECT_EQ(1u, meta.pruned);
      EXPECT_EQ(zone::tor, meta.get_origin_zone());
      EXPECT_EQ(m, meta.get_relay_method());
    }
  }

  // Negative control on this suite: a field that always returned `invalid`
  // would pass the migration test and the zeroed-record test. It must not pass
  // this one.
  TEST(txpool_origin_zone, the_field_actually_distinguishes_zones)
  {
    cryptonote::txpool_tx_meta_t tor{};
    tor.set_origin_zone(zone::tor);
    cryptonote::txpool_tx_meta_t i2p{};
    i2p.set_origin_zone(zone::i2p);
    EXPECT_NE(tor.get_origin_zone(), i2p.get_origin_zone());
    EXPECT_NE(zone::invalid, tor.get_origin_zone());
  }
}
