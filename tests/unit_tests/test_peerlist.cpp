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

#include "gtest/gtest.h"

#include <boost/archive/portable_binary_oarchive.hpp>
#include <boost/serialization/version.hpp>
#include <boost/serialization/vector.hpp>

#include "common/util.h"
#include "p2p/net_peerlist.h"
#include "p2p/net_peerlist_boost_serialization.h"
#include "net/net_utils_base.h"

namespace
{
  // A store whose declared class version is BELOW current. The version gate is
  // the whole mechanism -- `load_peers` refuses on `ver < CURRENT` -- so the
  // fixture must differ from a current store in exactly that: same body a
  // current reader would parse, older declared version.
  //
  // An earlier attempt declared the literal v7 three-list layout. It was
  // VACUOUS: removing the version check left it green, because a body the
  // reader cannot parse yields no peers whether or not the gate rejects it.
  // A fixture that fails for the wrong reason cannot distinguish the fix from
  // its absence.
  struct legacy_low_version_store
  {
    std::vector<nodetool::peerlist_entry> peers;
  };
}

BOOST_CLASS_VERSION(legacy_low_version_store, 7)

namespace boost
{
  namespace serialization
  {
    template<typename Archive>
    void serialize(Archive& a, legacy_low_version_store& elem, const unsigned int /*ver*/)
    {
      // Mirrors the production writer `save_peers` EXACTLY: a bare uint64
      // length followed by the elements. Boost's own vector serializer emits a
      // collection header instead, and a fixture using it produced a body the
      // reader could not parse -- so the test passed with the version gate
      // removed, for the wrong reason. Verified by instrumenting the loader:
      // the fixture drives `serialize(peerlist_types, ver=7)` against
      // CURRENT=8, which is the comparison under test.
      const uint64_t size = elem.peers.size();
      a & size;
      for (auto& p : elem.peers)
        a & p;
    }
  }
}

TEST(peer_list, peer_list_general)
{
  nodetool::peerlist_manager plm;
  plm.init(nodetool::peerlist_types{}, false);
#define MAKE_IPV4_ADDRESS(a,b,c,d,e) epee::net_utils::ipv4_network_address{MAKE_IP(a,b,c,d),e}
#define ADD_GRAY_NODE(addr_, last_seen_) {  nodetool::peerlist_entry ple; ple.last_seen=last_seen_;ple.adr = addr_;plm.append_with_peer_gray(ple);}  
#define ADD_WHITE_NODE(addr_, last_seen_) {  nodetool::peerlist_entry ple;ple.last_seen=last_seen_; ple.adr = addr_;plm.append_with_peer_white(ple);}  

#define PRINT_HEAD(step) {std::vector<nodetool::peerlist_entry> bs_head; bool r = plm.get_peerlist_head(bs_head, 100);std::cout << "step " << step << ": " << bs_head.size() << std::endl;}

  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,1, 8080), 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,2, 8080), 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,3, 8080), 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,4, 8080), 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,5, 8080), 34345);

  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,1, 8080), 34345);
  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,2, 8080), 34345);
  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,3, 8080), 34345);
  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,4, 8080), 34345);

  size_t gray_list_size = plm.get_gray_peers_count();
  ASSERT_EQ(gray_list_size, 1);

  std::vector<nodetool::peerlist_entry> bs_head;
  bool r = plm.get_peerlist_head(bs_head, 100);
  std::cout << bs_head.size() << std::endl;
  ASSERT_TRUE(r);

  ASSERT_EQ(bs_head.size(), 4);


  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,5, 8080), 34345);
  ASSERT_EQ(plm.get_gray_peers_count(), 1);
  ASSERT_EQ(plm.get_white_peers_count(), 4);
}


TEST(peer_list, merge_peer_lists)
{
  //([^ \t]*)\t([^ \t]*):([^ \t]*) \tlast_seen: d(\d+)\.h(\d+)\.m(\d+)\.s(\d+)\n
  //ADD_NODE_TO_PL("\2", \3, 0x\1, (1353346618 -(\4*60*60*24+\5*60*60+\6*60+\7 )));\n
  nodetool::peerlist_manager plm;
  plm.init(nodetool::peerlist_types{}, false);
  std::vector<nodetool::peerlist_entry> outer_bs;
#define ADD_NODE_TO_PL(ip_, port_, timestamp_) {  nodetool::peerlist_entry ple; epee::string_tools::get_ip_int32_from_string(ple.adr.ip, ip_); ple.last_seen = timestamp_; ple.adr.port = port_;outer_bs.push_back(ple);}  
}

namespace
{
  bool check_empty(nodetool::peerlist_storage& peers, std::initializer_list<epee::net_utils::zone> zones)
  {
    bool pass = false;
    for (const epee::net_utils::zone zone : zones)
    {
      const nodetool::peerlist_types types{peers.take_zone(zone)};
      EXPECT_TRUE(types.gray.empty());
      pass = types.gray.empty();
    }
    return pass;
  }
}

namespace
{
  nodetool::peerlist_entry make_peer(std::uint8_t last_octet, std::int64_t last_seen = 34345)
  {
    nodetool::peerlist_entry ple{};
    ple.adr = epee::net_utils::ipv4_network_address{MAKE_IP(123, 43, 12, last_octet), 8080};
    ple.last_seen = last_seen;
    return ple;
  }
}

// Trust is earned in-process. A restored store contributes CANDIDATES only:
// white membership means "this process dialled it and it answered", with no
// past-session qualifier, so nothing loaded from disk may enter white.
//
// A persisted white list is an assertion standing in for an observation --
// it asserts that some earlier process verified something, on the strength
// of a file. White entries are dialled in preference to gray AND are the
// only ones `get_peerlist_head` gossips onward, so believing the file makes
// this node both a preferential dialler of, and an amplifier for, whatever
// a supplied or stale datadir contains.
TEST(peerlist_manager, restored_entries_are_all_demoted_to_gray)
{
  nodetool::peerlist_types restored{};
  restored.gray.push_back(make_peer(1));
  restored.gray.push_back(make_peer(2));
  restored.gray.push_back(make_peer(3));

  nodetool::peerlist_manager plm;
  ASSERT_TRUE(plm.init(std::move(restored), true));

  // The property: no restored entry is trusted.
  EXPECT_EQ(0u, plm.get_white_peers_count());

  // The control, and it is not decoration. Demotion must RECLASSIFY, never
  // discard -- the addresses are still the pool we dial from, and the whole
  // cost argument for this change is "ordering, not addresses". An
  // implementation that dropped the white entries outright would satisfy
  // the assertion above just as well, so the positive limb has to be here
  // or the test cannot tell the fix from a deletion.
  EXPECT_EQ(3u, plm.get_gray_peers_count());
}

// An operator-supplied candidate must survive a FULL gray list. It has never
// been dialled, so its `last_seen` is 0 and it sorts oldest -- which means the
// ordinary gray append would insert it and then trim it away on exactly the
// well-connected node where an operator typed `--add-peer`. Demoting restored
// peers into gray makes a full gray list the normal case, not the rare one.
TEST(peerlist_manager, an_operator_candidate_survives_a_full_gray_list)
{
  nodetool::peerlist_manager plm;
  ASSERT_TRUE(plm.init(nodetool::peerlist_types{}, true));

  // Fill gray to its cap with entries that all have a NONZERO last_seen, so
  // the operator entry is unambiguously the oldest by the `by_time` index.
  // Distinct octets rather than integer arithmetic on a packed address:
  // `MAKE_IP(...) + i` carries between octets and collides, which silently
  // under-fills the pool and makes the test assert against the wrong state.
  for (uint32_t i = 0; i < P2P_LOCAL_GRAY_PEERLIST_LIMIT; ++i)
  {
    nodetool::peerlist_entry ple{};
    ple.adr = epee::net_utils::ipv4_network_address{
      MAKE_IP(203, 0, 1 + (i / 250), 1 + (i % 250)), 8080};
    ple.last_seen = 5000 + i;
    ASSERT_TRUE(plm.append_with_peer_gray(ple));
  }
  ASSERT_EQ(P2P_LOCAL_GRAY_PEERLIST_LIMIT, plm.get_gray_peers_count());

  nodetool::peerlist_entry op{};
  op.adr = epee::net_utils::ipv4_network_address{MAKE_IP(198, 51, 100, 7), 8080};
  op.last_seen = 0;   // never dialled -- that is the point

  ASSERT_TRUE(plm.append_operator_candidate(op));

  // The property: it is present and dialable.
  const auto gray_holds = [&plm](std::uint32_t ip) {
    bool found = false;
    plm.foreach(false, [&](const nodetool::peerlist_entry& e) {
      if (e.adr.template as<epee::net_utils::ipv4_network_address>().ip() == ip)
        found = true;
      return true;
    });
    return found;
  };
  EXPECT_TRUE(gray_holds(MAKE_IP(198, 51, 100, 7)))
      << "an operator candidate was trimmed away at the gray cap, so --add-peer "
         "would silently do nothing on a well-connected node";

  // The control limb: it made ROOM rather than growing the list past its cap.
  // Without this, an implementation that simply skipped trimming would pass
  // the assertion above while letting gray grow unbounded.
  EXPECT_EQ(P2P_LOCAL_GRAY_PEERLIST_LIMIT, plm.get_gray_peers_count());

  // And it is NOT represented as verified.
  EXPECT_EQ(0u, plm.get_white_peers_count());
}

// Seed contact must be keyed on knowing NO peer, not on knowing no TRUSTED
// peer. White is empty on every boot now, so a white-only test would send
// every restarting node to a seed ahead of a gray pool of thousands.
TEST(peerlist_manager, a_restored_gray_pool_means_this_node_is_not_peerless)
{
  nodetool::peerlist_manager empty;
  ASSERT_TRUE(empty.init(nodetool::peerlist_types{}, true));
  // A genuinely empty node does need a seed.
  EXPECT_TRUE(empty.has_no_known_peers());

  nodetool::peerlist_types restored{};
  restored.gray.push_back(make_peer(1));

  nodetool::peerlist_manager plm;
  ASSERT_TRUE(plm.init(std::move(restored), true));

  // The regression limb: white IS empty here -- that is the whole point of the
  // demotion -- so a predicate reading only the white list would report this
  // node as peerless and send it to a seed.
  EXPECT_EQ(0u, plm.get_white_peers_count());
  EXPECT_EQ(1u, plm.get_gray_peers_count());
  EXPECT_FALSE(plm.has_no_known_peers());
}

// The saved file must not assert a trust its own loader is required to
// ignore. Both live lists are written into the one persisted candidate list;
// `peerlist_types` has no white member for a caller to fill even by accident.
TEST(peerlist_manager, saved_store_carries_no_trust)
{
  nodetool::peerlist_manager plm;
  ASSERT_TRUE(plm.init(nodetool::peerlist_types{}, true));

  ASSERT_TRUE(plm.append_with_peer_white(make_peer(1)));
  ASSERT_TRUE(plm.append_with_peer_gray(make_peer(2)));
  ASSERT_EQ(1u, plm.get_white_peers_count());

  nodetool::peerlist_types saved{};
  plm.get_peerlist(saved);

  EXPECT_EQ(2u, saved.gray.size());
}

// Round trip: what a running node earned this session comes back as
// candidates next session, not as trust.
TEST(peerlist_manager, white_does_not_survive_a_save_load_cycle)
{
  nodetool::peerlist_manager first;
  ASSERT_TRUE(first.init(nodetool::peerlist_types{}, true));
  ASSERT_TRUE(first.append_with_peer_white(make_peer(1)));
  ASSERT_TRUE(first.append_with_peer_white(make_peer(2)));
  ASSERT_EQ(2u, first.get_white_peers_count());

  nodetool::peerlist_types saved{};
  first.get_peerlist(saved);

  nodetool::peerlist_manager second;
  ASSERT_TRUE(second.init(std::move(saved), true));

  EXPECT_EQ(0u, second.get_white_peers_count());
  EXPECT_EQ(2u, second.get_gray_peers_count());
}

TEST(peerlist_storage, oversized_persisted_list_is_rejected)
{
  // PEERLIST_STORE_LIST_CEILING is derived from the runtime per-zone caps
  // the peerlist manager trims to (derivation at the constant's
  // definition); store() itself serializes whatever lists it is handed and
  // enforces nothing — which is what lets this test write an oversized
  // store. A list beyond the ceiling therefore cannot come from a normally
  // operating daemon, and open() must refuse it — falling back to the
  // empty-peerlist re-bootstrap — rather than reserve() memory of
  // disk-chosen magnitude at startup.
  nodetool::peerlist_storage peers{};
  nodetool::peerlist_types types{};
  types.gray.reserve(nodetool::PEERLIST_STORE_LIST_CEILING + 1);
  for (std::uint64_t i = 0; i <= nodetool::PEERLIST_STORE_LIST_CEILING; ++i)
    types.gray.push_back({epee::net_utils::ipv4_network_address{1000, 10}, 55, 0});

  std::ostringstream stream{};
  EXPECT_TRUE(peers.store(stream, types));

  std::istringstream in{stream.str()};
  EXPECT_FALSE(bool(nodetool::peerlist_storage::open(in, true)));
}

TEST(peerlist_storage, store_shape_and_version_move_together)
{
  // The mechanical coupling for CURRENT_PEERLIST_STORAGE_ARCHIVE_VER, which
  // has no other tree-wide enforcement: a FIXED peerlist_types serialized
  // through the PORTABLE archive path (the plain boost binary archive
  // embeds a library version in its header, so a digest over it would move
  // on a toolchain bump with no shape change) must hash to the checked-in
  // literal below — a hex string typed in, never computed from the build
  // under test. A red here with the digest changed and the constant
  // unchanged means the persisted shape moved without a version bump: bump
  // the constant in net_peerlist.h AND re-pin the digest, in the same
  // change.
  nodetool::peerlist_types types{};
  types.gray.push_back({epee::net_utils::ipv4_network_address{1000, 10}, 55, 0});
  types.gray.push_back({net::tor_address::unknown(), 88, 384});

  nodetool::peerlist_storage peers{};
  std::ostringstream stream{};
  ASSERT_TRUE(peers.store(stream, types)); // store() writes the portable archive
  const std::string bytes = stream.str();
  const crypto::hash digest = crypto::cn_fast_hash(bytes.data(), bytes.size());
  const std::string digest_hex = epee::string_tools::pod_to_hex(digest);

  // v8 store shape (id-less v5 entries), pinned 2026-09-06.
  const char* pinned = "61787d1a71a8e63149cab08aafc45780f1f1ed064bbd0ca4aea365990f06f536";
  EXPECT_EQ(8u, nodetool::CURRENT_PEERLIST_STORAGE_ARCHIVE_VER)
    << "store version moved to " << nodetool::CURRENT_PEERLIST_STORAGE_ARCHIVE_VER
    << ": re-pin the digest literal in this test in the same change";
  EXPECT_EQ(pinned, digest_hex)
    << "persisted peerlist shape changed (digest now " << digest_hex
    << ") while CURRENT_PEERLIST_STORAGE_ARCHIVE_VER is still "
    << nodetool::CURRENT_PEERLIST_STORAGE_ARCHIVE_VER
    << ": a shape change must bump the constant AND re-pin this digest together";
}

// The version bump is the mechanism that stops a pre-existing store handing
// this node pre-trusted peers, so it needs a test that actually presents one.
// Every other storage test here serializes the CURRENT one-list type and so
// cannot catch a loader that accepted, or silently misread, the old
// three-list format with its populated white section.
TEST(peerlist_storage, a_v7_store_is_dropped_whole)
{
  using zone = epee::net_utils::zone;

  std::string buffer{};
  {
    legacy_low_version_store legacy{};
    legacy.peers.push_back({epee::net_utils::ipv4_network_address{1000, 10}, 44, 55});

    std::ostringstream stream{};
    {
      boost::archive::portable_binary_oarchive a{stream};
      a << legacy;
    }
    buffer = stream.str();
  }
  ASSERT_FALSE(buffer.empty());

  std::istringstream stream{buffer};
  std::optional<nodetool::peerlist_storage> read_peers =
    nodetool::peerlist_storage::open(stream, true);

  // Unconditional: no `if (read_peers)` guard. A guard would let the test pass
  // by skipping its own assertion whenever `open` refused the stream, which is
  // how the first version of this test passed with the version gate removed.
  ASSERT_TRUE(bool(read_peers));
  nodetool::peerlist_types restored = read_peers->take_zone(zone::public_);
  EXPECT_TRUE(restored.gray.empty())
    << "a store declaring a pre-current version restored " << restored.gray.size()
    << " peer(s); the version gate is the only thing preventing an older "
       "store's entries -- including its white section -- from being adopted";
  EXPECT_TRUE(check_empty(*read_peers, {zone::invalid, zone::public_, zone::tor, zone::i2p}));
}

TEST(peerlist_storage, store)
{
  using address_type = epee::net_utils::address_type;
  using zone = epee::net_utils::zone;

  // The store carries ONE list. Entries are given distinct last_seen stamps
  // so every assertion below is a lookup rather than a positional read --
  // `do_take_zone` sorts by zone and makes within-zone order an
  // implementation detail no test should depend on. (Entries carry no id
  // any more; last_seen is the discriminator the fixture controls.)
  const auto find_seen = [](const std::vector<nodetool::peerlist_entry>& v,
                            std::int64_t last_seen) -> const nodetool::peerlist_entry*
  {
    for (const auto& e : v)
      if (e.last_seen == last_seen) return &e;
    return nullptr;
  };

  nodetool::peerlist_storage peers{};
  EXPECT_TRUE(check_empty(peers, {zone::invalid, zone::public_, zone::tor, zone::i2p}));

  std::string buffer{};
  {
    nodetool::peerlist_types types{};
    types.gray.push_back({epee::net_utils::ipv4_network_address{1000, 10}, 55, 0});
    types.gray.push_back({epee::net_utils::ipv4_network_address{2000, 20}, 45, 0});
    types.gray.push_back({net::tor_address::unknown(), 75, 0});
    types.gray.push_back({net::tor_address::unknown(), 88, 0});

    std::ostringstream stream{};
    EXPECT_TRUE(peers.store(stream, types));
    buffer = stream.str();
  }
  EXPECT_TRUE(check_empty(peers, {zone::invalid, zone::public_, zone::tor, zone::i2p}));
  {
    std::istringstream stream{buffer};
    std::optional<nodetool::peerlist_storage> read_peers =
      nodetool::peerlist_storage::open(stream, true);
    ASSERT_TRUE(bool(read_peers));
    peers = std::move(*read_peers);
  }
  EXPECT_TRUE(check_empty(peers, {zone::invalid, zone::i2p}));

  nodetool::peerlist_types types = peers.take_zone(zone::public_);
  EXPECT_TRUE(check_empty(peers, {zone::invalid, zone::public_, zone::i2p}));

  ASSERT_EQ(2u, types.gray.size());
  {
    const nodetool::peerlist_entry* a = find_seen(types.gray, 55);
    ASSERT_NE(nullptr, a);
    ASSERT_EQ(address_type::ipv4, a->adr.get_type_id());
    EXPECT_EQ(1000u, a->adr.template as<epee::net_utils::ipv4_network_address>().ip());
    EXPECT_EQ(10u, a->adr.template as<epee::net_utils::ipv4_network_address>().port());
    EXPECT_EQ(55u, a->last_seen);

    const nodetool::peerlist_entry* b = find_seen(types.gray, 45);
    ASSERT_NE(nullptr, b);
    EXPECT_EQ(2000u, b->adr.template as<epee::net_utils::ipv4_network_address>().ip());
    EXPECT_EQ(20u, b->adr.template as<epee::net_utils::ipv4_network_address>().port());
    EXPECT_EQ(45u, b->last_seen);
  }

  types = peers.take_zone(zone::tor);
  EXPECT_TRUE(check_empty(peers, {zone::invalid, zone::public_, zone::i2p, zone::tor}));

  ASSERT_EQ(2u, types.gray.size());
  {
    const nodetool::peerlist_entry* a = find_seen(types.gray, 75);
    ASSERT_NE(nullptr, a);
    ASSERT_EQ(address_type::tor, a->adr.get_type_id());
    EXPECT_STREQ(net::tor_address::unknown_str(),
                 a->adr.template as<net::tor_address>().host_str());
    EXPECT_EQ(75u, a->last_seen);

    const nodetool::peerlist_entry* b = find_seen(types.gray, 88);
    ASSERT_NE(nullptr, b);
    EXPECT_EQ(88u, b->last_seen);
  }
}
