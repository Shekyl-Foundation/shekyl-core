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

#include "common/util.h"
#include "p2p/net_peerlist.h"
#include "net/net_utils_base.h"

TEST(peer_list, peer_list_general)
{
  nodetool::peerlist_manager plm;
  plm.init(nodetool::peerlist_types{}, false);
#define MAKE_IPV4_ADDRESS(a,b,c,d,e) epee::net_utils::ipv4_network_address{MAKE_IP(a,b,c,d),e}
#define ADD_GRAY_NODE(addr_, id_, last_seen_) {  nodetool::peerlist_entry ple; ple.last_seen=last_seen_;ple.adr = addr_; ple.id = id_;plm.append_with_peer_gray(ple);}  
#define ADD_WHITE_NODE(addr_, id_, last_seen_) {  nodetool::peerlist_entry ple;ple.last_seen=last_seen_; ple.adr = addr_; ple.id = id_;plm.append_with_peer_white(ple);}  

#define PRINT_HEAD(step) {std::vector<nodetool::peerlist_entry> bs_head; bool r = plm.get_peerlist_head(bs_head, 100);std::cout << "step " << step << ": " << bs_head.size() << std::endl;}

  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,1, 8080), 121241, 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,2, 8080), 121241, 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,3, 8080), 121241, 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,4, 8080), 121241, 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,5, 8080), 121241, 34345);

  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,1, 8080), 121241, 34345);
  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,2, 8080), 121241, 34345);
  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,3, 8080), 121241, 34345);
  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,4, 8080), 121241, 34345);

  size_t gray_list_size = plm.get_gray_peers_count();
  ASSERT_EQ(gray_list_size, 1);

  std::vector<nodetool::peerlist_entry> bs_head;
  bool r = plm.get_peerlist_head(bs_head, 100);
  std::cout << bs_head.size() << std::endl;
  ASSERT_TRUE(r);

  ASSERT_EQ(bs_head.size(), 4);


  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,5, 8080), 121241, 34345);
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
#define ADD_NODE_TO_PL(ip_, port_, id_, timestamp_) {  nodetool::peerlist_entry ple; epee::string_tools::get_ip_int32_from_string(ple.adr.ip, ip_); ple.last_seen = timestamp_; ple.adr.port = port_; ple.id = id_;outer_bs.push_back(ple);}  
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
    ple.id = 121241;
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
    types.gray.push_back({epee::net_utils::ipv4_network_address{1000, 10}, 44, 55});

  std::ostringstream stream{};
  EXPECT_TRUE(peers.store(stream, types));

  std::istringstream in{stream.str()};
  EXPECT_FALSE(bool(nodetool::peerlist_storage::open(in, true)));
}

TEST(peerlist_storage, store)
{
  using address_type = epee::net_utils::address_type;
  using zone = epee::net_utils::zone;

  // The store carries ONE list. Entries are given distinct addresses and ids
  // so every assertion below is a lookup rather than a positional read --
  // `do_take_zone` sorts by zone and makes within-zone order an implementation
  // detail no test should depend on.
  const auto find_id = [](const std::vector<nodetool::peerlist_entry>& v,
                          nodetool::peerid_type id) -> const nodetool::peerlist_entry*
  {
    for (const auto& e : v)
      if (e.id == id) return &e;
    return nullptr;
  };

  nodetool::peerlist_storage peers{};
  EXPECT_TRUE(check_empty(peers, {zone::invalid, zone::public_, zone::tor, zone::i2p}));

  std::string buffer{};
  {
    nodetool::peerlist_types types{};
    types.gray.push_back({epee::net_utils::ipv4_network_address{1000, 10}, 44, 55});
    types.gray.push_back({epee::net_utils::ipv4_network_address{2000, 20}, 84, 45});
    types.gray.push_back({net::tor_address::unknown(), 64, 75});
    types.gray.push_back({net::tor_address::unknown(), 99, 88});

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
    const nodetool::peerlist_entry* a = find_id(types.gray, 44);
    ASSERT_NE(nullptr, a);
    ASSERT_EQ(address_type::ipv4, a->adr.get_type_id());
    EXPECT_EQ(1000u, a->adr.template as<epee::net_utils::ipv4_network_address>().ip());
    EXPECT_EQ(10u, a->adr.template as<epee::net_utils::ipv4_network_address>().port());
    EXPECT_EQ(55u, a->last_seen);

    const nodetool::peerlist_entry* b = find_id(types.gray, 84);
    ASSERT_NE(nullptr, b);
    EXPECT_EQ(2000u, b->adr.template as<epee::net_utils::ipv4_network_address>().ip());
    EXPECT_EQ(20u, b->adr.template as<epee::net_utils::ipv4_network_address>().port());
    EXPECT_EQ(45u, b->last_seen);
  }

  types = peers.take_zone(zone::tor);
  EXPECT_TRUE(check_empty(peers, {zone::invalid, zone::public_, zone::i2p, zone::tor}));

  ASSERT_EQ(2u, types.gray.size());
  {
    const nodetool::peerlist_entry* a = find_id(types.gray, 64);
    ASSERT_NE(nullptr, a);
    ASSERT_EQ(address_type::tor, a->adr.get_type_id());
    EXPECT_STREQ(net::tor_address::unknown_str(),
                 a->adr.template as<net::tor_address>().host_str());
    EXPECT_EQ(75u, a->last_seen);

    const nodetool::peerlist_entry* b = find_id(types.gray, 99);
    ASSERT_NE(nullptr, b);
    EXPECT_EQ(88u, b->last_seen);
  }
}
