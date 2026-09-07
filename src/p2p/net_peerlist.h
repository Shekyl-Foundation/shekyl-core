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

// TODO(shekyl-v4): Evaluate replacing boost::multi_index_container with a
// simpler data structure or standalone multi-index library. The peerlist uses
// composite indices (by address, by last-seen time, by id) which have no
// direct std equivalent.
#pragma once

#include <cstdint>
#include <iosfwd>
#include <iterator>
#include <list>
#include <string>
#include <vector>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <optional>
#include <boost/range/adaptor/reversed.hpp>


#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "net/enums.h"
#include "p2p_protocol_defs.h"
#include "syncobj.h"

namespace nodetool
{
  // Corruption ceiling for each list in the persisted peerlist store. A
  // legitimate store holds at most one list per network zone (public_ /
  // i2p / tor), each trimmed to its cap — the largest is
  // P2P_LOCAL_GRAY_PEERLIST_LIMIT. The 4x headroom over cap * zones
  // keeps this a corruption detector, never an operational
  // limit: the length prefix is untrusted disk input, and past this
  // ceiling loading it would mean a reserve() of disk-chosen magnitude at
  // startup instead of the designed drop-and-rebootstrap.
  constexpr std::uint64_t PEERLIST_STORE_LIST_CEILING =
    P2P_LOCAL_GRAY_PEERLIST_LIMIT * 3 * 4;

  // The persisted peerlist carries CANDIDATES and nothing else. There is no
  // `white` member on purpose: white membership means "this process dialled it
  // and it answered", so a type that could express restored-white would let a
  // future caller assert a trust no observation backs. The restore path cannot
  // write the white list because it has no white list to write -- the
  // invariant is enforced by the type rather than by a comment nobody reads.
  // The persisted peerlist store's schema version. Bumped on every change
  // to the persisted shape; `load_peers` drops any pre-current store
  // wholesale (the cache is disposable and re-bootstraps). Mechanical
  // coupling: `peerlist_storage.store_shape_and_version_move_together`
  // (tests/unit_tests/test_peerlist.cpp) pins a digest of the serialized
  // shape NEXT TO an assertion of this value, so a shape change that
  // forgets this constant goes red with a message naming both.
  constexpr unsigned CURRENT_PEERLIST_STORAGE_ARCHIVE_VER = 8;

  struct peerlist_types
  {
    std::vector<peerlist_entry> gray;
  };

  class peerlist_storage
  {
  public:
    peerlist_storage()
      : m_types{}
    {}

    //! \return Peers stored in stream `src` in `new_format` (portable archive or older non-portable).
    static std::optional<peerlist_storage> open(std::istream& src, const bool new_format);

    //! \return Peers stored in file at `path`
    static std::optional<peerlist_storage> open(const std::string& path);

    peerlist_storage(peerlist_storage&&) = default;
    peerlist_storage(const peerlist_storage&) = delete;

    ~peerlist_storage() noexcept;

    peerlist_storage& operator=(peerlist_storage&&) = default;
    peerlist_storage& operator=(const peerlist_storage&) = delete;

    //! Save peers from `this` and `other` in stream `dest`.
    bool store(std::ostream& dest, const peerlist_types& other) const;

    //! Save peers from `this` and `other` in one file at `path`.
    bool store(const std::string& path, const peerlist_types& other) const;

    //! \return Peers in `zone` and from remove from `this`.
    peerlist_types take_zone(epee::net_utils::zone zone);

  private:
    peerlist_types m_types;
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class peerlist_manager
  {
  public: 
    bool init(peerlist_types&& peers, bool allow_local_ip);
    size_t get_white_peers_count(){CRITICAL_REGION_LOCAL(m_peerlist_lock); return m_peers_white.size();}
    size_t get_gray_peers_count(){CRITICAL_REGION_LOCAL(m_peerlist_lock); return m_peers_gray.size();}
    //! \return True only when this zone knows NO peer at all, in either list.
    //
    // Seed contact is the one thing this answers, and it must be keyed on the
    // union rather than on the white list. White is empty on every boot now
    // that trust is earned in-process, so a white-only test would report
    // "I know nobody" to a node holding thousands of restored candidates --
    // sending it to a seed ahead of dials that would have succeeded, showing
    // seeds every restart, and letting a seed's handshake peerlist evict
    // stored entries at cap.
    bool has_no_known_peers(){CRITICAL_REGION_LOCAL(m_peerlist_lock); return m_peers_white.empty() && m_peers_gray.empty();}
    bool merge_peerlist(const std::vector<peerlist_entry>& outer_bs, const std::function<bool(const peerlist_entry&)> &f = NULL);
    bool get_peerlist_head(std::vector<peerlist_entry>& bs_head, bool anonymize, uint32_t depth = P2P_DEFAULT_PEERS_IN_HANDSHAKE);
    void get_peerlist(std::vector<peerlist_entry>& pl_gray, std::vector<peerlist_entry>& pl_white);
    void get_peerlist(peerlist_types& peers);
    bool get_white_peer_by_index(peerlist_entry& p, size_t i);
    bool get_gray_peer_by_index(peerlist_entry& p, size_t i);
    template<typename F> bool foreach(bool white, const F &f);
    void evict_host_from_peerlist(bool white, const peerlist_entry& pr);
    bool append_with_peer_white(const peerlist_entry& pr, bool trust_last_seen = false);
    bool append_with_peer_gray(const peerlist_entry& pr);
    bool append_operator_candidate(const peerlist_entry& pr);
    bool set_peer_just_seen(const epee::net_utils::network_address& addr, uint32_t pruning_seed);
    bool is_host_allowed(const epee::net_utils::network_address &address);
    bool get_random_gray_peer(peerlist_entry& pe);
    bool remove_from_peer_gray(const peerlist_entry& pe);
    bool remove_from_peer_white(const peerlist_entry& pe);
    template<typename F> size_t filter(bool white, const F &f); // f returns true: drop, false: keep
    
  private:
    struct by_time{};
    struct by_addr{};

    struct modify_last_seen
    {
      modify_last_seen(time_t last_seen):m_last_seen(last_seen){}
      void operator()(peerlist_entry& e)
      {
        e.last_seen = m_last_seen;
      }
    private:
      time_t m_last_seen;
    };


    typedef boost::multi_index_container<
      peerlist_entry,
      boost::multi_index::indexed_by<
      // access by peerlist_entry::net_adress
      boost::multi_index::ordered_unique<boost::multi_index::tag<by_addr>, boost::multi_index::member<peerlist_entry,epee::net_utils::network_address,&peerlist_entry::adr> >,
      // sort by peerlist_entry::last_seen<
      boost::multi_index::ordered_non_unique<boost::multi_index::tag<by_time>, boost::multi_index::member<peerlist_entry,int64_t,&peerlist_entry::last_seen> >
      > 
    > peers_indexed;


  private: 
    void trim_white_peerlist();
    void trim_gray_peerlist();
    static peerlist_entry get_nth_latest_peer(peers_indexed& peerlist, size_t n);

    friend class boost::serialization::access;
    epee::critical_section m_peerlist_lock;
    std::string m_config_folder;
    bool m_allow_local_ip;


    peers_indexed m_peers_gray;
    peers_indexed m_peers_white;
  };
  //--------------------------------------------------------------------------------------------------
  inline void peerlist_manager::trim_gray_peerlist()
  {
    while(m_peers_gray.size() > P2P_LOCAL_GRAY_PEERLIST_LIMIT)
    {
      peers_indexed::index<by_time>::type& sorted_index=m_peers_gray.get<by_time>();
      sorted_index.erase(sorted_index.begin());
    }
  }
  //--------------------------------------------------------------------------------------------------
  inline void peerlist_manager::trim_white_peerlist()
  {
    while(m_peers_white.size() > P2P_LOCAL_WHITE_PEERLIST_LIMIT)
    {
      peers_indexed::index<by_time>::type& sorted_index=m_peers_white.get<by_time>();
      sorted_index.erase(sorted_index.begin());
    }
  }
  //--------------------------------------------------------------------------------------------------
  inline
  peerlist_entry peerlist_manager::get_nth_latest_peer(peers_indexed& peerlist, const size_t n)
  {
    // Is not thread-safe nor does it check bounds. Do this before calling. Indexing starts at 0.
    peers_indexed::index<by_time>::type& by_time_index = peerlist.get<by_time>();
    auto by_time_it = --by_time_index.end();
    std::advance(by_time_it, -static_cast<long long>(n));
    return *by_time_it;
  }
  //--------------------------------------------------------------------------------------------------
  inline 
  bool peerlist_manager::merge_peerlist(const std::vector<peerlist_entry>& outer_bs, const std::function<bool(const peerlist_entry&)> &f)
  {
    CRITICAL_REGION_LOCAL(m_peerlist_lock);
    for(const peerlist_entry& be:  outer_bs)
    {
      if (!f || f(be))
        append_with_peer_gray(be);
    }
    // delete extra elements
    trim_gray_peerlist();    
    return true;
  }
  //--------------------------------------------------------------------------------------------------
  inline
  bool peerlist_manager::get_white_peer_by_index(peerlist_entry& p, size_t i)
  {
    CRITICAL_REGION_LOCAL(m_peerlist_lock);
    if(i >= m_peers_white.size())
      return false;

    p = peerlist_manager::get_nth_latest_peer(m_peers_white, i);
    return true;
  }
  //--------------------------------------------------------------------------------------------------
  inline
    bool peerlist_manager::get_gray_peer_by_index(peerlist_entry& p, size_t i)
  {
    CRITICAL_REGION_LOCAL(m_peerlist_lock);
    if(i >= m_peers_gray.size())
      return false;

    p = peerlist_manager::get_nth_latest_peer(m_peers_gray, i);
    return true;
  }
  //--------------------------------------------------------------------------------------------------
  inline 
  bool peerlist_manager::is_host_allowed(const epee::net_utils::network_address &address)
  {
    //never allow loopback ip
    if(address.is_loopback())
      return false;

    if(!m_allow_local_ip && address.is_local())
      return false;

    return true;
  }
  //--------------------------------------------------------------------------------------------------
  inline 
  bool peerlist_manager::get_peerlist_head(std::vector<peerlist_entry>& bs_head, bool anonymize, uint32_t depth)
  {
    CRITICAL_REGION_LOCAL(m_peerlist_lock);
    peers_indexed::index<by_time>::type& by_time_index=m_peers_white.get<by_time>();
    uint32_t cnt = 0;

    // picks a random set of peers within the whole set, rather pick the first depth elements.
    // The intent is that if someone asks twice, they can't easily tell:
    // - this address was not in the first list, but is in the second, so the only way this can be
    // is if its last_seen was recently reset, so this means the target node recently had a new
    // connection to that address
    // - this address was in the first list, and not in the second, which means either the address
    // was moved to the gray list (if it's not accessible, which the attacker can check if
    // the address accepts incoming connections) or it was the oldest to still fit in the 250 items,
    // so its last_seen is old.
    //
    // See Cao, Tong et al. "Exploring the Monero Peer-to-Peer Network". https://eprint.iacr.org/2019/411
    //
    const uint32_t pick_depth = anonymize ? m_peers_white.size() : depth;
    bs_head.reserve(pick_depth);
    for(const peers_indexed::value_type& vl: boost::adaptors::reverse(by_time_index))
    {
      if(cnt++ >= pick_depth)
        break;

      bs_head.push_back(vl);
    }

    if (anonymize)
    {
      std::shuffle(bs_head.begin(), bs_head.end(), crypto::random_device{});
      if (bs_head.size() > depth)
        bs_head.resize(depth);
      for (auto &e: bs_head)
        e.last_seen = 0;
    }

    return true;
  }
  //--------------------------------------------------------------------------------------------------
  template<typename F> inline
  bool peerlist_manager::foreach(bool white, const F &f)
  {
    CRITICAL_REGION_LOCAL(m_peerlist_lock);
    peers_indexed::index<by_time>::type& by_time_index = white ? m_peers_white.get<by_time>() : m_peers_gray.get<by_time>();
    for(const peers_indexed::value_type& vl: boost::adaptors::reverse(by_time_index))
      if (!f(vl))
        return false;
    return true;
  }
  //--------------------------------------------------------------------------------------------------
  inline
  bool peerlist_manager::set_peer_just_seen(const epee::net_utils::network_address& addr, uint32_t pruning_seed)
  {
    TRY_ENTRY();
    CRITICAL_REGION_LOCAL(m_peerlist_lock);
    //find in white list
    peerlist_entry ple;
    ple.adr = addr;
    ple.last_seen = time(NULL);
    ple.pruning_seed = pruning_seed;
    return append_with_peer_white(ple, true);
    CATCH_ENTRY_L0("peerlist_manager::set_peer_just_seen()", false);
  }
  //--------------------------------------------------------------------------------------------------
  inline
  bool peerlist_manager::append_with_peer_white(const peerlist_entry& ple, bool trust_last_seen)
  {
    TRY_ENTRY();
    if(!is_host_allowed(ple.adr))
      return true;

     CRITICAL_REGION_LOCAL(m_peerlist_lock);
    //find in white list
    auto by_addr_it_wt = m_peers_white.get<by_addr>().find(ple.adr);
    if(by_addr_it_wt == m_peers_white.get<by_addr>().end())
    {
      //put new record into white list
      evict_host_from_peerlist(true, ple);
      m_peers_white.insert(ple);
      trim_white_peerlist();
    }else
    {
      //update record in white list
      peerlist_entry new_ple = ple;
      if (by_addr_it_wt->pruning_seed && ple.pruning_seed == 0) // guard against older nodes not passing pruning info around
        new_ple.pruning_seed = by_addr_it_wt->pruning_seed;
      if (!trust_last_seen)
        new_ple.last_seen = by_addr_it_wt->last_seen; // do not overwrite the last seen timestamp, incoming peer lists are untrusted
      m_peers_white.replace(by_addr_it_wt, new_ple);
    }
    //remove from gray list, if need
    auto by_addr_it_gr = m_peers_gray.get<by_addr>().find(ple.adr);
    if(by_addr_it_gr != m_peers_gray.get<by_addr>().end())
    {
      m_peers_gray.erase(by_addr_it_gr);
    }
    return true;
    CATCH_ENTRY_L0("peerlist_manager::append_with_peer_white()", false);
  }
  //--------------------------------------------------------------------------------------------------
  inline
  bool peerlist_manager::append_with_peer_gray(const peerlist_entry& ple)
  {
    TRY_ENTRY();
    if(!is_host_allowed(ple.adr))
      return true;

    CRITICAL_REGION_LOCAL(m_peerlist_lock);
    //find in white list
    auto by_addr_it_wt = m_peers_white.get<by_addr>().find(ple.adr);
    if(by_addr_it_wt != m_peers_white.get<by_addr>().end())
      return true;

    //update gray list
    auto by_addr_it_gr = m_peers_gray.get<by_addr>().find(ple.adr);
    if(by_addr_it_gr == m_peers_gray.get<by_addr>().end())
    {
      //put new record into white list
      m_peers_gray.insert(ple);
      trim_gray_peerlist();    
    }else
    {
      //update record in gray list
      peerlist_entry new_ple = ple;
      if (by_addr_it_gr->pruning_seed && ple.pruning_seed == 0) // guard against older nodes not passing pruning info around
        new_ple.pruning_seed = by_addr_it_gr->pruning_seed;
      new_ple.last_seen = by_addr_it_gr->last_seen; // do not overwrite the last seen timestamp, incoming peer list are untrusted
      m_peers_gray.replace(by_addr_it_gr, new_ple);
    }
    return true;
    CATCH_ENTRY_L0("peerlist_manager::append_with_peer_gray()", false);
  }
  //--------------------------------------------------------------------------------------------------
  inline
  bool peerlist_manager::append_operator_candidate(const peerlist_entry& ple)
  {
    TRY_ENTRY();
    if(!is_host_allowed(ple.adr))
      return true;

    CRITICAL_REGION_LOCAL(m_peerlist_lock);

    // Already known: verified this session, or already a candidate.
    if(m_peers_white.get<by_addr>().find(ple.adr) != m_peers_white.get<by_addr>().end())
      return true;
    if(m_peers_gray.get<by_addr>().find(ple.adr) != m_peers_gray.get<by_addr>().end())
      return true;

    // MAKE ROOM FIRST, so the entry being added cannot be the one evicted.
    //
    // `append_with_peer_gray` cannot serve this caller: it inserts and then
    // trims from the `by_time` front, and an operator-supplied entry has never
    // been dialled so its `last_seen` is 0 -- it sorts first and is erased
    // immediately whenever gray is at its cap. That is precisely the
    // well-connected node where an operator's `--add-peer` would silently do
    // nothing, and the demotion of restored peers into gray makes a full gray
    // list the normal case rather than the rare one.
    //
    // This is a SLOT POLICY, not a trust claim: an operator-named candidate
    // outranks the least-recently-seen gossiped candidate for a place in the
    // pool. It says nothing about whether the address answers -- the entry is
    // still gray, still undialled, still never gossiped, and still has to earn
    // white by a dial like anything else.
    //
    // Deliberately NOT done by writing a synthetic `last_seen`: this node has
    // not seen the address, and recording an observation it never made is the
    // exact category error this change exists to remove.
    auto& by_time_index = m_peers_gray.get<by_time>();
    while(m_peers_gray.size() >= P2P_LOCAL_GRAY_PEERLIST_LIMIT && !by_time_index.empty())
      by_time_index.erase(by_time_index.begin());

    m_peers_gray.insert(ple);
    return true;
    CATCH_ENTRY_L0("peerlist_manager::append_operator_candidate()", false);
  }
  //--------------------------------------------------------------------------------------------------
  inline
  bool peerlist_manager::get_random_gray_peer(peerlist_entry& pe)
  {
    TRY_ENTRY();

    CRITICAL_REGION_LOCAL(m_peerlist_lock);

    if (m_peers_gray.empty()) {
      return false;
    }

    size_t random_index = crypto::rand_idx(m_peers_gray.size());
    pe = peerlist_manager::get_nth_latest_peer(m_peers_gray, random_index);

    return true;

    CATCH_ENTRY_L0("peerlist_manager::get_random_gray_peer()", false);
  }
  //--------------------------------------------------------------------------------------------------
  inline
  bool peerlist_manager::remove_from_peer_white(const peerlist_entry& pe)
  {
    TRY_ENTRY();

    CRITICAL_REGION_LOCAL(m_peerlist_lock);

    peers_indexed::index_iterator<by_addr>::type iterator = m_peers_white.get<by_addr>().find(pe.adr);

    if (iterator != m_peers_white.get<by_addr>().end()) {
      m_peers_white.erase(iterator);
    }

    return true;

    CATCH_ENTRY_L0("peerlist_manager::remove_from_peer_white()", false);
  }
  //--------------------------------------------------------------------------------------------------
  inline
  bool peerlist_manager::remove_from_peer_gray(const peerlist_entry& pe)
  {
    TRY_ENTRY();

    CRITICAL_REGION_LOCAL(m_peerlist_lock);

    peers_indexed::index_iterator<by_addr>::type iterator = m_peers_gray.get<by_addr>().find(pe.adr);

    if (iterator != m_peers_gray.get<by_addr>().end()) {
      m_peers_gray.erase(iterator);
    }

    return true;

    CATCH_ENTRY_L0("peerlist_manager::remove_from_peer_gray()", false);
  }
  //--------------------------------------------------------------------------------------------------
  template<typename F> size_t peerlist_manager::filter(bool white, const F &f)
  {
    size_t filtered = 0;
    TRY_ENTRY();
    CRITICAL_REGION_LOCAL(m_peerlist_lock);
    peers_indexed::index<by_addr>::type& sorted_index = white ? m_peers_white.get<by_addr>() : m_peers_gray.get<by_addr>();
    auto i = sorted_index.begin();
    while (i != sorted_index.end())
    {
      if (f(*i))
      {
        i = sorted_index.erase(i);
        ++filtered;
      }
      else
        ++i;
    }
    CATCH_ENTRY_L0("peerlist_manager::filter()", filtered);
    return filtered;
  }
  //--------------------------------------------------------------------------------------------------
}

