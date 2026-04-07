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

// TODO(shekyl-v4): Replace boost::serialization with a zero-copy binary codec.
// This header defines on-disk and P2P wire formats; migration requires a
// versioned format transition and backward-compatibility shim.
#pragma once

#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/is_bitwise_serializable.hpp>
#include <boost/serialization/split_free.hpp>
#include <boost/version.hpp>
#include <optional>
#include <variant>

// Use Boost's own std::variant serialization when available (Boost >= 1.78)
#if __has_include(<boost/serialization/std_variant.hpp>)
  #include <boost/serialization/std_variant.hpp>
#else
namespace boost { namespace serialization {
  template<size_t I, class Archive, typename... Ts>
  void variant_load_impl(Archive &ar, int which, std::variant<Ts...> &v)
  {
    if constexpr (I < sizeof...(Ts)) {
      if (which == static_cast<int>(I)) {
        std::variant_alternative_t<I, std::variant<Ts...>> val{};
        ar & val;
        v = std::move(val);
      } else {
        variant_load_impl<I + 1>(ar, which, v);
      }
    }
  }
  template<class Archive, typename... Ts>
  void save(Archive &ar, const std::variant<Ts...> &v, const unsigned int /*version*/)
  {
    int which = static_cast<int>(v.index());
    ar & which;
    std::visit([&ar](const auto &val) { ar & val; }, v);
  }
  template<class Archive, typename... Ts>
  void load(Archive &ar, std::variant<Ts...> &v, const unsigned int /*version*/)
  {
    int which;
    ar & which;
    variant_load_impl<0>(ar, which, v);
  }
  template<class Archive, typename... Ts>
  void serialize(Archive &ar, std::variant<Ts...> &v, const unsigned int version)
  {
    boost::serialization::split_free(ar, v, version);
  }
}}
#endif

// Boost 1.84+ handles std::optional in <boost/serialization/optional.hpp>
#if BOOST_VERSION >= 108400
  #include <boost/serialization/optional.hpp>
#else
namespace boost { namespace serialization {
  template<class Archive, class T>
  void save(Archive &ar, const std::optional<T> &o, const unsigned int /*version*/)
  {
    const bool has_value = o.has_value();
    ar & has_value;
    if (has_value)
      ar & *o;
  }
  template<class Archive, class T>
  void load(Archive &ar, std::optional<T> &o, const unsigned int /*version*/)
  {
    bool has_value = false;
    ar & has_value;
    if (has_value) {
      T v;
      ar & v;
      o = std::move(v);
    } else {
      o = std::nullopt;
    }
  }
  template<class Archive, class T>
  void serialize(Archive &ar, std::optional<T> &o, const unsigned int version)
  {
    split_free(ar, o, version);
  }
}}
#endif
#include <boost/archive/portable_binary_iarchive.hpp>
#include <boost/archive/portable_binary_oarchive.hpp>
#include "cryptonote_basic.h"
#include "difficulty.h"
#include "common/unordered_containers_boost_serialization.h"
#include "crypto/crypto.h"
#include "fcmp/rctTypes.h"
#include "fcmp/rctOps.h"

namespace boost
{
  namespace serialization
  {

  //---------------------------------------------------
  template <class Archive>
  inline void serialize(Archive &a, crypto::public_key &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::public_key)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::secret_key &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::secret_key)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::key_derivation &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::key_derivation)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::key_image &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::key_image)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::view_tag &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::view_tag)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::signature &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::signature)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::hash &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::hash)]>(x);
  }
  template <class Archive>
  inline void serialize(Archive &a, crypto::hash8 &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(crypto::hash8)]>(x);
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txout_to_script &x, const boost::serialization::version_type ver)
  {
    a & x.keys;
    a & x.script;
  }


  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txout_to_key &x, const boost::serialization::version_type ver)
  {
    a & x.key;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txout_to_tagged_key &x, const boost::serialization::version_type ver)
  {
    a & x.key;
    a & x.view_tag;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txout_to_staked_key &x, const boost::serialization::version_type ver)
  {
    a & x.key;
    a & x.view_tag;
    a & x.lock_tier;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txout_to_scripthash &x, const boost::serialization::version_type ver)
  {
    a & x.hash;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txin_gen &x, const boost::serialization::version_type ver)
  {
    a & x.height;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txin_to_script &x, const boost::serialization::version_type ver)
  {
    a & x.prev;
    a & x.prevout;
    a & x.sigset;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txin_to_scripthash &x, const boost::serialization::version_type ver)
  {
    a & x.prev;
    a & x.prevout;
    a & x.script;
    a & x.sigset;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txin_to_key &x, const boost::serialization::version_type ver)
  {
    a & x.amount;
    a & x.key_offsets;
    a & x.k_image;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::txin_stake_claim &x, const boost::serialization::version_type ver)
  {
    a & x.amount;
    a & x.staked_output_index;
    a & x.from_height;
    a & x.to_height;
    a & x.k_image;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::tx_out &x, const boost::serialization::version_type ver)
  {
    a & x.amount;
    a & x.target;
  }


  template <class Archive>
  inline void serialize(Archive &a, cryptonote::transaction_prefix &x, const boost::serialization::version_type ver)
  {
    a & x.version;
    a & x.unlock_time;
    a & x.vin;
    a & x.vout;
    a & x.extra;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::pqc_authentication &x, const boost::serialization::version_type ver)
  {
    a & x.auth_version;
    a & x.scheme_id;
    a & x.flags;
    a & x.hybrid_public_key;
    a & x.hybrid_signature;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::transaction &x, const boost::serialization::version_type ver)
  {
    a & x.version;
    a & x.unlock_time;
    a & x.vin;
    a & x.vout;
    a & x.extra;
    if (x.version == 1)
    {
      a & x.signatures;
    }
    else
    {
      a & (rct::rctSigBase&)x.rct_signatures;
      if (x.rct_signatures.type != rct::RCTTypeNull)
        a & x.rct_signatures.p;
      if (x.version >= 3 && !x.vin.empty() && !std::holds_alternative<cryptonote::txin_gen>(x.vin[0]))
        a & x.pqc_auths;
    }
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::block &b, const boost::serialization::version_type ver)
  {
    a & b.major_version;
    a & b.minor_version;
    a & b.timestamp;
    a & b.prev_id;
    a & b.nonce;
    a & b.curve_tree_root;
    //------------------
    a & b.miner_tx;
    a & b.tx_hashes;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::key &x, const boost::serialization::version_type ver)
  {
    a & reinterpret_cast<char (&)[sizeof(rct::key)]>(x);
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::ctkey &x, const boost::serialization::version_type ver)
  {
    a & x.dest;
    a & x.mask;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::BulletproofPlus &x, const boost::serialization::version_type ver)
  {
    a & x.V;
    a & x.A;
    a & x.A1;
    a & x.B;
    a & x.r1;
    a & x.s1;
    a & x.d1;
    a & x.L;
    a & x.R;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::ecdhTuple &x, const boost::serialization::version_type ver)
  {
    a & x.mask;
    a & x.amount;
  }

  template <class Archive>
  inline typename std::enable_if<Archive::is_loading::value, void>::type serializeOutPk(Archive &a, rct::ctkeyV &outPk_, const boost::serialization::version_type ver)
  {
    rct::keyV outPk;
    a & outPk;
    outPk_.resize(outPk.size());
    for (size_t n = 0; n < outPk_.size(); ++n)
    {
      outPk_[n].dest = rct::identity();
      outPk_[n].mask = outPk[n];
    }
  }

  template <class Archive>
  inline typename std::enable_if<Archive::is_saving::value, void>::type serializeOutPk(Archive &a, rct::ctkeyV &outPk_, const boost::serialization::version_type ver)
  {
    rct::keyV outPk(outPk_.size());
    for (size_t n = 0; n < outPk_.size(); ++n)
      outPk[n] = outPk_[n].mask;
    a & outPk;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::rctSigBase &x, const boost::serialization::version_type ver)
  {
    a & x.type;
    if (x.type == rct::RCTTypeNull)
      return;
    if (x.type != rct::RCTTypeFcmpPlusPlusPqc)
      throw boost::archive::archive_exception(boost::archive::archive_exception::other_exception, "Unsupported rct type");
    a & x.ecdhInfo;
    serializeOutPk(a, x.outPk, ver);
    a & x.txnFee;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::rctSigPrunable &x, const boost::serialization::version_type ver)
  {
    a & x.bulletproofs_plus;
    a & x.pseudoOuts;
  }

  template <class Archive>
  inline void serialize(Archive &a, rct::rctSig &x, const boost::serialization::version_type ver)
  {
    a & x.type;
    if (x.type == rct::RCTTypeNull)
      return;
    if (x.type != rct::RCTTypeFcmpPlusPlusPqc)
      throw boost::archive::archive_exception(boost::archive::archive_exception::other_exception, "Unsupported rct type");
    a & x.ecdhInfo;
    serializeOutPk(a, x.outPk, ver);
    a & x.txnFee;
    //--------------
    a & x.p.bulletproofs_plus;
    a & x.p.pseudoOuts;
  }

  template <class Archive>
  inline void serialize(Archive &a, cryptonote::difficulty_type &x, const boost::serialization::version_type ver)
  {
    if (Archive::is_loading::value)
    {
      // load high part
      uint64_t v = 0;
      a & v;
      x = v;
      // load low part
      x = x << 64;
      a & v;
      x += v;
    }
    else
    {
      // store high part
      cryptonote::difficulty_type x_ = (x >> 64) & 0xffffffffffffffff;
      uint64_t v = x_.convert_to<uint64_t>();
      a & v;
      // store low part
      x_ = x & 0xffffffffffffffff;
      v = x_.convert_to<uint64_t>();
      a & v;
    }
  }

}
}

BOOST_CLASS_VERSION(rct::rctSigPrunable, 2)
BOOST_CLASS_VERSION(rct::rctSig, 2)
