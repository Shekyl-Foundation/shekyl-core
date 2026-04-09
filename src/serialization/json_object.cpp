// Copyright (c) 2016-2022, The Monero Project
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

#include "json_object.h"

#include <boost/range/adaptor/transformed.hpp>
#include <variant>
#include <limits>
#include <type_traits>

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_core/cryptonote_tx_utils.h"

// drop macro from windows.h
#ifdef GetObject
  #undef GetObject
#endif

namespace cryptonote
{

namespace json
{

namespace
{
  template<typename Source, typename Destination>
  constexpr bool precision_loss()
  {
    return
      std::numeric_limits<Destination>::is_signed != std::numeric_limits<Source>::is_signed ||
      std::numeric_limits<Destination>::min() > std::numeric_limits<Source>::min() ||
      std::numeric_limits<Destination>::max() < std::numeric_limits<Source>::max();
  }

  template<typename Source, typename Type>
  void convert_numeric(Source source, Type& i)
  {
    static_assert(
      (std::is_same<Type, char>() && std::is_same<Source, int>()) ||
      std::numeric_limits<Source>::is_signed == std::numeric_limits<Type>::is_signed,
      "comparisons below may have undefined behavior"
    );
    if (source < std::numeric_limits<Type>::min())
    {
      throw WRONG_TYPE{"numeric underflow"};
    }
    if (std::numeric_limits<Type>::max() < source)
    {
      throw WRONG_TYPE{"numeric overflow"};
    }
    i = Type(source);
  }

  template<typename Type>
  void to_int(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsInt())
    {
      throw WRONG_TYPE{"integer"};
    }
    convert_numeric(val.GetInt(), i);
  }
  template<typename Type>
  void to_int64(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsInt64())
    {
      throw WRONG_TYPE{"integer"};
    }
    convert_numeric(val.GetInt64(), i);
  }

  template<typename Type>
  void to_uint(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsUint())
    {
      throw WRONG_TYPE{"unsigned integer"};
    }
    convert_numeric(val.GetUint(), i);
  }
  template<typename Type>
  void to_uint64(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsUint64())
    {
      throw WRONG_TYPE{"unsigned integer"};
    }
    convert_numeric(val.GetUint64(), i);
  }
}

void read_hex(const rapidjson::Value& val, epee::span<std::uint8_t> dest)
{
  if (!val.IsString())
  {
    throw WRONG_TYPE("string");
  }

  if (!epee::from_hex::to_buffer(dest, {val.GetString(), val.GetStringLength()}))
  {
    throw BAD_INPUT();
  }
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const rapidjson::Value& src)
{
  src.Accept(dest);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const boost::string_ref i)
{
  dest.String(i.data(), i.size());
}

void fromJsonValue(const rapidjson::Value& val, std::string& str)
{
  if (!val.IsString())
  {
    throw WRONG_TYPE("string");
  }

  str = val.GetString();
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const std::vector<std::uint8_t>& src)
{
  const std::string hex = epee::to_hex::string(epee::to_span(src));
  dest.String(hex.data(), hex.size());
}

void fromJsonValue(const rapidjson::Value& val, std::vector<std::uint8_t>& dest)
{
  if (!val.IsString())
  {
    throw WRONG_TYPE("string");
  }

  dest.resize(val.GetStringLength() / 2);
  if ((val.GetStringLength() % 2) != 0 || !epee::from_hex::to_buffer(epee::to_mut_span(dest), {val.GetString(), val.GetStringLength()}))
  {
    throw BAD_INPUT();
  }
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, bool i)
{
  dest.Bool(i);
}

void fromJsonValue(const rapidjson::Value& val, bool& b)
{
  if (!val.IsBool())
  {
    throw WRONG_TYPE("boolean");
  }
  b = val.GetBool();
}

void fromJsonValue(const rapidjson::Value& val, unsigned char& i)
{
  to_uint(val, i);
}

void fromJsonValue(const rapidjson::Value& val, char& i)
{
  to_int(val, i);
}

void fromJsonValue(const rapidjson::Value& val, signed char& i)
{
  to_int(val, i);
}

void fromJsonValue(const rapidjson::Value& val, unsigned short& i)
{
  to_uint(val, i);
}

void fromJsonValue(const rapidjson::Value& val, short& i)
{
  to_int(val, i);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const unsigned int i)
{
  dest.Uint(i);
}

void fromJsonValue(const rapidjson::Value& val, unsigned int& i)
{
  to_uint(val, i);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const int i)
{
  dest.Int(i);
}

void fromJsonValue(const rapidjson::Value& val, int& i)
{
  to_int(val, i);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const unsigned long long i)
{
  static_assert(!precision_loss<unsigned long long, std::uint64_t>(), "bad uint64 conversion");
  dest.Uint64(i);
}

void fromJsonValue(const rapidjson::Value& val, unsigned long long& i)
{
  to_uint64(val, i);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const long long i)
{
  static_assert(!precision_loss<long long, std::int64_t>(), "bad int64 conversion");
  dest.Int64(i);
}

void fromJsonValue(const rapidjson::Value& val, long long& i)
{
  to_int64(val, i);
}

void fromJsonValue(const rapidjson::Value& val, unsigned long& i)
{
  to_uint64(val, i);
}

void fromJsonValue(const rapidjson::Value& val, long& i)
{
  to_int64(val, i);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::pqc_authentication& auth)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, auth_version, auth.auth_version);
  INSERT_INTO_JSON_OBJECT(dest, scheme_id, auth.scheme_id);
  INSERT_INTO_JSON_OBJECT(dest, flags, auth.flags);
  INSERT_INTO_JSON_OBJECT(dest, hybrid_public_key, auth.hybrid_public_key);
  INSERT_INTO_JSON_OBJECT(dest, hybrid_signature, auth.hybrid_signature);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::pqc_authentication& auth)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, auth.auth_version, auth_version);
  GET_FROM_JSON_OBJECT(val, auth.scheme_id, scheme_id);
  GET_FROM_JSON_OBJECT(val, auth.flags, flags);
  GET_FROM_JSON_OBJECT(val, auth.hybrid_public_key, hybrid_public_key);
  GET_FROM_JSON_OBJECT(val, auth.hybrid_signature, hybrid_signature);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::transaction& tx)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, version, tx.version);
  INSERT_INTO_JSON_OBJECT(dest, unlock_time, tx.unlock_time);
  INSERT_INTO_JSON_OBJECT(dest, inputs, tx.vin);
  INSERT_INTO_JSON_OBJECT(dest, outputs, tx.vout);
  INSERT_INTO_JSON_OBJECT(dest, extra, tx.extra);
  if (!tx.pruned)
  {
    INSERT_INTO_JSON_OBJECT(dest, signatures, tx.signatures);
  }
  {
    dest.Key("fcmp");
    toJsonValue(dest, tx.rct_signatures, tx.pruned);
  }
  if (!tx.pqc_auths.empty())
  {
    INSERT_INTO_JSON_OBJECT(dest, pqc_auths, tx.pqc_auths);
  }

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::transaction& tx)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, tx.version, version);
  GET_FROM_JSON_OBJECT(val, tx.unlock_time, unlock_time);
  GET_FROM_JSON_OBJECT(val, tx.vin, inputs);
  GET_FROM_JSON_OBJECT(val, tx.vout, outputs);
  GET_FROM_JSON_OBJECT(val, tx.extra, extra);
  GET_FROM_JSON_OBJECT(val, tx.rct_signatures, fcmp);

  const auto& sigs = val.FindMember("signatures");
  if (sigs != val.MemberEnd())
  {
    fromJsonValue(sigs->value, tx.signatures);
  }

  const auto pqc = val.FindMember("pqc_auths");
  if (pqc != val.MemberEnd())
  {
    fromJsonValue(pqc->value, tx.pqc_auths);
  }

  const auto& rsig = tx.rct_signatures;
  if (!cryptonote::is_coinbase(tx) && rsig.p.bulletproofs_plus.empty() && rsig.get_pseudo_outs().empty() && rsig.p.fcmp_pp_proof.empty() && sigs == val.MemberEnd())
    tx.pruned = true;
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::block& b)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, major_version, b.major_version);
  INSERT_INTO_JSON_OBJECT(dest, minor_version, b.minor_version);
  INSERT_INTO_JSON_OBJECT(dest, timestamp, b.timestamp);
  INSERT_INTO_JSON_OBJECT(dest, prev_id, b.prev_id);
  INSERT_INTO_JSON_OBJECT(dest, nonce, b.nonce);
  INSERT_INTO_JSON_OBJECT(dest, miner_tx, b.miner_tx);
  INSERT_INTO_JSON_OBJECT(dest, tx_hashes, b.tx_hashes);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::block& b)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, b.major_version, major_version);
  GET_FROM_JSON_OBJECT(val, b.minor_version, minor_version);
  GET_FROM_JSON_OBJECT(val, b.timestamp, timestamp);
  GET_FROM_JSON_OBJECT(val, b.prev_id, prev_id);
  GET_FROM_JSON_OBJECT(val, b.nonce, nonce);
  GET_FROM_JSON_OBJECT(val, b.miner_tx, miner_tx);
  GET_FROM_JSON_OBJECT(val, b.tx_hashes, tx_hashes);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::txin_v& txin)
{
  dest.StartObject();
  struct add_input
  {
    rapidjson::Writer<epee::byte_stream>& dest;

    void operator()(cryptonote::txin_to_key const& input) const
    {
      INSERT_INTO_JSON_OBJECT(dest, to_key, input);
    }
    void operator()(cryptonote::txin_gen const& input) const
    {
      INSERT_INTO_JSON_OBJECT(dest, gen, input);
    }
    void operator()(cryptonote::txin_to_script const& input) const
    {
      INSERT_INTO_JSON_OBJECT(dest, to_script, input);
    }
    void operator()(cryptonote::txin_to_scripthash const& input) const
    {
      INSERT_INTO_JSON_OBJECT(dest, to_scripthash, input);
    }
    void operator()(cryptonote::txin_stake_claim const& input) const
    {
      INSERT_INTO_JSON_OBJECT(dest, stake_claim, input);
    }
  };
  std::visit(add_input{dest}, txin);
  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_v& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  if (val.MemberCount() != 1)
  {
    throw MISSING_KEY("Invalid input object");
  }

  for (auto const& elem : val.GetObject())
  {
    if (elem.name == "to_key")
    {
      cryptonote::txin_to_key tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
    else if (elem.name == "gen")
    {
      cryptonote::txin_gen tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
    else if (elem.name == "to_script")
    {
      cryptonote::txin_to_script tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
    else if (elem.name == "to_scripthash")
    {
      cryptonote::txin_to_scripthash tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
    else if (elem.name == "stake_claim")
    {
      cryptonote::txin_stake_claim tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
  }
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::txin_gen& txin)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, height, txin.height);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_gen& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txin.height, height);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::txin_to_script& txin)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, prev, txin.prev);
  INSERT_INTO_JSON_OBJECT(dest, prevout, txin.prevout);
  INSERT_INTO_JSON_OBJECT(dest, sigset, txin.sigset);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_script& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txin.prev, prev);
  GET_FROM_JSON_OBJECT(val, txin.prevout, prevout);
  GET_FROM_JSON_OBJECT(val, txin.sigset, sigset);
}


void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::txin_to_scripthash& txin)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, prev, txin.prev);
  INSERT_INTO_JSON_OBJECT(dest, prevout, txin.prevout);
  INSERT_INTO_JSON_OBJECT(dest, script, txin.script);
  INSERT_INTO_JSON_OBJECT(dest, sigset, txin.sigset);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_scripthash& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txin.prev, prev);
  GET_FROM_JSON_OBJECT(val, txin.prevout, prevout);
  GET_FROM_JSON_OBJECT(val, txin.script, script);
  GET_FROM_JSON_OBJECT(val, txin.sigset, sigset);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::txin_to_key& txin)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, amount, txin.amount);
  INSERT_INTO_JSON_OBJECT(dest, key_offsets, txin.key_offsets);
  INSERT_INTO_JSON_OBJECT(dest, key_image, txin.k_image);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_key& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txin.amount, amount);
  GET_FROM_JSON_OBJECT(val, txin.key_offsets, key_offsets);
  GET_FROM_JSON_OBJECT(val, txin.k_image, key_image);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::txin_stake_claim& txin)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, amount, txin.amount);
  INSERT_INTO_JSON_OBJECT(dest, staked_output_index, txin.staked_output_index);
  INSERT_INTO_JSON_OBJECT(dest, from_height, txin.from_height);
  INSERT_INTO_JSON_OBJECT(dest, to_height, txin.to_height);
  INSERT_INTO_JSON_OBJECT(dest, key_image, txin.k_image);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_stake_claim& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txin.amount, amount);
  GET_FROM_JSON_OBJECT(val, txin.staked_output_index, staked_output_index);
  GET_FROM_JSON_OBJECT(val, txin.from_height, from_height);
  GET_FROM_JSON_OBJECT(val, txin.to_height, to_height);
  GET_FROM_JSON_OBJECT(val, txin.k_image, key_image);
}


void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::txout_to_script& txout)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, keys, txout.keys);
  INSERT_INTO_JSON_OBJECT(dest, script, txout.script);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_script& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txout.keys, keys);
  GET_FROM_JSON_OBJECT(val, txout.script, script);
}


void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::txout_to_scripthash& txout)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, hash, txout.hash);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_scripthash& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txout.hash, hash);
}


void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::txout_to_key& txout)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, key, txout.key);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_key& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txout.key, key);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::txout_to_tagged_key& txout)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, key, txout.key);
  INSERT_INTO_JSON_OBJECT(dest, view_tag, txout.view_tag);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_tagged_key& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txout.key, key);
  GET_FROM_JSON_OBJECT(val, txout.view_tag, view_tag);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::txout_to_staked_key& txout)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, key, txout.key);
  INSERT_INTO_JSON_OBJECT(dest, view_tag, txout.view_tag);
  INSERT_INTO_JSON_OBJECT(dest, lock_tier, txout.lock_tier);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_staked_key& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txout.key, key);
  GET_FROM_JSON_OBJECT(val, txout.view_tag, view_tag);
  GET_FROM_JSON_OBJECT(val, txout.lock_tier, lock_tier);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::tx_out& txout)
{
  dest.StartObject();
  INSERT_INTO_JSON_OBJECT(dest, amount, txout.amount);

  struct add_output
  {
    rapidjson::Writer<epee::byte_stream>& dest;

    void operator()(cryptonote::txout_to_key const& output) const
    {
      INSERT_INTO_JSON_OBJECT(dest, to_key, output);
    }
    void operator()(cryptonote::txout_to_tagged_key const& output) const
    {
      INSERT_INTO_JSON_OBJECT(dest, to_tagged_key, output);
    }
    void operator()(cryptonote::txout_to_script const& output) const
    {
      INSERT_INTO_JSON_OBJECT(dest, to_script, output);
    }
    void operator()(cryptonote::txout_to_scripthash const& output) const
    {
      INSERT_INTO_JSON_OBJECT(dest, to_scripthash, output);
    }
    void operator()(cryptonote::txout_to_staked_key const& output) const
    {
      INSERT_INTO_JSON_OBJECT(dest, to_staked_key, output);
    }
  };
  std::visit(add_output{dest}, txout.target);
   dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::tx_out& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  if (val.MemberCount() != 2)
  {
    throw MISSING_KEY("Invalid input object");
  }

  for (auto const& elem : val.GetObject())
  {
    if (elem.name == "amount")
    {
      fromJsonValue(elem.value, txout.amount);
    }

    if (elem.name == "to_key")
    {
      cryptonote::txout_to_key tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txout.target = std::move(tmpVal);
    }
    else if (elem.name == "to_tagged_key")
    {
      cryptonote::txout_to_tagged_key tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txout.target = std::move(tmpVal);
    }
    else if (elem.name == "to_script")
    {
      cryptonote::txout_to_script tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txout.target = std::move(tmpVal);
    }
    else if (elem.name == "to_scripthash")
    {
      cryptonote::txout_to_scripthash tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txout.target = std::move(tmpVal);
    }
    else if (elem.name == "to_staked_key")
    {
      cryptonote::txout_to_staked_key tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txout.target = std::move(tmpVal);
    }
  }
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::connection_info& info)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, incoming, info.incoming);
  INSERT_INTO_JSON_OBJECT(dest, localhost, info.localhost);
  INSERT_INTO_JSON_OBJECT(dest, local_ip, info.local_ip);
  INSERT_INTO_JSON_OBJECT(dest, address_type, info.address_type);

  INSERT_INTO_JSON_OBJECT(dest, ip, info.ip);
  INSERT_INTO_JSON_OBJECT(dest, port, info.port);
  INSERT_INTO_JSON_OBJECT(dest, rpc_port, info.rpc_port);
  INSERT_INTO_JSON_OBJECT(dest, rpc_credits_per_hash, info.rpc_credits_per_hash);

  INSERT_INTO_JSON_OBJECT(dest, peer_id, info.peer_id);

  INSERT_INTO_JSON_OBJECT(dest, recv_count, info.recv_count);
  INSERT_INTO_JSON_OBJECT(dest, recv_idle_time, info.recv_idle_time);

  INSERT_INTO_JSON_OBJECT(dest, send_count, info.send_count);
  INSERT_INTO_JSON_OBJECT(dest, send_idle_time, info.send_idle_time);

  INSERT_INTO_JSON_OBJECT(dest, state, info.state);

  INSERT_INTO_JSON_OBJECT(dest, live_time, info.live_time);

  INSERT_INTO_JSON_OBJECT(dest, avg_download, info.avg_download);
  INSERT_INTO_JSON_OBJECT(dest, current_download, info.current_download);

  INSERT_INTO_JSON_OBJECT(dest, avg_upload, info.avg_upload);
  INSERT_INTO_JSON_OBJECT(dest, current_upload, info.current_upload);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::connection_info& info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, info.incoming, incoming);
  GET_FROM_JSON_OBJECT(val, info.localhost, localhost);
  GET_FROM_JSON_OBJECT(val, info.local_ip, local_ip);
  GET_FROM_JSON_OBJECT(val, info.address_type, address_type);

  GET_FROM_JSON_OBJECT(val, info.ip, ip);
  GET_FROM_JSON_OBJECT(val, info.port, port);
  GET_FROM_JSON_OBJECT(val, info.rpc_port, rpc_port);
  GET_FROM_JSON_OBJECT(val, info.rpc_credits_per_hash, rpc_credits_per_hash);

  GET_FROM_JSON_OBJECT(val, info.peer_id, peer_id);

  GET_FROM_JSON_OBJECT(val, info.recv_count, recv_count);
  GET_FROM_JSON_OBJECT(val, info.recv_idle_time, recv_idle_time);

  GET_FROM_JSON_OBJECT(val, info.send_count, send_count);
  GET_FROM_JSON_OBJECT(val, info.send_idle_time, send_idle_time);

  GET_FROM_JSON_OBJECT(val, info.state, state);

  GET_FROM_JSON_OBJECT(val, info.live_time, live_time);

  GET_FROM_JSON_OBJECT(val, info.avg_download, avg_download);
  GET_FROM_JSON_OBJECT(val, info.current_download, current_download);

  GET_FROM_JSON_OBJECT(val, info.avg_upload, avg_upload);
  GET_FROM_JSON_OBJECT(val, info.current_upload, current_upload);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::tx_blob_entry& tx)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, blob, tx.blob);
  INSERT_INTO_JSON_OBJECT(dest, prunable_hash, tx.prunable_hash);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::tx_blob_entry& tx)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, tx.blob, blob);
  GET_FROM_JSON_OBJECT(val, tx.prunable_hash, prunable_hash);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::block_complete_entry& blk)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, block, blk.block);
  INSERT_INTO_JSON_OBJECT(dest, transactions, blk.txs);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::block_complete_entry& blk)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, blk.block, block);
  GET_FROM_JSON_OBJECT(val, blk.txs, transactions);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::block_with_transactions& blk)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, block, blk.block);
  INSERT_INTO_JSON_OBJECT(dest, transactions, blk.transactions);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::block_with_transactions& blk)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, blk.block, block);
  GET_FROM_JSON_OBJECT(val, blk.transactions, transactions);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::transaction_info& tx_info)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, height, tx_info.height);
  INSERT_INTO_JSON_OBJECT(dest, in_pool, tx_info.in_pool);
  INSERT_INTO_JSON_OBJECT(dest, transaction, tx_info.transaction);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::transaction_info& tx_info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, tx_info.height, height);
  GET_FROM_JSON_OBJECT(val, tx_info.in_pool, in_pool);
  GET_FROM_JSON_OBJECT(val, tx_info.transaction, transaction);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::output_key_and_amount_index& out)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, amount_index, out.amount_index);
  INSERT_INTO_JSON_OBJECT(dest, key, out.key);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_key_and_amount_index& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, out.amount_index, amount_index);
  GET_FROM_JSON_OBJECT(val, out.key, key);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::amount_with_random_outputs& out)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, amount, out.amount);
  INSERT_INTO_JSON_OBJECT(dest, outputs, out.outputs);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::amount_with_random_outputs& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, out.amount, amount);
  GET_FROM_JSON_OBJECT(val, out.outputs, outputs);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::peer& peer)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, id, peer.id);
  INSERT_INTO_JSON_OBJECT(dest, ip, peer.ip);
  INSERT_INTO_JSON_OBJECT(dest, port, peer.port);
  INSERT_INTO_JSON_OBJECT(dest, rpc_port, peer.rpc_port);
  INSERT_INTO_JSON_OBJECT(dest, rpc_credits_per_hash, peer.rpc_credits_per_hash);
  INSERT_INTO_JSON_OBJECT(dest, last_seen, peer.last_seen);
  INSERT_INTO_JSON_OBJECT(dest, pruning_seed, peer.pruning_seed);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::peer& peer)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, peer.id, id);
  GET_FROM_JSON_OBJECT(val, peer.ip, ip);
  GET_FROM_JSON_OBJECT(val, peer.port, port);
  GET_FROM_JSON_OBJECT(val, peer.rpc_port, rpc_port);
  GET_FROM_JSON_OBJECT(val, peer.rpc_credits_per_hash, rpc_credits_per_hash);
  GET_FROM_JSON_OBJECT(val, peer.last_seen, last_seen);
  GET_FROM_JSON_OBJECT(val, peer.pruning_seed, pruning_seed);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::tx_in_pool& tx)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, tx, tx.tx);
  INSERT_INTO_JSON_OBJECT(dest, tx_hash, tx.tx_hash);
  INSERT_INTO_JSON_OBJECT(dest, blob_size, tx.blob_size);
  INSERT_INTO_JSON_OBJECT(dest, weight, tx.weight);
  INSERT_INTO_JSON_OBJECT(dest, fee, tx.fee);
  INSERT_INTO_JSON_OBJECT(dest, max_used_block_hash, tx.max_used_block_hash);
  INSERT_INTO_JSON_OBJECT(dest, max_used_block_height, tx.max_used_block_height);
  INSERT_INTO_JSON_OBJECT(dest, kept_by_block, tx.kept_by_block);
  INSERT_INTO_JSON_OBJECT(dest, last_failed_block_hash, tx.last_failed_block_hash);
  INSERT_INTO_JSON_OBJECT(dest, last_failed_block_height, tx.last_failed_block_height);
  INSERT_INTO_JSON_OBJECT(dest, receive_time, tx.receive_time);
  INSERT_INTO_JSON_OBJECT(dest, last_relayed_time, tx.last_relayed_time);
  INSERT_INTO_JSON_OBJECT(dest, relayed, tx.relayed);
  INSERT_INTO_JSON_OBJECT(dest, do_not_relay, tx.do_not_relay);
  INSERT_INTO_JSON_OBJECT(dest, double_spend_seen, tx.double_spend_seen);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::tx_in_pool& tx)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, tx.tx, tx);
  GET_FROM_JSON_OBJECT(val, tx.blob_size, blob_size);
  GET_FROM_JSON_OBJECT(val, tx.weight, weight);
  GET_FROM_JSON_OBJECT(val, tx.fee, fee);
  GET_FROM_JSON_OBJECT(val, tx.max_used_block_hash, max_used_block_hash);
  GET_FROM_JSON_OBJECT(val, tx.max_used_block_height, max_used_block_height);
  GET_FROM_JSON_OBJECT(val, tx.kept_by_block, kept_by_block);
  GET_FROM_JSON_OBJECT(val, tx.last_failed_block_hash, last_failed_block_hash);
  GET_FROM_JSON_OBJECT(val, tx.last_failed_block_height, last_failed_block_height);
  GET_FROM_JSON_OBJECT(val, tx.receive_time, receive_time);
  GET_FROM_JSON_OBJECT(val, tx.last_relayed_time, last_relayed_time);
  GET_FROM_JSON_OBJECT(val, tx.relayed, relayed);
  GET_FROM_JSON_OBJECT(val, tx.do_not_relay, do_not_relay);
  GET_FROM_JSON_OBJECT(val, tx.double_spend_seen, double_spend_seen);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::hard_fork_info& info)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, version, info.version);
  INSERT_INTO_JSON_OBJECT(dest, enabled, info.enabled);
  INSERT_INTO_JSON_OBJECT(dest, window, info.window);
  INSERT_INTO_JSON_OBJECT(dest, votes, info.votes);
  INSERT_INTO_JSON_OBJECT(dest, threshold, info.threshold);
  INSERT_INTO_JSON_OBJECT(dest, voting, info.voting);
  INSERT_INTO_JSON_OBJECT(dest, state, info.state);
  INSERT_INTO_JSON_OBJECT(dest, earliest_height, info.earliest_height);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::hard_fork_info& info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, info.version, version);
  GET_FROM_JSON_OBJECT(val, info.enabled, enabled);
  GET_FROM_JSON_OBJECT(val, info.window, window);
  GET_FROM_JSON_OBJECT(val, info.votes, votes);
  GET_FROM_JSON_OBJECT(val, info.threshold, threshold);
  GET_FROM_JSON_OBJECT(val, info.voting, voting);
  GET_FROM_JSON_OBJECT(val, info.state, state);
  GET_FROM_JSON_OBJECT(val, info.earliest_height, earliest_height);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::output_amount_count& out)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, amount, out.amount);
  INSERT_INTO_JSON_OBJECT(dest, total_count, out.total_count);
  INSERT_INTO_JSON_OBJECT(dest, unlocked_count, out.unlocked_count);
  INSERT_INTO_JSON_OBJECT(dest, recent_count, out.recent_count);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_amount_count& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, out.amount, amount);
  GET_FROM_JSON_OBJECT(val, out.total_count, total_count);
  GET_FROM_JSON_OBJECT(val, out.unlocked_count, unlocked_count);
  GET_FROM_JSON_OBJECT(val, out.recent_count, recent_count);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::output_amount_and_index& out)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, amount, out.amount);
  INSERT_INTO_JSON_OBJECT(dest, index, out.index);

  dest.EndObject();
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_amount_and_index& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, out.amount, amount);
  GET_FROM_JSON_OBJECT(val, out.index, index);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::output_key_mask_unlocked& out)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, key, out.key);
  INSERT_INTO_JSON_OBJECT(dest, mask, out.mask);
  INSERT_INTO_JSON_OBJECT(dest, unlocked, out.unlocked);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_key_mask_unlocked& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, out.key, key);
  GET_FROM_JSON_OBJECT(val, out.mask, mask);
  GET_FROM_JSON_OBJECT(val, out.unlocked, unlocked);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::error& err)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, code, err.code);
  INSERT_INTO_JSON_OBJECT(dest, error_str, err.error_str);
  INSERT_INTO_JSON_OBJECT(dest, message, err.message);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::error& error)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, error.code, code);
  GET_FROM_JSON_OBJECT(val, error.error_str, error_str);
  GET_FROM_JSON_OBJECT(val, error.message, message);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::BlockHeaderResponse& response)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, major_version, response.major_version);
  INSERT_INTO_JSON_OBJECT(dest, minor_version, response.minor_version);
  INSERT_INTO_JSON_OBJECT(dest, timestamp, response.timestamp);
  INSERT_INTO_JSON_OBJECT(dest, prev_id, response.prev_id);
  INSERT_INTO_JSON_OBJECT(dest, nonce, response.nonce);
  INSERT_INTO_JSON_OBJECT(dest, height, response.height);
  INSERT_INTO_JSON_OBJECT(dest, depth, response.depth);
  INSERT_INTO_JSON_OBJECT(dest, hash, response.hash);
  INSERT_INTO_JSON_OBJECT(dest, difficulty, response.difficulty);
  INSERT_INTO_JSON_OBJECT(dest, reward, response.reward);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::BlockHeaderResponse& response)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, response.major_version, major_version);
  GET_FROM_JSON_OBJECT(val, response.minor_version, minor_version);
  GET_FROM_JSON_OBJECT(val, response.timestamp, timestamp);
  GET_FROM_JSON_OBJECT(val, response.prev_id, prev_id);
  GET_FROM_JSON_OBJECT(val, response.nonce, nonce);
  GET_FROM_JSON_OBJECT(val, response.height, height);
  GET_FROM_JSON_OBJECT(val, response.depth, depth);
  GET_FROM_JSON_OBJECT(val, response.hash, hash);
  GET_FROM_JSON_OBJECT(val, response.difficulty, difficulty);
  GET_FROM_JSON_OBJECT(val, response.reward, reward);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const rct::rctSig& sig, const bool prune)
{
  using boost::adaptors::transform;

  dest.StartObject();

  const auto just_mask = [] (rct::ctkey const& key) -> rct::key const&
  {
    return key.mask;
  };

  INSERT_INTO_JSON_OBJECT(dest, type, sig.type);
  if (sig.type != rct::RCTTypeNull)
  {
    INSERT_INTO_JSON_OBJECT(dest, enc_amounts, sig.enc_amounts);
    INSERT_INTO_JSON_OBJECT(dest, commitments, transform(sig.outPk, just_mask));
    INSERT_INTO_JSON_OBJECT(dest, fee, sig.txnFee);
  }

  // prunable
  if (!prune && (!sig.p.bulletproofs_plus.empty() || !sig.get_pseudo_outs().empty()
      || !sig.p.fcmp_pp_proof.empty()))
  {
    dest.Key("prunable");
    dest.StartObject();

    INSERT_INTO_JSON_OBJECT(dest, bulletproofs_plus, sig.p.bulletproofs_plus);
    INSERT_INTO_JSON_OBJECT(dest, pseudo_outs, sig.get_pseudo_outs());
    INSERT_INTO_JSON_OBJECT(dest, curve_trees_tree_depth, sig.p.curve_trees_tree_depth);
    INSERT_INTO_JSON_OBJECT(dest, fcmp_pp_proof, sig.p.fcmp_pp_proof);

    dest.EndObject();
  }

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, rct::rctSig& sig)
{
  using boost::adaptors::transform;

  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, sig.type, type);
  if (sig.type != rct::RCTTypeNull)
  {
    GET_FROM_JSON_OBJECT(val, sig.enc_amounts, enc_amounts);
    GET_FROM_JSON_OBJECT(val, sig.outPk, commitments);
    GET_FROM_JSON_OBJECT(val, sig.txnFee, fee);
  }

  // prunable
  const auto prunable = val.FindMember("prunable");
  if (prunable != val.MemberEnd())
  {
    rct::keyV pseudo_outs = std::move(sig.get_pseudo_outs());

    GET_FROM_JSON_OBJECT(prunable->value, sig.p.bulletproofs_plus, bulletproofs_plus);
    GET_FROM_JSON_OBJECT(prunable->value, pseudo_outs, pseudo_outs);
    GET_FROM_JSON_OBJECT(prunable->value, sig.p.curve_trees_tree_depth, curve_trees_tree_depth);
    GET_FROM_JSON_OBJECT(prunable->value, sig.p.fcmp_pp_proof, fcmp_pp_proof);

    sig.get_pseudo_outs() = std::move(pseudo_outs);
  }
  else
  {
    sig.p.bulletproofs_plus.clear();
    sig.get_pseudo_outs().clear();
    sig.p.fcmp_pp_proof.clear();
  }
}

void fromJsonValue(const rapidjson::Value& val, rct::ctkey& key)
{
  key.dest = {};
  fromJsonValue(val, key.mask);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const std::array<uint8_t, 9>& enc_amount)
{
  const std::string hex = epee::to_hex::string({enc_amount.data(), enc_amount.size()});
  dest.String(hex.data(), hex.size());
}

void fromJsonValue(const rapidjson::Value& val, std::array<uint8_t, 9>& enc_amount)
{
  if (!val.IsString())
    throw WRONG_TYPE("string");
  if (val.GetStringLength() != 18)
    throw WRONG_TYPE("18-char hex string for enc_amount");
  if (!epee::from_hex::to_buffer({enc_amount.data(), enc_amount.size()},
      {val.GetString(), val.GetStringLength()}))
    throw WRONG_TYPE("valid hex for enc_amount");
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const rct::BulletproofPlus& p)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, V, p.V);
  INSERT_INTO_JSON_OBJECT(dest, A, p.A);
  INSERT_INTO_JSON_OBJECT(dest, A1, p.A1);
  INSERT_INTO_JSON_OBJECT(dest, B, p.B);
  INSERT_INTO_JSON_OBJECT(dest, r1, p.r1);
  INSERT_INTO_JSON_OBJECT(dest, s1, p.s1);
  INSERT_INTO_JSON_OBJECT(dest, d1, p.d1);
  INSERT_INTO_JSON_OBJECT(dest, L, p.L);
  INSERT_INTO_JSON_OBJECT(dest, R, p.R);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, rct::BulletproofPlus& p)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, p.V, V);
  GET_FROM_JSON_OBJECT(val, p.A, A);
  GET_FROM_JSON_OBJECT(val, p.A1, A1);
  GET_FROM_JSON_OBJECT(val, p.B, B);
  GET_FROM_JSON_OBJECT(val, p.r1, r1);
  GET_FROM_JSON_OBJECT(val, p.s1, s1);
  GET_FROM_JSON_OBJECT(val, p.d1, d1);
  GET_FROM_JSON_OBJECT(val, p.L, L);
  GET_FROM_JSON_OBJECT(val, p.R, R);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::DaemonInfo& info)
{
  dest.StartObject();

  const uint64_t difficulty_top64 = (info.wide_difficulty >> 64).convert_to<std::uint64_t>();
  const uint64_t cumulative_difficulty_top64 = (info.wide_cumulative_difficulty >> 64).convert_to<std::uint64_t>();

  INSERT_INTO_JSON_OBJECT(dest, height, info.height);
  INSERT_INTO_JSON_OBJECT(dest, target_height, info.target_height);
  INSERT_INTO_JSON_OBJECT(dest, top_block_height, info.top_block_height);
  INSERT_INTO_JSON_OBJECT(dest, difficulty, info.difficulty);
  INSERT_INTO_JSON_OBJECT(dest, difficulty_top64, difficulty_top64);
  INSERT_INTO_JSON_OBJECT(dest, target, info.target);
  INSERT_INTO_JSON_OBJECT(dest, tx_count, info.tx_count);
  INSERT_INTO_JSON_OBJECT(dest, tx_pool_size, info.tx_pool_size);
  INSERT_INTO_JSON_OBJECT(dest, alt_blocks_count, info.alt_blocks_count);
  INSERT_INTO_JSON_OBJECT(dest, outgoing_connections_count, info.outgoing_connections_count);
  INSERT_INTO_JSON_OBJECT(dest, incoming_connections_count, info.incoming_connections_count);
  INSERT_INTO_JSON_OBJECT(dest, white_peerlist_size, info.white_peerlist_size);
  INSERT_INTO_JSON_OBJECT(dest, grey_peerlist_size, info.grey_peerlist_size);
  INSERT_INTO_JSON_OBJECT(dest, mainnet, info.mainnet);
  INSERT_INTO_JSON_OBJECT(dest, testnet, info.testnet);
  INSERT_INTO_JSON_OBJECT(dest, stagenet, info.stagenet);
  INSERT_INTO_JSON_OBJECT(dest, nettype, info.nettype);
  INSERT_INTO_JSON_OBJECT(dest, top_block_hash, info.top_block_hash);
  INSERT_INTO_JSON_OBJECT(dest, cumulative_difficulty, info.cumulative_difficulty);
  INSERT_INTO_JSON_OBJECT(dest, cumulative_difficulty_top64, cumulative_difficulty_top64);
  INSERT_INTO_JSON_OBJECT(dest, block_size_limit, info.block_size_limit);
  INSERT_INTO_JSON_OBJECT(dest, block_weight_limit, info.block_weight_limit);
  INSERT_INTO_JSON_OBJECT(dest, block_size_median, info.block_size_median);
  INSERT_INTO_JSON_OBJECT(dest, block_weight_median, info.block_weight_median);
  INSERT_INTO_JSON_OBJECT(dest, adjusted_time, info.adjusted_time);
  INSERT_INTO_JSON_OBJECT(dest, start_time, info.start_time);
  INSERT_INTO_JSON_OBJECT(dest, version, info.version);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::DaemonInfo& info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  uint64_t difficulty_top64 = 0;
  uint64_t cumulative_difficulty_top64 = 0;

  GET_FROM_JSON_OBJECT(val, info.height, height);
  GET_FROM_JSON_OBJECT(val, info.target_height, target_height);
  GET_FROM_JSON_OBJECT(val, info.top_block_height, top_block_height);
  GET_FROM_JSON_OBJECT(val, info.difficulty, difficulty);
  GET_FROM_JSON_OBJECT(val, difficulty_top64, difficulty_top64);
  GET_FROM_JSON_OBJECT(val, info.target, target);
  GET_FROM_JSON_OBJECT(val, info.tx_count, tx_count);
  GET_FROM_JSON_OBJECT(val, info.tx_pool_size, tx_pool_size);
  GET_FROM_JSON_OBJECT(val, info.alt_blocks_count, alt_blocks_count);
  GET_FROM_JSON_OBJECT(val, info.outgoing_connections_count, outgoing_connections_count);
  GET_FROM_JSON_OBJECT(val, info.incoming_connections_count, incoming_connections_count);
  GET_FROM_JSON_OBJECT(val, info.white_peerlist_size, white_peerlist_size);
  GET_FROM_JSON_OBJECT(val, info.grey_peerlist_size, grey_peerlist_size);
  GET_FROM_JSON_OBJECT(val, info.mainnet, mainnet);
  GET_FROM_JSON_OBJECT(val, info.testnet, testnet);
  GET_FROM_JSON_OBJECT(val, info.stagenet, stagenet);
  GET_FROM_JSON_OBJECT(val, info.nettype, nettype);
  GET_FROM_JSON_OBJECT(val, info.top_block_hash, top_block_hash);
  GET_FROM_JSON_OBJECT(val, info.cumulative_difficulty, cumulative_difficulty);
  GET_FROM_JSON_OBJECT(val, cumulative_difficulty_top64, cumulative_difficulty_top64);
  GET_FROM_JSON_OBJECT(val, info.block_size_limit, block_size_limit);
  GET_FROM_JSON_OBJECT(val, info.block_weight_limit, block_weight_limit);
  GET_FROM_JSON_OBJECT(val, info.block_size_median, block_size_median);
  GET_FROM_JSON_OBJECT(val, info.block_weight_median, block_weight_median);
  GET_FROM_JSON_OBJECT(val, info.adjusted_time, adjusted_time);
  GET_FROM_JSON_OBJECT(val, info.start_time, start_time);
  GET_FROM_JSON_OBJECT(val, info.version, version);

  info.wide_difficulty = difficulty_top64;
  info.wide_difficulty <<= 64;
  info.wide_difficulty += info.difficulty;

  info.wide_cumulative_difficulty = cumulative_difficulty_top64;
  info.wide_cumulative_difficulty <<= 64;
  info.wide_cumulative_difficulty += info.cumulative_difficulty;
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::rpc::output_distribution& dist)
{
  dest.StartObject();

  INSERT_INTO_JSON_OBJECT(dest, distribution, dist.data.distribution);
  INSERT_INTO_JSON_OBJECT(dest, amount, dist.amount);
  INSERT_INTO_JSON_OBJECT(dest, start_height, dist.data.start_height);
  INSERT_INTO_JSON_OBJECT(dest, base, dist.data.base);

  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_distribution& dist)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, dist.data.distribution, distribution);
  GET_FROM_JSON_OBJECT(val, dist.amount, amount);
  GET_FROM_JSON_OBJECT(val, dist.data.start_height, start_height);
  GET_FROM_JSON_OBJECT(val, dist.data.base, base);
}

void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const cryptonote::tx_block_template_backlog_entry& entry)
{
  dest.StartObject();
  INSERT_INTO_JSON_OBJECT(dest, id, entry.id);
  INSERT_INTO_JSON_OBJECT(dest, weight, entry.weight);
  INSERT_INTO_JSON_OBJECT(dest, fee, entry.fee);
  dest.EndObject();
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::tx_block_template_backlog_entry& entry)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, entry.id, id);
  GET_FROM_JSON_OBJECT(val, entry.weight, weight);
  GET_FROM_JSON_OBJECT(val, entry.fee, fee);
}

}  // namespace json

}  // namespace cryptonote
