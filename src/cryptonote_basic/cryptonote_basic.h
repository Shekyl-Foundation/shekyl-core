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

#pragma once

#include <optional>
#include <variant>
#include <boost/functional/hash/hash.hpp>
#include <vector>
#include <type_traits>
#include <sstream>
#include <atomic>
#include "serialization/variant.h"
#include "serialization/containers.h"
#include "serialization/binary_archive.h"
#include "serialization/json_archive.h"
#include "serialization/debug_archive.h"
#include "serialization/crypto.h"
#include "serialization/keyvalue_serialization.h" // eepe named serialization
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "misc_language.h"
#include "fcmp/rctTypes.h"
#include "device/device.hpp"
#include "cryptonote_basic/fwd.h"

namespace cryptonote
{
  typedef std::vector<crypto::signature> ring_signature;

  // Migration alias: the inherited field name "rct_signatures" and type "rct::rctSig"
  // predate Shekyl's FCMP++ architecture. New code should use ct_signatures.
  // Full rename to ct:: namespace deferred to a separate PR.
  using ct_signatures = rct::rctSig;


  /* outputs */

  struct txout_to_script
  {
    std::vector<crypto::public_key> keys;
    std::vector<uint8_t> script;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(keys)
      FIELD(script)
    END_SERIALIZE()
  };

  struct txout_to_scripthash
  {
    crypto::hash hash;
  };

  // outputs <= HF_VERSION_VIEW_TAGS
  struct txout_to_key
  {
    txout_to_key() { }
    txout_to_key(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
  };

  // outputs >= HF_VERSION_VIEW_TAGS
  struct txout_to_tagged_key
  {
    txout_to_tagged_key() { }
    txout_to_tagged_key(const crypto::public_key &_key, const crypto::view_tag &_view_tag) : key(_key), view_tag(_view_tag) { }
    crypto::public_key key;
    crypto::view_tag view_tag; // optimization to reduce scanning time

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(view_tag)
    END_SERIALIZE()
  };

  /* inputs */

  struct txin_gen
  {
    size_t height;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(height)
    END_SERIALIZE()
  };

  struct txin_to_script
  {
    crypto::hash prev;
    size_t prevout;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_scripthash
  {
    crypto::hash prev;
    size_t prevout;
    txout_to_script script;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(script)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_key
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(key_offsets)
      FIELD(k_image)
    END_SERIALIZE()
  };

  enum class archival_bond_post_kind : uint8_t
  {
    JoinMarket = 0,
    Rebond = 1,
    Unbond = 2,
    HoldingsUpdate = 3,
  };

  enum class archival_holdings_kind : uint8_t
  {
    ShardSetCompact = 0,
    CompleteTree = 1,
  };

  struct archival_holdings_descriptor
  {
    archival_holdings_kind kind = archival_holdings_kind::ShardSetCompact;
    std::vector<uint64_t> shard_ids;

    BEGIN_SERIALIZE_OBJECT()
      uint8_t kind_u8 = static_cast<uint8_t>(kind);
      FIELD(kind_u8)
      if (kind_u8 > static_cast<uint8_t>(archival_holdings_kind::CompleteTree))
        return false;
      kind = static_cast<archival_holdings_kind>(kind_u8);
      if (kind == archival_holdings_kind::ShardSetCompact)
      {
        FIELD(shard_ids)
        if (shard_ids.size() > config::ARCHIVAL_MAX_HOLDINGS_SHARDS)
          return false;
      }
      else if (!shard_ids.empty())
        return false;
    END_SERIALIZE()
  };

  // Gate-4 §3.4.1 — archival bond-post vin (dense tag 0x03; see VARIANT_TAG below).
  struct txin_archival_bond_post
  {
    std::vector<uint8_t> hybrid_public_key;
    crypto::hash p_canonical_id;
    uint8_t post_kind;
    // GF-1 debit authorizer (gate-4 §4.1 / gate-6 §9.6), JoinMarket-coupled on
    // the wire (§9.11, matching the Rust bond wire and shekyl-wire): present
    // with the exact canonical single-key length iff post_kind == JoinMarket,
    // empty (and absent from the wire) on every other kind. Committed once
    // into the bond record at JoinMarket connect; every later bond_debit
    // verifies against the committed copy, never the identity key.
    std::vector<uint8_t> bond_spend_pk;
    archival_holdings_descriptor holdings;
    uint64_t bonded_total_atomic;
    uint64_t bond_credit;
    uint64_t bond_debit;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(hybrid_public_key)
      // Exact canonical single-key length: a truncated key is malformed, not a
      // shorter valid key (matches the Rust bond wire + blockchain.cpp's
      // structural check; PR #229 review).
      if (hybrid_public_key.size() != config::PQC_HYBRID_SINGLE_KEY_LEN)
        return false;
      FIELD(p_canonical_id)
      FIELD(post_kind)
      if (post_kind > static_cast<uint8_t>(archival_bond_post_kind::HoldingsUpdate))
        return false;
      if (post_kind == static_cast<uint8_t>(archival_bond_post_kind::JoinMarket))
      {
        FIELD(bond_spend_pk)
        if (bond_spend_pk.size() != config::PQC_HYBRID_SINGLE_KEY_LEN)
          return false;
      }
      else if (!bond_spend_pk.empty())
      {
        // §9.11 coupling: only JoinMarket carries the debit authorizer. On
        // read this branch is unreachable (the field is default-empty); on
        // write it makes a misconstruction loud instead of silently dropping
        // the key from the emitted bytes.
        return false;
      }
      FIELD(holdings)
      VARINT_FIELD(bonded_total_atomic)
      VARINT_FIELD(bond_credit)
      VARINT_FIELD(bond_debit)
    END_SERIALIZE()
  };

  // Gate-2 §5.1 — archival serve-credit response vin (dense tag 0x02; see VARIANT_TAG below).
  // RF-D1 / rule 40 (ARCHIVAL_RESPONSE_FORMAT.md §3.5): the serve-credit vin
  // is the KEPT half of a pass record as an OPAQUE blob, the same shape as
  // txin_archival_reward_emission. `canonical_bytes` is the complete Rust
  // canonical encoding (leading wire tag 0x02 included); the retention codec
  // owns the layout, the parse and every structural bound. C++ never reads
  // inside: the three fields consensus indexes by -- (P, shard, E) -- come
  // through `shekyl_archival_serve_credit_extract`, and admission verifies
  // through `shekyl_archival_verify_serve_credit_vin` with this vin's pruned
  // record (rctSig.p.serve_credit_pruned[i]) alongside.
  //
  // This used to be a typed struct with nine fields. Two of those were values
  // the verifier derives (RF-D6), one more was the challenged leaf the
  // verifier reads from its own chunk (RF-D8), and the signature container
  // was split across the kept/pruned boundary (RF-D2). What remained was a
  // second codec of one layout, and two codecs of one layout drift.
  constexpr uint8_t TXIN_ARCHIVAL_SERVE_CREDIT_WIRE_TAG = 0x02;

  struct txin_archival_serve_credit_response
  {
    std::vector<uint8_t> canonical_bytes;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(canonical_bytes)
      // Transport-layer shape only (allocation bound + wire-tag echo); a blob
      // passing here can still be garbage -- the Rust parser is the validator.
      if (canonical_bytes.size() < 2 || canonical_bytes.size() > config::ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES)
        return false;
      if (canonical_bytes[0] != TXIN_ARCHIVAL_SERVE_CREDIT_WIRE_TAG)
        return false;
    END_SERIALIZE()
  };


  // C-1 (REWARD_EMISSION_VIN_PLAN.md PR-E2 shim, reassigned to C-1) — archival
  // reward-emission vin (dense tag 0x04; see VARIANT_TAG below). Thin transport
  // only: the field is the complete Rust canonical encoding (leading wire tag
  // 0x04 included — emission_wire.rs owns the codec, the parse, and every
  // structural bound; single source of truth). C++ never reads inside the blob;
  // consensus code that needs fields (the block-level (P,E) pass, dispatch)
  // obtains them through the shekyl_emission_* FFI parse, never a C++ decode.
  // Wire tag for the archival reward-emission vin — the single C++ source for
  // the three sites that MUST agree on the byte: this struct's transport guard,
  // the VARIANT_TAG registration (below), and json_object.cpp's tag echo.
  // Mirrors Rust's VIN_TYPE_ARCHIVAL_REWARD_EMISSION (emission_wire.rs owns the
  // codec). The dense-tag registry has renumbered before (0x06 -> 0x04); a named
  // constant means a future renumber touches one line, not three scattered ones.
  constexpr uint8_t TXIN_ARCHIVAL_REWARD_EMISSION_WIRE_TAG = 0x04;

  struct txin_archival_reward_emission
  {
    std::vector<uint8_t> canonical_bytes;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(canonical_bytes)
      // Transport-layer shape only (allocation bound + wire-tag echo); a blob
      // passing here can still be garbage — the Rust parser is the validator.
      if (canonical_bytes.size() < 2 || canonical_bytes.size() > config::ARCHIVAL_EMISSION_VIN_MAX_BYTES)
        return false;
      if (canonical_bytes[0] != TXIN_ARCHIVAL_REWARD_EMISSION_WIRE_TAG)
        return false;
    END_SERIALIZE()
  };

  typedef std::variant<txin_gen, txin_to_script, txin_to_scripthash, txin_to_key, txin_archival_serve_credit_response, txin_archival_bond_post, txin_archival_reward_emission> txin_v;

  // The txin_to_key (spend) subset of vin. This count — not vin.size() — sizes
  // the prunable pseudoOuts array: an archival bond-post vin occupies a
  // pqc_auths slot but carries no pseudo-out (its cleartext bond_credit rides
  // the CT balance instead; see rctTypes.h serialize_ctsig_prunable). For a
  // pure spend every vin is txin_to_key, so the two counts coincide. The
  // authoritative wire definition is Rust-side (shekyl-wire, GENESIS_TX_WIRE_FORMAT.md
  // §9.9); this helper keeps the C++ parser byte-aligned with it.
  inline size_t count_spend_inputs(const std::vector<txin_v>& vin)
  {
    size_t n = 0;
    for (const auto& in : vin)
      if (std::holds_alternative<txin_to_key>(in))
        ++n;
    return n;
  }

  // The serve-credit subset of vin. This count -- not vin.size() -- sizes the
  // prunable region's pruned pass-record array (RF-D1: one record per
  // serve-credit vin, in vin order, no count on the wire).
  inline size_t count_serve_credit_inputs(const std::vector<txin_v>& vin)
  {
    size_t n = 0;
    for (const auto& in : vin)
      if (std::holds_alternative<txin_archival_serve_credit_response>(in))
        ++n;
    return n;
  }

  // Archival special-vin taxonomy. A tx is exactly one of: a pure serve-credit
  // response (every vin a serve-credit), a bond-post, a reward-emission (each
  // carrying ONE special vin with every co-resident a key-imaged spend — the
  // Q11 mixing rule, arity 1 per Q3 §2.1), or `none` (a regular FCMP++ spend,
  // which the special branches fall through to). This classification is
  // consensus and is consumed by three sites that MUST agree on what a given tx
  // is — check_tx_inputs (CT dispatch), check_tx_outputs (the v3
  // zero-plaintext-vout carve-out for emission reward vouts), and
  // ver_non_input_consensus (RCT semantics) — so the predicate lives here once
  // (REWARD_EMISSION_E3_GATING_ROUND.md §2.2 / §9.5). Do not re-open-code it: a
  // second copy that drifts splits validators on whether a tx is an emission tx.
  enum class archival_tx_kind { none, serve_credit_only, bond_post, emission };

  struct archival_tx_classification
  {
    archival_tx_kind kind = archival_tx_kind::none;
    size_t special_index = 0;      // index of the bond-post / emission vin (kind-dependent)
    size_t spend_input_count = 0;  // co-resident txin_to_key spends
  };

  inline archival_tx_classification classify_archival_tx(const std::vector<txin_v>& vin)
  {
    archival_tx_classification c;
    if (vin.empty())
      return c;
    bool serve_credit_only = true;
    size_t bond_post_count = 0, emission_count = 0, to_key_count = 0;
    size_t bond_post_index = 0, emission_index = 0;
    for (size_t i = 0; i < vin.size(); ++i)
    {
      const auto& in = vin[i];
      if (!std::holds_alternative<txin_archival_serve_credit_response>(in))
        serve_credit_only = false;
      if (std::holds_alternative<txin_archival_bond_post>(in))
      {
        ++bond_post_count;
        bond_post_index = i;
      }
      else if (std::holds_alternative<txin_archival_reward_emission>(in))
      {
        ++emission_count;
        emission_index = i;
      }
      else if (std::holds_alternative<txin_to_key>(in))
        ++to_key_count;
    }
    c.spend_input_count = to_key_count;
    if (serve_credit_only)
      c.kind = archival_tx_kind::serve_credit_only;
    else if (bond_post_count == 1 && emission_count == 0 && to_key_count + 1 == vin.size())
    {
      c.kind = archival_tx_kind::bond_post;
      c.special_index = bond_post_index;
    }
    else if (emission_count == 1 && bond_post_count == 0 && to_key_count + 1 == vin.size())
    {
      c.kind = archival_tx_kind::emission;
      c.special_index = emission_index;
    }
    return c;
  }

  // Whether a tx carries any archival reward-emission vin. Emission reward vouts
  // store (add_transaction) and remove (remove_tx_outputs) as amount-0 RCT
  // records with their outPk commitment kept; the store and remove sides MUST
  // gate on the SAME predicate or a block pop corrupts the output index, so the
  // check lives here once (C-1, REWARD_EMISSION_E3_GATING_ROUND.md §9.5 item 7).
  // Deliberately the loose "has an emission vin" storage predicate, distinct
  // from classify_archival_tx's strict well-formedness used in consensus verify.
  inline bool tx_has_archival_emission_vin(const std::vector<txin_v>& vin)
  {
    for (const auto& in : vin)
      if (std::holds_alternative<txin_archival_reward_emission>(in))
        return true;
    return false;
  }

  typedef std::variant<txout_to_script, txout_to_scripthash, txout_to_key, txout_to_tagged_key> txout_target_v;

  //typedef std::pair<uint64_t, txout> out_t;
  struct tx_out
  {
    uint64_t amount;
    txout_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()


  };

  struct pqc_authentication
  {
    uint8_t auth_version;
    uint8_t scheme_id;
    uint16_t flags;
    std::vector<uint8_t> hybrid_public_key;   // canonical HybridPublicKey
    std::vector<uint8_t> hybrid_signature;    // canonical HybridSignature

    BEGIN_SERIALIZE_OBJECT()
      FIELD(auth_version)
      FIELD(scheme_id)
      FIELD(flags)
      FIELD(hybrid_public_key)
      if (hybrid_public_key.size() > config::PQC_MAX_PUBLIC_KEY_BLOB)
        return false;
      FIELD(hybrid_signature)
      if (hybrid_signature.size() > config::PQC_MAX_SIGNATURE_BLOB)
        return false;
    END_SERIALIZE()
  };

  class transaction_prefix
  {

  public:
    // tx information
    size_t   version;
    uint64_t unlock_time;  //number of block (or time), used as a limitation like: spend this tx not early then block/time

    std::vector<txin_v> vin;
    std::vector<tx_out> vout;
    //extra
    std::vector<uint8_t> extra;

    BEGIN_SERIALIZE()
      VARINT_FIELD(version)
      if(version == 0 || CURRENT_TRANSACTION_VERSION < version) return false;
      VARINT_FIELD(unlock_time)
      FIELD(vin)
      FIELD(vout)
      FIELD(extra)
    END_SERIALIZE()

  public:
    transaction_prefix(){ set_null(); }
    void set_null()
    {
      version = 1;
      unlock_time = 0;
      vin.clear();
      vout.clear();
      extra.clear();
    }
  };

  class transaction: public transaction_prefix
  {
  private:
    // hash cash
    mutable std::atomic<bool> hash_valid;
    mutable std::atomic<bool> prunable_hash_valid;
    mutable std::atomic<bool> blob_size_valid;

  public:
    std::vector<std::vector<crypto::signature> > signatures; //count signatures  always the same as inputs count
    rct::rctSig rct_signatures;
    std::vector<pqc_authentication> pqc_auths; // one per input for FCMP++ txs

    // hash cash
    mutable crypto::hash hash;
    mutable crypto::hash prunable_hash;
    mutable size_t blob_size;

    bool pruned;

    std::atomic<unsigned int> unprunable_size;
    /** Byte offset from tx blob start where pqc_auths begin (binary only); equals unprunable_size if absent. */
    std::atomic<unsigned int> pqc_auths_offset;
    std::atomic<unsigned int> prefix_size;

    transaction();
    transaction(const transaction &t);
    transaction &operator=(const transaction &t);
    virtual ~transaction();
    void set_null();
    void invalidate_hashes();
    bool is_hash_valid() const { return hash_valid.load(std::memory_order_acquire); }
    void set_hash_valid(bool v) const { hash_valid.store(v,std::memory_order_release); }
    bool is_prunable_hash_valid() const { return prunable_hash_valid.load(std::memory_order_acquire); }
    void set_prunable_hash_valid(bool v) const { prunable_hash_valid.store(v,std::memory_order_release); }
    bool is_blob_size_valid() const { return blob_size_valid.load(std::memory_order_acquire); }
    void set_blob_size_valid(bool v) const { blob_size_valid.store(v,std::memory_order_release); }
    void set_hash(const crypto::hash &h) const { hash = h; set_hash_valid(true); }
    void set_prunable_hash(const crypto::hash &h) const { prunable_hash = h; set_prunable_hash_valid(true); }
    void set_blob_size(size_t sz) const { blob_size = sz; set_blob_size_valid(true); }

    BEGIN_SERIALIZE_OBJECT()
      if (!typename Archive<W>::is_saving())
      {
        set_hash_valid(false);
        set_prunable_hash_valid(false);
        set_blob_size_valid(false);
      }

      const auto start_pos = ar.getpos();

      FIELDS(*static_cast<transaction_prefix *>(this))

      if (std::is_same<Archive<W>, binary_archive<W>>())
        prefix_size = ar.getpos() - start_pos;

      if (version == 1)
      {
        if (std::is_same<Archive<W>, binary_archive<W>>())
          unprunable_size = ar.getpos() - start_pos;

        ar.tag("signatures");
        ar.begin_array();
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), signatures);
        bool signatures_not_expected = signatures.empty();
        if (!signatures_not_expected && vin.size() != signatures.size())
          return false;

        if (!pruned) for (size_t i = 0; i < vin.size(); ++i)
        {
          size_t signature_size = get_signature_size(vin[i]);
          if (signatures_not_expected)
          {
            if (0 == signature_size)
              continue;
            else
              return false;
          }

          PREPARE_CUSTOM_VECTOR_SERIALIZATION(signature_size, signatures[i]);
          if (signature_size != signatures[i].size())
            return false;

          FIELDS(signatures[i]);

          if (vin.size() - i > 1)
            ar.delimit_array();
        }
        ar.end_array();
      }
      else
      {
        // The tag is a JSON-archive-only key (binary_archive::tag is a no-op,
        // so the binary wire format is unaffected); it names the CT signature
        // data in `decode_as_json` / `print_tx` / tx-pool JSON output.
        ar.tag("ct_signatures");
        if (!vin.empty())
        {
          ar.begin_object();
          bool r = rct_signatures.serialize_rctsig_base(ar, vin.size(), vout.size());
          if (!r || !ar.good()) return false;
          ar.end_object();
        }
        if (std::is_same<Archive<W>, binary_archive<W>>())
          pqc_auths_offset = ar.getpos() - start_pos;
        if (!serialize_pqc_auths(ar))
          return false;
        if (!vin.empty())
        {
          if (std::is_same<Archive<W>, binary_archive<W>>())
            unprunable_size = ar.getpos() - start_pos;

          if (!pruned && rct_signatures.type != rct::CTTypeNull)
          {
            // pseudoOuts are sized by the spend subset, not vin.size() — see
            // count_spend_inputs. Matches the consensus pins in blockchain.cpp
            // / tx_verification_utils.cpp (`pseudoOuts.size() == num_spend`).
            ar.tag("ctsig_prunable");
            ar.begin_object();
            bool r = rct_signatures.p.serialize_ctsig_prunable(ar, rct_signatures.type, count_spend_inputs(vin), count_serve_credit_inputs(vin), vout.size());
            if (!r || !ar.good()) return false;
            ar.end_object();
          }
        }
      }
      if (!typename Archive<W>::is_saving())
        pruned = false;
    END_SERIALIZE()

    // The tx-level `pqc_auths` encoding, in ONE place.
    //
    // It used to be written out twice -- here in the full serializer and again
    // in `serialize_base` -- and the two copies drifted inside a single change:
    // the RF-D9 serve-credit exemption landed in one and not the other, so a
    // serve-credit tx became writable by the full serializer while the pruned
    // form LMDB and the RPC use (`serialize_base`) still refused it. A duplicate
    // is not synchronised, it is deleted (rule 15); both serializers now call
    // this.
    //
    // RF-D9. The serve-credit shape carries NO pqc_auths at all: the
    // countersignature attests a *read* and rides the vin, while pqc_auths is
    // per-input *spend* authorization (blockchain.cpp:3746, "signature is on
    // the vin"). Consensus requires the vector empty
    // (tx_verification_utils.cpp:118).
    //
    // Deciding that from the vin TYPES -- already parsed by the time this runs
    // -- rather than by sniffing for EOF is what makes the write path possible
    // at all. Before, the tolerance was guarded by `binary_archive<false>` and
    // so existed only when READING: a serve-credit tx could be parsed and never
    // produced, because `pqc_auths.size() != vin.size()` rejected the empty
    // vector consensus mandates. The shape is a property of the transaction,
    // not of how far a stream has been consumed, so it is read off the
    // transaction.
    template<bool W, template <bool> class Archive>
    bool serialize_pqc_auths(Archive<W> &ar)
    {
      if (!(version >= 3 && !vin.empty() && !std::holds_alternative<txin_gen>(vin[0])))
        return true;
      const bool serve_credit_shape =
        classify_archival_tx(vin).kind == archival_tx_kind::serve_credit_only;
      bool read_pqc = !serve_credit_shape;
      if (serve_credit_shape)
      {
        // Saving: REFUSE a non-empty vector, never normalise it. A serializer
        // is a faithful encoder, not a validator that rewrites its input --
        // clearing here would mutate a (const_cast) object and emit the bytes
        // of a different, valid transaction, silently. The pre-RF-D9 code
        // rejected the mismatch; that behaviour is kept. Loading: nothing is
        // read for this shape, so the vector is "read as zero elements" --
        // clear() is the correct deserialisation of an absent array.
        if constexpr (typename Archive<W>::is_saving())
        {
          if (!pqc_auths.empty())
            return false;
        }
        else
          pqc_auths.clear();
      }
      if constexpr (std::is_same_v<Archive<W>, binary_archive<false>>)
      {
        // Retained for the storage-pruned full-spend form, which is a
        // stream-position fact and genuinely cannot be typed off the vin.
        if (ar.eof() || ar.remaining_bytes() == 0)
        {
          read_pqc = false;
          pqc_auths.clear();
        }
      }
      if (!read_pqc)
        return true;
      ar.tag("pqc_auths");
      ar.begin_array();
      PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), pqc_auths);
      if (pqc_auths.size() != vin.size())
        return false;
      for (size_t i = 0; i < vin.size(); ++i)
      {
        FIELDS(pqc_auths[i])
        if (vin.size() - i > 1)
          ar.delimit_array();
      }
      ar.end_array();
      return ar.good();
    }

    template<bool W, template <bool> class Archive>
    bool serialize_base(Archive<W> &ar)
    {
      const auto start_pos = ar.getpos();
      FIELDS(*static_cast<transaction_prefix *>(this))

      if (version == 1)
      {
      }
      else
      {
        // JSON-archive-only key; see the do_serialize note above.
        ar.tag("ct_signatures");
        if (!vin.empty())
        {
          ar.begin_object();
          bool r = rct_signatures.serialize_rctsig_base(ar, vin.size(), vout.size());
          if (!r || !ar.good()) return false;
          ar.end_object();
        }
        if (std::is_same<Archive<W>, binary_archive<W>>())
          pqc_auths_offset = ar.getpos() - start_pos;
        if (!serialize_pqc_auths(ar))
          return false;
      }
      if (!typename Archive<W>::is_saving())
        pruned = true;
      if (std::is_same<Archive<W>, binary_archive<W>>())
        unprunable_size = ar.getpos() - start_pos;
      return ar.good();
    }

  private:
    static size_t get_signature_size(const txin_v& tx_in);
  };

  inline transaction::transaction(const transaction &t):
    transaction_prefix(t),
    hash_valid(false),
    prunable_hash_valid(false),
    blob_size_valid(false),
    signatures(t.signatures),
    rct_signatures(t.rct_signatures),
    pqc_auths(t.pqc_auths),
    pruned(t.pruned),
    unprunable_size(t.unprunable_size.load()),
    pqc_auths_offset(t.pqc_auths_offset.load()),
    prefix_size(t.prefix_size.load())
  {
    if (t.is_hash_valid())
    {
      hash = t.hash;
      set_hash_valid(true);
    }
    if (t.is_blob_size_valid())
    {
      blob_size = t.blob_size;
      set_blob_size_valid(true);
    }
    if (t.is_prunable_hash_valid())
    {
      prunable_hash = t.prunable_hash;
      set_prunable_hash_valid(true);
    }
  }

  inline transaction &transaction::operator=(const transaction &t)
  {
    transaction_prefix::operator=(t);

    set_hash_valid(false);
    set_prunable_hash_valid(false);
    set_blob_size_valid(false);
    signatures = t.signatures;
    rct_signatures = t.rct_signatures;
    pqc_auths = t.pqc_auths;
    if (t.is_hash_valid())
    {
      hash = t.hash;
      set_hash_valid(true);
    }
    if (t.is_prunable_hash_valid())
    {
      prunable_hash = t.prunable_hash;
      set_prunable_hash_valid(true);
    }
    if (t.is_blob_size_valid())
    {
      blob_size = t.blob_size;
      set_blob_size_valid(true);
    }
    pruned = t.pruned;
    unprunable_size = t.unprunable_size.load();
    pqc_auths_offset = t.pqc_auths_offset.load();
    prefix_size = t.prefix_size.load();
    return *this;
  }

  inline
  transaction::transaction()
  {
    set_null();
  }

  inline
  transaction::~transaction()
  {
  }

  inline
  void transaction::set_null()
  {
    transaction_prefix::set_null();
    signatures.clear();
    rct_signatures.type = rct::CTTypeNull;
    pqc_auths.clear();
    set_hash_valid(false);
    set_prunable_hash_valid(false);
    set_blob_size_valid(false);
    pruned = false;
    unprunable_size = 0;
    pqc_auths_offset = 0;
    prefix_size = 0;
  }

  inline
  void transaction::invalidate_hashes()
  {
    set_hash_valid(false);
    set_prunable_hash_valid(false);
    set_blob_size_valid(false);
  }

  inline
  size_t transaction::get_signature_size(const txin_v& tx_in)
  {
    struct txin_signature_size_visitor
    {
      size_t operator()(const txin_gen& txin) const{return 0;}
      size_t operator()(const txin_to_script& txin) const{return 0;}
      size_t operator()(const txin_to_scripthash& txin) const{return 0;}
      size_t operator()(const txin_to_key& txin) const {return txin.key_offsets.size();}
      size_t operator()(const txin_archival_serve_credit_response& txin) const {return 0;}
      size_t operator()(const txin_archival_bond_post& txin) const {return 0;}
      // Emission auths live inside the canonical blob (Rust-verified), not in
      // the C++ signatures array.
      size_t operator()(const txin_archival_reward_emission& txin) const {return 0;}
    };

    return std::visit(txin_signature_size_visitor(), tx_in);
  }



  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  // Empty-set archival attestation root: Rust `attestation_root(&[])` via
  // shekyl_attestation_root_empty. Cached; the sole valid empty commitment —
  // never null_hash (ARCHIVAL_CREDIT_WIRE.md §3).
  const crypto::hash& empty_attestation_root();

  struct block_header
  {
    uint8_t major_version;
    uint8_t minor_version;  // now used as a voting mechanism, rather than how this particular block is built
    uint64_t timestamp;
    crypto::hash  prev_id;
    uint32_t nonce;
    crypto::hash  curve_tree_root; // FCMP++ curve tree root after this block's outputs
    crypto::hash  attestation_root; // archival credit-wire attestation root over this block's pass records (ARCHIVAL_CREDIT_WIRE.md §3)

    block_header()
      : major_version(0), minor_version(0), timestamp(0), prev_id(crypto::null_hash),
        nonce(0), curve_tree_root(crypto::null_hash),
        attestation_root(empty_attestation_root()) {}

    BEGIN_SERIALIZE()
      VARINT_FIELD(major_version)
      VARINT_FIELD(minor_version)
      VARINT_FIELD(timestamp)
      FIELD(prev_id)
      FIELD(nonce)
      FIELD(curve_tree_root)
      FIELD(attestation_root)
    END_SERIALIZE()
  };

  struct block: public block_header
  {
  private:
    // hash cash
    mutable std::atomic<bool> hash_valid;

  public:
    block(): block_header(), hash_valid(false) {}
    block(const block &b): block_header(b), hash_valid(false), miner_tx(b.miner_tx), tx_hashes(b.tx_hashes) { if (b.is_hash_valid()) { hash = b.hash; set_hash_valid(true); } }
    block &operator=(const block &b) { block_header::operator=(b); hash_valid = false; miner_tx = b.miner_tx; tx_hashes = b.tx_hashes; if (b.is_hash_valid()) { hash = b.hash; set_hash_valid(true); } return *this; }
    void invalidate_hashes() { set_hash_valid(false); }
    bool is_hash_valid() const { return hash_valid.load(std::memory_order_acquire); }
    void set_hash_valid(bool v) const { hash_valid.store(v,std::memory_order_release); }
    void set_hash(const crypto::hash &h) const { hash = h; set_hash_valid(true); }

    transaction miner_tx;
    std::vector<crypto::hash> tx_hashes;

    // hash cash
    mutable crypto::hash hash;

    BEGIN_SERIALIZE_OBJECT()
      if (!typename Archive<W>::is_saving())
        set_hash_valid(false);

      FIELDS(*static_cast<block_header *>(this))
      FIELD(miner_tx)
      FIELD(tx_hashes)
      if (tx_hashes.size() > CRYPTONOTE_MAX_TX_PER_BLOCK)
        return false;
    END_SERIALIZE()
  };


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct account_public_address
  {
    crypto::public_key m_spend_public_key;
    crypto::public_key m_view_public_key;
    // Invariant: 1216 bytes = X25519_pub[0..32] || ML-KEM-768_ek[32..1216].
    // X25519_pub is derived from m_view_public_key via Edwards→Montgomery map.
    // Canonical assemblers: get_account_address_from_str, generate_pqc_key_material.
    // See SHEKYL_PQC_PUBLIC_KEY_BYTES in shekyl_ffi.h.
    std::vector<uint8_t> m_pqc_public_key;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(m_spend_public_key)
      FIELD(m_view_public_key)
      FIELD(m_pqc_public_key)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_spend_public_key)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_view_public_key)
      KV_SERIALIZE_OPT(m_pqc_public_key, std::vector<uint8_t>())
    END_KV_SERIALIZE_MAP()

    bool operator==(const account_public_address& rhs) const
    {
      return m_spend_public_key == rhs.m_spend_public_key &&
             m_view_public_key == rhs.m_view_public_key &&
             m_pqc_public_key == rhs.m_pqc_public_key;
    }

    bool operator!=(const account_public_address& rhs) const
    {
      return !(*this == rhs);
    }
  };

  static_assert(!std::is_trivially_copyable_v<account_public_address>,
    "account_public_address is non-POD (includes m_pqc_public_key); never memcmp the struct");

  struct keypair
  {
    crypto::public_key pub;
    crypto::secret_key sec;

    static inline keypair generate(hw::device &hwdev)
    {
      keypair k;
      hwdev.generate_keys(k.pub, k.sec);
      return k;
    }
  };
  //---------------------------------------------------------------

}

namespace std {
  template <>
  struct hash<cryptonote::account_public_address>
  {
    std::size_t operator()(const cryptonote::account_public_address& addr) const
    {
      // https://stackoverflow.com/a/17017281
      size_t res = 17;
      res = res * 31 + hash<crypto::public_key>()(addr.m_spend_public_key);
      res = res * 31 + hash<crypto::public_key>()(addr.m_view_public_key);
      res = res * 31 + boost::hash_range(addr.m_pqc_public_key.begin(), addr.m_pqc_public_key.end());
      return res;
    }
  };
}

BLOB_SERIALIZER(cryptonote::txout_to_key);
BLOB_SERIALIZER(cryptonote::txout_to_scripthash);

// Genesis dense tag scheme (GENESIS_TX_WIRE_FORMAT.md §2.0 / §5 gate-(c) item 2).
// Surviving genesis arms are numbered dense from 0x00; the shed CryptoNote/legacy
// arms (no genesis producer) are parked at 0xf0+ so they never collide with the
// active low tag space. Full type-removal of the parked arms is §5 item 1 — its
// own rule-60 cut (heavy consensus refactor; the dead types stay compile-present
// but off-wire until then).
VARIANT_TAG(binary_archive, cryptonote::txin_gen, 0x00);
VARIANT_TAG(binary_archive, cryptonote::txin_to_script, 0xf0);          // shed (parked)
VARIANT_TAG(binary_archive, cryptonote::txin_to_scripthash, 0xf1);      // shed (parked)
VARIANT_TAG(binary_archive, cryptonote::txin_to_key, 0x01);             // fcmp spend
VARIANT_TAG(binary_archive, cryptonote::txin_archival_serve_credit_response, 0x02);
VARIANT_TAG(binary_archive, cryptonote::txin_archival_bond_post, 0x03);
VARIANT_TAG(binary_archive, cryptonote::txin_archival_reward_emission, cryptonote::TXIN_ARCHIVAL_REWARD_EMISSION_WIRE_TAG);  // F-C1b: dense next-free, = Rust wire tag
VARIANT_TAG(binary_archive, cryptonote::txout_to_script, 0xf0);         // shed (parked)
VARIANT_TAG(binary_archive, cryptonote::txout_to_scripthash, 0xf1);     // shed (parked)
VARIANT_TAG(binary_archive, cryptonote::txout_to_key, 0xf2);            // shed (parked)
VARIANT_TAG(binary_archive, cryptonote::txout_to_tagged_key, 0x00);     // sole genesis output
VARIANT_TAG(binary_archive, cryptonote::transaction, 0xcc);
VARIANT_TAG(binary_archive, cryptonote::block, 0xbb);

VARIANT_TAG(json_archive, cryptonote::txin_gen, "gen");
VARIANT_TAG(json_archive, cryptonote::txin_to_script, "script");
VARIANT_TAG(json_archive, cryptonote::txin_to_scripthash, "scripthash");
VARIANT_TAG(json_archive, cryptonote::txin_to_key, "key");
VARIANT_TAG(json_archive, cryptonote::txin_archival_serve_credit_response, "archival_serve_credit_response");
VARIANT_TAG(json_archive, cryptonote::txin_archival_bond_post, "archival_bond_post");
VARIANT_TAG(json_archive, cryptonote::txin_archival_reward_emission, "archival_reward_emission");
VARIANT_TAG(json_archive, cryptonote::txout_to_script, "script");
VARIANT_TAG(json_archive, cryptonote::txout_to_scripthash, "scripthash");
VARIANT_TAG(json_archive, cryptonote::txout_to_key, "key");
VARIANT_TAG(json_archive, cryptonote::txout_to_tagged_key, "tagged_key");
VARIANT_TAG(json_archive, cryptonote::transaction, "tx");
VARIANT_TAG(json_archive, cryptonote::block, "block");

VARIANT_TAG(debug_archive, cryptonote::txin_gen, "gen");
VARIANT_TAG(debug_archive, cryptonote::txin_to_script, "script");
VARIANT_TAG(debug_archive, cryptonote::txin_to_scripthash, "scripthash");
VARIANT_TAG(debug_archive, cryptonote::txin_to_key, "key");
VARIANT_TAG(debug_archive, cryptonote::txin_archival_serve_credit_response, "archival_serve_credit_response");
VARIANT_TAG(debug_archive, cryptonote::txin_archival_bond_post, "archival_bond_post");
VARIANT_TAG(debug_archive, cryptonote::txin_archival_reward_emission, "archival_reward_emission");
VARIANT_TAG(debug_archive, cryptonote::txout_to_script, "script");
VARIANT_TAG(debug_archive, cryptonote::txout_to_scripthash, "scripthash");
VARIANT_TAG(debug_archive, cryptonote::txout_to_key, "key");
VARIANT_TAG(debug_archive, cryptonote::txout_to_tagged_key, "tagged_key");
VARIANT_TAG(debug_archive, cryptonote::transaction, "tx");
VARIANT_TAG(debug_archive, cryptonote::block, "block");
