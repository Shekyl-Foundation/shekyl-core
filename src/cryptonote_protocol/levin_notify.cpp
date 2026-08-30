// Copyright (c) 2019-2022, The Monero Project
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

/*! \file
    \brief Transport for Dandelion++ relay; the scheduling lives in Rust.

    RP-3a of `docs/design/DAEMON_RELAY_PRIVACY.md`. The stem map, the per-peer
    fluff batching and the epoch role moved to `shekyl-relay`; what stays here is
    epee framing, padding, the socket, and the boost::asio timer that sleeps.

    So this file is deliberately the layer with no decisions in it. It asks the
    zone what to do and does it. Any `if` here that re-derives something the zone
    already decided is a second copy of that decision — and this is the layer the
    `levin_notify` gtests structurally cannot see through, so a bug in it hides
    underneath a green suite (§18.4a). Read it for what it forwards, not for what
    it computes. */

#include "levin_notify.h"

#include <atomic>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/system_error.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <algorithm>
#include <map>
#include <limits>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include "byte_slice.h"
#include "net/levin_base.h"
#include "common/expect.h"
#include "common/varint.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/connection_context.h"
#include "cryptonote_core/i_core_events.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "p2p/net_node.h"
#include "shekyl/shekyl_ffi.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "net.p2p.tx"

namespace cryptonote
{
namespace levin
{
  /*! Development opt-in for the noise carrier. Defaults OFF, and the
      default is the shipped behaviour.

      A RUNTIME switch rather than a compile-time one, and that is the
      difference between a gate and a hope. Behind `#ifdef` the only
      configuration that reaches the carrier is the one CI never builds, so
      the code would be untestable by the repository's own gate — the
      failure mode a reviewer named on the first draft. Defaulting off and
      letting a test turn it on means the carrier's path is exercised by the
      ordinary suite, and every existing `has_noise == false` fixture keeps
      passing untouched because the default did not move.

      NOT an operator switch, and §3.1 of `COVER_TRAFFIC_RESTORATION.md` is
      the ruling rather than the caution: one encrypted zone has ONE embargo
      distribution, the carrier moves `hop` by ~9x, and a carrier-adaptive
      embargo is refused by §18's argument at its third application. Enabling
      this under today's constants runs the zone's alpha below the 0.90 pin.
      It exists so the mechanism can be built and tested before the two
      reopening criteria are met, not so an operator can choose it. */
  std::atomic<bool>& carrier_development_flag() noexcept
  {
    static std::atomic<bool> enabled{false};
    return enabled;
  }

  bool carrier_development_enabled() noexcept
  {
    return carrier_development_flag().load(std::memory_order_relaxed);
  }

  bool set_carrier_development(const bool enabled) noexcept
  {
    return carrier_development_flag().exchange(enabled, std::memory_order_relaxed);
  }

  namespace
  {
    constexpr const std::size_t connection_id_reserve_size = 100;

    constexpr const std::chrono::minutes dandelionpp_min_epoch{CRYPTONOTE_DANDELIONPP_MIN_EPOCH};
    constexpr const std::chrono::seconds dandelionpp_epoch_range{CRYPTONOTE_DANDELIONPP_EPOCH_RANGE};


    /* The Dandelion++ fluff delay used to be drawn here, from a Poisson
       distribution over quarter-seconds. It is drawn in `shekyl-relay` now, from
       the memoryless family the derivation actually calls for — the inherited
       draw is F-4 of DAEMON_RELAY_PRIVACY.md, and it is gone rather than ported
       so it cannot be reintroduced by symmetry with a noise delay drawn here. */

    /* The relay FFI speaks whole milliseconds on the caller's own monotonic
       clock. `steady_clock`'s epoch is arbitrary but fixed for the process, so
       the two conversions below round-trip and the zone's deadlines land back on
       the same timeline the timer waits on. */

    //! \return Now, in the millisecond clock the relay zone is driven on.
    std::uint64_t now_ms() noexcept
    {
      return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    //! \return `ms` from `now_ms()` as a point the `steady_timer` can wait on.
    std::chrono::steady_clock::time_point from_ms(const std::uint64_t ms) noexcept
    {
      return std::chrono::steady_clock::time_point{std::chrono::milliseconds{ms}};
    }

    static_assert(sizeof(boost::uuids::uuid) == 16, "connection ids cross the relay FFI as 16 raw bytes");
    static_assert(sizeof(crypto::hash) == 32, "tx hashes cross the relay FFI as packed 32-byte ids");

    //! §46: hand the stemmed txs to the zone's observation watch. The
    //! deadline is drawn Rust-side (zone-cached embargo timer); `source` is
    //! null for locally-originated (nil uuid), matching `in_mapping_[nil]`.
    void record_stem_observation(
      RelayZoneHandle* const relay,
      const std::vector<cryptonote::blobdata>& txs,
      const boost::uuids::uuid& destination,
      const boost::uuids::uuid& source)
    {
      const std::vector<crypto::hash> hashes = stem_watch_tx_hashes(txs);
      if (hashes.empty())
        return;
      const bool local = source.is_nil();
      shekyl_relay_zone_record_stem(
        relay, reinterpret_cast<const std::uint8_t*>(hashes.data()), hashes.size(),
        reinterpret_cast<const std::uint8_t*>(std::addressof(destination)),
        local ? nullptr : reinterpret_cast<const std::uint8_t*>(std::addressof(source)),
        now_ms()
      );
    }

    //! \return `id` as the 16 raw bytes the relay FFI reads.
    const std::uint8_t* uuid_bytes(const boost::uuids::uuid& id) noexcept
    {
      return reinterpret_cast<const std::uint8_t*>(std::addressof(id));
    }

    //! \return `ids` as a contiguous run of 16-byte ids, or nullptr when empty.
    const std::uint8_t* uuid_bytes(const std::vector<boost::uuids::uuid>& ids) noexcept
    {
      return ids.empty() ? nullptr : reinterpret_cast<const std::uint8_t*>(ids.data());
    }

    uint64_t get_median_remote_height(connections& p2p)
    {
        std::vector<uint64_t> remote_heights;
        remote_heights.reserve(connection_id_reserve_size);
        p2p.foreach_connection([&remote_heights] (detail::p2p_context& context) {
          if (!context.m_is_income)
          {
            remote_heights.emplace_back(context.m_remote_blockchain_height);
          }
          return true;
        });

        if (remote_heights.empty())
        {
          return 0;
        }

        const size_t n = remote_heights.size() / 2;
        std::sort(remote_heights.begin(), remote_heights.end());
        if (remote_heights.size() % 2 != 0)
        {
          return remote_heights[n];
        }
        return remote_heights[n-1];
    }

    uint64_t get_blockchain_height(connections& p2p, i_core_events* core)
    {
      const uint64_t local_blockchain_height = core->get_current_blockchain_height();
      if (core->is_synchronized())
      {
        return local_blockchain_height;
      }
      return std::max(local_blockchain_height, get_median_remote_height(p2p));
    }

    //! \return Outgoing connections supporting fragments in `connections` filtered by blockchain height.
    std::vector<boost::uuids::uuid> get_out_connections(connections& p2p, uint64_t blockchain_height)
    {
      std::vector<boost::uuids::uuid> outs;
      outs.reserve(connection_id_reserve_size);

      /* The foreach call is serialized with a lock, but should be quick due to
         the reserve call so a strand is not used. Investigate if there is lots
         of waiting in here. */

      p2p.foreach_connection([&outs, blockchain_height] (detail::p2p_context& context) {
        if (!context.m_is_income && context.m_remote_blockchain_height >= blockchain_height)
          outs.emplace_back(context.m_connection_id);
        return true;
      });

      MDEBUG("Found " << outs.size() << " out connections having height >= " << blockchain_height);
      return outs;
    }

    std::vector<boost::uuids::uuid> get_out_connections(connections& p2p, i_core_events* core)
    {
      return get_out_connections(p2p, get_blockchain_height(p2p, core));
    }

    //! How wide a zone's stem set is and how long its epoch runs.
    struct relay_zone_params
    {
      std::size_t stems;
      std::chrono::seconds min_epoch;
      std::chrono::seconds epoch_range;
    };

    /* The fragment-size guard MOVED TO RUST, which is what this comment's own
       FOLLOWUP asked for: "the constants should cross to Rust and `NoiseQueues`'
       window should be derived from them, at which point this assertion moves
       with them." Both `#define`s are gone from cryptonote_config.h; the window
       and the cap are `shekyl_relay_privacy::params::carrier`, derived rather
       than inherited, and the packet-size bound is asserted in that crate's
       `tests/carrier_window.rs` against levin's own DEFAULT_MAX_PACKET_SIZE
       instead of a second copy of the limit. The constraint is guarded in one
       language now because it only has constants in one. */

    constexpr relay_zone_params public_zone_params()
    {
      return {CRYPTONOTE_DANDELIONPP_STEMS, dandelionpp_min_epoch, dandelionpp_epoch_range};
    }

    /*! Build the Rust relay zone for `nzone`.

        **The noise flag is set here again, behind a development opt-in.**
        #515 deleted the C++ machinery that used to execute the carrier and
        `NoiseQueues` is the port; what this function now does is turn the
        Rust-owned carrier ON for an encrypted zone when
        `set_carrier_development` says so.

        BY DEFAULT IT DOES NOT. The opt-in is off unless a test or a developer
        sets it, so in a shipped build `get_status().has_noise` still reads
        false everywhere and `select_anonymity`'s noise-priority arm stays
        dormant — the property every `has_noise == false` fixture leans on.

        That caller does not wait on the daemon cutover, and C++ stays the
        transport for the carrier as it is for stem and fluff.

        CORRECTED AGAIN 2026-08-26. The line here previously said the gap was
        "a Rust-internal join, not a language boundary move". The first half
        understates the work and the second half is FALSE. Four pieces are
        missing, and one of them is this boundary:

          1. an owner — nothing constructs or holds `NoiseQueues` outside its
             own tests;
          2. an enqueue path — no production caller ever puts a real fragment
             in;
          3. the join — BOTH noise effects, not one. `Driver::poll` emits
             `Effect::NoiseSend{channel, peer}` and
             `Effect::NoiseUnbind{channel}`; neither is handed to
             `NoiseQueues::take_for_send` / `::unbind`, and `unbind` is what
             invalidates outstanding tokens;
          4. THE BOUNDARY. `NoiseSendCb` is
             `fn(ctx, channel: usize, peer: *const u8)` — no bytes out, no
             status back — and `on_noise` below only logs. `take_for_send` is
             deliberately NON-DESTRUCTIVE, so its token must be resolved
             (advance on a successful send, leave the queue alone on failure),
             and the current signature has no way to say which happened.

        Widening it does not breach CV-4. That rule forbids feeding the
        SCHEDULER traffic-dependent input — a kind, a queue depth, a
        has-real-pending flag — so the cadence cannot react to traffic.
        Carrying opaque bytes OUTWARD, chosen by Rust after the cadence has
        already decided when and to whom, tells the scheduler nothing. See
        `NoiseSendCb`'s own note, which is about the inbound direction. */
    RelayZoneHandle* make_relay_zone(const epee::net_utils::zone nzone)
    {
      const relay_zone_params params = public_zone_params();

      /* One bit, and it is NOT the noise enable. The transposition hazard the
         named bits were introduced for (RP-3a shipped it once: the i2p/tor
         outbound-only fluff rule swapped with the noise enable) cannot recur
         from here, because only one of the two is ever set. The Rust side
         still pins both values and refuses noise on a cleartext zone. */
      std::uint32_t flags = 0;
      if (nzone != epee::net_utils::zone::public_)
        flags |= SHEKYL_RELAY_ZONE_OUTBOUND_FLUFF_ONLY;

      /* A DEVELOPMENT FLAG, and deliberately not an operator switch. The
         distinction is a ruling, not caution.

         The carrier changes `hop` by roughly an order of magnitude — a
         cadence residual of ~6.25 s against a cleartext-link transit of
         ~715 ms — and `shekyl_dandelionpp_embargo_draw_seconds` takes a zone
         and nothing else. So an operator switch would put two populations on
         one encrypted zone drawing from ONE embargo distribution with hops
         that differ ~9x. Provision at the low end and carrier-on nodes run
         alpha far below the 0.90 pin; provision at the high end and every
         carrier-off node on that zone pays a large over-provision.

         A carrier-adaptive embargo is not the escape. §18 refused a
         degree-adaptive embargo because embargo length is inferable from
         fluff timing; §94.9 applied the same argument to posture. This is the
         THIRD application, and the "but the carrier is already visible"
         objection fails on AUDIENCE: the carrier is visible to a directly
         connected peer, while embargo length is inferable by anyone who can
         time a fluff. A carrier-adaptive embargo would republish an
         adjacent-peer fact to every network observer.

         So enabling this under today's constants is a privacy regression, not
         a configuration. It is reachable here for development and tests, and
         `SHEKYL_RELAY_ZONE_NOISE_ENABLED` stays off in every build that is
         not one. See COVER_TRAFFIC_RESTORATION.md §3.1 for the two reopening
         criteria that turn it into a shippable switch. */
      /* The carrier needs an ENCRYPTED link — it hides by payload
         indistinguishability, which needs encryption at step one. That is
         `LinkSecrecy`, a different axis from the outbound-fluff rule above
         even though today's zone set makes the two conditions coincide: i2p
         and tor are both encrypted AND anonymizing, and this line must not be
         read as testing the second. P2P link encryption on a cleartext zone
         would separate them.

         Not duplicated: `LinkSecrecy::of` in Rust is the authority and
         `Zone::new` REFUSES noise on a cleartext link, so if these ever
         disagree the zone fails to construct rather than carrying quietly. */
      if (carrier_development_enabled() && nzone != epee::net_utils::zone::public_)
        flags |= SHEKYL_RELAY_ZONE_NOISE_ENABLED;

      return shekyl_relay_zone_new(
        now_ms(), std::uint8_t(nzone), params.stems,
        std::uint32_t(params.min_epoch.count()), std::uint32_t(params.epoch_range.count()),
        flags
      );
    }

    epee::levin::message_writer make_tx_message(std::vector<blobdata>&& txs, const bool pad, const bool fluff)
    {
      NOTIFY_NEW_TRANSACTIONS::request request{};
      request.txs = std::move(txs);
      request.dandelionpp_fluff = fluff;

      if (pad)
      {
        size_t bytes = 9 /* header */ + 4 /* 1 + 'txs' */ + tools::get_varint_data(request.txs.size()).size();
        for(auto tx_blob_it = request.txs.begin(); tx_blob_it!=request.txs.end(); ++tx_blob_it)
          bytes += tools::get_varint_data(tx_blob_it->size()).size() + tx_blob_it->size();

        // stuff some dummy bytes in to stay safe from traffic volume analysis
        static constexpr const size_t granularity = 1024;
        size_t padding = granularity - bytes % granularity;
        const size_t overhead = 2 /* 1 + '_' */ + tools::get_varint_data(padding).size();
        if (overhead > padding)
          padding = 0;
        else
          padding -= overhead;
        request._ = std::string(padding, ' ');

        epee::byte_slice arg_buff;
        epee::serialization::store_t_to_binary(request, arg_buff);

        // we probably lowballed the payload size a bit, so added a but too much. Fix this now.
        size_t remove = arg_buff.size() % granularity;
        if (remove > request._.size())
          request._.clear();
        else
          request._.resize(request._.size() - remove);
        // if the size of _ moved enough, we might lose byte in size encoding, we don't care
      }

      epee::levin::message_writer out;
      if (!epee::serialization::store_t_to_binary(request, out.buffer))
        throw std::runtime_error{"Failed to serialize to epee binary format"};

      return out;
    }

    bool make_payload_send_txs(connections& p2p, std::vector<blobdata>&& txs, const boost::uuids::uuid& destination, const bool pad, const bool fluff)
    {
      epee::byte_slice blob = make_tx_message(std::move(txs), pad, fluff).finalize_notify(NOTIFY_NEW_TRANSACTIONS::ID);
      // A padded message must reach the wire padded. `make_tx_message`
      // quantizes the blob to a 1024-byte boundary with a run of spaces
      // precisely so an observer cannot read transaction volume off the
      // frame size; zstd erases that run almost perfectly, which would put
      // the frame size back in step with the real payload and hand the
      // observer the signal the operator paid bandwidth to hide.
      //
      // Nothing on the wire marks a message as deliberately sized, so the
      // compressor cannot make this call — only this layer knows. Privacy
      // beats bandwidth here (mission priority 2: privacy is the product),
      // and the cost is bounded: padding is opt-in via --pad-transactions.
      //
      // Pinned by the levin_notify.padding_survives_the_emit_path gtest.
      if (!pad)
        blob = epee::levin::try_compress_message(std::move(blob));
      /* Same `res > 0` as the carrier's send below, and INHERITED WRONG here:
         this returned `p2p.send(...)` straight into a `bool`, so -1 ("the send
         failed") reported success.

         It matters on the live stem path. `dandelionpp_notify` treats a true
         return as "sent" — it records a stem observation and returns without
         retrying. So a transport failure charged a successor with an
         observation for a transaction that never left, and F-10's accounting
         then waited on a silence that peer was never given a chance to break.
         Found sweeping the carrier's own conversion; fixed here rather than
         left as the next instance of it. */
      const int res = p2p.send(std::move(blob), destination);
      return res > 0;
    }

    /* The current design uses `asio::strand`s. The documentation isn't as clear
       as it should be - a `strand` has an internal `mutex` and `bool`. The
       `mutex` synchronizes thread access and the `bool` is set when a thread is
       executing something "in the strand". Therefore, if a callback has lots of
       work to do in a `strand`, asio can switch to some other task instead of
       blocking 1+ threads to wait for the original thread to complete the task
       (as is the case when client code has a `mutex` inside the callback). The
       downside is that asio _always_ allocates for the callback, even if it can
       be immediately executed. So if all work in a strand is minimal, a lock
       may be better.

       This code uses one strand per zone. `dispatch` is used heavily, which
       means "execute immediately in _this_ thread if the strand is not in
       use, otherwise queue the callback to be executed immediately after the
       strand completes its current task". `post` is used where deferred
       execution to an `asio::io_context::run` thread is preferred.

       The zone strand serializes access to the relay zone handle, which is a
       `&mut self` state machine in Rust and must have exactly one caller at
       a time. It also keeps `foreach_connection` — which takes a lock of its
       own — off the notifying thread. */
  } // anonymous

  namespace detail
  {
    struct zone
    {
      explicit zone(boost::asio::io_context& io_service, std::shared_ptr<connections> p2p, epee::net_utils::zone zone, bool pad_txs)
        : p2p(std::move(p2p)),
          wake(io_service),
          strand(io_service),
          relay(make_relay_zone(zone), &shekyl_relay_zone_free),
          pending_wakes(0),
          nzone(zone),
          pad_txs(pad_txs)
      {}

      const std::shared_ptr<connections> p2p;
      /*! One timer for every scheduled relay step, armed from
          `shekyl_relay_zone_next_wake()`. The zone owns the deadline *value*;
          this owns the *sleep*. A second timer would need a second deadline,
          and that would be a copy of a fact the zone already holds. */
      boost::asio::steady_timer wake;
      boost::asio::io_context::strand strand;
      //! Stem map, per-peer fluff batches, epoch role. Only touch in `strand`.
      const std::unique_ptr<RelayZoneHandle, void (*)(RelayZoneHandle*)> relay;
      /*! Outstanding `wake` callbacks. Re-arming cancels the pending wait, and a
          canceled callback that re-armed in turn would cancel the next one
          forever — so only the last outstanding callback does work. The
          inherited `flush_callbacks` guarded the same hazard on `flush_txs`. */
      std::uint32_t pending_wakes;
      const epee::net_utils::zone nzone;         //!< Zone is public ipv4/ipv6 connections, or i2p or tor
      const bool pad_txs;                        //!< Pad txs to the next boundary for privacy

      /*! One transaction handed to the carrier, awaiting its verdict.

          The carrier holds framed bytes it cannot parse, so the identity has
          to live on this side. `blob` is kept because
          `on_transactions_relayed` takes blobs, and `successor` because F-10
          charges an observation to the peer a stem was given to — neither is
          recoverable from the token, which is opaque by design. */
      struct carrier_pending
      {
        blobdata blob;
        crypto::hash txid;
        boost::uuids::uuid successor;
        /*! The relay method the CALLER asked for, not the one the wire used.

            `originated_stays_in_zone` takes the requested method — an origin
            asking for `local` on an anonymity zone keeps `local` however it
            travelled. Recording `stem` here would strip that pin off every
            carrier-borne origin, which is the §92 carve-out the pool arm
            exists to protect. */
        relay_method requested;
      };

      /*! Transactions in the carrier, by the token the enqueue minted.

          LIVES ON THE ZONE because the gap between enqueue and verdict is a
          cadence tick at least and a full epoch at most — far longer than the
          notify operation that enqueued it, which is why it cannot live in
          `dandelionpp_notify`. Strand-confined like everything else here.

          Bounded by construction rather than by policy: the queue refuses more
          than `MAX_FRAGMENTS` windows per message, and a channel holds what it
          holds, so this cannot grow without the carrier growing with it. Every
          entry is erased by its verdict, and `unbind` guarantees a verdict for
          anything the carrier drops. */
      std::map<std::uint64_t, carrier_pending> carrier_pending_by_token;
      //! Mints the next token. Opaque to Rust; only this side reads it.
      std::uint64_t next_carrier_token = 1;
    };
  } // detail

  namespace
  {


    /*! Performs the effects a relay-zone call produced.

        Handlers are transport: frame and send. Neither decides anything —
        the decisions were taken in Rust before the callback fired, which is
        why no variant tag crosses the boundary and there is nothing here to
        decode wrongly. The noise arms log and return: no zone constructed
        here enables the carrier.

        \pre A handler must NOT call back into the zone. It runs while Rust
        holds `&mut` on the zone's state, so re-entering through any
        `shekyl_relay_zone_*` call would alias that borrow. Everything these do
        is either transport or a `post` to another strand; note that `post`
        always defers, where `dispatch` could run the posted work inline and
        re-enter that way. Re-arming happens *after* the FFI call returns. */
    /* Every method here is a Rust callback: `shekyl_relay_zone_*` invokes them
       across the FFI boundary, where an exception unwinding back into Rust is
       undefined behaviour. So each is `noexcept` and catches internally — a
       dropped relay or a skipped repoint is recoverable; a corrupted unwind is
       not. `core` and `outs` exist for `on_outbound`, which the epoch branch of
       `poll` calls back to gather the outbound set lazily. */
    struct relay_effects
    {
      std::shared_ptr<detail::zone> zone;
      /*! NON-CONST since the carrier producer landed, and the widening is
          real rather than incidental. This was `const` while the sink only
          READ core — `on_outbound` filters by blockchain height. It now also
          RECORDS: `on_carrier_resolved` is the one place the pool learns a
          carrier-borne transaction was relayed, and that mutates the pool.
          `notify::core_` was non-const all along; the `const` was added here
          and at `relay_wake` to say "this path only reads", which stopped
          being true. */
      i_core_events* core = nullptr;
      std::vector<boost::uuids::uuid> outs;
      /*! The instant this poll was driven at, for records made inside it.

          `poll` is driven with `shekyl_relay_zone_next_wake()` on the
          scheduled path — a deadline the zone chose, not the wall clock — so a
          record stamped with `now_ms()` from inside a callback sits on a
          different timeline from the schedule that produced it. The stem
          watch's deadline is computed from its stamp, so the two must agree or
          an observation expires against a clock nothing else reads.

          Zero means "no poll drove this", which is the `force_fluff` sink;
          nothing there records. */
      std::uint64_t poll_now_ms = 0;

      /*! What became of a transaction handed to the carrier.

          UNREACHABLE UNTIL THE PRODUCER LANDS, and deliberately loud rather
          than silent. Nothing calls `shekyl_relay_zone_noise_enqueue` yet
          (COVER_TRAFFIC_RESTORATION.md §3.1a), so no message can be in a
          carrier queue and no outcome can resolve. A no-op here would look
          like a decision; this says which half is missing.

          When the producer lands this becomes the ONLY place the pool learns a
          carrier-borne transaction was relayed. `sent == false` must be read
          as NOT relayed rather than as "not yet": an unbound channel discards
          what it held, and an origin given the derived interval for a
          discarded transaction waits it out for something that will never be
          sent. */
      static void on_carrier_resolved(void* ctx, std::uint64_t token, bool sent) noexcept
      {
        assert(ctx != nullptr);
        try
        {
          relay_effects& self = *static_cast<relay_effects*>(ctx);
          detail::zone& z = *self.zone;

          const auto found = z.carrier_pending_by_token.find(token);
          if (found == z.carrier_pending_by_token.end())
          {
            /* A verdict for a token this zone never minted. Loud rather than
               ignored: the carrier returns what it was given, so this means
               the map and the queue have diverged — a real bug, and silence
               would let it accumulate. */
            MERROR("carrier resolved unknown token " << token);
            return;
          }
          /* Moved, not copied: the entry is erased on the next line and its
             blob is a whole transaction. */
          const detail::zone::carrier_pending pending = std::move(found->second);
          z.carrier_pending_by_token.erase(found);

          if (!sent)
          {
            /* DISCARDED: the message left the carrier without reaching a peer.
               Nothing is recorded, and that is the whole point — `relayed`
               stays false, so `local_relay_base` keeps MIN_RELAY_TIME and the
               origin retries on the short grid instead of waiting out the
               derived interval for a transaction that was never sent. */
            MDEBUG("carrier discarded a transaction; leaving it unrelayed for retry");
            return;
          }

          /* SENT, and only now. Both records fire here because this is where
             the send is known to have happened AND the successor is known to
             be the peer that received it — neither was true at enqueue. */
          if (self.core)
          {
            const std::vector<blobdata> one{pending.blob};
            self.core->on_transactions_relayed(
              epee::to_span(one),
              cryptonote::originated_stays_in_zone(pending.requested, z.nzone)
                ? relay_method::local : relay_method::stem,
              z.nzone);
          }
          shekyl_relay_zone_record_stem(
            z.relay.get(),
            reinterpret_cast<const std::uint8_t*>(std::addressof(pending.txid)), 1,
            reinterpret_cast<const std::uint8_t*>(std::addressof(pending.successor)),
            nullptr,
            /* The POLL's clock, not the wall clock: this record shares a
               timeline with the schedule that produced the send. */
            self.poll_now_ms
          );
        }
        catch (const std::exception& e)
        {
          MERROR("Failed to resolve a carrier transaction: " << e.what());
        }
      }

      //! Send one peer's whole batch as a single notification.
      static void on_fluff(void* ctx, const std::uint8_t* peer, const ShekylRelayBlob* blobs, std::size_t n) noexcept
      {
        assert(ctx != nullptr);
        try
        {
          detail::zone& z = *static_cast<relay_effects*>(ctx)->zone;
          if (!z.p2p)
            return;

          boost::uuids::uuid destination{};
          std::memcpy(std::addressof(destination), peer, sizeof(destination));

          std::vector<blobdata> txs;
          txs.reserve(n);
          for (std::size_t i = 0; i < n; ++i)
            txs.emplace_back(reinterpret_cast<const char*>(blobs[i].ptr), blobs[i].len);

          /* The zone released this batch already sorted and de-duplicated: the
             order transactions were received in is an observable, and forwarding
             it would hand it to every peer downstream. */

          /* A FLUFF over i2p/tor sends with the `fluff` flag — this arm only,
             and that is now a distinction rather than a blanket rule.

             The inherited comment here said the flag went on *every* i2p/tor
             release, on the reasoning that "the i2p/tor network is therefore
             replacing the sybil protection of Dandelion++", and closed by
             noting that "Dandelion++ stem phase over i2p/tor is also worth
             investigating". §89 answers that: the zone stems, because a
             transport is a parameter and changing it does not change the
             graph. The sybil-substitution reasoning is retired with it — §64
             priced it, and minting onion addresses is free, so it was the
             outbound-only reach rule doing that work, never the network.

             A stem send on this zone now clears the flag (`dandelionpp_notify`).
             Which arm set it is load-bearing downstream: a receiver keeps its
             `forward` default when the flag is clear, so `still_stemming`
             holds and R-1's coherence branch fires (`net_node.inl`, §89.7). */
          make_payload_send_txs(*z.p2p, std::move(txs), destination, z.pad_txs, true);
        }
        catch (const std::exception& e)
        {
          MERROR("relay fluff callback threw, dropping batch: " << e.what());
        }
        catch (...)
        {
          MERROR("relay fluff callback threw a non-standard exception, dropping batch");
        }
      }

      /* The noise send below is REACHABLE now, and it transports rather than
         logging. That is the carrier caller landing: `NoiseQueues` in
         `shekyl-relay` holds the buffers, the join in `relay_zone_ffi`
         resolves a fragment, and this arm puts it on the wire — the same
         thing this file does for stem and fluff, which is why it never needed
         the daemon cutover.

         Its unbind sibling is GONE rather than kept as a loud failure: that
         effect is now consumed inside Rust by `NoiseQueues::unbind`, and C++
         has held no channel state since #515. A callback with no job is not a
         backstop.

         Reaching this arm still requires a zone with the carrier enabled, and
         `make_relay_zone` only enables it under the development flag — see
         its comment for why that is a development flag and not a product
         switch. */
      /*! Put one carrier emission on the wire. Dummy and real fragment are
          the same call and the same size by construction — this side cannot
          tell them apart, and CV-4 is why it must not be able to.

          The bytes arrive already framed: Rust built the levin message, so
          there is no `make_tx_message` here and no padding decision. A
          carrier emission is a fixed window; quantizing it would be
          re-deriving a length that is already constant.

          NOT compressed, and that is the same argument `make_payload_send_txs`
          makes for a padded blob one level up. The window is constant so an
          observer cannot read volume off the frame — compressing it would put
          the frame size back in step with the real payload and hand back
          exactly the signal the carrier spends bandwidth to hide.

          The return is the token's resolution: true advances the queue past
          this fragment, false leaves it for the next emission. */
      static bool on_noise(void* ctx, std::size_t channel, const std::uint8_t* peer,
                           const std::uint8_t* bytes, std::size_t len) noexcept
      {
        assert(ctx != nullptr);
        try
        {
          detail::zone& z = *static_cast<relay_effects*>(ctx)->zone;
          if (!z.p2p || bytes == nullptr || len == 0)
            return false;

          boost::uuids::uuid destination{};
          std::memcpy(std::addressof(destination), peer, sizeof(destination));

          /* Spelled as a span of the type it actually is. The cast that stood
             here was not merely redundant: `epee::span`'s converting ctor
             refuses `const char*` -> `const uint8_t*` (`safe_conversion`
             allows only an exact match or added const), so `{char*, len}`
             could not select the initializer_list-of-spans ctor at all. It
             selected `byte_slice(std::string&&)` instead, via `std::string`'s
             `(ptr, count)` ctor — a working line that did something other
             than what it read as. A reviewer read it as the span form and
             called it a compile error; it compiled, and both of us were
             reading a different overload than the compiler chose. */
          epee::byte_slice blob{epee::span<const std::uint8_t>{bytes, len}};
          /* `res > 0`, not a bare conversion. `connections::send` returns an
             INT: 1 sent, 0 no such connection, -1 the send itself failed. A
             direct `int -> bool` makes -1 report DELIVERED, so Rust resolves
             the token with `sent` and the fragment is dropped for good — the
             precise failure the status return exists to prevent, inverted.
             Same check `net_node.inl` uses at its own send site. */
          const int res = z.p2p->send(std::move(blob), destination);
          return res > 0;
        }
        catch (const std::exception& e)
        {
          MERROR("noise send for channel " << channel << " threw: " << e.what());
          return false;
        }
        catch (...)
        {
          MERROR("noise send for channel " << channel << " threw a non-standard exception");
          return false;
        }
      }

      //! Gather the outbound connection set on demand.
      //!
      //! `poll` calls this only when a wake crosses an epoch boundary, so the
      //! locked connection scan and median-height sort are paid at a rollover
      //! and never on a fluff release. The result is stored in `outs` so the
      //! returned span outlives the FFI call; an empty set returns nullptr.
      static const std::uint8_t* on_outbound(void* ctx, std::size_t* out_n) noexcept
      {
        assert(ctx != nullptr);
        relay_effects& self = *static_cast<relay_effects*>(ctx);
        try
        {
          if (self.zone && self.zone->p2p && self.core)
            self.outs = get_out_connections(*self.zone->p2p, self.core);
        }
        catch (const std::exception& e)
        {
          // An empty set at a boundary rebuilds the map over no peers — the
          // already-tolerated no-outbound state, self-healing on the next
          // update_stems — but log it, since it is otherwise a silent one-epoch
          // stem/noise dropout.
          self.outs.clear();
          MWARNING("relay outbound gather threw, rebuilding over no peers: " << e.what());
        }
        catch (...)
        {
          self.outs.clear();
          MWARNING("relay outbound gather threw a non-standard exception, rebuilding over no peers");
        }
        *out_n = self.outs.size();
        return uuid_bytes(self.outs);
      }
    };

    //! \pre Called within `zone->strand`.
    void relay_update_stems(const std::shared_ptr<detail::zone>& zone, const std::vector<boost::uuids::uuid>& outs)
    {
      if (!zone)
        return;

      assert(zone->strand.running_in_this_thread());

      shekyl_relay_zone_update_stems(zone->relay.get(), uuid_bytes(outs), outs.size());
    }

    //! Runs every relay step that has come due, and re-arms the single timer.
    struct relay_wake
    {
      std::shared_ptr<detail::zone> zone_;
      /*! Non-const because this is what constructs the poll sink, and the
          sink records carrier verdicts. Arming itself still only reads. */
      i_core_events* core_;

      //! \pre Called within `zone->strand`.
      static void arm(std::shared_ptr<detail::zone> zone, i_core_events* core)
      {
        assert(zone != nullptr);
        assert(zone->strand.running_in_this_thread());

        detail::zone& this_zone = *zone;
        ++this_zone.pending_wakes;
        this_zone.wake.expires_at(from_ms(shekyl_relay_zone_next_wake(this_zone.relay.get())));
        this_zone.wake.async_wait(boost::asio::bind_executor(this_zone.strand, relay_wake{std::move(zone), core}));
      }

      void operator()(const boost::system::error_code error)
      {
        if (!zone_ || !zone_->pending_wakes || --zone_->pending_wakes || !zone_->p2p)
          return;

        assert(zone_->strand.running_in_this_thread());

        if (error && error != boost::system::errc::operation_canceled)
          throw boost::system::system_error{error, "relay wake timer failed"};

        /* The connection set is gathered lazily: `poll` calls `on_outbound`
           back only when this wake crosses an epoch boundary and the stem map
           must be rebuilt. A fluff-release wake — the common case — never pays
           for the locked connection scan and median-height sort the inherited
           fluff path also skipped. The epoch deadline stays the zone's; this
           side answers "give me the set", never "is it time", so no copy of the
           deadline lives here. `sink` carries `core_` because `on_outbound`
           needs it to filter by blockchain height. */
        const std::uint64_t at = now_ms();
        relay_effects sink{zone_, core_};
        sink.poll_now_ms = at;
        shekyl_relay_zone_poll(
          zone_->relay.get(), at,
          std::addressof(sink), relay_effects::on_outbound,
          relay_effects::on_fluff, relay_effects::on_noise,
          relay_effects::on_carrier_resolved
        );

        arm(std::move(zone_), core_);
      }
    };

    /*! The "fluff" portion of the Dandelion++ algorithm. Every tx is queued
        per-connection behind a randomized delay drawn by the zone, and released
        when that deadline comes due. This side only hands over the batch and
        re-arms the timer against whatever deadline the zone now holds. */
    struct relay_fluff
    {
      std::shared_ptr<detail::zone> zone_;
      std::vector<blobdata> txs_;
      boost::uuids::uuid source_;
      i_core_events* core_;

      void operator()()
      {
        run(std::move(zone_), epee::to_span(txs_), source_, core_);
      }

      //! \pre Called within `zone->strand`.
      static void run(std::shared_ptr<detail::zone> zone, epee::span<const blobdata> txs, const boost::uuids::uuid& source, i_core_events* core)
      {
        if (!zone || !zone->p2p || txs.empty())
          return;

        assert(zone->strand.running_in_this_thread());

        MDEBUG("Queueing " << txs.size() << " transaction(s) for Dandelion++ fluffing");

        std::vector<ShekylRelayBlob> batch;
        batch.reserve(txs.size());
        for (const blobdata& tx : txs)
          batch.push_back(ShekylRelayBlob{reinterpret_cast<const std::uint8_t*>(tx.data()), tx.size()});

        const std::size_t accepted = shekyl_relay_zone_queue_fluff(
          zone->relay.get(), now_ms(), batch.data(), batch.size(), uuid_bytes(source)
        );
        if (accepted == 0)
          MWARNING("Unable to send transaction(s), no available connections");

        relay_wake::arm(std::move(zone), core);
      }
    };

    //! Checks fluff status for this node, and then does stem or fluff for txes
    struct dandelionpp_notify
    {
      std::shared_ptr<detail::zone> zone_;
      i_core_events* core_;
      std::vector<blobdata> txs_;
      boost::uuids::uuid source_;
      relay_method tx_relay;

      //! \pre Called in `zone_->strand`
      void operator()()
      {
        if (!zone_ || !core_ || txs_.empty())
          return;

        assert(zone_->strand.running_in_this_thread());

        /* Stem-or-fluff is the zone's call, including "the origin always stems"
           (RD-4) and the one NoRoute refresh. This offers the outbound snapshot
           and performs transport; re-deriving `!fluffing || local` or owning
           the refresh loop here would put zone scheduling in the one layer the
           gtest oracle cannot see through. */
        boost::uuids::uuid destination{};
        const bool local_origin = (tx_relay == relay_method::local);
        std::vector<boost::uuids::uuid> outs = get_out_connections(*zone_->p2p, core_);

        /* What the wire does and what the txpool is told are the same thing on
           clearnet and deliberately not the same for an origin on an anonymity
           zone. §89 opened the stem gates here; the pool class is what keeps
           the *backstop* in-zone, and §30.5 forbids that backstop reaching
           clearnet. So an originated transaction keeps its `local` record
           whatever the transport did — it still stems on the wire below. */
        /* Takes WHAT WAS SENT rather than closing over `txs_`, because after
           the carrier the two differ. A batch can split — the carrier accepts
           some transactions and refuses others — and recording `txs_` would
           record the accepted ones as relayed AT SEND TIME, which is the
           precise falsification this change exists to remove, and then record
           them a second time when their carrier verdict arrives. */
        const auto record_relayed = [this](const relay_method method,
                                           const std::vector<blobdata>& sent) {
          if (sent.empty())
            return;
          core_->on_transactions_relayed(
            epee::to_span(sent),
            cryptonote::originated_stays_in_zone(tx_relay, zone_->nzone) ? relay_method::local : method,
            zone_->nzone
          );
        };

        /* `plan_dispatch`, not `plan_relay`: phase, carrier and slot in ONE
           crossing (rule 40). This is §2.9 step 4's own description —
           "`send_txs` consumes `plan_dispatch`" — reaching its first real
           use, and it is what makes the carrier reachable by a real
           transaction rather than by dummies alone (§3.1a). */
        std::uint8_t carrier = SHEKYL_RELAY_CARRIER_ORDINARY;
        std::uint32_t channel = 0;
        std::int32_t plan = shekyl_relay_zone_plan_dispatch_with_refresh(
          zone_->relay.get(), uuid_bytes(source_), local_origin,
          uuid_bytes(outs), outs.size(),
          reinterpret_cast<std::uint8_t*>(std::addressof(destination)),
          std::addressof(carrier), std::addressof(channel)
        );

        /* What still needs the ordinary wire. The carrier takes transactions
           out of this; whatever it refuses stays, and the existing stem path
           below sends exactly those.

           A BATCH THEREFORE SPLITS, and the split is not a convenience — it is
           what keeps a SIZE refusal from becoming a PRIVACY regression. The
           realistic refusal is a transaction too large to fragment inside
           `MAX_FRAGMENTS` windows. Failing the whole batch on that would put
           the other transactions on the clear wire because one of their
           neighbours was big, which is a worse outcome reached for an
           unrelated reason. Both halves go to the same stem slot either way,
           so splitting costs nothing that not splitting would have saved.

           A later reader simplifying this to "return an error instead of
           partitioning" would be trading the privacy of the small
           transactions for the tidiness of the control flow. */
        std::vector<blobdata> to_send = txs_;

        if (plan == SHEKYL_RELAY_PLAN_STEM && carrier == SHEKYL_RELAY_CARRIER_NOISE)
        {
          /* ONE TRANSACTION PER ENQUEUE, which is §2.9b made structural at the
             crossing: two transactions in one carrier message would share a
             window, a slot and a successor — the pairwise linkage Dandelion++
             exists to deny. The crossing cannot express a batch, so this loops
             rather than passing `txs_`. */
          std::vector<blobdata> refused;
          for (blobdata& tx : to_send)
          {
            /* F-9's canonical hash, via the same helper the stem watch is
               armed with. Blob bytes are not a stable identity across relay
               hops, and the verdict this token resolves has to name the
               transaction the pool knows. */
            const std::vector<crypto::hash> id = stem_watch_tx_hashes({tx});
            if (id.size() != 1)
            {
              refused.push_back(std::move(tx));
              continue;
            }
            const std::uint64_t token = zone_->next_carrier_token++;
            if (!shekyl_relay_zone_noise_enqueue(
                  zone_->relay.get(), channel,
                  reinterpret_cast<const std::uint8_t*>(tx.data()), tx.size(), token))
            {
              refused.push_back(std::move(tx));
              continue;
            }
            /* Recorded ONLY on acceptance, and the pool is told NOTHING yet.
               An enqueue is not a send: the windows go out on later cadence
               ticks, and CV-1 discards an in-flight run when the epoch rolls.
               `record_relayed` and the stem observation fire in
               `on_carrier_resolved`, where the send is known to have happened
               and the successor is known to be the peer that received it. */
            zone_->carrier_pending_by_token.emplace(
              token, detail::zone::carrier_pending{tx, id.front(), destination, tx_relay});
          }
          to_send = std::move(refused);
          if (to_send.empty())
          {
            MDEBUG("Handed " << txs_.size() << " transaction(s) to the carrier on channel "
                   << channel);
            return;
          }
        }

        if (plan != SHEKYL_RELAY_PLAN_FLUFF_EPOCH)
        {
          /* THE RELAY IS RECORDED WHERE THE SEND IS KNOWN TO HAVE HAPPENED,
             which is inside the success arms below rather than here.

             Recording it up front told the pool a stem had been launched
             before one had — and on the paths where none ever is (`NoRoute`,
             or both send attempts failing) that claim was simply false. It is
             not a cosmetic ordering: `set_relayed` sets `meta.relayed`, and
             `local_relay_base` reads exactly that bit to choose an origin's
             backoff. `relayed == false` means "no stem was ever launched, so
             no embargo exists anywhere to complete" and keeps MIN_RELAY_TIME;
             `relayed == true` buys the derived interval, which provisions for
             a stem completing. A send that never happened was therefore
             claiming the long wait on the strength of an event that did not
             occur — the same falsification an unsent `local` entry was fixed
             for.

             The fluff record below still fires on every failure path, so the
             pool is not left un-told; it is told the thing that actually
             happened. `record_stem_observation` was already placed this way,
             and the two records now arm on the same event. */
          if (plan == SHEKYL_RELAY_PLAN_STEM &&
              make_payload_send_txs(*zone_->p2p, std::vector<blobdata>{to_send}, destination, zone_->pad_txs, false))
          {
            record_relayed(relay_method::stem, to_send);
            record_stem_observation(zone_->relay.get(), to_send, destination, source_);
            /* Source is intentionally omitted in debug log for privacy - a
               nil uuid indicates source is that node. */
            MDEBUG("Sent " << to_send.size() << " transaction(s) to " << destination << " using Dandelion++ stem");
            return;
          }

          // Stem send failed, or still unroutable after the one NoRoute refresh:
          // force a mid-epoch map refresh (connection list may be stale) and
          // re-plan once. Transport retry only — refresh policy already lived
          // in the first call for the empty-map case.
          outs = get_out_connections(*zone_->p2p, core_);
          relay_update_stems(zone_, outs);
          plan = shekyl_relay_zone_plan_relay(
            zone_->relay.get(), uuid_bytes(source_), local_origin,
            reinterpret_cast<std::uint8_t*>(std::addressof(destination))
          );
          if (plan == SHEKYL_RELAY_PLAN_STEM &&
              make_payload_send_txs(*zone_->p2p, std::vector<blobdata>{to_send}, destination, zone_->pad_txs, false))
          {
            record_relayed(relay_method::stem, to_send);
            record_stem_observation(zone_->relay.get(), to_send, destination, source_);
            MDEBUG("Sent " << to_send.size() << " transaction(s) to " << destination << " using Dandelion++ stem");
            return;
          }

          MERROR("Unable to send transaction(s) via Dandelion++ stem");
        }

        /* ONE BATCH, TOLD AND SENT — and they are inseparable rather than
           separately correct.

           These were two statements sharing a variable, and review found the
           variable changed in one and not the other: the fallback recorded
           `txs_` while sending `to_send`, so a carrier-accepted transaction
           was claimed as relayed before any window of it went out AND fluffed
           a second time, defeating the carrier for exactly the transaction it
           had taken.

           A test holds the RECORD half — `take_relayed` observes what the pool
           was told. It cannot hold the SEND half: the only route into this
           fallback from a carrier epoch is a stem send that fails, and in the
           unit fixture a failed write tears down the peers the fluff would go
           to, so the wire is empty and any assertion on it is vacuous.

           So the two are made unrepresentable-apart instead of separately
           asserted (rule 50: when no check can fail, encode it). One
           parameter, used twice, in one call — an edit that changes what is
           sent changes what is recorded with it, and the record assertion
           therefore covers both.

           Order is load-bearing: `record_relayed` reads `zone_->nzone`, and
           `relay_fluff::run` moves `zone_`. */
        const auto fluff_and_record = [this, &record_relayed](const std::vector<blobdata>& batch) {
          record_relayed(relay_method::fluff, batch);
          relay_fluff::run(std::move(zone_), epee::to_span(batch), source_, core_);
        };
        fluff_and_record(to_send);
      }
    };

  } // anonymous

  notify::notify(boost::asio::io_context& service, std::shared_ptr<connections> p2p, epee::net_utils::zone zone, const bool pad_txs, i_core_events& core)
    : zone_(std::make_shared<detail::zone>(service, std::move(p2p), zone, pad_txs))
    , core_(std::addressof(core))
  {
    if (!zone_->p2p)
      throw std::logic_error{"cryptonote::levin::notify cannot have nullptr p2p argument"};
    if (!zone_->relay)
      throw std::logic_error{"cryptonote::levin::notify could not open its relay zone"};

    /* GATE 1 of 3, deleted at §89.5. This was
       `if (covert_enabled || zone == public_)`, so a non-covert anonymity zone
       got neither its initial stem map nor an armed wake timer. Every zone
       stems now, and `make_relay_zone` has always been unconditional, so there
       is no transport question left to ask here.

       The zone drew its first epoch when it was constructed, matching the
       inherited `start_epoch` running once here. All that is left is to offer
       it the connections that already exist and arm the timer on the deadline
       it chose. */
    boost::asio::dispatch(zone_->strand, [z = zone_, core = core_] {
      relay_update_stems(z, get_out_connections(*z->p2p, core));
      relay_wake::arm(z, core);
    });

    /* No per-channel timer to start: the zone armed every covert deadline at
       construction and the single `wake` timer serves them (§20.2a). */
  }

  notify::~notify() noexcept
  {}

  notify::status notify::get_status() const noexcept
  {
    if (!zone_)
      return {false, false, false};

    /* Stem slots backed by a live peer — the inherited `connection_count`, and
       only meaningful when the zone runs covert channels. Published by it as a
       single-writer atomic precisely because this method is callable from any
       thread (§18.5 finding 1). */
    const std::size_t connection_count = shekyl_relay_zone_live_stems(zone_->relay.get());
    const bool noise = shekyl_relay_zone_noise_enabled(zone_->relay.get());
    bool has_outgoing = connection_count;
    if (!noise)
      has_outgoing = zone_->p2p->get_out_connections_count();
    return {noise, CRYPTONOTE_NOISE_CHANNELS <= connection_count, has_outgoing};
  }

  void notify::new_out_connection()
  {
    /* GATE 2 of 3, deleted at §89.5 — and the predicate went with it rather
       than being rewritten.

       This read `!covert_enabled || CRYPTONOTE_NOISE_CHANNELS <= live_stems`,
       so a new peer triggered a stem-map refresh only on a covert zone. That
       under-maintained every other zone including the public one: the map
       self-populates on `NoRoute` and on send failure, so what was lost was
       the *proactive* refresh, not liveness.

       The obvious repair was to swap the covert throttle for the zone's own
       stem width. That would have left C++ deciding a relay question, which
       §18 gives to Rust. Instead the decision moves down: `update_stems` is
       already a no-op when nothing needs doing — `StemMap::update` returns
       `Unchanged` when every slot is live at full width, and a bound slot is
       taken out of the candidate pool rather than re-drawn, so an
       unconditional call cannot re-point an existing stem. The throttle was
       C++ guessing at a condition Rust already evaluates exactly. */
    if (!zone_)
      return;

    boost::asio::dispatch(zone_->strand, [z = zone_, core = core_] {
      relay_update_stems(z, get_out_connections(*z->p2p, core));
    });
  }

  void notify::on_handshake_complete(const boost::uuids::uuid &id, bool is_income)
  {
    if (!zone_)
      return;

    boost::asio::dispatch(zone_->strand, [z = zone_, id, is_income] {
      shekyl_relay_zone_on_handshake(z->relay.get(), uuid_bytes(id), is_income);
    });
  }

  void notify::on_connection_close(const boost::uuids::uuid &id)
  {
    if (!zone_)
      return;

    boost::asio::dispatch(zone_->strand, [z = zone_, id] {
      shekyl_relay_zone_on_close(z->relay.get(), uuid_bytes(id));
    });
  }

  /* `run_epoch` and `run_fluff` force a *step*, where the inherited code
     cancelled a *timer*. With one timer covering both kinds of wake, cancelling
     it would no longer say which step was wanted — and the forced step runs the
     same zone code the deadline would have, so neither is a test-only path. */

  void notify::run_epoch()
  {
    if (!zone_)
      return;

    boost::asio::dispatch(zone_->strand, [z = zone_, core = core_] {
      const std::vector<boost::uuids::uuid> outs = get_out_connections(*z->p2p, core);
      shekyl_relay_zone_force_epoch(z->relay.get(), now_ms(), uuid_bytes(outs), outs.size());
      relay_wake::arm(z, core);
    });
  }

  void notify::run_next_wake()
  {
    /* §18.4's live diagnostic rides the existing wake — no new timer. The
       transition is Rust's answer (the floor comparison lives there, on the
       logging path only); this site owns the operator-facing WARN. Wire
       behavior is untouched by construction: nothing below reads the note. */
    if (zone_ && zone_->p2p)
    {
      /* size_t -> u32, bounded explicitly rather than narrowed implicitly. A
         count above u32 is already garbage (outbound connections are capped
         orders of magnitude below), and clamping keeps the reading on the
         side the diagnostic treats as healthy — above-floor is Steady, so a
         clamped value can never fabricate a below-floor WARN. */
      switch (shekyl_relay_zone_note_achieved_out(
        static_cast<std::uint8_t>(zone_->nzone),
        static_cast<std::uint32_t>(std::min<std::size_t>(
          zone_->p2p->get_out_connections_count(),
          std::numeric_limits<std::uint32_t>::max()))))
      {
        case 1:
          MWARNING("Anonymity zone below the provisioned outbound-connection floor"
                " (D9/§18.4: stemming CONTINUES; diagnostic only — see"
                " /get_stem_tallies on the admin listener)");
          break;
        case 2:
          MWARNING("Anonymity zone recovered to the provisioned outbound-connection floor");
          break;
        default: break;
      }
    }
    if (!zone_)
      return;

    /* Advance to the next scheduled event and run it — the function is named
       for what its body does (§20.6; the inherited `run_stems` never touched
       stems, and after RP-3b there are no noise timers left for it to cancel
       either).

       **No forcing path, deliberately.** `force_fluff`/`force_epoch` state the
       house idiom — same code as `poll`, only which work counts as due differs
       — but each still carries a force flag, so one branch diverges between
       forced and scheduled. Covert needs zero branches: the entire difference
       is the value of `now`, so this drives the *production* path and a covert
       send here is a genuinely due send, re-armed exactly as production
       re-arms it. Anyone adding a forcing path for another subsystem should
       reach for this shape before `force_fluff`'s.

       A pending fluff batch with an earlier deadline fires first and the
       caller polls again. That is the real interleaving, not a wrinkle —
       skipping past it to reach covert would be the test-only channel this
       shape exists to avoid. */
    boost::asio::dispatch(zone_->strand, [z = zone_, core = core_] {
      const std::uint64_t at = shekyl_relay_zone_next_wake(z->relay.get());
      relay_effects sink{z, core};
      sink.poll_now_ms = at;
      shekyl_relay_zone_poll(
        z->relay.get(), at,
        std::addressof(sink), relay_effects::on_outbound,
        relay_effects::on_fluff, relay_effects::on_noise,
        relay_effects::on_carrier_resolved
      );
      relay_wake::arm(z, core);
    });
  }

  void notify::run_fluff()
  {
    if (!zone_)
      return;

    boost::asio::dispatch(zone_->strand, [z = zone_, core = core_] {
      relay_effects sink{z};
      shekyl_relay_zone_force_fluff(
        z->relay.get(), now_ms(), std::addressof(sink), relay_effects::on_fluff
      );
      relay_wake::arm(z, core);
    });
  }

  void notify::record_arrival(std::shared_ptr<const std::vector<crypto::hash>> hashes, const boost::uuids::uuid& from)
  {
    if (!zone_ || !hashes || hashes->empty())
      return;

    /* The strand serializes all access to the relay handle; this is a
       read-modify of the zone's stem watch, so it takes the same path as
       every other handle call rather than racing them. Hashes are the join
       key — the caller already parsed once for the whole fan-out. */
    boost::asio::dispatch(zone_->strand, [zone = zone_, hashes = std::move(hashes), from, core = core_] ()
    {
      /* `from` identifies the arriving peer so the watch can refuse to
         resolve an observation charged to that same peer (F-10). A nil uuid
         means "no peer", which never matches a successor. */
      std::vector<crypto::hash> propagated(hashes->size());
      const std::size_t n = shekyl_relay_zone_record_arrival(
        zone->relay.get(), reinterpret_cast<const std::uint8_t*>(hashes->data()), hashes->size(),
        from.is_nil() ? nullptr : reinterpret_cast<const std::uint8_t*>(std::addressof(from)),
        reinterpret_cast<std::uint8_t*>(propagated.data()));

      /* The verdicts that fired on THIS arrival, forwarded once. Sized at the
         arrival count because the propagated set is a subset of it, so the
         buffer is exact without a probe call.

         Same seam `on_transactions_relayed` uses, for the same reason: the
         relay strand owns the handle and holds no pool reference, and core is
         the only thing that reaches both. Nothing is decided here — the pool
         scopes the fact to the entry class that asked the question. */
      if (n != 0 && core != nullptr)
      {
        propagated.resize(n);
        core->on_stem_propagated(epee::to_span(propagated));
      }
    });
  }

  std::vector<crypto::hash> stem_watch_tx_hashes(const std::vector<cryptonote::blobdata>& txs)
  {
    /* F-9: blob bytes are not a stable identity across relay hops. The
       canonical hash is computed from the *parsed* transaction — the one
       identity every hop preserves. A blob that does not parse has no
       canonical identity and is skipped.

       **Recorded as a trade, not a free win (§49.4).** These blobs are parsed
       again by `handle_incoming_tx` moments later, so the observation path
       still pays a duplicate parse relative to admission — but it pays it
       **once per batch**, not once per network zone. Carrying the hash out of
       verification would remove the remaining duplicate. */
    std::vector<crypto::hash> hashes{};
    hashes.reserve(txs.size());
    for (const auto& blob : txs)
    {
      cryptonote::transaction tx{};
      crypto::hash hash{};
      if (cryptonote::parse_and_validate_tx_from_blob(blob, tx, hash))
        hashes.push_back(hash);
    }
    return hashes;
  }

  std::vector<notify::stem_tally_row> notify::stem_snapshot() const
  {
    /* §55 TRANSIT, NOT STRUCTURE. Forwards a Rust-owned published snapshot
       to a Rust consumer (shekyl-daemon-rpc); the hop through C++ exists
       only because net_node owns the relay zone handles' lifetime. It
       disappears with the p2p migration -- do not build on it.

       Two-call sizing on row count. The second call's return is
       authoritative: publish can shrink or grow between probes, so never
       require wrote == first_need (that discards a successful shrink write).
       One retry covers a concurrent grow. */
    static_assert(sizeof(stem_tally_row) == sizeof(ShekylStemTallyRow),
      "stem_tally_row must match ShekylStemTallyRow");
    static_assert(alignof(stem_tally_row) == alignof(ShekylStemTallyRow),
      "stem_tally_row alignment must match ShekylStemTallyRow");

    std::vector<stem_tally_row> out;
    if (!zone_)
      return out;
    auto* handle = zone_->relay.get();
    std::size_t need = shekyl_relay_zone_stem_snapshot(handle, nullptr, 0);
    for (int attempt = 0; attempt < 2; ++attempt)
    {
      out.resize(need);
      const std::size_t wrote = shekyl_relay_zone_stem_snapshot(
        handle,
        need ? reinterpret_cast<ShekylStemTallyRow*>(out.data()) : nullptr,
        need);
      if (wrote <= need)
      {
        out.resize(wrote);
        return out;
      }
      need = wrote;
    }
    out.clear();
    return out;
  }

  bool notify::floor_snapshot(std::uint32_t& achieved, std::uint32_t& floor, bool& below) const
  {
    /* §18.4 admin-surface read; same handle discipline as stem_snapshot. */
    if (!zone_)
      return false;
    return shekyl_relay_zone_floor_snapshot(
      static_cast<std::uint8_t>(zone_->nzone), &achieved, &floor, &below);
  }

  std::string format_stem_tally_row_json(
    const notify::stem_tally_row& row, epee::net_utils::zone z)
  {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out = "{\"peer\":\"";
    for (std::uint8_t b : row.peer)
    {
      out += HEX[b >> 4];
      out += HEX[b & 0xf];
    }
    out += "\",\"zone\":\"";
    out += epee::net_utils::zone_to_string(z);
    out += "\",\"propagated\":";
    out += std::to_string(row.propagated);
    out += ",\"silent\":";
    out += std::to_string(row.silent);
    out += ",\"distinct_sources\":";
    out += std::to_string(row.distinct_sources);
    out += '}';
    return out;
  }

  std::size_t notify::stem_in_flight() const
  {
    return zone_ ? shekyl_relay_zone_stem_in_flight(zone_->relay.get()) : 0;
  }

  bool notify::send_txs(std::vector<blobdata> txs, const boost::uuids::uuid& source, relay_method tx_relay)
  {
    if (txs.empty())
      return true;

    if (!zone_)
      return false;

    /* Dandelion++ runs on every zone, regardless of noise (§93.1). The
       inherited covert branch that stood here — noise taking precedence,
       stem demoted to local, all-channel broadcast — is DELETED, not
       repaired (§2.9 step 4). Its opening sentence ("If noise is enabled
       in a zone, it always takes precedence") was the architecture; the
       code no longer does that, and a comment that still said so would
       instruct the next reader to rebuild it.

       Noise masks the node↔proxy wire against an **external** observer;
       Dandelion++ defends against an **internal** adversarial peer. Enabling
       one is not a reason to disable the other. The Rust executor
       (`NoiseQueues`) owns the carrier and attaches it *below* the phase
       (`plan_dispatch`). Three of the four pieces that were owed are BUILT:
       `RelayZoneHandle` owns the queue, `dispatch` joins BOTH of
       `Driver::poll`'s noise effects, and `NoiseSendCb` carries bytes out and
       a send status back. The enqueue CROSSING exists too.

       WHAT IS STILL OWED is its producer: nothing calls
       `shekyl_relay_zone_noise_enqueue`, so a carrier zone emits dummies only
       and real transactions stay on the ordinary path below.
       `COVER_TRAFFIC_RESTORATION.md` §3.1a names the remaining work —
       swapping this function's `plan_relay` for
       `plan_dispatch_with_refresh`, which already returns the carrier and
       channel it needs.

       In a shipped build no zone here enables noise at all — the opt-in
       defaults off — so the deleted branch was unreachable in production
       either way; both notifier constructions pass a null noise payload. See
       `COVER_TRAFFIC_RESTORATION.md` §3's status table, the row headed
       "§2.9 step 2 — covert executor".

       Recording parity was checked before the deletion. `fluff` makes the
       identical `on_transactions_relayed` call below. `stem`/`local` are
       recorded inside `dandelionpp_notify`'s `record_relayed`, with
       `originated_stays_in_zone` applied — the *planned* method rather than
       the blanket `local` downgrade. `none`/`block` were being RELAYED by
       the deleted branch, which had no switch at all; the arm below refuses
       them, and `none` means do not relay.

       What is *not* symmetric is the txpool class an origin keeps — see
       `originated_stays_in_zone` at the record sites in `dandelionpp_notify`. */

    switch (tx_relay)
    {
      default:
      case relay_method::none:
      case relay_method::block:
        return false;
      case relay_method::stem:
      case relay_method::local:
        /* GATE 3 of 3, deleted at §89.5. This was gated on
           `zone_->nzone == public_`, so stem/local on i2p/tor fell
           through into the fluff arm and the anonymity zone diffused where
           the design said it stemmed (§63). Tor is a transport like the
           clear internet; changing the transport does not change the graph.

           The outbound-only fluff rule is unaffected and still applies when
           this stem later fluffs — it travels with the zone's `reach`
           (`FluffReach::OutboundOnly`, set from `nzone != public_` in
           `make_relay_zone`), which no stemming decision touches. */
        // this will change a local tx to stem or fluff ...
        boost::asio::dispatch(
          zone_->strand,
          dandelionpp_notify{zone_, core_, std::move(txs), source, tx_relay}
        );
        break;
      case relay_method::fluff:
        core_->on_transactions_relayed(epee::to_span(txs), tx_relay, zone_->nzone);
        boost::asio::dispatch(zone_->strand, relay_fluff{zone_, std::move(txs), source, core_});
        break;
    }
    return true;
  }
} // levin
} // net
