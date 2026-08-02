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

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/system_error.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <stdexcept>
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
  namespace
  {
    constexpr const std::size_t connection_id_reserve_size = 100;

    constexpr const std::chrono::minutes noise_min_epoch{CRYPTONOTE_NOISE_MIN_EPOCH};
    constexpr const std::chrono::seconds noise_epoch_range{CRYPTONOTE_NOISE_EPOCH_RANGE};

    /* The covert send DELAY is drawn in `shekyl-relay` now (NoiseCadence); these
       two survive only for the fragment-budget static_assert below, which is a
       real invariant: a real notification must fit inside one covert epoch. */
    constexpr const std::chrono::seconds noise_min_delay{CRYPTONOTE_NOISE_MIN_DELAY};
    constexpr const std::chrono::seconds noise_delay_range{CRYPTONOTE_NOISE_DELAY_RANGE};

    constexpr const std::chrono::minutes dandelionpp_min_epoch{CRYPTONOTE_DANDELIONPP_MIN_EPOCH};
    constexpr const std::chrono::seconds dandelionpp_epoch_range{CRYPTONOTE_DANDELIONPP_EPOCH_RANGE};


    /* The Dandelion++ fluff delay used to be drawn here, from a Poisson
       distribution over quarter-seconds. It is drawn in `shekyl-relay` now, from
       the memoryless family the derivation actually calls for — the inherited
       draw is F-4 of DAEMON_RELAY_PRIVACY.md, and it is gone rather than ported
       so it cannot be reintroduced by symmetry with the noise delays below. */

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

    //! \return `id` as the 16 raw bytes the relay FFI reads.
    //! §46/§48: canonical tx hashes for the observation watch. Parsed here
    //! rather than blob-hashed, because blob bytes are not a stable identity
    //! across relay hops (F-9) — the canonical hash is computed from the
    //! parsed transaction and is the one identity every hop preserves. A blob
    //! that does not parse has no canonical identity and is skipped: it
    //! cannot be a transaction this node stemmed.
    std::vector<crypto::hash> canonical_tx_hashes(const std::vector<cryptonote::blobdata>& txs)
    {
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

    //! §46: hand the stemmed txs to the zone's observation watch. The
    //! deadline is drawn Rust-side; `source` is null for locally-originated
    //! (nil uuid), matching `in_mapping_[nil]`.
    void record_stem_observation(
      RelayZoneHandle* const relay,
      const std::vector<cryptonote::blobdata>& txs,
      const boost::uuids::uuid& destination,
      const boost::uuids::uuid& source)
    {
      const std::vector<crypto::hash> hashes = canonical_tx_hashes(txs);
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

    uint64_t get_blockchain_height(connections& p2p, const i_core_events* core)
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

    std::vector<boost::uuids::uuid> get_out_connections(connections& p2p, const i_core_events* core)
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

    /* Two independent parameter sets, kept whole rather than selected field by
       field. `CRYPTONOTE_NOISE_CHANNELS` and `CRYPTONOTE_DANDELIONPP_STEMS`
       happen to be equal today and have no reason to stay that way, so choosing
       between them per-field reads as an accident where choosing between the
       sets reads as the decision it is. */

    constexpr relay_zone_params noise_zone_params()
    {
      return {CRYPTONOTE_NOISE_CHANNELS, noise_min_epoch, noise_epoch_range};
    }

    constexpr relay_zone_params public_zone_params()
    {
      return {CRYPTONOTE_DANDELIONPP_STEMS, dandelionpp_min_epoch, dandelionpp_epoch_range};
    }

    /*! \return A relay zone for this daemon zone.

        The relay parameters this side still chooses, because it is the only
        side that knows how the zone is configured. Note the two questions are
        independent: the epoch comes from whether *noise* is enabled, and the
        fluff reach from which *network* this is. An i2p zone with noise
        disabled still fluffs outbound-only. Everything the zone then *does*
        with them belongs to `shekyl-relay`. */
    RelayZoneHandle* make_relay_zone(const epee::net_utils::zone nzone, const bool covert_enabled)
    {
      const relay_zone_params params = covert_enabled ? noise_zone_params() : public_zone_params();

      /* Named bits, not two bools: adjacent `bool` arguments transpose silently
         across a C ABI, and transposing these two swaps the i2p/tor
         outbound-only fluff rule with the covert enable — the regression RP-3a
         shipped once. This is also the ONLY place the covert-enabled fact is
         derived from the payload; every other site asks the zone. */
      std::uint32_t flags = 0;
      if (nzone != epee::net_utils::zone::public_)
        flags |= SHEKYL_RELAY_ZONE_OUTBOUND_FLUFF_ONLY;
      if (covert_enabled)
        flags |= SHEKYL_RELAY_ZONE_COVERT_ENABLED;

      return shekyl_relay_zone_new(
        now_ms(), params.stems,
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
      blob = epee::levin::try_compress_message(std::move(blob));
      return p2p.send(std::move(blob), destination);
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

       This code uses a strand per "zone" and a strand per "channel in a zone".
       `dispatch` is used heavily, which means "execute immediately in _this_
       thread if the strand is not in use, otherwise queue the callback to be
       executed immediately after the strand completes its current task".
       `post` is used where deferred execution to an `asio::io_context::run`
       thread is preferred.

       The strand per "zone" serializes access to the relay zone handle, which
       is a `&mut self` state machine in Rust and must have exactly one caller
       at a time. It also keeps `foreach_connection` — which takes a lock of its
       own — off the notifying thread.

       The strand per "channel" may need a re-visit. The most "expensive" code
       is figuring out the noise/notification to send. If levin code is
       optimized further, it might be better to just use standard locks per
       channel. */

    //! A queue of levin messages for a noise i2p/tor link
    struct noise_channel
    {
      explicit noise_channel(boost::asio::io_context& io_service)
        : active(nullptr),
          queue(),
          strand(io_service),
          connection(boost::uuids::nil_uuid())
      {}

      // `asio::io_context::strand` cannot be copied or moved
      noise_channel(const noise_channel&) = delete;
      noise_channel& operator=(const noise_channel&) = delete;

      // Only read/write these values "inside the strand"

      epee::byte_slice active;
      std::deque<epee::byte_slice> queue;
      boost::asio::io_context::strand strand;
      boost::uuids::uuid connection;
    };
  } // anonymous

  namespace detail
  {
    struct zone
    {
      explicit zone(boost::asio::io_context& io_service, std::shared_ptr<connections> p2p, epee::byte_slice covert_payload_in, epee::net_utils::zone zone, bool pad_txs)
        : p2p(std::move(p2p)),
          covert_payload(std::move(covert_payload_in)),
          wake(io_service),
          strand(io_service),
          channels(),
          relay(make_relay_zone(zone, !covert_payload.empty()), &shekyl_relay_zone_free),
          pending_wakes(0),
          nzone(zone),
          pad_txs(pad_txs)
      {
        /* Channel construction asks the zone, not the payload: the enable fact
           has exactly one birth site (the `make_relay_zone` argument above) and
           every other reader — this loop included — consumes the zone's copy.
           Width comes from the zone's stem count (channel i ↔ slot i), not a
           parallel `#define`, so the two sides cannot silently diverge.
           `relay` is fully initialized here because members initialize in
           declaration order and this is the constructor body. */
        const std::size_t channel_width = shekyl_relay_zone_stem_width(relay.get());
        for (std::size_t count = 0;
             shekyl_relay_zone_covert_enabled(relay.get()) && count < channel_width;
             ++count)
          channels.emplace_back(io_service);
      }

      const std::shared_ptr<connections> p2p;
      /*! The dummy covert packet, and the fragment unit every covert send is
          cut to. Payload ONLY: whether the zone runs covert channels is the
          zone's fact now (`shekyl_relay_zone_covert_enabled`), not this
          field's emptiness. It used to be both, which is why nine sites
          re-derived an enable flag from a byte buffer (§20.4). */
      const epee::byte_slice covert_payload;
      /*! One timer for every scheduled relay step, armed from
          `shekyl_relay_zone_next_wake()`. The zone owns the deadline *value*;
          this owns the *sleep*. A second timer would need a second deadline,
          and that would be a copy of a fact the zone already holds. */
      boost::asio::steady_timer wake;
      boost::asio::io_context::strand strand;
      std::deque<noise_channel> channels;  //!< Never touch after init; only update elements on `noise_channel.strand`
      //! Stem map, per-peer fluff batches, epoch role. Only touch in `strand`.
      const std::unique_ptr<RelayZoneHandle, void (*)(RelayZoneHandle*)> relay;
      /*! Outstanding `wake` callbacks. Re-arming cancels the pending wait, and a
          canceled callback that re-armed in turn would cancel the next one
          forever — so only the last outstanding callback does work. The
          inherited `flush_callbacks` guarded the same hazard on `flush_txs`. */
      std::uint32_t pending_wakes;
      const epee::net_utils::zone nzone;         //!< Zone is public ipv4/ipv6 connections, or i2p or tor
      const bool pad_txs;                        //!< Pad txs to the next boundary for privacy
    };
  } // detail

  namespace
  {
    //! Adds a message to the sending queue of the channel.
    class queue_covert_notify
    {
      std::shared_ptr<detail::zone> zone_;
      epee::byte_slice message_; // Requires manual copy constructor
      const std::size_t destination_;

    public:
      queue_covert_notify(std::shared_ptr<detail::zone> zone, epee::byte_slice message, std::size_t destination)
        : zone_(std::move(zone)), message_(std::move(message)), destination_(destination)
      {}

      queue_covert_notify(queue_covert_notify&&) = default;
      queue_covert_notify(const queue_covert_notify& source)
        : zone_(source.zone_), message_(source.message_.clone()), destination_(source.destination_)
      {}

      //! \pre Called within `zone_->channels[destionation_].strand`.
      void operator()()
      {
        if (!zone_)
          return;

        noise_channel& channel = zone_->channels.at(destination_);
        assert(channel.strand.running_in_this_thread());

        /* Truthful within one covert interval: `clear_channel` nils this at
           every due tick the stem slot spends unbound, and `send_noise` nils
           it on a send failure — so nil here means the channel will not fire
           and queuing would accumulate without bound. */
        if (!channel.connection.is_nil())
          channel.queue.push_back(std::move(message_));
        else if (destination_ == 0 && shekyl_relay_zone_live_stems(zone_->relay.get()) == 0)
          MWARNING("Unable to send transaction(s) to " << epee::net_utils::zone_to_string(zone_->nzone) <<
			" - no available outbound connections");
      }
    };

    //! Clears a channel whose stem slot is unbound at a due tick.
    struct clear_channel
    {
      std::shared_ptr<detail::zone> zone_;
      const std::size_t channel_;

      //! \pre Called within `zone_->channels[channel_].strand`.
      void operator()() const
      {
        if (!zone_)
          return;

        noise_channel& channel = zone_->channels.at(channel_);
        assert(channel.strand.running_in_this_thread());

        /* The inherited nil-repoint semantics (`update_channel` with a nil
           connection), kept exactly. Nil the binding so `queue_covert_notify`'s
           enqueue guard reads the truth and stops queuing to a channel that no
           longer fires; drop the in-flight remainder (never resume it — CV-1);
           drop the queue, because every covert message was cloned to every
           channel, so the surviving channels still carry it, and holding it
           here would grow without bound on a node with fewer peers than
           channels — a permanent state for a one-outbound-connection zone.
           The bound-to-bound repoint has no analogue here: the new binding
           travels with the next send, where `send_noise` rebinds and discards
           the remainder.

           Runs at EVERY due tick while the slot stays unbound, not once at
           the transition — Rust derives it from the map at each poll rather
           than remembering what the binding used to be. Every line below is
           idempotent, which is what makes that repetition free, and it is
           what makes a lost or swallowed clear self-heal one covert interval
           later instead of leaving the enqueue guard stale forever. */

        channel.connection = boost::uuids::nil_uuid();
        channel.active = nullptr;
        channel.queue.clear();
      }
    };

    /*! Performs the effects a relay-zone call produced.

        Both handlers are transport: frame and send, or re-point a covert
        channel at a new stem slot. Neither decides anything — the decisions were
        taken in Rust before the callback fired, which is why no variant tag
        crosses the boundary and there is nothing here to decode wrongly.

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
    //! Post a covert send to `channel`'s strand. Defined after `send_noise`.
    void post_covert_send(const std::shared_ptr<detail::zone>& zone, std::size_t channel,
                          const boost::uuids::uuid& peer, const i_core_events* core);

    struct relay_effects
    {
      std::shared_ptr<detail::zone> zone;
      const i_core_events* core = nullptr;
      std::vector<boost::uuids::uuid> outs;

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

          /* Always send with `fluff` flag, even over i2p/tor. The hidden service
             will disable the forwarding delay and immediately fluff. The i2p/tor
             network is therefore replacing the sybil protection of Dandelion++.
             Dandelion++ stem phase over i2p/tor is also worth investigating
             (with/without "noise"?). */
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

      //! A covert channel came due with its stem slot unbound: clear it.
      //!
      //! The other half of the deleted slot array (§20.3): the binding travels
      //! with each send, and the *loss* of a binding travels here — one channel
      //! index, no array, no width to reconcile. Fires per due tick while the
      //! slot stays unbound (see `clear_channel` for why that repetition is
      //! the design). Runs on the zone strand (the wake fired there) and posts
      //! to the channel's own strand, exactly like `on_covert` — nothing reads
      //! the zone handle off the zone strand.
      static void on_covert_unbind(void* ctx, std::size_t channel) noexcept
      {
        assert(ctx != nullptr);
        try
        {
          relay_effects& self = *static_cast<relay_effects*>(ctx);
          if (!self.zone || channel >= self.zone->channels.size())
            return;
          boost::asio::post(self.zone->channels[channel].strand, clear_channel{self.zone, channel});
        }
        catch (const std::exception& e)
        {
          MERROR("covert unbind dispatch threw, channel not cleared: " << e.what());
        }
        catch (...)
        {
          MERROR("covert unbind dispatch threw a non-standard exception, channel not cleared");
        }
      }

      //! A covert channel is due to send.
      //!
      //! Runs on the **zone strand** (the wake fired there) and does no byte
      //! work: it posts to the channel's own strand, which still serializes
      //! `active`/`queue`/`connection` against `queue_covert_notify`. So the
      //! zone handle is never touched from a channel strand — acceptance
      //! item 8 — and the `:374` discipline comment keeps its referent.
      //!
      //! Note what it does NOT take: any hint of what is being sent (CV-4).
      //! C++ picks dummy-or-real from a queue Rust cannot see.
      static void on_covert(void* ctx, std::size_t channel, const std::uint8_t* peer) noexcept
      {
        assert(ctx != nullptr);
        try
        {
          relay_effects& self = *static_cast<relay_effects*>(ctx);
          if (!self.zone || channel >= self.zone->channels.size())
            return;
          /* The binding travels with the send (§20.3's inversion): never nil,
             because an unbound slot emits nothing at all (CV-2). */
          boost::uuids::uuid destination{};
          std::memcpy(std::addressof(destination), peer, sizeof(destination));
          post_covert_send(self.zone, channel, destination, self.core);
        }
        catch (const std::exception& e)
        {
          MERROR("covert send dispatch threw, channel not sent: " << e.what());
        }
        catch (...)
        {
          MERROR("covert send dispatch threw a non-standard exception");
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
      const i_core_events* core_;

      //! \pre Called within `zone->strand`.
      static void arm(std::shared_ptr<detail::zone> zone, const i_core_events* core)
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
        relay_effects sink{zone_, core_};
        shekyl_relay_zone_poll(
          zone_->relay.get(), now_ms(),
          std::addressof(sink), relay_effects::on_outbound,
          relay_effects::on_fluff, relay_effects::on_covert_unbind,
          relay_effects::on_covert
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
      const i_core_events* core_;

      void operator()()
      {
        run(std::move(zone_), epee::to_span(txs_), source_, core_);
      }

      //! \pre Called within `zone->strand`.
      static void run(std::shared_ptr<detail::zone> zone, epee::span<const blobdata> txs, const boost::uuids::uuid& source, const i_core_events* core)
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

        std::int32_t plan = shekyl_relay_zone_plan_relay_with_refresh(
          zone_->relay.get(), uuid_bytes(source_), local_origin,
          uuid_bytes(outs), outs.size(),
          reinterpret_cast<std::uint8_t*>(std::addressof(destination))
        );

        if (plan != SHEKYL_RELAY_PLAN_FLUFF_EPOCH)
        {
          core_->on_transactions_relayed(epee::to_span(txs_), relay_method::stem);

          if (plan == SHEKYL_RELAY_PLAN_STEM &&
              make_payload_send_txs(*zone_->p2p, std::vector<blobdata>{txs_}, destination, zone_->pad_txs, false))
          {
            record_stem_observation(zone_->relay.get(), txs_, destination, source_);
            /* Source is intentionally omitted in debug log for privacy - a
               nil uuid indicates source is that node. */
            MDEBUG("Sent " << txs_.size() << " transaction(s) to " << destination << " using Dandelion++ stem");
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
              make_payload_send_txs(*zone_->p2p, std::vector<blobdata>{txs_}, destination, zone_->pad_txs, false))
          {
            record_stem_observation(zone_->relay.get(), txs_, destination, source_);
            MDEBUG("Sent " << txs_.size() << " transaction(s) to " << destination << " using Dandelion++ stem");
            return;
          }

          MERROR("Unable to send transaction(s) via Dandelion++ stem");
        }

        core_->on_transactions_relayed(epee::to_span(txs_), relay_method::fluff);
        relay_fluff::run(std::move(zone_), epee::to_span(txs_), source_, core_);
      }
    };

    /*! Sends one covert packet on a channel the zone said is due.

        No timer and no re-arm: the zone owns *when* (§20.2a), so this is a
        handler posted to the channel's strand, not a self-perpetuating wait.
        Deleting `next_noise` is what makes the zone strand the sole caller
        into the relay handle — with per-channel timers, this ran on a channel
        strand and would have had to reach the handle from there. */
    struct send_noise
    {
      std::shared_ptr<detail::zone> zone_;
      const std::size_t channel_;
      const boost::uuids::uuid peer_;
      const i_core_events* core_;

      //! \pre Called within `zone_->channels[channel_].strand`.
      void operator()()
      {
        if (!zone_ || !zone_->p2p)
          return;

        assert(zone_->channels.at(channel_).strand.running_in_this_thread());
        static_assert(
          CRYPTONOTE_MAX_FRAGMENTS <= (noise_min_epoch / (noise_min_delay + noise_delay_range)),
          "Max fragments more than the max that can be sent in an epoch"
        );

        noise_channel& channel = zone_->channels.at(channel_);
        if (channel.connection != peer_)
        {
          /* Rebind at send time — §20.3's inversion moves the binding here
             from the pushed-slot repoint. Clearing `active` restarts any
             in-flight message rather than resuming it (CV-1): the remainder
             of a real fragment run sent to the new peer would make this send
             longer than a dummy, and length is the one thing the covert
             channel holds constant. */
          channel.connection = peer_;
          channel.active = nullptr;
        }

        if (!channel.connection.is_nil())
        {
          epee::byte_slice message = nullptr;
          if (!channel.active.empty())
            message = channel.active.take_slice(zone_->covert_payload.size());
          else if (!channel.queue.empty())
          {
            channel.active = channel.queue.front().clone();
            message = channel.active.take_slice(zone_->covert_payload.size());
          }
          else
            message = zone_->covert_payload.clone();

          if (zone_->p2p->send(std::move(message), channel.connection))
          {
            if (!channel.queue.empty() && channel.active.empty())
              channel.queue.pop_front();
          }
          else
          {
            channel.active = nullptr;
            channel.connection = boost::uuids::nil_uuid();
            auto height = get_blockchain_height(*zone_->p2p, core_);

            auto connections = get_out_connections(*zone_->p2p, height);
            if (connections.empty())
              MWARNING("Unable to send transaction(s) to " << epee::net_utils::zone_to_string(zone_->nzone) <<
			" - no suitable outbound connections at height " << height);

            boost::asio::post(zone_->strand, [z = zone_, connections = std::move(connections)] {
              relay_update_stems(z, connections);
            });
          }
        }

      }
    };

    void post_covert_send(const std::shared_ptr<detail::zone>& zone, const std::size_t channel,
                          const boost::uuids::uuid& peer, const i_core_events* core)
    {
      boost::asio::post(zone->channels[channel].strand, send_noise{zone, channel, peer, core});
    }
  } // anonymous

  notify::notify(boost::asio::io_context& service, std::shared_ptr<connections> p2p, epee::byte_slice noise, epee::net_utils::zone zone, const bool pad_txs, i_core_events& core)
    : zone_(std::make_shared<detail::zone>(service, std::move(p2p), std::move(noise), zone, pad_txs))
    , core_(std::addressof(core))
  {
    if (!zone_->p2p)
      throw std::logic_error{"cryptonote::levin::notify cannot have nullptr p2p argument"};
    if (!zone_->relay)
      throw std::logic_error{"cryptonote::levin::notify could not open its relay zone"};

    const bool covert_enabled = shekyl_relay_zone_covert_enabled(zone_->relay.get());
    if (covert_enabled || zone == epee::net_utils::zone::public_)
    {
      const auto now = std::chrono::steady_clock::now();

      /* The zone drew its first epoch when it was constructed, matching the
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
    const bool noise = shekyl_relay_zone_covert_enabled(zone_->relay.get());
    bool has_outgoing = connection_count;
    if (!noise)
      has_outgoing = zone_->p2p->get_out_connections_count();
    return {noise, CRYPTONOTE_NOISE_CHANNELS <= connection_count, has_outgoing};
  }

  void notify::new_out_connection()
  {
    if (!zone_ || !shekyl_relay_zone_covert_enabled(zone_->relay.get()) ||
        CRYPTONOTE_NOISE_CHANNELS <= shekyl_relay_zone_live_stems(zone_->relay.get()))
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
      relay_effects sink{z, core};
      shekyl_relay_zone_poll(
        z->relay.get(), shekyl_relay_zone_next_wake(z->relay.get()),
        std::addressof(sink), relay_effects::on_outbound,
        relay_effects::on_fluff, relay_effects::on_covert_unbind, relay_effects::on_covert
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

  void notify::record_arrival(std::shared_ptr<const std::vector<blobdata>> txs)
  {
    if (!zone_ || !txs || txs->empty())
      return;

    /* The strand serializes all access to the relay handle; this is a
       read-modify of the zone's stem watch, so it takes the same path as
       every other handle call rather than racing them. */
    boost::asio::dispatch(zone_->strand, [zone = zone_, txs = std::move(txs)] ()
    {
      const std::vector<crypto::hash> hashes = canonical_tx_hashes(*txs);
      if (hashes.empty())
        return;
      shekyl_relay_zone_record_arrival(
        zone->relay.get(), reinterpret_cast<const std::uint8_t*>(hashes.data()), hashes.size());
    });
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

    /* If noise is enabled in a zone, it always takes precedence. The technique
       provides good protection against ISP adversaries, but not sybil
       adversaries. Noise is currently only enabled over I2P/Tor - those
       networks provide protection against sybil attacks (we only send to
       outgoing connections).

       If noise is disabled, Dandelion++ is used for public networks only.
       Dandelion++ over I2P/Tor should be an interesting case to investigate,
       but the mempool/stempool needs to know the zone a tx originated from to
       work properly. */

    if (shekyl_relay_zone_covert_enabled(zone_->relay.get()) && !zone_->channels.empty())
    {
      // covert send in "noise" channel
      static_assert(
        CRYPTONOTE_MAX_FRAGMENTS * CRYPTONOTE_NOISE_BYTES <= LEVIN_DEFAULT_MAX_PACKET_SIZE, "most nodes will reject this fragment setting"
      );

      if (tx_relay == relay_method::stem)
      {
        MWARNING("Dandelion++ stem not supported over noise networks");
        tx_relay = relay_method::local; // do not put into stempool embargo (hopefully not there already!).
      }

      core_->on_transactions_relayed(epee::to_span(txs), tx_relay);

      // Padding is not useful when using noise mode. Send as stem so receiver
      // forwards in Dandelion++ mode.
      epee::byte_slice message = epee::levin::make_fragmented_notify(
        zone_->covert_payload.size(), NOTIFY_NEW_TRANSACTIONS::ID, make_tx_message(std::move(txs), false, false)
      );
      if (CRYPTONOTE_MAX_FRAGMENTS * zone_->covert_payload.size() < message.size())
      {
        MERROR("notify::send_txs provided message exceeding covert fragment size");
        return false;
      }

      for (std::size_t channel = 0; channel < zone_->channels.size(); ++channel)
      {
        boost::asio::dispatch(
          zone_->channels[channel].strand,
          queue_covert_notify{zone_, message.clone(), channel}
        );
      }
    }
    else
    {
      switch (tx_relay)
      {
        default:
        case relay_method::none:
        case relay_method::block:
          return false;
        case relay_method::stem:
        case relay_method::forward:
        case relay_method::local:
          if (zone_->nzone == epee::net_utils::zone::public_)
          {
            // this will change a local/forward tx to stem or fluff ...
            boost::asio::dispatch(
              zone_->strand,
              dandelionpp_notify{zone_, core_, std::move(txs), source, tx_relay}
            );
            break;
          }
          /* fallthrough */
        case relay_method::fluff:
          /* If sending stem/forward/local txes over non public networks,
             continue to claim that relay mode even though it used the "fluff"
             routine. A "fluff" over i2p/tor is not the same as a "fluff" over
             ipv4/6. Marking it as "fluff" here will make the tx immediately
             visible externally from this node, which is not desired. */
          core_->on_transactions_relayed(epee::to_span(txs), tx_relay);
          boost::asio::dispatch(zone_->strand, relay_fluff{zone_, std::move(txs), source, core_});
          break;
      }
    }
    return true;
  }
} // levin
} // net
