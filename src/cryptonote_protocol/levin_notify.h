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

#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/uuid/uuid.hpp>
#include <memory>
#include <string>
#include <vector>

#include "byte_slice.h"
#include "crypto/hash.h"
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_protocol/enums.h"
#include "cryptonote_protocol/fwd.h"
#include "net/enums.h"
#include "span.h"

namespace epee
{
namespace levin
{
    template<typename> class async_protocol_handler_config;
}
}

namespace nodetool
{
  template<typename> struct p2p_connection_context_t;
}

namespace cryptonote
{
namespace levin
{
  namespace detail
  {
    using p2p_context = nodetool::p2p_connection_context_t<cryptonote::cryptonote_connection_context>;
    struct zone; //!< Internal data needed for zone notifications
  } // detail

  using connections = epee::levin::async_protocol_handler_config<detail::p2p_context>;

  /*! Turn the noise carrier on for ENCRYPTED zones built after this call.
      Development only; defaults off, and the default is shipped behaviour.

      Runtime rather than `#ifdef` so the carrier's path is reachable by the
      ordinary test suite: a compile-time gate makes the only configuration
      that runs the carrier the one CI never builds. Not an operator switch —
      `COVER_TRAFFIC_RESTORATION.md` §3.1 is the ruling, and enabling it under
      today's embargo constants runs an encrypted zone's alpha below the
      0.90 pin. Returns the previous value so a test can restore it. */
  bool set_carrier_development(bool enabled) noexcept;

  //! Whether the development carrier opt-in is currently set.
  bool carrier_development_enabled() noexcept;

  //! Provides tx notification privacy
  class notify
  {
    std::shared_ptr<detail::zone> zone_;
    i_core_events* core_;

  public:
    struct status
    {
      bool has_noise;
      bool connections_filled; //!< True when has zone has `CRYPTONOTE_NOISE_CHANNELS` outgoing noise channels
      bool has_outgoing; //!< True when zone has outgoing connections
    };

    //! Construct an instance that cannot notify.
    notify() noexcept
      : zone_(nullptr)
      , core_(nullptr)
    {}

    //! Construct an instance with available notification `zones`.
    explicit notify(boost::asio::io_context& service, std::shared_ptr<connections> p2p, epee::net_utils::zone zone, bool pad_txs, i_core_events& core);

    notify(const notify&) = delete;
    notify(notify&&) = default;

    ~notify() noexcept;

    notify& operator=(const notify&) = delete;
    notify& operator=(notify&&) = default;

    //! \return Status information for zone selection.
    status get_status() const noexcept;

    //! Probe for new outbound connection - skips if not needed.
    void new_out_connection();

    void on_handshake_complete(const boost::uuids::uuid &id, bool is_income);
    void on_connection_close(const boost::uuids::uuid &id);

    //! Run the logic for the next epoch immediately. Only use in testing.
    void run_epoch();

    /*! Advance to the zone's next scheduled event and run it — one poll at
        `next_wake()`, exactly as the production timer would, then re-arm.
        Only use in testing.

        Renamed from the inherited `run_stems`, whose name was a dead
        assumption twice over: it never touched Dandelion++ stems, and after
        RP-3b its body no longer cancels noise timers either (there are none
        to cancel — the zone folds every covert deadline into `next_wake()`).
        The name follows the body (§20.6). */
    void run_next_wake();

    //! Run the logic for flushing all Dandelion++ fluff queued txs. Only use in testing.
    void run_fluff();

    /*! Send txs using `cryptonote_protocol_defs.h` payload format wrapped in a
        levin header. Dandelion++ decides the phase on every zone, regardless
        of whether the zone also runs noise channels
        (`shekyl_relay_zone_noise_enabled`). Noise is a carrier, not a routing
        verdict: it does not demote a stem, and it does not broadcast to every
        channel. Until the daemon cutover gives `NoiseQueues` an in-process
        caller, a noise-configured zone still emits its dummy cadence but this
        method does not queue the transaction onto it.

        \param txs The transactions that need to be serialized and relayed.
        \param source The source of the notification. `is_nil()` indicates this
          node is the source. Dandelion++ will use this to map a source to a
          particular stem.

      \return True iff the notification is queued for sending. */
    bool send_txs(std::vector<blobdata> txs, const boost::uuids::uuid& source, relay_method tx_relay);

    //! §46: resolve pending stem observations for arrived **canonical hashes**
    //! (any peer, any path — called on every zone, before pool admission).
    //! Hashes are the join key (F-9); the caller parses once and fans one
    //! shared vector so multi-zone nodes do not re-parse per zone. Unknown
    //! hashes are ignored Rust-side.
    void record_arrival(std::shared_ptr<const std::vector<crypto::hash>> hashes, const boost::uuids::uuid& from);

    //! §55: one published stem-outcome row (peer + raw counts). Layout
    //! matches the Rust FFI row; kept as a C++ type here so this header does
    //! not pull in the whole shekyl_ffi surface.
    struct stem_tally_row
    {
      std::uint8_t peer[16];
      std::uint64_t propagated;
      std::uint64_t silent;
      std::uint64_t distinct_sources;
    };

    //! §55: this zone's published stem-outcome rows. Two-call sizing on row
    //! count; the write-call return is authoritative when it fits. Reads a
    //! published snapshot, so it is safe from any thread — same discipline
    //! as `stem_in_flight` below. Transit for a Rust->Rust readout; see the
    //! .cpp note.
    std::vector<stem_tally_row> stem_snapshot() const;

    //! §18.4 diagnostic for the admin snapshot: false until the zone has
    //! reported once. Never exposed on the public listener (§16.3).
    bool floor_snapshot(std::uint32_t& achieved, std::uint32_t& floor, bool& below) const;

    //! §46: stem observations pending resolution. Reads a published atomic on
    //! the relay handle (same discipline as `live_stems` / get_status), so it
    //! is safe from any thread — including the gtest harness after it drains
    //! the strand.
    std::size_t stem_in_flight() const;
  };

  //! One stem-tally JSON object, including the zone it was collected from.
  //! Production `node_server::stem_tallies_json` and the unit table call this
  //! so the label cannot drift from the merge. What edit reds the zone field:
  //! omit `"zone"` here. `ShekylStemTallyRow` stays 40 bytes -- the zone is
  //! known at C++ merge time, not on the FFI row.
  std::string format_stem_tally_row_json(
    const notify::stem_tally_row& row, epee::net_utils::zone z);

  //! §46/§48: canonical tx hashes for the stem-observation watch (F-9).
  //! Parsed once at the fan-out boundary; blob bytes are not a stable identity
  //! across relay hops.
  std::vector<crypto::hash> stem_watch_tx_hashes(const std::vector<cryptonote::blobdata>& txs);
} // levin
} // cryptonote
