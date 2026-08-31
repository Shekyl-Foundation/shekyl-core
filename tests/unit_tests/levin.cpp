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

#include <algorithm>
#include <boost/uuid/nil_generator.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <cstring>
#include <gtest/gtest.h>
#include <limits>
#include <set>
#include <map>

#include "byte_slice.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/connection_context.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/i_core_events.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_protocol/levin_notify.h"
#include "int-util.h"
#include "p2p/net_node.h"
#include "net/levin_base.h"
#include "net/levin_compression.h"
#include "span.h"

namespace
{
    class test_endpoint final : public epee::net_utils::i_service_endpoint
    {
        boost::asio::io_context& io_service_;
        std::size_t ref_count_;

      public:
        /*! When false, every `do_send` fails — the transport rejecting a write.

            Process-wide because `test_endpoint` is constructed deep inside the
            connection machinery and has no seam a fixture could thread a flag
            through. Restored by RAII at each use; a leaked `false` would fail
            unrelated fixtures and read as a flake. */
        static bool& deliver()
        {
            static bool value = true;
            return value;
        }

      private:
        virtual bool do_send(epee::byte_slice message) override final
        {
            if (!deliver())
                return false;
            send_queue_.push_back(std::move(message));
            return true;
        }

        virtual bool close() override final
        {
            return true;
        }

        virtual bool send_done() override final
        {
            throw std::logic_error{"send_done not implemented"};
        }

        virtual bool call_run_once_service_io() override final
        {
            return io_service_.run_one();
        }

        virtual bool request_callback() override final
        {
            throw std::logic_error{"request_callback not implemented"};
        }

        virtual boost::asio::io_context& get_io_context() override final
        {
            return io_service_;
        }

        virtual bool add_ref() override final
        {
            ++ref_count_;
            return true;
        }

        virtual bool release() override final
        {
            --ref_count_;
            return true;
        }

    public:
        test_endpoint(boost::asio::io_context& io_service)
          : epee::net_utils::i_service_endpoint(),
	          io_service_(io_service),
            ref_count_(0),
            send_queue_()
        {}

        virtual ~test_endpoint() noexcept(false) override final
        {
            EXPECT_EQ(0u, ref_count_);
        }

        std::deque<epee::byte_slice> send_queue_;
    };

    class test_core_events final : public cryptonote::i_core_events
    {
        std::map<cryptonote::relay_method, std::vector<cryptonote::blobdata>> relayed_;
        std::map<cryptonote::relay_method, epee::net_utils::zone> zones_;
        //! Propagation verdicts, in arrival order. Read by
        //! `stem_watch_records_and_arrival_resolves`, which is what makes the
        //! forwarding leg asserted rather than inferred from the watch.
        std::vector<crypto::hash> stem_propagated_;

        virtual bool is_synchronized() const final
        {
            return false;
        }

        virtual uint64_t get_current_blockchain_height() const final
        {
            return 0;
        }

        virtual void on_stem_propagated(epee::span<const crypto::hash> txids) override final
        {
            for (const auto& id : txids)
                stem_propagated_.push_back(id);
        }

        virtual void on_transactions_relayed(epee::span<const cryptonote::blobdata> txes, cryptonote::relay_method relay, epee::net_utils::zone zone) override final
        {
            std::vector<cryptonote::blobdata>& cached = relayed_[relay];
            for (const auto& tx : txes)
                cached.push_back(tx);
            /* §89.2: the embargo is drawn per zone, and the zone arrives here
               rather than on the txpool entry. Recorded so a test can assert
               WHICH zone a relay was attributed to — asserting only the relay
               method would pass whatever zone the dispatch happened to pick. */
            zones_[relay] = zone;
        }

    public:
        test_core_events()
          : relayed_()
        {}

        std::size_t relayed_method_size() const noexcept
        {
            return relayed_.size();
        }

        bool has_stem_txes() const noexcept
        {
            return relayed_.count(cryptonote::relay_method::stem);
        }

        //! \return The zone the last `relay`-method relay was attributed to.
        epee::net_utils::zone relayed_zone(cryptonote::relay_method relay) const
        {
            const auto found = zones_.find(relay);
            if (found == zones_.end())
                throw std::logic_error{"no relay recorded for that method"};
            return found->second;
        }

        //! \return Every propagation verdict forwarded so far, in arrival order.
        const std::vector<crypto::hash>& stem_propagated() const noexcept
        {
            return stem_propagated_;
        }

        std::vector<cryptonote::blobdata> take_relayed(cryptonote::relay_method relay)
        {
            auto elems = relayed_.find(relay);
            if (elems == relayed_.end())
                throw std::logic_error{"on_transactions_relayed empty"};

            std::vector<cryptonote::blobdata> out{std::move(elems->second)};
            relayed_.erase(elems);
            /* Zone rides with the relay event; drop it with the blobs so
               `relayed_zone` cannot return a stale attribution after consume. */
            zones_.erase(relay);
            return out;
        }
    };

    class test_connection
    {
        test_endpoint endpoint_;
        cryptonote::levin::detail::p2p_context context_;
        epee::levin::async_protocol_handler<cryptonote::levin::detail::p2p_context> handler_;

    public:
        test_connection(boost::asio::io_context& io_service, cryptonote::levin::connections& connections, boost::uuids::random_generator& random_generator, const bool is_incoming)
          : endpoint_(io_service),
            context_(),
            handler_(std::addressof(endpoint_), connections, context_)
        {
            using base_type = epee::net_utils::connection_context_base;
            static_cast<base_type&>(context_) = base_type{random_generator(), {}, is_incoming, false};
            context_.m_state = cryptonote::cryptonote_connection_context::state_normal;
            handler_.after_init_connection();
        }

        //! Sizes of the frames still queued, as they would go on the wire.
        //!
        //! The decoded-message assertions elsewhere in this file cannot see
        //! a size defect: the receive path inflates a COMPRESSED bucket
        //! before handing it up, so padding present in the *decoded*
        //! message says nothing about whether it survived to the wire.
        std::vector<std::size_t> queued_wire_sizes() const
        {
            std::vector<std::size_t> sizes;
            sizes.reserve(endpoint_.send_queue_.size());
            for (const auto& message : endpoint_.send_queue_)
                sizes.push_back(message.size());
            return sizes;
        }

        //\return Number of messages processed
        std::size_t process_send_queue(const bool valid = true)
        {
            std::size_t count = 0;
            for ( ; !endpoint_.send_queue_.empty(); ++count, endpoint_.send_queue_.pop_front())
            {
                EXPECT_EQ(valid, handler_.handle_recv(endpoint_.send_queue_.front().data(), endpoint_.send_queue_.front().size()));
            }
            return count;
        }

        const boost::uuids::uuid& get_id() const noexcept
        {
            return context_.m_connection_id;
        }

        bool is_incoming() const noexcept
        {
            return context_.m_is_income;
        }
    };

    struct received_message
    {
        boost::uuids::uuid connection;
        int command;
        std::string payload;
    };

    class test_receiver final : public epee::levin::levin_commands_handler<cryptonote::levin::detail::p2p_context>
    {
        std::deque<received_message> invoked_;
        std::deque<received_message> notified_;

        template<typename T>
        static std::pair<boost::uuids::uuid, typename T::request> get_message(std::deque<received_message>& queue)
        {
            if (queue.empty())
                throw std::logic_error{"Queue has no received messges"};

            if (queue.front().command != T::ID)
                throw std::logic_error{"Unexpected ID at front of message queue"};

            epee::serialization::portable_storage storage{};
            if(!storage.load_from_binary(epee::strspan<std::uint8_t>(queue.front().payload)))
                throw std::logic_error{"Unable to parse epee binary format"};

            typename T::request request{};
            if (!request.load(storage))
                throw std::logic_error{"Unable to load into expected request"};

            boost::uuids::uuid connection = queue.front().connection;
            queue.pop_front();
            return {connection, std::move(request)};
        }

        static received_message get_raw_message(std::deque<received_message>& queue)
        {
            received_message out{std::move(queue.front())};
            queue.pop_front();
            return out;
        }

        virtual int invoke(int command, const epee::span<const uint8_t> in_buff, epee::byte_stream& buff_out, cryptonote::levin::detail::p2p_context& context) override final
        {
            buff_out.clear();
            invoked_.push_back(
                {context.m_connection_id, command, std::string{reinterpret_cast<const char*>(in_buff.data()), in_buff.size()}}
            );
            return 1;
        }

        virtual int notify(int command, const epee::span<const uint8_t> in_buff, cryptonote::levin::detail::p2p_context& context) override final
        {
            notified_.push_back(
                {context.m_connection_id, command, std::string{reinterpret_cast<const char*>(in_buff.data()), in_buff.size()}}
            );
            return 1;
        }

        virtual void callback(cryptonote::levin::detail::p2p_context& context) override final
        {}

        virtual void on_connection_new(cryptonote::levin::detail::p2p_context& context) override final
        {
            if (notifier)
                notifier->on_handshake_complete(context.m_connection_id, context.m_is_income);
        }

        virtual void on_connection_close(cryptonote::levin::detail::p2p_context& context) override final
        {
            if (notifier)
                notifier->on_connection_close(context.m_connection_id);
        }

    public:
        test_receiver()
          : epee::levin::levin_commands_handler<cryptonote::levin::detail::p2p_context>(),
            invoked_(),
            notified_()
        {}

        virtual ~test_receiver() noexcept override final{}

        std::size_t invoked_size() const noexcept
        {
            return invoked_.size();
        }

        std::size_t notified_size() const noexcept
        {
            return notified_.size();
        }

        template<typename T>
        std::pair<boost::uuids::uuid, typename T::request> get_invoked()
        {
            return get_message<T>(invoked_);
        }

        template<typename T>
        std::pair<boost::uuids::uuid, typename T::request> get_notification()
        {
            return get_message<T>(notified_);
        }

        received_message get_raw_notification()
        {
            return get_raw_message(notified_);
        }

        std::shared_ptr<cryptonote::levin::notify> notifier{};
    };

    class levin_notify : public ::testing::Test
    {
        const std::shared_ptr<cryptonote::levin::connections> connections_;
        std::set<boost::uuids::uuid> connection_ids_;

    public:
        levin_notify()
          : ::testing::Test(),
            connections_(std::make_shared<cryptonote::levin::connections>()),
            connection_ids_(),
            random_generator_(),
            io_service_(),
            receiver_(),
            contexts_(),
            events_()
        {
            connections_->set_handler(std::addressof(receiver_), nullptr);
        }

        virtual void TearDown() override final
        {
            EXPECT_EQ(0u, receiver_.invoked_size());
            EXPECT_EQ(0u, receiver_.notified_size());
            EXPECT_EQ(0u, events_.relayed_method_size());
        }

        cryptonote::levin::connections& get_connections() noexcept { return *connections_; }

        void add_connection(const bool is_incoming)
        {
            contexts_.emplace_back(io_service_, *connections_, random_generator_, is_incoming);
            EXPECT_TRUE(connection_ids_.emplace(contexts_.back().get_id()).second);
            EXPECT_EQ(connection_ids_.size(), connections_->get_connections_count());
        }

        /*! Build a notifier on the clearnet or i2p zone.

            No noise parameter: the C++ noise machinery is deleted and
            `NoiseQueues` owns the window, so a `noise_size` argument has
            nothing left to size. Enabling the carrier is not a per-notifier
            argument either — it is the process-wide runtime opt-in
            `set_carrier_development`, default off, which the cases that need
            it drive explicitly. */
        std::shared_ptr<cryptonote::levin::notify> make_notifier(bool is_public, bool pad_txs)
        {
            epee::net_utils::zone zone = is_public ? epee::net_utils::zone::public_ : epee::net_utils::zone::i2p;
            receiver_.notifier.reset(
              new cryptonote::levin::notify{io_service_, connections_, zone, pad_txs, events_}
            );
            return receiver_.notifier;
        }

        /*! Advance the zone schedule until `stop(sent)` holds, or give up after
            `max_advances`. Each advance processes every context's send queue and
            accumulates the count. Used for covert noise *and* scheduled fluff —
            both ride `run_next_wake()` / the production timer path.

            One advance = one `run_next_wake()` = one poll at the zone's next
            deadline. For covert, that is **one** channel firing (two only when
            independent draws collide on the same millisecond). The inherited
            tests instead cancelled every channel's timer per call, which
            synchronized the channels — a state the production schedule
            structurally cannot produce, and one that would be a covert-traffic
            defect if it could: simultaneous emission makes the aggregate bursty
            and periodic, the exact shape constant-rate cover exists to deny
            (§20.9). Oracles that drive through this helper assert totals over
            however many advances a round needs; the per-advance cadence property
            lives where it can be held deterministically:
            `covert_channels_emit_one_per_advance_not_synchronized` in
            `shekyl-relay`, whose RNG and clock are parameters. */
        template<typename F>
        std::size_t drive_schedule(cryptonote::levin::notify& notifier, F&& stop, const unsigned max_advances = 16)
        {
            std::size_t sent = 0;
            for (unsigned i = 0; i < max_advances && !stop(sent); ++i)
            {
                notifier.run_next_wake();
                io_service_.restart();
                if (io_service_.poll() == 0)
                    break; // the drive is dead; the caller's assertions report it
                for (auto& context : contexts_)
                    sent += context.process_send_queue();
            }
            return sent;
        }

        /*! Fluff totals oracle shared by the force-driven and schedule-driven
            paths. Payload identity, aggregate count, padding empty, and the
            fluff bit are force-independent (§20.10 audit): if either driver
            needs different totals, a fluff assertion has started encoding the
            forced side. Source exclusion and per-peer queue counts stay at the
            call site — those interact with when queues are drained. */
        void expect_fluff_totals(std::vector<cryptonote::blobdata> txs, const std::size_t eligible_peers = 9)
        {
            EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));
            std::sort(txs.begin(), txs.end());
            ASSERT_EQ(eligible_peers, receiver_.notified_size());
            for (std::size_t count = 0; count < eligible_peers; ++count)
            {
                auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
                EXPECT_EQ(txs, notification.txs);
                EXPECT_TRUE(notification._.empty());
                EXPECT_TRUE(notification.dandelionpp_fluff);
            }
        }

        /*! One round of anonymity-zone relay under §89's stemming posture.

            Shared by the six `private_*` cases, which differ only in the method
            handed to `send_txs` and whether padding is on. The assertions are
            written once because six copies is how one of them quietly stops
            checking what it claims to — and one of the things it checks here is
            a rule a port has already broken once.

            \param sent_as method handed to `send_txs` (stem, local or forward)
            \param padded  whether the notifier was built with `pad_txs`
            \return true if this round stemmed rather than fluffed */
        bool run_private_round(cryptonote::levin::notify& notifier,
                               const std::vector<cryptonote::blobdata>& txs,
                               const cryptonote::relay_method sent_as,
                               const bool padded)
        {
            std::vector<cryptonote::blobdata> sorted_txs = txs;
            std::sort(sorted_txs.begin(), sorted_txs.end());

            auto context = contexts_.begin();
            EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), sent_as));

            io_service_.restart();
            EXPECT_LT(0u, io_service_.poll());

            /* §30.5 — an origin keeps its `local` txpool class whatever the
               transport did, so for that case the record no longer
               discriminates the wire outcome, and the origin always stems
               (D++ §4.4). For relayed traffic the record still tracks the
               wire, because it must arm the per-zone embargo (§89.2). */
            const bool originated = (sent_as == cryptonote::relay_method::local);
            const bool is_stem = originated || events_.has_stem_txes();
            const auto method =
              originated ? cryptonote::relay_method::local
                         : (is_stem ? cryptonote::relay_method::stem
                                    : cryptonote::relay_method::fluff);

            /* Exactly one class recorded per round — the negative control for
               the §30.5 rule. `upgrade_relay_method` is monotone, so an origin
               that ALSO recorded `stem` or `fluff` has left the `local` class
               permanently, and the next pool re-relay hands the user's own
               transaction to the clearnet arm. Asserting only that `local` is
               present would pass with that upgrade sitting beside it. */
            EXPECT_EQ(1u, events_.relayed_method_size());

            /* §89.2 draws the embargo per zone, and the zone reaches the draw
               with the relay rather than off the txpool entry. Asserting the
               METHOD alone would pass whichever zone the dispatch attributed
               it to, which is the axis this round changed. */
            EXPECT_EQ(epee::net_utils::zone::i2p, events_.relayed_zone(method));
            EXPECT_EQ(txs, events_.take_relayed(method));

            if (!is_stem)
            {
                notifier.run_fluff();
                io_service_.restart();
                EXPECT_LT(0u, io_service_.poll());
            }

            std::size_t send_count = 0;
            EXPECT_EQ(0u, context->process_send_queue());
            for (++context; context != contexts_.end(); ++context)
            {
                const std::size_t sent = context->process_send_queue();
                /* OUTBOUND ONLY — stemming or fluffing, and this is the
                   assertion to protect. On a hidden service an inbound peer is
                   a stranger who dialled us; RP-3a dropped that rule in the
                   port and these `private_*` cases are what caught it. Opening
                   the stem gates must not cost the catcher. */
                if (sent)
                    EXPECT_EQ(1u, (context - contexts_.begin()) % 2);
                send_count += sent;
            }

            /* One successor when stemming; the outbound half of ten when
               fluffing — never nine, which would mean the outbound-only reach
               was lost. */
            const std::size_t expected = is_stem ? 1u : 5u;
            EXPECT_EQ(expected, send_count);
            EXPECT_EQ(expected, receiver_.notified_size());
            for (std::size_t count = 0; count < expected; ++count)
            {
                auto notification =
                  receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
                EXPECT_EQ(is_stem ? txs : sorted_txs, notification.txs);
                EXPECT_EQ(padded, !notification._.empty());
                /* The flag varies on this zone again (§64.1 reviving §61.1's
                   partition argument): false on a stem send, true on a fluff.
                   Before §89 it was true unconditionally here. */
                EXPECT_EQ(!is_stem, notification.dandelionpp_fluff);
            }
            return is_stem;
        }

        /*! Build a private (i2p) notifier with ten alternating in/out peers
            and two fixed txs — shared setup for the stemming cases. */
        std::shared_ptr<cryptonote::levin::notify> make_private_stem_fixture(const bool padded)
        {
            auto notifier_ptr = make_notifier(false, padded);
            auto& notifier = *notifier_ptr;
            for (unsigned count = 0; count < 10; ++count)
                add_connection(count % 2 == 0);
            {
                const auto status = notifier.get_status();
                EXPECT_FALSE(status.has_noise);
                EXPECT_FALSE(status.connections_filled);
                EXPECT_TRUE(status.has_outgoing);
            }
            notifier.new_out_connection();
            io_service_.poll();
            return notifier_ptr;
        }

        static std::vector<cryptonote::blobdata> private_stem_txs()
        {
            std::vector<cryptonote::blobdata> txs(2);
            txs[0].resize(100, 'e');
            txs[1].resize(200, 'f');
            return txs;
        }

        /*! Drive stem/forward until both epoch roles appear, or pin local as
            always-stem. One shell so the six cases cannot drift. */
        void run_private_stemming_case(const cryptonote::relay_method method,
                                       const bool padded)
        {
            auto notifier_ptr = make_private_stem_fixture(padded);
            auto& notifier = *notifier_ptr;
            const auto txs = private_stem_txs();
            ASSERT_EQ(10u, contexts_.size());

            if (method == cryptonote::relay_method::local)
            {
                /* D++ §4.4: origin always stems, independent of epoch role.
                   Waiting for fluff would hang. Four rounds on freshly drawn
                   epochs so a role-dependent regression cannot hide. */
                for (unsigned round = 0; round < 4; ++round)
                {
                    EXPECT_TRUE(run_private_round(notifier, txs, method, padded))
                      << "local must stem on every epoch role; round " << round;
                    notifier.run_epoch();
                }
                return;
            }

            /* stem and forward are role-dependent — observe both outcomes.
               (forward is NOT exempt the way local is; an earlier draft pinned
               always-stem and failed only when full-suite run order moved RNG.) */
            /* Bounded, and it has to be: the regression these six cases exist
               to catch — the transport gate coming back — pins the outcome to
               one value, and an unbounded wait for the other one turns a red
               assertion into a CI job timeout with no failing test named.
               P(role never varies | correct) = 0.8^64 ≈ 6e-7 at the zone's
               20 % fluff probability, so the bound cannot flake in practice. */
            constexpr unsigned max_rounds = 64;
            bool has_stemmed = false;
            bool has_fluffed = false;
            for (unsigned round = 0; round < max_rounds; ++round)
            {
                const bool is_stem = run_private_round(notifier, txs, method, padded);
                has_stemmed |= is_stem;
                has_fluffed |= !is_stem;
                if (has_stemmed && has_fluffed)
                    return;
                notifier.run_epoch();
            }

            ADD_FAILURE() << "epoch role never varied over " << max_rounds
                          << " rounds (stemmed=" << has_stemmed
                          << " fluffed=" << has_fluffed
                          << ") — the anonymity zone is pinned to one outcome, "
                             "which is what a restored transport gate looks like (§89)";
        }

        boost::uuids::random_generator random_generator_;
        boost::asio::io_context io_service_;
        test_receiver receiver_;
        std::deque<test_connection> contexts_;
        test_core_events events_;
    };
}

/* Pure R-1 coherence gate — pins the production predicate without needing a
   full non-public `handle_notify_new_transactions` mock (§89.7). Fluff must
   never cohere (liveness exit); anonymity stem/local must.

   The table lost its `forward` row when Q12-U2 deleted the class. That row was
   never a separate case here — `forward` and `stem` always answered
   identically — which is a small piece of evidence for the deletion rather
   than against it: a class the routing predicate could not distinguish was not
   carrying a routing distinction. */
TEST(r1_coherence_predicate, table)
{
    using cryptonote::relay_method;
    using epee::net_utils::zone;

    // Fluff is the exit on every origin — coherence would strand txs.
    for (const auto origin : {zone::public_, zone::i2p, zone::tor, zone::invalid})
        EXPECT_FALSE(cryptonote::r1_coherence_keeps_origin(relay_method::fluff, origin));

    // Clearnet / invalid never cohere via this path.
    for (const auto method : {relay_method::stem, relay_method::local})
    {
        EXPECT_FALSE(cryptonote::r1_coherence_keeps_origin(method, zone::public_));
        EXPECT_FALSE(cryptonote::r1_coherence_keeps_origin(method, zone::invalid));
        EXPECT_FALSE(cryptonote::r1_coherence_keeps_origin(relay_method::none, zone::tor));
        EXPECT_FALSE(cryptonote::r1_coherence_keeps_origin(relay_method::block, zone::tor));
    }

    // Pre-fluff on a real anonymity zone — the live §89 path.
    for (const auto method : {relay_method::stem, relay_method::local})
    {
        EXPECT_TRUE(cryptonote::r1_coherence_keeps_origin(method, zone::i2p));
        EXPECT_TRUE(cryptonote::r1_coherence_keeps_origin(method, zone::tor));
        EXPECT_TRUE(cryptonote::is_pre_fluff_relay(method));
    }
    EXPECT_FALSE(cryptonote::is_pre_fluff_relay(relay_method::fluff));
}

/* Q12-D5a once-at-origin routing. Production `send_txs` requires a token
   only this helper can construct. What edit reds the table: return
   `decision::public_clearnet` from the `keep_arrival` arm (coherence
   removed) — `(stem, tor)` below fails. What edit fails to compile:
   constructing a `zone_route` outside this helper, or calling `send_txs`
   without one. The table still does not drive `handle_notify_new_transactions`
   on a non-public context (FOLLOWUPS / `t_core`). */
TEST(once_at_origin_route, table)
{
    using cryptonote::relay_method;
    using cryptonote::zone_route;
    using epee::net_utils::zone;

    // Coherence: still-stemming on a real anonymity origin stays there.
    EXPECT_EQ(zone_route::decision::keep_arrival,
              cryptonote::once_at_origin_route(relay_method::stem, zone::tor).get());
    EXPECT_EQ(zone_route::decision::keep_arrival,
              cryptonote::once_at_origin_route(relay_method::stem, zone::i2p).get());
    EXPECT_EQ(zone_route::decision::keep_arrival,
              cryptonote::once_at_origin_route(relay_method::local, zone::tor).get());

    // Relayed clearnet inherit — no roll. This is the deleted divert.
    EXPECT_EQ(zone_route::decision::public_clearnet,
              cryptonote::once_at_origin_route(relay_method::stem, zone::public_).get());

    // Originated, roll said anon (`invalid`) — fail closed, never clearnet.
    EXPECT_EQ(zone_route::decision::anonymity_fail_closed,
              cryptonote::once_at_origin_route(relay_method::local, zone::invalid).get());
    EXPECT_EQ(zone_route::decision::anonymity_fail_closed,
              cryptonote::once_at_origin_route(relay_method::stem, zone::invalid).get());

    // Originated, roll said clearnet (`public_`) — by design, not a fallback.
    EXPECT_EQ(zone_route::decision::public_clearnet,
              cryptonote::once_at_origin_route(relay_method::local, zone::public_).get());

    /* DESIGN A (sec 91): a fluff floods EVERY configured zone, from every
       origin. It was `public_clearnet` — clearnet alone — which made an
       anonymity zone a depth-one injection point and left a Tor-only node
       unable to maintain a mempool (sec 91.1). Coherence still refuses a
       fluff; what changed is where a refused fluff goes. */
    EXPECT_EQ(zone_route::decision::broadcast_all_zones,
              cryptonote::once_at_origin_route(relay_method::fluff, zone::tor).get());
    EXPECT_EQ(zone_route::decision::broadcast_all_zones,
              cryptonote::once_at_origin_route(relay_method::fluff, zone::i2p).get());
    EXPECT_EQ(zone_route::decision::broadcast_all_zones,
              cryptonote::once_at_origin_route(relay_method::fluff, zone::public_).get());
    EXPECT_EQ(zone_route::decision::broadcast_all_zones,
              cryptonote::once_at_origin_route(relay_method::fluff, zone::invalid).get());
}

/* The roll's zone mapping moved fully behind the FFI
   (`shekyl_relay_zone_roll_originated_zone`, one crossing). Its two former
   witnesses here have owners: outcome distinctness is `roll_mapping_preserves
   _the_design_fallback_distinction` in `shekyl-relay::zone_route`, and the
   byte-to-`epee` cast contract is the `static_assert` block in `enums.h`. */

/* Zone-labelled stem tally. Production `stem_tallies_json` calls this.
   What edit reds it: omit the `"zone"` key from `format_stem_tally_row_json`.
   A test that only grepped the merge loop could pass if the helper never
   ran; sharing the function is the witness. */
TEST(stem_tally_json, row_carries_zone_from_the_merge)
{
    cryptonote::levin::notify::stem_tally_row row{};
    row.peer[0] = 0xab;
    row.peer[1] = 0xcd;
    row.propagated = 3;
    row.silent = 1;
    row.distinct_sources = 2;

    const std::string tor =
      cryptonote::levin::format_stem_tally_row_json(row, epee::net_utils::zone::tor);
    EXPECT_NE(std::string::npos, tor.find("\"zone\":\"tor\""));
    EXPECT_NE(std::string::npos, tor.find("\"peer\":\"abcd"));
    EXPECT_NE(std::string::npos, tor.find("\"propagated\":3"));
    EXPECT_NE(std::string::npos, tor.find("\"silent\":1"));
    EXPECT_NE(std::string::npos, tor.find("\"distinct_sources\":2"));

    const std::string i2p =
      cryptonote::levin::format_stem_tally_row_json(row, epee::net_utils::zone::i2p);
    EXPECT_NE(std::string::npos, i2p.find("\"zone\":\"i2p\""));
    EXPECT_EQ(std::string::npos, i2p.find("\"zone\":\"tor\""));

    EXPECT_NE(
      std::string::npos,
      cryptonote::levin::format_stem_tally_row_json(row, epee::net_utils::zone::public_)
        .find("\"zone\":\"public\""));
    EXPECT_NE(
      std::string::npos,
      cryptonote::levin::format_stem_tally_row_json(row, epee::net_utils::zone::invalid)
        .find("\"zone\":\"invalid\""));
}

/* §89 private stemming posture: the anonymity zone STEMS. Outbound-only fluff
   reach is asserted every round inside `run_private_round`. Cases differ only
   by method and padding. */
TEST_F(levin_notify, private_stem_without_padding)
{
    run_private_stemming_case(cryptonote::relay_method::stem, false);
}

TEST_F(levin_notify, private_local_without_padding)
{
    run_private_stemming_case(cryptonote::relay_method::local, false);
}

TEST_F(levin_notify, private_stem_with_padding)
{
    run_private_stemming_case(cryptonote::relay_method::stem, true);
}

TEST_F(levin_notify, private_local_with_padding)
{
    run_private_stemming_case(cryptonote::relay_method::local, true);
}

TEST(make_header, no_expect_return)
{
    static constexpr const std::size_t max_length = std::numeric_limits<std::size_t>::max();

    const epee::levin::bucket_head2 header1 = epee::levin::make_header(1024, max_length, 5601, false);
    EXPECT_EQ(SWAP64LE(LEVIN_SIGNATURE), header1.m_signature);
    EXPECT_FALSE(header1.m_have_to_return_data);
    EXPECT_EQ(SWAP64LE(max_length), header1.m_cb);
    EXPECT_EQ(SWAP32LE(1024), header1.m_command);
    EXPECT_EQ(SWAP32LE(LEVIN_PROTOCOL_VER_1), header1.m_protocol_version);
    EXPECT_EQ(SWAP32LE(5601), header1.m_flags);
}

TEST(make_header, expect_return)
{
    const epee::levin::bucket_head2 header1 = epee::levin::make_header(65535, 0, 0, true);
    EXPECT_EQ(SWAP64LE(LEVIN_SIGNATURE), header1.m_signature);
    EXPECT_TRUE(header1.m_have_to_return_data);
    EXPECT_EQ(0u, header1.m_cb);
    EXPECT_EQ(SWAP32LE(65535), header1.m_command);
    EXPECT_EQ(SWAP32LE(LEVIN_PROTOCOL_VER_1), header1.m_protocol_version);
    EXPECT_EQ(0u, header1.m_flags);
}

TEST(message_writer, invoke_with_empty_payload)
{
    const epee::byte_slice message = epee::levin::message_writer{}.finalize_invoke(443);
    const epee::levin::bucket_head2 header =
        epee::levin::make_header(443, 0, LEVIN_PACKET_REQUEST, true);
    ASSERT_EQ(sizeof(header), message.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), message.data(), sizeof(header)) == 0);
}

TEST(message_writer, invoke_with_payload)
{
    std::string bytes(100, 'a');
    std::generate(bytes.begin(), bytes.end(), crypto::random_device{});

    epee::levin::message_writer writer{};
    writer.buffer.write(epee::to_span(bytes));

    const epee::byte_slice message = writer.finalize_invoke(443);
    const epee::levin::bucket_head2 header =
        epee::levin::make_header(443, bytes.size(), LEVIN_PACKET_REQUEST, true);

    ASSERT_EQ(sizeof(header) + bytes.size(), message.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), message.data(), sizeof(header)) == 0);
    EXPECT_TRUE(std::memcmp(bytes.data(), message.data() + sizeof(header), bytes.size()) == 0);
}

TEST(message_writer, notify_with_empty_payload)
{
    const epee::byte_slice message = epee::levin::message_writer{}.finalize_notify(443);
    const epee::levin::bucket_head2 header =
        epee::levin::make_header(443, 0, LEVIN_PACKET_REQUEST, false);
    ASSERT_EQ(sizeof(header), message.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), message.data(), sizeof(header)) == 0);
}

TEST(message_writer, notify_with_payload)
{
    std::string bytes(100, 'a');
    std::generate(bytes.begin(), bytes.end(), crypto::random_device{});

    epee::levin::message_writer writer{};
    writer.buffer.write(epee::to_span(bytes));

    const epee::byte_slice message = writer.finalize_notify(443);
    const epee::levin::bucket_head2 header =
        epee::levin::make_header(443, bytes.size(), LEVIN_PACKET_REQUEST, false);

    ASSERT_EQ(sizeof(header) + bytes.size(), message.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), message.data(), sizeof(header)) == 0);
    EXPECT_TRUE(std::memcmp(bytes.data(), message.data() + sizeof(header), bytes.size()) == 0);
}

TEST(message_writer, response_with_empty_payload)
{
    const epee::byte_slice message = epee::levin::message_writer{}.finalize_response(443, 1);
    epee::levin::bucket_head2 header =
        epee::levin::make_header(443, 0, LEVIN_PACKET_RESPONSE, false);
    header.m_return_code = SWAP32LE(1);
    ASSERT_EQ(sizeof(header), message.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), message.data(), sizeof(header)) == 0);
}

TEST(message_writer, response_with_payload)
{
    std::string bytes(100, 'a');
    std::generate(bytes.begin(), bytes.end(), crypto::random_device{});

    epee::levin::message_writer writer{};
    writer.buffer.write(epee::to_span(bytes));

    const epee::byte_slice message = writer.finalize_response(443, 6450);
    epee::levin::bucket_head2 header =
        epee::levin::make_header(443, bytes.size(), LEVIN_PACKET_RESPONSE, false);
    header.m_return_code = SWAP32LE(6450);

    ASSERT_EQ(sizeof(header) + bytes.size(), message.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), message.data(), sizeof(header)) == 0);
    EXPECT_TRUE(std::memcmp(bytes.data(), message.data() + sizeof(header), bytes.size()) == 0);
}

TEST(message_writer, error)
{
    epee::levin::message_writer writer{};
    writer.buffer.clear();

    EXPECT_THROW(writer.finalize_invoke(0), std::runtime_error);
    EXPECT_THROW(writer.finalize_notify(0), std::runtime_error);
    EXPECT_THROW(writer.finalize_response(0, 0), std::runtime_error);
}

TEST(make_noise, invalid)
{
    EXPECT_TRUE(epee::levin::make_noise_notify(sizeof(epee::levin::bucket_head2) - 1).empty());
}

TEST(make_noise, valid)
{
    static constexpr const std::uint32_t flags =
        LEVIN_PACKET_BEGIN | LEVIN_PACKET_END;

    const epee::byte_slice noise = epee::levin::make_noise_notify(1024);
    const epee::levin::bucket_head2 header =
        epee::levin::make_header(0, 1024 - sizeof(epee::levin::bucket_head2), flags, false);

    ASSERT_EQ(1024, noise.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), noise.data(), sizeof(header)) == 0);
    EXPECT_EQ(1024 - sizeof(header), std::count(noise.cbegin() + sizeof(header), noise.cend(), 0));
}

TEST(make_fragment, invalid)
{
    EXPECT_TRUE(epee::levin::make_fragmented_notify(0, 0, epee::levin::message_writer{}).empty());
}

TEST(make_fragment, single)
{
    const epee::byte_slice noise = epee::levin::make_noise_notify(1024);
    const epee::byte_slice fragment = epee::levin::make_fragmented_notify(noise.size(), 11, epee::levin::message_writer{});
    const epee::levin::bucket_head2 header =
        epee::levin::make_header(11, 1024 - sizeof(epee::levin::bucket_head2), LEVIN_PACKET_REQUEST, false);

    EXPECT_EQ(1024, noise.size());
    ASSERT_EQ(1024, fragment.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), fragment.data(), sizeof(header)) == 0);
    EXPECT_EQ(1024 - sizeof(header), std::count(noise.cbegin() + sizeof(header), noise.cend(), 0));
}

TEST(make_fragment, multiple)
{
    std::string bytes(1024 * 3 - 150, 'a');
    std::generate(bytes.begin(), bytes.end(), crypto::random_device{});

    epee::levin::message_writer message;
    message.buffer.write(epee::to_span(bytes));

    const epee::byte_slice noise = epee::levin::make_noise_notify(1024);
    epee::byte_slice fragment = epee::levin::make_fragmented_notify(noise.size(), 114, std::move(message));

    EXPECT_EQ(1024 * 3, fragment.size());

    epee::levin::bucket_head2 header =
        epee::levin::make_header(0, 1024 - sizeof(epee::levin::bucket_head2), LEVIN_PACKET_BEGIN, false);

    ASSERT_LE(sizeof(header), fragment.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), fragment.data(), sizeof(header)) == 0);

    fragment.take_slice(sizeof(header));
    header.m_flags = LEVIN_PACKET_REQUEST;
    header.m_cb = bytes.size();
    header.m_command = 114;

    ASSERT_LE(sizeof(header), fragment.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), fragment.data(), sizeof(header)) == 0);

    fragment.take_slice(sizeof(header));

    ASSERT_LE(bytes.size(), fragment.size());
    EXPECT_TRUE(std::memcmp(bytes.data(), fragment.data(), 1024 - sizeof(header) * 2) == 0);

    bytes.erase(0, 1024 - sizeof(header) * 2);
    fragment.take_slice(1024 - sizeof(header) * 2);
    header.m_flags = 0;
    header.m_cb = 1024 - sizeof(header);
    header.m_command = 0;

    ASSERT_LE(sizeof(header), fragment.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), fragment.data(), sizeof(header)) == 0);

    fragment.take_slice(sizeof(header));

    ASSERT_LE(bytes.size(), fragment.size());
    EXPECT_TRUE(std::memcmp(bytes.data(), fragment.data(), 1024 - sizeof(header)) == 0);

    bytes.erase(0, 1024 - sizeof(header));
    fragment.take_slice(1024 - sizeof(header));
    header.m_flags = LEVIN_PACKET_END;

    ASSERT_LE(sizeof(header), fragment.size());
    EXPECT_TRUE(std::memcmp(std::addressof(header), fragment.data(), sizeof(header)) == 0);

    fragment.take_slice(sizeof(header));
    EXPECT_TRUE(std::memcmp(bytes.data(), fragment.data(), bytes.size()) == 0);

    fragment.take_slice(bytes.size());

    EXPECT_EQ(18, fragment.size());
    EXPECT_EQ(18, std::count(fragment.cbegin(), fragment.cend(), 0));
}

// ── Compression shim (shekyl_levin_* FFI) ──────────────────────────────────
//
// These bite against the C++↔Rust marshaling seam (buffer ownership, length
// handling, return-code mapping, limit plumbing); the codec itself — the
// constants, the frame handling, the caps, and which messages may be
// compressed at all — is owned and tested by rust/shekyl-levin. Before this
// seam existed the C++ tree had no compression coverage at all.
//
// The emit half has no payload-level entry point to test: `epee::levin`
// exposes only whole-message compression, because every question that
// decides whether a buffer may be compressed is about its bucket header.

TEST(levin_compression, message_roundtrips_through_the_ffi)
{
    // End-to-end over the emit path: finalize a notify, compress the whole
    // message, verify the header rewrite, then inflate the payload back.
    std::string payload(8 * 1024, '\0');
    for (std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<char>(i % 251);

    epee::levin::message_writer message;
    message.buffer.write(epee::to_span(payload));

    epee::byte_slice compressed_msg =
        epee::levin::try_compress_message(message.finalize_notify(2002));
    ASSERT_LE(sizeof(epee::levin::bucket_head2), compressed_msg.size());
    EXPECT_LT(compressed_msg.size(), payload.size());

    epee::levin::bucket_head2 head;
    std::memcpy(std::addressof(head), compressed_msg.data(), sizeof(head));
    EXPECT_TRUE(SWAP32LE(head.m_flags) & LEVIN_PACKET_COMPRESSED);
    EXPECT_EQ(SWAP64LE(head.m_cb), compressed_msg.size() - sizeof(head));

    const epee::span<const uint8_t> frame{
        compressed_msg.data() + sizeof(head), compressed_msg.size() - sizeof(head)};
    std::string decompressed;
    ASSERT_TRUE(epee::levin::decompress_payload(
        frame, decompressed, LEVIN_DEFAULT_MAX_PACKET_SIZE));
    EXPECT_EQ(payload, decompressed);
}

TEST(levin_compression, small_message_is_returned_unchanged)
{
    // Below the 256-byte payload minimum (single-sourced in
    // rust/shekyl-levin) the decline must hand the caller its own message
    // back byte for byte — not an empty slice, and not a re-framed one.
    const std::string payload(255, 'a');
    epee::levin::message_writer message;
    message.buffer.write(epee::to_span(payload));

    epee::byte_slice original = message.finalize_notify(2002);
    epee::byte_slice result = epee::levin::try_compress_message(original.clone());

    ASSERT_EQ(original.size(), result.size());
    EXPECT_EQ(0, std::memcmp(original.data(), result.data(), original.size()));

    epee::levin::bucket_head2 head;
    std::memcpy(std::addressof(head), result.data(), sizeof(head));
    EXPECT_FALSE(SWAP32LE(head.m_flags) & LEVIN_PACKET_COMPRESSED);
}

TEST(levin_compression, cover_traffic_is_returned_unchanged)
{
    // A noise bucket's constant on-wire size is the entire property the
    // white-noise feature buys. The C++ this shim replaced did not check the
    // noise class at all — it would have compressed one and shortened it.
    epee::byte_slice noise = epee::levin::make_noise_notify(4096);
    ASSERT_EQ(4096u, noise.size());

    epee::byte_slice result = epee::levin::try_compress_message(noise.clone());
    ASSERT_EQ(noise.size(), result.size());
    EXPECT_EQ(0, std::memcmp(noise.data(), result.data(), noise.size()));
}

TEST(levin_compression, garbage_frame_rejected)
{
    // The false⇒empty contract on the decompress failure path: a reused
    // non-empty `output` must not retain stale bytes after rejection.
    const std::string garbage = "definitely not a zstd frame";
    std::string decompressed = "stale-caller-reuse";
    EXPECT_FALSE(epee::levin::decompress_payload(
        epee::strspan<uint8_t>(garbage), decompressed, LEVIN_DEFAULT_MAX_PACKET_SIZE));
    EXPECT_TRUE(decompressed.empty());
}

TEST(levin_compression, inflation_bounded_by_the_callers_limit)
{
    // A valid frame whose declared content size exceeds max_output must be
    // rejected before allocation — this is the limit the async handler
    // passes from min(packet limit, per-command cap).
    const std::string payload(8 * 1024, '\0');
    epee::levin::message_writer message;
    message.buffer.write(epee::to_span(payload));
    epee::byte_slice compressed_msg =
        epee::levin::try_compress_message(message.finalize_notify(2002));
    ASSERT_LT(sizeof(epee::levin::bucket_head2), compressed_msg.size());

    const epee::span<const uint8_t> frame{
        compressed_msg.data() + sizeof(epee::levin::bucket_head2),
        compressed_msg.size() - sizeof(epee::levin::bucket_head2)};

    std::string decompressed = "stale-caller-reuse";
    EXPECT_FALSE(epee::levin::decompress_payload(frame, decompressed, 1024));
    EXPECT_TRUE(decompressed.empty());
    EXPECT_TRUE(epee::levin::decompress_payload(frame, decompressed, payload.size()));
    EXPECT_EQ(payload, decompressed);
}

TEST_F(levin_notify, defaulted)
{
    cryptonote::levin::notify notifier{};
    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_FALSE(status.has_outgoing);
    }
    EXPECT_TRUE(notifier.send_txs({}, random_generator_(), cryptonote::relay_method::local));

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    EXPECT_FALSE(notifier.send_txs(std::move(txs), random_generator_(), cryptonote::relay_method::local));
}

TEST_F(levin_notify, fluff_without_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'f');
    txs[1].resize(200, 'e');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::fluff));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        notifier.run_fluff();
        ASSERT_LT(0u, io_service_.poll());

        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
            EXPECT_EQ(1u, context->process_send_queue());

        expect_fluff_totals(txs);
    }
}

TEST_F(levin_notify, stem_without_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'f');
    txs[1].resize(200, 'e');

    std::vector<cryptonote::blobdata> sorted_txs = txs;
    std::sort(sorted_txs.begin(), sorted_txs.end());

    ASSERT_EQ(10u, contexts_.size());
    bool has_stemmed = false;
    bool has_fluffed = false;
    while (!has_stemmed || !has_fluffed)
    {
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        const bool is_stem = events_.has_stem_txes();
        EXPECT_EQ(txs, events_.take_relayed(is_stem ? cryptonote::relay_method::stem : cryptonote::relay_method::fluff));

        if (!is_stem)
        {
            notifier.run_fluff();
            ASSERT_LT(0u, io_service_.poll());
        }

        std::size_t send_count = 0;
        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
        {
            const std::size_t sent = context->process_send_queue();
            if (sent && is_stem)
            {
                EXPECT_EQ(1u, (context - contexts_.begin()) % 2);
            }
            send_count += sent;
        }

        EXPECT_EQ(is_stem ? 1u : 9u, send_count);
        ASSERT_EQ(is_stem ? 1u : 9u, receiver_.notified_size());
        for (unsigned count = 0; count < (is_stem ? 1u : 9u); ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            if (is_stem)
              EXPECT_EQ(txs, notification.txs);
            else
              EXPECT_EQ(sorted_txs, notification.txs);
            EXPECT_TRUE(notification._.empty());
            EXPECT_EQ(!is_stem, notification.dandelionpp_fluff);
        }

        has_stemmed |= is_stem;
        has_fluffed |= !is_stem;
        notifier.run_epoch();
    }
}

TEST_F(levin_notify, stem_no_outs_without_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(true);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_FALSE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'f');
    txs[1].resize(200, 'e');

    std::vector<cryptonote::blobdata> sorted_txs = txs;
    std::sort(sorted_txs.begin(), sorted_txs.end());

    ASSERT_EQ(10u, contexts_.size());

    auto context = contexts_.begin();
    EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));

    io_service_.restart();
    ASSERT_LT(0u, io_service_.poll());
    EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));
    if (events_.has_stem_txes())
    {
        EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::stem));
    }

    notifier.run_fluff();
    ASSERT_LT(0u, io_service_.poll());

    std::size_t send_count = 0;
    EXPECT_EQ(0u, context->process_send_queue());
    for (++context; context != contexts_.end(); ++context)
    {
        send_count += context->process_send_queue();
    }

    EXPECT_EQ(9u, send_count);
    ASSERT_EQ(9u, receiver_.notified_size());
    for (unsigned count = 0; count < 9u; ++count)
    {
        auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
        EXPECT_EQ(sorted_txs, notification.txs);
        EXPECT_TRUE(notification._.empty());
        EXPECT_TRUE(notification.dandelionpp_fluff);
    }
}

TEST_F(levin_notify, local_without_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> my_txs(2);
    my_txs[0].resize(100, 'f');
    my_txs[1].resize(200, 'e');

    std::vector<cryptonote::blobdata> their_txs{2};
    their_txs[0].resize(300, 'g');
    their_txs[1].resize(250, 'h');

    std::vector<cryptonote::blobdata> my_sorted_txs = my_txs;
    std::sort(my_sorted_txs.begin(), my_sorted_txs.end());

    std::vector<cryptonote::blobdata> their_sorted_txs = their_txs;
    std::sort(their_sorted_txs.begin(), their_sorted_txs.end());

    ASSERT_EQ(10u, contexts_.size());
    bool has_stemmed = false;
    bool has_fluffed = false;
    while (!has_stemmed || !has_fluffed)
    {
        // run their "their" txes first
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(their_txs, context->get_id(), cryptonote::relay_method::stem));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        const bool is_stem = events_.has_stem_txes();
        EXPECT_EQ(their_txs, events_.take_relayed(is_stem ? cryptonote::relay_method::stem : cryptonote::relay_method::fluff));

        if (!is_stem)
        {
            notifier.run_fluff();
            ASSERT_LT(0u, io_service_.poll());
        }

        std::size_t send_count = 0;
        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
        {
            const std::size_t sent = context->process_send_queue();
            if (sent && is_stem)
            {
                EXPECT_EQ(1u, (context - contexts_.begin()) % 2);
            }
            send_count += sent;
        }

        EXPECT_EQ(is_stem ? 1u : 9u, send_count);
        ASSERT_EQ(is_stem ? 1u : 9u, receiver_.notified_size());
        for (unsigned count = 0; count < (is_stem ? 1u : 9u); ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
	    if (is_stem)
	      EXPECT_EQ(their_txs, notification.txs);
	    else
	      EXPECT_EQ(their_sorted_txs, notification.txs);
            EXPECT_TRUE(notification._.empty());
            EXPECT_EQ(!is_stem, notification.dandelionpp_fluff);
        }

        // run "my" txes which must always be stem
        context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(my_txs, context->get_id(), cryptonote::relay_method::local));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        EXPECT_TRUE(events_.has_stem_txes());
        EXPECT_EQ(my_txs, events_.take_relayed(cryptonote::relay_method::stem));

        send_count = 0;
        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
        {
            const std::size_t sent = context->process_send_queue();
            if (sent)
            {
                EXPECT_EQ(1u, (context - contexts_.begin()) % 2);
            }
            send_count += sent;
        }

        EXPECT_EQ(1u, send_count);
        EXPECT_EQ(1u, receiver_.notified_size());
        auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
        EXPECT_EQ(my_txs, notification.txs);
        EXPECT_TRUE(notification._.empty());
        EXPECT_TRUE(!notification.dandelionpp_fluff);

        has_stemmed |= is_stem;
        has_fluffed |= !is_stem;
        notifier.run_epoch();
    }
}


TEST_F(levin_notify, block_without_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_FALSE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::block));

        io_service_.restart();
        ASSERT_EQ(0u, io_service_.poll());
    }
}

TEST_F(levin_notify, none_without_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_FALSE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::none));

        io_service_.restart();
        ASSERT_EQ(0u, io_service_.poll());
    }
}

TEST_F(levin_notify, fluff_with_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, true);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'f');
    txs[1].resize(200, 'e');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::fluff));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        notifier.run_fluff();
        ASSERT_LT(0u, io_service_.poll());

        EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));
        std::sort(txs.begin(), txs.end());
        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
            EXPECT_EQ(1u, context->process_send_queue());

        ASSERT_EQ(9u, receiver_.notified_size());
        for (unsigned count = 0; count < 9; ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_EQ(txs, notification.txs);
            EXPECT_FALSE(notification._.empty());
            EXPECT_TRUE(notification.dandelionpp_fluff);
        }
    }
}

// A padded transaction message must reach the wire padded.
//
// `make_tx_message` quantizes the serialized payload to a 1024-byte boundary
// with a run of spaces so an observer cannot read transaction volume off the
// frame size. zstd erases that run almost perfectly, so compressing a padded
// message puts the frame size back in step with the real payload and hands
// the observer exactly the signal the operator paid bandwidth to hide.
//
// This has to be asserted on the *wire* bytes. Every other padding test in
// this file inspects the decoded notification, and the decoded message
// carries its padding either way — the receive path inflates a COMPRESSED
// bucket before handing it up. Reverting the `if (!pad)` guard in
// `make_payload_send_txs` leaves all of those green and fails only this.
//
// The transaction bodies are pseudorandom on purpose. Real Shekyl wire
// bytes measure 7.97–7.995 bits/B of entropy and zstd level 1 *expands*
// them (FOLLOWUPS Z-1, 2026-08-06), so a compressible corpus here would
// prove the guard matters for traffic that does not exist. What makes a
// padded message compressible is not its payload, it is the padding: a run
// of ~1000 identical spaces collapses to a couple of dozen bytes, which
// beats the ~0.1% the incompressible bodies expand by. That is why the
// quantization falls even when the transactions themselves are noise.
TEST_F(levin_notify, padding_survives_the_emit_path)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, true);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    notifier.new_out_connection();
    io_service_.poll();

    // Incompressible bodies, matching the Z-1 measurement of real traffic.
    // A cheap deterministic PRNG, not `crypto::rand`: the test must fail the
    // same way on every run.
    std::vector<cryptonote::blobdata> txs(2);
    std::uint32_t state = 0x9e3779b9u;
    for (auto& tx : txs)
    {
        tx.resize(4096);
        for (char& byte : tx)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            byte = static_cast<char>(state & 0xff);
        }
    }

    ASSERT_EQ(10u, contexts_.size());
    auto context = contexts_.begin();
    EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::fluff));

    io_service_.restart();
    ASSERT_LT(0u, io_service_.poll());
    notifier.run_fluff();
    ASSERT_LT(0u, io_service_.poll());

    unsigned inspected = 0;
    for (++context; context != contexts_.end(); ++context)
    {
        for (const std::size_t wire_size : context->queued_wire_sizes())
        {
            ASSERT_LT(sizeof(epee::levin::bucket_head2), wire_size);
            const std::size_t payload = wire_size - sizeof(epee::levin::bucket_head2);
            EXPECT_EQ(0u, payload % 1024)
                << "padded message went on the wire at " << payload
                << " payload bytes, which is not a 1024-byte multiple";
            ++inspected;
        }
    }
    EXPECT_LT(0u, inspected) << "no frames observed; the test proved nothing";

    // Drain, so the receive path is still exercised and the fixture's
    // teardown invariants hold.
    for (context = contexts_.begin(); context != contexts_.end(); ++context)
        context->process_send_queue();
    EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));
    std::sort(txs.begin(), txs.end());
    for (unsigned count = 0; count < inspected; ++count)
    {
        auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
        EXPECT_EQ(txs, notification.txs);
        EXPECT_FALSE(notification._.empty());
    }
}

// The guard above must not have simply switched compression off: with
// padding disabled the compressor still has to be reachable.
//
// This one deliberately uses a *compressible* corpus, which the padding
// test deliberately does not. The claim here is only "the !pad branch
// still reaches the codec" — a wire frame smaller than the transactions it
// carries is possible only if the compressor ran. It is emphatically NOT a
// claim that real traffic compresses; Z-1 measured real bodies at 7.99
// bits/B, where zstd level 1 expands them and the only-if-smaller rule
// declines. Using realistic bytes here would make this test pass for the
// wrong reason — by proving nothing at all.
TEST_F(levin_notify, unpadded_messages_still_compress)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(4096, 'f');
    txs[1].resize(4096, 'e');

    ASSERT_EQ(10u, contexts_.size());
    auto context = contexts_.begin();
    EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::fluff));

    io_service_.restart();
    ASSERT_LT(0u, io_service_.poll());
    notifier.run_fluff();
    ASSERT_LT(0u, io_service_.poll());

    unsigned inspected = 0;
    for (++context; context != contexts_.end(); ++context)
    {
        for (const std::size_t wire_size : context->queued_wire_sizes())
        {
            EXPECT_LT(wire_size, txs[0].size() + txs[1].size())
                << "unpadded message went on the wire uncompressed";
            ++inspected;
        }
    }
    EXPECT_LT(0u, inspected) << "no frames observed; the test proved nothing";

    // Draining also proves the compressed frames are the receive path's
    // problem and not just smaller bytes: each one must inflate back into
    // the original transactions.
    for (context = contexts_.begin(); context != contexts_.end(); ++context)
        context->process_send_queue();
    EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));
    std::sort(txs.begin(), txs.end());
    for (unsigned count = 0; count < inspected; ++count)
    {
        auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
        EXPECT_EQ(txs, notification.txs);
    }
}

TEST_F(levin_notify, stem_with_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, true);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    bool has_stemmed = false;
    bool has_fluffed = false;
    while (!has_stemmed || !has_fluffed)
    {
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        const bool is_stem = events_.has_stem_txes();
        EXPECT_EQ(txs, events_.take_relayed(is_stem ? cryptonote::relay_method::stem : cryptonote::relay_method::fluff));

        if (!is_stem)
        {
            notifier.run_fluff();
            ASSERT_LT(0u, io_service_.poll());
        }

        std::size_t send_count = 0;
        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
        {
            const std::size_t sent = context->process_send_queue();
            if (sent && is_stem)
            {
                EXPECT_EQ(1u, (context - contexts_.begin()) % 2);
                EXPECT_FALSE(context->is_incoming());
            }
            send_count += sent;
        }

        EXPECT_EQ(is_stem ? 1u : 9u, send_count);
        ASSERT_EQ(is_stem ? 1u : 9u, receiver_.notified_size());
        for (unsigned count = 0; count < (is_stem ? 1u : 9u); ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_EQ(txs, notification.txs);
            EXPECT_FALSE(notification._.empty());
            EXPECT_EQ(!is_stem, notification.dandelionpp_fluff);
        }

        has_stemmed |= is_stem;
        has_fluffed |= !is_stem;
        notifier.run_epoch();
    }
}

TEST_F(levin_notify, stem_no_outs_with_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, true);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(true);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_FALSE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'f');
    txs[1].resize(200, 'e');

    std::vector<cryptonote::blobdata> sorted_txs = txs;
    std::sort(sorted_txs.begin(), sorted_txs.end());

    ASSERT_EQ(10u, contexts_.size());

    auto context = contexts_.begin();
    EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));

    io_service_.restart();
    ASSERT_LT(0u, io_service_.poll());
    EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));
    if (events_.has_stem_txes())
    {
        EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::stem));
    }

    notifier.run_fluff();
    ASSERT_LT(0u, io_service_.poll());

    std::size_t send_count = 0;
    EXPECT_EQ(0u, context->process_send_queue());
    for (++context; context != contexts_.end(); ++context)
    {
        send_count += context->process_send_queue();
    }

    EXPECT_EQ(9u, send_count);
    ASSERT_EQ(9u, receiver_.notified_size());
    for (unsigned count = 0; count < 9u; ++count)
    {
        auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
        EXPECT_EQ(sorted_txs, notification.txs);
        EXPECT_FALSE(notification._.empty());
        EXPECT_TRUE(notification.dandelionpp_fluff);
    }
}

TEST_F(levin_notify, local_with_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, true);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> my_txs(2);
    my_txs[0].resize(100, 'e');
    my_txs[1].resize(200, 'f');

    std::vector<cryptonote::blobdata> their_txs{2};
    their_txs[0].resize(300, 'g');
    their_txs[1].resize(250, 'h');

    ASSERT_EQ(10u, contexts_.size());
    bool has_stemmed = false;
    bool has_fluffed = false;
    while (!has_stemmed || !has_fluffed)
    {
      // run their "their" txes first
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(their_txs, context->get_id(), cryptonote::relay_method::stem));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        const bool is_stem = events_.has_stem_txes();
        EXPECT_EQ(their_txs, events_.take_relayed(is_stem ? cryptonote::relay_method::stem : cryptonote::relay_method::fluff));

        if (!is_stem)
        {
            notifier.run_fluff();
            ASSERT_LT(0u, io_service_.poll());
        }

        std::size_t send_count = 0;
        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
        {
            const std::size_t sent = context->process_send_queue();
            if (sent && is_stem)
            {
                EXPECT_EQ(1u, (context - contexts_.begin()) % 2);
                EXPECT_FALSE(context->is_incoming());
            }
            send_count += sent;
        }

        EXPECT_EQ(is_stem ? 1u : 9u, send_count);
        ASSERT_EQ(is_stem ? 1u : 9u, receiver_.notified_size());
        for (unsigned count = 0; count < (is_stem ? 1u : 9u); ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_EQ(their_txs, notification.txs);
            EXPECT_FALSE(notification._.empty());
            EXPECT_EQ(!is_stem, notification.dandelionpp_fluff);
        }

        // run "my" txes which must always be stem
        context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(my_txs, context->get_id(), cryptonote::relay_method::local));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        EXPECT_TRUE(events_.has_stem_txes());
        EXPECT_EQ(my_txs, events_.take_relayed(cryptonote::relay_method::stem));

        send_count = 0;
        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
        {
            const std::size_t sent = context->process_send_queue();
            if (sent)
            {
                EXPECT_EQ(1u, (context - contexts_.begin()) % 2);
            }
            send_count += sent;
        }

        EXPECT_EQ(1u, send_count);
        EXPECT_EQ(1u, receiver_.notified_size());
        auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
        EXPECT_EQ(my_txs, notification.txs);
        EXPECT_FALSE(notification._.empty());
        EXPECT_TRUE(!notification.dandelionpp_fluff);

        has_stemmed |= is_stem;
        has_fluffed |= !is_stem;
        notifier.run_epoch();
    }
}

TEST_F(levin_notify, block_with_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, true);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_FALSE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::block));

        io_service_.restart();
        ASSERT_EQ(0u, io_service_.poll());
    }
}

TEST_F(levin_notify, none_with_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, true);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_FALSE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::none));

        io_service_.restart();
        ASSERT_EQ(0u, io_service_.poll());
    }
}

TEST_F(levin_notify, private_fluff_without_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::fluff));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        notifier.run_fluff();
        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());

        EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));

        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
        {
            const bool is_incoming = ((context - contexts_.begin()) % 2 == 0);
            EXPECT_EQ(is_incoming ? 0u : 1u, context->process_send_queue());
        }

        ASSERT_EQ(5u, receiver_.notified_size());
        for (unsigned count = 0; count < 5; ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_EQ(txs, notification.txs);
            EXPECT_TRUE(notification._.empty());
            EXPECT_TRUE(notification.dandelionpp_fluff);
        }
    }
}

TEST_F(levin_notify, private_block_without_padding)
{
    /* `block` and `none` never reach the relay path on any zone — `send_txs`
       returns false for both before the transport question is asked — so §89's
       stemming ruling does not touch this case. The inherited comment here
       said "private mode always uses fluff but marked as stem"; that is false
       since §89 and was never what this case tested. */
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_FALSE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::block));

        io_service_.restart();
        ASSERT_EQ(0u, io_service_.poll());
    }
}

TEST_F(levin_notify, private_none_without_padding)
{
    /* `block` and `none` never reach the relay path on any zone — `send_txs`
       returns false for both before the transport question is asked — so §89's
       stemming ruling does not touch this case. The inherited comment here
       said "private mode always uses fluff but marked as stem"; that is false
       since §89 and was never what this case tested. */
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_FALSE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::none));

        io_service_.restart();
        ASSERT_EQ(0u, io_service_.poll());
    }
}

TEST_F(levin_notify, private_fluff_with_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, true);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::fluff));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        notifier.run_fluff();
        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());

        EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));

        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
        {
            const bool is_incoming = ((context - contexts_.begin()) % 2 == 0);
            EXPECT_EQ(is_incoming ? 0u : 1u, context->process_send_queue());
        }

        ASSERT_EQ(5u, receiver_.notified_size());
        for (unsigned count = 0; count < 5; ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_EQ(txs, notification.txs);
            EXPECT_FALSE(notification._.empty());
            EXPECT_TRUE(notification.dandelionpp_fluff);
        }
    }
}

TEST_F(levin_notify, private_block_with_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, true);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_FALSE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::block));

        io_service_.restart();
        ASSERT_EQ(0u, io_service_.poll());
    }
}

TEST_F(levin_notify, private_none_with_padding)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, true);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_FALSE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::none));

        io_service_.restart();
        ASSERT_EQ(0u, io_service_.poll());
    }
}

TEST_F(levin_notify, stem_mappings)
{
    static constexpr const unsigned test_connections_count = (CRYPTONOTE_DANDELIONPP_STEMS + 1) * 2;

    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < test_connections_count; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(test_connections_count, contexts_.size());
    for (;;)
    {
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        if (events_.has_stem_txes())
            break;

        EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));
        notifier.run_fluff();
        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());

        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
            EXPECT_EQ(1u, context->process_send_queue());

        ASSERT_EQ(test_connections_count - 1, receiver_.notified_size());
        for (unsigned count = 0; count < test_connections_count - 1; ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_EQ(txs, notification.txs);
            EXPECT_TRUE(notification._.empty());
            EXPECT_TRUE(notification.dandelionpp_fluff);
        }

        notifier.run_epoch();
        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
    }
    EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::stem));

    std::set<boost::uuids::uuid> used;
    std::map<boost::uuids::uuid, boost::uuids::uuid> mappings;
    {
        std::size_t send_count = 0;
        for (auto context = contexts_.begin(); context != contexts_.end(); ++context)
        {
            const std::size_t sent = context->process_send_queue();
            if (sent)
            {
                EXPECT_EQ(1u, (context - contexts_.begin()) % 2);
                EXPECT_FALSE(context->is_incoming());
                used.insert(context->get_id());
                mappings[contexts_.front().get_id()] = context->get_id();
            }
            send_count += sent;
        }

        EXPECT_EQ(1u, send_count);
        ASSERT_EQ(1u, receiver_.notified_size());
        for (unsigned count = 0; count < 1u; ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_EQ(txs, notification.txs);
            EXPECT_TRUE(notification._.empty());
            EXPECT_FALSE(notification.dandelionpp_fluff);
        }
    }

    for (unsigned i = 0; i < contexts_.size() * 2; i += 2)
    {
        auto& incoming = contexts_[i % contexts_.size()];
        EXPECT_TRUE(notifier.send_txs(txs, incoming.get_id(), cryptonote::relay_method::stem));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::stem));

        std::size_t send_count = 0;
        for (auto context = contexts_.begin(); context != contexts_.end(); ++context)
        {
            const std::size_t sent = context->process_send_queue();
            if (sent)
            {
                EXPECT_EQ(1u, (context - contexts_.begin()) % 2);
                EXPECT_FALSE(context->is_incoming());
                used.insert(context->get_id());

                auto inserted = mappings.emplace(incoming.get_id(), context->get_id()).first;
                EXPECT_EQ(inserted->second, context->get_id()) << "incoming index " << i;
            }
            send_count += sent;
        }

        EXPECT_EQ(1u, send_count);
        ASSERT_EQ(1u, receiver_.notified_size());
        for (unsigned count = 0; count < 1u; ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_EQ(txs, notification.txs);
            EXPECT_TRUE(notification._.empty());
            EXPECT_FALSE(notification.dandelionpp_fluff);
        }
    }

    EXPECT_EQ(CRYPTONOTE_DANDELIONPP_STEMS, used.size());
}

TEST_F(levin_notify, fluff_multiple)
{
    static constexpr const unsigned test_connections_count = (CRYPTONOTE_DANDELIONPP_STEMS + 1) * 2;

    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < test_connections_count; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'e');
    txs[1].resize(200, 'f');

    ASSERT_EQ(test_connections_count, contexts_.size());
    for (;;)
    {
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        if (!events_.has_stem_txes())
            break;

        EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::stem));

        std::size_t send_count = 0;
        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
        {
            const std::size_t sent = context->process_send_queue();
            if (sent)
            {
                EXPECT_EQ(1u, (context - contexts_.begin()) % 2);
                EXPECT_FALSE(context->is_incoming());
            }
            send_count += sent;
        }

        EXPECT_EQ(1u, send_count);
        ASSERT_EQ(1u, receiver_.notified_size());
        for (unsigned count = 0; count < 1; ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_EQ(txs, notification.txs);
            EXPECT_TRUE(notification._.empty());
            EXPECT_FALSE(notification.dandelionpp_fluff);
        }

        notifier.run_epoch();
        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
    }
    EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));
    notifier.run_fluff();
    io_service_.restart();
    ASSERT_LT(0u, io_service_.poll());
    {
        auto context = contexts_.begin();
        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
            EXPECT_EQ(1u, context->process_send_queue());

        ASSERT_EQ(contexts_.size() - 1, receiver_.notified_size());
        for (unsigned count = 0; count < contexts_.size() - 1; ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_EQ(txs, notification.txs);
            EXPECT_TRUE(notification._.empty());
            EXPECT_TRUE(notification.dandelionpp_fluff);
        }
    }

    for (unsigned i = 0; i < contexts_.size() * 2; i += 2)
    {
        auto& incoming = contexts_[i % contexts_.size()];
        EXPECT_TRUE(notifier.send_txs(txs, incoming.get_id(), cryptonote::relay_method::stem));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        notifier.run_fluff();
        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());

        EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));

        for (auto& context : contexts_)
        {
            if (std::addressof(incoming) == std::addressof(context))
                EXPECT_EQ(0u, context.process_send_queue());
            else
                EXPECT_EQ(1u, context.process_send_queue());
        }

        ASSERT_EQ(contexts_.size() - 1, receiver_.notified_size());
        for (unsigned count = 0; count < contexts_.size() - 1; ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_EQ(txs, notification.txs);
            EXPECT_TRUE(notification._.empty());
            EXPECT_TRUE(notification.dandelionpp_fluff);
        }
    }
}

TEST_F(levin_notify, fluff_with_duplicate)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    {
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise);
        EXPECT_FALSE(status.connections_filled);
        EXPECT_TRUE(status.has_outgoing);
    }
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(9);
    txs[0].resize(100, 'e');
    txs[1].resize(100, 'e');
    txs[2].resize(100, 'e');
    txs[3].resize(100, 'e');
    txs[4].resize(200, 'f');
    txs[5].resize(200, 'f');
    txs[6].resize(200, 'f');
    txs[7].resize(200, 'f');
    txs[8].resize(200, 'f');

    ASSERT_EQ(10u, contexts_.size());
    {
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::fluff));

        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        notifier.run_fluff();
        ASSERT_LT(0u, io_service_.poll());

        EXPECT_EQ(0u, context->process_send_queue());
        for (++context; context != contexts_.end(); ++context)
            EXPECT_EQ(1u, context->process_send_queue());

        EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));
        std::sort(txs.begin(), txs.end());
        ASSERT_EQ(9u, receiver_.notified_size());
        for (unsigned count = 0; count < 9; ++count)
        {
            auto notification = receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>().second;
            EXPECT_NE(txs, notification.txs);
            EXPECT_EQ(notification.txs.size(), 2);
            EXPECT_TRUE(notification._.empty());
            EXPECT_TRUE(notification.dandelionpp_fluff);
        }
    }

}

/*! The fluff totals oracle, reached through the SCHEDULED path.
    Closes the force-flag half of the §20.10 carry-forward and part of the
    §18.4c honest-scope gap ("the production timer path has no C++-side
    coverage — every gtest drives through force hooks").

    Shares `expect_fluff_totals` with `fluff_without_padding` — the coupling is
    structural, not prose. Drive is `drive_schedule` (same helper noise uses),
    so per-peer deadlines fall due across several advances instead of releasing
    together under `run_fluff`. The force branch's per-peer simultaneous queue
    counts are not re-asserted here: those are force-path-shaped. If this ever
    needs the force hook to pass, a fluff assertion has started encoding the
    forced side. */
TEST_F(levin_notify, fluff_via_scheduled_drive)
{
    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(2);
    txs[0].resize(100, 'f');
    txs[1].resize(200, 'e');

    ASSERT_EQ(10u, contexts_.size());
    auto context = contexts_.begin();
    EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::fluff));
    io_service_.restart();
    ASSERT_LT(0u, io_service_.poll());

    // 64 > default 16: fluff releases one peer (or a small collision set) per
    // advance, so nine eligible peers need headroom for epoch wakes in between.
    drive_schedule(notifier,
        [this](std::size_t) { return receiver_.notified_size() >= 9u; },
        64);

    EXPECT_EQ(0u, context->process_send_queue());
    expect_fluff_totals(txs);
}

/*! **TRIPWIRE — this test PINS INHERITED BEHAVIOUR THAT §89 CONTRADICTS.**

    Read this before "fixing" it. Both assertions below are deliberate records
    of a **known-wrong** state (`DAEMON_RELAY_PRIVACY.md` §42.5a), not a
    specification:

      1. `take_relayed(relay_method::local)` — the covert branch DOWNGRADES a
         stem to `local` with `MWARNING("Dandelion++ stem not supported over
         noise networks")`. That is Monero's posture, in which noise mode
         *replaces* Dandelion++. §89 ruled the anonymity zone **stems**.
      2. `notified_size() == 2` — the covert send loops over EVERY channel
         (`for channel < zone_->channels.size()`), not the bound stem slot.
         The Rust substrate already models the target: `CovertSchedule` binds
         channel `i` to stem slot `i` (§20.3) and pins the deadline vector's
         length to `NOISE_CHANNELS`. **The two sides disagree today, and this
         test is where the disagreement is visible.**

    **When §42.3's restoration lands, this test MUST go red, and greening it
    means changing the expectations, not the code:** `take_relayed` becomes
    `relay_method::stem`, and `notified_size()` becomes **1** — the bound slot
    alone. A change that keeps this test green as written has not implemented
    §42.3; it has preserved the bypass.

    This annotation exists because the failure mode is specific and cheap: an
    implementer hits a failing regression test and silences the oracle. The
    edit that reds this test is the edit that matters. */
/*! CV-1 (§20.5): repointing a covert channel discards any in-flight message
    remainder — the message is restarted from its first fragment or dropped,
    never resumed. The inherited rule lived in `update_channel` as an
    imperative comment ("DO NOT try to send the remainder of the fragments,
    this additional send time can leak that this node was sending out a real
    notify (tx) instead of dummy noise") and had no test anywhere — §20.5's
    named finding, verified by grep over this whole file. After the §20.3
    inversion the discard lives at exactly ONE site, `send_noise`'s
    rebind-at-send, which is what makes this witness meaningful now and not
    before part B: while the old repoint path was alive there were two
    discard sites, and a resume injected into one could pass behind the
    other's discard.

    Fixture: ONE outbound peer, so the stem map holds one slot and channel 0
    is the only sender. A 3000-byte tx against a 2048-byte covert payload
    takes two sends per complete notification, so stopping after one send
    leaves a genuine remainder in flight — asserted via
    `notified_size() == 0`, without which this is the RP-3a seal's no-input
    vacuity in covert costume. The peer is then closed, a successor added,
    and the map refreshed: the churned slot rebinds (bound→bound crosses
    with the next send, not as an unbind), and the next send must restart.

    The property is asserted where the defect is observable: the SUCCESSOR
    reassembles the complete, intact notification. A resumed remainder
    cannot satisfy this — the successor receives a fragment stream with no
    start fragment, and the message is popped from the queue once the
    remainder drains, so no notification ever arrives.

    Negative control (run and observed to fail): removing the rebind's
    `channel.active = nullptr;` in `send_noise` fails this test — the final
    drive exhausts its advances with zero notifications. */
TEST_F(levin_notify, command_max_bytes)
{
    static constexpr int ping_command = nodetool::COMMAND_PING::ID;

    add_connection(true);

    std::string payload(4096, 'h');
    epee::byte_slice bytes;
    {
        epee::levin::message_writer dest{};
        dest.buffer.write(epee::to_span(payload));
        bytes = dest.finalize_notify(ping_command);
    }

    EXPECT_EQ(1, get_connections().send(bytes.clone(), contexts_.front().get_id()));
    EXPECT_EQ(1u, contexts_.front().process_send_queue(true));
    EXPECT_EQ(1u, receiver_.notified_size());

    const received_message msg = receiver_.get_raw_notification();
    EXPECT_EQ(ping_command, msg.command);
    EXPECT_EQ(contexts_.front().get_id(), msg.connection);
    EXPECT_EQ(payload, msg.payload);

    {
        payload.push_back('h');
        epee::levin::message_writer dest{};
        dest.buffer.write(epee::to_span(payload));
        bytes = dest.finalize_notify(ping_command);
    }

    EXPECT_EQ(1, get_connections().send(std::move(bytes), contexts_.front().get_id()));
    EXPECT_EQ(1u, contexts_.front().process_send_queue(false));
    EXPECT_EQ(0u, receiver_.notified_size());
}

TEST_F(levin_notify, stem_watch_records_and_arrival_resolves)
{
    // §46 wiring witness: a successful Dandelion++ stem send must arm one
    // observation per tx in the zone's stem watch (record_stem at the xmit
    // site), and record_arrival with the same blobs must resolve them. The
    // arithmetic is covered Rust-side; what this asserts is that the TWO C++
    // call sites are actually wired — negative controls: removing the
    // record_stem call leaves in-flight at 0 (first assert fails); removing
    // the record_arrival dispatch leaves it at 2 (second assert fails).
    static constexpr const unsigned test_connections_count = (CRYPTONOTE_DANDELIONPP_STEMS + 1) * 2;

    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < test_connections_count; ++count)
        add_connection(count % 2 == 0);
    notifier.new_out_connection();
    io_service_.poll();

    /* F-9: the watch keys on CANONICAL tx hashes, parsed at the call sites —
       so unlike the other tests in this file, the blobs must parse. Two
       minimal transactions, distinguished by unlock_time. */
    std::vector<cryptonote::blobdata> txs(2);
    {
        cryptonote::transaction tx{};
        tx.unlock_time = 1;
        txs[0] = cryptonote::t_serializable_object_to_blob(tx);
        tx.unlock_time = 2;
        txs[1] = cryptonote::t_serializable_object_to_blob(tx);
    }

    ASSERT_EQ(0u, notifier.stem_in_flight());

    // Drive until a stem epoch actually sends (fluff epochs re-roll). Bound
    // the re-rolls so a scheduling regression fails with an assertion rather
    // than hanging the suite — q is high enough that a stem epoch arrives
    // well within a few dozen flips under the test RNG.
    static constexpr unsigned kMaxEpochRolls = 64;
    unsigned rolls = 0;
    for (;;)
    {
        ASSERT_LT(rolls, kMaxEpochRolls)
            << "no stem send after " << kMaxEpochRolls
            << " epoch rolls — zone never entered a stem epoch";
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));
        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        if (events_.has_stem_txes())
            break;
        EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff));
        notifier.run_fluff();
        io_service_.restart();
        io_service_.poll();
        for (auto &ctx : contexts_)
            ctx.process_send_queue();
        while (receiver_.notified_size())
            receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
        notifier.run_epoch();
        io_service_.restart();
        io_service_.poll();
        ++rolls;
    }
    EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::stem));
    for (auto &ctx : contexts_)
        ctx.process_send_queue();
    while (receiver_.notified_size())
        receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();

    EXPECT_EQ(2u, notifier.stem_in_flight())
        << "a successful stem send must arm one observation per tx";

    /* F-10: an arrival from the charged successor resolves nothing. The
       stem destination is always an OUTGOING connection, so the first
       context (created incoming) is provably not it — using it proves the
       exclusion is peer-scoped rather than blanket. The exclusion's own
       semantics are witnessed Rust-side; this asserts the uuid reaches it. */
    auto incoming = contexts_.begin();
    ASSERT_TRUE(incoming->is_incoming());
    /* Arrival path takes canonical hashes (join key), not blobs — same shape
       production uses after the one-shot parse at fan-out. */
    notifier.record_arrival(
        std::make_shared<const std::vector<crypto::hash>>(
            cryptonote::levin::stem_watch_tx_hashes(txs)),
        incoming->get_id());
    io_service_.restart();
    io_service_.poll();

    EXPECT_EQ(0u, notifier.stem_in_flight())
        << "the same txs arriving from another peer must resolve the observations";

    /* The FORWARDING leg, asserted rather than inferred. `stem_in_flight`
       reaching zero says the watch resolved; it says nothing about the verdict
       reaching core, and the disarm consumer lives on the far side of
       `on_stem_propagated`. A dispatch that resolved the observations and
       forwarded nothing passes the line above — which is this assertion's
       negative control: drop the `core->on_stem_propagated` call in
       `levin_notify.cpp`'s `record_arrival` and this goes red on its own. */
    EXPECT_EQ(cryptonote::levin::stem_watch_tx_hashes(txs), events_.stem_propagated())
        << "the propagation verdicts must cross into core, keyed by canonical "
           "hash and in arrival order";
}

/*! A stem that never left must not be recorded as relayed.

    `record_relayed` fired BEFORE `make_payload_send_txs`, so the pool was told
    a stem had been launched on every path where one never was — `NoRoute`, or
    both send attempts failing.

    Not a cosmetic ordering. `set_relayed` writes `meta.relayed`, and
    `local_relay_base` reads exactly that bit to choose an origin's backoff:
    `false` keeps MIN_RELAY_TIME because "no stem was ever launched, so no
    embargo exists anywhere to complete", `true` buys the derived interval,
    which provisions for a stem completing. A send that never happened claiming
    `true` is the same falsification an unsent `local` entry was fixed for, and
    it costs the origin the long wait on the strength of an event that did not
    occur.

    THE ORACLE NEEDS A STEM EPOCH AND A FAILING TRANSPORT, and neither can be
    established after the other alone: the loop that finds a stem epoch
    recognises it BY the stem record, which is the thing under test. So the
    epoch is established first with delivery working and drained, then delivery
    is cut WITHIN that epoch — an epoch persists across sends until
    `run_epoch`.

    Negative control: restore `record_relayed(relay_method::stem)` above the
    send in `dandelionpp_notify` and the first assertion fails. */
TEST_F(levin_notify, a_failed_stem_is_not_recorded_as_relayed)
{
    static constexpr const unsigned test_connections_count = (CRYPTONOTE_DANDELIONPP_STEMS + 1) * 2;

    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, false);
    auto &notifier = *notifier_ptr;

    for (unsigned count = 0; count < test_connections_count; ++count)
        add_connection(count % 2 == 0);
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> first(1);
    std::vector<cryptonote::blobdata> second(1);
    {
        cryptonote::transaction tx{};
        tx.unlock_time = 1;
        first[0] = cryptonote::t_serializable_object_to_blob(tx);
        tx.unlock_time = 2;
        second[0] = cryptonote::t_serializable_object_to_blob(tx);
    }

    // PHASE 1 — reach a stem epoch with the transport working, so that the
    // failure below is known to be a stem epoch's failure and not a fluff
    // epoch trivially recording fluff.
    static constexpr unsigned kMaxEpochRolls = 64;
    unsigned rolls = 0;
    for (;;)
    {
        ASSERT_LT(rolls, kMaxEpochRolls)
            << "no stem send after " << kMaxEpochRolls << " epoch rolls";
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(first, context->get_id(), cryptonote::relay_method::stem));
        io_service_.restart();
        ASSERT_LT(0u, io_service_.poll());
        if (events_.has_stem_txes())
            break;
        EXPECT_EQ(first, events_.take_relayed(cryptonote::relay_method::fluff));
        notifier.run_fluff();
        io_service_.restart();
        io_service_.poll();
        for (auto &ctx : contexts_)
            ctx.process_send_queue();
        while (receiver_.notified_size())
            receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
        notifier.run_epoch();
        io_service_.restart();
        io_service_.poll();
        ++rolls;
    }
    EXPECT_EQ(first, events_.take_relayed(cryptonote::relay_method::stem));
    for (auto &ctx : contexts_)
        ctx.process_send_queue();
    while (receiver_.notified_size())
        receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();

    // PHASE 2 — same epoch, transport now refusing every write.
    struct deliver_guard
    {
        deliver_guard() { test_endpoint::deliver() = false; }
        ~deliver_guard() { test_endpoint::deliver() = true; }
    } no_delivery;

    auto context = contexts_.begin();
    EXPECT_TRUE(notifier.send_txs(second, context->get_id(), cryptonote::relay_method::stem));
    io_service_.restart();
    io_service_.poll();

    EXPECT_FALSE(events_.has_stem_txes())
        << "a stem that failed to reach the wire was recorded as relayed — "
           "`meta.relayed` then buys the derived origin interval on the "
           "strength of a send that never happened";

    // The fluff fallback still records, which is the half that IS true: the
    // pool is told what actually happened rather than nothing at all. Drained
    // so `TearDown`'s undrained-event assertion reads the subject.
    EXPECT_EQ(second, events_.take_relayed(cryptonote::relay_method::fluff));
    for (auto &ctx : contexts_)
        ctx.process_send_queue();
    while (receiver_.notified_size())
        receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
}

/*! The development opt-in reaches the carrier, and CI can run it.

    The point of a RUNTIME flag rather than `#ifdef`: behind a compile-time
    gate the only configuration that runs the carrier is the one CI never
    builds, so the code would be untestable by the repository's own gate. The
    default is unchanged — every `has_noise == false` fixture in this file
    still passes untouched — and this case is the one that flips it. */
TEST_F(levin_notify, the_development_opt_in_enables_the_carrier_on_an_encrypted_zone)
{
    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    const bool prior = cryptonote::levin::set_carrier_development(true);
    /* Restored however this test leaves, because the flag is process-wide and
       a leaked `true` would silently arm every fixture that runs after it —
       the failure would land in an unrelated test and read as a flake. */
    struct restore_t {
        bool prior;
        ~restore_t() { cryptonote::levin::set_carrier_development(prior); }
    } restore{prior};

    {
        // ENCRYPTED zone: the carrier engages.
        std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, true);
        ASSERT_LT(0u, io_service_.poll());
        EXPECT_TRUE(notifier_ptr->get_status().has_noise)
            << "the development opt-in must reach an encrypted zone, or the "
               "carrier has no configuration a gate can exercise";
    }
    {
        // CLEARTEXT zone: still refused, and by Rust rather than by this flag.
        // `Zone::new` rejects a noise carrier on a cleartext link (§93.2), so
        // the opt-in cannot force one — the carrier hides by payload
        // indistinguishability, which needs encryption at step one.
        std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(true, true);
        ASSERT_LT(0u, io_service_.poll());
        EXPECT_FALSE(notifier_ptr->get_status().has_noise)
            << "link secrecy is the carrier's precondition; the opt-in does "
               "not get to override the Rust gate that enforces it";
    }
}

/*! The carrier is OFF BY DEFAULT, on both zone classes.

    Renamed from `cpp_cannot_enable_the_noise_carrier`, because that property
    stopped being true in this change: `set_carrier_development(true)` is a
    C++ path that sets the flag. The test kept passing — it just no longer
    tested what its name said, which is worse than failing, and the sibling
    case above proves the opposite property deliberately.

    What survives, and is worth a gate: the DEFAULT is off, and nothing in an
    ordinary build turns it on. That is the invariant every other fixture in
    this file leans on when it asserts `has_noise == false`.

    Its own predecessor (`noise_does_not_override_the_phase`, #513) went when
    the C++ noise machinery did — `noise_channel`, `send_noise`,
    `clear_channel`, `queue_covert_notify`, the channel deque and the payload
    are all deleted, and `NoiseQueues` in `shekyl-relay` is the carrier. The
    phase-versus-carrier property that test asserted lives in Rust now
    (`a_noise_carrier_does_not_change_the_phase`), which is where the carrier
    is. `has_noise` here reads the Rust-owned zone fact through
    `shekyl_relay_zone_noise_enabled`, so it is not a constant this test could
    pass against by construction. */
/* The `res > 0` fix's regression test was blocked by the harness, and the
   blocker turned out to BE the defect next door.

   `test_endpoint::deliver()` above is the injection it needs and it works —
   `do_send` returns false on demand. What did not work was an oracle around
   it: `TearDown`'s `relayed_method_size() == 0` fired, because
   `dandelionpp_notify` called `record_relayed` BEFORE
   `make_payload_send_txs`, so a relay was recorded for a send that never
   happened and no drain matched it.

   That ordering is now fixed, and
   `a_failed_stem_is_not_recorded_as_relayed` above is the test the injection
   was kept for. The undrained-event assertion stopped fighting the fixture
   the moment the record moved to the success arm — it had been reporting the
   defect, not obstructing the test.

   The `res > 0` fix itself is `net_node.inl:2503-2504`'s check applied to the
   same call: `connections::send` returns 1/0/-1 and both sites compare `> 0`.

   CORRECTION to what this note used to claim. It said the ordering mattered
   "since F-10's tallies read that record". They do not. F-10's tallies are
   armed by `record_stem_observation`, which was already correctly placed
   after a successful send. The record that was falsified is `meta.relayed`,
   read by `local_relay_base` to choose an origin's backoff — a different
   consumer, and the one an unsent `local` entry was already fixed for. The
   claim was written from the shape of the neighbouring bug rather than from
   the call chain. */

/*! The carrier actually EMITS through `on_noise`, and the frames are levin.

    The C++ half of the boundary this change widened, and it was uncovered:
    the opt-in test above only checks a constructed bit, and the Rust tests
    stop at the FFI. So "the callback marshals bytes correctly" rested on
    nothing on this side, which is where the raw-zeros dummy would have shown
    up as dropped peers rather than a failing assertion. */
TEST_F(levin_notify, the_carrier_emits_levin_frames_through_on_noise)
{
    const bool prior = cryptonote::levin::set_carrier_development(true);
    struct restore_t {
        bool prior;
        ~restore_t() { cryptonote::levin::set_carrier_development(prior); }
    } restore{prior};

    // OUTBOUND connections: noise channels are stem slots, and an unbound slot
    // emits nothing at all (CV-2). Incoming ones never enter the stem map.
    for (unsigned count = 0; count < 4; ++count)
        add_connection(false);

    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, true);
    auto& notifier = *notifier_ptr;
    ASSERT_LT(0u, io_service_.poll());
    ASSERT_TRUE(notifier.get_status().has_noise) << "fixture: the carrier must be on";

    notifier.new_out_connection();
    io_service_.poll();

    const std::size_t sent =
      drive_schedule(notifier, [](std::size_t n) { return n != 0; });
    EXPECT_LT(0u, sent)
      << "a carrier zone must emit on its cadence — zero means `on_noise` "
         "never reached the transport, which is the state this PR's Rust-side "
         "tests cannot see";
}

TEST_F(levin_notify, the_noise_carrier_is_off_by_default)
{
    for (unsigned count = 0; count < 10; ++count)
        add_connection(count % 2 == 0);

    // Both zone classes, because the flag is derived per zone: an encrypted
    // zone is the one that WOULD be eligible, and it is still not enabled.
    for (const bool is_public : {true, false})
    {
        std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(is_public, true);
        auto &notifier = *notifier_ptr;
        ASSERT_LT(0u, io_service_.poll());

        /* Read what each arm actually demonstrates, because they are NOT the
           same refusal and only one of them is this test's subject.

           On i2p, `has_noise` is false because the development opt-in is off
           — the property named above, and the one the sibling test flips. On
           the PUBLIC zone there are two refusals stacked, and the second never
           runs: even with the opt-in ON, `Zone::new` rejects a noise carrier
           on a cleartext link (§93.2) before the flag is consulted. The
           sibling test asserts exactly that, so the claim is now covered
           rather than argued.

           So the public arm is coverage of the Rust gate, not of this test's
           claim, and a reader taking both arms as evidence for "the default is
           off" would be over-reading it by one refusal. */
        const auto status = notifier.get_status();
        EXPECT_FALSE(status.has_noise)
            << "the carrier is off unless a development build turns it on "
            << "(zone is " << (is_public ? "public" : "i2p") << ")";
    }
}

/*! **A real transaction rides the carrier onto the wire, and the pool is told
    only when it gets there.**

    §3.1a's reopening criterion: *"this row is not marked landed until a test
    drives a real transaction through the queue onto the wire."* Before the
    producer, a development-flag zone emitted **dummies only** — the cadence
    ran, the frames were valid, and `dandelionpp_notify` still sent every real
    transaction straight through `make_payload_send_txs`. The Rust tests could
    not see that: they exercise the queue and the crossing, and both were
    correct while nothing upstream put a transaction in.

    The two halves this asserts are the ones the producer had to get right:

    1. **The transaction does NOT take the ordinary stem wire.** No relay is
       recorded at send time, because an enqueue is not a send.
    2. **A relay IS recorded once the carrier drains it** — the completion
       verdict crossing back and firing `on_transactions_relayed`.

    Assertion 1 alone would pass if the transaction vanished; assertion 2 alone
    would pass if it had gone out the ordinary way. Together they say it went
    by the carrier.

    What edit reds this: reverting `plan_dispatch_with_refresh` to `plan_relay`
    (the transaction takes the ordinary wire, so a relay is recorded
    immediately and assertion 1 fails), or dropping the record from
    `on_carrier_resolved` (nothing is ever recorded and assertion 2 fails). */
TEST_F(levin_notify, a_real_transaction_rides_the_carrier_and_records_on_arrival)
{
    const bool prior = cryptonote::levin::set_carrier_development(true);
    struct restore_t {
        bool prior;
        ~restore_t() { cryptonote::levin::set_carrier_development(prior); }
    } restore{prior};

    // Outbound only: a noise channel is a stem slot, and an unbound slot emits
    // nothing at all (CV-2).
    for (unsigned count = 0; count < 4; ++count)
        add_connection(false);

    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, true);
    auto& notifier = *notifier_ptr;
    ASSERT_LT(0u, io_service_.poll());
    ASSERT_TRUE(notifier.get_status().has_noise) << "fixture: the carrier must be on";

    notifier.new_out_connection();
    io_service_.poll();

    /* F-9: the carrier keys its pending record on the CANONICAL hash, parsed
       from the blob, so this transaction must actually parse — unlike the
       synthetic blobs most tests in this file use. */
    std::vector<cryptonote::blobdata> txs(1);
    {
        cryptonote::transaction tx{};
        tx.unlock_time = 7;
        txs[0] = cryptonote::t_serializable_object_to_blob(tx);
    }

    /* DRIVE UNTIL THE CARRIER TAKES IT, because the epoch roll is the
       schedule's call and a fluff epoch sends by the ordinary path. The first
       draft of this test asserted on the first send: it passed alone and
       failed in the full suite, where the RNG had been advanced by earlier
       tests and the first epoch happened to be fluff.

       The exit condition is "nothing was recorded at send time", which is the
       carrier path's own signature — an ordinary stem or a fluff records
       immediately, and only an enqueue records nothing. That is the same
       circularity `stem_watch_records_and_arrival_resolves` has to solve, and
       the same answer: re-roll, and recognise the epoch by what it did. */
    static constexpr unsigned kMaxEpochRolls = 64;
    unsigned rolls = 0;
    for (;;)
    {
        ASSERT_LT(rolls, kMaxEpochRolls)
            << "no carrier-borne send after " << kMaxEpochRolls
            << " epoch rolls — the zone never entered a stem epoch with a "
               "noise carrier";
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));
        io_service_.restart();
        io_service_.poll();

        if (events_.relayed_method_size() == 0)
            break; // The carrier accepted it and told the pool nothing yet.

        /* Recorded at send time, so this epoch sent by the ordinary path.
           Drain and roll. */
        for (const auto method : {cryptonote::relay_method::fluff,
                                  cryptonote::relay_method::stem,
                                  cryptonote::relay_method::local})
        {
            if (events_.relayed_method_size() == 0)
                break;
            try { events_.take_relayed(method); } catch (const std::logic_error&) {}
        }
        notifier.run_fluff();
        io_service_.restart();
        io_service_.poll();
        for (auto& ctx : contexts_)
            ctx.process_send_queue();
        while (receiver_.notified_size())
            receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
        notifier.run_epoch();
        io_service_.restart();
        io_service_.poll();
        ++rolls;
    }

    // Drive the cadence until the pool hears about it. One minimal
    // transaction frames to a single window, so it completes on the first
    // emission of its channel — but which channel is due is the schedule's
    // call, so this drives rather than assuming.
    drive_schedule(notifier, [this](std::size_t) {
        return events_.relayed_method_size() != 0;
    });

    ASSERT_NE(0u, events_.relayed_method_size())
        << "the carrier never told the pool the transaction was relayed. "
           "Either it never reached the wire, or the completion verdict did "
           "not cross back — and an origin left unrecorded here waits on the "
           "short grid for a transaction that has already gone";

    // Drain for TearDown, and confirm it was OUR transaction rather than
    // something the fluff path emitted.
    const auto method = events_.has_stem_txes()
        ? cryptonote::relay_method::stem : cryptonote::relay_method::local;
    EXPECT_EQ(txs, events_.take_relayed(method))
        << "the pool was told about a different transaction than the one the "
           "carrier carried";

    for (auto& ctx : contexts_)
        ctx.process_send_queue();
    while (receiver_.notified_size())
        receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
}

/*! **A batch the carrier can only partly take splits, and each half is
    accounted once.**

    The split path was written and never driven: the end-to-end test above
    enqueues a single transaction the carrier accepts whole, so `to_send` is
    empty and the function returns before any of this runs. Review found two
    real defects living there, both of which this test now holds:

    1. `record_relayed` closed over `txs_`, so the ordinary wire recorded the
       WHOLE batch — including the transactions the carrier had taken. Those
       were then recorded a second time when their carrier verdict arrived, and
       the first record was the send-time falsification this change exists to
       remove.
    2. The fluff fallback sent `txs_` as well, so a carrier-accepted
       transaction went out by fluff too — a duplicate send that defeats the
       carrier for exactly the transactions it took.

    The refusal is driven by SIZE, which is the realistic one: a transaction
    larger than `MAX_FRAGMENTS` windows (5 x 20,480 B) cannot be fragmented and
    the queue refuses it. The small one rides the carrier, the large one does
    not.

    What edit reds this: restoring `txs_` in either `record_relayed` or the
    fluff fallback — the first over-records the batch, the second sends the
    carried transaction twice. */
TEST_F(levin_notify, a_batch_the_carrier_partly_refuses_splits_without_double_counting)
{
    const bool prior = cryptonote::levin::set_carrier_development(true);
    struct restore_t {
        bool prior;
        ~restore_t() { cryptonote::levin::set_carrier_development(prior); }
    } restore{prior};

    for (unsigned count = 0; count < 4; ++count)
        add_connection(false);

    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, true);
    auto& notifier = *notifier_ptr;
    ASSERT_LT(0u, io_service_.poll());
    ASSERT_TRUE(notifier.get_status().has_noise) << "fixture: the carrier must be on";
    notifier.new_out_connection();
    io_service_.poll();

    /* Two transactions that both parse (F-9), one of which cannot fit the
       carrier's fragment cap. `extra` is the only field that can be grown
       without making the blob unparseable. */
    std::vector<cryptonote::blobdata> txs(2);
    {
        cryptonote::transaction small{};
        small.unlock_time = 11;
        txs[0] = cryptonote::t_serializable_object_to_blob(small);

        cryptonote::transaction large{};
        large.unlock_time = 12;
        large.extra.assign(130000, 0x5A); // > MAX_FRAGMENTS * WINDOW_BYTES
        txs[1] = cryptonote::t_serializable_object_to_blob(large);
    }
    ASSERT_LT(102400u, txs[1].size()) << "fixture: the large tx must exceed the fragment cap";

    static constexpr unsigned kMaxEpochRolls = 64;
    unsigned rolls = 0;
    std::vector<cryptonote::blobdata> recorded;
    for (;;)
    {
        ASSERT_LT(rolls, kMaxEpochRolls) << "no stem epoch with a noise carrier";
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));
        io_service_.restart();
        io_service_.poll();

        if (events_.relayed_method_size() != 0 && events_.has_stem_txes())
        {
            recorded = events_.take_relayed(cryptonote::relay_method::stem);
            break; // A stem epoch: the split happened, or would have.
        }
        for (const auto method : {cryptonote::relay_method::fluff,
                                  cryptonote::relay_method::local})
        {
            if (events_.relayed_method_size() == 0)
                break;
            try { events_.take_relayed(method); } catch (const std::logic_error&) {}
        }
        notifier.run_fluff();
        io_service_.restart();
        io_service_.poll();
        for (auto& ctx : contexts_)
            ctx.process_send_queue();
        while (receiver_.notified_size())
            receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
        notifier.run_epoch();
        io_service_.restart();
        io_service_.poll();
        ++rolls;
    }

    /* ONLY the refused transaction took the ordinary wire. Recording both
       would mean the carrier-accepted one was claimed as relayed at send time
       — before any window of it went out — which is the falsification the
       completion verdict exists to prevent. */
    ASSERT_EQ(1u, recorded.size())
        << "the ordinary stem wire recorded " << recorded.size() << " transaction(s); "
           "the carrier took one of the two, so exactly one should remain";
    EXPECT_EQ(txs[1], recorded.front())
        << "the transaction recorded on the ordinary wire is not the one the "
           "carrier refused — the split kept the wrong half";

    for (auto& ctx : contexts_)
        ctx.process_send_queue();
    while (receiver_.notified_size())
        receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();

    /* THE FLUFF FALLBACK, in the SAME epoch, because defect (2) lives there
       and the assertions above cannot see it: they break on a successful stem
       send and never reach it.

       Cutting delivery makes both stem attempts fail, so the split batch falls
       through to fluff — and fluff must send only what the carrier refused. A
       carrier-accepted transaction fluffed here would go out twice and defeat
       the carrier for the one transaction it actually took. */
    {
        struct deliver_guard {
            deliver_guard() { test_endpoint::deliver() = false; }
            ~deliver_guard() { test_endpoint::deliver() = true; }
        } no_delivery;

        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));
        io_service_.restart();
        io_service_.poll();

        /* The RECORD is the oracle here, and its reach is limited — stated
           rather than implied.

           This catches `record_relayed(fluff, txs_)`: the pool must be told
           about the refused transaction only. It does NOT catch the sibling
           defect in the same fallback, `relay_fluff::run(..., txs_, ...)`,
           because `take_relayed` observes what the pool was TOLD and that
           defect is in what the fluff path SENDS. */
        const auto fluffed = events_.take_relayed(cryptonote::relay_method::fluff);
        ASSERT_EQ(1u, fluffed.size())
            << "the fluff fallback told the pool about " << fluffed.size()
            << " transaction(s); the carrier holds one of the two, and its "
               "verdict is what records it";
        EXPECT_EQ(txs[1], fluffed.front())
            << "the pool was told about the transaction the carrier took, not "
               "the one it refused";
    }

    /* THE SEND HALF IS COVERED BY CONSTRUCTION, not by a second assertion.

       `relay_fluff::run` and `record_relayed` no longer take separate spans:
       `fluff_and_record` passes ONE batch to both, so the set fluffed and the
       set recorded cannot differ. The assertion above therefore holds the send
       as well — an edit that fluffs the wrong batch records the wrong batch
       and reds here.

       That is deliberate rather than convenient. A direct assertion on the
       wire is not available: the only route into this fallback from a carrier
       epoch is a stem send that FAILS, and in this fixture a failed write
       tears the connection down, so no peers remain to fluff to and the
       payload is empty. A first draft asserted on it and was caught by its own
       non-vacuity guard. Rule 50's second clause — when no check can fail,
       encode it so the mistake is unrepresentable — is the answer, and it is a
       better one than the harness would have been. */

    for (auto& ctx : contexts_)
        ctx.process_send_queue();
    while (receiver_.notified_size())
        receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
}

/*! **A transaction already in the carrier is not handed over twice.**

    The pool re-offers on its own schedule and that schedule is SHORTER than
    the carrier can hold: a `local` entry stays `relayed == false` while queued
    and becomes retryable at `MIN_RELAY_TIME` (300 s), while the channel budget
    permits up to a full epoch (600 s) of windows. So `relay_txpool_transactions`
    can offer the same transaction again before its first token resolves.

    A token-keyed map accepts both copies happily, because the tokens differ.
    The result is the same transaction occupying two runs of windows and
    producing two stem observations — double-counted in F-10's tallies, with a
    second successor charged for a delivery that happened once.

    `stem_in_flight` is the oracle: it counts armed observations, so a second
    enqueue that produced a second delivery would show as two.

    What edit reds this: dropping the `carrier_pending_by_token` scan from the
    producer. */
TEST_F(levin_notify, a_transaction_already_in_the_carrier_is_not_enqueued_twice)
{
    const bool prior = cryptonote::levin::set_carrier_development(true);
    struct restore_t {
        bool prior;
        ~restore_t() { cryptonote::levin::set_carrier_development(prior); }
    } restore{prior};

    for (unsigned count = 0; count < 4; ++count)
        add_connection(false);

    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, true);
    auto& notifier = *notifier_ptr;
    ASSERT_LT(0u, io_service_.poll());
    ASSERT_TRUE(notifier.get_status().has_noise) << "fixture: the carrier must be on";
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(1);
    {
        cryptonote::transaction tx{};
        tx.unlock_time = 23;
        txs[0] = cryptonote::t_serializable_object_to_blob(tx);
    }

    static constexpr unsigned kMaxEpochRolls = 64;
    unsigned rolls = 0;
    for (;;)
    {
        ASSERT_LT(rolls, kMaxEpochRolls) << "no carrier-borne send";
        auto context = contexts_.begin();
        EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));
        io_service_.restart();
        io_service_.poll();
        if (events_.relayed_method_size() == 0)
            break; // The carrier took it.
        for (const auto method : {cryptonote::relay_method::fluff,
                                  cryptonote::relay_method::stem,
                                  cryptonote::relay_method::local})
        {
            if (events_.relayed_method_size() == 0)
                break;
            try { events_.take_relayed(method); } catch (const std::logic_error&) {}
        }
        notifier.run_fluff();
        io_service_.restart();
        io_service_.poll();
        for (auto& ctx : contexts_)
            ctx.process_send_queue();
        while (receiver_.notified_size())
            receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
        notifier.run_epoch();
        io_service_.restart();
        io_service_.poll();
        ++rolls;
    }

    /* Offer the SAME transaction again, in the same epoch, exactly as the pool
       would at MIN_RELAY_TIME. The carrier still holds the first copy. */
    auto context = contexts_.begin();
    EXPECT_TRUE(notifier.send_txs(txs, context->get_id(), cryptonote::relay_method::stem));
    io_service_.restart();
    io_service_.poll();
    EXPECT_EQ(0u, events_.relayed_method_size())
        << "the second offer took the ordinary wire — the producer did not "
           "recognise that the carrier already owns this transaction";

    /* Drain the carrier COMPLETELY before counting. Stopping at the first
       completion is what a first draft did, and it passed with the dedup
       removed: a second copy sits BEHIND the first in the channel, so at that
       moment only one had been delivered and the oracle saw one either way.
       The stop condition returns false so the drive runs to its bound. */
    drive_schedule(notifier, [](std::size_t) { return false; }, 24);

    ASSERT_NE(0u, events_.relayed_method_size()) << "the carrier never delivered";
    const auto method = events_.has_stem_txes()
        ? cryptonote::relay_method::stem : cryptonote::relay_method::local;
    const auto told = events_.take_relayed(method);
    EXPECT_EQ(1u, told.size())
        << "the pool was told about the transaction " << told.size()
        << " times: a second copy rode the carrier, which double-counts it in "
           "F-10's tallies and charges a second successor for a delivery that "
           "happened once";
    for (auto& ctx : contexts_)
        ctx.process_send_queue();
    while (receiver_.notified_size())
        receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
}

/*! **The discard matrix: the two relay classes retry by different mechanisms,
    so a discard must do different things for them.**

    This is the case no test drove, and its absence let a real regression land:
    a first fix for the forwarded-stem stranding applied the fluff fallback to
    EVERY discard, which recorded originated transactions as relayed and bought
    them the derived 1148 s for a send that never happened.

    | class | retries by | a discard must |
    | --- | --- | --- |
    | `local` (originated) | `relayed == false` → `MIN_RELAY_TIME` | record NOTHING |
    | forwarded stem | `last_relayed_time`, moved only by `on_transactions_relayed` | fluff, or it is stranded until it expires |

    Two tests rather than one loop: the discard is driven by destroying every
    peer so the slots unbind, and that desynchronises the fixture's own
    connection bookkeeping — so each case needs a fresh fixture rather than a
    second pass over a spent one.

    Two tests rather than one loop, for that reason. */

/*! An ORIGINATED transaction the carrier discards stays unrelayed.

    `set_relayed` sets `meta.relayed` unconditionally, so recording a discard
    would buy the origin the derived 1148 s for a send that never happened —
    the falsification §92.5c reserves the short grid for.

    What edit reds this: removing the `originated_here` early return, which is
    exactly the regression this case exists to hold. */
TEST_F(levin_notify, a_discarded_origin_is_left_unrelayed_for_the_short_grid)
{
    const bool prior = cryptonote::levin::set_carrier_development(true);
    struct restore_t {
        bool prior;
        ~restore_t() { cryptonote::levin::set_carrier_development(prior); }
    } restore{prior};

    for (unsigned count = 0; count < 4; ++count)
        add_connection(false);

    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, true);
    auto& notifier = *notifier_ptr;
    ASSERT_LT(0u, io_service_.poll());
    ASSERT_TRUE(notifier.get_status().has_noise);
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(1);
    {
        cryptonote::transaction tx{};
        tx.unlock_time = 31;
        txs[0] = cryptonote::t_serializable_object_to_blob(tx);
    }

    // Originated: `local`, with a NIL source.
    static constexpr unsigned kMaxEpochRolls = 64;
    unsigned rolls = 0;
    for (;;)
    {
        ASSERT_LT(rolls, kMaxEpochRolls) << "no carrier-borne send";
        EXPECT_TRUE(notifier.send_txs(txs, boost::uuids::uuid{}, cryptonote::relay_method::local));
        io_service_.restart();
        io_service_.poll();
        if (events_.relayed_method_size() == 0)
            break;
        for (const auto m : {cryptonote::relay_method::fluff,
                             cryptonote::relay_method::stem,
                             cryptonote::relay_method::local})
        {
            if (events_.relayed_method_size() == 0)
                break;
            try { events_.take_relayed(m); } catch (const std::logic_error&) {}
        }
        notifier.run_fluff();
        io_service_.restart();
        io_service_.poll();
        for (auto& ctx : contexts_)
            ctx.process_send_queue();
        while (receiver_.notified_size())
            receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
        notifier.run_epoch();
        io_service_.restart();
        io_service_.poll();
        ++rolls;
    }

    /* Every peer gone, THEN an epoch roll. Destroying the connections is not
       enough on its own: the stem map keeps its bindings, so the channel goes
       on sending to a dead peer and the message restarts forever without ever
       being discarded. Measured — 24 `NoiseSend` effects and zero
       `NoiseUnbind`. The map is rebuilt at an epoch boundary, and only then
       does a slot with no peer produce the unbind that clears the queue. */
    contexts_.clear();
    io_service_.restart();
    io_service_.poll();
    notifier.run_epoch();
    io_service_.restart();
    io_service_.poll();
    drive_schedule(notifier, [](std::size_t) { return false; }, 24);

    EXPECT_EQ(0u, events_.relayed_method_size())
        << "an originated transaction discarded by the carrier was recorded as "
           "relayed. `set_relayed` sets `meta.relayed` unconditionally, so the "
           "origin now waits the derived interval for a send that never "
           "happened, and the short-grid retry is gone";

    while (receiver_.notified_size())
        receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
}

/*! A FORWARDED stem the carrier discards is fluffed, not stranded.

    Admission stamps `last_relayed_time` with `time_t::max()` and
    `get_relayable_transactions`' stem arm skips while that stamp is in the
    future, so only `on_transactions_relayed` can make it eligible again.

    What edit reds this: dropping the fluff fallback, which strands the
    transaction until it expires out of the pool. */
TEST_F(levin_notify, a_discarded_forwarded_stem_falls_back_to_fluff)
{
    const bool prior = cryptonote::levin::set_carrier_development(true);
    struct restore_t {
        bool prior;
        ~restore_t() { cryptonote::levin::set_carrier_development(prior); }
    } restore{prior};

    for (unsigned count = 0; count < 4; ++count)
        add_connection(false);

    std::shared_ptr<cryptonote::levin::notify> notifier_ptr = make_notifier(false, true);
    auto& notifier = *notifier_ptr;
    ASSERT_LT(0u, io_service_.poll());
    ASSERT_TRUE(notifier.get_status().has_noise);
    notifier.new_out_connection();
    io_service_.poll();

    std::vector<cryptonote::blobdata> txs(1);
    {
        cryptonote::transaction tx{};
        tx.unlock_time = 32;
        txs[0] = cryptonote::t_serializable_object_to_blob(tx);
    }

    const boost::uuids::uuid source = contexts_.begin()->get_id();
    static constexpr unsigned kMaxEpochRolls = 64;
    unsigned rolls = 0;
    for (;;)
    {
        ASSERT_LT(rolls, kMaxEpochRolls) << "no carrier-borne send";
        EXPECT_TRUE(notifier.send_txs(txs, source, cryptonote::relay_method::stem));
        io_service_.restart();
        io_service_.poll();
        if (events_.relayed_method_size() == 0)
            break;
        for (const auto m : {cryptonote::relay_method::fluff,
                             cryptonote::relay_method::stem,
                             cryptonote::relay_method::local})
        {
            if (events_.relayed_method_size() == 0)
                break;
            try { events_.take_relayed(m); } catch (const std::logic_error&) {}
        }
        notifier.run_fluff();
        io_service_.restart();
        io_service_.poll();
        for (auto& ctx : contexts_)
            ctx.process_send_queue();
        while (receiver_.notified_size())
            receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
        notifier.run_epoch();
        io_service_.restart();
        io_service_.poll();
        ++rolls;
    }

    // See the sibling test: the map must be rebuilt before a slot can unbind.
    contexts_.clear();
    io_service_.restart();
    io_service_.poll();
    notifier.run_epoch();
    io_service_.restart();
    io_service_.poll();
    drive_schedule(notifier, [](std::size_t) { return false; }, 24);

    /* The assertion is that the entry was UN-STRANDED, not that a peer took
       it. Every peer is gone by this point — that is how the unbind is forced
       — so the fluff reaches nobody and the daemon logs it. Recording anyway
       is the deliberate trade at the call site: it moves `last_relayed_time`
       off `time_t::max()`, which is the only thing that ever makes this entry
       relayable again, and the entry then re-relays on the ordinary grid once
       a peer returns. Not recording would strand it permanently, including
       after peers come back. */
    ASSERT_NE(0u, events_.relayed_method_size())
        << "a forwarded stem discarded by the carrier was recorded as nothing. "
           "Admission stamped `last_relayed_time` with time_t::max() and only "
           "`on_transactions_relayed` moves it, so this transaction is "
           "ineligible for forwarding until it expires out of the pool";
    EXPECT_EQ(txs, events_.take_relayed(cryptonote::relay_method::fluff))
        << "the fallback recorded something other than the discarded stem";

    while (receiver_.notified_size())
        receiver_.get_notification<cryptonote::NOTIFY_NEW_TRANSACTIONS>();
}
