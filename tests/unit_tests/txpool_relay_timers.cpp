// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// RP-4 (docs/design/DAEMON_RELAY_PRIVACY.md §17.1): the embargo and
// MIN_RELAY_TIME are disjoint timers, and that must stay true.
//
// get_relayable_transactions dispatches on relay *method*: stem is gated
// solely by `last_relayed_time > now` — which for a stemmed tx IS its embargo
// deadline — while get_relay_delay/MIN_RELAY_TIME gates only
// local/fluff/block. (`forward` shared the stem arm until Q12-U2 deleted the
// class; the disjointness this file guards is unchanged by that.)
// That disjointness is why lengthening the embargo from the inherited 39s
// to the derived 144s cannot race the re-broadcast interval, even though
// the origin-alone black-hole recovery p90 (~331s) now exceeds
// MIN_RELAY_TIME (300s).
//
// Armed here rather than left as prose because a future edit that folded stem
// into the get_relay_delay branch would reintroduce the race silently: the
// daemon would still relay, just at the wrong time, and no existing test looks.
// The discriminating case is a stem tx whose embargo has *just* expired — the
// two branches disagree there, so it fails loudly if they are ever merged.

#define IN_UNIT_TESTS

#include "gtest/gtest.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <functional>
#include <limits>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include "blockchain_db/testdb.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
// cryptonote_core.h defines cryptonote::test_options (blockchain.h only
// forward-declares it), needed by init_blockchain's fakechain options.
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "net/net_utils_base.h"
#include "shekyl/shekyl_ffi.h"

using namespace cryptonote;

namespace
{

// Minimal in-memory txpool-backed TestDB for relay-timer probes.
class RelayTimerTestDB : public BaseTestDB
{
public:
  explicit RelayTimerTestDB(uint64_t height) : m_height(height) { m_open = true; }

  crypto::hash block_id_at(uint64_t height) const
  {
    crypto::hash h = crypto::null_hash;
    const uint64_t tagged_height = height + 1;
    memcpy(h.data, &tagged_height, sizeof(tagged_height));
    return h;
  }

  virtual uint64_t height() const override { return m_height; }
  virtual crypto::hash get_block_hash_from_height(const uint64_t& height) const override
  {
    return block_id_at(height);
  }
  virtual crypto::hash top_block_hash(uint64_t* block_height = NULL) const override
  {
    if (block_height)
      *block_height = m_height ? m_height - 1 : 0;
    return m_height ? block_id_at(m_height - 1) : crypto::null_hash;
  }

  virtual void add_txpool_tx(const crypto::hash& txid, const cryptonote::blobdata_ref& blob,
    const cryptonote::txpool_tx_meta_t& meta) override
  {
    m_txpool[txid] = {meta, cryptonote::blobdata(blob.data(), blob.size())};
  }
  virtual void update_txpool_tx(const crypto::hash& txid, const cryptonote::txpool_tx_meta_t& meta) override
  {
    const auto it = m_txpool.find(txid);
    if (it != m_txpool.end())
      it->second.meta = meta;
  }
  virtual void remove_txpool_tx(const crypto::hash& txid) override { m_txpool.erase(txid); }
  virtual uint64_t get_txpool_tx_count(relay_category = relay_category::broadcasted) const override
  {
    return m_txpool.size();
  }
  virtual bool txpool_has_tx(const crypto::hash& txid, relay_category) const override
  {
    return m_txpool.count(txid) != 0;
  }
  virtual bool get_txpool_tx_meta(const crypto::hash& txid, cryptonote::txpool_tx_meta_t& meta) const override
  {
    const auto it = m_txpool.find(txid);
    if (it == m_txpool.end())
      return false;
    meta = it->second.meta;
    return true;
  }
  virtual bool get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata& bd, relay_category) const override
  {
    const auto it = m_txpool.find(txid);
    if (it == m_txpool.end())
      return false;
    bd = it->second.blob;
    return true;
  }
  virtual cryptonote::blobdata get_txpool_tx_blob(const crypto::hash& txid, relay_category) const override
  {
    return m_txpool.at(txid).blob;
  }
  virtual bool for_all_txpool_txes(
    std::function<bool(const crypto::hash&, const cryptonote::txpool_tx_meta_t&, const cryptonote::blobdata_ref*)> f,
    bool include_blob = false, relay_category = relay_category::broadcasted) const override
  {
    for (const auto& entry : m_txpool)
    {
      cryptonote::blobdata_ref ref{entry.second.blob.data(), entry.second.blob.size()};
      if (!f(entry.first, entry.second.meta, include_blob ? &ref : nullptr))
        return false;
    }
    return true;
  }

private:
  struct pool_entry
  {
    cryptonote::txpool_tx_meta_t meta;
    cryptonote::blobdata blob;
  };

  uint64_t m_height;
  std::unordered_map<crypto::hash, pool_entry> m_txpool;
};

struct BlockchainAndPool
{
  cryptonote::tx_memory_pool txpool;
  cryptonote::Blockchain bc;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif
  BlockchainAndPool() : txpool(bc), bc(txpool) {}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
};

bool init_blockchain(Blockchain& bc, BlockchainDB* db)
{
  const std::pair<uint8_t, uint64_t> hard_forks[] = {
    std::make_pair(static_cast<uint8_t>(1), static_cast<uint64_t>(0)),
    std::make_pair(static_cast<uint8_t>(0), static_cast<uint64_t>(0)),
  };
  const cryptonote::test_options test_options = {hard_forks, 5000};
  return bc.init(db, cryptonote::FAKECHAIN, true, &test_options, 1, nullptr);
}

crypto::hash make_txid(uint8_t fill)
{
  crypto::hash h;
  memset(h.data, fill, sizeof(h.data));
  return h;
}

cryptonote::blobdata make_minimal_tx_blob()
{
  cryptonote::transaction tx{};
  tx.version = 1;
  tx.unlock_time = 0;
  return cryptonote::tx_to_blob(tx);
}

txpool_tx_meta_t make_meta(uint64_t weight, time_t receive_time)
{
  txpool_tx_meta_t meta{};
  meta.weight = weight;
  meta.fee = 1000;
  meta.receive_time = receive_time;
  meta.set_relay_method(relay_method::fluff);
  return meta;
}

// A pool holding one tx with the given relay method and timers.
//
// Ownership: `db` is a raw pointer on purpose. `Blockchain::init` takes
// ownership of the BlockchainDB (blockchain.cpp: `m_db = db`), and
// `~Blockchain` calls `deinit()`, which does `delete m_db`. Holding it in a
// unique_ptr here would double-free, so the raw pointer *is* the correct
// expression of "owned elsewhere from `init()` onward" — it is not a leak.
// Copying would alias that single ownership (and `BlockchainAndPool`'s members
// hold references to each other), so copies are deleted rather than left to be
// discovered.
struct RelayTimerFixture
{
  BlockchainAndPool bap;
  RelayTimerTestDB* db; //!< owned by `bap.bc` from `init()` on; freed in ~Blockchain.
  crypto::hash txid;
  cryptonote::blobdata blob;

  RelayTimerFixture() : db(new RelayTimerTestDB(300)), txid(make_txid(0x77)),
                        blob(make_minimal_tx_blob()) {}

  RelayTimerFixture(const RelayTimerFixture&) = delete;
  RelayTimerFixture& operator=(const RelayTimerFixture&) = delete;

  bool init() { return init_blockchain(bap.bc, db); }

  //! `relayed` defaults to the sent case; the unsent one is a `local`-only
  //! state (`insert_attested_tx`) and the tests that drive it say so.
  void put(relay_method method, time_t receive_time, time_t last_relayed_time,
           bool relayed = true)
  {
    txpool_tx_meta_t meta = make_meta(100, receive_time);
    meta.set_relay_method(method);
    meta.last_relayed_time = last_relayed_time;
    meta.relayed = relayed;
    db->add_txpool_tx(txid, {blob.data(), blob.size()}, meta);
  }

  bool relayable()
  {
    std::vector<std::tuple<crypto::hash, cryptonote::blobdata, relay_method>> txs;
    bap.txpool.get_relayable_transactions(txs);
    for (const auto& t : txs)
      if (std::get<0>(t) == txid)
        return true;
    return false;
  }
};

} // namespace

TEST(txpool_relay_timers, stem_is_gated_by_its_embargo_not_min_relay_time)
{
  const time_t now = time(nullptr);
  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());

  // The discriminating case: a stem tx whose embargo expired a moment ago. The
  // embargo says "relay now"; MIN_RELAY_TIME (300s since it was set) says
  // "wait". Only the embargo may govern a stem tx, so it must be relayable.
  fx.put(relay_method::stem, now - 10, now - 1);
  EXPECT_TRUE(fx.relayable())
    << "an expired embargo must release the tx immediately; if MIN_RELAY_TIME "
       "gated stem txs this would wait ~300s and the sec 17.1 reconciliation "
       "would be broken";
}

TEST(txpool_relay_timers, stem_under_embargo_is_held_however_old_the_tx_is)
{
  const time_t now = time(nullptr);
  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());

  // Received long ago (well past MIN_RELAY_TIME) but the embargo deadline is
  // still in the future: age must not release it. The deadline is the gate.
  fx.put(relay_method::stem, now - 100000, now + 3600);
  EXPECT_FALSE(fx.relayable())
    << "a stem tx must stay held until its embargo deadline passes";
}

// ─────────────────────────────────────────────────────────────────────────────
// §92.5c item 3: an ORIGIN's re-broadcast is derived, not `MIN_RELAY_TIME`.
//
// `originated_stays_in_zone` pins an anonymity-zone origin at `local`
// permanently, so that entry lives on the re-broadcast branch for its whole
// life. §15.4 cleared `MIN_RELAY_TIME` from the embargo's neighbourhood
// because it "governs an already-fluffed transaction" — true when written, and
// vacated by that predicate, which created a class that is never fluffed.
//
// At 300 s the origin re-emitted BELOW its own zone's embargo median (346 s).
// The base is now the 1-in-10 survival quantile — the confidence the network
// itself uses (`EMBARGO_FULL_TRAVEL_PROBABILITY`) — which is 1148 s.
// ─────────────────────────────────────────────────────────────────────────────

TEST(txpool_relay_timers, local_holds_past_min_relay_time)
{
  const time_t now = time(nullptr);
  const time_t derived =
    static_cast<time_t>(shekyl_dandelionpp_origin_retry_interval_seconds(
      static_cast<std::uint8_t>(epee::net_utils::zone::invalid)));
  ASSERT_GT(derived, 300) << "the derived origin retry must exceed MIN_RELAY_TIME, "
                             "or this test cannot discriminate";

  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());

  // THE discriminating case: SENT, and last relayed 400 s ago — past
  // MIN_RELAY_TIME (300 s), short of the derived interval. Reverting the base
  // to MIN_RELAY_TIME turns this green→red, which is the whole point of the
  // case. `relayed` is what separates it from
  // `an_unsent_local_still_falls_back_at_min_relay_time`, which is the same
  // 400 s and expects the opposite verdict.
  fx.put(relay_method::local, now - 400, now - 400, /*relayed=*/true);
  EXPECT_FALSE(fx.relayable())
    << "an origin must not re-emit at MIN_RELAY_TIME: that is inside its own "
       "zone's embargo median, so the retry fires while the stem is still "
       "propagating normally";
}

TEST(txpool_relay_timers, local_is_released_after_the_derived_interval)
{
  const time_t now = time(nullptr);
  const time_t derived =
    static_cast<time_t>(shekyl_dandelionpp_origin_retry_interval_seconds(
      static_cast<std::uint8_t>(epee::net_utils::zone::invalid)));

  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());

  // The other side, so the hold above is not simply "local never relays".
  fx.put(relay_method::local, now - (derived + 60), now - (derived + 60),
         /*relayed=*/true);
  EXPECT_TRUE(fx.relayable())
    << "past the derived interval the origin's backstop must fire; a hold with "
       "no release is not a backoff, it is a disarm nobody ruled on";
}

TEST(txpool_relay_timers, an_unsent_local_still_falls_back_at_min_relay_time)
{
  const time_t now = time(nullptr);

  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());

  // `insert_attested_tx`'s state: stamped `local`, never sent, this loop named
  // as the fallback if the engine's fire-and-forget submit nudge missed. There
  // is no stem to have completed and no embargo anywhere, so the derived
  // interval provisions against an event that cannot have happened -- it would
  // be 848 s of added latency on a FIRST send.
  //
  // Same 400 s as `local_holds_past_min_relay_time`, which is the point: the
  // two cases differ only in `relayed`, so the base must discriminate on
  // exactly that axis. Deleting the `!meta.relayed` arm of `local_relay_base`
  // turns this green->red.
  fx.put(relay_method::local, now - 400, now - 400, /*relayed=*/false);
  EXPECT_TRUE(fx.relayable())
    << "a local tx that was never sent must not inherit the origin's stem-"
       "completion wait: the nudge-missed fallback is a liveness question, "
       "not a privacy one";
}

// §92.5c item 1: the disarm predicate. F-10 already computes it — "this came
// back from somewhere other than where I sent it" — and this is the consumer.
//
// The re-broadcast exists because an origin cannot observe its own stem. The
// moment it can, the reason is gone, so the predicate retires the timer rather
// than shortening it.

// ONE `relayable()` CALL PER FIXTURE, and the reason is load-bearing.
// `get_relayable_transactions` sets `m_next_check = now + 2 min` on every
// call, so a second call in the same test returns false whatever the entry
// says. A before/after pair inside one fixture therefore goes green on the
// clock rather than on the subject — which is how the first draft of the
// disarm test below passed while asserting nothing. Each case builds its own
// pool and asks once.

TEST(txpool_relay_timers, an_observed_local_stops_re_broadcasting)
{
  const time_t now = time(nullptr);
  const time_t derived =
    static_cast<time_t>(shekyl_dandelionpp_origin_retry_interval_seconds(
      static_cast<std::uint8_t>(epee::net_utils::zone::invalid)));

  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());
  // Past the derived interval, so the TIMER would release it — the disarm has
  // to be what holds it, or this case proves nothing.
  fx.put(relay_method::local, now - (derived + 60), now - (derived + 60), /*relayed=*/true);
  fx.bap.txpool.on_stem_propagated(epee::to_span(std::vector<crypto::hash>{fx.txid}));

  EXPECT_FALSE(fx.relayable())
    << "an origin that has seen its transaction circulating has nothing left "
       "to rescue; the re-broadcast must retire, not merely wait longer";
}

TEST(txpool_relay_timers, the_same_local_without_the_verdict_still_relays)
{
  const time_t now = time(nullptr);
  const time_t derived =
    static_cast<time_t>(shekyl_dandelionpp_origin_retry_interval_seconds(
      static_cast<std::uint8_t>(epee::net_utils::zone::invalid)));

  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());
  // The control for the case above: same entry, same age, no verdict. Without
  // this pair the disarm test cannot distinguish "the predicate fired" from
  // "nothing was ever relayable".
  fx.put(relay_method::local, now - (derived + 60), now - (derived + 60), /*relayed=*/true);

  EXPECT_TRUE(fx.relayable())
    << "past the derived interval and unobserved, the origin's backstop fires";
}

TEST(txpool_relay_timers, a_propagated_fluff_entry_is_not_disarmed)
{
  const time_t now = time(nullptr);

  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());
  // The scoping check. The watch resolves observations for every stem this
  // node placed, relayed ones included — and a relayed entry sits at `fluff`,
  // where MIN_RELAY_TIME governs and nobody asked the origin's question.
  // Letting a verdict reach that arm would silence a timer on a class that
  // never armed a disarm.
  fx.put(relay_method::fluff, now - 400, now - 400, /*relayed=*/true);
  fx.bap.txpool.on_stem_propagated(epee::to_span(std::vector<crypto::hash>{fx.txid}));

  EXPECT_TRUE(fx.relayable())
    << "the disarm is the local arm's alone — a propagation verdict for a "
       "relayed entry must leave its ordinary re-relay untouched";
}

TEST(txpool_relay_timers, fluff_still_obeys_min_relay_time)
{
  const time_t now = time(nullptr);
  RelayTimerFixture fx;
  ASSERT_TRUE(fx.init());

  // The other half of the disjointness: a just-relayed fluff tx is held by
  // get_relay_delay/MIN_RELAY_TIME, which the embargo change must not disturb.
  fx.put(relay_method::fluff, now, now);
  EXPECT_FALSE(fx.relayable())
    << "a fluff tx relayed just now must wait out MIN_RELAY_TIME";
}

// ─────────────────────────────────────────────────────────────────────────────
// The embargo deadline rounds AWAY from now (RP-4, sec 17).
//
// `now` carries a sub-second remainder and the stored deadline is a whole-second
// time_t, so the conversion must round — and the direction is a privacy
// decision. Truncating (what to_time_t does on its own) would shave up to ~999ms
// off every embargo, undoing one layer down what the Rust side's div_ceil does
// one layer up; under-provisioning fluffs early, the privacy-losing direction.
//
// Tested on a synthetic `now` rather than the system clock, so the fractional
// case is exercised deterministically instead of whenever the clock happens to
// land off a second boundary.
// ─────────────────────────────────────────────────────────────────────────────
namespace
{
  // A time_point at `whole` seconds past the epoch plus `frac` milliseconds.
  std::chrono::system_clock::time_point at(std::time_t whole, int frac_ms)
  {
    return std::chrono::system_clock::from_time_t(whole) + std::chrono::milliseconds{frac_ms};
  }
}

TEST(relay_deadline, fractional_now_rounds_up_never_down)
{
  // The case the bug lived in: 1ms past the second, so truncation would return
  // 1000 + 144 and silently shorten the embargo by 999ms.
  EXPECT_EQ(cryptonote::detail::relay_deadline(at(1000, 1), 144), 1145)
    << "a sub-second remainder must push the deadline to the next whole second";
  // Worst case for truncation.
  EXPECT_EQ(cryptonote::detail::relay_deadline(at(1000, 999), 144), 1145);
  // Anywhere in the interior rounds to the same next second.
  EXPECT_EQ(cryptonote::detail::relay_deadline(at(1000, 500), 144), 1145);
}

TEST(relay_deadline, exact_second_is_not_padded)
{
  // On an exact boundary there is nothing to round: ceil must be the identity,
  // not an unconditional +1. Rounding up here would lengthen every embargo by a
  // second for no reason, which is a (smaller) drift in the other direction.
  EXPECT_EQ(cryptonote::detail::relay_deadline(at(1000, 0), 144), 1144);
  EXPECT_EQ(cryptonote::detail::relay_deadline(at(0, 0), 0), 0);
}

TEST(relay_deadline, an_out_of_range_draw_saturates_forward_never_backward)
{
  /* The FFI declares `uint64_t` and `seconds::rep` is signed, so a value past
     the signed range would cast NEGATIVE — a deadline in the past, which
     shortens the delay. Shortening is the privacy-losing direction for both
     callers, and it would be silent: the transaction relays early and nothing
     reports it.

     No shipped draw reaches here (both tables truncate far below), so this
     guards the declared type rather than a live path — which is exactly the
     kind of boundary a future caller reads and trusts. */
  const auto now = at(1000, 0);
  const std::time_t plain = cryptonote::detail::relay_deadline(now, 144);

  for (const std::uint64_t absurd : {
         std::uint64_t{1} << 62,
         std::uint64_t{1} << 63,                       // exactly the sign bit
         std::numeric_limits<std::uint64_t>::max(),
       })
  {
    const std::time_t got = cryptonote::detail::relay_deadline(now, absurd);
    EXPECT_GT(got, plain)
      << "an absurd draw must saturate FORWARD, not wrap: got " << got
      << " against " << plain << " for a normal 144 s draw";
    EXPECT_GE(got, static_cast<std::time_t>(1000))
      << "a saturated deadline must never land at or before `now`";
  }

  // Control: the guard must not disturb a normal draw. Without this, clamping
  // everything to a constant would pass the assertions above.
  EXPECT_EQ(cryptonote::detail::relay_deadline(now, 144), 1144);
  EXPECT_EQ(cryptonote::detail::relay_deadline(now, 0), 1000);
}

TEST(relay_deadline, zero_draw_still_never_lands_in_the_past)
{
  // A 0s draw is legitimate (~0.17%: the memoryless geometric's support includes
  // 0). It must still not resolve to an already-past deadline when `now` is
  // mid-second, which is exactly what truncation would produce.
  EXPECT_EQ(cryptonote::detail::relay_deadline(at(5000, 1), 0), 5001);
  EXPECT_EQ(cryptonote::detail::relay_deadline(at(5000, 0), 0), 5000);
}

TEST(relay_deadline, is_monotonic_in_the_draw)
{
  // A longer draw can never yield an earlier deadline, at any sub-second offset.
  for (const int frac : {0, 1, 250, 999})
  {
    std::time_t previous = std::numeric_limits<std::time_t>::min();
    for (std::uint64_t draw = 0; draw <= 300; ++draw)
    {
      const std::time_t d = cryptonote::detail::relay_deadline(at(1000, frac), draw);
      EXPECT_GE(d, previous) << "non-monotonic at frac=" << frac << " draw=" << draw;
      previous = d;
    }
  }
}
