# P2P timing engine

**Status: OPEN — Round 1, 2026-09-25.** The round is the design of the
engine [`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D6 already
named. It does not re-open that ruling. Implementation does not start
until the round closes. **Rule 26 is cited explicitly**
(`26-sub-pr-design-discipline.mdc`): the engine crosses the FFI and
replaces asio's event loop. Numeric budgets are not written before a
measurement (rule 26 B9). This document mints no identifier family.
The register row is P2P-3's **TE**.

Pinned to `fix/p2p-transport-hmac-oracle` `55d7b2b16`, which sits on
`dev` after the transport-layer design. Line numbers below were read
at that pin.

Opening this round discharges D6's third falsifier: the interim
executor is bounded because its end is this round, not LV-3.

---

## What is already ruled

D6, not this document:

- Until this engine lands, one socketless `io_context` remains, built
  by D5's constructor, with a measured thread budget in place of the
  hard-coded 10. C++ on a transport thread only posts work to it.
- This engine then owns every deadline in Rust. C++ is called, not
  driven. C++ work runs on a budgeted blocking pool owned by Rust,
  never on an async worker, with one delivery at a time per connection.
  The `io_context` is deleted. C++ has no event loop.
- Relay dispatch is the next round after this one (P2P-3 **RD**). This
  round arms the relay `Driver`'s sleep. It does not send relay messages.
- The cryptonote handler stays the open register row. It runs on the
  blocking pool once this engine lands. Its replacement has no owner.

The deadlines D6 named, and where they are at this pin:

| Deadline | Where it lives now |
| --- | --- |
| Levin invoke timeout | `anvoke_handler` arms `m_timer` on the connection's `io_context` (`levin_protocol_handler_async.h:229`, waits at `:236` and `:298`). Two waits, not the single site D6's summary cited. |
| Idle cadence | Two handlers, each 1 second, on the public zone (`net_node.inl:1146-1147`). |
| Executor pool | Hard-coded `thrds_count = 10` (`net_node.inl:1150`). |
| Shared context | `add_zone` builds every other zone on the public zone's `io_context` (`net_node.inl:805`). |
| Relay sleep | `shekyl-relay`'s `Driver` does not sleep. It returns `next_wake` (`driver/mod.rs:6-13`, `:123-124`). The asio timer is what sleeps. There is no cached `armed_deadline`; the next wake is derived (`:18-21`). |

---

## What this round has to decide

These are open. A number is not an answer.

1. **Where the sleeps run.** D5 gives the transport layer its own
   runtime, because a peer flood must not starve wallet RPC, and it
   refuses an unbudgeted third runtime. This round decides whether the
   engine's sleeps share that runtime or are a budgeted runtime of
   their own. The blocking pool is separate from either: C++ does not
   run on an async worker.
2. **One wake, or one timer per deadline.** The relay driver is built
   so one caller arms one timer against `next_wake` and does not keep
   a second copy of the deadline. Levin invokes are many timeouts at
   once, cancelled when the response arrives. The idle cadences are
   periodic. The engine has to hold all three without giving the relay
   driver a cached deadline.
3. **The call into C++.** An expiry carries an id. C++ keeps the
   pending-invoke state. The shape of that id, of cancel, and of "one
   delivery at a time" on the blocking pool is this round's contract.
4. **Shutdown.** The interim's order is already ruled (stop accept,
   cancel transport tasks, drain, stop). This round names the engine's
   own order: which deadlines are cancelled, which C++ calls are
   allowed to finish, and what a deadline firing during shutdown is.

## Falsifier

Re-cut this round, rather than implement from it, if a deadline the
daemon already arms is missing from the table above. Check by reading
the timer and `async_wait` sites at the pin, not by trusting this list.
