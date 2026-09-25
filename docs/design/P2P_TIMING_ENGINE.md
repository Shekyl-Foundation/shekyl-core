# P2P timing engine

**Status: CLOSED — Round 2, 2026-09-25.** The nine proposals are ruled.
Wakes go to the owner's home. The wake set is ordered by time. Slice 1
holds one list deadline. PWD-B2 leaves the interim tick first. Nothing
here is a number. Periods belong to their owners. **Rule 26 is cited
explicitly.** This document mints no identifier family. The register
row is P2P-3's **TE**. The design is closed. The pre-flight is
discharged at `dev` `78eef562d`. The engine core is the next code.
The C++ bridge waits until after the transport cutover.

Pinned to `fix/p2p-transport-hmac-oracle` `55d7b2b16`. Line numbers
were read there. Opening the round still discharges D6's third
falsifier ([`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D6).

**Pre-flight discharged 2026-09-25** at `dev` `78eef562d` (the #860
merge). Substrate re-read: `levin_notify.cpp:495` and `:895`,
`net_node.h:720-725`, and `Driver::next_wake`. The relay function is
now `driver/mod.rs:158`; the design had cited `:149`. It is still
derived on every call and not cached. No other cited site moved. The
closed design names no bench and no numeric budget, so there was no
artifact to run. No redesign. The core may be written. The C++ bridge
still waits.

---

## What D6 already ruled

Not reopened here. Until this engine lands, one socketless `io_context`
remains. Then this engine owns every deadline in Rust. C++ is called,
not driven, on a budgeted blocking pool, one delivery at a time per
connection. The `io_context` is deleted. Relay dispatch is the next
round (P2P-3 **RD**). This round arms the relay sleep. It does not send
relay messages.

---

## Schedules — Round 1 table FIRED 2026-09-25

Round 1 listed two idle cadences and did not name the relay timer or
the schedules those cadences poll. The falsifier fired. The table
below is the replacement. Each row is one job. A shared interval is
what the code does today, not a constant of this engine.

The engine carries no periods. A timer exists only when an action must
happen and no event will cause it. Its period is derived from the need
it serves, never inherited. Until the owner re-derives the job, the
engine runs today's behaviour so a differential harness can match it.

| Job | Today | Owner |
| --- | --- | --- |
| Relay wake | `steady_timer wake` in `src/cryptonote_protocol/levin_notify.cpp:495`, armed at `:895` from `Driver::next_wake` (`shekyl-relay` `driver/mod.rs:158`; pre-flight: was cited as `:149` at the design pin) | relay `Driver`. This engine only sleeps until that wake |
| Chain-state backstop | `peer_sync_idle_maker` sends command 1002 every 60 s (`P2P_DEFAULT_HANDSHAKE_INTERVAL`, `cryptonote_config.h:185`). Both sides exchange height and top block (`process_payload_sync_data`) | sync lane. The period is how long a node can be stale after a missed announcement, against the block time. New blocks are already pushed when found |
| Peerlist gossip | the same 1002 response carries up to 250 addresses (`p2p_protocol_defs.h:215-239`) into the gray list | peerlist, slices 1 and 3. Also a privacy surface: each exchange shows a peer part of this node's view of the network |
| Connection liveness | the same 1002 is a request that must be answered, and it keeps the session off the inherited idle timer | the transport layer, per connector (D9). Not a Levin command |
| Per-connection timed sync | today it is the same 60 s maker as the three jobs above. PWD-B2 already ruled a per-connection draw, so sessions are not correlated by phase | the connection. One of the first owners to leave `idle_worker` |
| Outbound fill | `connections_maker`, gated at 1 s (`net_node.h:721`). The fill loop `sleep_for`s 1 s when it makes no connection (`net_node.inl:2063`) and dials serially | slice 3. A call can run for many seconds. The blocking pool has to allow that |
| Gray refill | `gray_peerlist_housekeeping`, gated at 60 s (`net_node.h:723`). That timer both triggered promotion and capped it at about one probe a minute | **replaced by an event (2026-09-25).** The diversity floor is the eclipse minimum. The refill line sits above it. If white is already below the refill line, including empty, the count is the event. Otherwise one deadline, the earliest white expiry, and a re-count when it fires. No timer per entry |
| Promotion pace | the same 60 s gate, secretly | slice 3. A bounded derived rate, jittered. This is the timer that remains |
| Peerlist store | `store_config`, gated at 30 min (`net_node.h:722`) | slice 1 |
| Incoming-connection check | `check_incoming_connections`, gated at 1 h (`net_node.h:724`) | slice 3 |
| Tor process death | `check_ephemeral_tor_liveness`, gated at 60 s (`net_node.h:725`, body at `net_node.inl:2229`) | not a timer. The Tor-control actor owns the child and can report its exit |
| Idle-peer kick | `m_idle_peer_kicker`, 8 s (`cryptonote_protocol_handler.h:205`), run from `on_idle` (`cryptonote_protocol_handler.inl:1665`) | the cryptonote handler's open register row |
| Standby check | `m_standby_checker`, 100 ms (`:206`). The tick that polls it is 1 s, so today it runs about once a second | the same open row |
| Sync search | `m_sync_search_checker`, 101 s (`:207`) | the same open row |
| Peers-monitor thread | its own thread, `sleep_for(1s)` (`net_node.inl:1113-1140`) | not this engine. D8 retires it with slice 3 |
| Rate-limit sleep | `handler_response_blocks_now` (`cryptonote_protocol_handler-base.cpp:102`). Its calls are commented out (`cryptonote_protocol_handler.inl:966-967` and `cryptonote_protocol_handler.h:238`) | not a deadline. Delete the function (rule 15) |

`idle_worker` (`net_node.inl:2217-2226`) is the 1-second poll over the
six `node_server` gates. `on_idle` is the poll over the three
cryptonote gates. They are not two schedules. Dial, handshake, gap,
and idle deadlines are owners of this engine too. They are specified
with the transport layer, not missing rows of this inventory.

The inherited handshake interval is 60, comment spelled `//secondes`,
with no derivation on either side of the fork. Three different jobs
share that minute. None of them needed 60.

Timed sync stays one message until its owners split it. PWD-B2 already
ruled that it fires per connection, independently drawn, so sessions
are not correlated by phase. It did not ask why 60.

Levin invoke timeouts are not in this table. They are keyed one-shots,
below. The C++ type at `levin_protocol_handler_async.h:226` is spelled
`anvoke_handler`. That file goes away with the event loop, so the
spelling is not renamed there. Rust spells it `invoke`. The waits are
at `:236` and `:298`.

Anything that merely expires is evaluated when it is next used, from
timestamps: ban entries, the 24-hour peerlist demotion, the accept-rate
bucket's refill. Bans already work that way: `is_remote_host_allowed`
unbans on lookup. No timer per peerlist entry.

---

## Ruled answers (2026-09-25)

### 1. The engine delivers wakes; the owner polls at home

An owner is a state machine with `next_wake(now)` and `poll(now)` that
returns effects. It never sleeps. The engine does not poll an owner
that lives somewhere else. It delivers a wake message to that owner's
home, and the owner polls itself there. A per-connection transport
state machine, and PWD-B2's per-connection timed sync, live with the
connection. Their events arrive on transport tasks. The engine thread
does not share that state.

Owners that live on the engine thread poll in place: the relay
`Driver`, and the interim C++ cadences. The invoke bridge is the same
pattern. Expiry is a message on the connection's queue.

The owner reports a new `next_wake` only when its earliest deadline
changes. A byte arriving does not re-arm the engine.

An early or spurious wake is harmless, because the owner checks `now`.
Waking late is the failure. Lateness has two parts, both measured: the
delay in delivering the wake, and the delay in the owner's home queue.

### 2. A period is an owner

A periodic owner's next wake is last-run-finished plus its period.
Fixed delay. No catch-up burst after a stall, and no overlapping run.
One mechanism.

**The interim coupling is a known defect.** Until the owners land, one
`idle_worker` tick runs all six `node_server` gates in sequence.
`connections_maker` can block for many seconds, and timed sync waits
behind it. PWD-B2's per-connection timed sync is one of the first
owners to land, rather than staying inside `idle_worker` until the
sync and peerlist splits. The other gates may keep today's call until
their owners exist, and those calls do not overlap one another.

### 3. The wake set is ordered by time

The engine never scans owners. It keeps wake hints in a structure
ordered by time and wakes only the earliest. A superseded hint is
discarded by a generation number, not by a search. Cost per re-arm is
logarithmic in the number of owners. Nothing on the tick is linear in
that number. A loop over every owner would rebuild `idle_worker`'s
one-second poll inside the new engine.

A timer exists only when an action must happen and no event will cause
it. Ban entries, the 24-hour demotion's correctness, and the
accept-rate bucket's refill are evaluated when next used, from
timestamps. The demotion's *notice* is the one list deadline in the
table, not a timer per entry.

### 4. The call into C++

A Levin invoke timeout is `arm(connection, invoke_id, deadline)` and
returns an opaque `TimerId` that is never reused. Cancelling a stale id
does nothing. Cancel is best-effort. Correctness is the delivery, not
the cancel.

Expiry is a message on that connection's queue, the same queue as its
incoming bytes, one delivery at a time. A response racing its timeout
is whichever is dequeued first. C++ resolves the invoke by id,
idempotently. Firing a timer only enqueues. The engine does not wait on
C++. C++ does not block the engine.

An invoke timeout queued behind a stuck handler for the same connection
waits with it. The backstop is the transport layer's per-connection gap
and idle deadlines: they close the connection whatever C++ is doing.

Idle cadences run on their own lane of the blocking pool, never
overlapping. When LV-3 moves invokes into Rust, invoke timeouts become
ordinary owner deadlines and this bridge goes away.

### 5. Where the sleeps run

One dedicated engine thread, budget one, counted in D5. Not the
transport runtime. That runtime is where attacker-driven work lands,
and a tokio timer fires only when a worker polls the time driver. A
saturated transport runtime means late relay wakes.

An owner's `poll` is cheap and never blocks. Heavy work is posted
elsewhere. That is what makes one thread enough.

If the transport design's step-7 flood measurement shows relay lateness
no better on this thread than on the transport runtime, merge the
engine into the transport runtime.

### 6. Shutdown, in order

1. Stop accepting new registrations. A deadline that fires after this,
   other than the aborts in step 3, is dropped.
2. The transport stops accepting new connections. Connection queues
   stay up.
3. Pending invoke timeouts are enqueued as `Aborted(Shutdown)`, not
   `Timeout`, on those queues, and each queue delivers that message.
   Shutdown is not a peer misbehaving. The queues exist for this step.
4. Then the transport cancels its tasks. Those owners drop, and their
   deadlines go with them.
5. A periodic callback already running finishes. No new one starts.
6. Relay owners drop. Whether anything is flushed first is a hook the
   relay lane exposes. It is not this engine's decision.
7. The blocking pool drains.
8. The engine thread exits.

### 7. What the engine never does

It does not draw randomness. Distributions stay in the policy crates
the conformance tests grade. It does not coalesce or quantise a
privacy-sensitive deadline. Timer slack is only for a class labelled
housekeeping.

### 8. The clock is monotonic and passed in

Tests pass a clock as a constructor argument or a type parameter, not a
cargo feature. `shekyl-ffi`'s features merge into the production build,
so a feature-gated test clock would ship. Virtual time lets relay
conformance and the transport timeouts run deterministically.

### 9. Lateness is an output

Every fire records two delays, per owner class: how late the wake was
delivered, and how long it then waited in the owner's home queue. That
is the input to the step-7 lateness measurement and to D5's budgets. It
is exposed to the operator over RPC, never to a peer.

---

## One mechanism, one job

A setting, field, timer, or structure that serves more than one job is
split. Each job names an owner. The owner derives its own value, or
replaces the mechanism with an event. A value shared between jobs is
inherited, not derived. The shared setting ends up tuned for whichever
job its author was thinking of, and the others cannot change it without
disturbing the first.

This round is the first place that test is applied on purpose. Timed
sync is three rows in the table above for that reason.

---

## Implementation order

The transport layer's per-connection deadlines are owners of this
engine. Building them on tokio timers, then moving them, would edit
that path twice. The engine therefore lands in two pieces. D6's order
is unchanged: the transport cutover still precedes the deletion of the
interim executor.

1. **The engine core, first.** A small Rust crate. The owner trait
   (`next_wake`, `poll`), the time-ordered wake set with generation
   numbers, delivery of a wake to the owner's home, the injected
   monotonic clock, and lateness recording. It is tested in virtual
   time. The transport layer uses it from its first line. The pre-flight
at `dev` `78eef562d` is that gate.
2. **The C++ bridge, after the transport cutover.** Invoke-timeout
   arming, the interim idle cadences on the blocking pool, moving the
   relay `Driver`'s sleep off asio, and deleting the `io_context`.
   That is the replacement D6 already ruled.
