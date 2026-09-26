# P2P timing engine

**Status: CLOSED — Round 2, 2026-09-25.** The nine proposals are ruled.
Wakes go to the owner's home. The wake set is ordered by time. Slice 1
holds one list deadline. PWD-B2 leaves the interim tick first. Nothing
here is a number. Periods belong to their owners. **Rule 26 is cited
explicitly.** This document mints no identifier family. The register
row is P2P-3's **TE**. The design is closed. The pre-flight is
`ca825e8df`, which re-read `dev` `78eef562d` and landed before the
crate. The engine core is
`shekyl-timing-engine`: wake hints, an earlier-only arm, one outstanding
wake per owner, and lateness per class. The engine service and the C++
bridge are not in that crate. The service's concurrency decisions are
the addendum below (2026-09-25, not a new round). The bridge waits until
after the transport cutover.

Pinned to `fix/p2p-transport-hmac-oracle` `55d7b2b16`. Line numbers
were read there. Opening the round still discharges D6's third
falsifier ([`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D6).

**Pre-flight discharged 2026-09-25** by `ca825e8df`, the commit before
the crate. It re-read the substrate at `dev` `78eef562d` (the #860
merge). Substrate re-read: `levin_notify.cpp:495` and `:895`,
`net_node.h:720-725`, and `Driver::next_wake`. The relay function is
now `driver/mod.rs:158`; the design had cited `:149`. It is still
derived on every call and not cached. No other cited site moved. The
closed design names no bench and no numeric budget, so there was no
artifact to run. No redesign. The core may be written. It has since
been written, as `shekyl-timing-engine`. The C++ bridge still waits.

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
| Relay wake | `steady_timer wake` in `src/cryptonote_protocol/levin_notify.cpp:495`, armed at `:895` from `Driver::next_wake` (`shekyl-relay` `driver/mod.rs:158`) | relay `Driver`. This engine only sleeps until that wake |
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

The owner reports a new `next_wake` only when the earliest deadline
moves earlier. A deadline that moves later is not reported. The owner
is woken at the old time, which is harmless because it checks `now`,
and it re-arms then. Idle and gap timers, which move later on every
byte, do not re-arm the engine on each byte. The core holds the same
rule: `arm` at a deadline that is not strictly earlier than the one
already stored is a no-op and returns the current generation. An owner
that is not armed, because it fired or was cleared, takes the new
deadline as its first hint.

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
one-second poll inside the new engine. The count of armed owners is
updated as owners arm, fire, clear, and deregister, so stale hints are
heap length minus that count. The heap is rebuilt when stale hints
outnumber live ones: at most one rebuild per doubling.

Equal deadlines fire in owner-id order, oldest owner first. The order
is fixed so virtual-time tests and relay conformance are deterministic.
Nanosecond ticks and jittered draws make a tie rare. Older owners are
served first when one happens. Fairness must not depend on that order.

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

Pi-4 `wake_hints` run, 2026-09-26, `skl-pi` (aarch64, 4 cores), about
four minutes:
[`timing_engine_wake_hints_pi4_20260926T003745Z.txt`](../benchmarks/timing_engine_wake_hints_pi4_20260926T003745Z.txt).
An earlier arm at 2^18 owners is 177 ns; one due poll is 377 ns. That
file is the measurement D5's engine-thread budget is taken from. The
budget is not written here.

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

A `Tick` is nanoseconds since the clock's origin. `ManualClock` is the
test clock. `MonotonicClock` is the production clock: `std::time::Instant`,
origin at construction. On Linux that instant is `CLOCK_MONOTONIC`, which
does not advance while the system is suspended, so a deadline is not late
by the time the machine spent suspended. The transport layer and the C++
bridge use this clock. They do not keep their own.

### 9. Lateness is an output

Every fire records two delays, per owner class: how late the wake was
delivered, and how long it then waited in the owner's home queue. Each
class keeps the sum, the maximum, and a 64-bucket power-of-two histogram,
so the tail — how often a wake is late by at least a power-of-two
threshold — is a bucket sum. That is the input to the step-7 lateness
measurement and to D5's budgets. It is exposed to the operator over RPC,
never to a peer.

An owner has at most one outstanding wake. A later fire before the home
reports replaces that wake, and the replacement is its own lateness
count. The pending set is one slot per owner. Deregistering removes that
slot. A slow home cannot pile up wakes for the same owner.

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

1. **The engine core, landed as `shekyl-timing-engine`.** Wake hints
   ordered by time and dropped by generation. An owner reports a new
   deadline by calling `arm`, and only when that deadline is earlier
   than the one stored. The engine's `poll` hands due wakes back; the
   owner polls itself at home. There is no owner trait in this crate,
   because the engine does not call the owner. The clock is injected.
   Lateness is a per-class histogram, and each owner has one outstanding
   wake. Tested in virtual time against a list scanned in full. The
   transport layer uses it from its first line. The pre-flight at `dev`
   `78eef562d` was the gate before this crate.
2. **The C++ bridge, after the transport cutover.** Invoke-timeout
   arming, the interim idle cadences on the blocking pool, moving the
   relay `Driver`'s sleep off asio, and deleting the `io_context`.
   That is the replacement D6 already ruled.

## The engine service — ADDENDUM 2026-09-25, not a new round

The crate is the data structure. The transport layer calls a service
around it, from its first line. These are the decisions that service is
built from. The service is `EngineService` in `shekyl-timing-engine`
(landed 2026-09-26). Invoke aborts stay on the bridge. Shutdown steps
2–8 stay with the transport and the bridge; step 1 is this service.

**Owners never wait on the engine.** `arm`, `clear`, and `deregister`
are fire-and-forget: the send returns when the command is queued, not
when the engine has applied it. A `Wake` already carries its
`generation`, so the home learns that generation from the wake it is
handed, not from a reply to `arm`. Owner ids are handed out by the
handle from an atomic counter, so registering is not a round trip
either. The handle is a type in this crate. `OwnerId`'s field stays
private (`OwnerId(u64)`); transport never constructs one. `register`
takes the id the handle minted in this crate and refuses a duplicate,
including an id that was deregistered. A stale hint for that id is
still in the heap, and reusing the id would let it match the new
owner's first arming.
*Records-was: the core assigned ids itself (`Engine::register`,
`next_id`).* That is the core change. A public constructor on
`OwnerId` is not part of it. An id the handle minted is handed out by
`IdSource` in the same crate. The core's bench uses that source
because it calls `register` directly.

**One outstanding wake is the delivery primitive.** Each owner has a
single wake slot. It is not a queue. Delivery writes the newest `Wake`
into that slot. If the slot was empty, it wakes the home. If the slot
already held a wake, it does not wake the home again, and the core
counts the replacement (`ClassLateness.replaced_wakes`). The home takes
whatever wake is in the slot when it runs, so `note_home` is handed the
generation the core still holds. Leaving the older wake in the slot
would make `note_home` return `NoSuchWake` and the newer wake
unreportable. The home drops the slot's lock before it does any work,
so the engine thread never waits on the owner. Close and deregister
record a terminal mark on that slot even when a wake is already
waiting. The waiting wake is handed out once. The next poll or wait
returns `Closed` or `UnknownOwner`. A seal that only wrote the mark
into an empty slot would, after that wake was taken, leave the slot
empty and the engine thread already gone, and the next wait would
block. The handle also checks its own deregistered flag when the slot
is empty, so a home that has deregistered does not observe `Ok(None)`.

After every command the thread delivers whatever is due, not once per
sleep. A burst of commands must not hold a due wake until the mailbox
has drained. Delivering only on the way into the sleep would put that
wake behind the burst.

A home that panics while holding the slot lock poisons it. The engine
thread's next deliver then panics on that lock and aborts the process.
Release builds already abort on any panic, so this is the same outcome,
not a second failure mode.

**The engine thread sleeps by blocking on the mailbox.** The timeout is
`next_deadline() - now` when a deadline is armed, and the thread blocks
with no timeout when none is. There is no async runtime on that thread.
Its budget is one thread, counted in D5, and it needs no reactor. It is
not the transport runtime.

**The handle applies the earlier-only rule before anything is queued.**
Admission bounds how many owners exist. It does not bound how often one
owner sends. The engine's earlier-only rule runs when it applies an
`arm`, so an `arm` that is queued and then discarded has already taken
a slot in the mailbox. An idle deadline that only moves later would
send one command per event. The handle knows the deadline it has armed.
An `arm` that is not strictly earlier is not sent. The handle's memory
of that deadline resets when the home takes the wake — that is how it
learns the deadline fired — and on `clear` and `deregister`. The reset
is on receipt, not when the engine fires: until the home takes the
wake it still believes the old deadline is armed. Without the reset,
the next legitimate arm, including a later one, is suppressed. An
`arm` enters the mailbox only when that owner's deadline moves
earlier, and `clear`, `deregister`, and `note_home` enter when the
home sends them. That is the traffic. It is not a fixed capacity: a
deadline can keep moving earlier for as long as the connection lives.
A mailbox that refused an earlier `arm` would drop a gap deadline
without the owner knowing, so the queue is not given a length that
rejects. The thread's drain, below, is what keeps the queue from
accumulating.

Commands from one owner are applied in the order that owner sent them.
Each owner lives in exactly one home, and that home sends its own
commands one at a time. The mailbox is one FIFO, which is what keeps
that sender's order. A queue that reordered one home's commands would
not meet this.

On the Pi 4, at 2^18 owners, an earlier arm is 177 ns and one due poll
is 377 ns
([the capture](../benchmarks/timing_engine_wake_hints_pi4_20260926T003745Z.txt)).
That is this thread's drain rate, a few million commands a second. It
is not D5's budget.

**Homes report back through the same mailbox.** `note_home` is a
command on that mailbox, not a side channel. The home stamps
`polled_at` itself, at the moment it observes the wake.

**Every home uses the engine's clock, cloned from the same origin.**
`MonotonicClock::new` stores `Instant::now()` as its origin, and `now`
is nanoseconds since that instant. The clock is `Clone`, and a clone
keeps the origin. The service constructs one clock and clones it to
each home. A home that called `MonotonicClock::new` itself would report
lateness from a different zero.

**After close.** Each handle holds a closed flag. `register`, `arm`,
`clear`, and `deregister` check it and return `EngineError::Closed`
without sending. Commands already in the mailbox are dropped, not
applied. A wake already in the slot is still handed out once, and the
next wait returns `Closed`. `close` is shutdown step 1.

**If the engine thread panics, the process aborts.** A dead engine
leaves every gap timer and handshake deadline unarmed, so a flood holds
its slots until something else notices. There is no safe degraded mode.
The abort is that thread's failure. It is not a crate-wide panic
strategy.
