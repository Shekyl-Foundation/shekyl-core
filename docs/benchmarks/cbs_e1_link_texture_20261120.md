# `CBS-E1` link texture: what does a node's link look like to a watcher, and does a transaction stand out on it? Registration, 2026-11-20

**State of this record: REGISTERED 2026-11-20, not started. Nothing has
been collected. The run starts on Rick's go, after `v3.1.0-alpha.12`
ships.** Everything under "Registered before the run" is fixed from the
moment this record is pushed. A change after that is a dated amendment
that says what had been read by then. Results are added below.

The ruling this serves is `CBS-E1` of the cover-by-shape round
(`docs/design/COVER_BY_SHAPE.md`, #1480; Rick, 2026-11-20): the texture of
a link is read the way a watcher reads it, as bytes on each connection
over time, captured on the host, with no daemon change. The reading
before it is
[`trc1_guard_connection_20261112.md`](trc1_guard_connection_20261112.md),
whose instrument and rules this one follows where it can.

## The question

Cover by shape proposes that a transaction leave as pieces of ordinary
size at an ordinary pace. "Ordinary" is not a known number. This reading
answers two questions, per connector:

1. What does a link carry: how many bytes per window, in what bursts, with
   what gaps between them?
2. Before any change, how well does a watcher of those bytes separate the
   windows that hold one of the node's own sends from the others? This is
   the "before" reading for the round's pass mark (`CBS-E5`).

It does not decide piece size, pace, or any of `CBS-E2`–`CBS-E7`.

## What had been read before this registration

- All of TRC-1's guard-connection record: its results are the reason for
  this reading. On one relay-carrying node, a window holding one of the
  node's own sends was above the other windows' 99th percentile 82.6 % of
  the time at 0.1 s, 3.2 % at 1 s and 6.2 % at 10 s, with a ranking figure
  (AUC) of 0.93, 0.93 and 0.82.
- No capture of the kind registered here has been taken on any node. The
  capture has not run on a fleet host at all. The reducer has run only on
  fixtures built by its own test.
- Nothing is known yet of the sizes of this network's messages by type or
  of a link's texture; `COVER_BY_SHAPE.md` §3 lists what was read.

## Registered before the run

**Subject.** Three `v3.1.0-alpha.12` release nodes of the test fleet, none
running a Tor relay: one clearnet only, under the record layer; one Tor
only; one both. Rick names the hosts; their identities stay in
`shekyl-dev`. The build is the release build: no measurement feature.

**Instrument.** `shekyl-dev` `infrastructure/texture/capture.py`.

- **What it captures.** `tcpdump`'s one-line summaries of every TCP packet
  on the host except remote administration: the packet's time, its two
  endpoints and its TCP payload length. No packet content is read or
  stored.
- **Which connections are the daemon's.** Once a second it lists the
  host's established TCP sockets and classifies them by port:
  - `clearnet`: not loopback, with the daemon's P2P port at either end;
  - `tor_out`: a loopback socket to the local Tor client's SOCKS port;
  - `tor_in`: a loopback socket from the onion service's target port.
  - An outbound session to a peer that listens on another port is not
    seen. The hourly note (below) is the check.
- **Tor, after Tor.** On the Tor nodes, TRC-1's guard sampler
  (`infrastructure/trc1/guard_sample.py`) runs for the same hours.
- **Hourly notes.** Host load, `tcpdump`'s received and dropped packet
  counts, the count of classified sockets by kind, and the daemon's own
  peer count (`peer_inbound_count` and `peer_outbound_count` of its status
  reply).
- **Preflight.** Before the run, on each host, the capture sends a known
  number of bytes over a loopback connection of its own and checks that
  the captured lines add up to that number, once. A host that fails does
  not run.
- **No contact with the daemon.** Nothing connects to it beyond the
  hourly status read, signals it or changes its configuration.

**The run.** 72 hours from Rick's go. Capture starts with the run, and the
record notes when the fleet reports synced.

**The sends.** TRC-1's wallet send loop
(`infrastructure/trc1/send_loop.py`) on one node, logging each send's
times, with some hours at a higher rate. The record states which node and
which hours. Each accepted send's serialized size is read from the daemon
afterwards, as TRC-1 did.

**The reduction.** `shekyl-dev` `scripts/texture/reduce.py`, run on each
host. Its definitions:

- **Bytes.** TCP payload bytes. A host capture sees frames before the
  network card splits them, so a captured packet's size is not a size on
  the wire. **Every figure is bytes over time; no packet size is
  reported.** On clearnet these are the record layer's bytes, and on Tor
  they are the bytes handed to the local Tor client.
- **Sent.** From the daemon's end of a connection to the peer's.
- **Connector.** `clearnet`, or `tor` for `tor_out` and `tor_in` together.
- **Slot.** 0.1 s, aligned to the capture's first packet. Times are whole
  microseconds from the capture's stamps.
- **Window.** 0.1 s, 1 s and 10 s. A link's windows are those inside its
  open-to-close span. The connector's sum is over the whole run.
- **Attribution.** A packet belongs to a link when its two endpoints are
  the link's and its time is within 2 s of the link's logged span.
- **Coverage.** Payload bytes on the daemon's ports that match no logged
  link are counted and reported. **Validity line:** a node whose
  unattributed share is above 1 % is reported as such, and its tables are
  not pooled with the others.
- **Burst.** On one link, sent direction: a maximal run of payload
  packets in which each follows the one before by less than the gap
  threshold. Its size is the sum of their payload bytes. The gap between
  bursts is the next burst's first packet time minus this burst's last.
  Reported at thresholds of **0.1 s and 1 s**.
- **Segments.** Named from what was happening, fixed before reading:
  - `resync`: from the start until the fleet reports synced;
  - `ordinary`: the rest, outside the higher-rate hours;
  - `high_rate`: the hours the send loop ran faster.
  A window belongs to the segment its first slot is in.
- **Median split (secondary).** A clock hour is busy when its sent bytes
  on that connector are at or above the median hour's, else quiet. The
  first and last hours of the run are partial and are in neither.
- **Matching a send (TRC-1's rule, its Amendment 1 item 3).** For each
  accepted send, on one series of sent bytes: the first run of consecutive
  non-empty slots that starts within 10 s of the send's submit and whose
  total reaches the transaction's serialized size. Matched on each link's
  own series, and on the connector's summed series.
- **Send groups (TRC-1's).** Matched; not seen (accepted, no run reached
  its size); rejected by the daemon; failed before submit.
- **The watcher's test.** Send windows against other windows, scored by
  bytes sent in the window: the share of send windows above the other
  windows' 99th percentile, and the Mann-Whitney AUC with ties counted
  half. A send window is the window holding a matched send's first slot.
  The 10 s after every submit that reached the daemon are left out of the
  other windows, except the send window itself.

**What is reported.** Per node, connector and segment:

1. Coverage, the socket counts against the daemon's peer counts, dropped
   packets and load.
2. Bytes sent per window at 0.1 s, 1 s and 10 s: the share of empty
   windows, the median, 90th and 99th percentiles and the maximum, for
   each link and for the connector's sum.
3. Burst sizes and gaps at both thresholds.
4. The send groups.
5. The watcher's test at 0.1 s, 1 s and 10 s, in the layout of TRC-1's
   table, pooled over links and on the connector's sum. On the Tor nodes,
   TRC-1's own test on the guard connections for the same hours, beside
   it.

**What this cannot say.**

- A test network is thinner than a live one: the texture read here is a
  lower bound on how busy a link is.
- On Tor, the loopback sockets are before Tor. What a watcher of the
  node's line sees is the guard connections, which the guard sampler
  reads.
- The capture stamps a packet when the host's stack handles it, not when
  it leaves the host.
- Sends are matched by size. A send whose bytes are interleaved with a
  larger burst still matches; one sent as several runs with empty slots
  between them is "not seen". The groups table shows how often.

**Data.** The raw capture and the socket log hold peer addresses. They
stay on the capture host, are never copied off and never committed, and
are deleted once Rick accepts this record. The reduced tables name a
connection by a local index only, and are added beside this record.

## Results

None yet.
