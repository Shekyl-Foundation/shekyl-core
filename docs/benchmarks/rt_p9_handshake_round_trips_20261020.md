# `RT-P9`: the channel's handshake on a real network leg to the floor device. Registration of 2026-10-20

**State of this record: registered; not yet run.** Results are added under
"Results"; "Registered before the run" is not edited afterwards. An
amendment made before any registered result is read is dated and says
what changed.

## The question

The maintainer ruled on 2026-10-20 that the handshake's deadlines come
from a measurement, not an assumption. RT-P6's results first proposed a
deadline built from the ledger's *unmeasured* anonymity-zone transit
assumption, and that figure is struck. The ruling is to register and run
round trips on an onion RPC leg to the floor device now, and to derive
from them the **message-1 deadline** and the **whole-handshake deadline**,
with a clearnet LAN figure beside them.

This probe measures the deadlines' own subject: the real `hybridXK`
handshake, mac1 and the ruled budget included, over a TCP connection to a
daemon on the floor device, timed on the daemon's clock from the instant
its `accept` returns.

## Registered before the run

**Subject.** `shekyl-rpc-channel` at the commit carrying this
registration (mac1 and the handshake budget in place, PR #1137). The
harness is `rust/shekyl-rpc-channel/examples/rt_p9_handshake_round_trips.rs`,
built in release with the pinned toolchain (1.94.0): on the floor device
from a fresh clone of that commit, and on the development workstation
from the same commit.

**What runs.** One TCP connection per sample. On it, the real handshake,
with no framing, since every message has a fixed length:
- the client sends message 1 (2,336 bytes);
- the daemon replies with message 2 (2,320);
- the client sends message 3 (1,264 + a 64-byte payload);
- the daemon replies with message 4 (1,120 + a 64-byte payload);
- the client sends its first record (a 64-byte payload, sealed);
- the daemon opens it and replies with one sealed record.

The daemon role (`serve`) runs on the floor device, unpinned, as a daemon
would, under the ruled budget, one connection at a time, until it is
stopped. The client role runs on the development workstation. The client
numbers its samples and carries the number in the first 8 bytes of its
first record, so the daemon's row for a completed sample names the
client's row it pairs with. A connection that fails before the first
record is the daemon's alone: counted, not paired.

**The two legs:**
- **onion:** the client reaches the daemon through a Tor client on the
  workstation (its own `tor` process, Tor 0.4.9.13 from the Tor Expert
  Bundle, with a SOCKS port only). The daemon is behind a temporary onion
  service published by a separate `tor` process on the floor device (the
  bundle the device's daemon ships, Tor 0.4.9.13, its own data directory,
  no SOCKS port). Each connection uses a fresh SOCKS username, so Tor
  isolates it on a circuit of its own: every sample meets what a client's
  first connection meets. The daemon's own managed Tor and its testnet
  daemon are not touched.
- **lan:** the client connects directly to the floor device's address on
  the Foundation LAN.

**Counts:** 300 connections on each leg, one at a time. The onion leg runs
first; the LAN leg follows on the same build.

**What is stamped.**
- **The daemon**, in nanoseconds from `accept`: message 1 received,
  message 2 sent, message 3 received, message 4 sent, the first record
  opened, the reply sent.
- **The client**, in nanoseconds from the start of its connect: connected
  (the SOCKS reply, for the onion leg), message 1 sent, message 2
  received, message 3 sent, message 4 received, the first record sent,
  the reply received.
- A sample that fails is recorded as failed, with the stamps it reached.
  Each read waits at most 120 s.

**Statistics:** nearest-rank median, 90th and 99th percentiles and
maximum of each stamp, over the completed samples, by
`scripts/bench/rt_p9_summary.py`. It refuses a capture of any other shape,
checks the gates below, and, when they are met, derives the deadlines by
the rule below. It reports a void run as VOID and derives nothing.

**Gates.** A run is void if fewer than 95 % of either leg's connections
complete the handshake, or if, on any completed sample, one side's round
trip is shorter than the other side's time between the same two messages:
the client's from message 1 sent to message 2 received against the
daemon's from message 1 received to message 2 sent, and the daemon's from
message 2 sent to message 3 received against the client's from message 2
received to message 3 sent, by more than 1 ms. Each side reads only its
own clock, so this is the check that the two sides' stamps describe the
same exchange. The millisecond is slack for the stamps themselves: a
"sent" stamp is taken when the write returns, which can follow the bytes'
departure, and on loopback, before this registration, one side's round
trip read as up to 0.6 µs shorter than the other's turn.

**Conditions recorded at the start and the end:** the floor device's load,
temperature, governor and under-voltage alarm, and whether its testnet
daemon is active; the time of day (Tor latency varies).

**The derivation — fixed now, for the maintainer to confirm.** Both
deadlines run on the daemon's clock from `accept`, and both come from the
onion leg, since one deadline must serve an onion client.
- **The message-1 deadline** is twice the onion leg's 99th percentile of
  the time from `accept` to message 1 received, rounded up to the next
  whole second.
- **The whole-handshake deadline** is twice the onion leg's 99th
  percentile of the time from `accept` to the first record opened,
  rounded up to the next whole second.

The factor of two covers the tail beyond a 300-sample 99th percentile,
slower links than the Foundation's, and load on the daemon. The LAN leg's
same two figures are reported beside them. Each deadline lands in code with
a measurement-ledger row, measured by `BA-T37`, on this capture.

**Captures:** `docs/benchmarks/rt_p9_handshake_round_trips_20261020_captures/`:
both sides' TSVs for each leg, the summary, the conditions and
`SHA256SUMS`. The onion address is not recorded: it is a throwaway key and
names nothing worth keeping. The LAN address is the role "the floor
device", not the number.

**What this does not measure.**
- A client on another network, or a Tor path from outside the Foundation's
  uplink.
- A daemon under load from other clients.
- The connection's setup before `accept`: the onion rendezvous happens
  before the daemon's clock starts, and the client's connect time is
  reported but bounds no deadline.

**Dry run, then the registered run.** The dry run is ten connections on
each leg, after the onion service's descriptor is published, through the
same commands and the same summary (`--samples 10`), recorded here. The
registered run follows under the claim, with fresh output directories and
a fresh daemon identity. At most two registered attempts; a void attempt
is recorded with its cause, the cause is fixed, and the second is made
under the same lines.

## Dry run

**2026-10-20, 05:32:19Z to 05:34:03Z, at `dfc2ae3956`** (this
registration with #1137's results and the budget constant they moved,
merged in). Ten connections a leg, through the same scripts and the
summary (`--samples 10`). Both gates were met, and every connection on
both legs completed. Its figures are not data. What it showed of the
instrument:
- **The onion leg works end to end:** the client's Tor reaches the
  device's temporary onion service, and each connection, under its own
  SOCKS username, takes its own circuit. A sample takes about 9 s, mostly
  the client's connect (3.2 s at the median, and 37 s for one connection
  that waited on circuits). So 300 samples take about 45 minutes.
- **The daemon's clock** reads `accept` → message 1 in hundreds of
  milliseconds on the onion leg (median 708 ms) and 0.4 ms on the LAN.
  That is the round trip the onion service's `CONNECTED` cell and the
  client's first write make, as expected.
- **The two sides' stamps agree** on every sample, within the slack.

**How the source reached the device.** GitHub was slow or unreachable
from the device and the workstation that morning (it served the device
at about 33 KB/s at 04:50Z, and a push from the workstation timed out at
05:15Z). The device's source is therefore a depth-1 clone of
`dfc2ae3956`, made on the workstation and copied over the LAN, and the
script checks the commit by its hash before building. The submodules come
from the device's own checkout: their pinned commits are unchanged, and
the harness links none of them. The client is built on the workstation
from the same commit.

## Results

None yet.
