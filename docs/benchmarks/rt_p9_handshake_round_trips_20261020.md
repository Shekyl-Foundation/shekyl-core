# `RT-P9`: the channel's handshake on a real network leg to the floor device. Registration of 2026-10-20

**State of this record: run 2026-10-20; attempt 1 void, attempt 2 met its gates; results below.** Results are added under
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

### The deadlines: message 1 in 4 s, the whole handshake in 11 s

**Attempt 2 met both gates**, and by the registered rule:

| Deadline, from `accept` | Onion p99 | Deadline | LAN p99, beside it |
|---|---:|---:|---:|
| Message 1 received | 1,803.4 ms | **4 s** | 0.7 ms |
| First record opened (the whole handshake) | 5,231.9 ms | **11 s** | 8.6 ms |

They land in code as `MESSAGE1_DEADLINE` and `HANDSHAKE_DEADLINE`
(`rust/shekyl-rpc-channel/src/deadline.rs`), each with a
measurement-ledger row measured by `BA-T37` on this capture. RT-W10's
listener enforces them.

**What the rule leaves out, counted:**
- Message 1: one of attempt 2's 300 onion connections took longer than
  4 s (4,488.8 ms), so a daemon with this deadline would have closed it.
  So did one of void attempt 1's 300 (17,557.9 ms).
- The whole handshake: none of attempt 2's took longer than 11 s (the
  slowest took 7,791.1 ms). One of attempt 1's did (20,441.8 ms).
- So about one onion connection in 300 meets a closed connection under
  these deadlines. §4.5's failure table names the case ("The node did not
  complete the handshake in time."). It does not say whether the client
  retries it; that is for RT-W10 to settle.

### Attempt 2, 06:07:07Z to 06:31:29Z: met

At `666bbded3c`, with the client waiting 100 ms between connections.
Fresh output directories and a fresh daemon identity for each leg. The
onion service and the client's Tor were the same processes as attempt
1's. Captures, with checksums:
[`rt_p9_handshake_round_trips_20261020_captures/attempt2/`](rt_p9_handshake_round_trips_20261020_captures/attempt2/).
`rt_p9_summary.py` reproduces the summary below from them.

**Conditions.**
- The device: the floor device (Raspberry Pi 4, Cortex-A72), its
  `ondemand` governor, the daemon role unpinned.
- The client: the development workstation, its Tor client from the Tor
  Expert Bundle 15.0.24 (Tor 0.4.9.13), on the Foundation's uplink.
- The run began 25 s after the device's build ended, so the 1-minute load
  read 2.76 at the start, and 0.11 at the end. Temperature went from
  51.6 °C to 46.7 °C, and the under-voltage alarm stayed clear.
- The testnet daemon was active throughout and used 8.85 s of CPU over the
  24 minutes.
- **The LAN leg's daemon turns are about twice attempt 1's:**
  `accept` → message 2 sent, 5.2 ms at the median, against 2.4 ms. The
  likely reason, not checked by this run (which did not record clock
  speed per connection): the connections are now 100 ms apart, so under
  `ondemand` the cores probably clock down between them, while attempt 1's
  back-to-back loop held them up. The onion leg, at seconds per
  connection, would be in the first state in both attempts. The LAN
  figure is reported, not used.

#### Completion

| Leg | Connections | Completed | Share | Accepted by the daemon, not completed |
|---|---:|---:|---:|---:|
| onion | 300 | 300 | 100.0% | 0 |
| lan | 300 | 300 | 100.0% | 0 |

#### The daemon, from `accept` (ms)

| Leg | Stamp | n | median | p90 | p99 | max |
|---|---|---:|---:|---:|---:|---:|
| onion | message1_received | 300 | 550.8 | 1,027.9 | 1,803.4 | 4,488.8 |
| onion | message2_sent | 300 | 555.4 | 1,032.0 | 1,808.4 | 4,493.1 |
| onion | message3_received | 300 | 1,129.3 | 1,957.2 | 3,122.4 | 6,281.4 |
| onion | message4_sent | 300 | 1,131.3 | 1,959.4 | 3,124.5 | 6,283.5 |
| onion | first_record_opened | 300 | 1,704.5 | 2,802.4 | 5,231.9 | 7,791.1 |
| onion | reply_sent | 300 | 1,704.7 | 2,802.5 | 5,232.0 | 7,791.2 |
| lan | message1_received | 300 | 0.4 | 0.5 | 0.7 | 1.0 |
| lan | message2_sent | 300 | 5.2 | 5.3 | 5.5 | 5.6 |
| lan | message3_received | 300 | 5.9 | 6.1 | 6.3 | 6.7 |
| lan | message4_sent | 300 | 6.9 | 7.8 | 8.0 | 8.1 |
| lan | first_record_opened | 300 | 7.4 | 8.3 | 8.6 | 8.6 |
| lan | reply_sent | 300 | 7.4 | 8.3 | 8.6 | 8.6 |

#### The client, from the start of its connect (ms)

| Leg | Stamp | n | median | p90 | p99 | max |
|---|---|---:|---:|---:|---:|---:|
| onion | connected | 300 | 2,040.7 | 3,552.6 | 16,852.9 | 45,107.3 |
| onion | message1_sent | 300 | 2,040.9 | 3,552.8 | 16,853.1 | 45,107.5 |
| onion | message2_received | 300 | 2,631.6 | 4,395.3 | 17,180.2 | 46,708.8 |
| onion | message3_sent | 300 | 2,631.8 | 4,395.5 | 17,180.4 | 46,709.0 |
| onion | message4_received | 300 | 3,234.3 | 5,426.8 | 17,513.6 | 47,857.8 |
| onion | first_record_sent | 300 | 3,234.4 | 5,427.0 | 17,513.7 | 47,857.9 |
| onion | reply_received | 300 | 3,782.1 | 6,361.7 | 17,848.8 | 49,466.8 |
| lan | connected | 300 | 0.4 | 0.5 | 0.5 | 0.6 |
| lan | message1_sent | 300 | 0.6 | 0.7 | 0.9 | 1.2 |
| lan | message2_received | 300 | 6.0 | 6.2 | 6.4 | 6.6 |
| lan | message3_sent | 300 | 6.2 | 6.4 | 6.6 | 7.0 |
| lan | message4_received | 300 | 7.7 | 8.6 | 8.9 | 8.9 |
| lan | first_record_sent | 300 | 7.8 | 8.7 | 9.0 | 9.0 |
| lan | reply_received | 300 | 8.1 | 9.0 | 9.3 | 9.4 |

#### Gates

Met: every leg completed at least 95%, and on every completed sample the two sides' stamps describe one exchange.

#### The deadlines

Each is 2 × the onion leg's 99th percentile from `accept`, rounded up to a whole second. The LAN figure beside it is the same rule applied to the LAN leg, reported, not used.

| Deadline | Onion p99 (ms) | Deadline (s) | LAN p99 (ms) | LAN by the same rule (s) |
|---|---:|---:|---:|---:|
| message 1 | 1,803.4 | 4 | 0.7 | 1 |
| whole handshake | 5,231.9 | 11 | 8.6 | 1 |

### Attempt 1, 05:34:12Z to 06:00:52Z: void

At `dfc2ae3956`. **The onion leg completed 300 of 300. The LAN leg
completed 272 of 300, below the 95 % gate, so the attempt is void** and
nothing is derived from it. Its data is kept, with checksums, in
[`rt_p9_handshake_round_trips_20261020_captures/attempt1_void/`](rt_p9_handshake_round_trips_20261020_captures/attempt1_void/).

**The cause is the harness, and the budget did what it is built to.**
- The client made its 300 LAN connections back to back, and they took
  1.3 s in all: about 230 handshakes a second from one client.
- The daemon role runs under the ruled handshake budget: 115 a second,
  with a one-second burst.
- From the 257th connection (sample 256) on, about every other one was
  refused right after message 1 was received: no message 2 was sent, and
  the client saw the connection close. That is the budget's silent drop,
  once the burst was spent.
- The harness's own comment said one handshake at a time never exhausts
  the budget. On the LAN that is false: one handshake costs the daemon
  about 2.2 ms of CPU, so a single client looping without pause asks for
  more than a quarter of a core.

**The fix, at the commit after this record:** the client waits 100 ms
between connections (`BETWEEN_SAMPLES`), which keeps one client at 10
handshakes a second. Checked on loopback under the ruled budget: 300 of
300 completed on both sides, where attempt 1's LAN leg dropped 28.
Nothing else changes; attempt 2 is made under the same lines, both legs,
with a fresh daemon identity.

**What the drop says about the design, for the record (not a gate):**
- A client that reconnects in a tight loop on a fast link reaches the
  budget alone.
- The drop is silent, so that client is told what §4.5's failure table
  tells a client whose copy of the daemon's key is wrong: the node closed the connection
  without answering. A budget drop and a bad bundle look the same from
  the client side.
