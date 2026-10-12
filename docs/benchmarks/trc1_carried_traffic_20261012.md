# `TRC-1` step 2: what does an ordinary operator relay carry? Registration, 2026-10-12

**State of this record: REGISTERED 2026-10-12, Part A only. Nothing has
been collected under it yet.** The four questions the draft posed were
ruled on 2026-10-12 and are recorded under "Ruled before registration".
"Registered before the run" is not edited from here on; an amendment is
dated and says what had been read. Results are added below it.

Step 1 is [`trc1_relay_posture_20261006.md`](trc1_relay_posture_20261006.md):
the operator topology is running. This record is step 2 of the falsifier
chain in [`TOR_COVER_POSTURE.md`](../design/TOR_COVER_POSTURE.md) §8.

## The question

`TOR_COVER_POSTURE.md` §1 rules that on Tor a node's originated cells are
hidden among the cells a non-exit relay carries, when the node's Tor client
is that relay process. §8 says the measurement behind that has not been
taken: how much such a process carries, across hours and consensus weights,
at the size an ordinary operator runs.

This record measures two things on one process, over the same intervals:

- **Carried volume.** Bytes the relay process moves on its OR connections.
- **Originated volume.** Bytes the daemon moves through that process: its
  outbound dials through the process's SOCKS port and the inbound sessions
  the process's onion service delivers to it.

## What this record does not decide

It does not decide whether originated cells are distinguishable.
`DAEMON_RELAY_PRIVACY.md` §96 item 4 names that test: the `PM-3` watermark
reproduction, with its precision and recall. This record produces the
volume series that test runs against, and the conditions it was taken
under. No threshold on the ratio of the two volumes is registered here, and
none is to be read into the results.

## Data in hand, read before this registration

The relay has run since 2026-10-06 03:23Z without a restart. Two sources
were accumulating before any protocol existed, and both were read on
2026-10-11 and 2026-10-12 before this was written. They are stated here so
that the registration is not taken for a blind one.

Tor's own heartbeat, cumulative since the process started:

| Heartbeat (UTC) | Circuits open | Sent | Received |
| --- | --- | --- | --- |
| 2026-10-09 15:23 | 34 | 808.96 MB | 868.45 MB |
| 2026-10-10 21:23 | 27 | 1.01 GB | 1.09 GB |
| 2026-10-11 03:23 | 1,145 | 7.13 GB | 7.42 GB |
| 2026-10-11 09:23 | 8,194 | 25.56 GB | 27.13 GB |
| 2026-10-11 15:23 | 6,772 | 43.04 GB | 45.85 GB |
| 2026-10-11 21:23 | 6,752 | 59.01 GB | 62.92 GB |

The directory's daily write history for the same relay reads 2,241 to
3,759 B/s for 2026-10-06 through 2026-10-09 and 18,500 B/s for the day
centred on 2026-10-10 12:00Z. Its consensus weight was 1 in every one of
the 35 directory samples from 2026-10-06 02:00Z to 2026-10-11 18:00Z. The
directory of 2026-10-11 20:00Z lists the flags Fast, HSDir, Running,
Stable, V2Dir and Valid, a guard probability of 0, and an observed
bandwidth of 1,138,437 B/s.

**Two readings of that, neither a result.**

- For its first four and a half days the process moved about 2 to 4 kB/s.
  One cell is 514 bytes. `TOR_COVER_POSTURE.md` §1 describes a relay
  carrying thousands of cells a second; this one carried fewer than ten.
- From some time between 2026-10-10 21:23Z and 2026-10-11 03:23Z it has
  moved about 0.8 MB/s, against a configured average of 1 MB/s, at a
  consensus weight of 1. In the same hours Tor's denial-of-service counters
  began to move: at 2026-10-11 21:23Z, 400 circuits killed for too many
  cells and 7,718 concurrent connections from one address refused, both 0
  at 2026-10-10 21:23Z. A snapshot at 2026-10-12 02:32Z counted 7,072 TCP
  sockets held by the process, 6,734 of them inbound to its OR port. A
  relay that path selection gives a middle probability of 1.5e-8 does not
  receive that from path selection. The cause is not established. The
  onset is about 18 hours after the process reached 96 hours of uptime.

**This volume is recorded as a condition, not as ordinary operator load.**
How it is treated is ruling 3 below.

## Ruled before registration

Rick, 2026-10-12, on the four questions the draft posed: "as proposed".

1. **Per-connection volume and the control port.** Part A (totals, kernel
   only) is registered and runs alone. Part B (the share on the
   connections that carry the process's own circuits) is **not
   registered**. It needs a reading of Tor's control port, and that
   reading is not ruled. The reason it is wanted stands as the draft gave
   it: a wire observer sees each TCP connection separately, Tor sends a
   client's circuits through a small set of entry guards, and so the
   process's total volume is an upper bound on the cover one originated
   burst has. *That is reasoning from Tor's design. It has not been
   measured here, and it may be wrong about how a relay that is also a
   client picks its first hop.* Part A does not answer it.
2. **Horizon.** Collection runs to 2026-11-10, five weeks after the
   relay's first start. Results are reported per consensus weight as the
   directory published it. If the weight is 1 throughout, the record says
   the run covers a weight of 1 and nothing above it, and step 2 is not
   met on the weights axis.
3. **The volume that began on 2026-10-11** is never pooled with what came
   before it. Every interval carries the directory weight and the
   denial-of-service counters, and results are given separately for
   intervals before the onset, after it, and after it ends if it ends.
   Which of them describes an ordinary operator is ruled when they are
   read.
4. **Interval.** One snapshot every 60 seconds. That gives a rate per
   minute. A stem is seventeen cells and leaves in well under a second, so
   this record cannot show whether one burst had company.

## Registered before the run

**Subject.** One Tor process, Tor Project `tor` 0.4.9.13, running as a
non-exit relay at `RelayBandwidthRate` 1 MB/s and `RelayBandwidthBurst`
2 MB/s on a test seed with two cores and 4 GB of memory, and the `shekyld`
whose `--tx-proxy` and `--anonymous-inbound` are that process, with
`--no-ephemeral-tor`. That rate is what this record means by ordinary
operator scale. The relay's identity and the host are in `shekyl-dev`,
`infrastructure/trc1/`.

**Instruments.** Nothing registered here opens a connection to the Tor
process, signals it, or changes its configuration.

| Instrument | What it gives | Granularity |
| --- | --- | --- |
| Kernel socket counters (`ss -tinp`), by owning process | bytes acknowledged and bytes received on every TCP socket of the relay and of the daemon | one snapshot per interval |
| The uplink interface's byte counters | every byte the host sent and received | same snapshot |
| Tor's heartbeat in the journal | cumulative bytes, open circuits, connection counts, denial-of-service counters, onion-service introductions | 6 hours |
| The Tor directory (Onionoo `details`, `weights`, `bandwidth`) | consensus weight, flags, selection probabilities, the relay's own reported history | hourly; daily for history |

**Part A: totals.** Every 60 seconds one snapshot is taken and reduced, in
memory, to one row:

- `carried_out`, `carried_in`: the sum over the relay's sockets that are
  not loopback of the change in bytes acknowledged and in bytes received
  since the previous snapshot, counting only sockets present in both.
  Originated cells leave on these sockets too, so they are inside this
  figure and are not subtracted from it.
- `relay_sockets_in`, `relay_sockets_out`: how many such sockets are
  inbound to the OR port and how many the relay opened.
- `sockets_gone`, `sockets_new`: how many of the previous snapshot's
  sockets are absent, and how many are new.
- `originated_out`, `originated_in`: the same sums over the daemon's
  loopback sockets to the process's SOCKS port and from its onion-service
  target port. The daemon's clearnet sockets are not counted.
- `originated_sockets`: how many such sockets there are.
  `originated_*` is what the daemon handed to Tor and took from it, before
  Tor's cell framing and circuit overhead. `carried_*` is bytes on the
  wire. The two are not in the same unit, the framing between them is not
  reconstructed here, and one divided by the other is not a share.
- `uplink_tx`, `uplink_rx`: the change in the interface counters.
- the snapshot's time, and how long taking it took.

**The collector keeps no address.** A socket is matched between two
snapshots by its address pair, in memory, for that purpose only. No
address, port of a remote peer, or per-socket figure is written to disk or
leaves the host. The raw snapshot is never written. This is a property of
the protocol and not a convenience: the snapshot is the address of every
relay and client connected to this relay.

**What the totals miss, and the check on it.** A socket that closes
between two snapshots takes its last bytes with it, so `carried_*` is a
lower bound. `uplink_*` is an upper bound: it holds everything else the
host sends. Over each 6-hour heartbeat window three figures are compared:
the heartbeat's own difference, the sum of `carried_*`, and the sum of
`uplink_*`.

**Lines, read in this order.** They are about the method. None is a
verdict on cover.

1. **The relay process changed** (a different process id, or a heartbeat
   whose uptime restarted): the series ends there. What follows is a new
   series, reported separately, and the record says the process's flags
   and counters began again.
2. **A snapshot took longer than 5 seconds, or more than 5 % of the
   snapshots in a window are missing:** that window is **void** for rates
   and is reported as void.
3. **Over a heartbeat window the sum of `carried_*` is below 80 % of the
   heartbeat's difference:** that window's per-minute series is reported
   as **undercounted**, the heartbeat's figure stands for the window, and
   no per-minute rate from it is quoted.
4. **Over a heartbeat window the sum of `originated_*` is 0:** the window
   is reported as **no originated traffic**. It says the daemon sent
   nothing through Tor then. It says nothing about cover.

**What is reported.** Per hour of the day in UTC, and per consensus weight
as the directory published it for that hour: the median and the 5th and
95th percentiles of `carried_out + carried_in` in bytes per second, and of
`originated_out + originated_in`, over the windows that are not void.
Beside them, per day: the heartbeat's denial-of-service counters, open
circuits, and the directory's flags. The originated figures on a testnet
with a handful of transactions a day are expected to be near zero for long
stretches. That is a condition of this run. A small originated share here
is not evidence that originated traffic is hidden, and the record does not
say it is.

**Conditions that change during the run, registered now.**

- **The daemon is replaced once.** At the `v3.1.0-alpha.10` fleet install
  the daemon is stopped, installed from the release package, started on a
  new chain, and its configuration is unchanged. The relay is not touched.
  The stop and start times, the two binaries' digests, and the relay's
  process id before and after are recorded. Originated figures are reported
  separately for the `v3.1.0-alpha.9` daemon and the `v3.1.0-alpha.10`
  daemon and are never pooled: the chain, the network id and the peers all
  differ.
- **Two earlier daemon restarts** fall before this registration, on
  2026-10-06 01:45Z and 2026-10-08 16:34Z. The data in hand spans both.
- **The volume that began on 2026-10-11** is treated as ruling 3 says.

**Horizon.** Collection runs from the registered start to 2026-11-10
00:00Z. It ends earlier only on line 1, and is not extended after any
result is read without an amendment that says what was read.

**Dry run.** Before the registered start the collector runs for one hour
into a scratch file that is then deleted, with its rows checked for shape
only: every column present, the snapshot time under the limit, no address
in the output. No figure from the dry run is read into this record.

**Part B is not registered.** See ruling 1. If it is registered later it
is an amendment to this record, dated, saying what of Part A had been read
by then.

## Results

None. Nothing has been collected under this record.
