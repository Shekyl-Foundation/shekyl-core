# `TRC-1` step 2: what does an ordinary operator relay carry? Registration, 2026-10-12

**State of this record: REGISTERED 2026-10-12, Part A only. Collection
started 2026-10-12 05:55Z and runs to 2026-11-10. Interim results to
2026-10-16 17:07Z are below. Amendment 1 (2026-10-16) adds a memory cap on
the relay and memory columns to the collector.** The four questions the draft posed were
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

## Amendment 1, 2026-10-16: a memory cap on the relay

*Written after everything under "Interim results" had been read, and
after two earlier reads (2026-10-12 14:02Z and 2026-10-14 05:07Z: means
per 6-hour block, the heartbeats, the directory). Rick, 2026-10-16: "make
the memory change … that also gives us a contrast point to see if it makes
any difference with the memory cap".*

**Why.** The relay was killed by the kernel for lack of memory twice on
2026-10-14 (interim result 1). With `MaxMemInQueues` unset, Tor sizes it
at three quarters of physical memory: 2,933 MB on this 4 GB host, which
has no swap and also runs the daemon. Tor never reached its own limit; the
kernel's came first.

**The change to the subject.** `MaxMemInQueues 512 MBytes` in the relay's
configuration, applied by a reload signal to the running process, no
earlier than one hour after the collector change below. Tor's source marks
the option as changeable while running, so the process is not restarted:
its id is kept and registered line 1 does not end the series. The series
is split at the reload into an **uncapped** and a **capped** arm, reported
separately and never pooled. 512 MB is twice Tor's lowest unwarned value
for a relay (256 MB) and leaves the daemon and the system the rest of the
host. `MaxHSDirCacheBytes` is unset and follows at 20 % of it.

**The change to the instrument.** Collector version 2 adds three columns
to each row: `relay_rss_kb` and `daemon_rss_kb` (each process's resident
memory from `/proc`) and `mem_available_kb` (the host's). It writes them to
`obs_v2.tsv`, so each file keeps one column set. It also keeps Tor's own
notices of running low on memory and of killing circuits to recover it.
Version 1 stops when version 2 starts.

**What the contrast reports, per arm:** the relay's resident memory
(median, 95th percentile, maximum); kills by the kernel; Tor's own
low-memory notices; and carried volume as registered. **What it cannot
say:** a before-and-after on one relay cannot separate the cap from changes
in what the network sends it, and the uncapped arm's memory record is the
hour before the reload plus the two kills. The direct evidence that the cap
acted is Tor's notice that it killed circuits for memory. A kill by the
kernel in the capped arm ends the series under line 1, as before.

## Interim results, to 2026-10-16 17:07Z

**Read in full on 2026-10-16 to write this section.** The captures beside
this record hold every row. Rates are carried out plus in, and originated
out plus in, in bytes per second. The two are not in one unit and are not
divided.

| File | What |
| --- | --- |
| [`_obs.tsv`](trc1_carried_traffic_20261012_obs.tsv) | every collector row, with the two process ids replaced by series and daemon release, and the directory weight in force |
| [`_summary.tsv`](trc1_carried_traffic_20261012_summary.tsv) | per series, release and weight |
| [`_series.tsv`](trc1_carried_traffic_20261012_series.tsv) | per series, release, weight and UTC hour: the registered breakdown |
| [`_windows.tsv`](trc1_carried_traffic_20261012_windows.tsv) | registered lines 2, 3 and 4 per heartbeat window |
| [`_heartbeats.tsv`](trc1_carried_traffic_20261012_heartbeats.tsv) | Tor's heartbeat figures, the host's name removed |
| [`_directory.tsv`](trc1_carried_traffic_20261012_directory.tsv) | consensus weight and flags per published consensus |

The reduction is a script in `shekyl-dev`, `scripts/trc1/analyze_step2.py`.

### 1. The relay process changed twice: three series

On 2026-10-14 at 19:47:28Z the kernel killed the relay for lack of memory.
It held 1,538,444 kB anonymous memory; its service manager recorded a
1.9 GB peak over 8 days 16 hours. The relay was restarted ten seconds later
with the same identity keys, and was killed the same way at 20:04:42Z,
after 17 minutes and a 1.4 GB peak. It has run since 20:04:52Z. By line 1,
each process is its own series. Nothing watched the collector's log between
reads, so the kills were found on 2026-10-16; the lane now reads that log
first at every check.

| Series | Relay process | Collected |
| --- | --- | --- |
| S1 | from 2026-10-06 03:23Z | 2026-10-12 05:56Z to 2026-10-14 19:47Z, 3,712 rows |
| S2 | 17 minutes | 16 rows |
| S3 | from 2026-10-14 20:04Z | 2026-10-14 20:06Z onward; 2,702 rows to the cut |

### 2. The lines

- **Line 1:** the two process changes above.
- **Line 2:** one window is void, the first (2026-10-12 03:23Z to
  09:23Z): collection began inside it, 208 of 360 rows. No snapshot took
  more than 5 seconds.
- **Line 3:** in every complete window the collector's sum is 0.83 to
  0.995 of the heartbeat's, so none is undercounted. Two stretches have no
  heartbeat pair and are unchecked: S2, and S3's first six hours.
- **Line 4:** every window has originated traffic.

### 3. Volume by series, release and weight

| Series | Daemon | Weight | Rows | Carried p5 / median / p95 | Originated p5 / median / p95 |
| --- | --- | --- | --- | --- | --- |
| S1 | alpha.9 | 1 | 904 | 680,113 / 1,251,750 / 1,904,667 | 147 / 174 / 1,263 |
| S1 | alpha.9 | 310 | 2,100 | 359,948 / 1,060,520 / 1,744,114 | 164 / 174 / 1,422 |
| S1 | alpha.9 | 380 | 708 | 1,059,347 / 1,721,182 / 3,005,737 | 168 / 178 / 1,470 |
| S2 | alpha.9 | 380 | 16 | 2,563,281 / 3,625,718 / 6,148,640 | 0 / 20 / 66 |
| S3 | alpha.9 | 380 | 954 | 180,494 / 412,729 / 1,907,395 | 168 / 174 / 1,448 |
| S3 | alpha.9 | 370 | 1,677 | 35,987 / 899,523 / 1,588,721 | 161 / 174 / 1,448 |
| S3 | alpha.10 | 370 | 71 | 964,146 / 1,245,082 / 1,960,425 | 62 / 296 / 808 |

The daemon was replaced at 15:56:57Z to 15:57:18Z on 2026-10-16, as
registered, with the relay process unchanged. alpha.10 also replaced the
daemon's dialer, so its originated figures differ from alpha.9's for two
reasons at once. Its 71 rows are an hour.

### 4. The directory

Consensus weight was 1 until the consensus of 2026-10-12 20:00Z, then 310
(1 again for the single consensus of 2026-10-13 05:00Z), 380 from
2026-10-14 08:00Z and 370 from 2026-10-15 12:00Z. The guard probability
was 0 throughout. The HSDir flag, held when this record began, is absent from the
consensus of 2026-10-15 12:00Z on: the restart reset the uptime it needs.

### 5. What these say, and what they do not

- **Volume does not follow weight here.** At weight 1 the relay carried
  as much as at 310, and S1's volume began at weight 1 (the data in hand).
  These are observations of one relay over four days. They are not a
  property of weight.
- **The restart changed what arrives.** S1 held thousands of open
  circuits and its denial-of-service counters rose throughout: 1,477
  circuits killed for too many cells and 19,150 concurrent connections
  from one address refused by 2026-10-14 15:23Z. S3 holds hundreds of
  circuits, and its counters stood at 80 and 3,657 after 42 hours. S3's
  volume fell to a median of 413 kB/s for its first 16 hours and returned
  to about 900 kB/s. The cause is not established. The HSDir flag was lost
  in the same hours.
- **Hours of the day.** Each UTC hour has at most three days of rows per
  series. Day-to-day change is larger than any daily shape in them, so no
  daily shape is claimed.
- **The originated share** is a few hundred bytes per second against
  hundreds of thousands to millions carried. That is the registered
  condition of a quiet testnet; it is not evidence that originated cells
  are hidden.
- **Memory.** A relay at the configured rate, on a 4 GB host beside the
  daemon, with Tor's own memory default, was killed by the kernel after
  eight days and again after 17 minutes. Amendment 1 is the response.

## Results

**Amendment 1 is in effect from 2026-10-16 18:15:36Z.** Collector version
2 started at 17:12:38Z, so the uncapped arm has an hour of memory rows (62).
The relay then held 1,585,220 kB resident. The cap was applied by a reload
signal; Tor logged the reload and re-read its configuration with no error,
and the process id did not change, so S3 continues as the capped arm.

Collection started 2026-10-12 05:55Z, after this registration was pushed
(2026-10-12, `1dacebeda`).

The dry run ran from 04:55Z to 05:55Z and its output was deleted: 60 rows
at 60-second spacing, every column present and numeric, the slowest
snapshot 526 ms, no address in the output. No figure from it was read.
