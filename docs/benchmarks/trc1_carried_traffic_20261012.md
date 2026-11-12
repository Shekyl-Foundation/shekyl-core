# `TRC-1` step 2: what does an ordinary operator relay carry? Registration, 2026-10-12

**State of this record: COMPLETE 2026-11-11. Registered 2026-10-12, Part
A only. Collection ran from 2026-10-12 05:55Z to the horizon, 2026-11-10
00:00Z. Below are the interim results to 2026-10-16 17:07Z, Amendment 1
(2026-10-16: a memory cap on the relay and memory columns in the
collector), the conditions that changed during the run without an
amendment, and the final results.** The four questions the draft posed were
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

## Conditions that changed during the run, recorded at the end

*Written 2026-11-11. None of these was amended when it happened. Each is
stated with the reads taken by then. After Amendment 1 the collected data
was read three times: on 2026-10-17 (health only, no figure), on
2026-10-29 21:40Z (memory and rates per relay process and arm, the latest
directory row, the latest heartbeat), and on 2026-11-05 19:46Z (rates and
memory per half day, the minute rows of 2026-10-31 10:00Z to 13:40Z, the
kernel's kill reports, the directory since 2026-10-29, the heartbeats since
2026-10-30).*

1. **The daemon froze, 2026-10-17 21:00:40Z to 2026-10-27 17:33:50Z.** The
   alpha.10 daemon stopped answering (a deadlock in that release). Its
   process stayed alive, so the collector saw no process change. Its
   originated traffic is 0 from that minute. It was found on 2026-10-27.
   Its rows carry the release label `v3.1.0-alpha.10-frozen`.
2. **The daemon was replaced a second time, on 2026-10-27.** The
   registration names one replacement. The frozen alpha.10 daemon was
   stopped. alpha.11 was installed from the signed release package, its
   configuration was converted to that release's format with the same Tor
   wiring, and the chain data was removed. It was started at 17:36:08Z
   and synchronized within a minute. The relay process did not change.
   alpha.11 also carries a new dialer. This followed the reads of
   2026-10-12, 10-14 and 10-16 and the health check of 10-17.
3. **The host's daily package upgrade restarted the relay twice**, on
   2026-10-21 at 06:13Z and on 2026-10-24 at 06:09Z, both times for
   library upgrades and with a clean stop. Line 1 ends S3 and S4 there. The
   daily upgrade was then turned off from 2026-10-27 17:44Z to the end of
   the run, so no package was installed on the host for its last two
   weeks. It was turned back on 2026-11-11 23:49Z.
4. **The daemon was restarted by its service manager after a kernel kill,
   on 2026-10-31 at 13:34:49Z** (final result 6). The binary and the
   release label are unchanged.

## Final results, to 2026-11-10 00:00Z

**Read in full on 2026-11-11 to write this section.** Collection reached
the horizon. The collector ran on past it, and no row after 2026-11-10
00:00Z is in any figure below. The captures beside this record hold every
row to the horizon. The interim captures are left as they were.

| File | What |
| --- | --- |
| [`_final_obs.tsv`](trc1_carried_traffic_20261012_final_obs.tsv) | every collector row to the horizon, both versions: the process ids replaced by series, arm and daemon release, the directory weight in force, and the memory columns from version 2 on |
| [`_final_stints.tsv`](trc1_carried_traffic_20261012_final_stints.tsv) | per series, arm and release |
| [`_final_summary.tsv`](trc1_carried_traffic_20261012_final_summary.tsv) | per series, arm, release and weight |
| [`_final_series.tsv`](trc1_carried_traffic_20261012_final_series.tsv) | per series, arm, release, weight and UTC hour: the registered breakdown |
| [`_final_hours.tsv`](trc1_carried_traffic_20261012_final_hours.tsv) | per series, arm, release and UTC hour over all weights, with the number of days in each |
| [`_final_memory.tsv`](trc1_carried_traffic_20261012_final_memory.tsv) | Amendment 1's contrast: resident memory per series, arm and release |
| [`_final_windows.tsv`](trc1_carried_traffic_20261012_final_windows.tsv) | registered lines 2, 3 and 4 per heartbeat window |
| [`_final_heartbeats.tsv`](trc1_carried_traffic_20261012_final_heartbeats.tsv) | Tor's heartbeat figures by series, the host's name removed |
| [`_final_directory.tsv`](trc1_carried_traffic_20261012_final_directory.tsv) | consensus weight and flags per published consensus |
| [`_final_kills.tsv`](trc1_carried_traffic_20261012_final_kills.tsv) | every kernel out-of-memory kill from the start of collection to 2026-11-11, each marked inside or after the horizon |
| [`_final_notices.tsv`](trc1_carried_traffic_20261012_final_notices.tsv) | Tor's low-memory events per UTC day |

The reduction is the same `shekyl-dev` script, extended to read both
collector versions. Its labels are explicit: the six relay processes
below are S1 to S6, and any relay process not named is X1, X2, ... in
order of first appearance. Rates are bytes per second, carried out plus
in and originated out plus in. The two are not in one unit and are not
divided.

### 1. Series

| Series | Relay process | Rows | Ended by |
| --- | --- | --- | --- |
| S1 | from 2026-10-06 03:23Z | 3,712 | a kernel kill, 2026-10-14 19:47:28Z |
| S2 | 17 minutes | 16 | a kernel kill, 20:04:42Z |
| S3 | from 2026-10-14 20:04Z | 9,247 | the daily upgrade, 2026-10-21 06:13Z |
| S4 | from 2026-10-21 06:13Z | 4,315 | the daily upgrade, 2026-10-24 06:09Z |
| S5 | from 2026-10-24 06:09Z | 10,513 | a kernel kill, 2026-10-31 13:23:04Z |
| X1–X66 | 2026-10-31 13:23Z to 23:08Z | 509 in all | each a kernel kill |
| S6 | from 2026-10-31 23:08:51Z | 13,010 | the horizon |

There was no host reboot in the run. Inside the horizon the kernel killed
the relay 69 times and the daemon once.

### 2. The lines

- **Line 1:** 72 relay processes. Six are long enough to report. The 66
  started between 2026-10-31 13:23Z and 23:08Z each lived a few minutes,
  have no heartbeat pair and are not reported by rate.
- **Line 2:** one window of 107 is void, the first, as at the interim. No
  snapshot took more than 5 seconds.
- **Line 3:** in every other window the collector's sum is 0.831 to 0.997
  of the heartbeat's. None is undercounted.
- **Line 4:** 34 windows have **no originated traffic**, all of them under
  the frozen daemon (windows ending 2026-10-18 08:05Z to 2026-10-27
  12:09Z). The daemon sent nothing through Tor then. That says nothing
  about cover.

### 3. Volume by series, arm and release

| Series | Arm | Daemon | Weight | Rows | Carried p5 / median / p95 | Originated p5 / median / p95 |
| --- | --- | --- | --- | --- | --- | --- |
| S1 | uncapped | `v3.1.0-alpha.9` | 1–380 | 3,712 | 446,581 / 1,192,072 / 2,028,143 | 161 / 174 / 1,395 |
| S2 | uncapped | `v3.1.0-alpha.9` | 380 | 16 | 2,563,281 / 3,625,718 / 6,148,640 | 0 / 20 / 66 |
| S3 | uncapped | `v3.1.0-alpha.9` | 370–380 | 2,631 | 40,955 / 789,151 / 1,786,906 | 161 / 174 / 1,448 |
| S3 | uncapped | `v3.1.0-alpha.10` | 350–370 | 138 | 820,874 / 1,116,591 / 1,948,893 | 62 / 296 / 582 |
| S3 | capped | `v3.1.0-alpha.10` | 350 | 1,606 | 905,781 / 1,402,810 / 1,972,155 | 32 / 135 / 505 |
| S3 | capped | `v3.1.0-alpha.10-frozen` | 260–350 | 4,872 | 859,437 / 1,225,557 / 1,877,071 | 0 / 0 / 0 |
| S4 | capped | `v3.1.0-alpha.10-frozen` | 230–260 | 4,315 | 240,540 / 1,070,054 / 1,783,333 | 0 / 0 / 0 |
| S5 | capped | `v3.1.0-alpha.10-frozen` | 230–250 | 5,004 | 297,393 / 628,659 / 1,248,789 | 0 / 0 / 0 |
| S5 | capped | no daemon | 250 | 2 | 630,749 / 647,268 / 663,787 | 0 / 0 / 0 |
| S5 | capped | `v3.1.0-alpha.11` | 240–270 | 5,507 | 418,785 / 738,852 / 1,531,560 | 314 / 1,204 / 3,343 |
| S6 | capped | `v3.1.0-alpha.11` | 210–290 | 13,010 | 107,939 / 656,012 / 1,554,848 | 271 / 531 / 23,311 |

Originated figures are never pooled across releases. alpha.11's are
higher than alpha.9's and alpha.10's: a new dialer, and more of its peers
reached over Tor. S6's 95th percentile comes from its start, after the daemon's own
restart. On 2026-11-01 originated traffic ran at 10 to 14 kB/s, on
2026-11-02 near 1.4 kB/s, and from 2026-11-03 near 320 B/s. The cause of the first day's
level is not established.

### 4. Hours of the day

S5 under alpha.11 spans four days, and S6 nine. S6's median per UTC hour
ranges from 550 to 731 kB/s, while its median per day ranges from 166 to
818 kB/s. Day-to-day change is larger than any hour-of-day shape, as at
the interim, so no daily shape is claimed.

### 5. The directory

The consensus weight was 1 until 2026-10-12 20:00Z, then 310, 380 from
2026-10-14, 370 and 350 through 2026-10-17, 260 from 2026-10-18, 230 to
260 from 2026-10-21, and 210 to 290 from 2026-10-28 to the horizon. The
guard probability was 0 in every sample. The HSDir flag was absent from
2026-10-14 20:00Z (the first consensus after S1's kill) to 2026-10-18
21:00Z. It was absent again from 2026-10-21 07:00Z (S4's start) to
2026-10-28 07:00Z, and held from then to the horizon, through the
2026-10-31 kills. *The interim section dates the first loss to the
consensus of 2026-10-15 12:00Z; its own captures show 2026-10-14 20:00Z.*

Ruling 2: the run covers weights from 1 to 380, so step 2 is not
confined to a weight of 1. It covers that range and nothing above it.

Tor's denial-of-service counters rose in every series. At the horizon S6
reported 5,235 open circuits, 27,083 circuits killed for too many cells
and 13,103 concurrent connections from one address refused. The volume
that began on 2026-10-11 did not end within the run.

### 6. Memory: Amendment 1's contrast

Resident memory in MiB (median / maximum), and the host's lowest
available memory:

| Series | Arm | Daemon | Rows | Relay | Daemon | Lowest available |
| --- | --- | --- | --- | --- | --- | --- |
| S3 | uncapped | `v3.1.0-alpha.10` | 62 | 1,509 / 1,548 | 328 / 328 | 1,613 |
| S3 | capped | `v3.1.0-alpha.10` | 1,606 | 1,555 / 1,569 | 331 / 333 | 1,602 |
| S3 | capped | `v3.1.0-alpha.10-frozen` | 4,872 | 1,565 / 1,587 | 333 / 333 | 1,470 |
| S4 | capped | `v3.1.0-alpha.10-frozen` | 4,315 | 737 / 744 | 332 / 332 | 2,352 |
| S5 | capped | `v3.1.0-alpha.10-frozen` | 5,004 | 710 / 735 | 332 / 332 | 2,311 |
| S5 | capped | `v3.1.0-alpha.11` | 5,507 | 758 / 1,320 | 854 / 1,147 | 33 |
| S6 | capped | `v3.1.0-alpha.11` | 13,010 | 1,198 / 1,257 | 1,133 / 1,411 | 837 |

- **The reload did not shrink the running process.** S3 held about
  1.5 GiB before the cap and the same for the five days after it.
- **The relays started with the cap in place held half that**, 0.71 to
  0.76 GiB, at carried volumes at or below S3's. Tor logged no low-memory event
  in S4 or S5, so the cap was not killing circuits, and this is not
  evidence that it acted. Two other differences overlap with it: the
  directory cache for onion services is sized at a fifth of the cap
  (about 100 MiB here, about 590 MiB unset), and the HSDir flag was absent
  for all of S4 and S5's first four days. They are not separated.
- **alpha.11's daemon holds two and a half to three and a half times
  alpha.10's memory.** It stepped up by about 250 MiB on 2026-10-30, which
  matches that release's RandomX caches growing at height 2112, an issue
  of the release. From then the host
  had about 1.5 GiB available.
- **The surge of 2026-10-31.** Between 12:16Z and 12:20Z the relay's
  inbound sockets went from 4,489 to 8,179 and its resident memory from
  785 to 1,291 MiB. The host's uplink then sent 2 to 8 MB/s and received
  about 1 MB/s, far above `RelayBandwidthRate`. The cause is not
  established. Tor's memory notices later reported up to 195 MB of lzma
  compression buffers; that is a figure from the notice, not a mechanism.
  From 13:15Z to 13:22Z the host's available memory fell from 1.1 GB to
  33 MB while neither process's resident memory grew. The kernel's kill
  report does not show it as anonymous or slab memory, and it is not
  accounted for here.
- **The cap acted, and the kernel killed the relay anyway.** From 13:23Z
  the kernel killed the relay, holding 0.97 to 1.18 GB of anonymous memory
  each time, 67 times until 23:08Z. It killed the daemon once, at 13:34Z
  with 1.12 GB. Tor's cap engaged for the first time in the run: 2,350
  low-memory events that day, each killing hundreds of circuits, with
  about 43,000 still open late that evening. That is the direct evidence Amendment 1 named,
  and it did not prevent the kills.
- **The memory did not come back.** S6 held 1.2 GiB for nine days at
  ordinary volume (median 656 kB/s), about 2.3 times the cap. The daemon
  held 1.1 GiB, and the host's lowest available memory was 837 MiB.

On a 4 GB host with no swap, a relay at this rate beside the daemon was
killed by the kernel both without the cap and with it. The cap bounds
Tor's queues. The process's resident memory ran at 1.4 to 3 times it.

**After the horizon** (in no figure above; marked "after" in the kill and
notice captures): on 2026-11-11 from 12:04Z to 15:24Z the same happened
again. There were 392 low-memory events, and the kernel killed the relay
16 times and the daemon once. The collector stopped at about 13:46Z. It
was not among the processes the kernel named, and the cause is not
established.

### 7. Comparison

This compares the daemon's bytes with the relay's. The figures come from
`_final_obs.tsv`, reduced by the same script into
[`_final_comparison.tsv`](trc1_carried_traffic_20261012_final_comparison.tsv).
Originated bytes are counted before Tor pads them into 514-byte cells, so
the share on the wire is somewhat higher than these figures. They are
per-minute totals over all of the relay's connections. The daemon's cells
leave on one of them, the connection to its first hop.

| | All rows (41,322) | Rows with a live daemon (27,129) |
| --- | --- | --- |
| Originated bytes as a share of carried bytes | 0.18 % | 0.29 % |
| Share per minute, median / 95th percentile | 0.03 % / 1.10 % | 0.08 % / 1.79 % |
| Median outbound bytes per second | 390,306 | 336,190 |
| One 17-cell stem (8,738 bytes) against that second | 2.2 % | 2.6 % |
| Minutes with outbound under 17 cells/s | 0.039 % | 0.055 % |
| Minutes with outbound under 170 cells/s | 6.4 % | 9.2 % |

"Rows with a live daemon" leaves out the frozen alpha.10 daemon and the
two minutes with no daemon. Rows in which the relay carried nothing are
left out of the share per minute: 15 of all rows, 14 of the live-daemon
rows. The figures given when this comparison was asked for were 0.19 %,
0.08 % / 1.8 %, 2.2 %, 0.04 % and 6.4 %. The script's figures stand, and
two of them differ:
- the overall share is 0.18 %;
- the per-minute share is 0.03 % / 1.10 % over all rows. The figures
  asked about match the live-daemon rows instead.

### 8. What these say, and what they do not

- **Volume does not follow weight in one direction here.** The relay
  carried as much at weight 1 as at 310, and less at 210 to 290 than at
  350. These are observations of one relay across six processes. They are
  not a property of weight.
- **Ruling 3.** The volume that began on 2026-10-11 never ended, and
  2026-10-31 added a second surge on top of it. Results are given per
  series. Which of them describes an ordinary operator is left by ruling 3
  to be ruled on reading. This record does not rule it.
- **The originated share** is a few hundred to about 1,200 bytes per
  second against 0.1 to 2 MB/s carried. That is the registered condition
  of a quiet testnet. It is not evidence that originated cells are hidden.
- **Distinguishability is not decided here.** The `PM-3` watermark test
  named under "What this record does not decide" runs against this volume
  series. Part B, the share on the process's own guard connections, was
  never registered, and nothing here answers it.
- **Memory is a condition of the posture, not only of this run.** A relay
  run as `TOR_RELAY.md` describes, on a small host beside the daemon, was
  killed by the kernel 69 times in the horizon. The cap did not stop it.
