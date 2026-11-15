# `TRC-1` guard-connection reading: can the guard connection's byte counts show when the daemon sent? Registration, 2026-11-12

**State of this record: COMPLETE 2026-11-15. Registered 2026-11-12;
collected from 2026-11-12 20:57Z (sampler version 2 from 21:27Z) to the
horizon, 2026-11-14 21:48Z. Amendment 1 (2026-11-12) changed the
instrument and four definitions before any guard-connection byte figure
was read. The results are at the end.**
Everything under "Registered before the run" is fixed from the moment
this record is pushed. A change after that is a dated amendment that says
what had been read by then. Results are added below.

Step 2 is [`trc1_carried_traffic_20261012.md`](trc1_carried_traffic_20261012.md).
This reading follows it in the falsifier chain of
[`TOR_COVER_POSTURE.md`](../design/TOR_COVER_POSTURE.md) §8.

## The question

Step 2 measured the relay's total volume. The daemon's traffic was 0.18 %
of the relay's bytes over the run (step 2, final result 7), and one
17-cell stem is 2.2 % of a median outbound second. Those are per-minute
totals over all of the relay's connections. The daemon's cells leave on
one of them, the relay's connection to the entry guard that carries its
circuits.

This reading answers one question. Looking only at the byte counts on the
guard connection over time, can an observer tell when the daemon sent?

## What had been read before this registration

- All of step 2: every collected row to its horizon, the final results,
  and the comparison of originated against carried bytes.
- Tor 0.4.9.13's source, for Part 1 below.
- The relay's guard state: the `Guard` lines of Tor's `state` file, read
  for their fields and their count. There are 31 sampled guards and 7
  confirmed ones.
- One minute of the 100 ms sampler on the relay host on 2026-11-12, for
  shape only. It wrote 601 rows with three guards tracked, the slowest
  reading took 73 ms, and one sample was more than 50 ms late. Its output
  was deleted without any byte figure being read.

No guard-connection byte count had been read.

## Part 1: does the relay send its own circuits through entry guards?

Read at tag `tor-0.4.9.13` (commit `3c575400909e`).

**Yes.** A process running as a non-bridge relay sends its own circuits
through its entry guards:

- `UseEntryGuards` defaults to 1 (`src/app/config/config.c:694`). No relay
  or server-mode code turns it off. Only single-onion mode and directory
  authorities do (`config.c:3265-3277`,
  `src/feature/dirauth/dirauth_config.c:90-93`).
- `choose_good_entry_server` returns a guard from the guard set for every
  purpose except testing circuits on a non-bridge
  (`src/core/or/circuitbuild.c:2502-2507`).
- **SOCKS streams** ride general-purpose circuits
  (`src/core/or/circuituse.c:2975`), so they use a guard.
- **Onion-service circuits** use a guard too. That covers introduction
  (`src/feature/hs/hs_circuit.c:1068`), rendezvous (`hs_circuit.c:378`,
  `523`), and descriptor upload and fetch (`circuituse.c:2967-2971`).
  Descriptor traffic must be anonymous (`src/feature/dircommon/directory.c:146-148`).
- **Not through guards:**
  - Directory fetches. A public relay uses no directory guards
    (`src/feature/dirclient/dirclient.c:316-318`).
  - One-hop tunnels (`circuitbuild.c:2120-2124`).
  - Reachability and bandwidth self-tests (`src/feature/relay/selftest.c:264`).

**How many guards.**
- Tor keeps three primary guards (`DFLT_N_PRIMARY_GUARDS`,
  `src/feature/client/entrynodes.h:458`). A circuit uses one
  (`DFLT_N_PRIMARY_GUARDS_TO_USE`, `entrynodes.h:463`): the first live
  primary guard (`entrynodes.c:2193-2216`).
- Conflux is on by default with two legs per set
  (`src/core/or/conflux_params.c:31`, `57`). A second leg excludes the
  first leg's guard (`entrynodes.c:3877-3884`), so SOCKS streams can use
  two guards at once.
- Vanguards-lite pins the second hop only (`circuitbuild.c:2362-2366`).

**Which guards are primary.** The `state` file does not record which
guards are primary; Tor computes that in memory
(`entrynodes.c:1956-2016`). The candidates are the confirmed, listed
guards in `sampled_idx` order. Tor keeps its confirmed list in that order
(`entrynodes.c:1910-1911`), not in `confirmed_idx` order. At this
registration the first three by that rule are also the first three by
`confirmed_idx`.

**Shared connection.** The relay's own circuits extend over the same
channel lookup as the circuits it relays for others
(`circuitbuild.c:636-643`, `src/core/or/channel.c:2496-2555`). So own
cells share the existing relay-to-relay connection to the guard with
relayed traffic.

## Registered before the run

**Subject.** The relay process of step 2 is Tor Project `tor` 0.4.9.13, a
non-exit relay at `RelayBandwidthRate` 1 MB/s with `MaxMemInQueues`
512 MB. It has been running since 2026-11-11 14:58Z. The daemon of step 2
is `v3.1.0-alpha.11`, whose Tor client is that process. The host and the
relay's identity are in `shekyl-dev`, `infrastructure/trc1/`. Step 2's
60-second collector keeps running beside this reading.

**Instrument (Part 4).** The 100 ms sampler is `shekyl-dev`
`infrastructure/trc1/guard_sample.py`.

- **Which guards.** Once a minute it reads Tor's `state` file and takes up
  to three confirmed, listed guards in Tor's primary order (Part 1),
  labelled `g0`, `g1`, `g2`. It looks up each one's address in Tor's
  cached microdescriptor consensus.
- **What it samples.** Every 100 ms it takes one kernel socket reading
  (`ss -tin`, filtered in the kernel). For each tracked guard it records
  the change in bytes sent and bytes received, summed over the relay's
  sockets to and from that guard's address. It records the same for the
  daemon's loopback sockets to Tor's SOCKS port and from the onion
  service's target port.
  - A socket new since the last sample counts its whole counters.
  - A socket that closes between two samples loses its last bytes.
  - Bytes sent include retransmissions.
- **Lateness.** Each row records how late its sample was against the
  100 ms schedule. A slot that could not be taken has no row.
- **No address or guard identity is written.** Each is held in memory
  only, to build the filter and label sockets. A change in the tracked
  guards is written as a new epoch number.
- **No contact with Tor.** Nothing connects to the Tor process, signals it
  or changes its configuration. Tor's two files are read through `sudo`
  once a minute.

**Assumption:** 100 ms. Basis: a stem leaves in well under a second.

**The sends (Part 5).**
- **Wallet.** A testnet wallet on the relay host drives
  `shekyl-wallet-rpc` against the daemon's own loopback RPC. That RPC port
  is neither of the two daemon ports the sampler counts. The loop is
  `shekyl-dev` `infrastructure/trc1/send_loop.py`.
- **What each send is.** One real transaction paying 0.1 SKL to the
  wallet's own address, at the `standard` fee priority. The gap before
  each send is drawn uniformly from 240 to 360 seconds. Every send logs
  the start and end of its refresh, build and submit calls, the daemon's
  verdict, and the transaction hash.
- **Funding.** The wallet is funded once, before the start, by one
  transaction with many outputs from the fleet's mining wallet. That
  transaction confirms and unlocks before collection starts.

**Duration.** 48 hours from the start. **Assumption.** Basis: about 570
own sends, across two day-night cycles. The run is extended if kernel kills
remove more than a quarter of that time.

**What splits or voids the data (Part 7).**
1. **A new relay process starts a new series**, reported separately. The
   first 30 minutes of each process are dropped.
2. **A change in the tracked guards starts a new series.**
3. **Void windows.** A window is void if more than 5 % of its 100 ms
   slots are missing or more than 50 ms late. A 100 ms window is one
   slot, so it is void if that slot is missing or late by more than 50 ms.

**Windows.** 100 ms (one slot), 1 s (10 slots) and 10 s (100 slots),
aligned to the start of each series after its first 30 minutes. One cell
is 514 bytes.

**Definitions.**
- A **daemon write** is a slot in which the daemon's loopback sockets sent
  more than 0 bytes, to the SOCKS port or on an onion-service session.
- An **own-transaction send** is the first daemon write that begins after a
  logged submit call starts, if it comes within 10 seconds. If none comes,
  that send is reported as not seen.
- The send's **size** is the daemon's loopback bytes sent in that slot and
  the 9 that follow, in cells, rounded up. Other daemon traffic in that
  second is inside it, so it is an upper bound.
- An **own-transaction window** is the window holding the own-transaction
  send's first slot, shifted by the delay of item 3 rounded to 100 ms.
- An **any-daemon-send window** is a window holding at least one daemon
  write, with the same shift. All other non-void windows are
  **no-daemon-send windows**.

**What is reported (Part 6).**
1. **Part 1's answer, and the guard state.** How many confirmed guards
   the `state` file showed at the start and at the end, and every change
   in the tracked guards.
2. **Guard-connection volume.** For each tracked guard, outbound and
   inbound, in cells per second over 1 s windows: the 1st, 5th, 50th and
   95th percentiles. Also its share of the relay's total bytes from step
   2's collector over the same minutes.
3. **The delay from a daemon write to bytes leaving on the guard
   connection,** measured from the data. It is the cross-correlation of
   the daemon's loopback bytes sent with each guard's bytes sent, at lags
   0 to 3 s in 100 ms steps. The lag of the peak is reported for each
   guard, with the peak's height against the correlation at lags of 5 to
   10 s.
4. **Each own-transaction send against the guard.** Its size in cells
   against the guard connection's outbound cells in the same window, for
   each guard and window length. Reported as each send's ratio, and as the
   distribution of those ratios.
5. **The observer's test.** For windows of 100 ms, 1 s and 10 s, the
   score is only the guard connection's outbound bytes in the window.
   - **Comparisons:** own-transaction windows against all other non-void
     windows, and any-daemon-send windows against no-daemon-send windows.
   - **For each comparison:** the share of send windows whose score is
     above the 99th percentile of the other windows, and the area under
     the ROC curve (the Mann-Whitney statistic, ties counted half).
   - **Score per guard and summed.** The score is computed for each
     tracked guard separately, since an observer watches one connection.
     It is also computed for the sum of the three, since conflux can split
     a stream over two.
   - **Without the shift too.** Each figure is also reported with no shift
     (delay 0).

**No pass mark is set here.** The figures are reported, and the ruling
on them is Rick's.

**Data.** The raw 100 ms rows and the send log stay in `shekyl-dev`. The
reduced tables are added beside this record with the results.

## Amendment 1, 2026-11-12: guard coverage, sample validity, matching sends, cell size

*Written 2026-11-12 at about 21:30Z. Collection had started at 20:57:11Z.
No guard-connection byte figure had been read. What had been read by then:
- row counts and late samples (11 of 5,551 rows more than 50 ms late at
  21:06Z);
- the sampler's log (three guards tracked, no epoch change);
- the send log (item 5 below);
- two shape-only smoke runs of the new sampler version.

Prompted by review of this record (PR #1356).*

1. **Fallback guards.** When no primary guard is usable, Tor falls back
   to a confirmed non-primary guard, then to any usable sampled guard
   (`src/feature/client/entrynodes.c:2315-2349`). Circuits on those would
   be missed by the three tracked guards.
   - **Instrument change.** Sampler version 2 (`guard_sample.py`) also
     samples every other listed sampled guard, summed as `gx`. Once a
     minute it writes Tor's path-bias counters (`pb_circ_attempts`,
     `pb_use_attempts`) summed per label, to `guard_state.tsv`. Tor writes
     a guard's counters within 30 s of a change (`entrynodes.c:3636`).
   - **Fallback seen.** If `gx`'s counters rose between two reads, that
     interval is "fallback seen". Its windows are left out of item 5 and
     counted.
   - **The check is partial.** The counters leave out rendezvous and
     conflux circuits (`src/feature/client/circpathbias.c`,
     `pathbias_should_count`). So item 3's correlation is also run on
     `gx`'s bytes, and a peak there is reported as uncovered sending.
   - **Version 1 rows are not used.** Rows from version 1 (20:57:11Z
     until the switch) have no `gx` and go into no result.
2. **Sample validity.** A row's deltas run from the previous row. So a
   row after a missed or late slot carries more than 100 ms of bytes.
   - **The rule.** A slot is valid only if the previous scheduled slot has
     a row, neither row is more than 50 ms late, and it is not the first
     row after a relay or guard epoch change.
   - **What it applies to.** Byte figures come only from valid slots. In
     Part 7's 5 % rule (line 3), invalid slots count as missing. The same
     rule applies to daemon writes and to send matching.
3. **Matching a send to its write.** The first daemon write after a
   submit may be other daemon traffic. The daemon may also hold a
   transaction without sending it at once. So each send is matched by its
   own size, and this replaces the registered definition of an
   own-transaction send.
   - **Its size.** The transaction's serialized size is read from the
     daemon by its logged hash (`get_transactions`).
   - **The own-transaction send** is the first run of consecutive valid
     slots with daemon loopback bytes sent that starts within 10 s after
     the submit call starts and whose total reaches that size.
   - **Sends are reported in four groups:** matched; not seen (accepted,
     with no matching run within 10 s); rejected (the daemon's verdict was
     not `ACCEPTED`); and failed before submit (a build or submit error).
   - **Item 5's comparison groups** leave out any window within 10 s
     after a submit that is not a matched send. That keeps a mislabelled
     stem out of the "other windows".
4. **Cells.** A relay cell carries at most 498 bytes of payload in 514
   bytes on the wire (`src/core/or/or.h:563-584`).
   - The registered "bytes ÷ 514, rounded up, an upper bound" is
     withdrawn.
   - Item 4 reports each send as plaintext bytes and as its minimum wire
     bytes, ⌈bytes ÷ 498⌉ × 514. Each is set against the guard
     connection's outbound bytes in the same window.
   - Neither figure is a bound. Other daemon traffic in the window can add
     to the plaintext, and framing can add cells.
   - Guard volumes in item 2 stay in 514-byte cell equivalents.
5. **Sends so far, and the duration.** Of the first six attempts:
   - **The first three** failed before submit because the funds were not
     yet spendable, though the wallet already reported them unlocked.
   - **The fourth** (21:16:27Z) failed in the signer, with an error that
     does not name its cause.
   - **The fifth and sixth** (21:21:59Z and 21:26:25Z) were accepted.
   - **A hand-made build** at 21:21:55Z, made without a refresh, also
     failed in the signer. The loop's build four seconds later, after its
     refresh, succeeded.
   - **The sending wallet's server since 21:28Z** is a build of
     `v3.1.0-alpha.11` that also logs the signer's underlying error and is
     otherwise the release. It was restarted from the wallet's files.
   - **Duration.** The 48 hours now count from the first accepted own send
     under sampler version 2. The run ends at 48 hours or at the alpha.12
     changeover, whichever comes first.


## Results, to 2026-11-14 21:48Z

**Read in full on 2026-11-15 to write this section.** Collection stopped
at 07:57:58Z that day. Before this read, only row counts, send counts and
the sampler's log had been looked at; no guard-connection byte figure.

**What was read:**
- every sampler version 2 row up to the horizon;
- the path-bias counter file and the sampler's log;
- the send log, with each accepted send's serialized size read from the
  daemon by its hash;
- step 2's continued 60-second collector over the same minutes.

The reduction is `shekyl-dev` `scripts/trc1/analyze_guard.py`. The raw rows
and the send log are in `shekyl-dev`. The reduced tables are beside this
record, and they hold no address, guard identity or transaction hash.

| File | What |
| --- | --- |
| [`_series.tsv`](trc1_guard_connection_20261112_series.tsv) | item 1: each series, its span, valid slots, and path-bias rises per guard |
| [`_volume.tsv`](trc1_guard_connection_20261112_volume.tsv) | item 2: cells per second per guard over 1 s windows, per series and pooled |
| [`_share.tsv`](trc1_guard_connection_20261112_share.tsv) | item 2: each guard's share of the relay's carried bytes |
| [`_delay.tsv`](trc1_guard_connection_20261112_delay.tsv), [`_delay_peak.tsv`](trc1_guard_connection_20261112_delay_peak.tsv) | item 3: correlation of daemon bytes sent with guard bytes sent, by lag |
| [`_send_groups.tsv`](trc1_guard_connection_20261112_send_groups.tsv) | Amendment 1 item 3: the send groups |
| [`_sends.tsv`](trc1_guard_connection_20261112_sends.tsv), [`_sends_summary.tsv`](trc1_guard_connection_20261112_sends_summary.tsv) | item 4: each matched send against each guard and window, and the distributions |
| [`_test.tsv`](trc1_guard_connection_20261112_test.tsv) | item 5: the observer's test, per series and pooled |
| [`_meta.tsv`](trc1_guard_connection_20261112_meta.tsv) | the horizon, rows, excluded rows |

### 1. Part 1, the guard state, and the series

**Part 1's answer stands.** The relay's own circuits go through its entry
guards. Tor's `state` file held 7 confirmed guards out of 31 sampled at
the start (2026-11-12) and 7 out of 31 at the end (read 2026-11-15, after
the run).

**The horizon.** It is 48 hours from the first send accepted under sampler
version 2, which was submitted at 2026-11-12 21:48:04Z. So the horizon is
2026-11-14 21:48:04Z.

**A third out-of-memory episode.** The relay process running since
2026-11-11 14:58Z was killed by the kernel at 12:08Z on 2026-11-14.
- **Length.** The episode lasted until 02:25Z on 2026-11-15. The kernel
  killed `tor` about 170 times and the daemon once (12:16Z), and Tor
  logged 5,134 low-memory notice lines.
- **Effect on the data.** Every relay process in the episode lived a few
  minutes, inside the 30-minute drop, so nothing from 12:08Z to the
  horizon is usable.
- **No extension.** That is 9.7 hours, 20 % of the 48, under the quarter
  that would have extended the run.

**Six series.** The usable data is the first relay process across six
guard epochs:

| Series | Guard epoch | From | To | Hours | Valid slots | Path-bias rises g0 / g1 / g2 / others |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | 0 | 2026-11-12T21:27Z | 2026-11-13T16:32Z | 19.1 | 99.5 % | 1052 / 989 / 0 / 0 |
| 1 | 1 | 2026-11-13T16:32Z | 2026-11-13T18:27Z | 1.9 | 99.5 % | 108 / 109 / 0 / 0 |
| 2 | 2 | 2026-11-13T18:27Z | 2026-11-13T23:03Z | 4.6 | 99.5 % | 260 / 222 / 0 / 0 |
| 3 | 3 | 2026-11-13T23:03Z | 2026-11-14T02:13Z | 3.2 | 99.5 % | 177 / 183 / 0 / 0 |
| 4 | 4 | 2026-11-14T02:13Z | 2026-11-14T03:13Z | 1.0 | 99.5 % | 55 / 4 / 31 / 0 |
| 5 | 5 | 2026-11-14T03:13Z | 2026-11-14T12:08Z | 8.9 | 99.5 % | 508 / 510 / 0 / 0 |

- **Where the boundaries fall.** At the sampler's detection time, up to
  60 s after Tor changed its primaries. All three tracked guards had a
  consensus address throughout.
- **Which guards carried counted circuits.** Path-bias counters rose on
  `g0` and `g1` together in every series, which fits conflux running on
  two guards. `g2` rose only in series 4. No other guard ever rose, so
  "fallback seen" (Amendment 1 item 1) occurs in no interval.
- **Rows excluded as resets.** The validity rule of Amendment 1 item 2
  applies to every reset of the sampler's socket table. That covers the 7
  epoch changes and also 22 changes of the fallback set, after which the
  sampler clears its table too, so the next row carries whole counters.
  2,971 rows were excluded as resets.

### 2. Guard-connection volume

Cells per second (514-byte cell equivalents) over all 135,871 non-void
1 s windows. `gx` is the 22 to 25 other listed guards, summed.

| Guard | Outbound p1 / p5 / p50 / p95 | Inbound p1 / p5 / p50 / p95 |
| --- | --- | --- |
| `g0` | 0.00 / 0.00 / 1.04 / 16.1 | 0.00 / 0.00 / 1.04 / 19.4 |
| `g1` | 0.00 / 0.00 / 1.04 / 10.0 | 0.00 / 0.00 / 1.04 / 14.6 |
| `g2` | 0.00 / 0.00 / 0.00 / 3.1 | 0.00 / 0.00 / 0.00 / 2.1 |
| `gx` | 1.04 / 2.09 / 11.43 / 59.8 | 1.04 / 2.09 / 8.34 / 105.1 |

Over 2,042 matched minutes, the three tracked guard connections carried
0.47 % of the relay's carried bytes: `g0` 0.23 %, `g1` 0.19 %, `g2`
0.04 %. All the other guards together carried 1.12 %. At the median, each
of the two working guard connections moves about one cell a second each
way.

### 3. The delay from a daemon write to the guard connection

| Guard | Peak lag | Correlation at the peak | At 5–10 s, mean / max |
| --- | --- | --- | --- |
| `g0` | 0 s | 0.738 | 0.015 / 0.050 |
| `g1` | 0 s | 0.453 | 0.011 / 0.040 |
| `g2` | 0 s | 0.007 | -0.001 / 0.001 |
| `gx` | 0.5 s | 0.001 | -0.001 / 0.000 |
| `sum` | 0 s | 0.746 | 0.016 / 0.055 |

- **No measurable delay.** The daemon's loopback bytes sent line up with
  `g0`'s and `g1`'s outbound bytes in the same 100 ms slot. So the
  registered shift is 0, and each shifted figure below equals the
  unshifted one, reported once.
- **No uncovered sending.** `gx` shows no peak above its floor.

### 4. The sends, and each send against the guard

Sends from the start of sampler version 2 to the horizon fall into five
groups:
- **453 matched.**
- **4 not seen.**
- **3 rejected.** All between 21:32Z and 21:42Z on 2026-11-12, after the
  sending wallet's server was restarted (Amendment 1 item 5).
- **5 failed before submit.** Each was the wallet's construct-side
  balance self-check (`BalanceSelfCheck`), on 2026-11-14.
- **110 outside a usable series.** Accepted during the out-of-memory
  episode.

Every accepted send was 13,619 bytes serialized: at least 28 relay cells,
or 14,392 bytes on the wire. The table gives each matched send's plaintext
bytes, and its minimum wire bytes, against the guard connection's outbound
bytes in the window holding it. `inf` means that guard sent nothing in that
window.

| Window | Guard | Sends | Plaintext ÷ guard outbound, p5 / p50 / p95 | Minimum wire ÷ guard outbound, p5 / p50 / p95 |
| --- | --- | --- | --- | --- |
| 0.1 s | `g0` | 453 | 0.92 / 1.26 / inf | 0.96 / 1.31 / inf |
| 0.1 s | `g1` | 453 | 0.96 / inf / inf | 1.01 / inf / inf |
| 0.1 s | `g2` | 453 | inf / inf / inf | inf / inf / inf |
| 0.1 s | `sum` | 453 | 0.88 / 0.95 / inf | 0.93 / 0.99 / inf |
| 1 s | `g0` | 442 | 0.75 / 0.95 / inf | 0.79 / 0.99 / inf |
| 1 s | `g1` | 442 | 0.82 / 12.77 / inf | 0.87 / 13.43 / inf |
| 1 s | `g2` | 442 | 12.77 / inf / inf | 13.43 / inf / inf |
| 1 s | `sum` | 442 | 0.61 / 0.88 / 0.96 | 0.64 / 0.92 / 1.01 |
| 10 s | `g0` | 422 | 0.07 / 0.39 / 5.11 | 0.07 / 0.41 / 5.37 |
| 10 s | `g1` | 422 | 0.10 / 0.52 / 8.51 | 0.11 / 0.54 / 8.95 |
| 10 s | `g2` | 422 | 0.69 / 25.54 / inf | 0.73 / 26.85 / inf |
| 10 s | `sum` | 422 | 0.04 / 0.21 / 0.70 | 0.04 / 0.22 / 0.73 |

In the 100 ms slot holding the send, the three guard connections together
send about the send's own minimum wire bytes (median ratio 0.99). Over the
whole second, the send is 88 % of their outbound bytes at the median.

### 5. The observer's test

The score is the guard connection's outbound bytes in the window. Each
cell gives the share of send windows above the other windows' 99th
percentile, then the area under the ROC curve. The figures are pooled
over the six series, and the per-series figures are in the capture.

**Own vs other.**

| Window | Send windows / other windows | `g0` | `g1` | `g2` | Sum of the three |
| --- | --- | --- | --- | --- | --- |
| 0.1 s | 453 / 1,383,576 | 55.2 %, 0.786 | 32.9 %, 0.661 | 0.4 %, 0.493 | 82.6 %, 0.928 |
| 1 s | 442 / 135,352 | 3.2 %, 0.784 | 1.6 %, 0.664 | 0.5 %, 0.482 | 3.2 %, 0.930 |
| 10 s | 422 / 13,137 | 7.6 %, 0.808 | 6.6 %, 0.756 | 0.5 %, 0.488 | 6.2 %, 0.817 |

**Any daemon send vs none.**

| Window | Send windows / other windows | `g0` | `g1` | `g2` | Sum of the three |
| --- | --- | --- | --- | --- | --- |
| 0.1 s | 65,015 / 1,319,014 | 16.4 %, 0.787 | 11.5 %, 0.685 | 1.0 %, 0.502 | 18.2 %, 0.878 |
| 1 s | 41,750 / 94,044 | 17.0 %, 0.760 | 10.4 %, 0.685 | 1.0 %, 0.502 | 9.8 %, 0.751 |
| 10 s | 13,130 / 429 | 8.7 %, 0.769 | 5.2 %, 0.728 | 0.9 %, 0.515 | 6.1 %, 0.741 |

Per series, sum of the three, 100 ms, own transaction against other windows: series 0: 220 sends, 89.5 %, AUC 0.962; series 1: 23 sends, 34.8 %, AUC 0.625; series 2: 55 sends, 76.4 %, AUC 0.919; series 3: 36 sends, 83.3 %, AUC 0.942; series 4: 12 sends, 66.7 %, AUC 0.790; series 5: 107 sends, 61.7 %, AUC 0.941.


### 6. What these say, and what they do not

- **The guard connections carry little.** Between them they carry about
  half a percent of the relay's bytes. The relay's relayed volume is
  mostly on other connections, and the daemon's own sends make up most of
  what crosses the guard connections.
- **One send stands out at 100 ms.** Watching the two working guard
  connections together, an observer ranks the window holding the daemon's
  own transaction above a random other window 93 % of the time, and 79 %
  on `g0` alone.
  - 83 % of those sends are above the 99th percentile of the other
    windows (55 % on `g0` alone).
- **At 1 s and 10 s the ranking holds, but few sends top the 99th
  percentile.** The area under the curve stays at 0.82 to 0.93 for the
  sum. The sum's share above the 99th percentile falls to 3 % and 6 %, because the
  daemon's other traffic fills the top of the comparison: some daemon send
  falls in 97 % of 10 s windows.
- **No pass mark.** This record does not apply step 3 of
  `TOR_COVER_POSTURE.md` §8. The ruling on these figures is Rick's.
- **Limits:**
  - one relay and one daemon, on a quiet testnet;
  - kernel counters read every 100 ms, so no delay below that is
    resolved;
  - guard-epoch boundaries known only to within a minute;
  - windows aligned to each series' start;
  - the daemon's own traffic other than these sends is unlabelled.

### Conditions during the run

- **Wallet signer failures.** The sending wallet's signer failed on
  2026-11-12 (cause unnamed) and ten times on 2026-11-14. On 11-14 the
  diagnostic build named the cause: `BalanceSelfCheck`, "input-side and
  output-side commitment sums differ". These are a wallet finding, handed
  to the wallet lane. Sends were accepted again after each burst.
- **Collection ran past the horizon,** to 2026-11-15 07:57:58Z. Rows after
  the horizon go into no figure above.
- **The daily package upgrade** was turned back on at the stop, and
  restarted the relay at about 08:08Z on 2026-11-15.
