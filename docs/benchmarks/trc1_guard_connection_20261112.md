# `TRC-1` guard-connection reading: can the guard connection's byte counts show when the daemon sent? Registration, 2026-11-12

**State of this record: REGISTERED 2026-11-12, collecting since
2026-11-12 20:57Z. Amendment 1 (2026-11-12, below) changes the instrument
and four definitions before any guard-connection byte figure was read.**
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
- the send log (every attempt failed, item 5 below);
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
5. **Sends so far, and the duration.** Every send attempt since the start
   failed before submit.
   - **The first three** failed because the funds were not yet spendable,
     though the wallet already reported them unlocked.
   - **Every later one** failed in the signer, with an error that does not
     name its cause.
   - **A comparison.** The same build from the funding wallet, which was
     scanned from genesis, succeeds. The sending wallet had been restored
     from height 11640 and is being re-scanned from genesis.
   - **Duration.** The 48 hours now count from the first accepted own send
     under sampler version 2. The run ends at 48 hours or at the alpha.12
     changeover, whichever comes first.
