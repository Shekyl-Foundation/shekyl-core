# P2P cutover cross-build, 2026-09-29

Private testnet pair, option off. Not the public testnet: each node
dialled only the other, on loopback. The seam pin is `2af7279fb`
(the close-cause log on `979d9dc13`). The epee pin is `d09bf3ef0`,
the branch base, so the pair differs by the cutover commits. Current
`dev` has moved past that base with non-transport commits; it was
not the peer.

`--clearnet-transport-encrypt` was not set.

## What passed

- **Dial, both directions, clearnet.** Before any ban, each node
  reported one incoming session and one outgoing session. The seam
  node reported the same counts as socket counts.
- **Sync from genesis, both directions.** One node held a chain at
  height 80 (`top_block_hash` prefix `aa78f57dece25694`). The other
  was started with an empty store and reached that height and that
  hash. Then the roles were reversed, same tip.
- **Block relay, both directions, clearnet.** While one node mined
  at fixed difficulty 1, the other applied `NOTIFY_NEW_COMPACT_BLOCK`
  and the tips matched at height 80. Heights briefly differed and
  then matched again.
- **Timed ban.** `set_bans` of `127.0.0.1` for 3600 seconds closed
  both seam sockets with `LocalClose` and dropped both session
  counts to zero. `get_bans` reported `permanent: false` and about
  3598 seconds left. The next dials were `AdmissionRefused`.
- **Permanent ban file.** A ban file containing `127.0.0.1` loaded
  as `permanent: true` and `seconds: 0`. A second start with the
  same file loaded the same row. Dials were `AdmissionRefused`.
  No "Ban duration does not fit the clock" line.

## What did not

- **Transaction relay, both directions.** A transaction submitted
  on the seam node stayed in the seam pool. A second, submitted on
  the epee node, stayed in the epee pool. Each side logged
  `Unable to send transaction(s) via Dandelion++ stem`, then
  `Unable to send transaction(s), no available connections`. At
  those moments the relay counted `0` outbound connections with
  remote height at least the local height, after earlier moments
  in the same run had counted `1`. Session counts were still one
  in and one out. This is not on the harness expected-divergence
  list (`P2P_DIFFERENTIAL_HARNESS.md`).
- **An explicit `--in-peers 1` did not refuse at accept.** A second
  epee node connected. The seam inbound socket count rose past 1.
  An explicit inbound cap skips the process ceiling
  (`apply_inbound_ceiling` returns when the cap is explicit).
- **A derived ceiling of 0 refused the handshake and did not log a
  cause.** With no `--in-peers` and a descriptor soft limit of 64,
  the ceiling resolved to 0 (38 held, 112 reserved). Inbound stayed
  0. The epee handshake failed with
  `LEVIN_ERROR_CONNECTION_DESTROYED` before the handshake completed.
  No `seam close` line was written for that refusal. The seam's own
  outbound dial still completed.

## D12 causes that were logged

| When | Cause |
| --- | --- |
| Epee process stopped while the seam held both sockets | `PeerClosed` on each socket |
| Timed ban of the peer | `LocalClose` on each socket, then `AdmissionRefused` on the next dials |
| Ban file loaded, including after a restart | `AdmissionRefused` on dials |

## Epee-to-epee control

Same private testnet, same exclusive pair, same fixed difficulty,
one node mining, then a spend. Both processes were the epee pin
`d09bf3ef0` with one addition: an empty relay walk logs every
candidate's direction, state, recorded height, the local height,
and which message last wrote the recorded height.

At the send the origin's local height was 85 and the filter
threshold was 85. It had two candidates, one inbound and one
outbound, both `normal`. Each recorded height was 45, last written
by timed sync, so neither was eligible. The peer's walk was the
same shape, recorded height 46 against local height 85, also last
written by timed sync.

The stem send still completed. The peer added the transaction to
its pool. Fluff on both nodes then logged `no available
connections`.

The peer's own local height was 85, because it had received those
blocks from the mining node, and it still recorded the mining node
at 46, last written by timed sync. Receiving a block does not
update the sender's recorded height. On a two-node network fluff
had nobody else to send to: fluff skips the source, and the source
was the only other session. Fluff does not read recorded height.
This branch raises the sender's recorded chain length when the
block is accepted, and relay eligibility is the session's normal
state rather than that height.

The seam-versus-epee run failed earlier than this. That run logged
`Unable to send transaction(s) via Dandelion++ stem` and the
transaction stayed in the origin pool. Two epee nodes, with the
filter in the same empty state, still stemmed. The stem failure is
the send, not the choice of peer. The failing send now logs the
connection id, its zone and direction, whether the registry held
it, and the seam's return and cause.

## Rerun on the current branch, same day

The daemon binary contains the accepted-block height raise, the
`state_normal` eligibility rule, the accept-time inbound cap, and
the seam send log. `--version` still prints `v3.1.0-c05ca6808`
because CMake stamped it at configure time. The epee peer is still
`d09bf3ef0`, so it still filters stems by recorded height.

Unit tests, built here with `BUILD_TESTS=ON`:

- `relay_peer.an_accepted_block_raises_recorded_height_and_never_lowers_it` passed.
- The five `node_server.in_peers_*` tests passed, including a cap
  above the derived ceiling refusing startup and `--in-peers 0`
  staying 0.
- `seam_endpoint.a_relay_send_on_the_strand_reaches_the_seam_connection`
  failed on this run. Both payloads were shorter than a Levin
  header, so the hit returned before `do_send`. The nil-uuid miss
  returned 0 from the Levin connection map and never asked the seam.
  The test now sends a real `bucket_head2`, and the miss is an id
  the hub does not hold, asserted with the seam's `found` flag.

Daemon admission, private loopback:

- `--in-peers 1000000` exited with `Inbound cap 1000000 for public
  exceeds the descriptor ceiling 524238; refusing to start.`
- `--in-peers 1` with two epee dialers kept one inbound session.
  The second dial logged `seam accept refused cause AdmissionRefused`.
- A descriptor soft limit of 64 derived a ceiling of 0 (24 held,
  112 reserved, the second figure after the Tor reservation).
  The inbound count stayed 0. The dialer's handshake failed with
  `LEVIN_ERROR_CONNECTION` and the seam logged `AdmissionRefused`.

Stem, seam origin, heights matched near 112:

- The seam logged `Found 1 out connections in normal state` and
  `Sent 1 transaction(s)` on a stem. No `seam send refused`.
- The epee peer logged `Including transaction` for that same
  transaction. Both pools were empty afterward because the miner
  included it.
- Fluff on both sides then logged `no available connections`. On
  two nodes the only other session is the source, which fluff skips.
- The epee peer's own walk at that moment still had both sessions
  `normal` and ineligible: recorded height 69 against local height
  118, last written by timed sync and by chain entry. It stemmed
  anyway, from a map built earlier, and the seam included the
  transaction again.

A second submit, originated on the epee peer a few seconds later,
stayed in the epee pool. That walk logged `candidates=0` and
`Unable to send transaction(s) via Dandelion++ stem`. The link had
just re-handshaked. That failure is an empty epee walk, not a seam
refusal.

## The option on, same day

Two cutover daemons on loopback with `--clearnet-transport-encrypt`
at both ends never established a channel. Every dial logged
`TransportHandshakeFailed` within about 70 µs of the TCP connect, at
both ends, with no `PrefixMismatch`. That is faster than the
handshake's cryptography, so the refusal came before any byte.

The zone host stored the timing engine's handle and dropped the
`EngineService` when its constructor returned. The service's `Drop`
sets the closed flag every handle shares, so each `register` for a
transport deadline returned `Closed`, which the connectors report as
`TransportHandshakeFailed`. The plaintext path arms no deadline and
never saw it; the Tor dial clock and gap timer arm one and would
have failed the same way. The host now owns the service and stops it
in `shekyl_zone_shutdown`, engine first, then the pool, then the
join. `the_engine_outlives_ensure` fails on the old shape.

After the fix the pair established on the first dial. The connectors
now log each span, in nanoseconds, one line per connection: the
clearnet TCP connect, the handshake by role and kind, the responder's
blocking-pool queue wait and compute time, the Tor SOCKS dial, and
the Tor channel-to-session gap. The clearnet gap is the interval from
`NEW CONNECTION` to `CONNECTION HANDSHAKED OK` in the C++ log. These
loopback figures are a smoke of the lines, not a link: initiator
handshake 1.54 ms, responder queue 106 µs and compute 363 µs, Levin
gap 43 ms. The deadline pin is the commit that carries the spans.

## Tor, same day

The first Tor connection on this branch was between an x86_64 daemon
here and an off-site daemon on a Foundation seed host, both on the
cutover pin. The seed side published a managed onion with
proof-of-work through the pinned `15.0.19` Tor. The dialing side ran
the same pinned Tor itself with a fixed SocksPort and `--tx-proxy`,
because `--add-exclusive-node <onion>` creates the tor zone at option
parse and `handle_command_line` refuses it before the managed Tor
could have supplied its SOCKS address. That is a composition gap in
the default posture, noted here and not fixed in this run.

Two defects, found in that order:

- **Every Tor dial was `DialFailed` about 100 µs in.** The zone host
  learned the SOCKS address only through `listen_tor`, which `init`
  calls for a tor zone that binds. An outbound-only `--tx-proxy tor`
  zone never bound, so the host had no proxy, and its dialed
  connections had no tor binding to post to. `init` now installs both
  for that zone.
- **Bytes into the seed's Tor forward listener vanished.** The onion
  connection logged `NEW CONNECTION`, then nothing until
  `LevinHandshakeTimeout` at +5 s. Raw bytes sent straight into the
  forward listener on the seed's own loopback did the same, so the Tor
  network was not the cause. `Deliver` and `Closed` posts carried a
  null `observed`; the adapter routes by `observed->connector`, so
  both landed on the clearnet binding and were dropped. Every post
  now names its row's connector. This is the review's "Tor events
  lose socket binding after establishment".

After both, the dial connected in 3.93 s (SOCKS exchange, circuit,
rendezvous; `proxy_connect_ns` 125 µs of that), the Levin handshake
completed, and the gap was 597 ms outbound and 649 ms on the seed.
Timed syncs followed. One sample, not a distribution.

The floor device runs the pinned aarch64 `16.0a12` Tor beside its
daemon and publishes a proof-of-work onion through it.

A third defect surfaced when the floor device dialed the seed while
the x86_64 session was still up: every new inbound connection on the
seed logged `NEW CONNECTION` and went deaf. `drive_inbound` held a
blocking thread for the life of a connection and the zone hands its
runtime one blocking lane, so a daemon read from one connection at a
time and every later one waited in the pool's queue until the first
closed. The inbound drive is a task now, awaiting the strand on a
`Notify`; `two_connections_deliver_on_one_blocking_lane` pins it.
After that the seed carried the x86_64 session and the floor's dials
together.

## Tor dial distribution, floor device (2026-09-29)

Raw samples: [`p2p_tor_dial_floor_20260929.tsv`](p2p_tor_dial_floor_20260929.tsv).

Conditions, per D9:

- Dialer: the floor device (Pi 4 Model B, aarch64, 4 cores), daemon
  `572ed17c3`, the pinned `16.0a12` Tor (`0.4.9.12`) run beside it
  with a fixed SocksPort and `--tx-proxy`, because a named onion peer
  cannot yet be dialed under the managed posture (above). The client
  Tor was restarted between samples, so each dial built its circuits
  fresh; bootstrap from a cached consensus took 3–5 s and is not in
  any span. The RandomX miner was off. Nothing else ran on the device.
- Service: an off-site Foundation seed host (x86_64, 4 cores), daemon
  `a764f5a76`, managed ephemeral onion published through the pinned
  `15.0.19` Tor (`0.4.9.11`) with proof-of-work on. One other Tor
  session was live on it throughout.
- Link: the Tor network, from a LAN client to a host in South America.
  Clearnet RTT between the two sites is about 170 ms; the Tor path is
  whatever the circuits were.
- n = 100, no timeouts. Samples 1–19 and 20–100 were one run.

| span | p50 | p90 | p99 | max | 2 × p99 |
| --- | --- | --- | --- | --- | --- |
| Tor dial (`dial_ns`: SOCKS exchange, circuit, rendezvous) | 1.84 s | 3.40 s | 4.54 s | 4.76 s | **9.1 s** |
| loopback connect to the SOCKS port (`proxy_connect_ns`) | 0.4 ms | 0.5 ms | 0.5 ms | 0.5 ms | — |
| channel to session (`gap_ns`, outbound side) | 626 ms | 827 ms | 1.26 s | 1.32 s | **2.6 s** |

p99 is the 99th of the 100 sorted samples (4.537 s and 1.260 s), one
sample from each max. Twice each is 9.07 s and 2.52 s, rounded up to
9.1 s and 2.6 s per D9. The placeholder both clocks run on today is
the Levin invoke timeout, 5 s. This run's slowest dial cleared it by
240 ms. A later run under these conditions whose p99 exceeds 4.55 s
or 1.30 s reopens the respective deadline. Neither is wired yet, and
the clearnet distributions are owed before the deadline commit.

The inbound drive's wake was per hub when these samples were taken:
every strand answer woke every waiting driver. One other session was
live, so the herd here was two. The wake is per row from `212c3260e`.

## Clearnet LAN distribution, floor device responder (2026-09-30 UTC)

Raw samples:
[`p2p_clearnet_lan_floor_responder_20260930.tsv`](p2p_clearnet_lan_floor_responder_20260930.tsv).

Conditions, per D9:

- Dialer: this build host (x86_64), daemon `1485e5ae3`, one outbound
  to the floor device and nothing else; `--clearnet-transport-encrypt`
  on, ephemeral Tor off, no miner.
- Responder: the floor device (Pi 4 Model B, aarch64, 4 cores), daemon
  `1485e5ae3`, `--clearnet-transport-encrypt` on, ephemeral Tor off,
  inbound cap 16, one inbound live at a time. Sharing its four cores:
  one idle regtest daemon from an unrelated lane, nothing else. The
  RandomX miner was off; the mining floor device is its own record.
- Link: one LAN segment, 0.2 ms RTT.
- Method: each sample is a fresh TCP connection and a fresh NNhfs
  handshake. The dialer's outbound cap was set to 0 and back to 12 over
  RPC; the drop closes the session, and the exclusive-peer redial runs
  on the next 1 s tick with no cap or recently-failed gate. Spans are
  matched to their connection id on the side that logged them. The
  spans are the connector's own (`shekyl_clearnet::drive`), except the
  gap, which is the dialer's `NEW CONNECTION` to `CONNECTION HANDSHAKED
  OK`.
- n = 100, no timeouts.

| span | p50 | p90 | p99 | max | 2 × p99 |
| --- | --- | --- | --- | --- | --- |
| TCP connect (`connect_ns`, dialer) | 0.31 ms | 0.38 ms | 0.76 ms | 0.97 ms | 1.6 ms |
| initiator handshake (`handshake_ns`, dialer: first write to session) | 3.72 ms | 4.17 ms | 7.15 ms | 7.23 ms | **14.3 ms** |
| responder queue wait (`queue_ns`, floor: handshake job queued to started) | 51 µs | 66 µs | 95 µs | 119 µs | 0.2 ms |
| responder compute (`compute_ns`, floor: the NNhfs arithmetic) | 2.17 ms | 2.23 ms | 2.31 ms | 2.37 ms | 4.7 ms |
| responder handshake (`handshake_ns`, floor: first read to session) | 2.73 ms | 2.98 ms | 5.54 ms | 6.23 ms | **11.1 ms** |
| channel to session (`gap_ns`, dialer) | 1.85 ms | 2.27 ms | 5.31 ms | 8.32 ms | **10.7 ms** |

p99 is the 99th of the 100 sorted samples; precision 0.1 ms; 2 × p99
rounded up per D9. Two things this distribution bounds and one it does
not:

- The floor device's responder cost is 2.2 ms of arithmetic with a
  99th percentile 0.14 ms above the median, and a queue wait under
  0.1 ms with one handshake at a time. The tail on the handshake spans
  is not the arithmetic: on samples 55, 58 and 91 the initiator's span
  and the responder's span are long together (6.1–7.1 ms and 5.1–6.2
  ms) while `compute_ns` stays at 2.2 ms, so the wait is around the
  compute — the job's dispatch or the socket — not in it; on sample 56
  the initiator's span is the max (7.2 ms) with the responder's at its
  median, a wait on the dialer's side alone.
- The gap's max (8.3 ms, sample 58) is the same sample. The gap p99
  here is 5.3 ms against 1.26 s on Tor; the gap deadline stays owned
  by the Tor distribution.
- The TCP connect is the LAN's. A connect deadline derived from 0.76
  ms would refuse every peer past the first router. The clearnet
  connect and initiator-handshake deadlines are owed to the off-site
  leg, whose RTT is about 170 ms; this record's 14.3 ms is the LAN
  bound on the handshake with the network term near zero.

A later run under these conditions whose p99 exceeds 7.15 ms
(initiator), 5.55 ms (responder) or 5.32 ms (gap) reopens the
respective figure.

### The defect this leg found

The first attempt at this distribution ran at `a6af6b5ba` with the
churn on the responder's side (`in_peers 0`, then 16) and produced one
sample per 60 s. The acceptor logged `LocalClose` and `CLOSE
CONNECTION` at once; the dialer's log was silent until its own
timed-sync 54 s later, and `PeerClosed` landed 0.6 ms after that send.
The responder's local close never reached the wire: `Hub::record`
posted `Closed` and released the admission slot, but the `Session`
whose drop closes the outbound queue was parked in the inbound drive
waiting on the peer, and `ZoneDial` has no `reader_stopped`. The socket
stayed open until the peer wrote. A peer that never writes would have
held it for good — a ban, a protocol refusal, `del_in_connections`,
all of them silent on the wire.

Fixed in `1485e5ae3` (`SendHalf::close`; `record` closes the row's
send half). Verified on this pair before the sweep: `in_peers 0` on
the floor, `LocalClose` there and `PeerClosed` on the dialer within
1 ms of each other. Unit test `a_local_close_ends_the_writer` is red on
the previous shape.

## Clearnet LAN distribution, floor device initiator (2026-09-30 UTC)

Two runs, recorded side by side, not merged. Raw samples:
[`p2p_clearnet_lan_floor_initiator_run1_20260930.tsv`](p2p_clearnet_lan_floor_initiator_run1_20260930.tsv),
[`p2p_clearnet_lan_floor_initiator_run2_20260930.tsv`](p2p_clearnet_lan_floor_initiator_run2_20260930.tsv).

Conditions, per D9:

- Dialer: the floor device (Pi 4 Model B, aarch64, 4 cores), daemon
  `1485e5ae3` in run 1 and `54ba2b6cd` in run 2 (the second adds the
  initiator's pre-write spans; no behaviour change), one outbound and
  nothing else; `--clearnet-transport-encrypt` on, ephemeral Tor off.
  The RandomX miner was off. Sharing its four cores: the same idle
  regtest daemon as the responder leg.
- Responder: a LAN VM (x86_64, 8 cores), the portable daemon at
  `1485e5ae3`, inbound cap 16, one inbound live at a time. It is not a
  quiet host: it shared its cores with a testnet miner of an unrelated
  lane at about 3.4 cores throughout, and its load average rose from
  5 to 8.5 across the two runs. It was the only LAN acceptor available
  — this build host's firewall admits ssh only and there is no
  privilege here to open a port, and the other VM carries the same
  miner. The floor device's own spans are what this leg is for; the
  responder's tails are the VM's and are attributed as such below.
- Link: one LAN segment, 0.2 ms RTT.
- Method: as the responder leg — dialer-side `out_peers` churn, spans
  matched by connection id.
- n = 100 each, no timeouts.

Run 1 (`1485e5ae3`):

| span | p50 | p90 | p99 | max | 2 × p99 |
| --- | --- | --- | --- | --- | --- |
| TCP connect (`connect_ns`, floor) | 0.54 ms | 0.72 ms | 0.88 ms | 0.99 ms | 1.8 ms |
| initiator handshake (`handshake_ns`, floor) | 3.40 ms | 4.51 ms | 109 ms | 4.30 s | — (VM's, see below) |
| responder queue wait (`queue_ns`, VM) | 74 µs | 145 µs | 344 µs | 561 µs | — |
| responder compute (`compute_ns`, VM) | 0.66 ms | 0.86 ms | 1.24 ms | 1.43 ms | — |
| responder handshake (`handshake_ns`, VM) | 1.84 ms | 2.52 ms | 79 ms | 108 ms | — |
| channel to session (`gap_ns`, floor) | 2.49 ms | 3.18 ms | 4.30 ms | 74 ms | 8.6 ms |

Run 2 (`54ba2b6cd`), the floor's three waits before message 1 added:

| span | p50 | p90 | p99 | max | 2 × p99 |
| --- | --- | --- | --- | --- | --- |
| TCP connect (`connect_ns`, floor) | 0.49 ms | 0.64 ms | 0.84 ms | 0.88 ms | 1.7 ms |
| initiator blocking-lane wait (`queue_ns`, floor) | 54 µs | 99 µs | 357 µs | 1.41 ms | 0.8 ms |
| initiator compute (`compute_ns`, floor: keygen and message 1) | 0.40 ms | 0.91 ms | 1.04 ms | 1.15 ms | 2.1 ms |
| initiator write under the up gate (`write_ns`, floor) | 89 µs | 141 µs | 210 µs | 239 µs | 0.5 ms |
| initiator handshake (`handshake_ns`, floor) | 3.42 ms | 4.45 ms | 715 ms | 4.19 s | — (VM's, see below) |
| responder queue wait (`queue_ns`, VM) | 81 µs | 155 µs | 310 µs | 887 µs | — |
| responder compute (`compute_ns`, VM) | 0.66 ms | 0.84 ms | 1.12 ms | 2.02 ms | — |
| responder handshake (`handshake_ns`, VM) | 1.76 ms | 2.68 ms | 35 ms | 4.18 s | — |
| channel to session (`gap_ns`, floor) | 2.44 ms | 3.49 ms | 34 ms | 111 ms | — (VM's) |

Precision 0.1 ms. What the two runs establish:

- The floor device as initiator is tight where it can be measured on
  its own. Across 200 handshakes its TCP connect p99 is under 0.9 ms
  and, in the 100 that have them, its lane wait, compute and write are
  each under 1.5 ms at their max, with no sample of the pre-write path
  above that. The 0.40 ms is the initiator's first job only (what it
  needs to send message 1); its second job, on message 2, is not
  spanned, so it is not compared with the responder's 2.17 ms from
  the previous section.
- Every tail above 20 ms is the VM's. Run 1 samples 24, 91, 95 and run
  2 samples 28 and 59 are long on both sides with the VM's compute at
  0.6–0.8 ms: a wait around the compute on the loaded host, not in it.
  Run 2 sample 59 (4.19 s, both sides) puts the wait between the VM
  accepting the socket and reading message 1 — the floor's own
  pre-write spans on that sample are 52 µs, 0.98 ms, 97 µs.
- Run 1 sample 41 (4.30 s on the floor, 1.3 ms on the VM) was read at
  the time as a floor-side stall. Run 2 refutes the reading: the VM's
  span starts when its accept path starts, and on a starved host that
  is late, so a short VM span with a long floor span is the same VM
  wait with the clock started after it. The pre-write spans were added
  because run 1 could not tell these apart; run 2 can, and found no
  floor-side stall in 100.
- Run 2 sample 46 (715 ms on the floor, 1.76 ms on the VM, floor
  pre-write spans normal) is the one sample neither side's spans
  attribute: the VM's responder span ends before its writer puts
  message 2 on the wire, and the floor has no span on its message-2
  read and second job. On a host at load 8.5 the VM's writer is the
  likelier; it is not shown. A span on the responder's message-2
  write would close this and is owed with the deadline commit.
- The initiator-handshake and gap p99s in this leg are the VM's
  scheduling and derive nothing. The floor's initiator handshake under
  a quiet responder is the previous section's 7.15 ms read from the
  other end; its connect and handshake deadlines are owed to the
  off-site leg.

A later run under these conditions whose p99 exceeds 0.88 ms (connect),
0.36 ms (lane), 1.04 ms (compute) or 0.21 ms (write) on the floor
device reopens the respective figure (p99s 0.877, 0.357, 1.037 and
0.210 ms, rounded up at 0.01 ms).

## Not this run

Tor relay and the floor device's inbound Tor distribution were not
run. The off-site clearnet leg and the thread-budget legs are not in
this record. The off-site clearnet leg waits on a firewall rule for
the seed-side daemon's private port.
