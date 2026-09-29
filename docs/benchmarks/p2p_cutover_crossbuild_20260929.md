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
daemon and publishes a proof-of-work onion through it. Its Tor dial
and inbound distributions are the next records.

## Not this run

Tor relay was not run. The floor-device deadline and thread-budget
distributions are not in this record. The off-site clearnet leg waits
on a firewall rule for the seed-side daemon's private port.
