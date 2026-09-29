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
had nobody else to send to anyway. On a larger network the same
lag leaves fluff with only the peers whose timed sync landed since
the last block. That is a relay-lane defect, recorded in
`FOLLOWUPS.md`, and it is not a cutover blocker: epee does it too.

The seam-versus-epee run failed earlier than this. That run logged
`Unable to send transaction(s) via Dandelion++ stem` and the
transaction stayed in the origin pool. Two epee nodes, with the
filter in the same empty state, still stemmed. The stem failure is
the send, not the choice of peer.

## Not this run

Tor dial and Tor relay were not run. This machine has no `tor`
binary. The floor-device deadline and thread-budget measurements
are not in this record.
