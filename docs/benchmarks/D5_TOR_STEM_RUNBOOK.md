# D-5 Tor stem runbook

The command sequence for the rerun that records #924. The previous hop,
and why its two "not measured" reasons were a misread, is
[`p2p_cutover_crossbuild_20260929.md`](p2p_cutover_crossbuild_20260929.md)
under "The hop, same day". This file is that run as steps, plus the
fluff the two-node hop could not show.

The handshake id is
`cSHAKE256(shekyl/p2p-network-id-v1, genesis_block_hash)`, derived in
`5a1a405ae`. The run that completed used `409762e06`, which deletes
the non-clearnet command allowlist on top of that derivation. The
attempt that stopped at step 6, and the run that finished it, are
the two sections at the end of this file.

## What this run records

1. **Stem.** The seed's measurement daemon originates one transaction.
   The floor's measurement daemon receives it over Tor. Three
   timestamps, same txid:
   - seed: `Sent 1 transaction(s) … using Dandelion++ stem`
   - floor: `Including transaction`
   - floor: `Transaction added to pool`

   The hop is the first interval. The previous hop was 658 ms, then
   1.36 s to the pool line. One sample does not replace the 1 625 ms
   transit assumption (`DAEMON_RELAY_PRIVACY.md` D-5). When the log
   names them, also record the input count and the tree depth.
2. **The third daemon syncs the mined chain over Tor.** It starts at
   height 1. Its height reaching the floor's, and the time that took,
   is a required step. The early return that used to skip chain sync
   on a non-public session is deleted on this head (`aebe4c5cc`), so
   this session is a sync path. If the height stays 1, the fluffed
   transaction cannot be admitted, the fluff observation cannot be
   made, and the run stops. That is a finding for the PR, not a reason
   to open a clearnet path to this daemon.
3. **Fluff.** After the floor fluffs, the third daemon's pool shows
   the transaction. The previous hop queued fluff and logged
   `Unable to send transaction(s) via Dandelion++ stem` because a
   two-node stem has no further outbound. That line on this run, with
   the third peer's pool empty, means the fluff leg failed.

## Who is not in the topology

The seed's production daemon and the floor's standing regtest stay up
and are not peers. Their handshake id is the pre-derivation constant,
so they fail this build at byte 8. That separation is the point: a
measurement daemon cannot accidentally peer with them. Do not dial
them, do not point `mine start` or `send` at their RPC, and do not
reuse their data directory.

## Binaries

Two binaries of the same commit. The completed run's binaries are
`409762e06`. A later commit on this branch handshakes with either,
because the id is a function of the genesis hash. Each measurement
`shekyld --version` names the commit before anything dials.

The floor binary is the aarch64 `shekyld` built on the floor. The seed
binary is a portable x86-64 build of the same commit (`ARCH=x86-64`,
the seed deploy). The September portable deploy carries the hand-pinned
id and does not handshake with the floor build, so the run uses the
redeploy. The x86 worktree binary is neither of these.

The miner and the fluff receiver are two processes of that seed
binary, separate data directories, on the seed host. The floor runs
the one aarch64 process.

## The three processes

Fresh data directories, not the standing ones. `--testnet
--fixed-difficulty 1`. Fakechain skips the ephemeral onion
(`add_ephemeral_tor_zone` returns before the tor starts), so a regtest
daemon cannot publish the address this run dials. Testnet is the
network the previous hop mined on, and this build's testnet id still
fails the handshake against a daemon on the hand-pinned id. RPC bound
to loopback. Log level includes the `MDEBUG` lines the previous hop
was read from (`Sent … using Dandelion++ stem`, `Queueing … for
Dandelion++ fluffing`).

**Miner (seed).** Mines the chain. Its only dial is the floor's
per-boot onion, through the warm client Tor that is already up. Do not
restart that Tor: a restart drops the cached descriptor, which is the
failure the inbound distribution fixed by keeping the Tor warm and
restarting the daemon instead. `--add-exclusive-node` is the floor's
onion and no other. `--tx-proxy` names that Tor's SOCKS address. A
count on `--tx-proxy`, if one is written, is at least 12; a smaller
count refuses startup. The count is a cap, not the number of peers
this run dials.

Both seed processes publish a per-boot onion through that one Tor.
The miner's dial list does not include the fluff receiver's onion. A
session from the miner to the receiver would be a second session on
the receiver, and its pool line would no longer be an inbound-Tor-only
observation.

The floor syncs that mined chain from the seed over clearnet, as the
previous hop did, so the Tor session below is not how the floor gets
the chain.

**Stem receiver (floor).** Default ephemeral per-boot onion: no
`--anonymous-inbound`, no `--no-ephemeral-tor`. Miner off on this
process. Read the onion from its log once it is published. Its
exclusive dial is the fluff receiver's onion — the `--out-peers 0`
process, read from that process's log — and it keeps that dial up
while the miner dials the floor.

**Fluff receiver.** The seed binary again, its own data directory,
`--out-peers 0`, its own per-boot onion on the same warm Tor. It dials
nothing. The floor is the process that dials this onion. The miner
does not. From the receiver's side that session is the only one, and
it is inbound Tor.

## Sequence

1. Confirm the floor binary and the seed binary both name the commit
   the run is recording. The completed run named `409762e06`.
   The fluff receiver is a second process of the seed binary.
2. Start the miner. From a wallet opened against its RPC, `shekyl-cli
   mine start`. The daemon is `--testnet`; the wallet is that network.
   The retired spelling `start_mining` redirects to `mine start`.
   Confirm the height is moving.
3. Start the floor. Copy its per-boot onion. Sync the miner's chain
   over clearnet. The floor's height matches the miner's before the
   third daemon is asked to sync.
4. Start the fluff receiver. It is at height 1. Copy the per-boot
   onion from this process's log, the `--out-peers 0` one. The miner's
   onion is a different address on the same Tor. Confirm the receiver
   has no outbound session.
5. The floor takes the fluff receiver's onion as an exclusive node and
   dials it. The miner's exclusive node stays the floor's onion. With
   the miner's dial of the floor also up, confirm the receiver's only
   session is the inbound Tor session from the floor, and that the
   miner has no session to the receiver.
6. **Required.** The fluff receiver's height reaches the floor's, over
   that Tor session. Record the time from the handshake to the matching
   height. If it does not, stop. The fluff observation cannot be made,
   and the PR has a finding.
7. Confirm the seed's Tor session to the floor is up and left up. The
   previous attempt's 39 s one-sided `PeerClosed` was the sampler
   restarting the dialer; a session left up did not repeat it. No
   `seam close` on either end from here through the hop.
8. From that same wallet, `shekyl-cli send` one spend. The retired
   spelling `transfer` redirects to `send`.
9. Read the logs for that txid.

| Where | Line | What it means |
| --- | --- | --- |
| Miner | `Sent 1 transaction(s) … using Dandelion++ stem` | Stem left. Timestamp is the start of the hop. |
| Floor | `Received NOTIFY_NEW_TRANSACTIONS` | Stem arrived. This tree has no `Including transaction` line. Timestamp minus the line above is the hop. |
| Floor | `Transaction added to pool` | Node-local interval, from `Including transaction`. |
| Floor | `Queueing … transaction(s) for Dandelion++ fluffing` | Fluff was queued. |
| Fluff receiver | its pool shows the txid | The inbound-only peer admitted the fluff, after step 6. It must not have logged `Sent … using Dandelion++ stem` for this txid. |
| Floor | `Unable to send transaction(s) via Dandelion++ stem` | The two-node outcome. With the fluff receiver up, this line means the fluff had no session to use. |

10. Stop the three measurement processes. Leave the standing daemons
    as they were found.

## Run, 2026-10-02 — step 6 did not complete

Both binaries were `5a1a405ae`. The daemons were `--testnet
--fixed-difficulty 1`. The miner and the fluff receiver were two
processes of the seed binary. The miner's only dial was the floor's
onion, through the warm Tor that was already up. The floor dialed the
fluff receiver's onion. The fluff receiver was `--out-peers 0`.

The floor's public clearnet port was not reachable, and the account
on that host cannot change the firewall. The floor's clearnet session
was a forward of the miner's loopback p2p port. On that session the
floor's height went from 1 to 87 in under a minute. That sync is not
a Tor sync.

The only Tor sync attempted was the receiver's, and it failed. The
floor log has no `session has no connector` and no `map::at`. At
18:28:24Z the floor logged `Filtered command (#1007)` and sent 0
bytes; the receiver's `portable_storage` then rejected that empty
body (`LEVIN_ERROR_FORMAT`), and its own chain request failed to
send (`Failed to request missing objects, dropping connection`).
From 18:20:23Z through 18:28:39Z the receiver's height stayed 1,
with one inbound Tor session and no outbound. The spend was not
sent. The stem timestamps and the fluff observation are owed after
the fix, on this same rig. The three measurement processes were
stopped. The standing daemons were left as they were found.

## Run, 2026-10-02 — the receiver synced over Tor

Both binaries were `409762e06`. Same flags as the attempt above
(`--testnet --fixed-difficulty 1`), except the floor used the default
posture: a named onion and no `--tx-proxy`, no `--anonymous-inbound`,
no `--no-ephemeral-tor`. It published its own per-boot onion and
dialed the receiver's. The miner dialed that onion through the warm
Tor (`--tx-proxy`, `--no-ephemeral-tor`) and did not dial the
receiver. The receiver was `--out-peers 0`. The seed ran one managed
Tor, the receiver's.

The floor's chain still arrived over a forward of the miner's
loopback p2p, height 1 to 84. That sync is not a Tor sync.

The first Tor sync is the receiver's. One attempt while the floor
was still at height 41 died (`LEVIN_ERROR_CONNECTION_DESTROYED` on
command 1007). The session that established once the floor was at
84 finished. At 19:42:22.165Z the receiver logged the session
(`outbound=false`) and remote height 84; command 1007 came back as
29 bytes, then the chain requests. At 19:42:43.331Z it logged
`Synced 84/84`. Wall time from the established session to height 84
is 21.2 s. The node's own add line for that span is 0.588 s at
5.10 blocks/s. One inbound Tor socket. The outbound count stayed 0
by accident: `--out-peers 0` does not bind the ephemeral Tor zone,
which installs the default outbound cap, and the one outbound dial
closed before its handshake.

The spend is
`0d9d8bc2713af9e80e1af31621ce7d2f77101927e5908caf0dee2a6c2f26e16c`,
weight 13235. The log has no `Including transaction` line; arrival
is `Received NOTIFY_NEW_TRANSACTIONS`.

| Where | When (UTC) | Line |
| --- | --- | --- |
| Miner | 19:46:06.954Z | `Sent 1 transaction(s) … using Dandelion++ stem` |
| Floor | 19:46:07.490Z | `Received NOTIFY_NEW_TRANSACTIONS (1 txes)`, inbound Tor |
| Floor | 19:46:07.870Z | `Transaction added to pool` |

The hop is 536 ms to the receive line and 916 ms to the pool line.
The receiver's pool showed the same txid at 19:46:09.864Z, on its
inbound Tor session (`NOTIFY_NEW_TRANSACTIONS` at 19:46:09.729Z).
The receiver logged no stem send for it. That floor log is level 1,
so it has no stem line and no fluff line. The same millisecond as
the pool add it sent command 2002 to its clearnet peer; 1.27 s
later it sent command 2002 to the receiver's onion.

A second spend on the same topology, with the floor at log level 2,
names the arm. Tx
`04e0bacb3f191edb9a2a89be5a90f036a5dd4f16bdccfcdea9ae03c3bb2609e8`.
At 19:58:23.167Z the floor logged `Sent 1 transaction(s) to
00000000-0000-0000-0700-000000000000 using Dandelion++ stem`, the
send that the traffic line shows going to the clearnet peer. At
19:58:23.787Z it logged `Queueing 1 transaction(s) for Dandelion++
fluffing`, and at 19:58:24.037Z it sent command 2002 to the
receiver's onion. The receiver admitted that notification inbound
at 19:58:24.609Z and added it to the pool at 19:58:24.662Z. The
inbound-only Tor peer received a fluff. The stem successor was the
clearnet peer, which is the miner, the transaction's origin. A stem
arriving at a node that already holds it in stem state is the loop
case, and the rule there is fluff now: the miner sent
`NOTIFY_NEW_TRANSACTIONS` back, and the floor logged the fluff queue
at 19:58:23.787Z. The 620 ms from the stem line to that queue is one
clearnet round trip plus the miner's pool handling, not the floor's
embargo. That is what a three-node ring does when its only clearnet
edge points at the origin; a wider graph does not, and nothing about
the embargo should be derived from this interval.

The three measurement processes were stopped. The standing daemons
were left as they were found. One sample does not replace the
1 625 ms transit assumption.
