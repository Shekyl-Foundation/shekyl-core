# D-5 Tor stem runbook

The command sequence for the rerun that records #924. The previous hop,
and why its two "not measured" reasons were a misread, is
[`p2p_cutover_crossbuild_20260929.md`](p2p_cutover_crossbuild_20260929.md)
under "The hop, same day". This file is that run as steps, plus the
fluff the two-node hop could not show.

The head the binaries are built from is the derivation commit
`5a1a405ae`: the handshake id is
`cSHAKE256(shekyl/p2p-network-id-v1, genesis_block_hash)`, not the
hand-pinned bytes `23ca43d2f` moved. The run records that head. It has
not been run. Until it has, #924 is complete in the tree and incomplete
in the record.

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

Two binaries, both `5a1a405ae`. A later commit on this branch
handshakes with either, because the id is a function of the genesis
hash. The record's binaries are this commit. Each measurement
`shekyld --version` names it before anything dials.

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

1. Confirm the floor binary and the seed binary both name `5a1a405ae`.
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
| Floor | `Including transaction` | Stem arrived. Timestamp minus the line above is the hop. |
| Floor | `Transaction added to pool` | Node-local interval, from `Including transaction`. |
| Floor | `Queueing … transaction(s) for Dandelion++ fluffing` | Fluff was queued. |
| Fluff receiver | its pool shows the txid | The inbound-only peer admitted the fluff, after step 6. It must not have logged `Sent … using Dandelion++ stem` for this txid. |
| Floor | `Unable to send transaction(s) via Dandelion++ stem` | The two-node outcome. With the fluff receiver up, this line means the fluff had no session to use. |

10. Stop the three measurement processes. Leave the standing daemons
    as they were found.
