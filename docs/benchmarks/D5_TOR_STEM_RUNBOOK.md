# D-5 Tor stem runbook

The command sequence for the rerun that records #924. The previous hop,
and why its two "not measured" reasons were a misread, is
[`p2p_cutover_crossbuild_20260929.md`](p2p_cutover_crossbuild_20260929.md)
under "The hop, same day". This file is that run as steps, plus the
fluff the two-node hop could not show.

Written against `5a1a405ae`. Not yet run at that commit. Until it is,
#924 is complete in the tree and incomplete in the record.

## What this run records

Two facts, both on measurement daemons built from the same commit:

1. **Stem.** The seed's measurement daemon originates one transaction.
   The floor's measurement daemon receives it over Tor. The hop is the
   interval from the seed's `Sent 1 transaction(s) … using Dandelion++
   stem` to the floor's `Including transaction` for that txid. The
   previous hop was 658 ms of that interval and 1.36 s from
   `Including transaction` to `Transaction added to pool`. One sample
   does not replace the 1 625 ms transit assumption
   (`DAEMON_RELAY_PRIVACY.md` D-5). Record the txid, both timestamps,
   and, when the log names them, the input count and the tree depth.
2. **Fluff.** An inbound-only Tor peer, a third measurement daemon,
   receives that transaction as fluff. The previous hop queued fluff
   and logged `Unable to send transaction(s) via Dandelion++ stem`
   because a two-node stem has no further outbound. That line on this
   run, with the third peer silent, means the fluff leg failed.

## Who is not in the topology

The seed's production daemon and the floor's standing regtest stay up
and are not peers. Their handshake id is the pre-derivation constant.
This build's id is the first 16 bytes of
`cSHAKE256(shekyl/p2p-network-id-v1, genesis_block_hash)`, so the
prefix differs at byte 8 and the handshake stops there. Do not dial
them, do not point `mine start` or `send` at their RPC, and do not
reuse their data directory.

## Binaries

Every measurement `shekyld` is `5a1a405ae`. `shekyld --version` on each
one names that commit before anything dials.

The floor binary is aarch64, built on the floor. The x86 worktree
binary does not run there. An x86 measurement daemon built from this
worktree is configured and built against that worktree's build
directory by absolute path (`cmake --build <worktree>/build`), not
`cmake --build build` from a shell whose current directory might be
another checkout.

## The three processes

Fresh data directories. `--regtest --fixed-difficulty 1`. RPC bound to
loopback. Log level includes the `MDEBUG` lines the previous hop was
read from (`Sent … using Dandelion++ stem`, `Queueing … for Dandelion++
fluffing`).

**Miner (seed).** Mines the chain. Its only dial is the floor's
per-boot onion, through the warm client Tor that is already up. Do not
restart that Tor: a restart drops the cached descriptor, which is the
failure the inbound distribution fixed by keeping the Tor warm and
restarting the daemon instead. `--add-exclusive-node` is that onion.
`--tx-proxy` names that Tor's SOCKS address. A count on `--tx-proxy`,
if one is written, is at least 12; a smaller count refuses startup.
The count is a cap, not the number of peers this run dials — the
exclusive node is the one dial.

**Stem receiver (floor).** Default ephemeral per-boot onion: no
`--anonymous-inbound`, no `--no-ephemeral-tor`. Miner off on this
process. Read the onion from its log once it is published.

**Fluff receiver.** Same commit, same chain, `--out-peers 0`, its own
per-boot onion. It dials nothing. The floor dials that onion, so the
stem receiver has an outbound that is not the stem's source.

On this commit a Tor session syncs. The previous hop also opened
clearnet, because a non-public handshake then returned before asking
for the chain. That return was deleted (`aebe4c5cc`). If a peer is
still at height 1 after the Tor handshake, stop: the session did not
sync, and a clearnet side path is a finding, not the next step.

## Sequence

1. Start the miner. From a wallet opened against its RPC, `shekyl-cli
   mine start`. The daemon is `--regtest`; the wallet is that network.
   The retired spelling `start_mining` redirects to `mine start`.
   Confirm the height is moving.
2. Start the floor receiver. Copy its per-boot onion.
3. Start the fluff receiver. Copy its per-boot onion. Confirm it has
   no outbound session.
4. Point the floor at the fluff receiver's onion
   (`--add-exclusive-node` of that onion, through the floor's Tor).
   Confirm the fluff receiver's only session is inbound.
5. Point the miner at the floor's onion and dial. Confirm one
   outbound on the miner and the matching inbound on the floor. Leave
   that session up. The previous attempt's 39 s one-sided `PeerClosed`
   was the sampler restarting the dialer; a session left up did not
   repeat it. No `seam close` on either end from here through the hop.
6. Confirm the three heights match. The miner is the chain they match.
7. From that same wallet, `shekyl-cli send` one spend. The retired
   spelling `transfer` redirects to `send`.
8. Read the logs for that txid.

| Where | Line | What it means |
| --- | --- | --- |
| Miner | `Sent 1 transaction(s) … using Dandelion++ stem` | Stem left. Timestamp is the start of the hop. |
| Floor | `Including transaction` | Stem arrived. Timestamp minus the line above is the hop. |
| Floor | `Transaction added to pool` | Node-local interval, from `Including transaction`. |
| Floor | `Queueing … transaction(s) for Dandelion++ fluffing` | Fluff was queued. |
| Fluff receiver | `Including transaction`, then `Transaction added to pool` | The inbound-only peer received the fluff. It must not have logged `Sent … using Dandelion++ stem` for this txid. |
| Floor | `Unable to send transaction(s) via Dandelion++ stem` | The two-node outcome. With the fluff receiver up, this line means the fluff had no session to use. |

9. Stop the three measurement processes. Leave the standing daemons
   as they were found.
