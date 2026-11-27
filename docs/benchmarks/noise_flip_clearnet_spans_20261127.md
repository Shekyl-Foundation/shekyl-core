# Clearnet spans after the Noise flip, floor device on the LAN, 2026-11-27

**Status: MEASURED. The clearnet dial, handshake and gap deadlines
(`spans.rs`: 1.415 s, 1.426 s, 1.430 s) do not move.** This is the Noise
flip's deadline proof (shekyl-core #1560, Rick's brief of 2026-11-23): the
spans re-measured with every clearnet session encrypted, on the LAN, with
the floor device at one end. The per-dial spans are
[`noise_flip_clearnet_floor_initiator_lan_20261127.tsv`](noise_flip_clearnet_floor_initiator_lan_20261127.tsv).

## Why the deadlines can stand

The deadlines were derived in
[`p2p_cutover_crossbuild_20260929.md`](p2p_cutover_crossbuild_20260929.md)
from three paths (LAN, a datacenter, South America): one RTT per span with
slope about 1, a node-local residual, and the 700 ms ceiling. Every leg of
that derivation already ran with the record layer on
(`--clearnet-transport-encrypt`). The flip removes the option to run without
it; it does not change the handshake or the framing. So the question for
this proof is whether the node-local terms have moved since, on the device
the deadlines are provisioned at (rule 76).

## Conditions

- **Dialer:** the floor device (Pi 4 Model B, aarch64, 4 cores), a release
  `shekyld` at #1560's head `4a80affc9f`, regtest, Tor off, dial-only, one
  peer. Sharing its cores: its resident testnet daemon (alpha.12), running.
- **Responder:** a build VM (x86_64), the same head's release `shekyld`,
  regtest, Tor off, otherwise quiet.
- **Link:** one LAN segment. Ping RTT min/avg/max 0.300/0.408/0.622 ms before
  the run and 0.199/0.363/0.486 ms after (20 echoes each).
- **Method:** each sample is a fresh daemon start on the floor device, so a
  fresh TCP connection and a fresh NNhfs handshake. The spans are the
  connector's own lines (`shekyl_clearnet::drive`): `connect_ns` of
  "clearnet dial connected", `handshake_ns` of the initiator's "clearnet
  channel established", and the gap from that line to "clearnet handshake
  frame received; the gap ends", by the log's timestamps.
- n = 100, no timeouts, no dial failures. p99 is rank ⌈0.99 n⌉.

## Results

| span | p50 | p90 | p99 | max | 2 × p99 | deadline |
| --- | --- | --- | --- | --- | --- | --- |
| TCP connect (`connect_ns`) | 0.66 ms | 0.88 ms | 1.19 ms | 1.72 ms | 2.4 ms | 1.415 s |
| initiator handshake (`handshake_ns`) | 5.00 ms | 5.77 ms | 7.36 ms | 14.83 ms | 14.7 ms | 1.426 s |
| channel to session (gap) | 1.44 ms | 1.91 ms | 3.39 ms | 4.37 ms | 6.8 ms | 1.430 s |

The 2026-09-30 LAN leg had the floor device as the responder: connect p99
0.76 ms, initiator handshake p99 7.15 ms, gap p99 5.31 ms, at 0.2 ms RTT.
Here the floor device dials. Its handshake p99 (7.36 ms) is within 0.3 ms of
that leg's, and its median residual over the RTT is about 4.6 ms, under the
12.5 ms handshake term the derivation carries. The connect and gap
residuals are about 0.3 ms and 1 ms. No span moved a term of the derivation,
so the deadlines stay.

## What this does not say

- **The wide-area legs were not re-run.** Their RTT term is the path's, and
  the record layer was already on in them.
- **The floor device dialled; it was not also the responder here.** The
  2026-09-30 leg covers that direction with the record layer on.
- **The gap is from log timestamps**, microsecond resolution, on one clock.
