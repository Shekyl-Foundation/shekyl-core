# LV-3 step c clearnet pair, 2026-10-04

Record for PR #950. Binary `v3.1.0-aa2588032` on both stakers. Testnet,
each with its own data directory, `--in-peers 8`, `--log-level 2`, and
`--add-exclusive-node` naming only the other. RPC stayed on loopback.
Nothing else was dialed.

## Handshake

Started 2026-10-04 23:45Z. Within two seconds each side held one
outbound session and one inbound session. `print_cn` showed both
`normal`, the outbound row aimed at the peer's testnet p2p port and
the inbound row at the peer's ephemeral port.

The same two rows were still `normal` at 2026-10-05 00:49Z, livetime
3794 s on the main staker and 3795 s on the staging staker.

Handshake lines, peer address replaced by the role:

Main staker:

```text
2026-10-04T23:45:43.642666Z INFO  [the staging staker OUT] NEW CONNECTION
2026-10-04T23:45:43.648653Z INFO  [the staging staker OUT] New connection handshaked
2026-10-04T23:45:43.648947Z DEBUG [the staging staker OUT] CONNECTION HANDSHAKED OK.
2026-10-04T23:45:44.495982Z INFO  [the staging staker INC] NEW CONNECTION
```

Staging staker:

```text
2026-10-04T23:45:43.642983Z INFO  [the main staker INC] NEW CONNECTION
2026-10-04T23:45:44.495936Z INFO  [the main staker OUT] NEW CONNECTION
2026-10-04T23:45:44.497875Z INFO  [the main staker OUT] New connection handshaked
2026-10-04T23:45:44.498222Z DEBUG [the main staker OUT] CONNECTION HANDSHAKED OK.
```

`New connection handshaked` is the outbound invoke completing. The
inbound row is the peer's dial; `print_cn` is what shows it `normal`.

Over the hour, counted from each log:

| | timed sync | idle handshake round | invoke timeout | `CONNECTION_DESTROYED` |
| --- | --- | --- | --- | --- |
| main staker | 127 | 64 | 0 | 0 |
| staging staker | 126 | 64 | 0 | 0 |

No `Timeout on invoke operation`. No `CONNECTION_DESTROYED` on a live
session.

## Shutdown

SIGTERM of the process that had held the sessions.

The main staker returned in 0.277 s. Both sessions closed from
`normal` with `LocalClose`:

```text
2026-10-05T00:49:10.138085Z INFO net: seam close id 1 cause LocalClose reply 0
2026-10-05T00:49:10.138229Z INFO net: seam close id 2 cause LocalClose reply 0
2026-10-05T00:49:10.138980Z INFO [INC] state: closed in state normal
2026-10-05T00:49:10.139177Z INFO [OUT] state: closed in state normal
2026-10-05T00:49:10.138714Z INFO global: Node stopped.
```

The staging staker saw that stop as `PeerClosed` on both sessions,
still from `normal`, and logged neither an invoke timeout nor
`CONNECTION_DESTROYED`. Its own SIGTERM returned in 0.180 s
(2026-10-05 00:50:01Z, `Node stopped`). No 60-second destructor stall
on either side.

## `--out-peers 1`

The main staker was started again with `--out-peers 1`, exclusive to
the staging staker, plus a second exclusive node that does not exist
(an address in TEST-NET-1). Startup refused before any dial:

```text
ERROR net::p2p: Outbound connection cap 1 is below the floor of 12 that the relay embargo derivation assumes (F-8b); refusing to start under-provisioned. Omit the option for the default (12) or give a value >= 12.
ERROR daemon: Exception in main! Failed to initialize p2p server.
```

The recount-versus-stale-zero comparison was not observed. The process
never reached the dial cap.
