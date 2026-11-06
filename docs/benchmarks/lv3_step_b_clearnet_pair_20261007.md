# LV-3 step b clearnet pair, 2026-10-07

Record for the step-b walks. The binary is this branch built
`x86-64-v3`. Testnet, each host with its own data directory,
`--allow-local-ip`, `--no-igd`, `--log-level 2`, p2p on 18021, RPC on
loopback 18029, and `--add-exclusive-node` naming only the other.
Nothing else was dialed. The installed testnet daemon on each host
was left running on its own ports.

## Handshake

Started 2026-10-07 01:11Z. Within the same second each side held one
outbound session and one inbound session.

Main staker, peer address replaced by the role:

```text
2026-10-07T01:11:19.107314Z INFO  [the staging staker OUT] NEW CONNECTION
2026-10-07T01:11:19.112545Z INFO  [the staging staker OUT] New connection handshaked
2026-10-07T01:11:19.112953Z DEBUG [the staging staker OUT] CONNECTION HANDSHAKED OK.
2026-10-07T01:11:19.670597Z INFO  [the staging staker INC] NEW CONNECTION
```

Staging staker:

```text
2026-10-07T01:11:19.095242Z INFO  [the main staker INC] NEW CONNECTION
2026-10-07T01:11:19.658143Z INFO  [the main staker OUT] NEW CONNECTION
2026-10-07T01:11:19.660731Z INFO  [the main staker OUT] New connection handshaked
2026-10-07T01:11:19.660989Z DEBUG [the main staker OUT] CONNECTION HANDSHAKED OK.
```

`New connection handshaked` is the outbound invoke completing. The
inbound row is the peer's dial.

The idle handshake walk ran once a minute on each side
(`STARTED PEERLIST IDLE HANDSHAKE` / `FINISHED` at 01:12:10Z and
01:13:10Z on the main staker, and the same minute on the staging
staker). Timed sync then ran on both the inbound session and the
outbound session. No `Timeout on invoke`. No `CONNECTION_DESTROYED`.

## Shutdown

SIGTERM of both processes at 2026-10-07 01:14:09Z.

The main staker closed both sessions `LocalClose` and logged
`Node stopped` at 01:14:09.517Z. The staging staker saw `PeerClosed`
on both sessions and logged `Node stopped` at 01:14:09.872Z. Neither
side logged an invoke timeout or `CONNECTION_DESTROYED`. No
60-second destructor stall.
