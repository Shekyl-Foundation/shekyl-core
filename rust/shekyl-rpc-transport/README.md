# Shekyl RPC transport

Two things, because they must not disagree:

1. **Client.** `shekyl-rpc-client`'s `Rpc` trait implemented over HTTP(S) — a
   small, pooled `hyper` client owned in `http_client` (re-absorbed from the
   vendored `simple-request`, which this crate was relocated from) with an
   **optional SOCKS5h** proxy connector. The proxy always resolves the daemon
   hostname remotely, so the local resolver never sees it. Requires tokio.
2. **Listen classification.** `listen` (`classify_listen`,
   `parse_listen_addr`) is the one classifier for every Shekyl RPC listener
   — wallet and daemon — so "wildcard" and "loopback" mean one thing,
   IPv4-mapped spellings included (`docs/design/RPC_TRANSPORT_POSTURE.md`
   RT-1, RT-2). The refusals themselves stay with each listener.
