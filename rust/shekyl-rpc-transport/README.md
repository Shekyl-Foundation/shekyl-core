# Shekyl RPC transport

Three things, because they must not disagree:

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
3. **"This computer".** `local` (`LocalTarget`) dials a run-as-me daemon's
   owner's leg, found by the daemon's own rendezvous naming
   (`shekyl-rpc-channel`'s `rendezvous`): the socket on Unix, the pipe a
   rendezvous record names on Windows, one connection per call. "Not
   running" and a failed peer check are distinct failures (`LocalFault`);
   the peer check's is a security failure and is never retried
   (`docs/design/RPC_CHANNEL.md` RT-15, §7.1). The local legs' HTTP
   exchange lives here once, for every client. The account's root and the
   Unix peer's account come from `shekyl-os-account`, the leaf with no
   network stack that the daemon's process crate reads the same root from.
