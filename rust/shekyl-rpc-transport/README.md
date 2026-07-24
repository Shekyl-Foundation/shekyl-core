# Shekyl RPC transport

`shekyl-rpc-client`'s `Rpc` trait implemented over HTTP(S) — a small, pooled
`hyper` client owned in `http_client` (re-absorbed from the vendored
`simple-request`, which this crate was relocated from) with an **optional
SOCKS5h** proxy connector. The proxy always resolves the daemon hostname
remotely, so the local resolver never sees it. Requires tokio.
