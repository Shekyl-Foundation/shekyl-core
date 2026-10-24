| Option | Kind | Default | Where | Runtime | Description |
|--------|------|---------|-------|---------|-------------|
| `help` | switch | — | command line | no | Print the options and exit. |
| `version` | switch | — | command line | no | Print the version and the operating system, and exit. |
| `network` | `mainnet` / `testnet` / `stagenet` / `regtest` | `mainnet` | command line | no | The network to run: mainnet, testnet, stagenet or regtest. Chooses the configuration file. |
| `config-file` | absolute path | /etc/shekyl/shekyld-<network>.toml on Linux, FreeBSD and macOS; the daemon's root and shekyld-<network>.toml on Windows | command line | no | The configuration file. A missing file at the default path means the defaults; a missing file at a named path is refused. |
| `data-dir` | absolute path | the daemon's root and the network's subdirectory | both | no | The data directory. An explicit path is used as given. |
| `log-file` | absolute path | the daemon's root, logs/shekyld-<network>.log | both | no | The log file. |
| `log-level` | `error` / `warn` / `info` / `debug` / `trace` | `warn` | both | yes | The log level: error, warn, info, debug or trace. |
| `log-category` | map to `error` / `warn` / `info` / `debug` / `trace` | `none` | both | yes | A log level for one subsystem, as subsystem=level; `none` is no overrides. |
| `log-size-max` | bytes, such as `512MiB` (at least 1) | `1GiB` | both | no | The disk the log may use, live file and archives together. |
| `clearnet` | `on` / `off` | `on` | both | no | The clearnet connector. |
| `tor` | `managed` / `operator` / `off` | `managed` | both | no | The Tor connector: a managed Tor, the operator's own Tor, or off. |
| `tor-socks` | IP endpoint (`address:port`) | — | both | no | The operator's Tor SOCKS endpoint; required with tor = operator. |
| `tor-socks-username` | secret (file only, never shown) | — | file | no | The SOCKS username for tor-socks. |
| `tor-socks-password` | secret (file only, never shown) | — | file | no | The SOCKS password for tor-socks. |
| `tor-onion` | v3 onion with a port | — | both | no | This node's onion service and virtual port, on the operator's Tor. |
| `tor-onion-listen` | IP endpoint (`address:port`) | — | both | no | The local endpoint the operator's Tor forwards tor-onion to; required with it. |
| `tor-file` | absolute path | tor/tor beside the executable, else the version-exact bundle directory under /opt/shekyl/ on Unix | both | no | The managed Tor binary; tor = managed only. It is verified against the pin wherever it is. |
| `clearnet-socks` | IP endpoint (`address:port`) | — | both | no | A SOCKS proxy for clearnet dials. |
| `clearnet-socks-username` | secret (file only, never shown) | — | file | no | The SOCKS username for clearnet-socks. |
| `clearnet-socks-password` | secret (file only, never shown) | — | file | no | The SOCKS password for clearnet-socks. |
| `clearnet-listen` | list of IP endpoint (`address:port`) (`none` for empty) | 0.0.0.0 and the network's p2p port | both | no | The clearnet listen endpoints; `none` is dial-only on clearnet. |
| `clearnet-advertise` | list of IP endpoint (`address:port`) (`none` for empty) | — | both | no | The clearnet endpoints peers can reach this node at; at most one per address family. |
| `p2p-local` | switch | — | both | no | Accept peers at private addresses, for a private test network. |
| `p2p-peer` | list of IP endpoint or v3 onion with a port (`none` for empty) | `none` | both | no | Peers to connect to, by IP or onion. |
| `p2p-closed-peer` | list of IP endpoint or v3 onion with a port (`none` for empty) | `none` | both | no | The only peers to connect to; non-empty declares a closed network. |
| `p2p-disclose-early` | switch | — | both | no | Disclose known peers and this node's address below the white-diversity floor, for bootstrapping a small network. |
| `p2p-ban-file` | absolute path | — | both | no | A file of addresses to refuse, one per line. |
| `p2p-upload-max` | rate, such as `1MiB/s` (at least 1), or `unlimited` | `unlimited` | both | yes | The upload rate limit, or `unlimited`. |
| `p2p-download-max` | rate, such as `1MiB/s` (at least 1), or `unlimited` | `unlimited` | both | yes | The download rate limit, or `unlimited`. |
| `txpool-weight-max` | bytes, such as `512MiB` (at least 1) | `648000000B` | both | no | The transaction pool's weight bound. |
| `notify-block` | command (an array of words; placeholders `{height}`, `{hash}`) | — | file | no | A command to run on a new block, with {height} and {hash}. |
| `notify-reorg` | command (an array of words; placeholders `{split-height}`, `{height}`, `{added}`, `{removed}`) | — | file | no | A command to run on a reorganization, with {split-height}, {height}, {added} and {removed}. |
| `notify-block-rate` | command (an array of words; placeholders `{window}`, `{observed}`, `{expected}`) | — | file | no | A command to run on a block-rate warning, with {window}, {observed} and {expected}. |
| `mine-address` | Shekyl address | — | both | no | Mine to this address from start. |
| `mine-threads` | integer ≥ 1, or `auto` | `auto` | both | no | The mining thread count, or `auto`. |
| `rpc-admin-listen` | list of IP endpoint (`address:port`) (`none` for empty) | 127.0.0.1 and the network's rpc port | both | no | The plaintext full-access listeners, loopback only; `none` is no admin listener. |
| `rpc-view-listen` | list of IP endpoint (`address:port`) (`none` for empty) | `none` | both | no | The plaintext view listeners, loopback only. |
| `rpc-cors-origin` | list of web origin (`none` for empty) | `none` | both | no | Web origins allowed to call the RPC; `none` denies all. `*` is refused. |
| `rpc-connections-max` | integer ≥ 1 | `25` | both | no | The RPC connection cap. |
| `console` | switch | — | command line | no | Run the interactive console. |
<!-- development rows, live on the named networks only and not in --help: dev-clearnet-encrypt (testnet, stagenet, regtest); dev-sync (regtest); dev-relay-cover (testnet, stagenet, regtest); dev-rpc (testnet, stagenet, regtest); dev-difficulty (regtest); dev-pow-seed-epoch-blocks (regtest); dev-pow-seed-epoch-lag (regtest); dev-settlement-epoch-blocks (regtest); dev-archival-reorg-depth (regtest) -->
