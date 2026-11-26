| Option | Kind | Default | Where | Runtime | Description |
|--------|------|---------|-------|---------|-------------|
| `help` | switch | — | command line | no | Print the options and exit. |
| `version` | switch | — | command line | no | Print the version and the operating system, and exit. |
| `rpc-key-create` | switch | — | command line | no | Make this tunnel's key at rpc-key-file, readable by this account alone, print its fingerprint for the node's `rpc client add`, and exit. Refused if a key is there. |
| `rpc-key-show` | switch | — | command line | no | Print this tunnel's fingerprint and exit. |
| `network` | `mainnet` / `testnet` / `stagenet` / `regtest` | `mainnet` | command line | no | The node's network: mainnet, testnet, stagenet or regtest. Chooses the configuration file. |
| `config-file` | absolute path | this account's root and shekyl-rpc-tunnel-<network>.toml | command line | no | The configuration file. A missing file at the default path means the defaults; a missing file at a named path is refused. |
| `daemon-endpoint` | IP endpoint or v3 onion with a port | — | both | no | The node's channel listener: an IP address and a port, or an onion and a port (reached through daemon-socks). Required. |
| `daemon-socks` | IP endpoint (`address:port`) | — | both | no | A SOCKS5 proxy to reach the node through; the proxy resolves its name. Required for an onion. |
| `daemon-bundle-file` | absolute path | — | both | no | The node's public bundle, as `rpc bundle show` prints it on that node. Required. |
| `rpc-key-file` | absolute path | this account's root and rpc-shekyl-rpc-tunnel-<network>.key | both | no | This tunnel's channel key, readable by this account alone (make it with rpc-key-create). |
| `rpc-grant` | list of `health` / `status` / `chain` / `pool` / `peers` / `submit` / `mining-work` / `mining-control` / `bans` / `node` / `config` / `enroll` / `view` / `wallet` / `miner` / `admin` (`none` for empty) | `view` | both | no | The grants the tunnel's sessions ask for, as grant and preset words, the option repeated. The node clamps it to this tunnel's ceiling; the tunnel reports what it received. |
| `listen` | IP endpoint (`address:port`) | — | both | no | The local listener consumers reach the node through: a loopback address and a port, never a wildcard (RT-14). Required unless listen-socket-file is set. |
| `listen-socket-file` | absolute path | — | both | no | A socket for local consumers, in a directory only this account can enter, in place of listen. Not on Windows. |
| `log-file` | absolute path | this account's root, logs/shekyl-rpc-tunnel-<network>.log | both | no | The log file. |
| `log-level` | `error` / `warn` / `info` / `debug` / `trace` | `warn` | both | no | The log level: error, warn, info, debug or trace. |
| `log-category` | map to `error` / `warn` / `info` / `debug` / `trace` | `none` | both | no | A log level for one subsystem, as subsystem=level; `none` is no overrides. |
| `log-size-max` | bytes, such as `512MiB` (at least 1) | `1GiB` | both | no | The disk the log may use, live file and archives together. |
