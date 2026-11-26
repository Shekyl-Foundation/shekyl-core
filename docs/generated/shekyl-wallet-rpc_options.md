| Option | Kind | Default | Where | Runtime | Description |
|--------|------|---------|-------|---------|-------------|
| `help` | switch | — | command line | no | Print the options and exit. |
| `version` | switch | — | command line | no | Print the version and exit. |
| `config-verify` | switch | — | command line | no | Check the configuration as a start would, print the effective configuration, and exit. Creates nothing and binds nothing. |
| `network` | `mainnet` / `testnet` / `stagenet` / `regtest` | `mainnet` | command line | no | The network every wallet binds to: mainnet, testnet, stagenet or regtest. Chooses the configuration file. |
| `config-file` | absolute path | this account's root and shekyl-wallet-rpc-<network>.toml | command line | no | The configuration file. A missing file at the default path means the defaults; a missing file at a named path is refused. |
| `wallet-dir` | absolute path | this account's root and wallets/<network> | both | no | The directory of wallet files. |
| `rpc-listen` | IP endpoint (`address:port`) | `127.0.0.1:29500` | both | no | The address the server listens on: an IP address and a port, never a wildcard. An address off this machine needs rpc-username and rpc-password, and carries them in the clear. |
| `rpc-socket-file` | absolute path | — | both | no | A Unix socket to listen on in place of rpc-listen, in a directory only this account can enter. Not on Windows. |
| `rpc-username` | secret (file only, never shown) | — | file | no | The HTTP basic user clients must give. Set with rpc-password, or neither. |
| `rpc-password` | secret (file only, never shown) | — | file | no | The HTTP basic password clients must give. Set with rpc-username, or neither. |
| `daemon-endpoint` | IP endpoint or v3 onion with a port | — | both | no | The daemon on another computer: an IP address and a port, or an onion and a port (reached through daemon-socks). Unset is this computer's node. |
| `daemon-socks` | IP endpoint (`address:port`) | — | both | no | A SOCKS5 proxy to reach daemon-endpoint through; the proxy resolves its name. Required for an onion. |
| `log-file` | absolute path | — | both | no | A log file. Unset, the server logs to standard error and writes no file. |
| `log-level` | `error` / `warn` / `info` / `debug` / `trace` | `warn` | both | no | The log level: error, warn, info, debug or trace. |
| `log-category` | map to `error` / `warn` / `info` / `debug` / `trace` | `none` | both | no | A log level for one subsystem, as subsystem=level; `none` is no overrides. |
| `log-size-max` | bytes, such as `512MiB` (at least 1) | `1GiB` | both | no | The disk a named log file may use, live file and archives together. |
| `tor-file` | absolute path | — | both | no | The Tor binary a serving wallet runs. Unset, the bundled one is found. Either way it must match the pinned build. |
