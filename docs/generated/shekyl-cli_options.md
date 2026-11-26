| Option | Kind | Default | Where | Runtime | Description |
|--------|------|---------|-------|---------|-------------|
| `help` | switch | — | command line | no | Print the options and exit. |
| `version` | switch | — | command line | no | Print the version and exit. |
| `config-verify` | switch | — | command line | no | Check the configuration as a start would, print the effective configuration, and exit. Creates nothing and connects to nothing. |
| `network` | `mainnet` / `testnet` / `stagenet` / `regtest` | `mainnet` | command line | no | The network: mainnet, testnet, stagenet or regtest. Chooses the configuration file. |
| `config-file` | absolute path | this account's root and shekyl-cli-<network>.toml | command line | no | The configuration file. A missing file at the default path means the defaults; a missing file at a named path is refused. |
| `wallet-dir` | absolute path | this account's root and wallets/<network> | both | no | The directory of wallet files, for the wallet server this program hosts. |
| `wallet-file` | absolute path | — | both | no | The wallet to open at start, as the absolute path of its <name>.wallet file. Its folder is the wallet directory. Not with wallet-rpc-endpoint or wallet-rpc-socket-file: that server's wallets are on its computer, so use `wallet open <name>`. |
| `daemon-endpoint` | IP endpoint or v3 onion with a port | — | both | no | The daemon on another computer: an IP address and a port, or an onion and a port (reached through daemon-socks). Unset is this computer's node. |
| `daemon-bundle-file` | absolute path | — | both | no | The node's public bundle, as `rpc bundle show` prints it on that node. Set, the enrollment words reach the node at daemon-endpoint over the channel, and daemon-endpoint is required. |
| `rpc-key-file` | absolute path | this account's root and rpc-client.key | both | no | This client's channel key, readable by this account alone. |
| `wallet-rpc-endpoint` | IP endpoint or v3 onion with a port | — | both | no | An external shekyl-wallet-rpc to use instead of hosting one: an IP address and a port, or an onion and a port (reached through daemon-socks). |
| `wallet-rpc-socket-file` | absolute path | — | both | no | An external shekyl-wallet-rpc's Unix socket, in place of wallet-rpc-endpoint. Not on Windows. |
| `daemon-socks` | IP endpoint (`address:port`) | — | both | no | A SOCKS5 proxy for the connections to another computer; the proxy resolves names. Required for an onion. |
| `debug` | switch | — | both | no | Print the machine detail of a failure. |
| `wallet-password-file` | absolute path, or `stdin` | — | both | no | The wallet password: a file only this account can read, or `stdin` for one line of standard input. Required when standard input is not a terminal. |
| `archival-complete-tree` | switch | — | both | no | Post a Foundation CompleteTree bond before the first command: unbounded disk, no reward. Needs wallet-file. |
| `archival-acknowledge` | `serve without reward` | — | command line | no | The exact phrase that accepts archival-complete-tree's terms when standard input is not a terminal. |
| `json` | switch | — | command line | no | Print one JSON object per command. Seeds and passwords are never included. |
| `script-file` | absolute path | — | command line | no | Run the commands in this file as one session. `#` starts a comment. The first failure stops the file. |
| `log-file` | absolute path | — | both | no | A log file. Unset, logs go to standard error and no file is written. |
| `log-level` | `error` / `warn` / `info` / `debug` / `trace` | `warn` | both | no | The log level: error, warn, info, debug or trace. |
| `log-category` | map to `error` / `warn` / `info` / `debug` / `trace` | `none` | both | no | A log level for one subsystem, as subsystem=level; `none` is no overrides. |
| `log-size-max` | bytes, such as `512MiB` (at least 1) | `1GiB` | both | no | The disk a named log file may use, live file and archives together. |
| `tor-file` | absolute path | — | both | no | The Tor binary the wallet server this program hosts runs when it serves. Unset, the bundled one is found. Either way it must match the pinned build. Not with wallet-rpc-endpoint or wallet-rpc-socket-file. |
