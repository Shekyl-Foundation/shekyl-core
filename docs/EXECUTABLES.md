# Shekyl Executables

This document describes every binary produced by a Shekyl build.
`cargo xtask build` stages them in `build/bin/`.

## Quick reference

| Binary | Purpose |
|--------|---------|
| `shekyld` | Full-node daemon (P2P, consensus, RPC) |
| `shekyl-cli` | Interactive command-line wallet (Rust) |
| `shekyl-wallet-rpc` | Headless wallet exposed via JSON-RPC |
| `shekyl-rpc-tunnel` | Reaches a daemon's RPC channel from another host (`docs/design/RPC_CHANNEL.md` §8) |

---

## Default network ports

| Network | P2P | RPC (HTTP) | Reserved |
|---------|-----|------------|----------|
| Mainnet | 11021 | 11029 | 11025 |
| Testnet | 12021 | 12029 | 12025 |
| Stagenet | 13021 | 13029 | 13025 |

Select a network with `--testnet` or `--stagenet`. Mainnet is the default.

---

## 1. `shekyld` — Full-Node Daemon

The core network participant. Validates blocks and transactions, relays them
over P2P, serves the JSON-RPC API, and optionally mines.

### Usage

```
shekyld [options] [command]
```

### Options

Generated from the daemon's table (`INPUT_GRAMMAR.md` IG-9; `shekyld
--help` prints the same rows): every option, its kind, its default, where
it may be given (the command line, the configuration file, or both) and
whether `option_set` changes it while the daemon runs. A configuration
file is TOML with the same names (see the example in `USER_GUIDE.md`).

<!-- shekyld-options: begin -->
| Option | Kind | Default | Where | Runtime | Description |
|--------|------|---------|-------|---------|-------------|
| `help` | switch | — | command line | no | Print the options and exit. |
| `version` | switch | — | command line | no | Print the version and the operating system, and exit. |
| `rpc-console-key-reset` | switch | — | command line | no | Replace a service's console key and exit without starting: takes the data directory's lock, writes the new key's private half, and touches no other enrollment. Service mode only; refused while the daemon runs. |
| `config-verify` | switch | — | command line | no | Check the configuration as a start would and exit without starting: nothing is created, no lock is taken and no network is joined. Prints the account checked and the effective configuration; a refusal is start's own. |
| `network` | `mainnet` / `testnet` / `stagenet` / `regtest` | `mainnet` | command line | no | The network to run: mainnet, testnet, stagenet or regtest. Chooses the configuration file. |
| `service` | switch | — | command line | no | Run as this machine's service instance, started by the service manager under the daemon's own account. Serves no owner socket. On Windows it arrives with the service-manager dispatcher (RT-W14). |
| `owning-connection` | integer ≥ 3 | — | command line | no | The descriptor (a socket handle on Windows) of one end of a connected stream socket pair the starting process created for this daemon. The daemon writes a ready line on it once its owner's socket is served, and stops when the other end closes. For a wallet that starts its own daemon; not with service. |
| `instance` | name (an instance name) | — | both | no | This node's name, for a second node of the same network on this machine: 1 to 16 lower-case letters, digits or hyphens. Unset is the default instance. A named instance needs its own data-dir. |
| `config-file` | absolute path, or `none` | /etc/shekyl/shekyld-<network>.toml on Linux, FreeBSD and macOS; the daemon's root and shekyld-<network>.toml on Windows | command line | no | The configuration file. A missing file at the default path means the defaults; a missing file at a named path is refused; `none` reads no file, for a program that starts its own daemon on the command line alone. |
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
| `tor-onion-key-file` | absolute path | — | both | no | This node's persistent onion: Tor's own hs_ed25519_secret_key; tor = managed only. Unset, the managed Tor's onion is new at every boot. |
| `tor-file` | absolute path | tor/tor beside the executable, else the version-exact bundle directory under /opt/shekyl/ on Unix | both | no | The managed Tor binary; tor = managed only. It is verified against the pin wherever it is. |
| `clearnet-socks` | IP endpoint (`address:port`) | — | both | no | A SOCKS proxy for clearnet dials. |
| `clearnet-socks-username` | secret (file only, never shown) | — | file | no | The SOCKS username for clearnet-socks. |
| `clearnet-socks-password` | secret (file only, never shown) | — | file | no | The SOCKS password for clearnet-socks. |
| `clearnet-listen` | list of IP endpoint (`address:port`) (`none` for empty) | 0.0.0.0 and the network's p2p port | both | no | The clearnet listen endpoints; `none` is dial-only on clearnet. Beside `clearnet off`, `none` confirms it. |
| `clearnet-advertise` | list of IP endpoint (`address:port`) (`none` for empty) | — | both | no | The clearnet endpoints peers can reach this node at; at most one per address family. Beside `clearnet off`, `none` confirms it. |
| `p2p-local` | switch | — | both | no | Accept peers at private addresses, for a private test network. |
| `p2p-peer` | list of IP endpoint or v3 onion with a port (`none` for empty) | `none` | both | no | Peers to connect to, by IP or onion. |
| `p2p-closed-peer` | list of IP endpoint or v3 onion with a port (`none` for empty) | `none` | both | no | The only peers to connect to; non-empty declares a closed network. |
| `p2p-disclose-early` | switch | — | both | no | Disclose known peers and this node's address below the white-diversity floor, for bootstrapping a small network. |
| `p2p-ban-file` | absolute path | — | both | no | A file of addresses to refuse, one per line. |
| `p2p-upload-max` | rate, such as `1MiB/s` (at least 1), or `unlimited` | `unlimited` | both | yes | The upload rate limit, or `unlimited`. |
| `p2p-download-max` | rate, such as `1MiB/s` (at least 1), or `unlimited` | `unlimited` | both | yes | The download rate limit, or `unlimited`. |
| `notify-block` | command (an array of words; placeholders `{height}`, `{hash}`) | — | file | no | A command to run on a new block, with {height} and {hash}. |
| `notify-reorg` | command (an array of words; placeholders `{split-height}`, `{height}`, `{added}`, `{removed}`) | — | file | no | A command to run on a reorganization, with {split-height}, {height}, {added} and {removed}. |
| `notify-block-rate` | command (an array of words; placeholders `{window}`, `{observed}`, `{expected}`) | — | file | no | A command to run on a block-rate warning, with {window}, {observed} and {expected}. |
| `mine` | `on` / `off` | `off` | both | no | Start the miner at start, to mine-address. |
| `mine-address` | Shekyl address | — | both | no | The address the miner pays. |
| `mine-threads` | integer ≥ 1, or `auto` | `auto` | both | no | The mining thread count, or `auto`. |
| `rpc-listen` | list of IP endpoint (`address:port`) (`none` for empty) | `none` | both | no | The authenticated channel's listeners: enrolled clients reach the node here over the Noise channel, from this host or another. Any address, a wildcard included; `none` is no channel listener. |
| `rpc-socket-dir` | absolute path | — | both | no | The directory for the owner's socket, where the account has no session directory (a test host). It must be local, owned by this account, with mode 0700. Unset uses the session directory. |
| `rpc-admin-listen` | list of IP endpoint (`address:port`) (`none` for empty) | 127.0.0.1 and the network's rpc port | both | no | The plaintext full-access listeners, loopback only; `none` is no admin listener. |
| `rpc-view-listen` | list of IP address, with or without a port (`address[:port]`) (`none` for empty) | `none` | both | no | The plaintext view listeners, loopback only; an address with no port takes the network's view port. |
| `rpc-cors-origin` | list of web origin (`none` for empty) | `none` | both | no | Web origins allowed to call the RPC; `none` denies all. `*` is refused. |
| `rpc-connections-max` | integer ≥ 1 | `25` | both | no | The RPC connection cap. |
<!-- development rows, live on the named networks only and not in --help: dev-sync (regtest); dev-relay-cover (testnet, stagenet, regtest); dev-rpc (regtest); dev-difficulty (regtest); dev-pow-seed-epoch-blocks (regtest); dev-pow-seed-epoch-lag (regtest); dev-settlement-epoch-blocks (regtest); dev-archival-reorg-depth (regtest) -->
<!-- shekyld-options: end -->

### Daemon commands

The daemon has no console and reads nothing from stdin. Its commands are
`shekyl-cli` words, sent over the daemon's RPC; none needs an open wallet.
Mining (`mine start`, `mine stop`, `mine status`) and the node's health
(`chain`) are listed with the rest of `shekyl-cli`'s words
[below](#interactive-commands); `help` in `shekyl-cli` lists every word.

| Command | Description |
|---------|-------------|
| `daemon status` | Height against the network's, network, mining state, hash rate, connections, uptime |
| `daemon stop` | Stop the daemon |
| `sync status` | Sync progress and peer states |
| `peer list [--white] [--gray] [--max <n>]` | The daemon's peer lists |
| `peer stats` | Peer-list counts |
| `peer connections` | Open connections |
| `p2p stats` | Network traffic statistics |
| `txpool list [--short]` | The transaction pool's contents |
| `txpool stats` | Transaction pool statistics |
| `txpool flush [id]` | Remove one transaction, or all, from the pool |
| `ban list` | Banned peers |
| `ban add <ip> [--duration <quantity>]` | Ban an address |
| `ban remove <ip>` | Lift a ban |
| `ban show <ip>` | One address's ban |
| `option show [<name>]` | The daemon's options and their values |
| `option set <name> <value>` | Change an option whose Runtime column above says yes, such as `log-level` |

### Examples

```bash
# Start a mainnet full node with default settings
shekyld

# Start a testnet node (RPC on loopback; a wildcard or network bind is refused)
shekyld --network testnet

# Add a view-only listener for your own wallet on a second port; admin
# stays on rpc-admin-listen. RPC is operator-to-operator — this is not a
# public remote node (shekyld does not advertise RPC over P2P).
shekyld --rpc-view-listen 127.0.0.1:11030 \
        --config-file /etc/shekyl/shekyld-mainnet.toml

# Use a custom data directory
shekyld --data-dir /mnt/ssd/shekyl-data

```

---

## 2. `shekyl-cli` — Interactive CLI Wallet (Rust)

A Rust-native interactive CLI wallet. It is a pure JSON-RPC client of
`shekyl-wallet-rpc` (Shape B): by default it self-hosts a wallet-RPC server
in-process over a private, owner-only local endpoint; with
`--wallet-rpc-endpoint` or `--wallet-rpc-socket-file` it connects to an
external one instead. The contract is
[`docs/api/wallet_rpc.yaml`](api/wallet_rpc.yaml); the capability ledger is
[`docs/CLI_PARITY_MATRIX.md`](CLI_PARITY_MATRIX.md).

Replaces the legacy `shekyl-wallet-cli` (C++ simplewallet), which has been
removed.

### Usage

```
shekyl-cli [options] [command words]
```

Options come before the command. `shekyl-cli help` lists the commands.

### Options

The full list, generated from the option table, is
[`docs/generated/shekyl-cli_options.md`](generated/shekyl-cli_options.md).
The ones most runs use:

| Option | Description |
|--------|-------------|
| `--network <name>` | `mainnet` (default), `testnet`, `stagenet` or `regtest` |
| `--daemon-endpoint <ip:port or onion:port>` | A daemon on another computer. Unset, this computer's node on `--network`, on its own socket or pipe. A daemon that is not loopback is disclosed on stderr at startup |
| `--daemon-socks <ip:port>` | A SOCKS5 proxy for connections to another computer; it resolves names |
| `--wallet-dir <path>` | Directory for wallet files. Default: `wallets/<network>/` in the per-account root (`~/.shekyl`, or `%LOCALAPPDATA%\Shekyl` on Windows; INPUT_GRAMMAR IG-13), created when a wallet is made |
| `--wallet-file <path>` | Open this wallet at start: the absolute path of its `<name>.wallet` file |
| `--wallet-password-file <path or stdin>` | The wallet password, from a file only this account can read or one line of standard input. Required when standard input is not a terminal |
| `--wallet-rpc-endpoint <ip:port>`, `--wallet-rpc-socket-file <path>` | Use an external `shekyl-wallet-rpc` instead of hosting one |
| `--log-level`, `--log-category`, `--log-file`, `--log-size-max` | Logging, as the daemon's. No file is written unless `--log-file` names one |
| `--config-verify` | Check the configuration, print the effective configuration, and exit |
| `--json`, `--script-file <path>`, `--debug` | One JSON object per command; run a file of commands; show machine error detail |

### Interactive commands

This section mirrors the live `help` output; where they disagree, the
binary's `help` wins. Deleted wallet2-era commands (accounts, subaddresses,
secret display, key images, sweeps, `get_tx_key`) refuse at parse time with
guidance naming the Shekyl-native replacement; the full disposition ledger
is [`docs/CLI_PARITY_MATRIX.md`](CLI_PARITY_MATRIX.md).

**Wallet**

| Command | Description |
|---------|-------------|
| `wallet create <name> [--mnemonic-file <path>]` | Create a new wallet. With the flag, the seed goes to a new owner-only file instead of the screen |
| `wallet open <name>` | Open an existing wallet |
| `wallet close` | Close the current wallet |
| `wallet restore <name> [--mnemonic-file <path>] [--wallet-restore-height <n>]` | Restore from the recovery words, read from the file or asked for without echo |
| `wallet password` | Change the wallet password |
| `wallet refresh` | Sync with the daemon |
| `wallet rescan [hard]` | Rebuild transaction history from the chain (`hard` accepted; same rescan) |
| `wallet` | Wallet summary (height, balance, address) |
| `status` | Wallet and daemon sync heights |

**Address and balance**

| Command | Description |
|---------|-------------|
| `address [--full \| --out <path>]` | Show the wallet's primary address (short display form by default; `--full` prints all ~2,030 characters; `--out` writes the full form to a new private file) |
| `balance` | Balance breakdown |

**Sending and history**

| Command | Description |
|---------|-------------|
| `send <amount> <address> [--priority economy\|standard\|high] [--yes]` | Send SKL (build → confirm → submit/discard) |
| `fee [--inputs N] [--outputs N]` | Fee quotes and size estimate |
| `tx list [--in \| --out] [--unmatched]` | Recent transactions; `--unmatched` lists receives with no payment-request match |
| `tx show <id>` | Details for a transaction |
| `tx note <txid> [<text...>]` | Show the local note for a transaction, or attach one (the note is everything after the txid, verbatim) |
| `tx abandon <txid>` | Give up on a dispatched send; funds stay locked until the network is confirmed to have dropped it |

**Receiving (payment requests)**

| Command | Description |
|---------|-------------|
| `request new <amount> <label> [--expiry <unix\|1h\|7d>]` | Create a payment request (`shekyl:` URI); expiry is wall-clock unix seconds or a duration from now |
| `request list [--matched \| --all]` | List payment requests (pending by default) |
| `uri make [--amount X] [--label L] [--address ADDR]` | Compose a `shekyl:` payment URI |
| `uri read <uri>` | Decode a `shekyl:` payment URI |

**Staking**

| Command | Description |
|---------|-------------|
| `stake` | Staking state and scan height |
| `stake balance` | Staked-balance breakdown |
| `stake outputs` | Unspent staking-side outputs |
| `stake available` | How much staking money can be moved back to this wallet |
| `stake add <amount> [--yes]` | Add funds to the staking balance (prints a privacy note, then confirms) |
| `stake return <amount> [--yes]` | Move staking funds back to this wallet (fee and destination automatic) |
| `stake release [--yes]` | Post the permanent exit for the staked bond (irreversible; confirms first) |
| `stake collect [--yes]` | Collect the released exit funds back into this wallet (one pass at a time) |
| `stake join <shard-id>...` | Name the shards to serve; it does not post until wallet-RPC `stake` accepts a shard set |

**Shards and the chain**

| Command | Description |
|---------|-------------|
| `shard list all` | The network's archival shard coverage |
| `shard list mine` | The shards this wallet holds |
| `shard show <id>` | One shard's coverage |
| `shard fetch <id> [--png <path>] [--size <n>]` | Fetch a shard; `--png` writes an image of it |
| `chain` | Daemon and chain health (separate connection) |

**Mining** (the daemon does the hashing; these control it — CU-3)

| Command | Description |
|---------|-------------|
| `mine start [threads\|auto]` | Start mining on the daemon, paying its `mine-address` (default threads: `min(cores, 4)`; the shell sends only the thread count; the daemon owns the threads, so mining keeps running after the CLI exits) |
| `mine stop` | Stop mining on the daemon |
| `mine status` | Mining state, thread count, and hash rate |

The retired spellings `start_mining`, `stop_mining` and `mining_status`
do not run; each names its `mine` replacement. Does not require an open
wallet. Requires the unrestricted RPC listener and a daemon on the same
network as the CLI. The default daemon is loopback. A remote
`--daemon-endpoint` is
allowed, and `mine start` reminds you that mining will run on that
machine's CPU.
A still-syncing daemon refuses `mine start` until it is caught up.

**Proofs and message signing**

| Command | Description |
|---------|-------------|
| `prove payment <txid> <address> [message...]` | Prove a payment (open wallet required) |
| `check payment <txid> <address> <proof> [message...]` | Verify a payment proof (no wallet needed) |
| `prove reserve [amount] [message...]` | Prove unspent reserve (FULL wallet) |
| `check reserve <address> <proof> [message...]` | Verify a reserve proof (no wallet needed) |
| `sign <message...>` | Sign a message as this wallet's address |
| `verify <address> <signature> <message...>` | Check a message signature (no wallet needed) |

**Meta**

| Command | Description |
|---------|-------------|
| `version` | CLI and wallet-RPC versions |
| `help [command]` | Show all commands, or one command's usage |
| `exit` / `quit` | Exit shekyl-cli |

The wallet2-era and pre-shell spellings (`transfer`, `transfers`,
`show_transfer`, `stake_in`, `drain`, `unstake`, `get_tx_proof`,
`staking_info`, and the rest) do not run; each names its replacement.

Offline cold signing (`describe_transfer` / `sign_transfer` /
`submit_transfer`) answers RESERVED: A4 descoped cold *signing* from V3.0
(cold storage ships, cold signing does not).

### Examples

```bash
# Start the shell (wallets live in ~/.shekyl/wallets/mainnet/ by default)
shekyl-cli

# Open an existing testnet wallet against the testnet daemon on this
# machine (the default daemon and wallet directory follow the network)
shekyl-cli --network testnet --wallet-file ~/.shekyl/wallets/testnet/miner.wallet

# Reach a node of yours on another machine through its onion service
shekyl-cli --daemon-socks 127.0.0.1:9050 \
           --daemon-endpoint <56 characters>.onion:11029
```

---

## 3. `shekyl-wallet-rpc` — Wallet RPC Server

The Shekyl-native wallet JSON-RPC server (`docs/api/wallet_rpc.yaml`). Most
users never start it by hand: `shekyl-cli` hosts one in-process over a
private, owner-only local endpoint. Run it standalone for tooling that speaks
JSON-RPC over HTTP, or to serve several wallets from one process.

### Usage

```
shekyl-wallet-rpc [options]
```

### Options

The full list, generated from the option table, is
[`docs/generated/shekyl-wallet-rpc_options.md`](generated/shekyl-wallet-rpc_options.md).

| Option | Description |
|--------|-------------|
| `--wallet-dir <dir>` | Directory of wallet files. Default: `wallets/<network>/` in the account's root |
| `--rpc-listen <ip:port>` | Listen address (default `127.0.0.1:29500`; IPv6 as `[::1]:29500`). Hostnames are not resolved, and a wildcard is refused. Only loopback addresses are accepted |
| `--rpc-socket-file <path>` | A Unix socket in place of `rpc-listen`, in a directory that is this account's alone (made 0700 if missing). Not on Windows |
| `rpc-username`, `rpc-password` | HTTP basic authentication, both or neither, in the configuration file only |
| `--daemon-endpoint <ip:port or onion:port>` | The daemon. Unset, this computer's node on `--network`; a node run as a service is refused with its view listener as the value to set (`-29214`) |
| `--daemon-socks <ip:port>` | A SOCKS5 proxy for the daemon connection; it resolves names. Required for an onion |
| `--network <name>` | Network every create and open binds to (default `mainnet`) |
| `--log-level`, `--log-category`, `--log-file`, `--log-size-max` | Logging, as the daemon's. No file is written unless `--log-file` names one |
| `--config-verify` | Check the configuration, print the effective configuration, and exit |
| `--version` | Print the release version and exit |

The server prints its effective configuration at every start.

### Why the two bind refusals exist

A wildcard bind is a bind to interfaces that do not exist yet: the VPN that
comes up tomorrow, the hotspot enabled in an airport, the bridge a container
runtime adds next week. A specific address is a decision about a network you
can see; a wildcard is standing consent to networks you cannot. And an
unauthenticated wallet RPC that the network can reach honours every request,
spends included, so there is no deployment in which it is acceptable. **The
network being yours is not what provides the security.** Your LAN holds the
TV, the plug with old firmware, a guest's phone and the router, so "it's only
my network" is not a reason to disable authentication. Design record:
`docs/design/RPC_TRANSPORT_POSTURE.md` (RT-1, RT-2).

### Examples

```bash
# Local tooling over loopback (the login, if any, is in the config file)
shekyl-wallet-rpc --wallet-dir ~/wallets \
                  --rpc-listen 127.0.0.1:29500 \
                  --daemon-endpoint 127.0.0.1:11029

# Local deployment over a Unix socket (filesystem permissions carry the
# authorization; auth may be left disabled)
shekyl-wallet-rpc --wallet-dir ~/wallets \
                  --rpc-socket-file /run/user/1000/shekyl/wallet.sock

# Reachable on one specific address: rpc-username and rpc-password must be
# in the config file, and the transport is cleartext HTTP. See
# RPC_TRANSPORT_POSTURE.md before exposing a wallet beyond the machine
shekyl-wallet-rpc --wallet-dir ~/wallets \
                  --rpc-listen 192.168.1.20:29500
```

## Common options

These options are accepted by most executables:

| Option | Description |
|--------|-------------|
| `--help` | Print usage and exit |
| `--version` | Print version and exit |
| `--log-level <0-4>` | Logging verbosity |
| `--log-file <path>` | Log file path |
| `--max-log-file-size <bytes>` | Rotate logs at this size |
| `--max-log-files <n>` | Number of rotated log files to keep |
| `--max-concurrency <n>` | Cap thread usage |
| `--config-file <file>` | Read options from a config file |
| `--testnet` | Use testnet (port and data directory defaults change) |
| `--stagenet` | Use stagenet |
| `--data-dir <path>` | Override the data directory |
