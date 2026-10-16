# Shekyl Executables

This document describes every binary produced by a Shekyl build.
All binaries are placed in `build/release/bin/` (or `build/debug/bin/`).

## Quick reference

| Binary | Purpose |
|--------|---------|
| `shekyld` | Full-node daemon (P2P, consensus, RPC) |
| `shekyl-cli` | Interactive command-line wallet (Rust) |
| `shekyl-wallet-rpc` | Headless wallet exposed via JSON-RPC |
| `shekyl-gen-ssl-cert` | TLS certificate / key generator for RPC |
| `shekyl-blockchain-import` | Import a bootstrap file into the chain DB |
| `shekyl-blockchain-export` | Export chain DB to a bootstrap file |
| `shekyl-blockchain-usage` | Output-reuse histogram |
| `shekyl-blockchain-ancestry` | Trace output ancestry graphs |
| `shekyl-blockchain-depth` | Measure transaction depth to coinbase (historical/analytical) |
| `shekyl-blockchain-stats` | Time-series chain statistics |
| `shekyl-mdb-copy` | Compact a stopped daemon's LMDB database |
| `shekyl-utils-deserialize` | Decode hex blobs to human-readable JSON |
| `shekyl-utils-object-sizes` | Print sizeof for core data structures |

The `shekyl-utils-*` executables are only built when `BUILD_DEBUG_UTILITIES=ON`.

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
<!-- development rows, live on the named networks only and not in --help: dev-clearnet-encrypt (testnet, stagenet, regtest); dev-sync (regtest); dev-relay-cover (testnet, stagenet, regtest); dev-difficulty (regtest); dev-pow-seed-epoch-blocks (regtest); dev-pow-seed-epoch-lag (regtest); dev-settlement-epoch-blocks (regtest); dev-archival-reorg-depth (regtest) -->
<!-- shekyld-options: end -->

### Interactive console commands

With `--console`, the daemon provides a command console on its own
terminal. Under a service manager (systemd, launchd, Task Scheduler, or
the GUI wallet's Tauri sidecar) nothing reads the daemon's stdin, so no
flag is needed there:

| Command | Description |
|---------|-------------|
| `help` | List available commands |
| `status` | Current sync height, network, hashrate |
| `print_height` | Current blockchain height |
| `print_bc <start> [end]` | Print block range |
| `print_block <hash\|height>` | Print a single block |
| `print_tx <txid>` | Print transaction details |
| `print_pl` | Print peer list |
| `print_cn` | Print active connections |
| `print_net_stats` | Network traffic statistics |
| `print_pool` | Full transaction pool contents |
| `print_pool_sh` | Short transaction pool summary |
| `print_pool_stats` | Pool statistics |
| `start_mining <addr> [threads]` | Start mining to an address |
| `stop_mining` | Stop mining |
| `mining_status` | Current mining status |
| `diff` | Current network difficulty |
| `sync_info` | Blockchain sync progress and peer states |
| `bans` | List banned peers |
| `ban <ip> [seconds]` | Ban an IP address |
| `unban <ip>` | Remove a ban |
| `flush_txpool [txid]` | Remove transactions from the pool |
| `pop_blocks <n>` | Remove the top N blocks (for recovery) |
| `version` | Print daemon version |
| `save` | Force a blockchain save |
| `exit` / `stop_daemon` | Shut down the daemon |

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
in-process over a private, owner-only local endpoint; with `--rpc-url` it
connects to an external one instead. The contract is
[`docs/api/wallet_rpc.yaml`](api/wallet_rpc.yaml); the capability ledger is
[`docs/CLI_PARITY_MATRIX.md`](CLI_PARITY_MATRIX.md).

Replaces the legacy `shekyl-wallet-cli` (C++ simplewallet), which has been
removed.

### Usage

```
shekyl-cli [options]
```

### Key options

| Option | Description |
|--------|-------------|
| `--daemon-address <host:port\|url>` | Daemon to connect to. Default: this machine's daemon at the RPC port for `--network` (`11029` / `12029` / `13029`). With `--rpc-url` the self-hosted wallet RPC is not started, but the REPL still queries the daemon at this address directly. A daemon that is not loopback is disclosed on stderr at startup (USER_GUIDE "Connecting to a daemon"; `RPC_TRANSPORT_POSTURE.md` §1) |
| `--rpc-url <url>` | Connect to an external `shekyl-wallet-rpc` instead of self-hosting one (`http://host:port`, or `uds:///path/to.sock` on Unix) |
| `--network <type>` | Network the self-hosted wallet server binds to: `mainnet` (default), `testnet`, `stagenet`. With `--rpc-url` that server is not started, and the flag is then read only to supply the default daemon port for the REPL's own daemon queries — so a run that names its own `--daemon-address` never consults it |
| `--testnet` / `--stagenet` | Shorthand for `--network testnet` / `--network stagenet` — the same flags `shekyld` takes (CU-1). The prompt names the selected network |
| `--wallet-dir <path>` | Directory for wallet files. Default: the per-network `~/.shekyl/wallets/<network>/`, created on demand, so wallets on different networks never share a directory (CU-1). Ignored with `--rpc-url`. `--engine-dir` is a hidden alias (CU-2) |
| `--wallet <name>` | Open a wallet immediately on startup. `--engine-file` is a hidden alias (CU-2) |
| `--proxy <socks5h://host:port>` | SOCKS proxy for the daemon connections. Prefer `socks5h://`: the REPL's direct daemon queries honor the scheme, and `socks5://` resolves the hostname locally (a DNS leak, warned at startup) |
| `--daemon-ca-cert <pem>` | PEM CA certificate for an `https://` daemon with a custom CA |
| `--debug` | Show structured RPC error details on failures |

### Interactive commands

This section mirrors the live `help` output; where they disagree, the
binary's `help` wins. Deleted wallet2-era commands (accounts, subaddresses,
secret display, key images, sweeps, `get_tx_key`) refuse at parse time with
guidance naming the Shekyl-native replacement; the full disposition ledger
is [`docs/CLI_PARITY_MATRIX.md`](CLI_PARITY_MATRIX.md).

**Wallet**

| Command | Description |
|---------|-------------|
| `wallet create <name>` | Create a new wallet (also non-interactive: `shekyl-cli create <name> --seed-out <path>`) |
| `wallet open <name>` | Open an existing wallet |
| `wallet close` | Close the current wallet |
| `wallet restore <name> <seed...>` | Restore from the recovery words |
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
| `mine start [threads\|auto]` | Start mining on the local daemon, paying to this wallet (default threads: `min(cores, 4)`; the daemon owns the threads, so mining keeps running after the CLI exits) |
| `mine stop` | Stop mining on the daemon |
| `mine status` | Mining state, thread count, and hash rate |

The retired spellings `start_mining`, `stop_mining` and `mining_status`
do not run; each names its `mine` replacement. Requires an open wallet,
the unrestricted RPC listener, and a daemon on the same network as the
CLI. The default daemon is loopback (the recommended posture); a remote
`--daemon-address` is allowed and `mine start` reminds you of the risk.
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
# machine (the default daemon address and wallet directory follow the flag)
shekyl-cli --testnet --wallet miner

# Reach a node of yours on another machine through its onion service
shekyl-cli --proxy socks5h://127.0.0.1:9050 \
           --daemon-address mynode.onion:11029
```

---

## 3. `shekyl-wallet-rpc` — Wallet RPC Server

The Shekyl-native wallet JSON-RPC server (`docs/api/wallet_rpc.yaml`). Most
users never start it by hand: `shekyl-cli` hosts one in-process over a
private, owner-only local endpoint. Run it standalone for tooling that speaks
JSON-RPC over HTTP, or to serve several wallets from one process.

> The flags below are those of the Rust binary under `rust/shekyl-wallet-rpc`.
> An earlier revision of this section described the retired C++
> `shekyl-wallet-rpc` (`--rpc-bind-port`, `--rpc-ssl*`, `--confirm-external-bind`,
> digest auth); none of those exist.

### Usage

```
shekyl-wallet-rpc [--wallet-dir <dir>] [--rpc-bind <addr>] [--rpc-login <user:pass>] [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--wallet-dir <dir>` | Directory of wallet files (default `.`); `create_wallet` / `open_wallet` operate here |
| `--rpc-bind <addr>` | Listen address: a numeric `IP:PORT` (TCP; default `127.0.0.1:29500`; IPv6 as `[::1]:29500`; hostnames such as `localhost` are **not** resolved) or `uds:///path/to.sock` (Unix only). **Wildcard addresses (`0.0.0.0`, `::`, `[::]`) are refused** — bind a specific IP address. **A non-loopback address refuses to start without `--rpc-login`** |
| `--rpc-login <user:pass>` | HTTP basic authentication, `NAME:PASSWORD` with **both halves non-empty** — a value without `:`, or with a blank half, is refused at startup. Required for any non-loopback `--rpc-bind` (where the server also logs that Basic travels in the clear until the TLS leg lands); omitted = auth disabled, accepted only on loopback or a UDS socket |
| `--disable-rpc-login` | Run without authentication. Refused on a non-loopback bind, and refused together with `--rpc-login` (a contradiction, not a precedence) |
| `--daemon-address <url>` | Daemon JSON-RPC base URL. Default: this machine's daemon at the RPC port for `--network` (`http://127.0.0.1:11029` on mainnet). A daemon that is not loopback is disclosed in the log at startup, `--proxy` or not (`RPC_TRANSPORT_POSTURE.md` §1) |
| `--proxy <socks5h://host:port>` | SOCKS5h proxy for the daemon connection; the proxy resolves the hostname |
| `--network <mainnet\|testnet\|stagenet>` | Network every create/open binds to (default `mainnet`) |
| `--log-file <path>` | Optional file sink for `tracing` events |

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
# Local tooling over loopback, with authentication
shekyl-wallet-rpc --wallet-dir ~/wallets \
                  --rpc-bind 127.0.0.1:29500 \
                  --rpc-login user:password \
                  --daemon-address http://127.0.0.1:11029

# Local deployment over a Unix socket (filesystem permissions carry the
# authorization; auth may be left disabled)
shekyl-wallet-rpc --wallet-dir ~/wallets \
                  --rpc-bind uds:///run/user/1000/shekyl.sock

# Reachable on one specific address — authentication is mandatory here,
# and the transport is cleartext HTTP: see RPC_TRANSPORT_POSTURE.md for
# the remote-transport round before exposing a wallet beyond the machine
shekyl-wallet-rpc --wallet-dir ~/wallets \
                  --rpc-bind 192.168.1.20:29500 \
                  --rpc-login user:password
```

## 4. `shekyl-gen-ssl-cert` — TLS Certificate Generator

Generates an RSA TLS certificate and private key. No Shekyl RPC binary consumes them any more (the C++ `--rpc-ssl-*` surface is retired, §3); the output suits a TLS terminator you run in front of the daemon.
Prints the SHA-256 fingerprint of the generated certificate.

### Usage

```
shekyl-gen-ssl-cert --certificate-filename=<file> --private-key-filename=<file> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--certificate-filename <file>` | Output path for the PEM certificate (required) |
| `--private-key-filename <file>` | Output path for the PEM private key (required) |
| `--passphrase <pass>` | Encrypt the private key with a passphrase |
| `--passphrase-file <file>` | Read passphrase from a file |
| `--prompt-for-passphrase` | Interactively prompt for a passphrase |

### Example

```bash
shekyl-gen-ssl-cert \
    --certificate-filename /etc/shekyl/rpc.crt \
    --private-key-filename /etc/shekyl/rpc.key
# → prints SHA-256 fingerprint. No Shekyl RPC binary takes `--rpc-ssl-*` any
#   more (see §3); the output is for a TLS terminator you run in front.
```

---

## 5. Blockchain Utilities

These tools operate directly on the LMDB blockchain database. The node must be
stopped before running any tool that opens the database in read-write mode.

### `shekyl-blockchain-import`

Imports a raw blockchain bootstrap file into the LMDB database.

```bash
# Import with full verification
shekyl-blockchain-import --input-file blockchain.raw

# Fast import (skip verification — dangerous)
shekyl-blockchain-import --input-file blockchain.raw --dangerous-unverified-import 1

# Count blocks in a bootstrap file without importing
shekyl-blockchain-import --input-file blockchain.raw --count-blocks

# Import to testnet database
shekyl-blockchain-import --testnet --input-file blockchain.raw

# Pop the last 100 blocks (recovery)
shekyl-blockchain-import --pop-blocks 100
```

Key options: `--input-file`, `--data-dir`, `--batch-size`, `--resume` /
`--no-resume`, `--block-stop`, `--count-blocks`, `--pop-blocks`,
`--dangerous-unverified-import`.

### `shekyl-blockchain-export`

Exports the chain database to a portable bootstrap file.

```bash
# Export the full chain
shekyl-blockchain-export --output-file blockchain.raw

# Export a specific block range
shekyl-blockchain-export --block-start 0 --block-stop 500000

```

Key options: `--output-file`, `--data-dir`, `--block-start`, `--block-stop`.

### `shekyl-blockchain-usage`

Prints a histogram of output reuse — how many times each output appears as a
ring member in transaction inputs. FCMP++ inputs carry no ring-member
references, so this tool has no substrate on post-genesis data; it is a
deletion-audit candidate (`docs/FOLLOWUPS.md`, V3.2 legacy spend-graph
utilities entry).

```bash
shekyl-blockchain-usage ~/.shekyl/lmdb
shekyl-blockchain-usage ~/.shekyl/lmdb --rct-only
```

Key options: positional `<input path>`, `--rct-only`.

### `shekyl-blockchain-ancestry`

Traces the ancestry graph of transaction outputs to understand output
provenance. FCMP++ spends do not reveal which output they consume, so
ancestry tracing has no substrate on post-genesis transactions; this tool is
a deletion-audit candidate (`docs/FOLLOWUPS.md`, V3.2 legacy spend-graph
utilities entry).

```bash
# Refresh the ancestry cache, then query by txid
shekyl-blockchain-ancestry --refresh --txid <hash>

# Query ancestry at a specific block height
shekyl-blockchain-ancestry --height 150000
```

Key options: `--data-dir`, `--txid`, `--output <amount/offset>`, `--height`,
`--refresh`, `--include-coinbase`, `--cache-outputs`, `--cache-txes`.

### `shekyl-blockchain-depth`

For a given transaction or block, walks inputs back to coinbase and reports
the minimum depth. FCMP++ spends do not reveal which output they consume, so
input-walking has no substrate on post-genesis transactions; this tool is a
deletion-audit candidate (`docs/FOLLOWUPS.md`, V3.2 legacy spend-graph
utilities entry).

```bash
# Depth of a specific transaction
shekyl-blockchain-depth --txid <hash>

# Average depth for all transactions in a block
shekyl-blockchain-depth --height 200000
```

Key options: `--data-dir`, `--txid`, `--height`, `--include-coinbase`.

### `shekyl-blockchain-stats`

Outputs tab-separated chain statistics suitable for plotting and analysis.

```bash
# Full stats with emission and difficulty data
shekyl-blockchain-stats --with-emission --with-diff --with-fees

# Stats for a specific block range
shekyl-blockchain-stats --block-start 100000 --block-stop 200000

# Include hourly transaction distribution
shekyl-blockchain-stats --with-hours --with-inputs --with-outputs
```

Key options: `--data-dir`, `--block-start`, `--block-stop`, `--with-inputs`,
`--with-outputs`, `--with-hours`, `--with-emission`, `--with-fees`,
`--with-diff`. Note: `--with-ringsize` has been removed (not applicable to
FCMP++ transactions).

### `shekyl-mdb-copy`

Compacts a stopped daemon's LMDB database by copying it without its free
pages (upstream LMDB's `mdb_copy`, built from the vendored source). The
stripe engine that used to free those pages (`--prune-blockchain`) was
deleted 2026-09-21 (`PDM-Q7`). No daemon path discards tx bodies today:
the C++ depth-based discard was deleted 2026-09-22 as well, and the uniform
discard is S-PRUNE, still a skeleton (`docs/design/DRS_E1_SPRUNE.md`). The tool
reclaims whatever free pages the store already holds. You temporarily need
disk space for both copies.

```bash
# Stop shekyld first; the destination directory must exist and be empty
mkdir /path/to/compacted
shekyl-mdb-copy -c ~/.shekyl/lmdb /path/to/compacted/

# Then replace the old lmdb directory with the compacted copy
```

Run it as the user that owns the data directory (the copy opens the
database read-only but still needs write access to the source's
reader-lock file, `lock.mdb`; a `sudo` run leaves the compacted copy
root-owned, so the daemon cannot use it after the swap), and always pass
both paths — with the destination omitted the tool streams the entire
database to standard output.

The former `shekyl-blockchain-prune` (schema-aware pruned copy) and
`shekyl-blockchain-prune-known-spent-data` (spend-graph pruning, no substrate
under FCMP++) were retired; the daemon's in-place prune plus this
schema-agnostic compaction replace them.

---

## 6. Debug Utilities

Built only when `BUILD_DEBUG_UTILITIES=ON` is set at CMake configure time.

### `shekyl-utils-deserialize`

Decodes a hex-encoded block, transaction, or `tx_extra` blob into
human-readable JSON.

```bash
shekyl-utils-deserialize --input <hex-string>
```

### `shekyl-utils-object-sizes`

Prints `sizeof` for the major data structures used throughout the codebase
(P2P messages, transaction types, wallet structures, etc.). Useful for
profiling memory layout and detecting struct bloat.

```bash
shekyl-utils-object-sizes
```

No options — simply run and inspect the output.

---

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
