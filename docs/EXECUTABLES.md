# Shekyl Executables

This document describes every binary produced by a Shekyl build.
All binaries are placed in `build/release/bin/` (or `build/debug/bin/`).

## Quick reference

| Binary | Purpose |
|--------|---------|
| `shekyld` | Full-node daemon (P2P, consensus, RPC) |
| `shekyl-cli` | Interactive command-line wallet (Rust) |
| `shekyl-wallet-rpc` | Headless wallet exposed via JSON-RPC |
| `shekyl-gen-trusted-multisig` | Offline multisig wallet set generator |
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

### Key options

| Option | Description |
|--------|-------------|
| `--data-dir <path>` | Blockchain and config directory (default `~/.shekyl`) |
| `--config-file <file>` | Read options from a config file |
| `--testnet` | Run on testnet |
| `--stagenet` | Run on stagenet |
| `--log-level <0-4>` | Logging verbosity |
| `--log-file <path>` | Log output file (default `~/.shekyl/logs/shekyld.log`, suffixed `-testnet` / `-stagenet` / `-regtest` as applicable). The live file and every rotated archive are written with POSIX mode `0600`. |
| `--max-log-file-size <bytes>` | Rotate the log file at this size (default ~100 MB) |
| `--max-log-files <n>` | Number of rotated archives to retain (default 50; `0` disables pruning) |
| `--non-interactive` | Disable interactive console (for use under a service manager) |
| `--rpc-bind-ip <ip>` | RPC listen address (default `127.0.0.1`); IPv4 or IPv6 (`::1`). Loopback only — a wildcard or a network address is refused at start (`RPC_TRANSPORT_POSTURE.md` RT-1/RT-2) |
| `--rpc-bind-port <port>` | RPC listen port (default per network, see table above); Axum sole transport |
| `--rpc-use-ipv6` | Also bind `--rpc-bind-ipv6-address` (default `::1`) on the same RPC start; same loopback-only refusals. Not a second security model |
| `--restricted-rpc` | Restrict RPC to view-only / safe methods |
| `--rpc-restricted-bind-port <port>` | Separate restricted RPC listener |
| `--rpc-access-control-origins <list>` | Comma-separated CORS allow-list (default: deny) |
| `--p2p-bind-port <port>` | P2P listen port |
| `--add-peer <ip:port>` | Add a persistent peer |
| `--add-priority-node <ip:port>` | Always try to connect to this peer |
| `--add-exclusive-node <ip:port>` | Connect only to these peers |
| `--seed-node <ip:port>` | Connect to a seed node for initial peer discovery |
| `--out-peers <n>` | Maximum outbound connections |
| `--in-peers <n>` | Maximum inbound connections |
| `--hide-my-port` | Do not advertise this node to the network |
| `--no-igd` | Disable UPnP port forwarding |
| `--prune-blockchain` | Enable blockchain pruning |
| `--offline` | Run without P2P networking |
| `--ban-list <file>` | File of IPs to ban |
| `--max-txpool-weight <bytes>` | Maximum transaction pool size |
| `--block-notify <cmd>` | Execute command on new block (substitutes `%s` with hash) |
| `--db-sync-mode <mode>` | Database sync mode: `safe`, `fast`, `fastest` |

### Interactive console commands

When running interactively (without `--non-interactive`), the
daemon provides a command console. Under a service manager (systemd,
launchd, Task Scheduler, or the GUI wallet's Tauri sidecar), run with
`--non-interactive`:

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
| `hard_fork_info` | Hard fork voting status |
| `bans` | List banned peers |
| `ban <ip> [seconds]` | Ban an IP address |
| `unban <ip>` | Remove a ban |
| `flush_txpool [txid]` | Remove transactions from the pool |
| `pop_blocks <n>` | Remove the top N blocks (for recovery) |
| `set_log <level>` | Change log level at runtime |
| `limit [up\|down] [kB/s]` | View or set bandwidth limits |
| `out_peers <n>` | Change max outbound peers |
| `in_peers <n>` | Change max inbound peers |
| `version` | Print daemon version |
| `save` | Force a blockchain save |
| `exit` / `stop_daemon` | Shut down the daemon |

### Examples

```bash
# Start a mainnet full node with default settings
shekyld

# Start a testnet node (RPC on loopback; a wildcard or network bind is refused)
shekyld --testnet

# Start a restricted (view-only) listener for your own wallet on a second
# port; admin stays on the main RPC. RPC is operator-to-operator — this is
# not a public remote node (shekyld does not advertise RPC over P2P).
shekyld --non-interactive --rpc-restricted-bind-port 11030 \
        --config-file /etc/shekyl/shekyld.conf

# Use a custom data directory
shekyld --data-dir /mnt/ssd/shekyl-data

# Pruned node (saves ~2/3 disk space)
shekyld --prune-blockchain
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
| `--engine-dir <path>` | Directory for wallet files (default `.`). Ignored with `--rpc-url` |
| `--engine-file <name>` | Open a wallet immediately on startup |
| `--proxy <socks5h://host:port>` | SOCKS proxy for the daemon connections. Prefer `socks5h://`: the REPL's direct daemon queries honor the scheme, and `socks5://` resolves the hostname locally (a DNS leak, warned at startup) |
| `--daemon-ca-cert <pem>` | PEM CA certificate for an `https://` daemon with a custom CA |
| `--debug` | Show structured RPC error details on failures |

### Interactive commands

This section mirrors the live `help` output; where they disagree, the
binary's `help` wins. Deleted wallet2-era commands (accounts, subaddresses,
secret display, key images, sweeps, `get_tx_key`) refuse at parse time with
guidance naming the Shekyl-native replacement; the full disposition ledger
is [`docs/CLI_PARITY_MATRIX.md`](CLI_PARITY_MATRIX.md).

**Wallet lifecycle**

| Command | Description |
|---------|-------------|
| `create <filename>` | Create a new wallet (also non-interactive: `create <name> --seed-out <path>`) |
| `open <filename>` | Open an existing wallet |
| `close` | Close the current wallet |
| `restore <filename> <seed...>` | Restore from mnemonic seed |
| `password` | Change wallet password |
| `refresh` | Sync with the daemon |
| `rescan` | Rebuild transaction history from the chain (`hard` accepted; same rescan) |
| `status` | Wallet and daemon sync heights |

**Address and balance**

| Command | Description |
|---------|-------------|
| `address` | Show the wallet's primary address |
| `balance` | Balance breakdown |

**Transfers**

| Command | Description |
|---------|-------------|
| `transfer <amount> <address> [--priority N] [--no-confirm]` | Send SKL (build → confirm → submit/discard) |
| `transfers` | Recent transactions |
| `show_transfer <txid>` | Details for a transaction |
| `get_tx_note <txid>` | Show the local note for a transaction |
| `set_tx_note <txid> <note>` | Attach a local note (the note is everything after the txid, verbatim) |
| `abandon <txid>` | Give up on a dispatched send; funds stay locked until the network is confirmed to have dropped it |
| `fee [--inputs N] [--outputs N]` | Fee quotes and size estimate |

**Receiving (payment requests)**

| Command | Description |
|---------|-------------|
| `request new <amount> <label> [--expiry <height>]` | Create a payment request (`shekyl:` URI) |
| `requests list [pending\|matched\|all]` | List payment requests |
| `make_uri [--amount X] [--label L] [--address ADDR]` | Compose a `shekyl:` payment URI |
| `parse_uri <uri>` | Decode a `shekyl:` payment URI |
| `history incoming --unattributed` | Receives with no payment-request match |

**Staking**

| Command | Description |
|---------|-------------|
| `stake [--complete-tree-foundation]` | Make this wallet a staker |
| `staked_balance` | Staked-balance breakdown |
| `staked_outputs` | Unspent staking-side outputs |
| `staking_info` | Staking state and scan height |
| `stake_in <amount>` | Add funds to the staking balance (prints a privacy note, then confirms) |
| `drain_balance` | How much staking money can be moved back to this wallet |
| `drain <amount>` | Move staking funds back to this wallet (fee and destination automatic; no flags) |
| `chain_health` | Daemon/chain health (separate connection) |

**Proofs and message signing**

| Command | Description |
|---------|-------------|
| `get_tx_proof <txid> <address> [message]` | Prove a payment (open wallet required) |
| `check_tx_proof <txid> <address> <proof> [message]` | Verify a tx proof (no wallet needed) |
| `get_reserve_proof [amount] [message]` | Prove unspent reserve (FULL wallet) |
| `check_reserve_proof <address> <proof> [message]` | Verify a reserve proof (no wallet needed) |
| `sign <message>` | Sign a message as this wallet's address |
| `verify <address> <signature> <message>` | Check a message signature (no wallet needed) |

**Meta**

| Command | Description |
|---------|-------------|
| `engine_info` | Wallet summary (height, balance, address) |
| `version` | CLI and wallet-RPC versions |
| `help` | Show help |
| `exit` / `quit` | Exit shekyl-cli |

Offline cold signing (`describe_transfer` / `sign_transfer` /
`submit_transfer`) answers RESERVED: A4 descoped cold *signing* from V3.0
(cold storage ships, cold signing does not).

### Examples

```bash
# Create a new wallet interactively
shekyl-cli --engine-dir ~/wallets

# Open an existing wallet against the testnet daemon on this machine (the
# default daemon address follows --network)
shekyl-cli --network testnet --engine-dir ~/wallets --engine-file testnet

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

## 4. `shekyl-gen-trusted-multisig` — Multisig Wallet Generator

Creates a complete set of N multisig wallets with a given M-of-N threshold in
one step. Intended for trusted setups where all keys are generated on a single
machine (e.g. organizational cold storage).

### Usage

```
shekyl-gen-trusted-multisig --filename-base=<name> --scheme=M/N [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--filename-base <name>` | Base name for wallet files (produces `<name>-1`, `<name>-2`, etc.) |
| `--scheme <M/N>` | Multisig threshold scheme (e.g. `2/3`) |
| `--threshold <M>` | Alternatively, specify M and N separately |
| `--participants <N>` | Number of participants (used with `--threshold`) |
| `--testnet` | Generate testnet wallets |
| `--stagenet` | Generate stagenet wallets |
| `--create-address-file` | Write `.address.txt` files alongside wallets |

### Example

```bash
# Generate a 2-of-3 multisig wallet set
shekyl-gen-trusted-multisig --filename-base cold-storage --scheme 2/3
```

Output: `cold-storage-1`, `cold-storage-2`, `cold-storage-3` wallet files, and
the shared multisig address printed to stdout.

---

## 5. `shekyl-gen-ssl-cert` — TLS Certificate Generator

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

## 6. Blockchain Utilities

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
`--drop-hard-fork`, `--dangerous-unverified-import`.

### `shekyl-blockchain-export`

Exports the chain database to a portable bootstrap file.

```bash
# Export the full chain
shekyl-blockchain-export --output-file blockchain.raw

# Export a specific block range
shekyl-blockchain-export --block-start 0 --block-stop 500000

# Export as blocks.dat format
shekyl-blockchain-export --blocksdat --output-file blocks.dat
```

Key options: `--output-file`, `--data-dir`, `--block-start`, `--block-stop`,
`--blocksdat`.

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
pages (upstream LMDB's `mdb_copy`, built from the vendored source). Pruning
itself happens inside the daemon (`--prune-blockchain`, or the
`prune_blockchain` command); an in-place prune marks pages free without
shrinking the file, and this tool reclaims that space. You temporarily need
disk space for both copies.

```bash
# Stop shekyld first; the destination directory must exist and be empty
mkdir /path/to/compacted
shekyl-mdb-copy -c ~/.shekyl/lmdb /path/to/compacted/

# Then replace the old lmdb directory with the compacted copy
```

Run it as the user that owns the data directory (the copy opens the
database read-only but still creates and writes the reader-lock file,
`lock.mdb`, in the source directory; a `sudo` run leaves root-owned files
the daemon cannot reopen), and always pass both paths — with the
destination omitted the tool streams the entire database to standard
output.

The former `shekyl-blockchain-prune` (schema-aware pruned copy) and
`shekyl-blockchain-prune-known-spent-data` (spend-graph pruning, no substrate
under FCMP++) were retired; the daemon's in-place prune plus this
schema-agnostic compaction replace them.

---

## 7. Debug Utilities

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
