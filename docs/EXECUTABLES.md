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
| `shekyl-blockchain-prune` | Prune blockchain LMDB in place |
| `shekyl-blockchain-prune-known-spent-data` | Prune known-spent output buckets |
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
| `--rpc-bind-ip <ip>` | RPC listen address (default `127.0.0.1`) |
| `--rpc-bind-port <port>` | RPC listen port (default per network, see table above); Axum sole transport |
| `--restricted-rpc` | Restrict RPC to view-only / safe methods |
| `--rpc-restricted-bind-port <port>` | Separate restricted RPC listener |
| `--rpc-access-control-origins <list>` | Comma-separated CORS allow-list (default: deny) |
| `--confirm-external-bind` | Required when binding RPC to non-loopback |
| `--p2p-bind-port <port>` | P2P listen port |
| `--add-peer <ip:port>` | Add a persistent peer |
| `--add-priority-node <ip:port>` | Always try to connect to this peer |
| `--add-exclusive-node <ip:port>` | Connect only to these peers |
| `--seed-node <ip:port>` | Connect to a seed node for initial peer discovery |
| `--out-peers <n>` | Maximum outbound connections |
| `--in-peers <n>` | Maximum inbound connections |
| `--hide-my-port` | Do not advertise this node to the network |
| `--no-igd` | Disable UPnP port forwarding |
| `--public-node` | Advertise as a public node |
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

# Start a testnet node bound to all interfaces
shekyld --testnet --rpc-bind-ip 0.0.0.0 --confirm-external-bind

# Start a restricted public node (background it via systemd — see
# contrib/packaging/linux/shekyld.service for an example unit)
shekyld --non-interactive --restricted-rpc --public-node \
        --rpc-bind-ip 0.0.0.0 --confirm-external-bind \
        --config-file /etc/shekyl/shekyld.conf

# Use a custom data directory
shekyld --data-dir /mnt/ssd/shekyl-data

# Pruned node (saves ~2/3 disk space)
shekyld --prune-blockchain
```

---

## 2. `shekyl-cli` — Interactive CLI Wallet (Rust)

A Rust-native interactive CLI wallet built on `shekyl-wallet-rpc` (library
mode). Uses the same wallet stack as the GUI: wallet2 via FFI for lifecycle
operations, Rust scanner for reads, and native-sign for transaction
construction.

Replaces the legacy `shekyl-wallet-cli` (C++ simplewallet), which has been
removed.

### Usage

```
shekyl-cli [options]
```

### Key options

| Option | Description |
|--------|-------------|
| `--daemon-address <host:port>` | Daemon to connect to (default `localhost:11028`) |
| `--daemon-login <user:password>` | Daemon authentication |
| `--trusted-daemon` | Trust the daemon (skip proof verification) |
| `--network <type>` | `mainnet`, `testnet`, or `stagenet` |
| `--wallet-dir <path>` | Directory for wallet files (default `.`) |
| `--wallet-file <file>` | Open a wallet file on startup |
| `--proxy <socks5://host:port>` | SOCKS5 proxy with stream isolation |
| `--daemon-ca-cert <pem>` | PEM CA certificate for self-signed daemon TLS |
| `--debug` | Show raw error details in stderr or debug log |

### Interactive commands

**Wallet lifecycle**

| Command | Description |
|---------|-------------|
| `create <filename> [language]` | Create a new wallet |
| `open <filename>` | Open an existing wallet |
| `close` | Close the current wallet (auto-saves) |
| `restore <file> <seed> [height]` | Restore from mnemonic seed |
| `save` | Save wallet to disk |
| `password` | Change wallet password |

**Queries**

| Command | Description |
|---------|-------------|
| `address [account]` | Show wallet address |
| `balance` | Show unlocked, locked, and staked balances |
| `status` | Sync status and daemon info |
| `transfers [in\|out\|pending\|failed\|all]` | Transaction history |
| `show_transfer <txid>` | Details for a single transaction |
| `wallet_info` | Wallet type, address, network |

**Transactions**

| Command | Description |
|---------|-------------|
| `transfer <amount> <address> [priority]` | Send SKL |
| `sweep_all <address>` | Send entire balance |
| `refresh` | Sync from daemon |

**Staking**

| Command | Description |
|---------|-------------|
| `stake <tier> [amount]` | Stake to a tier |
| `unstake [key_image]` | Request unstaking |
| `claim` | Claim staking rewards |
| `staking_info` | Current staking status |
| `chain_health` | Network health via daemon RPC |

**Keys and proofs**

| Command | Description |
|---------|-------------|
| `seed` | Display mnemonic seed (with confirmation gate) |
| `viewkey` | Display private view key |
| `spendkey` | Display private spend key |
| `get_tx_key <txid>` | Get transaction secret key |
| `check_tx_key <txid> <key> <addr>` | Verify a transaction proof |
| `get_tx_proof <txid> <addr> [msg]` | Generate tx proof |
| `check_tx_proof <txid> <addr> <sig> [msg]` | Verify tx proof |
| `get_reserve_proof [amount]` | Generate reserve proof |
| `check_reserve_proof <addr> <sig>` | Verify reserve proof |
| `sign <file>` | Sign a file |
| `verify <file> <addr> <sig>` | Verify a signed file |
| `export_key_images <file>` | Export key images |
| `import_key_images <file>` | Import key images |

**Offline signing**

| Command | Description |
|---------|-------------|
| `describe_transfer <file>` | Describe an unsigned transaction |
| `sign_transfer <file>` | Sign an unsigned transaction |
| `submit_transfer <file>` | Submit a signed transaction |

**Other**

| Command | Description |
|---------|-------------|
| `rescan` | Full blockchain rescan (requires confirmation) |
| `version` | Show version |
| `help [command]` | Show help |
| `exit` / `quit` | Close wallet and exit |

### Examples

```bash
# Create a new wallet interactively
shekyl-cli --wallet-dir ~/wallets

# Open an existing wallet against a testnet daemon
shekyl-cli --network testnet --wallet-file ~/wallets/testnet \
           --daemon-address 127.0.0.1:12029

# Use a Tor proxy for stream-isolated daemon connection
shekyl-cli --proxy socks5://127.0.0.1:9050 \
           --daemon-address mynode.onion:11028
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
| `--rpc-bind <addr>` | Listen address: `HOST:PORT` (TCP; default `127.0.0.1:29500`) or `uds:///path/to.sock` (Unix only). **Wildcard addresses (`0.0.0.0`, `::`, `[::]`) are refused** — bind one specific interface. **A non-loopback address refuses to start without `--rpc-login`** |
| `--rpc-login <user:pass>` | HTTP basic authentication. Required for any non-loopback `--rpc-bind`; omitted = auth disabled, accepted only on loopback or a UDS socket |
| `--disable-rpc-login` | Disable auth even if `--rpc-login` is set. Refused on a non-loopback bind |
| `--daemon-address <url>` | Daemon JSON-RPC base URL (default `http://127.0.0.1:28581`) |
| `--proxy <socks5h://host:port>` | SOCKS5h proxy for the daemon connection; the proxy resolves the hostname |
| `--network <mainnet\|testnet\|stagenet>` | Network every create/open binds to (default `mainnet`) |
| `--log-file <path>` | Optional file sink for `tracing` events |

### Why the two bind refusals exist

A wildcard bind is a bind to interfaces that do not exist yet: the VPN that
comes up tomorrow, the hotspot enabled in an airport, the bridge a container
runtime adds next week. A specific address is a decision about a network you
can see; a wildcard is standing consent to networks you cannot. And an
unauthenticated wallet RPC that the network can reach honours every request,
spends included, so there is no deployment in which it is acceptable. **Your
LAN is not a trust boundary** — it holds the TV, the plug with old firmware,
a guest's phone and the router — so "it's only my network" is not a reason to
disable authentication. Design record:
`docs/design/RPC_TRANSPORT_POSTURE.md` (RT-1, RT-2).

### Examples

```bash
# Local tooling over loopback, with authentication
shekyl-wallet-rpc --wallet-dir ~/wallets \
                  --rpc-bind 127.0.0.1:29500 \
                  --rpc-login user:password \
                  --daemon-address http://127.0.0.1:28581

# Local deployment over a Unix socket (filesystem permissions carry the
# authorization; auth may be left disabled)
shekyl-wallet-rpc --wallet-dir ~/wallets \
                  --rpc-bind uds:///run/user/1000/shekyl.sock

# Reachable from one specific interface — authentication is mandatory here,
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

Generates an RSA TLS certificate and private key for use with RPC SSL.
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
# → prints SHA-256 fingerprint; use with --rpc-ssl-certificate / --rpc-ssl-private-key
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

### `shekyl-blockchain-prune`

Creates a pruned copy of the LMDB database, removing most historical
transaction data while preserving headers and recent blocks.

```bash
# Prune the blockchain (swaps original with pruned copy)
shekyl-blockchain-prune

# Prune with fast sync mode
shekyl-blockchain-prune --db-sync-mode fastest
```

Key options: `--data-dir`, `--db-sync-mode`, `--copy-pruned-database`.

### `shekyl-blockchain-prune-known-spent-data`

Removes output data for amounts where all outputs are provably spent. Under
FCMP++ no output is ever provably spent (spends do not reveal which output
they consume), so this tool has no substrate on post-genesis data; it is a
deletion-audit candidate (`docs/FOLLOWUPS.md`, V3.2 legacy spend-graph
utilities entry).

```bash
# Dry run to see what would be pruned
shekyl-blockchain-prune-known-spent-data --dry-run --verbose

# Prune using a known-spent list file
shekyl-blockchain-prune-known-spent-data --input spent-outputs.txt
```

Key options: `--data-dir`, `--input`, `--dry-run`, `--verbose`.

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
