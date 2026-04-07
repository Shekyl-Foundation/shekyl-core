# Shekyl Executables

This document describes every binary produced by a Shekyl build.
All binaries are placed in `build/release/bin/` (or `build/debug/bin/`).

## Quick reference

| Binary | Purpose |
|--------|---------|
| `shekyld` | Full-node daemon (P2P, consensus, RPC) |
| `shekyl-wallet-cli` | Interactive command-line wallet |
| `shekyl-wallet-rpc` | Headless wallet exposed via JSON-RPC |
| `shekyl-gen-trusted-multisig` | Offline multisig wallet set generator |
| `shekyl-gen-ssl-cert` | TLS certificate / key generator for RPC |
| `shekyl-blockchain-import` | Import a bootstrap file into the chain DB |
| `shekyl-blockchain-export` | Export chain DB to a bootstrap file |
| `shekyl-blockchain-mark-spent-outputs` | Build a spent-output database (historical/analytical) |
| `shekyl-blockchain-usage` | Output-reuse histogram |
| `shekyl-blockchain-ancestry` | Trace output ancestry graphs |
| `shekyl-blockchain-depth` | Measure transaction depth to coinbase (historical/analytical) |
| `shekyl-blockchain-stats` | Time-series chain statistics |
| `shekyl-blockchain-prune` | Prune blockchain LMDB in place |
| `shekyl-blockchain-prune-known-spent-data` | Prune known-spent output buckets |
| `shekyl-utils-deserialize` | Decode hex blobs to human-readable JSON |
| `shekyl-utils-object-sizes` | Print sizeof for core data structures |
| `shekyl-utils-dns-checks` | Verify Shekyl DNS seed/update records |

The last three (`shekyl-utils-*`) are only built when `BUILD_DEBUG_UTILITIES=ON`.

---

## Default network ports

| Network | P2P | RPC (HTTP) | ZMQ |
|---------|-----|------------|-----|
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
| `--log-file <path>` | Log output file |
| `--detach` | Run as a background daemon (Linux) |
| `--pidfile <path>` | PID file when detached |
| `--non-interactive` | Disable interactive console |
| `--rpc-bind-ip <ip>` | RPC listen address (default `127.0.0.1`) |
| `--rpc-bind-port <port>` | RPC listen port (default per network, see table above) |
| `--restricted-rpc` | Restrict RPC to view-only / safe methods |
| `--rpc-restricted-bind-port <port>` | Separate restricted RPC listener |
| `--rpc-login <user:pass>` | HTTP digest authentication for RPC |
| `--confirm-external-bind` | Required when binding RPC to non-loopback |
| `--rpc-ssl <mode>` | `enabled`, `disabled`, or `autodetect` |
| `--rpc-ssl-certificate <pem>` | TLS certificate for RPC |
| `--rpc-ssl-private-key <pem>` | TLS private key for RPC |
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
| `--zmq-rpc-bind-port <port>` | ZMQ RPC port |
| `--no-zmq` | Disable ZMQ entirely |
| `--ban-list <file>` | File of IPs to ban |
| `--max-txpool-weight <bytes>` | Maximum transaction pool size |
| `--block-notify <cmd>` | Execute command on new block (substitutes `%s` with hash) |
| `--db-sync-mode <mode>` | Database sync mode: `safe`, `fast`, `fastest` |

### Interactive console commands

When running interactively (without `--non-interactive` or `--detach`), the
daemon provides a command console:

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

# Start a restricted public node as a background service
shekyld --detach --restricted-rpc --public-node \
        --rpc-bind-ip 0.0.0.0 --confirm-external-bind \
        --config-file /etc/shekyl/shekyld.conf

# Use a custom data directory
shekyld --data-dir /mnt/ssd/shekyl-data

# Pruned node (saves ~2/3 disk space)
shekyld --prune-blockchain
```

---

## 2. `shekyl-wallet-cli` — Interactive Wallet

A full-featured command-line wallet supporting transfers, staking, multisig,
hardware wallets, and message signing.

### Usage

```
shekyl-wallet-cli [--wallet-file=<file> | --generate-new-wallet=<file>] [options]
```

### Key options

| Option | Description |
|--------|-------------|
| `--wallet-file <file>` | Open an existing wallet |
| `--generate-new-wallet <file>` | Create a new wallet |
| `--restore-deterministic-wallet` | Restore from a 25-word mnemonic seed |
| `--restore-height <height>` | Block height to start scanning from during restore |
| `--electrum-seed <words>` | Provide the seed on the command line |
| `--generate-from-view-key <file>` | Create a view-only wallet |
| `--generate-from-spend-key <file>` | Create a wallet from a spend key |
| `--generate-from-keys <file>` | Create a wallet from address + view key + spend key |
| `--generate-from-device <file>` | Create a wallet backed by a hardware device |
| `--daemon-address <host:port>` | Daemon to connect to |
| `--daemon-host <host>` | Daemon hostname |
| `--daemon-port <port>` | Daemon RPC port |
| `--trusted-daemon` | Trust the daemon (enables advanced queries) |
| `--untrusted-daemon` | Treat the daemon as untrusted |
| `--testnet` | Use testnet |
| `--stagenet` | Use stagenet |
| `--password <pass>` | Wallet password (avoid on shared systems) |
| `--password-file <file>` | Read password from a file |
| `--daemon-ssl <mode>` | SSL mode for daemon connection |
| `--hw-device <device>` | Hardware wallet device string |
| `--mnemonic-language <lang>` | Language for the seed phrase |
| `--subaddress-lookahead <m:n>` | Subaddress lookahead range |
| `--offline` | Run without connecting to a daemon |
| `--config-file <file>` | Read options from a config file |

### Interactive wallet commands

After opening a wallet, these commands are available at the `[wallet ...]:`
prompt:

**Balances and addresses**

| Command | Description |
|---------|-------------|
| `balance [detail]` | Display balance (unlocked and total) |
| `address [new <label> \| all \| <index>]` | Show, create, or list subaddresses |
| `account [new <label> \| switch <idx> \| all]` | Manage accounts |
| `integrated_address [payment_id]` | Generate an integrated address |
| `address_book [add\|delete]` | Manage the address book |
| `wallet_info` | Wallet type, address, path, daemon |

**Transfers**

| Command | Description |
|---------|-------------|
| `transfer <addr> <amount> [payment_id]` | Send SKL |
| `sweep_all <addr>` | Send entire balance to an address |
| `sweep_account <idx> <addr>` | Send all funds from one account |
| `sweep_single <key_image> <addr>` | Sweep a specific output |
| `show_transfers [in\|out\|pending\|failed\|pool]` | Transaction history |
| `incoming_transfers [available\|unavailable]` | List incoming outputs |
| `export_transfers [csv]` | Export transaction history |

**Staking**

| Command | Description |
|---------|-------------|
| `stake <tier> <amount>` | Lock coins for staking (tier 0/1/2) |
| `unstake` | Release matured staked outputs |
| `claim_rewards` | Claim accrued staking rewards |
| `staking_info` | Display current staking status |

**Keys and proofs**

| Command | Description |
|---------|-------------|
| `seed` | Display the mnemonic seed |
| `viewkey` | Display the private view key |
| `spendkey` | Display the private spend key |
| `get_tx_key <txid>` | Get a transaction's secret key |
| `check_tx_key <txid> <key> <addr>` | Verify a transaction proof |
| `sign <file>` | Sign a file with the wallet key |
| `verify <file> <addr> <sig>` | Verify a signed file |

**Mining**

| Command | Description |
|---------|-------------|
| `start_mining [threads]` | Start mining through the daemon |
| `stop_mining` | Stop mining |

**Maintenance**

| Command | Description |
|---------|-------------|
| `refresh` | Rescan for new transactions |
| `rescan_bc [hard]` | Full blockchain rescan |
| `bc_height` | Current blockchain height |
| `fee` | Current fee estimate |
| `status` | Wallet and daemon sync status |
| `save` | Save the wallet to disk |
| `password <new>` | Change the wallet password |
| `set <option> <value>` | Change wallet settings |
| `help [command]` | Show help for a command |
| `exit` | Close the wallet |

**Multisig (PQC-only via `scheme_id = 2`)**

Classical Monero-style multisig commands (`prepare_multisig`, `make_multisig`,
`exchange_multisig_keys`, `export_multisig_info`, `import_multisig_info`,
`sign_multisig`, `submit_multisig`) have been removed. All multisig on Shekyl
NG uses PQC-only authorization via `scheme_id = 2` in the `pqc_auth` layer.
See `docs/PQC_MULTISIG.md` for the file-based signing protocol.

### Examples

```bash
# Create a new wallet
shekyl-wallet-cli --generate-new-wallet ~/wallets/main

# Open an existing wallet against a testnet daemon
shekyl-wallet-cli --testnet --wallet-file ~/wallets/testnet \
                  --daemon-address 127.0.0.1:12029

# Restore a wallet from seed starting at a specific height
shekyl-wallet-cli --restore-deterministic-wallet \
                  --restore-height 100000 \
                  --generate-new-wallet ~/wallets/restored

# Non-interactive: get balance and exit
echo "balance" | shekyl-wallet-cli --wallet-file ~/wallets/main --password "pass"
```

---

## 3. `shekyl-wallet-rpc` — Wallet RPC Server

A headless wallet that exposes all wallet operations through a JSON-RPC
interface. Designed for integration with exchanges, payment processors, and
application backends.

### Usage

```
shekyl-wallet-rpc [--wallet-file=<file> | --wallet-dir=<dir>] --rpc-bind-port=<port> [options]
```

### Key options

| Option | Description |
|--------|-------------|
| `--wallet-file <file>` | Wallet file to open at startup |
| `--wallet-dir <dir>` | Directory of wallets (enables `open_wallet` / `create_wallet` RPC) |
| `--generate-from-json <file>` | Create wallet from a JSON descriptor |
| `--rpc-bind-port <port>` | Port for the RPC server (required) |
| `--rpc-bind-ip <ip>` | RPC listen address (default `127.0.0.1`) |
| `--rpc-login <user:pass>` | HTTP digest authentication |
| `--disable-rpc-login` | Explicitly disable authentication |
| `--restricted-rpc` | Restrict to view-only methods |
| `--confirm-external-bind` | Required when binding to non-loopback |
| `--daemon-address <host:port>` | Daemon to connect to |
| `--trusted-daemon` | Trust the daemon |
| `--testnet` | Use testnet |
| `--stagenet` | Use stagenet |
| `--password <pass>` | Wallet password |
| `--password-file <file>` | Read password from a file |
| `--no-initial-sync` | Skip initial blockchain sync at startup |
| `--detach` | Run as a background daemon (Linux) |
| `--non-interactive` | Disable console input |
| `--rpc-ssl <mode>` | TLS for the RPC server |
| `--rpc-ssl-certificate <pem>` | TLS certificate |
| `--rpc-ssl-private-key <pem>` | TLS private key |
| `--daemon-ssl <mode>` | TLS for daemon connection |

### Examples

```bash
# Single-wallet mode with authentication
shekyl-wallet-rpc --wallet-file ~/wallets/main \
                  --rpc-bind-port 18083 \
                  --rpc-login user:password \
                  --daemon-address 127.0.0.1:11029

# Multi-wallet mode (exchange use case)
shekyl-wallet-rpc --wallet-dir ~/wallets/ \
                  --rpc-bind-port 18083 \
                  --rpc-login user:password \
                  --disable-rpc-login \
                  --non-interactive --detach

# Testnet with TLS
shekyl-wallet-rpc --testnet --wallet-file ~/wallets/testnet \
                  --rpc-bind-port 28083 \
                  --rpc-ssl enabled \
                  --rpc-ssl-certificate /etc/ssl/rpc.pem \
                  --rpc-ssl-private-key /etc/ssl/rpc.key \
                  --daemon-address 127.0.0.1:12029
```

---

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

### `shekyl-blockchain-mark-spent-outputs`

Builds a database of known-spent outputs. This tool is retained for
historical and analytical purposes. Ring-based output selection analysis is
not applicable to FCMP++ transactions, which use full UTXO set membership
proofs.

```bash
# Scan the default chain database
shekyl-blockchain-mark-spent-outputs ~/.shekyl/lmdb

# Export the spent-output list
shekyl-blockchain-mark-spent-outputs ~/.shekyl/lmdb --export
```

Key options: positional `<input path(s)>`, `--spent-output-db-dir`,
`--rct-only`, `--check-subsets`, `--export`, `--extra-spent-list`.

### `shekyl-blockchain-usage`

Prints a histogram of output amount references. This tool is retained for
historical and analytical purposes. Ring-based analysis is not applicable to
FCMP++ transactions.

```bash
shekyl-blockchain-usage ~/.shekyl/lmdb
shekyl-blockchain-usage ~/.shekyl/lmdb --rct-only
```

Key options: positional `<input path>`, `--rct-only`.

### `shekyl-blockchain-ancestry`

Traces the ancestry graph of transaction outputs to understand output
provenance. This tool is retained for historical and analytical purposes.
Ring-based ancestry analysis is not applicable to FCMP++ transactions.

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
the minimum depth. This tool is retained for historical and analytical
purposes. Ring-based depth analysis is not applicable to FCMP++ transactions.

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

Removes output data for amounts where all outputs are provably spent.

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

### `shekyl-utils-dns-checks`

Resolves Shekyl's hardcoded DNS seed, update, checkpoint, and seg-height
hostnames and verifies DNSSEC signatures. Reports whether all name servers
return consistent results.

```bash
shekyl-utils-dns-checks
```

No options — performs all checks and prints results.

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
