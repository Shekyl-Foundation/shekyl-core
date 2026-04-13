# Shekyl CLI User Guide

This guide covers the command-line tools shipped with shekyl-core. If you
prefer a graphical interface, see the
[Shekyl GUI Wallet User Guide](https://github.com/Shekyl-Foundation/shekyl-gui-wallet/blob/main/docs/USER_GUIDE.md)
instead -- both guides share the same section structure so you can
cross-reference equivalent features.

---

## Table of Contents

1. [Introduction and Prerequisites](#introduction-and-prerequisites)
2. [Running a Node (shekyld)](#running-a-node-shekyld)
3. [Wallet Basics (shekyl-wallet-cli)](#wallet-basics-shekyl-wallet-cli)
4. [Sending and Receiving](#sending-and-receiving)
5. [Staking](#staking)
6. [Mining](#mining)
7. [PQC Multisig](#pqc-multisig)
8. [Anonymity Networks (Tor and I2P)](#anonymity-networks-tor-and-i2p)
9. [Network Selection](#network-selection)
10. [Post-Quantum Security](#post-quantum-security)
11. [Wallet RPC Server](#wallet-rpc-server-shekyl-wallet-rpc)
12. [Blockchain Utilities](#blockchain-utilities)
13. [Security and Backup](#security-and-backup)
14. [Troubleshooting](#troubleshooting)
15. [Glossary](#glossary)
16. [Getting Help](#getting-help)

---

## Introduction and Prerequisites

### What are the CLI tools?

Shekyl ships a set of command-line programs for running a node, managing
wallets, and working with blockchain data. They are the same programs that
the GUI wallet uses behind the scenes, and they give you full control over
every feature.

Use the CLI tools when you want to:

- Run a dedicated node on a server (headless, no desktop environment)
- Script wallet operations or build integrations
- Access advanced features not yet exposed in the GUI
- Operate over SSH or inside containers

### System requirements

- **OS:** Linux (x86_64, ARM64), macOS (Intel, Apple Silicon), Windows (MSYS2)
- **Disk:** ~50 GB for a full node; ~10 GB with `--prune-blockchain`
- **RAM:** 4 GB minimum, 8 GB recommended during initial sync
- **Network:** Reliable broadband; the initial sync downloads the full chain

### Shipped executables

| Binary | Purpose |
|--------|---------|
| `shekyld` | Full node daemon -- connects to the network, syncs the chain, relays transactions |
| `shekyl-wallet-cli` | Interactive command-line wallet |
| `shekyl-wallet-rpc` | Wallet RPC server for programmatic access |
| `shekyl-gen-ssl-cert` | Generate self-signed SSL certificates for RPC |
| `shekyl-blockchain-import` | Import blockchain from a file |
| `shekyl-blockchain-export` | Export blockchain to a file |
| `shekyl-blockchain-prune` | Prune or copy-prune a blockchain database |
| `shekyl-blockchain-stats` | Print blockchain statistics |
| `shekyl-blockchain-mark-spent-outputs` | Build a database of known-spent outputs |
| `shekyl-blockchain-ancestry` | Trace transaction ancestry chains |
| `shekyl-blockchain-depth` | Compute minimum chain depth for outputs |
| `shekyl-blockchain-usage` | Analyse blockchain storage usage |
| `shekyl-blockchain-prune-known-spent-data` | Remove provably-spent prunable data |

### Getting the binaries

Download pre-built releases from the
[GitHub releases page](https://github.com/Shekyl-Foundation/shekyl-core/releases),
or build from source following the
[Installation Guide](INSTALLATION_GUIDE.md).

---

## Running a Node (`shekyld`)

The daemon is the engine of the Shekyl network. It downloads and verifies
every block, maintains the UTXO set, and relays transactions. Your wallet
talks to the daemon -- it cannot function without one.

### First launch

```bash
./shekyld
```

On first run, `shekyld` creates a data directory and begins downloading the
blockchain from peers. The default locations are:

- **Linux:** `~/.shekyl/`
- **macOS:** `~/.shekyl/`
- **Windows:** `C:\ProgramData\shekyl\`

Initial sync takes several hours depending on your hardware and network. You
will see log lines showing block height, download rate, and verification
progress. Let it run until you see "SYNCHRONIZED OK" in the output.

### Configuration file

Instead of passing flags on the command line, you can write them in a config
file. The syntax is `optionname=value`, one per line. Boolean flags use
`optionname=1`.

```
# shekyld.conf
data-dir=/var/lib/shekyl
log-file=/var/log/shekyl/shekyld.log
log-level=0
prune-blockchain=1
rpc-bind-ip=0.0.0.0
confirm-external-bind=1
restricted-rpc=1
```

Load a config file with `--config-file /path/to/shekyld.conf`. See
[`utils/conf/shekyld.conf`](../utils/conf/shekyld.conf) for a minimal
example.

### Key daemon flags

**Data and logging**

| Flag | Description |
|------|-------------|
| `--data-dir <path>` | Override the blockchain data directory |
| `--log-file <path>` | Write logs to a specific file |
| `--log-level <0-4>` | Verbosity: 0 = minimal, 4 = trace |
| `--max-log-file-size <bytes>` | Rotate logs when they exceed this size (default 104857600) |
| `--max-log-files <n>` | Number of rotated log files to keep |

**Synchronization and storage**

| Flag | Description |
|------|-------------|
| `--prune-blockchain` | Enable pruning (~95% storage reduction for old prunable data) |
| `--db-sync-mode <mode>` | LMDB sync mode: `safe`, `fast`, `fastest` |
| `--block-sync-size <n>` | Number of blocks per sync batch |
| `--fast-block-sync 1` | Use precomputed block hashes to skip PoW verification during sync |

**RPC**

| Flag | Description |
|------|-------------|
| `--rpc-bind-port <port>` | HTTP RPC listen port (default: 11029 mainnet) |
| `--rpc-bind-ip <addr>` | Bind address for RPC (default: 127.0.0.1) |
| `--rpc-login <user:pass>` | Require HTTP digest authentication |
| `--restricted-rpc` | Disable admin endpoints (safe for public-facing nodes) |
| `--rpc-ssl <mode>` | `enabled`, `disabled`, or `autodetect` |
| `--confirm-external-bind` | Required when binding RPC to 0.0.0.0 |
| `--no-rust-rpc` | Disable the Axum-based Rust RPC transport (on by default) |

**Peer-to-peer**

| Flag | Description |
|------|-------------|
| `--p2p-bind-port <port>` | P2P listen port (default: 11021 mainnet) |
| `--out-peers <n>` | Maximum outbound peer connections |
| `--in-peers <n>` | Maximum inbound peer connections |
| `--add-peer <host:port>` | Manually add a peer |
| `--add-priority-node <host:port>` | Peer that is always maintained |
| `--ban-list <path>` | File of banned IP addresses |
| `--hide-my-port` | Do not advertise your port to peers |

**Background operation**

| Flag | Description |
|------|-------------|
| `--detach` | Run as a background daemon (Linux/macOS) |
| `--pidfile <path>` | Write the process ID to a file (use with `--detach`) |
| `--non-interactive` | Disable the interactive console |

### Interactive console

When `shekyld` is running in the foreground, you get an interactive console.
Type `help` to list all commands. The most useful ones, grouped by purpose:

**Status and information**

| Command | Description |
|---------|-------------|
| `status` | One-line summary: height, net hash, connections, sync state |
| `print_height` | Current blockchain height |
| `diff` | Current mining difficulty |
| `sync_info` | Detailed sync and peer download state |
| `hard_fork_info` | Current and upcoming hard fork versions |
| `version` | Daemon version string |

**Mining**

| Command | Description |
|---------|-------------|
| `start_mining <addr> [threads]` | Start the built-in CPU miner |
| `stop_mining` | Stop mining |
| `mining_status` | Current mining state, hash rate, address |
| `show_hr` / `hide_hr` | Toggle real-time hash rate display |

**Network and peers**

| Command | Description |
|---------|-------------|
| `print_pl` | Full peer list |
| `print_pl_stats` | Peer list statistics |
| `print_cn` | Active connections with data transfer stats |
| `print_net_stats` | Aggregate network bandwidth |
| `bans` | List all banned peers |
| `ban <ip> [seconds]` | Ban a peer |
| `unban <ip>` | Remove a ban |
| `limit_up <kB/s>` / `limit_down <kB/s>` | Set bandwidth limits |
| `out_peers <n>` / `in_peers <n>` | Adjust peer count at runtime |

**Chain inspection**

| Command | Description |
|---------|-------------|
| `print_bc <start> [end]` | Print block headers in a range |
| `print_block <height or hash>` | Print a single block's details |
| `print_tx <txid>` | Print transaction details |
| `is_key_image_spent <key_image>` | Check if a key image is spent |
| `print_pool` | Full transaction pool |
| `print_pool_sh` | Transaction pool (short format) |
| `print_pool_stats` | Pool statistics |
| `alt_chain_info` | Show alternative chain branches |
| `bc_dyn_stats <last_n>` | Dynamic block stats for recent blocks |
| `print_coinbase_tx_sum <start> <count>` | Sum of coinbase outputs in a range |

**Maintenance**

| Command | Description |
|---------|-------------|
| `save` | Force a blockchain save |
| `flush_txpool [txid]` | Remove transaction(s) from the pool |
| `flush_cache [bad-txs\|bad-blocks]` | Clear internal caches |
| `pop_blocks <n>` | Roll back the last N blocks |
| `prune_blockchain` | Enable pruning on a non-pruned database |
| `set_bootstrap_daemon <addr>` | Set or clear a bootstrap daemon for fast-sync |

**Exit**

| Command | Description |
|---------|-------------|
| `stop_daemon` / `exit` | Gracefully shut down |

---

## Wallet Basics (`shekyl-wallet-cli`)

### Creating a new wallet

```bash
./shekyl-wallet-cli --generate-new-wallet /path/to/mywallet
```

You will be prompted for a password and a language for your mnemonic seed.
The wallet generates a 25-word seed phrase -- **write it down on paper
immediately**. This seed is the only way to recover your funds if your
wallet file is lost.

Your wallet is automatically a V3 wallet with full post-quantum key material
(Ed25519 + ML-DSA-65). No extra steps are needed.

### Restoring from a seed phrase

```bash
./shekyl-wallet-cli --restore-deterministic-wallet \
    --generate-new-wallet /path/to/restored \
    --restore-height 100000
```

You will be prompted to enter your 25 words. The `--restore-height` flag
tells the wallet to skip scanning blocks before that height, which is much
faster. If you don't know the exact height, use `--restore-date 2026-03-15`
to estimate it.

### Restoring from keys

For advanced recovery, you can restore from individual keys:

- **From spend key:** `--generate-from-spend-key /path/to/wallet`
- **From view key:** `--generate-from-view-key /path/to/wallet` (creates a
  view-only wallet)
- **From both keys + address:** `--generate-from-keys /path/to/wallet`

### Opening an existing wallet

```bash
./shekyl-wallet-cli --wallet-file /path/to/mywallet
```

### Connecting to a daemon

By default, the wallet connects to `localhost:11029`. To connect to a
different daemon:

```bash
./shekyl-wallet-cli --wallet-file /path/to/mywallet \
    --daemon-address 192.168.1.10:11029 \
    --trusted-daemon
```

Use `--trusted-daemon` when you control the daemon (your own machine). Use
`--untrusted-daemon` for remote public nodes -- the wallet will take extra
precautions to avoid leaking information.

To connect through a SOCKS proxy (e.g. Tor):

```bash
./shekyl-wallet-cli --wallet-file /path/to/mywallet \
    --proxy socks4a:127.0.0.1:9050 \
    --daemon-address <onion-address>:11029
```

### Understanding Bech32m addresses

Shekyl uses a segmented **Bech32m** address format with three parts:

1. **Classical segment** (`shekyl1...`) -- ~113 characters, contains Ed25519
   spend and view public keys
2. **PQC-A segment** (`skpq...`) -- contains part of the ML-KEM-768
   encapsulation key
3. **PQC-B segment** (`skpq2...`) -- contains the rest of the ML-KEM-768 key

The full address is approximately 2,030 characters. When sharing addresses,
use copy-paste or URIs. The classical segment alone is sufficient for
view-only scanning and display purposes.

To see your address inside the wallet:

```
[wallet]: address
```

---

## Sending and Receiving

### Receiving SKL

Display your address with the `address` command. Share this address with the
sender.

**Subaddresses** let you give a unique address to each sender without
revealing your main address:

```
[wallet]: address new [label]
```

**Integrated addresses** embed a payment ID into the address for merchant
use:

```
[wallet]: integrated_address [payment_id]
```

**Address book** for saving frequent recipients:

```
[wallet]: address_book add <address> [description]
[wallet]: address_book
```

### Managing accounts

Accounts let you organize funds into separate "buckets" within one wallet:

```
[wallet]: account new [label]
[wallet]: account switch <index>
[wallet]: account label <index> <label>
```

### Checking your balance

```
[wallet]: balance
[wallet]: balance detail
```

Other useful commands:

- `incoming_transfers [available|unavailable|all]` -- list individual outputs
- `unspent_outputs [min_amount] [max_amount]` -- filter by amount

### Sending SKL

Basic transfer:

```
[wallet]: transfer <address> <amount>
```

You can send to multiple recipients in one transaction:

```
[wallet]: transfer <addr1> <amount1> <addr2> <amount2>
```

The wallet automatically constructs an FCMP++ membership proof for each
spent input, signs with both Ed25519 and ML-DSA-65 (hybrid PQC), and
broadcasts the transaction.

**Priority levels** control the fee (higher priority = higher fee = faster
confirmation):

```
[wallet]: set priority <0|1|2|3|4>
```

**Offline signing** (air-gapped):

```
[wallet]: transfer --do-not-relay <address> <amount>
[wallet]: sign_transfer
[wallet]: submit_transfer
```

### Sweep commands

Move all funds or specific subsets:

| Command | Description |
|---------|-------------|
| `sweep_all <address>` | Send entire balance to one address |
| `sweep_below <amount> <address>` | Consolidate outputs below a threshold |
| `sweep_single <key_image> <address>` | Send a specific output |
| `sweep_account <address>` | Sweep the current account |

### Transaction verification and proofs

Prove to a third party that a payment was made:

| Command | Description |
|---------|-------------|
| `get_tx_key <txid>` | Retrieve the transaction secret key |
| `check_tx_key <txid> <txkey> <address>` | Verify a payment using the tx key |
| `get_tx_proof <txid> <address>` | Generate a cryptographic proof of payment |
| `check_tx_proof <txid> <address> <signature>` | Verify a payment proof |
| `get_reserve_proof [all\|<amount>]` | Prove you hold at least a certain balance |
| `check_reserve_proof <address> <signature>` | Verify a reserve proof |

### Transaction history

```
[wallet]: show_transfers [in|out|pending|failed|pool] [min_height] [max_height]
[wallet]: show_transfer <txid>
[wallet]: export_transfers [csv]
```

### Fees

Check the current fee estimate:

```
[wallet]: fee
```

V3 transactions are larger than legacy transactions due to FCMP++ proofs
and PQC authentication material. A typical 2-input, 2-output transaction is
approximately 23 KB. Fees scale with transaction size.

---

## Staking

Shekyl uses a **claim-based** staking model. You lock SKL for a chosen
period, rewards accrue in a global pool, and you claim your share with
explicit claim transactions. You never hand control of your coins to anyone.

### Staking tiers

| Tier | Lock Period | Yield Multiplier |
|------|-------------|------------------|
| Short | ~1,000 blocks (~33 hours) | 1.0x |
| Medium | ~25,000 blocks (~35 days) | 1.5x |
| Long | ~150,000 blocks (~208 days) | 2.0x |

There is no minimum stake amount.

### Commands

**Stake:**

```
[wallet]: stake <tier> <amount>
```

Where `<tier>` is 0 (Short), 1 (Medium), or 2 (Long).

**View staking status:**

```
[wallet]: staking_info
```

Shows your staked outputs, lock heights, accrued rewards, and claim status.

**Claim rewards:**

```
[wallet]: claim_rewards
```

You can claim rewards at any time after the staked output is created -- even
during the lock period. Claims draw from the global pool and do not touch
your principal. Each claim transaction can cover a maximum range of blocks
(`MAX_CLAIM_RANGE`), so multiple claims may be needed to drain a large
backlog.

**Unstake:**

```
[wallet]: unstake
```

Unlocks your principal after the lock period has elapsed (i.e., the chain
height exceeds `creation_height + tier_lock_blocks`). If the lock has not
expired, the transaction will be rejected.

### Accrual rules

- Rewards accrue for blocks in the range `(creation_height, effective_lock_until]`,
  where `effective_lock_until = creation_height + tier_lock_blocks`.
- After `effective_lock_until`, the output **stops accruing** new rewards but
  you can still claim the backlog that accumulated during the lock window.
- A staked output that is never unstaked does **not** earn indefinitely. The
  accrual cap at `effective_lock_until` keeps the commitment symmetric.

### Privacy considerations

- Staked outputs are on-chain distinguishable (lock tier is visible).
- Claim transactions use `RCTTypeNull` and do not generate FCMP++ proofs.
- Batch your claims rather than claiming every block -- frequent claims
  create a more fingerprintable on-chain pattern.

---

## Mining

Mining secures the network and earns you block rewards. Shekyl uses
**RandomX**, an algorithm designed for ordinary CPUs.

### From the daemon console

```
start_mining <address> [threads]
stop_mining
mining_status
```

### From the wallet

```
[wallet]: start_mining [threads]
[wallet]: stop_mining
```

These commands tell the connected daemon to mine. Rewards are sent to
your wallet address.

### Background mining

Launch the daemon with background mining flags:

```bash
./shekyld --bg-mining-enable \
    --bg-mining-idle-threshold 90 \
    --bg-mining-min-idle-interval 10 \
    --start-mining <address> --mining-threads 2
```

Background mining runs at the lowest CPU priority and pauses when system
utilisation exceeds the idle threshold.

### The 60-block lock

Mined coins are **locked for 60 blocks** (~2 hours) before they become
spendable. This protects against chain reorganisations that could
invalidate the coinbase.

### Coinbase PQC

When your daemon mines a block, the coinbase transaction automatically
performs ML-KEM self-encapsulation to generate per-output PQC keys for
the reward. This happens transparently -- no configuration needed.

---

## PQC Multisig

Shekyl's multisig requires M-of-N participants to authorise a spend. It
uses the same hybrid Ed25519 + ML-DSA-65 signature scheme as single-signer
transactions, with a maximum of 7 participants.

### How it works

All multisig coordination happens **off-chain** using file exchange. On-chain,
the FCMP++ membership proof uses a single classical key -- the M-of-N
threshold lives entirely in the PQC auth layer.

1. **Build:** The coordinator creates the transaction body and FCMP++ proof.
2. **Export:** The coordinator exports a signing request file (JSON) for
   each signer to review.
3. **Sign:** Each of the M required signers independently produces a hybrid
   (Ed25519 + ML-DSA-65) signature over the canonical payload.
4. **Assemble:** The coordinator collects all M signature files, assembles the
   `pqc_auth` container, and broadcasts the transaction.

### Wallet RPC methods

| Method | Description |
|--------|-------------|
| `create_pqc_multisig_group` | Create a group with N total, M required, participant keys |
| `get_pqc_multisig_info` | Check if wallet is part of a multisig group and its parameters |
| `export_multisig_signing_request` | Export a transaction for co-signers |
| `sign_multisig_partial` | Produce a partial signature over the signing request |
| `import_multisig_signatures` | Import M signatures and assemble the final transaction |

### Transaction size

Each additional signer adds approximately 5.3 KB of authentication material.

| Configuration | Auth Size | vs. Single |
|---------------|-----------|------------|
| Single signer | ~5.3 KB | baseline |
| 2-of-3 | ~12.5 KB | 2.4x |
| 3-of-5 | ~19.7 KB | 3.7x |
| 5-of-7 | ~30.2 KB | 5.7x |

### Use cases

- **Treasury management:** 2-of-3 or 3-of-5 ensures no single person can
  spend development or community funds.
- **Staking security:** Long-tier staked positions (up to ~208 days) locked
  for months are a single point of failure with one key. Multisig staked
  outputs use the same `scheme_id = 2` for claims and unlocks.
- **Inheritance and recovery:** 2-of-3 where the owner holds two keys and a
  trusted party holds one.
- **Escrow:** Buyer, seller, and arbitrator each hold a key in a 2-of-3.

---

## Anonymity Networks (Tor and I2P)

> **Status: Experimental.** There are known metadata leak vectors. See
> [ANONYMITY_NETWORKS.md](ANONYMITY_NETWORKS.md) for the full threat matrix.

Shekyl can broadcast transactions over Tor or I2P so that observers cannot
link your IP address to your transactions. Regular block sync and peer
communication still uses IPv4 to resist Sybil attacks.

### Daemon: outbound transaction proxy

```bash
./shekyld --tx-proxy tor,127.0.0.1:9050,10 \
          --tx-proxy i2p,127.0.0.1:9000
```

The `10` parameter is the maximum number of outbound connections over that
network.

### Daemon: inbound hidden service

To receive connections over Tor:

```bash
./shekyld --anonymous-inbound <your-onion>.onion:11021,127.0.0.1:11021,25
```

For I2P:

```bash
./shekyld --anonymous-inbound <your-b32>.b32.i2p:11021,127.0.0.1:11021,25
```

### Wallet through Tor

```bash
./shekyl-wallet-cli --wallet-file /path/to/wallet \
    --proxy socks4a:127.0.0.1:9050 \
    --daemon-address <onion-address>:11029
```

The daemon must expose a hidden service for RPC (separate from the P2P
hidden service).

### Key behaviours

- When any anonymity mode is active, locally-originated transactions are
  **only** sent to peers on anonymity networks.
- If no anonymity peers are available, the transaction is **held** -- it will
  never be broadcast over a public connection.
- V3 transactions are larger (~7-8 KB vs ~2-3 KB pre-PQC), creating a more
  distinctive traffic burst. Consider dummy traffic and fragmentation tuning.

---

## Network Selection

Shekyl runs four networks. Use the right one for your purpose:

| Network | Flag | P2P Port | RPC Port | Use |
|---------|------|----------|----------|-----|
| Mainnet | *(default)* | 11021 | 11029 | Production -- real money |
| Testnet | `--testnet` | 12021 | 12029 | Protocol experiments |
| Stagenet | `--stagenet` | 13021 | 13029 | Integration testing (exchange, wallet) |
| Fakechain | `--regtest` | n/a | n/a | Local deterministic testing |

Both the daemon and wallet must be started with the same network flag:

```bash
./shekyld --testnet
./shekyl-wallet-cli --testnet --wallet-file /path/to/testnet-wallet
```

To switch the daemon to a different network inside the wallet at runtime:

```
[wallet]: set_daemon <address:port>
```

---

## Post-Quantum Security

Every Shekyl transaction is protected by two layers of cryptography:

1. **Ed25519** -- a battle-tested classical signature algorithm.
2. **ML-DSA-65** (FIPS 204) -- a NIST-standardized post-quantum lattice-based
   signature at security level 3.

Both signatures must be valid for a transaction to be accepted. An attacker
would need to break both classical and post-quantum assumptions
simultaneously.

Additionally, each output has its own post-quantum keypair derived through
a **hybrid KEM** (X25519 + ML-KEM-768). When someone sends you coins, the
transaction includes an encrypted key exchange that produces a unique
ML-DSA-65 signing key for that output. Compromising one output's key does
not affect any other.

All of this happens automatically. You do not need to enable anything or
understand the cryptographic details. The wallet handles key generation,
encapsulation, signing, and verification behind the scenes.

For the full technical specification, see
[POST_QUANTUM_CRYPTOGRAPHY.md](POST_QUANTUM_CRYPTOGRAPHY.md).

---

## Wallet RPC Server (`shekyl-wallet-rpc`)

The wallet RPC server provides programmatic JSON-RPC access to wallet
functions. Use it for exchange integrations, automated payments, or
building applications on top of Shekyl.

### Launching

```bash
./shekyl-wallet-rpc \
    --wallet-file /path/to/wallet \
    --rpc-bind-port 11030 \
    --rpc-login user:password \
    --daemon-address 127.0.0.1:11029
```

### Key flags

| Flag | Description |
|------|-------------|
| `--wallet-file <path>` | Wallet file to open |
| `--wallet-dir <path>` | Directory for `create_wallet`/`open_wallet` RPC methods |
| `--rpc-bind-port <port>` | Port to listen on (required) |
| `--rpc-login <user:pass>` | Require HTTP digest auth (strongly recommended) |
| `--disable-rpc-login` | Disable auth -- **dangerous**, use only in trusted environments |
| `--restricted-rpc` | Limit to read-only and transfer operations |
| `--rpc-ssl <mode>` | Enable SSL (`enabled`, `disabled`, `autodetect`) |
| `--daemon-address <addr>` | Connect to a specific daemon |
| `--trusted-daemon` | Disable privacy-preserving request splitting |

### Method categories

All methods are called via `POST /json_rpc`. Key groups:

- **Wallet lifecycle:** `create_wallet`, `open_wallet`, `close_wallet`,
  `restore_deterministic_wallet`
- **Balance and address:** `get_balance`, `get_address`, `create_address`,
  `get_accounts`
- **Transfers:** `transfer`, `transfer_split`, `sweep_all`, `sweep_single`,
  `get_transfers`, `get_transfer_by_txid`
- **Keys and proofs:** `query_key`, `get_tx_key`, `check_tx_key`,
  `get_tx_proof`, `sign`, `verify`
- **Staking:** `stake`, `unstake`, `claim_rewards`, `get_staked_outputs`,
  `get_staked_balance`
- **PQC Multisig:** `create_pqc_multisig_group`, `get_pqc_multisig_info`,
  `export_multisig_signing_request`, `sign_multisig_partial`,
  `import_multisig_signatures`
- **UTXO control:** `freeze`, `thaw`, `frozen`
- **Mining:** `start_mining`, `stop_mining`

For the full RPC reference, see [WALLET_RPC_RUST.md](WALLET_RPC_RUST.md).

---

## Blockchain Utilities

These standalone tools operate directly on the blockchain database. Stop
`shekyld` before using them (they need exclusive access to the LMDB files).

### `shekyl-blockchain-import`

Import a blockchain file (from `blockchain-export` or a trusted source):

```bash
./shekyl-blockchain-import --input-file blockchain.raw --batch-size 5000
```

Use `--dangerous-unverified-import` only with files you trust completely --
it skips all verification for speed.

### `shekyl-blockchain-export`

Export the blockchain to a portable file:

```bash
./shekyl-blockchain-export --output-file blockchain.raw
./shekyl-blockchain-export --output-file partial.raw --block-start 0 --block-stop 100000
```

### `shekyl-blockchain-prune`

Create a pruned copy of the database (keeps only ~5% of prunable data):

```bash
./shekyl-blockchain-prune --copy-pruned-database /path/to/pruned/
```

Or prune in-place (modifies the existing database):

```bash
./shekyl-blockchain-prune
```

### `shekyl-blockchain-stats`

Print statistics about the blockchain:

```bash
./shekyl-blockchain-stats --with-emission --with-fees --with-diff
```

Additional flags: `--with-inputs`, `--with-outputs`, `--with-hours`.

### Other utilities

| Tool | Purpose |
|------|---------|
| `shekyl-blockchain-mark-spent-outputs` | Build a database of provably-spent outputs for privacy analysis |
| `shekyl-blockchain-ancestry` | Trace the input ancestry of a transaction |
| `shekyl-blockchain-depth` | Compute minimum chain depth for an output or transaction |
| `shekyl-blockchain-usage` | Analyse storage usage across the blockchain |
| `shekyl-blockchain-prune-known-spent-data` | Remove prunable data for outputs that are provably spent |

All tools accept `--data-dir`, `--testnet`, `--stagenet`, and
`--log-level` flags.

---

## Security and Backup

### Your mnemonic seed

Your 25-word seed phrase is the **only** way to recover your wallet.
No company, no foundation, no developer can recover it for you.

To display it inside the wallet:

```
[wallet]: seed
```

For an encrypted version (requires the wallet password to decode):

```
[wallet]: encrypted_seed
```

**Write your seed on paper. Store it offline. Never share it.**

### Key export

| Command | Description |
|---------|-------------|
| `viewkey` | Display your secret and public view keys |
| `spendkey` | Display your secret and public spend keys |
| `restore_height` | Display the wallet's creation height |

### View-only wallets

A view-only wallet can monitor incoming transactions but cannot spend. To
create one:

```
[wallet]: save_watch_only
```

To track outgoing transactions in a view-only wallet, periodically export
key images from your full wallet and import them:

```
# On the full wallet:
[wallet]: export_key_images /path/to/key_images

# On the view-only wallet:
[wallet]: import_key_images /path/to/key_images
```

### Changing your password

```
[wallet]: password
```

### Key derivation hardening

For additional brute-force resistance when your wallet file might be exposed:

```bash
./shekyl-wallet-cli --wallet-file /path/to/wallet --kdf-rounds 10000
```

Higher values slow down wallet opening but make password cracking much harder.

---

## Troubleshooting

### Daemon won't sync

- **Firewall:** Ensure port 11021 (P2P) is open for inbound connections, or
  use `--out-peers` to increase outbound connections.
- **Disk space:** A full node needs ~50 GB. Use `--prune-blockchain` to
  reduce to ~5 GB.
- **Corrupted database:** Try `pop_blocks 100` in the daemon console to
  roll back recent blocks. As a last resort, delete the LMDB directory and
  resync.
- **DNS:** If checkpoint DNS resolution fails, try
  `--disable-dns-checkpoints`.

### Wallet balance is wrong or zero

- **Not synced:** Run `refresh` in the wallet. Make sure the daemon is fully
  synchronised first.
- **Restore height too high:** If you restored from seed with a height above
  your first transaction, the wallet missed those transactions. Re-restore
  with a lower height or use `--restore-date`.
- **Stale spent data:** Run `rescan_spent` to recheck which outputs have
  been spent.
- **Full rescan:** `rescan_bc` rescans the entire blockchain from your
  wallet's creation height.

### Transaction not confirming

- Make sure the daemon is synced (`status` in daemon console).
- The transaction pool can be checked with `print_pool` in the daemon.
- If a transaction is stuck, check `show_transfers pending` in the wallet.

### Version mismatch

If the wallet warns about a daemon version mismatch:

```bash
./shekyl-wallet-cli --allow-mismatched-daemon-version --wallet-file /path/to/wallet
```

This should only be used temporarily while updating.

### Reading logs

Increase daemon verbosity for debugging:

```bash
./shekyld --log-level 2
```

Or change it at runtime in the console:

```
set_log 2
```

Wallet logs are written to the same directory as the wallet file, with a
`.log` extension.

---

## Glossary

| Term | Meaning |
|------|---------|
| **Address** | Your Bech32m-encoded public identifier for receiving SKL. Contains both classical (~113 char) and PQC (~1,750 char) key segments. Safe to share. |
| **Atomic unit** | The smallest unit of SKL. 1 SKL = 1,000,000,000 atomic units. |
| **Block** | A bundle of transactions added to the blockchain roughly every 2 minutes. |
| **Block height** | The sequential number of a block, starting from 0. |
| **Block reward** | New SKL created and given to the miner who finds a valid block. |
| **Config file** | A text file (`shekyld.conf`) containing daemon options in `name=value` format, loaded with `--config-file`. |
| **Console** | The interactive command prompt inside `shekyld` when running in foreground mode. |
| **Daemon** | The background program (`shekyld`) that connects to the Shekyl network and maintains the blockchain. |
| **Difficulty** | A measure of how hard mining puzzles are. Adjusts automatically to target ~2-minute blocks. |
| **Emission** | The schedule by which new SKL is created. The total supply is mathematically capped. |
| **FCMP++ membership proof** | A zero-knowledge proof that the spent output exists in the full UTXO set without revealing which one. The anonymity set is every output on the blockchain. |
| **Hybrid signature** | Two signatures on every transaction: Ed25519 (classical) and ML-DSA-65 (quantum-resistant). |
| **Key images** | Cryptographic markers that prevent double-spending. Exported from full wallets to track spends in view-only wallets. |
| **KDF rounds** | Key derivation function iterations; higher values make wallet password brute-forcing harder. |
| **Mnemonic seed** | The 25 words that fully restore your wallet. Treat as a master password you can never change. |
| **ML-DSA-65** | A quantum-resistant signature algorithm standardized by NIST (FIPS 204). |
| **Privacy** | FCMP++ proofs, stealth addresses, and per-output PQC keys (hybrid X25519 + ML-KEM-768) hide who sends, who receives, and how much. Automatic. |
| **Pruning** | Removing old prunable transaction data to reduce storage. The node can still verify new blocks. |
| **RandomX** | Shekyl's mining algorithm, designed for regular CPUs. |
| **RPC** | Remote Procedure Call -- the JSON-based API exposed by the daemon and wallet RPC server. |
| **Staking** | Locking SKL for a period to earn yield from the emission pool. |
| **Stealth address** | A one-time address generated for each transaction so only sender and receiver know the destination. |
| **Subaddress** | A derived address within your wallet, useful for separating incoming payments by source. |
| **View-only wallet** | A wallet that can see incoming transactions but cannot spend. Created with `save_watch_only`. |

---

## Getting Help

- **In-repo documentation:** Browse the
  [docs/ directory](https://github.com/Shekyl-Foundation/shekyl-core/tree/main/docs)
  or the [online documentation browser](https://shekyl.org/resources/documents).
- **GUI wallet guide:**
  [USER_GUIDE.md](https://github.com/Shekyl-Foundation/shekyl-gui-wallet/blob/main/docs/USER_GUIDE.md)
  covers the same features from the graphical interface.
- **Source code:** [shekyl-core on GitHub](https://github.com/Shekyl-Foundation/shekyl-core)
- **Built-in help:** Run `shekyld --help`, `shekyl-wallet-cli --help`, or
  type `help` inside any interactive console.

---

*This guide covers Shekyl CLI tools v0.4.x. TransactionV3 with FCMP++
membership proofs and hybrid PQC spend authorization is the required
transaction format on the rebooted chain.*
