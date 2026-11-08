# Shekyl CLI User Guide

This guide covers the command-line tools shipped with shekyl-core. If you
prefer a graphical interface, see the
[Shekyl GUI Wallet User Guide](https://github.com/Shekyl-Foundation/shekyl-gui-wallet/blob/main/docs/USER_GUIDE.md)
instead -- both guides share the same section structure so you can
cross-reference equivalent features.

Links to other documents point into the repository's `docs/` folder. If
you are reading this inside a release archive, find them at
<https://github.com/Shekyl-Foundation/shekyl-core/tree/main/docs>.

---

## Table of Contents

1. [Introduction and Prerequisites](#introduction-and-prerequisites)
2. [Running a Node (shekyld)](#running-a-node-shekyld)
3. [Wallet Basics (shekyl-cli)](#wallet-basics-shekyl-cli)
4. [Sending and Receiving](#sending-and-receiving)
5. [Staking](#staking)
6. [Mining](#mining)
7. [PQC Multisig](#pqc-multisig)
8. [Anonymity Networks (Tor)](#anonymity-networks-tor)
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

- **OS / architecture:** Linux (**x86_64, ARM64 only**), macOS (Intel,
  Apple Silicon), Windows (**64-bit only**, via MSYS2). **32-bit
  targets are not supported and must not be used:** Shekyl's
  post-quantum primitives (ML-KEM-768, ML-DSA-65) require 64-bit
  arithmetic for their constant-time security property, and running a
  32-bit Shekyl wallet exposes the wallet private key to a published
  timing-side-channel attack class (see `docs/STRUCTURAL_TODO.md`
  §"32-bit targets cannot safely run Shekyl" for the technical
  analysis). If your hardware is 32-bit-only — older Raspberry Pi Zero
  / Pi 1, pre-2005 x86 desktops, some embedded boards — Shekyl is not
  appropriate for it.
- **Disk:** ~50 GB for a full node (every node prunes the same way under
  archival pruning once it lands; there is no pruning flag — see
  `docs/design/ARCHIVAL_PRUNED_DAEMON_MODE.md`)
- **RAM:** 4 GB minimum, 8 GB recommended during initial sync
- **Network:** Reliable broadband; the initial sync downloads the full chain

### Shipped executables

| Binary | Purpose |
|--------|---------|
| `shekyld` | Full node daemon -- connects to the network, syncs the chain, relays transactions |
| `shekyl-cli` | Interactive command-line wallet |
| `shekyl-wallet-rpc` | Wallet RPC server for programmatic access |

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
- **Windows:** `%LOCALAPPDATA%\Shekyl\` (the per-account root; a service install uses `%ProgramData%\shekyl\`)

To check a configuration without starting, add `--config-verify` to the
command you would start with, run as the account that will run the daemon:

```bash
./shekyld --network testnet --config-verify
```

It reads the configuration file and every flag exactly as a start would,
checks that the account could create the data directory and the log file,
reads the network marker, judges the development levers and the managed
Tor's pin, and exits: 0 when a start would accept, with the account
checked and the effective configuration on standard output; 2 when a
start would refuse, with the same typed refusals on standard error. It
creates nothing, takes no lock and joins no network, so it can run while
the daemon is up. A port already in use and Tor's bootstrap are outside
its verdict.

Initial sync takes several hours depending on your hardware and network.
To see where it is, run `chain` in `shekyl-cli` (no wallet needed): while
the daemon is still catching up, a `Target: … (syncing)` line sits under
its height, and the line is gone once the daemon reports itself
synchronised.

### Configuration file

Instead of passing options on the command line, you can write them in a
configuration file. The file is TOML; each key is an option's name, spelled
as on the command line without the leading dashes, and a switch is `true`
or `false`. The daemon reads `/etc/shekyl/shekyld-<network>.toml` by
default (`shekyld-mainnet.toml` on mainnet; on Windows the file sits in the
daemon's root), and `--config-file /path/to/file.toml` names another. The
network itself is always given on the command line, because it chooses the
file. A file that anyone but root and the daemon's account can write is
refused.

A file that holds a SOCKS username or password is read only by root, by
the daemon's account, and by the daemon's group while that account is the
group's only member (a service install keeps the file `root:shekyl`
`0640`). The check reads the accounts the system enumerates, so accounts
from a directory service that does not list its accounts are not seen by
it: keep the daemon's group a local group.

<!-- shekyld-example: begin -->
# shekyld configuration file. Every key is an option's name, spelled
# as on the command line without the leading dashes. The network is
# always given on the command line, because it chooses the file.
# Every line below is commented out: uncomment one to set it.

# The data directory. An explicit path is used as given.
# Default: the daemon's root and the network's subdirectory.
# data-dir = "/path"

# The log file.
# Default: the daemon's root, logs/shekyld-<network>.log.
# log-file = "/path"

# The log level: error, warn, info, debug or trace.
# log-level = "warn"

# A log level for one subsystem, as subsystem=level; `none` is no
# overrides.
# log-category = "none"

# The disk the log may use, live file and archives together.
# log-size-max = "1GiB"

# The clearnet connector.
# clearnet = "on"

# The Tor connector: a managed Tor, the operator's own Tor, or off.
# tor = "managed"

# The operator's Tor SOCKS endpoint; required with tor = operator.
# tor-socks = "127.0.0.1:11029"

# The SOCKS username for tor-socks.
# tor-socks-username = "<secret>"

# The SOCKS password for tor-socks.
# tor-socks-password = "<secret>"

# This node's onion service and virtual port, on the operator's Tor.
# tor-onion = "<56 characters>.onion:11021"

# The local endpoint the operator's Tor forwards tor-onion to; required
# with it.
# tor-onion-listen = "127.0.0.1:11029"

# The managed Tor binary; tor = managed only. It is verified against the
# pin wherever it is.
# Default: tor/tor beside the executable, else the version-exact bundle directory under /opt/shekyl/ on Unix.
# tor-file = "/path"

# A SOCKS proxy for clearnet dials.
# clearnet-socks = "127.0.0.1:11029"

# The SOCKS username for clearnet-socks.
# clearnet-socks-username = "<secret>"

# The SOCKS password for clearnet-socks.
# clearnet-socks-password = "<secret>"

# The clearnet listen endpoints; `none` is dial-only on clearnet.
# Default: 0.0.0.0 and the network's p2p port.
# clearnet-listen = ["127.0.0.1:11029"]

# The clearnet endpoints peers can reach this node at; at most one per
# address family.
# clearnet-advertise = ["<public-address>:11021"]

# Accept peers at private addresses, for a private test network.
# p2p-local = true

# Peers to connect to, by IP or onion.
# p2p-peer = "none"

# The only peers to connect to; non-empty declares a closed network.
# p2p-closed-peer = "none"

# Disclose known peers and this node's address below the white-diversity
# floor, for bootstrapping a small network.
# p2p-disclose-early = true

# A file of addresses to refuse, one per line.
# p2p-ban-file = "/path"

# The upload rate limit, or `unlimited`.
# p2p-upload-max = "unlimited"

# The download rate limit, or `unlimited`.
# p2p-download-max = "unlimited"

# A command to run on a new block, with {height} and {hash}.
# notify-block = ["/path/to/command", "{height}"]

# A command to run on a reorganization, with {split-height}, {height},
# {added} and {removed}.
# notify-reorg = ["/path/to/command", "{split-height}"]

# A command to run on a block-rate warning, with {window}, {observed} and
# {expected}.
# notify-block-rate = ["/path/to/command", "{window}"]

# Start the miner at start, to mine-address.
# mine = "off"

# The address the miner pays.
# mine-address = "<address>"

# The mining thread count, or `auto`.
# mine-threads = "auto"

# The plaintext full-access listeners, loopback only; `none` is no admin
# listener.
# Default: 127.0.0.1 and the network's rpc port.
# rpc-admin-listen = ["127.0.0.1:11029"]

# The plaintext view listeners, loopback only.
# rpc-view-listen = "none"

# Web origins allowed to call the RPC; `none` denies all. `*` is refused.
# rpc-cors-origin = "none"

# The RPC connection cap.
# rpc-connections-max = 25
<!-- shekyld-example: end -->

Every option's name, kind and default is in `shekyld --help`.

### Daemon options

Generated from the daemon's table (`INPUT_GRAMMAR.md` IG-9); `shekyld
--help` prints the same rows. "Where" says whether an option is given on
the command line, in the configuration file, or either; "Runtime" says
whether `option_set` changes it while the daemon runs.

<!-- shekyld-options: begin -->
| Option | Kind | Default | Where | Runtime | Description |
|--------|------|---------|-------|---------|-------------|
| `help` | switch | — | command line | no | Print the options and exit. |
| `version` | switch | — | command line | no | Print the version and the operating system, and exit. |
| `config-verify` | switch | — | command line | no | Check the configuration as a start would and exit without starting: nothing is created, no lock is taken and no network is joined. Prints the account checked and the effective configuration; a refusal is start's own. |
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
| `notify-block` | command (an array of words; placeholders `{height}`, `{hash}`) | — | file | no | A command to run on a new block, with {height} and {hash}. |
| `notify-reorg` | command (an array of words; placeholders `{split-height}`, `{height}`, `{added}`, `{removed}`) | — | file | no | A command to run on a reorganization, with {split-height}, {height}, {added} and {removed}. |
| `notify-block-rate` | command (an array of words; placeholders `{window}`, `{observed}`, `{expected}`) | — | file | no | A command to run on a block-rate warning, with {window}, {observed} and {expected}. |
| `mine` | `on` / `off` | `off` | both | no | Start the miner at start, to mine-address. |
| `mine-address` | Shekyl address | — | both | no | The address the miner pays. |
| `mine-threads` | integer ≥ 1, or `auto` | `auto` | both | no | The mining thread count, or `auto`. |
| `rpc-admin-listen` | list of IP endpoint (`address:port`) (`none` for empty) | 127.0.0.1 and the network's rpc port | both | no | The plaintext full-access listeners, loopback only; `none` is no admin listener. |
| `rpc-view-listen` | list of IP endpoint (`address:port`) (`none` for empty) | `none` | both | no | The plaintext view listeners, loopback only. |
| `rpc-cors-origin` | list of web origin (`none` for empty) | `none` | both | no | Web origins allowed to call the RPC; `none` denies all. `*` is refused. |
| `rpc-connections-max` | integer ≥ 1 | `25` | both | no | The RPC connection cap. |
<!-- development rows, live on the named networks only and not in --help: dev-clearnet-encrypt (testnet, stagenet, regtest); dev-sync (regtest); dev-relay-cover (testnet, stagenet, regtest); dev-rpc (regtest); dev-difficulty (regtest); dev-pow-seed-epoch-blocks (regtest); dev-pow-seed-epoch-lag (regtest); dev-settlement-epoch-blocks (regtest); dev-archival-reorg-depth (regtest) -->
<!-- shekyld-options: end -->

The daemon's RPC takes no login and no TLS: inbound RPC is plaintext, on
loopback only. A machine of yours elsewhere reaches it through a Tor onion
service you run in front of that loopback RPC (see "Connecting to a daemon").
Do not publish this RPC through a reverse proxy. The proxy would hand the
plaintext, with no login, to whoever can reach it.
Wallet-RPC has login and TLS options for its own listener.

The authenticated channel (`docs/design/RPC_CHANNEL.md` §1) is not what
`shekyld` serves today. When the channel is served, run it where no path
can read the connection's opening: on this machine, the local socket;
between your machines, a tunnel that ends on the daemon's host, such as
host-to-host WireGuard, or an onion service whose forward to the daemon
stays on that host. Any other path is your choice and is strongly
discouraged. An observer who can read an opening can replay it and keep
the node busy refusing new ones. That denial of service belongs to the
future channel. It is not a property of today's loopback RPC, and
`shekyld` does not detect which path you chose.

**Background operation**

`shekyld` always runs in the foreground. Use your platform's service
manager for background operation (systemd on Linux, launchd on macOS,
Task Scheduler on Windows); the GUI wallet supervises its own bundled
`shekyld` via the Tauri sidecar. An example systemd unit lives at
`contrib/packaging/linux/shekyld.service`. The daemon has no console and
reads nothing from stdin; its commands are `shekyl-cli` words (see
[Commands](#commands)).

**Crash dumps**

`shekyld` hardens itself before it reads an argument: on every Unix it
writes no core file whatever the system's limit, and on Linux and
FreeBSD a process that is not root cannot attach a debugger to it. A
fault ends it by the signal; a stack overflow prints the runtime's
message and ends it by `SIGABRT` (on FreeBSD by `SIGSEGV` without the
message). On Windows it raises no fault dialog and ends itself before
Windows Error Reporting is consulted: a fault or a stack overflow exits
with the exception's code (`0xC0000005`, `0xC00000FD`), a panic with
`0xC0000409`, and none of them writes a dump or a report, whatever the
machine's policy (shown on a machine with a `LocalDumps` policy in
force, 2026-11-02). The installer also excludes `shekyld.exe` from
Windows Error Reporting's reporting, as a backstop for the failures the
process cannot route itself — an allocation failure, heap corruption the
system detects, a C++ stack check. In the same run those fail-fast exits
wrote no dump either while the daemon's own error mode stood; the
backstop is for the case it does not. It does not reach a **LocalDumps**
policy: on a machine where
`HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps`
is set (by Group Policy or by hand), Windows can still write a memory
dump of one of *those* failures to that policy's folder (by default
`%LOCALAPPDATA%\CrashDumps`). If you run the daemon on such a machine,
treat that folder as you treat the data directory: a dump holds the
process's memory, and while the daemon holds no wallet keys, it does
hold its onion service's secret key, its peer list and its mining
address.

### Commands

`shekyld` takes options. A bare word is refused. Daemon commands — chain
height, a transaction, mining, stopping the daemon — are `shekyl-cli`
words, against the daemon this wallet is using.

---

## Wallet Basics (`shekyl-cli`)

`shekyl-cli` is an interactive shell: start it, then type commands at the
prompt. The prompt always names the network — and the open wallet, when
there is one:

```
mainnet>
testnet:miner>
```

Type `help` for the command list grouped by subject, and `help <command>`
for that command's arguments. Tab completes a subject, then its verbs,
then its flags. Up-arrow recalls earlier commands. A line above the prompt
shows the CLI version, the local time, and wallet sync: synced, a block
count behind, no wallet, daemon unreachable, or wallet RPC unreachable.
A failed wallet-RPC read is not reported as a dead daemon.
A pipe runs the same commands and stops at the first failure; pass
`--password-file` with `--wallet`.

Wallet files live under `~/.shekyl/wallets/<network>/` by default, one
directory per network, so a testnet wallet can never shadow a mainnet one.
`--wallet-dir <path>` overrides the directory.

### Creating a new wallet

At the prompt:

```
mainnet> wallet create mywallet
```

You will be prompted for a password, and the wallet's 24-word BIP-39 seed
phrase (English wordlist) is shown **once** — **write it down on paper
immediately**. This seed is the only way to recover your funds if your
wallet file is lost. To keep the seed out of logs and scrollback, `wallet create`
refuses to print it when output is piped or redirected. A script uses
the `create` subcommand below, not a `wallet create` line.

For scripts there is a non-interactive subcommand that writes the seed to a
file instead of the terminal (created `0600`, refusing to overwrite):

```bash
./shekyl-cli create mywallet --seed-out /safe/path/seed.txt \
    [--password-file <path> | --password-stdin]
```

Your wallet is automatically a V3 wallet with full post-quantum key material
(Ed25519 + ML-DSA-65). No extra steps are needed.

### Restoring from a seed phrase

At the prompt:

```
mainnet> wallet restore mywallet word1 word2 ... word24
```

or non-interactively, reading the seed from a file:

```bash
./shekyl-cli restore mywallet --seed-file /safe/path/seed.txt \
    [--password-file <path> | --password-stdin]
```

If you opted in to a BIP-39 passphrase at creation, you will need it here
too. After a restore, run `refresh` to scan the chain for your funds.

The seed words are the only restore path: every wallet key (spend, view,
message-signing, ML-KEM) derives from the master seed, so there is no
separate restore-from-keys flow and no view-only wallet variant.

### Opening an existing wallet

At the prompt:

```
mainnet> wallet open mywallet
```

or open at startup:

```bash
./shekyl-cli --wallet mywallet
```

### Connecting to a daemon

By default the wallet connects to a daemon on this machine, at the RPC
port for the selected network (`127.0.0.1:11029` on mainnet; `--testnet`
and `--stagenet` pick the matching port automatically). If no daemon is
answering there, the wallet says so when it starts and names the command
that would fix it (`shekyld --network testnet`, and the port it answers on).

`shekyld` serves RPC on loopback only, so a node of yours on another
machine is reached through a Tor onion service you run in front of its
loopback RPC (see "Wallet through Tor" below), over a SOCKS proxy:

```bash
./shekyl-cli --wallet mywallet \
    --proxy socks5h://127.0.0.1:9050 \
    --daemon-address <onion-address>:11029
```

Shekyl RPC is operator-to-operator: there is no recommended configuration
in which the wallet talks to a daemon someone else controls, and `shekyld`
does not advertise itself as a public node. A `--daemon-address` that is
not loopback is said out loud when the wallet starts — whoever operates
that daemon sees which blocks the wallet requests and what it broadcasts,
and no proxy or encryption changes that. The warning reads the same for
your own node: it states what a daemon is told, not who you are talking
to. Without `--proxy`, a non-loopback address additionally warns that the
connection itself is visible on the network path.

### Understanding Bech32m addresses

Shekyl uses a segmented **Bech32m** address format with three parts:

1. **Classical segment** (`shekyl1...`) -- ~113 characters, contains Ed25519
   spend and view public keys
2. **PQC-A segment** (`skpq...`) -- contains part of the ML-KEM-768
   encapsulation key
3. **PQC-B segment** (`skpq2...`) -- contains the rest of the ML-KEM-768 key

The full address is approximately 2,030 characters. When sharing addresses,
use `address --out`, `make_uri`, or payment-request URIs — never retype it.

To see your address inside the wallet:

```
mainnet> address
```

By default this prints a **short display form** (the first 24 characters,
an ellipsis, and the last 12) plus the full length — enough to recognize
the address at a glance, and explicitly not valid for pasting.
`address --full` prints the whole string; `address --out <path>` writes it
to a new private file so the full form never has to transit terminal
scrollback or shell history.

---

## Sending and Receiving

### Receiving SKL

Your wallet has **one reusable primary address**. On-chain privacy comes from
per-output cryptography (stealth outputs, hybrid KEM) — **not** from generating a
new address for every sender. Reuse your address freely; rotation does not
improve chain privacy and is not recommended as default hygiene.

Display your primary address:

```
mainnet> address
```

(the short display form; `address --full` / `address --out <path>` for the
real string — see "Understanding Bech32m addresses" above).

**Merchants and invoicing:** create a **payment request** (amount, label,
optional expiry) and share a `shekyl:` URI with query parameters:

```
mainnet> request new <amount> <label> [--expiry <unix|1h|7d>]
mainnet> requests list [pending|matched|all]
```

Attribution is cooperative (off-chain label + optional on-wire `enc_label`
echo when the product flag is enabled). Unattributed inbound payments are
normal — funds are still yours; `history incoming --unattributed` lists
them. `make_uri` / `parse_uri` compose and decode `shekyl:` URIs directly.

**Separate contexts** (e.g. personal vs business) use **separate wallet
files** — deliberate opsec, not a casual default. There are no accounts or
subaddresses in the Shekyl model; payment requests carry the
per-payer/per-purpose attribution that subaddresses carried elsewhere.

### Checking your balance

```
mainnet> balance
```

shows the balance breakdown (spendable now vs still locked). `wallet`
prints a one-shot summary — height, balance, address — and `status` shows
wallet and daemon sync heights.

### Sending SKL

Basic transfer (one recipient per transaction):

```
mainnet> send <amount> <address>
```

The wallet automatically constructs an FCMP++ membership proof for each
spent input, signs with both Ed25519 and ML-DSA-65 (hybrid PQC), and
broadcasts the transaction.

**Priority** controls the fee (higher priority = higher fee = faster
confirmation). `--priority` takes `economy`, `standard`, or `high`.
The default is `standard`.

```
mainnet> send <amount> <address> --priority standard
```

**There is no offline ("air-gapped") signing workflow, by design.** An
FCMP++ membership proof needs the live curve tree, so an offline signer
cannot deliver the isolation such a workflow claims — the "cold" half
would still need current chain data to build a valid transaction. Cold
*storage* is the seed phrase on paper; a machine that signs is online.
Every `send` shows the built transaction (destination, amount, fee)
and waits for your confirmation before broadcasting — decline it and
nothing leaves the wallet.

### No sweep commands

The Monero-era sweep family (`sweep_all`, `sweep_below`, `sweep_single`,
`sweep_unmixable`) does not exist: with a single primary address, no
accounts, and no mixin rules there is nothing to consolidate toward. To
move your funds, `send` the amount `balance` shows as spendable.
(`stake return` is staking-side: it moves staking funds back to this
wallet.)

### Transaction verification and proofs

Prove to a third party that a payment was made. A multi-word `[message]`
binds into the proof; the verifier must supply the identical string:

| Command | Description |
|---------|-------------|
| `prove payment <txid> <address> [message]` | Prove a payment to `<address>` (sent or received; open wallet required) |
| `check payment <txid> <address> <proof> [message]` | Verify a tx proof (no wallet needed) |
| `prove reserve [amount] [message]` | Prove unspent reserve (omit the amount to prove the full balance) |
| `check reserve <address> <proof> [message]` | Verify a reserve proof (no wallet needed) |

There is no `get_tx_key` / `check_tx_key`: the raw per-tx key is a bearer
credential over the whole transaction, so its export is rejected in the
proofs contract (WI-RPC-3) — the scoped `prove payment` / `check payment`
pair covers the use case.

### Transaction history

```
mainnet> tx list
mainnet> tx show <id>
mainnet> tx note <txid> <note>
mainnet> tx note <txid>
```

`tx list` lists recent transactions; `tx abandon <txid>` gives up on a
dispatched send (funds stay locked until the network is confirmed to have
dropped it).

### Fees

Check fee quotes and the size estimate:

```
mainnet> fee [--inputs N] [--outputs N]
```

V3 transactions are larger than legacy transactions due to FCMP++ proofs
and PQC authentication material. A typical 2-input, 2-output transaction is
approximately 23 KB. Fees scale with transaction size.

---

## Staking

Shekyl staking is **archival pay-for-service**. You bond SKL as on-chain
collateral backing archival service, and you earn a share of the block
reward-emission leg for the archival work your position verifiably performs.
There are **no duration tiers, no lock period, no claim transactions, and no
minimum stake** — those belonged to an earlier claim-based design that was
retired before genesis. Your principal stays yours the whole time; the bond
is an honesty anchor (slashable for misbehavior), not a custody transfer.
When you are done staking, `stake release` posts the permanent release and
`stake collect` returns the released collateral to your balance.

For the economic model, see
[`DESIGN_CONCEPTS.md`](DESIGN_CONCEPTS.md) §Component 3–4 and the canonical
specs [`V3_STAKER_ARCHIVAL.md`](V3_STAKER_ARCHIVAL.md) (mechanism) and
[`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md) (reward leg).
If you intend to *run* a staker, read the
[`STAKER_OPERATOR_GUIDE.md`](STAKER_OPERATOR_GUIDE.md) first — it covers the
timing and funding footguns that matter for your privacy.

### How it works

- **Activation is one-time.** You activate staking once; the wallet then posts
  your archival bond and runs the background scan that answers challenges and
  tracks your service. You do not hand control of your coins to anyone.
- **Reward is by verified serve-work, not by amount or duration.** The
  reward budget is divided among stakers in proportion to *capped* verified
  serve-work, so a larger position does not buy a proportionally larger share.
- **Rewards arrive automatically.** They are paid through the loud
  reward-emission leg (public amounts) and received to a firewalled pseudonym.
  There is no manual "claim" step: the open wallet submits the claim
  transaction itself once each reward epoch settles. Very small rewards are
  held until enough accumulate to be worth the network fee, and a wallet that
  was closed for a while claims its backlog shortly after you reopen it.
  Automatic claiming currently requires the wallet's daemon to be on the same
  machine (a loopback address). If your wallet points at a remote daemon —
  even one you run yourself — rewards are not claimed automatically yet; they
  are held, and the wallet raises an operator alarm rather than claiming over
  the remote connection. Remote-daemon claiming arrives with remote-daemon
  support as a whole.
- **Principal stays liquid.** You can release collateral by releasing, subject
  to a release cooldown. There is no fixed lock height to wait out.

### Wallet support today

The full staking surface is live in interactive `shekyl-cli` (type
`help stake` — or any staking command's name — for usage):

- **Read:** `stake` shows this wallet's posture and what can move back.
  `stake balance` and `stake outputs` are the breakdowns. `stake join`
  names shard ids and does not post until the wallet can send a shard set.
- **Foundation nodes** are not a prompt command. The hidden startup flag
  `--complete-tree-foundation` (with `--wallet`) states the terms and
  requires the phrase. Unbounded disk, no reward.
- **Principal movement:** `stake add <amount>` adds funds to the staking
  balance; `stake available` shows what can move back; `stake return <amount>`
  moves it back (fee and destination are automatic).
- **Release:** `stake release` posts the permanent release and `stake collect`
  returns the released collateral. `stake exit` and `unstake` name `stake release`
  and do not run. The wallet-rpc method is still `unstake`.
- **Work in progress and endings:** `stake` also lists each stake, reward
  claim, return or release still in progress, and how each last ended if it
  did not complete. A node can refuse one; it is then never sent again, and
  its funds stay set aside until the height `stake` shows, because only the
  chain can say whether it was mined. If it was not, the funds come back on
  their own after that height, with nothing to do and no fee. Once you have
  read the endings `stake` showed, `stake acknowledge <stake|claim|return|release>`
  clears those of that kind; an ending that arrives later stays until you
  have seen it. A stake whose set-aside funds were all spent without the
  stake confirming is kept, not withdrawn, and the wallet raises an alarm:
  check its logs.

**Wallet RPC** exposes the same verbs (`stake`, `get_staked_balance`,
`get_staked_outputs`, `staking_info`, `stake_in`, `drain`,
`get_drain_balance`, `unstake`, `collect_unstaked`,
`acknowledge_staking_outcome`); reward-related reads
never conflate bonded principal with received rewards. **The desktop GUI**
exposes staker activation directly.

### Privacy considerations

- **Bond-post timing is a privacy surface, and the wallet handles it for
  you.** The wallet draws a randomized entry standoff before posting your bond;
  do not override, batch, or schedule bond-posts to a clock or an external
  event (see the operator guide's footguns).
- **Reward reception is firewalled.** Emission-leg rewards are attributed to a
  pseudonym, keeping your archival identity separate from your spending
  identity — provided you do not defeat the firewall by funding or draining
  through linked events.

---

## Mining

Mining secures the network and earns you block rewards. Shekyl uses
**RandomX v2**, an algorithm designed for ordinary CPUs.

The commands below run the node's **built-in miner**. It is the same
code the node uses to check blocks, so it is always correct, but it is
tuned for checking one block at a time, not for hashing as fast as your
CPU can. It is fine for testing, for a small contribution, or for
learning the flow. If you want more hashrate, run a **dedicated miner**
as a separate program that uses **this node's** block template. A miner
built for another coin (including stock Monero XMRig) will not produce
blocks this network accepts. `shekyl-cli mine start` prints that
reminder when the built-in miner starts.

### From the wallet

```
mainnet> mine start          # default threads: min(cores, 4)
mainnet> mine start 8        # explicit thread count
mainnet> mine status         # active/idle, threads, hash rate
mainnet> mine stop
```

`start_mining`, `stop_mining`, and `mining_status` name the lines above and
do not run. Mining on a running daemon is `mine start`, `mine stop` and
`mine status` in `shekyl-cli`.

These commands **control** mining on the connected daemon — the daemon
still does the hashing (no RandomX runs in the wallet process), and the
daemon owns the mining threads, so mining keeps running after you close
the CLI. Rewards pay the daemon's `mine-address`. The shell sends only
the thread count; you do not pass an address.

`mine` does not require an open wallet. It does require the unrestricted
RPC listener and a daemon on the same network as the CLI. The silent
default is a daemon on this machine. A remote `--daemon-address` is
allowed: `mine start` reminds you that mining will run on that machine's
CPU, then continues.
If the daemon is still syncing, `mine start` refuses — the daemon will not
mine until it has caught up.

### Mining from start

To mine from the moment the daemon starts, turn the miner on and give it
the address it pays; `mine-threads` is the thread count (`auto`, the
default, is one per core, and a count above the machine's is refused
before the daemon starts):

```bash
./shekyld --mine on --mine-address <address> --mine-threads 2
```

The same rows go in the configuration file. `mine-address` alone starts
nothing: the daemon holds the address for `start_mining` (or
`shekyl-cli mine start`) to use later. `mine = on` without an address is
refused before the daemon starts. The start-up configuration line shows
the address shortened to its first and last eight characters.

The miner mines only on a chain the node knows to be synced. A node that
is alone on its network with `clearnet` or `tor` on has no view of that
network and never counts itself synced: the start announces `mining: the
miner waits for a view of the network …`, `mining_status` reports
`no_template` with `mine.not_synced` (`no_view`), and the height does not
move. That is the rule, not a fault. To mine alone — a fresh regtest, a
single-machine test — declare it: turn both connectors off,

```bash
./shekyld --network regtest --clearnet off --tor off \
  --mine on --mine-address <address>
```

or name the whole network with `p2p-closed-peer`, which counts the node
synced while none of its named peers is up. `dev-sync` is not this lever:
it only stops the node asking peers for blocks, and a node with a
connector on still has a network it could be behind.

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

### Planned wallet-RPC surface

These methods are the v31 design's shape and are **not yet in the wallet-RPC
contract registry** (`docs/api/wallet_rpc.yaml`); they land with the
multisig implementation:

| Method | Description |
|--------|-------------|
| `create_pqc_multisig_group` | Create a group with N total, M required, participant keys |
| `get_pqc_multisig_info` | Check if wallet is part of a multisig group and its parameters |
| `export_multisig_signing_request` | Export a transaction for co-signers |
| `sign_multisig_partial` | Produce a partial signature over the signing request |
| `import_multisig_signatures` | Import M signatures and assemble the final transaction |

### Transaction size

Each additional signer adds roughly another hybrid key + signature of
authentication material (~5.4 KB solo baseline via `pqc_auth_weight()`).

| Configuration | Auth Size | vs. Single |
|---------------|-----------|------------|
| Single signer | ~5.4 KB | baseline |
| 2-of-3 | ~12.8 KB | ~2.4× |
| 3-of-5 | ~20.2 KB | ~3.7× |
| 5-of-5 | ~27 KB | ~5.0× |

Whole-tx weights (FCMP++/Bp+/KEM dominate) are closer to ~2.4× solo for
5-of-5 — see `V3_ROLLOUT.md`. Target cap is
`MAX_MULTISIG_PARTICIPANTS = 5` (MSW-G; code still `= 7` until MSW-1).

### Use cases

- **Treasury management:** 2-of-3 or 3-of-5 ensures no single person can
  spend development or community funds.
- **Staking security:** A bonded archival position keeps significant
  collateral committed over a long service life and is slashable for
  misbehavior, so controlling it with a single key is a single point of
  failure. Use multisig to protect the keys that control bonded value.
- **Inheritance and recovery:** 2-of-3 where the owner holds two keys and a
  trusted party holds one.
- **Escrow:** Buyer, seller, and arbitrator each hold a key in a 2-of-3.

---

## Anonymity Networks (Tor)

> **Status: Experimental.** There are known metadata leak vectors. See
> [ANONYMITY_NETWORKS.md](ANONYMITY_NETWORKS.md) for the full threat matrix.

> **Tor-zone cover is an operator choice, not a protocol default (TRC,
> recorded 2026-09-12).** Wire-observer resistance on Tor comes from running a
> **non-exit** Tor relay in a **separate process** from `shekyld`, with the
> node's Tor **client that same process** (originated cells on the relay's OR
> connections). A sidecar client Tor — including the default managed
> ephemeral instance — is uncovered. See [TOR_RELAY.md](TOR_RELAY.md). The
> daemon does not check, warn, or refuse on that basis. The contract is
> [design/TOR_COVER_POSTURE.md](design/TOR_COVER_POSTURE.md).

Shekyl can broadcast transactions over Tor so that observers cannot
link your IP address to your transactions. I2P is not a network this
daemon dials. Regular block sync and peer communication still uses IPv4
to resist Sybil attacks.

### Daemon: Tor

The Tor connector is on by default: `tor = managed` runs the bundled Tor
(`tor-file` names the binary). To use a Tor you run, name its SOCKS
endpoint and, to be reachable over Tor, your onion service and the local
endpoint it forwards to:

```bash
./shekyld --tor operator --tor-socks 127.0.0.1:9050 \
    --tor-onion <your-onion>.onion:11021 --tor-onion-listen 127.0.0.1:11021
```

`--tor off` is clearnet only. For Tor-zone *cover*, that SocksPort must be
the non-exit relay process — see [TOR_RELAY.md](TOR_RELAY.md) — not a
second client Tor.

### Wallet through Tor

```bash
./shekyl-cli --wallet mywallet \
    --proxy socks5h://127.0.0.1:9050 \
    --daemon-address <onion-address>:11029
```

The daemon must expose a hidden service for RPC (separate from the P2P
hidden service). The wallet still states at startup that the daemon's
operator sees what it asks for — true of your own node too; see
"Connecting to a daemon".

### Key behaviours

- When any anonymity mode is active, locally-originated transactions are
  **only** sent to peers on anonymity networks.
- If no anonymity peers are available, the transaction is **held** -- it will
  never be broadcast over a public connection.
- V3 transactions are larger (~7-8 KB vs ~2-3 KB pre-PQC), creating a more
  distinctive traffic burst. On Tor that burst is mixed by operator relay
  volume ([TOR_RELAY.md](TOR_RELAY.md)), not by dummy traffic. Tor is the
  only encrypted network, so dummy traffic is not a second network's cover.

---

## Network Selection

Shekyl runs four networks. Use the right one for your purpose:

| Network | Daemon | P2P Port | RPC Port | Use |
|---------|--------|----------|----------|-----|
| Mainnet | *(default)* | 11021 | 11029 | Production -- real money |
| Testnet | `--network testnet` | 12021 | 12029 | Protocol experiments |
| Stagenet | `--network stagenet` | 13021 | 13029 | Integration testing (exchange, wallet) |
| Regtest | `--network regtest` | n/a | n/a | Local deterministic testing |

Both the daemon and wallet must be started on the same network (the
wallet's `--testnet` / `--stagenet` are shorthand for `--network …`):

```bash
./shekyld --network testnet
./shekyl-cli --testnet
```

The wallet keeps the networks from mixing on its own:

- Wallet files live in a **per-network directory**
  (`~/.shekyl/wallets/testnet/`), so a testnet wallet can never shadow a
  mainnet one.
- The prompt names the network (`testnet:miner>`), so you always know
  which money you are holding.
- The default daemon address follows the flag (`127.0.0.1:12029` on
  testnet), and `mine start` refuses if the daemon reports a different
  network than the CLI was started with.

Switching networks is a restart (`exit`, then start again with the other
flag) — a deliberate speed bump between test money and real money.

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

`shekyl-wallet-rpc` is the JSON-RPC server behind every Shekyl wallet
client: `shekyl-cli` hosts one in-process for you over a private local
endpoint, so most users never start it directly. Run it yourself for
tooling that speaks JSON-RPC over HTTP, or to serve several wallets from one
process. The contract is `docs/api/wallet_rpc.yaml`; the flag reference is
`docs/EXECUTABLES.md` §3.

### Launching

```bash
./shekyl-wallet-rpc \
    --wallet-dir /path/to/wallets \
    --rpc-bind 127.0.0.1:29500 \
    --rpc-login user:password \
    --daemon-address http://127.0.0.1:11029
```

### Key flags

| Flag | Description |
|------|-------------|
| `--wallet-dir <path>` | Directory of wallet files; `create_wallet` / `open_wallet` work here |
| `--rpc-bind <addr>` | A numeric `IP:PORT` (default `127.0.0.1:29500`; IPv6 as `[::1]:29500`; hostnames are not resolved) or `uds:///path/to.sock` (Unix). Wildcard addresses (`0.0.0.0`, `::`, `[::]`) are **refused** — bind a specific IP address; a non-loopback address **requires** `--rpc-login` |
| `--rpc-login <user:pass>` | HTTP basic auth, both halves non-empty (anything else is refused at startup). Mandatory off loopback; on loopback or a UDS socket it may be omitted |
| `--disable-rpc-login` | Run without auth — refused off loopback, and refused together with `--rpc-login` (pass one) |
| `--daemon-address <url>` | Your node's RPC URL. Default: this machine's daemon at the RPC port for `--network`. A daemon that is not loopback is disclosed in the log at startup, `--proxy` or not (see "Connecting to a daemon" above) |
| `--proxy <socks5h://…>` | Route the daemon connection through a SOCKS5h proxy |
| `--network <name>` | `mainnet` (default), `testnet`, or `stagenet` |

**Three things the server will refuse, on purpose.** Binding `0.0.0.0` or
`::` binds every interface your machine has *and every one it gains later*
(a VPN, a hotspot, a container bridge), so the server asks you to name the
one interface you mean. And it will not serve without authentication on any
address other than loopback: a wallet RPC the network can reach honours
every request, spends included. **The network being yours is not what
provides the security** — the TV, the smart plug and a guest's phone are on
your home network too. And it answers only requests whose `Content-Type` is
`application/json` (anything else gets HTTP 415): that is what stops a web
page in your browser from driving the wallet on `127.0.0.1` — every real
client sends it anyway — and, when you run without `--rpc-login`, it answers
only to its IP address or `localhost`, not to a hostname a web page could
have pointed at your machine.

### Method categories

All methods are called via `POST /json_rpc`. The specified surface (per the
contract's `x-shekyl-method-registry`):

- **Wallet lifecycle:** `create_wallet`, `restore_wallet`, `open_wallet`,
  `close_wallet`, `change_password`, `get_wallet_info`
- **Balance and address:** `get_balance`, `get_primary_address`
- **Sending:** `build_pending_tx`, `submit_pending_tx`,
  `discard_pending_tx`, `abandon_tx`, `estimate_tx_size_and_weight`,
  `get_default_fee_priority`
- **History:** `get_transfers`, `get_transfer_by_id`, `set_tx_note`,
  `get_tx_note`
- **Sync:** `refresh`, `rescan_blockchain`, `get_height`, `get_version`
- **Payment requests and URIs:** `create_payment_request`,
  `list_payment_requests`, `make_uri`, `parse_uri`
- **Staking:** `stake` (activation), `get_staked_balance`,
  `get_staked_outputs`, `staking_info` (reads); `stake_in`, `drain`,
  `get_drain_balance` (WI-RPC-5); `unstake` and `collect_unstaked` (the
  composed exit, PR-C); `acknowledge_staking_outcome` (clears an ending
  `staking_info` reports). There is no `claim` RPC — emission claims are
  engine-side automation, and that name is rejected, not reserved.
- **Proofs and signing:** `get_tx_proof`, `check_tx_proof`,
  `get_reserve_proof`, `check_reserve_proof`, `sign_message`,
  `verify_message`

There are **no wallet-RPC mining methods**: the daemon does the hashing,
and mining is controlled through the daemon's own restricted-off endpoints
(which the `shekyl-cli` `mine` verbs drive). Monero-era names the registry
refuses outright — `get_tx_key`/`check_tx_key`, spend proofs,
`sweep_*`/accounts, cold-signing export/import — are recorded as REJECTED
in the contract so they cannot be silently re-minted.

For the full RPC reference, see the wallet-RPC contract
[`docs/api/wallet_rpc.yaml`](api/wallet_rpc.yaml).

---

## Security and Backup

### Your mnemonic seed

Your 24-word BIP-39 seed phrase is the **only** way to recover your
wallet. No company, no foundation, no developer can recover it for you.

The seed is shown **exactly once**, when the wallet is created or
restored; there is no `seed` command to redisplay it afterwards (see "No
secret export" below). If you did not record it then, and the wallet file
is still healthy, create a new wallet and transfer the funds to it.

If you opted in to a BIP-39 passphrase at creation time, the seed words
alone are not sufficient -- you must also retain the passphrase. There
is no on-device "encrypted seed" variant; the passphrase is never
stored.

**Write your seed on paper. Store it offline. Never share it.**

### No secret export, no view-only wallets

The wallet deliberately has **no secret-egress surface**: there are no
`viewkey` / `spendkey` display commands, no key-image export, and no
view-only ("watch-only") wallet variant. Your seed backup is shown exactly
once, at create/restore time — everything else derives from it. Under
FCMP++ a view key is not a chain-scanning credential the way it was in
CryptoNote-era coins, so a view-only wallet would not deliver the
third-party-auditor use case; balance disclosure to a third party is
served by reserve proofs (`prove reserve` / `check reserve`)
with scoped, cryptographic disclosure instead of a standing credential.

### Changing your password

```
mainnet> wallet password
```

prompts for the current password, then the new one twice.

---

## Troubleshooting

### Daemon won't sync

- **Firewall:** Ensure port 11021 (P2P) is open for inbound connections.
  The outbound count is a protocol constant, not an option: a node that
  takes no inbound still syncs over the peers it dials. The daemon's
  "p2p inbound state" log line says how many inbound connections it holds.
- **Disk space:** A full node needs ~50 GB. There is no pruning flag. The
  stripe engine was deleted 2026-09-21 (`PDM-Q7`); uniform archival discard
  has not landed (S-PRUNE, `docs/design/DRS_E1_SPRUNE.md`).
- **Damaged chain store:** there is no command that rolls blocks back. If
  the daemon refuses to open its store, stop it, delete `chain.db` and
  `pool.db` from its data directory, and start it again: it downloads the
  chain from peers. Leave the rest of the data directory in place.

### Wallet balance is wrong or zero

- **Not synced:** Run `wallet refresh`. `status` shows the wallet's
  height next to the daemon's — make sure the daemon is fully synchronised
  first.
- **Full rescan:** `wallet rescan` rebuilds your transaction history from the
  chain (transaction keys, notes, payment requests and staking records are
  kept). This can take a while. `wallet rescan hard` is the same rescan.

### Transaction not confirming

- Make sure the daemon is synced (`status` in the wallet shows both
  heights; `chain` and `sync status` in `shekyl-cli` show the daemon's
  connections and sync state).
- The transaction pool can be checked with `txpool list` in `shekyl-cli`.
- Check the transaction's state with `tx list` / `tx show <id>`
  in the wallet. A dispatched send that the network has dropped can be
  given up with `tx abandon <txid>`.

### Reading logs

Increase daemon verbosity for debugging:

```bash
./shekyld --log-level debug
```

Or change it at runtime from `shekyl-cli`:

```
option set log-level debug
```

`shekyl-cli` logs to stderr only (warnings and up by default; tune with
`SHEKYL_LOG`, see "Logging" below) — it writes no log file, so nothing
about your wallet activity lands on disk beside the wallet.

---

## Logging

Every Shekyl binary logs through the `shekyl-logging` crate, built on
[`tracing`] and [`tracing-subscriber`]. How you set the level depends on
the binary.

### For operators

**`shekyld`** takes its levels from its configuration, never from the
environment:

- `log-level` is the base level: `error`, `warn` (the default), `info`,
  `debug` or `trace`.
- `log-category` sets a level for one subsystem, as `subsystem=level`:
  `daemon`, `p2p`, `sync`, `chain`, `store`, `txpool`, `relay`, `rpc`,
  `tor`, `miner`, `notify` or `archival`. Another key is refused when the
  configuration is read. For example, in `shekyld-<network>.toml`:

  ```toml
  log-level = "info"
  log-category = { p2p = "debug", tor = "trace" }
  ```

  Both are runtime options, so a change takes effect without a restart.

`shekyld` writes standard error and its log file (`log-file`, by default
`logs/shekyld-<network>.log` under the daemon's root). `log-size-max`
bounds the disk the live file and its archives use together. The file and
every archive are created with POSIX mode `0600`.

**`shekyl-cli` and `shekyl-wallet-rpc`** read `SHEKYL_LOG`, in
[`tracing-subscriber` `EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)
syntax:

```
SHEKYL_LOG=warn                                  # bare level: all targets at WARN
SHEKYL_LOG=info,shekyl_wallet_rpc=debug          # level per target
SHEKYL_LOG=shekyl_wallet_rpc::scanner=trace      # nested module target
```

A target is a Rust module path. A log category of the old C++ daemon
(`net.p2p:DEBUG`, `blockchain`, `*:WARNING`) names nothing, and
`SHEKYL_LOG` refuses it by name at start rather than filtering in silence.
`RUST_LOG` and the `MONERO_LOGS` / `MONERO_LOG_FORMAT` variables are not
read.

Unset, `shekyl-cli` logs warnings and up and `shekyl-wallet-rpc` info and
up. `shekyl-cli` writes standard error only; redirect with `2> path` if
you want a file. `shekyl-wallet-rpc` writes standard error, and a file too
when you pass `--log-file <PATH>`: the parent directory is created with
mode `0700` and the file with `0600` on POSIX, and the file is not
rotated.

Lines are `tracing-subscriber`'s format: an RFC 3339 UTC timestamp, the
level as a full word, and the target.

### For integrators

The `shekyl-logging` crate is the hinge. Read
[`rust/shekyl-logging/README.md`](../rust/shekyl-logging/README.md)
before writing a new Rust binary; in particular, note the `LoggerGuard`
footgun (dropping the guard silently loses buffered events; the crate
uses `#[must_use]` and a workspace-wide
`clippy::let_underscore_must_use = "deny"` lint to catch the common
shape). A subsystem's targets are listed in
`rust/shekyl-logging/src/subsystem.rs`; a crate rename changes that list,
never an operator's configuration.

[`tracing`]: https://docs.rs/tracing
[`tracing-subscriber`]: https://docs.rs/tracing-subscriber

---

## Glossary

| Term | Meaning |
|------|---------|
| **Address** | Your Bech32m-encoded public identifier for receiving SKL. Contains both classical (~113 char) and PQC (~1,750 char) key segments. Safe to share. |
| **Atomic unit** | The smallest unit of SKL. 1 SKL = 1,000,000,000 atomic units. |
| **Block** | A bundle of transactions added to the blockchain roughly every 2 minutes. |
| **Block height** | The sequential number of a block, starting from 0. |
| **Block reward** | New SKL created and given to the miner who finds a valid block. |
| **Config file** | A TOML file (`/etc/shekyl/shekyld-<network>.toml` by default) holding daemon options under their command-line names, or another file named with `--config-file`. |
| **Daemon** | The background program (`shekyld`) that connects to the Shekyl network and maintains the blockchain. |
| **Difficulty** | A measure of how hard mining puzzles are. Adjusts automatically to target ~2-minute blocks. |
| **Emission** | The schedule by which new SKL is created. The total supply is mathematically capped. |
| **FCMP++ membership proof** | A zero-knowledge proof that the spent output exists in the full UTXO set. The proof does not identify which output, transactions publish no per-output value derived from the key a spend reveals, and amounts and recipients remain hidden. (A pre-genesis defect, `PL-D1`, briefly published such a value; `PL-D3` closed it on 2026-09-14, before launch, by publishing a blinded commitment instead — one only the proof itself can check, without revealing it.) |
| **Hybrid signature** | Two signatures on every transaction: Ed25519 (classical) and ML-DSA-65 (quantum-resistant). |
| **Key images** | Cryptographic markers that prevent double-spending. Derived and tracked internally by the wallet; there is no export surface. |
| **KDF rounds** | Key derivation function iterations; higher values make wallet password brute-forcing harder. |
| **Mnemonic seed** | The 24 BIP-39 words that fully restore your wallet (plus your passphrase, if you opted in to one). Treat as a master password you can never change. |
| **ML-DSA-65** | A quantum-resistant signature algorithm standardized by NIST (FIPS 204). |
| **Privacy** | FCMP++ proofs, stealth addresses, and per-output PQC keys (hybrid X25519 + ML-KEM-768) hide who sends, who receives, and how much. Automatic. |
| **Pruning** | Removing old prunable transaction data to reduce storage. The node can still verify new blocks. |
| **RandomX** | Shekyl's mining algorithm, designed for regular CPUs. |
| **RPC** | Remote Procedure Call -- the JSON-based API exposed by the daemon and wallet RPC server. |
| **Staking** | Locking SKL for a period to earn yield from the emission pool. |
| **Stealth address** | A one-time address generated for each transaction so only sender and receiver know the destination. |
| **Payment request** | A merchant invoice record (amount, label, expiry) tied to your primary address — replaces per-sender subaddress rotation. |
---

## Getting Help

- **In-repo documentation:** Browse the
  [docs/ directory](https://github.com/Shekyl-Foundation/shekyl-core/tree/main/docs)
  or the [online documentation browser](https://shekyl.org/resources/documents).
- **GUI wallet guide:**
  [USER_GUIDE.md](https://github.com/Shekyl-Foundation/shekyl-gui-wallet/blob/main/docs/USER_GUIDE.md)
  covers the same features from the graphical interface.
- **Source code:** [shekyl-core on GitHub](https://github.com/Shekyl-Foundation/shekyl-core)
- **Built-in help:** Run `shekyld --help` or `shekyl-cli --help`. Daemon
  commands are `shekyl-cli` words.

---

*This guide covers Shekyl CLI tools v0.4.x. TransactionV3 with FCMP++
membership proofs and hybrid PQC spend authorization is the required
transaction format on the rebooted chain.*
