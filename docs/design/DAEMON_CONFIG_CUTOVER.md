# Daemon configuration cutover — the option surface moves to Rust

**Status: OPEN — Round 0 brief, held (2026-10-14; DC-Q13…DC-Q17 ruled the same day).** Rule 26 is cited.
The input grammar's Part A is ruled and merged (#1067, merge `7cf70b7052`):
its rules are the cursor rule
[`83-input-grammar`](../../.cursor/rules/83-input-grammar.mdc) and the
daemon's names are [`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) §5. This brief is
the single replacement of the 2026-10-13 draft, written under Rick's review
of that draft: the C++ is not canonical, so the configuration is designed in
Rust and the C++ appears only as what the cutover deletes. The brief owns
the mechanism. Option names, kinds, defaults, surfaces and diagnostic codes
are the grammar's and are cited, never restated. No implementation starts
until PR-3 (#1056) merges and the grammar's Part B (#1068) merges with the
run-mode row of DC-Q17 and is folded in (§1.2).

Anchors pinned to `dev` `7cf70b7052` (2026-10-14; the option surface is
unchanged from `737da31276`, where the Round 0 read-out was taken). PR-3
citations are branch citations at `8359ef5312` (`feat/p2p3-dialer-cutover`)
and are written without a leading `src/` or `rust/`, so the pinned-anchor
gate does not resolve them against `dev`. §9's pre-flight re-pins both at
the implementation pin.

Identifier families (registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2): **DC-Q** the
questions and their rulings, **DC-F** findings established at source,
**DC-N** items Rick added at the ruling. The crates are `shekyl-options` (the
grammar's shared crate) and `shekyl-daemon-config` (IG-Q13).

---

## 1. Rulings and open questions

### 1.1 Ruled (Rick, 2026-10-13 and 2026-10-14)

| Id | Ruling | Where it lands |
| --- | --- | --- |
| DC-Q1 | Rust reads every option directly. Every Rust consumer takes its section of the typed configuration at construction. Every C++→Rust configuration push and every configuration parameter on a Rust start function is deleted in the cutover. A Rust-owned read-only snapshot serves only the C++ that still consumes values, and only shrinks. No C++ parses or relays configuration | §2, §3, §4 |
| DC-Q2 | The Rust parse runs before anything is constructed; nothing starts on a refusal. Diagnostics and exit codes are IG-11's. The ban file is read in Rust at parse | §2.2 |
| DC-Q3 | TOML at the per-network system path, `--config-file` replacing it whole; no environment layer; a command-line list replaces the file's whole; the file validated whole before anything applies; ownership and permission checks; one effective-configuration line; the daemon never writes its file (`INPUT_GRAMMAR.md` §0 R2, R6, R7; the `config-file` row) | §2.4 |
| DC-Q4 | No backward compatibility pre-genesis: `removed_flags.{h,cpp}` is deleted, not ported; refused features keep REJECTED rows in the Rust table (IG-10); an unknown name gets a nearest-name suggestion | §4 |
| DC-Q5 | An explicit `data-dir` is taken as given; the default layout keeps the network subdirectory. The defence against a directory serving the wrong chain is a network marker owned by this lane, in Rust, separate from the DC-N1 lock (IG-Q17, ruled 2026-10-13). DC-F1 is a separate chain-store check and no longer blocks the cutover. The regtest Tor skip, the regtest wipe and `check_block_rate`'s regtest skip are deleted: FAKECHAIN conforms to production | §2.5, §2.6 |
| DC-Q6 | The deletions and folds of `INPUT_GRAMMAR.md` §5 (UPnP and miniupnpc, `out-peers`, the debug knobs, `bg-mining-*`, and the rest). Runtime changes share the startup constructor (IG-12), implemented here | §2.7, §4 |
| DC-Q7 | SOCKS credentials are typed secrets, file only, held only in Rust, plumbed to the dialer. Home from the passwd entry and the known-folder API (IG-13, IG-Q14). The Windows default-directory split goes | §2.4, §2.5 |
| DC-Q8 | `utils/conf/shekyld.conf` is deleted; every launcher, the GUI sidecar and the Foundation configurations in `shekyl-dev` change in step; a recipe gate | §5 |
| DC-Q9 | Generated documentation and its gate (IG-9) | §5.3 |
| DC-Q10 | (a), an operator-configured public address: `clearnet-advertise`. (b) rejected; (c) died with UPnP | §2.8, §8 |
| DC-Q11 | The deletion table, extended by every ruling above | §4 |
| DC-Q12 | One cutover for the parse surface and every Rust consumer, based on PR-3 after it merges. The blockchain utilities keep their own option sets until IG Part B | §9 |
| Review of `057112b2` (Rick, 2026-10-13) | §3 is the Rust typed configuration by section with a "replaces" column; the C++ list lives only in §4. One RPC start call carrying the core handle. No configuration or Rust-derived value crosses to the zone host. The Rust-ownable runtime changes call their Rust owners. A Windows permission allowlist. §6 lists only failures the types cannot prevent. The snapshot recounted after IG-Q4 | throughout |
| Grammar §0 (Rick, 2026-10-13; merged with #1067) | `shekyld`'s process entry, `main()`, moves to Rust in this lane (the Windows service round, RT-16) | §2.2, DC-Q13 |
| DC-Q13 (Rick, 2026-10-14) | (b): CMake builds the executable and its `main` makes one call into Rust, which owns the process. The C++ remnant exposes one coarse entry pair, `run(snapshot)` returning a status and `stop()`, both `noexcept` and catching every C++ exception, so none unwinds through Rust frames. Rust's entry catches its own panics into an exit status. One signal owner, Rust: `tools::signal_handler::install` is deleted from `Daemon::run`. The pair replaces the orchestration in `main.cpp` and `daemon.cpp`, and the C++ shrinks | §2.2, §4.2 |
| DC-Q14 (Rick, 2026-10-14) | A Rust runner owns the notify commands, fed chain facts by the C++ event sites (requirements in §2.10; the reaping hazard it removes is DC-F12) | §2.10, §4.2 |
| RT-16, Windows service mode (Rick, 2026-10-13; recorded by the Windows lane for [`RPC_CHANNEL.md`](RPC_CHANNEL.md) RT-16, not yet on `dev`) | `shekyld` itself answers the Windows Service Control Manager, in Rust, entered only through RT-16's declared service-mode switch, which is a daemon-config option. No wrapper process and no self-registration: installing is the installer's and `shekyl-cli`'s, and restart on failure is the SCM's failure actions, set at install. On POSIX nothing changes: systemd and launchd run the foreground process. A run-as-user daemon's home is always per-user (`%LOCALAPPDATA%` on Windows, never the roaming profile, whatever the token); a machine-wide home exists only in the declared service mode, and only when the installer created it. The SCM dispatcher needs the process entry, which is this lane's (DC-Q13) | §2.2, §2.4, §2.5, DC-Q17 |
| DC-Q15 (Rick, 2026-10-14) | The lock is `shekyld.lock` at the data directory's root, held through `flock` or `LockFileEx` and never deleted on exit. The marker is `shekyld.network` (TOML content, not a `.toml` name, so it is not mistaken for operator configuration), holding `network` and `network-id`, written by temporary file, `fsync`, rename and directory `fsync`, read only under the lock. Its refusals tell another network apart from the same network with a different network id (an earlier release's data after a regenesis: use a fresh `data-dir`) | §2.2, §2.6, §6 |
| DC-Q16 (Rick, 2026-10-14) | One generic set request and one generic show request, carrying the option's name and its value as text in the grammar's syntax, parsed by the table and routed to the row's owner. Show never returns a secret, only that it is set. Both need the admin grant by default; a row may declare itself visible at the view grant, and otherwise the view grant sees nothing. Set accepts only rows marked Runtime and refuses any other with a code saying it is startup-only. Show reports each value's source (`default`, `file`, `cli`, `runtime`). The RPC lane names the methods | §2.7, §6 |
| DC-Q17 (Rick, 2026-10-14) | (1) The run mode is an option of the closed-set kind, command-line only: it selects the config root, so the file cannot set it, and a file key is refused. The grammar round names it. (2) The config-file default follows the run mode on every platform: in service mode the system root (`/etc/shekyl` on Unix, the installer-created `%ProgramData%\Shekyl` on Windows); in user mode the per-account root (the home's `.shekyl` on Unix, `FOLDERID_LocalAppData\Shekyl` on Windows). A directory that fails the allowlist of §2.4 is refused, never read | §2.4, §2.5, §6 |
| RT-W14's start reporting (Rick, 2026-10-14) | Under the SCM the Rust entry reports `SERVICE_START_PENDING` with checkpoints and wait hints through steps 2 to 8 of §2.2, and `SERVICE_RUNNING` only when RT-15's rendezvous is published. Without it the SCM's start timeout of about 30 seconds kills the service (error 1053): the managed Tor's bootstrap alone may take 300 seconds ([`src/p2p/net_node.inl:892`](../../src/p2p/net_node.inl)) | §2.2 |

### 1.2 Open before implementation

- **The grammar's Part B (#1068, open).** Rick's Part B ruling of
  2026-10-14 changes IG-12 and two names this brief uses: a runtime value is
  marked in a Runtime column and changed with `option set` and read with
  `option show` (source `runtime`); mining starts and stops with `mine
  start` and `mine stop`; `mining-address` and `mining-threads` become
  `mine-address` and `mine-threads`; the per-account root on Windows is
  `FOLDERID_LocalAppData` plus `Shekyl`. This brief cites the merged Part A
  and is changed in one replacement when #1068 merges.
- **The run mode's name and row (DC-Q17).** The grammar round names the
  option and adds its row; DC-Q16's per-row view visibility is a column of
  the same table. Neither exists on `dev` or in #1068 at the time of
  writing; `run-as-service` is a REJECTED name (`INPUT_GRAMMAR.md` §5).

---

## 2. The mechanism

### 2.1 Ownership

`shekyl-daemon-config` builds the daemon's table from `shekyl-options`
(IG-15) and owns precedence, the per-network file, the permission checks,
the lock, the marker, the effective-configuration line, and the typed
configuration: one section per Rust owner (§3). The composition root is the
daemon's Rust image, which already names itself so
([`rust/shekyl-daemon-image/src/lib.rs:30-36`](../../rust/shekyl-daemon-image/src/lib.rs)).
The parse result is held in Rust for the life of the process. Each Rust
owner takes its section when it is constructed and holds it; nothing
re-reads configuration later.

Cross-option constraints are types, so a contradiction cannot be built
(`INPUT_GRAMMAR.md` §4): the clearnet posture is `Off` or `On { listen,
socks, advertise }`, the Tor posture is `Off`, `Managed` or `Operator {
socks, onion }`, a SOCKS endpoint for a connector that is off does not
exist, and an offline node is the product of the two being off (IG-Q3).

What crosses the FFI after the cutover, and nothing else:

- Rust to C++: the remnant's entry pair, `run(snapshot)` and `stop()`
  (DC-Q13), and the one runtime request that still reaches the miner
  (§2.7).
- C++ to Rust: the core handle, once, to the RPC start (§2.3); the core's
  tip, published as it changes (`shekyl_core_publish_tip`, `dialer_ffi.rs:372`
  on PR-3, called from `blockchain.cpp:5959` there); chain facts for the
  notify runner (§2.10).

### 2.2 The start sequence (DC-Q13)

1. `main()` calls `shekyl_daemon_main()`; Rust owns the process from here.
   Rust's entry catches its own panics and turns them into an exit status.
   On Windows, in service mode (DC-Q17), the entry connects to the Service
   Control Manager's dispatcher before anything else (the dispatcher is
   RT-W14's, built on this entry); outside the SCM that connect fails and
   the start is refused (rule 82). A start by the SCM in user mode fails in
   the SCM's own terms. Under the SCM the entry reports
   `SERVICE_START_PENDING`, with a checkpoint and a wait hint at each of
   steps 2 to 8 below, and `SERVICE_RUNNING` only when RT-15's rendezvous
   is published; the start takes longer than the SCM's default timeout of
   about 30 seconds, and a service that reports no progress is killed
   (error 1053).
2. Rust reads its arguments with `std::env::args_os` (IG-Q2), resolves
   the run mode, `--network` and `--config-file`, checks the file's permissions (§2.4),
   reads and validates it whole, applies the command line over it per key,
   resolves every path (§2.5), reads the ban file, and constructs the typed
   sections. `--help` and `--version` are answered here. A refusal renders
   through IG-11 and exits with status 2; nothing below runs.
3. Rust takes the data-directory lock, `shekyld.lock` (DC-N1, DC-Q15),
   through `flock` or `LockFileEx`, and holds it for the life of the
   process; the file is never deleted. There is no lock today:
   `tools::file_locker` ([`src/common/util.h:101-105`](../../src/common/util.h))
   has no caller, and the comment at
   [`src/cryptonote_core/cryptonote_core.cpp:480`](../../src/cryptonote_core/cryptonote_core.cpp)
   says "try to lock it" over code that only creates the directory.
4. Under the lock, Rust checks the network marker (§2.6), writing it when
   the directory holds no daemon store.
5. Rust initialises logging from its section, then emits the required
   announcements: the effective-configuration line, every `dev-` lever set,
   and the posture line (Tor-only, clearnet-only, offline), to the log and
   to standard error whatever the level (IG-14).
6. Rust installs the one signal handler and starts the managed Tor's
   bootstrap, if the Tor posture is `Managed`. Nothing that serves peers or
   clients starts yet.
7. Rust fills the snapshot (§2.9) and calls the remnant's `run(snapshot)`
   on a thread of its own. C++ constructs core, which publishes its tip
   (`shekyl_core_publish_tip`), then the protocol handler and what remains
   of `net_node`, and calls the RPC start once with the core handle (§2.3).
8. Only then does Rust start the zone host, its listeners and the dialer,
   each from its section: a peer that connects earlier would find no tip
   to handshake with and no protocol handler to receive its messages.
9. Stop is Rust's, and there is one stop path, fed by the POSIX signals,
   every Windows console event (Ctrl-C, Ctrl-Break, window close, logoff,
   shutdown), and the SCM's stop and pre-shutdown controls (DC-F13). The
   handler stops the dialer and the zone host, stops the RPC, calls the remnant's `stop()`,
   joins the `run` thread, stops the managed Tor, and releases the lock
   last. `run` and `stop` are `noexcept` and catch every C++ exception;
   `run` returns its status to Rust, which becomes the exit status.

`tools::signal_handler::install` in `Daemon::run`
([`src/daemon/daemon.cpp:272`](../../src/daemon/daemon.cpp)) is deleted:
one process has one signal owner. The orchestration in
`src/daemon/main.cpp` and `src/daemon/daemon.cpp` is replaced by the entry
pair.

### 2.3 RPC: one start call

`shekyl_daemon_rpc_start` today takes the core pointer and eight
configuration values
([`rust/shekyl-daemon-rpc/src/ffi_exports.rs:78-88`](../../rust/shekyl-daemon-rpc/src/ffi_exports.rs)),
and C++ calls it once per listener from a loop over admin and restricted
instances ([`src/daemon/daemon.cpp:175`](../../src/daemon/daemon.cpp),
[`:194`](../../src/daemon/daemon.cpp), [`:287-326`](../../src/daemon/daemon.cpp)).
After the cutover it takes the core handle and nothing else. The Rust
server builds its whole listener set from the RPC section: every
`rpc-admin-listen` endpoint at the admin grant and every `rpc-view-listen`
endpoint at the view grant, each loopback only by RT-14
([`RPC_CHANNEL.md`](RPC_CHANNEL.md), RT-14), the origin list, and the one
connection cap. There is no per-listener C++ loop and no admin-or-restricted
parameter; the C++ `rpcs` vector, the second `core_rpc_server` built for the
restricted port, and `core_rpc_server::init`'s reading of options go.

### 2.4 The config file (DC-Q3)

The default location follows the run mode on every platform (DC-Q17): in
service mode the system root (`/etc/shekyl` on Unix, the
installer-created `%ProgramData%\Shekyl` on Windows), in user mode the
per-account root (the home's `.shekyl` on Unix,
`FOLDERID_LocalAppData\Shekyl` on Windows); the file in it is chosen by
the network. Precedence and the missing-file rule are the `config-file` row
of `INPUT_GRAMMAR.md` §5: a missing file at the default path is the
defaults, stated in the effective-configuration line; a missing file at a
path the operator named refuses with a code naming the path. The run mode
and the network are command-line only, because they choose the file.

The checks run in this order, so that no value from an unsafe file is ever
read:

1. Open the file and judge the opened handle, not the path: a symbolic link
   is judged by its target.
2. Refuse if the file, or any directory from it to the root, can be written
   by anyone outside the permitted principals.
3. Read and parse the whole file; refuse on any defect (IG-11).
4. If the parsed file holds a secret, refuse if the file can be read by
   anyone outside the permitted principals.
5. Apply.

The permitted principals are root and the daemon's account on Unix. On
Windows the check is an **allowlist**: write is permitted only to SYSTEM,
Administrators and the daemon's own account, and any other access-control
entry that grants write refuses, whatever it names (Authenticated Users,
INTERACTIVE, a user's SID, CREATOR OWNER, Everyone, Users). The installer
creates the directory with exactly that list. The read check for a secret
uses the same allowlist.

The checks above are the same in both run modes. In user mode the
daemon's own account may write its file: whoever can write that account's
files can already run code as it. In service mode only the system root is
read, and only through the installer's restrictive list, which closes the
pre-created-directory hole of §7 item 7.

### 2.5 Paths and secrets (DC-Q7, IG-13)

- Home comes from the passwd entry on Unix and the known-folder API on
  Windows, never from `HOME`, `XDG_*` or `%APPDATA%`. On Windows a
  run-as-user daemon's root is per-user and never the roaming profile
  (RT-16; the grammar's Part B names `FOLDERID_LocalAppData`); a
  machine-wide root exists only in the declared service mode, created by
  the installer. Today it comes from
  `HOME`, with `/` when unset
  ([`src/common/util.cpp:645-649`](../../src/common/util.cpp)). An account
  with no home has no default paths, and the paths it needs are named on
  the command line (the shipped unit already passes both).
- The per-user runtime directory, when an owner needs one, comes from the
  platform's own interface (IG-Q14). This slice reads none; the socket
  directory of RT-W10 is RPC_CHANNEL's.
- The default data directory is the home's `.shekyl` with the network's
  subdirectory; an explicit `data-dir` is taken as given (DC-Q5). One
  Windows rule: the admin-membership split in
  [`src/common/daemon_default_data_dir.cpp:79-98`](../../src/common/daemon_default_data_dir.cpp)
  is deleted with the file.
- The data-directory port suffix
  ([`src/p2p/net_node.inl:1045-1048`](../../src/p2p/net_node.inl)) is
  deleted: it was a silent path move standing in for a lock.
- SOCKS credentials are typed secrets: zeroized, shown in the
  effective-configuration line only as set (IG-6, IG-14), held in Rust,
  never in the snapshot, handed to the dialer with the endpoint. Today they
  are parsed ([`src/net/parse.cpp:267-296`](../../src/net/parse.cpp)) and
  never reach Rust (DC-F3); `rust/shekyl-socks` already speaks RFC 1929
  ([`rust/shekyl-socks/src/lib.rs:6-36`](../../rust/shekyl-socks/src/lib.rs)).

### 2.6 The network and the marker (DC-Q5)

The network selects one params row: the ports, the default data
subdirectory, the default log file name, the seed list, and the network id
derived from genesis. FAKECHAIN conforms to production. Deleted outright:
the managed Tor skip ([`src/p2p/net_node.inl:684`](../../src/p2p/net_node.inl),
[`:854`](../../src/p2p/net_node.inl)), the database wipe on start
([`src/cryptonote_core/cryptonote_core.cpp:516-524`](../../src/cryptonote_core/cryptonote_core.cpp)),
and `check_block_rate`'s regtest skip
([`src/cryptonote_core/cryptonote_core.cpp:1621`](../../src/cryptonote_core/cryptonote_core.cpp)).
A harness that wants a fresh chain uses a fresh `data-dir`.

The marker (IG-Q17, DC-Q15) is `shekyld.network` at the data directory's
root: TOML content holding `network` and `network-id`, under a name that is
not mistaken for operator configuration. It is written to a temporary file,
`fsync`ed, renamed into place, and the directory is `fsync`ed; it is read
only while the lock is held, so two starts cannot both find an empty
directory and both mark it. The cases:

- The directory holds no daemon store: the marker is written, recording the
  network name and the network id, before any store is created.
- It holds a marker for this network: start.
- It holds a marker for another network: refuse with a code naming both
  networks and the fix (a different `data-dir`, or the other network).
- It holds a marker for this network's name with a different network id:
  refuse with its own code. This is an earlier release's data after a
  regenesis, and the fix is a fresh `data-dir`.
- It holds a daemon store and no marker: refuse likewise. The directory is
  never marked after the fact.

"A daemon store" is a closed set the pre-flight reads at the implementation
pin. At `7cf70b7052` it is the LMDB environment
(`CRYPTONOTE_BLOCKCHAINDATA_FILENAME`,
[`src/cryptonote_config.h:275`](../../src/cryptonote_config.h)) and the
peer-state file (`P2P_NET_DATA_FILENAME`,
[`src/cryptonote_config.h:277`](../../src/cryptonote_config.h)); the Rust
chain store joins it when the daemon opens one. The managed Tor's data
directory is not a store. DC-F1, the check of a store's block 0 against the
network, stays the chain-store lane's and does not block this cutover.

### 2.7 Runtime changes (IG-12)

Today every runtime change is forwarded to the C++ JSON handlers through
one dispatch
([`rust/shekyl-daemon-rpc/src/handlers/json.rs:82-91`](../../rust/shekyl-daemon-rpc/src/handlers/json.rs),
[`:389-395`](../../rust/shekyl-daemon-rpc/src/handlers/json.rs)). After the
cutover:

- `/set_limit` builds the two rate values with the constructors of
  `p2p-upload-max` and `p2p-download-max` and calls the link's Rust owner.
- `/in_peers` builds the value with `p2p-inbound-max`'s constructor and
  calls the zone host's admission owner.
- `/set_log_level` and `/set_log_categories` build their values with the
  constructors of `log-level` and `log-category` and call `shekyl-logging`.
- `/start_mining` builds `mining-address` and `mining-threads` with their
  constructors and is the only one that reaches C++, carrying the validated
  values, until the miner moves to Rust.
- `/out_peers` and its console command are deleted with the option.

Each refuses exactly as the startup parse does. The live value belongs to
its owner, and no request writes the config file.

Under the Part B ruling these handlers become one generic set request and
one generic show request (DC-Q16). Each carries an option's name and, for
set, its value as text in the grammar's syntax; the table's own parser and
constructor build the value and the request goes to the row's owner. Set
accepts only a row marked Runtime and refuses any other with a startup-only
code. Show reports each value with its source (`default`, `file`, `cli`,
`runtime`), so an operator sees that a runtime change does not survive a
restart, and shows a secret only as set. Both need the admin grant; a row
may declare itself visible at the view grant, and the view grant sees no
other row. The RPC lane names the two methods; `mine start` is the one
request that still reaches C++.

### 2.8 The clearnet public address (DC-Q10)

`clearnet-advertise` (`INPUT_GRAMMAR.md` §5) is read by the peer lists at
construction and given to the same own-address entry the onion uses
(`shekyl_peerlist_set_own_address`, `dialer_ffi.rs:537` on PR-3), so both
connectors obey one rule. Unset, clearnet stays dial-only, as PR-3 leaves
it, and the posture line says so.

### 2.9 The C++ snapshot

One read-only structure, filled once by Rust before the C++ remnant is
constructed, holding exactly the values whose reader is still C++. The
lane-owned knobs are not in it: under IG-Q4 they are not ported, and the
C++ keeps today's defaults as constants until their lanes decide.

| Field | Reader | From |
| --- | --- | --- |
| the resolved data directory | core (the LMDB environment) | `data-dir` |
| the network | core, the miner, the console client | `network` |
| offline, derived from both connectors being off | core ([`src/cryptonote_core/cryptonote_core.cpp:1552`](../../src/cryptonote_core/cryptonote_core.cpp)), the protocol handler | `clearnet`, `tor` (IG-Q3) |
| the fixed difficulty | core | `dev-difficulty` |
| the pool's weight bound | core | `txpool-weight-max` |
| sync on or off | the protocol handler | `dev-sync` |
| the mining address | the miner | `mining-address` |
| the mining threads | the miner | `mining-threads` |
| console on or off | the C++ console | `console` |
| the console's command words | the C++ console client | the positional words |
| the console's RPC endpoint | the C++ console client | the first `rpc-admin-listen` endpoint |

**Eleven fields.** A gate pins the count and fails when it rises; each later
slice that moves a reader deletes its field. If the pre-flight finds a C++
reader of the advertised address surviving PR-3, it is a twelfth field,
recorded there.

### 2.10 The notify runner (DC-Q14)

A Rust runner owns the three commands. Each C++ event site pushes the
event's facts through one FFI call per kind (a new block: height and hash;
a reorganization: split height, new height, blocks added, blocks removed;
a block-rate warning: the window in seconds, the observed and the expected
counts). The push hands the facts to the runner and returns: it never
blocks the chain path. The runner:

- runs the row's argument array with its `{name}` placeholders filled
  (IG-Q5), with no shell;
- clears the environment, the rule the Tor launcher already follows
  ([`rust/shekyl-tor-control-client/src/control/actor.rs:883`](../../rust/shekyl-tor-control-client/src/control/actor.rs));
- gives the child a null standard input and no inherited descriptors;
- reaps its own children and never changes a process-wide signal
  disposition (DC-F12);
- keeps at most one command in flight per kind; an event that arrives
  while one runs is coalesced or dropped, and each drop is counted in a log
  line. Today every event spawns without bound.

---

## 3. The typed configuration, by section

Each section is what its Rust owner needs, designed for that owner. Names,
kinds and defaults are `INPUT_GRAMMAR.md` §5's and are not restated. The
"Replaces" column names the C++ options §4 deletes.

| Section | Owner | Holds | Replaces |
| --- | --- | --- | --- |
| paths | `shekyl-daemon-config` (lock, marker); core through the snapshot | the run mode (user or service, DC-Q17), the resolved data directory and log file, and their sources | `data-dir`, `log-file`, `config-file`, `os-version` (folded into `version`) |
| logging | `shekyl-logging` | the level, the per-category levels, the disk budget for the live file and its archives (IG-Q19) | `log-level`, `max-log-file-size`, `max-log-files` |
| network | `shekyl-daemon-config`, read by every owner | the network and its params row | `testnet`, `stagenet`, `regtest` |
| clearnet connector | the zone host and the dialer | the posture: `Off`, or `On` with listen endpoints, an optional SOCKS endpoint with its credentials, and the advertised endpoints | `p2p-bind-ip`, `p2p-bind-ipv6-address`, `p2p-bind-port`, `p2p-bind-port-ipv6`, `p2p-use-ipv6`, `p2p-ignore-ipv4`, `p2p-external-port`, `proxy`, and `offline` with the Tor connector |
| Tor connector | `shekyl-tor` and the zone host | the posture: `Off`, `Managed`, or `Operator` with a SOCKS endpoint, its credentials, and an optional onion with its local listen endpoint | `no-ephemeral-tor`, `tx-proxy`, `anonymous-inbound` |
| p2p policy | the dialer and the peer lists | the operator's peers, the closed-network declaration (absent or non-empty, DC-F11), the local-range override, early disclosure, the ban file's entries, the inbound cap, the two rate bounds | `add-peer`, `seed-node`, `add-exclusive-node`, `allow-local-ip`, `p2p-disclose-early` (PR-3), `ban-list`, `in-peers`, `limit-rate-up`, `limit-rate-down`, `limit-rate`, `out-peers`, `tos-flag`, `no-igd`, `igd` |
| rpc | `shekyl-daemon-rpc` | the admin and view listener sets, the origin list, the connection cap | `rpc-bind-ip`, `rpc-bind-ipv6-address`, `rpc-use-ipv6`, `rpc-bind-port`, `rpc-restricted-bind-ip`, `rpc-restricted-bind-ipv6-address`, `rpc-restricted-bind-port`, `restricted-rpc`, `rpc-access-control-origins`, `rpc-max-connections`, `rpc-max-connections-per-public-ip`, `rpc-max-connections-per-private-ip`, `rpc-response-soft-limit`, `disable-rpc-ban` |
| txpool | core, through the snapshot | the weight bound | `max-txpool-weight` |
| notify | the Rust runner (DC-Q14) | three commands, each an argument array with its named placeholders | `block-notify`, `reorg-notify`, `block-rate-notify` |
| mining | the miner, through the snapshot | the address and the thread count | `start-mining`, `mining-threads`, the five `bg-mining-*` |
| dev | each lever's owner | the levers of `INPUT_GRAMMAR.md` §5, each accepted only on the networks its row names, never on mainnet (IG-8) | `fixed-difficulty`, `no-sync`, `clearnet-transport-encrypt`, `carrier-development`, the four environment levers |
| session | the C++ console, through the snapshot, until R8 | console on or off, the command words | `non-interactive`, `daemon_command` |

In no section, because nothing is configured: `keep-fakechain` (no wipe),
`max-concurrency` (IG-Q7), the three test levers, `show-time-stats`.
Lane-owned and not ported (IG-Q4): `prep-blocks-threads`, `block-sync-size`,
`span-limit`, `block-download-max-size`, `db-sync-mode`, `db-salvage`,
`keep-alt-blocks`, `pad-transactions`.

---

## 4. What is deleted

### 4.1 The C++ options (83 registered in `shekyld`, and PR-3's one)

Every row's disposition is `INPUT_GRAMMAR.md` §5's; the C++ declaration is
deleted in every case.

| File | Sites | Options |
| --- | --- | --- |
| [`src/daemon/main.cpp:102-120`](../../src/daemon/main.cpp), declared in [`src/daemon/command_line_args.h:38-141`](../../src/daemon/command_line_args.h) and [`src/common/command_line.cpp:71-72`](../../src/common/command_line.cpp) | 13 | `help`, `version`, `os-version`, `config-file`, `log-file`, `log-level`, `max-log-file-size`, `max-log-files`, `max-concurrency`, `proxy`, `non-interactive`, `daemon_command`, `carrier-development` |
| [`src/cryptonote_core/cryptonote_core.cpp:237-260`](../../src/cryptonote_core/cryptonote_core.cpp), declared [`:74-188`](../../src/cryptonote_core/cryptonote_core.cpp) | 20 | `data-dir`, `testnet`, `stagenet`, `regtest`, `keep-fakechain`, `fixed-difficulty`, `prep-blocks-threads`, `show-time-stats`, `block-sync-size`, `test-drop-download`, `test-drop-download-height`, `test-dbg-lock-sleep`, `offline`, `block-download-max-size`, `span-limit`, `max-txpool-weight`, `block-notify`, `reorg-notify`, `block-rate-notify`, `keep-alt-blocks` |
| [`src/cryptonote_basic/miner.cpp:278-286`](../../src/cryptonote_basic/miner.cpp), declared [`:92-98`](../../src/cryptonote_basic/miner.cpp) | 7 | `start-mining`, `mining-threads`, `bg-mining-enable`, `bg-mining-ignore-battery`, `bg-mining-min-idle-interval`, `bg-mining-idle-threshold`, `bg-mining-miner-target` |
| [`src/blockchain_db/blockchain_db.cpp:199-203`](../../src/blockchain_db/blockchain_db.cpp) | 2 | `db-sync-mode`, `db-salvage` |
| [`src/p2p/net_node.inl:107-136`](../../src/p2p/net_node.inl), declared [`src/p2p/net_node.cpp:93-158`](../../src/p2p/net_node.cpp) | 27 on `dev`, 26 at PR-3's head | `p2p-bind-ip`, `p2p-bind-ipv6-address`, `p2p-bind-port`, `p2p-bind-port-ipv6`, `p2p-use-ipv6`, `p2p-ignore-ipv4`, `p2p-external-port`, `allow-local-ip`, `add-peer`, `add-priority-node` and `seed-node` (both gone on PR-3), `add-exclusive-node`, `tx-proxy`, `anonymous-inbound`, `no-ephemeral-tor`, `ban-list`, `no-sync`, `no-igd`, `igd`, `out-peers`, `in-peers`, `tos-flag`, `limit-rate-up`, `limit-rate-down`, `limit-rate`, `pad-transactions`, `clearnet-transport-encrypt`; and PR-3's `p2p-disclose-early` (`arg_p2p_disclose_early`, `net_node.cpp:131` at `fce0a2fa`) |
| [`src/rpc/rpc_args.cpp:116-122`](../../src/rpc/rpc_args.cpp), declared [`:91-105`](../../src/rpc/rpc_args.cpp) | 7 registered of 15 | `rpc-bind-ip`, `rpc-bind-ipv6-address`, `rpc-restricted-bind-ip`, `rpc-restricted-bind-ipv6-address`, `rpc-use-ipv6`, `rpc-access-control-origins`, `disable-rpc-ban`; and the eight TLS and login descriptors registered for nothing (DC-F6) |
| [`src/rpc/core_rpc_server.cpp:92-103`](../../src/rpc/core_rpc_server.cpp), declared [`:1402-1450`](../../src/rpc/core_rpc_server.cpp) | 7 | `rpc-bind-port`, `rpc-restricted-bind-port`, `restricted-rpc`, `rpc-max-connections-per-public-ip`, `rpc-max-connections-per-private-ip`, `rpc-max-connections`, `rpc-response-soft-limit` |

### 4.2 Deletion rows

Every row is an `rg -n -e … <paths>` whose count is observed non-zero at
the base and zero after (rule 47). A literal pipe in a pattern is `\|`.

| Deleted | Before | After |
| --- | --- | --- |
| every `add_arg` in daemon-linked code | `rg -n -e 'command_line::add_arg' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db` → more than 80 | 0 (`src/common/command_line.{h,cpp}` stays for the utilities until IG Part B) |
| every `arg_descriptor` there | `rg -n -e 'arg_descriptor<' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db` → more than 0 | 0 |
| the map reads | `rg -n -e 'get_arg(vm' -e 'has_arg(vm' -e 'is_arg_defaulted(vm' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db src/cryptonote_protocol` → more than 90 | 0 |
| `variables_map` and `program_options` in `shekyld` | `rg -n -e 'variables_map' -e 'program_options' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db src/cryptonote_protocol` → more than 0; `rg -n -e 'Boost_PROGRAM_OPTIONS_LIBRARY' src/daemon/CMakeLists.txt` → 1 | 0 and 0 |
| `src/daemon/command_line_args.h`, `src/common/removed_flags.{h,cpp}`, `src/rpc/rpc_args.{h,cpp}`, `src/common/daemon_default_data_dir.{h,cpp}` | files exist; `removed_flags.cpp` still sends Windows operators to Task Scheduler ([`src/common/removed_flags.cpp:158-162`](../../src/common/removed_flags.cpp)), which RT-16 rejects; `daemon_default_data_dir.cpp` infers the mode from the account's elevation, which RT-16 forbids | `rg -n -e 'removed_flags' -e 'rpc_args' -e 'daemon_default_data_dir' -e 'command_line_args' src tests` → 0 |
| the RPC start's configuration and the C++ listener loop (§2.3) | `shekyl_daemon_rpc_start` has nine parameters; `rg -n -e 'rpc_instance' -e 'rust_rpc_handles' src/daemon` → more than 0 | one parameter, the core handle; 0 |
| the zone host's C++-supplied values (Rick's review, item 3) | at PR-3's head `shekyl_zone_listen_clearnet` takes the bind values, the SOCKS host and port, the encrypt flag, the network id and the ceiling (`zone_ffi.rs:402-415`); the ceiling is computed in C++ (`transport_ceiling`, `net_node.h:456`, `net_node.inl:834`, `:970`, `:1003`); the spans are already Rust's (the transport layer's `spans.rs` on PR-3) | the zone host reads its sections, the network id comes from the network row, the ceiling from Rust's own resolver; `rg -n -e 'transport_ceiling' -e 'm_network_id' src/p2p` → 0 |
| every other configuration push | `rg -n -e shekyl_zone_set_connector_cap -e shekyl_zone_clear_connector_cap -e shekyl_link_set_up -e shekyl_link_set_down src rust/shekyl-ffi/src src/shekyl/shekyl_ffi.h` → more than 6; `shekyl_log_init_file`, `shekyl_log_set_level`, `shekyl_log_set_categories` called from [`contrib/epee/src/mlog.cpp:215`](../../contrib/epee/src/mlog.cpp), [`:306`](../../contrib/epee/src/mlog.cpp), [`:338`](../../contrib/epee/src/mlog.cpp); `shekyl_daemon_tor_start`'s data-directory parameter ([`src/p2p/net_node.inl:896-898`](../../src/p2p/net_node.inl)) | the pushes gone; the managed Tor reads the paths section; `mlog_configure` shrinks to installing the tracing forwarder |
| PR-3's pushes | `rg -n -e shekyl_dialer_set_out_peers -e shekyl_peerlist_allow_local_ip -e shekyl_peerlist_admit_operator -e shekyl_peerlist_disclose_early -e shekyl_dialer_set_exclusive -e shekyl_dialer_open_address_file -e note_own_address -e admit_operator_peer src rust/shekyl-ffi src/shekyl/shekyl_ffi.h` → more than 8 at the PR-3 merge (`dialer_ffi.rs:325`, `:438`, `:463`, `:485`, `:512`; `peerlist_ffi.rs:67`) | 0; `shekyl_peerlist_set_own_address` survives only as the peer lists' own entry, called by `shekyl-tor` and by the configuration, never by C++ |
| the reverse pulls | `rg -n -e shekyl_p2p_default_out_peers -e shekyl_relay_zone_min_provisioned_out_peers -e shekyl_dialer_out_target src` → more than 3 | 0 |
| UPnP | `rg -n -i -e 'upnp' -e 'm_igd' -e 'igd_t' src/p2p` → more than 40 ([`src/p2p/net_node.h:463-467`](../../src/p2p/net_node.h), [`:663-670`](../../src/p2p/net_node.h), [`src/p2p/net_node.inl:66-68`](../../src/p2p/net_node.inl), [`:1183-1189`](../../src/p2p/net_node.inl), [`:2358`](../../src/p2p/net_node.inl), [`:3381-3383`](../../src/p2p/net_node.inl)) | 0 |
| miniupnpc | `rg -n -i -e 'miniupnp' -e 'UPNP' CMakeLists.txt external/CMakeLists.txt cmake/FindMiniupnpc.cmake .gitmodules contrib/brew/Brewfile .github/workflows src/p2p/CMakeLists.txt` → more than 15 ([`CMakeLists.txt:490`](../../CMakeLists.txt), [`external/CMakeLists.txt:32-51`](../../external/CMakeLists.txt)) | 0; the submodule leaves `.gitmodules` and the tree; the note at [`scripts/ci/check_doc_claims.py:694`](../../scripts/ci/check_doc_claims.py) is updated |
| `out-peers` and its runtime surface | `rg -n -e 'out_peers' -e 'OUT_PEERS' -e 'change_max_out_public_peers' -e 'get_max_out_public_peers' src rust/shekyl-daemon-rpc/src` → more than 20 ([`src/rpc/core_rpc_server.cpp:1166-1171`](../../src/rpc/core_rpc_server.cpp), [`src/daemon/command_server.cpp:211-213`](../../src/daemon/command_server.cpp), [`rust/shekyl-daemon-rpc/src/server.rs:344`](../../rust/shekyl-daemon-rpc/src/server.rs)) | 0 |
| the `,N` suffixes | `rg -n -e 'get_max_connections' -e 'max_connections' src/p2p/net_node.cpp src/p2p/net_node.h` → more than 8 | 0 |
| `disable-rpc-ban` and the RPC server's dead scorer | `rg -n -e 'disable_rpc_ban' -e 'core_rpc_server::add_host_fail' -e 'RPC_IP_FAILS_BEFORE_BLOCK' src` → more than 5 ([`src/rpc/core_rpc_server.cpp:173-190`](../../src/rpc/core_rpc_server.cpp); the shared context is unblockable, [`src/rpc/core_rpc_ffi.cpp:84-89`](../../src/rpc/core_rpc_ffi.cpp)) | 0; `node_server::add_host_fail` ([`src/p2p/net_node.inl:451`](../../src/p2p/net_node.inl)) is the P2P function and stays |
| the test and debug levers | `rg -n -e 'test_drop_download' -e 'g_test_dbg_lock_sleep' -e 'show_time_stats' src contrib/epee/include/syncobj.h` → more than 10 | 0 |
| background mining's options and runtime arguments | `rg -n -e 'do_background_mining' -e 'ignore_battery' -e 'bg_mining' src` → more than 10 | 0 for the options and the `start_mining` arguments; the miner's background thread is the mining lane's (§10) |
| the network booleans and `keep-fakechain` | `rg -n -e 'arg_testnet_on' -e 'arg_stagenet_on' -e 'arg_regtest_on' -e 'keep_fakechain' src` → more than 20 | 0 in daemon-linked code; the utilities' copies are re-homed (§9) |
| the three regtest arms | the FAKECHAIN tests at [`src/p2p/net_node.inl:684`](../../src/p2p/net_node.inl), [`:854`](../../src/p2p/net_node.inl), [`src/cryptonote_core/cryptonote_core.cpp:516`](../../src/cryptonote_core/cryptonote_core.cpp), [`:1621`](../../src/cryptonote_core/cryptonote_core.cpp) | gone; [`:477`](../../src/cryptonote_core/cryptonote_core.cpp) (the `/fake` subdirectory) becomes the params row; [`:624`](../../src/cryptonote_core/cryptonote_core.cpp) (the pool's flag) is the pool lane's and is listed, not deleted |
| the data-directory port suffix | `rg -n -e 'm_config_folder + "/" + public_zone.m_port' src/p2p/net_node.inl` → 1 | 0 |
| `Blockchain::m_offline` and its parameter | [`src/cryptonote_core/blockchain.cpp:302`](../../src/cryptonote_core/blockchain.cpp), [`src/cryptonote_core/blockchain.h:1145`](../../src/cryptonote_core/blockchain.h) | 0 |
| the undefined `extern nodetool::arg_offline` | [`src/p2p/net_node.h:829`](../../src/p2p/net_node.h) | 0 |
| `m_require_ipv4` | `rg -n -e 'm_require_ipv4' src` → 2 | 0 |
| the environment levers | `rg -n -e 'getenv("SHEKYL_' src/cryptonote_core/blockchain.cpp` → 2; `rg -n -e 'env::var("SEEDHASH_' rust/shekyl-ffi/src/pow_randomx_ffi.rs` → 4; `rg -n -e 'getenv("RPC_LOGIN")' src/rpc` → 1 | 0; the four `dev-` levers replace them, and Rust arms the schedules from its section |
| the carrier global | `rg -n -e 'set_carrier_development' src` → more than 2 | 0; the relay reads `dev-relay-cover` |
| `tools::set_max_concurrency` from the daemon | [`src/daemon/main.cpp:310-311`](../../src/daemon/main.cpp) | gone with `main.cpp`'s parse |
| the C++ notify path | [`src/common/notify.cpp:52`](../../src/common/notify.cpp) splits a command string on whitespace; [`src/common/spawn.cpp:124`](../../src/common/spawn.cpp) sets `SIGCHLD` to ignored for the whole process (DC-F12) | `tools::Notify` and the daemon's use of `tools::spawn` gone; `rg -n -e 'SIGCHLD' src/daemon src/cryptonote_core src/common/notify.cpp` → 0 for the daemon (the runner is Rust's, DC-Q14) |
| the C++ signal owner and orchestration (DC-Q13) | [`src/daemon/daemon.cpp:272`](../../src/daemon/daemon.cpp) installs `tools::signal_handler`, whose Windows handler stops only on Ctrl-C and Ctrl-Break ([`src/common/util.h:193-201`](../../src/common/util.h), DC-F13); `Daemon::run`, `t_internals` and `main.cpp`'s body orchestrate the start | `rg -n -e 'signal_handler::install' src/daemon` → 0; the orchestration replaced by the remnant's `run(snapshot)` and `stop()`; `main.cpp` is one call |
| `utils/conf/shekyld.conf` | the file exists; cited at [`docs/USER_GUIDE.md:131-133`](../USER_GUIDE.md) | gone |
| `scripts/ci/check_carrier_flag_hidden.sh` | exists | replaced by a table test that `dev-relay-cover` is hidden and refused on mainnet |
| C++ tests of the deleted mechanism | `tests/unit_tests/command_line.cpp:52-104`, `tests/unit_tests/rpc_args_daemon_surface.cpp` | deleted; `IsYes` stays |
| C++ tests that build a `variables_map` | `rg -n -e 'variables_map' tests/unit_tests/node_server.cpp tests/core_tests/chaingen.h tests/core_tests/chaingen_main.cpp tests/unit_tests/sync_orphan_arm.cpp tests/unit_tests/main.cpp tests/performance_tests/main.cpp` → more than 10 | 0; they construct the remnant from a snapshot built by the real Rust parse of a test argument list (rule 26 B2) |
| the disclose-early rename's acceptance | `rg -n -e 'small_network' -e 'SmallNetwork' -e 'SMALL_NETWORK' -e 'small-network' src rust docs` | only PR-3's UNFREEZE record (IG-Q20) |

---

## 5. Ripples

### 5.1 Launchers, re-censused at `7cf70b7052`

Every launcher moves to the grammar's names in the cutover. Under DC-Q5 a
regtest daemon that is not offline runs the managed Tor, and nothing wipes
a chain.

| Launcher | What changes beyond spelling | Regtest, not offline |
| --- | --- | --- |
| [`contrib/packaging/linux/shekyld.service:12`](../../contrib/packaging/linux/shekyld.service) | drops `--non-interactive` (no console unless asked, IG-Q8) | — |
| [`utils/fleet/skl-node@.service:35`](../../utils/fleet/skl-node@.service) and its siblings; [`utils/fleet/gen_host_configs.sh:69-88`](../../utils/fleet/gen_host_configs.sh) | the generated files become TOML; `--network` moves to the unit's command line; the UPnP key goes | — |
| [`rust/shekyl-engine-core/src/engine/regtest_e2e.rs:355-392`](../../rust/shekyl-engine-core/src/engine/regtest_e2e.rs) | the `Linked` arm already declines the managed Tor | yes, already handled |
| [`rust/shekyl-levin/tests/dual_stack.rs:71-72`](../../rust/shekyl-levin/tests/dual_stack.rs), [`rust/shekyl-levin/tests/inbound_cost_bench.rs:166-167`](../../rust/shekyl-levin/tests/inbound_cost_bench.rs) | `--out-peers 0` goes; each gains the Tor-off setting (Rick names the second) | yes |
| [`scripts/bench/drs_bench.py:256-257`](../../scripts/bench/drs_bench.py) | loses `--keep-fakechain` and `--db-sync-mode` (IG-Q4); the linked daemons gain the Tor-off setting | yes, except the offline seed at [`:291`](../../scripts/bench/drs_bench.py) |
| [`scripts/bench/wss_q1b_regtest_open_edge.sh`](../../scripts/bench/wss_q1b_regtest_open_edge.sh), [`rust/shekyl-wire/tests/vectors/capture_coinbase.py`](../../rust/shekyl-wire/tests/vectors/capture_coinbase.py), [`rust/shekyl-curve-tree/tests/fixtures/gen_ct2_fixture.py`](../../rust/shekyl-curve-tree/tests/fixtures/gen_ct2_fixture.py) | spelling | offline |
| [`scripts/bench/ba_t5_session2_run.sh`](../../scripts/bench/ba_t5_session2_run.sh), [`scripts/bench/ba_t5_session3_run.sh`](../../scripts/bench/ba_t5_session3_run.sh) | the restricted port becomes a view listener | testnet |
| [`rust/shekyl-cli/tests/json_script.rs:291`](../../rust/shekyl-cli/tests/json_script.rs), [`rust/shekyl-cli/tests/scripts/daemon_session.txt:8`](../../rust/shekyl-cli/tests/scripts/daemon_session.txt) | spelling | testnet, offline |
| [`rust/shekyl-cli/src/main.rs:524-532`](../../rust/shekyl-cli/src/main.rs) | its daemon-down message prints the daemon's network spelling | — |
| [`contrib/tor/shekyl-over-tor.sh`](../../contrib/tor/shekyl-over-tor.sh) | passes `--detach`, retired in V3.1, so it is broken today (DC-F8); rewritten or deleted | — |
| [`Dockerfile`](../../Dockerfile) | spelling; drops `--non-interactive` | — |
| the GUI sidecar (`shekyl-gui-wallet`, `daemon_manager.rs`) | passes `--rpc-admin-listen none --rpc-view-listen 127.0.0.1:<port>` (`INPUT_GRAMMAR.md` §5); a PR in that repository, merged with the cutover | — |
| `shekyl-dev`: configuration examples, unit files, the stressnet playbook, the Foundation seed recipe (roles only, rule 37) | TOML files at the system path; a change in that repository under its own authorisation | — |

### 5.2 Gates

`scripts/ci/check_dial_path_freeze.py`: an edit to its shrink files carries
the dated UNFREEZE line, or waits for PR-3 to retire the rows.
`scripts/ci/check_ffi_signatures.sh` covers every signature in §2.3 and
§4.2. `scripts/ci/check_network_uniformity.sh`: the FAKECHAIN arms are
outside its fence; this cutover deletes three and adds none. New: the
grammar gate (IG-3, IG-9) over the daemon's table; the snapshot field-count
gate (§2.9); the recipe gate (DC-Q8), asserting that the shipped unit's
paths agree with its `StateDirectory` and `LogsDirectory` and that every
flag a unit or template passes is a live name.

### 5.3 Documentation

The option tables at [`docs/EXECUTABLES.md:52-84`](../EXECUTABLES.md) and
[`docs/USER_GUIDE.md:135-190`](../USER_GUIDE.md), and the example at
[`docs/USER_GUIDE.md:115-133`](../USER_GUIDE.md), are generated from the
table and gated (IG-9). `docs/proxies.md` is rewritten for the connector
postures and loses `--add-node`, which never existed. The release notes say
the log budget falls from an effective 5 GiB to 1 GiB (IG-Q19).

---

## 6. Failure modes the types cannot prevent (rule 82)

A contradiction between options is not listed: the sections cannot express
one (§2.1). What remains are inputs the operator can give and states of the
machine. Every refusal is a typed code rendered by IG-11, names what was
wrong and where, says what to do, and happens before anything starts; the
exit status is 2.

| Case | Outcome |
| --- | --- |
| a named config file is missing | refuse, naming the path |
| the file cannot be opened or read | refuse, naming the path and the OS error |
| the file, or a directory above it, can be written by a principal outside the allowlist (§2.4) | refuse, naming the path and the principal found |
| the file holds a secret and can be read outside the allowlist | refuse, naming the key, never its value |
| a symbolic link whose target fails either check | refuse, naming the target |
| the file is not valid TOML | refuse, naming file, line and column |
| an unknown name, on either surface | refuse with the nearest live name (IG-10) |
| a REJECTED or RESERVED name | refuse with its reason (IG-10) |
| a value its kind refuses: a range, a unit, `*` as an origin, a hostname as an endpoint, a relative path, a non-UTF-8 argument | refuse, naming the option, the source and the rule |
| a value on a surface its row forbids: a secret or a command on the command line, the network or the run mode in the file | refuse, naming where it may be given |
| a `dev-` option on a network its row does not name, and on mainnet always (IG-8) | refuse |
| no account home and no explicit paths | refuse, naming the options that fix it |
| the data directory cannot be created, or is not a directory | refuse, naming the path and the OS error |
| the data directory is locked by another daemon (DC-N1) | refuse, naming the directory |
| the marker names another network | refuse, naming both networks and the fix (§2.6) |
| the marker names this network with a different network id | refuse with its own code: an earlier release's data after a regenesis; use a fresh `data-dir` |
| a daemon store with no marker | refuse; the directory is never marked after the fact |
| the log location cannot be written | refuse, naming the path |
| the ban file cannot be read, or a line does not parse | refuse, naming the file and the line |
| a listener cannot bind | its owner refuses to start, naming the endpoint, and the daemon stops |
| a runtime change the constructor refuses (§2.7) | the request fails with the code the startup parse would give; the daemon runs |
| a set request for a row not marked Runtime | the request fails with the startup-only code; the daemon runs |
| service mode outside the SCM (Windows) | refuse at entry, naming the run mode and how the service is started |

---

## 7. Threat-model addenda (rule 26 A3)

1. **Run code as the daemon's account by writing its config file.** The
   notify commands execute programs. Route: the allowlist and the check
   order of §2.4; a file writable outside the allowlist is never read.
2. **Read a SOCKS credential** from the process list, a log, the
   effective-configuration line or a bug report. Route: file only, shown as
   set, held in Rust, zeroized (§2.5).
3. **Drive the admin listener from a web page.** A wildcard origin lets any
   page in the operator's browser read and call the plaintext admin
   listener. Route: the origin kind accepts only explicit origins
   (`INPUT_GRAMMAR.md` §5). Today a `*` is worse than permissive: it aborts
   the daemon (DC-F10).
4. **Make the node announce an attacker's relay as its address.** Route:
   only the operator names the public address (§2.8); the peer-learned
   shape is rejected (§8).
5. **Put two daemons, or two networks, on one store.** Route: the lock
   (DC-N1) and the marker (§2.6); DC-F1 checks the store's own contents.
6. **Turn on a development lever on mainnet** through a stray line in a
   file. Route: IG-8's refusal at parse.
7. **Configure an elevated daemon from an unprivileged account on a shared
   Windows host.** Today an elevated daemon's default data directory is
   under `%ProgramData%`, which any local user may create first, and the
   daemon loads `shekyl.conf` from it unasked
   ([`src/daemon/main.cpp:178-216`](../../src/daemon/main.cpp)): the
   planted file can set the proxy (exposing the node's traffic origin) or
   the log path (an administrator's file write). Route: the auto-load and
   the elevation branch are deleted; a pre-created directory carries a
   write-granting entry for its creator, so the allowlist of §2.4 refuses
   it rather than reading it; only service mode reads the system root,
   and the installer creates it with the restrictive list, so that refusal
   is not left for an attacker to cause (DC-Q17).

---

## 8. Rejections, with reopening criteria (rules 21, 26 A4)

- **The peer-learned public address (DC-Q10 (b)).** A peer can make the
  node dial any address it names, and a reflector at the candidate passes
  the self-dial while putting the attacker on every inbound session.
  Reopens on two conditions together: a measured share of inbound-willing
  operators who cannot set `clearnet-advertise`, and a design that tells a
  reflector from a route. Re-evaluated in a P2P design round.
- **UPnP.** Attack surface the managed onion makes unnecessary for inbound.
  Reopens on a ruling that clearnet inbound without an operator-configured
  address is a product requirement.
- **A retired-flag table.** Every release before genesis is a wipe. Reopens
  at genesis; the REJECTED rows are the record until then.
- **The blockchain utilities** keep their own option sets until IG Part B
  rules each tool; carried in §10.
- **The daemon's console and positional commands** stay in C++ until
  RT-15's local leg exists and `shekyl-cli` serves them (R8); carried in
  §10.

---

## 9. Sequencing and pre-flight

One cutover PR, based on PR-3 after it merges, once Part B, with the run mode's
row, is folded in (§1.2). It
lands the table, the parse, the sections, the lock, the marker, logging in
Rust, the announcements, the Rust `main()` and the remnant's entry pair,
the notify runner, the one RPC start, every Rust
owner reading its section, the snapshot, the runtime handlers of §2.7,
every deletion of §4, every launcher of §5.1 in this repository, and the
generated documentation. The blockchain utilities keep their option sets;
the descriptors they share with the daemon (`arg_data_dir`,
`arg_testnet_on`, `arg_stagenet_on`, `arg_db_sync_mode`) move into a header
they own, and `src/blockchain_utilities/blockchain_import.cpp:662`'s call to
`core::init_options` becomes a call into it.

Pre-flight (rule 26), recorded in `docs/design/DAEMON_CONFIG_CUTOVER_AUDIT.md`
before the first production commit:

1. Re-pin every citation at the implementation pin with PR-3 merged; re-run
   the §5.1 census (`rg -l -e shekyld` outside `src/` and `docs/`).
2. Observe every §4.2 before-count non-zero, and check the snapshot's field
   list against the C++ readers that survive PR-3.
3. Read the daemon-store set for the marker (§2.6) at that pin.
4. Rule 17 at source for every crate the parse and the checks need beyond
   `shekyl-options`.
5. Demonstrate DC-F12 with a test before the runner replaces the C++ path:
   a notify spawn through `tools::spawn`, then the managed Tor's exit, whose
   `child.wait()` does not return its status.

Interactions: RT-W10 takes `rpc-listen` from reserved to live and makes
`rpc-admin-listen` a REJECTED row; RT-16 adds the service run mode on top of
the Rust `main()`, and RT-W14's SCM dispatcher hooks the entry of §2.2
step 1; slice 4 deletes the C++ peer-list handler; the RD and
chain-sync lanes do not touch the option surface.

---

## 10. Carries (rule 26 A5: each has a FOLLOWUPS row and a target)

| Carry | Target |
| --- | --- |
| DC-F1, the genesis-at-open check on a store's contents (no longer a blocker) | [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) |
| DC-N2, the console moves to `shekyl-cli` | RT-15, [`RPC_CHANNEL.md`](RPC_CHANNEL.md) |
| the blockchain utilities' option sets | IG Part B; this brief §9 |
| the GUI sidecar's arguments | this brief §5.1; the GUI repository |
| the background miner's thread | the mining lane ([`CLI_USABILITY.md`](CLI_USABILITY.md) §1) |
| the inherited defaults of `txpool-weight-max` (IG-Q11) and `rpc-connections-max` (IG-Q12) | rows the implementing PR files when the names land, owned by the pool's and the RPC lane's documents |
| the `removed_flags` shim sunset | this brief §4; the row leaves with the files |

---

## 11. Findings established at source (DC-F1…DC-F13)

| Id | Finding | Route |
| --- | --- | --- |
| DC-F1 | `Blockchain::init` creates genesis only in an empty store and checks nothing in a non-empty one ([`src/cryptonote_core/blockchain.cpp:356-369`](../../src/cryptonote_core/blockchain.cpp)) | carried, §10; not a blocker (DC-Q5) |
| DC-F2 | The documented per-network log file never existed: the default path takes the module name first ([`contrib/epee/src/mlog.cpp:64-82`](../../contrib/epee/src/mlog.cpp)) | absorbed: the network row names the file |
| DC-F3 | SOCKS credentials are parsed and never reach Rust | absorbed, §2.5 |
| DC-F4 | The silent auto-load path ignored `--data-dir` and, on Windows, differed from the data directory | absorbed by DC-Q3 |
| DC-F5 | Dead declarations and readers: the declared `log-file` default, `log-level`'s empty help, `rpc-response-soft-limit`, `tos-flag`, `p2p-ignore-ipv4`, `nodetool::arg_offline`, `Blockchain::m_offline`, `core_rpc_server::add_host_fail`, `tools::file_locker` | absorbed, §4 |
| DC-F6 | Eight TLS and login descriptors are built for every `rpc_args::descriptors` and registered for nothing | absorbed, §4 |
| DC-F7 | The deployment recipe disagreed with itself: `utils/conf/shekyld.conf` against the shipped unit | absorbed by DC-Q8 |
| DC-F8 | `contrib/tor/shekyl-over-tor.sh` passes a flag retired in V3.1 | absorbed, §5.1 |
| DC-F9 | A list given on both surfaces kept only the command line's, undocumented | absorbed: IG-6 makes it the rule |
| DC-F10 | A `*` origin aborts the daemon after its log says RPC started. `shekyl_daemon_rpc_start` returns a handle and spawns the server ([`rust/shekyl-daemon-rpc/src/ffi_exports.rs:208-212`](../../rust/shekyl-daemon-rpc/src/ffi_exports.rs)); the task builds the CORS layer ([`rust/shekyl-daemon-rpc/src/server.rs:87-115`](../../rust/shekyl-daemon-rpc/src/server.rs)); tower-http 0.6.8 panics on a wildcard passed to `AllowOrigin::list` (its `allow_origin.rs`, lines 60 to 64, read at source); the workspace builds with `panic = "abort"` in both profiles (`rust/Cargo.toml`, lines 671 to 676), so the process ends; no panic hook is installed, so the reason reaches standard error only. Entries that are not valid header values are logged and dropped ([`rust/shekyl-daemon-rpc/src/server.rs:100-102`](../../rust/shekyl-daemon-rpc/src/server.rs)) | absorbed: the origin kind refuses both at parse |
| DC-F11 | A list option with no values was "present" to the C++: the vector semantic installs an empty default ([`src/common/command_line.h:179-183`](../../src/common/command_line.h)) and `has_arg` tests the map entry ([`src/common/command_line.h:256-262`](../../src/common/command_line.h)), so every start declared a closed network with no peers. PR-3 reads an empty declaration as none on the Rust side (`6fc926404`) | absorbed: the closed-network declaration is absent or non-empty |
| DC-F13 | On Windows a run-as-user daemon is terminated, not stopped, by every console event but Ctrl-C and Ctrl-Break: the handler logs "Exiting without saving" and returns `FALSE` for window close, logoff and shutdown ([`src/common/util.h:193-201`](../../src/common/util.h)), so RT-16's "stops at logout" does not hold today. Low severity: the stores are transactional and Tor exits through `TAKEOWNERSHIP` | absorbed: one stop path for every signal, console event and SCM control (§2.2 step 9) |
| DC-F12 | The first notify command switches child reaping off for the whole process. `tools::spawn` sets `signal(SIGCHLD, SIG_IGN)` after a spawn it does not wait for ([`src/common/spawn.cpp:124`](../../src/common/spawn.cpp)); from then on the kernel reaps every child, the managed Tor included, which the Rust side waits on ([`rust/shekyl-tor-control-client/src/control/actor.rs:616`](../../rust/shekyl-tor-control-client/src/control/actor.rs), [`:1011`](../../rust/shekyl-tor-control-client/src/control/actor.rs)). Under tokio 1.51.0 on Linux the pidfd reaper's wait then fails with `ECHILD` instead of an exit status; on macOS and FreeBSD the `SIGCHLD` handler tokio relies on is overwritten and the wait never completes | absorbed: the Rust runner reaps its own children and never changes a signal disposition (§2.10); pre-flight demonstrates it (§9) |

---

## 12. What this round examined and did not find

Examined with nothing to report: the Windows installer passes no daemon
flags; no CI workflow launches the daemon with flags; no environment read
in `src/daemon`, `src/p2p` or `src/rpc` beyond §4.2; no script in this
repository, the GUI or `shekyl-dev` passes `block-rate-notify`;
`shekyl-chain-replay` spawns no daemon. Not examined: the GUI's settings
screen, the mobile wallet, the stressnet harness's own configuration.

---

## 13. Instructions to the implementing agent

Written for the agent that lands the cutover after PR-3 merges and §1.2 is
ruled. Read rules 00, 06, 08, 17, 19, 20, 22, 23, 25, 26, 35, 36, 40, 45,
47, 50, 71, 82, 83, 90, 94 and 95, and `INPUT_GRAMMAR.md`, before the first
commit.

1. **Preconditions.** PR-3 is on `dev`; the grammar's Part B is on `dev`
   with the run mode's row, and folded into this brief. Stop and ask if any is not
   true.
2. **Worktree and branch.** One worktree off `dev`; stage explicit paths;
   push each commit to the open PR after merging `dev`; no attribution
   trailers or footers.
3. **Pre-flight first** (§9), recorded before any production commit.
4. **Commit order, every commit building:** (a) the daemon's table in
   `shekyl-options` terms, the parse, the file checks, the sections, the
   lock and the marker, with a test for every §6 row; (b) the Rust
   `main()` and its one signal owner, logging in Rust, the announcements,
   the snapshot and its field-count gate, the remnant's `run(snapshot)` and
   `stop()` pair, `noexcept` and exception-catching; (c) every Rust owner
   reading its section, the one RPC start, every configuration parameter
   removed from every start function, the FFI header and its signature gate
   green; (d) the runtime handlers of §2.7 and the notify runner of §2.10; (e) every §4.2 deletion, with
   its before and after counts in the commit message; (f) every launcher,
   the generated documentation and its gate; (g) the index and FOLLOWUPS
   rows of §10.
5. **No new daemon option in C++.** A value C++ needs reaches it through
   the snapshot, or not at all.
6. **Names come from `INPUT_GRAMMAR.md`.** A name the table lacks is a row
   brought to the maintainer, never a local choice (rule 83).
7. **Gates before done:** `cargo fmt --check`, `cargo clippy --all-targets
   -- -D warnings`, the workspace tests excluding the RandomX differential
   crate, the C++ unit tests, every docs gate, the grammar gate, the FFI
   signature gate, and the dial-path freeze gate's state recorded, run on a
   fresh checkout of the pushed SHA.
8. **Rule 37.** Never name a Foundation host; the `shekyl-dev` change is a
   separate change under its own authorisation.
9. **Stop and ask** if a §4.2 before-count is zero, if a §5.1 launcher is
   missing, if the grammar table lacks a row the sections need, or if a C++
   reader of configuration survives that is not in §2.9.
