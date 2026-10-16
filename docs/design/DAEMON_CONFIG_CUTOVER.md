# Daemon configuration cutover — the option surface moves to Rust

**Status: OPEN — Round 0 brief, complete (2026-10-15; every DC-Q ruled, the grammar's Part B folded in, PR-3 merged).** Rule 26 is cited.
The input grammar is ruled and merged: Part A (#1067, merge `7cf70b7052`)
and Part B (#1068, merge `cd1d0cc8ed`). Its rules are the cursor rule
[`83-input-grammar`](../../.cursor/rules/83-input-grammar.mdc) and the
daemon's names are [`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) §5. This brief is
the single replacement of the 2026-10-13 draft, written under Rick's review
of that draft: the C++ is not canonical, so the configuration is designed in
Rust and the C++ appears only as what the cutover deletes. The brief owns
the mechanism. Option names, kinds, defaults, surfaces and diagnostic codes
are the grammar's and are cited, never restated. PR-3 (#1056), which the
cutover builds on, merged on 2026-10-15.

Anchors pinned to `dev` `d26148535e` (2026-10-15, the implementation pin).
The pre-flight that re-pinned them is
[`DAEMON_CONFIG_CUTOVER_AUDIT.md`](DAEMON_CONFIG_CUTOVER_AUDIT.md).

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
| The grammar's Part B (Rick, 2026-10-14; merged with #1068) | IG-12's contract: a row is marked runtime (`yes` or `no`, IG-9) and changed with `option set`, read with `option show`, whose sources include `runtime`; mining changes while running through `mine start` and `mine stop`, so `mine-address` and `mine-threads` are not runtime. IG-9's row gains `view` (DC-Q16). `mine` is the subject everywhere (IG-Q21). IG-13 per platform: one per-account root (the passwd home plus `.shekyl` on Linux, FreeBSD and macOS; `FOLDERID_LocalAppData` plus `Shekyl` on Windows); on Windows the run mode selects the daemon's root; on Linux, FreeBSD and macOS the config file is `/etc/shekyl/` and the data and log defaults sit under the per-account root. The daemon console's catalog (`INPUT_GRAMMAR.md` §13: `daemon status`, `daemon stop`, no successor for `pop_blocks`); the C++ console is not renamed and dies with R8 (IG-Q25). The utilities' fate (§14.1, IG-Q26) | §2.4, §2.5, §2.7, §2.9, §3, §4.2, §9 |
| DC-Q13 (Rick, 2026-10-14) | (b): CMake builds the executable and its `main` makes one call into Rust, which owns the process. The C++ remnant exposes one coarse entry pair, `run(snapshot)` returning a status and `stop()`, both `noexcept` and catching every C++ exception, so none unwinds through Rust frames. Rust's entry installs a panic hook that records the panic on standard error and, without waiting, in the log before the workspace's `panic = "abort"` ends the process (confirmed by Rick, 2026-10-14). One signal owner, Rust: `tools::signal_handler::install` is deleted from `Daemon::run`. The pair replaces the orchestration in `main.cpp` and `daemon.cpp`, and the C++ shrinks | §2.2, §4.2 |
| DC-Q14 (Rick, 2026-10-14) | A Rust runner owns the notify commands, fed chain facts by the C++ event sites (requirements in §2.10; the reaping hazard it removes is DC-F12) | §2.10, §4.2 |
| RT-16, Windows service mode (Rick, 2026-10-13; [`RPC_CHANNEL.md`](RPC_CHANNEL.md) RT-16, its Consequences, merged with #1070; the verbatim record is [`WINDOWS_SERVICE_RULING_2026-10-13.md`](../completed/WINDOWS_SERVICE_RULING_2026-10-13.md)) | `shekyld` itself answers the Windows Service Control Manager, in Rust, entered only through RT-16's declared service-mode switch, which is a daemon-config option. No wrapper process and no self-registration: installing is the installer's and `shekyl-cli`'s, and restart on failure is the SCM's failure actions, set at install. On POSIX nothing changes: systemd and launchd run the foreground process. A run-as-user daemon's home is always per-user (`%LOCALAPPDATA%` on Windows, never the roaming profile, whatever the token); a machine-wide home exists only in the declared service mode, and only when the installer created it. The SCM dispatcher needs the process entry, which is this lane's (DC-Q13) | §2.2, §2.4, §2.5, DC-Q17 |
| DC-Q15 (Rick, 2026-10-14) | The lock is `shekyld.lock` at the data directory's root, held through `flock` or `LockFileEx` and never deleted on exit. The marker is `shekyld.network` (TOML content, not a `.toml` name, so it is not mistaken for operator configuration), holding `network` and `network-id`, written by temporary file, `fsync`, rename and directory `fsync`, read only under the lock. Its refusals tell another network apart from the same network with a different network id (an earlier release's data after a regenesis: use a fresh `data-dir`) | §2.2, §2.6, §6 |
| DC-Q16 (Rick, 2026-10-14) | One generic set request and one generic show request, carrying the option's name and its value as text in the grammar's syntax, parsed by the table and routed to the row's owner. Show never returns a secret, only that it is set. Set needs the `node` grant; show discloses each row only under the grant the row names (the runtime-requests ruling below; `RPC_CHANNEL.md` RT-O24). Set accepts only rows marked Runtime and refuses any other with a code saying it is startup-only. Show reports each value's source (`default`, `file`, `cli`, `runtime`). The RPC lane names the methods | §2.7, §6 |
| DC-Q17 / IG-Q36 (Rick, 2026-10-14; RT-16 ruled 2026-10-13) | `service` is a switch, off by default, command line only (DC-Q18), with the grammar's `reserved` visibility until RT-W14 builds the service-manager dispatcher and public after: `shekyld` answers the platform's service manager (RT-16). It is accepted only where RT-16 defines it, Windows, and refused elsewhere with a typed code. The run mode selects one root, and every default path (`config-file`, `data-dir`, `log-file`) derives from it. On Windows a run-as-user daemon uses the per-account root (`FOLDERID_LocalAppData`) and `service` uses `%ProgramData%\shekyl\`, which only the installer creates (owner and access list: Administrators, SYSTEM and the service account); the daemon never creates the machine-wide root, and one that is missing, mis-owned or writable by others refuses with a typed code. Linux and macOS keep the `/etc/shekyl/` config files in every mode (R2). The REJECTED row `run-as-service` keeps its name with a new reason. The name and rows land in #1068; the mechanism, including the deletion of the elevation branch in `daemon_default_data_dir.cpp`, lands here. Both cite RT-16 by document. | §2.2, §2.4, §2.5, §6 |
| DC-Q18 (Rick, 2026-10-14) | `service` is command-line only (IG-7): the run mode selects the file, so a key in that file could only restate or contradict it, and on Windows the installer's service registration carries the command line. A `service` key in the file is refused. Only the grammar row's Surface cell changes | §2.4, §6 |
| Runtime requests and disclosure (Rick, 2026-10-14, with [`RPC_CHANNEL.md`](RPC_CHANNEL.md) §6.4, RT-O23…RT-O27, PR #1073) | (1) IG-9's `view` field becomes the row's disclosing grant: `health`, `status`, `peers` or `config`, default `config`; `log-level`, `log-category` and the two P2P rate rows are `status`. (2) Every runtime row's default is writable as a value: a rate takes `unlimited` and `log-category` takes `none` (no per-category overrides); an empty category list never means logging off. (3) `/pop_blocks` has no grammar successor; it is an armed test lever (RT-O9.2), RT-W10's. §6.4: the requests are `option_set` and `option_show`, JSON-RPC methods only; `option_set` is in the `node` grant, which is setting every runtime row; set is all or nothing over infallible applies; a secret row carries `secret: true` and `set`, never a value; refusals carry the IG-11 diagnostics in the error's `data` member under one new code; one lock over a set, one audit line per set | §2.7, §4.2 |
| RT-W14's start reporting (Rick, 2026-10-14) | Under the SCM the Rust entry reports `SERVICE_START_PENDING` with checkpoints and wait hints through steps 2 to 8 of §2.2, and `SERVICE_RUNNING` only when RT-15's rendezvous is published. Without it the SCM's start timeout of about 30 seconds kills the service (error 1053): the managed Tor's bootstrap alone may take 300 seconds ([`src/p2p/net_node.inl:757`](../../src/p2p/net_node.inl)) | §2.2 |
| Inbound cap deleted (Rick, 2026-10-14; `INPUT_GRAMMAR.md` IG-Q40) | `p2p-inbound-max` is deleted and `in-peers` is a REJECTED row (IG-10) whose reopener is a byte quota for metered links (§8). The Rust descriptor safety bound (`InboundCeiling`) is the only inbound bound and is unchanged; the daemon does not raise its own descriptor limit. The unbounded cases (Windows, an unlimited or unreadable limit, an unreadable count, headroom past the counter) behave as today and stay PWD-B1's (the FOLLOWUPS row on a Windows node's inbound bound); their warnings name nothing the operator can set. Adversarial per-session cost stays with PWD-B12 and PWD-B1. The runtime set is four rows, and a set builds then applies, with no check step (§2.7). A refused inbound connection is tested against the real bound, on Unix only (§5.2). The benchmark scripts take `clearnet-listen none` and the Foundation configurations in `shekyl-dev` drop `in-peers` in the cutover (§5.1). PWD-I7 closes with this ruling | §2.7, §4.2, §5, §6, §8 |
| The Tor binary (Rick, 2026-10-15; TSR-F8, [`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md), merged #1077; `INPUT_GRAMMAR.md` IG-Q41) | `SHEKYL_TOR_BINARY` becomes the config key `tor-file`, a path accepted only with `tor = managed`. Its default is today's location: `tor/tor` beside the running executable, else the version-exact bundle directory under `/opt/shekyl/` on Unix. A set value is verified against the pin exactly as a discovered binary is, with no fall-through to discovery (`discover_and_verify_at`). The environment tier leaves the shared discovery function, so the wallet loses it too and keeps its settings-file path (IG-13) | §3, §4.2, §5.3 |

### 1.2 Open before implementation

Nothing for the cutover. #1083 (the managed Tor launcher reads only its
own configuration, and starts on Windows) is a prerequisite of the Tor
supervisor, not of this cutover.

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
  tip, published as it changes (`shekyl_core_publish_tip`, `rust/shekyl-ffi/src/dialer_ffi.rs:398`,
  called from `src/cryptonote_core/blockchain.cpp:5959`); chain facts for the
  notify runner (§2.10).

### 2.2 The start sequence (DC-Q13)

1. `main()` calls `shekyl_daemon_main()`; Rust owns the process from here.
   **A panic is never silent.** The workspace builds with `panic = "abort"`
   in both profiles (`rust/Cargo.toml`, lines 671 to 676), so a panic cannot
   be caught and turned into an exit status, and an unwind across the C++
   frames below would be undefined anyway. The entry therefore installs a
   panic hook first (Rick, 2026-10-14). It records the panicking thread's
   name, the panic's message and its location, and it never blocks:
   standard error first, written directly with no lock taken; then the
   log, only through a non-blocking attempt that is skipped if it would
   wait, because the panicking thread may hold the logging lock. Then the
   process aborts. The abort's crash status is distinct from the
   configuration refusal's 2 and the runtime failure's 1 (IG-11), so a
   supervisor tells the three apart. Both start-time files survive an
   abort intact: the lock is an operating-system lock the kernel releases
   with the process, and the marker is only ever replaced by a renamed,
   flushed temporary file (§2.6).
   **`service` before and after RT-W14.** The SCM dispatcher, the
   `SERVICE_START_PENDING` checkpoints and wait hints through steps 2 to 8,
   and `SERVICE_RUNNING` once RT-15's rendezvous is published are RT-W14's
   (`RPC_CHANNEL.md`, RT-W14, which waits on RT-W10), built on this entry:
   without them the SCM's start timeout of about 30 seconds kills a start
   that the managed Tor's bootstrap alone can stretch to 300 seconds (error
   1053). Until RT-W14 lands, the `service` row has the grammar's
   `reserved` visibility (IG-9, IG-10), as `rpc-listen` has for RT-W10
   (`INPUT_GRAMMAR.md` §5): it is not accepted, and its refusal names RT-W14.
   The grammar lane sets the row's visibility (Rick, 2026-10-14).
   Everything else `service` selects is built here and switched on by
   RT-W14: the root by run mode, the machine-wide root's checks (§2.4), and
   the elevation branch's deletion.
2. Rust reads its arguments with `std::env::args_os` (IG-Q2), resolves
   the run mode (`service`), `--network` and `--config-file`, checks the file's permissions (§2.4),
   reads and validates it whole, applies the command line over it per key,
   resolves every path (§2.5), reads the ban file, and constructs the typed
   sections. `--help` and `--version` are answered here. A refusal renders
   through IG-11 and exits with status 2; nothing below runs.
   **Client mode.** When positional command words are given, `shekyld` is a
   client of a daemon that is already running, as the remnant's client branch
   in `src/daemon/main.cpp` is
   today: it takes no lock, checks no marker, creates no data directory,
   writes no log file and makes no announcement. Rust logs to standard
   error only, fills a snapshot holding the words, the network and the
   first `rpc-admin-listen` endpoint, and calls the remnant's
   `run(snapshot)`, which runs the C++ console client against that endpoint
   (its transport is already Rust's: `rust/shekyl-daemon-rpc/src/ctl_client.rs`,
   `console/mod.rs`) and returns its status. A command with
   `rpc-admin-listen = none` has no daemon to reach and is refused at parse
   with a typed code naming the option. Steps 3 onward are for a daemon
   start only. Client mode dies with the C++ console (R8, DC-N2).
3. Rust takes the data-directory lock, `shekyld.lock` (DC-N1, DC-Q15),
   through `flock` or `LockFileEx`, and holds it for the life of the
   process; the file is never deleted. There is no lock today:
   `tools::file_locker` ([`src/common/util.h:101-105`](../../src/common/util.h))
   has no caller, and the comment at
   line 487 of `src/cryptonote_core/cryptonote_core.cpp` at `d26148535e`
   says "try to lock it" over code that only creates the directory.
4. Under the lock, Rust checks the network marker (§2.6), writing it when
   the directory holds no daemon store.
5. Rust initialises logging from its section, then emits the required
   announcements: the effective-configuration line, every `dev-` lever set,
   and the posture line (Tor-only, clearnet-only, offline), to the log and
   to standard error whatever the level (IG-14).
6. Rust installs the one signal handler and, if the Tor posture is
   `Managed`, starts the managed Tor's supervisor (Rick, 2026-10-14): one
   Rust owner of the state machine `Bootstrapping`, `Usable`, `Degraded`,
   `Restarting`, where *usable* is defined by a self-dial probe. Start is
   the supervisor's first iteration, with no separate bootstrap-failure
   path: a bootstrap that does not finish is capped backoff, retried
   forever, never a start refusal. The SOCKS endpoint is a value the
   supervisor publishes, never configuration. The Tor lane's Round 0 is
   [`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) (merged #1077): §4.3 the state
   machine, §4.7 the launch. Nothing that serves peers or clients starts yet.
7. Rust fills the snapshot (§2.9) and calls the remnant's `run(snapshot)`
   on a thread of its own. C++ constructs core, which publishes its tip
   (`shekyl_core_publish_tip`), then the protocol handler and what remains
   of `net_node`, and calls the RPC start once with the core handle (§2.3).
8. Only then does Rust start the zone host, its listeners and the dialer,
   each from its section: a peer that connects earlier would find no tip
   to handshake with and no protocol handler to receive its messages.
   Step 8 does not wait for the managed Tor ([`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md)
   §11): the Tor connector starts parked on its link and resumes when the
   supervisor publishes `Usable`, which is also what keeps the SCM start
   (RT-W14) off the bootstrap time. The link is the Tor lane's
   (`TSR-F1`; its increment 5 replaces the zone host's proxy slot with it);
   until it lands, the Rust `main()` drives today's `DaemonTorControl` and
   awaits its start at step 8, bounded by the bootstrap deadline, after
   which the node runs clearnet-only with a warning (FOLLOWUPS: the parked
   Tor connector).
9. Stop is Rust's, and there is one stop path, fed by the POSIX signals,
   every Windows console event (Ctrl-C, Ctrl-Break, window close, logoff,
   shutdown), and the SCM's stop and pre-shutdown controls (DC-F13). The
   handler stops the dialer and the zone host, then stops the RPC. Then two
   stops run in parallel (Rick, 2026-10-14): the remnant's `stop()` with
   the join of the `run` thread, and the managed Tor supervisor's
   teardown ([`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) §4.7, merged #1077). The lock
   is released last, after both. `run` and `stop` are `noexcept` and catch every C++ exception;
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
`rpc-admin-listen` endpoint at the `admin` preset and every `rpc-view-listen`
endpoint at the `view` preset (`RPC_CHANNEL.md` §6.1), each loopback only by RT-14
([`RPC_CHANNEL.md`](RPC_CHANNEL.md), RT-14), the origin list, and the one
connection cap. There is no per-listener C++ loop and no admin-or-restricted
parameter; the C++ `rpcs` vector, the second `core_rpc_server` built for the
restricted port, and `core_rpc_server::init`'s reading of options go.

### 2.4 The config file (DC-Q3)

The default location (DC-Q17, IG-13): on Linux, FreeBSD and macOS the
`/etc/shekyl/` files, the daemon having one run mode there (R2); on Windows the root of the run mode, the
per-account root (`FOLDERID_LocalAppData`) for a run-as-user daemon and
the installer-created `%ProgramData%\shekyl\` with `service`. The file in
the root is chosen by the network. Precedence and the missing-file rule are the `config-file` row
of `INPUT_GRAMMAR.md` §5: a missing file at the default path is the
defaults, stated in the effective-configuration line; a missing file at a
path the operator named refuses with a code naming the path. The network and
`service` are command-line only, because they choose the file (DC-Q18).

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

The checks above are the same in both run modes. A run-as-user daemon's
own account may write its file: whoever can write that account's files can
already run code as it. On Windows the machine-wide root is read only with
`service`; the daemon never creates it, and a root that is missing,
mis-owned (an owner other than Administrators or SYSTEM) or writable by
anyone outside Administrators, SYSTEM and the service account refuses with
a typed code. That closes the pre-created-directory hole of §7 item 7.

### 2.5 Paths and secrets (DC-Q7, IG-13)

- Home comes from the passwd entry on Unix and the known-folder API on
  Windows, never from `HOME`, `XDG_*` or `%APPDATA%`. On Windows the
  run mode selects one root and every default path derives from it: the
  per-account `FOLDERID_LocalAppData` root for a run-as-user daemon, never
  the roaming profile, and `%ProgramData%\shekyl\` with `service`, created
  only by the installer (DC-Q17). Today it comes from
  `HOME`, with `/` when unset
  ([`src/common/util.cpp:645-649`](../../src/common/util.cpp)). An account
  with no home has no default paths, and the paths it needs are named on
  the command line (the shipped unit already passes both).
- The per-user runtime directory, when an owner needs one, comes from the
  platform's own interface (IG-Q14). This slice reads none; the socket
  directory of RT-W10 is RPC_CHANNEL's.
- On Linux, FreeBSD and macOS the data and log defaults sit under the
  per-account root, the passwd home's `.shekyl` (IG-13), while the config
  file stays under `/etc/shekyl/`. The default data directory is the
  root with the network's subdirectory; an explicit `data-dir` is taken as given (DC-Q5). One
  Windows rule: the admin-membership split in
  lines 79 to 98 of `src/common/daemon_default_data_dir.cpp` at `d26148535e`
  is deleted with the file.
- The data-directory port suffix
  ([`src/p2p/net_node.inl:907-910`](../../src/p2p/net_node.inl)) is
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
the managed Tor skip ([`src/p2p/net_node.inl:617`](../../src/p2p/net_node.inl),
[`:719`](../../src/p2p/net_node.inl)), the database wipe on start
(lines 523 to 531 of `src/cryptonote_core/cryptonote_core.cpp` at `d26148535e`),
and `check_block_rate`'s regtest skip
(line 1628 of `src/cryptonote_core/cryptonote_core.cpp` at `d26148535e`).
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
pin. At `d26148535e` it is the LMDB environment
(`CRYPTONOTE_BLOCKCHAINDATA_FILENAME`,
[`src/cryptonote_config.h:215`](../../src/cryptonote_config.h)) and the
peer-state file (`P2P_NET_DATA_FILENAME`,
[`src/cryptonote_config.h:217`](../../src/cryptonote_config.h)); the Rust
chain store joins it when the daemon opens one. The managed Tor's data
directory is not a store. DC-F1, the check of a store's block 0 against the
network, stays the chain-store lane's and does not block this cutover.

### 2.7 Runtime changes (IG-12, DC-Q16, `RPC_CHANNEL.md` §6.4)

Today every runtime change is forwarded to the C++ JSON handlers through
one dispatch
([`rust/shekyl-daemon-rpc/src/handlers/json.rs:82-91`](../../rust/shekyl-daemon-rpc/src/handlers/json.rs),
[`:389-395`](../../rust/shekyl-daemon-rpc/src/handlers/json.rs)), one
endpoint per knob. After the cutover there are two JSON-RPC methods,
`option_set` and `option_show` (RT-O23), served natively by
`shekyl-daemon-rpc` through an options handle the composition root
supplies, with no FFI (RT-O26):

- **`option_set`** takes a list of name and value pairs, each value text in
  the grammar's syntax. The table's own parser and constructor build every
  value first, exactly as at startup, and the set applies all or nothing:
  one refusal refuses the request and every refusal in it is reported. A
  duplicate name, an unknown name and an empty list are refused. It accepts
  only a row marked runtime (`p2p-upload-max`, `p2p-download-max`,
  `log-level`, `log-category`) and refuses any other
  with the startup-only code. It is in the `node` grant (RT-O24); until
  RT-W10 it joins `RESTRICTED_METHODS`
  ([`rust/shekyl-daemon-rpc/src/handlers/json_rpc.rs:49`](../../rust/shekyl-daemon-rpc/src/handlers/json_rpc.rs)),
  so the view listener refuses it. It never writes the config file.
- **Build, then apply: all or nothing under one lock** (Rick, 2026-10-14).
  No runtime row's validity depends on its owner's live state, so every
  refusal is its constructor's. A set runs two steps under its one lock:
  1. **build**: every value through its constructor;
  2. **apply**: each owner takes the built value and cannot fail.

  Every refusal is reported before anything is applied, so the set is all
  or nothing. The startup parse runs the same constructors: one rule on
  both surfaces (IG-12). The logging owner's apply does not meet step 2 yet:
  its filter is swapped through a reload handle whose `reload` returns a
  `Result`, reachable only through the FFI module
  ([`rust/shekyl-logging/src/ffi.rs:639`](../../rust/shekyl-logging/src/ffi.rs)).
  The cutover gives `shekyl-logging` a Rust interface that holds the
  handle for the life of the process and cannot fail.
- **What a change does to traffic already running.** A rate limit takes
  effect on the next transfer and never aborts one in flight.
- **Defaults are values.** Every runtime row's default can be written back:
  a rate takes `unlimited`, and `log-category` takes `none` for no
  per-category overrides. An empty category list never
  means logging off; the inherited reading
  ([`rust/shekyl-logging/src/filter.rs:155-162`](../../rust/shekyl-logging/src/filter.rs))
  goes.
- **`option_show`** takes an optional list of names and returns each row
  the caller may see, in table order, with its name, source (`default`,
  `file`, `cli`, `runtime`) and whether it is runtime. A value row carries
  `value`, text or null; a secret row carries no value, only `secret: true`
  and `set`. The text it prints round-trips through `option_set`, held by a
  property test. It is served to `health`, and each row is present only
  under the grant the row names: `health`, `status`, `peers` or `config`,
  default `config` (RT-O24). The four runtime rows are `status`; rows that
  link the operator or describe the host stay `config`, which only the
  `admin` preset carries. Until RT-W10, `Disclosure`
  ([`rust/shekyl-daemon-rpc/src/info.rs:70`](../../rust/shekyl-daemon-rpc/src/info.rs))
  gains a `config` axis, set in `FULL` and clear in `VIEW`.
- **Errors** carry the IG-11 diagnostics in the JSON-RPC error's `data`
  member under one new code, with a `CORE_RPC_VERSION` bump (RT-O25).
- **Concurrency and audit.** One lock covers a whole set, and show reads
  under it. Each applied set writes one audit line: the caller, each row,
  its old and new value. A table gate holds that no row is both runtime
  and secret (RT-O27).
- **`mine start` and `mine stop`** build `mine-address` and `mine-threads`
  through their constructors and are the one request that still reaches
  C++, carrying validated values, until the miner moves to Rust.

The live value belongs to its owner. Deleted with their handlers and
callers: `/set_limit`, `/in_peers`, `/out_peers`, `/set_log_level`,
`/set_log_categories` and `/get_limit`. `/in_peers` and `/out_peers` set
options this cutover deletes, so nothing replaces them; `option_set`
replaces the other setters, and `option_show` replaces `/get_limit`, which
leaves RK-8 instead of being ported (§4.2). `/pop_blocks` is not
this cutover's: it becomes an armed test lever behind RT-W10's start
switch (RT-O9.2; DC-F14).

### 2.8 The clearnet public address (DC-Q10)

`clearnet-advertise` (`INPUT_GRAMMAR.md` §5) is read by the peer lists at
construction and given to the same own-address entry the onion uses
(`shekyl_peerlist_set_own_address`, `rust/shekyl-ffi/src/dialer_ffi.rs:563`), so both
connectors obey one rule. Unset, clearnet stays dial-only, as it is today,
and the posture line says so.

### 2.9 The C++ snapshot

One read-only structure, filled once by Rust before the C++ remnant is
constructed, holding exactly the values whose reader is still C++. The
lane-owned knobs are not in it: under IG-Q4 they are not ported, and the
C++ keeps today's defaults as constants until their lanes decide.

| Field | Reader | From |
| --- | --- | --- |
| the resolved data directory | core (the LMDB environment) | `data-dir` |
| the network | core, the miner, the console client | `network` |
| offline, derived from both connectors being off | core (line 1559 of `src/cryptonote_core/cryptonote_core.cpp` at `d26148535e`), the protocol handler | `clearnet`, `tor` (IG-Q3) |
| the fixed difficulty | core | `dev-difficulty` |
| the pool's weight bound | core | `txpool-weight-max` |
| sync on or off | the protocol handler | `dev-sync` |
| the mining address | the miner | `mine-address` |
| the mining threads | the miner | `mine-threads` |
| console on or off | the C++ console | `console` |
| the console's command words | the C++ console client | the positional words; empty for a daemon start |
| the console's RPC endpoint | the C++ console client | the first `rpc-admin-listen` endpoint, present only in client mode, where its absence is refused at parse (§2.2) |

**Eleven fields.** A gate pins the count and fails when it rises; each later
slice that moves a reader deletes its field. If the pre-flight finds a C++
reader of the advertised address on `dev`, it is a twelfth field,
recorded there.

The relay's identity and the descriptors reserved for the inbound ceiling
are read inside Rust (the zone the remnant opens, and the seam bind). They
are one preparation the Rust `main()` installs before `run`, not snapshot
fields. The RPC reads offline from the same fact the snapshot carries for
C++, at its configure, so a peer-list answer is offline before any dialer
call.

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
| paths | `shekyl-daemon-config` (lock, marker); core through the snapshot | the run mode (`service`, DC-Q17), the resolved data directory and log file, and their sources | `data-dir`, `log-file`, `config-file`, `os-version` (folded into `version`) |
| logging | `shekyl-logging` | the level, the per-category levels, the disk budget for the live file and its archives (IG-Q19) | `log-level`, `max-log-file-size`, `max-log-files` |
| network | `shekyl-daemon-config`, read by every owner | the network and its params row | `testnet`, `stagenet`, `regtest` |
| clearnet connector | the zone host and the dialer | the posture: `Off`, or `On` with listen endpoints, an optional SOCKS endpoint (credentials are refused until a dial sends them), and the advertised endpoints | `p2p-bind-ip`, `p2p-bind-ipv6-address`, `p2p-bind-port`, `p2p-bind-port-ipv6`, `p2p-use-ipv6`, `p2p-ignore-ipv4`, `p2p-external-port`, `proxy`, and `offline` with the Tor connector |
| Tor connector | `shekyl-tor` and the zone host | the posture: `Off`, `Managed` with the Tor binary's path, or `Operator` with a SOCKS endpoint (credentials are refused until a dial sends them) and an optional onion with its local listen endpoint | `no-ephemeral-tor`, `tx-proxy`, `anonymous-inbound`, `SHEKYL_TOR_BINARY` (environment) |
| p2p policy | the dialer and the peer lists | the operator's peers, the closed-network declaration (absent or non-empty, DC-F11), the local-range override, early disclosure, the ban file's entries, the two rate bounds | `add-peer`, `seed-node`, `add-exclusive-node`, `allow-local-ip`, `p2p-disclose-early` (PR-3), `ban-list`, `in-peers`, `limit-rate-up`, `limit-rate-down`, `limit-rate`, `out-peers`, `tos-flag`, `no-igd`, `igd` |
| rpc | `shekyl-daemon-rpc` | the admin and view listener sets, the origin list, the connection cap | `rpc-bind-ip`, `rpc-bind-ipv6-address`, `rpc-use-ipv6`, `rpc-bind-port`, `rpc-restricted-bind-ip`, `rpc-restricted-bind-ipv6-address`, `rpc-restricted-bind-port`, `restricted-rpc`, `rpc-access-control-origins`, `rpc-max-connections`, `rpc-max-connections-per-public-ip`, `rpc-max-connections-per-private-ip`, `rpc-response-soft-limit`, `disable-rpc-ban` |
| txpool | core, through the snapshot | the weight bound | `max-txpool-weight` |
| notify | the Rust runner (DC-Q14) | three commands, each an argument array with its named placeholders | `block-notify`, `reorg-notify`, `block-rate-notify` |
| mine | the miner, through the snapshot | the address and the thread count | `start-mining`, `mining-threads`, the five `bg-mining-*` |
| dev | each lever's owner | the levers of `INPUT_GRAMMAR.md` §5, each accepted only on the networks its row names, never on mainnet (IG-8) | `fixed-difficulty`, `no-sync`, `clearnet-transport-encrypt`, `carrier-development`, the four environment levers |
| session | the C++ console, through the snapshot, until R8 | console on or off, the command words | `non-interactive`, `daemon_command` |

In no section, because nothing is configured: `keep-fakechain` (no wipe),
`max-concurrency` (IG-Q7), the three test levers, `show-time-stats`.
Lane-owned and not ported (IG-Q4): `prep-blocks-threads`, `block-sync-size`,
`span-limit`, `block-download-max-size`, `db-sync-mode`, `db-salvage`,
`keep-alt-blocks`, `pad-transactions`.

---

## 4. What is deleted

### 4.1 The C++ options (82 registered in `shekyld`)

Every row's disposition is `INPUT_GRAMMAR.md` §5's; the C++ declaration is
deleted in every case.

| File | Sites | Options |
| --- | --- | --- |
| lines 102 to 120 of `src/daemon/main.cpp` at `d26148535e`, declared in lines 38 to 141 of `src/daemon/command_line_args.h` at `d26148535e` and [`src/common/command_line.cpp:71-72`](../../src/common/command_line.cpp) | 13 | `help`, `version`, `os-version`, `config-file`, `log-file`, `log-level`, `max-log-file-size`, `max-log-files`, `max-concurrency`, `proxy`, `non-interactive`, `daemon_command`, `carrier-development` |
| lines 237 to 260 of `src/cryptonote_core/cryptonote_core.cpp` at `d26148535e`, declared [`:74-188`](../../src/cryptonote_core/cryptonote_core.cpp) | 20 | `data-dir`, `testnet`, `stagenet`, `regtest`, `keep-fakechain`, `fixed-difficulty`, `prep-blocks-threads`, `show-time-stats`, `block-sync-size`, `test-drop-download`, `test-drop-download-height`, `test-dbg-lock-sleep`, `offline`, `block-download-max-size`, `span-limit`, `max-txpool-weight`, `block-notify`, `reorg-notify`, `block-rate-notify`, `keep-alt-blocks` |
| [`src/cryptonote_basic/miner.cpp:278-286`](../../src/cryptonote_basic/miner.cpp), declared [`:92-98`](../../src/cryptonote_basic/miner.cpp) | 7 | `start-mining`, `mining-threads`, `bg-mining-enable`, `bg-mining-ignore-battery`, `bg-mining-min-idle-interval`, `bg-mining-idle-threshold`, `bg-mining-miner-target` |
| [`src/blockchain_db/blockchain_db.cpp:199-203`](../../src/blockchain_db/blockchain_db.cpp) | 2 | `db-sync-mode`, `db-salvage` |
| [`src/p2p/net_node.inl:105-133`](../../src/p2p/net_node.inl), declared lines 87 to 153 of `src/p2p/net_node.cpp` at `d26148535e` | 26 | `p2p-bind-ip`, `p2p-bind-ipv6-address`, `p2p-bind-port`, `p2p-bind-port-ipv6`, `p2p-use-ipv6`, `p2p-ignore-ipv4`, `p2p-external-port`, `allow-local-ip`, `add-peer`, `add-priority-node` and `seed-node` (both gone on PR-3), `add-exclusive-node`, `tx-proxy`, `anonymous-inbound`, `no-ephemeral-tor`, `ban-list`, `no-sync`, `no-igd`, `igd`, `out-peers`, `in-peers`, `tos-flag`, `limit-rate-up`, `limit-rate-down`, `limit-rate`, `pad-transactions`, `clearnet-transport-encrypt`; and PR-3's `p2p-disclose-early` (`arg_p2p_disclose_early`, `src/p2p/net_node.cpp` line 131 at `d26148535e` at `fce0a2fa`) |
| lines 116 to 122 of `src/rpc/rpc_args.cpp` at `d26148535e`, declared at 91 to 105 (the file is deleted by commit (c)) | 7 registered of 15 | `rpc-bind-ip`, `rpc-bind-ipv6-address`, `rpc-restricted-bind-ip`, `rpc-restricted-bind-ipv6-address`, `rpc-use-ipv6`, `rpc-access-control-origins`, `disable-rpc-ban`; and the eight TLS and login descriptors registered for nothing (DC-F6) |
| [`src/rpc/core_rpc_server.cpp:92-103`](../../src/rpc/core_rpc_server.cpp), declared [`:1402-1450`](../../src/rpc/core_rpc_server.cpp) | 7 | `rpc-bind-port`, `rpc-restricted-bind-port`, `restricted-rpc`, `rpc-max-connections-per-public-ip`, `rpc-max-connections-per-private-ip`, `rpc-max-connections`, `rpc-response-soft-limit` |

### 4.2 Deletion rows

Every row is an `rg -n -e … <paths>` whose count is observed non-zero at
the base and zero after (rule 47). A literal pipe in a pattern is `\|`.

| Deleted | Before | After |
| --- | --- | --- |
| every `add_arg` in daemon-linked code | `rg -n -e 'command_line::add_arg' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db` → more than 80 | 0 (`src/common/command_line.{h,cpp}` stays for the utilities until IG Part B) |
| every `arg_descriptor` there | `rg -n -e 'arg_descriptor<' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db` → more than 0 | 0 |
| the map reads | `rg -n -F -e 'get_arg(vm' -e 'has_arg(vm' -e 'is_arg_defaulted(vm' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db src/cryptonote_protocol` → more than 90 | 0 |
| `variables_map` and `program_options` in `shekyld` | `rg -n -e 'variables_map' -e 'program_options' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db src/cryptonote_protocol` → more than 0; `rg -n -e 'Boost_PROGRAM_OPTIONS_LIBRARY' src/daemon/CMakeLists.txt` → 1 | 0 and 0 |
| `src/daemon/command_line_args.h`, `src/common/removed_flags.{h,cpp}`, `src/rpc/rpc_args.{h,cpp}`, `src/common/daemon_default_data_dir.{h,cpp}` | files exist; `removed_flags.cpp` still sends Windows operators to Task Scheduler (lines 158 to 162 of `src/common/removed_flags.cpp` at `d26148535e`), which RT-16 rejects; `daemon_default_data_dir.cpp` infers the mode from the account's elevation, which RT-16 forbids | `rg -n -e 'removed_flags' -e 'rpc_args' -e 'daemon_default_data_dir' -e 'command_line_args' src tests` → 0 |
| the RPC start's configuration and the C++ listener loop (§2.3) | `shekyl_daemon_rpc_start` has nine parameters; `rg -n -e 'rpc_instance' -e 'rust_rpc_handles' src/daemon` → more than 0 | one parameter, the core handle; 0 |
| the zone host's C++-supplied values (Rick's review, item 3) | `shekyl_zone_listen_clearnet` takes the bind values, the SOCKS host and port, the encrypt flag, the network id and the ceiling (`rust/shekyl-ffi/src/zone_ffi.rs:452-464`); the ceiling is computed in C++ (`transport_ceiling`, `src/p2p/net_node.h` line 456 at `d26148535e`, `src/p2p/net_node.inl:832`, `:968`, `:997`); the spans are already Rust's (the transport layer's `spans.rs` on PR-3) | the zone host reads its sections, the network id comes from the network row, the ceiling from Rust's own resolver; `rg -n -e 'transport_ceiling' -e 'm_network_id' src/p2p` → 0 |
| every other configuration push | `rg -n -e shekyl_zone_set_connector_cap -e shekyl_zone_clear_connector_cap -e shekyl_link_set_up -e shekyl_link_set_down src rust/shekyl-ffi/src src/shekyl/shekyl_ffi.h` → more than 6; `shekyl_log_init_file`, `shekyl_log_set_level`, `shekyl_log_set_categories` called from [`contrib/epee/src/mlog.cpp:215`](../../contrib/epee/src/mlog.cpp), [`:306`](../../contrib/epee/src/mlog.cpp), [`:338`](../../contrib/epee/src/mlog.cpp); `shekyl_daemon_tor_start`'s data-directory parameter ([`src/p2p/net_node.inl:761-763`](../../src/p2p/net_node.inl)) | the pushes gone; the managed Tor reads the paths section; `mlog_configure` shrinks to installing the tracing forwarder |
| PR-3's pushes | `rg -n -e shekyl_dialer_set_out_peers -e shekyl_peerlist_allow_local_ip -e shekyl_peerlist_admit_operator -e shekyl_peerlist_disclose_early -e shekyl_dialer_set_exclusive -e shekyl_dialer_open_address_file -e note_own_address -e admit_operator_peer src rust/shekyl-ffi src/shekyl/shekyl_ffi.h` → more than 8 (`rust/shekyl-ffi/src/dialer_ffi.rs:351`, `:464`, `:489`, `:511`, `:538`; `rust/shekyl-ffi/src/peerlist_ffi.rs:68`) | 0; `shekyl_peerlist_set_own_address` survives only as the peer lists' own entry, called by `shekyl-tor` and by the configuration, never by C++ |
| the reverse pulls | `rg -n -e shekyl_p2p_default_out_peers -e shekyl_relay_zone_min_provisioned_out_peers -e shekyl_dialer_out_target src` → more than 3 | 0 |
| UPnP | `rg -n -i -e 'upnp' -e 'm_igd' -e 'igd_t' src/p2p` → more than 40 ([`src/p2p/net_node.h:227-231`](../../src/p2p/net_node.h), [`:383-390`](../../src/p2p/net_node.h), [`src/p2p/net_node.inl:66-68`](../../src/p2p/net_node.inl), [`:1013-1019`](../../src/p2p/net_node.inl), [`:1275`](../../src/p2p/net_node.inl), [`:2096-2098`](../../src/p2p/net_node.inl)) | 0 |
| miniupnpc | `rg -n -i -e 'miniupnp' -e 'UPNP' CMakeLists.txt external/CMakeLists.txt cmake/FindMiniupnpc.cmake .gitmodules contrib/brew/Brewfile .github/workflows src/p2p/CMakeLists.txt` → more than 15 ([`CMakeLists.txt:490`](../../CMakeLists.txt), [`external/CMakeLists.txt:32-51`](../../external/CMakeLists.txt)) | 0; the submodule leaves `.gitmodules` and the tree; the note at [`scripts/ci/check_doc_claims.py:694`](../../scripts/ci/check_doc_claims.py) is updated |
| `out-peers` and its runtime surface | `rg -n -e 'out_peers' -e 'OUT_PEERS' -e 'change_max_out_public_peers' -e 'get_max_out_public_peers' src rust/shekyl-daemon-rpc/src` → more than 20 ([`src/rpc/core_rpc_server.cpp:1166-1171`](../../src/rpc/core_rpc_server.cpp), [`src/daemon/command_server.cpp:211-213`](../../src/daemon/command_server.cpp), [`rust/shekyl-daemon-rpc/src/server.rs:344`](../../rust/shekyl-daemon-rpc/src/server.rs)) | 0 |
| the inbound cap and every text that names it (§1.1, the inbound-cap ruling) | `rg -n -e 'in_peers' -e 'in-peers' -e 'change_max_in_public_peers' -e 'get_max_in_public_peers' -e 'm_inbound_cap_explicit' src rust tests` → more than 90 (lines 1700 to 1711 of `src/p2p/net_node.inl` at `d26148535e`, lines 1970 to 1999 at `d26148535e`, the console word at [`src/daemon/command_server.cpp:217`](../../src/daemon/command_server.cpp), and the five unbounded-case warnings at lines 1825 to 1853 of `src/p2p/net_node.inl` at `d26148535e`) | 0; the safety bound stays, and its warnings say that inbound is unbounded and why, naming nothing the operator can set; `InboundCeiling::resolve`'s `reserved` no longer counts explicit inbound caps, since no zone has one; the C++ tests that pin `--in-peers 0` suppressing the address announcement (lines 1768 to 1774 of `tests/unit_tests/node_server.cpp` at `d26148535e`) are replaced by the same assertion under `clearnet-listen none` |
| the per-knob runtime endpoints, their callers and the console words (§2.7, `RPC_CHANNEL.md` §6.4) | `rg -n -e '"/set_limit"' -e '"/in_peers"' -e '"/set_log_level"' -e '"/set_log_categories"' -e '"/get_limit"' rust/shekyl-daemon-rpc/src/server.rs` → more than 5 ([`rust/shekyl-daemon-rpc/src/server.rs:267`](../../rust/shekyl-daemon-rpc/src/server.rs), [`:319-349`](../../rust/shekyl-daemon-rpc/src/server.rs)); the callers of `/get_limit`: the Rust console's `print_net_stats` ([`rust/shekyl-daemon-rpc/src/console/mod.rs:1116-1161`](../../rust/shekyl-daemon-rpc/src/console/mod.rs)), the Python framework ([`utils/python-rpc/framework/daemon.py:433-436`](../../utils/python-rpc/framework/daemon.py)), the C++ client test ([`tests/unit_tests/daemon_rpc_client.cpp:107-110`](../../tests/unit_tests/daemon_rpc_client.cpp)), and the regtest check of `print_net_stats` | 0; `option_set` and `option_show` in their place, the callers moved to them; `/get_limit` leaves RK-8 (replaced, not ported). `/pop_blocks` stays and moves behind RT-W10's armed switch (RT-O9.2) |
| the `,N` suffixes | `rg -n -e 'get_max_connections' -e 'max_connections' src/p2p/net_node.cpp src/p2p/net_node.h` → more than 8 | 0 |
| `disable-rpc-ban` and the RPC server's dead scorer | `rg -n -e 'disable_rpc_ban' -e 'core_rpc_server::add_host_fail' -e 'RPC_IP_FAILS_BEFORE_BLOCK' src` → more than 5 ([`src/rpc/core_rpc_server.cpp:173-190`](../../src/rpc/core_rpc_server.cpp); the shared context is unblockable, [`src/rpc/core_rpc_ffi.cpp:84-89`](../../src/rpc/core_rpc_ffi.cpp)) | 0; `node_server::add_host_fail` ([`src/p2p/net_node.inl:395`](../../src/p2p/net_node.inl)) is the P2P function and stays |
| the test and debug levers | `rg -n -e 'test_drop_download' -e 'g_test_dbg_lock_sleep' -e 'show_time_stats' src contrib/epee/include/syncobj.h` → more than 10 | 0 |
| background mining's options and runtime arguments | `rg -n -e 'do_background_mining' -e 'ignore_battery' -e 'bg_mining' src` → more than 10 | 0 for the options and the `start_mining` arguments; the miner's background thread is the mining lane's (§10) |
| the network booleans and `keep-fakechain` | `rg -n -e 'arg_testnet_on' -e 'arg_stagenet_on' -e 'arg_regtest_on' -e 'keep_fakechain' src` → more than 20 | 0 in daemon-linked code; the utilities' copies are re-homed (§9) |
| the three regtest arms | the FAKECHAIN tests at [`src/p2p/net_node.inl:617`](../../src/p2p/net_node.inl), [`:719`](../../src/p2p/net_node.inl), line 523 of `src/cryptonote_core/cryptonote_core.cpp` at `d26148535e`, [`:1628`](../../src/cryptonote_core/cryptonote_core.cpp) | gone; [`:484`](../../src/cryptonote_core/cryptonote_core.cpp) (the `/fake` subdirectory) becomes the params row; [`:631`](../../src/cryptonote_core/cryptonote_core.cpp) (the pool's flag) is the pool lane's and is listed, not deleted |
| the data-directory port suffix | `rg -n -F -e 'm_config_folder + "/" + public_zone.m_port' src/p2p/net_node.inl` → 1 | 0 |
| `Blockchain::m_offline` and its parameter | [`src/cryptonote_core/blockchain.cpp:302`](../../src/cryptonote_core/blockchain.cpp), [`src/cryptonote_core/blockchain.h:1145`](../../src/cryptonote_core/blockchain.h) | 0 |
| the undefined `extern nodetool::arg_offline` | line 507 of `src/p2p/net_node.h` at `d26148535e` | 0 |
| `m_require_ipv4` | `rg -n -e 'm_require_ipv4' src` → 2 | 0 |
| the environment levers | `rg -n -F -e 'getenv("SHEKYL_' src/cryptonote_core/blockchain.cpp` → 2; `rg -n -F -e 'env::var("SEEDHASH_' rust/shekyl-ffi/src/pow_randomx_ffi.rs` → 4; `rg -n -F -e 'getenv("RPC_LOGIN")' src/rpc` → 1; `rg -n -e 'SHEKYL_TOR_BINARY' rust docs/COMPILING_DEBUGGING_TESTING.md` → 8, read once at [`rust/shekyl-tor-control-client/src/binary.rs:491`](../../rust/shekyl-tor-control-client/src/binary.rs) | 0; the four `dev-` levers replace them, and Rust arms the schedules from its section; `tor-file` replaces the Tor override, and `discover_and_verify` keeps only its two discovered tiers |
| the carrier global | `rg -n -e 'set_carrier_development' src` → more than 2 | 0; the relay reads `dev-relay-cover` |
| `tools::set_max_concurrency` from the daemon | the two lines of `main.cpp` at `d26148535e`, recorded in the audit §2 | gone with `main.cpp`'s parse (commit (b)) |
| the C++ notify path and its process-wide `SIGCHLD` change (DC-F12) | line 52 of `src/common/notify.cpp` at `d26148535e` splits a command string on whitespace; line 124 of `src/common/spawn.cpp` at `d26148535e` sets `SIGCHLD` to ignored for the whole process; the daemon is their only user (`src/cryptonote_core/cryptonote_core.cpp:53`, `src/cryptonote_core/blockchain.cpp:72` include `notify.h`), with `tests/unit_tests/notify.cpp` | `src/common/notify.{h,cpp}`, `src/common/spawn.{h,cpp}` and `tests/unit_tests/notify.cpp` deleted with their CMake entries; `rg -n -e 'tools::Notify' -e 'tools::spawn' -e 'SIGCHLD' src tests` → 0 (the runner is Rust's, DC-Q14, and tests itself) |
| the C++ signal owner and orchestration (DC-Q13) | [`src/daemon/daemon.cpp:272`](../../src/daemon/daemon.cpp) installs `tools::signal_handler`, whose Windows handler stops only on Ctrl-C and Ctrl-Break ([`src/common/util.h:193-201`](../../src/common/util.h), DC-F13); `Daemon::run`, `t_internals` and `main.cpp`'s body orchestrate the start | `rg -n -e 'signal_handler::install' src/daemon` → 0; the orchestration replaced by the remnant's `run(snapshot)` and `stop()`; `main.cpp` is one call |
| `utils/conf/shekyld.conf` | the file exists; cited at [`docs/USER_GUIDE.md:131-133`](../USER_GUIDE.md) | gone |
| `scripts/ci/check_carrier_flag_hidden.sh` | exists | replaced by a table test that `dev-relay-cover` is hidden and refused on mainnet |
| C++ tests of the deleted mechanism | lines 54 to 120 of `tests/unit_tests/command_line.cpp` at `d26148535e`, `tests/unit_tests/rpc_args_daemon_surface.cpp` | deleted; `IsYes` stays |
| C++ tests that build a `variables_map` | `rg -n -e 'variables_map' tests/unit_tests/node_server.cpp tests/core_tests/chaingen.h tests/core_tests/chaingen_main.cpp tests/unit_tests/sync_orphan_arm.cpp tests/unit_tests/main.cpp tests/performance_tests/main.cpp` → more than 10 | 0; they construct the remnant from a snapshot built by the real Rust parse of a test argument list (rule 26 B2) |
| the disclose-early rename's acceptance (IG-Q20) | `rg -n -e 'small_network' -e 'SmallNetwork' -e 'SMALL_NETWORK' -e 'small-network' src rust` → 0 at `d26148535e` | no match in `src` or `rust`, the grammar's acceptance (`INPUT_GRAMMAR.md` IG-Q20) |

---

## 5. Ripples

### 5.1 Launchers, re-censused at `d26148535e`

Every launcher moves to the grammar's names in the cutover. Under DC-Q5 a
regtest daemon that is not offline runs the managed Tor, and nothing wipes
a chain.

| Launcher | What changes beyond spelling | Regtest, not offline |
| --- | --- | --- |
| [`contrib/packaging/linux/shekyld.service:12`](../../contrib/packaging/linux/shekyld.service) | drops `--non-interactive` (no console unless asked, IG-Q8) | — |
| [`utils/fleet/skl-node@.service:35`](../../utils/fleet/skl-node@.service) and its siblings; [`utils/fleet/gen_host_configs.sh:69-88`](../../utils/fleet/gen_host_configs.sh) | the generated files become TOML; `--network` moves to the unit's command line; the UPnP key goes | — |
| [`rust/shekyl-engine-core/src/engine/regtest_e2e.rs:359-396`](../../rust/shekyl-engine-core/src/engine/regtest_e2e.rs) | the `Linked` arm already declines the managed Tor | yes, already handled |
| [`rust/shekyl-levin/tests/dual_stack.rs:71-72`](../../rust/shekyl-levin/tests/dual_stack.rs), [`rust/shekyl-levin/tests/inbound_cost_bench.rs:166-167`](../../rust/shekyl-levin/tests/inbound_cost_bench.rs) | `--out-peers 0` goes; each gains the Tor-off setting (Rick names the second) | yes |
| [`scripts/bench/drs_bench.py:256-257`](../../scripts/bench/drs_bench.py) | loses `--keep-fakechain` and `--db-sync-mode` (IG-Q4); the linked daemons gain the Tor-off setting | yes, except the offline seed at [`:291`](../../scripts/bench/drs_bench.py) |
| [`scripts/bench/wss_q1b_regtest_open_edge.sh`](../../scripts/bench/wss_q1b_regtest_open_edge.sh), [`rust/shekyl-wire/tests/vectors/capture_coinbase.py`](../../rust/shekyl-wire/tests/vectors/capture_coinbase.py), [`rust/shekyl-curve-tree/tests/fixtures/gen_ct2_fixture.py`](../../rust/shekyl-curve-tree/tests/fixtures/gen_ct2_fixture.py) | spelling | offline |
| [`scripts/bench/ba_t5_session2_run.sh`](../../scripts/bench/ba_t5_session2_run.sh), [`scripts/bench/ba_t5_session3_run.sh`](../../scripts/bench/ba_t5_session3_run.sh) | the restricted port becomes a view listener; `--in-peers 0` and the P2P bind flags become `clearnet-listen none` | testnet |
| [`rust/shekyl-cli/tests/json_script.rs:291`](../../rust/shekyl-cli/tests/json_script.rs), [`rust/shekyl-cli/tests/scripts/daemon_session.txt:8`](../../rust/shekyl-cli/tests/scripts/daemon_session.txt) | spelling | testnet, offline |
| [`rust/shekyl-cli/src/main.rs:524-532`](../../rust/shekyl-cli/src/main.rs) | its daemon-down message prints the daemon's network spelling | — |
| `contrib/tor/shekyl-over-tor.sh` at `d26148535e` (deleted by commit (f1)) | passes `--detach`, retired in V3.1, so it is broken today (DC-F8); rewritten or deleted | — |
| [`Dockerfile`](../../Dockerfile) | spelling; drops `--non-interactive` | — |
| the GUI sidecar (`shekyl-gui-wallet`, `daemon_manager.rs`) | passes `--rpc-admin-listen none --rpc-view-listen 127.0.0.1:<port>` (`INPUT_GRAMMAR.md` §5); a PR in that repository, merged with the cutover | — |
| `shekyl-dev`: configuration examples, unit files, the stressnet playbook, the Foundation seed recipe (roles only, rule 37) | TOML files at the system path; an explicit `in-peers` goes; a change in that repository under its own authorisation | — |

### 5.2 Gates

`scripts/ci/check_dial_path_freeze.py`: PR-3 retired its function rows; its
shrink rows stay on `src/p2p/net_node.inl`, `src/p2p/net_node.h` and
`src/cryptonote_protocol/levin_notify.cpp` until those files are deleted
([`scripts/ci/dial_path_freeze.tsv`](../../scripts/ci/dial_path_freeze.tsv)).
The cutover's deletions there are free; a line it edits there rather than
deletes carries a dated UNFREEZE line in the dialer brief.
`scripts/ci/check_ffi_signatures.sh` covers every signature in §2.3 and
§4.2. `scripts/ci/check_network_uniformity.sh`: the FAKECHAIN arms are
outside its fence; this cutover deletes three and adds none. The Windows job's daemon smoke test (Rick, 2026-10-14), which replaces
the daemonizer-removal step on today's spellings ahead of the cutover,
boots the built `shekyld.exe` offline on regtest with a fresh data
directory and a free RPC port, waits for `get_info`, stops it over RPC and
asserts exit 0 within a timeout and a created store; the cutover extends
the same job with the Rust `main()` and its one stop path, a second daemon
on the same data directory refused by the lock, a config directory whose
access list grants Users write refused with exit 2, and another network's
data directory refused by the marker; RT-W14 later adds a service-manager
case (install, start, `SERVICE_RUNNING`, stop).

The cutover's edit of the job's script (`scripts/ci/daemon_boot_stop_smoke.ps1`,
#1072; Rick, 2026-10-14):

- **Say why the daemon never answered.** The `get_info` poll catches and
  ignores every error, so a daemon that listens but keeps answering with
  an HTTP error is reported as a bare timeout. The poll keeps its last
  error and prints it with the timeout message.
- **The store check moves with the store.** The script looks for the
  store under `fake\lmdb\data.mdb`, a path the regtest branch at
  line 484 of `src/cryptonote_core/cryptonote_core.cpp` at `d26148535e`
  makes. Under DC-Q5 an explicit data directory is used as given and the
  network subdirectory is row data for the default layout only, so the
  check asserts the store at the path the cutover gives it. It also
  asserts `shekyld.lock`, present and held while the daemon runs, and the
  `shekyld.network` marker, holding `regtest` and its network id after the
  run (DC-Q15).
- **A Ctrl-Break case needs its own launch.** `GenerateConsoleCtrlEvent`
  delivers Ctrl-Break, not Ctrl-C, to a process started in its own process
  group (`CREATE_NEW_PROCESS_GROUP`). .NET's `Process.Start` cannot set that
  flag, so the case needs a small `CreateProcess` call or helper, and the
  runner's process needs a console. Whether the hosted Windows runner has
  one is a pre-flight check (§9), not an assumption; if it has none, the
  case belongs in the Windows lane's local run instead of CI. Window close,
  logoff and shutdown cannot be generated this way at all.

New: the
grammar gate (IG-3, IG-9) over the daemon's table; the snapshot field-count
gate (§2.9); the recipe gate (DC-Q8), asserting that the shipped unit's
paths agree with its `StateDirectory` and `LogsDirectory` and that every
flag a unit or template passes is a live name; the refused-inbound test
(Rick, 2026-10-14), which uses the real safety bound with no option and no
development lever: it starts the daemon with a lowered descriptor limit on
the child (`prlimit` or `ulimit -n`), fills the derived ceiling, and
asserts that the next accept is refused. It runs on Unix only, because
Windows has no per-process descriptor limit (PWD-B1).

### 5.3 Documentation

The option tables at [`docs/EXECUTABLES.md:53-82`](../EXECUTABLES.md) and
[`docs/USER_GUIDE.md:135-190`](../USER_GUIDE.md), and the example at
[`docs/USER_GUIDE.md:115-133`](../USER_GUIDE.md), are generated from the
table and gated (IG-9). `docs/proxies.md` is rewritten for the connector
postures and loses `--add-node`, which never existed.
`SHEKYL_P2P_PROTOCOL.md`'s passage on the derived port advertisement names
`clearnet-listen none` as the operator's way to stay unannounced, where it
names `--in-peers 0` today. `docs/COMPILING_DEBUGGING_TESTING.md`'s Tor
section names `tor-file` where it names `SHEKYL_TOR_BINARY` today. The release notes say
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
| a value on a surface its row forbids: a secret or a command on the command line, the network or `service` in the file | refuse, naming where it may be given |
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
| a runtime change its constructor refuses, such as a log level the grammar does not name (§2.7) | the request fails with the code the startup parse would give, nothing in it is applied, and the daemon runs |
| a set request for a row not marked Runtime | the request fails with the startup-only code; the daemon runs |
| `service` outside the SCM (Windows) | refuse at entry, naming how the service is started |
| `service` on Linux, FreeBSD or macOS | refuse with its typed code: the platform's service manager runs the foreground process |
| `service` on Windows with the machine-wide root missing, mis-owned, or writable outside Administrators, SYSTEM and the service account | refuse with its typed code, naming the root and what was found; the daemon never creates it |

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
   (lines 178 to 216 of `src/daemon/main.cpp` at `d26148535e`): the
   planted file can set the proxy (exposing the node's traffic origin) or
   the log path (an administrator's file write). Route: the auto-load and
   the elevation branch are deleted; a pre-created directory carries a
   write-granting entry for its creator, so the allowlist of §2.4 refuses
   it rather than reading it; only `service` reads the machine-wide
   root, the installer alone creates it with its owner and list, and the
   daemon refuses one that is missing, mis-owned or writable by others
   (DC-Q17).

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
- **An operator inbound cap (`in-peers`; IG-Q40).** A peer count is a
  poor proxy for what an operator pays, which is bytes: the two rate
  limits bound that, and the descriptor safety bound keeps the process
  whole. Reopens as a byte quota, not a count, when an operator on a
  metered link needs one.
- **A retired-flag table.** Every release before genesis is a wipe. Reopens
  at genesis; the REJECTED rows are the record until then.
- **The blockchain utilities** keep their own option sets until IG Part B
  rules each tool; carried in §10.
- **The daemon's console and positional commands** stay in C++ until
  RT-15's local leg exists and `shekyl-cli` serves them (R8); carried in
  §10.

---

## 9. Sequencing and pre-flight

One cutover PR, based on `dev` with PR-3 merged. It
lands the table, the parse, the sections, the lock, the marker, logging in
Rust, the announcements, the Rust `main()` and the remnant's entry pair,
the notify runner, the one RPC start, every Rust
owner reading its section, the snapshot, the runtime handlers of §2.7,
every deletion of §4, every launcher of §5.1 in this repository, and the
generated documentation. The utilities Part B deletes go in their own PRs (`INPUT_GRAMMAR.md`
§14.1); those that remain (`shekyl-blockchain-import`, `-export`, `-stats`
until the redb cutover, and DRS-E2's `shekyl-e2-trace-export`) keep their
option sets; the descriptors they share with the daemon (`arg_data_dir`,
`arg_testnet_on`, `arg_stagenet_on`, `arg_db_sync_mode`) move into a header
they own, and `src/blockchain_utilities/blockchain_import.cpp:662`'s call to
`core::init_options` becomes a call into it.

Pre-flight (rule 26), recorded in `docs/design/DAEMON_CONFIG_CUTOVER_AUDIT.md`
before the first production commit:

1. Re-pin every citation at the implementation pin; re-run
   the §5.1 census (`rg -l -e shekyld` outside `src/` and `docs/`).
2. Observe every §4.2 before-count non-zero, and check the snapshot's field
   list against the C++ readers on `dev`.
3. Read the daemon-store set for the marker (§2.6) at that pin.
4. Rule 17 at source for every crate the parse and the checks need beyond
   `shekyl-options`.
5. Check whether the hosted Windows runner's process has a console, which
   decides where the Ctrl-Break case of §5.2 runs: in CI, or in the Windows
   lane's local run.
6. Demonstrate DC-F12 with a test before the runner replaces the C++ path:
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
| the inherited default of `txpool-weight-max` (IG-Q11) | [`DRS_E5_POOL_ALT_PRUNE.md`](DRS_E5_POOL_ALT_PRUNE.md), the pool's live document |
| the inherited default of `rpc-connections-max` (IG-Q12) | RT-O9.4, [`RPC_CHANNEL.md`](RPC_CHANNEL.md) |
| the `removed_flags` shim sunset | this brief §4; the row leaves with the files |

---

## 11. Findings established at source (DC-F1…DC-F14)

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
| DC-F10 | A `*` origin aborts the daemon after its log says RPC started. `shekyl_daemon_rpc_start` returned a handle and spawned the server (lines 208 to 212 of `rust/shekyl-daemon-rpc/src/ffi_exports.rs` at `d26148535e`); the task builds the CORS layer ([`rust/shekyl-daemon-rpc/src/server.rs:87-115`](../../rust/shekyl-daemon-rpc/src/server.rs)); tower-http 0.6.8 panics on a wildcard passed to `AllowOrigin::list` (its `allow_origin.rs`, lines 60 to 64, read at source); the workspace builds with `panic = "abort"` in both profiles (`rust/Cargo.toml`, lines 671 to 676), so the process ends; no panic hook is installed, so the reason reaches standard error only. Entries that are not valid header values are logged and dropped ([`rust/shekyl-daemon-rpc/src/server.rs:100-102`](../../rust/shekyl-daemon-rpc/src/server.rs)) | absorbed: the origin kind refuses both at parse |
| DC-F11 | A list option with no values was "present" to the C++: the vector semantic installs an empty default ([`src/common/command_line.h:179-183`](../../src/common/command_line.h)) and `has_arg` tests the map entry ([`src/common/command_line.h:256-262`](../../src/common/command_line.h)), so every start declared a closed network with no peers. PR-3 reads an empty declaration as none on the Rust side (`6fc926404`) | absorbed: the closed-network declaration is absent or non-empty |
| DC-F14 | `/pop_blocks` is not limited to regtest today. Neither its handler ([`src/rpc/core_rpc_server.cpp:1186`](../../src/rpc/core_rpc_server.cpp)) nor the chain code checks the network, and the route is only `AdminOnly` ([`rust/shekyl-daemon-rpc/src/server.rs:353-355`](../../rust/shekyl-daemon-rpc/src/server.rs)), so a caller on the loopback admin listener can rewind a mainnet chain; the harness comment calling it "FAKECHAIN-gated" ([`rust/shekyl-engine-core/src/engine/regtest_e2e.rs:771`](../../rust/shekyl-engine-core/src/engine/regtest_e2e.rs)) is false | routed: RT-O9.2's armed test lever, RT-W10's (`RPC_CHANNEL.md` §6.4); the comment is corrected when the route moves |
| DC-F13 | On Windows a run-as-user daemon is terminated, not stopped, by every console event but Ctrl-C and Ctrl-Break: the handler logs "Exiting without saving" and returns `FALSE` for window close, logoff and shutdown ([`src/common/util.h:193-201`](../../src/common/util.h)), so RT-16's "stops at logout" does not hold today. Low severity: the stores are transactional and Tor exits through `TAKEOWNERSHIP` | absorbed: one stop path for every signal, console event and SCM control (§2.2 step 9) |
| DC-F12 | The first notify command switches child reaping off for the whole process. `tools::spawn` sets `signal(SIGCHLD, SIG_IGN)` after a spawn it does not wait for (line 124 of `src/common/spawn.cpp` at `d26148535e`); from then on the kernel reaps every child, the managed Tor included, which the Rust side waits on ([`rust/shekyl-tor-control-client/src/control/actor.rs:616`](../../rust/shekyl-tor-control-client/src/control/actor.rs), [`:1011`](../../rust/shekyl-tor-control-client/src/control/actor.rs)). Under tokio 1.51.0 on Linux the pidfd reaper's wait then fails with `ECHILD` instead of an exit status; on macOS and FreeBSD the `SIGCHLD` handler tokio relies on is overwritten and the wait never completes | absorbed: the Rust runner reaps its own children and never changes a signal disposition (§2.10); pre-flight demonstrates it (§9) |

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

Written for the agent that lands the cutover. Read rules 00, 06, 08, 17, 19, 20, 22, 23, 25, 26, 35, 36, 40, 45,
47, 50, 71, 82, 83, 90, 94 and 95, and `INPUT_GRAMMAR.md`, before the first
commit.

1. **Preconditions.** PR-3 is on `dev`. The runtime requests are
   `RPC_CHANNEL.md` §6.4's (RT-O23…RT-O27), ruled 2026-10-14. Stop and ask if any is not
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
   the generated documentation and its gate, and the Windows smoke job's
   cutover cases and its script's edit (§5.2); (g) the index and FOLLOWUPS
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
