# Daemon configuration cutover — pre-flight record

**Status: OPEN — the pre-flight of the cutover's implementation (2026-10-15), recorded before the first production commit as [`DAEMON_CONFIG_CUTOVER.md`](DAEMON_CONFIG_CUTOVER.md) §9 requires.** Sibling record of that brief, which owns the design; this file records what was observed at the implementation pin and the decisions the implementation takes inside the brief. It mints no identifier family.

Implementation pin: `dev` `d26148535e` (2026-10-15). Branch
`feat/daemon-config-cutover`.

---

## 0. The ruling this implementation follows for the managed Tor

Rick, 2026-10-15, when the cutover started:

> Follow DAEMON_CONFIG_CUTOVER.md §13, with one sequencing note: the Tor
> supervisor (TOR_SUPERVISOR.md, merged #1077) is ruled but not implemented,
> and it lists DC-F12 as its prerequisite, which this cutover fixes. So §2.2
> steps 6 and 9 drive today's Rust Tor owner (DaemonTorControl: start,
> publish, shutdown) from the Rust main() — Tor bootstrap early at step 6,
> teardown at step 9 in parallel with the remnant's stop. No Tor code stays
> in or moves through C++. The supervisor's increment 5 later replaces that
> single call site.

The brief's steps 6 and 9 name the supervisor; until its increment 5 lands,
the call site they describe drives `DaemonTorControl`
([`rust/shekyl-tor-control-daemon/src/ephemeral.rs`](../../rust/shekyl-tor-control-daemon/src/ephemeral.rs)).
§7 below records how.

## 1. Re-pin and census (§9 item 1)

The brief's 218 `file:line` citations (114 links, 104 inline paths) were
mapped by line content from `bd444b7158` to `d26148535e`. Seven code files
changed between the two pins; no cited line moved or changed, so the brief's
pin statement moves and nothing else does. Three citations of
[`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) named sections the merged document
renumbered (§3.2, §3.7, §3.8); they now name §4.3 and §4.7.

The §5.1 census (`git grep -l -e shekyld` outside `src/` and `docs/`) finds
92 files at both pins, the same set.

## 2. Before-counts and the snapshot (§9 item 2)

Every §4.2 row with a command, run at the pin:

| Row | Before |
| --- | --- |
| every `add_arg` in daemon-linked code | 90 |
| every `arg_descriptor` there | 134 |
| the map reads | 124 |
| `variables_map` and `program_options` in `shekyld`; the CMake link | 69; 1 |
| the RPC start's configuration and the C++ listener loop | 11 |
| every other configuration push | 21 |
| PR-3's pushes | 47 |
| the reverse pulls | 11 |
| UPnP | 71 |
| miniupnpc | 59 |
| `out-peers` and its runtime surface | 71 |
| the inbound cap and every text that names it | 95 |
| the per-knob runtime endpoints | 10 |
| the `,N` suffixes | 11 |
| `disable-rpc-ban` and the RPC server's dead scorer | 13 |
| the test and debug levers | 41 |
| background mining's options and runtime arguments | 53 |
| the network booleans and `keep-fakechain` | 55 |
| the data-directory port suffix | 1 |
| `m_require_ipv4` | 2 |
| the environment levers | 2; 4; 1; 8 |
| the carrier global | 6 |
| C++ tests that build a `variables_map` | 16 |
| the disclose-early rename's acceptance | 0, the expected value |

Four commands in the brief returned 0 as written: their patterns hold `(`
or `+`, which `rg` reads as regular-expression syntax, so the search failed
or matched something else. Run as fixed strings they give the counts the
brief states. The brief now passes `-F` to the map reads, the port suffix
and the three environment levers. The rows that cite lines rather than a
command were read at the pin and still say what the brief says of them.

**The snapshot.** Daemon-linked C++ reads 89 distinct options through
`get_arg`, `has_arg` and `is_arg_defaulted`. Read against
[`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) §5, each one either moves to a Rust
owner (§3 of the brief), is deleted (§4), keeps its C++ reader as a
lane-owned constant (IG-Q4: `block-sync-size`, `span-limit`,
`block-download-max-size`, `db-sync-mode`, `db-salvage`, `keep-alt-blocks`,
`pad-transactions`, `prep-blocks-threads`), or is one of the snapshot's
fields. The brief's eleven fields are all present, and no other C++
reader of configuration is live: `m_external_port` is read at the pin only
by `get_announced_address`, which `get_announced_port` alone calls, and
nothing but the unit tests calls that (the function's own comment says no
handshake carries the address; the disclosure sample that does is Rust's).
**The snapshot has eleven fields.** The advertised endpoints
(`clearnet-advertise`) are not dropped: a peer's port is part of what is
checked with it (the seam's `AdvertisedEndpoint` and `adopt_redial`,
`rust/shekyl-seam/src/connection.rs`, which has no production caller yet
because the C++ handshake carries no port), so the value's home is Rust —
the peer lists' own entry (§2.8), where the handshake owner reads it
(Rick, 2026-10-15).

## 3. The daemon-store set (§9 item 3)

At the pin a daemon store is the LMDB environment, `lmdb/data.mdb` under the
data directory
([`src/cryptonote_config.h:215`](../../src/cryptonote_config.h),
[`src/blockchain_db/lmdb/db_lmdb.cpp:2016`](../../src/blockchain_db/lmdb/db_lmdb.cpp)),
and `p2pstate.bin`
([`src/cryptonote_config.h:217`](../../src/cryptonote_config.h)), which PR-3
made the Rust dialer's address file under the same name
([`src/p2p/net_node.inl:123`](../../src/p2p/net_node.inl)). The marker
treats either as a store.

## 4. Dependencies (§9 item 4, rule 17)

Read at source in the registry; nothing new enters `Cargo.lock`.

| Need | Crate, as the workspace already pins it |
| --- | --- |
| the TOML file, with a line for every value (IG-11) | `toml` 0.8.23 with `parse`, as `shekyl-engine-prefs` and `shekyl-chain-store` use it, and `serde`. `toml` re-exports `serde_spanned::Spanned` with no feature gate (line 174 of the crate's `lib.rs`), so each top-level key deserialises into a `Spanned` value carrying its byte range, and a parse error carries its span (`Error::span`, line 70 of its `de.rs`). A repeated key is a TOML parse error |
| the nearest live name (IG-10) | `strsim` 0.11.1, already in the lock |
| the passwd home, `flock`, `fsync` of a directory | `libc` 0.2 |
| the known-folder root, the Windows allowlist, `LockFileEx`, a write-through rename | `windows-sys` 0.61, as `shekyl-win-sec` pins it, with `Win32_UI_Shell` (`SHGetKnownFolderPath`, `FOLDERID_LocalAppData`), `Win32_Security_Authorization` (`GetSecurityInfo`), `Win32_Storage_FileSystem` (`LockFileEx`, `MoveFileExW`) and `Win32_System_IO` |
| the one signal owner | `tokio` 1.51.0 with `signal`: `unix::signal`, and on Windows `ctrl_c`, `ctrl_break`, `ctrl_close`, `ctrl_logoff`, `ctrl_shutdown` (the crate's `signal/windows.rs` module) |

## 5. The hosted Windows runner's console (§9 item 5)

The answer can only be read off a hosted run. The Windows smoke script now
prints, on every run, how many processes share its console and whether a
console window exists
([`scripts/ci/daemon_boot_stop_smoke.ps1`](../../scripts/ci/daemon_boot_stop_smoke.ps1)).
The cutover's first Windows job reports it, and this section records the
answer before commit (f) writes the Ctrl-Break case.

## 6. DC-F12 demonstrated (§9 item 6)

[`rust/shekyl-tor-control-client/tests/dc_f12_sigchld_ignored.rs`](../../rust/shekyl-tor-control-client/tests/dc_f12_sigchld_ignored.rs)
spawns a tokio child under the default disposition and gets its status,
then makes the call `tools::spawn` makes
(line 124 of `src/common/spawn.cpp` at `d26148535e`) and spawns a
second. On Linux at the pin the second `wait()` returns at once with
`ECHILD` ("No child processes"): the kernel reaped the child itself. The
managed Tor's reaper reads that error as a wedge, so
`TorChild::shutdown` publishes `TorExit::Killed` for a Tor that exited
cleanly
([`rust/shekyl-tor-control-client/src/control/actor.rs:616`](../../rust/shekyl-tor-control-client/src/control/actor.rs)).
The test reproduces the syscall, not the C++ path, because a Rust test
cannot link `tools::spawn` and the defect is the disposition, whoever sets
it. It is a binary of its own because a disposition is process-wide.
Commit (d) added the positive twin,
[`rust/shekyl-ffi/tests/dc_f12_runner_reaps_its_children.rs`](../../rust/shekyl-ffi/tests/dc_f12_runner_reaps_its_children.rs):
the Rust runner runs one command of each kind and awaits each, and a tokio
child spawned afterwards still returns its status from `wait()`. A binary
of its own, for the same reason as the negative one.

## 7. Decisions the implementation takes inside the brief

- **Where the entry lives.** The start and stop logic is a new safe crate,
  `shekyl-daemon`, over `shekyl-daemon-config`, `shekyl-logging`,
  `shekyl-ffi`'s Rust surface and `shekyl-runtime`. Its one C symbol,
  `shekyl_daemon_main`, is defined there and carried into the archive by
  `shekyl-daemon-image`, the composition root §2.1 names, as
  `shekyl-ffi`'s exports are: `shekyl-ffi` cannot define it without
  depending on crates that depend on `shekyl-ffi`. The C++ defines no
  symbol Rust imports: `main()` hands the entry a `ShekylDaemonEntry` of
  the version strings and two function pointers, `run` and `stop`, so no
  Rust crate links against the daemon's objects, every Rust test drives
  the entry with a fake pair, and the signature gate's rule that every
  declared `shekyl_` function is a Rust export holds. The entry, the entry
  types and the snapshot are `rust/shekyl-daemon/src/entry.rs`, a gate
  surface; `shekyl_daemon_snapshot_field_count` is the export the C++
  asserts, and the two `no_mangle` items carry the crate's only
  `allow(unsafe_code)`, each scoped to itself.
- **The daemon at each intermediate commit.** From commit (b) Rust owns
  `argv` and parses it with the grammar. Until commit (e) deletes the last
  C++ reader, C++ still reads options through `boost::program_options`, so
  every commit is a working daemon: Rust renders the parsed configuration
  into today's spellings, and the remnant's `run` parses that rendering as
  `main.cpp` parses `argv` today. The renderer is one Rust module, deleted
  in commit (e) with the readers; the snapshot gate counts the twelve
  fields, not the rendering.
- **The RPC start is the step 7 to 8 rendezvous.** The Rust `main()`
  records the RPC section (`shekyl_daemon_rpc::ffi_exports::configure`)
  before the remnant is constructed, and waits on the receiver that
  `shekyl_daemon_rpc_start(core)` completes: `Ok` once every admin and
  view listener is bound and served, `Err` with the refusal otherwise,
  in which case the remnant's `run` throws and returns 1. The start is
  the last act of §2.2 step 7, so its completion is the one signal that
  the core exists; no second export is needed for it. One server, one
  connection tracker, two routers: `rpc-admin-listen` at the admin
  preset, `rpc-view-listen` at the view preset
  (`rust/shekyl-daemon-rpc/src/server.rs`, `serve_presets`). The C++
  `core_rpc_server` is one object with no preset of its own
  (`caller_is_restricted` is always false; Rust's `served_routes` is the
  only gate), and `rpc_args.{h,cpp}` and the dead RPC scorer
  (`add_host_fail`, `disable_rpc_ban`, `RPC_IP_FAILS_BEFORE_BLOCK`) go
  with it: deleting `rpc_args` leaves the scorer's one input a constant.
- **One stop path, from the remnant too.** Rust holds the RPC handle, so
  a `run` that returned before the RPC was stopped would destroy the core
  under a serving handler. The two triggers inside the remnant, the
  console's `exit` and the RPC's `stop_daemon`, therefore ask the one
  owner through `shekyl_daemon_request_stop()` (the third export of
  `entry.rs`), observed by the same `select!` as the signals; the stop
  then runs in step 9's order: the RPC drained, then the remnant's
  `stop`. `shekyl_daemon_rpc_stop()` stays as the remnant's own call
  before it destroys the core, a no-op when the owner already stopped
  the RPC, so the path where `run` ends first is safe too. The stop
  sequence runs on the main thread outside the owner's `block_on`: the
  RPC's stop blocks on its own runtime's drain, and a runtime cannot be
  entered from inside another's `block_on`.
- **The managed Tor at steps 6, 8 and 9** (`rust/shekyl-daemon/src/tor.rs`).
  Step 6 spawns `DaemonTorControl::start` on the owner's runtime, so
  discovery and bootstrap overlap the core's construction, and step 8
  awaits it after the RPC rendezvous; nothing blocks the remnant's start
  on a bootstrap. A Tor not found, not usable on this platform, or not
  bootstrapped is today's degrade, one warning and a clearnet-only boot,
  never a start refusal. The zone host's Tor forward listener is bound
  first and the onion published to it, and only then is the onion this
  node's own Tor address. Step 9 calls the remnant's `stop`, which
  returns at once, tears the Tor down, then joins the run thread: the
  parallel teardown. A death between start and stop is logged once from
  a watcher on the owner's runtime (`death_watch`).
- **Every network owner reads its section** (`rust/shekyl-daemon/src/network.rs`).
  Two moments: `record` before the remnant is constructed, for what the
  owners read at their build when the remnant's `init` binds the seam
  (offline, `p2p-local` — which the lists read at their build and refuse
  to change after — the relay's posture and `dev-relay-cover`, the
  descriptors reserved for the inbound ceiling, the link bounds, the ban
  file's entries); `start` at step 8, after the one RPC start, for the
  zone host's listeners and dialers, this node's own addresses and the
  dialer's peers. The seam binds with Rust's own ceiling
  (`inbound_ceiling_ffi::configured`): the C++ `transport_ceiling`,
  `apply_inbound_ceiling` and `descriptor_reservations` go, and with them
  the inbound cap's runtime counters, the `/in_peers` and `/out_peers`
  endpoints, their console words and their request structs, which had no
  backend left. Both C++ zones are built whatever the posture: the zone
  host decides which carries traffic, so no C++ reads the Tor posture.
  The relay's identity is the recorded posture: `shekyl_relay_zone_new`
  takes no mask and no flags, and refuses (null) when nothing is
  recorded; `shekyl_relay_posture_record` is the C++ test harness's way
  to record one. The two reverse pulls the protocol handler's sync
  heuristics read (`shekyl_dialer_out_target`,
  `shekyl_p2p_default_out_peers`) stay until commit (e) decides their
  replacement.
- **SOCKS credentials are refused.** The dial path offers a proxy no
  authentication (`shekyl-clearnet`'s and `shekyl-tor`'s `proxy` is a bare
  endpoint; `shekyl-socks` connects as `Isolation::Principal`), so a
  `clearnet-socks-username`, `clearnet-socks-password`, `tor-socks-username`
  or `tor-socks-password` would be accepted and never sent. The sections
  refuse each given one with `config.value.conflict` naming the fact, until
  the dial carries credentials (FOLLOWUPS: the SOCKS credentials row). Whether
  those four rows should be `reserved` in the grammar is Rick's call; on the
  Tor path a credential would also displace the persona isolation key.
- **The ban file holds hosts and subnets.** The ban table is keyed by IP, so
  an onion line is refused at parse (`config.ban-file.line`) rather than
  read and never applied.
- **The C++ Tor path.** Under the ruling in §0, `add_ephemeral_tor_zone`,
  `check_ephemeral_tor_liveness` and the C++ calls into
  `shekyl_daemon_tor_*` go. The Rust FFI exports `shekyl_daemon_tor_*`
  ([`rust/shekyl-ffi/src/daemon_tor_ffi.rs`](../../rust/shekyl-ffi/src/daemon_tor_ffi.rs))
  and the blocking facade
  ([`rust/shekyl-tor-control-daemon/src/blocking.rs`](../../rust/shekyl-tor-control-daemon/src/blocking.rs))
  then have no caller. [`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) §4.12 asks
  that those deletions go to Rick before they are cut; they are listed in
  commit (e)'s message and removed there only with his word.
- **The runtime rows (commit (d), §2.7, `RPC_CHANNEL.md` §6.4).** The
  options handle
  ([`rust/shekyl-daemon/src/options.rs`](../../rust/shekyl-daemon/src/options.rs))
  holds the resolved map under one lock. A set's build runs `TABLE.live`
  first, the runtime mark second and the constructor last, so a secret or a
  command row is refused as startup-only (`config.runtime.startup-only`)
  and never as a surface fault; a collection's text is split on whitespace,
  the inverse of `Value::render`, so `log-category` takes `p2p=trace
  sync=info` and `none`. The apply is one step per owner: the link budget
  takes both rates in one call (`link_ffi::set_limits`), and the logging
  owner's typed apply (`shekyl_logging::subsystem::apply`) takes the base
  level and the overrides and cannot fail on its input, the subscriber's
  handle held from `init` for the life of the process; it also records the
  directive the C reader `shekyl_log_get_categories` reports. The audit line
  names the admin listener as the caller until RT-W10 names connections.
  `source` on the wire is one of the four words, a file source with no
  path or line (rule 37). The in-process console arm reaches the handle
  through the crate's recorded configure, since it holds the core and not
  the server's state; `print_net_stats` reads the two rate rows of
  `option_show` back through their constructors and prints `no limit` for
  `unlimited`. The link exports `shekyl_link_set_up`, `shekyl_link_set_down`,
  `shekyl_link_get_up` and `shekyl_link_get_down` go with their callers:
  the bounds are set from Rust only. The Python framework gains
  `option_set` and `option_show` in place of its four methods.
  `CORE_RPC_VERSION` is 3.57: the two methods, the JSON-RPC error's `data`
  member under code `-26`, and the four routes gone.
- **`mine start` carries built values (commit (d), §2.7's last bullet).**
  The Rust `/start_mining` handler builds `miner_address` through the
  `mine-address` row and `threads_count` through `mine-threads` (`0` is the
  grammar's `auto`) before the request is dispatched to C++; a refusal is
  the IG-11 text in the REST error envelope with status 400, and the
  address's network check stays the miner's, as at startup. The in-process
  C++ console calls the C++ handler directly and bypasses this until R8
  retires it; a remote console reaches the Rust handler.
- **Development levers exist only on their networks, at every reader
  (IG-8).** `resolve` gave every live row with a default value one,
  including a `dev-` row off its networks, so the effective-configuration
  line and `option_show` on mainnet printed `dev-sync=on (default)`, a
  lever mainnet refuses. A `dev-` row off its networks now has no default
  and is absent from both; `option_show` refuses it by name with
  `config.dev.network`, the startup parse's own refusal.
- **The notify runner (commit (d), §2.10, DC-Q14).** The runner
  ([`rust/shekyl-ffi/src/notify_ffi.rs`](../../rust/shekyl-ffi/src/notify_ffi.rs))
  is installed by the Rust `main()` from the notify section beside the RPC
  configure, before the core exists, and its children run on the signal
  owner's runtime, so they are awaited by the process that spawned them and
  no disposition changes. The C++ event sites push facts and return:
  `shekyl_notify_block(height, hash)` from the main-chain add and from each
  promoted block of a reorganization (the `BlockNotifyCallback` vector,
  `add_block_notify` and the core's `hash_notify` go: the runner is the
  only registrant there was), `shekyl_notify_reorg(first_new, count, added,
  removed)` and `shekyl_notify_block_rate(window_s, observed, expected)`.
  The glossary terms are rendered in Rust from those facts: `{split-height}`
  is `first_new - 1`, the last block both chains share, and `{height}` on a
  reorganization is `count - 1`, the new tip; `{window}` is in seconds where
  the C++ passed minutes. A `{name}` is replaced wherever it appears in an
  argument, the program's path included (IG-Q5: braces are the only
  syntax). The child gets a cleared environment, a null standard input and
  a null standard output and error, so a command's own output never
  interleaves with the daemon's; an operator who wants the output redirects
  it in the command. On Windows the one variable a program needs to start,
  `SystemRoot`, is set from `GetSystemWindowsDirectoryW`
  (`shekyl-win-sec`'s `system_windows_directory`) and never from the
  daemon's environment, the rule the Tor launcher follows
  (`TOR_BUNDLE_DISTRIBUTION.md` TB-7 part 2); no Windows job runs a notify
  command yet, so that line is compiled on the Windows job and not yet
  exercised there. One command per kind is in flight; an event that
  arrives while one runs is dropped, and the completed command's log line
  carries the count. `src/common/notify.{h,cpp}`, `spawn.{h,cpp}`, the
  three `arg_*_notify` descriptors, `m_block_rate_notify`, `m_reorg_notify`
  and `set_reorg_notify`, the `notify` unit test and its `test_notifier`
  helper are deleted; the runner's file joins the FFI signature gate.
- **The remnant reads the snapshot and parses nothing (commit (e1), §2.9,
  §4.2).** `core::init`, `miner::init`, `node_server::init` and `Daemon`
  take the eleven-field snapshot; the protocol handler's `init()` takes
  nothing; `run(snapshot)` has no argument vector. Lane-owned knobs the
  grammar does not port (`INPUT_GRAMMAR.md` §5, IG-Q4) are today's
  defaults as named constants beside their readers, each comment naming
  its lane. The fakechain wipe on start is off (§2.6, R3); its arm goes
  with the other regtest arms in (e2). The `show-time-stats` lever's
  timing prints are debug-level log lines, selected by `log-level` and
  `log-category` as every other diagnostic is. The C++ test binaries
  construct the remnant from a snapshot the real parse builds
  (`shekyl_daemon_snapshot_parse`, `shekyl_daemon_snapshot_free`, in
  `shekyl-daemon`'s entry, rule 26 B2): `core_tests` links the daemon
  image for it, as `unit_tests` does; `node_server.cpp`'s non-offline
  fixture records the relay's posture itself, as `levin.cpp`'s does, so
  it no longer depends on an earlier test having recorded one. The
  blockchain utilities keep `testnet`, `stagenet`, `regtest` and
  `data-dir` in `src/blockchain_utilities/daemon_network_args.h` until
  the grammar's Part B rules each tool (§9, §10). `/start_mining` loses
  `do_background_mining` and `ignore_battery` with the background-mining
  options (a 3.57 change, recorded in its note); the miner's own
  background thread stays, the mining lane's (§10).
- **The regtest arms, the environment levers and the reverse pulls (commit
  (e2), §2.6, §4.2).** The `/fake` subdirectory, the wipe on start and
  `check_block_rate`'s FAKECHAIN skip are gone: the network selects the
  default data subdirectory in the Rust configuration and FAKECHAIN
  conforms to production (a regtest store is now `<data-dir>/lmdb`; the
  Windows smoke's path follows). `Blockchain::init` loses its `offline`
  parameter and the member nothing read. The schedule levers reach their
  owners from the `dev-` rows, recorded by the Rust `main()` at step 6
  before the core whose first epoch arithmetic latches them exists:
  `pow_randomx_ffi::record_seed_epoch` (a value off the power-of-two
  schedule is the row's `config.value.range` refusal, where the C clamps
  silently substituted the mainnet value) and
  `archival_ffi::arm_settlement_schedule` through a typed
  `arm_settlement_epoch_override(blocks, reorg_cap)`. The daemon reads no
  environment: `legacy.rs` is gone, the chain's two environment gates with
  it (a lever off its networks is refused by the row's network rule, IG-8),
  and the exports `shekyl_archival_settlement_epoch_override_present` and
  `shekyl_archival_settlement_epoch_arm_regtest` with their four codes.
  The retention crate's environment-reading arm stays for the wallet engine
  and its regtest harness, which are the engine lane's (FOLLOWUPS: the
  wallet engine's settlement lever). `SHEKYL_TOR_BINARY` is gone from the
  Tor binary discovery: `tor-file` names a binary (IG-Q41), nothing is read
  from the environment, and the full-bundle refusal test names a file
  instead. The reverse pulls `shekyl_dialer_out_target`,
  `shekyl_p2p_default_out_peers` and
  `shekyl_relay_zone_min_provisioned_out_peers` are gone with the protocol
  handler's copy of the target (`m_max_out_peers`, `set_max_out_peers`,
  `get_max_out_peers`): the two sync heuristics that compared counts
  against it hand their counts to `shekyl_sync_room_for_syncing_peer` and
  `shekyl_sync_wants_more_outbound` (`shekyl-ffi/src/sync_ffi.rs`, a gate
  surface), which read the dialer's target at use time. `m_require_ipv4`,
  the data-directory port suffix and `RPC_LOGIN` were already zero at
  (c2).
- **The launchers and harnesses speak the grammar (commit (f1), §5.1).**
  Every launcher the brief's §5.1 table names is re-spelled in the
  grammar's words and no other: the packaged unit and the fleet units
  name `--network` and `--config-file` and the fleet generator writes a
  TOML file per node; the regtest harnesses (`regtest_e2e.rs`, the levin
  live tests, the wire and curve-tree capture scripts, the WSS edge
  script, the CLI daemon-session test) spawn `shekyld --network regtest`
  with both connectors off for the offline posture, `--clearnet-listen`
  and `--p2p-closed-peer` for a linked pair, `--dev-sync off` for a sink,
  `--rpc-view-listen` for the second listener, `--console` when a test
  drives the in-process arm (nothing reads stdin otherwise, so no FIFO is
  held open), and the schedule pair as `--dev-settlement-epoch-blocks`
  and `--dev-archival-reorg-depth` on the command line, not the child's
  environment (the daemon reads none, so there is nothing to scrub). Every
  test daemon passes `--tor off`: regtest's default is the managed Tor,
  and a test daemon launching one is a hang on a machine without a Tor
  binary; the second measurement rig's Tor-off setting is Rick's to name
  (§5.1), this one is recorded here. The BA-T5 sync daemons take
  `--clearnet-listen none` for no inbound and `--p2p-closed-peer` for
  their one peer. The DRS bench cannot keep DRS-D9's `safe` durability:
  the daemon takes no sync-mode row (IG-Q4, the DRS lane's) and runs the
  lane's constant, and the artifact gate refuses a record whose daemon did
  not run `safe`; the bench is re-spelled and refuses before any daemon
  starts, naming the FOLLOWUPS row, rather than record a durability it did
  not impose. `contrib/tor/shekyl-over-tor.sh` is deleted (DC-F8). The
  wallet CLI's daemon-down hint names `shekyld --network testnet`. Not
  run here: the fleet launcher (it addresses the Foundation's hosts) and
  the BA-T5 sessions (they measure on a testnet peer).
- **A test for every §6 row.** Commit (a) carries a table from each §6 row
  to its test. A row that only Windows can exercise names where it runs:
  the Windows CI job, or the Windows seat by hand. A `cfg(windows)` test
  that no job runs is not counted as coverage.

## 8. The §6 rows and their tests (commit (a))

Every row of the brief's §6 that commit (a) can refuse has a test that
refuses it with its code, named here. A row only Windows can exercise names
where it runs; a `cfg(windows)` test no job runs is not counted. The rows an
owner refuses at its own start, and the runtime rows, are commits (c) and
(d)'s.

| §6 row | Test |
| --- | --- |
| a named config file is missing | `shekyl-daemon-config` `file::tests::a_missing_default_file_is_the_defaults_and_a_missing_named_file_refuses` |
| the file cannot be opened or read | `file::tests::a_file_that_cannot_be_opened_is_unreadable` |
| the file, or a directory above it, can be written outside the allowlist | Unix: `file::tests::a_writable_file_or_directory_is_refused_naming_the_place_and_the_principal` (the rule on described trees), `file::tests::a_world_writable_file_is_refused_at_the_file_itself` (a real file). Windows: the DACL walk in `shekyl-win-sec::dacl`, run by the Windows job's cutover case (§5.2 of the brief, a directory granting Users write) |
| the file holds a secret and can be read outside the allowlist | `file::tests::a_secret_is_readable_only_by_owner_and_root`; Windows as above |
| a symbolic link whose target fails either check | `file::tests::a_symbolic_link_is_judged_by_its_target` |
| the file is not valid TOML | `shekyl-options` `input::tests::invalid_toml_and_a_repeated_key_name_their_line` |
| an unknown name, on either surface | `shekyl-options` `table::tests::a_misspelled_name_is_refused_with_the_nearest_public_name`, `input::tests::an_unknown_key_in_the_file_offers_the_nearest_name_with_its_line` |
| a REJECTED or RESERVED name | `shekyl-options` `table::tests::rejected_and_reserved_names_are_refused_with_their_reasons` |
| a value its kind refuses | `shekyl-options` `kind::tests`: quantities and units, integers, endpoints, origins (`*`), commands, `a_path_is_absolute_only`; `input::tests::a_non_utf8_argument_is_refused_by_position` |
| a value on a surface its row forbids | `shekyl-options` `input::tests::a_missing_value_and_a_file_only_secret_on_the_cli_are_refused`, `input::tests::a_file_value_carries_its_line_and_cli_only_rows_are_refused_there` |
| a `dev-` option on a network its row does not name | `resolve::tests::a_development_lever_is_refused_off_its_networks_and_always_on_mainnet` |
| no account home and no explicit paths | `sections::tests::no_home_refuses_each_path_that_needs_it_and_not_an_explicit_one`, `paths::tests::the_root_is_the_account_home_and_no_home_refuses` |
| the data directory cannot be created, or is not a directory | `lock::tests::a_data_directory_that_is_a_file_is_unusable` |
| the data directory is locked by another daemon | Unix: `lock::tests::the_lock_is_taken_once_and_refused_to_a_second_holder`. Windows: the job's second-daemon case (brief §5.2) |
| the marker names another network | `marker::tests::another_network_refuses_naming_both_and_the_fix` |
| the marker names this network with a different network id | `marker::tests::the_same_network_with_another_id_is_a_regenesis_refusal` |
| a daemon store with no marker | `marker::tests::a_store_with_no_marker_is_never_marked_after_the_fact` |
| the log location cannot be written | `sections::tests::the_log_location_is_created_or_refused` |
| the ban file cannot be read, or a line does not parse | `sections::tests::the_ban_file_is_read_at_parse_and_a_bad_line_is_named` |
| a listener cannot bind | RPC: `shekyl-daemon-rpc` `bind::tests::wildcard_binds_are_refused`, `bind::tests::network_binds_are_refused`, `bind::tests::the_seam_refuses_before_binding` (the refusals); a bound socket in use is `bind_listener`'s error, logged by `shekyl_daemon_rpc_start`, which returns -1 and the remnant's `run` 1; `shekyl-daemon` `run::tests::a_stop_request_from_the_remnant_runs_the_one_stop_path` covers the wait that start completes. The zone host: `shekyl-ffi` `zone_ffi::tests::a_clearnet_endpoint_already_bound_is_refused_with_its_address` (the refusal names the endpoint; `network::start` logs it and the daemon stops with 1) |
| a runtime change its constructor refuses; a set for a row not marked runtime | `shekyl-daemon` `options::tests::refusals_carry_their_codes_and_nothing_applies_beside_one` (startup-only, unknown, rejected and a syntax refusal in one request, nothing applied); the RT-O25 property `options::tests::every_runtime_row_round_trips_its_shown_text_through_set`; the logging owner's apply, `shekyl-logging` `tests/runtime_reload.rs`; the RPC's framing, `shekyl-daemon-rpc` `options::tests::a_refused_pair_refuses_the_whole_set_and_reports_every_refusal` and `handlers::json_rpc::tests::restricted_method_list_matches_the_specification` |
| `service` outside the SCM, on Linux, FreeBSD or macOS, or with a bad root | `service` is a reserved row until RT-W14, refused by `table::tests::rejected_and_reserved_names_are_refused_with_their_reasons`; the missing root by `paths::tests::the_service_root_is_program_data_or_a_refusal`; the three cases are RT-W14's to test when the row goes live |

Cross-row refusals the types make (`INPUT_GRAMMAR.md` §4), beyond §6:
`sections::tests::an_operator_tor_needs_its_socks_and_an_onion_needs_its_listener`,
`a_connector_that_is_off_cannot_carry_its_endpoints_or_its_peers`,
`socks_credentials_need_each_other_and_their_endpoint`,
`advertise_takes_one_endpoint_per_family`,
`a_mining_address_is_checked_against_the_network`,
`positional_words_make_a_client_that_needs_an_admin_endpoint`.
