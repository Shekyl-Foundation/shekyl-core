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
fields. The brief's eleven fields are all present, and one more reader
exists: the handshake builds the node's announced clearnet address from
`m_external_port`
([`src/p2p/net_node.inl:429`](../../src/p2p/net_node.inl), used at
[`:1930`](../../src/p2p/net_node.inl)). That is the C++ reader of the
advertised address the brief anticipates, so **the snapshot has twelve
fields**: the twelfth is the advertised clearnet port, from
`clearnet-advertise`, absent when none is advertised. It goes when the
handshake's address moves to Rust.

## 3. The daemon-store set (§9 item 3)

At the pin a daemon store is the LMDB environment, `lmdb/data.mdb` under the
data directory
([`src/cryptonote_config.h:215`](../../src/cryptonote_config.h),
[`src/blockchain_db/lmdb/db_lmdb.cpp:2016`](../../src/blockchain_db/lmdb/db_lmdb.cpp)),
and `p2pstate.bin`
([`src/cryptonote_config.h:217`](../../src/cryptonote_config.h)), which PR-3
made the Rust dialer's address file under the same name
([`src/p2p/net_node.inl:139`](../../src/p2p/net_node.inl)). The marker
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
([`src/common/spawn.cpp:124`](../../src/common/spawn.cpp)) and spawns a
second. On Linux at the pin the second `wait()` returns at once with
`ECHILD` ("No child processes"): the kernel reaped the child itself. The
managed Tor's reaper reads that error as a wedge, so
`TorChild::shutdown` publishes `TorExit::Killed` for a Tor that exited
cleanly
([`rust/shekyl-tor-control-client/src/control/actor.rs:616`](../../rust/shekyl-tor-control-client/src/control/actor.rs)).
The test reproduces the syscall, not the C++ path, because a Rust test
cannot link `tools::spawn` and the defect is the disposition, whoever sets
it. It is a binary of its own because a disposition is process-wide.
Commit (d) adds the positive twin: the Rust runner's children are reaped
and a tokio child's `wait()` still returns its status.

## 7. Decisions the implementation takes inside the brief

- **Where the entry lives.** The start and stop logic is a new safe crate,
  `shekyl-daemon`, over `shekyl-daemon-config`, `shekyl-daemon-rpc`,
  `shekyl-ffi`'s Rust surface and `shekyl-tor-control-daemon`. Its one C
  ABI symbol, `shekyl_daemon_main`, is exported by `shekyl-daemon-image`,
  the composition root §2.1 names: `shekyl-ffi` cannot export it without
  depending on `shekyl-daemon-rpc`, which depends on neither. The remnant's
  pair, defined in C++, is declared and wrapped in `shekyl-ffi` and
  declared for C++ in `src/shekyl/shekyl_ffi.h`, so the signature gate
  covers it.
- **The daemon at each intermediate commit.** From commit (b) Rust owns
  `argv` and parses it with the grammar. Until commit (e) deletes the last
  C++ reader, C++ still reads options through `boost::program_options`, so
  every commit is a working daemon: Rust renders the parsed configuration
  into today's spellings, and the remnant's `run` parses that rendering as
  `main.cpp` parses `argv` today. The renderer is one Rust module, deleted
  in commit (e) with the readers; the snapshot gate counts the twelve
  fields, not the rendering.
- **The managed Tor at steps 6, 8 and 9.** Step 6 starts
  `DaemonTorControl::start` on its own thread, so bootstrap overlaps the
  core's construction; it is awaited before step 8. The zone host then
  gets the SOCKS address, or, if bootstrap failed, today's degrade: the
  Tor posture is unavailable for this boot and the posture line says so.
  The onion is published after step 8, because it forwards to the zone
  host's loopback listener. Step 9 runs the teardown in parallel with the
  remnant's stop. A death between start and stop is logged once, as
  today.
- **The C++ Tor path.** Under the ruling in §0, `add_ephemeral_tor_zone`,
  `check_ephemeral_tor_liveness` and the C++ calls into
  `shekyl_daemon_tor_*` go. The Rust FFI exports `shekyl_daemon_tor_*`
  ([`rust/shekyl-ffi/src/daemon_tor_ffi.rs`](../../rust/shekyl-ffi/src/daemon_tor_ffi.rs))
  and the blocking facade
  ([`rust/shekyl-tor-control-daemon/src/blocking.rs`](../../rust/shekyl-tor-control-daemon/src/blocking.rs))
  then have no caller. [`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) §4.12 asks
  that those deletions go to Rick before they are cut; they are listed in
  commit (e)'s message and removed there only with his word.
- **A test for every §6 row.** Commit (a) carries a table from each §6 row
  to its test. A row that only Windows can exercise names where it runs:
  the Windows CI job, or the Windows seat by hand. A `cfg(windows)` test
  that no job runs is not counted as coverage.
