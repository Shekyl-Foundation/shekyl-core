# Daemon configuration cutover — the option surface moves to Rust

**Status: OPEN — DRAFT, held (Round 0 ruled 2026-10-13; not landed).**
Rule 26 is cited. This brief is held as one draft until the input-grammar
round (IG) rules its Part A; option spellings, value kinds, the option-table
schema, the parser, the diagnostic renderer and the exit-code rule belong to
that round and are **not** written here. Names fold in when IG rules. No
implementation starts until PR-3 (#1056) has merged and IG Part A is ruled.
No amendments to this draft before then.

Anchors pinned to `dev` `737da31276` (2026-10-13, the tip this draft is
based on). The read-out that fed Round 0 was taken at `435e83e166` the same
day; every file cited here was re-checked at `737da31276`. PR-3 citations
are branch citations at `baaba2bddd` (`feat/p2p3-dialer-cutover`, 139
commits ahead of `dev`, re-pinned from `a07a64e9a2` the same day) and are written without a leading `src/` or `rust/`
so the pinned-anchor gate does not resolve them against `dev`.

**The IG source of record was not reachable at this pin.** Rick's rulings
name it as `claude/INPUT_GRAMMAR_ROUND0.md`; no file of that name exists in
`shekyl-core`, `shekyl-dev`, or any remote branch at `737da31276`. The
option table in §3 therefore carries today's C++ name and `file:line` as the
records-was anchor and an **IG row** column that reads `pending IG Part A`
on every row. A grounded review of the IG Part A draft was produced by this
lane the same day and sits in its working notes outside the repository; the
draft's proposed spellings are deliberately not copied here. When the IG table lands, each row's spelling and kind are
copied in mechanically; nothing else in this brief changes.

Identifier families minted here (registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 in this change):
**DC-Q1…DC-Q12** (the twelve questions and their rulings), **DC-F1…DC-F9**
(findings established at source), **DC-N1…DC-N4** (new items Rick added
to the brief). Crate names are pending IG-Q13.

---

## 1. Rulings of record (DC-Q1…DC-Q12, Rick, 2026-10-13)

| Id | Question | Ruling | Where it lands |
| --- | --- | --- | --- |
| DC-Q1 | Who owns parsing, the file, defaults, validation, help | **Rust reads every option directly.** Every Rust consumer takes its section of the typed configuration at construction. Every C++→Rust configuration push, PR-3's four included, and every configuration parameter on a Rust start function is deleted **in the cutover**, not consumer by consumer. A Rust-owned read-only snapshot exists only for the C++ that still consumes values (core, miner, the C++ remnant of `net_node`, the protocol handler) and only shrinks. No C++ parses or relays configuration. Crate names pending IG-Q13 | §2.1, §2.3, §4 |
| DC-Q2 | Parse order | The first call after `tools::on_startup` is the Rust parse; nothing is constructed before it returns *run*. The refusal format and the exit-code rule are IG-11's. The ban file is read in Rust at parse | §2.2 |
| DC-Q3 | Config file | TOML. No environment layer anywhere (the four env levers become regtest-only development options, IG-8). A command-line list replaces the file's whole list. **Auto-load reversed:** the daemon loads a system-path file selected by the network at startup; `--network` is command-line only and a network key in the file is refused; `--config-file` replaces that path whole; a missing file is the defaults, stated in the startup line; the file is validated whole before anything applies; the daemon refuses to start if the file or any parent directory is writable, or when it holds secrets readable, by anyone but root or the daemon's account; on Windows the installer creates the directory with a restrictive ACL and the daemon refuses a permissive one. One startup line logs every effective value and its source, secrets redacted. The daemon never writes its config file | §2.4, §6 |
| DC-Q4 | Retired flags | **Reversed: no backward compatibility pre-genesis.** No retired-flag table; `removed_flags.{h,cpp}` is deleted, not ported. Our own scripts are fixed in the same PR. Deliberately refused features keep a REJECTED entry with a reason (rule 23, IG-10). An unknown name gets a nearest-name suggestion from the table | §4, §8 |
| DC-Q5 | Network type | One `--network` option. The data-directory network subdirectory is kept as row data until a genesis-at-open check exists (DC-F1, routed to the chain-store lane). **Reversed on the two booleans:** the regtest Tor skip and the regtest database wipe are deleted, not made row data; `--keep-fakechain` goes; the inbound-cost bench gains the flag that declines Tor. FAKECHAIN conforms to production. `check_block_rate`'s regtest skip is its own row | §2.6, §4, §5 |
| DC-Q6 | Validation as types | **UPnP deleted entirely** (both flags, the code, the vendored miniupnpc). `--out-peers` retired: the outbound degree is a protocol constant owned by the relay-privacy params; the `out_peers` RPC and console command go. Deleted: `--tos-flag`, `--p2p-ignore-ipv4`, `--rpc-response-soft-limit`, `--disable-rpc-ban` (the RPC server's `add_host_fail` has no caller), `--rpc-max-connections-per-public-ip`, `--seed-node`, the `,N` suffixes, `--test-drop-download`, `--test-drop-download-height`, `--test-dbg-lock-sleep`, `--show-time-stats`, the `--bg-mining-*` five. Sync, LMDB, alt-block and padding knobs are lane-owned, pending IG-Q4. Runtime changes use the same constructor and refusals as startup (IG-12); this slice implements it | §2.7, §4 |
| DC-Q7 | Secrets and paths | SOCKS credentials are typed secrets: zeroized, redacted, held only in Rust, accepted **only** from the permission-checked config file (never argv: `/proc/<pid>/cmdline` is world-readable), plumbed to the dialer. A missing `HOME` refuses. One Windows default-directory rule. No systemd environment reads | §2.5 |
| DC-Q8 | Deployment | Delete `utils/conf/shekyld.conf`. The shipped unit, the fleet templates and generator, the harnesses, the GUI sidecar argv (`shekyl-gui-wallet`, cross-repo) and the Foundation configurations in `shekyl-dev` change in step with the cutover (rule 37: roles, not hosts). Recipe gate: yes | §5 |
| DC-Q9 | Docs | Generate and gate (IG-9) | §5.3 |
| DC-Q10 | Clearnet public host | **(a)** an operator-configured public address. (c) died with UPnP. (b) rejected with the reopening criteria in §8 | §2.8, §8 |
| DC-Q11 | Deletion table | Extended with everything above, plus miniupnpc and its CMake wiring; `removed_flags.{h,cpp}` and their tests; `Blockchain::m_offline` (read by nothing); the `daemon_default_data_dir` split; the data-directory port suffix | §4 |
| DC-Q12 | Sequencing | Based on PR-3 after it merges; **one cutover** for the parse surface and every Rust consumer. Blockchain utilities: keep or delete per tool is decided in IG Part B; until then they keep their own C++ option sets and the shared descriptors are re-homed to them | §9 |

New items (Rick, 2026-10-13): **DC-N1** the data-directory lock (IG draft
F2); **DC-N2** the console moves to `shekyl-cli` (R8); **DC-N3** the full
launcher census; **DC-N4** the effective-configuration line and the IG-11
renderer as the operator surface, with rule-82 failure modes. Each has a
section below.

---

## 2. The mechanism

### 2.1 Ownership (DC-Q1)

One Rust crate (name pending IG-Q13) owns the daemon's option table, the
parse of the command line and the TOML file, the defaults, validation into
a typed configuration of per-subsystem sections, help text, and the
generator the documentation gate reads (IG-9). The kinds of its rows are
IG's. The crate depends on the leaf crates that own constants it validates
against (the relay-privacy params for the outbound degree, the peer-policy
crate for the inbound ceiling) and never on a subsystem.

Every Rust consumer takes its section at construction from the composition
root. The daemon's composition root already exists:
[`rust/shekyl-daemon-image/src/lib.rs:30-36`](../../rust/shekyl-daemon-image/src/lib.rs)
names itself so for the archival fetch scheduler. The parse result is held
in Rust for the life of the process. Nothing crosses the FFI as a
configuration value in either direction except the read-only snapshot of
§2.3.

**What each Rust start function loses at the cutover.** Today's
configuration pushes, all deleted:

| Entry on `dev` | Parameters that are configuration today | After the cutover |
| --- | --- | --- |
| `shekyl_daemon_rpc_start` ([`rust/shekyl-daemon-rpc/src/ffi_exports.rs:78-88`](../../rust/shekyl-daemon-rpc/src/ffi_exports.rs); called at [`src/daemon/daemon.cpp:300-308`](../../src/daemon/daemon.cpp)) | bind host, port, v6 host, restricted, CORS list, three connection caps | keeps the core pointer and the start/stop lifecycle; reads the RPC section of the Rust-held configuration; which listener it is (admin or restricted) is a parameter of the lifecycle, not a value |
| `shekyl_zone_listen_clearnet` ([`rust/shekyl-ffi/src/zone_ffi.rs:415-427`](../../rust/shekyl-ffi/src/zone_ffi.rs); [`src/p2p/zone_server.h:315-319`](../../src/p2p/zone_server.h)) | four bind values, the IPv6 enable, the SOCKS host and port of `--proxy`, the encrypt flag | keeps the network id, the spans and the ceiling (constants and runtime state); reads the P2P section |
| `shekyl_zone_listen_tor`, `shekyl_zone_set_tor_proxy` ([`rust/shekyl-ffi/src/zone_ffi.rs:550`](../../rust/shekyl-ffi/src/zone_ffi.rs), [`:638`](../../rust/shekyl-ffi/src/zone_ffi.rs); [`src/p2p/zone_server.h:345-348`](../../src/p2p/zone_server.h), [`:369`](../../src/p2p/zone_server.h)) | SOCKS host and port, the operator inbound bind | read the Tor posture section (proxy, credentials, operator onions) |
| `shekyl_zone_set_connector_cap`, `shekyl_zone_clear_connector_cap` ([`src/p2p/net_node.inl:3020-3060`](../../src/p2p/net_node.inl)) | the inbound cap per connector | the cap is read from the P2P section by the zone host; the descriptor-reservation arithmetic in `descriptor_reservations` ([`src/p2p/net_node.inl:2991-3017`](../../src/p2p/net_node.inl)) moves to Rust with it, because its only inputs are configuration (the outbound degree, now a constant; the inbound caps) and a runtime count Rust already holds (`shekyl_seam_inbound_held`) |
| `shekyl_link_set_up`, `shekyl_link_set_down` ([`rust/shekyl-ffi/src/link_ffi.rs:36`](../../rust/shekyl-ffi/src/link_ffi.rs), [`:42`](../../rust/shekyl-ffi/src/link_ffi.rs); [`src/p2p/net_node.inl:3275`](../../src/p2p/net_node.inl), [`:3292`](../../src/p2p/net_node.inl)) | the three rate limits | the link reads the P2P section at construction; the runtime `set_limit` path is §2.7 |
| `shekyl_log_init_file` ([`rust/shekyl-logging/src/ffi.rs:242-250`](../../rust/shekyl-logging/src/ffi.rs); [`contrib/epee/src/mlog.cpp:215-221`](../../contrib/epee/src/mlog.cpp)), `shekyl_log_set_level`, `shekyl_log_set_categories` ([`contrib/epee/src/mlog.cpp:306`](../../contrib/epee/src/mlog.cpp), [`:338`](../../contrib/epee/src/mlog.cpp)) | directory, prefix, rotation size, rotation count, level, categories | logging is initialised in Rust from the logging section before the parse returns; `mlog_configure` shrinks to installing the tracing forwarder ([`src/daemon/main.cpp:292-298`](../../src/daemon/main.cpp)); `mlog_set_log` at startup goes. The runtime `set_log_level` path is §2.7 |
| `shekyl_daemon_tor_start` ([`rust/shekyl-ffi/src/daemon_tor_ffi.rs:142-150`](../../rust/shekyl-ffi/src/daemon_tor_ffi.rs); [`src/p2p/net_node.inl:896-898`](../../src/p2p/net_node.inl)) | the data directory as the tor data-directory parent | reads the paths section |
| `shekyl_relay_zone_new` flags ([`src/cryptonote_protocol/levin_notify.cpp:297-301`](../../src/cryptonote_protocol/levin_notify.cpp)) | the carrier development switch, via a process-wide global set at [`src/daemon/main.cpp:329-331`](../../src/daemon/main.cpp) | the relay reads the development section; the global and its setter go |
| PR-3's four: `shekyl_dialer_set_out_peers` (`dialer_ffi.rs:310` at `baaba2bddd`; called from `net_node.inl:1706`, `:1883`, `:1898`), `shekyl_peerlist_allow_local_ip` (`peerlist_ffi.rs:67`), `shekyl_peerlist_set_own_address` (`dialer_ffi.rs:504`) via `note_own_address` (`zone_server.h:227-231`, `net_node.inl:660`), `shekyl_peerlist_admit_operator` (`dialer_ffi.rs:423`) | the outbound cap, the local-address override, the operator onion, the operator peers | the dialer and the peer lists read the P2P section at construction; `--out-peers` is retired (DC-Q6), so the first entry has no value left to carry |

The reverse pulls, `shekyl_p2p_default_out_peers` and
`shekyl_relay_zone_min_provisioned_out_peers`
([`rust/shekyl-ffi/src/relay_zone_ffi/mod.rs:1133`](../../rust/shekyl-ffi/src/relay_zone_ffi/mod.rs),
[`:1148`](../../rust/shekyl-ffi/src/relay_zone_ffi/mod.rs)), lose their
C++ callers with `set_max_out_peers` and the `,N` parser and go with them.

### 2.2 The start sequence (DC-Q2)

1. `tools::on_startup`, `prctl(PR_SET_DUMPABLE, 0)` as today
   ([`src/daemon/main.cpp:79-85`](../../src/daemon/main.cpp)).
2. **The Rust parse.** Rust reads the process arguments itself
   (`std::env::args_os`, not the C++ `argv`: on Windows the C++ `main`
   receives a narrowed command line and Rust reads the native one). It
   resolves `--network` and `--config-file`, performs the permission check
   of §2.4 on the file, reads and validates the file whole, applies the
   command line over it, resolves every path to an absolute path, reads the
   ban file, constructs the typed sections, and either returns *run* or
   prints the IG-11 diagnostic and returns an exit. `--help`, `--version`
   and `--os-version` are answered here. Nothing below runs on an exit.
3. **The data-directory lock (DC-N1).** Rust takes an exclusive lock on the
   resolved data directory before anything else touches it. There is no
   lock today: `tools::file_locker`
   ([`src/common/util.h:101-105`](../../src/common/util.h), defined at
   [`src/common/util.cpp:269-330`](../../src/common/util.cpp)) has no caller
   in `src/` or `tests/`. The lock is held for the life of the process; a
   held lock is a refusal naming the directory and that another daemon holds
   it (§6). The workspace already carries `fd-lock` 4.0.4 (used by
   `shekyl-engine-file`); rule 17 verification at implementation.
4. **Logging** is initialised in Rust from the logging section.
5. **The effective-configuration line (DC-N4)** is emitted: every option,
   its effective value, its source (command line, file, default), the file
   path or "no file: defaults", secrets redacted (§2.5).
6. The parse returns *run*. C++ constructs core from the snapshot (§2.3),
   then the protocol handler, then the C++ remnant of `net_node`; the Rust
   zone host, the dialer, the relay and the RPC listeners start on their
   existing lifecycle calls and read their own sections. The console-command
   branch ([`src/daemon/main.cpp:343-392`](../../src/daemon/main.cpp)) stays
   in C++ until DC-N2 and reads the snapshot.

### 2.3 The C++ snapshot (DC-Q1)

One read-only structure, filled once by one call after the parse returns,
holding exactly the values whose surviving reader is C++. Derived from the
§3 consumer column, the initial field list is:

core: `data-dir`, `network`, `fixed-difficulty`, `prep-blocks-threads`,
`block-sync-size`, `offline`, `block-download-max-size`, `span-limit`,
`max-txpool-weight`, `block-notify`, `reorg-notify`, `block-rate-notify`,
`keep-alt-blocks`, `db-sync-mode`, `db-salvage`, `max-concurrency`;
miner: `start-mining`, `mining-threads`; the `net_node` remnant:
`p2p-external-port` (read at the own-address test and the port-only advert,
[`src/p2p/net_node.inl:1553`](../../src/p2p/net_node.inl),
[`:2486`](../../src/p2p/net_node.inl)), `pad-transactions`
([`:1207`](../../src/p2p/net_node.inl)), `add-exclusive-node`,
`no-sync`, the console's RPC bind pair; the protocol handler:
`block-download-max-size`, `span-limit`.

**Twenty-four fields at the cutover.** A gate pins the count and fails when
it rises; every later slice that moves a consumer deletes its field. The
listed names are today's C++ names; the snapshot carries IG's.

### 2.4 The config file (DC-Q3)

- **Format:** TOML. One file. Tables match the sections. Key spellings are
  IG's.
- **Location:** a system path selected by the network, pending IG for the
  exact spelling; Rick's ruling names `/etc/shekyl/shekyld-<network>.toml`
  and `%ProgramData%\shekyl\…` on Windows. `--network` is command-line
  only; a network key inside the file is refused (the file was chosen by
  the network, so a key that disagrees is a contradiction, not an override).
  `--config-file` replaces the path whole. A missing file at the selected
  path is the defaults, and the startup line says so. The daemon never
  writes the file.
- **Precedence:** command line over file over defaults. No environment
  layer. A list given on the command line replaces the file's whole list.
- **Validation order:** the file is read and validated whole before
  anything applies. A refusal names the key, the line, and the fix (IG-11).
- **Permission check, in this order:** (1) open the file and check the
  opened descriptor, not the path, so a symlink to a writable target is
  judged by its target; (2) refuse if the file or any parent directory is
  writable by anyone but root or the daemon's account; (3) read and parse
  whole; (4) if the parsed file holds a secret (§2.5), refuse if it is
  readable by anyone but root or the daemon's account; (5) apply. On
  Windows the installer creates the directory with a restrictive ACL and the
  daemon refuses a DACL granting write to Users or Everyone.
- **Interaction with RT-16:** a daemon run as the logged-in user that finds
  a root-owned system file selecting a system data directory is RT-16's
  case (service mode; [`RPC_CHANNEL.md`](RPC_CHANNEL.md), RT-16). This
  slice applies the file as found and does not decide which account should
  own it; the refusal set above is the same in both run modes.

### 2.5 Secrets and paths (DC-Q7)

The only credential-bearing options today are `--proxy`
([`src/daemon/command_line_args.h:97`](../../src/daemon/command_line_args.h))
and `--tx-proxy` ([`src/p2p/net_node.cpp:129`](../../src/p2p/net_node.cpp)),
whose `socks5://user:pass@` form is parsed into `userinfo` at
[`src/net/parse.cpp:267-296`](../../src/net/parse.cpp) and dropped before
Rust: the zone entries take host and port only (DC-F3).
`rust/shekyl-socks` already speaks RFC 1929 username/password
([`rust/shekyl-socks/src/lib.rs:6-36`](../../rust/shekyl-socks/src/lib.rs))
with a redacting, wiping username type.

- SOCKS credentials are typed secrets: zeroized on drop, redacted in every
  rendering, held in Rust only, absent from the snapshot, handed to the
  dialer with the proxy endpoint.
- They are accepted **only** from the config file. A credential on the
  command line is a refusal naming the reason (`/proc/<pid>/cmdline` is
  world-readable). A file holding one triggers step (4) of §2.4.
- The socks4 and socks4a schemes are refused at parse: the Rust client is
  SOCKS5.
- Paths: the data directory, the log file, the config file. Resolved
  absolute at parse. A missing `HOME` is a refusal, not `/.shekyl`
  ([`src/common/util.cpp:645-649`](../../src/common/util.cpp) today). One
  Windows rule: the admin-membership split in `daemon_default_data_dir`
  ([`src/common/daemon_default_data_dir.cpp:79-98`](../../src/common/daemon_default_data_dir.cpp))
  is deleted; RT-16 decides the machine-wide home for service mode. The
  daemon does not read `STATE_DIRECTORY` or `LOGS_DIRECTORY`; the shipped
  unit passes explicit flags.
- The network subdirectory under the data directory stays (DC-Q5), applied
  from the network params row, until DC-F1 lands.

### 2.6 The network (DC-Q5)

One option, `--network`, command-line only. The network selects one params
row: the p2p and RPC ports, the data subdirectory, the log file name, the
seed list, the network id. Every network-dependent default derives from
that row by one function; the config file's path is selected by it. The
three boolean flags of today
([`src/cryptonote_core/cryptonote_core.cpp:74-88`](../../src/cryptonote_core/cryptonote_core.cpp))
are deleted, not retired.

FAKECHAIN conforms to production. Deleted outright: the managed-Tor skip
([`src/p2p/net_node.inl:684`](../../src/p2p/net_node.inl),
[`:854`](../../src/p2p/net_node.inl)); the database wipe on start and
`--keep-fakechain`
([`src/cryptonote_core/cryptonote_core.cpp:516-524`](../../src/cryptonote_core/cryptonote_core.cpp));
the `check_block_rate` skip
([`src/cryptonote_core/cryptonote_core.cpp:1621`](../../src/cryptonote_core/cryptonote_core.cpp)).
The last one is not harmless: on a regtest chain mined at fixed
difficulty 1 the stall detector's windows (`:1649-1654`) will fire the
warning and `block-rate-notify` whenever a harness pauses mining; the
harnesses in §5 that pass `block-rate-notify` are none today, and the
warning is a log line, so the row's consequence is log noise in harness
output, recorded here so it is not read as a regression.

### 2.7 Validation and runtime changes (DC-Q6, IG-12)

The constructor of a value owns its invariants; the subsystem owns
constraints on runtime state. The inbound cap against the descriptor
ceiling and a bind's success are the subsystem's; everything that can be
decided from the value alone is the constructor's. The four runtime
handlers, `/set_limit`, `/in_peers`, `/set_log_level`, `/start_mining`
([`rust/shekyl-daemon-rpc/src/server.rs:289-349`](../../rust/shekyl-daemon-rpc/src/server.rs))
and their console twins
([`src/daemon/command_server.cpp:116-119`](../../src/daemon/command_server.cpp),
[`:217-219`](../../src/daemon/command_server.cpp)), construct the same
typed value through the same constructor as the startup parse and return
the same refusal; the C++ they reach receives a validated value, never a
raw one. `/out_peers`
([`rust/shekyl-daemon-rpc/src/server.rs:344`](../../rust/shekyl-daemon-rpc/src/server.rs),
[`:430`](../../rust/shekyl-daemon-rpc/src/server.rs)) and the `out_peers`
console command ([`src/daemon/command_server.cpp:211-213`](../../src/daemon/command_server.cpp))
are deleted with the option.

A consequence of IG-12 this brief owns: with the five `--bg-mining-*`
options deleted, the background-mining arguments of `start_mining`
(`do_background_mining`, `ignore_battery`,
[`src/rpc/core_rpc_server_commands_defs.h:183-191`](../../src/rpc/core_rpc_server_commands_defs.h))
have no startup twin to share a constructor with. They go with the options,
and the background miner's runtime surface is listed in §4 so the lane that
owns mining sees the deletion.

### 2.8 The clearnet public address (DC-Q10)

Shape (a): an operator-configured public address, name pending IG. A
global-unicast endpoint whose port defaults to `--p2p-external-port` and
then the bind port; given to the same own-address entry the onion uses
(`shekyl_peerlist_set_own_address` on the PR-3 branch, read at construction
after the cutover) so both connectors obey one rule. Without it, clearnet
stays dial-only, as PR-3 leaves it (`P2P_3_SLICE_3_DIALER_BRIEF.md:506-511`
at `baaba2bddd`), and the startup line says so.

---

## 3. The option table (83 registered in shekyld at the pin)

Columns: today's name (records-was), declared at, what it is, disposition,
reader after the cutover, IG row. "dep(T/S)" marks a default that follows
`--testnet` or `--stagenet` today. Every "IG row" cell reads *pending IG
Part A*; it is one column so the fold-in is one edit per row.

### 3.1 `src/daemon/main.cpp` (13 sites, [`src/daemon/main.cpp:102-120`](../../src/daemon/main.cpp))

| Today | Declared | What | Disposition | Reader after | IG row |
| --- | --- | --- | --- | --- | --- |
| `help`, `version` | [`src/common/command_line.cpp:71-72`](../../src/common/command_line.cpp) | switches | KEEP, answered by the parse | Rust | pending IG Part A |
| `os-version` | [`src/daemon/command_line_args.h:87`](../../src/daemon/command_line_args.h) | switch | KEEP | Rust | pending IG Part A |
| `config-file` | [`:38-51`](../../src/daemon/command_line_args.h); dep(T/S) default under the compiled root | path | KEEP; replaces the system path whole; command-line only | Rust | pending IG Part A |
| `log-file` | [`:53-66`](../../src/daemon/command_line_args.h); declared default dead (DC-F2) | path | KEEP | Rust (logging) | pending IG Part A |
| `log-level` | [`:78`](../../src/daemon/command_line_args.h); empty help | level or category spec | KEEP | Rust (logging) | pending IG Part A |
| `max-log-file-size`, `max-log-files` | [`:68-76`](../../src/daemon/command_line_args.h) | sizes | KEEP | Rust (logging) | pending IG Part A |
| `max-concurrency` | [`:91`](../../src/daemon/command_line_args.h) | count | KEEP | C++ snapshot (`tools::set_max_concurrency`, [`src/common/util.cpp:861`](../../src/common/util.cpp)) | pending IG Part A |
| `proxy` | [`:97`](../../src/daemon/command_line_args.h) | SOCKS endpoint, credentials file-only | KEEP | Rust (zone host) | pending IG Part A |
| `non-interactive` | [`:108`](../../src/daemon/command_line_args.h) | switch, command-line only | KEEP until DC-N2 | C++ (`main.cpp:400`) | pending IG Part A |
| `daemon_command` (hidden positional) | [`:83`](../../src/daemon/command_line_args.h) | words | KEEP until DC-N2 | C++ console client | pending IG Part A |
| `carrier-development` (hidden) | [`:137`](../../src/daemon/command_line_args.h) | switch, command-line only | KEEP as a development option (IG-8) | Rust (relay) | pending IG Part A |

### 3.2 `src/cryptonote_core/cryptonote_core.cpp` (20 sites, [`src/cryptonote_core/cryptonote_core.cpp:237-260`](../../src/cryptonote_core/cryptonote_core.cpp))

| Today | Declared | What | Disposition | Reader after | IG row |
| --- | --- | --- | --- | --- | --- |
| `data-dir` | [`:99-110`](../../src/cryptonote_core/cryptonote_core.cpp); dep(T/S) always | path | KEEP; subdir from the params row | C++ snapshot; Rust (tor, lock) | pending IG Part A |
| `testnet`, `stagenet`, `regtest` | [`:74-88`](../../src/cryptonote_core/cryptonote_core.cpp) | switches | DELETE, replaced by `--network` | Rust; the network in the snapshot | pending IG Part A |
| `keep-fakechain` | [`:89`](../../src/cryptonote_core/cryptonote_core.cpp) | switch | DELETE with the wipe | — | REJECTED entry (IG-10) |
| `fixed-difficulty` | [`:94`](../../src/cryptonote_core/cryptonote_core.cpp) | number | KEEP, regtest-only (IG-8) | C++ snapshot | pending IG Part A |
| `prep-blocks-threads` | [`:140`](../../src/cryptonote_core/cryptonote_core.cpp) | count | lane-owned, pending IG-Q4 | C++ snapshot | pending IG-Q4 |
| `show-time-stats` | [`:145`](../../src/cryptonote_core/cryptonote_core.cpp) | number | DELETE | — | REJECTED entry |
| `block-sync-size` | [`:150`](../../src/cryptonote_core/cryptonote_core.cpp); overflow only logged at `:636` | count | lane-owned, pending IG-Q4; the overflow becomes a refusal | C++ snapshot | pending IG-Q4 |
| `test-drop-download`, `test-drop-download-height`, `test-dbg-lock-sleep` | [`:126-138`](../../src/cryptonote_core/cryptonote_core.cpp) | test levers | DELETE | — | REJECTED entry |
| `offline` | [`:112`](../../src/cryptonote_core/cryptonote_core.cpp); a second dead `extern` at [`src/p2p/net_node.h:829`](../../src/p2p/net_node.h) | switch | KEEP | C++ snapshot; Rust | pending IG Part A |
| `block-download-max-size`, `span-limit` | [`:116-125`](../../src/cryptonote_core/cryptonote_core.cpp) | sizes | lane-owned, pending IG-Q4 | C++ snapshot (protocol handler) | pending IG-Q4 |
| `max-txpool-weight`, `keep-alt-blocks` | [`:155`](../../src/cryptonote_core/cryptonote_core.cpp), [`:185`](../../src/cryptonote_core/cryptonote_core.cpp) | size, switch | lane-owned, pending IG-Q4 | C++ snapshot | pending IG-Q4 |
| `block-notify`, `reorg-notify`, `block-rate-notify` | [`:160-184`](../../src/cryptonote_core/cryptonote_core.cpp) | program strings, executed | KEEP; file-only is a question for IG (an exec string on argv is visible but not secret) | C++ snapshot | pending IG Part A |

### 3.3 `src/cryptonote_basic/miner.cpp` (7 sites, [`src/cryptonote_basic/miner.cpp:278-286`](../../src/cryptonote_basic/miner.cpp))

| Today | Declared | What | Disposition | Reader after | IG row |
| --- | --- | --- | --- | --- | --- |
| `start-mining` | [`:92`](../../src/cryptonote_basic/miner.cpp) | wallet address, validated for the network | KEEP | C++ snapshot | pending IG Part A |
| `mining-threads` | [`:93`](../../src/cryptonote_basic/miner.cpp) | count | KEEP | C++ snapshot | pending IG Part A |
| `bg-mining-enable`, `bg-mining-ignore-battery`, `bg-mining-min-idle-interval`, `bg-mining-idle-threshold`, `bg-mining-miner-target` | [`:94-98`](../../src/cryptonote_basic/miner.cpp) | switches and percentages | DELETE (with the runtime arguments, §2.7) | — | REJECTED entry |

### 3.4 `src/blockchain_db/blockchain_db.cpp` (2 sites, [`src/blockchain_db/blockchain_db.cpp:199-203`](../../src/blockchain_db/blockchain_db.cpp))

| Today | Declared | What | Disposition | Reader after | IG row |
| --- | --- | --- | --- | --- | --- |
| `db-sync-mode` | [`:183`](../../src/blockchain_db/blockchain_db.cpp) | mode spec | lane-owned, pending IG-Q4 | C++ snapshot | pending IG-Q4 |
| `db-salvage` | [`:188`](../../src/blockchain_db/blockchain_db.cpp) | switch | lane-owned, pending IG-Q4 | C++ snapshot | pending IG-Q4 |

### 3.5 `src/p2p/net_node.inl` (27 sites, [`src/p2p/net_node.inl:107-136`](../../src/p2p/net_node.inl); descriptors [`src/p2p/net_node.cpp:93-158`](../../src/p2p/net_node.cpp))

| Today | Declared | What | Disposition | Reader after | IG row |
| --- | --- | --- | --- | --- | --- |
| `p2p-bind-ip`, `p2p-bind-ipv6-address`, `p2p-bind-port`, `p2p-bind-port-ipv6`, `p2p-use-ipv6` | [`:93-120`](../../src/p2p/net_node.cpp), [`:142`](../../src/p2p/net_node.cpp); ports dep(T/S) | addresses, ports, switch | KEEP | Rust (zone host) | pending IG Part A |
| `p2p-ignore-ipv4` | [`:143`](../../src/p2p/net_node.cpp); sets a field nothing reads | switch | DELETE | — | REJECTED entry |
| `p2p-external-port` | [`:122`](../../src/p2p/net_node.cpp); PWD-E6 | port | KEEP | C++ snapshot; Rust (public address default) | pending IG Part A |
| `allow-local-ip` | [`:123`](../../src/p2p/net_node.cpp) | switch | KEEP, regtest and private networks | Rust (peer lists) | pending IG Part A |
| `add-peer` | [`:124`](../../src/p2p/net_node.cpp) | list of addresses | KEEP | Rust (dialer) | pending IG Part A |
| `add-priority-node` | [`:125`](../../src/p2p/net_node.cpp) | list | DELETED on PR-3 at `baaba2bddd`, which also adds a retired-flag row for it (`removed_flags.cpp:120` on the branch); that row goes with the shim (DC-Q4) | — | REJECTED entry |
| `add-exclusive-node` | [`:126`](../../src/p2p/net_node.cpp) | list | KEEP (a closed-network declaration) | C++ snapshot until slice 4; Rust | pending IG Part A |
| `seed-node` | [`:128`](../../src/p2p/net_node.cpp) | list | DELETE (Rick, 2026-10-13). PR-3 at `baaba2bddd` keeps it, reworded as a dial candidate like `add-peer` (`net_node.cpp:123` on the branch); the deletion is this cutover's row, not PR-3's | — | REJECTED entry |
| `tx-proxy` | [`:129`](../../src/p2p/net_node.cpp) | zone, SOCKS endpoint, credentials file-only; the `,N` suffix and the `disable_noise` token deleted | KEEP | Rust (zone host, dialer) | pending IG Part A |
| `anonymous-inbound` | [`:135`](../../src/p2p/net_node.cpp) | onion, bind; the `,N` suffix deleted | KEEP | Rust (zone host, peer lists) | pending IG Part A |
| `no-ephemeral-tor` | [`:136`](../../src/p2p/net_node.cpp) | switch | KEEP | Rust | pending IG Part A |
| `ban-list` | [`:137`](../../src/p2p/net_node.cpp) | path, read at parse | KEEP | Rust | pending IG Part A |
| `no-sync` | [`:138`](../../src/p2p/net_node.cpp) | switch | KEEP | C++ snapshot (protocol handler) | pending IG Part A |
| `no-igd`, `igd` | [`:140-141`](../../src/p2p/net_node.cpp) | switch, mode | DELETE with UPnP | — | REJECTED entry |
| `out-peers` | [`:144`](../../src/p2p/net_node.cpp) | count | DELETE: the degree is `P2P_DEFAULT_OUT_PEERS` ([`rust/shekyl-relay-privacy/src/params.rs:194`](../../rust/shekyl-relay-privacy/src/params.rs)); the anonymity cap is `MIN_PROVISIONED_OUT_PEERS` ([`:219`](../../rust/shekyl-relay-privacy/src/params.rs)) | — | REJECTED entry |
| `in-peers` | [`:145`](../../src/p2p/net_node.cpp) | count | KEEP | Rust (zone host) | pending IG Part A |
| `tos-flag` | [`:146`](../../src/p2p/net_node.cpp); any value but −1 refuses | number | DELETE | — | REJECTED entry |
| `limit-rate-up`, `limit-rate-down`, `limit-rate` | [`:148-150`](../../src/p2p/net_node.cpp) | rates | KEEP | Rust (link) | pending IG Part A |
| `pad-transactions` | [`:152`](../../src/p2p/net_node.cpp) | switch | lane-owned, pending IG-Q4 | C++ snapshot (relay padding) | pending IG-Q4 |
| `clearnet-transport-encrypt` | [`:155`](../../src/p2p/net_node.cpp) | switch, pre-genesis test gate | KEEP until the flip deletes it | Rust (zone host) | pending IG Part A |

### 3.6 `src/rpc/rpc_args.cpp` (7 registered of 15, [`src/rpc/rpc_args.cpp:116-122`](../../src/rpc/rpc_args.cpp)) and `src/rpc/core_rpc_server.cpp` (7 sites, [`src/rpc/core_rpc_server.cpp:92-103`](../../src/rpc/core_rpc_server.cpp))

| Today | Declared | What | Disposition | Reader after | IG row |
| --- | --- | --- | --- | --- | --- |
| `rpc-bind-ip`, `rpc-bind-ipv6-address`, `rpc-use-ipv6` | [`src/rpc/rpc_args.cpp:91-95`](../../src/rpc/rpc_args.cpp) | addresses, switch | KEEP | Rust (RPC) | pending IG Part A |
| `rpc-restricted-bind-ip`, `rpc-restricted-bind-ipv6-address` | [`:93-94`](../../src/rpc/rpc_args.cpp) | addresses | KEEP | Rust (RPC) | pending IG Part A |
| `rpc-access-control-origins` | [`:97`](../../src/rpc/rpc_args.cpp) | list | KEEP | Rust (RPC) | pending IG Part A |
| `disable-rpc-ban` | [`:105`](../../src/rpc/rpc_args.cpp); its only reader guards a function nothing calls | switch | DELETE | — | REJECTED entry |
| the eight TLS and login descriptors | [`:96-104`](../../src/rpc/rpc_args.cpp); never registered for shekyld | — | DELETE with `rpc_args` | — | — |
| `rpc-bind-port` | [`src/rpc/core_rpc_server.cpp:1402-1414`](../../src/rpc/core_rpc_server.cpp); dep(T/S) | port | KEEP | Rust (RPC); C++ console until DC-N2 | pending IG Part A |
| `rpc-restricted-bind-port`, `restricted-rpc` | [`:1416-1426`](../../src/rpc/core_rpc_server.cpp) | port, switch | KEEP | Rust (RPC) | pending IG Part A |
| `rpc-max-connections`, `rpc-max-connections-per-private-ip` | [`:1434-1444`](../../src/rpc/core_rpc_server.cpp) | counts | KEEP | Rust (RPC) | pending IG Part A |
| `rpc-max-connections-per-public-ip` | [`:1428`](../../src/rpc/core_rpc_server.cpp) | count | DELETE | — | REJECTED entry |
| `rpc-response-soft-limit` | [`:1446`](../../src/rpc/core_rpc_server.cpp); read by nothing | size | DELETE | — | REJECTED entry |

### 3.7 Configuration sources outside the table

`HOME` with a `/` fallback ([`src/common/util.cpp:645`](../../src/common/util.cpp));
`SHEKYL_SETTLEMENT_EPOCH_BLOCKS` and `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS`
([`src/cryptonote_core/blockchain.cpp:339-346`](../../src/cryptonote_core/blockchain.cpp));
`SEEDHASH_EPOCH_BLOCKS` and `SEEDHASH_EPOCH_LAG`
([`rust/shekyl-ffi/src/pow_randomx_ffi.rs:350-351`](../../rust/shekyl-ffi/src/pow_randomx_ffi.rs),
[`:666-667`](../../rust/shekyl-ffi/src/pow_randomx_ffi.rs)); the
`RPC_LOGIN` path ([`src/rpc/rpc_args.cpp:158`](../../src/rpc/rpc_args.cpp),
dead for shekyld); the carrier global. All of these are deletion rows
(§4), their replacements being regtest-only development options in the
table (IG-8).

---

## 4. What is deleted

Every row is an `rg -n -e … <paths>` whose count is asserted non-zero at
the base and zero after (rule 47). A literal pipe in a pattern is written
`\|`. Paths are repo-relative.

| Deleted | Before | After |
| --- | --- | --- |
| every `add_arg` site in daemon-linked code | `rg -n -e 'command_line::add_arg' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db` → 91 | 0 |
| every `arg_descriptor` in those directories | `rg -n -e 'arg_descriptor<' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db` → more than 0 | 0 (`src/common/command_line.{h,cpp}` and its `IsYes` test stay: the utilities keep `program_options` until IG Part B) |
| `src/daemon/command_line_args.h`, `src/common/removed_flags.{h,cpp}`, `src/rpc/rpc_args.{h,cpp}`, `src/common/daemon_default_data_dir.{h,cpp}` | files exist | `rg -n -e 'removed_flags' -e 'rpc_args' -e 'daemon_default_data_dir' -e 'command_line_args' src tests` → 0 |
| the map reads | `rg -n -e 'get_arg(vm' -e 'has_arg(vm' -e 'is_arg_defaulted(vm' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db src/cryptonote_protocol` → more than 100 | 0 |
| `variables_map` on the daemon surface | `rg -n -e 'variables_map' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db src/cryptonote_protocol` → more than 0 | 0; `src/blockchain_utilities/blockchain_import.cpp:662` keeps its own call to a re-homed `init_options` (DC-Q12) |
| `boost::program_options` out of shekyld | `rg -n -e 'program_options' src/daemon src/cryptonote_core src/p2p src/rpc src/cryptonote_basic src/blockchain_db src/cryptonote_protocol` → more than 0; `rg -n -e 'Boost_PROGRAM_OPTIONS_LIBRARY' src/daemon/CMakeLists.txt` → 1 | 0 and 0 |
| every configuration parameter on a Rust start function (§2.1 table) | the nine values of `shekyl_daemon_rpc_start`; the bind, proxy and encrypt parameters of `shekyl_zone_listen_clearnet`; the host and port of `shekyl_zone_listen_tor` and `shekyl_zone_set_tor_proxy`; `shekyl_zone_set_connector_cap`, `shekyl_zone_clear_connector_cap`, `shekyl_link_set_up`, `shekyl_link_set_down`, `shekyl_log_init_file`'s values, `shekyl_log_set_level` and `shekyl_log_set_categories` at startup, `shekyl_daemon_tor_start`'s data-dir parameter | `rg -n -e shekyl_zone_set_connector_cap -e shekyl_zone_clear_connector_cap -e shekyl_link_set_up -e shekyl_link_set_down src rust/shekyl-ffi/src src/shekyl/shekyl_ffi.h` → 0; the signatures of the survivors carry no configuration value (`scripts/ci/check_ffi_signatures.sh` holds the header to the Rust) |
| PR-3's four pushes and two adapters | `rg -n -e shekyl_dialer_set_out_peers -e shekyl_peerlist_allow_local_ip -e shekyl_peerlist_set_own_address -e shekyl_peerlist_admit_operator -e note_own_address -e admit_operator_peer src rust/shekyl-ffi src/shekyl/shekyl_ffi.h` → 6 or more at the PR-3 merge | 0 |
| UPnP: the two options, the `igd_t` enum and `m_igd`, the eight mapping functions, the three includes, the delayed arm | `rg -n -i -e 'upnp' -e 'm_igd' -e 'igd_t' src/p2p` → more than 40 ([`src/p2p/net_node.h:463-467`](../../src/p2p/net_node.h), [`:663-670`](../../src/p2p/net_node.h), [`:739`](../../src/p2p/net_node.h), [`src/p2p/net_node.inl:66-68`](../../src/p2p/net_node.inl), [`:1183-1189`](../../src/p2p/net_node.inl), [`:1265-1266`](../../src/p2p/net_node.inl), [`:2358`](../../src/p2p/net_node.inl), [`:3381-3383`](../../src/p2p/net_node.inl)) | 0 |
| miniupnpc: the submodule, the find module, the build wiring, the CI and brew package lines | `rg -n -i -e 'miniupnp' -e 'UPNP' CMakeLists.txt external/CMakeLists.txt cmake/FindMiniupnpc.cmake .gitmodules contrib/brew/Brewfile .github/workflows/build.yml .github/workflows/nightly-live-daemon-slow.yml .github/workflows/economics-c2a-prime.yml .github/workflows/randomx-v2-differential.yml src/p2p/CMakeLists.txt` → more than 15 ([`CMakeLists.txt:490`](../../CMakeLists.txt) `check_submodule`, [`:606`](../../CMakeLists.txt); [`external/CMakeLists.txt:32-51`](../../external/CMakeLists.txt); [`src/p2p/CMakeLists.txt:41`](../../src/p2p/CMakeLists.txt)) | 0; `external/miniupnp` removed from `.gitmodules` and the tree; the doc-claims gate's note at [`scripts/ci/check_doc_claims.py:694`](../../scripts/ci/check_doc_claims.py) updated |
| `--out-peers` and its runtime surface | `rg -n -e 'out_peers' -e 'OUT_PEERS' -e 'change_max_out_public_peers' -e 'get_max_out_public_peers' -e 'shekyl_p2p_default_out_peers' src rust/shekyl-daemon-rpc/src rust/shekyl-ffi/src` → more than 20 ([`src/rpc/core_rpc_server.cpp:1166-1171`](../../src/rpc/core_rpc_server.cpp), [`src/rpc/core_rpc_server_commands_defs.h:862-872`](../../src/rpc/core_rpc_server_commands_defs.h), [`src/daemon/command_parser_executor.cpp:551-569`](../../src/daemon/command_parser_executor.cpp), [`src/daemon/rpc_command_executor.cpp:856-884`](../../src/daemon/rpc_command_executor.cpp), [`src/daemon/command_server.cpp:211-213`](../../src/daemon/command_server.cpp), [`src/p2p/net_node.inl:2939-2966`](../../src/p2p/net_node.inl), [`:3136`](../../src/p2p/net_node.inl), [`:3212`](../../src/p2p/net_node.inl), [`rust/shekyl-daemon-rpc/src/server.rs:344`](../../rust/shekyl-daemon-rpc/src/server.rs), [`:430`](../../rust/shekyl-daemon-rpc/src/server.rs), [`:686`](../../rust/shekyl-daemon-rpc/src/server.rs)) | 0 |
| the `,N` suffix parser and the two `max_connections` fields | `rg -n -e 'get_max_connections' -e 'max_connections' src/p2p/net_node.cpp src/p2p/net_node.h` → more than 8 ([`src/p2p/net_node.cpp:63`](../../src/p2p/net_node.cpp), [`:213-233`](../../src/p2p/net_node.cpp), [`:296-301`](../../src/p2p/net_node.cpp), [`src/p2p/net_node.h:80`](../../src/p2p/net_node.h)) | 0 |
| `--seed-node` | `rg -n -e 'arg_p2p_seed_node' src/p2p` → 4 ([`src/p2p/net_node.h:820`](../../src/p2p/net_node.h), [`src/p2p/net_node.inl:120`](../../src/p2p/net_node.inl), [`:562-567`](../../src/p2p/net_node.inl), [`src/p2p/net_node.cpp:128`](../../src/p2p/net_node.cpp)) | 0 |
| `--disable-rpc-ban` and the RPC server's dead ban scoring | `rg -n -e 'disable_rpc_ban' -e 'core_rpc_server::add_host_fail' src/rpc` → more than 5 ([`src/rpc/core_rpc_server.cpp:173-190`](../../src/rpc/core_rpc_server.cpp), [`src/rpc/core_rpc_server.h:185`](../../src/rpc/core_rpc_server.h), [`:193-195`](../../src/rpc/core_rpc_server.h)); `RPC_IP_FAILS_BEFORE_BLOCK` ([`src/cryptonote_config.h:266`](../../src/cryptonote_config.h)) | 0. `node_server::add_host_fail` ([`src/p2p/net_node.inl:451`](../../src/p2p/net_node.inl)) is a different function with six callers and stays |
| `--tos-flag`, `--p2p-ignore-ipv4` and `m_require_ipv4`, `--rpc-response-soft-limit`, `--rpc-max-connections-per-public-ip` and its `ConnLimits` field | `rg -n -e 'tos_flag' -e 'm_require_ipv4' -e 'rpc_response_soft_limit' -e 'per_public_ip' src rust/shekyl-daemon-rpc/src` → more than 10 | 0 |
| the test levers: `test-drop-download`, `test-drop-download-height`, `test-dbg-lock-sleep`, `show-time-stats` and their readers | `rg -n -e 'test_drop_download' -e 'g_test_dbg_lock_sleep' -e 'show_time_stats' src contrib/epee/include/syncobj.h` → more than 10 | 0 |
| the background miner's options and runtime arguments | `rg -n -i -e 'background' src/cryptonote_basic/miner.cpp src/cryptonote_basic/miner.h src/rpc/core_rpc_server.cpp src/rpc/core_rpc_server_commands_defs.h src/daemon/command_parser_executor.cpp` → more than 90 | the option rows and `do_background_mining`, `ignore_battery`, `bg_ignore_battery` gone; whether the miner's background thread itself goes is the mining lane's (DC-N4 is not it); recorded in the FOLLOWUPS carry |
| the three network booleans and `--keep-fakechain` | `rg -n -e 'arg_testnet_on' -e 'arg_stagenet_on' -e 'arg_regtest_on' -e 'arg_keep_fakechain' -e 'keep_fakechain' src` → more than 20 | 0 |
| the regtest Tor skip, the regtest wipe, the regtest block-rate skip | `rg -n -e 'FAKECHAIN' src/p2p/net_node.inl src/cryptonote_core/cryptonote_core.cpp` → 7 ([`src/p2p/net_node.inl:684`](../../src/p2p/net_node.inl), [`:854`](../../src/p2p/net_node.inl); [`src/cryptonote_core/cryptonote_core.cpp:477`](../../src/cryptonote_core/cryptonote_core.cpp), [`:516`](../../src/cryptonote_core/cryptonote_core.cpp), [`:624`](../../src/cryptonote_core/cryptonote_core.cpp), [`:1621`](../../src/cryptonote_core/cryptonote_core.cpp)) | the three control-flow arms at `:684`, `:854`, `:516`, `:1621` gone; `:477` (the data subdir) becomes the params row; `:624` (the mempool's regtest flag) is listed for the lane that owns the pool and not deleted here |
| the data-directory port suffix | `rg -n -e 'm_config_folder + "/"' src/p2p/net_node.inl` → 1 ([`src/p2p/net_node.inl:1045-1048`](../../src/p2p/net_node.inl)) | 0; the lock (DC-N1) is what keeps two daemons out of one directory |
| `Blockchain::m_offline` | `rg -n -e 'm_offline' src/cryptonote_core/blockchain.cpp src/cryptonote_core/blockchain.h` → 2 ([`src/cryptonote_core/blockchain.cpp:302`](../../src/cryptonote_core/blockchain.cpp), [`src/cryptonote_core/blockchain.h:1145`](../../src/cryptonote_core/blockchain.h)) | 0; the `offline` parameter of `Blockchain::init` ([`:278`](../../src/cryptonote_core/blockchain.cpp)) goes with it |
| the dead `extern nodetool::arg_offline` | `rg -n -e 'arg_offline' src/p2p/net_node.h` → 1 | 0 |
| the environment levers | `rg -n -e 'getenv("SHEKYL_' src/cryptonote_core/blockchain.cpp` → 2; `rg -n -e 'env::var("SEEDHASH_' rust/shekyl-ffi/src/pow_randomx_ffi.rs` → 4; `rg -n -e 'getenv("RPC_LOGIN")' src/rpc` → 1 | 0; replaced by regtest-only options in the table (IG-8) |
| the carrier global | `rg -n -e 'set_carrier_development' src` → more than 2 | 0 |
| `utils/conf/shekyld.conf` | file exists; cited at [`docs/USER_GUIDE.md:131-133`](../USER_GUIDE.md) | gone; the guide's example is generated (IG-9) |
| `scripts/ci/check_carrier_flag_hidden.sh` | exists | retired in the same PR; replaced by a Rust test that the row is hidden |
| `tests/unit_tests/command_line.cpp:52-104` (the removed-flags tests), `tests/unit_tests/rpc_args_daemon_surface.cpp` | exist | deleted; `IsYes` stays with `command_line.cpp` |
| the C++ test harnesses that build a `variables_map` | `rg -n -e 'variables_map' tests/unit_tests/node_server.cpp tests/core_tests/chaingen.h tests/core_tests/chaingen_main.cpp tests/unit_tests/sync_orphan_arm.cpp tests/unit_tests/main.cpp tests/performance_tests/main.cpp` → more than 10 (`node_server.cpp` alone has eleven `init_options` calls) | 0; they construct from the real Rust parse of a test argument list, never a test-only entry (rule 26 B2) |
| the launchers' flag spellings | §5.1 | each edited in the same PR |

---

## 5. Ripples

### 5.1 Launchers (DC-N3), re-censused at `737da31276`

Every file outside `src/` and `docs/` that passes a daemon flag. Columns:
what it passes today that this brief changes; whether it runs regtest
without `--offline` (and therefore spawns the managed Tor once the skip is
deleted); whether it relied on the regtest wipe.

| Launcher | Flags this brief changes | Regtest without `--offline` | Relied on the wipe |
| --- | --- | --- | --- |
| [`contrib/packaging/linux/shekyld.service:12`](../../contrib/packaging/linux/shekyld.service) | none of the deleted ones; spellings fold in with IG | — | — |
| [`utils/fleet/skl-node@.service:35`](../../utils/fleet/skl-node@.service), the two sibling templates, and [`utils/fleet/gen_host_configs.sh:69-88`](../../utils/fleet/gen_host_configs.sh) | the file becomes TOML at the system path; `stagenet=1` becomes `--network` on the unit's command line; `no-igd=1` goes | — | — |
| the GUI sidecar, `daemon_manager.rs` under the GUI's `src-tauri/src`, lines 112 to 120 (`shekyl-gui-wallet`, cross-repo) | none deleted; spellings fold in | — | — |
| [`rust/shekyl-cli/src/main.rs:524-532`](../../rust/shekyl-cli/src/main.rs) | emits `shekyld --testnet` or `--stagenet` in its daemon-down message: a consumer of the daemon's spelling inside another binary; edited in the cutover | — | — |
| [`rust/shekyl-engine-core/src/engine/regtest_e2e.rs:355-392`](../../rust/shekyl-engine-core/src/engine/regtest_e2e.rs) | `--regtest`, `--no-igd` | the `Linked` arm already passes `--no-ephemeral-tor` ([`:386`](../../rust/shekyl-engine-core/src/engine/regtest_e2e.rs)); the `Offline` arm is offline | no: it removes the directory itself ([`:350`](../../rust/shekyl-engine-core/src/engine/regtest_e2e.rs)) |
| [`rust/shekyl-engine-core/src/engine/regtest_e2e.rs:5087-5095`](../../rust/shekyl-engine-core/src/engine/regtest_e2e.rs) (`shekyl-e2-trace-export`) | `--regtest` | a utility, not the daemon; IG Part B | — |
| [`rust/shekyl-levin/tests/dual_stack.rs:71-72`](../../rust/shekyl-levin/tests/dual_stack.rs) | `--regtest`, `--no-igd`, `--out-peers 0` | **yes**: gains the Tor-decline flag | unknown until pre-flight |
| [`rust/shekyl-levin/tests/inbound_cost_bench.rs:166-167`](../../rust/shekyl-levin/tests/inbound_cost_bench.rs) | `--regtest`, `--no-igd`, `--out-peers 0` | **yes**: gains the Tor-decline flag (Rick's ruling names this file) | unknown until pre-flight |
| [`scripts/bench/drs_bench.py:256-257`](../../scripts/bench/drs_bench.py) | `--regtest`, `--keep-fakechain`, `--allow-local-ip`, `--no-igd` | the linked daemons: **yes**, gain the Tor-decline flag; the seed at [`:291`](../../scripts/bench/drs_bench.py) is offline | **yes**: it passes `--keep-fakechain` to defeat the wipe; with the wipe gone the flag goes and the behaviour is unchanged |
| [`scripts/bench/wss_q1b_regtest_open_edge.sh`](../../scripts/bench/wss_q1b_regtest_open_edge.sh) | `--regtest`, `--no-igd` | offline | unknown until pre-flight |
| [`scripts/bench/ba_t5_session2_run.sh`](../../scripts/bench/ba_t5_session2_run.sh), [`scripts/bench/ba_t5_session3_run.sh`](../../scripts/bench/ba_t5_session3_run.sh) | `--testnet`, `--no-igd`, `--in-peers`, `--rpc-restricted-bind-port` | testnet, not regtest | — |
| [`rust/shekyl-cli/tests/json_script.rs:291`](../../rust/shekyl-cli/tests/json_script.rs), [`rust/shekyl-cli/tests/scripts/daemon_session.txt:8`](../../rust/shekyl-cli/tests/scripts/daemon_session.txt) | `--testnet` | spawns `--testnet --offline` | — |
| [`rust/shekyl-wire/tests/vectors/capture_coinbase.py`](../../rust/shekyl-wire/tests/vectors/capture_coinbase.py), [`rust/shekyl-curve-tree/tests/fixtures/gen_ct2_fixture.py`](../../rust/shekyl-curve-tree/tests/fixtures/gen_ct2_fixture.py) | `--regtest` | offline | unknown until pre-flight |
| [`rust/shekyl-chain-ingest/src/bin/shekyl-chain-replay.rs`](../../rust/shekyl-chain-ingest/src/bin/shekyl-chain-replay.rs) | `--regtest` on its own command line; it dials a daemon, it does not spawn one | — | — |
| [`rust/shekyl-staking-sim/src/gf7_seal.rs`](../../rust/shekyl-staking-sim/src/gf7_seal.rs), [`rust/shekyl-engine-core/src/engine/daemon_observability.rs`](../../rust/shekyl-engine-core/src/engine/daemon_observability.rs), [`rust/shekyl-engine-core/src/engine/gf7_sealing_run.rs`](../../rust/shekyl-engine-core/src/engine/gf7_sealing_run.rs) | mention `--regtest` in prose; spawn nothing | — | — |
| [`contrib/tor/shekyl-over-tor.sh`](../../contrib/tor/shekyl-over-tor.sh) | passes `--detach` (retired in V3.1) and `--tx-proxy`: broken today (DC-F8) | — | — |
| [`Dockerfile`](../../Dockerfile) | `--non-interactive`, `--p2p-bind-ip`, `--p2p-bind-port`, `--restricted-rpc`, `--rpc-bind-port` | — | — |
| the Foundation seed recipe in `shekyl-dev` | `--config-file` with a per-network file; `no-igd`, `out-peers`, `in-peers`, `add-peer`, `restricted-rpc` keys (roles only, rule 37) | — | — |

Two sibling test files that build the options map in-process rather than
spawning are in §4's harness row.

### 5.2 Gates and tests pinned to the C++ mechanism

`scripts/ci/check_carrier_flag_hidden.sh` (retired, §4);
`scripts/ci/check_dial_path_freeze.py` with its shrink rows on
`net_node.inl`, `net_node.h` and `levin_notify.cpp` (an edited `get_arg`
line is an added code line; the cutover lands after PR-3 retires the body
rows, and each shrink-row edit carries the dated `UNFREEZE` line form the
dialer brief prescribes); `scripts/ci/check_ffi_signatures.sh` (every
signature change in §2.1 is covered); `scripts/ci/check_network_uniformity.sh`
(the FAKECHAIN arms are outside its fence by design; this brief deletes
three of them and adds none).

### 5.3 Documentation (DC-Q9)

The option tables at [`docs/EXECUTABLES.md:52-84`](../EXECUTABLES.md) and
[`docs/USER_GUIDE.md:135-190`](../USER_GUIDE.md), and the example at
[`docs/USER_GUIDE.md:115-133`](../USER_GUIDE.md), are generated from the
table and gated (IG-9). `docs/proxies.md` documents `--add-node`, which does
not exist, and the UPnP paragraph goes. One false claim is removed by
construction: [`docs/EXECUTABLES.md:61`](../EXECUTABLES.md) and the comment
at [`src/daemon/main.cpp:260-266`](../../src/daemon/main.cpp) promise a
per-network log suffix that never reaches the path (DC-F2).

---

## 6. Failure modes (rule 82; DC-N4)

The effective-configuration line and the IG-11 renderer are the operator
surface. IG-11 owns the wording; this brief owns the list. Each refusal
names what was wrong, where (flag, or file and line), and what to do. Each
is reachable before any listener exists, so none can half-start the node.

| Case | What the operator reads | Exit |
| --- | --- | --- |
| no config file at the selected path, none named | the startup line: "no file at `<path>`: defaults", every value marked *default* | run |
| `--config-file` names a file that does not exist | the path, that it was named explicitly | refuse |
| the file exists and cannot be opened | the path and the OS error; never "missing, so defaults" | refuse |
| the file or a parent directory is writable by another account | the path, the owner and mode found, the mode required | refuse |
| the file is a symlink whose target fails the check | the target path (the opened descriptor was judged) | refuse |
| the file holds a secret and is readable by another account | the path, the mode found, the mode required, which key is the secret (its name, never its value) | refuse |
| Windows: the directory's DACL grants write to Users or Everyone | the ACE found | refuse |
| TOML syntax error | file, line, column, the parser's message | refuse |
| an unknown key | file, line, the key, the nearest live name (DC-Q4) | refuse |
| a key of the wrong kind or out of range | file, line, the key, the kind or range (IG) | refuse |
| a network key inside the file | file, line, that the network is chosen on the command line and selects the file | refuse |
| a secret on the command line | the flag, that credentials are accepted only from the file, where the file is | refuse |
| a list on the command line and in the file | the startup line marks the list *command line*; the file's list is not merged | run |
| two options that contradict (an operator onion with no Tor proxy source; the restricted port equal to the admin port) | both names, the rule | refuse |
| `HOME` unset and no `--data-dir` | the rule and the flag that fixes it | refuse |
| the data directory cannot be created or is not a directory | the path and the OS error | refuse |
| the data directory is locked by another daemon (DC-N1) | the path, that another daemon holds it; never a second daemon sharing a store | refuse |
| the log file's directory cannot be written | the path and the OS error | refuse |
| the ban file cannot be read or holds an unparseable line | the path, the line | refuse |
| a Tor-decline flag together with an operator onion | both names, that one declines the managed Tor and the other needs a proxy source | refuse |
| a public address that is not global unicast (DC-Q10) | the value and the rule | refuse |
| a runtime change (`set_limit`, `in_peers`, `set_log_level`, `start_mining`) that fails the same constructor | the same message the startup parse would give (IG-12) | the request fails; the daemon runs |

---

## 7. Threat-model addenda (rule 26 A3)

Objectives an attacker might pursue through the configuration surface,
each routed:

1. **Run code as the daemon's account by writing its config file.** The
   three notify options execute a program string. Route: the permission
   check of §2.4 (absorbed). A file writable by another account is a refusal,
   so the attacker must already own the daemon's account or root.
2. **Read a SOCKS credential from the process list, a log, or a bug
   report.** Route: credentials never on argv, redacted in every rendering,
   held only in Rust (absorbed, §2.5).
3. **Make the node announce an attacker-run relay as its address.** Route:
   DC-Q10 (b) rejected; only the operator names the public address (§8).
4. **Point two daemons at one store and corrupt it.** Route: the exclusive
   lock (DC-N1, absorbed); the subdirectory by network stays until DC-F1.
5. **Open a store from another network's chain.** Route: not absorbed here;
   DC-F1 is carried to the chain-store lane (§10), with the subdirectory as
   the defence until then.
6. **Enumerate a node's configuration from a peer.** Route: nothing in this
   brief changes what crosses the wire; the effective-configuration line is
   local. No finding.

---

## 8. Rejections, each with reopening criteria (rules 21, 26 A4)

- **DC-Q10 (b), the peer-learned public address.** Rejected: a peer can
  make the node dial any address it names, and a reflector at the candidate
  passes the self-dial while putting the attacker on every inbound session.
  Reopens on two conditions together: a measured share of inbound-willing
  operators who cannot set (a), and a design that distinguishes a reflector
  from a route. Re-evaluated in a P2P design round.
- **(c), the gateway-reported address.** Died with UPnP (DC-Q6).
- **UPnP.** Rejected as attack surface the managed onion makes unnecessary
  for inbound. Reopens only on a ruling that clearnet inbound without an
  operator-configured address is a product requirement; re-evaluated in a
  P2P design round with the surface audited.
- **A retired-flag table.** Rejected pre-genesis: every release is a wipe.
  Reopens at genesis, when a release stops being a wipe; the REJECTED
  entries of IG-10 are the record until then.
- **An environment layer.** Rejected: a source no unit file or bug report
  shows. Reopens only if IG rules otherwise for every binary.
- **The blockchain utilities.** Kept on their own C++ option sets with the
  shared descriptors re-homed; keep-or-delete per tool is IG Part B's. The
  carry is §10.
- **The daemon's console and positional commands.** Kept in C++ until
  RT-15's local leg exists (DC-N2); the carry is §10.

---

## 9. Sequencing (DC-Q12) and pre-flight

One cutover PR, based on PR-3 after it merges and after IG Part A is ruled:
the crate, the table, the TOML file, the typed sections, the snapshot, the
lock, logging in Rust, the startup line, `main.cpp` cut to the Rust parse,
every Rust consumer reading its section, every C++ producer and push
deleted (§4), every launcher edited (§5.1), the docs generated (§5.3). The
blockchain utilities keep their option sets with
`cryptonote::arg_data_dir`, `arg_testnet_on`, `arg_stagenet_on` and
`arg_db_sync_mode` moved into a header they own, so `cryptonote_core.cpp`
loses them and `blockchain_import.cpp:662`'s `core::init_options` call
becomes a call into that header.

Pre-flight (rule 26 Round 0), run before the first production commit and
recorded in a sibling `DAEMON_CONFIG_CUTOVER_AUDIT.md`:

1. Substrate re-check at the implementation pin: every `file:line` in §3
   and §4, with PR-3 merged; the §5.1 census re-run (`rg -l -e shekyld`
   outside `src/` and `docs/`), the "unknown until pre-flight" cells filled.
2. Artifact execution: the §4 before-counts observed non-zero; the
   dial-path freeze gate's state after PR-3; the launchers in §5.1 run on
   the Rust parse; the docs gates (IG-9) run on the generated tables; the
   snapshot field count observed at twenty-four.
3. Rule 17 at source for `fd-lock` and `toml` at the pinned versions.

Interactions: RT-W10 re-scopes the `--rpc-*` bind parsing into
`shekyl-daemon-rpc`; this brief's RPC section is what it reads. IG Part A's
"no environment layer anywhere" contradicts the wallet ruling at
[`docs/V3_WALLET_DECISION_LOG.md:416-437`](../V3_WALLET_DECISION_LOG.md)
(an environment layer, a `--config` flag, XDG paths); that entry needs a
superseding entry from the IG ruling, and this cutover touches no wallet
binary. The `shekyl-dev` consumers of the daemon's spellings (configuration
examples, unit files, the stressnet playbook) move with the cutover under
their own authorisation, named by role (rule 37). RT-16 adds a
service-mode switch as a future row and decides the system file's owner.
Slice 4 deletes the C++ peerlist handler and takes `add-exclusive-node`'s
reader with it. The RD and chain-sync lanes do not touch the option surface
except through the environment levers, which become regtest options here.

---

## 10. Carries (rule 26 A5: each has a FOLLOWUPS row and a named target)

| Carry | FOLLOWUPS row | Target |
| --- | --- | --- |
| DC-F1 genesis-at-open check | "A non-empty chain store is opened without checking its block 0 against this network's genesis" | [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) |
| DC-N2 the console moves to `shekyl-cli` | "The daemon's positional commands and interactive console move to `shekyl-cli` when RT-15's local leg exists" | RT-15, [`RPC_CHANNEL.md`](RPC_CHANNEL.md) |
| DC-Q12 utilities | "The blockchain utilities keep their own C++ option sets until IG Part B rules keep-or-delete per tool" | this brief |
| DC-Q8 GUI sidecar | "The GUI sidecar's daemon argument list follows the cutover's spellings" | this brief; the GUI repository |
| the background miner's runtime surface | "The background miner's thread and the `start_mining` arguments it served" | the mining lane (owner named in the row) |
| the `removed_flags` shim sunset | existing row at `FOLLOWUPS.md`, re-owned by this brief: the shim is deleted in the cutover | this brief |

---

## 11. Findings established at source (DC-F1…DC-F9)

| Id | Finding | Route |
| --- | --- | --- |
| DC-F1 | `Blockchain::init` generates genesis only for an empty store and the non-empty arm is empty ([`src/cryptonote_core/blockchain.cpp:356-369`](../../src/cryptonote_core/blockchain.cpp)); nothing checks a stored block 0 against the network | carried, §10 |
| DC-F2 | The per-network log suffix never reaches the path: `mlog_get_default_log_path` takes the module name first ([`contrib/epee/src/mlog.cpp:64-82`](../../contrib/epee/src/mlog.cpp)); `docs/EXECUTABLES.md:61` and `main.cpp:260-266` are false | absorbed: logging in Rust from the params row, docs generated |
| DC-F3 | SOCKS credentials and the socks4 selection are parsed and dropped at the FFI | absorbed, §2.5 |
| DC-F4 | The silent auto-load path is the compiled default root, ignores `--data-dir`, and on Windows non-admin is a different tree from the data directory | absorbed: DC-Q3's system path, one Windows rule |
| DC-F5 | `arg_log_file`'s declared default is dead; `arg_log_level`'s help is empty; `rpc-response-soft-limit` is read by nothing; `tos-flag` refuses every value but its default; `p2p-ignore-ipv4` sets a field nothing reads; `nodetool::arg_offline` has no definition; `Blockchain::m_offline` is read by nothing; `core_rpc_server::add_host_fail` has no caller; `tools::file_locker` has no caller | absorbed, §4 |
| DC-F6 | Eight TLS and login descriptors are constructed for every `rpc_args::descriptors` and registered for nothing; the only `include_listener_tls_auth=true` caller is a test | absorbed, §4 |
| DC-F7 | `utils/systemd/shekyld.service` was deleted by #1054; the shipped unit passes flags and no config file; `utils/conf/shekyld.conf` names `/var/lib/shekyl-core` and a binary `shekyl-core`; `docs/USER_GUIDE.md:131-133` cites it | absorbed, DC-Q8 |
| DC-F8 | `contrib/tor/shekyl-over-tor.sh` passes `--detach`, retired in V3.1: broken today | absorbed, §5.1 (edited or deleted in the cutover) |
| DC-F9 | Boost's `store` keeps the first non-defaulted value and no descriptor is `composing()`, so a list given on both sides keeps only the command line's; the behaviour DC-Q3 ratifies was already the behaviour, undocumented | absorbed, §2.4 |

---

## 12. What this round examined and did not find

Examined with nothing to report: the Windows installer passes no daemon
flags ([`contrib/packaging/windows/shekyl.nsi:47`](../../contrib/packaging/windows/shekyl.nsi),
[`:86`](../../contrib/packaging/windows/shekyl.nsi)); the CI workflows
launch no daemon with flags; no `getenv` in `src/daemon`, `src/p2p`,
`src/rpc` beyond §3.7; `shekyl-cli` and `shekyl-wallet-rpc` implement no
config file to align with (the decision log's TOML ruling at
[`docs/V3_WALLET_DECISION_LOG.md:416-437`](../V3_WALLET_DECISION_LOG.md) is
prose only); no docs gate names either option document; `shekyl-chain-replay`
spawns no daemon. Not examined: the GUI's settings surface beyond the
sidecar argument list; the mobile wallet; the stressnet Python harness's own
`--config`; the IG document, which was not reachable.

---

## 13. Instructions to the implementing agent

Written for: the agent that lands the cutover PR after PR-3 merges and IG
Part A rules. Read rules 00, 06, 08, 17, 20, 22, 23, 25, 26, 40, 45, 47,
50, 71, 82, 90, 94 and 95 before the first commit.

1. **Preconditions.** PR-3 (#1056) is on `dev`. IG Part A is ruled and its
   table is on `dev`. Fold IG's spellings and kinds into §3's IG-row column
   as the first commit of your branch; nothing else in this brief changes.
2. **Worktree and branch.** One worktree off `dev`; one branch; stage
   explicit paths; every push separately authorised; no attribution footers.
3. **Pre-flight first.** Run §9's three pre-flight steps and record them in
   `docs/design/DAEMON_CONFIG_CUTOVER_AUDIT.md` before any production
   commit. Every §4 before-count must be observed non-zero.
4. **One cutover PR.** Commit order, every commit building: (a) the crate
   and the table (IG kinds), the TOML reader, the permission check, the
   lock, the typed sections, the startup line, with tests for every §6 row;
   (b) `main.cpp` cut to the Rust parse, logging in Rust, the snapshot
   filled, core, miner, protocol and the `net_node` remnant reading it;
   (c) every Rust consumer reading its section at construction, every
   configuration parameter deleted from every start function (§2.1), the
   FFI header regenerated and the signature gate green; (d) every §4
   deletion with its before and after counts in the commit message; (e)
   every §5.1 launcher edited, the docs generated and their gate green;
   (f) the index row and FOLLOWUPS rows of §10 landed, the `removed_flags`
   sunset row deleted.
5. **The snapshot only shrinks.** Add the field-count gate at twenty-four
   in commit (b). A later field is a ruling, not a convenience.
6. **No new daemon option in C++** (standing rule, 2026-10-13). A value C++
   needs comes through the snapshot or not at all.
7. **Gates before claiming done.** `cargo fmt --check`, `cargo clippy
   --all-targets -- -D warnings`, the workspace tests excluding the RandomX
   differential crate, the C++ unit tests, every docs gate, the FFI
   signature gate, the dial-path freeze gate's state recorded; run them on a
   fresh checkout of the pushed SHA.
8. **Rule 37.** Never name a Foundation host; the seed recipe change goes to
   `shekyl-dev` as a separate change under its own authorisation.
9. **Stop and ask** if any §4 before-count is zero, if a §5.1 launcher is
   missing at your pin, if the IG table lacks a row for a KEEP option in §3,
   or if PR-3 merged with `--add-priority-node` still live (then its
   deletion joins §4 with a row of its own).
