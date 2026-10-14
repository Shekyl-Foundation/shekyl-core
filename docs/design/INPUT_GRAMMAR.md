# Shekyl input grammar — Round 0, Part A (the rules) and the daemon's names

**Status:** RULED 2026-10-13 (Rick) — Round 0, Part A. IG-Q1…IG-Q19 ruled as
proposed at revision 3 with the amendments carried in-line (IG-8, the
`config-file` row, IG-Q12, IG-Q14) and IG-Q17 as ruled the same day. The
rules IG-1…IG-15 are the cursor rule
[`83-input-grammar`](../../.cursor/rules/83-input-grammar.mdc); this document
holds the glossary tree and the name tables. Part B (the name tables of
`shekyl-cli`, `shekyl-wallet-rpc`, the consoles and the utilities) is
brought to the maintainer for ruling before anything lands.
**Verified against:** `shekyl-core` @ `737da3127` (`dev`; the option surface
is unchanged from `2c3fae3c`, only `rpc_facts_ffi.*` moved) and PR-3 (#1056,
`feat/p2p3-dialer-cutover`) @ `1e189a3e8`. Reviewed at **`737da3127`**. Every
`file:line` is at the dev pin unless marked `[PR-3]`.
**Identifier family:** `IG-` (input grammar): rules `IG-1…IG-15`, questions
`IG-Q1…IG-Qn`, findings `IG-F1…IG-Fn`. The prefixes collide with no
registered family. Registered at birth in the PR that lands this document
(rule 94).
**The `R1…R9` tokens in §0** are the maintainer's numbered rulings of
2026-10-13, cited the same way by the daemon-configuration cutover brief
(`DAEMON_CONFIG_CUTOVER.md`, draft PR #1066); they are not an identifier
family of this document.

**Sequencing (ruled 2026-10-13).** Part A (the rules) plus the daemon's
section of the name table gate the daemon-config brief. Part B — the name
tables for `shekyl-cli`, `shekyl-wallet-rpc`, the consoles and the
utilities — runs in parallel with the daemon-config brief, under the rules
and the glossary ruled here. The daemon-config implementation is based on
PR-3 after it merges. Genesis gate: the grammar gate passes on every shipped
binary.

---

## 0. Rulings this document builds on (Rick, 2026-10-13)

- **One grammar, project-wide, designed first.** Every binary is built to it; no surface is the reference, and nothing is patched around existing spellings.
- **No backward compatibility before genesis.** Renamed spellings leave no trace and no migration table; our own scripts and configs are fixed in the same change. A *feature* deliberately refused keeps one REJECTED entry with its reason (rule 23).
- **English only.** Each human-facing string has one home; diagnostics are typed codes with parameters.
- **No aliases. No negative names.** A capability on by default is a closed set.
- **Config (R2, R6, R7):** TOML; the network picks the file (`/etc/shekyl/shekyld-<network>.toml`); `--network` is command-line only; `--config-file` replaces the default path whole; the CLI replaces the file per key, lists whole; the file is validated whole before anything applies; ownership and permission checks; file keys are the option names exactly; one startup line shows every effective value and its source. No environment-variable layer in any binary. Credentials are typed secrets (R9).
- **Rust reads every option directly (R1).** No C++ parses or relays configuration; no new option is added in C++.
- **Deleted:** UPnP and miniupnpc (R4); `--out-peers` (the outbound degree is a protocol constant: below 12, Dandelion++ breaks); `bg-mining-*`; both regtest branches, the managed-Tor skip and the database wipe, with `--keep-fakechain` (R3); `--seed-node`, the `,N` suffixes, `--disable-rpc-ban`, the per-public-IP RPC cap, the debug knobs (R5). Sync and LMDB knobs go to their lanes, not ported (R5).
- **`--offline` means "run with P2P not running"** (Rick's reading; its spelling is IG-Q3).
- **`shekyld`'s process entry (`main()`) moves to Rust** in the daemon-config lane (Windows service round, RT-16).
- **The C++ is not canonical.** Every row is justified by the design. Where a row matches what the C++ does, that is not its reason; the C++ appears in this document only as what the cutover deletes.

---

## 1. Scope

The grammar governs every identifier a person types or a script depends on:

- command-line flags of every shipped binary;
- config-file keys;
- command words of `shekyl-cli` (and of the daemon console until it moves into `shekyl-cli`);
- enumeration keywords, unit spellings, and REJECTED names.

Out of scope: RPC method names (a wire contract owned by the RPC lane) and log category names (owned by `shekyl-logging`). Either can be brought in by ruling.

---

## 2. The rules

**IG-1 Lexical.** An identifier is lowercase ASCII, `[a-z][a-z0-9]*` segments joined by single hyphens. Identifiers, keywords and units are never translated.

**IG-2 One vocabulary, as a tree.** The glossary is a tree of terms. Each term is defined once, project-wide, and lists its parents; a term with no parent is a *subject*. A term reused under several parents keeps its one meaning (`listen` under `clearnet`, `onion`, `rpc` and `view`). Every segment of every name is a term in the tree, including plain words (`file`, `dir`, `max`, `help`): the gate has no exemption list.

**IG-3 Structure.** A name is a path through the tree: it starts at a subject and each segment is a child of the one before (`tor-socks-password` is `tor` → `socks` → `password`). A subject alone is a name (`network`). The qualifiers `max` and `min` may end any path. A path-valued option ends in `file` or `dir`. A term may both carry a value and have children (`tor`, `tor-socks`). `dev` is a subject like any other (IG-8); its children may be other subjects (`dev-clearnet-encrypt`). The gate checks that a name is well formed; whether it is an option is the table's. A command is `<path> <verb>`, where the verbs are terms of kind *verb* defined under that subject; how the shell's forms map onto this is Part B's.

The gate walks every live and reserved name in every binary's table (an X row is a refused spelling, exempt by kind; IG-10) and fails on: an undefined segment; an adjacent pair that is not a parent→child edge in the tree; a qualifier anywhere but last; a term defined twice. The edit that proves it can fail: add an option `socks-tor`.

**IG-4 No negation.** No term is `no`, `non`, `not`, `disable`, `enable`, `ignore`, `skip` or `without`. A switch defaults to off. A capability that is on by default is a closed set (`<on|off>`, or named modes).

**IG-5 One option per value; one name per option.** No two options set the same value; no aliases; no hidden duplicates; no short flags; no prefix abbreviation. A rename leaves no trace.

**IG-6 Value kinds.** A kind is a syntax. Every option has exactly one:

| Kind | CLI | File | Syntax |
|---|---|---|---|
| switch | `--x` | `x = true` / `false` | default off |
| one-of | `--x word` | `x = "word"` | a closed lowercase keyword set; the default is named |
| integer | `--x 12` | `x = 12` | decimal, no sign unless the row allows it, no separators |
| quantity | `--x 100MiB` | `x = "100MiB"` | an integer and a unit: bytes `B KiB MiB GiB TiB` (IEC only; `KB`/`MB` refused as ambiguous); rates the same over `/s`; durations `ms s min h d` |
| endpoint | `--x 127.0.0.1:11029`, `--x [::1]:11029` | string | a literal IP and a port; no hostnames |
| peer-endpoint | an endpoint, or `<v3>.onion:port` | string | |
| address | `--x shekyl1…` | string | a Shekyl address, checked against the network |
| path | `--x /abs/path` | string | absolute only |
| secret | not accepted | string | file only; never logged or echoed; zeroized; held only in Rust |
| command | not accepted | array of strings `["/path/prog", "arg", "%h"]` | file only; run without a shell; placeholders named in the row |
| list (of a scalar kind) | the flag repeated | an array under the same key | the keyword `none` is the empty list; a CLI list replaces the file's list whole |
| map (of a scalar kind) | `--x key=value`, repeated | a table under the same key | keys are a closed set named in the row; a CLI map replaces the file's map whole |

A row narrows its kind with a constraint stated in the row and enforced by its constructor (a range, "global unicast only", "onion only"). A row may admit named keywords from the closed keyword set alongside its kind (`unlimited`, `auto`). A row with no default is *unset* when not given, and the row states what unset means; there are no sentinel values. There are no floating-point values anywhere in the grammar.

**IG-7 Surfaces.** Each row says where it may be given. Command-line only: `help`, `version`, `network`, `config-file`. File only: every secret and every command value. Everything else: both, CLI winning per key.

**IG-8 Development levers.** A `dev-` option is hidden from help and generated docs, names the networks it is accepted on as data in its row (a `dev-` option given on any other network is refused at parse, rule 71), and is announced at every start when set. It follows every other rule. **No `dev-` option is ever accepted on mainnet**: a lever mainnet genuinely needs is not a development lever and gets a public row.

**IG-9 One table per binary, generated everything.** The table row: id, name, kind, constraint, keywords, default (a value, unset, or "derived from the network row"), surfaces, visibility (`public` / `dev` / `rejected`), accepted networks (`dev` only), owning subsystem, help text. From the table: `--help`, completion, the documentation tables, and an annotated TOML example. A gate regenerates the docs and diffs them, and asserts the table is non-empty (rule 47).

**IG-10 Unknown and refused names.** An unknown name is one general refusal that names the nearest live name, computed from the table (edit distance), never from a hand list. A REJECTED row (a feature deliberately refused) carries its reason and a pointer to the decision; it is never accepted, never in help, and its refusal states the reason. A REJECTED row is a contract entry in the sense of rule 23, not a code symbol: it is never deleted as dead.

**IG-11 Diagnostics.** Every refusal is a typed value: a stable code (`config.value.range`, `config.file.permissions`, …), the option, the source (`cli`, `file:path:line`, `default`) and named parameters. One renderer turns it into the English message, which states what was wrong, where, and what to do (rule 82). Machine output and logs carry the code. A configuration refusal exits with status 2; a runtime failure with 1.

**IG-12 Runtime changes share the constructor.** A value that can also change while running (rates, inbound cap, log level, mining) is built by the same constructor on both surfaces, with the same refusals. The live value is owned by its subsystem. No binary ever writes its own config file.

**IG-13 Inputs come from the table, and nowhere else.** No option value comes from the environment. Default paths come from the operating system's account and known-folder interfaces (the passwd entry's home on Unix, the known-folder API on Windows), not from `HOME`, `XDG_*` or `%APPDATA%`. The only environment reads permitted are presentation-only (terminal capabilities that change rendering, never a value). Every resolved default path appears in the startup line with its source. A service account whose passwd home is unset or `/nonexistent` has no default paths: the packaging sets the account's home or the unit passes `--data-dir` and `--log-file` (the shipped unit does both, IG-F10).

**IG-14 Required announcements are not log events.** The effective-configuration line, `dev-` lever warnings and posture warnings (clearnet-only, offline) reach the log and standard error at every start whatever the log level.

**IG-15 Home.** The rules become one cursor rule. The glossary tree and the name tables live in one design document. One Rust crate holds the table types, the value kinds and their parsers, the unit types, the diagnostic type and the renderer; every binary builds its table from it.

---

## 3. Glossary — the daemon's subtree (v1)

Indentation is the tree. A term listed under two parents is one term.

| Term | Parents | Meaning |
|---|---|---|
| help | — | print usage |
| version | — | print the version and the OS line |
| network | — | which chain: `mainnet`, `testnet`, `stagenet`, `regtest` |
| config | — | the TOML file of option values |
| data | — | the per-network directory holding the daemon's stores and state |
| log | — | the daemon's log sink |
| file | config, log, ban | a file path (value term) |
| dir | data | a directory path (value term) |
| level | log | a log severity: `error`, `warn`, `info`, `debug`, `trace` |
| category | log | a log category, owned by `shekyl-logging` |
| size | log | the disk a log may use |
| p2p | — | the peer-to-peer protocol, independent of connector |
| clearnet | —, dev | the clearnet connector (direct TCP) |
| tor | — | the Tor connector |
| socks | clearnet, tor | the SOCKS5 endpoint a connector dials through |
| username, password | socks | SOCKS5 credentials (RFC 1929); always secrets |
| onion | tor | this node's v3 onion service |
| listen | clearnet, onion, rpc, view, admin | a local endpoint a listener binds |
| advertise | clearnet | the endpoint we tell peers is ours |
| local | p2p | endpoints not dialable on the public internet (private, loopback, link-local) |
| peer | p2p, closed | another Shekyl node |
| closed | p2p | a network consisting only of the listed peers |
| ban | p2p | a host or subnet refused at socket admission |
| disclose | p2p | what this node tells other nodes of its known peers and its own address |
| early | disclose | below the white-diversity floor |
| inbound | p2p | connections other nodes open to us |
| upload, download | p2p | bytes we send, bytes we receive |
| txpool | — | the transaction pool |
| weight | txpool | transaction weight, in bytes |
| notify | — | run an operator command on an event |
| block | notify | a new block |
| rate | block | the block-rate check |
| reorg | notify, archival | a chain reorganization |
| mining | — | the daemon's own miner |
| address | mining | a Shekyl address (the payment meaning; never a network location) |
| threads | mining | a thread count |
| rpc | — | the daemon's RPC listeners |
| view | rpc | the view grant (RPC_CHANNEL RT-13) |
| admin | rpc | the admin grant (RPC_CHANNEL RT-O9) |
| cors | rpc | cross-origin resource sharing |
| origin | cors | an allowed origin |
| connections | rpc | concurrent connections |
| console | — | the daemon's interactive console (interim; R8) |
| dev | — | a development lever (IG-8) |
| encrypt | clearnet | the pre-flip clearnet encryption switch |
| relay | dev | transaction relay (Dandelion++) |
| cover | relay | Dandelion++ cover traffic ([`COVER_TRAFFIC_RESTORATION.md`](COVER_TRAFFIC_RESTORATION.md)) |
| sync | dev | chain synchronization |
| difficulty | dev | a fixed mining difficulty |
| pow | dev | the RandomX seed schedule |
| seed | pow | the RandomX seed |
| epoch | seed, settlement | a fixed-length run of blocks |
| blocks | epoch | a length in blocks |
| lag | epoch | the seed lag in blocks |
| settlement | dev | the archival settlement schedule |
| archival | dev | the archival layer |
| depth | reorg | a reorganization depth in blocks |
| max, min | any | qualifiers |

Value keywords: `on`, `off`, `managed`, `operator`, `auto`, `unlimited`, `none`, the four network names, the five levels.

Two words are given one meaning each by this table, ending two collisions: **address** is a Shekyl address only (network locations are *endpoints*; `mining-address` keeps its name, and Part B renames `shekyl-wallet-rpc --daemon-address`); **carrier** is the serve-credit witness carrier only ([`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md)), so today's `--carrier-development`, which arms the Dandelion++ *cover* traffic (`command_line_args.h:114-141`), becomes `dev-relay-cover`.

---

## 4. The shared crate and the parser

The table, kinds, parsers, units, diagnostics and renderer live in one crate (IG-Q13). `shekyl-daemon-config` builds the daemon's table from it and owns precedence, the per-network file, permission checks, the effective-config line and the typed `DaemonConfig` (sections per subsystem; each Rust consumer takes its section at construction; the C++ that remains reads a Rust-owned snapshot until its subsystem is Rust).

Cross-row constraints are types, not checks: the P2P section is built from a clearnet posture `Off | On { listen, socks, advertise }` and a Tor posture `Off | Managed | Operator { socks, onion }`, so a SOCKS endpoint for a connector that is off cannot be constructed, and a `p2p-peer` whose connector is off is refused by the section's constructor.

---

## 5. The daemon's name table

Legend — **R** rename or fold (no trace), **K** kept as is, **X** REJECTED row (the feature is refused; the reason is in the row), **–** removed with no trace (an implementation switch, a debug knob, or nothing left to switch), **L** lane-owned (not ported; IG-Q4), **N** new.

### Network, paths, logging

| Today | New | Kind | Default | Surface | Notes |
|---|---|---|---|---|---|
| `help` | `help` | switch | | CLI | K |
| `version` | `version` | switch | | CLI | K; prints the OS line too |
| `os-version` | — | | | | R into `version` |
| `testnet`, `stagenet`, `regtest` | `network` | one-of | `mainnet` | CLI | R |
| `config-file` | `config-file` | path | `/etc/shekyl/shekyld-<network>.toml`; Windows `%ProgramData%\shekyl\shekyld-<network>.toml` (known-folder API) | CLI | K; a missing file at the default per-network path means defaults, and the startup line says so; a missing file at a path the operator named refuses with a typed code (IG-11) that names the path; an unsafe file or directory refuses |
| `data-dir` | `data-dir` | path | account home + `.shekyl` + network subdir (row) | both | K; an explicit path is taken as given, the default layout keeps the network subdirectory, and a Rust network marker refuses a wrong-chain directory (IG-Q17, ruled 2026-10-13); no home refuses; one Windows rule (per-user); exclusive lock (IG-F2) |
| `log-file` | `log-file` | path | account home + `.shekyl/logs/shekyld-<network>.log` | both | K; the per-network name the docs promised (IG-F4) |
| `log-level` | `log-level` | one-of | `warn` | both | R (numeric 0–4 and category strings go); by default the log records what needs the operator's attention, and the startup and posture lines are announcements, not log events (IG-14); runtime `set_log_level` shares the constructor |
| — | `log-category` | map category→level | unset | both | N; replaces the category half of `log-level` and `set_log_categories`; the keys are validated against `shekyl-logging`'s category list at construction, by reference (§1 keeps the names out of this grammar) |
| `max-log-file-size`, `max-log-files` | `log-size-max` | quantity (bytes) | `1GiB` | both | R; the disk the log may use, live file and archives together; rotation inside it is the logging owner's (IG-Q19) |
| `max-concurrency` | — | | | | – (IG-Q7) |

### Connectors and P2P

| Today | New | Kind | Default | Surface | Notes |
|---|---|---|---|---|---|
| — | `clearnet` | one-of `on` `off` | `on` | both | N (IG-F6, IG-Q3) |
| `no-ephemeral-tor`, `tx-proxy`, `anonymous-inbound` | `tor` | one-of `managed` `operator` `off` | `managed` | both | R |
| (`tx-proxy` endpoint) | `tor-socks` | endpoint | unset | both | R; required with `tor = operator`, unconstructible otherwise |
| (`tx-proxy` `user:pass@`) | `tor-socks-username`, `tor-socks-password` | secret | unset | file | N; today parsed and never handed to Rust (IG-F11) |
| (`anonymous-inbound` onion) | `tor-onion` | peer-endpoint, onion only | unset | both | R; `tor = operator` only; one onion: a second onion on one node is a second identity an observer can link to the first, and it offers peers nothing the first does not |
| (`anonymous-inbound` bind) | `tor-onion-listen` | endpoint | unset | both | R; required with `tor-onion` |
| (`tx-proxy` / `anonymous-inbound` `,N`) | — | | | | – (R5) |
| `proxy` | `clearnet-socks` | endpoint | unset | both | R |
| (`proxy` `user:pass@`) | `clearnet-socks-username`, `clearnet-socks-password` | secret | unset | file | N |
| `p2p-bind-ip`, `p2p-bind-ipv6-address`, `p2p-bind-port`, `p2p-bind-port-ipv6`, `p2p-use-ipv6` | `clearnet-listen` | list of endpoint | `0.0.0.0:<row p2p port>` | both | R; `none` = dial-only on clearnet |
| `p2p-external-port` | `clearnet-advertise` | list of endpoint (global unicast; at most one per address family) | unset | both | R (Q10a; absorbs the external port; PWD-E6's capability kept) |
| `p2p-ignore-ipv4` | — | | | | – (the listen lists state the address families) |
| `no-igd`, `igd` | — | | | | X `upnp`, `igd` (R4) |
| `allow-local-ip` | `p2p-local` | switch | off | both | R |
| `add-peer`, `seed-node` | `p2p-peer` | list of peer-endpoint | `none` | both | R; IP and onion only (IG-Q6); seeds are ordinary peers |
| `add-exclusive-node` | `p2p-closed-peer` | list of peer-endpoint | `none` | both | R; non-empty declares a closed network |
| `small-network` `[PR-3]` | `p2p-disclose-early` | switch | off | both | R (IG-Q20); for bootstrapping or testing a network smaller than the white-diversity floor (48): this node discloses its known peers and its own address below the floor, on each connector until that connector's white count reaches the floor or the span `P2P_DISCLOSE_EARLY_SPAN_NANOS` ends it, whichever comes first; announced at start (IG-14) |
| `add-priority-node` | — | | | | X (bypasses the identity protections; removed by PR-3) |
| `ban-list` | `p2p-ban-file` | path | unset | both | R; read in Rust at parse |
| `out-peers` | — | | | | X (the outbound degree is a protocol constant) |
| `in-peers` | `p2p-inbound-max` | integer ≥ 1 | unset | both | R; unset is no operator cap; the transport layer's descriptor ceiling bounds admission whatever the cap (each layer owns its own count and admission: [`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D4 and D8, ruled 2026-09-25); runtime `in_peers` shares the constructor (IG-Q18) |
| `limit-rate-up` | `p2p-upload-max` | quantity (rate), or `unlimited` | `unlimited` | both | R; runtime `set_limit` shares the constructor; `0` refused on both surfaces |
| `limit-rate-down` | `p2p-download-max` | quantity (rate), or `unlimited` | `unlimited` | both | R |
| `limit-rate` | — | | | | R (one option per value) |
| `tos-flag` | — | | | | X (a traffic-class marking is a label any on-path observer can classify Shekyl traffic by) |
| `offline` | — | | | | R into `clearnet = off` and `tor = off` (IG-Q3) |
| `pad-transactions` | — | | | | L relay |
| `clearnet-transport-encrypt` | `dev-clearnet-encrypt` | switch | off | both | R; testnet, stagenet, regtest (IG-8: never mainnet); deleted at the Noise flip |
| `no-sync` | `dev-sync` | one-of `on` `off` | `on` | both | R; regtest; the chain-sync lane owns it |
| `carrier-development` | `dev-relay-cover` | switch | off | both | R; testnet, stagenet, regtest (IG-8: never mainnet); `check_carrier_flag_hidden.sh` replaced by a table test |

### Core, pool, notify, mining

| Today | New | Kind | Default | Surface | Notes |
|---|---|---|---|---|---|
| `test-drop-download`, `test-drop-download-height`, `test-dbg-lock-sleep`, `show-time-stats` | — | | | | – |
| `keep-fakechain` | — | | | | – (nothing is wiped, R3) |
| `fixed-difficulty` | `dev-difficulty` | integer ≥ 1 | unset | both | R; regtest |
| `prep-blocks-threads`, `block-sync-size`, `span-limit`, `block-download-max-size` | — | | | | L chain-sync |
| `db-sync-mode`, `db-salvage` | — | | | | L DRS |
| `keep-alt-blocks` | — | | | | L DRS-E5 |
| `max-txpool-weight` | `txpool-weight-max` | quantity (bytes) | `648000000B` | both | R; a Monero-derived operand (IG-Q11) |
| `block-notify` | `notify-block` | command | unset | file | R (IG-Q5) |
| `reorg-notify` | `notify-reorg` | command | unset | file | R |
| `block-rate-notify` | `notify-block-rate` | command | unset | file | R |
| `start-mining` | `mining-address` | address | unset | both | R; set means mine from start |
| `mining-threads` | `mining-threads` | integer ≥ 1, or `auto` | `auto` | both | K; one default for starting the miner on every surface: `shekyl-cli mine start` with no count is `auto` (`grammar.rs:539-540`); the miner's owner defines `auto` once |
| `bg-mining-*` (5) | — | | | | X (Monero background mining) |

### RPC, named for the ratified RPC_CHANNEL model

| Today | New | Kind | Default | Surface | Notes |
|---|---|---|---|---|---|
| — | `rpc-listen` | list of endpoint | | | **Reserved** for the authenticated channel listener (RT-W10); not in this cut's table |
| `rpc-bind-ip`, `rpc-bind-port`, `rpc-bind-ipv6-address`, `rpc-use-ipv6` | `rpc-admin-listen` | list of endpoint, loopback only | `127.0.0.1:<row rpc port>` | both | R; the interim plaintext full-access listener; loopback only by RT-14 (a plaintext listener never binds beyond loopback; only the authenticated channel listener may bind wildcard); becomes an X row when RT-W10 lands (IG-Q16) |
| `restricted-rpc`, `rpc-restricted-bind-port`, `rpc-restricted-bind-ip`, `rpc-restricted-bind-ipv6-address` | `rpc-view-listen` | list of endpoint, loopback only | `none` | both | R; survives RT-W10 unchanged (plaintext loopback at view, off by default, ruled 2026-10-08); the GUI sidecar passes `--rpc-admin-listen none --rpc-view-listen 127.0.0.1:<port>` |
| `rpc-access-control-origins` | `rpc-cors-origin` | list | `none` | both | R |
| `rpc-max-connections`, `rpc-max-connections-per-public-ip`, `rpc-max-connections-per-private-ip` | `rpc-connections-max` | integer ≥ 1 | `25` (inherited; IG-Q12) | both | R; one option for one value, where today three set it (IG-F1); the cutover ships the inherited 25 with a FOLLOWUPS row for the RPC lane to derive the default under the RT-O9 resource policy, the same shape as `txpool-weight-max` |
| `disable-rpc-ban` | — | | | | – (R5; the scorer it switches has no caller, IG-F9) |
| `rpc-response-soft-limit` | — | | | | – (response limits belong to the RPC resource policy, IG-Q12) |

### Session (interim, until `shekyl-cli` serves the console — R8)

| Today | New | Kind | Default | Surface | Notes |
|---|---|---|---|---|---|
| `non-interactive` | `console` | switch | off | CLI | R (IG-Q8); deleted with the console |
| `daemon_command` (positional) | unchanged | | | | moves to `shekyl-cli` (Part B) |

### Environment levers (regtest only, IG-8)

| Today | New | Kind |
|---|---|---|
| `SEEDHASH_EPOCH_BLOCKS` (`pow_randomx_ffi.rs:350`) | `dev-pow-seed-epoch-blocks` | integer |
| `SEEDHASH_EPOCH_LAG` (`:351`) | `dev-pow-seed-epoch-lag` | integer |
| `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` (`blockchain.cpp:339`) | `dev-settlement-epoch-blocks` | integer |
| `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS` (`:340`) | `dev-archival-reorg-depth` | integer |

The public-network refusal now in C++ (`blockchain.cpp:416-433`) becomes the IG-8 parse refusal; the announcement stays (IG-14).

### REJECTED rows carried from `removed_flags.cpp`

Criterion: a REJECTED row exists for a capability a user could reasonably ask for again. Implementation switches and folds leave no trace.

| Name | Disposition | Reason |
|---|---|---|
| `detach`, `pidfile`, `install-service`, `uninstall-service`, `start-service`, `stop-service`, `run-as-service` | X | the service manager runs `shekyld`; installing is the installer's and `shekyl-cli`'s (RT-16) |
| `rpc-login`, `rpc-ssl`, `rpc-ssl-private-key`, `rpc-ssl-certificate`, `rpc-ssl-ca-certificates`, `rpc-ssl-allowed-fingerprints`, `rpc-ssl-allow-chained`, `rpc-ssl-allow-any-cert` | X | the RPC channel replaces TLS and HTTP auth (RT-11) |
| `bootstrap-daemon-address`, `bootstrap-daemon-login`, `bootstrap-daemon-proxy` | X | no proxying to a third-party daemon |
| `public-node` | X | no public-node advertisement |
| `max-connections-per-ip` | X | no per-host inbound cap (the reason in `removed_flags.cpp`) |
| `no-rust-rpc`, `confirm-external-bind`, `rpc-ignore-ipv4`, `hide-my-port` | – | an implementation switch, a confirmation, a fold into the listen lists, and an advert now derived |

The `removed_flags` shim, its FOLLOWUPS sunset row, and its C++ tests go with the cutover; the X rows live in the Rust table.

**Count:** 83 registered options and 4 environment levers today, plus PR-3's `small-network`; 48 live names after, the four levers among them (unchanged at RT-W10: `rpc-listen` arrives and `rpc-admin-listen` becomes an X row).

---

## 6. Findings made while building the table

- **IG-F1 — the RPC per-IP cap is the real cap.** Loopback counts as local (`conn_limit.rs:247-251`), and the listener is loopback only, so every client shares one or two addresses. The per-private-IP cap (25) binds before the total (100), which is unreachable. Three options, one effective value.
- **IG-F2 — there is no data-directory lock.** `cryptonote_core.cpp:480` says "try to lock it" and only creates the directory; `tools::file_locker` (`util.cpp:269`) has no caller. The Monero workaround — suffixing the data directory with the P2P port when it is not the network default (`net_node.inl:1045-1048`) — is a network-keyed silent path move. An exclusive lock is taken in Rust when paths resolve, and the port suffix is deleted.
- **IG-F3 — `Blockchain::m_offline`** is assigned (`blockchain.cpp:302`) and read by nothing; `nodetool::arg_offline` (`net_node.h:829`) is declared and never defined (the live one is `cryptonote::arg_offline`, `cryptonote_core.cpp:112`).
- **IG-F4 — the documented per-network log file never existed** (`EXECUTABLES.md:61`; `mlog.cpp:64-82` takes `argv[0]`).
- **IG-F5 — `check_block_rate` skips on regtest** (`cryptonote_core.cpp:1621`): the R3 family. Its own deletion row.
- **IG-F6 — a Tor-only posture has no option.** A Tor-only node is a supported posture ([`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §"Tor-only is a supported posture", `:15095`), but nothing turns clearnet off: binding no clearnet listener stops clearnet inbound only; dials still go out on clearnet. `clearnet = off` is the option, and it removes clearnet from the dialer and the seed set.
- **IG-F7 — `carrier` means two things** (the Dandelion++ cover switch and the serve-credit witness carrier). §3 gives it one.
- **IG-F8 — `address` means two things** (a Shekyl address in `--start-mining`; a network location in `--add-peer`, and a URL in `shekyl-wallet-rpc --daemon-address`). §3 gives it one.
- **IG-F9 — the RPC fail-ban scorer has no caller.** `core_rpc_server::add_host_fail` (`core_rpc_server.cpp:173`) is defined and called by nothing; the bridge's comment records it as a no-op on that path (`core_rpc_ffi.cpp:84-89`). The six callers of `add_host_fail` elsewhere (`net_node.inl:1371,1456,2741,2749`, `cryptonote_protocol_handler.inl:2567,2612`) are `node_server::add_host_fail`, the P2P function, which `--disable-rpc-ban` never touched. The switch goes (R5). The dead scorer is C++ that goes when `core_rpc_server` is deleted; this cut deletes nothing beyond the option.
- **IG-F10 — the shipped unit** (`contrib/packaging/linux/shekyld.service:11`) passes `--non-interactive`, `--data-dir`, `--log-file` and no network; under IG-Q8 it drops the first, and `mainnet` applies.
- **IG-F11 — SOCKS credentials never reach Rust.** `net::socks::endpoint::get` parses `user:pass@` (`parse.cpp:267-296`), nothing in `src/p2p` or `src/shekyl` reads `userinfo`, and `shekyl_zone_listen_tor` takes a host and a port only (`shekyl_ffi.h:4484-4485`).

---

## 7. Landed text and consumers the cutover changes

- **Superseded rulings.** `V3_WALLET_DECISION_LOG.md:416-437` rules an environment layer, `--config` and XDG paths for the wallet binaries; IG-13 and R7 supersede it; the superseding entry is in the decision log (2026-10-13). `CLI_USABILITY.md:108` ("daemon flags do not change"), CU-2's hidden aliases and CU-7's diagnosing retired spellings are superseded by IG-5 and §0; Part B rewrites them.
- **Spellings inside other binaries.** `shekyl-cli`'s daemon-down copy prints `shekyld --testnet` (`rust/shekyl-cli/src/main.rs:528-529`); it changes in the cutover.
- **Consumers outside this repo, in lockstep.** `shekyl-dev` (`tools/config/*.conf.example`, `tools/config/systemd/*`, `scripts/seed/shekyld-*.service`, `stressnet/STRESSNET_PLAYBOOK.md`) and the GUI sidecar (the daemon argument list in `shekyl-gui-wallet`'s `daemon_manager.rs`, five flags) carry today's spellings. Each gets its PR, merged with the cutover, and the release that carries the cutover (alpha.11 or later) ships the new files with the binary: an old file makes the new daemon refuse to start with status 2.
- **Launchers in this repo.** The regtest harness, `drs_bench.py`, the fleet generator, the test scripts and fixture generators move to the new spellings in the cutover; under R3 regtest runs the managed Tor like every network and wipes nothing, so a harness that wants a fresh chain uses a fresh `data-dir`.

---

## 8. Questions, ruled 2026-10-13

**IG-Q1 — the rules — RULED 2026-10-13.** IG-1…IG-15 as written here, with IG-8's mainnet clause; they are the cursor rule `83-input-grammar`.

**IG-Q2 — the parser — RULED 2026-10-13.** clap's `derive` puts names in attributes, which defeats one table per binary, and its errors are its own English, outside IG-11. The parser is the shared crate's. The grammar is `--name value`, `--name=value`, switches and repeats; `--` ends options; no short flags; no abbreviation; arguments read with `std::env::args_os`, a non-UTF-8 argument refused with a typed code; suggestions from `strsim` (in the lock). A fuzz target covers the parser. clap leaves each binary as it conforms.

**IG-Q3 — the offline state — RULED 2026-10-13.** With connectors as subjects, "offline" is exactly `clearnet = off` and `tor = off`, and a `p2p-offline` switch would set that state a second way (IG-5). There is no offline option; the four postures are the product of the two connector settings (default; Tor-only; clearnet-only, warned at every start; offline, announced at every start). `core::m_offline` (`cryptonote_core.cpp:1552,1621`) and the protocol handler (`daemon.cpp:135`) read the derived fact.

**IG-Q4 — lane-owned knobs are not ported — RULED 2026-10-13.** The C++ keeps today's defaults as constants until each lane decides whether a knob exists. `drs_bench.py` loses `--block-sync-size`, `--db-sync-mode` and `--keep-fakechain`; DRS owns that loss.

**IG-Q5 — notify commands — RULED 2026-10-13.** An argument array, file only, run without a shell; the placeholders are named per row (`%h` height, `%b` block hash, …), and an unknown placeholder refuses.

**IG-Q6 — peer endpoints take no hostnames — RULED 2026-10-13.** Today `--add-peer` resolves DNS locally (`net_node.inl:520-548`), which leaks the lookup on a Tor-only node and makes the daemon a resolver. IP and onion only, and the network row's seed list likewise.

**IG-Q7 — `max-concurrency` — RULED 2026-10-13.** A cap on one C++ thread pool (`util.cpp:861`), a macOS workaround. Removed; concurrency belongs to the thread-budget work.

**IG-Q8 — the interim console — RULED 2026-10-13.** Every service unit and the GUI pass `--non-interactive`. No console unless `--console` is given, until R8 deletes it.

**IG-Q9 — absolute paths only — RULED 2026-10-13.** On both surfaces.

**IG-Q10 — integers only, IEC units only — RULED 2026-10-13.**

**IG-Q11 — `txpool-weight-max` — RULED 2026-10-13.** The default is "3 days at 300000 bytes" (`cryptonote_config.h:328`), a Monero operand. The name lands with the inherited default and a FOLLOWUPS row for the pool/economics owner to re-derive it.

**IG-Q12 — `rpc-connections-max`'s default — RULED 2026-10-13.** The only number on hand is the C++'s effective 25, which nobody derived. The cap is a resource limit, and RT-O9.4 ruled cost a resource policy separate from grants. The cutover ships the inherited value 25 with a FOLLOWUPS row for the RPC lane to derive the default under that policy, the same shape as `txpool-weight-max`.

**IG-Q13 — names — RULED 2026-10-13.** Family `IG-`; the shared crate `shekyl-options`; the daemon crate `shekyl-daemon-config`.

**IG-Q14 — no environment input (IG-13) — RULED 2026-10-13.** Default paths came from `HOME`, and the wallets read `XDG_RUNTIME_DIR` (`shekyl-wallet-rpc/src/server.rs:744`), so the environment still decided values. Home comes from the passwd entry and the Windows known-folder API. Each platform takes its per-user runtime directory from its own OS interface, never from the environment: Linux `/run/user/<uid>`; macOS `confstr(_CS_DARWIN_USER_TEMP_DIR)`; FreeBSD, or any platform without one, the typed refusal (IG-11) naming the explicit, operator-named socket directory ruled in the RPC channel round ([`RPC_CHANNEL.md`](RPC_CHANNEL.md) §7.1, 2026-10-09). Terminal reads (`shekyl-cli/src/display.rs:98-104`) stay, as presentation. Cost: a user who relocates `HOME` by environment passes `--data-dir` instead.

**IG-Q15 — `address` and `carrier` (§3, IG-F7, IG-F8) — RULED 2026-10-13.** `address` is a Shekyl address only; network locations are endpoints. `carrier` is the serve-credit witness carrier only; the cover switch is `dev-relay-cover`.

**IG-Q16 — RPC names for the ratified model — RULED 2026-10-13.** RPC_CHANNEL (ratified 2026-10-09) replaces today's listeners with the authenticated channel, the same-user socket, and an optional plaintext loopback listener at view. Naming today's full-access listener `rpc-listen` would hand that name to the channel listener later with a different meaning. `rpc-listen` is reserved for the channel listener; today's full-access listener is `rpc-admin-listen` (what it is: plaintext, loopback, admin), an X row when RT-W10 lands; `rpc-view-listen` is the ratified view listener from now on.

**IG-Q17 — an explicit `data-dir` is taken as given — RULED 2026-10-13 (the same ruling is DC-Q5 in the daemon-configuration cutover).** An explicit `data-dir` is taken as given; no network subdirectory is appended to it. The default `data-dir` keeps the network subdirectory as its default layout. The defence against a directory serving the wrong chain is a **network marker**, owned by the daemon-config lane, in Rust: written when the daemon creates its stores in a directory that holds none, recording the network id (derived from genesis) and the network name; a mismatch refuses the start with a typed code (IG-11) naming both networks and the fix; a directory holding a daemon store but no marker refuses likewise and is never marked after the fact. The marker is a separate file from the data-directory lock (DC-N1; IG-F2). DC-F1, the genesis-at-open check on the store's contents, stays with the chain-store lane as a separate check and is no longer a blocker for the cutover.

**IG-Q18 — "no inbound" — RULED 2026-10-13.** Today `--in-peers 0` turns all inbound off; with `p2p-inbound-max` ≥ 1, clearnet inbound off is `clearnet-listen none`, and the managed Tor's per-boot onion has no off. The managed ephemeral Tor is rejected in [`TOR_COVER_POSTURE.md`](TOR_COVER_POSTURE.md) §9 *as a cover configuration*, so the per-boot onion is inbound reachability (PWD-E7, default-on), not cover, and a dial-only posture loses no cover. Dial-only exists on the operator arm of this table — `tor = operator` with `tor-socks` set and `tor-onion` unset — so there is no new mode: `managed` always publishes, and an operator who wants dial-only runs the operator arm. `p2p-inbound-max` stays integer ≥ 1.

**IG-Q19 — one log budget — RULED 2026-10-13.** A file size and a file count multiply into a disk budget nobody chose (100 MiB × 50 = 5 GiB). The operator's resource is disk. One quantity, `log-size-max`, is the total for the live file and its archives; how often to rotate within it is the logging owner's. The default is 1 GiB; it is a reduction from today's effective 5 GiB (100 MiB × 50 archives, `EXECUTABLES.md:62-63`), and the release notes say so.

---

**IG-Q20 — PR-3's `--small-network` — RULED 2026-10-13.** PR-3 (head `1e189a3e8`, `src/p2p/net_node.cpp:135` `[PR-3]`) registers `--small-network` in C++ as the one ruled exception to "no new daemon option", a working name pending this table; it is read once into `shekyl_peerlist_small_network` (`src/p2p/net_node.inl:433` `[PR-3]`). The option is **`p2p-disclose-early`**, a public switch (§5): a network at genesis is small, and IG-8 accepts no `dev-` option on mainnet. The Rust symbols PR-3 adds for the switch take the name before PR-3 merges: `SMALL_NETWORK_SPAN_NANOS` becomes `P2P_DISCLOSE_EARLY_SPAN_NANOS`; `SmallNetwork` and `SmallNetworkEnd` become `DiscloseEarly` and `DiscloseEarlyEnd`; the `small_network` field, methods and test become `disclose_early`; the log line and doc comments name `--p2p-disclose-early`. The C++ option and its FFI push keep their names until the daemon-config cutover deletes them. Acceptance: `rg -n -i 'small.?network' rust/` returns nothing outside those two deletion rows.

---

## 9. Surfaces examined

Read for revision 1: all seven option-registering files linked into `shekyld` and every consumer of their options; the config-file path in `main.cpp`; `removed_flags.cpp`; the C++→Rust pushes on dev and PR-3; the RPC connection limiter; the seed-epoch and settlement overrides; the data-dir creation path; `CLI_USABILITY.md` and the CLI catalog and grammar; `shekyl-wallet-rpc`'s flags; the shipped executables list; every launcher of `shekyld` in this repo and the GUI sidecar.

Read again for revision 2, at `737da312` and `baaba2bd`: `core_rpc_server::add_host_fail` and its callers; `core_rpc_ffi.cpp`'s context comment; `set_max_in_peers` and the ceiling application in `net_node.inl`; `InboundCeiling`; the `--anonymous-inbound` loop; the miner's option read; `mlog.cpp`'s default categories; the cover switch in `command_line_args.h` and `main.cpp`; `shekyl_zone_listen_tor`'s signature; the wallet decision log entry; `shekyl-cli`'s daemon-down copy. The `shekyl-dev` and GUI consumer list is the implementing lane's grep, not re-run here.

Not read: the C++ console handlers' argument grammars (Part B), the Rust daemon console (Part B), the utilities' option sets (Part B), the GUI's settings screen, the mobile tree.
