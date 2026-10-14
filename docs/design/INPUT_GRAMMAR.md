# Shekyl input grammar — Round 0, Part A (the rules) and the daemon's names

**Status:** RULED 2026-10-13 (Rick) — Round 0, Part A. IG-Q1…IG-Q20 ruled as
proposed at revision 3 with the amendments carried in-line (IG-8, the
`config-file` row, IG-Q12, IG-Q14); IG-Q17 and IG-Q20 were ruled on their
own the same day. The
rules IG-1…IG-15 are the cursor rule
[`83-input-grammar`](../../.cursor/rules/83-input-grammar.mdc); this document
holds the glossary tree and the name tables. Part B (the name tables of
`shekyl-cli`, `shekyl-wallet-rpc`, the consoles and the utilities) is
brought to the maintainer for ruling before anything lands: §10–§15 are
Part B, DRAFT, each heading saying so.
**Verified against:** `shekyl-core` @ `737da3127` (`dev`; the option surface
is unchanged from `2c3fae3c`, only `rpc_facts_ffi.*` moved) and PR-3 (#1056,
`feat/p2p3-dialer-cutover`) @ `fce0a2fa`. Reviewed at **`737da3127`**. Every
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
- **Config (R2, R6, R7):** TOML; the network picks the file (`/etc/shekyl/shekyld-<network>.toml`); `--network` is command-line only; `--config-file` replaces the default path whole; the CLI replaces the file per key, lists whole; the file is validated whole before anything applies; ownership and permission checks; file keys are the option names exactly; one startup line shows every effective value and its source (a secret is shown as set, never its value: IG-6). No environment-variable layer in any binary. Credentials are typed secrets (R9).
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
| origin | `--x https://host:443` | string | an explicit web origin (RFC 6454): scheme `http` or `https`, a host, an optional port, nothing after; `*` is refused |
| path | `--x /abs/path` | string | absolute only |
| secret | not accepted | string | file only; never logged or echoed, and shown in the startup line only as set; zeroized; held only in Rust |
| command | not accepted | array of strings `["/path/prog", "arg", "{height}"]` | file only; run without a shell; placeholders are `{name}`, each name a glossary term under the row with one meaning everywhere; braces are the only syntax, `%` is literal; an unknown name refuses |
| list (of a scalar kind) | the flag repeated | an array under the same key | the keyword `none` is the empty list; a CLI list replaces the file's list whole |
| map (of a scalar kind) | `--x key=value`, repeated | a table under the same key | keys are a closed set named in the row; a CLI map replaces the file's map whole |

A row narrows its kind with a constraint stated in the row and enforced by its constructor (a range, "global unicast only", "onion only"). A row may admit named keywords from the closed keyword set alongside its kind (`unlimited`, `auto`). A row with no default is *unset* when not given, and the row states what unset means; there are no sentinel values. There are no floating-point values anywhere in the grammar.

**IG-7 Surfaces.** Each row says where it may be given. Command-line only: `help`, `version`, `network`, `config-file`. File only: every secret and every command value. Everything else: both, CLI winning per key.

**IG-8 Development levers.** A `dev-` option is hidden from help and generated docs, names the networks it is accepted on as data in its row (a `dev-` option given on any other network is refused at parse, rule 71), and is announced at every start when set. It follows every other rule. **No `dev-` option is ever accepted on mainnet**: a lever mainnet genuinely needs is not a development lever and gets a public row.

**IG-9 One table per binary, generated everything.** The table row: id, name, kind, constraint, keywords, default (a value, unset, or "derived from the network row"), surfaces, visibility (`public` / `dev` / `rejected` / `reserved`), accepted networks (`dev` only), owning subsystem, help text. From the table: `--help`, completion, the documentation tables, and an annotated TOML example. A gate regenerates the docs and diffs them, and asserts the table is non-empty (rule 47).

**IG-10 Unknown and refused names.** An unknown name is one general refusal that names the nearest live name, computed from the table (edit distance), never from a hand list. A REJECTED row (a feature deliberately refused) carries its reason and a pointer to the decision; it is never accepted, never in help, and its refusal states the reason. A REJECTED row is a contract entry in the sense of rule 23, not a code symbol: it is never deleted as dead. A RESERVED row (a name held for a ruled future option; rule 23's reserved slot) is the same kind of entry: never accepted, never in help, and its refusal names what the name is reserved for and where that is ruled.

**IG-11 Diagnostics.** Every refusal is a typed value: a stable code (`config.value.range`, `config.file.permissions`, …), the option, the source (`cli`, `file:path:line`, `default`) and named parameters. One renderer turns it into the English message, which states what was wrong, where, and what to do (rule 82). Machine output and logs carry the code. A configuration refusal exits with status 2; a runtime failure with 1.

**IG-12 Runtime changes share the constructor.** A value that can also change while running (rates, inbound cap, log level, mining) is built by the same constructor on both surfaces, with the same refusals. The live value is owned by its subsystem. No binary ever writes its own config file.

**IG-13 Inputs come from the table, and nowhere else.** No option value comes from the environment. Default paths come from the operating system's account and known-folder interfaces (the passwd entry's home on Unix, the known-folder API on Windows), not from `HOME`, `XDG_*` or `%APPDATA%`. The only environment reads permitted are presentation-only (terminal capabilities that change rendering, never a value). Every resolved default path appears in the startup line with its source. A service account whose passwd home is unset or `/nonexistent` has no default paths: the packaging sets the account's home or the unit passes `--data-dir` and `--log-file` (the shipped unit does both, IG-F10).

**IG-14 Required announcements are not log events.** The effective-configuration line, `dev-` lever warnings and posture warnings (clearnet-only, offline) reach the log and standard error at every start whatever the log level. The effective-configuration line shows every value and its source; a secret is shown as set, never its value (IG-6).

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
| height | block, reorg, split | a block height: under `block` the new block's, under `reorg` the new tip's, under `split` the last block both chains share |
| hash | block | the new block's hash |
| split | reorg | the point where the two chains part (`{split-height}`) |
| added | reorg | blocks in the new chain |
| removed | reorg | blocks discarded from the old chain |
| window | rate | the observation window, in seconds |
| observed | rate | blocks seen in the window |
| expected | rate | blocks expected in the window |
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
| `p2p-disclose-early` `[PR-3]` | `p2p-disclose-early` | switch | off | both | K (IG-Q20); for bootstrapping or testing a network smaller than the white-diversity floor (48): this node discloses its known peers and its own address below the floor, on each connector until that connector's white count reaches the floor or the span `P2P_DISCLOSE_EARLY_SPAN_NANOS` ends it, whichever comes first; announced at start (IG-14) |
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
| `block-notify` | `notify-block` | command | unset | file | R (IG-Q5); placeholders `{height}`, `{hash}` |
| `reorg-notify` | `notify-reorg` | command | unset | file | R (IG-Q5); placeholders `{split-height}` (the last block both chains share), `{height}` (the new tip), `{added}` (blocks in the new chain), `{removed}` (blocks discarded) |
| `block-rate-notify` | `notify-block-rate` | command | unset | file | R (IG-Q5); placeholders `{window}` (the window in seconds), `{observed}`, `{expected}` |
| `start-mining` | `mining-address` | address | unset | both | R; set means mine from start |
| `mining-threads` | `mining-threads` | integer ≥ 1, or `auto` | `auto` | both | K; one default for starting the miner on every surface: `shekyl-cli mine start` with no count is `auto` (`grammar.rs:539-540`); the miner's owner defines `auto` once |
| `bg-mining-*` (5) | — | | | | X (Monero background mining) |

### RPC, named for the ratified RPC_CHANNEL model

| Today | New | Kind | Default | Surface | Notes |
|---|---|---|---|---|---|
| — | `rpc-listen` | list of endpoint | | | visibility `reserved` (IG-9, IG-10): held for the authenticated channel listener (RT-W10); not accepted in this cut |
| `rpc-bind-ip`, `rpc-bind-port`, `rpc-bind-ipv6-address`, `rpc-use-ipv6` | `rpc-admin-listen` | list of endpoint, loopback only | `127.0.0.1:<row rpc port>` | both | R; the interim plaintext full-access listener; loopback only by RT-14 (a plaintext listener never binds beyond loopback; only the authenticated channel listener may bind wildcard); becomes an X row when RT-W10 lands (IG-Q16) |
| `restricted-rpc`, `rpc-restricted-bind-port`, `rpc-restricted-bind-ip`, `rpc-restricted-bind-ipv6-address` | `rpc-view-listen` | list of endpoint, loopback only | `none` | both | R; survives RT-W10 unchanged (plaintext loopback at view, off by default, ruled 2026-10-08); the GUI sidecar passes `--rpc-admin-listen none --rpc-view-listen 127.0.0.1:<port>` |
| `rpc-access-control-origins` | `rpc-cors-origin` | list of origin | `none` | both | R; explicit web origins only, `none` is CORS default-deny; `*` is refused: a wildcard lets any page in the operator's browser read and drive the plaintext admin listener |
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

**Count:** 83 registered options and 4 environment levers today, plus PR-3's `p2p-disclose-early`; 48 live names after, the four levers among them (unchanged at RT-W10: `rpc-listen` arrives and `rpc-admin-listen` becomes an X row).

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

**IG-Q5 — notify commands — RULED 2026-10-13, amended the same day.** An argument array, file only, run without a shell. Placeholders are named, `{name}`, where each name is a glossary term under its notify row (§3) and has one meaning everywhere; an unknown name refuses; braces are the only syntax, so `%` is literal. The sets, as designed and not as today's substitutions: `notify-block` `{height}`, `{hash}`; `notify-reorg` `{split-height}`, `{height}`, `{added}`, `{removed}`; `notify-block-rate` `{window}`, `{observed}`, `{expected}` (§5).

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

**IG-Q20 — PR-3's disclose-early switch — RULED 2026-10-13, amended the same day.** PR-3 registers one new C++ option as the one ruled exception to "no new daemon option", born under a working name and renamed in PR-3 at `fce0a2fa`: `arg_p2p_disclose_early` registering `p2p-disclose-early` (`src/p2p/net_node.cpp` `[PR-3]`), read once into `shekyl_peerlist_disclose_early`. The option is **`p2p-disclose-early`**, a public switch (§5): a network at genesis is small, and IG-8 accepts no `dev-` option on mainnet. The Rust symbols take the name in PR-3 too: `P2P_DISCLOSE_EARLY_SPAN_NANOS`, `DiscloseEarly` and `DiscloseEarlyEnd`, the `disclose_early` field, methods and test; the log line and doc comments name `--p2p-disclose-early`. The daemon-config cutover deletes the C++ option and its FFI push under these names. Acceptance: `rg -n -e 'small_network' -e 'SmallNetwork' -e 'SMALL_NETWORK' -e 'small-network' src rust docs` returns only PR-3's UNFREEZE record of the rename.

---

## 9. Surfaces examined

Read for revision 1: all seven option-registering files linked into `shekyld` and every consumer of their options; the config-file path in `main.cpp`; `removed_flags.cpp`; the C++→Rust pushes on dev and PR-3; the RPC connection limiter; the seed-epoch and settlement overrides; the data-dir creation path; `CLI_USABILITY.md` and the CLI catalog and grammar; `shekyl-wallet-rpc`'s flags; the shipped executables list; every launcher of `shekyld` in this repo and the GUI sidecar.

Read again for revision 2, at `737da312` and `baaba2bd`: `core_rpc_server::add_host_fail` and its callers; `core_rpc_ffi.cpp`'s context comment; `set_max_in_peers` and the ceiling application in `net_node.inl`; `InboundCeiling`; the `--anonymous-inbound` loop; the miner's option read; `mlog.cpp`'s default categories; the cover switch in `command_line_args.h` and `main.cpp`; `shekyl_zone_listen_tor`'s signature; the wallet decision log entry; `shekyl-cli`'s daemon-down copy. The `shekyl-dev` and GUI consumer list is the implementing lane's grep, not re-run here.

Not read: the C++ console handlers' argument grammars (Part B), the Rust daemon console (Part B), the utilities' option sets (Part B), the GUI's settings screen, the mobile tree.


---

## 10. Part B — the wallet binaries, the console and the utilities — DRAFT for ruling (2026-10-14)

Part B names every identifier of `shekyl-cli`, `shekyl-wallet-rpc`, the daemon's console and the utilities under the ruled rules (IG-1…IG-15) and glossary (§3). Each section below carries its own status in its heading; nothing in §10–§15 is ruled until marked. Verified against `shekyl-core` @ `7cf70b705` (`dev`). A name shared with the daemon's table (`network`, `config-file`, `log-*`) has a row here only where its kind, default or surface differs; otherwise the daemon's row (§5) is the row, and one meaning everywhere (IG-2) is what makes that possible.

**What Part B found, before the tables.** Two collisions the tree exposes are put to the maintainer first (IG-Q21, IG-Q22); kinds the wallet surfaces need and §2 lacks (IG-Q23); one secret taken on a prompt line (IG-Q24); the console's forty-four words, which R8 deletes into `shekyl-cli` (IG-Q25); the keep-or-delete per utility that DC-Q12 routed here (IG-Q26); and the scope of the gate (IG-Q27).

## 11. Glossary — the wallet subtree and the console's terms (v0) — DRAFT for ruling

Rows below add to §3. A term already in §3 that gains a parent here keeps its one meaning; where Part B needs the meaning widened, the row says so and IG-Q32 puts the widening to the maintainer (`password`, `address`, `rpc`, `relay`, `difficulty`, `height`, `connections`). Verbs are terms of kind *verb* under their subject (IG-3).

| Term | Parents | Meaning |
|---|---|---|
| wallet | — | the wallet: its files and its operations |
| daemon | — | the daemon a wallet binary talks to |
| script | — | a file of prompt lines run as one session |
| json | — | machine output: one object per command |
| debug | — | show the machine detail of a failure |
| tx | — | a transaction |
| request | — | a payment request |
| uri | — | a `shekyl:` payment URI |
| stake | — | the staking balance and bond |
| shard | — | an archival shard |
| mine | — | mining control (IG-Q21: one spelling with `mining`) |
| prove | — | make a proof |
| check | — | check a proof |
| sign | — | sign a message with the wallet key |
| verify | — | verify a signature |
| balance | —, stake | a balance breakdown |
| send | — | send money |
| fee | — | a fee quote |
| status | —, wallet, stake, mine, sync | the current state (IG-Q33) |
| chain | — | the chain the daemon holds |
| exit | — | leave the prompt |
| stop | —, mine | stop |
| key | tx | a key image |
| peer | p2p, closed, — | another Shekyl node |
| archival | dev, — | the archival layer |
| sync | dev, — | chain synchronization |
| block | notify, — | a block |
| ban | p2p, — | a host or subnet refused at socket admission |
| rpc | —, wallet | an RPC service: the daemon's, or the wallet's |
| file | config, log, ban, wallet, script, mnemonic, password, socket, png, address | a file path (value term) |
| dir | data, wallet | a directory path (value term) |
| password | socks, wallet, rpc | a secret credential; always a secret (IG-Q32 widens Part A's row) |
| username | socks, rpc | a credential's name |
| socks | clearnet, tor, daemon | the SOCKS5 endpoint dialled through |
| endpoint | daemon, rpc | a literal IP and port |
| socket | daemon, rpc | the local socket of RPC_CHANNEL RT-15 |
| mnemonic | wallet | the wallet's recovery words (IG-Q24: never on a command line) |
| stdin | password | read from standard input |
| name | wallet | a wallet's name |
| direction | list | `in` or `out` |
| unmatched | list | receives matching no request |
| matched | list | requests already paid |
| all | list | every entry |
| held | list | the shards this wallet holds |
| amount | send, request, uri, stake, prove | a decimal SKL amount (kind `amount`, IG-Q23) |
| label | request, uri | a human label |
| expiry | new | when a request stops being valid: a duration or a unix time |
| priority | send | `economy`, `standard` or `high` |
| yes | send, stake, tx | confirm without a prompt |
| full | address | the whole address, not the display form |
| address | mining, uri, send, check, verify, mine, — | a Shekyl address (Part A's meaning, widened to the wallet's rows); bare, the wallet's primary address |
| count | input, output | how many |
| input | fee | a transaction input |
| output | fee | a transaction output |
| image | key | a key image |
| spent | image | whether it is spent |
| message | sign, prove, check, verify | free text, the rest of the line |
| signature | verify | a signature |
| id | tx, shard | an identifier: a transaction hash or a shard number |
| text | note | free text |
| png | fetch | a PNG image of the shard |
| pixels | png | the image's side, in pixels |
| complete | archival | the whole corpus |
| tree | complete | the CompleteTree posture (IG-Q28) |
| acknowledge | archival | the acknowledgement phrase that posture requires |
| short | list | the short form |
| from | show, list, sum | the first height |
| to | show, list | the last height |
| last | stats | the most recent N blocks |
| hex | show | print the raw bytes as hex |
| hard | rescan | rebuild from the chain |
| seconds | add | a duration in seconds |
| alt | chain | the alternative chains |
| coinbase | chain | coinbase outputs |
| sum | coinbase | a total |
| stats | chain, peer, txpool, p2p | statistics |
| white | list | the white peer list |
| gray | list | the gray peer list |
| create | wallet | verb |
| open | wallet | verb |
| close | wallet | verb |
| restore | wallet | verb |
| refresh | wallet | verb |
| rescan | wallet | verb |
| list | tx, request, shard, peer, ban, txpool, chain | verb |
| show | tx, shard, chain, block, ban | verb |
| note | tx | verb |
| abandon | tx | verb |
| relay | dev, tx | transaction relay; as a verb, relay this transaction |
| new | request | verb |
| make | uri | verb |
| read | uri | verb |
| outputs | stake | verb: list the staking outputs |
| available | stake | verb |
| add | stake, ban | verb |
| return | stake | verb |
| release | stake | verb |
| collect | stake | verb |
| join | stake | verb |
| fetch | shard | verb |
| start | mine | verb |
| payment | prove, check | a payment proof |
| reserve | prove, check | a reserve proof |
| remove | ban | verb |
| flush | txpool | verb |
| pop | chain | verb (IG-Q25: `dev-`?) |
| connections | rpc, peer | concurrent connections; the live peer connections |
| difficulty | dev, chain | the difficulty |
| height | block, reorg, split, chain, restore | a block height |

Value keywords added: `in`, `out` (direction), `economy`, `standard`, `high` (priority), `white`, `gray`.

## 12. The wallet binaries' name tables — DRAFT for ruling

Legend as §5: **R** rename or fold, **K** kept, **X** REJECTED row, **–** removed with no trace, **N** new.

### 12.1 `shekyl-cli` — options

| Today | New | Kind | Default | Surface | Notes |
|---|---|---|---|---|---|
| `help`, `version` | same | switch | | CLI | K |
| `network`, `testnet`, `stagenet` | `network` | one-of | `mainnet` | CLI | R; the two shorthand flags are aliases (IG-5) and go |
| — | `config-file` | path | `/etc/shekyl/shekyl-cli-<network>.toml` | CLI | N; the wallet binaries' TOML file the decision log ruled, under Part A's shape (IG-Q29) |
| `wallet-dir` (alias `engine-dir`) | `wallet-dir` | path | account home + `.shekyl/wallets/<network>` | both | K; alias gone (IG-5) |
| `wallet` (alias `engine-file`) | `wallet-file` | path | unset | both | R (IG-3: a path ends in `file`); alias gone |
| `daemon-address` | `daemon-endpoint` | endpoint | `127.0.0.1:<row rpc port>` | both | R (IG-Q31); a hostname or URL is refused |
| (`daemon-address` `uds://`) | `daemon-socket-file` | path | unset | both | N (IG-Q31); RT-15's local leg; unconstructible together with `daemon-endpoint` |
| `rpc-url` | `wallet-rpc-endpoint` | endpoint | unset | both | R (IG-Q31); set means an external `shekyl-wallet-rpc`, not self-hosting |
| (`rpc-url` `uds://`) | `wallet-rpc-socket-file` | path | unset | both | N; unconstructible together with `wallet-rpc-endpoint` |
| `proxy` | `daemon-socks` | endpoint | unset | both | R; the dial to the daemon goes through it; no scheme is spelled (SOCKS5, names resolved remotely) |
| `daemon-ca-cert` | — | | | | X (RT-O8: the `https://` arm is deleted in RT-W12; the channel replaces TLS) |
| `debug` | `debug` | switch | off | both | K; prints the machine detail (`error.data`) of a failure |
| `password-file` | `wallet-password-file` | path | unset | both | R; a file holding the wallet password; required when stdin is not a terminal |
| `complete-tree-foundation` (hidden) | `archival-complete-tree` | switch | off | both | R (IG-Q28): a public row; hidden-but-not-`dev` has no visibility (IG-9) |
| `acknowledge` (hidden) | `archival-acknowledge` | one-of (the ruled phrase) | unset | CLI | R (IG-Q28) |
| `json` | `json` | switch | off | CLI | K |
| `script` | `script-file` | path | unset | CLI | R |
| — | `log-file`, `log-level`, `log-category`, `log-size-max` | as §5 | as §5, the file `shekyl-cli-<network>.log` | both | N; the daemon's rows apply |

### 12.2 `shekyl-cli` — the scripted subcommands' options

| Today | New | Kind | Surface | Notes |
|---|---|---|---|---|
| `create --seed-out` | `wallet create --mnemonic-file` | path | CLI | R (IG-Q24: the recovery words are written to a new `0600` file, never printed under `--json`) |
| `create --password-file`, `--password-stdin` | `--wallet-password-file`, `--wallet-password-stdin` | path; switch | CLI | R; the two are unconstructible together |
| `restore --seed-file` | `wallet restore --mnemonic-file` | path | CLI | R |
| `restore --restore-height` | `--wallet-restore-height` | integer | CLI | R |

### 12.3 `shekyl-cli` — command words

The prompt's forms today are bare noun, subject plus verb, and product verb (CU-7). Under IG-3 a command is `<path> <verb>`; a bare word is a subject whose one action needs no verb. The table lists the ruled form, positional kinds, and flags; flags are names under the command's last word.

| Today | New | Positionals (kinds) | Flags | Notes |
|---|---|---|---|---|
| `wallet` | `wallet status` | | | R (IG-Q33: `status` is a verb everywhere) |
| `wallet create <name>` | same | name | | K |
| `wallet open <name>` | same | name | | K |
| `wallet close` | same | | | K |
| `wallet restore <name> <seed...>` | `wallet restore <name>` | name | `--mnemonic-file <path>` | R (IG-Q24: the words come from a file or a hidden prompt, never the line) |
| `wallet password` | same | | | K |
| `wallet refresh` | same | | | K |
| `wallet rescan [hard]` | `wallet rescan` | | `--hard` | R |
| `balance` | `balance` | | | K |
| `send <amount> <address> [--priority p] [--yes]` | same | amount, address | `--priority` one-of; `--yes` | K |
| `fee [--inputs N] [--outputs N]` | `fee` | | `--input-count`, `--output-count` integer | R (IG-Q22: `outputs` is a stake verb) |
| `address [--full \| --out <path>]` | `address` | | `--full`; `--file <path>` | R (IG-Q22: `out` is a direction) |
| `status` | `wallet status` | | | R (IG-Q33) |
| `chain` | `chain` | | | K |
| `version`, `help [command]`, `exit` (`quit`) | same; `quit` goes | | | K; the synonym is an alias (IG-5) |
| `tx list [--in \| --out] [--unmatched]` | `tx list` | | `--direction in\|out`; `--unmatched` | R (IG-Q22) |
| `tx show <id>` | same | id | `--hex` (the console's `+hex`) | K |
| `tx note <txid> [<text...>]` | same | id, text | | K |
| `tx abandon <txid>` | same | id | | K |
| `request new <amount> <label> [--expiry e]` | same | amount, label | `--expiry` quantity (duration) or integer (unix time) | K |
| `request list [--matched \| --all]` | same | | `--matched`; `--all` | K |
| `uri make [--amount X] [--label L] [--address A]` | same | | `--amount`; `--label`; `--address` | K |
| `uri read <uri>` | same | uri (string) | | K |
| `stake` | `stake status` | | | R (IG-Q33) |
| `stake balance`, `stake outputs`, `stake available` | same | | | K |
| `stake add <amount> [--yes]`, `stake return <amount> [--yes]` | same | amount | `--yes` | K |
| `stake release [--yes]`, `stake collect` | same | | `--yes` | K |
| `stake join <shard-id>...` | same | id… | | K |
| `shard list`, `shard list all`, `shard list mine` | `shard list`, `shard list all`, `shard list held` | | | R (`mine` is the mining subject) |
| `shard show <id>` | same | id | | K |
| `shard fetch <id> [--png p] [--size s]` | same | id | `--png-file <path>`; `--png-pixels` integer | R (`size` is the log budget) |
| `mine start [threads\|auto]`, `mine stop`, `mine status` | same (IG-Q21) | integer or `auto` | | K |
| `prove payment <txid> <address> [message...]`, `prove reserve [amount] [message...]` | same | id, address, message; amount, message | | K |
| `check payment <txid> <address> <proof> [message...]`, `check reserve <address> <proof> [message...]` | same | | | K |
| `sign <message...>`, `verify <address> <signature> <message...>` | same | | | K |
| the `RETIRED` table (`transfer`, `transfers`, `show_transfer`, `get_tx_note`, `set_tx_note`, `abandon`, `stake_in`, `drain`, `drain_balance`, `unstake`, `stake exit`, `collect_unstaked`, `get_tx_proof`, `check_tx_proof`, `get_reserve_proof`, `check_reserve_proof`, `start_mining`, `stop_mining`, `mining_status`, `chain_health`, …) | — | | | – (IG-Q30: §0 rules no migration table; none names a refused feature) |

### 12.4 `shekyl-wallet-rpc` — options

| Today | New | Kind | Default | Surface | Notes |
|---|---|---|---|---|---|
| `help`, `version` | same | switch | | CLI | K |
| `network` | `network` | one-of | `mainnet` | CLI | K |
| — | `config-file` | path | `/etc/shekyl/shekyl-wallet-rpc-<network>.toml` | CLI | N (IG-Q29) |
| `wallet-dir` | `wallet-dir` | path | account home + `.shekyl/wallets/<network>` | both | K; today's `.` is relative (IG-Q9) |
| `rpc-bind` (IP:port) | `rpc-listen` | endpoint, loopback unless credentials are set | `127.0.0.1:29500` | both | R; a wildcard is refused (RT-1); the daemon's table reserves the same name for the same meaning (IG-10) |
| `rpc-bind` (`uds://`) | `rpc-socket-file` | path | unset | both | N; Unix only; refused on Windows |
| `rpc-login` | `rpc-username`, `rpc-password` | secret | unset | file | R (IG-Q29); both set or neither; a non-loopback `rpc-listen` with neither is refused |
| `disable-rpc-login` | — | | | | – (IG-4; "no credentials" is the absence of the two rows, accepted on loopback or a socket) |
| `daemon-address` | `daemon-endpoint`, `daemon-socket-file` | endpoint; path | `127.0.0.1:<row rpc port>`; unset | both | R (IG-Q31) |
| `proxy` | `daemon-socks` | endpoint | unset | both | R |
| `log-file` | `log-file`, with `log-level`, `log-category`, `log-size-max` | as §5 | the file `shekyl-wallet-rpc-<network>.log` | both | K; the daemon's rows apply |

## 13. The daemon console — DRAFT for ruling (IG-Q25)

The console's forty-four C++ words (`src/daemon/command_server.cpp`) and the twenty methods the Rust console already renders (`rust/shekyl-daemon-rpc/src/console/mod.rs`) are one surface that R8 moves into `shekyl-cli` (DC-N2, blocked on RT-15). This table gives each word its `shekyl-cli` form under IG-3; whether the interim C++ console is renamed to it or deleted unrenamed is IG-Q25.

| Today | New | Positionals / flags | Notes |
|---|---|---|---|
| `help [cmd]`, `apropos <kw>...` | `help [command]` | | `apropos` folds into `help` |
| `print_height` | `chain height` | | |
| `print_bc <from> [<to>]` | `chain show` | `--from`, `--to` integer | |
| `bc_dyn_stats <n>` | `chain stats` | `--last` integer | |
| `alt_chain_info [hash]` | `chain alt [hash]` | hash | |
| `print_coinbase_tx_sum <from> [<count>]` | `chain coinbase sum` | `--from`, `--last` | |
| `diff` | `chain difficulty` | | |
| `pop_blocks <n>` | `dev-chain-pop <n>` | integer | IG-8: a destructive lever, regtest only; or an X row |
| `print_block <hash\|height>` | `block show <hash\|height>` | hash or integer | |
| `print_tx <hash> [+hex] [+json]` | `tx show <id>` | `--hex`; `--json` is the session's | shares the wallet's word |
| `relay_tx <txid>` | `tx relay <id>` | id | |
| `is_key_image_spent <ki>` | `tx key image spent <image>` | hash | |
| `print_pool`, `print_pool_sh`, `print_pool_stats`, `flush_txpool [txid]` | `txpool list [--short]`, `txpool stats`, `txpool flush [id]` | | |
| `print_pl [white] [gray] [limit]`, `print_pl_stats`, `print_cn`, `print_net_stats` | `peer list [--white] [--gray] [--max N]`, `peer stats`, `peer connections`, `p2p stats` | | |
| `limit [kB/s]`, `limit_up`, `limit_down` | `p2p-upload-max <rate\|unlimited>`, `p2p-download-max <rate\|unlimited>` | quantity (rate) | IG-12: the option name is the command; `limit` (both at once) is one option per value and goes |
| `out_peers <n>` | — | | X: the option is deleted (§5) |
| `in_peers <n>` | `p2p-inbound-max <n>` | integer ≥ 1 | IG-12 |
| `bans`, `ban <ip\|@file> [secs]`, `unban <ip>`, `banned <ip>` | `ban list`, `ban add <ip> [--seconds N]`, `ban remove <ip>`, `ban show <ip>` | an IP; a file is `p2p-ban-file` | |
| `start_mining <addr> [threads\|auto] [bg] [battery]`, `stop_mining`, `mining_status`, `show_hr`, `hide_hr` | `mine start <address> [threads\|auto]`, `mine stop`, `mine status` | | the background arguments go with `bg-mining-*` (§5); the hash-rate display is `mine status` |
| `set_log <level\|categories>` | `log-level <level>`, `log-category <k=v>...` | one-of; map | IG-12 |
| `status`, `print_status`, `sync_info` | `status`, `sync status` | | `print_status` is a duplicate |
| `stop_daemon`, `exit` | `stop` | | one word for one act |
| `save`, `flush_cache [bad-txs] [bad-blocks]` | — | | –: LMDB and C++ cache internals; nothing to switch once the Rust store owns commits |
| `version` | `version` | | |

## 14. The utilities — DRAFT for ruling (IG-Q26, IG-Q27)

DC-Q12 routed keep-or-delete per tool here. The recommendation column is the lane's; the ruling is the maintainer's. A kept tool gets its table in the ruling commit; a deleted one gets no row (an implementation, not a refused feature) unless the maintainer names it a refused feature.

| Binary | Options today | Recommendation | Reason |
|---|---|---|---|
| `shekyl-blockchain-import`, `-export` | `input-file`/`output-file`, `log-level`, `block-start`, `block-stop`, `batch-size`, `pop-blocks`, `dangerous-unverified-import`, `batch`, `resume`, plus `data-dir`, `testnet`, `stagenet` | delete | Monero bootstrap-file tools over LMDB; the Rust corpus tools (`shekyl-chain-replay fetch` / `replay`) are the successor, and DRS's store replaces LMDB |
| `shekyl-blockchain-usage`, `-ancestry`, `-depth`, `-stats` | `rct-only`, `with-ringsize`, `txid`, `output`, `height`, `cache-*`, `with-*`, … | delete | ring-signature-era analytics (`rct-only`, `ringsize`) with no referent under FCMP++ (rule 60) |
| `shekyl-mdb-copy` | LMDB's own | delete with LMDB | DRS's redb cutover; until then it is LMDB's tool, not ours to name |
| `shekyl-gen-ssl-cert` | `certificate-filename`, `private-key-filename`, `passphrase`, `passphrase-file`, `prompt-for-passphrase` | delete | RT-11: the RPC channel replaces TLS; the `rpc-ssl-*` rows are already X (§5) |
| `shekyl-gen-trusted-multisig` | documented in `EXECUTABLES.md` §4 | the doc row goes | the binary does not exist in the tree (the C++ wallet was deleted in Phase 5) |
| `shekyl-utils-deserialize` (`cn_deserialize`), `shekyl-utils-object-sizes` | `input`, `log-level`; none | delete | C++ debug tools; `tx show --hex` and the Rust codecs' tests cover the need |
| `shekyl-e2-trace-export` (opt-in build) | `out`, `block-start`, `block-stop`, `data-dir`, network | DRS-E2's | the replay driver's own tool; its table is that lane's if it ships |
| `geblock` (`shekyl-genesis-tool`) | subcommands `gen-wallets`, `build`, `verify`, `block-id`; `--network`, `--out-dir`, `--recipients`, `--config`, `--recipients-dir` | table it (IG-Q27) | the genesis ceremony tool; not on the shipped list but every operator of the ceremony types its names |
| `shekyl-chain-replay`, `shekyl-wss-q1b-bench` | clap | out of the gate (IG-Q27) unless ruled in | development and benchmark tools, never shipped |

## 15. Questions for Part B — DRAFT for ruling

**IG-Q21 — `mining` and `mine`.** One tree, one spelling: the daemon's rows are `mining-address` and `mining-threads` (§5, ruled); the wallet's commands are `mine start`, `mine stop`, `mine status` (CU-3, landed). Proposal: the subject is `mine` everywhere, and §5's two rows become `mine-address` and `mine-threads` in the ruling commit (a Part A rename the maintainer authorizes); the console's `mine start` takes the address the daemon's row would otherwise hold.

**IG-Q22 — `out`, `outputs` and `size`.** `address --out <path>` is a path, `tx list --out` a direction, `fee --outputs N` a count, `stake outputs` a verb, `shard fetch --size` pixels while `log-size-max` is disk. IG-2 allows one meaning. Proposal: `address --file`, `tx list --direction in|out`, `fee --input-count` / `--output-count`, `shard fetch --png-file` / `--png-pixels`.

**IG-Q23 — kinds the wallet needs.** §2 has no `amount`, `id`, `name` or `text` kind. Proposal: `amount` is a decimal SKL string with at most nine places, parsed exactly to atomic units by `shekyl-units` (a fixed-point decimal, not a float); `id` is a 64-hex transaction hash or a decimal shard number, as the row says; `name` is a wallet file name (one path component, no separators); `text` is the rest of the line, verbatim. Durations reuse the quantity kind (`1h`, `7d`); `--expiry` also admits an integer unix time.

**IG-Q24 — a secret on a prompt line.** `wallet restore <name> <seed...>` takes the recovery words on the line; IG-6 says a secret is never accepted on the command line, and a `--script` file is a command line. Proposal: `wallet restore <name> --mnemonic-file <path>` and, at a terminal, a hidden prompt; the words never appear in a line, a history or a script.

**IG-Q25 — the console.** R8 moves the console into `shekyl-cli`; renaming forty-four interim C++ words that R8 deletes is rule-15 churn. Proposal: §13 is the catalog both the Rust console and `shekyl-cli` serve; the C++ console is not renamed and dies with R8; until then the Rust console's twenty methods already render through one export and take §13's words at the cutover.

**IG-Q26 — the utilities.** Rule per row of §14.

**IG-Q27 — the gate's scope.** "Every shipped binary" is `EXECUTABLES.md`'s list; `geblock` is not on it and is typed by the ceremony's operators; `shekyl-chain-replay` and the bench are never shipped. Proposal: the gate's subject is every binary a release or a ceremony ships, named as a list the gate asserts non-empty (rule 47); development tools follow the rules by convention and are not in the gate.

**IG-Q28 — hidden flags that are not `dev-`.** `--complete-tree-foundation` and `--acknowledge` are hidden today; IG-9 has no visibility for a hidden public option. Proposal: `archival-complete-tree` (public, documented as the Foundation posture) and `archival-acknowledge` (one-of: the ruled phrase).

**IG-Q29 — the wallet binaries' file and credentials.** The decision log ruled TOML for the wallet binaries and Part A superseded its environment layer. Proposal: `config-file` under Part A's shape (`/etc/shekyl/<binary>-<network>.toml`), and `rpc-username` / `rpc-password` as file-only secrets replacing `--rpc-login`, with `--disable-rpc-login` gone (IG-4): no credentials is the absence of the rows, accepted on loopback or a socket only.

**IG-Q30 — the `RETIRED` table and `quit`.** §0 rules no migration table and no aliases. Proposal: the table and the synonym go; none of its rows names a refused feature, so no X row.

**IG-Q31 — the daemon and wallet-RPC addresses.** `--daemon-address` and `--rpc-url` take `http://host:port` or `uds:///path`, neither an endpoint. Proposal: `daemon-endpoint` (endpoint) and `daemon-socket-file` (path), unconstructible together; `wallet-rpc-endpoint` and `wallet-rpc-socket-file` the same; a hostname is refused (IG-Q6's reason: a resolver leaks).

**IG-Q32 — Part A rows Part B widens.** `password` (§3: "SOCKS5 credentials") becomes "a secret credential; always a secret", with parents `socks`, `wallet`, `rpc`; `address` gains the wallet's parents and is also a subject (the bare command); `rpc` gains parent `wallet`; `relay`, `difficulty`, `height`, `connections` gain the console's parents. Meanings do not change; parents do.

**IG-Q33 — `status`.** A bare `status` command, `mine status` and `sync status` make `status` both a subject and a verb. Proposal: `status` is a verb everywhere (`wallet status`, `stake status`, `mine status`, `sync status`); the daemon's bare `status` stays as the one subject-less word, or becomes `daemon status` when the console moves.
