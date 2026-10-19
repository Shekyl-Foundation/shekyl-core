# Shekyl input grammar — the rules and every binary's names

**Status:** RULED (Rick) — Part A 2026-10-13 (§0–§9, IG-Q1…IG-Q20), Part B
2026-10-14 (§10–§15, IG-Q21…IG-Q39); IG-Q40, the inbound cap, 2026-10-14;
IG-Q41, the Tor binary, 2026-10-15; Part C (§16–§20, IG-Q42…IG-Q57), the RPC wire's names, DRAFT, posed 2026-10-18.
Each question carries its ruling in
its own line. The rules IG-1…IG-15 are the cursor rule
[`83-input-grammar`](../../.cursor/rules/83-input-grammar.mdc); this
document holds the glossary tree and the name tables.
**Verified against:** `shekyl-core` @ `737da3127` (`dev`; the option surface
is unchanged from `2c3fae3c`, only `rpc_facts_ffi.*` moved) and PR-3 (#1056,
`feat/p2p3-dialer-cutover`) @ `fce0a2fa`. Reviewed at **`737da3127`**. Every
`file:line` is at the dev pin unless marked `[PR-3]`. Part B (§10–§15) is
verified against `shekyl-core` @ `7cf70b705` (`dev`).
**Identifier family:** `IG-` (input grammar): rules `IG-1…IG-15`, questions
`IG-Q1…IG-Qn`, findings `IG-F1…IG-Fn`. The prefixes collide with no
registered family. Registered at birth in the PR that lands this document
(rule 94).
**The `R1…R9` tokens in §0** are the maintainer's numbered rulings of
2026-10-13, cited the same way by the daemon-configuration cutover brief
(`DAEMON_CONFIG_CUTOVER.md`, draft PR #1066); they are not an identifier
family of this document.

**Sequencing (ruled 2026-10-13).** Part A gates the daemon-configuration cutover, which is based on PR-3 after it merges. Part B's names are implemented by the wallet binaries' own PRs and the utility deletions (FOLLOWUPS). Genesis gate: the grammar gate passes on every binary target we author (IG-Q27).

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
- enumeration keywords, unit spellings, and REJECTED names;
- RPC method, parameter and reply-field names on the daemon's wire ([`RPC_WIRE.md`](RPC_WIRE.md) RW-Q1, RW-Q10; the census is Part C).

Out of scope: log category names (owned by `shekyl-logging`); they can be brought in by ruling.

---

## 2. The rules

**IG-1 Lexical.** An identifier is lowercase ASCII `[a-z][a-z0-9]*` segments. One path has three renderings and no other: words at the prompt (`chain height`); `-`-joined in option names and TOML keys (`log-level`); `_`-joined on the RPC wire for method, parameter and reply-field names (`chain_height`; [`RPC_WIRE.md`](RPC_WIRE.md) RW-Q9). Identifiers, keywords and units are never translated.

**IG-2 One vocabulary, as a tree.** The glossary is a tree of terms. Each term is defined once, project-wide, and lists its parents; a term with no parent is a *subject*. A term reused under several parents keeps its one meaning (`listen` under `clearnet`, `onion`, `rpc` and `view`). Every segment of every name is a term in the tree, including plain words (`file`, `dir`, `max`, `help`): the gate has no exemption list.

**IG-3 Structure.** A name is a path through the tree: it starts at a subject and each segment is a child of the one before (`tor-socks-password` is `tor` → `socks` → `password`). A subject alone is a name (`network`). The qualifiers `max` and `min` may end any path. A path-valued option ends in `file` or `dir`. A term may both carry a value and have children (`tor`, `tor-socks`). `dev` is a subject like any other (IG-8); its children may be other subjects (`dev-clearnet-encrypt`). The gate checks that a name is well formed; whether it is an option is the table's. A command is a path whose last term is a *verb* (the command acts) or a *view* (a noun whose command prints it); verbs and views are terms of that kind under their parent, a subject that is itself a verb or a view is a command alone (`send`, `balance`), and each command has exactly one spelling. A view changes no state; a command that changes state ends in a verb.

The gate walks every live and reserved name and every command in every binary's table (an X row is a refused spelling, exempt by kind; IG-10) and fails on: an undefined segment; an adjacent pair that is not a parent→child edge in the tree; a qualifier anywhere but last; a term defined twice. The edit that proves it can fail: add an option `socks-tor`.

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
| hash | `--x 6f1c…` | string | 64 hexadecimal characters, a 32-byte value: a transaction id, a block hash or a key image |
| bytes | `--x AAEC…` | string | base64 (RFC 4648 §4, padded): a block's or a transaction's serialized bytes; hex is the `hash` kind only ([`RPC_WIRE.md`](RPC_WIRE.md) RW-Q4) |
| amount | `--x 1.5` | string | a decimal SKL amount with at most `DISPLAY_DECIMAL_POINT` fractional digits (`shekyl-units`, the one source), parsed exactly to atomic units; never a float |
| name | `--x miner` | string | a wallet's name: one path component, no separators |
| text | the rest of the line | string | free text, verbatim |
| origin | `--x https://host:443` | string | an explicit web origin (RFC 6454): scheme `http` or `https`, a host, an optional port, nothing after; `*` is refused |
| path | `--x /abs/path` | string | absolute only |
| secret | not accepted | string | file only; never logged or echoed, and shown in the startup line only as set; zeroized; held only in Rust |
| command | not accepted | array of strings `["/path/prog", "arg", "{height}"]` | file only; run without a shell; placeholders are `{name}`, each name a glossary term under the row with one meaning everywhere; braces are the only syntax, `%` is literal; an unknown name refuses |
| list (of a scalar kind) | the flag repeated | an array under the same key | the keyword `none` is the empty list; a CLI list replaces the file's list whole |
| map (of a scalar kind) | `--x key=value`, repeated | a table under the same key | keys are a closed set named in the row; the keyword `none` is the empty map; a CLI map replaces the file's map whole |

A row narrows its kind with a constraint stated in the row and enforced by its constructor (a range, "global unicast only", "onion only"). A row may admit named keywords from the closed keyword set alongside its kind (`unlimited`, `auto`, `stdin`); paths are absolute, so a keyword never collides with a file. A row with no default is *unset* when not given, and the row states what unset means; there are no sentinel values. There are no floating-point values anywhere in the grammar.

**IG-7 Surfaces.** Each row says where it may be given. Command-line only: `help`, `version`, `network`, `config-file`, `service` (each selects which file is read, so a key in that file could only restate or contradict it). File only: every secret and every command value. Everything else: both, CLI winning per key.

**IG-8 Development levers.** A `dev-` option is hidden from help and generated docs, names the networks it is accepted on as data in its row (a `dev-` option given on any other network is refused at parse, rule 71), and is announced at every start when set. It follows every other rule. **No `dev-` option is ever accepted on mainnet**: a lever mainnet genuinely needs is not a development lever and gets a public row.

**IG-9 One table per binary, generated everything.** The table row: id, name, kind, constraint, keywords, default (a value, unset, or "derived from the network row"), surfaces, runtime (`yes` or `no`: whether `option set` accepts the row, IG-12), grant (`health`, `status`, `peers` or `config`, default `config`: the grant under which `option show` discloses the row; [`RPC_CHANNEL.md`](RPC_CHANNEL.md) §6.4, RT-O24), visibility (`public` / `dev` / `rejected` / `reserved`), accepted networks (`dev` only), owning subsystem, help text. From the table: `--help`, completion, the documentation tables, and an annotated TOML example. A gate regenerates the docs and diffs them, and asserts the table is non-empty (rule 47). A row names `health` only if it passes RPC_CHANNEL §6.1's line for that grant: a client needs it to decide whether it can use the node now, and it says nothing lasting about the node; no row does today. The peer, closed-peer and ban rows are `peers`; everything that describes the host or links the operator (`mine-address`, `tor-onion`, paths, SOCKS endpoints, notify commands) is `config`; a secret's value is shown under no grant.

**IG-10 Unknown and refused names.** An unknown name is one general refusal that names the nearest live name, computed from the table (edit distance), never from a hand list. A REJECTED row (a feature deliberately refused) carries its reason and a pointer to the decision; it is never accepted, never in help, and its refusal states the reason. A REJECTED row is a contract entry in the sense of rule 23, not a code symbol: it is never deleted as dead. A RESERVED row (a name held for a ruled future option; rule 23's reserved slot) is the same kind of entry: never accepted, never in help, and its refusal names what the name is reserved for and where that is ruled.

**IG-11 Diagnostics.** Every refusal is a typed value: a stable code (`config.value.range`, `config.file.permissions`, …), the option, the source (`cli`, `file:path:line`, `default`, `runtime`) and named parameters. One renderer turns it into the English message, which states what was wrong, where, and what to do (rule 82). Machine output and logs carry the code. A configuration refusal exits with status 2; a runtime failure with 1.

**IG-12 Runtime changes share the constructor.** A value that can also change while running (rates, log level and categories, mining) is marked runtime in its row (IG-9) and is built by the same constructor on both surfaces, with the same refusals. `option set <name> <value>` changes it: it refuses a row not marked runtime with a typed code, requires the `node` grant, and never writes the file. `option show [<name>]` reports each value with its source (`default`, `file`, `cli`, `runtime`) and returns each row whose grant (IG-9) the caller holds; a row the caller may not see is absent, never emptied, and a secret's value is shown under no grant, only whether it is set. Every runtime row's default is writable as a value (`unlimited`, `none`), so `option set` returns a row to its default without a restart; what `option show` prints is valid input to `option set` and builds the same value; and no row is both runtime and a secret, which the gate asserts (RPC_CHANNEL §6.4, RT-O25, RT-O27). Mining changes while running through `mine start` and `mine stop` instead, which build `mine-address` and `mine-threads` through their constructors, so those rows are not marked runtime. The live value is owned by its subsystem. No binary ever writes its own config file.

**IG-13 Inputs come from the table, and nowhere else.** No option value comes from the environment. Default paths come from the operating system's account and known-folder interfaces, never from `HOME`, `XDG_*` or `%APPDATA%`. Each binary's per-account root is the passwd entry's home plus `.shekyl` on Linux, FreeBSD and macOS, and `SHGetKnownFolderPath(FOLDERID_LocalAppData)` plus `Shekyl` on Windows, never Roaming AppData, which copies the wallet and its config to domain servers (rule 36); a run-as-user daemon's data and log defaults, the wallet directory and the wallet binaries' config files sit under it. On Windows the daemon's run mode selects its root, and every default path it derives (`config-file`, `data-dir`, `log-file`) sits under that root: run-as-user uses the per-account root and `service` (IG-Q36) uses `%ProgramData%\shekyl\`, which only the installer creates (owner and ACL: Administrators, SYSTEM and the service account); the daemon never creates the machine-wide root, and one that is missing, mis-owned or writable by others refuses with a typed code. On Linux, FreeBSD and macOS the daemon has one run mode (`service` is refused there): its config file is R2's `/etc/shekyl/`, and its data and log defaults sit under the per-account root. The only environment reads permitted are presentation-only (terminal capabilities that change rendering, never a value). Every resolved default path appears in the startup line with its source. A service account whose passwd home is unset or `/nonexistent` has no default paths: the packaging sets the account's home or the unit passes `--data-dir` and `--log-file` (the shipped unit does both, IG-F10).

**IG-14 Required announcements are not log events.** The effective-configuration line, `dev-` lever warnings and posture warnings (clearnet-only, offline, a plaintext RPC listener bound beyond loopback) reach the log and standard error at every start whatever the log level. The effective-configuration line shows every value and its source; a secret is shown as set, never its value (IG-6).

**IG-15 Home.** The rules become one cursor rule. The glossary tree and the name tables live in one design document. One Rust crate holds the table types, the value kinds and their parsers, the unit types, the diagnostic type and the renderer; every binary builds its table from it.

---

## 3. Glossary — Part A's terms

A term listed under two parents is one term. Part B's terms are §11; a parent added here by Part B is IG-Q32's.

| Term | Parents | Meaning |
|---|---|---|
| help | — | *view* — print usage |
| version | — | *view* — print the version and the OS line |
| network | — | which chain: `mainnet`, `testnet`, `stagenet`, `regtest` |
| config | — | the TOML file of option values |
| data | — | the per-network directory holding the daemon's stores and state |
| log | — | the daemon's log sink |
| file | config, log, ban, wallet, script, password, socket, png, address, mnemonic, recipients, constants, tor | a file path (value term) |
| dir | data, wallet, create, recipients | a directory path (value term) |
| level | log | a log severity: `error`, `warn`, `info`, `debug`, `trace` |
| category | log | a log category, owned by `shekyl-logging` |
| size | log | the disk a log may use |
| p2p | — | the peer-to-peer protocol, independent of connector |
| clearnet | —, dev | the clearnet connector (direct TCP) |
| tor | — | the Tor connector |
| socks | clearnet, tor, daemon | the SOCKS5 endpoint a connector dials through |
| username | socks, rpc | a credential's name (SOCKS5, RFC 1929; the wallet RPC's authentication) |
| password | socks, wallet, rpc | a secret credential; always a secret |
| onion | tor | this node's v3 onion service |
| listen | clearnet, onion, rpc, view, admin | a local endpoint a listener binds |
| advertise | clearnet | the endpoint we tell peers is ours |
| local | p2p | endpoints not dialable on the public internet (private, loopback, link-local) |
| peer | p2p, closed, — | another Shekyl node |
| closed | p2p | a network consisting only of the listed peers |
| ban | p2p, — | a host or subnet refused at socket admission |
| disclose | p2p | what this node tells other nodes of its known peers and its own address |
| early | disclose | below the white-diversity floor |
| inbound | p2p | connections other nodes open to us |
| upload | p2p | bytes we send |
| download | p2p | bytes we receive |
| txpool | — | the transaction pool |
| weight | txpool | transaction weight, in bytes |
| notify | — | run an operator command on an event |
| block | notify, —, genesis | a block: under `notify` the new one; under `genesis`, *view* — the genesis block id and transaction hash |
| rate | block | the block-rate check |
| reorg | notify, archival | a chain reorganization |
| height | block, reorg, split, chain, restore | a block height: under `block` the new block's, under `reorg` the new tip's, under `split` the last block both chains share; under `chain`, *view* — the chain's height |
| hash | block | the new block's hash |
| split | reorg | the point where the two chains part (`{split-height}`) |
| added | reorg | blocks in the new chain |
| removed | reorg | blocks discarded from the old chain |
| window | rate | the observation window, in seconds |
| observed | rate | blocks seen in the window |
| expected | rate | blocks expected in the window |
| mine | — | the daemon's miner and its control |
| address | mine, make, — | a Shekyl address (the payment meaning; never a network location); bare, *view* — the wallet's primary address |
| threads | mine | a thread count |
| rpc | —, wallet | an RPC service's listeners: the daemon's, or the wallet's (`shekyl-wallet-rpc`, and `wallet-rpc-*` in `shekyl-cli`) |
| view | rpc | the `view` preset, a fixed set of grants (RPC_CHANNEL §6.1) |
| admin | rpc | the `admin` preset, every grant (RPC_CHANNEL §6.1) |
| cors | rpc | cross-origin resource sharing |
| origin | cors | an allowed origin |
| connections | rpc, peer | concurrent connections; under `peer`, *view* — the live peer connections |
| console | — | the daemon's interactive console (interim; R8) |
| dev | — | a development lever (IG-8) |
| encrypt | clearnet | the pre-flip clearnet encryption switch |
| relay | dev, tx | transaction relay (Dandelion++); under `tx`, *verb* — relay a transaction |
| cover | relay | Dandelion++ cover traffic ([`COVER_TRAFFIC_RESTORATION.md`](COVER_TRAFFIC_RESTORATION.md)) |
| sync | dev, — | chain synchronization |
| difficulty | dev, chain | a fixed mining difficulty; under `chain`, *view* — the current difficulty |
| pow | dev | the RandomX seed schedule |
| seed | pow | the RandomX seed |
| epoch | seed, settlement | a fixed-length run of blocks |
| blocks | epoch | a length in blocks |
| lag | epoch | the seed lag in blocks |
| settlement | dev | the archival settlement schedule |
| archival | dev, — | the archival layer |
| depth | reorg | a reorganization depth in blocks |
| max | any | qualifiers |
| min | any | qualifiers |

Value keywords: `on`, `off`, `managed`, `operator`, `auto`, `unlimited`, `none`, `stdin`, the four network names, the five levels.

Two words are given one meaning each by this table, ending two collisions: **address** is a Shekyl address only (network locations are *endpoints*; `mine-address` keeps its name, and Part B renames `shekyl-wallet-rpc --daemon-address`); **carrier** is the serve-credit witness carrier only ([`ARCHIVAL_SERVE_CREDIT_SPEC.md`](ARCHIVAL_SERVE_CREDIT_SPEC.md)), so today's `--carrier-development`, which arms the Dandelion++ *cover* traffic (`command_line_args.h:114-141`), becomes `dev-relay-cover`.

---

## 4. The shared crate and the parser

The table, kinds, parsers, units, diagnostics and renderer live in one crate (IG-Q13). `shekyl-daemon-config` builds the daemon's table from it and owns precedence, the per-network file, permission checks, the effective-config line and the typed `DaemonConfig` (sections per subsystem; each Rust consumer takes its section at construction; the C++ that remains reads a Rust-owned snapshot until its subsystem is Rust).

Cross-row constraints are types, not checks: the P2P section is built from a clearnet posture `Off | On { listen, socks, advertise }` and a Tor posture `Off | Managed | Operator { socks, onion }`, so a SOCKS endpoint for a connector that is off cannot be constructed, and a `p2p-peer` whose connector is off is refused by the section's constructor.

---

## 5. The daemon's name table

The Runtime column marks the rows `option set` accepts (IG-12). The Grant column names the grant under which `option show` discloses a live row (IG-9); blank is the default, `config`.

Legend — **R** rename or fold (no trace), **K** kept as is, **X** REJECTED row (the feature is refused; the reason is in the row), **–** removed with no trace (an implementation switch, a debug knob, or nothing left to switch), **L** lane-owned (not ported; IG-Q4), **N** new.

### Network, paths, logging

| Today | New | Kind | Default | Surface | Runtime | Grant | Notes |
|---|---|---|---|---|---|---|---|
| `help` | `help` | switch | | CLI |  |  | K |
| `version` | `version` | switch | | CLI |  |  | K; prints the OS line too |
| `os-version` | — | | | |  |  | R into `version` |
| `testnet`, `stagenet`, `regtest` | `network` | one-of | `mainnet` | CLI |  |  | R |
| — | `service` | switch | off | CLI |  |  | N (IG-Q36, IG-Q37); visibility `reserved` (IG-9, IG-10) until RT-W14 builds the SCM dispatcher: not accepted, and its refusal names RT-W14. Live: `shekyld` answers the platform's service manager ([`RPC_CHANNEL.md`](RPC_CHANNEL.md) RT-16); accepted only where RT-16 defines it (Windows), refused elsewhere with a typed code; selects the daemon's root (IG-13) |
| `config-file` | `config-file` | path | `/etc/shekyl/shekyld-<network>.toml` on Linux, FreeBSD and macOS; on Windows the daemon's root (IG-13) + `shekyld-<network>.toml` | CLI |  |  | K; a missing file at the default per-network path means defaults, and the startup line says so; a missing file at a path the operator named refuses with a typed code (IG-11) that names the path; an unsafe file or directory refuses |
| `data-dir` | `data-dir` | path | the daemon's root (IG-13) + network subdir (row) | both |  |  | K; an explicit path is taken as given, the default layout keeps the network subdirectory, and a Rust network marker refuses a wrong-chain directory (IG-Q17, ruled 2026-10-13); no home refuses; the daemon's root on every platform (IG-13, IG-Q36); exclusive lock (IG-F2) |
| `log-file` | `log-file` | path | the daemon's root (IG-13) + `logs/shekyld-<network>.log` | both |  |  | K; the per-network name the docs promised (IG-F4) |
| `log-level` | `log-level` | one-of | `warn` | both | yes | status | R (numeric 0–4 and category strings go); by default the log records what needs the operator's attention, and the startup and posture lines are announcements, not log events (IG-14); runtime `set_log_level` shares the constructor |
| — | `log-category` | map category→level, or `none` | `none` | both | yes | status | N; `none` is no per-category overrides, and an empty category list never means logging off; replaces the category half of `log-level` and `set_log_categories`; the keys are validated against `shekyl-logging`'s category list at construction, by reference (§1 keeps the names out of this grammar) |
| `max-log-file-size`, `max-log-files` | `log-size-max` | quantity (bytes) | `1GiB` | both |  |  | R; the disk the log may use, live file and archives together; rotation inside it is the logging owner's (IG-Q19) |
| `max-concurrency` | — | | | |  |  | – (IG-Q7) |

### Connectors and P2P

| Today | New | Kind | Default | Surface | Runtime | Grant | Notes |
|---|---|---|---|---|---|---|---|
| — | `clearnet` | one-of `on` `off` | `on` | both |  |  | N (IG-F6, IG-Q3) |
| `no-ephemeral-tor`, `tx-proxy`, `anonymous-inbound` | `tor` | one-of `managed` `operator` `off` | `managed` | both |  |  | R |
| (`tx-proxy` endpoint) | `tor-socks` | endpoint | unset | both |  |  | R; required with `tor = operator`, unconstructible otherwise |
| (`tx-proxy` `user:pass@`) | `tor-socks-username`, `tor-socks-password` | secret | unset | file |  |  | N; carried on the dial as an RFC 1929 pair: given together or refused (`config.value.requires`), each half 1 to 255 bytes (`config.value.range`) (IG-F11) |
| (`anonymous-inbound` onion) | `tor-onion` | peer-endpoint, onion only | unset | both |  |  | R; `tor = operator` only; one onion: a second onion on one node is a second identity an observer can link to the first, and it offers peers nothing the first does not |
| (`anonymous-inbound` bind) | `tor-onion-listen` | endpoint | unset | both |  |  | R; required with `tor-onion` |
| (`SHEKYL_TOR_BINARY`, environment) | `tor-file` | path | derived: `tor/tor` beside the executable, else the version-exact bundle directory under `/opt/shekyl/` (Unix) | both |  |  | N; `tor = managed` only, unconstructible otherwise; verified against the pin as the discovered binary is, with no fall-through to discovery (IG-Q41) |
| (`tx-proxy` / `anonymous-inbound` `,N`) | — | | | |  |  | – (R5) |
| `proxy` | `clearnet-socks` | endpoint | unset | both |  |  | R |
| (`proxy` `user:pass@`) | `clearnet-socks-username`, `clearnet-socks-password` | secret | unset | file |  |  | N; carried on the dial as an RFC 1929 pair: given together or refused (`config.value.requires`), each half 1 to 255 bytes (`config.value.range`) |
| `p2p-bind-ip`, `p2p-bind-ipv6-address`, `p2p-bind-port`, `p2p-bind-port-ipv6`, `p2p-use-ipv6` | `clearnet-listen` | list of endpoint | `0.0.0.0:<row p2p port>` | both |  |  | R; `none` = dial-only on clearnet |
| `p2p-external-port` | `clearnet-advertise` | list of endpoint (global unicast; at most one per address family) | unset | both |  |  | R (Q10a; absorbs the external port; PWD-E6's capability kept) |
| `p2p-ignore-ipv4` | — | | | |  |  | – (the listen lists state the address families) |
| `no-igd`, `igd` | — | | | |  |  | X `upnp`, `igd` (R4) |
| `allow-local-ip` | `p2p-local` | switch | off | both |  |  | R |
| `add-peer`, `seed-node` | `p2p-peer` | list of peer-endpoint | `none` | both |  | peers | R; IP and onion only (IG-Q6); seeds are ordinary peers |
| `add-exclusive-node` | `p2p-closed-peer` | list of peer-endpoint | `none` | both |  | peers | R; non-empty declares a closed network |
| `p2p-disclose-early` `[PR-3]` | `p2p-disclose-early` | switch | off | both |  |  | K (IG-Q20); for bootstrapping or testing a network smaller than the white-diversity floor (48): this node discloses its known peers and its own address below the floor, on each connector until that connector's white count reaches the floor or the span `P2P_DISCLOSE_EARLY_SPAN_NANOS` ends it, whichever comes first; announced at start (IG-14) |
| `add-priority-node` | — | | | |  |  | X (bypasses the identity protections; removed by PR-3) |
| `ban-list` | `p2p-ban-file` | path | unset | both |  | peers | R; read in Rust at parse |
| `out-peers` | — | | | |  |  | X (the outbound degree is a protocol constant) |
| `in-peers` | — | | | |  |  | X (no operator inbound cap: the descriptor safety bound is the only inbound bound, and the rate rows bound what an operator pays; reopens as a byte quota for metered links, IG-Q40) |
| `limit-rate-up` | `p2p-upload-max` | quantity (rate), or `unlimited` | `unlimited` | both | yes | status | R; runtime `set_limit` shares the constructor; `0` refused on both surfaces |
| `limit-rate-down` | `p2p-download-max` | quantity (rate), or `unlimited` | `unlimited` | both | yes | status | R |
| `limit-rate` | — | | | |  |  | R (one option per value) |
| `tos-flag` | — | | | |  |  | X (a traffic-class marking is a label any on-path observer can classify Shekyl traffic by) |
| `offline` | — | | | |  |  | R into `clearnet = off` and `tor = off` (IG-Q3) |
| `pad-transactions` | — | | | |  |  | L relay |
| `clearnet-transport-encrypt` | `dev-clearnet-encrypt` | switch | off | both |  |  | R; testnet, stagenet, regtest (IG-8: never mainnet); deleted at the Noise flip |
| `no-sync` | `dev-sync` | one-of `on` `off` | `on` | both |  |  | R; regtest; the chain-sync lane owns it |
| `carrier-development` | `dev-relay-cover` | switch | off | both |  |  | R; testnet, stagenet, regtest (IG-8: never mainnet); `check_carrier_flag_hidden.sh` replaced by a table test |

### Core, pool, notify, mine

| Today | New | Kind | Default | Surface | Runtime | Grant | Notes |
|---|---|---|---|---|---|---|---|
| `test-drop-download`, `test-drop-download-height`, `test-dbg-lock-sleep`, `show-time-stats` | — | | | |  |  | – |
| `keep-fakechain` | — | | | |  |  | – (nothing is wiped, R3) |
| `fixed-difficulty` | `dev-difficulty` | integer ≥ 1 | unset | both |  |  | R; regtest |
| `prep-blocks-threads`, `block-sync-size`, `span-limit`, `block-download-max-size` | — | | | |  |  | L chain-sync |
| `db-sync-mode`, `db-salvage` | — | | | |  |  | L DRS |
| `keep-alt-blocks` | — | | | |  |  | L DRS-E5 |
| `max-txpool-weight` | `txpool-weight-max` | quantity (bytes) | `648000000B` | both |  |  | R; a Monero-derived operand; deleted at the DRS-X flip, the pool's cap deriving from the chain (IG-Q11, amended 2026-10-17) |
| `block-notify` | `notify-block` | command | unset | file |  |  | R (IG-Q5); placeholders `{height}`, `{hash}` |
| `reorg-notify` | `notify-reorg` | command | unset | file |  |  | R (IG-Q5); placeholders `{split-height}` (the last block both chains share), `{height}` (the new tip), `{added}` (blocks in the new chain), `{removed}` (blocks discarded) |
| `block-rate-notify` | `notify-block-rate` | command | unset | file |  |  | R (IG-Q5); placeholders `{window}` (the window in seconds), `{observed}`, `{expected}` |
| `start-mining` | `mine-address` | address | unset | both |  |  | R; set means mine from start; `mine start` builds it while running (IG-12) |
| `mining-threads` | `mine-threads` | integer ≥ 1, or `auto` | `auto` | both |  |  | R (IG-Q21); `mine start` builds it while running (IG-12); one default for starting the miner on every surface: `shekyl-cli mine start` with no count is `auto` (`grammar.rs:539-540`); the miner's owner defines `auto` once |
| `bg-mining-*` (5) | — | | | |  |  | X (Monero background mining) |

### RPC, named for the ratified RPC_CHANNEL model

| Today | New | Kind | Default | Surface | Runtime | Grant | Notes |
|---|---|---|---|---|---|---|---|
| — | `rpc-listen` | list of endpoint | | |  |  | visibility `reserved` (IG-9, IG-10): held for the authenticated channel listener (RT-W10); not accepted in this cut |
| `rpc-bind-ip`, `rpc-bind-port`, `rpc-bind-ipv6-address`, `rpc-use-ipv6` | `rpc-admin-listen` | list of endpoint, loopback only | `127.0.0.1:<row rpc port>` | both |  |  | R; the interim plaintext full-access listener; loopback only by RT-14 (a plaintext listener never binds beyond loopback; only the authenticated channel listener may bind wildcard); becomes an X row when RT-W10 lands (IG-Q16) |
| `restricted-rpc`, `rpc-restricted-bind-port`, `rpc-restricted-bind-ip`, `rpc-restricted-bind-ipv6-address` | `rpc-view-listen` | list of endpoint, loopback only | `none` | both |  |  | R; survives RT-W10 unchanged (plaintext loopback at view, off by default, ruled 2026-10-08); the GUI sidecar passes `--rpc-admin-listen none --rpc-view-listen 127.0.0.1:<port>` |
| `rpc-access-control-origins` | `rpc-cors-origin` | list of origin | `none` | both |  |  | R; explicit web origins only, `none` is CORS default-deny; `*` is refused: a wildcard lets any page in the operator's browser read and drive the plaintext admin listener |
| `rpc-max-connections`, `rpc-max-connections-per-public-ip`, `rpc-max-connections-per-private-ip` | `rpc-connections-max` | integer ≥ 1 | `25` (inherited; IG-Q12) | both |  |  | R; one option for one value, where today three set it (IG-F1); the cutover ships the inherited 25 with a FOLLOWUPS row for the RPC lane to derive the default under the RT-O9 resource policy, the same shape as `txpool-weight-max` |
| `disable-rpc-ban` | — | | | |  |  | – (R5; the scorer it switches has no caller, IG-F9) |
| `rpc-response-soft-limit` | — | | | |  |  | – (response limits belong to the RPC resource policy, IG-Q12) |

### Session (interim, until `shekyl-cli` serves the console — R8)

| Today | New | Kind | Default | Surface | Runtime | Grant | Notes |
|---|---|---|---|---|---|---|---|
| `non-interactive` | `console` | switch | off | CLI |  |  | R (IG-Q8); deleted with the console |
| `daemon_command` (positional) | unchanged | | | |  |  | moves to `shekyl-cli` (Part B) |

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
| `detach`, `pidfile`, `install-service`, `uninstall-service`, `start-service`, `stop-service`, `run-as-service` | X | `shekyld` never daemonizes or registers itself; installing is the installer's and `shekyl-cli`'s, and on Windows `shekyld` answers the service manager through `service` (RT-16) |
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
- **IG-F11 — SOCKS credentials reach the dial — CLOSED 2026-10-17 (#1112).** The four secret rows are carried on the SOCKS5 dial as RFC 1929 credentials, given as a pair or refused, file only, shown as `set` and never in the snapshot.

---

## 7. Landed text and consumers the cutover changes

- **Superseded rulings.** `V3_WALLET_DECISION_LOG.md:416-437` rules an environment layer, `--config` and XDG paths for the wallet binaries; IG-13 and R7 supersede it; the superseding entry is in the decision log (2026-10-13). `CLI_USABILITY.md:108` ("daemon flags do not change"), CU-2's hidden aliases and CU-7's diagnosing retired spellings are superseded by IG-5 and §0; they are rewritten with Part B's implementation (FOLLOWUPS).
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

**IG-Q11 — `txpool-weight-max` — RULED 2026-10-13; AMENDED 2026-10-17 (Rick, on #1102).** The default is "3 days at 300000 bytes" (`cryptonote_config.h:328`), a Monero operand. The name landed with the inherited default and a FOLLOWUPS row for the pool's owner to re-derive it. The re-derivation is done: the Rust pool derives its cap from the chain, `REFERENCE_BLOCK_MAX_AGE` blocks at the block weight limit (`DRS_E5_POOL_ALT_PRUNE.md` CEN-M10), and reads no option. **`txpool-weight-max` is deleted at the DRS-X flip** and joins the retired options, refused with "the pool's cap derives from the chain (CEN-M10)". The C++ pool reads it until then. The reasons:
- the cap is derived, not chosen: any lower number only discards transactions that could still be mined;
- a per-node cap changes what a node holds under pressure, which peers see through pool sync;
- on a floor device the chain binds before the pool does.

*Reopening criterion:* a floor-device measurement at the flip in which pool RSS, not the chain, binds first at a realistic weight limit. The remedy then is a compact in-memory representation, not an option.

**IG-Q12 — `rpc-connections-max`'s default — RULED 2026-10-13.** The only number on hand is the C++'s effective 25, which nobody derived. The cap is a resource limit, and RT-O9.4 ruled cost a resource policy separate from grants. The cutover ships the inherited value 25 with a FOLLOWUPS row for the RPC lane to derive the default under that policy, the same shape as `txpool-weight-max`.

**IG-Q13 — names — RULED 2026-10-13.** Family `IG-`; the shared crate `shekyl-options`; the daemon crate `shekyl-daemon-config`.

**IG-Q14 — no environment input (IG-13) — RULED 2026-10-13.** Default paths came from `HOME`, and the wallets read `XDG_RUNTIME_DIR` (`shekyl-wallet-rpc/src/server.rs:744`), so the environment still decided values. Home comes from the passwd entry and the Windows known-folder API. Each platform takes its per-user runtime directory from its own OS interface, never from the environment: Linux `/run/user/<uid>`; macOS `confstr(_CS_DARWIN_USER_TEMP_DIR)`; FreeBSD, or any platform without one, the typed refusal (IG-11) naming the explicit, operator-named socket directory ruled in the RPC channel round ([`RPC_CHANNEL.md`](RPC_CHANNEL.md) §7.1, 2026-10-09). Terminal reads (`shekyl-cli/src/display.rs:98-104`) stay, as presentation. Cost: a user who relocates `HOME` by environment passes `--data-dir` instead.

**IG-Q15 — `address` and `carrier` (§3, IG-F7, IG-F8) — RULED 2026-10-13.** `address` is a Shekyl address only; network locations are endpoints. `carrier` is the serve-credit witness carrier only; the cover switch is `dev-relay-cover`.

**IG-Q16 — RPC names for the ratified model — RULED 2026-10-13.** RPC_CHANNEL (ratified 2026-10-09) replaces today's listeners with the authenticated channel, the same-user socket, and an optional plaintext loopback listener at view. Naming today's full-access listener `rpc-listen` would hand that name to the channel listener later with a different meaning. `rpc-listen` is reserved for the channel listener; today's full-access listener is `rpc-admin-listen` (what it is: plaintext, loopback, admin), an X row when RT-W10 lands; `rpc-view-listen` is the ratified view listener from now on.

**IG-Q17 — an explicit `data-dir` is taken as given — RULED 2026-10-13 (the same ruling is DC-Q5 in the daemon-configuration cutover).** An explicit `data-dir` is taken as given; no network subdirectory is appended to it. The default `data-dir` keeps the network subdirectory as its default layout. The defence against a directory serving the wrong chain is a **network marker**, owned by the daemon-config lane, in Rust: written when the daemon creates its stores in a directory that holds none, recording the network id (derived from genesis) and the network name; a mismatch refuses the start with a typed code (IG-11) naming both networks and the fix; a directory holding a daemon store but no marker refuses likewise and is never marked after the fact. The marker is a separate file from the data-directory lock (DC-N1; IG-F2). DC-F1, the genesis-at-open check on the store's contents, stays with the chain-store lane as a separate check and is no longer a blocker for the cutover.

**IG-Q18 — "no inbound" — RULED 2026-10-13.** Today `--in-peers 0` turns all inbound off; the daemon has no inbound count (IG-Q40), so clearnet inbound off is `clearnet-listen none`, and the managed Tor's per-boot onion has no off. The managed ephemeral Tor is rejected in [`TOR_COVER_POSTURE.md`](TOR_COVER_POSTURE.md) §9 *as a cover configuration*, so the per-boot onion is inbound reachability (PWD-E7, default-on), not cover, and a dial-only posture loses no cover. Dial-only exists on the operator arm of this table — `tor = operator` with `tor-socks` set and `tor-onion` unset — so there is no new mode: `managed` always publishes, and an operator who wants dial-only runs the operator arm.

**IG-Q19 — one log budget — RULED 2026-10-13.** A file size and a file count multiply into a disk budget nobody chose (100 MiB × 50 = 5 GiB). The operator's resource is disk. One quantity, `log-size-max`, is the total for the live file and its archives; how often to rotate within it is the logging owner's. The default is 1 GiB; it is a reduction from today's effective 5 GiB (100 MiB × 50 archives, `EXECUTABLES.md:62-63`), and the release notes say so.

---

**IG-Q20 — PR-3's disclose-early switch — RULED 2026-10-13, amended the same day.** PR-3 registers one new C++ option as the one ruled exception to "no new daemon option", born under a working name and renamed in PR-3 at `fce0a2fa`: `arg_p2p_disclose_early` registering `p2p-disclose-early` (`src/p2p/net_node.cpp` `[PR-3]`), read once into `shekyl_peerlist_disclose_early`. The option is **`p2p-disclose-early`**, a public switch (§5): a network at genesis is small, and IG-8 accepts no `dev-` option on mainnet. The Rust symbols take the name in PR-3 too: `P2P_DISCLOSE_EARLY_SPAN_NANOS`, `DiscloseEarly` and `DiscloseEarlyEnd`, the `disclose_early` field, methods and test; the log line and doc comments name `--p2p-disclose-early`. The daemon-config cutover deletes the C++ option and its FFI push under these names. Acceptance: `rg -n -e 'small_network' -e 'SmallNetwork' -e 'SMALL_NETWORK' -e 'small-network' src rust` returns no match.

---

## 9. Surfaces examined

Read for revision 1: all seven option-registering files linked into `shekyld` and every consumer of their options; the config-file path in `main.cpp`; `removed_flags.cpp`; the C++→Rust pushes on dev and PR-3; the RPC connection limiter; the seed-epoch and settlement overrides; the data-dir creation path; `CLI_USABILITY.md` and the CLI catalog and grammar; `shekyl-wallet-rpc`'s flags; the shipped executables list; every launcher of `shekyld` in this repo and the GUI sidecar.

Read again for revision 2, at `737da312` and `baaba2bd`: `core_rpc_server::add_host_fail` and its callers; `core_rpc_ffi.cpp`'s context comment; `set_max_in_peers` and the ceiling application in `net_node.inl`; `InboundCeiling`; the `--anonymous-inbound` loop; the miner's option read; `mlog.cpp`'s default categories; the cover switch in `command_line_args.h` and `main.cpp`; `shekyl_zone_listen_tor`'s signature; the wallet decision log entry; `shekyl-cli`'s daemon-down copy. The `shekyl-dev` and GUI consumer list is the implementing lane's grep, not re-run here.

Read for Part B, at `7cf70b705`: `shekyl-cli`'s options, its scripted subcommands and its command catalog (`catalog.rs`, `grammar.rs`); `shekyl-wallet-rpc`'s options; the C++ console's forty-four handlers (`command_server.cpp`) and the Rust console's methods; every utility's descriptors; `geblock`'s commands; the consumers of the utilities in the workflows, the gates, the installer and `EXECUTABLES.md`.

Not read: the GUI's settings screen, the mobile tree.

---

## 10. Part B — the wallet binaries, the console and the tools

Part B names every identifier of `shekyl-cli`, `shekyl-wallet-rpc`, the daemon's console and the tools under IG-1…IG-15 and the glossary (§3, §11). A name shared with the daemon's table (`network`, `config-file`, `log-*`) has a row here only where its kind, default or surface differs; otherwise the daemon's row (§5) is the row. No wallet-binary row is runtime: the shell's `option set` and `option show` act on the daemon (§13). The names are implemented by the wallet binaries' own PRs and the utility deletions (FOLLOWUPS).

## 11. Glossary — Part B's terms

Rows below add to §3; a term already in §3 is not repeated (its Part B parents are in §3). Verbs and views are marked (IG-3).

| Term | Parents | Meaning |
|---|---|---|
| wallet | — | the wallet: its files and its operations |
| daemon | — | the daemon a wallet binary or the shell talks to |
| service | — | run under the platform's service manager (RT-16) |
| script | — | a file of prompt lines run as one session |
| json | — | machine output: one object per command |
| debug | — | show the machine detail of a failure |
| option | — | a runtime-changeable row of the daemon's table (IG-12) |
| tx | — | a transaction |
| request | — | a payment request |
| uri | — | a `shekyl:` payment URI |
| stake | — | the staking balance and bond |
| shard | — | an archival shard |
| prove | — | make a proof |
| check | — | check a proof |
| sign | — | *verb* — sign a message with the wallet key |
| verify | —, genesis | *verb* — check a claim against its source: a message signature, or under `genesis` every network rebuilt against the pins |
| send | — | *verb* — send money |
| fee | — | *view* — a fee quote |
| balance | —, stake | *view* — a balance breakdown |
| chain | — | the chain the daemon holds; bare, *view* — its health |
| exit | — | *verb* — leave the prompt |
| status | wallet, stake, mine, sync, daemon | *view* — the current state |
| stop | mine, daemon | *verb* — stop |
| set | option, password, note | *verb* — assign a value |
| show | tx, shard, chain, block, ban, option | *verb* — print one item |
| endpoint | daemon, rpc | a peer-endpoint the binary dials (IG-Q31) |
| socket | daemon, rpc | the local socket of RPC_CHANNEL RT-15 |
| mnemonic | create, restore | the wallet's recovery words (IG-Q24) |
| direction | list | `in` or `out` |
| unmatched | list | receives matching no request |
| matched | list | requests already paid |
| all | list | *view* — every entry |
| held | list | *view* — the shards this wallet holds |
| amount | make | an amount (kind `amount`) |
| label | make | a human label |
| expiry | create | how long a request stays valid: a duration |
| priority | send | `economy`, `standard` or `high` |
| yes | send, add, return, release, collect | confirm without a prompt |
| full | address | the whole address, not the display form |
| count | input, output | how many |
| input | fee | a transaction input |
| output | fee | a transaction output |
| png | fetch | a PNG image of the shard |
| pixels | png | the image's side, in pixels |
| complete | archival | the whole corpus |
| tree | complete | the CompleteTree posture (IG-Q28) |
| acknowledge | archival | the acknowledgement phrase that posture requires |
| short | list | the short form |
| from | show, sum | the first height |
| to | show | the last height |
| last | stats, sum | the most recent N blocks |
| body | show | a block's or transaction's serialized bytes, kind `bytes` |
| hard | rescan | rebuild from the chain |
| seconds | add | a duration, in seconds |
| alt | chain | *view* — the alternative chains |
| coinbase | chain | coinbase outputs |
| sum | coinbase | *view* — a total |
| stats | chain, peer, txpool, p2p | *view* — statistics |
| white | list | the white peer list |
| gray | list | the gray peer list |
| spent | chain | *view* — whether a key image is spent |
| create | wallet, request, recipients | *verb* — create |
| open | wallet | *verb* — open |
| close | wallet | *verb* — close |
| restore | wallet | *verb* — restore from the recovery words |
| refresh | wallet | *verb* — sync with the daemon |
| rescan | wallet | *verb* — rebuild the history |
| list | tx, request, shard, peer, ban, txpool | *verb* — print the entries |
| note | tx | *view* — a transaction's local note |
| abandon | tx | *verb* — give up on a dispatched send |
| decode | tx | *verb* — decode a transaction blob |
| make | uri | *verb* — compose |
| read | uri | *verb* — decode |
| outputs | stake | *view* — the staking-side outputs |
| available | stake | *view* — what can move back to the wallet |
| add | stake, ban | *verb* — add |
| return | stake | *verb* — move staking funds back |
| release | stake | *verb* — post the bond's exit |
| collect | stake | *verb* — collect the released funds |
| join | stake | *verb* — name the shards to serve |
| fetch | shard | *verb* — fetch |
| start | mine | *verb* — start |
| payment | prove, check | *view* — a payment proof, or the verdict on one |
| reserve | prove, check | *view* — a reserve proof, or the verdict on one |
| remove | ban | *verb* — remove |
| flush | txpool | *verb* — flush |

Value keywords added: `in`, `out` (direction), `economy`, `standard`, `high` (priority).

## 12. The wallet binaries' name tables

Legend as §5: **R** rename or fold, **K** kept, **X** REJECTED row, **–** removed with no trace, **N** new.

### 12.1 `shekyl-cli` — options

| Today | New | Kind | Default | Surface | Runtime | Notes |
|---|---|---|---|---|---|---|
| `help`, `version` | same | switch | | CLI | | K |
| `network`, `testnet`, `stagenet` | `network` | one-of | `mainnet` | CLI | | R; the shorthand flags go (IG-5) |
| — | `config-file` | path | the account root (IG-13) + `shekyl-cli-<network>.toml` | CLI | | N (IG-Q29) |
| `wallet-dir` (alias `engine-dir`) | `wallet-dir` | path | the account root + `wallets/<network>` | both | | K; the alias goes (IG-5) |
| `wallet` (alias `engine-file`) | `wallet-file` | path | unset | both | | R (IG-3: a path ends in `file`); the alias goes |
| `daemon-address` | `daemon-endpoint` | peer-endpoint | `127.0.0.1:<row rpc port>` | both | | R (IG-Q31): an IP or an onion, because a local wallet with a remote daemon over Tor is a supported posture; a hostname or URL is refused |
| (`daemon-address` `uds://`) | `daemon-socket-file` | path | unset | both | | N; RT-15's local leg; unconstructible together with `daemon-endpoint` |
| `rpc-url` | `wallet-rpc-endpoint` | peer-endpoint | unset | both | | R (IG-Q31); set means an external `shekyl-wallet-rpc`, not self-hosting |
| (`rpc-url` `uds://`) | `wallet-rpc-socket-file` | path | unset | both | | N; unconstructible together with `wallet-rpc-endpoint` |
| `proxy` | `daemon-socks` | endpoint | unset | both | | R; SOCKS5, names resolved by the proxy |
| `daemon-ca-cert` | — | | | | | X (RT-O8: the `https://` arm is deleted in RT-W12; the channel replaces TLS) |
| `debug` | `debug` | switch | off | both | | K; prints the machine detail (`error.data`) of a failure |
| `password-file` | `wallet-password-file` | path, or `stdin` | unset | both | | R (IG-5): one option; `stdin` reads the password from standard input; a group- or world-readable file refuses with a typed code, as the config file does; required when stdin is not a terminal |
| `complete-tree-foundation` | `archival-complete-tree` | switch | off | both | | R (IG-Q28): a public row |
| `acknowledge` | `archival-acknowledge` | one-of (the ruled phrase) | unset | CLI | | R (IG-Q28) |
| `json` | `json` | switch | off | CLI | | K |
| `script` | `script-file` | path | unset | CLI | | R |
| — | `log-file`, `log-level`, `log-category`, `log-size-max` | as §5 | as §5, the file `shekyl-cli-<network>.log` | both | | N; the daemon's rows apply |

### 12.2 `shekyl-cli` — the scripted subcommands' options

| Today | New | Kind | Surface | Notes |
|---|---|---|---|---|
| `create --seed-out` | `wallet create --mnemonic-file` | path | CLI | R (IG-Q24): the recovery words are written to a new `0600` file |
| `restore --seed-file` | `wallet restore --mnemonic-file` | path | CLI | R (IG-Q24): a group- or world-readable file refuses with a typed code |
| `create`, `restore`: `--password-file`, `--password-stdin` | `--wallet-password-file` | path, or `stdin` | CLI | R (IG-5): one option (§12.1) |
| `restore --restore-height` | `--wallet-restore-height` | integer | CLI | R |

### 12.3 `shekyl-cli` — command words

A command's last term is a verb or a view, and a command that changes state ends in a verb (IG-3); its flags are names under that term.

| Today | New | Positionals | Flags | Notes |
|---|---|---|---|---|
| `wallet` | `wallet status` | | | R (IG-Q33) |
| `wallet create <name>` | same | name | `--mnemonic-file <path>` (scripted) | K |
| `wallet open <name>` | same | name | | K |
| `wallet close` | same | | | K |
| `wallet restore <name> <seed...>` | `wallet restore <name>` | name | `--mnemonic-file <path>` | R (IG-Q24): the words come from the file or a hidden prompt, never a line, a history or a script |
| `wallet password` | `wallet password set` | | | R (IG-Q34) |
| `wallet refresh` | same | | | K |
| `wallet rescan [hard]` | `wallet rescan` | | `--hard` | R |
| `balance` | `balance` | | | K |
| `send <amount> <address> [--priority p] [--yes]` | same | amount, address | `--priority economy\|standard\|high`; `--yes` | K |
| `fee [--inputs N] [--outputs N]` | `fee` | | `--input-count`, `--output-count` integer | R (IG-Q22) |
| `address [--full \| --out <path>]` | `address` | | `--full`; `--file <path>` | R (IG-Q22) |
| `status` | `wallet status` | | | R (IG-Q33) |
| `chain` | `chain` | | | K |
| `version`, `help [command]` | same | | | K |
| `exit` (synonym `quit`) | `exit` | | | R (IG-Q30): `quit` goes |
| `tx list [--in \| --out] [--unmatched]` | `tx list` | | `--direction in\|out`; `--unmatched` | R (IG-Q22) |
| `tx show <id>` | same | hash | `--body` | K; `--body` prints the transaction's serialized bytes, kind `bytes` (RW-Q4) |
| `tx note <txid> [<text...>]` | `tx note <id>`, `tx note set <id> <text>` | hash; hash, text | | R (IG-Q34): `tx note` is a view; `tx note set` with empty text clears the note |
| `tx abandon <txid>` | same | hash | | K |
| — | `tx decode <body>` | bytes (a transaction's serialized bytes) | | N (IG-Q26, RW-Q4): decodes with the Rust codecs; `shekyl-utils-deserialize` then goes |
| `request new <amount> <label> [--expiry e]` | `request create <amount> <label>` | amount, text | `--expiry` quantity (duration) | R (IG-Q34) |
| `request list [--matched \| --all]` | same | | `--matched`; `--all` | K |
| `uri make [--amount X] [--label L] [--address A]` | same | | `--amount` amount; `--label` text; `--address` address | K |
| `uri read <uri>` | same | a `shekyl:` URI | | K |
| `stake` | `stake status` | | | R (IG-Q33) |
| `stake balance`, `stake outputs`, `stake available` | same | | | K |
| `stake add <amount> [--yes]`, `stake return <amount> [--yes]` | same | amount | `--yes` | K |
| `stake release [--yes]`, `stake collect [--yes]` | same | | `--yes` | K |
| `stake join <shard-id>...` | same | integer… | | K |
| — | `stake acknowledge <kind>` | one of `stake`, `claim`, `return`, `release` | | N, RULED 2026-10-17 (Rick, #1109). Clears the endings of that kind that `stake` showed, through the newest one shown (`acknowledge_staking_outcome { kind, through_height }`, `WALLET_RPC_STAKING_OUTCOMES.md` WR-Q2, §7.3); the kind words are the ones `stake` prints |
| `shard list`, `shard list all`, `shard list mine` | `shard list`, `shard list all`, `shard list held` | | | R (IG-Q22) |
| `shard show <id>` | same | integer | | K |
| `shard fetch <id> [--png p] [--size n]` | same | integer | `--png-file <path>`; `--png-pixels` integer | R (IG-Q22) |
| `mine start [threads\|auto]`, `mine stop`, `mine status` | same | integer or `auto` | | K (IG-Q21) |
| `prove payment <txid> <address> [message...]`, `prove reserve [amount] [message...]` | same | hash, address, text; amount, text | | K; views (IG-Q34) |
| `check payment <txid> <address> <proof> [message...]`, `check reserve <address> <proof> [message...]` | same | hash, address, text; address, text | | K; views (IG-Q34) |
| `sign <message...>`, `verify <address> <signature> <message...>` | same | text; address, text | | K |
| the `RETIRED` table (`transfer`, `transfers`, `show_transfer`, `get_tx_note`, `set_tx_note`, `abandon`, `stake_in`, `drain`, `drain_balance`, `unstake`, `stake exit`, `collect_unstaked`, `get_tx_proof`, `check_tx_proof`, `get_reserve_proof`, `check_reserve_proof`, `start_mining`, `stop_mining`, `mining_status`, `chain_health`, …) | — | | | – (IG-Q30) |

### 12.4 `shekyl-wallet-rpc` — options

| Today | New | Kind | Default | Surface | Runtime | Notes |
|---|---|---|---|---|---|---|
| `help`, `version` | same | switch | | CLI | | K |
| `network` | `network` | one-of | `mainnet` | CLI | | K |
| — | `config-file` | path | the account root (IG-13) + `shekyl-wallet-rpc-<network>.toml` | CLI | | N (IG-Q29) |
| `wallet-dir` | `wallet-dir` | path | the account root + `wallets/<network>` | both | | K; the default is no longer the working directory (IG-Q9) |
| `rpc-bind` (IP:port) | `rpc-listen` | endpoint | `127.0.0.1:29500` | both | | R; a wildcard is refused (RT-1); a non-loopback bind is accepted only with `rpc-username` and `rpc-password` set, and every such start carries an IG-14 announcement that credentials and traffic cross the network in the clear; when the RPC channel's wallet leg lands (RT-W10), `rpc-listen` becomes the channel listener and the plaintext non-loopback arm is refused (FOLLOWUPS); the daemon's table reserves the same name for the same meaning |
| `rpc-bind` (`uds://`) | `rpc-socket-file` | path | unset | both | | N; Unix only; refused on Windows |
| `rpc-login` | `rpc-username`, `rpc-password` | secret | unset | file | | R (IG-Q29); both set or neither |
| `disable-rpc-login` | — | | | | | – (IG-4): no credentials is the absence of the two rows, accepted on loopback or a socket |
| `daemon-address` | `daemon-endpoint`, `daemon-socket-file` | peer-endpoint; path | `127.0.0.1:<row rpc port>`; unset | both | | R (IG-Q31) |
| `proxy` | `daemon-socks` | endpoint | unset | both | | R |
| `log-file` | `log-file`, with `log-level`, `log-category`, `log-size-max` | as §5 | the file `shekyl-wallet-rpc-<network>.log` | both | | K; the daemon's rows apply |

## 13. The daemon console

The catalog the Rust console and `shekyl-cli` serve (IG-Q25). The interim C++ console (`src/daemon/command_server.cpp`) is not renamed and is deleted with R8 (DC-N2).

| Today | New | Positionals / flags | Notes |
|---|---|---|---|
| `help [cmd]`, `apropos <kw>...` | `help [command]` | | `apropos` folds into `help` |
| `print_height` | `chain height` | | |
| `print_bc <from> [<to>]` | `chain show` | `--from`, `--to` integer | |
| `bc_dyn_stats <n>` | `chain stats` | `--last` integer | |
| `alt_chain_info [hash]` | `chain alt [hash]` | hash | |
| `print_coinbase_tx_sum <from> [<count>]` | `chain coinbase sum` | `--from`, `--last` integer | |
| `diff` | `chain difficulty` | | |
| `is_key_image_spent <ki>` | `chain spent <key-image>` | hash | |
| `pop_blocks <n>` | — | | –: no grammar successor; it is an armed test lever (RPC_CHANNEL RT-O9.2, §6.4) |
| `print_block <hash\|height>` | `block show <hash\|height>` | hash or integer | |
| `print_tx <hash> [+hex] [+json]` | `tx show <id>` | hash; `--body`; `--json` is the session's | shares the wallet's word |
| `relay_tx <txid>` | `tx relay <id>` | hash | |
| `print_pool`, `print_pool_sh`, `print_pool_stats`, `flush_txpool [txid]` | `txpool list [--short]`, `txpool stats`, `txpool flush [id]` | | |
| `print_pl [white] [gray] [limit]`, `print_pl_stats`, `print_cn`, `print_net_stats` | `peer list [--white] [--gray] [--max N]`, `peer stats`, `peer connections`, `p2p stats` | | |
| `limit [kB/s]`, `limit_up`, `limit_down`, `set_log <level\|categories>` | `option set <name> <value>`, `option show [<name>]` | an option name; a value of that row's kind | IG-12: `option set` takes only the rows §5 marks runtime, needs the `node` grant, and never writes the file; `option show` reports each source and returns each row whose grant the caller holds (§5's Grant column); `limit` (both rates at once) is one option per value and goes |
| `out_peers <n>`, `in_peers <n>` | — | | – (each option is an X row, §5) |
| `bans`, `ban <ip\|@file> [secs]`, `unban <ip>`, `banned <ip>` | `ban list`, `ban add <ip> [--seconds N]`, `ban remove <ip>`, `ban show <ip>` | an IP; a file is `p2p-ban-file` | |
| `start_mining <addr> [threads\|auto] [bg] [battery]`, `stop_mining`, `mining_status`, `show_hr`, `hide_hr` | `mine start <address> [threads\|auto]`, `mine stop`, `mine status` | address; integer or `auto` | builds `mine-address` and `mine-threads` (IG-12); the background arguments go with `bg-mining-*` (§5); the hash rate is in `mine status` |
| `status`, `print_status`, `sync_info` | `daemon status`, `sync status` | | `print_status` is a duplicate of `status` (IG-Q33) |
| `stop_daemon`, `exit` | `daemon stop` | | IG-Q33: no bare word in the shared shell stops the daemon |
| `save`, `flush_cache [bad-txs] [bad-blocks]` | — | | –: LMDB and C++ cache internals |
| `version` | `version` | | |

## 14. The utilities and the tools

### 14.1 Keep or delete (IG-Q26)

| Binary | Ruling | Reason |
|---|---|---|
| `shekyl-blockchain-usage`, `-ancestry`, `-depth` | deleted, each in its own PR (FOLLOWUPS) | ring-signature-era analytics (`rct-only`, `ringsize`) with no referent under FCMP++ (rule 60) |
| `shekyl-gen-ssl-cert` | deleted (FOLLOWUPS) | RT-11: the RPC channel replaces TLS |
| `shekyl-utils-object-sizes` | deleted (FOLLOWUPS) | a C++ debug tool with no remaining job |
| `shekyl-blockchain-import`, `-export`, `-stats`, `shekyl-mdb-copy` | go with LMDB at the redb cutover; not renamed meanwhile (FOLLOWUPS) | LMDB tools; offline bootstrap afterwards, if wanted, is the chain-ingest file source feeding the daemon's store, the DRS lane's to design |
| `shekyl-utils-deserialize` | stays until `tx decode` (§12.3) lands, then goes | the decode need is real; the Rust codecs serve it |
| `shekyl-e2-trace-export` | DRS-E2's | the replay driver's own tool |
| `geblock` | its table is §14.2 | the genesis ceremony tool |
| `shekyl-chain-replay`, `shekyl-wss-q1b-bench`, and every other binary target the gate enumerates | in the gate (IG-Q27); their tables come with the gate (FOLLOWUPS) | development tools follow the grammar |

Each deletion fixes its consumers: the weekly workflow's comment, the logging and blob-dump gate comments that name the tools, the Windows installer and the build workflows for `shekyl-mdb-copy`, and `EXECUTABLES.md`.

### 14.2 `geblock`

The four acts of the genesis ceremony tool under IG-3 (IG-Q35). `geblock` has no path defaults: every path flag is required wherever it applies, so the command line records exactly what the ceremony used. Terms this table adds (the parents it gives `verify`, `create`, `dir`, `file` and `block` are in §3 and §11):

| Term | Parents | Meaning |
|---|---|---|
| genesis | — | the genesis block and its ceremony |
| recipients | genesis, build, verify, block | the genesis recipients: their wallets and the recipients file |
| constants | verify, block | the C header that holds the genesis pins and nonce |
| build | genesis | *verb* — build the genesis coinbase transaction |

| Today | New | Flags | Notes |
|---|---|---|---|
| `gen-wallets --network n --out-dir d` | `genesis recipients create` | `--network`; `--dir <path>` (required) | creates the directory fresh, mode `0700`, refused if it exists or lies inside a git tree; writes the wallet files `0600`, under the secret-file checks of IG-Q24 and §12.1 |
| `build --network n [--recipients f]` | `genesis build` | `--network`; `--recipients-file <path>` (required) | the transaction hex goes to stdout |
| `verify [--config f] [--recipients-dir d]` | `genesis verify` | `--constants-file <path>`, `--recipients-dir <path>` (both required) | `--config` named the C header, which IG-7's `config-file` cannot also name |
| `block-id --network n [--recipients f] [--config f]` | `genesis block` | `--network`; `--recipients-file <path>`, `--constants-file <path>` (both required) | |

## 15. Questions for Part B

**IG-Q21 — `mine` — RULED 2026-10-14.** `mine` is the subject everywhere; Part A's `mining-address` and `mining-threads` are `mine-address` and `mine-threads` (§5).

**IG-Q22 — `out`, `outputs` and `size` — RULED 2026-10-14.** `address --file`, `tx list --direction in|out`, `fee --input-count` / `--output-count`, `shard fetch --png-file` / `--png-pixels`, `shard list held`.

**IG-Q23 — kinds the wallet needs — RULED 2026-10-14.** IG-6 gains `hash` (64 hexadecimal characters: transaction ids and block hashes), `amount` (at most `DISPLAY_DECIMAL_POINT` fractional digits, `shekyl-units` the one source, parsed exactly to atomic units, never a float), `name` and `text`. Shard ids are `integer`; there is no `id` kind. `--expiry` takes a duration only.

**IG-Q24 — the recovery words — RULED 2026-10-14.** The recovery words never appear on a command line, in a history or in a script; they come from `--mnemonic-file` or a hidden prompt. The mnemonic file and the password file get the config file's ownership and permission checks: a group- or world-readable file refuses with a typed code. The wallet password is one option, `wallet-password-file`, admitting the keyword `stdin` (IG-5).

**IG-Q25 — the console — RULED 2026-10-14.** The C++ console is not renamed and dies with R8. §13 is the catalog the Rust console and `shekyl-cli` serve: runtime settings are `option set` and `option show` (IG-12); `is_key_image_spent` is the view `chain spent <key-image>`; `pop_blocks` has no grammar successor: it is an armed test lever (RT-O9.2, RPC_CHANNEL §6.4); the daemon's words are `daemon status` and `daemon stop`.

**IG-Q26 — the utilities — RULED 2026-10-14.** As §14.1. The deletions are separate implementation PRs, each fixing its consumers. `tx decode <body>` (§12.3) replaces `shekyl-utils-deserialize`.

**IG-Q27 — the gate's scope — RULED 2026-10-14.** The gate's subject is every binary target we author, enumerated mechanically from the Cargo workspace and CMake, never from a hand-kept list; the gate asserts the set is non-empty (rule 47). Development tools are in it. The exceptions are the tools bound to LMDB or the C++ while they last, and `shekyl-mdb-copy`, which is LMDB's upstream tool.

**IG-Q28 — the CompleteTree flags — RULED 2026-10-14.** `archival-complete-tree` and `archival-acknowledge` are public rows.

**IG-Q29 — the wallet binaries' file and credentials — RULED 2026-10-14.** The config file lives in the account root, found through the OS interface, never the environment (IG-13): the passwd entry's home plus `.shekyl/<binary>-<network>.toml` on Linux, FreeBSD and macOS; `SHGetKnownFolderPath(FOLDERID_LocalAppData)` plus `Shekyl\<binary>-<network>.toml` on Windows, never Roaming AppData, which copies the wallet and its config to domain servers (rule 36). The wallet directory and the daemon's data directory sit under the same root, one rule. `rpc-username` and `rpc-password` are file-only secrets; `--disable-rpc-login` goes (IG-4).

**IG-Q30 — the `RETIRED` table and `quit` — RULED 2026-10-14.** Both go, with no X rows.

**IG-Q31 — the daemon and wallet-RPC addresses — RULED 2026-10-14.** `daemon-endpoint` and `wallet-rpc-endpoint` are kind peer-endpoint, an IP or an onion, because a local wallet with a remote daemon over Tor is a supported posture; a hostname is refused. The socket-file rows stand beside them, unconstructible together. `shekyl-wallet-rpc`'s `rpc-listen` is interim until the RPC channel's wallet leg lands: it accepts a non-loopback bind when credentials are set, every such start carries an IG-14 announcement, and a FOLLOWUPS row refuses the plaintext non-loopback arm at RT-W10. The daemon's RPC rows are Part A's.

**IG-Q32 — Part A's terms that gain parents — RULED 2026-10-14.** The parents widen as §3 lists; the meanings are unchanged, and `username` and `password` name the wallet RPC's credentials as well as SOCKS5's.

**IG-Q33 — `status` — RULED 2026-10-14.** `status` is a view everywhere: `wallet status`, `stake status`, `mine status`, `sync status`, and the daemon's `daemon status`. The daemon stops with `daemon stop`, so the shared `shekyl-cli` shell has no bare word that stops the daemon.

**IG-Q34 — commands IG-3's verb-or-view rule classifies — RULED 2026-10-14.** A view changes no state; a command that changes state ends in a verb (IG-3). `wallet password` changes the wallet, so it is `wallet password set`. `tx note <id>` is a view, and `tx note set <id> <text>` assigns the note; empty text clears it. `request new` is `request create`. `prove payment`, `prove reserve`, `check payment` and `check reserve` compute and print without changing anything, so they are views. `set` keeps one meaning, assign a value, under `option`, `password` and `note`.

**IG-Q35 — `geblock`'s table — RULED 2026-10-14.** §14.2, with its glossary rows. `geblock` has no path defaults: `--dir`, `--recipients-file`, `--recipients-dir` and `--constants-file` are required wherever they apply, so the command line records exactly what the ceremony used. `genesis recipients create` creates its directory fresh (`0700`, refused if it exists or lies inside a git tree) and writes the wallet files `0600`, under the secret-file checks of IG-Q24 and §12.1.

**IG-Q36 — the service run mode — RULED 2026-10-14, amended the same day** (the same ruling is DC-Q17 in the daemon-configuration cutover; [`RPC_CHANNEL.md`](RPC_CHANNEL.md) RT-16, ruled 2026-10-13). `service` is a public switch, off by default, given on the command line only (IG-Q37): `shekyld` answers the platform's service manager (RT-16); it is accepted only where RT-16 defines it (Windows) and refused elsewhere with a typed code. The run mode selects one root and every default path (`config-file`, `data-dir`, `log-file`) derives from it: on Windows, run-as-user uses the per-account root (`FOLDERID_LocalAppData`) and `service` uses `%ProgramData%\shekyl\`, which only the installer creates (owner and ACL: Administrators, SYSTEM and the service account); the daemon never creates the machine-wide root, and one that is missing, mis-owned or writable by others refuses with a typed code. Linux and macOS keep R2's `/etc/shekyl/` files in every mode. The REJECTED row `run-as-service` keeps its name with the reason in §5. The mechanism, including the deletion of the elevation branch in `daemon_default_data_dir.cpp`, is the daemon-configuration cutover's. Until RT-W14 builds the SCM dispatcher, the row has visibility `reserved` (IG-9, IG-10), worded like the `rpc-listen` row: it is not accepted, and its refusal names RT-W14. Kind, default, surface (command line only, IG-Q37) and the IG-13 root rule stand as ruled; only the row's visibility changes until RT-W14 lands.

**IG-Q37 — where `service` is given — RULED 2026-10-14** (DC-Q18 in the daemon-configuration cutover). Command line only (IG-7): the run mode selects the file, so a key in that file could only restate or contradict it, and on Windows the installer's service registration carries the command line.

**IG-Q38 — what `option show` may reveal — RULED 2026-10-14** (DC-Q16's grammar side, with RPC_CHANNEL §6.4, RT-O24). IG-9's row names the grant under which `option show` discloses it: `health`, `status`, `peers` or `config`, default `config`. `log-level`, `log-category` and the two P2P rate rows are `status`. A row names `health` only if it passes RPC_CHANNEL §6.1's line for that grant: a client needs it to decide whether it can use the node now, and it says nothing lasting about the node; no row does today. The peer, closed-peer and ban rows are `peers`; everything that describes the host or links the operator (`mine-address`, `tor-onion`, paths, SOCKS endpoints, notify commands) is `config`; a secret's value is shown under no grant. IG-12 carries the contract: `option set` refuses a row not marked runtime with a typed code, requires the `node` grant and never writes the file; `option show` reports each value with its source and returns each row whose grant the caller holds.

**IG-Q39 — runtime defaults are values — RULED 2026-10-14** (with RPC_CHANNEL §6.4, RT-O25 and RT-O27). Every runtime row's default is writable as a value: a rate takes `unlimited`, and `log-category` takes `none` (no per-category overrides); an empty category list never means logging off. What `option show` prints is valid input to `option set` and builds the same value, and no row is both runtime and a secret.

**IG-Q40 — the inbound cap — RULED 2026-10-14** (Rick; the same ruling is in [`DAEMON_CONFIG_CUTOVER.md`](DAEMON_CONFIG_CUTOVER.md) §1.1). `p2p-inbound-max` is deleted, and `in-peers` is an X row (§5) whose reopener is a byte quota for metered links. The descriptor safety bound (`InboundCeiling`, [`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D4 and D8) is the only inbound bound and is unchanged; the daemon does not raise its own descriptor limit. What an operator pays is bytes, which the rate rows bound; which peers keep a slot is eviction (PWD-I8); handshake cost follows the accept rate (`P2P_TRANSPORT_LAYER.md` D10.3) and the onion proof-of-work. The unbounded cases (Windows, an unlimited or unreadable limit, an unreadable count) behave as today and are PWD-B1's, and their warnings name nothing the operator can set. The runtime set is four rows: `p2p-upload-max`, `p2p-download-max`, `log-level` and `log-category`.

**IG-Q41 — the Tor binary — RULED 2026-10-15** (Rick, on TSR-F8; the same ruling is in [`DAEMON_CONFIG_CUTOVER.md`](DAEMON_CONFIG_CUTOVER.md) §1.1). `SHEKYL_TOR_BINARY` was an environment input, which IG-13 refuses. It becomes the config key `tor-file`, accepted only with `tor = managed`, whose default is today's location: `tor/tor` beside the running executable, else the version-exact bundle directory under `/opt/shekyl/` on Unix. A set value changes where the binary is looked for, never whether it is verified: it passes the same pin gate, and its failure never falls through to discovery. The environment tier leaves the shared discovery function, so the wallet binaries lose it too; their override is the wallet's settings file.

---

## 16. Part C — the RPC wire's names

**DRAFT, posed 2026-10-18.** Ground: `dev` `2470176c1`. Part C applies [`RPC_WIRE.md`](RPC_WIRE.md) RW-Q1, RW-Q6, RW-Q9 and RW-Q10 to every method the daemon serves, with its parameters and its reply fields (RW-Q8). The method census is §17, the field census §18, the glossary rows §19, and the questions §20. Each row takes its question's recommended answer until that question is ruled. The names land in one rename PR after the store flip, at `CORE_RPC_VERSION` 4.0, with every in-tree client changed in the same PR (RW-Q8); until then the wire keeps today's names.

The rules Part C applies are ruled. It adds no rule; each question in §20 is a convention needed to write the names, or a consequence of a rule for a row already ruled.

- A method name is an IG-3 path rendered with `_` (RW-Q1, RW-Q9). `get` is never a term, and a state change ends in a verb.
- A read ends in a view noun, or in `show` (one item, by a typed selector) or `list` (a bounded list). Each reply type has one method. Where `shekyl-cli` has a word for the method (§13), the method takes its path.
- A parameter or reply-field name is a glossary path rendered with `_`, and never encodes its kind or unit (RW-Q10). Height and count are named in the field (RW-Q4).
- `status` leaves every reply, and a failure is only the JSON-RPC error object (RW-Q3). Each value takes its kind's one encoding (RW-Q4): an amount is decimal atomic units, a 128-bit quantity is one `HexU128` field, a hash is `HashHex`, a body is `bytes`. RK-D23's three states replace every presence flag (`has_*`), every `""` sentinel and every `u64::MAX` sentinel: absent means withheld by grant, `null` means no answer.

**The version read.** `version` is in every grant set. Every authenticated connection may call it, as may the same-user socket and the plaintext view listener. It is never served before authentication (`RPC_CHANNEL.md` §4.3). In its reply only the `version` field is frozen: the key, a JSON integer, `(major << 16) | minor` (RK-D25, RW-Q6). The method's name and its empty params are frozen from the RW-Q6 ruling on. Every other field of the reply follows this Part like any other.

## 17. The method census

Every method served at `2470176c1`: 68 served names (43 JSON-RPC names and 25 REST paths, aliases counted) over 54 methods, which become 42. The grant is `RPC_CHANNEL.md` §6.1's. A parameter's kind is IG-6's or RW-Q4's.

| Served today | Method | Parameters | Grant | Notes |
|---|---|---|---|---|
| `get_version` | `version` | — | every grant | frozen (§16) |
| `/get_height` (`/getheight`), `get_block_count` (`getblockcount`) | `chain_height` | — | chain | IG-Q45, IG-Q46 |
| `get_block_header_by_height` (`getblockheaderbyheight`), `get_block_header_by_hash` (`getblockheaderbyhash`), `get_last_block_header` (`getlastblockheader`), `on_get_block_hash` (`on_getblockhash`) | `block_header_show` | `{"height": n}`, `{"hash": h}` or `"tip"`; `pow` (switch) | chain | RW-Q1; IG-Q46, IG-Q56 |
| `get_block_headers_range` (`getblockheadersrange`) | `block_header_list` | `from`, `to` (inclusive heights), or `hash` (a list); `pow` (switch) | chain | RW-Q1; IG-Q53, IG-Q56 |
| `get_block` (`getblock`) | `block_show` | the selector as `block_header_show`'s; `pow` (switch); `prune` (switch) | chain | RW-Q5's first output index is a field; IG-Q55 |
| `/get_blocks_by_height.bin` (`/getblocks_by_height.bin`) | `block_list` | `height` (a list); `prune` (switch) | chain | RW-Q5; bounded, `RPC_CHANNEL.md` §6.3; IG-Q55 |
| `/get_o_indexes.bin` | — | — | — | deleted (RW-Q5) |
| `/get_transactions` (`/gettransactions`) | `tx_show`, `tx_list` | `id`, one or a list; `prune` (switch) | chain, pool | IG-Q50, IG-Q55; unrelayed entries are host-only (RT-O9.3) |
| `/is_key_image_spent` | `chain_spent` | `key_image` (a list) | chain | a view with an input (IG-Q43) |
| `get_fee_estimate` | `fee` | — | chain | IG-Q52 |
| `get_coinbase_tx_sum` | `chain_coinbase_sum` | `from`, `to` | chain | IG-Q44 |
| `get_alternate_chains`, `/get_alt_blocks_hashes` | `chain_alt` | — | status | IG-Q46 |
| `get_curve_tree_info`, `get_curve_tree_checkpoint` | `curve_show` | `{"height": n}` or `"tip"` | chain | one reply type (IG-Q47) |
| `get_archival_emission_claim_source` | `archival_claim_show` | `{"persona": h}` | chain | the wallet's contract |
| `get_archival_shard_coverage` | `shard_coverage` | — | chain | |
| `request_archival_shard` | `shard_fetch` | `id` | node | the wallet's word (§12.3) |
| `get_info`, `/get_info` (`/getinfo`) | `daemon_status` | — | health; each field by its grant | §13's word |
| `sync_info` | `sync_status` | — | peers | §13's word |
| `get_connections` | `peer_connections` | — | peers | §13's word |
| `/get_peer_list` | `peer_list` | `local` (switch), `banned` (switch) | peers | IG-Q51 |
| `/get_net_stats` | `p2p_stats` | — | status | §13's word |
| `option_set` | `option_set` | `option` (a list of `name`, `value`) | node | named today |
| `option_show` | `option_show` | `name` (a list, optional) | per row (IG-9) | named today |
| `/stop_daemon` | `daemon_stop` | — | node | §13's word |
| `/get_transaction_pool`, `/get_transaction_pool_hashes`, `get_txpool_backlog` | `txpool_list` | — | pool | IG-Q46, IG-Q57 |
| `/get_transaction_pool_stats` | `txpool_stats` | — | pool | IG-Q57 |
| `flush_txpool` | `txpool_flush` | `id` (a list, optional) | node | |
| `relay_tx` | `tx_relay` | `id` (a list) | node | |
| `/submit_transaction` | `tx_submit` | `body` | submit | |
| `get_block_template` (`getblocktemplate`), `get_miner_data` | `block_template` | `address`, `extra`, `extra_size` | mining-work | a view with inputs (IG-Q43); IG-Q46 |
| `submit_block` (`submitblock`) | `block_submit` | `body` | mining-work | named, not positional (RW-Q2) |
| `calc_pow` | `block_pow` | `height`, `hashing`, `seed` | mining-work | IG-Q48 |
| `/start_mining`, `/stop_mining`, `/mining_status` | `mine_start`, `mine_stop`, `mine_status` | `address`, `threads` (an integer or `auto`) for `mine_start` | mining-control | §13's words |
| `set_bans` | `ban_add`, `ban_remove` | `host`; `duration` for `ban_add` | bans | one verb per change; IG-Q44 |
| `get_bans`, `banned` | `ban_list`, `ban_show` | `host` for `ban_show` | bans | IG-Q46 |
| `/get_stem_tallies` | `relay_stats` | — | host-only (RT-O9.3) | |
| `generateblocks` | `dev_block_generate` | `count`, `address`, `nonce` | armed lever (RT-O9.2) | IG-Q49 |
| `/pop_blocks` | `dev_chain_pop` | `count` | armed lever (RT-O9.2) | IG-Q49 |
| `save_bc`, `flush_cache`, `inject_archival_serve_credit`, `/set_log_hash_rate` | — | — | — | deleted (`DRS_X_STORE_FLIP.md` DX-Q3) |

Words of `shekyl-cli` (§11, §13) that render part of another method's reply have no method of their own and stay in `shekyl-cli`'s table (RW-Q7): `chain` (bare), `chain difficulty`, `chain stats` and `peer stats`.

## 18. The field census

Each shape's fields today, and their names under this Part. A reply of `show` is the item itself, and a reply of `list` is an array of items in selector order (IG-Q53). `status` leaves every reply (RW-Q3) and is not repeated below.

**Block header** (`block_header_show`, `block_header_list`; `header` in a block):

| Today | Part C | Kind |
|---|---|---|
| `major_version`, `minor_version` | `version_major`, `version_minor` | integer |
| `timestamp` | `time` | time (IG-Q54) |
| `prev_hash` | `parent` | hash |
| `nonce` | `nonce` | integer |
| `orphan_status` | `orphan` | switch |
| `height` | `height` | integer, ordinal |
| `depth` | `depth` | integer, blocks above this one |
| `hash` | `hash` | hash |
| `difficulty`, `wide_difficulty`, `difficulty_top64` | `difficulty` | `HexU128` |
| `cumulative_difficulty`, `wide_cumulative_difficulty`, `cumulative_difficulty_top64` | `difficulty_cumulative` | `HexU128` |
| `reward` | `reward` | amount |
| `block_size`, `block_weight` | `weight` | integer, bytes |
| `long_term_weight` | `weight_longterm` | integer, bytes |
| `num_txes` | `tx_count` | integer |
| `pow_hash` | `pow` | hash; absent unless asked for (IG-Q56) |
| `miner_tx_hash` | `coinbase` | hash, the coinbase transaction's id |
| `curve_tree_root` | `curve_root` | hash |
| `attestation_root` | `attestation_root` | hash |

`get_block_header_by_hash`'s slot (`hash`, `block_header`) goes: a list reply is in selector order and an unknown item is `null` in its slot (IG-Q53).

**Block** (`block_show`, `block_list`): `block_header` → `header`; `blob` → `body` (bytes); `tx_hashes` → `tx`, a list of `{id, body}` (`block_list` carries each body, as `get_blocks_by_height.bin` does today; `block_show` the same element; each `body` is the pruned form when `prune` is set, IG-Q55); the first output's global index → `output_index` (RW-Q5). `miner_tx_hash` repeats the header's and goes; `json`, epee's rendering, goes (RW-Q4).

**Chain height** (`chain_height`): `height` (`/get_height`'s and `get_block_count`'s count) → `height`, the tip's ordinal (IG-Q45); `hash` → `hash`, the tip's.

**Transaction** (`tx_show`, `tx_list`): `tx_hash` → `id`; `as_hex`, `pruned_as_hex` → `body` (bytes; the pruned form when `prune` is set, IG-Q55); `prunable_as_hex` and `as_json` go; `prunable_hash` → `prunable_hash`; `archival_len` → `archival_size` (bytes); `pruned` goes (the request says); `in_pool` → `txpool` (switch); `double_spend_seen` goes (IG-Q57); `block_height` → `block_height`; `confirmations` → `confirmations`; `block_timestamp` → `block_time`; `output_indices` → `output_index` (a list); `relayed` → `public` (switch: the pool's one bit, IG-Q57; `true` for every caller below host-only, since an entry not yet public is host-only, RT-O9.3); `received_timestamp` goes with the pool's receive time (IG-Q57). `txs_hashes` → `id`; `missed_tx` goes (`null` in the slot).

**Spent** (`chain_spent`): `key_images` → `key_image`; `spent_status` (0, 1, 2) → a list of one-of `unspent`, `chain`, `txpool`, in request order.

**Fee** (`fee`): `fees`, three positional tiers → `economy`, `standard`, `high` (amounts per unit of weight; the priority keywords of §11, IG-Q52).

**Coinbase sum** (`chain_coinbase_sum`): `height`, `count` → `from`, `to`; `emission_amount`, `wide_emission_amount`, `emission_amount_top64` → `emission` (amount); the three `fee_amount` fields → `fee` (amount).

**Alternative chain** (`chain_alt`, an element per chain): `block_hash` → `hash` (its tip); `height` → `height`; `length` goes (it is the length of `block`); `difficulty`, `wide_difficulty`, `difficulty_top64` → `difficulty_cumulative` (`HexU128`; today's name hides that it is cumulative); `block_hashes` → `block` (a list of hashes, tip first); `main_chain_parent_block` → `parent`. `/get_alt_blocks_hashes`'s `blks_hashes` folds into it (IG-Q46).

**Curve tree** (`curve_show`): `root` (free-length hex today) → `root` (hash); `depth` → `layers`; `leaf_count` → `leaf_count`; `height` (`chain_height - 1` in one method) and `block_height` (the other) → `height`, ordinal.

**Archival claim source** (`archival_claim_show`): `p_id` → `persona`; `chain_height` → `height` (ordinal, IG-Q45); `current_settled_epoch` → `settled_epoch`; `has_bond_record`, `join_settlement_epoch` → `joined_epoch` (`null`: no bond record); `holdings_kind` (0, 1) → `holding`, one-of `shards`, `complete-tree`; `held_shard_ids` → `shard` (a list); `claimed_settlement_epochs` → `claim_epoch` (a list); `bonded_total_atomic` → `bond_total` (amount); `bad_interval_count` → `interval_bad_count`; `has_last_served_epoch`, `last_served_epoch` → `served_epoch` (`null`: never served); `has_last_settled_slash_epoch`, `last_settled_slash_epoch` → `slash_epoch` (`null`: never slashed); `epochs` → `epoch` (a list).
- Its epoch element: `settlement_epoch` → `epoch`; `close_block_height` → `closing_height`; `sigma_work_milli` → `work` (milli, IG-Q54); `budget_atomic`, `has_budget_row` → `budget` (amount, `null`: no budget row); `bonds` → `bond`; `shards` → `shard`; `credit_pairs` → `credit`; `claimant_bond_idx` (`u64::MAX` for none) → `claimant` (an index into `bond`, `null` for none).
- Its bond element: `join_settlement_epoch` → `joined_epoch`; `is_foundation_complete_tree` → `complete_tree` (switch); `bad_intervals_flat` (flattened pairs) → `interval_bad`, a list of `{from, to}`, inclusive.
- Its shard element: `shard_id` → `id`; `freeze_height` → `freeze_height`; `has_segment` → `segment` (switch). Its credit element: `bond_idx`, `shard_idx` → `bond`, `shard` (indices).

**Shard coverage** (`shard_coverage`): `as_of_height` → `height`; `leaf_count` → `leaf_count`; `frozen_count` → `frozen_count`; `settled_epoch` → `settled_epoch`; `budget_atomic` → `budget` (amount); `sigma_work_milli` → `work` (milli); `profit_estimate_available` goes (`null` in `profit`); `shards` → `shard`, whose element is `shard_id` → `id`, `bonded_count` → `bonded_count`, `served_count` → `served_count`, `freeze_height` → `freeze_height`, `join_scarcity_micro` → `scarcity` (micro, IG-Q54), `expected_profit_atomic` → `profit` (amount, `null` when not estimated).

**Shard fetch** (`shard_fetch`): `shard_id` → `id` (parameter and field); `shard_hash` → `hash`; `archival_len` → `size` (bytes); `block_count`, `tx_count`, `output_count`, `coinbase_output_count` keep their names; `time_range_seconds` → `duration`; `closing_height` → `closing_height`.

**Daemon status** (`daemon_status`, today's `get_info`; each field present only under its grant, `RPC_CHANNEL.md` §6.1):

| Today | Part C | Today | Part C |
|---|---|---|---|
| `height` (a count) | `height` (ordinal, IG-Q45) | `top_block_hash` | `hash` |
| `target_height` (a count) | `target_height` (ordinal, IG-Q45) | `synchronized` | `synchronized` |
| `busy_syncing` | `syncing` | `offline` | `offline` |
| `following_degraded` | `degraded` | `has_peers` | `peered` |
| `protocol_version` | `protocol_version` | `wide_difficulty` | `difficulty` |
| `wide_cumulative_difficulty` | `difficulty_cumulative` | `target` (seconds) | `block_spacing` (duration) |
| `tx_count` | `tx_count` | `block_weight_limit` | `block_weight_max` |
| `block_weight_median` | `block_weight_median` | `adjusted_time` | `time_adjusted` |
| `already_generated_coins` | `emission` | `release_multiplier` | `emission_multiplier` (micro) |
| `burn_pct` | `burn` (micro) | `total_burned` | `burn_total` |
| `staker_emission_share_effective` | `stake_share` (micro) | `tx_pool_size` | `txpool_count` |
| `start_time` | `started` | `free_space` | `disk_free` |
| `database_size` | `data_size` | `version` (a build string) | `revision` |
| `outgoing_connections_count` | `peer_outbound_count` | `incoming_connections_count` | `peer_inbound_count` |
| `alt_blocks_count` | `alt_count` | `rpc_connections_count` | `rpc_connections` |
| `public_incoming_socket_count` | `clearnet_inbound_count` | `public_outgoing_socket_count` | `clearnet_outbound_count` |
| `tor_incoming_socket_count` | `tor_inbound_count` | `tor_outgoing_socket_count` | `tor_outbound_count` |
| `p2p` (`running`, `offline`) | goes: it repeats `offline` | `white_peerlist_size` | `peer_white_count` |
| `grey_peerlist_size` | `peer_gray_count` | `tx_pool_unbroadcast_count` (host-only, RT-O9.3) | `txpool_private_count` (host-only) |
| `restricted` | `grant` (the grants the caller holds, `RPC_CHANNEL.md` §6.2) | | |

**Version** (`version`): `version` (frozen); `release` → `tagged`; `current_height` (a count) → `height` (ordinal, IG-Q45); `target_height` (a count) → `target_height` (ordinal, IG-Q45); `consensus_constants_digest` → `consensus_digest`; `nettype` → `network` (its value `fakechain` is `regtest`, §3's name); `genesis_hash` → `genesis`.

**Connection** (`peer_connections`; `peer` in `sync_status`): `incoming` → `inbound` (switch); `localhost`, `local_ip` → `local` (switch); `address`, `host`, `ip`, `port` → `endpoint` (peer-endpoint); `address_type` → `connector` (one-of `clearnet`, `tor`); `recv_count`, `send_count` → `download`, `upload` (bytes); `recv_idle_time`, `send_idle_time` → `download_idle`, `upload_idle` (duration); `state` → `state`; `live_time` → `age` (duration); `avg_download`, `current_download`, `avg_upload`, `current_upload` → `download_speed_average`, `download_speed_current`, `upload_speed_average`, `upload_speed_current` (bytes per second; KiB/s today); `support_flags` → `flags`; `connection_id` → `id`; `height` → `height`.

**Sync status** (`sync_status`): `height` (a count) → `height` (ordinal, IG-Q45); `target_height` (a count) → `target_height` (ordinal, IG-Q45); `peers`, each `{info: …}` → `peer`, a list of connections, unwrapped; `spans` → `span`, whose element is `start_block_height` → `from`, `nblocks` → `blocks`, `connection_id` → `connection`, `rate` → `download_speed` (bytes per second), `speed` (the queue's relative speed, a percentage today) → `pace` (micro), `size` → `size` (bytes), `remote_address` → `endpoint`; `overview`, an ASCII picture, goes: it is the console's rendering.

**Peer list** (`peer_list`, an element per peer): `host`, `ip`, `port` → `endpoint`; each element names its list in `tier`, one-of `white`, `gray` (IG-Q51); `white_list`, `gray_list` go. `public_only` (default true) → `local` (switch, default off: include local endpoints); `include_blocked` → `banned` (switch).

**P2P statistics** (`p2p_stats`): `start_time` → `started`; `total_bytes_in`, `total_bytes_out` → `download`, `upload` (bytes); `total_packets_in`, `total_packets_out` → `download_packets`, `upload_packets`.

**Options** (`option_set`, `option_show`): `options` → `option`, whose element keeps `name`, `value`, `source`, `runtime` and `secret`, and the secret form's `set` → `assigned` (§11's `set` is the verb; IG-Q42); `option_show`'s `names` → `name`. A refusal's `data` (IG-11, RW-Q3) keeps `code`, `option`, `source` and `message`, and its `params`, positional pairs today, become `parameter`, a map.

**Pool entry** (`txpool_list`): `id`, `weight`, `fee`, the Rust pool's listing (`rust/shekyl-mempool/src/relay.rs`, `Listed`; IG-Q57). Today's `tx_info` fields `id_hash` → `id`, `weight` → `weight`, `fee` → `fee`; `tx_json`, `tx_blob`, `blob_size`, `max_used_block_id_hash`, `max_used_block_height`, `kept_by_block`, `last_failed_height`, `last_failed_id_hash`, `receive_time`, `relayed`, `last_relayed_time`, `do_not_relay` and `double_spend_seen` go; the body is `tx_show`'s. `spent_key_images` goes with them. `/get_transaction_pool_hashes`' `tx_hashes` and `get_txpool_backlog`'s packed `backlog` fold into the list (IG-Q46).

**Pool statistics** (`txpool_stats`): `pool_stats` unwraps. `txs_total` → `count`; `bytes_total`, `bytes_min`, `bytes_max`, `bytes_med` → `weight_total`, `weight_min`, `weight_max`, `weight_median`; `fee_total` → `fee_total`; `num_double_spends` goes (IG-Q57); `num_not_relayed` (host-only, RT-O9.3) → `private_count` (host-only); `num_failing`, `oldest`, `num_10m`, `histo_98pc` and `histo` go (IG-Q57).

**Template** (`block_template`): parameters `wallet_address` → `address`, `reserve_size` → `extra_size` (bytes, at most 8), `extra_nonce` → `extra` (bytes); `prev_block`, refused when set, goes. Reply: the difficulty triple → `difficulty`; `height` → `height` (the next block's ordinal, `HEIGHT_SEMANTICS.md` §3.1 C6); `reserved_offset` → `extra_offset`; `expected_reward` → `reward`; `prev_hash` → `parent`; `seed_height` → `seed_height`; `blocktemplate_blob` → `body`; `blockhashing_blob` → `hashing` (bytes); `seed_hash` → `seed`; `next_seed_hash` (`""` when unchanged) → `seed_next` (`null` when unchanged). `get_miner_data` folds in (IG-Q46): its `major_version` → `version_major`, `median_weight` → `weight_median`, `already_generated_coins` (a number there) → `emission` (amount); its `height`, `prev_id`, `seed_hash` and `difficulty` (a `0x` string there) are the template's; its `tx_backlog` is `txpool_list`'s.

**Submit** (`block_submit`, `tx_submit`): `params[0]` and `tx_blob` → `body`; `block_id` → `hash`. `tx_submit`'s `verdict`, `height` and `cause` keep their names.

**Proof of work** (`block_pow`): `height` → `height`; `block_blob` → `hashing`; `seed_hash` (`""` allowed) → `seed` (optional). The bare-string reply → `{"pow": h}`.

**Miner** (`mine_start`, `mine_status`): `miner_address` → `address`; `threads_count` (0 for auto) → `threads` (an integer, or the keyword `auto`). Status: `active` → `active`; `speed` (hashes per second) → `speed`; `threads_count` → `threads`; `address` (`""` when idle) → `address` (`null` when idle); `pow_algorithm` (always `RandomX`) goes; `block_target` → `block_spacing`; `block_reward` → `reward`; the difficulty triple → `difficulty`.

**Bans** (`ban_add`, `ban_remove`, `ban_list`, `ban_show`): `set_bans`' list of `{host, ip, ban, seconds}` → one `host` and `duration` per `ban_add` and one `host` per `ban_remove`; `ip` goes (the host carries it); `banned`'s `address` → `host`. An entry: `host`, `seconds` → `duration` (remaining), `permanent` → `permanent`; `banned`'s `banned` goes (`ban_show` replies `null` for a host not banned).

**Pool and chain flush, relay** (`txpool_flush`, `tx_relay`): `txids` → `id`.

**Relay statistics** (`relay_stats`): `floor` → `floor`, whose element is `connector` → `connector`, `achieved_out_connections` → `outbound_count`, the inner `floor` → `outbound_min`, `below` → `below`; `tallies` → `tally`, whose element is `peer` (a 16-byte id) → `peer` (bytes), `connector` → `connector`, `propagated`, `silent` → `propagated`, `silent`, `distinct_sources` → `sender_count`.

**Armed levers**: `generateblocks`' `amount_of_blocks` → `count`, `wallet_address` → `address`, `starting_nonce` → `nonce`, `prev_block` goes; reply `height` → `height`, `blocks` → `hash` (a list). `pop_blocks`' `nblocks` → `count`; reply `height` (a count) → `height` (ordinal).

## 19. Glossary — Part C's terms

Rows below add to §3 and §11. A term already there that gains a parent here keeps its one meaning; where its meaning is stated per parent, as `height`'s is, the row under its new parent says what it names there.

**New terms:**

| Term | Parents | Meaning |
|---|---|---|
| header | block | a block's header; with `show` and `list`, the read |
| template | block | *view* — a block to mine on, built for an address |
| submit | block, tx | *verb* — hand to the daemon for acceptance |
| curve | — | the curve tree, FCMP++'s membership accumulator (IG-Q47) |
| root | curve | a tree's root hash |
| leaf | curve | a leaf of the curve tree |
| layers | curve | the tree's depth, in layers |
| claim | archival | an emission claim's source record |
| coverage | shard | *view* — holders per shard |
| persona | — | a persona's canonical id |
| generate | block | *verb* — mine blocks; only under `dev` |
| pop | chain | *verb* — remove blocks from the tip; only under `dev` |
| id | tx, connection, shard | an identifier: a transaction's id (a hash), a connection's, a shard's |
| key | — | a key; only in `key image` |
| image | key | a key image (a hash) |
| prune | tx | a switch: carry the pruned body |
| prunable | tx | the prunable part of a transaction |
| public | tx | the pool's one bit: the relay has made the transaction public (`DAEMON_RELAY_PRIVACY.md` acceptance criterion 2) |
| private | txpool | entries whose `public` bit is unset; with `count`, host-only (RT-O9.3) |
| confirmations | tx | blocks since the transaction's |
| parent | block | the block this one extends (a hash) |
| nonce | block | the header's nonce; under `dev block generate`, the first nonce |
| orphan | block | not on the main chain |
| reward | block, mine | the block's reward, an amount |
| cumulative | difficulty | summed over the chain to this block |
| longterm | weight | the long-term weight |
| median | weight, size | the median |
| total | fee, weight, burn, bond | a sum |
| attestation | header | the attestation tree |
| index | output | a global output index |
| time | block, header, daemon | a point in time (IG-Q54) |
| adjusted | time | the network-adjusted time |
| started | daemon, p2p | when it started, a time |
| duration | ban, shard | a span of time (IG-Q54) |
| spacing | block | the target time between blocks |
| target | sync | what the node is syncing to; `target height`, its height |
| synchronized | daemon | the node holds the target |
| syncing | daemon | the node is syncing |
| degraded | daemon | following, degraded |
| peered | daemon | at least one handshaken session (`has_peers`) |
| protocol | daemon | the P2P protocol's version |
| emission | coinbase, daemon | coins emitted |
| burn | daemon | the share the next coinbase burns (micro) and, with `total`, what has burned |
| tagged | version | a tagged release build |
| multiplier | emission | the release multiplier (micro; `shekyl-economics`) |
| share | stake | the stakers' effective emission share (micro) |
| disk | daemon | the data directory's disk |
| free | disk | its free space, in bytes |
| outbound | peer, clearnet, tor | connections we open |
| grant | daemon | the grants this connection holds |
| consensus | — | the consensus rules; `consensus digest`, the constants' digest |
| digest | consensus | a digest |
| connector | connection, floor, tally | one-of `clearnet`, `tor` |
| connection | span | the P2P connection downloading the span |
| host | ban | an IP address or subnet |
| banned | peer | include banned peers |
| parameter | — | a diagnostic's named parameters (IG-11) |
| offline | daemon | P2P is off (IG-Q3's offline state) |
| economy | fee | the `economy` tier's fee per unit of weight |
| standard | fee | the `standard` tier's |
| high | fee | the `high` tier's |
| name | option | an option's name |
| value | option | an option's value, valid input to `option set` |
| source | option | where the value came from: `default`, `file`, `cli`, `runtime` |
| runtime | option | whether `option set` accepts the row (IG-12) |
| secret | option | the row is a secret: its value is never shown |
| assigned | secret | the secret has a value |
| major | version | the major version |
| minor | version | the minor version |
| state | connection | the connection's state |
| age | connection | how long it has lived |
| idle | download, upload | time since the last bytes |
| speed | download, upload, mine | per second: bytes, or under `mine` hashes |
| average | speed | the average |
| current | speed | the current value |
| flags | connection | the peer's support flags |
| packets | download, upload | a packet count |
| span | sync | a block span being downloaded |
| pace | span | the span queue's relative speed, a ratio (micro) |
| tier | peer | which peer list holds it, one-of `white`, `gray` |
| offset | extra | where the reserved extra bytes start |
| extra | template | the coinbase's extra nonce: the bytes, and with `size` how many to reserve |
| revision | daemon | the build's version string |
| joined | bond, claim | the epoch the bond joined |
| closing | epoch, shard | the epoch's closing height |
| hashing | template, pow | the bytes proof of work hashes |
| next | seed | the next seed |
| active | mine | the miner is running |
| permanent | ban | a ban with no end |
| floor | relay | the per-connector outbound floor |
| below | floor | under the floor |
| tally | relay | per-successor relay outcomes |
| propagated | tally | propagated relays |
| silent | tally | silent relays |
| sender | tally | a distinct peer that sent the transaction; with `count` |
| holding | claim | one-of `shards`, `complete-tree` |
| settled | claim, coverage | the last settled epoch |
| bond | claim | an archival bond |
| interval | bond | an interval; `interval bad`, an interval the bond failed |
| bad | interval | failed |
| served | claim, coverage | served |
| slash | claim | slashed |
| work | epoch, coverage | the summed work (milli, IG-Q54) |
| budget | epoch, coverage | the budget, an amount |
| credit | epoch | a credit pair |
| claimant | epoch | the claiming bond's index |
| segment | shard | the shard's segment is held |
| freeze | shard | the freeze height |
| frozen | coverage | frozen shards, with `count` |
| bonded | coverage, shard | bonded holders, with `count` |
| scarcity | coverage | the join scarcity (micro, IG-Q54) |
| profit | coverage | the expected profit, an amount |

**Terms of §3, §11 and §14.2 that gain a parent:**

| Term | Gains parents | Meaning there |
|---|---|---|
| pow | —, dev, block | proof of work (RandomX): under `block`, *view* — a block's proof-of-work hash; under `dev`, its seed schedule (IG-Q48) |
| coinbase | header | the coinbase transaction: under `chain`, its outputs (§11); under `header`, its id |
| output | block | the block's first output; `output index`, its global index |
| alt | daemon | §11's `alt` gains `daemon`: the alternative blocks |
| genesis | version | §14.2's `genesis` gains `version`: the genesis block's hash |
| endpoint | connection, peer, span | §11's `endpoint`: the peer's |
| version | header | the block format's version (bare, §3's `version` is the binary's) |
| archival | tx | under `tx`, `archival size`: the archival form's length |

Value keywords added: `unspent` (spent), `tip` (a header, block or curve selector), `shards`, `complete-tree` (holding), `clearnet`, `tor` (connector), `white`, `gray` (tier).

Every term of §3 and §11 used as a field (`height`, `hash`, `count`, `weight`, `fee`, `address`, `size`, `depth`, `seed`, `threads`, `difficulty`, `from`, `to`, `blocks`, `download`, `upload`, `inbound`, `local`, `endpoint`, `white`, `gray`, …) gains the object that holds it as a parent and keeps its one meaning; the schema RW-Q7's table generates lists those edges for the gate. The implementing PR builds the field table from the reply types (RW-Q7) and brings any term this census missed as a row for ruling in its review.

## 20. Questions for Part C

Each is posed for ruling. A question that amends a ruled row names it.

**IG-Q42 — a field's name, and a list-valued parameter — POSED 2026-10-18.** RW-Q10 makes parameter and field names glossary paths, and two conventions are needed to write them. *Recommended:* a field's name is the rest of its path below the object that holds it, so inside a block header the field is `hash`, never `block_hash`; and a list-valued parameter or field takes the singular term with an array value (`{"height": [7, 8]}`), IG-6's list convention on the wire. The gate reads both from the schema RW-Q7's table generates from the request and reply types, never from a hand list. One consequence amends RT-O23's reply (`RPC_CHANNEL.md` §6.4): a secret row's `set` collides with §11's verb `set`, and becomes `assigned`.

**IG-Q43 — a view's inputs — POSED 2026-10-18.** RW-Q1 says a view noun takes no selector. Several reads take an input that is not a choice of stored item: `chain spent` takes key images, `block template` the address to pay, `block pow` a block's hashing bytes. *Recommended:* a *selector* picks a stored item and belongs only to `show` and `list`; an *input* parameterizes what a view computes, and a view may take inputs. `chain spent` (IG-Q25's view) stays a view.

**IG-Q44 — §13's range reads and the ban duration — POSED 2026-10-18.** This amends §13 rows ruled 2026-10-14 (IG-Q25).
- RW-Q1 gives `show` one item by a typed selector and makes `block header list` the bounded range of headers. §13 maps `print_bc <from> [<to>]`, a range of headers, to `chain show --from --to`.
- `print_coinbase_tx_sum <from> [<count>]` maps to `chain coinbase sum --from --last`, where `last` already means "the most recent N blocks" (§11).
- `alt_chain_info [hash]` maps to `chain alt [hash]`, a selector on a view.
- `ban add <ip> [--seconds N]` names its unit, which RW-Q10 refuses on the wire.

*Recommended:* `print_bc` becomes `block header list --from --to`, and `chain show` leaves §13; `chain coinbase sum` takes `--from` and `--to`, inclusive heights, so `last` keeps its one meaning; `chain alt` takes no argument and the console finds the chain in the one reply; `ban add <ip> [--duration <quantity>]`, an IG-6 duration.

**IG-Q45 — the tip's height — POSED 2026-10-18.** `/get_height`, `get_block_count`, `get_version`'s `current_height`, `get_info`'s and `sync_info`'s `height`, the `target_height` of `get_version`, `get_info` and `sync_info` (the core's target, a count: `src/rpc/rpc_facts_ffi.cpp`, `chain_tip`'s caller), the claim source's `chain_height` and `pop_blocks`' reply carry the chain's *count* (tip + 1, `HEIGHT_SEMANTICS.md` §1), most of them under the name `height`. `HEIGHT_SEMANTICS.md` §3.1 (C1, C2) keeps the wire a raw integer whose identity is its field's name, decoded once at the edge, and RW-Q4 names height versus count in the field. *Recommended:* every tip-shaped field is an ordinal, and no field carries the count. The tip is `height`, and `target_height` on `daemon_status`, `sync_status` and `version` moves with it in the same PR, so a client never compares an ordinal with a count. Each client's decode site changes from `ChainCount::from_raw` to `BlockHeight::from_raw` in the rename PR, and computes the count where it needs one. The change is safe across versions because no client decodes a reply from a daemon of another version: RK-Q11's version-first read (`DAEMON_RPC_KV_GET_INFO.md`, ruled 2026-10-10) compares `version` with `CORE_RPC_VERSION` and refuses a mismatch before the strict decode runs, and the rename PR (at 4.0) must not relax that match. The alternative keeps the count on the wire under the name `count` (`chain_height`'s reply would then be a count named by its field), which leaves a view called `height` that prints a count.

**IG-Q46 — the folds — POSED 2026-10-18.** RW-Q1 gives one method per reply type, which folds methods that answer one fact twice:
- `on_get_block_hash` into `block_header_show` (the hash is a header field), and `get_block_count` into `chain_height`;
- `/get_alt_blocks_hashes` into `chain_alt`, whose elements carry their blocks' hashes;
- `/get_transaction_pool_hashes` and `get_txpool_backlog` into `txpool_list`;
- `get_miner_data` into `block_template`: its only consumers are the regtest suite and the Python framework, and its fields are the template's. The FOLLOWUPS `get_miner_data` row (one chain state across its reads; owner `RPC_WIRE.md`'s per-lock-domain rule) moves to `block_template` with it;
- `get_bans` and `banned` into `ban_list` and `ban_show`, §13's words.

*Recommended:* all five. Each folded method's consumers move in the rename PR (RW-Q8).

**IG-Q47 — the curve tree — POSED 2026-10-18.** `get_curve_tree_info` and `get_curve_tree_checkpoint` reply one shape (root, depth, leaf count, height) for the tip and for a given height. `tree` is taken: under `complete` it is the CompleteTree posture (IG-Q28), and a term has one meaning (IG-2). *Recommended:* a new subject `curve`, the curve tree, and one method `curve_show` with the selector `{"height": n}` or `"tip"` (RW-Q1). The alternative gives `tree` the meaning "the curve tree" and renames IG-Q28's row.

**IG-Q48 — `pow` — POSED 2026-10-18.** This amends §3's `pow` row, ruled 2026-10-13. `calc_pow` computes a block's proof-of-work hash for an external miner; §3 defines `pow` under `dev` as "the RandomX seed schedule". *Recommended:* `pow` means proof of work (RandomX) everywhere, a subject and a child of `dev` and `block`: `block pow` is the view that computes the hash, the header's `pow` field holds it, and `dev-pow-seed-*` keeps its spelling, now read as "proof of work's seed".

**IG-Q49 — the armed levers' names — POSED 2026-10-18.** `generateblocks` and `pop_blocks` are armed test levers (RT-O9.2): never on mainnet, served only to the host's administrator when armed. IG-Q25 gives `pop_blocks` no console word; each still needs a method name under RW-Q1. *Recommended:* they sit under `dev`, as IG-8 places development options: `dev_block_generate` and `dev_chain_pop`. Neither has a console word, and IG-Q25 stands.

**IG-Q50 — one transaction and many — POSED 2026-10-18.** `/get_transactions` takes a list of ids; §13's word is `tx show <id>`. *Recommended:* two methods, two reply types (RW-Q1): `tx_show {"id": h}` and `tx_list {"id": [h, …]}`, bounded by the resource policy (`RPC_CHANNEL.md` §6.3). Unrelayed entries stay host-only in both (RT-O9.3).

**IG-Q51 — the peer list — POSED 2026-10-18.** `/get_peer_list` returns two arrays, and `public_only` defaults to true, against IG-4's "a switch defaults to off"; §13's word is `peer list [--white] [--gray] [--max N]`. *Recommended:* `peer_list` returns one list, each element naming its list in `tier` (`white` or `gray`); `public_only` becomes `local` (default off: include local endpoints, §3's `local`) and `include_blocked` becomes `banned`; the bound is the resource policy's, and the console's `--white`, `--gray` and `--max` filter the one reply.

**IG-Q52 — the fee read — POSED 2026-10-18.** `get_fee_estimate` returns three positional tiers. `fee` is the wallet's view "a fee quote". *Recommended:* the daemon method is `fee`, with that one meaning; its reply names its tiers by §11's priority keywords (`economy`, `standard`, `high`), each an amount per unit of weight, and the wallet's `fee` view prints a quote computed from it.

**IG-Q53 — a read's reply — POSED 2026-10-18.** Today each read wraps its result under its own key (`block_header`, `block_headers`, `headers`, `txs`, `chains`, `bans`, `connections`, `pool_stats`), and a by-hash read echoes each hash in a slot. *Recommended:* a `show` or view reply is the item itself; a `list` reply is an array of items in selector order, an unknown item `null` in its slot (RK-D23). The wrappers, the slots and `missed_tx` go.

**IG-Q54 — the wire kinds of time, quantities and fractions — POSED 2026-10-18.** RW-Q10 takes units out of names (`_seconds`, `_time`, `_timestamp`, `_milli`, `_micro`, `_pct`, KiB/s), so each unit must live in its kind. The economics ratios (`burn_pct`, `release_multiplier`, `staker_emission_share_effective`) are fixed-point at `shekyl_fixed_point_scale` = 1,000,000 (`config/economics_params.json`; `SCALE` in `rust/shekyl-economics/src/params.rs`), whatever their names say. RW-Q4's shared-kind rule ("where a wire kind is also a grammar kind, the syntax is IG-6's") would make a duration or a byte count IG-6's `quantity`, a string such as `"3600s"` or `"100MiB"`, on the wire. *Recommended:* as RW-Q4 did for the amount, these are wire kinds of their own, integers whose unit the kind fixes: `time` (unix seconds), `duration` (seconds), byte counts (bytes), rates (units per second), and `milli` and `micro`, a ratio in thousandths and in millionths. No field needs a percent: the economics ratios and the sync span's relative speed are `micro`, so no `percent` kind is minted. A client does arithmetic on them, and a renderer applies the unit once. Each kind's unit is stated once in RW-Q4's registry, never in a name. The console keeps IG-6's `quantity` for what an operator types (`--duration 1h`).

**IG-Q55 — a transaction's body — POSED 2026-10-18.** `/get_transactions` takes three switches that choose which of four always-present fields are filled (`decode_as_json`, `prune`, `split`). The wallet's block fetch reads the pruned form (`rust/shekyl-engine-core/src/engine/block_fetch.rs`), and only tests read the prunable part alone. *Recommended:* wherever a transaction's body is carried — `tx_show`, `tx_list`, and each transaction of `block_show` and `block_list` — the method takes the input `prune` (a switch, off by default), which makes each `body` the pruned form; a pruned entry then carries `prunable_hash`. The wallet's scan reads blocks with pruned bodies (`block_fetch.rs`), so `block_list` needs the switch as much as `tx_list` does. `split` and the JSON rendering go (RW-Q4).

**IG-Q56 — the proof-of-work hash in a header — POSED 2026-10-18.** `fill_pow_hash` has two restricted-listener policies: `get_block` and `get_block_header_by_height` blank the field silently, and the other three header methods refuse with `-19`. *Recommended:* one input, `pow` (a switch, off by default); a caller whose grant or resource bound does not cover it is refused with the RW-Q3 class that applies, never answered with a blank; the field is absent when not asked for.

**IG-Q57 — the pool's listing — POSED 2026-10-18.** The Rust pool's listing is id, weight and fee, never the receive time, because receive times across many nodes' listings point at a transaction's origin (the review of #1102; `rust/shekyl-mempool/src/relay.rs`, `Pool::listing`). *Recommended:* `txpool_list`'s element is exactly that listing, the body comes from `tx_show`, and the C++ pool's other fields go; `txpool_stats` keeps the counts and weights, and its fields derived from receive times (`oldest`, `num_10m`, `histo`, `histo_98pc`) and the C++ pool's `num_failing` go. The same grounding reaches the transaction entry and the statistics:
- `double_spend_seen` and `num_double_spends` go. `shekyl-mempool` holds no per-entry conflict flag: its door admits one spender per key image (`view.rs`, CEN-M7's conflict map), and the `conflicted` list in `template.rs` is the template builder's, not an entry's.
- `relayed` becomes the pool's one bit, `public` (`DAEMON_RELAY_PRIVACY.md` acceptance criterion 2; `DRS_X_STORE_FLIP.md` DX-F6). For any caller below host-only it is constant, `true`, because an entry not yet public is host-only (RT-O9.3).
- The counts of entries not yet public, `num_not_relayed` on the statistics and `tx_pool_unbroadcast_count` on `daemon_status`, are host-only, and are named after the pool's bit: `private_count` and `txpool_private_count`.
