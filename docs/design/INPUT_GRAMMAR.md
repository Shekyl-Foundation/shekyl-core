# Shekyl input grammar — the rules and every binary's names

**Status:** RULED (Rick) — Part A 2026-10-13 (§0–§9, IG-Q1…IG-Q20), Part B
2026-10-14 (§10–§15, IG-Q21…IG-Q39); IG-Q40, the inbound cap, 2026-10-14;
IG-Q41, the Tor binary, 2026-10-15; Part C (§16–§20, IG-Q42…IG-Q57), the RPC wire's names, 2026-10-19; Part D (§21–§22, IG-Q58…IG-Q65), checking a configuration and the shipped file, RULED 2026-10-22 (Rick), as written with the IG-Q64 package-header amendment; the sole-member rule it names is shekyl-core #1157; Part E (§23–§24, IG-Q66…IG-Q72), the Tor status fields, RULED 2026-10-24 (Rick), with amendments; Part F (§25–§26, IG-Q73…IG-Q93), the wire at the rename, RULED 2026-11-10 (Rick), as recommended; IG-Q94, the selector's wire form, RULED 2026-11-11 (Rick), as posed; Part G (§27, IG-Q103…IG-Q105), the owner's socket and the service mode, RULED 2026-11-12 (Rick), as posed. Parts C and F are the daemon's wire at `CORE_RPC_VERSION` 4.0 (`RPC_WIRE.md` RW-Q8), its schema generated at `docs/generated/rpc_wire_schema.tsv`.
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

**IG-2 One vocabulary, as a tree.** The glossary is a tree of terms. Each term is defined once, project-wide, and lists its parents; a term with no parent is a *subject*. A term reused under several parents keeps its one meaning (`listen` under `clearnet`, `onion`, `rpc` and `view`). Every segment of every name is a term in the tree, including plain words (`file`, `dir`, `max`, `help`): the gate has no exemption list. The glossary is acyclic: no term is its own ancestor through its parents, and the gate refuses a cycle. An edge expresses refinement only; a name that points at another subject does so by reference (IG-Q42).

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

**IG-7 Surfaces.** Each row says where it may be given. Command-line only: `help`, `version`, `network`, `config-file`, `service` (each selects which file is read, so a key in that file could only restate or contradict it) and `config-verify` (a key in the file would make every start a check). File only: every secret and every command value. Everything else: both, CLI winning per key.

**IG-8 Development levers.** A `dev-` option is hidden from help and generated docs, names the networks it is accepted on as data in its row (a `dev-` option given on any other network is refused at parse, rule 71), and is announced at every start when set. It follows every other rule. **No `dev-` option is ever accepted on mainnet**: a lever mainnet genuinely needs is not a development lever and gets a public row.

**IG-9 One table per binary, generated everything.** The table row: id, name, kind, constraint, keywords, default (a value, unset, or "derived from the network row"), surfaces, runtime (`yes` or `no`: whether `option set` accepts the row, IG-12), grant (`health`, `status`, `peers` or `config`, default `config`: the grant under which `option show` discloses the row; [`RPC_CHANNEL.md`](RPC_CHANNEL.md) §6.4, RT-O24), visibility (`public` / `dev` / `rejected` / `reserved`), accepted networks (`dev` only), owning subsystem, help text. From the table: `--help`, completion, the documentation tables, and an annotated TOML example. A gate regenerates the docs and diffs them, and asserts the table is non-empty (rule 47). A row names `health` only if it passes RPC_CHANNEL §6.1's line for that grant: a client needs it to decide whether it can use the node now, and it says nothing lasting about the node; no row does today. The peer, closed-peer and ban rows are `peers`; everything that describes the host or links the operator (`mine-address`, `tor-onion`, paths, SOCKS endpoints, notify commands) is `config`; a secret's value is shown under no grant.

**IG-10 Unknown and refused names.** An unknown name is one general refusal that names the nearest live name, computed from the table (edit distance), never from a hand list. A REJECTED row (a feature deliberately refused) carries its reason and a pointer to the decision; it is never accepted, never in help, and its refusal states the reason. A REJECTED row is a contract entry in the sense of rule 23, not a code symbol: it is never deleted as dead. A RESERVED row (a name held for a ruled future option; rule 23's reserved slot) is the same kind of entry: never accepted, never in help, and its refusal names what the name is reserved for and where that is ruled.

**IG-11 Diagnostics.** Every refusal is a typed value: a stable code (`config.value.range`, `config.file.permissions`, …), the option, the source (`cli`, `file:path:line`, `default`, `runtime`) and named parameters. One renderer turns it into the English message, which states what was wrong, where, and what to do (rule 82). Machine output and logs carry the code. A configuration refusal exits with status 2; a runtime failure with 1.

**IG-12 Runtime changes share the constructor.** A value that can also change while running (rates, log level and categories, mining) is marked runtime in its row (IG-9) and is built by the same constructor on both surfaces, with the same refusals. `option set <name> <value>` changes it: it refuses a row not marked runtime with a typed code, requires the `node` grant, and never writes the file. `option show [<name>]` reports each value with its source (`default`, `file`, `cli`, `runtime`) and returns each row whose grant (IG-9) the caller holds; a row the caller may not see is absent, never emptied, and a secret's value is shown under no grant, only whether it is set. Every runtime row's default is writable as a value (`unlimited`, `none`), so `option set` returns a row to its default without a restart; what `option show` prints is valid input to `option set` and builds the same value; and no row is both runtime and a secret, which the gate asserts (RPC_CHANNEL §6.4, RT-O25, RT-O27). Mining changes while running through `mine start` and `mine stop` instead, which build `mine-threads` through its constructor, so that row is not marked runtime. `mine-address` is the config row, not an argument of `mine start`, and is not marked runtime either. The live value is owned by its subsystem. No binary ever writes its own config file.

**IG-13 Inputs come from the table, and nowhere else.** No option value comes from the environment. Default paths come from the operating system's account and known-folder interfaces, never from `HOME`, `XDG_*` or `%APPDATA%`. Each binary's per-account root is the passwd entry's home plus `.shekyl` on Linux, FreeBSD and macOS, and `SHGetKnownFolderPath(FOLDERID_LocalAppData)` plus `Shekyl` on Windows, never Roaming AppData, which copies the wallet and its config to domain servers (rule 36); a run-as-user daemon's data and log defaults, the wallet directory and the wallet binaries' config files sit under it. On Windows the daemon's run mode selects its root, and every default path it derives (`config-file`, `data-dir`, `log-file`) sits under that root: run-as-user uses the per-account root and `service` (IG-Q36) uses `%ProgramData%\shekyl\`, which only the installer creates (owner and ACL: Administrators, SYSTEM and the service account); the daemon never creates the machine-wide root, and one that is missing, mis-owned or writable by others refuses with a typed code. On Linux, FreeBSD and macOS the run mode does not move the configuration file, which is R2's `/etc/shekyl/` in both modes; a run-as-user daemon's data and log defaults sit under the per-account root, and a `service` daemon's unit passes `data-dir` and `log-file` (IG-Q105). The only environment reads permitted are presentation-only (terminal capabilities that change rendering, never a value). Every resolved default path appears in the startup line with its source. A service account whose passwd home is unset or `/nonexistent` has no default paths: the packaging sets the account's home or the unit passes `--data-dir` and `--log-file` (the shipped unit does both, IG-F10).

**IG-14 Required announcements are not log events.** The effective-configuration line, `dev-` lever warnings and posture warnings (clearnet-only, offline, a plaintext RPC listener bound beyond loopback) reach the log and standard error at every start whatever the log level, and so does a stop the operator asked for (`stop requested by` its cause: a signal, a console event or the RPC's `stop_daemon`; Rick, 2026-11-06), with no level tag. A forced stop (chain sync's owner ending on its own) is an error event (`chain sync stopped:` the cause) and fails the exit. The effective-configuration line shows every value and its source; a secret is shown as set, never its value (IG-6).

**IG-15 Home.** The rules become one cursor rule. The glossary tree and the name tables live in one design document. One Rust crate holds the table types, the value kinds and their parsers, the unit types, the diagnostic type and the renderer; every binary builds its table from it.

---

## 3. Glossary — Part A's terms

A term listed under two parents is one term. Part B's terms are §11; a parent added here by Part B is IG-Q32's. The Kind column carries IG-3's verbs and views as data: one `parent:view` or `parent:verb` pair for each parent under which the term ends a command, with `—` for a bare subject; a blank cell is a term that ends no command. The italic *view* and *verb* in a meaning are its prose, and must agree with the column (the walk gate, `scripts/ci/check_input_grammar_walk.py`).

| Term | Parents | Meaning | Kind |
|---|---|---|---|
| help | — | *view* — print usage | —:view |
| version | — | *view* — print the version and the OS line | —:view |
| network | — | which chain: `mainnet`, `testnet`, `stagenet`, `regtest` | |
| config | — | the TOML file of option values | |
| data | — | the per-network directory holding the daemon's stores and state | |
| instance | — | which node of one network on this machine: the default instance, or a second node the operator names (RPC_CHANNEL §7.1, IG-Q103) | |
| log | — | the daemon's log sink | |
| file | config, log, ban, wallet, script, password, socket, png, address, mnemonic, recipients, constants, tor | a file path (value term) | |
| dir | data, wallet, create, recipients, socket | a directory path (value term); under `socket`, the directory that holds the owner's socket (IG-Q104) | |
| level | log | a log severity: `error`, `warn`, `info`, `debug`, `trace` | |
| category | log | a log category, owned by `shekyl-logging` | |
| size | log | the disk a log may use | |
| p2p | — | the peer-to-peer protocol, independent of connector | |
| clearnet | —, dev | the clearnet connector (direct TCP) | |
| tor | — | the Tor connector | |
| socks | clearnet, tor, daemon | the SOCKS5 endpoint a connector dials through | |
| username | socks, rpc | a credential's name (SOCKS5, RFC 1929; the wallet RPC's authentication) | |
| password | socks, wallet, rpc | a secret credential; always a secret | |
| onion | tor | this node's v3 onion service | |
| listen | clearnet, onion, rpc, view, admin | a local endpoint a listener binds | |
| advertise | clearnet | the endpoint we tell peers is ours | |
| local | p2p | endpoints not dialable on the public internet (private, loopback, link-local) | |
| peer | p2p, closed, — | another Shekyl node | |
| closed | p2p | a network consisting only of the listed peers | |
| ban | p2p, — | a host or subnet refused at socket admission | |
| disclose | p2p | what this node tells other nodes of its known peers and its own address | |
| early | disclose | below the white-diversity floor | |
| inbound | p2p | connections other nodes open to us | |
| upload | p2p | bytes we send | |
| download | p2p | bytes we receive | |
| txpool | — | the transaction pool | |
| weight | txpool | transaction weight, in bytes | |
| notify | — | run an operator command on an event | |
| block | notify, —, genesis | a block: under `notify` the new one; under `genesis`, *view* — the genesis block id and transaction hash | genesis:view |
| rate | block | the block-rate check | |
| reorg | notify, archival | a chain reorganization | |
| height | block, reorg, split, chain, restore | a block height: under `block` the new block's, under `reorg` the new tip's, under `split` the last block both chains share; under `chain`, *view* — the chain's height | chain:view |
| hash | block | the new block's hash | |
| split | reorg | the point where the two chains part (`{split-height}`) | |
| added | reorg | blocks in the new chain | |
| removed | reorg | blocks discarded from the old chain | |
| window | rate, speed | the observation window, in seconds | |
| observed | rate | blocks seen in the window | |
| expected | rate | blocks expected in the window | |
| mine | — | the daemon's miner and its control | |
| address | mine, make, — | a Shekyl address (the payment meaning; never a network location); bare, *view* — the wallet's primary address | —:view |
| threads | mine | a thread count | |
| rpc | —, wallet, dev | an RPC service's listeners: the daemon's, or the wallet's (`shekyl-wallet-rpc`, and `wallet-rpc-*` in `shekyl-cli`); under `dev`, the armed test levers it serves (RT-O9.2, IG-Q49) | |
| view | rpc | the `view` preset, a fixed set of grants (RPC_CHANNEL §6.1) | |
| admin | rpc | the `admin` preset, every grant (RPC_CHANNEL §6.1) | |
| cors | rpc | cross-origin resource sharing | |
| origin | cors | an allowed origin | |
| connections | rpc, peer | concurrent connections; under `peer`, *view* — the live peer connections | peer:view |
| dev | — | a development lever (IG-8) | |
| encrypt | clearnet | the pre-flip clearnet encryption switch | |
| relay | dev, tx | transaction relay (Dandelion++); under `tx`, *verb* — relay a transaction | tx:verb |
| cover | relay | Dandelion++ cover traffic ([`COVER_TRAFFIC_RESTORATION.md`](COVER_TRAFFIC_RESTORATION.md)) | |
| sync | dev, — | chain synchronization | |
| difficulty | dev, chain | a fixed mining difficulty; under `chain`, *view* — the current difficulty | chain:view |
| pow | dev | proof of work (RandomX); under `dev`, its seed schedule (IG-Q48) | |
| seed | pow | the RandomX seed | |
| epoch | seed, settlement | a fixed-length run of blocks | |
| blocks | epoch | a length in blocks | |
| lag | epoch | the seed lag in blocks | |
| settlement | dev | the archival settlement schedule | |
| archival | dev, — | the archival layer | |
| depth | reorg | a reorganization depth in blocks | |
| max | any | qualifiers | |
| min | any | qualifiers | |

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
| — | `config-verify` | switch | off | CLI |  |  | N (IG-Q58, IG-Q59): the configuration check. `shekyld` runs start's walk (`load`, then every refusal start makes before it creates anything) with nothing created, locked or latched, prints the account checked and the effective configuration, and exits 0, 2 or 1 as start would (IG-Q61, IG-Q62). `rust/shekyl-daemon/src/verify.rs`, `walk`, called from `run` |
| `os-version` | — | | | |  |  | R into `version` |
| `testnet`, `stagenet`, `regtest` | `network` | one-of | `mainnet` | CLI |  |  | R |
| — | `service` | switch | off | CLI |  |  | N (IG-Q36, IG-Q37, IG-Q105): this is the machine's service instance. Accepted on every platform. On Linux, FreeBSD and macOS it serves no owner socket ([`RPC_CHANNEL.md`](RPC_CHANNEL.md) §7.1) and keeps the plaintext loopback listeners (RT-O33). On Windows it also answers the service manager (RT-16), whose dispatcher is RT-W14's: until then a Windows start refuses the switch (`config.service.platform`), naming RT-W14. Selects the daemon's root on Windows (IG-13) |
| — | `instance` | name | unset, the default instance | both |  |  | N (IG-Q103): this node's name, for a second node of the same network on this machine ([`RPC_CHANNEL.md`](RPC_CHANNEL.md) §7.1): 1 to 16 of `[a-z0-9-]`, starting with a letter or a digit; `default` is refused by name. The rule is `shekyl-rpc-channel`'s `InstanceName`, and the name reaches no path: it is hashed into the rendezvous. A named instance needs an explicit `data-dir` |
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
| `clearnet-transport-encrypt` | `dev-clearnet-encrypt` | switch | off | both |  |  | R; testnet, stagenet, regtest, a staging flag their rows stage (`NETWORK_IDENTITY.md` NI-R9; IG-8: never mainnet); deleted at the Noise flip |
| `no-sync` | `dev-sync` | one-of `on` `off` | `on` | both |  |  | R; regtest; the chain-sync lane owns it |
| `carrier-development` | `dev-relay-cover` | switch | off | both |  |  | R; testnet, stagenet, regtest, a staging flag their rows stage (`NETWORK_IDENTITY.md` NI-R9; IG-8: never mainnet); `check_carrier_flag_hidden.sh` replaced by a table test |

### Core, pool, notify, mine

| Today | New | Kind | Default | Surface | Runtime | Grant | Notes |
|---|---|---|---|---|---|---|---|
| `test-drop-download`, `test-drop-download-height`, `test-dbg-lock-sleep`, `show-time-stats` | — | | | |  |  | – |
| `keep-fakechain` | — | | | |  |  | – (nothing is wiped, R3) |
| `fixed-difficulty` | `dev-difficulty` | integer ≥ 1 | unset | both |  |  | R; regtest |
| `prep-blocks-threads`, `block-sync-size`, `span-limit`, `block-download-max-size` | — | | | |  |  | X (chain sync's protocol constants replace `span-limit`, `block-sync-size` and `block-download-max-size`: the per-response, objects and global byte budgets and the deadlines, provisioned at the floor device, rule 76; a metered link is `p2p-download-max`, and a byte quota reopens under IG-Q40; `prep-blocks-threads` is the shared hasher budget's, derived from the floor device's scratchpads, DRS-X DX-Q2 item 6; [`P2P_3_CHAIN_SYNC_BRIEF.md`](P2P_3_CHAIN_SYNC_BRIEF.md) CS-Q12, ruled 2026-10-18) |
| `db-sync-mode` | — | | | |  |  | – (the DRS lane decided: no knob; the Rust store's durability is the constant `shekyl_chain_store::store::DURABILITY`, `Immediate`, DRS-D9, Rick 2026-10-26) |
| `db-salvage` | — | | | |  |  | L DRS |
| `keep-alt-blocks` | — | | | |  |  | L DRS-E5 |
| `max-txpool-weight` | — | | | |  |  | X `txpool-weight-max` (the pool's cap derives from the chain, CEN-M10: `REFERENCE_BLOCK_MAX_AGE` blocks at the block weight limit; IG-Q11, amended 2026-10-17); the inherited spelling leaves no trace (IG-5) |
| `block-notify` | `notify-block` | command | unset | file |  |  | R (IG-Q5); placeholders `{height}`, `{hash}` |
| `reorg-notify` | `notify-reorg` | command | unset | file |  |  | R (IG-Q5); placeholders `{split-height}` (the last block both chains share), `{height}` (the new tip), `{added}` (blocks in the new chain), `{removed}` (blocks discarded) |
| `block-rate-notify` | `notify-block-rate` | command | unset | file |  |  | R (IG-Q5); placeholders `{window}` (the window in seconds), `{observed}`, `{expected}` |
| — | `mine` | `on` / `off` | `off` | both |  |  | R (IG-Q21, amended 2026-11-02); `on` starts the miner once the node has opened, to `mine-address`, with `mine-threads`; `on` with no `mine-address` is refused at parse naming `mine-address` (IG-11, exit 2) |
| `start-mining` | `mine-address` | address | unset | both |  |  | R (IG-Q21, amended 2026-11-02); the address the miner pays; it is the config row and starts nothing by itself; the effective-configuration line shows it shortened to its first and last eight characters, `option show` the whole value under its grant |
| `mining-threads` | `mine-threads` | integer ≥ 1, or `auto` | `auto` | both |  |  | R (IG-Q21); the node's thread count for the start-time miner and for a `start_mining` that names none; a count above the host's parallelism is refused by the configuration check (exit 2); `mine start` builds it while running (IG-12); one default for starting the miner on every surface: `shekyl-cli mine start` with no count is `auto` (`grammar.rs:539-540`); the miner's owner defines `auto` once |
| `bg-mining-*` (5) | — | | | |  |  | X (Monero background mining) |

### RPC, named for the ratified RPC_CHANNEL model

| Today | New | Kind | Default | Surface | Runtime | Grant | Notes |
|---|---|---|---|---|---|---|---|
| — | `rpc-listen` | list of endpoint | | |  |  | visibility `reserved` (IG-9, IG-10): held for the authenticated channel listener (RT-W10); not accepted in this cut |
| — | `rpc-socket-dir` | path | unset: the account's session directory (IG-Q14) | both |  |  | N (IG-Q104): the directory for the owner's socket on a host with no session directory, a test host such as CI or a regtest harness ([`RPC_CHANNEL.md`](RPC_CHANNEL.md) §7.1). Asserted, not adopted: local, owned by the daemon's account, mode 0700, or the start refuses naming the condition. The harness creates it. Refused with `service`, which serves no owner socket |
| `rpc-bind-ip`, `rpc-bind-port`, `rpc-bind-ipv6-address`, `rpc-use-ipv6` | `rpc-admin-listen` | list of endpoint, loopback only | `127.0.0.1:<row rpc port>` | both |  |  | R; the interim plaintext full-access listener; loopback only by RT-14 (a plaintext listener never binds beyond loopback; only the authenticated channel listener may bind wildcard); becomes an X row when RT-W12 moves its clients (IG-Q16; RT-W12, not RT-W10, by RT-O33, ruled 2026-10-25) |
| `restricted-rpc`, `rpc-restricted-bind-port`, `rpc-restricted-bind-ip`, `rpc-restricted-bind-ipv6-address` | `rpc-view-listen` | list of endpoint, loopback only | `none` | both |  |  | R; keeps its method set (`view` plus `submit` and `mining-work`) through RT-W10 and is re-scoped to `view` in RT-W12, with the clients that use it (RT-O33, ruled 2026-10-25); plaintext loopback at view, off by default (ruled 2026-10-08); the GUI sidecar passes `--rpc-admin-listen none --rpc-view-listen 127.0.0.1:<port>` |
| `rpc-access-control-origins` | `rpc-cors-origin` | list of origin | `none` | both |  |  | R; explicit web origins only, `none` is CORS default-deny; `*` is refused: a wildcard lets any page in the operator's browser read and drive the plaintext admin listener |
| `rpc-max-connections`, `rpc-max-connections-per-public-ip`, `rpc-max-connections-per-private-ip` | `rpc-connections-max` | integer ≥ 1 | `25` (inherited; IG-Q12) | both |  |  | R; one option for one value, where today three set it (IG-F1); the cutover ships the inherited 25 with a FOLLOWUPS row for the RPC lane to derive the default under the RT-O9 resource policy (IG-Q12). The row stays live; `txpool-weight-max` closed as a rejected name (IG-Q11) and the pool's cap is CEN-M10 |
| — | `dev-rpc` | switch | off | both |  |  | N; regtest only, admitted by regtest's row (`NETWORK_IDENTITY.md` NI-R6, NI-R8; IG-8, IG-Q49: never mainnet); serves the armed test levers (`generateblocks` and `pop_blocks`; RT-O9.2, `RPC_CHANNEL.md` §6.1) to the host's administrator, refused outside the grant while off (`DRS_X_STORE_FLIP.md` DX-Q3, Q8) |
| `disable-rpc-ban` | — | | | |  |  | – (R5; the scorer it switches has no caller, IG-F9) |
| `rpc-response-soft-limit` | — | | | |  |  | – (response limits belong to the RPC resource policy, IG-Q12) |

### Environment levers (regtest only, IG-8)

The `Today` column is the environment read as it stood when the row was
ruled; the C++ files it cites are deleted (the p2p remnant cutover,
2026-11-05), the environment reads with them, and the levers are the
`dev-` rows alone, parsed by `shekyl-daemon`'s `levers.rs` (what each row
arms is that row's own status in the table).

| Today | New | Kind |
|---|---|---|
| `SEEDHASH_EPOCH_BLOCKS` (`pow_randomx_ffi.rs:350`) | `dev-pow-seed-epoch-blocks` | integer |
| `SEEDHASH_EPOCH_LAG` (`:351`) | `dev-pow-seed-epoch-lag` | integer |
| `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` (`blockchain.cpp:339`) | `dev-settlement-epoch-blocks` | integer |
| `SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS` (`:340`) | `dev-archival-reorg-depth` | integer |

The public-network refusal now in C++ (`blockchain.cpp:416-433`) becomes the IG-8 parse refusal; the announcement stays (IG-14).

### REJECTED rows carried from `removed_flags.cpp`, and the pruning lane's

Criterion: a REJECTED row exists for a capability a user could reasonably ask for again. Implementation switches and folds leave no trace. The two pruning rows are `DRS_SB_BELOW_HORIZON.md` SB-Q6's: the body horizon is a rule of the epoch calendar, with no option, no `option show` row and no lever.

| Name | Disposition | Reason |
|---|---|---|
| `detach`, `pidfile`, `install-service`, `uninstall-service`, `start-service`, `stop-service`, `run-as-service` | X | `shekyld` never daemonizes or registers itself; installing is the installer's and `shekyl-cli`'s, and on Windows `shekyld` answers the service manager through `service` (RT-16) |
| `rpc-login`, `rpc-ssl`, `rpc-ssl-private-key`, `rpc-ssl-certificate`, `rpc-ssl-ca-certificates`, `rpc-ssl-allowed-fingerprints`, `rpc-ssl-allow-chained`, `rpc-ssl-allow-any-cert` | X | the RPC channel replaces TLS and HTTP auth (RT-11) |
| `bootstrap-daemon-address`, `bootstrap-daemon-login`, `bootstrap-daemon-proxy` | X | no proxying to a third-party daemon |
| `public-node` | X | no public-node advertisement |
| `max-connections-per-ip` | X | no per-host inbound cap (the reason in `removed_flags.cpp`) |
| `prune-blockchain` | X | every daemon discards the same bodies at the same boundary (`ARCHIVAL_PRUNED_DAEMON_MODE.md` `PDM-Q2`, `PDM-Q9`); there is no node-local retention to choose (`PDM-Q7`). Bodies below the horizon are not held by any daemon; the archive serves them (`DRS_SB_BELOW_HORIZON.md` SB-Q6) |
| `sync-pruned-blocks` | X | trust-the-txid with no anchor; the skeleton band below the checkpoint is `PDM-Q5`'s and needs no flag (SB-Q6) |
| `no-rust-rpc`, `confirm-external-bind`, `rpc-ignore-ipv4`, `hide-my-port` | – | an implementation switch, a confirmation, a fold into the listen lists, and an advert now derived |

The `removed_flags` shim, its FOLLOWUPS sunset row, and its C++ tests go with the cutover; the X rows live in the Rust table.

**Count:** 83 registered options and 4 environment levers today, plus PR-3's `p2p-disclose-early`, DRS-X's `dev-rpc` and Part D's `config-verify`; 52 live names, the four environment levers among them (`rpc-listen` arrives at RT-W10's channel step and `rpc-admin-listen` becomes an X row at RT-W12, RT-O33; 52 between the two; `service`, `instance` and `rpc-socket-dir` arrived with IG-Q103…IG-Q105, 2026-11-12; `txpool-weight-max` became an X row with IG-Q11; `mine` arrived with IG-Q21's 2026-11-02 amendment; `console` left with the C++ console, 2026-11-03).

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

**IG-Q2 — the parser — RULED 2026-10-13.** clap's `derive` puts names in attributes, which defeats one table per binary, and its errors are its own English, outside IG-11. The parser is the shared crate's. The grammar is `--name value`, `--name=value`, switches and repeats; `--` ends options; no short flags; no abbreviation. A Rust bin reads its arguments with `std::env::args_os`. `shekyld`'s process entry is still C `main`, so it builds an `ArgumentVector` (`DAEMON_CONFIG_CUTOVER.md` §2.2): on Unix the `argc`/`argv` `main` passes, on Windows `GetCommandLineW`. `args_os` is empty on that Unix staticlib unless Rust's `lang_start` ran (the 2026-10-13 text said every binary reads `args_os`). A null slot is a failure, not a shorter vector. The Rust process entry collects `args_os` into the same type. A non-UTF-8 argument is refused with a typed code; suggestions from `strsim` (in the lock). A fuzz target covers the parser. clap leaves each binary as it conforms.

**IG-Q3 — the offline state — RULED 2026-10-13.** With connectors as subjects, "offline" is exactly `clearnet = off` and `tor = off`, and a `p2p-offline` switch would set that state a second way (IG-5). There is no offline option; the four postures are the product of the two connector settings (default; Tor-only; clearnet-only, warned at every start; offline, announced at every start). `core::m_offline` (`cryptonote_core.cpp:1552,1621`) and the protocol handler (`daemon.cpp:135`) read the derived fact.

**IG-Q4 — lane-owned knobs are not ported — RULED 2026-10-13.** The C++ keeps today's defaults as constants until each lane decides whether a knob exists. `drs_bench.py` loses `--block-sync-size`, `--db-sync-mode` and `--keep-fakechain`; DRS owns that loss.

**IG-Q5 — notify commands — RULED 2026-10-13, amended the same day.** An argument array, file only, run without a shell. Placeholders are named, `{name}`, where each name is a glossary term under its notify row (§3) and has one meaning everywhere; an unknown name refuses; braces are the only syntax, so `%` is literal. The sets, as designed and not as today's substitutions: `notify-block` `{height}`, `{hash}`; `notify-reorg` `{split-height}`, `{height}`, `{added}`, `{removed}`; `notify-block-rate` `{window}`, `{observed}`, `{expected}` (§5).

**IG-Q6 — peer endpoints take no hostnames — RULED 2026-10-13.** Today `--add-peer` resolves DNS locally (`net_node.inl:520-548`), which leaks the lookup on a Tor-only node and makes the daemon a resolver. IP and onion only, and the network row's seed list likewise.

**IG-Q7 — `max-concurrency` — RULED 2026-10-13.** A cap on one C++ thread pool (`util.cpp:861`), a macOS workaround. Removed; concurrency belongs to the thread-budget work.

**IG-Q8 — the interim console — RULED 2026-10-13; deleted 2026-11-03.** The switch `console` and the bare command words are gone with the C++ console. A bare word on `shekyld` is `config.cli.syntax` and names the token. Daemon commands are `shekyl-cli` words.

**IG-Q9 — absolute paths only — RULED 2026-10-13.** On both surfaces.

**IG-Q10 — integers only, IEC units only — RULED 2026-10-13.**

**IG-Q11 — `txpool-weight-max` — RULED 2026-10-13; AMENDED 2026-10-17 (Rick, on #1102).** The default is "3 days at 300000 bytes" (`cryptonote_config.h:328`), a Monero operand. The name landed with the inherited default and a FOLLOWUPS row for the pool's owner to re-derive it. The re-derivation is done: the Rust pool derives its cap from the chain, `REFERENCE_BLOCK_MAX_AGE` blocks at the block weight limit (`DRS_E5_POOL_ALT_PRUNE.md` CEN-M10), and reads no option. **`txpool-weight-max` is a rejected option**, refused with "the pool's cap derives from the chain (CEN-M10)" (`shekyl-daemon-config`'s table). The reasons:
- the cap is derived, not chosen: any lower number only discards transactions that could still be mined;
- a per-node cap changes what a node holds under pressure, which peers see through pool sync;
- on a floor device the chain binds before the pool does.

*Reopening criterion:* a floor-device measurement in which pool RSS, not the chain, binds first at a realistic weight limit; `DAEMON_REDB_STORE.md` §1.3a's PB-R1 reads the node's RSS at design load on the floor device. The remedy then is a compact in-memory representation, not an option.

**IG-Q12 — `rpc-connections-max`'s default — RULED 2026-10-13.** The only number on hand is the C++'s effective 25, which nobody derived. The cap is a resource limit, and RT-O9.4 ruled cost a resource policy separate from grants. The cutover ships the inherited value 25 with a FOLLOWUPS row for the RPC lane to derive the default under that policy. `rpc-connections-max` stays that option. `txpool-weight-max` closed under IG-Q11 as a rejected name, and the pool's cap is CEN-M10.

**IG-Q13 — names — RULED 2026-10-13.** Family `IG-`; the shared crate `shekyl-options`; the daemon crate `shekyl-daemon-config`.

**IG-Q14 — no environment input (IG-13) — RULED 2026-10-13.** Default paths came from `HOME`, and the wallets read `XDG_RUNTIME_DIR` (`shekyl-wallet-rpc/src/server.rs:744`), so the environment still decided values. Home comes from the passwd entry and the Windows known-folder API. Each platform takes its per-user runtime directory from its own OS interface, never from the environment: Linux `/run/user/<uid>`; macOS `confstr(_CS_DARWIN_USER_TEMP_DIR)`; FreeBSD, or any platform without one, the typed refusal (IG-11) naming the explicit, operator-named socket directory ruled in the RPC channel round ([`RPC_CHANNEL.md`](RPC_CHANNEL.md) §7.1, 2026-10-09). Terminal reads (`shekyl-cli/src/display.rs:98-104`) stay, as presentation. Cost: a user who relocates `HOME` by environment passes `--data-dir` instead.

**IG-Q15 — `address` and `carrier` (§3, IG-F7, IG-F8) — RULED 2026-10-13.** `address` is a Shekyl address only; network locations are endpoints. `carrier` is the serve-credit witness carrier only; the cover switch is `dev-relay-cover`.

**IG-Q16 — RPC names for the ratified model — RULED 2026-10-13.** RPC_CHANNEL (ratified 2026-10-09) replaces today's listeners with the authenticated channel, the same-user socket, and an optional plaintext loopback listener at view. Naming today's full-access listener `rpc-listen` would hand that name to the channel listener later with a different meaning. `rpc-listen` is reserved for the channel listener; today's full-access listener is `rpc-admin-listen` (what it is: plaintext, loopback, admin), an X row when RT-W12 moves its clients (RT-O33, ruled 2026-10-25, moved it from RT-W10); `rpc-view-listen` is the ratified view listener from now on.

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

Rows below add to §3; a term already in §3 is not repeated (its Part B parents are in §3). Verbs and views are marked (IG-3), in prose and in the Kind column, as §3 states.

| Term | Parents | Meaning | Kind |
|---|---|---|---|
| wallet | — | the wallet: its files and its operations | |
| daemon | — | the daemon a wallet binary or the shell talks to | |
| service | — | run under the platform's service manager (RT-16) | |
| script | — | a file of prompt lines run as one session | |
| json | — | machine output: one object per command | |
| debug | — | show the machine detail of a failure | |
| option | — | a runtime-changeable row of the daemon's table (IG-12) | |
| tx | — | a transaction | |
| request | — | a payment request | |
| uri | — | a `shekyl:` payment URI | |
| stake | — | the staking balance and bond | |
| shard | — | an archival shard | |
| prove | — | make a proof | |
| check | — | check a proof | |
| sign | — | *verb* — sign a message with the wallet key | —:verb |
| verify | —, genesis, config | *verb* — check a claim against its source: a message signature, under `genesis` every network rebuilt against the pins, or under `config` the configuration against the table and the paths it names (IG-Q58) | —:verb, genesis:verb, config:verb |
| send | — | *verb* — send money | —:verb |
| fee | — | *view* — a fee quote | —:view |
| balance | —, stake | *view* — a balance breakdown | —:view, stake:view |
| chain | — | the chain the daemon holds; bare, *view* — its health | —:view |
| exit | — | *verb* — leave the prompt | —:verb |
| status | wallet, stake, mine, sync, daemon | *view* — the current state | wallet:view, stake:view, mine:view, sync:view, daemon:view |
| stop | mine, daemon | *verb* — stop | mine:verb, daemon:verb |
| set | option, password, note | *verb* — assign a value | option:verb, password:verb, note:verb |
| show | tx, shard, block, ban, option | *verb* — print one item | tx:verb, shard:verb, block:verb, ban:verb, option:verb |
| endpoint | daemon, rpc | a peer-endpoint the binary dials (IG-Q31) | |
| socket | daemon, rpc | the local socket of RPC_CHANNEL RT-15 | |
| mnemonic | create, restore | the wallet's recovery words (IG-Q24) | |
| direction | list | `in` or `out` | |
| unmatched | list | receives matching no request | |
| matched | list | requests already paid | |
| all | list | *view* — every entry | list:view |
| held | list | *view* — the shards this wallet holds | list:view |
| amount | make | an amount (kind `amount`) | |
| label | make | a human label | |
| expiry | create | how long a request stays valid: a duration | |
| priority | send | `economy`, `standard` or `high` | |
| yes | send, add, return, release, collect | confirm without a prompt | |
| full | address | the whole address, not the display form | |
| count | input, output | how many | |
| input | fee | a transaction input | |
| output | fee | a transaction output | |
| png | fetch | a PNG image of the shard | |
| pixels | png | the image's side, in pixels | |
| complete | archival | the whole corpus | |
| tree | complete | the CompleteTree posture (IG-Q28) | |
| acknowledge | archival | the acknowledgement phrase that posture requires | |
| short | list | the short form | |
| from | list, sum | the first height | |
| to | list, sum | the last height, inclusive | |
| last | stats | the most recent N blocks | |
| body | show | a block's or transaction's serialized bytes, kind `bytes` | |
| hard | rescan | rebuild from the chain | |
| duration | add, ban, shard | a span of time: on the console IG-6's duration quantity (`--duration 1h`), on the wire the `duration` kind (IG-Q44, IG-Q54) | |
| alt | chain | *view* — the alternative chains | chain:view |
| coinbase | chain | coinbase outputs | |
| sum | coinbase | *view* — a total | coinbase:view |
| stats | chain, peer, txpool, p2p | *view* — statistics | chain:view, peer:view, txpool:view, p2p:view |
| white | list | the white peer list | |
| gray | list | the gray peer list | |
| spent | chain | *view* — whether a key image is spent | chain:view |
| create | wallet, request, recipients | *verb* — create | wallet:verb, request:verb, recipients:verb |
| open | wallet | *verb* — open | wallet:verb |
| close | wallet | *verb* — close | wallet:verb |
| restore | wallet | *verb* — restore from the recovery words | wallet:verb |
| refresh | wallet | *verb* — sync with the daemon | wallet:verb |
| rescan | wallet | *verb* — rebuild the history | wallet:verb |
| list | tx, request, shard, peer, ban, txpool | *verb* — print the entries | tx:verb, request:verb, shard:verb, peer:verb, ban:verb, txpool:verb |
| note | tx | *view* — a transaction's local note | tx:view |
| abandon | tx | *verb* — give up on a dispatched send | tx:verb |
| decode | tx | *verb* — decode a transaction blob | tx:verb |
| make | uri | *verb* — compose | uri:verb |
| read | uri | *verb* — decode | uri:verb |
| outputs | stake | *view* — the staking-side outputs | stake:view |
| available | stake | *view* — what can move back to the wallet | stake:view |
| add | stake, ban | *verb* — add | stake:verb, ban:verb |
| return | stake | *verb* — move staking funds back | stake:verb |
| release | stake | *verb* — post the bond's exit | stake:verb |
| collect | stake | *verb* — collect the released funds | stake:verb |
| join | stake | *verb* — name the shards to serve | stake:verb |
| fetch | shard | *verb* — fetch | shard:verb |
| start | mine | *verb* — start | mine:verb |
| payment | prove, check | *view* — a payment proof, or the verdict on one | prove:view, check:view |
| reserve | prove, check | *view* — a reserve proof, or the verdict on one | prove:view, check:view |
| remove | ban | *verb* — remove | ban:verb |
| flush | txpool | *verb* — flush | txpool:verb |

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
| `tx show <id>` | same | hash | `--body` | K (Rick, 2026-11-03): one report of transaction `<id>`. An open wallet that holds the id is the report, and the daemon is not asked. Otherwise the report is the daemon's view. `--body` fetches the serialized bytes from the daemon (kind `bytes`, RW-Q4). If neither source knows the id, the refusal names both |
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

The catalog `shekyl-cli` serves (IG-Q25). The C++ console is deleted (R8, DC-N2, 2026-11-03). These words are the shell's.

| Today | New | Positionals / flags | Notes |
|---|---|---|---|
| `help [cmd]`, `apropos <kw>...` | `help [command]` | | `apropos` folds into `help` |
| `print_height` | `chain height` | | |
| `print_bc <from> [<to>]` | `block header list` | `--from`, `--to` integer, inclusive heights | the method's path (IG-Q44) |
| `bc_dyn_stats <n>` | `chain stats` | `--last` integer | |
| `alt_chain_info [hash]` | `chain alt` | | the console finds a chain in the one reply (IG-Q44) |
| `print_coinbase_tx_sum <from> [<count>]` | `chain coinbase sum` | `--from`, `--to` integer, inclusive heights | IG-Q44 |
| `diff` | `chain difficulty` | | |
| `is_key_image_spent <ki>` | `chain spent <key-image>` | hash | |
| `pop_blocks <n>` | — | | –: no grammar successor; it is an armed test lever (RPC_CHANNEL RT-O9.2, §6.4) |
| `print_block <hash\|height>` | `block show <hash\|height>` | hash or integer | |
| `print_tx <hash> [+hex]` | `tx show <id>` | hash; `--body`; `--json` is the session's | One report (Rick, 2026-11-03): the open wallet's record when it holds the id, and the daemon is not asked; otherwise the daemon's view. `--body` fetches the bytes from the daemon. If neither source knows the id, the refusal names both. `+json` went with epee's rendering (IG-Q55) |
| `relay_tx <txid>` | `tx relay <id>` | hash | |
| `print_pool`, `print_pool_sh`, `print_pool_stats`, `flush_txpool [txid]` | `txpool list [--short]`, `txpool stats`, `txpool flush [id]` | | |
| `print_pl [white] [gray] [limit]`, `print_pl_stats`, `print_cn`, `print_net_stats` | `peer list [--white] [--gray] [--max N]`, `peer stats`, `peer connections`, `p2p stats` | | |
| `limit [kB/s]`, `limit_up`, `limit_down`, `set_log <level\|categories>` | `option set <name> <value>`, `option show [<name>]` | an option name; a value of that row's kind | IG-12: `option set` takes only the rows §5 marks runtime, needs the `node` grant, and never writes the file; `option show` reports each source and returns each row whose grant the caller holds (§5's Grant column); `limit` (both rates at once) is one option per value and goes |
| `out_peers <n>`, `in_peers <n>` | — | | – (each option is an X row, §5) |
| `bans`, `ban <ip\|@file> [secs]`, `unban <ip>`, `banned <ip>` | `ban list`, `ban add <ip> [--duration <quantity>]`, `ban remove <ip>`, `ban show <ip>` | an IP; a file is `p2p-ban-file` | |
| `start_mining <addr> [threads\|auto] [bg] [battery]`, `stop_mining`, `mining_status`, `show_hr`, `hide_hr` | `mine start [threads\|auto]`, `mine stop`, `mine status` | integer or `auto` | builds `mine-threads` while running (IG-12); `mine-address` is the config row; the background arguments go with `bg-mining-*` (§5); the hash rate is in `mine status` |
| `status`, `print_status`, `sync_info` | `daemon status`, `sync status` | | `print_status` is a duplicate of `status` (IG-Q33) |
| `stop_daemon`, `exit` | `daemon stop` | | IG-Q33: no bare word in the shared shell stops the daemon |
| `save`, `flush_cache [bad-txs] [bad-blocks]` | — | | –: LMDB and C++ cache internals |
| `version` | `version` | | |
| — | `rpc client add <fingerprint> --ceiling <grants>`, `rpc client set <fingerprint> --ceiling <grants>`, `rpc client remove <fingerprint>`, `rpc client list`, `rpc bundle show` | a hash; a list of grant and preset keywords | built by RT-W10 step 4 (IG-Q87): enrolment over the channel, under the `enrol` grant |

## 14. The utilities and the tools

### 14.1 Keep or delete (IG-Q26)

| Binary | Ruling | Reason |
|---|---|---|
| `shekyl-blockchain-usage`, `-ancestry`, `-depth` | deleted | ring-signature-era analytics (`rct-only`, `ringsize`) with no referent under FCMP++ (rule 60) |
| `shekyl-gen-ssl-cert` | deleted | RT-11: the RPC channel replaces TLS |
| `shekyl-utils-object-sizes` | deleted | a C++ debug tool with no remaining job |
| `shekyl-blockchain-import`, `-export`, `-stats`, `shekyl-mdb-copy` | deleted | the chain store is the Rust store; these read LMDB |
| `shekyl-utils-deserialize` | stays until `tx decode` (§12.3) lands, then goes | the decode need is real; the Rust codecs serve it |
| `shekyl-e2-trace-export` | deleted | the C++ LMDB harvest; the replay reads a frozen `trace.e2` |
| `geblock` | its table is §14.2 | the genesis ceremony tool |
| `shekyl-chain-replay`, `shekyl-wss-q1b-bench`, and every other binary target the gate enumerates | in the gate (IG-Q27); their tables come with the gate (FOLLOWUPS) | development tools follow the grammar |

Each remaining deletion fixes its consumers in the same change.

### 14.2 `geblock`

The four acts of the genesis ceremony tool under IG-3 (IG-Q35). `geblock` has no path defaults: every path flag is required wherever it applies, so the command line records exactly what the ceremony used. Terms this table adds (the parents it gives `verify`, `create`, `dir`, `file` and `block` are in §3 and §11):

| Term | Parents | Meaning | Kind |
|---|---|---|---|
| genesis | — | the genesis block and its ceremony | |
| recipients | genesis, build, verify, block | the genesis recipients: their wallets and the recipients file | |
| constants | verify, block | the C header that holds the genesis pins and nonce | |
| build | genesis | *verb* — build the genesis coinbase transaction | genesis:verb |

| Today | New | Flags | Notes |
|---|---|---|---|
| `gen-wallets --network n --out-dir d` | `genesis recipients create` | `--network`; `--dir <path>` (required) | creates the directory fresh, mode `0700`, refused if it exists or lies inside a git tree; writes the wallet files `0600`, under the secret-file checks of IG-Q24 and §12.1 |
| `build --network n [--recipients f]` | `genesis build` | `--network`; `--recipients-file <path>` (required) | the transaction hex goes to stdout |
| `verify [--config f] [--recipients-dir d]` | `genesis verify` | `--constants-file <path>`, `--recipients-dir <path>` (both required) | `--config` named the C header, which IG-7's `config-file` cannot also name |
| `block-id --network n [--recipients f] [--config f]` | `genesis block` | `--network`; `--recipients-file <path>`, `--constants-file <path>` (both required) | |

## 15. Questions for Part B

**IG-Q21 — `mine` — RULED 2026-10-14; amended 2026-11-02.** `mine` is the subject everywhere; Part A's `mining-address` and `mining-threads` are `mine-address` and `mine-threads` (§5). **Amendment (Rick, 2026-11-02):** `mine` is also a row, kind one-of `on`/`off`, default `off`, both surfaces, help "Start the miner at start, to mine-address." Not `mine-start`: the subject alone is the name, and starting is what the row does. `mine-address` has no default and starts nothing by itself; its help is "The address the miner pays." `mine = on` with no `mine-address` is refused at parse (IG-11, exit 2) naming `mine-address`. `mine-threads` is the node's thread count for the start-time miner and for a `start_mining` that names no count; a count above the host's parallelism is refused by the configuration check, exit 2. With `mine = on` the node calls the miner's start once after it opens, with that count; the miner idles until a job is posted; `start_mining` and `stop_mining` act on the running node, and a restart returns to the configuration. The effective-configuration line shows `mine-address` shortened to its first and last eight characters; `option show` gives the full value under its grant.

**IG-Q22 — `out`, `outputs` and `size` — RULED 2026-10-14.** `address --file`, `tx list --direction in|out`, `fee --input-count` / `--output-count`, `shard fetch --png-file` / `--png-pixels`, `shard list held`.

**IG-Q23 — kinds the wallet needs — RULED 2026-10-14.** IG-6 gains `hash` (64 hexadecimal characters: transaction ids and block hashes), `amount` (at most `DISPLAY_DECIMAL_POINT` fractional digits, `shekyl-units` the one source, parsed exactly to atomic units, never a float), `name` and `text`. Shard ids are `integer`; there is no `id` kind. `--expiry` takes a duration only.

**IG-Q24 — the recovery words — RULED 2026-10-14.** The recovery words never appear on a command line, in a history or in a script; they come from `--mnemonic-file` or a hidden prompt. The mnemonic file and the password file get the config file's ownership and permission checks: a group- or world-readable file refuses with a typed code. The wallet password is one option, `wallet-password-file`, admitting the keyword `stdin` (IG-5).

**IG-Q25 — the console — RULED 2026-10-14.** The C++ console is not renamed and dies with R8. §13 is the catalog the Rust console and `shekyl-cli` serve: runtime settings are `option set` and `option show` (IG-12); `is_key_image_spent` is the view `chain spent <key-image>`; `pop_blocks` has no grammar successor: it is an armed test lever (RT-O9.2, RPC_CHANNEL §6.4); the daemon's words are `daemon status` and `daemon stop`.

**IG-Q26 — the utilities — RULED 2026-10-14.** As §14.1. The deletions are separate implementation PRs, each fixing its consumers. `tx decode <body>` (§12.3) replaces `shekyl-utils-deserialize`.

**IG-Q27 — the gate's scope — RULED 2026-10-14.** The gate's subject is every binary target we author, enumerated mechanically from the Cargo workspace and CMake, never from a hand-kept list; the gate asserts the set is non-empty (rule 47). Development tools are in it. The exceptions were the tools bound to LMDB or the C++ while they lasted, and `shekyl-mdb-copy`, which was LMDB's upstream tool. Those exceptions are discharged: the tools are deleted.

**IG-Q28 — the CompleteTree flags — RULED 2026-10-14.** `archival-complete-tree` and `archival-acknowledge` are public rows.

**IG-Q29 — the wallet binaries' file and credentials — RULED 2026-10-14.** The config file lives in the account root, found through the OS interface, never the environment (IG-13): the passwd entry's home plus `.shekyl/<binary>-<network>.toml` on Linux, FreeBSD and macOS; `SHGetKnownFolderPath(FOLDERID_LocalAppData)` plus `Shekyl\<binary>-<network>.toml` on Windows, never Roaming AppData, which copies the wallet and its config to domain servers (rule 36). The wallet directory and the daemon's data directory sit under the same root, one rule. `rpc-username` and `rpc-password` are file-only secrets; `--disable-rpc-login` goes (IG-4).

**IG-Q30 — the `RETIRED` table and `quit` — RULED 2026-10-14.** Both go, with no X rows.

**IG-Q31 — the daemon and wallet-RPC addresses — RULED 2026-10-14.** `daemon-endpoint` and `wallet-rpc-endpoint` are kind peer-endpoint, an IP or an onion, because a local wallet with a remote daemon over Tor is a supported posture; a hostname is refused. The socket-file rows stand beside them, unconstructible together. `shekyl-wallet-rpc`'s `rpc-listen` is interim until the RPC channel's wallet leg lands: it accepts a non-loopback bind when credentials are set, every such start carries an IG-14 announcement, and a FOLLOWUPS row refuses the plaintext non-loopback arm at RT-W10. The daemon's RPC rows are Part A's.

**IG-Q32 — Part A's terms that gain parents — RULED 2026-10-14.** The parents widen as §3 lists; the meanings are unchanged, and `username` and `password` name the wallet RPC's credentials as well as SOCKS5's.

**IG-Q33 — `status` — RULED 2026-10-14.** `status` is a view everywhere: `wallet status`, `stake status`, `mine status`, `sync status`, and the daemon's `daemon status`. The daemon stops with `daemon stop`, so the shared `shekyl-cli` shell has no bare word that stops the daemon.

**IG-Q34 — commands IG-3's verb-or-view rule classifies — RULED 2026-10-14.** A view changes no state; a command that changes state ends in a verb (IG-3). `wallet password` changes the wallet, so it is `wallet password set`. `tx note <id>` is a view, and `tx note set <id> <text>` assigns the note; empty text clears it. `request new` is `request create`. `prove payment`, `prove reserve`, `check payment` and `check reserve` compute and print without changing anything, so they are views. `set` keeps one meaning, assign a value, under `option`, `password` and `note`.

**IG-Q35 — `geblock`'s table — RULED 2026-10-14.** §14.2, with its glossary rows. `geblock` has no path defaults: `--dir`, `--recipients-file`, `--recipients-dir` and `--constants-file` are required wherever they apply, so the command line records exactly what the ceremony used. `genesis recipients create` creates its directory fresh (`0700`, refused if it exists or lies inside a git tree) and writes the wallet files `0600`, under the secret-file checks of IG-Q24 and §12.1.

**IG-Q36 — the service run mode — RULED 2026-10-14, amended the same day** (the same ruling is DC-Q17 in the daemon-configuration cutover; [`RPC_CHANNEL.md`](RPC_CHANNEL.md) RT-16, ruled 2026-10-13). `service` is a public switch, off by default, given on the command line only (IG-Q37): `shekyld` answers the platform's service manager (RT-16); it is accepted only where RT-16 defines it (Windows) and refused elsewhere with a typed code. The run mode selects one root and every default path (`config-file`, `data-dir`, `log-file`) derives from it: on Windows, run-as-user uses the per-account root (`FOLDERID_LocalAppData`) and `service` uses `%ProgramData%\shekyl\`, which only the installer creates (owner and ACL: Administrators, SYSTEM and the service account); the daemon never creates the machine-wide root, and one that is missing, mis-owned or writable by others refuses with a typed code. Linux and macOS keep R2's `/etc/shekyl/` files in every mode. The REJECTED row `run-as-service` keeps its name with the reason in §5. The mechanism, including the deletion of the elevation branch in `daemon_default_data_dir.cpp`, is the daemon-configuration cutover's. Until RT-W14 builds the SCM dispatcher, the row has visibility `reserved` (IG-9, IG-10), worded like the `rpc-listen` row: it is not accepted, and its refusal names RT-W14. Kind, default, surface (command line only, IG-Q37) and the IG-13 root rule stand as ruled; only the row's visibility changes until RT-W14 lands. *Amended 2026-11-12 (IG-Q105):* `service` is accepted on every platform; on Windows a start refuses it until RT-W14's dispatcher.

**IG-Q37 — where `service` is given — RULED 2026-10-14** (DC-Q18 in the daemon-configuration cutover). Command line only (IG-7): the run mode selects the file, so a key in that file could only restate or contradict it, and on Windows the installer's service registration carries the command line.

**IG-Q38 — what `option show` may reveal — RULED 2026-10-14** (DC-Q16's grammar side, with RPC_CHANNEL §6.4, RT-O24). IG-9's row names the grant under which `option show` discloses it: `health`, `status`, `peers` or `config`, default `config`. `log-level`, `log-category` and the two P2P rate rows are `status`. A row names `health` only if it passes RPC_CHANNEL §6.1's line for that grant: a client needs it to decide whether it can use the node now, and it says nothing lasting about the node; no row does today. The peer, closed-peer and ban rows are `peers`; everything that describes the host or links the operator (`mine-address`, `tor-onion`, paths, SOCKS endpoints, notify commands) is `config`; a secret's value is shown under no grant. IG-12 carries the contract: `option set` refuses a row not marked runtime with a typed code, requires the `node` grant and never writes the file; `option show` reports each value with its source and returns each row whose grant the caller holds.

**IG-Q39 — runtime defaults are values — RULED 2026-10-14** (with RPC_CHANNEL §6.4, RT-O25 and RT-O27). Every runtime row's default is writable as a value: a rate takes `unlimited`, and `log-category` takes `none` (no per-category overrides); an empty category list never means logging off. What `option show` prints is valid input to `option set` and builds the same value, and no row is both runtime and a secret.

**IG-Q40 — the inbound cap — RULED 2026-10-14** (Rick; the same ruling is in [`DAEMON_CONFIG_CUTOVER.md`](DAEMON_CONFIG_CUTOVER.md) §1.1). `p2p-inbound-max` is deleted, and `in-peers` is an X row (§5) whose reopener is a byte quota for metered links. The descriptor safety bound (`InboundCeiling`, [`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D4 and D8) is the only inbound bound and is unchanged; the daemon does not raise its own descriptor limit. What an operator pays is bytes, which the rate rows bound; which peers keep a slot is eviction (PWD-I8); handshake cost follows the accept rate (`P2P_TRANSPORT_LAYER.md` D10.3) and the onion proof-of-work. The unbounded cases (Windows, an unlimited or unreadable limit, an unreadable count) behave as today and are PWD-B1's, and their warnings name nothing the operator can set. The runtime set is four rows: `p2p-upload-max`, `p2p-download-max`, `log-level` and `log-category`.

**IG-Q41 — the Tor binary — RULED 2026-10-15** (Rick, on TSR-F8; the same ruling is in [`DAEMON_CONFIG_CUTOVER.md`](DAEMON_CONFIG_CUTOVER.md) §1.1). `SHEKYL_TOR_BINARY` was an environment input, which IG-13 refuses. It becomes the config key `tor-file`, accepted only with `tor = managed`, whose default is today's location: `tor/tor` beside the running executable, else the version-exact bundle directory under `/opt/shekyl/` on Unix. A set value changes where the binary is looked for, never whether it is verified: it passes the same pin gate, and its failure never falls through to discovery. The environment tier leaves the shared discovery function, so the wallet binaries lose it too; their override is the wallet's settings file.

---

## 16. Part C — the RPC wire's names

**RULED 2026-10-19 (Rick): IG-Q42…IG-Q57 as recommended.** Ground: `dev` `2470176c1`. Part C applies [`RPC_WIRE.md`](RPC_WIRE.md) RW-Q1, RW-Q6, RW-Q9 and RW-Q10 to every method the daemon serves, with its parameters and its reply fields (RW-Q8). The method census is §17, the field census §18, the glossary rows §19, and the questions §20. The wire carries these names from `CORE_RPC_VERSION` 4.0: the one rename PR after the store flip, which changed every in-tree client with it (RW-Q8). Part F (§25–§26) re-takes the census at that PR's ground and names what Part C had not.

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
| `get_block_header_by_height` (`getblockheaderbyheight`), `get_block_header_by_hash` (`getblockheaderbyhash`), `get_last_block_header` (`getlastblockheader`), `on_get_block_hash` (`on_getblockhash`) | `block_header_show` | exactly one of `height`, `hash` or `tip` (`{"tip": null}`; IG-Q94); `pow` (switch) | chain | RW-Q1; IG-Q46, IG-Q56; `pow` is served to a bounded caller: the hash recorded at validation, inside the header cap (IG-F24) |
| `get_block_headers_range` (`getblockheadersrange`) | `block_header_list` | `from`, `to` (inclusive heights), or `hash` (a list); `pow` (switch) | chain | RW-Q1; IG-Q53, IG-Q56 |
| `get_block` (`getblock`) | `block_show` | the selector as `block_header_show`'s (IG-Q94); `pow` (switch); `prune` (switch) | chain | RW-Q5's first output index is a field; IG-Q55 |
| `/get_blocks_by_height.bin` (`/getblocks_by_height.bin`) | `block_list` | `height` (a list); `prune` (switch) | chain | RW-Q5; bounded, `RPC_CHANNEL.md` §6.3; IG-Q55 |
| `/get_o_indexes.bin` | — | — | — | deleted (RW-Q5) |
| `/get_transactions` (`/gettransactions`) | `tx_show`, `tx_list` | `id`, one or a list; `prune` (switch) | chain, pool | IG-Q50, IG-Q55; unrelayed entries are host-only (RT-O9.3) |
| `/is_key_image_spent` | `chain_spent` | `key_image` (a list) | chain | a view with an input (IG-Q43) |
| `get_fee_estimate` | `fee` | — | chain | IG-Q52 |
| `get_coinbase_tx_sum` | `chain_coinbase_sum` | `from`, `to` | chain | IG-Q44 |
| `get_alternate_chains`, `/get_alt_blocks_hashes` | `chain_alt` | — | status | IG-Q46 |
| `get_curve_tree_info`, `get_curve_tree_checkpoint` | `curve_show` | exactly one of `height` or `tip` (IG-Q94) | chain | one reply type (IG-Q47) |
| `get_archival_emission_claim_source` | `archival_claim_show` | `{"persona": h}` | chain | the wallet's contract |
| `get_archival_shard_coverage` | `shard_coverage` | — | chain | |
| `request_archival_shard` | `shard_fetch` | `id` | chain | the wallet's word (§12.3); bounded by the shard-fetch permit (IG-Q90, IG-Q91) |
| `get_info`, `/get_info` (`/getinfo`) | `daemon_status` | — | health; each field by its grant | §13's word |
| `sync_info` | `sync_status` | — | peers | §13's word |
| `get_connections` | `peer_connections` | — | peers | §13's word |
| `/get_peer_list` | `peer_list` | `local` (switch) | peers | IG-Q51 |
| `/get_net_stats` | `p2p_stats` | — | status | §13's word |
| `option_set` | `option_set` | `value` (a map from option name to value) | node | IG-Q42 |
| `option_show` | `option_show` | `name` (a list, optional) | per row (IG-9) | named today |
| `/stop_daemon` | `daemon_stop` | — | node | §13's word |
| `/get_transaction_pool`, `/get_transaction_pool_hashes`, `get_txpool_backlog` | `txpool_list` | — | pool | IG-Q46, IG-Q57 |
| `/get_transaction_pool_stats` | `txpool_stats` | — | pool | IG-Q57 |
| `flush_txpool` | `txpool_flush` | `id` (a list, optional) | node | |
| `relay_tx` | `tx_relay` | `id` (a list) | node | |
| `/submit_transaction` | `tx_submit` | `body` | submit | |
| `get_block_template` (`getblocktemplate`), `get_miner_data` | `block_template` | — | mining-work | the one posted job; it pays the node's `mine-address` (IG-F23); IG-Q46 |
| `submit_block` (`submitblock`) | `block_submit` | `body` | mining-work | named, not positional (RW-Q2) |
| `calc_pow` | `pow` | `height`, `hashing`, `seed` | mining-work | a view with inputs (IG-Q43); IG-Q48 |
| `/start_mining`, `/stop_mining`, `/mining_status` | `mine_start`, `mine_stop`, `mine_status` | `threads` (an integer or `auto`) for `mine_start` | mining-control | §13's words; the node mines to its `mine-address` (IG-12, IG-F23) |
| `set_bans` | `ban_add`, `ban_remove` | `host`; `duration` for `ban_add` | bans | one verb per change; IG-Q44 |
| `get_bans`, `banned` | `ban_list`, `ban_show` | `host` for `ban_show` | bans | IG-Q46 |
| `/get_stem_tallies` | `relay_stats` | — | host-only (RT-O9.3) | |
| `generateblocks` | `dev_block_generate` | `count` | armed lever (RT-O9.2) | IG-Q49; IG-F23 |
| `/pop_blocks` | `dev_chain_pop` | `count` | armed lever (RT-O9.2) | IG-Q49 |
| `save_bc`, `flush_cache`, `inject_archival_serve_credit`, `/set_log_hash_rate` | — | — | — | deleted (`DRS_X_STORE_FLIP.md` DX-Q3) |

Words of `shekyl-cli` (§11, §13) that render part of another method's reply have no method of their own and stay in `shekyl-cli`'s table (RW-Q7): `chain` (bare), `chain difficulty`, `chain stats` and `peer stats`.

## 18. The field census

Each shape's fields today, and their names under this Part. The names the types carry, each with the holder its walk starts from and the grant that shows it, are [`docs/generated/rpc_wire_schema.tsv`](../generated/rpc_wire_schema.tsv), rendered from `shekyl-rpc-types`' method table (`wire::TABLE`, RW-Q7) and held equal to it by a test there; `scripts/ci/check_input_grammar_walk.py` walks that file over §3, §11, §14.2 and §19 and checks §17 and this section against it. The census from source, with each key's wire type and `file:line`, is the appendix [`INPUT_GRAMMAR_PART_C_CENSUS.md`](INPUT_GRAMMAR_PART_C_CENSUS.md). A reply of `show` is the item itself, and a reply of `list` is an array of items in selector order (IG-Q53). `status` leaves every reply (RW-Q3) and is not repeated below.

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

`get_block_header_by_hash`'s slot (`hash`, `block_header`) goes: a list reply is in selector order, and a slot that does not hold the item is `{"missing": null}` (IG-Q53, IG-Q73).

**Block** (`block_show`, `block_list`): `block_header` → `header`; `blob` → `body` (bytes); `tx_hashes` → `tx`, a list of `{id, body}` (`block_list` carries each body, as `get_blocks_by_height.bin` does today; `block_show` the same element; each `body` is the skeleton when `prune` is set — the pruned form with `prunable_hash`, `pqc_auth_hash` and `archival_size` beside it, IG-Q55 as SB-Q2 amends it); a transaction whose body this node discarded at the archival horizon answers its slot as `archived`, `{id, shard}`, instead of a body (`archived` → `archived`, the slot state; `DRS_SB_BELOW_HORIZON.md` SB-Q2); the first output's global index → `output_index` (RW-Q5). `miner_tx_hash` repeats the header's and goes; `json`, epee's rendering, goes (RW-Q4).

**Chain height** (`chain_height`): `height` (`/get_height`'s and `get_block_count`'s count) → `height`, the tip's ordinal (IG-Q45); `hash` → `hash`, the tip's; `writer`, the chain store's writer, `{"live": null}` or `{"halted": {"height": h, "invariant": n}}` (IG-Q92).

**Transaction** (`tx_show`, `tx_list`): `tx_hash` → `id`; `as_hex`, `pruned_as_hex` → `body` (bytes; the pruned segment when `prune` is set, IG-Q55 — never with the `pqc_auths` bytes appended, SB-Q2); `prunable_as_hex` and `as_json` go; `prunable_hash` → `prunable_hash`; `pqc_auth_hash` → `pqc_auth_hash` (a nullable hash: the `pqc_auths` region's digest, the txid's third operand; `null` where the identity has no third component, the coinbase); `archival_len` → `archival_size` (bytes); the three operands are in the entry only under `prune`, and without it the entry is `{id, body}` with the whole body (`RPC_WIRE.md` RW-Q4 as amended, 4.1); `pruned` goes (the request says); `archived` (`{tx_hash, shard}`, the side list beside `missed_tx`) → `archived`, the slot state: this node discarded the body with its shard at the archival horizon and the archive serves it (`PDM-Q10`, SB-Q2); never under `prune`, since every node holds the skeleton at every horizon, and never a transaction that carries no archival good, whose skeleton is its whole body; `in_pool` → `pooled` (switch); `double_spend_seen` goes (IG-Q57); `block_height` → `mined_height`; `confirmations` → `confirmations`; `block_timestamp` → `mined_time`; `output_indices` → `output_index` (a list); `relayed` → `public` (switch: the pool's one bit, IG-Q57; `true` for every caller below host-only, since an entry not yet public is host-only, RT-O9.3); `received_timestamp` goes with the pool's receive time (IG-Q57). `txs_hashes` → `id`; `missed_tx`, `unavailable_tx` and the `archived` side list fold into the slot, which is the entry, `{"missing": null}`, `{"archived": {…}}`, or `null` where the pool could not be asked (IG-Q73).

**Spent** (`chain_spent`): `key_images` → `key_image`; `spent_status` (0, 1, 2) → a list of one-of `unspent`, `chain`, `txpool`, in request order.

**Fee** (`fee`): `fees`, three positional tiers → `economy`, `standard`, `high` (amounts per unit of weight; the priority keywords of §11, IG-Q52).

**Coinbase sum** (`chain_coinbase_sum`): `height`, `count` → `from`, `to`; `emission_amount`, `wide_emission_amount`, `emission_amount_top64` → `emission` (amount); the three `fee_amount` fields → `fee` (amount).

**Alternative chain** (`chain_alt`, an element per chain): `block_hash` → `hash` (its tip); `height` → `height`; `length` goes (it is the length of `block`); `difficulty`, `wide_difficulty`, `difficulty_top64` → `difficulty_cumulative` (`HexU128`; today's name hides that it is cumulative); `block_hashes` → `block` (a list of hashes, tip first); `main_chain_parent_block` → `parent`. `/get_alt_blocks_hashes`'s `blks_hashes` folds into it (IG-Q46).

**Curve tree** (`curve_show`): `root` (free-length hex today) → `root` (hash); `depth` → `layers`; `leaf_count` → `leaf_count`; `height` (`chain_height - 1` in one method) and `block_height` (the other) → `height`, ordinal.

**Archival claim source** (`archival_claim_show`): `p_id` → `persona`; `chain_height` → `height` (ordinal, IG-Q45); — → `hash`, the hash of the block at `height`, read in the same snapshot (IG-Q84); `current_settled_epoch` → `settled_epoch`; `has_bond_record`, `join_settlement_epoch` → `joined_epoch` (`null`: no bond record); `holdings_kind` (0, 1) → `holding`, one-of `shards`, `complete-tree`; `held_shard_ids` → `shard` (a list); `claimed_settlement_epochs` → `claimed` (a list of epochs); `bonded_total_atomic` → `bond_total` (amount); `bad_interval_count` → `failure_count`; `has_last_served_epoch`, `last_served_epoch` → `served_epoch` (`null`: never served); `has_last_settled_slash_epoch`, `last_settled_slash_epoch` → `slash_epoch` (`null`: never slashed); `epochs` → `epoch` (a list).
- Its epoch element: `settlement_epoch` → `id`; `close_block_height` → `closing_height`; `sigma_work_milli` → `work` (milli, IG-Q54); `budget_atomic`, `has_budget_row` → `budget` (amount, `null`: no budget row); `bonds` → `bond`; `shards` → `shard`; `credit_pairs` → `credit`; `claimant_bond_idx` (`u64::MAX` for none) → `claimant` (an index into `bond`, `null` for none).
- Its bond element: `join_settlement_epoch` → `joined_epoch`; `is_support_complete_tree` → `complete_tree` (switch); `bad_intervals_flat` (flattened pairs) → `failure`, a list of `{from, to}`, inclusive: the intervals the bond failed.
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
| `connectors` (a list of rows) | `connector`, a map from connector to its counts (IG-Q82) | `p2p` (`running`, `offline`) | goes: it repeats `offline` |
| `pool_retired` | `txpool_retired` (status; IG-Q74) | `tx_pool_unbroadcast_count` (host-only, RT-O9.3) | `txpool_private_count` (host-only) |
| `restricted` | `grant` (the grants the caller holds, `RPC_CHANNEL.md` §6.2) | — | `writer` (health; IG-Q92) |

A connector's counts (`connector`'s values): `incoming_sockets` → `inbound_count`; `outgoing_sockets` → `outbound_count`; `white_peerlist_size` → `peer_white_count`; `gray_peerlist_size` → `peer_gray_count`. `txpool_count` and `txpool_private_count` are `null` when `txpool_retired` is true.

**Version** (`version`; its fields walk under `daemon`, whose build and network the read names): `version` (frozen); `release` → `tagged`; `current_height` (a count) → `height` (ordinal, IG-Q45); `target_height` (a count) → `target_height` (ordinal, IG-Q45); `consensus_constants_digest` → `consensus_digest`; `nettype` → `network` (its value `fakechain` is `regtest`, §3's name); `genesis_hash` → `genesis`.

**Connection** (`peer_connections`): `incoming` → `inbound` (switch); `localhost`, `local_ip` → `local` (switch); `address`, `host`, `ip`, `port` → `endpoint` (peer-endpoint); `address_type` → `connector` (one-of `clearnet`, `tor`); `recv_count`, `send_count` → `download`, `upload` (bytes); `recv_idle_time`, `send_idle_time` → `download_idle`, `upload_idle` (duration); `state` (the session's mode) → `mode` (IG-Q81; `null` for a connection chain sync does not hold); `live_time` → `age` (duration); `avg_download`, `current_download`, `avg_upload`, `current_upload` → `download_speed_average`, `download_speed_current`, `upload_speed_average`, `upload_speed_current` (bytes per second; KiB/s today); `connection_id` → `id`; `height` (the claim's count) → `height`, the ordinal of the tip the peer claims, `null` before it has claimed (IG-Q81).

**Sync status** (`sync_status`; IG-Q80): `height` (a count) → `height` (ordinal, IG-Q45); `target_height` (a count) → `target_height` (ordinal); `state` → `state` (one-of `unpeered`, `behind`, `following`, `synced`); `stalled` → `stalled` (switch); `peers` → `session`, a list, whose element is `connection_id` → `connection`, `address` → `endpoint`, `claimed_height` → `height` (ordinal, `null` before a claim), `mode` → `mode`, `header_request` → `header` (`{age, due}` or `null`), `body_requests` → `span` (a list of `{from, blocks, size, age, due}`, from `start_height`, `count`, `planned_bytes`, `age_ms`, `due_in_ms`), `rate` → `download_speed` (bytes per second, `null` until a response has arrived). `age` and `due` are durations in whole seconds.

**Peer list** (`peer_list`, an element per peer): `host`, `ip`, `port` → `endpoint`; each element names its list in `tier`, one-of `white`, `gray` (IG-Q51); `white_list`, `gray_list` go. `public_only` (default true) → `local` (switch, default off: include local endpoints); `include_blocked` goes: banned hosts are `ban_list`'s (IG-Q51).

**P2P statistics** (`p2p_stats`): `start_time` → `started`; `total_bytes_in`, `total_bytes_out` → `download`, `upload` (bytes); `total_packets_in`, `total_packets_out` → `download_packets`, `upload_packets`.

**Options** (`option_set`, `option_show`): the reply's `options` unwraps (IG-Q53): the reply is the list of rows, and each row keeps `name`, `value`, `source`, `runtime` and `secret`, and the secret form's `set` → `assigned` (§11's `set` is the verb; IG-Q42). `option_set`'s `options`, a list of `{name, value}`, → `value`, a map from option name to value (IG-6's map; a name cannot be given twice); `option_show`'s `names` → `name`. A refusal's `data` is a diagnostic (IG-11, RW-Q3), whose fields walk under the subject `diagnostic`: `code`, `option`, `source` and `message` keep their names, and its `params`, positional pairs today, become `parameter`, a map.

**Pool entry** (`txpool_list`): `id`, `weight`, `fee`, the Rust pool's listing (`rust/shekyl-mempool/src/relay.rs`, `Listed`; IG-Q57). Today's `tx_info` fields `id_hash` → `id`, `weight` → `weight`, `fee` → `fee`; `tx_json`, `tx_blob`, `blob_size`, `max_used_block_id_hash`, `max_used_block_height`, `kept_by_block`, `last_failed_height`, `last_failed_id_hash`, `receive_time`, `relayed`, `last_relayed_time`, `do_not_relay` and `double_spend_seen` go; the body is `tx_show`'s. `spent_key_images` goes with them. `/get_transaction_pool_hashes`' `tx_hashes` and `get_txpool_backlog`'s packed `backlog` fold into the list (IG-Q46).

**Pool statistics** (`txpool_stats`): `pool_stats` unwraps. `txs_total` → `count`; `bytes_total`, `bytes_min`, `bytes_max`, `bytes_med` → `weight_total`, `weight_min`, `weight_max`, `weight_median`; `fee_total` → `fee_total`; `num_double_spends` goes (IG-Q57); `num_not_relayed` (host-only, RT-O9.3) → `private_count` (host-only); `num_failing`, `oldest`, `num_10m`, `histo_98pc` and `histo` go (IG-Q57).

**Template** (`block_template`): no parameters; the reply is the one posted job, which pays the node's `mine-address` (IG-F23). Reply: the difficulty triple → `difficulty`; `height` → `height` (the next block's ordinal, `HEIGHT_SEMANTICS.md` §3.1 C6); `reserved_offset` → `extra_offset`; `nonce_offset` → `nonce_offset` (IG-Q78); `expected_reward` → `reward`; `prev_hash` → `parent`; `seed_height` → `seed_height`; `blocktemplate_blob` → `body`; `blockhashing_blob` → `hashing` (bytes); `seed_hash` → `seed`; `next_seed_hash` (`""` when unchanged) → `seed_next` (`null` when unchanged). `get_miner_data` folds in (IG-Q46): its `major_version` → `version_major`, `median_weight` → `weight_median`, `already_generated_coins` (a number there) → `emission` (amount); its `height`, `prev_id`, `seed_hash` and `difficulty` (a `0x` string there) are the template's; its `tx_backlog` is `txpool_list`'s.

**Submit** (`block_submit`, `tx_submit`): `params[0]` and `tx_blob` → `body`; `block_id` → `hash`. `tx_submit`'s `verdict` keeps its name, with hyphenated keywords (`already-in-pool`; IG-Q86); `cause` is one object with one key, the cause, whose value is its payload or `null` (IG-Q76; `row` goes into it); `relay` on `already-in-pool` → `publication` (one-of `held`, `overdue`, `public`, `untracked`; IG-Q75); and its `height` (the block that holds the transaction, on `already-in-chain`) → `mined_height`, as on the transaction entry.

**Proof of work** (`pow`): `height` → `height`; `block_blob` → `hashing`; `seed_hash` (`""` allowed) → `seed` (optional). The bare-string reply → `{"pow": h}`.

**Miner** (`mine_start`, `mine_status`; IG-Q77): `mine_start` takes `threads` (an integer, or the keyword `auto`) and no address (IG-F23). Status: `active` → `active`; `speed` → `speed`, `{count, window}` (hashes counted over a window of complete seconds, a duration); `threads_count` → `threads` (an integer); `address` (`""` when unset) → `address` (`null` when unset); `pow_algorithm` (always `RandomX`) goes; `block_target` → `block_spacing`; the posted job's `height`, `block_reward` and difficulty triple → `height`, `reward`, `difficulty`, each `null` when no job is posted; `no_template` → `cause` (a diagnostic, or `null` when a job is posted); `pool_retired` → `txpool_retired` (IG-Q74).

**Bans** (`ban_add`, `ban_remove`, `ban_list`, `ban_show`): `set_bans`' list of `{host, ip, ban, seconds}` → one `host` and `duration` per `ban_add` and one `host` per `ban_remove`; `ip` goes (the host carries it); `banned`'s `address` → `host`. An entry: `host`, `seconds` → `duration` (remaining), `permanent` → `permanent`; `banned`'s `banned` goes (`ban_show` replies `null` for a host not banned).

**Pool and chain flush, relay** (`txpool_flush`, `tx_relay`): `txids` → `id`.

**Relay statistics** (`relay_stats`): `floor` → `floor`, whose element is `connector` → `connector`, `achieved_out_connections` → `outbound_count`, the inner `floor` → `outbound_min`, `below` → `below`; `tallies` → `tally`, whose element is `peer` (the connection's id) → `connection` (IG-Q83), `connector` → `connector` (`null` where it has not been observed; today's `unnamed`), `propagated`, `silent` → `propagated`, `silent`, `distinct_sources` → `sender_count`.

**Armed levers**: `generateblocks` takes `count` and nothing else (IG-F23); reply `height` → `height`, `blocks` → `hash` (a list). `pop_blocks`' `nblocks` → `count`; reply `height` (a count) → `height` (ordinal).

## 19. Glossary — Part C's terms

Rows below add to §3 and §11. A term already there that gains a parent here keeps its one meaning; where its meaning is stated per parent, as `height`'s is, the row under its new parent says what it names there.

**New terms:**

| Term | Parents | Meaning | Kind |
|---|---|---|---|
| header | block | a block's header; with `show` and `list`, the read | |
| template | block | *view* — a block to mine on, built for an address | block:view |
| submit | block, tx | *verb* — hand to the daemon for acceptance | block:verb, tx:verb |
| curve | — | the curve tree, FCMP++'s membership accumulator (IG-Q47) | |
| root | curve, attestation | a tree's root hash | |
| leaf | curve, coverage | a leaf of the curve tree | |
| layers | curve | the tree's depth, in layers | |
| claim | archival | an emission claim's source record | |
| coverage | shard | *view* — holders per shard | shard:view |
| persona | — | a persona's canonical id | |
| generate | block | *verb* — mine blocks; only under `dev` | block:verb |
| pop | chain | *verb* — remove blocks from the tip; only under `dev` | chain:verb |
| id | tx, connection, shard, epoch, txpool | an identifier: a transaction's id (a hash), a connection's, a shard's | |
| key | spent, console | a key: under `spent`, only in `key image`; under `console`, the console key (IG-Q88) | |
| image | key | a key image (a hash) | |
| tip | block, curve | the chain's last block, as a selector; its value is `null` (IG-Q94) | |
| prune | tx | a switch: carry the skeleton — the pruned segment with the txid's operands `prunable_hash`, `pqc_auth_hash` and `archival_size` (`DRS_SB_BELOW_HORIZON.md` SB-Q2) | |
| prunable | tx | the prunable part of a transaction | |
| pqc | tx | the transaction's `pqc_auths` region, the post-quantum authorizations; only in `pqc auth hash` | |
| auth | pqc | an authorization; only in `pqc auth hash`, the region's digest, the txid's third operand | |
| archived | tx | a slot state: this node discarded the body with its shard at the archival horizon, and the archive serves it; carries `id` and `shard` (`PDM-Q10`, SB-Q2) | |
| public | tx | the pool's one bit: the relay has made the transaction public (`DAEMON_RELAY_PRIVACY.md` acceptance criterion 2) | |
| private | txpool | entries whose `public` bit is unset; with `count`, host-only (RT-O9.3) | |
| confirmations | tx | blocks since the transaction's | |
| parent | block, alt, header, template | the block this one extends (a hash) | |
| nonce | block, header, template | the header's nonce; under `template`, with `offset`, where its bytes sit | |
| orphan | block, header | not on the main chain | |
| reward | block, mine, header, template | the block's reward, an amount | |
| cumulative | difficulty | summed over the chain to this block | |
| longterm | weight | the long-term weight | |
| median | weight, size | the median | |
| total | fee, weight, burn, bond | a sum | |
| attestation | header | the attestation tree | |
| index | output | a global output index | |
| time | block, header, daemon, mined | a point in time (IG-Q54) | |
| adjusted | time | the network-adjusted time | |
| started | daemon, p2p | when it started, a time | |
| spacing | block | the target time between blocks | |
| target | sync, daemon | what the node is syncing to; `target height`, its height | |
| synchronized | daemon | the node holds the target | |
| syncing | daemon | the node is syncing | |
| degraded | daemon | following, degraded | |
| peered | daemon | at least one handshaken session (`has_peers`) | |
| protocol | daemon | the P2P protocol; with `version`, its version | |
| emission | coinbase, daemon, sum, template | coins emitted | |
| burn | daemon | the share the next coinbase burns (micro) and, with `total`, what has burned | |
| tagged | version, daemon | a tagged release build | |
| multiplier | emission | the release multiplier (micro; `shekyl-economics`) | |
| share | stake | the stakers' effective emission share (micro) | |
| disk | daemon | the data directory's disk | |
| free | disk | its free space, in bytes | |
| outbound | peer, clearnet, tor, floor | connections we open | |
| grant | daemon | the grants this connection holds | |
| consensus | — | the consensus rules; `consensus digest`, the constants' digest | |
| digest | consensus | a digest | |
| connector | connection, floor, tally, sync, daemon | one-of `clearnet`, `tor`; under `sync`, the connectors the node syncs over (IG-Q71); under `daemon`, a map from each connector the node runs to its counts (IG-Q82) | |
| connection | peer, session, tally | a P2P connection; under `session` and `tally`, its id, as `peer_connections` gives it | |
| host | ban | an IP address or subnet | |
| parameter | diagnostic | a diagnostic's named parameters, a map (IG-11) | |
| diagnostic | — | a typed refusal (IG-11): a JSON-RPC error's `data` (RW-Q3) | |
| code | diagnostic | its stable dotted code (`config.value.range`) | |
| message | diagnostic | its one English rendering | |
| pooled | tx | in the pool, not yet in a block | |
| mined | tx | the block that holds the transaction; with `height` and `time` | |
| verdict | tx | the daemon's verdict on a submitted transaction | |
| cause | tx, tor, mine | why a rejected transaction was refused, one object with one key (IG-Q76); under `tor`, the supervisor's cause variant, one object or null (IG-Q70); under `mine`, why no job is posted, a diagnostic or null (IG-Q77) | |
| claimed | claim | the epochs this persona has claimed | |
| failure | bond, claim | an interval the bond failed, `{from, to}`; with `count`, how many | |
| offline | daemon | P2P is off (IG-Q3's offline state) | |
| economy | fee | the `economy` tier's fee per unit of weight | |
| standard | fee | the `standard` tier's | |
| high | fee | the `high` tier's | |
| name | option | an option's name | |
| value | option | an option's value, valid input to `option set` | |
| source | option, diagnostic | where the value came from: `default`, `file`, `cli`, `runtime` | |
| runtime | option | whether `option set` accepts the row (IG-12) | |
| secret | option | the row is a secret: its value is never shown | |
| assigned | option | a secret row has a value | |
| major | version | the major version | |
| minor | version | the minor version | |
| state | sync, tor | under `sync`, chain sync's derived state: one-of `unpeered`, `behind`, `following`, `synced` (IG-Q80); under `tor`, the §4.3 projection (IG-Q69) | |
| age | connection, header, span, tor | how long it has lived: a connection, a request in flight, or under `tor` the state (IG-Q93) | |
| idle | download, upload | time since the last bytes | |
| speed | download, upload, mine | per second: bytes under download and upload; under `mine`, hashes counted over `window` | |
| average | speed | the average | |
| current | speed | the current value | |
| packets | download, upload | a packet count | |
| span | session | a body span in flight to the session (IG-Q80) | |
| tier | peer | which peer list holds it, one-of `white`, `gray` | |
| offset | extra | where the reserved extra bytes start | |
| extra | template | the coinbase's reserved extra-nonce bytes; with `offset`, where they start | |
| revision | daemon | the build's version string | |
| joined | bond, claim | the epoch the bond joined | |
| closing | epoch, shard | the epoch's closing height | |
| hashing | template, pow | the bytes proof of work hashes | |
| next | seed | the next seed | |
| active | mine | the miner is running | |
| permanent | ban | a ban with no end | |
| floor | relay | the per-connector outbound floor | |
| below | floor | under the floor | |
| tally | relay | per-successor relay outcomes | |
| propagated | tally | propagated relays | |
| silent | tally | silent relays | |
| sender | tally | a distinct peer that sent the transaction; with `count` | |
| holding | claim | one-of `shards`, `complete-tree` | |
| settled | claim, coverage | the last settled epoch | |
| bond | — | an archival bond: a subject, which the claim source, an epoch and a credit name by reference (IG-Q42) | |
| served | claim, coverage, shard | served | |
| slash | claim | slashed | |
| work | epoch, coverage | the summed work (milli, IG-Q54) | |
| budget | epoch, coverage | the budget, an amount | |
| credit | epoch | a credit pair | |
| claimant | epoch | the claiming bond's index | |
| segment | shard | the shard's segment is held | |
| freeze | shard | the freeze height | |
| frozen | coverage | frozen shards, with `count` | |
| bonded | coverage, shard | bonded holders, with `count` | |
| scarcity | coverage, shard | the join scarcity (micro, IG-Q54) | |
| profit | coverage, shard | the expected profit, an amount | |
| hiding | daemon | an address-hiding session exists now, with no pin state: the class part of the hop-0 verdict (IG-Q67) | |
| posture | daemon | the connector settings in force: `tor` and `clearnet` (IG-Q68) | |
| origination | daemon | what happens to the node's own transactions (`OwnTx`), from the relay's two verdict parts (IG-Q68) | |
| facet | tor | which facet is down: outbound or inbound; null when the impaired state names no facet (IG-Q69) | |
| respawn | tor | a restart of the managed Tor; with `count`, how many | |
| progress | tor | how far bootstrap has come, an integer from 0 to 100 | |
| flagged | tor | the consensus does not recommend this Tor; independent of the state and of the cause (IG-Q70) | |
| fix | tor | a fix the operator may apply; the list is empty except for an install cause | |
| missing | tx | a slot state: the node was asked and holds no such item (IG-Q73) | |
| retired | txpool | the pool's file faulted and the node holds no pool until it restarts (IG-Q74) | |
| publication | tx | where the caller's own transaction stands with the relay: one-of `held`, `overdue`, `public`, `untracked` (IG-Q75) | |
| session | sync | a peer session chain sync holds (IG-Q80) | |
| mode | session, connection | what chain sync's header run is doing with the session: one-of `idle`, `reachable`, `slot`, `challenging`, `past-cap`, `evidence-candidate`, `evidence` | |
| due | header, span | until the response is late, a duration; `0` once it is | |
| stalled | sync | behind, with nothing moving toward the target | |
| writer | chain, daemon | the chain store's writer: `live`, or `halted` on an invariant (IG-Q92) | |
| invariant | writer | the `SI-` row of the store-invariant register that caught the halt, an integer | |
| client | rpc | a client identity enrolled on this daemon: a fingerprint and its ceiling (IG-Q87) | |
| bundle | rpc | this daemon's static public keys, given to a client that will be enrolled | |
| fingerprint | client | the client's static-key fingerprint, a hash (`RPC_CHANNEL.md` RT-O14) | |
| ceiling | client | the grants an enrolment may hold, stored expanded | |
| console | rpc | the console key: the host administrator's credential in service mode (IG-Q88) | |
| reset | key | *verb* — replace the console key, offline, under the data home's lock | key:verb |

**Terms of §3, §11 and §14.2 that gain a parent:**

| Term | Gains parents | Meaning there | Kind |
|---|---|---|---|
| pow | —, dev | proof of work (RandomX): bare, *view* — compute a block's proof-of-work hash; under `dev`, its seed schedule (IG-Q48). A header's `pow` field and the header reads' `pow` switch name it by reference (IG-Q42) | —:view |
| coinbase | header, shard | the coinbase transaction: under `chain`, its outputs (§11); under `header`, its id | |
| output | block, coinbase, shard, tx | the block's first output; `output index`, its global index | |
| alt | daemon | §11's `alt` gains `daemon`: the alternative blocks | |
| relay | — | §3's `relay` is also a subject: transaction relay, whose statistics `relay stats` reads | |
| endpoint | connection, peer, session | §11's `endpoint`: the peer's | |
| version | header, daemon, protocol, template | the version of what its parent names: under `header` and `template`, the block format's; under `protocol`, the P2P protocol's; under `daemon`, the RPC contract's, the field RW-Q6 freezes. Bare, §3's `version` is the binary's, so none of these is a reference to it | |
| blocks | span | a length in blocks | |
| add | client | *verb* — §11's `add`: enrol a client | client:verb |
| set | client | *verb* — §11's `set`: assign an enrolled client's ceiling | client:verb |
| remove | client | *verb* — §11's `remove`: revoke an enrolment | client:verb |
| offset | nonce | where its bytes start | |
| body | block, template, tx | a block's or transaction's serialized bytes, kind `bytes` | |
| complete | bond | the whole corpus | |
| count | alt, block, bonded, chain, failure, frozen, gray, inbound, leaf, outbound, private, sender, served, speed, tx, txpool, white, respawn | how many | |
| depth | header | a depth in blocks | |
| difficulty | alt, daemon, header, mine, template | a mining difficulty (`HexU128`) | |
| download | connection, session | bytes we receive | |
| epoch | claim, joined, served, settled, slash | a fixed-length run of blocks: the epoch its parent names | |
| from | block, failure, span | the first height | |
| gray | peer | the gray peer list | |
| hash | alt, auth, chain, claim, daemon, header, prunable, shard | a 32-byte hash that identifies what its parent names; under `auth`, the digest of the `pqc_auths` region | |
| height | alt, claim, closing, connection, coverage, curve, daemon, freeze, header, mine, mined, pow, seed, session, sync, target, template, writer | a block height, an ordinal: the height of what its parent names (a tip, a target, a block) | |
| inbound | clearnet, connection, peer, tor | connections other nodes open to us | |
| list | block, header, client | *verb* — print the entries; on the wire, a bounded list (RW-Q1) | block:verb, header:verb, client:verb |
| local | connection, peer | endpoints not dialable on the public internet | |
| seed | template | the RandomX seed | |
| show | claim, curve, header, bundle | *verb* — print one item, by a typed selector (RW-Q1) | claim:verb, curve:verb, header:verb, bundle:verb |
| size | archival, data, extra, shard, span | a size in bytes | |
| header | session | §19's `header`: the read of headers in flight to the session | |
| stats | relay | *view* — statistics | relay:view |
| to | block, failure | the last height, inclusive | |
| upload | connection | bytes we send | |
| weight | block, header, template, tx | a weight, in bytes | |
| white | peer | the white peer list | |

Value keywords added: `unspent` (spent), `shards`, `complete-tree` (holding), `clearnet`, `tor` (connector), `white`, `gray` (tier); by Part F, `live`, `halted` (writer), `held`, `overdue`, `public`, `untracked` (publication), `unpeered`, `behind`, `following`, `synced` (sync state), the session modes, and the verdict and cause keywords of IG-Q86.

Every term of §3 and §11 used as a field (`height`, `hash`, `count`, `weight`, `fee`, `address`, `size`, `depth`, `seed`, `threads`, `difficulty`, `from`, `to`, `blocks`, `download`, `upload`, `inbound`, `local`, `endpoint`, `white`, `gray`, …) gains the object that holds it as a parent and keeps its one meaning; the schema RW-Q7's table generates lists those edges for the gate. The implementing PR builds the field table from the reply types (RW-Q7) and brings any term this census missed as a row for ruling in its review.

## 20. Questions for Part C

Each is ruled. A question that amends a row ruled before it names that row, and the row carries the amendment.

**IG-Q42 — the names of parameters and fields, and how the gate walks them — RULED 2026-10-19, as recommended.** RW-Q10 makes parameter and field names glossary paths, and the conventions below are needed to write and to check them. *Recommended:*
- **A field's name** is the rest of its path below the object that holds it: inside a block header the field is `hash`, never `block_hash`.
- **A parameter's name** is the rest of its path below the object it selects or modifies. A selector's object is the method's subject: `block_header_show`'s `height` walks `block` → `height`. A modifier's object is what it modifies: `prune` modifies a transaction's body, so it walks `tx` → `prune` on every method that carries one, `block_show` and `block_list` included, and `pow` modifies a header, so it walks `header` → `pow`. An input (IG-Q43) parameterizes its view, so its object is the view: `chain_spent`'s `key_image` walks `spent` → `key` → `image`. A verb's argument walks below the noun the verb acts on: `ban_add`'s `host` walks `ban` → `host`.
- **A reference.** A field or parameter may name another subject directly: the subject alone, or a path starting at it (`block_count` walks `block` → `count`). That is a reference to the other thing, and it needs no edge from its holder: glossary edges express refinement only. The gate tries the holder's path first and the reference form second, and refuses a name valid neither way. In a method name, `dev` is followed by a reference (IG-Q49).
- **A list-valued parameter or field** takes the singular term with an array value (`{"height": [7, 8]}`), IG-6's list convention on the wire.
- **How the gate finds each object.** Every request and reply type in RW-Q7's table, and every type nested in one, carries its object's path as a constant on the type: a reply or element type names what it describes (`block header`, `peer connection`), a selector type names the method's subject, a modifier type names what it modifies (the transaction-body options carry `tx`), and a request type's remaining fields are inputs or arguments under the path its row gives. The schema generator emits each field with its holding type's path, and the gate walks that path followed by the field's terms. No list of objects is kept by hand.
- **The walk checks edges, not membership.** For every method, parameter and field, each adjacent pair of terms is a parent → child edge in §3, §11, §14.2 or §19, and a method's first term is a subject. A method's last term is a view or a verb under the parent its walk used, read from the Kind column (a bare-subject method, such as `fee`, `pow` or `version`, by its bare kind); a qualifier (`max`, `min`) may end any path. A name whose pairs are all terms but not all edges fails.

Three consequences amend RT-O23's wire (`RPC_CHANNEL.md` §6.4), landed with #1088: a secret row's `set` collides with §11's verb `set` and becomes `assigned`; `option_set`'s request, a list of `{name, value}` under the key `options`, cannot walk (`option` → `option`) and becomes `value`, a map from option name to value; and the replies' `options` wrapper goes (IG-Q53).

**IG-Q43 — a view's inputs — RULED 2026-10-19, as recommended.** RW-Q1 says a view noun takes no selector. Several reads take an input that is not a choice of stored item: `chain spent` takes key images, `block template` the address to pay, `pow` a block's hashing bytes. *Recommended:* a *selector* picks a stored item and belongs only to `show` and `list`; an *input* parameterizes what a view computes, and a view may take inputs. `chain spent` (IG-Q25's view) stays a view.

**IG-Q44 — §13's range reads and the ban duration — RULED 2026-10-19, as recommended.** This amends §13 rows ruled 2026-10-14 (IG-Q25).
- RW-Q1 gives `show` one item by a typed selector and makes `block header list` the bounded range of headers. §13 maps `print_bc <from> [<to>]`, a range of headers, to `chain show --from --to`.
- `print_coinbase_tx_sum <from> [<count>]` maps to `chain coinbase sum --from --last`, where `last` already means "the most recent N blocks" (§11).
- `alt_chain_info [hash]` maps to `chain alt [hash]`, a selector on a view.
- `ban add <ip> [--seconds N]` names its unit, which RW-Q10 refuses on the wire.

*Recommended:* `print_bc` becomes `block header list --from --to`, and `chain show` leaves §13; `chain coinbase sum` takes `--from` and `--to`, inclusive heights, so `last` keeps its one meaning; `chain alt` takes no argument and the console finds the chain in the one reply; `ban add <ip> [--duration <quantity>]`, an IG-6 duration.

**IG-Q45 — the tip's height — RULED 2026-10-19, as recommended.** `/get_height`, `get_block_count`, `get_version`'s `current_height`, `get_info`'s and `sync_info`'s `height`, the `target_height` of `get_version`, `get_info` and `sync_info` (the core's target, a count: `src/rpc/rpc_facts_ffi.cpp`, `chain_tip`'s caller), the claim source's `chain_height` and `pop_blocks`' reply carry the chain's *count* (tip + 1, `HEIGHT_SEMANTICS.md` §1), most of them under the name `height`. `HEIGHT_SEMANTICS.md` §3.1 (C1, C2) keeps the wire a raw integer whose identity is its field's name, decoded once at the edge, and RW-Q4 names height versus count in the field. *Recommended:* every tip-shaped field is an ordinal, and no field carries the count. The tip is `height`, and `target_height` on `daemon_status`, `sync_status` and `version` moves with it in the same PR, so a client never compares an ordinal with a count. Each client's decode site changes from `ChainCount::from_raw` to `BlockHeight::from_raw` in the rename PR, and computes the count where it needs one. The change is safe across versions because no client decodes a reply from a daemon of another version: RK-Q11's version-first read (`DAEMON_RPC_KV_GET_INFO.md`, ruled 2026-10-10) compares `version` with `CORE_RPC_VERSION` and refuses a mismatch before the strict decode runs, and the rename PR (at 4.0) must not relax that match. The alternative keeps the count on the wire under the name `count` (`chain_height`'s reply would then be a count named by its field), which leaves a view called `height` that prints a count.

**IG-Q46 — the folds — RULED 2026-10-19, as recommended.** RW-Q1 gives one method per reply type, which folds methods that answer one fact twice:
- `on_get_block_hash` into `block_header_show` (the hash is a header field), and `get_block_count` into `chain_height`;
- `/get_alt_blocks_hashes` into `chain_alt`, whose elements carry their blocks' hashes;
- `/get_transaction_pool_hashes` and `get_txpool_backlog` into `txpool_list`;
- `get_miner_data` into `block_template`: its only consumers are the regtest suite and the Python framework, and its fields are the template's. The FOLLOWUPS `get_miner_data` row (one chain state across its reads; owner `RPC_WIRE.md`'s per-lock-domain rule) moves to `block_template` with it;
- `get_bans` and `banned` into `ban_list` and `ban_show`, §13's words.

*Recommended:* all five. Each folded method's consumers move in the rename PR (RW-Q8).

**IG-Q47 — the curve tree — RULED 2026-10-19, as recommended.** `get_curve_tree_info` and `get_curve_tree_checkpoint` reply one shape (root, depth, leaf count, height) for the tip and for a given height. `tree` is taken: under `complete` it is the CompleteTree posture (IG-Q28), and a term has one meaning (IG-2). *Recommended:* a new subject `curve`, the curve tree, and one method `curve_show` with the selector `{"height": n}` or `"tip"` (RW-Q1). The alternative gives `tree` the meaning "the curve tree" and renames IG-Q28's row.

**IG-Q48 — `pow` — RULED 2026-10-19, as recommended.** This amends §3's `pow` row, ruled 2026-10-13. `calc_pow` computes a block's proof-of-work hash for an external miner; §3 defines `pow` under `dev` as "the RandomX seed schedule". *Recommended:* `pow` means proof of work (RandomX) everywhere, a subject and a child of `dev`: `pow` alone is the view that computes the hash (`calc_pow`'s successor), the header's `pow` field holds it and names it by reference (IG-Q42), and `dev-pow-seed-*` keeps its spelling, now read as "proof of work's seed".

**IG-Q49 — the armed levers' names — RULED 2026-10-19, as recommended.** `generateblocks` and `pop_blocks` are armed test levers (RT-O9.2): never on mainnet, served only to the host's administrator when armed. IG-Q25 gives `pop_blocks` no console word; each still needs a method name under RW-Q1. *Recommended:* they sit under `dev`, as IG-8 places development options: `dev_block_generate` and `dev_chain_pop`. In a method name, `dev` is followed by a reference (IG-Q42): `dev_block_generate` walks `dev`, then the reference `block` → `generate`, so the lever needs no `dev` → `block` edge, and its arguments and reply walk under the reference (`block` → `count`). Neither has a console word, and IG-Q25 stands.

**IG-Q50 — one transaction and many — RULED 2026-10-19, as recommended.** `/get_transactions` takes a list of ids; §13's word is `tx show <id>`. *Recommended:* two methods, two reply types (RW-Q1): `tx_show {"id": h}` and `tx_list {"id": [h, …]}`, bounded by the resource policy (`RPC_CHANNEL.md` §6.3). Unrelayed entries stay host-only in both (RT-O9.3).

**IG-Q51 — the peer list — RULED 2026-10-19, as recommended.** `/get_peer_list` returns two arrays, and `public_only` defaults to true, against IG-4's "a switch defaults to off"; §13's word is `peer list [--white] [--gray] [--max N]`. *Recommended:* `peer_list` returns one list, each element naming its list in `tier` (`white` or `gray`); `public_only` becomes `local` (default off: include local endpoints, §3's `local`) and `include_blocked` goes, because listing banned hosts is a `bans` fact (`RPC_CHANNEL.md` §6.1) that `ban_list` already answers, one method per fact; the bound is the resource policy's, and the console's `--white`, `--gray` and `--max` filter the one reply.

**IG-Q52 — the fee read — RULED 2026-10-19, as recommended.** `get_fee_estimate` returns three positional tiers. `fee` is the wallet's view "a fee quote". *Recommended:* the daemon method is `fee`, with that one meaning; its reply names its tiers by §11's priority keywords (`economy`, `standard`, `high`), each an amount per unit of weight, and the wallet's `fee` view prints a quote computed from it.

**IG-Q53 — a read's reply — RULED 2026-10-19, as recommended.** Today each read wraps its result under its own key (`block_header`, `block_headers`, `headers`, `txs`, `chains`, `bans`, `connections`, `pool_stats`), and a by-hash read echoes each hash in a slot. *Recommended:* a `show` or view reply is the item itself; a `list` reply is an array of items in selector order, an unknown item `null` in its slot (RK-D23). The wrappers, the slots and `missed_tx` go.

**IG-Q54 — the wire kinds of time, quantities and fractions — RULED 2026-10-19, as recommended.** RW-Q10 takes units out of names (`_seconds`, `_time`, `_timestamp`, `_milli`, `_micro`, `_pct`, KiB/s), so each unit must live in its kind. The economics ratios (`burn_pct`, `release_multiplier`, `staker_emission_share_effective`) are fixed-point at `shekyl_fixed_point_scale` = 1,000,000 (`config/economics_params.json`; `SCALE` in `rust/shekyl-economics/src/params.rs`), whatever their names say. RW-Q4's shared-kind rule ("where a wire kind is also a grammar kind, the syntax is IG-6's") would make a duration or a byte count IG-6's `quantity`, a string such as `"3600s"` or `"100MiB"`, on the wire. *Recommended:* as RW-Q4 did for the amount, these are wire kinds of their own, integers whose unit the kind fixes: `time` (unix seconds), `duration` (seconds), byte counts (bytes), rates (units per second), and `milli` and `micro`, a ratio in thousandths and in millionths. No field needs a percent: the economics ratios and the sync span's relative speed are `micro`, so no `percent` kind is minted. A client does arithmetic on them, and a renderer applies the unit once. Each kind's unit is stated once in RW-Q4's registry, never in a name. The console keeps IG-6's `quantity` for what an operator types (`--duration 1h`).

**IG-Q55 — a transaction's body — RULED 2026-10-19, as recommended.** `/get_transactions` takes three switches that choose which of four always-present fields are filled (`decode_as_json`, `prune`, `split`). The wallet's block fetch reads the pruned form (`rust/shekyl-engine-core/src/engine/block_fetch.rs`), and only tests read the prunable part alone. *Recommended:* wherever a transaction's body is carried — `tx_show`, `tx_list`, and each transaction of `block_show` and `block_list` — the method takes the input `prune` (a switch, off by default), which makes each `body` the pruned form; a pruned entry then carries the txid's operands `prunable_hash`, `pqc_auth_hash` and `archival_size` — the skeleton, one shape at every horizon (`DRS_SB_BELOW_HORIZON.md` SB-Q2, which amended this row 2026-10-31). Without `prune`, a slot whose body this node discarded at the archival horizon is `archived` (`{id, shard}`), not a failure (§18). The wallet's scan reads blocks with pruned bodies (`block_fetch.rs`), so `block_list` needs the switch as much as `tx_list` does. `split` and the JSON rendering go (RW-Q4).

**IG-Q56 — the proof-of-work hash in a header — RULED 2026-10-19, as recommended.** `fill_pow_hash` has two restricted-listener policies: `get_block` and `get_block_header_by_height` blank the field silently, and the other three header methods refuse with `-19`. *Recommended:* one input, `pow` (a switch, off by default); a caller whose grant or resource bound does not cover it is refused with the RW-Q3 class that applies, never answered with a blank; the field is absent when not asked for.

**IG-Q57 — the pool's listing — RULED 2026-10-19, as recommended.** The Rust pool's listing is id, weight and fee, never the receive time, because receive times across many nodes' listings point at a transaction's origin (the review of #1102; `rust/shekyl-mempool/src/relay.rs`, `Pool::listing`). *Recommended:* `txpool_list`'s element is exactly that listing, the body comes from `tx_show`, and the C++ pool's other fields go; `txpool_stats` keeps the counts and weights, and its fields derived from receive times (`oldest`, `num_10m`, `histo`, `histo_98pc`) and the C++ pool's `num_failing` go. The same grounding reaches the transaction entry and the statistics:
- `double_spend_seen` and `num_double_spends` go. `shekyl-mempool` holds no per-entry conflict flag: its door admits one spender per key image (`view.rs`, CEN-M7's conflict map), and the `conflicted` list in `template.rs` is the template builder's, not an entry's.
- `relayed` becomes the pool's one bit, `public` (`DAEMON_RELAY_PRIVACY.md` acceptance criterion 2; `DRS_X_STORE_FLIP.md` DX-F6). For any caller below host-only it is constant, `true`, because an entry not yet public is host-only (RT-O9.3).
- The counts of entries not yet public, `num_not_relayed` on the statistics and `tx_pool_unbroadcast_count` on `daemon_status`, are host-only, and are named after the pool's bit: `private_count` and `txpool_private_count`.

---

## 21. Part D — checking a configuration, and the file an install ships

**RULED 2026-10-22 (Rick): IG-Q58…IG-Q65 as recommended, with the IG-Q64 package-header amendment (#1157).** The check (IG-Q58…IG-Q62) is built: `config-verify` in `rust/shekyl-daemon/src/run.rs` and the walk in `rust/shekyl-daemon/src/verify.rs`, the creatability and read halves in `shekyl-daemon-config` (`lock.rs`, `marker.rs`, `sections/mod.rs`, `probe.rs`), the pure owner checks in `shekyl-ffi` and `shekyl-archival-retention`; IG-F15 is closed by it. IG-Q63 lands with each wallet binary's file loader (FOLLOWUPS); IG-Q64's packaging is the release lane's. Posed 2026-10-19, amended 2026-10-20 on review of PR #1129. Ground: `dev` `c9eb84017`. Two needs from the alpha.10 fleet, both given to this lane by Rick on 2026-10-19:
- **Check without starting.** Deploy tooling must validate a configuration without starting the daemon. Starting it joins the network. Running it in an unprivileged network namespace does not help: the config file's permission walk sees the real root as uid 65534 and refuses. Today the fleet validates through a harness outside the tree (`shekyl-dev` `scripts/seed/check_config.rs`), which calls the daemon config crate's `read_cli`, `read_file`, `resolve` and `build`, skips the permission walk, and hardcodes a home directory.
- **A file on install.** An installation should leave a configuration file with comments, so an operator can see what can be set and change it without reading the source.

**The ground, at `c9eb84017`** (IG-F12…IG-F16 are the gaps this Part found):
- No check-only mode exists. The daemon's parse-and-exit path is reachable only through a C ABI for tests (`rust/shekyl-daemon/src/run.rs`, `snapshot_parse`); `--help` and `--version` print and exit before any file is read (`run.rs`, `main`).
- Startup's `load` (`run.rs`) runs, in order: the choosers (network, run mode), the config-file path, `file::open` with the permission walk (`rust/shekyl-daemon-config/src/file.rs`: writers outside root and the daemon's account refused along every directory to the root; a file holding a secret refused if others can read it), `read_file`, `resolve` and `sections::build`. A refusal exits 2 (IG-11).
- After `load`, startup creates things a check must not: the data directory's lock creates the directory (`lock.rs`, `Lock::take`), the network marker is written when the directory is fresh (`marker::check_or_write`, which takes the lock as its proof), and the log check creates the log directory and file (`sections/mod.rs`, `log_location_writable`). A client invocation (`DaemonConfig::is_client`: a non-empty console command) returns before any of these (`run.rs`).
- Later, still before any socket, start refuses an owner value the table accepted. `record_seed_epoch` (`rust/shekyl-ffi/src/pow_randomx_ffi.rs`) refuses a seed-epoch length or lag that is not a power of two in range, and `arm_settlement_schedule` (`rust/shekyl-ffi/src/archival_ffi/epoch_close.rs`) refuses a settlement pair outside its range. Each function then latches process-global state; the `Latched` arm is a second record in the same process. `network::record` (`rust/shekyl-daemon/src/network.rs`) installs the remnant preparation, the link limits and the bans; its error is a second install that disagrees, returned as exit 1, and it does not judge the value.
- Ports are bound late and never probed. The managed Tor pin check is `discover_and_verify` / `discover_and_verify_at`, called from `tor::begin`, which then spawns Tor and bootstraps. A pin failure warns and the boot continues. TB-2, ruled 2026-10-19, keeps that announcement: the daemon starts, and a failing pin does not execute the binary ([`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) posture table). There is no later refusal.
- The annotated example already exists, generated from the table: `docs::example_toml` (`rust/shekyl-daemon-config/src/docs.rs`) renders `docs/generated/shekyld.example.toml`, every line commented out; a test parses it uncommented, and `scripts/ci/check_daemon_option_docs.py` holds `docs/USER_GUIDE.md`'s copy to it (IG-9).
- No package installs a configuration file. The `.deb` is built with `--deb-no-default-config-files` and installs nothing under `/etc` (`.github/workflows/gitian.yml`); the Windows installer copies binaries and shortcuts only (`contrib/packaging/windows/shekyl.nsi`). A missing file at the default path means defaults (§5's `config-file` row); a missing file at a named path refuses.

- **IG-F12 — the shipped unit's account is created by nothing.** `contrib/packaging/linux/shekyld.service` runs as `User=shekyl`; `deb-after-install.sh` only reloads systemd, so on a fresh install the unit cannot start.
- **IG-F13 — no installer creates the daemon's directories.** `/etc/shekyl/` (R2) and, on Windows, `%ProgramData%\shekyl\` (IG-13, IG-Q36: "only the installer creates" it) are created by no package today.
- **IG-F14 — the user guide's Windows root — CLOSED in this part.** At the ground, `docs/USER_GUIDE.md` names `C:\ProgramData\shekyl\` for a first run, where a run-as-user daemon uses the per-account `LocalAppData\Shekyl` (IG-13, `paths.rs`). The guide now names that root; a service install uses `%ProgramData%\shekyl\`.
- **IG-F15 — the path checks create what they test — CLOSED in this part.** At the ground, `Lock::take` created the data directory and the lock file, `log_location_writable` the log directory and the file, and `marker::check_or_write` wrote the marker when the directory was fresh, so a check that called them changed the machine. Each now asks first and creates after: `Lock::creatable`, `log_location_creatable` and `marker::read` are the questions, asked by the check and by the effect.
- **IG-F16 — the shipped unit runs mainnet only.** `contrib/packaging/linux/shekyld.service`'s `ExecStart` passes no `--network` (IG-F10 recorded that default). The package runs mainnet and reads `/etc/shekyl/shekyld-mainnet.toml`; testnet, the network every alpha release runs, needs an operator's own unit. The unit does pass `--data-dir /var/lib/shekyl` and `--log-file /var/log/shekyl/shekyld.log`, equal to its `StateDirectory`, `LogsDirectory` and `ReadWritePaths`, with `ProtectHome=true`.

## 22. Questions for Part D

Each carries its recommendation, ruled as recommended on 2026-10-22 (Rick). The check is one pure walk of the refusals start already makes, and the effects stay on start. The implementation is the daemon-configuration lane's (IG-12's coupling); the packaging is the release lane's. The Windows `service` run mode stays reserved until RT-W14 (IG-Q36): this part does not pre-build its machine-root probe.

**IG-Q58 — the check's name — RULED 2026-10-22.** *Recommended:* `config-verify`, a command-line-only switch (IG-7, beside `help` and `version`), off by default, public. It walks `config` → `verify`: §11's `verify` already means "check a claim against its source", and here the claim is the configuration and the source is the table. When this is ruled, the same edit adds the parent `config` and extends that one sentence to cover it (Kind `config:verb`). `config-check` would widen §11's `check`, which means "check a proof".

**IG-Q59 — what it does — RULED 2026-10-22.** *Recommended:* one walk, called from `shekyl-daemon`'s `run` (`verify.rs`), in start's order. `config-verify` runs the walk and exits. Start runs the same walk and, on acceptance, performs the effects the walk withheld. `--help` and `--version` still win, before the file is read. Every other flag is read as start reads it.
- **The walk.** `load`, unchanged: the choosers, the file under the permission walk, `read_file`, `resolve` and `build`. A client invocation used to stop here; that mode was deleted with the console (2026-11-03), so every start continues. Then, in order, stopping at the first refusal and printing that stage's whole vector, as `refuse` does: whether the account can create the data directory and open the lock file; whether the host has a network id (exit 1, the same `tell` as start); the marker read; whether the account can create the log directory and open the log file; the pure owner checks; the Tor pin read. Each pure function lives beside the effect it was split from, and the effect's function calls the pure half, so the decision is not written twice. `shekyl-daemon-config` does not gain a dependency on the owner latches.
- **The splits (IG-F15).** `Lock::take` and `log_location_writable` gain a creatability half that does not create, open or lock; start calls it and then creates. `marker::check_or_write` gains a read that does not write: absent when the directory is missing, or when the directory holds no marker and no store; matched; or the refusal start already returns (`config.marker.network`, `config.marker.network-id`, `config.marker.missing`, `config.marker.unreadable`). Verify calls the read. Start takes the lock, calls the read, and writes only when the read is absent. The lock stays the proof of the write, and start rechecks under it. `record_seed_epoch` and `arm_settlement_schedule` gain a pure check of the value. The walk calls that check. The record functions call it and then latch. The walk does not observe `Latched`.
- **Left on start.** Creating the directory, the lock file, the marker and the log file. `network::record`. Logging. Signals, the runtime, binds, the store, and anything sent. `tor::begin`'s spawn and bootstrap. The pin half is `discover_and_verify` / `discover_and_verify_at`. The walk classifies that error as the supervisor's pin does (`BundleMissing`, `Unavailable`, `PinRefused`) and warns with that cause's posture sentence; a missed discovery names the paths it searched, and the held sentence is the posture's for a link that is not up, with clearnet read from the connector. TB-2 does not turn that warning into a refusal ([`TOR_BUNDLE_DISTRIBUTION.md`](TOR_BUNDLE_DISTRIBUTION.md); the posture table in [`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md)).
- **Outside the verdict.** A port in use, Tor's bootstrap, disk space, mandatory-access policy (SELinux, AppArmor), and a held data-directory lock. Those are contention or the running service. The check takes no lock, so it can run while the daemon is up. Exit 0 says nothing about them.

**IG-Q60 — the permission rules and the account — RULED 2026-10-22.** *Recommended:* the real rules, always. The walk refuses a configuration or a path that start would refuse. There is no switch to relax the permission walk: a relaxed walk would be a negation (IG-4) and a security downgrade. The check never touches the network, so tooling runs it on the host, as the account that will start. IG-13 derives every default path from that account. Exit 0 certifies the calling account in the calling environment, and the success line names the account. Run as uid 0, the check adds a warning that it certified root. The packaged unit runs the check as its own user, inside the unit's execution context (IG-Q64), which is how a unit check certifies the daemon's account rather than root's.

**IG-Q61 — what it prints — RULED 2026-10-22.** *Recommended:* the walk's refusals on standard error, each as IG-11's typed diagnostic: its stable code, the option, the source (`cli`, `file:path:line`, `default`, `machine`) and the English rendering, one per line. The same `refuse` prints them. The codes are the machine interface; tooling matches the codes. On acceptance, standard output carries the account checked and then `announce::effective_configuration`, the line start announces (IG-14), every value with its source and a secret shown only as set. Standard error then carries `announce::dev_levers`, `announce::posture`, and a Tor pin warning when the pin half produced one. The check does not start logging, so those lines are not also written to the log; start's own announcement still is.

**IG-Q62 — exit codes — RULED 2026-10-22.** *Recommended:* the codes `load` and start already return. `0`, the walk accepted. `2`, `refuse`: a configuration or path refusal, including an unreadable file (`config.file.unreadable`), a marker disagreement, a creatability refusal, and an owner value the pure check refuses. `1`, the host failure start already returns as 1: no network id for the chosen network. Warnings do not change the code. The check does not invent a second bucket for an I/O error the diagnostic already classifies.

**IG-Q63 — the wallet binaries — RULED 2026-10-22.** *Recommended:* the same switch in each binary that reads a configuration file, `shekyl-wallet-rpc` and `shekyl-cli` (IG-Q29), landing with that binary's file loader. One name in the tree (IG-2). The shared meaning is that binary's own `load` and the pure checks its own start runs, reported with IG-11. The daemon's lock, marker, log, owner latches and Tor pin are the daemon's start.

**IG-Q64 — the file an install ships — RULED 2026-10-22.** IG-12 holds: no binary writes its own configuration file. The installer may, as IG-13 already lets it create the machine-wide root. *Recommended:*
- **The file.** The body is `docs::example_toml` (`rust/shekyl-daemon-config/src/docs.rs`), every option line commented out, one render copied per file. It is not re-rendered with concrete per-network defaults, and no row is uncommented. A package header is prefixed: the file's name, the check command (the unit's `ExecStartPre`, below), that the unit sets `data-dir` and `log-file`, that a command-line flag wins per key, that runtime rows change with `option set` (IG-12), and that a secret is permitted in this shipped `root:shekyl` `0640` file and refused only when another account can read it, which is the sole-member rule (`secret_readable_only_by_permitted`, #1157). The header is the only text that is not the example. Generated and gated like the example. **The sole-member rule (Rick, 2026-10-22; #1157), in `file.rs` too:** a file that holds a secret and is readable through the daemon's group is refused unless the group's only member is the daemon's account; the members are the group's member list plus every account whose primary group is that group; a membership that cannot be read completely refuses, naming why. Checked at every start and by `config-verify`. Windows is unchanged: its allowlist names principals.
- **Where.** One file for each public network the `network` row names (`mainnet`, `testnet`, `stagenet`). `regtest` is a harness network and gets no packaged file. On Linux, `/etc/shekyl/shekyld-<network>.toml` (R2), owner `root`, group `shekyl`, mode `0640`: the owner is root, and neither the group nor other write bit is set, which is the permission walk (`file.rs`). On Windows with `service`, the same shape under `%ProgramData%\shekyl\` when RT-W14 lands. A run-as-user Windows daemon has no machine path: the installer puts the rendered example beside the binaries, and an absent file at the per-account default means defaults.
- **The unit.** A template `shekyld@<network>.service` replaces today's mainnet-only unit (IG-F16) and keeps its sandbox (`ProtectHome=true`, `NoNewPrivileges=true`). `ExecStart` passes `--network %i --data-dir /var/lib/shekyl/%i --log-file /var/log/shekyl/%i/shekyld.log`. `StateDirectory=shekyl/%i`, `LogsDirectory=shekyl/%i`, `ReadWritePaths` those two paths. systemd creates the directories in the execution context and sets `$STATE_DIRECTORY` for `ExecStartPre` (`systemd.exec`). `ExecStartPre` is the same arguments plus `--config-verify`, so the check and the start share one environment, and a refusal happens before `ExecStart` creates anything. The template drops today's `ExecStartPre=/bin/mkdir`, because `LogsDirectory` creates the log directory. An operator enables `shekyld@testnet` or `shekyld@mainnet`. A hand invocation is that same `ExecStart` line plus `--config-verify`, run as the unit's user. Before the first start the state directory does not exist and the account cannot create `/var/lib/shekyl`; the refusal describes that process. `StateDirectory` remains the one creator of the data and log directories. A `tmpfiles.d` entry for them would be a second owner of the same paths.
- **The recipe gate.** `scripts/ci/check_launch_recipes.py` stays on the unit. It already pairs `--data-dir` with `/var/lib/<StateDirectory>` and `--log-file` with a file under `/var/log/<LogsDirectory>`, for the shipped unit and the fleet units, and it checks the keys the fleet generators write. The template adds one assertion: every `shekyld` invocation in the unit is covered, `ExecStart` passes `--network %i` and the two paths, and `ExecStartPre` passes those plus `--config-verify`. The fleet units and generators keep the checks they have.
- **When.** The package carries the current renderings under `/usr/share/shekyl/`, updated every release, and copies one into place only if no file exists there. An upgrade never overwrites an operator's file. On Linux this is a post-install copy, not a dpkg conffile, so a release that adds rows does not prompt on every upgrade. Post-install does not run the check: the directories do not exist yet, and a refusal there would describe the wrong environment. A bad file fails the next start at `ExecStartPre`, which fails the service and not the package transaction.
- **The account and `/etc/shekyl/`.** Declared, not scripted. A `sysusers.d` entry, shipped in `contrib/packaging/linux/` and used by both the `.deb` and the RPM: the group `shekyl`, and the system user `shekyl` in that group, home `/nonexistent`, shell `nologin`. Home `/nonexistent` is IG-13's case with no default paths, so the unit's flags are the paths (IG-F12). A `tmpfiles.d` entry for `/etc/shekyl/` only, `root:shekyl`, mode `0750` (IG-F13). On Windows the installer creates the machine-wide root when `service` lands (RT-W14).
- **Purge.** Purge removes the per-network files the post-install copy placed, then removes `/etc/shekyl/` only if it is empty (`rmdir`, never a recursive delete), so an operator's own files there survive and the directory stays with them. The chain data and logs, which systemd created for the service, and the system account follow their own conventions: the data is the operator's to delete, and a system account is kept so that a reused uid never owns another account's files.

**IG-Q65 — the shipped file's comments — RULED 2026-10-22, folded into IG-Q64.** The comments are `example_toml`'s: the row's help, and its default where the row has a derived one. `dev-` rows, REJECTED rows and RESERVED rows are already absent, because the renderer keeps `Visibility::Public` file rows. The package header is the only added text. A second comment contract would be a second renderer.

---

## 23. Part E — the Tor status fields

**RULED 2026-10-24 (Rick):** IG-Q66, IG-Q69, IG-Q70 and IG-Q71 as recommended, with amendments; IG-Q67 and IG-Q68 as amended; IG-Q72 answered by IG-Q68's row. Ground: `dev` `1045d90f0`. Rick assigned the naming to the RPC wire round ([`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) `TSR-Q12`, ruled 2026-10-20; the names are the wire contract's, [`RPC_WIRE.md`](RPC_WIRE.md)). The supervisor's increment 3 exposes one typed read; this Part names its fields on the wire under RW-Q1, RW-Q10 and Part C's rules (IG-Q42's walk, IG-Q53's replies, IG-Q54's kinds). The hop-0 split named below is GS-C1 (PR #1164, in flight, not on the ground; #1161 closed with its base). On the ground, `own_tx` still returns `AddressHiding` whenever health is true. GS-C1 replaces that function. This Part names the wire of the replacement, so the two lanes describe one read.

**Two producers; Health and Status are levels of one node state** (`RPC_CHANNEL.md` §6.1, ruled 2026-10-24). Status includes everything Health carries: holding `status` holds `health`. A field is present only at the level the caller holds. Health is the level for outside readers only. A wallet is never an outsider: a same-user wallet (the GUI, `shekyl-cli`, any wallet that conducts transactions) holds every grant through the owner leg (RT-15; the GUI through its owning connection), and a wallet reaching a service-mode daemon over the channel holds `status` through the `wallet` preset.

- **The relay's hop-0 verdict**, under every `tor` setting, in two parts. `connected`: an outbound session hides this node's address now. That is Health's boolean (`TSR-Q4` as GS-C1 reads it): an address-hiding session exists now, with no pin state; transient, and it says nothing lasting about the node, so it stays off any reply that would let an outsider tie the endpoint to the onion (§8). `routable`: `connected`, and this epoch's origin pin is not exhausted. `routable` implies `connected`. `origination` is read from both parts, under `status`: `connecting` is `connected` false with Tor on, and `rebuilding` is `connected` true with `routable` false. Health can be true while `origination` is `rebuilding`. The link being usable is neither part.
- **The managed supervisor**, and only that posture. `tor::begin` returns nothing unless the setting is managed. An operator's Tor has no child and no §4.3 phase (§4.9). The `tor` object is that projection. It is null unless `posture.tor` is `managed`.
- **Status** also carries (`TSR-Q12`): the posture (the `tor` and `clearnet` settings); `OwnTx`, carrying the two held cases as `connecting` and `rebuilding`; whether the node is syncing, and over what; and, inside the managed object, the §4.3 state, the cause as one variant, how long, the respawn count, the bootstrap percent, the version flag, and the fixes that apply.
- **Typed values, never sentences, and polling** (`TSR-Q13`). Clients read Status on their normal refresh. One renderer in a shared crate turns the values into words for the daemon's log line, `shekyl-cli` and the GUI. GS-C2 puts these reply fields on `daemon_status`. GS-C1 publishes the two verdict parts. The supervisor's increment 3 owns the managed projection, including growing the version flag out of the cause slot so a flag and a cause can both stand.

**The GUI's grant** (`TSR-Q12`'s third ask) is answered by ruled text, not by a question here, but not by a leg that exists yet. `RPC_CHANNEL.md` RT-15 rules that a caller running as the daemon's own OS user, over the owner-only socket or pipe, is the owner, with every grant, Status included, and names the GUI running `shekyld` as its child as the case it covers. That socket or pipe is RT-W10's, which is not built. Until it is, the GUI's sidecar runs with `--rpc-admin-listen none` and a loopback `--rpc-view-listen` (`shekyl-gui-wallet` `src-tauri/src/daemon_manager.rs`; DC-Q8), and the `view` preset carries no Status, so no leg carries Status to the GUI today. The GUI sync lane's GS-Q1, on launching the sidecar with an owning connection, concerns that gap. After RT-W10, a GUI pointed at a service-mode daemon reaches it over the channel and holds Status through the `wallet` preset (`RPC_CHANNEL.md` §6.1, ruled 2026-10-24).

**The grant boundary** (ruled 2026-10-24). RT-O9.3's host-only rule covers data about other people's transactions: stem tallies and unrelayed pool entries. `origination` describes the node's own sends, names no transaction, and sits in `status`.

**The names, as ruled** (§24 records each ruling):

| Field (holder) | Grant | Kind and values | From |
|---|---|---|---|
| `hiding` (`daemon_status`) | health | switch: an address-hiding session exists now, with no pin state (the class part). `origination` `address-hiding` implies it, because `routable` implies `connected`. It stays true while `origination` is `rebuilding`. Clients decide sends from `origination`, never from `hiding` (IG-Q67) | GS-C1 |
| `posture` (`daemon_status`) | status | object: `tor` (one-of `managed`, `operator`, `off`) and `clearnet` (one-of `on`, `off`), the settings' own names and keywords (§5) | `TSR-Q12` |
| `origination` (`daemon_status`) | status | one-of `address-hiding`, `connecting`, `rebuilding`, `clearnet-only`, `offline`, from the relay's two verdict parts. `address-hiding` is `routable`; `connecting` is Tor on with no address-hiding session (`connected` false); `rebuilding` is a live session with the epoch's origin pin exhausted (`connected` true, `routable` false). The renderer leads with `tor.cause` when one stands (IG-Q68) | `OwnTx` |
| `sync_connector` (`daemon_status`) | status | a list of one-of `clearnet`, `tor`: the connectors the node syncs over now; `[]` when it syncs over none | `TSR-Q12` |
| `tor` (`daemon_status`) | status | the managed supervisor's projection, below. Null unless `posture.tor` is `managed` | §4.9 |
| `tor.state` | status | one-of `restarting`, `waiting`, `bootstrapping`, `usable`, `impaired`. `waiting` is Restarting (held). `impaired` is §4.3's Degraded. The chain field `degraded` keeps that word | §4.3 |
| `tor.facet` | status | `outbound`, `inbound`, or null. The facet down. Null unless `state` is `impaired` and the cause names a facet. `descriptor-limit` is `impaired` and the value is null (RK-D23) | §4.3, §5 |
| `tor.cause` | status | null, or one object with one key, the variant below. The value is that variant's payload. A variant with no payload has `null`. No second object carries detail | §5 |
| `tor.age` | status | duration (IG-Q54, whole seconds) of awake time: how long `state` has stood. No reading of the node's wall clock is carried: it is wrong exactly when the cause is `clock-skew` (IG-Q93, on #1344; IG-Q96) | `TSR-Q12` |
| `tor.respawn_count` | status | integer: respawns since the daemon started | `TSR-Q12` |
| `tor.progress` | status | an integer 0 through 100 inclusive, or null. The last bootstrap percent while `state` is `bootstrapping`; 0 before the first sample. Null in every other state, because 0 is a sample (RK-D23) | §4.2 |
| `tor.flagged` | status | switch: the consensus does not recommend this Tor. Independent of `state` and of `cause`, so it stands while `state` is `usable` | §5 |
| `tor.fix` | status | a list of one-of `restore-managed`, `operator`, `clearnet-on`, `clearnet-only`. Empty unless `cause` is an install variant. `clearnet-on` is offered only when the clearnet setting is off | `ManagedTorFix` |

**Cause variants.** One key, so a clock skew cannot carry a path. §5's "Rendered from the cause: none" rows are not variants. The value is the payload.

| Key | Payload | Shown as | Fixes |
|---|---|---|---|
| `outbound-blocked` | null | `impaired`, facet `outbound` | none |
| `directory-unreachable` | null | `impaired`, facet `outbound` | none |
| `clock-skew` | a signed integer, seconds (IG-6, the row allows the sign) | `impaired`, facet `outbound` | none |
| `onion-unreachable` | null | `impaired`, facet `inbound` | none |
| `descriptor-limit` | a non-negative integer, how many Tor reported open. The supervisor reports that count and not a second limit | `impaired`, facet null | none |
| `exited` | an integer exit code, or null when the reap reported none (the process ended, or the control connection ended) | `restarting` | none |
| `unanswered` | null. A control reply missed its bound | `restarting` | none |
| `launch-failed` | null. A spawn that passed the pin did not come up | `restarting` | none |
| `install-defect` | a path (IG-6): the file the pin rejected. The binary was not executed. The pin error carries that path and `PinRefused` drops it; this value is the path | `waiting` | the install list |
| `missing` | null. Discovery found no bundle. The segment `not` is refused (IG-4), so this is not `not-installed` | `waiting` | the install list |
| `unavailable` | null. This release has no managed Tor for this platform | `waiting` | the install list |
| `unusable` | `unwritable`, `exhausted`, or null. `unwritable` is a directory the account cannot write. `exhausted` is no space left. Null is any other failure, which is the whole variant today: `DirectoryUnusable` carries no kind. The path is `data-dir`, already named under the `config` grant. The subject `data` keeps its meaning, and `full` keeps "the whole address" | `waiting` | none |

Directory wait is `state` `bootstrapping`, `cause` null, `progress` the last sample. A clock jump leaves the cause alone. It moves the shown state to `bootstrapping`, and `age` restarts with that state, only when the shown state changes: a live link that was `usable` and is not impaired. A jump during `bootstrapping`, during a standing impairment, or while the process is down leaves `state` and `cause` as they were, and `age` runs on. Today's `shown` reports an impairment before the resumed link for `outbound-blocked`, `directory-unreachable`, `clock-skew`, and `descriptor-limit`. `onion-unreachable` is the same projection once that cause exists: a jump does not clear it. No `resumed` keyword and no `directory-waiting` keyword. `exited`, `unanswered` and `launch-failed` are §5's one "exited or wedged" row, split by the sentence the renderer speaks (`TSR-Q13`): one keyword cannot carry three sentences. `onion-unreachable` is §5's row; the supervisor's descriptor-failed path does not set a cause yet, and the variant is the contract it grows to.

The install list is `restore-managed`, `operator`, `clearnet-only`, and `clearnet-on` only when clearnet is off. A crash, a bad data directory, an unanswered control connection and an impaired facet offer nothing. `clearnet-only` stays the operator's own choice of `tor = off` with `clearnet = on` (`TSR-Q10`, `TSR-Q11`), whether it appears as `origination` or as a fix.

**Terms these names need** are §19's rows, one home each (IG-15): `hiding`, `posture` and `origination` under `daemon`; `facet`, `respawn`, `progress`, `flagged` and `fix` under `tor`. Each walks under IG-Q42. `tor` and `clearnet` are subjects, used by reference under `posture` and, for `tor`, as the managed object. No term below ends a command, so no Kind cell is set. Value keywords are closed sets on a row. They are not paths, so a keyword adds no edge: `address-hiding` does not parent `hiding` under `address`.

Existing terms that gain a parent. The §19 row gains the parent and states the meaning per parent, as `height` does:

- `state` gains `tor` on its §19 defining row. Under `connection` it is the connection's state. Under `tor` it is the §4.3 projection.
- `cause` gains `tor` on its §19 defining row. Under `tx` it is why a rejected transaction was refused. Under `tor` it is the supervisor's cause variant, one object or null.
- `connector` gains `sync` on its §19 defining row, keeping "one-of `clearnet`, `tor`".
- `count` gains `respawn` on its §19 gains row. `count` is defined in §11, so a second defining row would be a duplicate. The meaning stays "how many".

These fields join the generated schema with the Tor supervisor lane's status PRs, and the walk then takes `hiding`, `posture`, `origination`, `sync_connector` and `tor` under `daemon`. `sync_connector` and `tor` are references: `sync` then `connector`, and the subject `tor`. Under `posture`, `tor` and `clearnet` are references. The managed object's fields walk under the subject `tor`: `state`, `facet`, `cause`, `age`, `respawn_count`, `progress`, `flagged` and `fix`.

`offline` is already the term "P2P is off" (IG-Q3). The origination keyword uses it with that meaning: Tor off and clearnet off.

Value keywords: `restarting`, `waiting`, `bootstrapping`, `usable`, `impaired` (state); `outbound`, `inbound` (facet; both already terms); the cause keys in the table above; `unwritable`, `exhausted` (`unusable`'s payload); `address-hiding`, `connecting`, `rebuilding`, `clearnet-only`, `offline` (origination); `restore-managed`, `clearnet-on` (fix). `operator` and `clearnet-only` are the settings those fixes name, with the same meaning as in `posture` and `origination`.

## 24. Questions for Part E

Each is ruled (Rick, 2026-10-24); an amendment is stated in the question's own lines. The managed projection is the supervisor's increment 3 (`TOR_SUPERVISOR.md` §12). The two verdict parts are GS-C1 (PR #1164). GS-C2 puts the reply fields on `daemon_status`. The `TSR-Q12` correction in the supervisor document is GS-C4; this Part does not edit that document, which #1164 already has open.

**IG-Q66 — where the fields live — RULED 2026-10-24, as recommended, with the levels amendment.** *Recommended:* in `daemon_status` (today's `get_info`). `hiding` is in the Health part. Everything else in the table is in the Status part. The grant filter withholds a level the caller does not hold (absent, never zeroed; RK-D23). Health and Status are levels of detail of one node state: Status includes everything Health carries, so holding `status` holds `health`, and a health caller does not see the pin. Clients already poll `daemon_status` on their normal refresh (`TSR-Q13`). Posture, origination and the sync connectors are not Tor's alone, so a `tor_status` method would split one node's state across two reads. The alternative was a `tor_status` view under the `status` grant, with `hiding` staying in `daemon_status`. *Amendment (Rick, 2026-10-24):* levels, not separate entities; `RPC_CHANNEL.md` §6.1 states the level in its grant table, and the `wallet` preset carries `status`.

**IG-Q67 — Health's boolean — RULED 2026-10-24, as amended.** *Ruling:* `hiding`, beside `peered`, is Health's level: an address-hiding session exists now, with no pin state. Clients decide sends from Status (`origination`), never from Health. *Recommended, as amended:* it is the class part. `origination` `address-hiding` implies `hiding`, because the pin part implies the class part. The converse is false. `hiding` stays true while `origination` is `rebuilding`, so a `view` caller cannot watch the pin move (`RPC_CHANNEL.md` §6.1). It says nothing about anonymity, and it is not the signal the send flow reads. The alternatives were `masked`, a longer `address_hiding` (that path would parent `hiding` under `address`, which is a Shekyl address), and defining `hiding` as true exactly when `origination` is `address-hiding`, which is the ground's `own_tx` and the function GS-C1 replaces.

**IG-Q68 — the posture and origination — RULED 2026-10-24, as amended.** *Ruling:* `origination` is one-of `address-hiding`, `connecting`, `rebuilding`, `clearnet-only`, `offline`, from the relay's two verdict parts: `connecting` is Tor on with no address-hiding session (`connected` false); `rebuilding` is a live session with the epoch's origin pin exhausted (`connected` true, `routable` false). There is no `hold` field; IG-Q72 is answered by this row. The renderer leads with `tor.cause` when one stands. *Recommended:* `posture` carries the two settings under their own option names and keywords (§5's `tor` and `clearnet` rows), so a value shown is valid input to the file. `origination` carries `OwnTx` as the ruling above. `address-hiding` is the pin part. Where Tor is `managed` or `operator` and the pin part is false, the value is `connecting` (`connected` false: no session hides the address now) or `rebuilding` (`connected` true: the pin is exhausted while a session is live). The value is read from the relay's verdict alone; the supervisor's state is not a second source for it. `clearnet-only` means one thing, here and as a fix: the operator's own choice of `tor = off` with `clearnet = on` (`TSR-Q10`, `TSR-Q11`). A node whose managed Tor is down reports `connecting` once the relay holds no address-hiding session (until then the verdict, and so `origination`, may still read `address-hiding` or `rebuilding`), and never `clearnet-only`, even while it syncs over clearnet. The send flow reads `origination` before broadcasting (`TSR-Q12`).

**IG-Q69 — the Tor object — RULED 2026-10-24, as recommended, amended:** the supervisor document and the shared renderer use the wire's words, `impaired` (was Degraded) and `waiting` (was Restarting (held)), so each state has one name. *Recommended:* one nested object, `tor`, null unless `posture.tor` is `managed`, with `state`, `facet`, `cause`, `age`, `respawn_count`, `progress`, `flagged` and `fix`. There is no `detail` object. Restarting (held) is the keyword `waiting`. §4.3's Degraded is the keyword `impaired`, because `degraded` is already the chain-following field on this reply (§19). `facet` is `outbound` or `inbound` when an impaired cause names a facet, and null for `descriptor-limit`. `cause` is null when the supervisor has no variant: the opening `restarting`, `usable`, and `bootstrapping` with no cause. A resume does not clear a variant. Where the cause was null and the link was `usable`, the state becomes `bootstrapping` and `age` dates it. A standing impairment stays `impaired` with its cause and its `age` (RK-D23: null is no answer, not a withheld field). `flagged` may be true in any state. `progress` is the bootstrap percent while `state` is `bootstrapping`, and null in every other state. *Amended 2026-11-10 (IG-Q93):* `since`, a time, is `age`, a duration from the monotonic clock; where this row dates a state, it restarts the age.

**IG-Q70 — the cause is one variant — RULED 2026-10-24, as recommended.** *Recommended:* `tor.cause` is null, or one object with one key, as the table in §23. The key is named by what the operator sees (rule 81). The value is that variant's payload, and a variant with no payload has null, so the illegal combinations a detail bag allowed cannot be written. `flagged` is the §5 announcement and is a switch, not a cause: the supervisor's single cause slot that stores the version flag is the slot increment 3 grows out of, because a usable node can be flagged and skewed at once and one slot cannot hold both. The open-file payload is the count Tor reported. The data-directory payload is `unwritable` or `exhausted`, not a field named `data` and not the keyword `full`. Fixes are the install variants only.

**IG-Q71 — syncing over what — RULED 2026-10-24, as recommended.** *Recommended:* `sync_connector`, a list of the connectors the node syncs over now. Health's `syncing` already says whether it syncs; the list says over what, and `[]` with `syncing` true is not a state the node can be in. The supervisor's current pair, configured clearnet and "the link is usable", is the stand-in a chain-sync feed replaces. This field is that feed.

**IG-Q72 — a hold while the projection is not the reason — RULED 2026-10-24: answered by IG-Q68's row.** The relay holds the node's own transactions in two cases that are not a Tor fault, not a respawn and not a fix. GS-C1 publishes both parts. `tor.cause` stays the supervisor's variant.
- `connecting`: no outbound session hides this node's address yet (`connected` false). After Tor boots, before the first onion peer completes its handshake, and also an operator Tor, which has no phase, until a session exists;
- `rebuilding`: the epoch's origin pin is exhausted while a session is live (`connected` true, `routable` false). Health stays true.

*Ruling:* there is no `hold` field. The two cases are `origination`'s `connecting` and `rebuilding` (IG-Q68), and the renderer leads with `tor.cause` when one stands. The keywords name what the operator sees (rule 81); `tor.since` dates the state, and an epoch's end would date the pin.

---

## 25. Part F — the wire at the rename

**RULED 2026-11-10 (Rick): IG-Q73…IG-Q93 as recommended.** Ground: `dev` `cf561f79d`, `CORE_RPC_VERSION` 3.70. Part C's census was last re-taken at 3.64, and the wire has moved six minors since. This Part re-takes the census at the ground, names what the rename PR (`RPC_WIRE.md` RW-Q8) finds unnamed, and rules each name as a question in §26. It adds no rule and registers no family: the questions continue `IG-Q`, the findings `IG-F`. Citations are `file:line` at the ground; `T/` is `rust/shekyl-rpc-types/src/` and `D/` is `rust/shekyl-daemon-rpc/src/`.

**The served surface at the ground.** `T/methods.rs:162-244` lists 51 methods under 64 served names: 32 JSON-RPC methods with 9 aliases, and 19 REST paths with 4 aliases, beside the `/json_rpc` endpoint's own row. Every row is served natively; the C++ table is gone (`D/handlers/json_rpc.rs:95-104`). Under Part C and this Part they become 42 methods on one path, with no alias.

### 25.1 Findings: ruled names the code never adopted

Each is implemented by the rename PR as ruled. None is a question.

- **IG-F17 — `option_set` takes a list.** Its request is `options`, a list of `{name, value}` (`T/options.rs:227-239`). IG-Q42 and §18 rule `value`, a map from option name to value, in which a name cannot appear twice.
- **IG-F18 — `option_show` takes `names`, and both replies wrap.** The request key is `names` (`T/options.rs:243-247`); §17 rules `name`. Both replies wrap their rows under `options` (`T/options.rs:251-254`), which IG-Q53 unwraps, and a secret row carries `set` (`T/options.rs:156-164`), which IG-Q42 rules `assigned`.
- **IG-F19 — a connection's byte counts.** `get_connections` carries `recv_count` and `send_count` (`T/p2p.rs:230`, `:233`); §18 rules `download` and `upload`.
- **IG-F20 — a diagnostic's parameters are positional pairs.** `Diagnostic.params` and `Refusal.params` are lists of pairs (`T/errors.rs:139`, `T/options.rs:220`); §18 rules `parameter`, a map.
- **IG-F21 — Part E's fields are ruled and not served.** `get_info`'s wire form (`T/info.rs:535-614`) carries none of `hiding`, `posture`, `origination`, `sync_connector` or `tor`. Their names stand as ruled (§23), with `tor.age` for `tor.since` (IG-Q93). The Tor supervisor lane's PR puts them on `get_info` first, in §23's shape and under §23's names; the rename merges it and moves them to `daemon_status` unchanged.
- **IG-F22 — the writer's halt is minted and no reply carries it.** `ConnectState` and `StoreInvariantRow` (`T/chain.rs:642`, `:656-668`) are `DAEMON_REDB_STORE.md` §3.6.2's halt on the tip: a halted writer's tip is stale, and a wallet that does not know refreshes against a chain that has moved on without it. The design deferred the field until the Rust store served `get_info`, which the flip did. The store mints the halt (`rust/shekyl-chain-store/src/store/mod.rs:521-528`), and no reply carries it. It is a missing function, built in the rename PR; its name is IG-Q92's.
- **IG-F23 — §17 and §5 rows the flip made stale.** `start_mining` takes `threads` only (`T/mining.rs:126-129`); `generateblocks` takes `count` only (`T/mining.rs:245-247`); `get_block_template` takes no parameters (`T/mining.rs:28`); §5's `dev-rpc` row still listed `inject_archival_serve_credit`, deleted with the C++ chain (`DRS_X_STORE_FLIP.md` DX-Q3). §17, §18.1 and §5 are corrected in the commit that poses this Part. §18's `address`, `extra` and `extra_size` parameter rows for `block_template`, and its `address` and `nonce` rows for `dev_block_generate`, name parameters that no longer exist.
- **IG-F24 — `pow` on a header read is served to a bounded caller.** IG-Q56 refuses a caller "whose grant or resource bound does not cover it". Since 3.67 the bound covers it: the header's hash is the one recorded at validation (`D/store_facts.rs:325`), it spends nothing from the hash budget (`D/hash_budget.rs:31`), and a bounded read stays inside the header cap (`RPC_CHANNEL.md` §6.3). §17 now says so. No refusal code is needed for it.
- **IG-F25 — the shard reply's closing height.** The reply key is `close_height` (`T/archival.rs:69`), where §18 reads today's name as `closing_height`. The ruled name, `closing_height`, is unchanged.

### 25.2 The census delta since 3.64

Every key added, changed or removed between Part C's last re-take and the ground. A row whose name is settled by an earlier ruling says so; the others are ruled in §26.

| Minor | Method today | Key at the ground | Source | Under this Part |
|---|---|---|---|---|
| 3.61 | `get_transactions` | `unavailable_tx` (a list of ids) | `T/transactions.rs:374-375` | folds into the slot (IG-Q73) |
| 3.61 | `get_transactions` | `missed_tx` | `T/transactions.rs:358-359` | folds into the slot (IG-Q73) |
| 3.64 | `get_transactions` | `archived`, a side list of `{tx_hash, shard}` | `T/transactions.rs:363-364`, `:330-334` | folds into the slot (IG-Q73) |
| 3.64 | `get_blocks_by_height.bin` | a per-slot `Full`, `Skeleton` or `Archived` | `T/bin_commands.rs:251-259` | the slot (IG-Q73) |
| 3.61 | `get_info` | `pool_retired`, written only when true | `T/info.rs:576-577` | IG-Q74 |
| 3.61 | `get_info` | `tx_pool_size`, `null` when the pool is retired | `T/info.rs:578` | `txpool_count`, as ruled; IG-Q74 |
| 3.61 | `get_info` | `tx_pool_unbroadcast_count`, `null` when retired | `T/info.rs:606-611` | `txpool_private_count`, as ruled; IG-Q74 |
| 3.63 | `mining_status` | `pool_retired` | `T/mining.rs:220` | IG-Q74 |
| 3.63 | `mining_status` | `height`, the posted job's | `T/mining.rs:217` | IG-Q77 |
| 3.63 | `mining_status` | `no_template`, a diagnostic or `null` | `T/mining.rs:222` | IG-Q77 |
| 3.63 | `mining_status` | `threads_count` | `T/mining.rs:204` | IG-Q77 |
| 3.65 | `mining_status` | `speed`, `{count, window}` | `T/mining.rs:203`, `:150-155` | IG-Q77 |
| 3.63 | `get_block_template` | `nonce_offset` | `T/mining.rs:47` | IG-Q78 |
| 3.63 | `/submit_transaction` | the cause `consensus_rule`, and `row` beside it | `T/lib.rs:303`, `:247-248` | IG-Q76 |
| 3.63 | `/submit_transaction` | the cause `join_market_unsupported` | gone from `T/lib.rs:264-312` | leaves the set; no name |
| 3.69 | `/submit_transaction` | `relay` on `already_in_pool`: `held`, `held_overdue`, `published`, `untracked` | `T/lib.rs:209-213`, `:170-179` | IG-Q75 |
| 3.66–3.67 | the four capped reads, `calc_pow` | the diagnostic `rpc.bound.exceeded` with `method`, `bound`, `asked`; `rpc.bound.budget` | `D/methods.rs:166-185`; `D/hash_budget.rs:141-143` | IG-Q79 |
| 3.68 | `sync_info` | `height`, `target_height` (counts), `state`, `stalled` | `T/p2p.rs:319-334` | IG-Q80 |
| 3.68 | `sync_info` | `peers[]`: `connection_id`, `address`, `claimed_height`, `mode`, `header_request`, `body_requests`, `rate` | `T/p2p.rs:294-312` | IG-Q80 |
| 3.68 | `sync_info` | the timing objects: `age_ms`, `due_in_ms`; a body span's `start_height`, `count`, `planned_bytes` | `T/p2p.rs:267-288` | IG-Q80 |
| 3.68 | `sync_info` | `spans`, `overview` | gone | §18's span rows and the terms `span` and `pace` go with them, but for `span` as IG-Q80 keeps it |
| 3.68 | `get_connections` | `height` (the claim's count, or `null`), `state` (the session's mode, or `null`) | `T/p2p.rs:250`, `:237` | IG-Q81 |
| 3.59 | `get_connections`, `sync_info` | `support_flags` | gone | no name |
| 3.56 | `get_connections`, `sync_info`, `/get_peer_list` | the offline reply, `{"status": "offline"}` alone | `T/p2p.rs:345-350` | IG-Q85 |
| 3.70 | `get_info` | `connectors[]`: `connector`, `incoming_sockets`, `outgoing_sockets`, `white_peerlist_size`, `gray_peerlist_size` | `T/info.rs:396-407`, `:601-602` | IG-Q82 |
| 3.70 | `get_info` | the six flat socket and list-size keys | gone | §18's `clearnet_inbound_count`, `clearnet_outbound_count`, `tor_inbound_count`, `tor_outbound_count`, `peer_white_count` and `peer_gray_count` rows on `daemon_status` go |
| `8494ffe88` | `/get_stem_tallies` | the connector value `unnamed`; `peer`, 32 hexadecimal characters | `T/p2p.rs:468-475`, `:494-495` | IG-Q83 |
| — | `get_archival_emission_claim_source` | no hash of the gather's tip | `T/archival_reads.rs:85-110` | IG-Q84 |
| 3.60 | `get_archival_emission_claim_source` | `is_support_complete_tree` | `T/archival_reads.rs:37` | `complete_tree`, as ruled |

Keywords whose spelling IG-Q86 rules: the sync modes `past_cap` and `evidence_candidate` and the sync state `no_view` (`T/p2p.rs:147-193`); the relay state `held_overdue`; the verdicts and causes of `/submit_transaction` (`T/lib.rs:193-312`); and the dotted diagnostic codes (`D/mining_methods.rs:39-92`, `D/ban_methods.rs:24-26`, `D/authority.rs:45-47`, `T/methods.rs:106`, `T/endpoint.rs:31`).

### 25.3 Names the next slice builds

RT-W10 step 4 builds enrolment over the channel. Its method names are ruled here (IG-Q87, IG-Q88) so that step 4's submission contract and route-to-grant table are written once. The rows join §13 marked "built by RT-W10 step 4". They do not join the method table in the rename PR, whose gate requires every row to be served.

One question is step 4's own and is not ruled here. Only the host is told `held` or `overdue` for a transaction it submitted (IG-Q75). A wallet reaching a service-mode daemon over the channel is a bounded key, so it loses that read for its own transactions. Telling the submitting fingerprint would let a stem successor that shares the fingerprint, as strangers behind a relaying site do, resubmit bytes this node sent it and learn that this node originated them. Any disclosure is therefore a ceiling bit given only to a single-owner device, never implied by `wallet`, and it is posed with step 4's grant work.

## 26. Questions for Part F

Each is ruled (Rick, 2026-11-10), as recommended. Each states the problem, then the question, then the recommendation that was ruled. A question that amends a ruled row names it, and the row carries the amendment.

**IG-Q73 — a list reply's slot — RULED 2026-11-10, as recommended; amends IG-Q53.** IG-Q53 puts `null` in a list reply's slot for "an unknown item". Under RK-D23, `null` means *no answer*. The daemon now tells three cases apart: asked and not found (`missed_tx`); could not ask, because the pool is retired (`unavailable_tx`, 3.61); and a body discarded with its shard at the archival horizon (`archived`, 3.64, SB-Q2). The wallet already treats them differently: `TransactionsUnavailable` is never "not found" (`rust/shekyl-engine-core/src/engine/block_fetch.rs`, `proofs_chain_facts.rs`). One `null` cannot carry three cases. *Question:* what is in a slot that does not hold the item? *Recommended:* a `list` reply's slot is exactly one of:
- the item itself;
- `{"missing": null}`: the node was asked and holds no such item (§23's `missing`: looked, and none is there);
- `{"archived": {"id": h, "shard": n}}`: the body was discarded with its shard, and the archive serves it (§19's `archived`);
- `null`: that item's source could not be asked (RK-D23).

A state other than the item is a one-key object naming the state, with its payload as the value, or `null` when it has none. That is IG-Q70's rule for `tor.cause`, applied once across the wire. Four consequences:
- A read whose only source cannot answer refuses whole (RW-Q3). A slot is `null` only in a read that spans sources which fail separately; today that is `tx_list`, over the chain and the pool.
- An unrelayed pool entry is `{"missing": null}` to every caller without the host's view (RT-O9.3), so a list read never reveals that one exists.
- `missed_tx`, `unavailable_tx` and the `archived` side list fold into the slot. No side list remains.
- `tx_show`, which has no slot, refuses a missing id (`RefusedByMethod`, `tx.missing`) and an unaskable one (`NotReady`, `txpool.retired`), and answers an archived one as `{"archived": {…}}`, the reply itself.

`missing` joins §19 beside `archived`, a slot state under `tx`: "the node was asked and holds no such item". It is §23's keyword, with the meaning it has there.

**IG-Q74 — a retired pool — RULED 2026-11-10, as recommended.** A node whose pool file faults retires the pool until it restarts (`rust/shekyl-node/src/facts.rs`). `get_info` says so with `pool_retired`, written only when true (`T/info.rs:576-577`), and `mining_status` with `pool_retired`, always written (`T/mining.rs:220`). `pool` is not a term: the subject is `txpool`. A key written only when true is absent for a reason other than a grant, which RK-D23 refuses. *Question:* what is the field, and where? *Recommended:* `txpool_retired`, a switch, always present, on `daemon_status` in the Status part and on `mine_status`. Everyone who can submit holds `status` (the `wallet` preset is `view`, `submit` and `status`), so Health would add only outside readers, who have no use for it. It walks by reference: the subject `txpool`, then a new term `retired` under it, "the pool's file faulted and the node holds no pool until it restarts". When it is true, `txpool_count` and the host's `txpool_private_count` are `null` (no answer), as today.

**IG-Q75 — the relay state on `already_in_pool` — RULED 2026-11-10, as recommended.** Since 3.69 the verdict `already_in_pool` carries a required `relay`: `held`, `held_overdue`, `published` or `untracked` (`T/lib.rs:170-179`, `:209-213`). `relay` under `tx` is the verb (§3: `tx relay`), so a field of that name states a kind it does not have. The glossary's word for an entry the relay has made public is `public` (§19), and `held` is §11's view of a wallet's shards. *Question:* what are the field and its states? *Recommended:* the field is `publication`, a new term under `tx`: "where the caller's own transaction stands with the relay". Its states are one-of `held` (unpublished, inside the daemon's publication budget), `overdue` (unpublished at or past that budget), `public` (the relay has made it public; §19's `public`) and `untracked` (pool-resident, with no origin row). `overdue` is judged on the daemon's clock when the state is read; the wallet converts it to neither blocks nor a duration. A caller without the owner's view is told `public` only, and only once the transaction is public (RT-O9.3). Keywords are not paths, so `held` here adds no edge to §11's `held`.

**IG-Q76 — the consensus row on a rejection — RULED 2026-11-10, as recommended.** Since 3.63 a rejection may carry the cause `consensus_rule`, with the refusing row's id (`"CEN-J15"`) in a sibling field `row` that is absent for every other cause (`T/lib.rs:240-249`, `:294-303`). A field absent for a reason other than a grant is what RK-D23 refuses, and a `null` there would say "no answer" where the truth is "this cause has no row". `row` is not a term. *Question:* how does a cause carry its payload? *Recommended:* IG-Q70's form. `cause` is one object with one key, the cause; its value is that cause's payload, or `null` when it has none: `{"consensus-rule": "CEN-J15"}`, `{"fee-too-low": null}`. No sibling field exists, so a row cannot ride a cause that has none. The skew rule is unchanged: a key this build does not know reads as `unrecognized` (`DAEMON_SUBMIT_VERDICT.md` §2.3), and a new rejection is still an added key (F38). The alternative keeps `cause` a keyword and adds a field `rule`, `null` for every cause but one.

**IG-Q77 — `mine_status` — RULED 2026-11-10, as recommended; amends §18's Miner row.** Three keys arrived with the Rust miner, and two ruled rows need their kind stated.
- `speed` is `{count, window}` since 3.65 (`T/mining.rs:150-155`): hashes counted over a window of complete seconds. §19 already walks `mine` → `speed` → `count` and `window`. *Recommended:* `speed` stays an object; `count` is an integer and `window` a `duration` (IG-Q54), zero before the first second completes. No rate is carried: a quotient read `0` for a miner below one hash a second.
- `threads_count` (`T/mining.rs:204`) names its kind. §18 rules `threads`. *Recommended:* `threads`, an integer: the count the miner runs with, never the keyword `auto`, which is an input.
- `height` (`T/mining.rs:217`), `block_reward` and the difficulty triple describe the posted job and read `0` when none is posted. *Recommended:* the job's three fields — `height` (the ordinal the block connects at), `reward` and `difficulty` — are `null` when no job is posted (RK-D23). `height` gains the parent `mine`.
- `no_template` (`T/mining.rs:222`) is a diagnostic saying why no job is posted, or `null`. `no` is refused as a term (IG-4). *Recommended:* `cause`, which gains the parent `mine`: "why no job is posted", a diagnostic (§19) or `null` when one is. `address` is `null` when `mine-address` is unset, as §18 rules.

**IG-Q78 — the template's nonce offset — RULED 2026-11-10, as recommended.** `get_block_template` carries `nonce_offset`: where the header's four nonce bytes sit, in both blobs (`T/mining.rs:47`). §18 has `reserved_offset` → `extra_offset` and no row for this one. *Question:* its name. *Recommended:* `nonce_offset`. `nonce` already has the parents `block` and `header`; it gains `template`, and `offset` gains the parent `nonce`: "where its bytes start".

**IG-Q79 — a refusal over a resource bound — RULED 2026-11-10, as recommended.** Since 3.66 a bounded caller over a bound is refused with class `OverResourceBound` (-32003). Every list cap shares one diagnostic, `rpc.bound.exceeded`, which names the method in a parameter (`D/methods.rs:166-185`); the hash budget's is `rpc.bound.budget` (`D/hash_budget.rs:141-143`). A client that must tell one bound from another reads a method name out of a parameter, and that name changes at the rename. *Question:* what does a client branch on? *Recommended:* the class, then one dotted code per bound, each with the parameters `bound` (the limit) and `asked`:

| Code | The bound | Value | Where |
|---|---|---|---|
| `bound.block` | blocks one `block_list` or one `block_header_list` by hash may name | 1,000 | `D/methods.rs:627`, `:963`; `D/read_methods.rs:490` |
| `bound.header` | headers one `block_header_list` range may span | 1,000 | `D/methods.rs:631`, `:1026` |
| `bound.tx` | ids one `tx_list` may name | 100 | `D/methods.rs:635`; `D/read_methods.rs:573` |
| `bound.key-image` | key images one `chain_spent` may name | 5,000 | `D/methods.rs:639`; `D/read_methods.rs:636` |
| `bound.pow-size` | the size of `pow`'s hashing bytes | `MAX_POW_BLOB_SIZE` | `D/read_methods.rs:191` |
| `bound.hash` | the shared hash budget, when it cannot pay one hash | one hash | `D/hash_budget.rs:141` |
| `bound.shard` | a bounded caller's shard fetch that would open a flight while another bounded caller's holds the one permit (IG-Q90) | one flight | after the ground, at `34255a8945`: the view desk's cache miss, `rust/shekyl-archival-fetch-sched/src/view.rs` (`ViewRefusal::Busy`); `D/shard_view.rs` |

The `pow` switch on a header read has no code (IG-F24), and a bounded `chain_coinbase_sum` waits for its one permit and is not refused. The method is never a parameter: the caller knows what it called.

**IG-Q80 — `sync_status` — RULED 2026-11-10, as recommended; replaces §18's Sync status row.** CS-5 replaced the reply (3.68, `T/p2p.rs:267-334`). §18's `peer` (a list of connections) and `span` rows describe a block queue that is deleted. Several of the new keys break a rule: `address` holds a network location, which §3 reserves for `endpoint`; `claimed_height` carries a count (RW-Q4, IG-Q45); `_ms` and `_bytes` are units (RW-Q10); and `header_request` and `body_requests` use `request`, §11's payment request. *Question:* the reply's names. *Recommended:*

| Today | Part F | Kind |
|---|---|---|
| `height` (a count) | `height` | integer, the tip's ordinal (IG-Q45) |
| `target_height` (a count, always present) | `target_height` | integer, the ordinal of the best verified chain's tip |
| `state` | `state` | one-of `unpeered`, `behind`, `following`, `synced` |
| `stalled` | `stalled` | switch: behind, with nothing moving toward the target |
| `peers` | `session` | a list, one element for each session chain sync holds; `[]` when none |
| — `connection_id` | `connection` | the connection's id, as `peer_connections` gives it |
| — `address` | `endpoint` | peer-endpoint |
| — `claimed_height` (a count) | `height` | integer, the ordinal of the tip the peer claims; `null` before it has claimed |
| — `mode` | `mode` | one-of `idle`, `reachable`, `slot`, `challenging`, `past-cap`, `evidence-candidate`, `evidence` |
| — `header_request` | `header` | the header read in flight to the session, `{age, due}`, or `null` when none is |
| — `body_requests` | `span` | a list of the body spans in flight; `[]` when none |
| — — `start_height`, `count` | `from`, `blocks` | the span's first height, and its length |
| — — `planned_bytes` | `size` | bytes: the response its deadline is planned for |
| — `age_ms` | `age` | duration: since it was sent |
| — `due_in_ms` | `due` | duration: until its response is late; `0` once it is |
| — `rate` | `download_speed` | bytes per second its last response arrived at; `null` until one has |

- `session` is a new term under `sync`: "a peer session chain sync holds". Its fields walk `sync` → `session`. `mode` and `due` are new terms; `stalled` is a new term under `sync`; `state` gains the parent `sync`; `connection`, `endpoint`, `height`, `header`, `span` and `download` gain the parent `session`; `age` and `due` sit under `header` and `span`. `header` under `session` is the read of headers in flight, which is §19's "with `show` and `list`, the read".
- `no_view` is `unpeered`: no session has completed a handshake, which is `daemon_status`'s `peered` false. `no` is refused as a segment (IG-4, as Part E refused `not-installed`).
- The timings are IG-Q54's `duration`, whole seconds: `age` rounds down and `due` rounds up, so `due` is `0` exactly when the response is late. The node's own test holds a deadline to a minute at most (`rust/shekyl-node/src/facts.rs:916`), and an operator reading a stall reads seconds. The alternative mints a second duration kind in milliseconds for these two fields alone.

**IG-Q81 — a connection's claim and mode — RULED 2026-11-10, as recommended; amends §18's Connection row.** Since 3.68 `get_connections` takes two fields from chain sync's view: `height`, the block count the peer claims, and `state`, the session's mode (`T/p2p.rs:237`, `:250`); each is `null` for a connection chain sync does not hold. `sync_info` calls the same two facts `claimed_height` and `mode`. *Question:* one fact, one name. *Recommended:* on `peer_connections` they are `height` (the ordinal of the tip the peer claims, `null` before it has claimed) and `mode` (IG-Q80's keywords, `null` for a connection chain sync does not hold). `state` leaves the connection; its §19 row keeps `tor` and gains `sync` (IG-Q80), and `mode` gains the parent `connection`.

**IG-Q82 — the connector rows on `daemon_status` — RULED 2026-11-10, as recommended; replaces six §18 rows.** Since 3.70 the Peers part reports one row for each connector the daemon runs, `connectors: [{connector, incoming_sockets, outgoing_sockets, white_peerlist_size, gray_peerlist_size}]` (`T/info.rs:396-407`); a connector it does not run has no row. `_sockets` and `_size` state a kind, `incoming` is ruled `inbound`, and an element that names its own connector lets one connector appear twice. *Question:* the field's shape and names. *Recommended:* `connector`, a map (IG-6) from connector — `clearnet`, `tor` — to that connector's counts: `inbound_count`, `outbound_count`, `peer_white_count` and `peer_gray_count`. A connector the daemon does not run has no key, and a name cannot appear twice, which is the reason IG-Q42 gave `option_set` a map. `connector` gains the parent `daemon`. Inside a connector's object the counts walk from its subject (`clearnet` → `inbound` → `count`) or by reference (`peer` → `white` → `count`); every edge exists. §18's six flat rows go. The alternative keeps a list whose element names its connector in `id`.

**IG-Q83 — `relay_stats` — RULED 2026-11-10, as recommended.** §18 rules the reply's names. Two facts are unnamed. A tally's connector may be `unnamed`, "a successor whose connector has not been observed" (`T/p2p.rs:463-475`), a third value where §19's `connector` is one-of `clearnet`, `tor`; and a tally's `peer` is the connection's id, 32 hexadecimal characters (`T/p2p.rs:492-495`), where §18 says `peer` (bytes). *Question:* both. *Recommended:* a tally's `connector` is `null` when it has not been observed (RK-D23: no answer), so `connector` keeps its two values everywhere; `peer` becomes `connection`, the connection's id in the one encoding `peer_connections` gives it, so a reader can join the two replies. `connection` gains the parent `tally`. The method stays host-only (RT-O9.3).

**IG-Q84 — the claim source's gather tip — RULED 2026-11-10, as recommended.** The reply carries the height it was gathered at (`chain_height`, `T/archival_reads.rs:88`) and not that block's hash, so the wallet cannot tell which chain the record was gathered on and brackets the read to close a reorg across it (FOLLOWUPS, "The claim-source reply should carry the hash of its own gather tip"). *Question:* the field. *Recommended:* `hash`, beside `height`: the hash of the block at `height`, read in the same snapshot. `hash` gains the parent `claim`, as `chain_height`'s reply pairs the two. The wallet's bracket goes when it reads the field.

**IG-Q85 — a read about peers on an offline daemon — RULED 2026-11-10, as recommended.** A daemon started offline answers `sync_info`, `get_connections` and `/get_peer_list` with `{"status": "offline"}` alone (`T/p2p.rs:336-350`): it has no peers by configuration, and an empty list would read as a running node with none (Rick, 2026-10-14). `status` leaves every reply (RW-Q3). RW-Q3 keeps a state a reply legitimately describes as data and refuses where a method cannot answer. *Question:* which is this? *Recommended:* a refusal: class `RefusedByMethod`, diagnostic `p2p.offline`. The three methods have nothing to describe, the state itself is already data on `daemon_status` (`offline`), and a client branches on the dotted code. It is not `NotReady`: asking again does not help. The alternative applies IG-Q73's one-key form to a whole reply, `{"offline": null}`, which gives two list methods a reply that is not a list.

**IG-Q86 — keywords and diagnostic codes on the wire — RULED 2026-11-10, as recommended.** IG-1 gives a path three renderings and says nothing of a keyword. Part E's keywords are hyphenated on the wire (`address-hiding`, `clearnet-only`, `restore-managed`), as §3's are (`complete-tree`); the keywords that arrived outside the grammar use `_` (`past_cap`, `held_overdue`, `already_in_pool`, `fee_too_low`). IG-11's diagnostic codes are dotted with hyphens inside a segment (`config.marker.network-id`); the daemon's RPC codes use `_` and negations (`mine.no_address`, `node.not_ready`, `rpc.grant.host_only`). *Question:* one spelling for each. *Recommended:*
- **A keyword has one spelling on every surface**: lowercase segments joined with `-`, never translated (IG-1). `_` joins only the segments of a method, parameter or field name. A keyword may be an object's key where the object is a one-key state (IG-Q70, IG-Q73). The verdicts become `accepted`, `already-in-pool`, `already-in-chain`, `rejected`; the causes `malformed`, `fee-too-low`, `double-spend-conflict`, `stale-root`, `reference-too-recent`, `reference-unknown`, `consensus-rule`, `unrecognized`; the sync keywords as IG-Q80.
- **No keyword and no code segment is a term IG-4 refuses**, as Part E refused `not-installed`: `reference_not_found` is `reference-unknown`, `no_view` is `unpeered`.
- **A diagnostic code is dotted segments**, each lowercase and `-`-joined, none an IG-4 term. The first names what refused: a glossary subject (`mine`, `block`, `tx`, `txpool`, `p2p`, `daemon`), or `grant` or `bound` for RW-Q3's two classes that belong to no method. The rename PR rewrites every RPC code to that form and lists each in the registry `RPC_WIRE.md` RW-Q3 keeps: `mine.no_address` is `mine.address.unset`, and `rpc.grant.host_only` is `grant.host-only`. A code names one source. `node.not_ready` is raised for several today — a handle not yet supplied, a pool that was never supplied, a retired pool, a relay with no driver (`D/handles.rs:124-151`) — and each takes its own code; none is labelled with another's cause. The full list is the PR's error-code mapping, reviewed with it.

**IG-Q87 — enrolment's names — RULED 2026-11-10, as recommended.** `RPC_CHANNEL.md` §5 names enrolment `shekyld rpc-enrol FINGERPRINT --ceiling GRANTS` and `shekyld rpc-revoke FINGERPRINT`. Both contradict landed rulings. IG-Q8 (2026-11-03): a bare word on `shekyld` is `config.cli.syntax`, and daemon commands are `shekyl-cli` words. IG-3: a command is a path, not a hyphenated verb. And §5 itself says enrolment runs over the channel, so each act is a method with a grant (`enrol`), and its `shekyl-cli` word is that method's path. *Question:* names for five acts: enrol a fingerprint with a ceiling; change an enrolled ceiling; revoke; list the enrolled set; show this daemon's public bundle. *Recommended:* the `ban` pattern, one verb per change (IG-Q44):

| Word | Method | Parameters | Grant |
|---|---|---|---|
| `rpc client add <fingerprint> --ceiling <grants>` | `rpc_client_add` | `fingerprint`, `ceiling` | enrol |
| `rpc client set <fingerprint> --ceiling <grants>` | `rpc_client_set` | `fingerprint`, `ceiling` | enrol |
| `rpc client remove <fingerprint>` | `rpc_client_remove` | `fingerprint` | enrol |
| `rpc client list` | `rpc_client_list` | — | enrol |
| `rpc bundle show` | `rpc_bundle_show` | — | enrol |

- `add` on an enrolled fingerprint is refused and names `set`; `set` on one not enrolled is refused and names `add`. Each call is bounded by §5's rule: the ceiling given, and the ceiling of the key being changed or removed, lie within the caller's effective grant. `list` returns the enrolments whose ceiling lies within it; the others are absent.
- `remove` closes every live session the fingerprint holds, and so does a `set` that lowers the ceiling (`RPC_CHANNEL.md` §5): the client reconnects to receive the new grant.
- A ceiling is stored and listed as its expanded grants, never as a preset's name. A request may name presets. A record that kept the name would widen every key enrolled under it when the preset's definition changed.
- The console key is not an enrolment (§5). It is never in `rpc_client_list`, and `rpc_client_remove` and `rpc_client_set` cannot name it.
- `fingerprint` is kind `hash`: 32 bytes (RT-O14). `ceiling` is a list of one-of the grant and preset keywords of `RPC_CHANNEL.md` §6.1. `rpc_bundle_show`'s reply is `{"bundle": b}`, kind `bytes`.
- New terms: `client` under `rpc`, "a client identity enrolled on this daemon: a fingerprint and its ceiling"; `bundle` under `rpc`, "this daemon's static public keys, given to a client that will be enrolled"; `fingerprint` and `ceiling` under `client`. `add`, `set`, `remove` and `list` gain the parent `client`; `show` gains `bundle`.
- `client` is used nowhere else as a term. `bundle` appears in prose for the Tor bundle and the witness bundle; neither is a name in any table, so the term has one meaning.

**IG-Q88 — the console key's reset — RULED 2026-11-10, as recommended.** `RPC_CHANNEL.md` §5 rules an offline, local reset of the console key that takes the data home's exclusive lock, so by design it cannot run over the channel, and it is therefore no method and no `shekyl-cli` word. Under IG-Q8 `shekyld` has no command words. *Question:* where does it live? *Recommended:* a `shekyld` switch, `--rpc-console-key-reset`, given on the command line only (IG-7), the shape `config-verify` already has (IG-Q58): a switch that selects what the process does and exits. It takes the lock, replaces the console enrolment, writes the new private half and exits without starting the node; it is refused in a run mode that has no console key, and while the lock is held. IG-Q8 refuses bare words, not a one-shot switch. New terms: `console` under `rpc`, "the console key: the host administrator's credential in service mode"; `reset`, a verb under `key`; `key` gains the parent `console` and its meaning widens from "only in `key image`" to "a key: under `spent`, in `key image`; under `console`, the console key".

**IG-Q89 — what a re-offer and a flush answer — RULED 2026-11-10, as recommended.** `relay_tx` and `flush_txpool` name ids and reply `status` alone (`D/pool_methods.rs:184-208`). Both hold the `node` grant, and a `node` key is bounded; entries not yet public are host-only (RT-O9.3). A reply that lets a bounded caller tell "held here, unpublished" from "not here" tells it this node originated the transaction, and so does a re-offer the caller can watch arrive on the network. *Question:* the reply, and what a bounded caller may cause. *Recommended:* each replies a list in selector order (IG-Q53): the id where the act was done, `{"missing": null}` where the pool the caller may see holds no such entry (IG-Q73). For a caller without the host's view an unpublished entry is not in that pool: its slot is `{"missing": null}` and the daemon neither re-offers nor removes it. The host's administrator sees and acts on every entry. A retired pool refuses the whole call (`NotReady`, `txpool.retired`). `txpool_flush` with no `id` removes every entry the caller may see and replies their ids.

**IG-Q90 — what one `shard_fetch` may cost — RULED 2026-11-10, as recommended.** `request_archival_shard` holds the `node` grant. Its view desk caches one view for each closed shard and runs one flight for each shard asked (`rust/shekyl-archival-fetch-sched/src/view.rs:140-158`); a flight reads the whole shard from its holders through the node's Tor. `RPC_CHANNEL.md` §6.3 bounds the four caps, the hash and the coinbase read, and names no bound here, so a bounded caller naming many closed shards opens as many flights. *Question:* the bound. *Recommended:* §6.3 gains it, in the coinbase read's shape: bounded callers share one shard-fetch permit, a cached view takes none, and a bounded call that would open a flight while the permit is out is `OverResourceBound`, `bound.shard`. The flight a refused caller did not open is not queued. **The producer's reads come first.** The scheduler is the one the bundle producer reads through, whose challenge reads have deadlines (`CHALLENGE_TIMEOUTS`); a missed read is a missed witness duty. So the permit caps bounded callers at one flight in total, the producer's reads take the client's `READS_AT_ONCE` slots before any view flight, and the host's own flights, which take no permit, yield to the producer too. A node with Tor off has no client to read through: `shard_fetch` refuses there with `RefusedByMethod`, `shard.tor-off`, never with "no skeleton".

**IG-Q91 — `shard_fetch`'s grant — RULED 2026-11-10, as recommended; amends `RPC_CHANNEL.md` §6.1.** `request_archival_shard` holds `node`, the control grant (§6.1). The wallet reads a closed shard's view through it (`rust/shekyl-wallet-contract/src/shard_view.rs:117`), and neither the `wallet` preset nor the view listener holds `node`, so a wallet's `get_shard_view` is refused by its grant before it reaches the desk. What the method reads is public, closed history. The grant stood in for the cost, and IG-Q90 bounds the cost. *Question:* which grant? *Recommended:* `chain`, bounded by IG-Q90. A site relaying strangers through a `view` key can open at most one flight at a time; a cached view is free; the producer keeps its slots. The alternative keeps `node`, and a wallet without `node` cannot read a closed shard's view.

**IG-Q92 — the writer's halt — RULED 2026-11-10, as recommended.** The chain store's writer halts when a connect or a pop hits a store invariant: it refuses until restart, and reads stay open (`DAEMON_REDB_STORE.md` §3.6.2; IG-F22). The tip a halted node serves is stale, and nothing on the wire says so. The wire type exists as `{"state": "live"}` or `{"state": "halted", "at_height": h, "row": n}` (`T/chain.rs:656-668`); `at_height` and `row` are not paths, and `row` is not a term. *Question:* the field, where it lives, and who may read it. *Recommended:* `writer`, on `chain_height`, the tip read, and on `daemon_status`, in IG-Q70's form: `{"live": null}`, or `{"halted": {"height": h, "invariant": n}}`, where `height` is the ordinal the halting connect or pop was working at and `invariant` is the `SI-` row of `STORE_INVARIANT_REGISTER.md` that caught it, an integer. Grant: `health` on `daemon_status`, and `chain` with the tip. Whoever reads the tip can know it is stale, a site that relays a halted node included. New terms: `writer` under `chain` and `daemon`, "the chain store's writer: live, or halted on an invariant"; `invariant` under `writer`. `height` gains the parent `writer`.

**IG-Q93 — when the Tor state began — RULED 2026-11-10, as recommended; amends IG-Q69 and §23's `tor.since` row.** §23 rules `tor.since` a time, unix seconds: when `state` began. A reading of the node's wall clock is wrong exactly when the cause is `clock-skew`, because the node's clock is the thing that is wrong; and a client on another machine subtracts its own clock from it, so what it computes is the skew between two machines added to the age. *Question:* does `tor.since` stand? *Recommended:* it becomes `tor.age`, a `duration` in whole seconds taken from the monotonic clock: how long `state` has stood, as IG-Q80 uses `age`. An age is right under a skewed clock and needs no second clock to read. Its one cost is that it is true as of the reply, which every polled field already is. `age` gains the parent `tor`, and `since` leaves §19. The Tor supervisor lane's PR writes the field as `tor.age`.

**IG-Q94 — a selector on the wire — RULED 2026-11-11, as posed; amends §17, §19 and §18.1.** §17 writes the selector of `block_header_show`, `block_show` and `curve_show` as `{"height": n}`, `{"hash": h}` or `"tip"`, beside the switches `pow` and `prune`. RW-Q2 makes `params` a named object, so a bare `"tip"` cannot stand beside a switch; and §18.1 walks `height` and `hash` as parameters of their own. *Question:* how does a call name its item? *Recommended:* `params` carries **exactly one** of the keys `height`, `hash` and `tip`, beside the method's switches: `{"height": 7, "pow": true}`, `{"hash": h}`, `{"tip": null}`. `tip` takes IG-Q70's form, a key whose value is `null` because it has no payload.
- **Exactly one, never zero.** A call that names no selector is refused (`BadParams`), and never means the tip: a client that dropped `height` by mistake would otherwise read the tip's header in place of block *n*, and a scan might never notice. Two selectors are refused the same way.
- **The walk changes.** `tip` was a value keyword (§19, "a header, block or curve selector"). Under this form it is a parameter, so it leaves the value-keyword list and is a term under `block` and `curve`, "the chain's last block, as a selector; its value is `null`"; §18.1's selector rows gain `tip`; §17's three cells read `height`, `hash` or `tip` (exactly one). All three are recorded in place.
- **The alternatives are worse.** A parameter `block` holding the selector repeats the method's own subject and adds a name. `"tip"` inside `height` gives one field two encodings, which RW-Q4 refuses.
- **Built by hand.** serde's `flatten` turns `deny_unknown_fields` off, so the request type has its own `Deserialize` and its own schema shape (one of several keys, flattened), and `conforms` refuses a call with no selector and one with two.

## 27. Part G — the owner's socket and the service mode

**RULED 2026-11-12 (Rick): IG-Q103 and IG-Q104 as posed; IG-Q105 as ruled.** RT-W10's third step builds the owner's socket and its rendezvous ([`RPC_CHANNEL.md`](RPC_CHANNEL.md) §7.1; the step's row in [`RPC_CHANNEL_RT_W10_PREFLIGHT.md`](RPC_CHANNEL_RT_W10_PREFLIGHT.md) §5). Two of its inputs had no row (F-15: "no socket-directory option or instance option"), and a daemon run as its user now refuses to start without a session directory, which every service manager's daemon lacks. This Part names the two inputs and rules the service mode those daemons take.

**IG-Q103 — the instance name — RULED 2026-11-12, as posed.** `instance`, a `name` (IG-6) whose rule is the owner's: 1 to 16 lower-case letters, digits or hyphens, starting with a letter or a digit, and `default` refused by name (§7.1, `shekyl-rpc-channel`'s `InstanceName::parse`). Unset is the default instance, the one a client means by "this computer". The name is hashed into the rendezvous with the network id and never becomes a path or an IPC name. A named instance is a second node, so it names its own `data-dir` or the start refuses (`config.value.requires`). Command line and file. The term `instance` is a root of the glossary (§3).

**IG-Q104 — the socket directory — RULED 2026-11-12, as posed.** `rpc-socket-dir`, a path: the directory for the owner's socket where the account has no session directory. Session-less test hosts (CI and the regtest harnesses) create it and pass it. It is asserted, not adopted: it must exist, be a directory and not a link, be owned by the daemon's account, have mode 0700, and be on a local filesystem; otherwise the start refuses, naming the condition that failed (`config.socket-dir.unusable`). A socket path over the platform's limit is refused with the path and the limit (`config.socket-dir.path-long`). With neither this nor a session directory, a daemon run as its user refuses and names the three ways forward: `service`, `loginctl enable-linger`, or this option (`config.socket-dir.none`). `dir` gains the parent `socket` (§3).

**IG-Q105 — the service mode on every platform — RULED 2026-11-12; amends IG-Q36.** `service` is accepted on every platform. On Linux and macOS it means only that this is the machine's service instance: it serves no same-user socket (§7.1), and it takes the machine-wide rendezvous in the service data home once RT-W10's channel step builds the channel. On Windows it also answers the service manager, and that dispatcher stays RT-W14's, so a Windows start refuses the switch until then. A daemon that cannot write the service data home refuses to start. A service daemon keeps the plaintext loopback listeners (RT-O33). A service is given no socket directory: `rpc-socket-dir` with `service` is refused (`config.value.conflict`). The seeds' units and the package's unit pass `service`. A Windows start's refusal is `config.service.platform`, "not available on this platform yet", naming RT-W14.
