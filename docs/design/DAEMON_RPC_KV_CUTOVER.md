# Daemon RPC — Phase 2: the KV cutover (native Rust handlers over facts FFI)

**Status:** **RK-1 through RK-4b landed** (the pattern slice, PR #534; count
+ hash-by-height, PR #540; the block-header projection, PR #541; whole blocks,
PR #548; the `.bin` mechanism, PR #555; the last binary endpoint and the FFI
bridge's deletion, PR #562) — per-slice shas in the §2 slice table. **RK-4c** (the transaction read set) is
**landed on this branch**, PR #576, sha stamped at merge — the tense the §2
rows use, which is written as of the merge this document lands with. Design
**open for RK-5**. Census and binding
decisions verified at source against `dev` **`077d97c4e`** (PR #528 merge);
every `file:line` below was read at that commit. RK-2's own census rows and
consumer set were re-verified at **`c5ca208e9`** (PR #534 merge), the commit
it was cut from.
**Identifier family:** `RK-` (RPC KV cutover), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 in the commit that
lands this document (rule 94). Neighbours present as families: `RF-`, `RP-`,
`RT-`, `DRS-`, `LV-`; `RK-` is free.
**Parent:** [`docs/DAEMON_RPC_RUST.md`](../DAEMON_RPC_RUST.md) — Phase 1
(transport) is complete and epee's HTTP surface is gone (#533); this is the
Phase 2 that document named and left unspecified.
**Process rule:** [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
is invoked for the FFI-boundary-moving slices; the mining/submit-block
slice (RK-7) is consensus-adjacent and gets its own pre-flight pass. Every
other slice is spec-first per
[`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc) with
this document as the spec.
**Decision authority:** Rick.

**Mission hierarchy** ([`00-mission`](../../.cursor/rules/00-mission.mdc)):
this is longevity work — the system must outlast the team, and a daemon
whose wire contract is defined by 2,645 lines of C++ macros that only epee
can read is not maintainable by an unknown future maintainer. It trades
nothing in security or privacy; where a slice touches a trust decision
(restricted mode, RK-D6) the Rust side is the stricter one.

---

## 0. Problem statement (verified at source)

Phase 1 left the request path as: Axum → raw body → `core_rpc_ffi_*`
(`src/rpc/core_rpc_ffi.cpp`, 508 L) → a C++ template that
`load_t_from_json` / `load_t_from_binary`s the body into a
`COMMAND_RPC_*::request`, calls the `core_rpc_server::on_*` handler
(`core_rpc_server.cpp`, 2,963 L), and `store_t_to_*`s the response back.
The wire types are **65 `COMMAND_RPC_*` structs carrying 872
`KV_SERIALIZE` fields** (`core_rpc_server_commands_defs.h`, 2,645 L). The
console (`rpc_command_executor.cpp`, 2,400 L) consumes the same structs on
both of its arms — in-process it calls `m_rpc_server->on_*` directly, and as
`shekyld <command>` it frames them as JSON through `src/daemon/rpc_client.h`.

The sentence Phase 1 wrote for Phase 2 — *"replace epee portable-storage in
`core_rpc_ffi.cpp` with a Rust-native codec"* — describes something that
cannot be built: a Rust codec cannot serialize a C++ struct it does not know
the layout of, and giving it that layout means a `#[repr(C)]` twin of every
wire struct, marshaled into a C++ handler — a permanent façade that
[`40-ffi-discipline`](../../.cursor/rules/40-ffi-discipline.mdc) forbids
and that would double every one of the 872 fields.

**The only honest exit:** the wire type and the handler move to Rust
*together*, one method at a time, and C++ supplies the facts the handler
needs through a coarse, typed FFI — exactly the shape `POST
/submit_transaction` already has
([`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md) §3–§4:
`shekyl_submit_snapshot_facts` fills a `#[repr(C)]` POD, the Rust engine
owns the decision and the wire). epee KV leaves the RPC path method by
method; when the last method moves, `core_rpc_server.cpp`,
`core_rpc_server_commands_defs.h`, the dispatch tables in
`core_rpc_ffi.cpp`, and the C++ console go. epee's portable-storage then
survives only on the P2P path, which is LV-2/LV-3's (`LV2_PORTABLE_STORAGE.md`)
and not this program's.

This is not a serialization project. It is the daemon-RPC half of the Rust
cutover, scheduled by validation surface
([`19`](../../.cursor/rules/19-validation-surface-discipline.mdc)).

---

## 1. Binding decisions

| ID | Decision | Why |
| --- | --- | --- |
| **RK-D1** | **Rust owns the wire types, once.** `shekyl-rpc-types` is the single definition of every daemon method's request/response (serde for JSON; `shekyl-portable-storage` for `.bin`), consumed by `shekyl-daemon-rpc` (server), `shekyl-rpc-client` (wallet), `shekyl-cli`, and the GUI. The wallet client's ad-hoc response structs (`rpc-client/src/lib.rs:342-397`, `HeightResponse`, `BlocksResponse`, …) retire as each method migrates — delete the duplicate, never synchronize it. | One definition is the only one that cannot drift. |
| **RK-D2** | **The handler moves with the type.** A method migrates whole: type, handler, console rendering. There is no intermediate in which a Rust type is marshaled into a C++ handler or a C++ struct is re-serialized by Rust. | Rule 40: no permanent façade; rule 20: new code is Rust. |
| **RK-D3** | **Facts FFI, coarse and typed.** One C export per method family (`shekyl_rpc_<family>_facts`), `#[repr(C)]` PODs with a bidirectional layout-twin test (the F26 pattern, `tests/unit_tests/daemon_submit_ffi_roundtrip.cpp`); variable-length data as C++-owned `(ptr,len)` views with an explicit free; distinct return codes; refuse, never panic, at the boundary. The facts shim holds **no policy** — it reads core state and returns. | Rule 40: coarse over fine; secrets and decisions stay in Rust. |
| **RK-D4** | **Wire equality is semantic for JSON, byte-exact for binary.** Oracle vectors are captured from the C++ handler *before* it is deleted (commit N captures, commit N+1 deletes — see §4) and pinned as test fixtures. JSON: parsed-equal, with epee's `KV_SERIALIZE_OPT` omission mirrored by `#[serde(skip_serializing_if)]` so existing clients see identical semantics; key order and whitespace are not contractual. Binary: byte-equal through `shekyl-portable-storage` (LV-2a already matches epee byte for byte). | The contract is the value, not epee's pretty-printer. |
| **RK-D5** | **Console rendering follows the method.** Both console arms — interactive in-process and `shekyld <command>` over the loopback client — render in Rust through one export, `shekyl_daemon_console_run(argv, ctx)`: with a live core handle it calls the native handler directly; without one it posts through the existing `shekyl_daemon_ctl_post` and renders the typed reply. The C++ executor entry for a migrated command becomes a one-line forward and is deleted in RK-C. | The console is the second consumer of every struct; leaving it in C++ keeps every struct alive. |
| **RK-D6** | **Restricted-mode policy is single-sourced in Rust.** A natively-served method's visibility is the Rust route table's `Visibility` / `RESTRICTED_METHODS` and nothing else; the C++ `m_restricted && ctx` branches die with their handlers. Closes the FOLLOWUPS "dual-list" item at RK-X. | One list can be tested (`route_table_matches_the_specification`). |
| **RK-D7** | **Store-agnostic handlers.** Each family's facts arrive through a trait (`ChainFacts`, `PoolFacts`, `PeerFacts`, … — the `SubmitStateShim` shape), with the FFI shim as today's only impl. When DRS-E lands the Rust store, a second impl reads it directly and the C++ shim is deleted; handlers and tests do not change. | DRS is the long pole; RPC must not wait for it, and must not be rewritten after it. |
| **RK-D8** | **One variable at a time: the cutover preserves each reply's shape; wire cleanup is its own slice.** Pre-genesis there is **no external wire contract** — every client of this RPC is in this tree (wallet, CLI, GUI, console, test framework) and ships with the daemon. The shape-preservation rule is therefore a *sequencing* discipline, not a compatibility promise: the epee oracle vectors can only pin a reply whose shape did not move, and a slice that both migrates a handler and changes its wire cannot be bisected. So each RK slice keeps field sets, names, defaults, aliases and status values as they were — **with one recorded exception: RK-4c retired `get_transactions`' `txs_as_hex` / `txs_as_json`** (rule 60; the only in-tree readers went in the same diff, and the removal landed as its own commit *after* byte-parity was green so the divergence bisects separately). The exception is narrow and deliberate: the rule's purpose is that a slice migrating a handler must not also move its wire, because the oracle vectors can only pin a shape that did not move and a slice doing both cannot be bisected. RK-4c satisfied both — parity first, removal after — which is the discipline, not a waiver of it; the Monero-era quirks that survive the cutover — the `status` string doubling as an error channel, `KV_SERIALIZE_OPT` omissions, positional JSON-RPC (`get_block_count`'s list request), the `/getheight`-style aliases — are **queued for RK-W**, a wire-cleanup slice after RK-X that redesigns the surface once, with every in-tree client updated in the same PR. `CORE_RPC_VERSION` stays a cheap skew guard between a wallet and a daemon from different builds (§2.3 of `DAEMON_SUBMIT_VERDICT.md`), bumped when a reply a client parses changes; it is not a ceremony. Diagnostic text inside a transport failure is neither shape nor status and may change at any time. | Parity needs a fixed shape; bisection needs one variable; nothing outside the tree needs the old shape. |
| **RK-D9** | **`rpc_target_wire_contract.cpp` is re-pinned, not preserved.** It asserts epee's pretty-printed `"block_target": 120` byte form on the claim that "offline grep-based monitoring relies on the canonical form". No such monitoring exists in the tree. When `mining_status` / `get_info` move (RK-5/RK-7) the test becomes a Rust test that the *value* is `SHEKYL_DAA_TARGET_SECONDS`. Reopen: a named monitoring consumer of the whitespace form. | A check whose subject is a formatter we are deleting is decorative. |
| **RK-D10** | **A hash on this wire is `HashHex` — 32 bytes, 64 lowercase hex characters, wire-level.** Every 32-byte hash the RPC carries is one type, which validates the hex once in the deserializer instead of leaving each consumer to parse it. It wraps raw bytes, **not** a domain newtype: a single `block_header` carries hashes of four kinds (block identity, transaction identity, two roots, a proof-of-work hash), so typing the wire field as `BlockHash` — §3.1's original sketch — would recreate on the wire the confusion `shekyl-types`' `hash32!` newtypes exist to prevent, and a generic `HashHex<T>` would need a trait plus newtypes for the roots and the PoW hash that this tree does not have. Consumers name the kind at their edge (rule 18), as `shekyl-wire::BlockHeader` already does with both roots. Where the wire's absent form is `""` rather than a missing field (`block_header.pow_hash`), the type is `Option<HashHex>` with an explicit `""`-as-absent serde, so the daemon's "was it filled?" flag survives to the wire; that quirk retires with the rest in RK-W. Landed in RK-3 — see the §7 log entry of 2026-08-23 for the rejected alternatives. | One definition, one parse, and no field that claims to be a kind of hash it is not. |

---

## 2. Census — every method, by validation surface

Live consumers at `077d97c4e`: **W** wallet (`shekyl-rpc-client` /
`engine-core`), **C** `shekyl-cli`, **G** GUI (`daemon_rpc.rs`), **K** console
(`rpc_command_executor.cpp`, 35 methods), **P** python-rpc framework /
functional tests, **F** fleet scripts, **R** regtest harness
(`engine-core/regtest_e2e.rs`). "Facts" = distinct `m_core.*` / `m_p2p.*`
calls in the handler (`core_rpc_server.cpp`).

| Slice | Surface | Methods (REST `/path` · JSON-RPC `name` · `.bin`) | KV fields | Facts | Consumers |
| --- | --- | --- | --- | --- | --- |
| **RK-1** — **landed** (PR #534, `c5ca208e9`) | Chain tip + version (the pattern slice) | `/get_height` `/getheight` · `get_version` | 8 + 15 | `shekyl_rpc_chain_tip`, `shekyl_rpc_hardforks` (`src/rpc/rpc_facts_ffi.cpp`) | W K P |
| **RK-2** — **landed** (PR #540, `64ee608ca`) | Block count + hash-by-height | `get_block_count` (`getblockcount`) · `on_get_block_hash` (`on_getblockhash`) | 4 + — (the hash reply is a bare JSON string) | `shekyl_rpc_chain_tip` (reused from RK-1), `shekyl_rpc_block_hash_at` | P (python-rpc, stressnet) |
| **RK-3** — **landed** (PR #541, `cbba3e261`) | The **block-header projection**; `HashHex` (RK-D10) | `get_block_header_by_height` (+ `getblockheaderbyheight`) | 9 (+ the shared 24-field `block_header_response`) | `shekyl_rpc_block_header_at` | W (`shekyl-rpc-client`) P |
| **RK-3b** — **landed** (PR #548, `3ed8baf08`) | Whole blocks | `get_block` (+ `getblock`) — header + blob + json + tx hashes, and the console's `print_block_by_hash` / `_by_height`, which read **only** this method | 22 | header facts + block blob + tx-hash list + **the epee-rendered `json` string** (RK-D11) | W C K R P |
| **RK-4a** — **landed** (PR #555, `bbed0ad71`) | The `.bin` mechanism, proved small | `/get_o_indexes.bin` | 12 | `get_tx_outputs_gindexs` | W (`shekyl-rpc-client`) |
| **RK-4b** — **landed** (PR #562, `85426f289`) | The remaining live binary endpoint | `/get_blocks_by_height.bin` `/getblocks_by_height.bin` | 15 | `get_blocks_by_height` | E (the engine's timing rig) |
| **RK-4c** — **landed** (this branch; PR #576, sha stamped at merge) | The transaction read set (the wallet's proofs path) | `/get_transactions` `/gettransactions` (+ the console's `print_transaction`) · `/is_key_image_spent` (+ the console's `is_key_image_spent`) — each console command reads **only** its own method | 31 + 8 | `get_split_transactions_blobs`, `get_pool_transactions_info`, `are_key_images_spent[_in_pool]` | W K P F R |
| **RK-4x** — **ruled: deleted** | `/get_blocks.bin` `/getblocks.bin` · `/get_hashes.bin` · `/gethashes.bin` | wallet2's batch sync, and wallet2 is gone. Retired rather than migrated, with `get_pool_info` and the pool's departure history behind it. Reopen clause in `DAEMON_RPC_RUST.md` | — (44 fields deleted, not ported) | — | none |
| **RK-5a** — **landed** (this branch; PR #585, sha stamped at merge) | The **p2p seam**, proved small | `sync_info` · `/get_net_stats` · `/get_peer_list` · `get_connections` — the methods whose facts are p2p-only | 11 + 7 + 10 + 7 (+ `connection_info`) | `get_public_*_count`, peerlist, throttle stats — **as scalars**, see §3.2; plus the `shekyl_rpc_chain_tip` retrofit | K P F |
| **RK-5b** | The header projection's remainder | `get_last_block_header` · `get_block_header_by_hash` · `get_block_headers_range` · `hard_fork_info` · `get_fee_estimate` | 8 + 11 + 10 + 15 + 10 | `fill_block_header_response`'s three, hard-fork voting info, `get_dynamic_base_fee_estimate_*` | W C K P |
| **RK-5c** | **`get_info`, the hub — and every console command that reads it** | `/get_info` `/getinfo` · `get_info` | 48 + 24 | 7 core reads, 5 p2p reads (scalars), ~20 bare getters | W C G K P F |
| **RK-6** | Mempool | `/get_transaction_pool` · `/get_transaction_pool_hashes` (its `.bin` sibling is **retired**, not pending — see §5; do not re-add it) · `/get_transaction_pool_stats` · `get_txpool_backlog` · `flush_txpool` · `relay_tx` | 8 + 7 + 7 + 26 + 7 + 7 | pool reads, `flush_txes_from_pool`, `get_protocol().relay_transactions` | K P |
| **RK-7** | Mining (consensus-adjacent → rule 26 pre-flight) | `get_block_template` · `submit_block` · `calc_pow` · `get_miner_data` · `add_aux_pow` · `generateblocks` · `/start_mining` `/stop_mining` `/mining_status` `/set_log_hash_rate` | 22 + 4 + 7 + 19 + 17 + 12 + 10 + 6 + 21 + 7 | `get_block_template`, `handle_block_found`, `check_incoming_block_size`, `get_miner()`, `get_miner_data` | K R P |
| **RK-8** | Admin + chain maintenance | `/set_log_level` `/set_log_categories` · `/get_limit` `/set_limit` · `/in_peers` `/out_peers` · `set_bans` `get_bans` `banned` · `/save_bc` · `/stop_daemon` · `/pop_blocks` · `prune_blockchain` · `flush_cache` · `get_alternate_chains` · `get_coinbase_tx_sum` · `get_output_histogram` | 7 + 30 + 8 + 10 + 9 + 9 + 13 + 12 + 8 + 6 + 6 + 8 + 9 + 7 + 17 + 14 + 18 | throttle, p2p limits/bans, `store_blockchain`, `send_stop_signal`, `pop_blocks`, pruning, alt chains, histogram | K P R |
| **RK-9** | Curve tree + archival | `get_curve_tree_path` · `get_curve_tree_info` · `get_curve_tree_checkpoint` · `get_archival_emission_claim_source` · `inject_archival_serve_credit` (regtest) | 19 + 10 + 11 + 40 + 35 | `get_db()` reads; the logic is already Rust (`shekyl-curve-tree`, `shekyl-archival-*`) | W G R |
| **RK-C** | Console retirement | `rpc_command_executor.cpp` / `command_parser_executor.cpp` / `command_server.cpp` → Rust; `src/daemon/rpc_client.h` dies | — | — | K |
| **RK-W** | Wire cleanup (after RK-X) | Redesign the surface once the handlers are all Rust: retire `status`-as-error-channel in favour of typed errors, drop OPT-omission quirks and positional JSON-RPC, collapse aliases (including the `on_`-prefixed names — `on_get_block_hash` is a C++ handler name that leaked onto the wire, and the bare `get_block_hash` a client would reach for has never been served); every in-tree client updated in the same PR; `CORE_RPC_VERSION` 4.0 | — | — | W C G K P |
| **RK-X** | Final deletion | `core_rpc_server.{h,cpp}`, `core_rpc_server_commands_defs.h`, `core_rpc_ffi.cpp` dispatch tables, `rpc_handler.*`, `message_data_structs.h`'s RPC half, `json_object.cpp`'s RPC (de)serializers; FOLLOWUPS dual-list closed | 872 → 0 | — | — |

Already native (no slice): `POST /submit_transaction` (§2 of
`DAEMON_SUBMIT_VERDICT.md`), `/get_stem_tallies` (`core_rpc_ffi_stem_tallies`
returns Rust-built JSON). `COMMAND_RPC_GET_OUTPUTS[_BIN]` (16 + 16 fields) and
`COMMAND_RPC_FAST_EXIT` (6) have **no dispatch row and no handler** —
they are deleted in RK-1 under rule 15, not migrated.

**Scope correction (2026-08-22, before RK-2 was cut).** `hard_fork_info`
was drafted into RK-2 by feature topic — "fork + count" — and moved to RK-5
by validation surface ([`19`](../../.cursor/rules/19-validation-surface-discipline.mdc)).
`COMMAND_RPC_HARD_FORK_INFO` has **three** C++ consumers, and two of them are
console commands that are not RK-2's: `show_status` (the `status` command)
and `print_blockchain_dynamic_stats` (`bc_dyn_stats`), both of which also
consume `get_info` and block headers. Migrating the type while those stay in
C++ leaves exactly the two outcomes RK-D1 and RK-D2 forbid — a second C++
definition of the reply for the console to parse, or a console command that
cannot be built. Its validation surface *is* `status`'s, so it migrates when
`status` does. RK-2 keeps the two methods with **no** console consumer at
all, which is why it needs no console work.

### 2.1 The console matrix — what actually bounds a slice

A method's C++ struct cannot be deleted while a console command still reads
it, and a console command can only move to Rust once **every** method it reads
has a Rust type. So the slice boundary is not the method — it is the console
command's read set. Enumerated from `rpc_command_executor.cpp` at `64ee608ca`:

| Console command | Methods it reads |
| --- | --- |
| `print_block_by_hash`, `print_block_by_height` | `get_block` **only** |
| `print_transaction` | `get_transactions` **only** — so it migrates with that method (RK-4c), as `print_block` did with `get_block` |
| `is_key_image_spent` | `is_key_image_spent` **only** — same shape, same slice (RK-4c) |
| `print_blockchain_info` | `get_block_headers_range`, **`get_info`** |
| `print_blockchain_dynamic_stats` | `get_block_headers_range`, `hard_fork_info`, `get_fee_estimate`, **`get_info`** |
| `alt_chain_info` | `get_block_header_by_hash`, `get_alternate_chains`, **`get_info`** |
| `show_status` | `hard_fork_info`, `mining_status`, **`get_info`** |
| `show_difficulty`, `version`, `print_transaction_pool_stats` | **`get_info`** (+ their own) |
| `print_pl`, `print_pl_stats` | `get_peer_list` **only** — both, with different arguments (RK-5a) |
| `print_cn` | `get_connections` **only** (RK-5a) |
| `sync_info` | `sync_info` **only** (RK-5a) |
| `print_net_stats` | `get_net_stats` **and `get_limit`** — the one crosser in RK-5a, and a §2.1.1 mixed arm |
| every other command | exactly one method |

**Census correction (2026-08-31, RK-5a).** The five rows above were missing.
The enumeration at `64ee608ca` collapsed them into "every other command:
exactly one method", which is true of four of them and **false of
`print_net_stats`** — it reads `/get_limit` as well, which is RK-8's. A
one-method row would have said RK-5a could migrate it outright; it takes a
§2.1.1 bridged leg instead. The lesson is the same one the eleven-site
disposition list taught: a summary row that says "every other" is not a
census, and the commands it hides are exactly the ones whose read sets
nobody checked.

**`get_info` is the hub**: **seven** commands read it — `alt_chain_info`,
`print_blockchain_dynamic_stats`, `print_blockchain_info`,
`print_transaction_pool_stats`, `show_difficulty`, `show_status`, `version`
(counted at `92807134a`; this line said six, which was wrong) — and *every*
console command that touches a header method also touches it. That is why the header methods
split the way they do — a method whose only console reader is self-contained
can move now; one whose reader also needs `get_info` moves when `get_info`
does. The alternative — migrating the handler while a C++ struct stays behind
for the console to parse the Rust reply with — is the cross-language
duplication RK-D1 exists to prevent, and it is exactly what was refused for
`hard_fork_info`.

A second constraint is testability: `check_core_ready()` reads
`is_synchronized()` off the p2p payload object, which has no double in this
tree. A method that consults it cannot have its facts export driven by a unit
test (§3.2), so `get_last_block_header` — which does — waits for RK-5, the
slice that must build that double for `get_info` anyway.

**Ordering rationale.** RK-1 is small and exercises both framings (REST
JSON, JSON-RPC), an OPT field, a vector field, a facts POD, the console
arm, and the oracle-vector harness — every mechanism the later slices
reuse, on a surface whose failure is visible in one `shekyld status`.
RK-2 adds the two mechanisms RK-1 had no occasion to exercise: **positional
JSON-RPC params** (`on_get_block_hash` takes `[height]`) and a **method-level
refusal** carrying the JSON-RPC code a client branches on
(`CORE_RPC_ERROR_CODE_WRONG_PARAM` / `_TOO_BIG_HEIGHT`), which every later
slice needs and RK-3 needs heavily. RK-4 is the slice that matters most (the
wallet's sync path, binary, byte-exact) and goes third so it lands on a
proven harness rather than proving it. RK-7 last among the core slices because it is the only one a
wrong shim could turn into a consensus-integrity problem (`submit_block`
reaches `handle_block_found`), so it carries the pre-flight pass.

---

### 2.1.1 The console read-graph forces a mixed arm, so §2.1 is amended

§2.1 says a console command can only move once **every** method it reads has a
Rust type. Applied to `get_info`'s seven readers, that rule cannot be satisfied
by any slice ordering, because the connected component of the read graph spans
four slices:

| console command | reads | crosses into |
| --- | --- | --- |
| `show_difficulty`, `version` | `get_info` | — |
| `print_blockchain_info` | + `get_block_headers_range` | — (RK-5b) |
| `print_blockchain_dynamic_stats` | + `get_block_headers_range`, `hard_fork_info`, `get_fee_estimate` | — (RK-5b) |
| `print_transaction_pool_stats` | + `get_transaction_pool_stats` | **RK-6** |
| `show_status` | + `hard_fork_info`, `mining_status` | **RK-7** |
| `alt_chain_info` | + `get_block_header_by_hash`, `get_alternate_chains` | **RK-8** |

Landing RK-6/7/8 first does not help: their console commands then mix on
`get_info` instead. **Mixing is unavoidable; only where it lands changes.** So
the rule is amended rather than quietly broken:

> A console command moves to Rust once every method it reads has a Rust type
> **or is still served through the bridge**, in which case the bridged call is
> recorded as the owing slice's §5 obligation and is replaced when that slice
> lands.

Two things make that safe rather than a promise. The bridged leg must name a
route that **still exists in the C++ dispatch table** — RK-4c shipped a console
arm naming a deleted route and it answered "no reply" on every invocation, so
the obligation rows below are load-bearing, not bookkeeping. And each mixed
command is covered by `ported_console_commands_answer_on_the_in_process_arm`,
so a later slice deleting its route turns that gate red instead of shipping a
dead console.

Mechanically the two bridges are different entry points: `alt_chain_info`'s
outstanding leg is JSON-RPC (`CoreRpc::json_rpc`), while
`print_transaction_pool_stats`'s and `show_status`'s are REST
(`CoreRpc::json_endpoint`). Reaching for the wrong one compiles and returns
`None`.

### 2.2 The restricted gate, and the eleven sites it woke

`m_restricted && ctx` appeared eleven times in `core_rpc_server.cpp`, and the
bridge passing `nullptr` made all eleven dead at once. Fixing the bridge wakes
**ten** of them, so each is a behaviour change on a configured listener and each
owes a disposition. Eight are unremarkable and are listed anyway, because "most
of them are fine" is a claim, not a review.

The eleventh is deleted rather than woken. `relay_tx` is the one method here
that Rust already refuses per-method (`RESTRICTED_METHODS`), so its C++ check
could not hold in any reachable state — the restricted listener never arrives,
and the admin listener's `m_restricted` is false. Cross-referencing the two
lists is what bounds that claim: of these eleven methods, `relay_tx` is the only
one Rust gates.

| Site | Handler | What `restricted` gates | Disposition |
| --- | --- | --- | --- |
| 209 | `on_get_info` | zeroes `alt_blocks_count`, the three connection counts, and passes `!restricted` as the pool count's sensitivity | **Two kinds at once.** The zeroed fields are a trim, intended. The pool count is disclosure: `tx_pool_size` counted the stem/local set for a public caller, and the *size* of that set is itself a signal. Now counts broadcast only |
| 346 | `on_get_transactions` | 100-hash cap; pool read's sensitivity | **The by-hash disclosure.** Cap fires; not-yet-broadcast transactions are no longer returned |
| 583 | `on_is_key_image_spent` | 5000-key-image cap | Cap fires. No disclosure change — this handler's pool half filters on `broadcasted` unconditionally, so it never had the defect |
| 887 | `on_get_transaction_pool` | enumeration scope | **The wholesale disclosure**, and the worst of them: no argument required |
| 908 | `on_get_transaction_pool_hashes` | enumeration scope | **The wholesale disclosure**, identifiers only — which is what makes 346 usable |
| 930 | `on_get_transaction_pool_stats` | statistics scope | Aggregates over the same set. A public caller's histogram no longer includes unbroadcast transactions |
| 1532 | `on_get_last_block_header` | `fill_pow_hash && !restricted` | Field trim, intended, and already the policy RK-3 pinned as `pow_hash_entitled` |
| 1548 | `on_get_block_header_by_hash` | 1000-hash cap; the same pow-hash trim | Cap fires; trim as above |
| 1619 | `on_get_block_headers_range` | range cap; the same pow-hash trim | Cap fires; trim as above |
| 1880 | `on_get_output_histogram` | refuses the all-amounts query, clamps `recent_cutoff` | Cost guards, intended. A restricted caller can no longer ask the expensive form — which is the point of them |
| 2071 | `on_relay_tx` | *(deleted)* | The only Rust-gated method in this table, so the check could not hold in any reachable state. Removed under rule 15 rather than kept as defence it never provided; see §7 |

Two further bridged invocations are converted with no disposition owed:
`dispatch_submitblock` and `dispatch_calcpow` are hand-written rather than
template dispatchers, and neither `on_submitblock` nor `on_calcpow` reads
`ctx` at all, so those two calls change nothing today. They move anyway,
because a bridge rule with silent exceptions is how this survived: a
`restricted` check added to either handler later would have been born dead
in exactly the way the eleven were.

The consumer question this raises is answered the same way each time: a
legitimate caller that needs the unrestricted answer is on the unrestricted
listener, where `m_restricted` is false and nothing here changed. What moves
is the restricted listener, and it moves to the policy it was configured for.

## 3. The mechanism (RK-1 defines it; later slices reuse it)

### 3.1 Types — `shekyl-rpc-types`

One method's types, as the shape every slice follows (the crate holds each
migrated method's; this is not the list):

```rust
/// Response of `GET|POST /get_height` (alias `/getheight`). The request body
/// is empty (and ignored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetHeightResponse {
    pub status: RpcStatus,
    /// Chain height: the top block's height **plus one** (a chain holding
    /// only the genesis block reports `1`).
    pub height: u64,
    /// The top block's hash.
    pub hash: HashHex,
}
```

(Verbatim from `shekyl-rpc-types/src/chain.rs`; the snippet is a mirror,
not a second definition — when they disagree the code is right and this
block is stale.) `hash` was a `String` in RK-1 on purpose: a hex-serde
newtype for one field is pre-provisioning. RK-3 — block headers, where
hashes multiply to six fields — introduced `HashHex` and migrated this
field to it, per **RK-D10** below.

Rules, all test-pinned in the crate: field names are the wire names; `u64`
serializes as a JSON number (epee does); hashes are lowercase hex strings
(epee `pod_to_hex`); `KV_SERIALIZE_OPT(f, d)` becomes
`#[serde(default, skip_serializing_if = "is_<d>")]`; **an empty sequence is
dropped from the document even when its member is a plain `KV_SERIALIZE`** —
`get_block`'s `tx_hashes` vanishes for a block with no transactions, which is
not an OPT declaration but epee's treatment of empty arrays, so it too needs
`skip_serializing_if` (captured, not assumed: RK-3b's `no_txes` vector);
unknown fields are **refused** on deserialize (`deny_unknown_fields`);
`status` is a typed newtype so `"OK"` / `"BUSY"` / free-text errors are one
type, not three string constants in three crates.

**On unknown fields** (corrected 2026-08-29; this section previously required
the opposite — "tolerated on deserialize, no `deny_unknown_fields` —
older/newer wallets" — and a slice implementing that rule now would be
implementing a retired one). The tolerance was justified by client skew across
a network that does not exist: pre-genesis every client ships with the daemon.
What it actually bought was a **renamed** field arriving unnoticed while the
name we look for defaults — a wrong value in the shape of a legitimate one, on
replies that feed proof verification. Refusing turns that into a parse error at
the boundary, and aligns this surface with the wallet-RPC params (F-1), where
an unknown key is `-32602` rather than a guess. Checked before changed: every
captured vector still parses with the denial on, so the types already model
everything the daemon emits.

Two carve-outs, both narrower than the old blanket rule. `SubmitVerdict`
(`shekyl-rpc-types::lib`) keeps its tolerance because a verdict arrives
**mid-submit**, where a daemon and wallet from different in-tree builds must
still agree on whether the transaction was accepted — failing that parse turns
an informational field into an ambiguous submit, which §2.3's skew design
exists to prevent (`skew_c` pins it). And denial does **not** close silent
defaults: `#[serde(default)]` still lets an *omitted* field become its zero
value, which is its own audit (FOLLOWUPS) because some absences are legitimate
`KV_SERIALIZE_OPT` omissions the vectors depend on.

### 3.2 Facts — the C export and its twin

```c
// src/rpc/rpc_facts_ffi.h (C ABI; daemon-only, linked through the daemon image)
typedef struct shekyl_rpc_chain_tip_facts {
    uint64_t chain_height;      // top block height + 1
    uint8_t  top_hash[32];
    uint64_t target_height;     // raw core target; "0 when synchronized" is the handler's rule
    uint8_t  synchronized;
    uint8_t  release_build;     // SHEKYL_VERSION_IS_RELEASE (build-generated, C++-owned)
    uint8_t  reserved[6];
} shekyl_rpc_chain_tip_facts;

int shekyl_rpc_chain_tip(core_rpc_handle* h, shekyl_rpc_chain_tip_facts* out);
// Hard-fork table: C++-owned view, explicit release.
typedef struct shekyl_rpc_hardfork_entry { uint8_t version; uint8_t reserved[7]; uint64_t height; } shekyl_rpc_hardfork_entry;
int shekyl_rpc_hardforks(core_rpc_handle* h, const shekyl_rpc_hardfork_entry** out, size_t* out_len, void** out_owner);
void shekyl_rpc_hardforks_free(void* owner);
```

RK-2 adds one more to the same family — the reply needs the tip and the hash
to agree, so it reads both in one call:

```c
typedef struct shekyl_rpc_block_hash_facts {
    uint8_t  hash[32];
    uint64_t chain_height;   // top block height + 1
    uint8_t  found;          // 0 when height >= chain_height; hash is then zero
    uint8_t  reserved[7];
} shekyl_rpc_block_hash_facts;

int shekyl_rpc_block_hash_at(core_rpc_handle* h, uint64_t height,
    shekyl_rpc_block_hash_facts* out);
```

Absence is **data** (`found == 0`), not a fault: a height past the tip is a
legitimate query outcome and becomes the method's `TOO_BIG_HEIGHT` refusal,
never a `FactsFault`.

**Variable-length facts are C++-allocated and released through a paired
export.** A fixed-size POD gets a layout twin and is copied out by value;
anything whose size the caller cannot know in advance — the hard-fork table
(RK-1), and RK-3b's block blob, tx-hash list and `json` string — is handed
back as `(pointer, length, opaque owner)` and freed by its `_free` twin, the
shape `shekyl_rpc_hardforks` / `shekyl_rpc_hardforks_free` already set. Rust
copies what it needs and releases the owner in the same function that
acquired it, so the free cannot be lost to an early return. **The export
clears the owner slot before anything can return**, including its own
argument validation: it is the one out-parameter whose stale value is
dangerous rather than merely wrong, because a caller reusing the variable
across calls would free the previous call's pointer a second time. One rule, one
mechanism: a second convention for the same problem is how a leak gets
written. The shim test drives the real acquire/release pair, not a stand-in.

**Atomicity is the shim's job.** Both reads happen under one acquisition of
the blockchain lock, because `Blockchain::get_block_id_by_height` takes none
and documents that a caller combining it with a height read must — and a miss
there is a *null hash*, not an exception, so the unlocked pair could answer 32
zero bytes as a successful block hash after a reorg. A facts export that can
report a value the chain does not hold is worse than one that is slower: any
export combining reads takes the lock (the mutex is recursive, and a shim that
takes no other lock cannot create an ordering cycle).

Twins in `shekyl-daemon-rpc/src/ffi.rs`; layout pinned both directions by
`tests/unit_tests/rpc_facts_ffi_roundtrip.cpp` (seed-derived per-field
values, the F26 pattern) — **every** POD in the family, which is what RK-D3
requires.

**An export is a thin adapter over a free function.** The `extern "C"` entry
point unwraps the handle; the body takes the core objects it reads
(`block_hash_at(Blockchain&, …)`), exactly as `daemon_submit::snapshot_facts`
does. That is what makes the decisions — bounds, lookups, classification —
reachable from a unit test with a controlled chain
(`tests/unit_tests/rpc_facts_shims.cpp`, a `BaseTestDB` under a real
`Blockchain`) instead of only through a live daemon. An export written as one
opaque block is testable only end-to-end, which is how a bound or a branch
ships unexercised; every new export takes this shape. (`shekyl_rpc_chain_tip`
is the one that does not yet: it reads `is_synchronized()` off the p2p payload
object, for which this tree has no double — RK-5 needs one for `get_info` and
takes it then.)

**Three states, three answers.** A facts export that can be absent needs
absence to mean one thing. For the block hash: past the tip is *data*
(`found == 0` → the method's `TOO_BIG_HEIGHT` refusal); in range and present
is the hash; in range and absent is neither — it is the store contradicting
itself, and it gets its own code (`-4`, logged and alertable) rather than
being folded into the too-big refusal, which would tell the caller their
height exceeded a tip it is below. Return codes: `0` ok, `-1` null handle, `-2`
core not ready, `-3` a core/P2P read threw (every export is an exception
barrier — logged in C++, a code to Rust, never an unwind across the C ABI,
which would abort the daemon). The shim reads; it does not decide.

**One lock is the rule; two locks are not.** RK-2 established that a facts
export combining reads takes `Blockchain::lock()` once, so the reply describes
one chain state. That rule stops at the pool boundary, and RK-4c is where it
first would have been overstepped. `get_transactions` reads the chain (split
blobs, per-tx height/timestamp/output-indices) *and* the pool (missing txes,
their details) — but the pool takes its locks in the opposite order:
`tx_memory_pool::check_for_key_images` holds `m_transactions_lock` and then
`m_blockchain` (`tx_pool.cpp:1500-1503`). A facts export that took
`Blockchain::lock()` first and then called a pool read would be the AB half of
an AB-BA deadlock against every pool path that already runs BA. The recursive
`epee::critical_section` makes re-entering the *same* lock safe; it does nothing
about two locks in two orders. So `get_transactions` matches the C++
handler's granularity — chain reads, then pool reads, unsynchronized between —
and names the race that granularity leaves rather than closing it with a lock
that would trade a stale answer for a hung daemon. **The rule is per
lock-domain, not per reply.**

**Which race, precisely** (corrected 2026-08-29; this paragraph previously said
"a tx mined between the blob read and the height read", which the landed shape
had already closed). A chain hit's blob, height and timestamp are read inside
one `CRITICAL_REGION_LOCAL(bc)` together with the tip, so those fields describe
a single chain state and cannot disagree with each other. The window that
remains is **between the two passes**: a transaction mined after the chain pass
missed it and before the pool is asked has left the pool and is not among this
reply's chain results, so it comes back as missed although the chain now holds
it. Absence is the only field that window can move — the alternative, a reply
whose fields describe two different chain states, is what the single critical
region prevents.
**Chain facts take an object; p2p facts take scalars.** The bodies above take
`Blockchain&` — and RK-4c's took the pool too — because a fixture can build
those: `BaseTestDB` under a real `Blockchain` via `BlockchainAndPool` is the
recipe every shim test uses. There is no equivalent for p2p, and not for want
of effort: `core_rpc_server::m_p2p` is a **concrete**
`nodetool::node_server<t_cryptonote_protocol_handler<cryptonote::core>>`, so a
double cannot subclass it, and the one harness in the tree that builds a
`node_server` (`tests/unit_tests/node_server.cpp`) instantiates it over
`test_core` — a different type, unusable here.

So the rule extends rather than bends: **a body takes what a fixture can build,
and takes everything else as values the adapter snapshots.** The p2p reads are
one-line getters (`get_public_connections_count`, the two peerlist sizes, the
outgoing count, `get_payload_object().is_synchronized()`) with their own
locking, so the thin `extern "C"` adapter reads them and passes integers and
bools to a body a test can drive with literals. Nothing is lost: the shim reads
and does not decide, and what it read is exactly what the body is given.

This also settles a debt RK-5a must pay rather than inherit.
`shekyl_rpc_chain_tip` predates the thin-adapter rule RK-2 established: it has
no free-function body at all, its logic sits inline in the `extern "C"` entry
point, and it reads `get_p2p().get_payload_object().is_synchronized()` there.
That is why it is the one facts export with no fixture — noted in §3.2 since
RK-1 and never fixed. RK-5a retrofits it to the standard shape, which is what
makes that slice a deliverable rather than a bare enabler.

### 3.3 Handler — behind a trait

```rust
pub trait ChainFacts: Send + Sync {
    fn chain_tip(&self) -> Result<ChainTip, FactsFault>;
    fn hardforks(&self) -> Result<Vec<HardFork>, FactsFault>;
}
pub fn get_height(facts: &dyn ChainFacts) -> Result<GetHeightResponse, RpcFault>;
pub fn get_version(facts: &dyn ChainFacts) -> Result<GetVersionResponse, RpcFault>;
```

Axum routes call these with the `FfiChainFacts` impl; unit tests call them
with an in-memory impl. `RpcFault` maps to the daemon's existing error
envelope (`status: "…"` on REST, `-32603`/`-32601` on JSON-RPC) — the same
codes the C++ path emitted for the same conditions, pinned by the oracle
vectors.

### 3.4 Console

The exported ABI (`src/shekyl/shekyl_ffi.h`, Rust in
`shekyl-daemon-rpc/src/console.rs`):

```c
int32_t shekyl_daemon_console_run(
    const char* const* argv, size_t argc,   // argv[0] selects the command
    void* rpc_server_ptr,                   // live core_rpc_server in-process, else NULL
    const char* address,                    // "host:port" as `shekyld <cmd>`, else NULL
    uint64_t timeout_secs,                  // remote-arm request bound
    uint8_t** out_ptr, size_t* out_len);    // text on OK, reason on ERR_REQUEST
// 0 OK · -1 ERR_NULL_PTR · -2 ERR_UNKNOWN · -3 ERR_REQUEST · -4 ERR_AMBIGUOUS_SOURCE
```

Exactly one of `rpc_server_ptr` / `address` is set (both → `-4`, refused
before either is touched). The live arm calls the native method directly;
the remote arm posts through `shekyl_daemon_ctl_post`'s transport and
renders the typed reply. RK-1 renders `print_height`; each later slice adds
its commands here and deletes the C++ bodies, which become one-line
forwards until RK-C removes the C++ console. `shekyld <cmd>`'s exit status
still derives from the sticky failure flag (#533): a non-zero return sets
it.

### 3.5 Oracle vectors

Commit *N* of a slice adds a C++ unit test that builds the `COMMAND_RPC_*`
response from **fixed facts** (not a live chain), epee-serializes it, and
writes the result into `tests/vectors/rpc/<method>.{json,bin}` when run
with `SHEKYL_WRITE_RPC_VECTORS=1`; the vectors are committed. Commit *N+1*
deletes the C++ handler, struct and dispatch rows; the Rust test feeds the
same fixed facts to the native handler and asserts parsed-equality (JSON)
or byte-equality (`.bin`) against the committed vector. The vector is the
contract's memory of the C++ oracle after the oracle is gone — stored as
the bytes epee produced (its JSON pretty-printer emits CRLF), with the
directory marked `-text` in `.gitattributes` so no platform's checkout
rewrites them; RK-D4 makes that whitespace non-contractual, so nothing
downstream depends on it either way.

---

## 4. Per-slice gate (every slice, no exceptions)

1. `cargo fmt --all -- --check`; `cargo +1.94.0 clippy --workspace --all-targets -- -D warnings`; tests for `shekyl-rpc-types`, `shekyl-daemon-rpc`, `shekyl-rpc-client` (and any consumer switched to the shared type).
2. Layout-twin test for every new facts POD (both directions, edge seeds).
3. Oracle vectors committed **before** the C++ deletion commit; Rust parity test green after it.
4. Full CMake build; the RPC/daemon unit-test subset; the route-table / restricted-list spec tests updated in the same commit as the route.
5. Live: a testnet `shekyld` answers the migrated method through the control client *and* through `curl`; the deleted C++ symbols are gone (`git grep` for the struct name returns only this document and the CHANGELOG).
6. CHANGELOG entry per slice; this document's §2 row stamped **landed (PR #, sha)**; `DAEMON_RPC_RUST.md`'s reachability table updated.

---

## 5. Deletion register (what dies, when)

| Item | Dies in | Condition |
| --- | --- | --- |
| `COMMAND_RPC_GET_OUTPUTS`, `_BIN`, `COMMAND_RPC_FAST_EXIT` (no dispatch row, no handler) | RK-1 | rule 15 — dead at `077d97c4e` |
| `on_get_height`, `on_get_version`, their structs, 3 dispatch rows, console bodies for `print_height` / `version`; `CORE_RPC_VERSION*` in C++; `rpc-client::HeightResponse` | RK-1 | oracle vectors committed first |
| each slice's handlers / structs / rows / console bodies / client duplicates | its slice | same |
| `rpc_target_wire_contract.cpp` | RK-5 / RK-7 | re-pinned in Rust (RK-D9) |
| ~~`build_get_blocks_by_height_req` / the hand-rolled response decode~~ | **done** (RK-4b, 2026-08-25) | it hand-builds `{heights:[u64]}` and walks the reply for block blobs, which is the typed command map's job once one exists. Its known-good shape is RK-4a's first cross-language KAT. The trigger is RK-4b's merge and the deletion rides in that PR: a removal scheduled for "after" a slice is a deferral with a date, not one with a trigger |
| `tx_memory_pool::m_added_txs_by_id` | when its last reader goes | RK-4x left it: two log lines read its `.size()` (`tx_pool.cpp:410`, `:533`), so it is not read-less. It is a per-txid record of *arrival* times, kept now only to print a count — retire it with those log lines, or replace the count with one the pool already knows |
| `/get_transaction_pool_hashes.bin` + `COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN` | **done** (2026-08-25) | the binary spelling of a route that is called; this one had no caller. Both handlers made the same two core reads and differed only raw-vs-hex, so the surviving JSON route keeps them and nothing went callerless. Found by `ci/rpc-route-liveness`; reopen clause in `DAEMON_RPC_RUST.md` |
| the `rpc_origin()` context (`core_rpc_ffi.cpp`) | RK-X | it exists because C++ handlers read a `connection_context*` to learn their own listener's posture. Every migrated handler takes the posture from `state.restricted` instead (RK-D6), so the last bridged handler takes this with it |
| **RK-6's scope: the whole pool trio, or only `get_transaction_pool_stats`?** | decide when RK-6 is scoped | The ordering above only binds if `/get_transaction_pool` and `/get_transaction_pool_hashes` leave C++ in RK-6. If they survive it, the REST leg keeps a subject either way and the order is free. §2's RK-6 row lists all three, so the row says they go together — but that is the row, and this document has been wrong about a row three times. Confirm against the tree when RK-6 is cut |
| `print_transaction_pool_stats`' bridged `get_transaction_pool_stats` leg (REST) | **RK-6** | §2.1.1 — the console command moves in RK-5c reading a route RK-6 still serves. RK-6 must re-point it when it deletes that route, or the in-process console gate goes red |
| `show_status`' bridged `mining_status` leg (REST) | **RK-7** | same, for the mining slice |
| `alt_chain_info`'s bridged `get_alternate_chains` leg (**JSON-RPC**, not REST) | **RK-8** | same, for the admin slice; note the different bridge entry point |
| the origin guard's `dispatch_json` leg — re-anchored on `include_sensitive` rather than a symptom | **RK-5c, in its own diff** | RK-5c retires `/get_info`, which is `dispatch_json`'s only remaining subject after RK-4c re-anchored on it, so the replacement must exist **before** the route leaves — not after, which is the shape that half-survived from RK-4c. The pool trio is the only `DJSON` surface that outlives RK-5, and it has no request caps, so the assertion cannot be a cap: it is that a transaction the node has not broadcast is absent from `/get_transaction_pool_hashes` and `/get_transactions` on the restricted listener and present on the admin one. That needs the **two-node regtest** (§7, 2026-08-27) — a single node measured the window shut on one run in three, and `do_not_relay` cannot supply a second subject because it cannot exist in this tree |
| ~~`core_rpc_server::get_connections_count()`~~ | **done** (RK-5a) | `{ return 0; }` since the Axum cutover, because C++ cannot see Axum's connections; the Rust tracker fills `rpc_connections_count` over the top of it. Worse than a plain stub: `on_get_info` reads `restricted ? 0 : get_connections_count()`, so **both arms are zero** — before #570 that was dead-looking dead code, and after #570 it is a live conditional with identical arms, which reads to an auditor as an intact restriction gate. Delete the member and write the constant with its reason; do not carry it into the facts POD. **Discharged:** the member is gone and `on_get_info` writes `res.rpc_connections_count = 0` with the reason beside it; the literal goes when `/get_info` moves in RK-5c |
| `print_net_stats`' bridged `get_limit` leg (REST + the live arm's `json_endpoint`) | **RK-8** | §2.1.1 — the console command moves in RK-5a reading a route RK-8 still serves, on **both** arms: `shekyld print_net_stats` posts to `/get_limit`, and the in-process arm reaches the same route through `CoreRpc::json_endpoint`. RK-8 must re-point both when it deletes the route. Covered by `ported_p2p_console_commands_answer_on_the_in_process_arm`, and the coverage was demonstrated, not asserted: pointing the leg at a non-existent route turns that test red |
| `GetLimitReplyProvisional` (`console.rs`) | **RK-8** | the two fields `print_net_stats` reads off `/get_limit`, declared locally because the shared type does not exist yet. It is replaced by `shekyl-rpc-types`' `GetLimitResponse` when RK-8 writes one — not left as a second definition of a type that then has two |
| ~~the `else` arm of `on_get_base_fee_estimate` and `Blockchain::get_dynamic_base_fee_estimate`~~ | **RK-5b** | `HF_VERSION_2021_SCALING` is 1 and `HardFork` is constructed with `original_version = 1` on every network, so `version >= HF_VERSION_2021_SCALING` is a tautology and the arm cannot run — for all time, not just at the shipped table, since versions only increase. The `Blockchain` method has that arm as its only caller and is callerless the moment it goes, so both die in the same diff (rule 15/60) |
| `hard_fork_info`'s voting **machinery** (`HardFork`'s threshold accounting, rolling window, per-height version) | **R4** (§10, "Header identity + hardfork collapse") | **not RK-5b's, and named here so it is not taken by accident.** CEN-B2 and CEN-B3 are bucket 4 and explicitly deferred to that round, which carries the V4 lattice-only activation question. RK-5b ports the RPC method as a faithful projection of what the daemon reports and re-expresses none of the semantics, so whichever way R4 rules, this slice's output needs no rework |
| `print_blockchain_info` / `print_blockchain_dynamic_stats` / `alt_chain_info` / `show_status` bridged `get_info` legs | **RK-5c** | §2.1.1 — all four console readers of RK-5b's methods also read `get_info`, so each moves in RK-5b carrying exactly one bridged call to a route the C++ table still serves, and RK-5c re-points them when it retires that route. `alt_chain_info` additionally carries `get_alternate_chains` (RK-8) and `show_status` `mining_status` (RK-7); those already have their own rows above. Every one is covered by the in-process console gate, which is the condition that makes a bridged leg safe rather than a promise |
| ~~`connection_info` (`cryptonote_protocol_defs.h`) and its `json_object` (de)serializer pair~~ | **done** (RK-5a) | rule 15, and the chain is worth recording because each link was checked rather than assumed. Retiring `on_get_connections` and `on_sync_info` left `t_cryptonote_protocol_handler::get_connections()` with zero callers; deleting that left `connection_info` read only by `toJsonValue`/`fromJsonValue` in `json_object.cpp`, which nothing in `src/` or `tests/` calls. So the struct, the protocol-handler method and the serializer pair all went together, along with the mirroring stub in `tests/unit_tests/node_server.cpp` — a payload-handler double whose `get_connections()` satisfied an interface requirement that no longer exists |
| ~~`connection_info::ssl` and the console's SSL column~~ | **done** (RK-5a) | it had **no `KV_SERIALIZE` row**, so it never reached the wire, and `print_connections` printed a column from it — always `no` over RPC, where the field arrives default-constructed. It could not have been anything else: the p2p listener is initialized `e_ssl_support_disabled` and the outbound `m_ssl_support`'s only assignment is the same value, so `cntxt.m_ssl` is false by construction. A column that can only say one thing is not information (§7) |
| ~~`txs_as_hex` / `txs_as_json`~~ | **done** (RK-4c) | rule 60 — the handler fills them "in case an old wallet asks" and the old wallet is `src/wallet/`, deleted. Both in-tree readers go with them **in the same diff**: `print_transaction`'s `res.txs_as_hex.front()` fallback (dead against our own daemon — the handler fills `txs` and `txs_as_hex` from the same loop, so `txs` is empty only when `txs_as_hex` is) and `scripts/check_testnet_genesis_consensus.py`, which reads `txs_as_hex[0]` and gets `txs[0].as_hex`. Deleted **after** byte-parity is green, as its own commit, so the divergence bisects separately |
| `obj_to_json_str(t)` / `obj_to_json_str(pruned_tx)` and the `as_json` field of `get_transactions` | RK-W | the same call as the `get_block` row below, on the tx path (RK-D11). It duplicates `as_hex` / `pruned_as_hex`, which carry the same tx in the consensus encoding every in-tree client already parses. RK-4c keeps it epee-rendered rather than growing a second renderer that must agree with the first |
| ~~the hand-rolled `get_transactions` params + response walk, and the `is_key_image_spent` pair~~ | **done** (RK-4c) | same trigger discipline as RK-4b's `build_get_blocks_by_height_req`: a removal scheduled for "after" a slice is a deferral with a date, not one with a trigger. Their known-good shapes are the slice's first cross-language KATs |
| `shekyl-rpc-client`'s hand-rolled `get_fee_estimate` params + decode (`DaemonClient::get_fee_estimates`) | RK-5 | travels with the method, which moved to RK-5 on 2026-08-26 (§7). Named here so the move does not lose it |
| `obj_to_json_str(blk)` and the `json` field of `get_block` | RK-W | the last epee *rendering* on the RPC path (RK-D11). It duplicates `blob`, which carries the same block in the consensus encoding every in-tree client can already parse |
| `block_header_response`, `fill_block_header_response`, and `core_rpc_server::get_block_reward` | RK-5 | the four remaining header methods move. `get_block_reward` is a private third copy of `cryptonote::get_outs_money_amount` whose name collides with the consensus `cryptonote::get_block_reward(median_weight, …)` (subsidy, not a coinbase sum); its single caller is `fill_block_header_response`, so it dies with it. Nothing new calls it — RK-3's facts export uses `get_outs_money_amount`. |
| `src/daemon/rpc_client.h` (#533) + the C++ executor/parser/command server | RK-C | every console command renders in Rust |
| `core_rpc_server.{h,cpp}`, `core_rpc_server_commands_defs.h`, `core_rpc_ffi.cpp` dispatch + `core_rpc_ffi_json_endpoint` / `_bin_endpoint` / `_json_rpc`, `rpc_handler.*`, `json_object.cpp` RPC arms, `message_data_structs.h` RPC half; FOLLOWUPS dual-list item | RK-X | zero C++ handlers left |
| every `shekyl_rpc_*_facts` shim | post-DRS-E | Rust store impl of each facts trait lands (RK-D7) |

---

## 6. Non-goals and reopen clauses (rule 21)

- **Not** a wire redesign. Method names, aliases, field names and defaults
  are preserved, and a slice that changes one reopens per method with its own
  bump and CHANGELOG operator-impact line.

  **Baseline as of 2026-08-29: `CORE_RPC_VERSION` is 3.25**, not the 3.22 this
  clause first recorded. Two slices took the reopen this clause offers rather
  than breaking it: RK-3 (→ 3.24) and RK-4c (→ 3.25, retiring
  `get_transactions`' `txs_as_hex` / `txs_as_json` under rule 60 — the handler
  filled them "in case an old wallet asks" and that wallet, `src/wallet/`, is
  deleted). A stated baseline that stops tracking the constant reads as a
  freeze, so it is updated here rather than left for a future slice to trip
  over.
- **Not** the P2P path. `portable_storage` on Levin, `cryptonote_protocol_defs.h`'s
  P2P structs and the peerlist are LV-2/LV-3's.
- **Not** the chain store. Facts shims read today's LMDB through core; the
  store swap is DRS's and RK-D7 is the seam that keeps the two independent.
- **Not** a new RPC surface for the wallet. If a slice finds a wallet need the
  current contract cannot serve, it is filed against the wallet plan, not
  added here.
- **Reopen RK-D5 (console in Rust)** only if a console command is found
  whose rendering needs C++-only state with no facts path — name the state.
- **Reopen RK-D9** with a named consumer of epee's whitespace form.

---

## 7. Decision log

| Date | Entry |
| --- | --- |
| 2026-09-01 | **RK-5b scoped against the tree, and the tree corrected two things the row assumed.** The slice is `get_last_block_header`, `get_block_header_by_hash`, `get_block_headers_range`, `hard_fork_info` and `get_fee_estimate` (whose handler is `on_get_base_fee_estimate` — a C++ name that never matched its route). Branched from `dev` 86a29b2c1, which is past #587 and #582; **verified rather than assumed** that #587's p2p-wire deletions left RK-5a intact — all twelve `connection_context` fields the facts adapter reads survive, and RK-5a never read the two that went. **(1) The origin-guard inventory holds.** Eight `caller_is_restricted` sites remain and they partition exactly as §7's 2026-08-29 entry predicted: `on_get_info` (RK-5c), the pool trio (RK-6), the three header methods here, and `on_get_output_histogram` (RK-8). RK-5b retires three, leaving the histogram as `dispatch_jsonrpc_we`'s **only** subject — the first time that template is down to one. Neither `hard_fork_info` nor `get_fee_estimate` has a restricted branch. **(2) `get_fee_estimate` has an unconditionally dead arm, and it is not the one the name suggests.** `on_get_base_fee_estimate` branches on `version >= HF_VERSION_2021_SCALING`, and `HF_VERSION_2021_SCALING` is **1** while `Blockchain` constructs `HardFork` with `original_version = 1` at all three of its call sites — so the comparison is a tautology on every network, FAKECHAIN included, and the `else` arm cannot run. Not merely dead at the shipped single-entry table (CEN-B1): dead for all time, because hard-fork versions only increase from `original_version`. That makes it a plain rule-60 removal rather than something entangled with the R4 hardfork round, and it strands `Blockchain::get_dynamic_base_fee_estimate` — one caller, this arm — which goes with it in RK-5b's own diff, the shape RK-4c set with `get_split_transactions_blobs`. The live arm resizes `fees` to 4 before indexing, so the `res.fee = res.fees[0]` beside it is safe and is carried as the C++ emits it. |
| 2026-09-01 | **`hard_fork_info` is ported as a projection, and that is a ruling rather than a preference.** Coordinated with the P2P/census steering session before starting (which also refuted a routing that would have pulled two `src/p2p/p2p_protocol_defs.h` deletions into this slice — they were dead since 2020 upstream, not stranded by RK-5a, so RK-5b declines them). The binding input: **CEN-B1 is bucket 2 but CEN-B2 and CEN-B3 are bucket 4**, both queued in the §10 R4 round that owns collapse-vs-redesign of the whole hard-fork subsystem with the V4 lattice-only activation question attached under rules 75/21. CEN-B3 says it outright — "delete the machinery or keep as scaffold — a design round's call, not the census's". So the census's own rule applies: C++ is a differential oracle only for **ratified** rows, and these are not. RK-5b therefore snapshots what `get_hard_fork_voting_info` returns and carries it verbatim onto the wire — **no threshold accounting, no window arithmetic, no vote predicate re-expressed in Rust.** The reasoning worth keeping is the asymmetry: a Rust reimplementation of the voting machinery is work R4 would have to undo if it collapses the subsystem, while a faithful projection survives either ruling. The C++ handler is already shaped this way, so this costs nothing now and buys optionality later. The one piece of logic that does move is request policy rather than consensus: `version = req.version > 0 ? req.version : get_next_hard_fork_version()` is "which version did you mean", and it goes in the free function over `Blockchain&` where a fixture can drive both arms. |
| 2026-09-01 | **Three review rounds found the same class, so RK-5a stops patching instances and gates the class.** Unchecked integer arithmetic on daemon-reply values produced a finding in each of rounds 1, 2 and 3 — the connection-speed cast, four accumulations in `sync_info`, then `limit_kb * 1024` in `print_net_stats`, one function away from the accumulations that had just been swept. The pattern is not carelessness about any one line; it is that fixing the instance in front of you leaves the mechanism intact. `#[deny(clippy::arithmetic_side_effects)]` now sits on the ten functions that render or project remote-supplied numbers — the six console renderers plus `project_connection`, `render_overview`, `kib_per_second` and `round_half_up`. Scoped to those rather than crate-wide on purpose: crate-wide flags 32 sites, most of them a self-contained date algorithm whose bounds are already argued, and 32 "this one is fine" annotations is the convention theater rule 47 warns about. Scoped, it flagged **four**, and all four became total *by construction* rather than annotated — `checked_div(...).unwrap_or(0)` in place of an `if seconds == 0` guard, `saturating_sub` in place of a guarded subtraction — so the gate carries **zero suppressions**. That distinction is the point: a guard is a thing a later edit can move away from its division; `checked_div` is not. Demonstrated rather than asserted — restoring `limit_kb * 1024` is a clippy error, which CI's `-D warnings` makes a build failure. |
| 2026-09-01 | **An `OPT` default that is not the zero value makes "empty body" and "`{}`" two different requests, and RK-5a is where that first mattered.** `dispatch_json` value-initializes its request and then deserializes **only if the body is non-empty** (`core_rpc_ffi.cpp`: `if (body_json && body_json[0])`). So a `KV_SERIALIZE_OPT(field, default)` whose default is not the value-initialized one resolves *differently* depending on how the caller omitted it: bodyless takes the zero, `{}` takes the declared default. `/get_peer_list`'s `public_only` is `OPT(…, true)`, so a bare `curl` got the **whole** peerlist and `-d '{}'` got the **public** subset — one route, two questions. Native Rust has no such split: an absent body and an absent field both mean `Default`, which is the declared default. That is the right resolution — the split was an artifact of a body-length guard, not a contract — but it **is** a behaviour change, and it had a live consumer. `utils/fleet/read_anon_histogram.sh` sends a bodyless `curl` and its own comment says it is counting *stored anonymity candidates*; narrowing that to the public subset would have changed what a Q12 measurement instrument reports without changing what it claims to report. The script now asks for `public_only: false` outright, in this PR, because a producer and its caller travel together. **The check this creates for later slices:** when migrating a method, list its request's `OPT` defaults and flag any that is not the zero value — that is the only shape where this bites, and `public_only` is the first one the cutover has met. Found by Copilot on #585; the caller was found by grepping for it rather than by trusting that none existed. |
| 2026-08-31 | **RK-5a landed: four p2p methods native, and five things the C++ was doing that the port would not.** `sync_info`, `get_connections`, `/get_net_stats` and `/get_peer_list` answer from Rust; their handlers, structs, dispatch rows and console bodies are deleted, and so is the C++ that only they reached. The seam's rule got its second half — `m_p2p` cannot be doubled, so the adapter **transcribes and computes nothing**, and every derivation moved to Rust where a test can reach it. Writing those derivations down is what surfaced the rest. **(1) One clock, not two.** `get_connections` called `time(NULL)` once for the idle times and again for the averages, so a connection could report a `live_time` that disagreed with the divisor behind its own `avg_download`. The export reports one `now` beside the list. **(2) Elapsed values saturate**: a clock that moves backwards made the unsigned subtraction wrap into an idle time of some hundreds of years. **(3) Two undefined float→integer casts**, one found in review. `(uint32_t)(x + 0.5f)` on the span `rate` is undefined for a negative or out-of-range float, and `rate` comes from measured bytes over measured intervals; `round_half_up` clamps. Copilot then found the second, which the first pass had left in C++: the per-connection `current_speed_*` are `double`s the rate estimator writes, and the adapter was truncating them with `static_cast<uint64_t>` before they crossed. The fix is the slice's own rule rather than a clamp in C++ — the truncation is a **derivation**, so the raw `double`s cross and `kib_per_second` clamps them beside `round_half_up`, which also makes the answer `trunc(x / 1024)` rather than `trunc(trunc(x) / 1024)`, as the C++ computed it. **(4) The overview's gap run had no ceiling** — `(start - expected) / nblocks` underscores, where `start_block_height` follows peer-advertised heights, so the length of a display string was a function of what a peer claimed. Clamped at 128, which is the one output this slice deliberately changes. **(5) `connection_info::ssl` was never on the wire** and drove a console column that therefore always read `no`; p2p SSL is structurally disabled, so the column could not have said anything else. Deleted with the field (§5). **No `CORE_RPC_VERSION` bump**: every reply's field set was compared before and after on two connected regtest nodes and is identical (23 keys on `connection_info`, 6 on `sync_info`, 6 on `/get_net_stats`, and the same omissions when empty), and the four behavioural changes above are value edge-cases, not shape. **The gating test grew a column, and that is the entry worth reading twice.** RK-5a brings the first **admin-only** native methods, so `native_methods_are_never_gated` — which asserted a constant — was about to assert something false. It is `native_methods_are_gated_exactly_as_specified`, per-name and in both directions: a public method that became gated is a route the wallet loses, and a gated one that became public is peer topology served to anyone who asks. `sync_info` lists this node's peers and `get_connections` *is* the connection table, so the second direction is mission #2, and migrating a method out of C++ moves it past exactly this gate. **Two constants cross the FFI rather than being restated**: the peerlist capacities and the span pruning-stripe label, both through handle-free exports — handle-free because `shekyld <command>` renders against a *remote* daemon with no core to ask, so anything a renderer needs from C++ configuration has to be reachable without one. **`print_net_stats` is the slice's one §2.1.1 crosser**, reading `/get_limit` (RK-8) on both arms; §5 carries the re-point row, and the console e2e was shown to catch a dead route rather than assumed to. |
| 2026-08-29 | **The origin guard's subject inventory, enumerated once so the countdown stops being rediscovered.** Eight `caller_is_restricted(ctx)` sites remain (down from eleven: #570 took `relay_tx`'s, RK-4c took two), and they partition the guard's future exactly. **`dispatch_json`:** `on_get_info` (RK-5c) and the pool trio (RK-6) — nothing else. **`dispatch_jsonrpc_we`:** the three header methods (RK-5b) and `on_get_output_histogram` (RK-8). So RK-5b retires the `get_block_header_by_hash` leg and leaves the histogram as that template's only subject, and RK-5c retires the `/get_info` leg and leaves the pool trio as `dispatch_json`'s only candidates. **`/get_peer_list` has no restricted branch**, checked rather than assumed, so RK-5a removes no subject — it is the one slice in this arc that costs the guard nothing. The prerequisite this creates is written into §5 against **RK-5c's own diff**, not as a follow-on, because a follow-on is what half-survived from RK-4c: the sensitivity assertion on the pool routes is what must exist before `/get_info` stops being bridged. |
| 2026-08-29 | **The rule-47 sweep has never been applied to the consensus scripts, and there is one confirmed instance.** The dead `/json_rpc` envelope the 2026-08-29 ultrareview found in `check_testnet_genesis_consensus.py` is rule 47's exact shape — a check whose subject was never there, since no JSON-RPC table ever dispatched `get_transactions` on this bridge, so the call answered "Method not found" before reaching the field the script read. It is at least the fourth instance in this arc and **the first outside CI**: the sweep has covered gates and workflows, and `scripts/` has been treated as if it were not instrumentation. It is. Named here as a known gap with one confirmed instance rather than swept now, because a sweep of every script is its own validation surface (rule 19) and would ride into a p2p seam slice on nothing but proximity. |
| 2026-08-29 | **Ultrareview round: four corrections, one of them the review's own class one turn later.** (1) **The refusal test pinned the wrong guard.** `a_refusal_carrying_a_body_is_refused_not_parsed` documented a body "built to clear every check downstream of the status" while labeling it with an invented txid, so with `refuse_unless_ok` deleted the call died at `parse_tx_batch`'s body-identity check — red on the regression, but pinning the *binding* while claiming to pin the *status guard*. This is the stale-docstring class this round swept in prose, caught in a test's own comment; the txid is now derived from the body and the honest red was observed (guard commented out → the call **succeeds**). (2) **The release checklist's consensus script wrapped `get_transactions` in a `/json_rpc` envelope** — a method no JSON-RPC table ever dispatched on this bridge, so the RK-4c field-name update sat on a call that answered "Method not found" before reaching it. It now POSTs to `/get_transactions`; the sweep confirmed it was the only enveloped caller in-tree. (3) **LMDB v10 → v11**: `prune_tx_data`'s corrected retention is a requirement pre-fix datadirs violate — one pruned by the buggy window (2026-08-22 → 2026-08-29 on `dev`) opens silently and answers `INCONSISTENT` for every previously pruned tx, forever — so the refusal moves to open-time per the schema file's own policy. (4) **The pruned identity gets its first cross-language KAT.** Every Rust test derived its expected pruned txid from `hash_with_supplied_prunable` itself, so a component-order error would leave fixtures and checks agreeing on the same wrong value — green in-tree, while every real daemon reply fails "a label is not an identity". `pruned_tx_hash_parity_v1.json` pins the 4-part PQC-spend arm (Rust-authored bytes; the C++ leg reproduces bytes, txid, prunable digest and the `serialize_base` framing with production functions), and the serve-credit parity pair gains the same assertion on the 3-part arm. The **live-oracle** spend KAT stays deferred on its named blocker, now in `FOLLOWUPS.md` rather than only in code comments. |
| 2026-08-29 | **The status banner was two slices stale, and a class sweep is what found it — after the sweep method was corrected.** Rick's observation: a grep matches *lines*, but a claim's status lives in the enclosing block, so a hit under a `DO NOT USE / this is the old spec` banner reads as live. Auditing this PR's own seven-statement sweep found no corrupted record, but the inverse sweep — the old claim under phrasings the grep did not spell — returned `gf7_sealing_run.rs`'s *"the grader trusts the label; a mislabeled row would be undetectable downstream"*, which is verbatim the vulnerability this slice closes and is in fact **the parenthetical justifying why the arm is bound by construction**. Editing it would have rewritten the sentence documenting a fix into a claim the fix was missing. That is a **third** category beside rule 91's *asserts-is* and *records-was*, and rule 91 gained it. **The repo already had the right mechanism and this author was not using it:** rule 95's `Status:` banner exists precisely so a grep-driven reader classifies a file before its body — so the sweep step is *read the banner*, not `-B6`. Applying it here: this document's banner read **"design open for RK-4a"** while RK-4a (#555), RK-4b (#562) and RK-4c had all been written, and six merged rows (RK-1 #534, RK-2 #540, RK-3 #541, RK-3b #548, RK-4a, RK-4b) still carried the placeholder `PR #, sha stamped at merge`. Stamping is **step 6 of this document's own per-slice checklist** and it was skipped six consecutive times, which is the case for a gate rather than a firmer intention: `check_landed_rows_stamped.py` fails a row claiming `**landed**` whose PR number is unstamped. It binds **only** the knowable half — a merge sha cannot exist pre-merge, so RK-4c's row passes legitimately — and both failure arms were observed red (unstamped row → 1; no landed rows → 2, rule 47) before the green was trusted. 59 landed rows across `docs/design` and `docs/completed` now stamp clean. **The gate's first red was this very log row**, which quotes the placeholder in a code span: a checker that cannot tell a string being *named* from one being *used* repeats the defect it was built to catch, so it strips code spans before matching — the same naming-vs-using distinction the sweep method needed, this time enforced rather than remembered. |
| 2026-08-28 | **RK-4c landed**: `/get_transactions` (+ `/gettransactions`) and `/is_key_image_spent` served natively, with `print_tx` and `is_key_image_spent` rendering in Rust on both arms, and the C++ handlers, structs, dispatch rows and both restricted caps deleted. The facts export is **indexed by request position** rather than batched-then-re-sorted, which deletes the C++ merge and the two internal errors that existed only because that merge could disagree with itself (`tx hash mismatch`, `internal error - txs is empty`). `entry`'s branching KV map is a **type** — `TxLocation::Mined \| Pooled`, with `in_pool` derived from the arm — so the flat six-optional-members shape, which round-trips every vector while still able to emit documents the daemon cannot produce, is unrepresentable. **The one-lock rule is per lock-domain, not per reply**: the pool takes `m_transactions_lock` before `m_blockchain`, so the chain reads take `Blockchain`'s lock once (tip included, so confirmations are computed against one height) and the pool is asked afterwards, unsynchronised — the C++ handler's granularity and its race, named rather than closed by a lock that would trade a stale answer for a hung daemon. **Corrected 2026-08-29:** §3.2 named the wrong race — the blob/height/timestamp/tip reads share one critical region, so the window is between the chain and pool *passes* (a tx mined in it is reported missed), not inside the chain pass. **Deliberate divergences:** the reply's `tx_hash` is canonical lower-case rather than an echo of the request's casing; `txs_as_hex` / `txs_as_json` are retired under rule 60 with `CORE_RPC_VERSION` → 3.25; a `spent_status` outside 0/1/2 is a malformed reply rather than a fourth state. **Two things the slice found rather than assumed.** The canned daemon double in `proofs_tests.rs` had drifted — a `json!` literal naming four fields where the contract has nine — and twelve tests failed the moment the reader became typed; that file already carried a comment saying `get_height` is built from the wire type because a literal had drifted once before, so it has now happened twice for the same reason. And #570's e2e used `/get_transactions` over the cap as its REST evidence that `dispatch_json` passes a connection context; migrating the route makes that row exercise the *Rust* cap instead, so it was re-pointed at `/get_info`, which is still bridged and whose restricted arm is observable on an idle daemon. A migration silently weakening another slice's guard is the failure mode to watch for whenever a route leaves C++. **The C++ this slice replaced is deleted, not orphaned** (added 2026-08-28, found in review): retiring `on_get_transactions` left `Blockchain::get_split_transactions_blobs` and the `core::` wrappers `get_split_transactions_blobs` / `get_pool_transactions_info` / `are_key_images_spent[_in_pool]` with **zero callers**, and the first of those carries a pruning model that is wrong for Shekyl — it reads the prunable hash only when the prunable *blob* survived, and sets the hash to null when it did not, which is the exact inversion of `prune_worker`, and the same defect this slice corrected in the facts export. Leaving it callerless would be worse than never having written it: pruning-and-serving-from-archive has no Monero counterpart, so the inherited C++ is a **first draft of a Shekyl system**, and the next port reads a callerless first draft as the design. The underlying reads stay (`have_tx_keyimges_as_spent`, `check_for_key_images`, `get_transactions_info` — the facts shim calls the last two directly, which is what made the wrappers dead). `get_transaction_version` went with them, disclosed as **already** dead on `dev` rather than orphaned here: no callers and no header declaration, so nothing outside `blockchain.cpp` could reach it. |
| 2026-08-28 | **`Blockchain::get_split_transactions_blobs` is callerless after RK-4c, and it is where the pruning defect actually lives.** RK-4c deleted `on_get_transactions`, its only caller, leaving the `Blockchain` method, `core`'s one-line forwarder, both declarations and the explicit template instantiation with nothing reaching them. That is rule-15 residue on its own, but the reason to delete it rather than leave it is sharper: it is the code that reads `get_prunable_tx_hash` **only when the prunable blob survived**, and sets the hash to `null_hash` otherwise. `prune_worker` deletes `txs_prunable` and never `txs_prunable_hash` — retaining the hash after dropping the bytes is the entire point of storing it, since it is what still binds a pruned body to its transaction. The ported facts export inherited that pairing and it was corrected there (92807134a); the C++ it was copied from was not. **Pruning-and-serving-from-archive is a Shekyl system with no Monero counterpart, so the inherited C++ is a first draft of it, not an oracle for it** — which is exactly why a wrong first draft left in the tree is worse than absent: the next port reads it as the design. Delete the method, the forwarder, the declarations and the instantiation, in RK-4c, since RK-4c is what made it callerless. |
| 2026-08-28 | **RK-5 re-sliced into RK-5a/5b/5c, and §2.1 amended because the console read-graph forces it.** Scoping RK-5 against the tree rather than the row turned up three things the census did not say. **(1) The "p2p double this slice must build" cannot be built.** `m_p2p` is a concrete `node_server<t_cryptonote_protocol_handler<cryptonote::core>>`, so a double cannot subclass it, and the one harness that constructs a `node_server` does so over `test_core` — the wrong instantiation. The rule extends instead: a body takes what a fixture can build and takes everything else as **scalars the adapter snapshots** (§3.2). That dissolves the blocker and exposes the debt underneath it — `shekyl_rpc_chain_tip` never got the thin-adapter shape RK-2 established, which is why it is the one export with no fixture, and RK-5a retrofits it. **(2) `get_info` has seven console readers, not six**, and their read-graph's connected component spans RK-5, RK-6, RK-7 and RK-8 (`show_status`→`mining_status`, `print_transaction_pool_stats`→`get_transaction_pool_stats`, `alt_chain_info`→`get_alternate_chains`). No ordering satisfies §2.1 as written: land RK-6/7/8 first and *their* console commands mix on `get_info` instead. Mixing is unavoidable, so §2.1.1 amends the rule to permit a bridged leg, on two conditions that make it safe rather than a promise — the leg must name a route the C++ table still serves (RK-4c shipped one that named a deleted route and answered "no reply" every time), and each mixed command is covered by the in-process console gate, so the slice that deletes the route turns it red. Three §5 obligation rows carry the re-points. **(3) `get_info` migrates last in the family**, because the moment its route leaves C++ all seven console commands must already be in Rust; with RK-5a/5b landed, four move clean and the three crossers carry exactly one bridged call each, which is the minimum the graph permits. Also found while scoping: `get_connections_count()` is `{ return 0; }` and has been since the Axum cutover — the Rust tracker fills `rpc_connections_count` over the top of it — so it is residue and must not enter the facts POD. |
| 2026-08-28 | **Ordering: RK-6 goes LAST, and the recommendation this entry first carried was anchored on the wrong route.** The first version argued RK-6 before RK-5c to protect #570's `dispatch_json` origin guard. That guard asserts **request caps**, and `on_get_info` has none — it has field trimming — so the premise was wrong about what the guard's subjects are. Corrected, the argument inverts. The guard's REST subjects were `get_transactions`' and `is_key_image_spent`'s caps, both retired by RK-4c, which is why RK-4c re-anchored the REST leg on `/get_info`'s trimming (`start_time` → 0, `free_space` → `u64::MAX`) in its own diff and bite-checked it. **RK-5c retires that subject in turn**, and the only durable bridged REST surface after it is the pool trio — so keeping the pool routes bridged as long as possible is what keeps the REST leg anchored through the rest of the arc. **RK-6 last.** The console graph is indifferent at equal bridged-call count, so subject life is the only live tiebreaker. |
| 2026-08-28 | **The origin guard's subject decays at the migration's rate, and re-anchoring it per slice is the wrong fix — this is the third instance of that class.** Twice now a check has lost its subject to a migration while still passing: RK-4c's REST leg, and RK-5c's in advance. Re-pointing it each time works and is exactly what the RK-1 census rows and `DAEMON_RPC_RUST.md`'s liveness row did before decaying anyway. The durable answer is to anchor on the property the fix protects rather than a symptom of it: `include_sensitive`, not the caps. **That assertion needs a two-node regtest** — one node stems a transaction to another that holds it for the embargo — because a single node has no persistent non-broadcast state: the engine submit relays fire-and-forget, and the tight form found the window already closed on one run in three (§7, 2026-08-27). **`do_not_relay` is not available as the second subject**: it cannot exist in this tree — no RPC accepts the flag, `tx_pool.cpp`'s only writer of the meta field hardcodes 0, and `relay_method::none`'s only writer is a transient initializer `upgrade_relay_method` raises on the same path. The stem transaction is the whole of it. Owed **before RK-5c retires `/get_info`**, since that is when the current anchor goes. |
| 2026-08-27 | **The handler→pool argument cannot be covered by a single-node e2e, and the reason is a measurement, not an opinion.** Copilot's fourth-round finding is right that the coverage stops short of the link that matters: the cap test proves the handlers *see* a context, `rpc_restricted_disclosure` proves the DB's category filter excludes pre-broadcast transactions, and nothing asserts each handler passes `!restricted` into its pool read — so changing that argument back to `true` restores the whole disclosure with every test green. The suggested fix is a live test that puts a `local` or stem transaction in the pool and asks both listeners. **Built it; it cannot be made deterministic here.** The engine submit admits as `relay_method::local` and then relays fire-and-forget (`tx_pool.cpp` §"the engine path's relay"), so `set_relayed` promotes it out of `local` within milliseconds. Measured: at t=0 the restricted listener enumerated 0 and returned 0 by hash while the admin listener saw the transaction — the property holds and was **observed end to end** — and by t=500 ms both listeners saw it, legitimately. Repeating the tight, no-delay form three times, the window was already closed on **one of three runs**. A ~33 % flake on a privacy gate is worse than no gate: it trains the next person to re-run it. So the test is not shipped, and the residual is named with the condition that would close it rather than a date: **a two-node regtest where one node stems to another that holds the transaction in `stem`** gives a state that persists as long as the embargo, which a single offline node has no way to produce (`local` is transient by design, `stem` needs a peer, `none` is unreachable). Until then the link is held structurally — all four sites derive from the one `caller_is_restricted(ctx)` predicate — and that is a weaker guarantee than a test, which is why it is written here rather than implied. |
| 2026-08-27 | **"Defence in depth" was the wrong retraction; the arm should not exist.** Yesterday's correction established that `relay_tx`'s C++ `restricted` gate is unreachable, and kept it on the grounds that it would matter if the Rust gate were loosened. Rick's reading is better and it is rule 15's: **the check cannot hold in any reachable state**, so it is not a second line of defence, it is residue. The restricted listener never enters the function — Rust answers 403 at the only transport — and on the admin listener `m_restricted` is false, so `caller_is_restricted(ctx)` is false there too, as it is for the console's null `ctx`. A branch that is false in every posture that exists defends nothing. Nor is the loosening argument sound: `RESTRICTED_METHODS` is pinned against an independent specification list by `restricted_method_list_matches_the_specification`, so dropping `relay_tx` from it fails a Rust test — the guard is a test, which is observable, rather than a dead branch, which is not. Deleted, and the count in §2.2 goes from eleven sites to ten. **The scope of the claim is bounded by cross-referencing the two lists rather than asserted:** of the eleven methods with a C++ restricted check, `relay_tx` is the only one Rust gates per-method, so this is a one-site sweep, not a class with unknown members. The cost of leaving it is measured rather than hypothetical: this expression was read as a live exploit path by Copilot's review, by this author, and into a CHANGELOG entry and a PR description that both had to be retracted. **Residual C++ that cannot fire is not free — it is a false premise that survives review because it looks like a guard.** |
| 2026-08-27 | **A guard CI never runs is the previous entry's lesson one turn later.** Moving the assertion to the live-daemon harness put it on the production path, and left it `#[ignore]`d — the Rust lane builds no `shekyld`, so the only check that can see whether the dispatchers pass a context never executed, while the C++ tests that *do* run cannot see it by construction. The privacy regression could have merged green. Copilot named it. The fix costs one step and no extra build: `build-ubuntu` already compiles `shekyld` with `BUILD_TESTS=ON` **and** installs the Rust toolchain, so the gate runs there with `SHEKYLD_BIN` pointed at the tree it just built (~3 s). It is not in `test-ubuntu`, which consumes the packed artifact and installs no Rust by design. **The first draft of that step was itself a green no-op:** `--exact` matches the *full* test path, so the bare function name selected nothing, and `cargo test` reports "0 passed" and exits 0 when a filter matches nothing. Observed before trusting it — `running 0 tests`. The step now filters on `engine::regtest_e2e::…` and asserts `1 passed` from the output, because the subject's existence is the thing a filter can silently lose (rule 47). Both halves were verified: the gate passes on the real filter and refuses on the bare-name one. |
| 2026-08-27 | **The guard for a C++ boundary belongs on the production path, and that path is reachable from Rust.** The first cut tested `rpc_origin()` through two `extern "C"` hooks: an assertion that it answers non-null. Copilot's second round named the flaw exactly — reverting any dispatcher to `nullptr`, the regression the test advertised, left it green, because a unit test of a helper cannot observe its call sites. Rick's rule 20 answer is the same one from the other side: if any of this can move to Rust, it should. It can. `regtest_e2e.rs` already spawns a live `shekyld`, so the daemon now takes an opt-in second listener from `--rpc-restricted-bind-port` (which binds an *additional* server with `restricted = true` fixed — not `--restricted-rpc`, which would flip the main listener's posture and destroy the unrestricted control the same test compares against) and `restricted_listener_applies_request_caps_through_the_ffi_bridge` puts a real over-cap request to each posture — crossing the Rust HTTP handler, `core_rpc_ffi_json_endpoint`, the dispatch table and the C++ handler. It covers **both** surviving templates and says which: the REST rows cross `core_rpc_ffi_json_endpoint` into `dispatch_json`, and two JSON-RPC rows cross `core_rpc_ffi_json_rpc` into `dispatch_jsonrpc_we` — one refusal written into `error_resp` (the error envelope) and one into `res.status` (the result envelope), because that template has two answer shapes and a test of one does not hold the other. Reverting either template to `nullptr` and rebuilding turns it red on that template's own assertion. The first cut of this entry claimed the bridged boundary as a whole on the strength of the REST rows alone, which was the same overclaim one level up — Copilot caught it. **The third template is gone rather than covered:** `dispatch_jsonrpc` (the no-`error_resp` variant) and its `DJRPC` macro had zero table rows, so they were dead code the fix had been maintaining, and rule 15 deletes them. What remains uncovered by the e2e, named rather than implied: `dispatch_submitblock` and `dispatch_calcpow`, whose handlers read no `ctx` at all. The listener is opt-in rather than always-on because this harness is `#[ignore]`d: CI would not catch a regression introduced into the spawn every other e2e test shares. **Both C test hooks are deleted with it** — a test-only export in a production C ABI is rule 40's smell, and the property they held is now held where it is true. What stays in C++ is what only C++ can see: that the shared context is not a bannable host (otherwise every caller scores against one empty address), and that the relay-category filter excludes every pre-broadcast state. The general form, worth carrying: **a check that cannot observe the thing it names is decorative, and the fix is usually to move the check to where the thing is observable, not to make the check cleverer.** |
| 2026-08-26 | **`relay_tx`'s dead `restricted` is an action, not a disclosure, and is fixed with the same change.** `on_relay_tx` reads `(broadcasted = get_pool_transaction(txid, …, broadcasted)) \|\| (!restricted && get_pool_transaction(txid, …, all))` (`core_rpc_server.cpp:2088`). With `restricted` false-by-construction the second arm evaluates live. **What this entry first claimed — that an unauthenticated caller could therefore make the daemon relay a transaction it had not broadcast — is wrong, and Copilot caught it.** `relay_tx` is in `RESTRICTED_METHODS` (`handlers/json_rpc.rs`), the daemon's *second* restricted gate, and Axum is the sole HTTP transport since #533 retired epee's, so a restricted listener answers **403 `Method not allowed in restricted mode`** before C++ is reached. Measured: 403 on the restricted listener, and the C++ handler's own "transaction not found in pool" on the admin one. So the C++ arm is unreachable from the network in the posture that matters, and the fix here is **defense in depth**: it matters if that method list changes, if a transport is added, or when the handler migrates and takes its own posture. The lesson is the one this branch keeps re-learning — exploitability is a claim about the whole path, and I priced it from the C++ end without checking the gate in front of it. The arm then sets `relay_method::local` for anything not already broadcast, which walks straight into the Q12-D5a residual documented immediately below it: a transaction that has already rolled clearnet and is still stemming is remapped to `local` and re-decided onto the anonymity zone — the once-at-origin violation that residual names. That remains reachable by whoever *can* reach the method — the operator on the admin listener, which is the posture the residual was scoped for — so the fix narrows nothing there and closes the restricted path that was never open. It is listed apart from the read leak because the failure is different in kind: the pool endpoints told an adversary what the node was holding, this one let them act on it. One correction to how it was first described here: the *return value* does not separate "already broadcast" from "was not, relayed anyway" — both arms answer OK, and what a caller learns from the reply alone is in-pool-in-any-category versus not-in-pool. The enumeration endpoints are what turn that into a stem oracle; this one is the lever, not the sensor. After the fix a restricted caller reaches only the `broadcasted` arm, so a not-yet-broadcast transaction answers "transaction not found in pool" and is neither disclosed nor relayed. |
| 2026-08-26 | **The inert `ctx` was the whole dispatch surface, and the fix is one predicate rather than a repaired expression.** `dispatch_json`, `dispatch_jsonrpc` and `dispatch_jsonrpc_we` all passed `nullptr`, so `m_restricted && ctx` was false at all eleven sites §2.2 lists, whatever the listener was configured as. On the pool paths that is not a cap: the sensitive flag chooses `relay_category::all` over `::broadcasted` and the DB's iteration skips what does not match (`db_lmdb.cpp:2680`), so the flag decides *existence*, and the excluded set is exactly `stem` and `local` — still-stemming transactions and the node's own submissions before relay. **`do_not_relay` is not in that set**, though `relay_category::all` would carry it: it cannot exist here. Its only `relay_method::none` writer is a transient initializer `upgrade_relay_method` raises on the same path, no RPC accepts the flag, and the meta field's sole writer hardcodes 0 — which is what `blockchain_db.h` already says about the category. The fix passes a shared `rpc_origin()` context instead. **What it deliberately does not do is repair the two-term expression.** The sensitive sites spelled `allow_sensitive = !request_has_rpc_origin \|\| !restricted`, which is `!restricted` for all four `(ctx, m_restricted)` combinations — the extra term never changed an answer, and it is a trap: deleting the `&& ctx` conjunct, which is the obvious-looking cleanup, leaves `!request_has_rpc_origin` forcing `allow_sensitive` unconditionally true while reading exactly like a fix. So both terms are gone and all eleven sites derive from one `caller_is_restricted(ctx)` on the server. The half-repairable shape no longer exists. The idiom itself is inherited and worth naming as a class: upstream a null `ctx` meant "an internal call, trust it", and here the bridge is the only caller of nearly all these handlers, which silently inverts it to "trust everything" — rule 16's *inherited code is not inherited architecture*, in the specific form of a premise the port changed without changing the expression that rested on it. It is unlikely to be the only instance. |
| 2026-08-26 | **`get_fee_estimate` moves RK-4c → RK-5; RK-4c is the transaction read set.** §2.1's rule is that a console command can only move to Rust once *every* method it reads has a Rust type, and `get_fee_estimate`'s only console reader is `print_blockchain_dynamic_stats` (`rpc_command_executor.cpp:1975`), which also reads `get_info`, `hard_fork_info` and `get_block_headers_range` — all three RK-5. Migrating it in RK-4c leaves exactly the two outcomes RK-D1/RK-D2 forbid: a second C++ definition of the reply for the console to parse, or a console command that cannot be built. This is the `hard_fork_info` correction of 2026-08-22 one slice later, and the same remedy — its validation surface *is* `print_blockchain_dynamic_stats`'s, so it migrates when that command does. The move also keeps a subsystem intact: `get_fee_estimate` has fifteen engine-core consumers (`fee_estimator`, `fee_query`, `fee_snapshot`, `drain_facade`, `bond_orchestrator`, `submit_lifecycle`, …) plus `shekyl-rpc-client`, none of which RK-4c would otherwise touch. **Two census-column corrections found by enumerating instead of reading the row:** `C` was claimed for RK-4c and is false — `shekyl-cli` depends on `shekyl-wallet-rpc`, not the daemon RPC, and names none of the three methods; `F` was missing and is true — `shekyl-dev`'s stressnet (`shekyl_rpc/daemon.py`) calls `/get_transactions` and `get_fee_estimate`. What remains in RK-4c is one validation surface: the two methods the wallet's proofs path reads, each with a console command that reads *only* it. |
| 2026-08-24 | **RK-3b landed**: `get_block` (+ `getblock`) served natively, with `print_block_by_hash` / `print_block_by_height` — the two console commands that read only this method — ported alongside it, so no C++ caller is left holding `block_header_response` for a Rust-produced reply. New facts export `shekyl_rpc_block_at`, the first with variable-length payloads: blob, tx-hash list and epee's `json` are owned by one allocation and released by one `shekyl_rpc_block_free` (§3.2). `orphan_status` becomes a real value, and the alt-block quirk is pinned by a shim test rather than described. The console's rendering moved with the method: `AtomicUnits::to_skl_string` is byte-exact with `print_money`, the UTC timestamp keeps the `<unknown>` cutoff, and the difficulty is decimalised from the `0x` wide form as the C++ did by constructing a `difficulty_type`. |
| 2026-08-26 | **`core_rpc_ffi_free_buf` went with the endpoint that allocated it.** RK-4b deleted `core_rpc_ffi_bin_endpoint` and left the matching free, plus a header comment that still described binary endpoints returning buffers through it. No caller remained. The public C ABI now matches the cutover claim: JSON strings via `core_rpc_ffi_free_string`, and the facts exports' own owners for variable-length answers. | A free with no allocator is the next dead ABI. |
| 2026-08-25 | **The restricted block cap fires for the first time (deliberate divergence).** `on_get_blocks_by_height` computed `restricted = m_restricted && ctx`, and `dispatch_bin` — the only bridge that reached it — always passed `ctx == nullptr`. So the cap was dead through that path: a restricted listener accepted a request for any number of heights, and `RESTRICTED_BLOCK_COUNT` guarded nothing. The Rust handler applies it. That is a **behaviour change, not parity**, and it is recorded as one rather than described as preservation: the constant and the check both existed and only the argument made them inert, so serving them as written is the safer reading of unambiguous intent, and pre-genesis no client relies on the gap. Same class as RK-2's negative-height divergence. | A check that cannot fire is not a policy that was chosen. |
| 2026-08-25 | **RK-4b landed, and the binary FFI bridge went with it.** `/get_blocks_by_height.bin` (+ alias) is served natively over `shekyl_rpc_blocks_by_height`. The capture settled a question the struct would have answered wrongly: `block_complete_entry` has five KV members and this handler sets two, so `pruned`, `block_weight` and `attestation_witness` never reach the wire — and because `pruned` is false the map serializes `txs` as a **`std::vector<blobdata>`, an array of strings**, dropping each entry's `prunable_hash`. The array-of-objects form is reachable only from p2p, whose schema is `shekyl-levin`'s; modelling it here would have carried a variant this daemon cannot emit. With this and RK-4a, **every `.bin` route is native**, so `dispatch_bin`, `bin_handler!`, `CoreRpc::bin_endpoint`, `core_rpc_ffi_bin_endpoint`, the `DBIN` macro, `bin_fn` and `get_bin_table` are all deleted — the binary half of the epee dispatch bridge is gone, ahead of RK-X. The engine's hand-rolled `build_get_blocks_by_height_req` and reply walk went in this diff as the §5 register required, and `Section::collect_bytes_named` — a tree-scanning "any field named X" helper that existed for that walk — went with its only caller. | A helper that outlives its only caller becomes the next untyped access. |
| 2026-08-24 | **RK-4a landed**: `/get_o_indexes.bin` served natively, and with it the RPC `.bin` schema layer (`shekyl-rpc-types::bin_commands`) and the byte-exact oracle harness the rest of RK-4 needs. Two wire rules came out of the captures rather than the C++ declarations, and neither is visible in the latter: `KV_SERIALIZE_VAL_POD_AS_BLOB` puts a hash on the wire as **32 raw bytes**, where the JSON side spells the same field as 64 hex characters; and an empty sequence is **absent**, not `[]`. Vectors are raw `.bin` compared as bytes. The wallet client's hand-rolled `Section` build and reply walk are deleted for the shared map — it was a second definition of a wire the daemon also defines — and `shekyl-rpc-client` drops its direct `shekyl-portable-storage` dependency, reaching the codec through the command map instead. The refusal shape is preserved exactly: an unknown transaction is a **200 carrying `status: \"Failed\"`**, which is what the C++ answered and what the client branches on. | RK-4x ruled: `/get_blocks.bin` and `/get_hashes.bin` are deleted, and the reason is privacy, not tidiness.** The caller enumeration was re-derived independently at `5bcb0e0c6` and holds. What changes the character of the decision is what stands behind the endpoint: `on_get_blocks` is the only caller of `core::get_pool_info`, which is the only reader of `tx_memory_pool::m_removed_txs_by_time` — a timestamped in-memory history of pool *departures*, each entry carrying a `sensitive` flag, kept solely to serve incremental pool deltas to wallet2's batch sync. That is precisely the timing correlate the relay-privacy work exists to deny, retained for an endpoint nobody calls. Migrating would have ported 33 KV fields *and* re-blessed the structure by giving it a live consumer again; deleting retires it. Under the mission's privacy-before-correctness ordering that settles it before the dead-code argument is reached. Steelmen rejected: no third party exists pre-genesis; batch sync, if ever wanted, is a design round against FCMP++ scanning needs emitting a typed Rust route, not a revival of a ring-signature-era API; and daemon-to-daemon sync is Levin, through the 3-argument `find_blockchain_supplement` overload, untouched. Precedent: `get_output_distribution`, deleted on the same predicate with a rule-21 reopen. | A structure that records when transactions leave the pool must not outlive its only reader. |
| 2026-08-24 | **The follow-on walk corrected two of its own premises.** Two symbols the ruling expected to go callerless do not, and the walk is why they were checked rather than assumed. **The `Blockchain` overload behind `on_get_hashes` stays**: `blockchain.cpp:3031` is reached both from the RPC handler *and* from `blockchain.cpp:3075`, which is the p2p `NOTIFY_RESPONSE_CHAIN_ENTRY` path — one overload, two callers, only one of them leaving. **`m_added_txs_by_id` stays**: beyond `get_pool_info` it is read for its `.size()` by two log lines (`tx_pool.cpp:410`, `:533`), so it does not go read-less when the endpoint does. Per the ruling's own instruction the endpoint deletion still lands and that map becomes a follow-on, filed in §5 with a trigger rather than a date. Genuinely going callerless and deleted here: the 9-argument `core::find_blockchain_supplement` and the `req_start_block` `Blockchain` overload beneath it, `core::get_pool_info` / `tx_memory_pool::get_pool_info`, the departure history in full (`m_removed_txs_by_time`, `removed_tx_info`, `track_removed_tx`, `m_removed_txs_start_time` and their trimming), and `COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT` / `_MAX_TX_COUNT`. | The value of walking a follow-on set is the entries it removes, not the ones it confirms. |
| 2026-08-24 | **The RK-4 census does not survive contact with the tree, and the slice splits three ways.** §2's RK-4 row named "the wallet's refresh path" and eight endpoints. Enumerating the callers at `3ed8baf08` says otherwise. **`/get_blocks.bin` and `/get_hashes.bin` have no caller anywhere** — not Rust, not C++, not `utils/python-rpc`, not `tests/functional_tests`, not stressnet; only their own route registration and doc rows that describe them. They were wallet2's batch sync, and `src/wallet/` was deleted. The Rust wallet fetches blocks one at a time over `get_block` / `get_transactions` / `get_o_indexes` — the transport its own `DaemonEngine` doc names — so `get_block` (RK-3b) has already migrated the refresh path's block read. `/get_blocks_by_height.bin` has exactly one consumer, the engine's timing-coupling rig; `/get_o_indexes.bin` has one, `shekyl-rpc-client`. **Landed:** RK-4 becomes **RK-4a** (`/get_o_indexes.bin` — the smallest live binary endpoint, where the portable-storage schema layer and the byte-exact oracle harness get proved), **RK-4b** (`/get_blocks_by_height.bin`, on the proved harness), and **RK-4c** (the JSON siblings, on the serde mechanism RK-1 already proved). This is RK-1's own argument one level down: the harness is built where being wrong is cheap. The two orphans are held as **RK-4x** pending a disposition ruling — `DAEMON_RPC_RUST.md` defines a method as live iff it has a route **and a live consumer**, and by that rule their "wallet refresh" consumer column is as stale as the rows already marked deleted beneath it. | Capturing byte-exact vectors for an endpoint nobody calls is the most expensive way to discover it is dead. |
| 2026-08-24 | **`shekyl-rpc-types` gains `shekyl-portable-storage`, and RK-D10's closing clause is superseded.** RK-D1 always said this crate is the single definition "serde for JSON; `shekyl-portable-storage` for `.bin`", so the dependency is anticipated, not new. But RK-D10's entry ends "`shekyl-rpc-types`' production dependency surface therefore stays serde alone", and its `Cargo.toml` says the same — both were written before a `.bin` method existed. RK-4a adds the dependency and updates both, rather than leaving two sealed texts disagreeing. The typed `.bin` command maps live in `shekyl-rpc-types` beside the JSON ones: `shekyl-levin` owns the p2p schemas and says so ("RPC maps stay out"), and splitting the RPC wire definition across two crates to preserve a dependency count would trade RK-D1 for bookkeeping. | One definition of a method's wire, whichever encoding it speaks. |
| 2026-08-24 | **The binary oracle vectors are raw `.bin` files, compared as bytes.** The `pin()` emitter writes and compares text, which is right for JSON and wrong for a format whose whole claim is byte-exactness — a stray newline translation would be invisible in the diff and fatal on the wire. RK-4a's emitter writes the bytes unmodified, the vectors carry `-text` in `.gitattributes` as the epee CRLF vectors already do, and the Rust side compares `Vec<u8>`, not `String`. | A byte-exact claim checked through a text pipe is not checked. |
| 2026-08-23 | **RK-D11: `get_block`'s `json` field stays epee-rendered, and is the reason RK-3b is not the end of epee on this path.** The field is `obj_to_json_str(blk)` — epee's JSON rendering of the *whole* block, miner transaction included. Reproducing it byte-exactly in Rust means reimplementing that renderer over the entire transaction structure (vin/vout/extra/signatures/`pqc_auths`), which is RK-4's subject matter and beyond, and doing it to match a renderer already queued for deletion. RK-D8 allows exactly one variable per slice, and for RK-3b that variable is *where the handler lives*. **Landed shape:** the facts export returns the rendered string as a variable-length payload and Rust passes it through untouched; the blob crosses as raw bytes and is hexed in Rust, per RK-3's convention. Registered in §5 to die with the field in RK-W, where the honest question is whether `json` should exist at all — it duplicates `blob`, which every in-tree client can already parse. **Reopen early** if any in-tree consumer starts *parsing* `json` rather than printing it: a field only rendered for human eyes can be retired on our schedule, one that is parsed cannot. | Matching a renderer we are deleting is work that dies twice. |
| 2026-08-23 | **RK-D12: `get_block`'s request `hash` stays a `String`, and is parsed in the handler.** `HashHex` is the right type for a hash *the daemon emits*; as a request field it would move the parse into serde, where a bad hash becomes the method's generic params refusal. The C++ answers something better and more specific — `-1 "Failed to parse hex representation of block hash. Hex = <what you sent>."` — and RK-2 established that refusal *messages* are preserved, not just codes. So the field is a `String`, the handler parses it with `HashHex::from_hex`, and the caller keeps the diagnostic that names their input. Dispatch is preserved with it: a non-empty `hash` wins and `height` is ignored; absent params mean height 0. | A type that improves the reply can degrade the refusal; the refusal is the part a broken client reads. |
| 2026-08-23 | **RK-3b inherits an alt-block quirk and keeps it.** `get_block` reaches blocks **by hash**, so unlike RK-3 it can return one off the main chain — `orphan_status` becomes a real value rather than a constant, and RK-3's POD comment ("reached by height, so never an alt block") is true of *that export only*. The inherited oddity: the C++ takes `block_height` from the coinbase's `txin_gen`, then reads depth, difficulty and both weights **by that height**, i.e. from the *main-chain* block at the alt block's height. Those fields therefore describe a different block than the header they sit in. Preserved under RK-D8 and recorded here rather than quietly fixed, because correcting it is a reply-content change and belongs with the rest of RK-W's clean-up. The coinbase-shape check (exactly one `txin_gen` vin, else `INTERNAL_ERROR`) ports with it. | A quirk written down is a decision; a quirk fixed mid-migration is an unbisectable diff. |
| 2026-08-23 | **A caller's type error must not become a plausible answer (deliberate divergence).** epee's `KV_SERIALIZE` *discards* the load's result, so `get_block_header_by_height` treated a missing field and a wrong-typed one identically: `{"height": "nope"}` left `height` at its `struct_init` zero and was answered with the **genesis header**. Absence keeping its default is worth preserving (`{}` means height 0, and tightening it is RK-W's wire change); silently answering a type error is not — it converts a client bug into a wrong answer rather than a loud one, and pre-genesis is exactly when that is cheap to fix. `on_get_block_hash` already refuses unparseable params with `-1 CORE_RPC_ERROR_CODE_WRONG_PARAM` (RK-2), and two sibling methods must not disagree about what a bad parameter means, so the wording is shared. Params must also be an **object**: serde's derive reads a struct out of a sequence, which would have handed this method a positional form nobody designed — and positional is `on_get_block_hash`'s shape, not this one's. Same class as RK-2's negative-height divergence: recorded, not silent. | An error a client can see beats an answer it cannot tell is wrong. |
| 2026-08-23 | **Work moved out of a lock must take its chain reads with it.** RK-3's projection lock was widened for atomicity, which swept the RandomX long hash inside it — ~1.2 s measured on a cold genesis block in a debug build — the figure is not the point, seconds-scale rather than microseconds is — i.e. that long with block handling and p2p stalled, reachable by any unrestricted caller or the operator's own `print_block`. Moving the hash out is only half the fix: `get_block_longhash(…, seed_hash = nullptr)` resolves the seed *itself*, via `Blockchain::get_pending_block_id_by_height`, which reads `m_prepare_height` / `m_prepare_blocks` with **no lock of its own**. Left implicit, the seed would be read after the unlock — pairing the locked block with a seed from another chain state, and racing the prepare-state members. **Landed:** the seed is read inside the lock (where `prepare_handle_incoming_blocks` writes those members, so the read is race-free) and passed to `get_block_longhash` explicitly; only the hashing itself is outside. RK-3b and RK-5 fill pow hashes too and must do the same. | Moving expensive work out of a critical section is only safe once the state it reads moves in. |
| 2026-08-23 | **RK-D10 supersedes §3.1's `HashHex` sketch.** §3.1 (RK-1) proposed `HashHex` as "hex serde over `BlockHash`". Building it in RK-3 showed that shape to be wrong: one `block_header` carries hashes of **four** kinds — a block identity (×2), a transaction identity, two Merkle-ish roots, and a proof-of-work hash — so typing the wire field as `BlockHash` would recreate on the wire exactly the confusion `shekyl-types`' `hash32!` newtypes exist to prevent. A generic `HashHex<T>` was rejected for the other direction: it needs a `Hash32` trait plus minted newtypes for the roots and the PoW hash that this tree does not have (`shekyl-wire::BlockHeader` types both roots as `[u8; 32]`, and `attestation_root()` / `selene_hash_init()` return raw arrays) — pre-provisioning, and a wider blast radius than this slice scoped. **Landed:** `HashHex` is a wire-level `[u8; 32]` with 64-lowercase-hex serde, and consumers convert at the edge into whichever domain hash they know they hold — the rule that rule 18 already states and `shekyl-wire` already follows. `shekyl-rpc-types`' production dependency surface therefore stays serde alone. The wire bytes are unchanged; the oracle vectors are the proof. | The wire's job is to carry bytes; naming their kind is the edge's job, where the kind is known. |
| 2026-08-23 | **`""` is a value on this wire, so `Option` is the honest type for it.** `block_header.pow_hash` is `""` unless the caller asked and was entitled; RK-3 models it as `Option<HashHex>` with an explicit `""`-as-absent serde rather than a `String` that might or might not be empty, which keeps the daemon's `pow_hash_filled` flag alive from the facts POD all the way to the wire. Emitted bytes unchanged. `GetHeightResponse.hash` needs no such treatment: its only producer is RK-1's Rust handler, which fills it on every reply it emits, and its failures leave through the error envelope. The `""`-as-absent quirk retires with the rest in RK-W. | A type that can represent a state the wire cannot produce is as wrong as one that cannot represent a state it does. |
| 2026-08-23 | **RK-3 landed**: `get_block_header_by_height` (+ `getblockheaderbyheight`) served natively, carrying the shared 24-field `BlockHeader` that RK-3b and RK-5's three deferred header methods reuse. New facts export `shekyl_rpc_block_header_at` — one lock for the bound, the block, its weights and both difficulties, so the whole projection describes one chain state — as a thin adapter over `daemon_rpc_facts::block_header_at(Blockchain&, …)`, driven by `rpc_facts_shims.cpp` against a test DB that serves real blocks. The 128-bit difficulties keep the wire's three-field rendering (`split_128`: low word, `0x`-hex whole, high word); `block_weight` / `long_term_weight` keep their OPT omission while `block_size`, filled from the same source, does not. A store that cannot produce an in-range block keeps the C++ contract's `INTERNAL_ERROR` (-5) and wording rather than becoming a generic internal error — the shim has already logged it. `pow_hash_entitled` names the `fill_pow_hash && !restricted` policy the C++ handler enforced inline, with its truth table pinned. `shekyl-rpc-client`'s private `BlockHeaderByHeightResponse` retires for the shared type, and now checks `status`. C++ `block_header_response` and `fill_block_header_response` stay: the four header methods still in C++ use them, and — unlike the `hard_fork_info` case — no console command parses a Rust-produced reply with them, so the two definitions never meet. |
| 2026-08-22 | **RK-2 landed**: `get_block_count` (+ `getblockcount`) and `on_get_block_hash` (+ `on_getblockhash`) served natively. Adds the two mechanisms RK-1 had no occasion to exercise — positional JSON-RPC params, typed as `GetBlockHashParams([u64; 1])` so arity/type refusals are the deserializer's (not a hand-written parser's), and `RpcFault::Refused(RpcRefusal { code, message })`, which carries `CORE_RPC_ERROR_CODE_WRONG_PARAM` / `_TOO_BIG_HEIGHT` onto the wire instead of collapsing to `-32603`; a refusal is normal traffic and is not logged as a daemon fault. New facts export `shekyl_rpc_block_hash_at` (POD + layout twins), which reads the tip and the hash in **one** call so the `TOO_BIG_HEIGHT` message cannot name a height that disagrees with the bound it failed. `get_block_count` needed no new facts — it is RK-1's `chain_tip().chain_height`. **One deliberate divergence:** a negative height is now `WRONG_PARAM`, where the C++ dispatcher's hand-rolled `std::stoull` parse wrapped it to a huge `u64` and answered `TOO_BIG_HEIGHT` — a parser artifact, not a decision. |
| 2026-08-21 | **RK-1 landed** on the design's own branch: `shekyl-rpc-types::chain` (GetHeightResponse, GetVersionResponse, HardForkEntry, RpcStatus, CORE_RPC_VERSION); `shekyl-daemon-rpc::{chain_facts, methods, console}`; `src/rpc/rpc_facts_ffi.{h,cpp}` + layout-twin test; oracle vectors captured from the C++ handlers before they, `COMMAND_RPC_GET_HEIGHT` / `_GET_VERSION`, the three handler-less structs (`GET_OUTPUTS`, `GET_OUTPUTS_BIN` — and the dead `core::get_outs` / `Blockchain::get_outs` chain behind it — `FAST_EXIT`) and the C++ `CORE_RPC_VERSION` macros were deleted. Console `print_height` renders in Rust on both arms. `shekyl-rpc-client`'s private `HeightResponse` retired for the shared type. |
| 2026-08-21 | Document opened after #533 (epee HTTP surface gone). Census at `077d97c4e`: 65 structs / 872 KV fields / 59 dispatch rows; per-handler core/p2p facts counted; consumers mapped (W/C/G/K/P/F/R). RK-D1…D9 bound. Phase 2 re-scoped from "Rust codec in `core_rpc_ffi.cpp`" (unbuildable without a façade) to method-wise native handlers over facts FFI. Slices RK-1…RK-9, RK-C, RK-X. RK-1 = `get_height` + `get_version` + deletion of the three handler-less structs. |
