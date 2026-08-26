# Daemon RPC — Phase 2: the KV cutover (native Rust handlers over facts FFI)

**Status:** **RK-1, RK-2, RK-3 and RK-3b landed** (the pattern slice, PR
#534; count + hash-by-height, PR #540; the block-header projection, PR #541;
whole blocks); design **open for RK-4a**. Census and binding
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
| **RK-D8** | **One variable at a time: the cutover preserves each reply's shape; wire cleanup is its own slice.** Pre-genesis there is **no external wire contract** — every client of this RPC is in this tree (wallet, CLI, GUI, console, test framework) and ships with the daemon. The shape-preservation rule is therefore a *sequencing* discipline, not a compatibility promise: the epee oracle vectors can only pin a reply whose shape did not move, and a slice that both migrates a handler and changes its wire cannot be bisected. So each RK slice keeps field sets, names, defaults, aliases and status values as they were; the Monero-era quirks that survive the cutover — the `status` string doubling as an error channel, `KV_SERIALIZE_OPT` omissions, positional JSON-RPC (`get_block_count`'s list request), the `/getheight`-style aliases — are **queued for RK-W**, a wire-cleanup slice after RK-X that redesigns the surface once, with every in-tree client updated in the same PR. `CORE_RPC_VERSION` stays a cheap skew guard between a wallet and a daemon from different builds (§2.3 of `DAEMON_SUBMIT_VERDICT.md`), bumped when a reply a client parses changes; it is not a ceremony. Diagnostic text inside a transport failure is neither shape nor status and may change at any time. | Parity needs a fixed shape; bisection needs one variable; nothing outside the tree needs the old shape. |
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
| **RK-1** — **landed** (this branch; PR #, sha stamped at merge) | Chain tip + version (the pattern slice) | `/get_height` `/getheight` · `get_version` | 8 + 15 | `shekyl_rpc_chain_tip`, `shekyl_rpc_hardforks` (`src/rpc/rpc_facts_ffi.cpp`) | W K P |
| **RK-2** — **landed** (this branch; PR #, sha stamped at merge) | Block count + hash-by-height | `get_block_count` (`getblockcount`) · `on_get_block_hash` (`on_getblockhash`) | 4 + — (the hash reply is a bare JSON string) | `shekyl_rpc_chain_tip` (reused from RK-1), `shekyl_rpc_block_hash_at` | P (python-rpc, stressnet) |
| **RK-3** — **landed** (this branch; PR #, sha stamped at merge) | The **block-header projection**; `HashHex` (RK-D10) | `get_block_header_by_height` (+ `getblockheaderbyheight`) | 9 (+ the shared 24-field `block_header_response`) | `shekyl_rpc_block_header_at` | W (`shekyl-rpc-client`) P |
| **RK-3b** — **landed** (this branch; PR #, sha stamped at merge) | Whole blocks | `get_block` (+ `getblock`) — header + blob + json + tx hashes, and the console's `print_block_by_hash` / `_by_height`, which read **only** this method | 22 | header facts + block blob + tx-hash list + **the epee-rendered `json` string** (RK-D11) | W C K R P |
| **RK-4a** — **landed** (this branch; PR #, sha stamped at merge) | The `.bin` mechanism, proved small | `/get_o_indexes.bin` | 12 | `get_tx_outputs_gindexs` | W (`shekyl-rpc-client`) |
| **RK-4b** — **landed** (this branch; PR #, sha stamped at merge) | The remaining live binary endpoint | `/get_blocks_by_height.bin` `/getblocks_by_height.bin` | 15 | `get_blocks_by_height` | E (the engine's timing rig) |
| **RK-4c** | The JSON siblings of the sync path | `/get_transactions` (+ the console's `print_transaction`, which reads **only** it) · `/is_key_image_spent` · `get_fee_estimate` | 31 + 8 + 10 | `get_split_transactions_blobs`, `are_key_images_spent[_in_pool]`, `get_dynamic_base_fee_estimate_*` | W C K P R |
| **RK-4x** — **ruled: deleted** | `/get_blocks.bin` `/getblocks.bin` · `/get_hashes.bin` · `/gethashes.bin` | wallet2's batch sync, and wallet2 is gone. Retired rather than migrated, with `get_pool_info` and the pool's departure history behind it. Reopen clause in `DAEMON_RPC_RUST.md` | — (44 fields deleted, not ported) | — | none |
| **RK-5** | Node state — **the hub** (see the console matrix below); also `hard_fork_info`, `get_last_block_header`, `get_block_header_by_hash`, `get_block_headers_range`, each moved here for a named reason | `/get_info` `/getinfo` · `get_info` · `sync_info` · `/get_net_stats` · `get_connections` · `/get_peer_list` · `hard_fork_info` · the three header methods above | 48 + 24 + 11 + 7 (+ `connection_info`) + 10 + 15 + 8 + 11 + 10 | 26 distinct core/p2p reads for `get_info`; peerlist, throttle stats; hard-fork voting info; **the p2p double** this slice must build | W C G K P F |
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
| `print_blockchain_info` | `get_block_headers_range`, **`get_info`** |
| `print_blockchain_dynamic_stats` | `get_block_headers_range`, `hard_fork_info`, `get_fee_estimate`, **`get_info`** |
| `alt_chain_info` | `get_block_header_by_hash`, `get_alternate_chains`, **`get_info`** |
| `show_status` | `hard_fork_info`, `mining_status`, **`get_info`** |
| `show_difficulty`, `version`, `print_transaction_pool_stats` | **`get_info`** (+ their own) |
| every other command | exactly one method |

**`get_info` is the hub**: six commands read it, and *every* console command
that touches a header method also touches it. That is why the header methods
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
unknown fields are
tolerated on deserialize (no `deny_unknown_fields` — older/newer wallets);
`status` is a typed newtype so `"OK"` / `"BUSY"` / free-text errors are one
type, not three string constants in three crates.

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
| `obj_to_json_str(blk)` and the `json` field of `get_block` | RK-W | the last epee *rendering* on the RPC path (RK-D11). It duplicates `blob`, which carries the same block in the consensus encoding every in-tree client can already parse |
| `block_header_response`, `fill_block_header_response`, and `core_rpc_server::get_block_reward` | RK-5 | the four remaining header methods move. `get_block_reward` is a private third copy of `cryptonote::get_outs_money_amount` whose name collides with the consensus `cryptonote::get_block_reward(median_weight, …)` (subsidy, not a coinbase sum); its single caller is `fill_block_header_response`, so it dies with it. Nothing new calls it — RK-3's facts export uses `get_outs_money_amount`. |
| `src/daemon/rpc_client.h` (#533) + the C++ executor/parser/command server | RK-C | every console command renders in Rust |
| `core_rpc_server.{h,cpp}`, `core_rpc_server_commands_defs.h`, `core_rpc_ffi.cpp` dispatch + `core_rpc_ffi_json_endpoint` / `_bin_endpoint` / `_json_rpc`, `rpc_handler.*`, `json_object.cpp` RPC arms, `message_data_structs.h` RPC half; FOLLOWUPS dual-list item | RK-X | zero C++ handlers left |
| every `shekyl_rpc_*_facts` shim | post-DRS-E | Rust store impl of each facts trait lands (RK-D7) |

---

## 6. Non-goals and reopen clauses (rule 21)

- **Not** a wire redesign. Method names, aliases, field names and defaults
  are preserved; `CORE_RPC_VERSION` stays 3.22 through the cutover.
  Reopen per method with its own bump and CHANGELOG operator-impact line.
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
| 2026-08-24 | **RK-3b landed**: `get_block` (+ `getblock`) served natively, with `print_block_by_hash` / `print_block_by_height` — the two console commands that read only this method — ported alongside it, so no C++ caller is left holding `block_header_response` for a Rust-produced reply. New facts export `shekyl_rpc_block_at`, the first with variable-length payloads: blob, tx-hash list and epee's `json` are owned by one allocation and released by one `shekyl_rpc_block_free` (§3.2). `orphan_status` becomes a real value, and the alt-block quirk is pinned by a shim test rather than described. The console's rendering moved with the method: `AtomicUnits::to_skl_string` is byte-exact with `print_money`, the UTC timestamp keeps the `<unknown>` cutoff, and the difficulty is decimalised from the `0x` wide form as the C++ did by constructing a `difficulty_type`. |
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
