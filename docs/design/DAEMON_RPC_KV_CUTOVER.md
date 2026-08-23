# Daemon RPC — Phase 2: the KV cutover (native Rust handlers over facts FFI)

**Status:** **RK-1 landed** (the pattern slice, PR #534); design **open for
RK-2**. Census and binding decisions verified at source against `dev`
**`077d97c4e`** (PR #528 merge); every `file:line` below was read at that
commit.
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
| **RK-2** | Block count + hash-by-height | `get_block_count` (`getblockcount`) · `on_get_block_hash` (`on_getblockhash`) | 4 + — (the hash reply is a bare JSON string) | `shekyl_rpc_chain_tip` (reused from RK-1), `shekyl_rpc_block_hash_at` | P (python-rpc, stressnet) |
| **RK-3** | Block headers / blocks | `get_last_block_header` · `get_block_header_by_hash` · `…_by_height` · `get_block_headers_range` · `get_block` | 8 + 11 + 9 + 10 + 22 (+ shared `block_header_response`, 25) | `get_block_by_hash`, `get_block_id_by_height`, reward/weight fills | W C G K R P |
| **RK-4** | Wallet sync (binary + its JSON siblings) | `/get_blocks.bin` `/getblocks.bin` · `/get_blocks_by_height.bin` · `/get_hashes.bin` · `/get_o_indexes.bin` · `/get_transactions` · `/is_key_image_spent` · `get_fee_estimate` | 33 + 15 + 11 + 12 + 31 + 8 + 10 | `find_blockchain_supplement`, `get_pool_info`, `get_tx_outputs_gindexs`, `get_split_transactions_blobs`, `are_key_images_spent[_in_pool]`, `get_dynamic_base_fee_estimate_*` | **W** (the wallet's refresh path) K P R |
| **RK-5** | Node state (+ `hard_fork_info`, moved here — see below) | `/get_info` `/getinfo` · `get_info` · `sync_info` · `/get_net_stats` · `get_connections` · `/get_peer_list` · `hard_fork_info` | 48 + 24 + 11 + 7 (+ `connection_info`) + 10 + 15 | 26 distinct core/p2p reads for `get_info`; `get_connections`, peerlist, throttle stats; hard-fork voting info | W C G K P F |
| **RK-6** | Mempool | `/get_transaction_pool` · `/get_transaction_pool_hashes[.bin]` · `/get_transaction_pool_stats` · `get_txpool_backlog` · `flush_txpool` · `relay_tx` | 8 + 7 + 7 + 7 + 26 + 7 + 7 | pool reads, `flush_txes_from_pool`, `get_protocol().relay_transactions` | K P |
| **RK-7** | Mining (consensus-adjacent → rule 26 pre-flight) | `get_block_template` · `submit_block` · `calc_pow` · `get_miner_data` · `add_aux_pow` · `generateblocks` · `/start_mining` `/stop_mining` `/mining_status` `/set_log_hash_rate` | 22 + 4 + 7 + 19 + 17 + 12 + 10 + 6 + 21 + 7 | `get_block_template`, `handle_block_found`, `check_incoming_block_size`, `get_miner()`, `get_miner_data` | K R P |
| **RK-8** | Admin + chain maintenance | `/set_log_level` `/set_log_categories` · `/get_limit` `/set_limit` · `/in_peers` `/out_peers` · `set_bans` `get_bans` `banned` · `/save_bc` · `/stop_daemon` · `/pop_blocks` · `prune_blockchain` · `flush_cache` · `get_alternate_chains` · `get_coinbase_tx_sum` · `get_output_histogram` | 7 + 30 + 8 + 10 + 9 + 9 + 13 + 12 + 8 + 6 + 6 + 8 + 9 + 7 + 17 + 14 + 18 | throttle, p2p limits/bans, `store_blockchain`, `send_stop_signal`, `pop_blocks`, pruning, alt chains, histogram | K P R |
| **RK-9** | Curve tree + archival | `get_curve_tree_path` · `get_curve_tree_info` · `get_curve_tree_checkpoint` · `get_archival_emission_claim_source` · `inject_archival_serve_credit` (regtest) | 19 + 10 + 11 + 40 + 35 | `get_db()` reads; the logic is already Rust (`shekyl-curve-tree`, `shekyl-archival-*`) | W G R |
| **RK-C** | Console retirement | `rpc_command_executor.cpp` / `command_parser_executor.cpp` / `command_server.cpp` → Rust; `src/daemon/rpc_client.h` dies | — | — | K |
| **RK-W** | Wire cleanup (after RK-X) | Redesign the surface once the handlers are all Rust: retire `status`-as-error-channel in favour of typed errors, drop OPT-omission quirks and positional JSON-RPC, collapse aliases; every in-tree client updated in the same PR; `CORE_RPC_VERSION` 4.0 | — | — | W C G K P |
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

```rust
/// Response of `GET|POST /get_height` (alias `/getheight`). The request body
/// is empty (and ignored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetHeightResponse {
    pub status: RpcStatus,  // the `status` string every reply carries
    pub height: u64,        // chain height = top block height + 1
    pub hash: String,       // top block hash, 64 lowercase hex chars
}
```

(Verbatim from `shekyl-rpc-types/src/chain.rs`; the snippet is a mirror,
not a second definition.) `hash` is a `String` in RK-1 on purpose:
`shekyl-types::BlockHash` serializes as a byte array, not hex, so it cannot
sit on this wire directly, and a hex-serde newtype for one field is
pre-provisioning. RK-3 — block headers, where hashes multiply — introduces
that newtype (`HashHex`, hex serde over `BlockHash`) and migrates this
field to it; until then the string's shape is pinned by the oracle vector.

Rules, all test-pinned in the crate: field names are the wire names; `u64`
serializes as a JSON number (epee does); hashes are lowercase hex strings
(epee `pod_to_hex`); `KV_SERIALIZE_OPT(f, d)` becomes
`#[serde(default, skip_serializing_if = "is_<d>")]`; unknown fields are
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

Twins in `shekyl-daemon-rpc/src/ffi.rs`; layout pinned both directions by
`tests/unit_tests/rpc_facts_ffi_roundtrip.cpp` (seed-derived per-field
values, the F26 pattern). Return codes: `0` ok, `-1` null handle, `-2`
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
| 2026-08-21 | **RK-1 landed** on the design's own branch: `shekyl-rpc-types::chain` (GetHeightResponse, GetVersionResponse, HardForkEntry, RpcStatus, CORE_RPC_VERSION); `shekyl-daemon-rpc::{chain_facts, methods, console}`; `src/rpc/rpc_facts_ffi.{h,cpp}` + layout-twin test; oracle vectors captured from the C++ handlers before they, `COMMAND_RPC_GET_HEIGHT` / `_GET_VERSION`, the three handler-less structs (`GET_OUTPUTS`, `GET_OUTPUTS_BIN` — and the dead `core::get_outs` / `Blockchain::get_outs` chain behind it — `FAST_EXIT`) and the C++ `CORE_RPC_VERSION` macros were deleted. Console `print_height` renders in Rust on both arms. `shekyl-rpc-client`'s private `HeightResponse` retired for the shared type. |
| 2026-08-21 | Document opened after #533 (epee HTTP surface gone). Census at `077d97c4e`: 65 structs / 872 KV fields / 59 dispatch rows; per-handler core/p2p facts counted; consumers mapped (W/C/G/K/P/F/R). RK-D1…D9 bound. Phase 2 re-scoped from "Rust codec in `core_rpc_ffi.cpp`" (unbuildable without a façade) to method-wise native handlers over facts FFI. Slices RK-1…RK-9, RK-C, RK-X. RK-1 = `get_height` + `get_version` + deletion of the three handler-less structs. |
