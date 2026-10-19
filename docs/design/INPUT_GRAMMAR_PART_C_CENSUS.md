# Input grammar Part C — the field census (appendix)

**Status:** RULED 2026-10-19 with [`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) Part C — the evidence for its §17–§18. A read-only census from source of every served method's parameters and reply fields, taken at `945e80dad`; every cited file is unchanged at `42c133186`. Nothing here was captured from a running daemon. It goes with the rename PR (`RPC_WIRE.md` RW-Q8), whose generated field table replaces it.

**Path abbreviations used in citations**

| abbr | path |
|---|---|
| `T/` | `rust/shekyl-rpc-types/src/` |
| `D/` | `rust/shekyl-daemon-rpc/src/` |
| `H` | `src/rpc/core_rpc_server_commands_defs.h` |
| `S` | `src/rpc/core_rpc_server.cpp` |
| `F` | `src/rpc/core_rpc_ffi.cpp` |

**Wire type vocabulary**

| term | meaning |
|---|---|
| `u64` / `u32` / `u16` / `u8` | JSON number |
| `bool` | JSON boolean |
| `string` | JSON string |
| `hash64` | a 64-char lowercase hex string (`HashHex`; on deserialize it accepts either case and refuses any other length): `T/hash.rs:168-191` |
| `hex128` | `"0x"` followed by minimal lowercase hex of a u128. Rust: `HexU128`, `T/hex128.rs:127-138`. C++: `cryptonote::hex`, `src/cryptonote_basic/difficulty.cpp:93`, through `store_128` at `S:74-79` |
| `hexstr` | a free-length lowercase hex string (`buff_to_hex_nodelimer` / `hex::encode`) |
| `atomic-dec` | a decimal string of atomic units (`AtomicUnitsString`, `rust/shekyl-units/src/wire.rs:40`) |
| `nullable<T>` | the key is always present, and its value is `T` or `null` (`Nullable`, `T/nullable.rs:67-70`) |
| `T?` | the key is omitted when empty, zero, false or `None` (the condition is given per row) |
| `[T]` | an array. **Empty sequences are omitted from the document** on both the epee and the serde side (stated at `T/transactions.rs:44-48` and `T/chain.rs:431-435`). An exception is marked where the source says so |

---

## 1. Shared shapes

### 1.1 Envelopes

**There is no `untrusted`, `credits` or `top_hash` key anywhere on this wire.** A grep of `src/rpc`, `T/` and `D/` finds no `KV_SERIALIZE(untrusted|credits|top_hash)` and no serde field with those names. The only shared base is `status`.

#### `rpc_response_base` / `RpcStatus`: the per-reply base

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | `"OK"`, `"BUSY"`, `"offline"` (P2P down), `"NOT MINING"`, or a free-text failure sentence (C++ and the REST refusals) | C++ `H:100-107`; Rust `T/chain.rs:213-251` (transparent newtype); `H:77-79` defines the constants |

**Carriers.** Every C++ response struct inherits `status` through `KV_SERIALIZE_PARENT(rpc_response_base)`. `COMMAND_RPC_BANNED` declares its own `status` with no parent (`H:834-847`). Every Rust reply struct carries `status` except the ones below.

**Replies with no `status`:**

| reply | wire shape | source |
|---|---|---|
| `on_get_block_hash` | bare `hash64` string | `D/methods.rs:447-451` |
| `calc_pow` | bare `hash64` string | `H:414` (`typedef std::string response`); `S:604`; `F:226-245` |
| `/submit_transaction` | a tagged `verdict` object | `T/lib.rs:165-206` |
| `/get_stem_tallies` | a hand-built `{floor,tallies}` object | `src/p2p/net_node.inl:772-826` |
| `option_set`, `option_show` | `{options:[…]}` | `D/options.rs:347-352` |

#### JSON-RPC envelope (`POST /json_rpc`)

| key | wire type | notes | source |
|---|---|---|---|
| request `jsonrpc` | string? | read and ignored | `D/types.rs:35` |
| request `id` | any | echoed | `D/types.rs:36` |
| request `method` | string | | `D/types.rs:37` |
| request `params` | any (`null` default) | Rust-native: object or `null`, except the positional `on_get_block_hash`. C++: `null` and `{}` are sent as an empty string, so the KV load is skipped and the request stays value-initialised (`D/handlers/json_rpc.rs:104-114`, `F:116`) | `D/types.rs:38-39` |
| reply `jsonrpc` | string `"2.0"` | | `D/types.rs:44` |
| reply `id` | any | | `D/types.rs:45` |
| reply `result` | any? | omitted on error | `D/types.rs:46-47` |
| reply `error` | object? | omitted on success | `D/types.rs:48-49` |
| `error.code` | i64 | -1 WRONG_PARAM, -2 TOO_BIG_HEIGHT, -5 INTERNAL, -6 WRONG_BLOCKBLOB, -9 CORE_BUSY, -10 WRONG_BLOCKBLOB_SIZE, -19 RESTRICTED, -22 ARCHIVAL_UNAVAILABLE, -24 SHARD_OPEN, -25 SKELETON_ABSENT, -26 CONFIG_REFUSED, -32601 not-found / restricted-gate, -32603 internal | `T/chain.rs:259-294`, `T/archival.rs:77-89`, `T/chain_reads.rs:141-145`, `D/handlers/json_rpc.rs:85-93`, `D/types.rs:54` |
| `error.message` | string | | `D/types.rs:55` |
| `error.data` | any? | only `option_set` / `option_show` refusals: `[Refusal]` (§1.9) | `D/types.rs:58-59`, `D/options.rs:449-455` |

An internal frame sits between Rust and C++: the FFI returns `{ok, result | error_code, error_message}` (`D/types.rs:97-101`; `F:116-146`). It never reaches the wire.

#### REST error envelope (Rust-produced)

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string `"ERROR"` | sent with HTTP 500 (dispatch or facts failure) or HTTP 400 (`/start_mining` table refusal) | `T/chain.rs:301-306`, `D/handlers/json.rs:64-74`, `D/handlers/json.rs:403-414` |
| `error` | string | the reason | same |

A second refusal form exists: **HTTP 200 carrying only a non-OK `status`**.

- `/get_transactions` and `/is_key_image_spent` emit it through `status_only` (`D/handlers/json.rs:286-288`).
- The `.bin` routes emit it through `bin_status` / `"Failed"` (`D/handlers/binary.rs:96-102,137-140`).
- Every C++ handler that sets `res.status = "<sentence>"; return true` emits it too.

#### `P2pReply` offline form

`get_connections`, `sync_info` and `/get_peer_list` answer `{"status":"offline"}` and nothing else when P2P is off (`T/p2p.rs:357-403`).

### 1.2 `block_header` (`BlockHeader`)

Rust-only (`T/chain.rs:353-393`). It appears as `block_header` in `get_block`, `get_block_header_by_height` and `get_last_block_header`. It appears as `block_headers[].block_header` in `get_block_header_by_hash` and as `headers[]` in `get_block_headers_range`.

| key | wire type | notes | source |
|---|---|---|---|
| `major_version` | u8 | | `T/chain.rs:356` |
| `minor_version` | u8 | | `T/chain.rs:357` |
| `timestamp` | u64 | unix s | `T/chain.rs:358` |
| `prev_hash` | hash64 | | `T/chain.rs:359` |
| `nonce` | u32 | | `T/chain.rs:360` |
| `orphan_status` | bool | | `T/chain.rs:361` |
| `height` | u64 | block **index** | `T/chain.rs:362` |
| `depth` | u64 | `chain_height - height - 1` | `T/chain.rs:363-364` |
| `hash` | hash64 | | `T/chain.rs:365` |
| `difficulty` | u64 | low 64 bits | `T/chain.rs:366-367` |
| `wide_difficulty` | hex128 (typed `String`) | | `T/chain.rs:368-369` |
| `difficulty_top64` | u64 | high 64 bits | `T/chain.rs:370-371` |
| `cumulative_difficulty` | u64 | low 64 | `T/chain.rs:372` |
| `wide_cumulative_difficulty` | hex128 (typed `String`) | | `T/chain.rs:373` |
| `cumulative_difficulty_top64` | u64 | | `T/chain.rs:374` |
| `reward` | u64 | atomic units, a **number** | `T/chain.rs:375-376` |
| `block_size` | u64 | always equal to `block_weight`; never omitted | `T/chain.rs:377-379` |
| `block_weight` | u64? | omitted at 0 | `T/chain.rs:380-381` |
| `num_txes` | u64 | | `T/chain.rs:382` |
| `pow_hash` | hash64 or `""` | `""` unless `fill_pow_hash` was set and the listener allows it (empty-string-as-absent) | `T/chain.rs:383-387`, `T/hash.rs:199-230` |
| `long_term_weight` | u64? | omitted at 0 | `T/chain.rs:388-389` |
| `miner_tx_hash` | hash64 | | `T/chain.rs:390` |
| `curve_tree_root` | hash64 | | `T/chain.rs:391` |
| `attestation_root` | hash64 | | `T/chain.rs:392` |

### 1.3 `BlockHeaderSlot` (in `get_block_header_by_hash`)

| key | wire type | notes | source |
|---|---|---|---|
| `hash` | hash64 | echoes the request | `T/headers.rs:79-82` |
| `block_header` | block_header? | omitted when this chain does not hold the block (a miss is data) | `T/headers.rs:83-85` |

### 1.4 `ConnectionInfo`

Used as `get_connections.connections[]` and as `sync_info.peers[].info`.

| key | wire type | notes | source |
|---|---|---|---|
| `incoming` | bool | | `T/p2p.rs:203` |
| `localhost` | bool | | `T/p2p.rs:204` |
| `local_ip` | bool | | `T/p2p.rs:205` |
| `address` | string | `host:port` (ipv4) or the onion | `T/p2p.rs:206-207` |
| `host` | string | | `T/p2p.rs:208-209` |
| `ip` | **string** | dotted ipv4; `""` on other arms | `T/p2p.rs:210-211` |
| `port` | **string** | `""` on non-ipv4 | `T/p2p.rs:212-213` |
| `recv_count` | u64 | bytes | `T/p2p.rs:214-215` |
| `recv_idle_time` | u64 | seconds | `T/p2p.rs:216-217` |
| `send_count` | u64 | bytes | `T/p2p.rs:218` |
| `send_idle_time` | u64 | seconds | `T/p2p.rs:219` |
| `state` | string enum | `before_handshake` / `synchronizing` / `standby` / `normal` / `unknown` | `T/p2p.rs:148-156,220` |
| `live_time` | u64 | seconds | `T/p2p.rs:221-222` |
| `avg_download` | u64 | KiB/s | `T/p2p.rs:223-224` |
| `current_download` | u64 | KiB/s | `T/p2p.rs:225-226` |
| `avg_upload` | u64 | KiB/s | `T/p2p.rs:227` |
| `current_upload` | u64 | KiB/s | `T/p2p.rs:228` |
| `support_flags` | u32 or **`null`** | always present (no skip) | `T/p2p.rs:229-230` |
| `connection_id` | string | 32 lowercase hex chars (uuid) | `T/p2p.rs:231-232` |
| `height` | u64 or **`null`** | the peer's claimed height; always present | `T/p2p.rs:233-235` |
| `address_type` | u8 | epee id: 1 ipv4, 2 ipv6, 4 tor | `T/p2p.rs:236-237` |

### 1.5 `SyncSpan` (`sync_info.spans[]`)

| key | wire type | notes | source |
|---|---|---|---|
| `start_block_height` | u64 | | `T/p2p.rs:264` |
| `nblocks` | u64 | | `T/p2p.rs:265` |
| `connection_id` | string | 32 hex chars | `T/p2p.rs:266-267` |
| `rate` | u32 | bytes/s | `T/p2p.rs:268-269` |
| `speed` | u32 | a **percentage** | `T/p2p.rs:270-271` |
| `size` | u64 | bytes | `T/p2p.rs:272-273` |
| `remote_address` | string | | `T/p2p.rs:274` |

`SyncInfoPeer` is `{info: ConnectionInfo}` (`T/p2p.rs:256-258`).

### 1.6 `Peer` (`/get_peer_list` `white_list[]` / `gray_list[]`)

| key | wire type | notes | source |
|---|---|---|---|
| `host` | string | | `T/p2p.rs:118` |
| `ip` | **u32** | ipv4 in network order; 0 on other arms | `T/p2p.rs:119-125` |
| `port` | **u16** | | `T/p2p.rs:126` |

### 1.7 `TxEntry` (`/get_transactions` `txs[]`)

The wire form is the flat `RawTxEntry` (`T/transactions.rs:139-167`). `in_pool` selects which arm's keys are present.

| key | wire type | notes | source |
|---|---|---|---|
| `tx_hash` | hash64 | | `T/transactions.rs:142` |
| `as_hex` | hexstr | always emitted, even `""` | `T/transactions.rs:143` |
| `pruned_as_hex` | hexstr | always emitted | `T/transactions.rs:144` |
| `prunable_as_hex` | hexstr | always emitted | `T/transactions.rs:145` |
| `prunable_hash` | hash64 | | `T/transactions.rs:146` |
| `archival_len` | u64 | bytes | `T/transactions.rs:115-122,147` |
| `as_json` | string (embedded JSON text) | epee rendering; always emitted | `T/transactions.rs:148` |
| `pruned` | bool? | omitted when false | `T/transactions.rs:149-150` |
| `in_pool` | bool | arm selector | `T/transactions.rs:151` |
| `double_spend_seen` | bool | | `T/transactions.rs:152` |
| `block_height` | u64 | mined arm only | `T/transactions.rs:154-155` |
| `confirmations` | u64 | mined arm only | `T/transactions.rs:156-157` |
| `block_timestamp` | u64 | mined arm only | `T/transactions.rs:158-159` |
| `output_indices` | [u64]? | mined arm; omitted when empty | `T/transactions.rs:160-161` |
| `relayed` | bool | pool arm only | `T/transactions.rs:163-164` |
| `received_timestamp` | u64 | pool arm only | `T/transactions.rs:165-166` |

### 1.8 C++ pool shapes (`/get_transaction_pool`, `/get_transaction_pool_stats`)

**`tx_info`** (`H:532-569`):

| key | wire type | notes | source |
|---|---|---|---|
| `id_hash` | hash64 | | `H:552` |
| `tx_json` | string (embedded JSON) | `obj_to_json_str` | `H:553`, `src/cryptonote_core/tx_pool.cpp:1577` |
| `blob_size` | u64 | | `H:554` |
| `weight` | u64? | `KV_SERIALIZE_OPT(weight,0)` | `H:555` |
| `fee` | u64 | | `H:556` |
| `max_used_block_id_hash` | hash64 | | `H:557` |
| `max_used_block_height` | u64 | | `H:558` |
| `kept_by_block` | bool | | `H:559` |
| `last_failed_height` | u64 | | `H:560` |
| `last_failed_id_hash` | hash64 | | `H:561` |
| `receive_time` | u64 | 0 when not sensitive (`tx_pool.cpp:1587`) | `H:562` |
| `relayed` | bool | | `H:563` |
| `last_relayed_time` | u64 | | `H:564` |
| `do_not_relay` | bool | | `H:565` |
| `double_spend_seen` | bool | | `H:566` |
| `tx_blob` | hexstr | hex-encoded in place | `H:567`, `S:307` |

**`spent_key_image_info`** (`H:571-580`):

| key | wire type | source |
|---|---|---|
| `id_hash` | hash64 (a key image) | `H:577` |
| `txs_hashes` | [hash64] | `H:578` |

**`txpool_stats`** (`H:669-702`):

| key | wire type | source |
|---|---|---|
| `bytes_total` | u64 | `H:688` |
| `bytes_min` | u32 | `H:689` |
| `bytes_max` | u32 | `H:690` |
| `bytes_med` | u32 | `H:691` |
| `fee_total` | u64 | `H:692` |
| `oldest` | u64 | `H:693` |
| `txs_total` | u32 | `H:694` |
| `num_failing` | u32 | `H:695` |
| `num_10m` | u32 | `H:696` |
| `num_not_relayed` | u32 | `H:697` |
| `histo_98pc` | u64 | `H:698` |
| `histo` | [txpool_histo] | `H:699` |
| `num_double_spends` | u32 | `H:700` |

**`txpool_histo`** (`H:658-667`):

| key | wire type | source |
|---|---|---|
| `txs` | u32 | `H:664` |
| `bytes` | u64 | `H:665` |

### 1.9 Options shapes (`option_set` / `option_show`)

**`ShownRow`** is custom-serialized (`D/options.rs:177-205`) and has two disjoint forms.

| key | wire type | notes | source |
|---|---|---|---|
| `name` | string | both forms | `D/options.rs:189,197` |
| `source` | string enum | `default` / `file` / `cli` / `runtime` | `D/options.rs:190,198` |
| `runtime` | bool | always `false` on the secret form | `D/options.rs:191,199` |
| `value` | string or `null` | value form only; `null` means unset | `D/options.rs:192` |
| `secret` | bool (`true`) | secret form only | `D/options.rs:200` |
| `set` | bool | secret form only | `D/options.rs:201` |

**`Refusal`** is the JSON-RPC `error.data[]` element (`D/options.rs:250-262`).

| key | wire type | notes | source |
|---|---|---|---|
| `code` | string | e.g. `config.value.range` | `D/options.rs:251-252` |
| `option` | string? | omitted when `None` | `D/options.rs:253-255` |
| `source` | string | | `D/options.rs:256-257` |
| `params` | `[[string,string]]` | **positional pairs**: `Vec<(String,String)>` | `D/options.rs:258-259` |
| `message` | string | | `D/options.rs:260-261` |

### 1.10 Chain-reads shapes (C++-served; Rust client mirrors in `T/chain_reads.rs` agree)

**`chain_info`** (`get_alternate_chains.chains[]`, `H:921-942`; mirror `T/chain_reads.rs:40-58`):

| key | wire type | notes | source |
|---|---|---|---|
| `block_hash` | hash64 | tip | `H:933` |
| `height` | u64 | tip height | `H:934` |
| `length` | u64 | alt blocks in the chain | `H:935` |
| `difficulty` | u64 | tip **cumulative** difficulty, low 64 | `H:936`, `T/chain_reads.rs:47-48` |
| `wide_difficulty` | hex128 | cumulative | `H:937` |
| `difficulty_top64` | u64 | cumulative, high 64 | `H:938` |
| `block_hashes` | [hash64] | tip first; never empty | `H:939` |
| `main_chain_parent_block` | hash64 | | `H:940` |

**`ban`, GETBANS form** (`get_bans.bans[]`, `H:750-763`):

| key | wire type | source |
|---|---|---|
| `host` | string | `H:758` |
| `ip` | u32 | `H:759` |
| `seconds` | u32 | `H:760` |
| `permanent` | bool | `H:761` |

**`ban`, SETBANS form** (`set_bans` params `bans[]`, `H:787-800`). This is a different struct under the same name.

| key | wire type | source |
|---|---|---|
| `host` | string | `H:795` |
| `ip` | u32 | `H:796` |
| `ban` | bool | `H:797` |
| `seconds` | u32 | `H:798` |

**`tx_backlog_entry` (`get_miner_data`)** (`H:367-378`):

| key | wire type | source |
|---|---|---|
| `id` | hash64 | `H:374`, `S:549` (`pod_to_hex`) |
| `weight` | u64 | `H:375` |
| `fee` | u64 | `H:376` |

**`tx_backlog_entry` (`get_txpool_backlog`)** (`H:629-634`) has **no KV map**. It is a POD `{weight u64, fee u64, time_in_pool u64}` that travels only as bytes inside `backlog` (§2.23).

### 1.11 Archival shapes

Rust mirrors live in `T/archival_reads.rs`; the C++ structs are canonical for the C++-served methods.

**`bond_row_t`** (`H:1122-1134`; mirror `T/archival_reads.rs:35-41`):

| key | wire type | notes | source |
|---|---|---|---|
| `join_settlement_epoch` | u64 | | `H:1130` |
| `is_foundation_complete_tree` | bool | | `H:1131` |
| `bad_intervals_flat` | [u64] | **flattened** `[start, end_exclusive, …]` pairs | `H:1126-1132` |

**`shard_row_t`** (`H:1137-1148`):

| key | wire type | source |
|---|---|---|
| `shard_id` | u64 | `H:1144` |
| `freeze_height` | u64 | `H:1145` |
| `has_segment` | bool | `H:1146` |

**`credit_pair_t`** (`H:1151-1160`):

| key | wire type | notes | source |
|---|---|---|---|
| `bond_idx` | u64 | index into `bonds` | `H:1157` |
| `shard_idx` | u64 | index into `shards` | `H:1158` |

**`epoch_snapshot_t`** (`H:1164-1202`):

| key | wire type | notes | source |
|---|---|---|---|
| `settlement_epoch` | u64 | | `H:1192` |
| `close_block_height` | u64 | close-processing height `(E+1)·SEB` | `H:1167-1171,1193` |
| `sigma_work_milli` | u64 | milli units | `H:1194` |
| `budget_atomic` | u64 | atomic units, a number | `H:1195` |
| `has_budget_row` | bool | presence flag for budget / sigma | `H:1196` |
| `bonds` | [bond_row_t] | | `H:1197` |
| `shards` | [shard_row_t] | | `H:1198` |
| `credit_pairs` | [credit_pair_t] | | `H:1199` |
| `claimant_bond_idx` | u64 | `UINT64_MAX` sentinel means none | `H:1185-1189,1200` |

**`coverage_row_t`** (`H:1313-1330`):

| key | wire type | notes | source |
|---|---|---|---|
| `shard_id` | u64 | | `H:1323` |
| `bonded_count` | u64 | | `H:1324` |
| `served_count` | u64 | | `H:1325` |
| `freeze_height` | u64 | | `H:1326` |
| `join_scarcity_micro` | u64 | micro units | `H:1327` |
| `expected_profit_atomic` | u64 | | `H:1328` |

### 1.12 `.bin` shapes (portable_storage, not JSON)

**`BlockEntry`** (`T/bin_commands.rs:216-221,245-249`):

| key | wire type | notes | source |
|---|---|---|---|
| `block` | blob (raw bytes) | | `T/bin_commands.rs:246` |
| `txs` | [blob]? | an array of raw byte strings; omitted when empty | `T/bin_commands.rs:247-249` |

---

## 2. Methods

**Visibility key**

| value | meaning |
|---|---|
| `both` | served on the restricted (view) and admin listeners |
| `admin` (JSON-RPC) | in `RESTRICTED_METHODS` (`D/handlers/json_rpc.rs:49-66`); the restricted listener answers HTTP 403 with `-32601 "Method not allowed in restricted mode"` |
| `admin` (REST) | `Visibility::AdminOnly` in `D/server.rs:209-326`; the path is not registered, so the restricted listener answers 404 |

### Rust-native JSON-RPC methods

Dispatch: `native_method_for`, `D/handlers/json_rpc.rs:214-243`. Arms: `D/handlers/json_rpc.rs:252-440`.

#### 2.1 `get_version`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | both |
| aliases | none |
| params | none (ignored) |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/chain.rs:477` |
| `version` | u32 | packed `major<<16 \| minor` (3.58 is 196666) | `T/chain.rs:478-479,197-199` |
| `release` | bool | | `T/chain.rs:480-481` |
| `current_height` | u64 | chain **count** | `T/chain.rs:482-483`, `D/methods.rs:187` |
| `target_height` | nullable<u64> | | `T/chain.rs:484-487` |
| `consensus_constants_digest` | hash64 | | `T/chain.rs:506` |
| `nettype` | string enum | `mainnet` / `testnet` / `stagenet` / `fakechain` | `T/chain.rs:512`, `T/consensus_digest.rs:76-85` |
| `genesis_hash` | hash64 | | `T/chain.rs:520` |

#### 2.2 `get_block_count`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | both |
| aliases | `getblockcount` |
| params | ignored (the legacy C++ request was a positional list nobody read; `D/methods.rs:196-200`) |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/chain.rs:326` |
| `count` | u64 | chain count | `T/chain.rs:327-328` |

#### 2.3 `on_get_block_hash`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | both |
| aliases | `on_getblockhash` |

**Params are positional.**

| key | wire type | notes | source |
|---|---|---|---|
| `params[0]` | u64 | exactly `[height]`; `[]`, `[1,2]`, `["1"]`, `{}` are refused with -1 | `T/chain.rs:341-343`, `D/methods.rs:220-226` |

| key | wire type | notes | source |
|---|---|---|---|
| `result` | hash64 | a **bare string**: no object, no `status` | `D/methods.rs:447-451` |

#### 2.4 `get_block_header_by_height`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | both |
| aliases | `getblockheaderbyheight` |

| key | wire type | notes | source |
|---|---|---|---|
| `height` | u64 | defaults to 0 | `T/chain.rs:458-460` |
| `fill_pow_hash` | bool | defaults to false. **Silently blanked** on the restricted listener (`pow_hash_entitled`) | `T/chain.rs:461-462`, `D/handlers/json_rpc.rs:183-185,424-438` |

The params must be an object or `null` (`D/methods.rs:290-302`).

| key | wire type | source |
|---|---|---|
| `status` | string | `T/chain.rs:469` |
| `block_header` | block_header (§1.2) | `T/chain.rs:470` |

#### 2.5 `get_block`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | both |
| aliases | `getblock` |

| key | wire type | notes | source |
|---|---|---|---|
| `hash` | string (hash64 text, not typed) | a non-empty value wins over `height` | `T/chain.rs:408-410` |
| `height` | u64 | defaults to 0 | `T/chain.rs:411-412` |
| `fill_pow_hash` | bool | **blanked** on restricted | `T/chain.rs:413-414`, `D/handlers/json_rpc.rs:279-290` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/chain.rs:428` |
| `block_header` | block_header | | `T/chain.rs:429` |
| `miner_tx_hash` | hash64 | **duplicates** `block_header.miner_tx_hash` | `T/chain.rs:430`, `D/methods.rs:380-381` |
| `tx_hashes` | [hash64]? | omitted when the block has no transactions | `T/chain.rs:431-435` |
| `blob` | hexstr | the block in consensus encoding | `T/chain.rs:436-437`, `D/methods.rs:391` |
| `json` | string? (embedded JSON) | epee rendering; omitted by store-backed handlers | `T/chain.rs:438-442` |

#### 2.6 `sync_info`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | **admin** |
| aliases | none |
| params | none |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | `"offline"` when P2P is off, with no other key | `T/p2p.rs:281`, `T/p2p.rs:357-403` |
| `height` | u64 | chain count | `T/p2p.rs:282-283` |
| `target_height` | nullable<u64> | | `T/p2p.rs:284-286` |
| `peers` | [{`info`: ConnectionInfo}]? | | `T/p2p.rs:287-288` |
| `spans` | [SyncSpan]? | | `T/p2p.rs:289-290` |
| `overview` | string | an ASCII picture, `"[]"` when empty | `T/p2p.rs:291-293` |

#### 2.7 `get_connections`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | **admin** |
| aliases | none |
| params | none |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | or the offline form | `T/p2p.rs:244` |
| `connections` | [ConnectionInfo]? | | `T/p2p.rs:245-246`, `D/methods.rs:1330` |

#### 2.8 `get_last_block_header`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | both |
| aliases | `getlastblockheader` |

| key | wire type | notes | source |
|---|---|---|---|
| `fill_pow_hash` | bool? | **Refused with -19** on restricted (`pow_hash_or_refuse`) | `T/headers.rs:26-31`, `D/methods.rs:823-832` |

| key | wire type | source |
|---|---|---|
| `status` | string | `T/headers.rs:45` |
| `block_header` | block_header | `T/headers.rs:46` |

#### 2.9 `get_block_header_by_hash`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | both |
| aliases | `getblockheaderbyhash` |

| key | wire type | notes | source |
|---|---|---|---|
| `hashes` | [hash64] | answered positionally. The singular `hash` was deleted and is now refused | `T/headers.rs:59-62`, `T/headers.rs:257-266` |
| `fill_pow_hash` | bool? | **refused -19** on restricted | `T/headers.rs:63-67` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/headers.rs:97` |
| `block_headers` | [BlockHeaderSlot] (§1.3)? | in request order | `T/headers.rs:98-100` |

#### 2.10 `get_block_headers_range`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | both |
| aliases | `getblockheadersrange` |

| key | wire type | notes | source |
|---|---|---|---|
| `start_height` | u64 | **required**; absent params or `{}` are refused | `T/headers.rs:116`, `D/methods.rs:261-272,875-886` |
| `end_height` | u64 | required, inclusive | `T/headers.rs:117-118` |
| `fill_pow_hash` | bool? | **refused -19** on restricted | `T/headers.rs:119-120` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/headers.rs:127` |
| `headers` | [block_header]? | plain headers, **not** slots | `T/headers.rs:128-129` |

#### 2.11 `get_fee_estimate`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | both |
| aliases | none |
| params | `{}` or `null`; any member is refused (`grace_blocks` was deleted in 3.57) (`T/headers.rs:177-179`, `D/methods.rs:890-896`) |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/headers.rs:195` |
| `fees` | [u64; 3] | **positional** tiers `[low, normal, high]`, exactly 3 | `T/headers.rs:154-169,196` |

#### 2.12 `request_archival_shard`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | **admin** |
| aliases | none |

| key | wire type | notes | source |
|---|---|---|---|
| `shard_id` | u64 | required; the params must be an object | `T/archival.rs:34-40`, `D/shard_view.rs:93-102` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/archival.rs:48` |
| `shard_id` | u64 | | `T/archival.rs:49` |
| `shard_hash` | hash64 | | `T/archival.rs:50-52` |
| `archival_len` | u64 | bytes | `T/archival.rs:53-54` |
| `block_count` | u64 | | `T/archival.rs:55-56` |
| `tx_count` | u64 | | `T/archival.rs:57-58` |
| `output_count` | u64 | | `T/archival.rs:59-60` |
| `coinbase_output_count` | u64 | | `T/archival.rs:61-62` |
| `time_range_seconds` | u64 | | `T/archival.rs:63-64` |
| `close_height` | u64 | | `T/archival.rs:65-69` |

Refusal codes: -22, -24, -25 (`T/archival.rs:92-96`).

#### 2.13 `option_set`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | **admin** |
| aliases | none |

| key | wire type | notes | source |
|---|---|---|---|
| `options` | [{`name`: string, `value`: string}] | non-empty; no duplicate names | `D/options.rs:323-336,363-383` |

| key | wire type | notes | source |
|---|---|---|---|
| `options` | [ShownRow] (§1.9) | **no `status`** | `D/options.rs:347-352,405-414` |

A refusal is error -26 with `data` set to `[Refusal]` (`D/options.rs:440-457`).

#### 2.14 `option_show`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | Rust native |
| visibility | both (rows filtered by grant: the restricted listener sees only Health rows; `D/options.rs:38-50,421-437`, `D/info.rs:86-106`) |
| aliases | none |

| key | wire type | notes | source |
|---|---|---|---|
| `names` | [string]? | absent or `null` params mean every row | `D/options.rs:339-344,391-399` |

| key | wire type | notes | source |
|---|---|---|---|
| `options` | [ShownRow] | **no `status`** | `D/options.rs:347-352` |

#### 2.15 `get_info` (also REST `/get_info`, `/getinfo`; same function, `D/handlers/json.rs:302-312`)

| attribute | value |
|---|---|
| transport | JSON-RPC **and** REST |
| owner | Rust native |
| visibility | both (parts withheld on restricted) |
| aliases | `/getinfo` (REST only) |
| params | ignored |

The serializer is the flat `GetInfoWire` (`T/info.rs:408-491`). It goes through `try_from`/`into`, so the Rust part names (`health`, `chain`, …) are not keys.

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/info.rs:411` |
| `height` | u64 | Health | `T/info.rs:414` |
| `top_block_hash` | hash64 | Health | `T/info.rs:415` |
| `target_height` | nullable<u64> | Health | `T/info.rs:416` |
| `synchronized` | bool | Health | `T/info.rs:417` |
| `busy_syncing` | bool | Health | `T/info.rs:418` |
| `offline` | bool | Health | `T/info.rs:419` |
| `following_degraded` | bool | Health | `T/info.rs:420` |
| `has_peers` | bool? | omitted iff `offline` | `T/info.rs:421-422` |
| `protocol_version` | u64 | Identity | `T/info.rs:425` |
| `wide_difficulty` | hex128 | Chain. **No low-64 / top64 siblings here** | `T/info.rs:428` |
| `wide_cumulative_difficulty` | hex128 | Chain | `T/info.rs:429` |
| `target` | u64 | seconds | `T/info.rs:430` |
| `tx_count` | u64 | | `T/info.rs:431` |
| `block_weight_limit` | u64 | written even at 0 | `T/info.rs:434` |
| `block_weight_median` | u64 | | `T/info.rs:435` |
| `adjusted_time` | u64 | | `T/info.rs:436` |
| `already_generated_coins` | **atomic-dec** | Economics | `T/info.rs:443` |
| `release_multiplier` | u64 | | `T/info.rs:444` |
| `burn_pct` | u64 | | `T/info.rs:445` |
| `total_burned` | **atomic-dec** | | `T/info.rs:446` |
| `staker_emission_share_effective` | u64 | | `T/info.rs:447` |
| `tx_pool_size` | u64 | Pool | `T/info.rs:450` |
| `start_time` | u64? | Status part; admin only | `T/info.rs:453-454` |
| `free_space` | u64? | Status | `T/info.rs:455-456` |
| `database_size` | u64? | Status | `T/info.rs:457-458` |
| `version` | string? | Status; a build string, unlike `get_version.version` (u32) | `T/info.rs:459-460` |
| `outgoing_connections_count` | u64? | Status; omitted if offline | `T/info.rs:461-462` |
| `incoming_connections_count` | u64? | Status | `T/info.rs:463-464` |
| `alt_blocks_count` | u64? | Status | `T/info.rs:465-466` |
| `rpc_connections_count` | u64? | Status | `T/info.rs:467-468` |
| `public_incoming_socket_count` | u64? | Peers part; admin only | `T/info.rs:471-472` |
| `public_outgoing_socket_count` | u64? | Peers | `T/info.rs:473-474` |
| `tor_incoming_socket_count` | u64? | Peers | `T/info.rs:475-476` |
| `tor_outgoing_socket_count` | u64? | Peers | `T/info.rs:477-478` |
| `p2p` | string enum? | `running` / `offline`; Peers | `T/info.rs:479-480,494-499` |
| `white_peerlist_size` | u64? | Peers | `T/info.rs:481-482` |
| `grey_peerlist_size` | u64? | Peers | `T/info.rs:483-484` |
| `tx_pool_unbroadcast_count` | u64? | Host part; admin only | `T/info.rs:487-488` |
| `restricted` | bool | the listener's posture | `T/info.rs:490` |

### C++-table JSON-RPC methods

Dispatch: `get_jsonrpc_table`, `F:248-280`. Handlers are in `S`. Results pass through Rust untouched (`D/handlers/json_rpc.rs:125-129`).

#### 2.16 `get_block_template`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | both |
| aliases | `getblocktemplate` (`F:256`) |
| handler | `S:430` |

| key | wire type | notes | source |
|---|---|---|---|
| `reserve_size` | u64 | at most 8 | `H:298,305` |
| `wallet_address` | string | | `H:299,306` |
| `prev_block` | string | any non-empty value is refused | `H:300,307`, `S:502` |
| `extra_nonce` | hexstr | at most 16 hex chars | `H:301,308` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `difficulty` | u64 | low 64 | `H:330` |
| `wide_difficulty` | hex128 | | `H:331` |
| `difficulty_top64` | u64 | | `H:332` |
| `height` | u64 | | `H:333` |
| `reserved_offset` | u64 | | `H:334` |
| `expected_reward` | u64 | atomic, a number | `H:335` |
| `prev_hash` | hash64 | | `H:336` |
| `seed_height` | u64 | | `H:337` |
| `blocktemplate_blob` | hexstr | | `H:338`, `S:517` |
| `blockhashing_blob` | hexstr | | `H:339` |
| `seed_hash` | hash64 | | `H:340` |
| `next_seed_hash` | hash64 or `""` | set only when it differs from `seed_hash` (`S:509`) | `H:341`, `S:510` |

#### 2.17 `get_miner_data`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | both |
| aliases | none |
| params | none |
| handler | `S:523` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `major_version` | u8 | | `H:384` |
| `height` | u64 | | `H:385` |
| `prev_id` | hash64 | | `H:386` |
| `seed_hash` | hash64 | | `H:387` |
| `difficulty` | **hex128 string** | `cryptonote::hex`; elsewhere `difficulty` is u64 | `H:363,388`, `S:554` |
| `median_weight` | u64 | | `H:389` |
| `already_generated_coins` | **u64 number** | `get_info` sends it as atomic-dec | `H:390` |
| `tx_backlog` | [{`id` hash64, `weight` u64, `fee` u64}] | | `H:367-380,391` |

#### 2.18 `calc_pow`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | **admin** |
| aliases | none |
| handler | `S:560`; dispatch `F:226-245` |

| key | wire type | notes | source |
|---|---|---|---|
| `height` | u64 | | `H:401,407` |
| `block_blob` | hexstr | a hashing blob | `H:402,408` |
| `seed_hash` | hash64 or `""` | | `H:403,409` |

| key | wire type | notes | source |
|---|---|---|---|
| `result` | hash64 | a **bare string**, no `status` | `H:414`, `S:604` |

#### 2.19 `submit_block`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | both |
| aliases | `submitblock` |
| handler | `S:608`; dispatch `F:187-223` |

**Params are positional.**

| key | wire type | notes | source |
|---|---|---|---|
| `params[0]` | hexstr | `[block_blob_hex]`, exactly one element. The dispatcher hand-scans the array for quoted strings | `H:420`, `F:187-223` |

| key | wire type | source |
|---|---|---|
| `status` | string | base |
| `block_id` | hash64 | `H:424,428`, `S:653` |

#### 2.20 `generateblocks`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | **admin** (also requires regtest) |
| aliases | none |
| handler | `S:658` |

| key | wire type | notes | source |
|---|---|---|---|
| `amount_of_blocks` | u64 | | `H:438,445` |
| `wallet_address` | string | | `H:439,446` |
| `prev_block` | string | non-empty is refused | `H:440,447` |
| `starting_nonce` | u32? | `OPT 0` | `H:441,448` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `height` | u64 | | `H:455,460` |
| `blocks` | [hash64] | block ids | `H:456,461`, `S:729` |

#### 2.21 `inject_archival_serve_credit`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | **both**: it is not in `RESTRICTED_METHODS`; the handler gates it on nettype (regtest / FAKECHAIN) |
| aliases | none |
| handler | `S:739` |

| key | wire type | notes | source |
|---|---|---|---|
| `p_canonical_id` | hash64 | | `H:474,480` |
| `shard_id` | u64 | | `H:475,481` |
| `settlement_epoch` | u64 | | `H:476,482` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `height` | u64 | a block **index**, not a count | `H:489-494,498` |

#### 2.22 `set_bans`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | **admin** |
| aliases | none |
| handler | `S:856` |

| key | wire type | notes | source |
|---|---|---|---|
| `bans` | [ban SETBANS form: `host`, `ip`, `ban`, `seconds`] | | `H:787-809` |

| key | wire type | source |
|---|---|---|
| `status` | string | `H:813-818` |

#### 2.23 `get_bans`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | **admin** |
| aliases | none |
| params | none |
| handler | `S:793` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `bans` | [ban GETBANS form: `host`, `ip`, `seconds`, `permanent`] | | `H:750-780` |

#### 2.24 `banned`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | **admin** |
| aliases | none |
| handler | `S:824` |

The request and response structs have no base parent.

| key | wire type | notes | source |
|---|---|---|---|
| `address` | string | host | `H:824-831` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | declared directly | `H:836,842` |
| `banned` | bool | | `H:837,843` |
| `seconds` | u32 | | `H:838,844` |
| `permanent` | bool | | `H:839,845` |

#### 2.25 `flush_txpool`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | **admin** |
| aliases | none |
| handler | `S:924` |

| key | wire type | notes | source |
|---|---|---|---|
| `txids` | [hash64] | empty means flush everything | `H:855,859` |

| key | wire type | source |
|---|---|---|
| `status` | string | `H:864-869` |

#### 2.26 `get_coinbase_tx_sum`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | **admin** |
| aliases | none |
| handler | `S:978` |

| key | wire type | source |
|---|---|---|
| `height` | u64 | `H:877,882` |
| `count` | u64 | `H:878,883` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `emission_amount` | u64 | low 64 | `H:890,899` |
| `wide_emission_amount` | hex128 | | `H:891,900` |
| `emission_amount_top64` | u64 | | `H:892,901` |
| `fee_amount` | u64 | | `H:893,902` |
| `wide_fee_amount` | hex128 | | `H:894,903` |
| `fee_amount_top64` | u64 | | `H:895,904` |

Rust mirror: `T/chain_reads.rs:83-91`.

#### 2.27 `get_alternate_chains`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | **admin** |
| aliases | none |
| params | none |
| handler | `S:995` |

| key | wire type | source |
|---|---|---|
| `status` | string | base |
| `chains` | [chain_info] (§1.10) | `H:946,950` |

#### 2.28 `relay_tx`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | **admin** |
| aliases | none |
| handler | `S:1048` |

| key | wire type | source |
|---|---|---|
| `txids` | [hash64] | `H:960,964` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | a failure is returned as a JSON-RPC error | `H:969-974` |

#### 2.29 `get_txpool_backlog`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | both |
| aliases | none |
| params | none |
| handler | `S:1117` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `backlog` | string of **raw POD bytes** | `KV_SERIALIZE_CONTAINER_POD_AS_BLOB`: 24 bytes per entry (`weight`, `fee`, `time_in_pool` as LE u64). The JSON escaping is epee's; not verified here | `H:629-634,648,652` |

#### 2.30 `flush_cache`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | **admin** |
| aliases | none |
| handler | `S:1133` |

| key | wire type | notes | source |
|---|---|---|---|
| `bad_blocks` | bool? | `OPT false` | `H:1009,1013` |

| key | wire type | source |
|---|---|---|
| `status` | string | `H:1018-1023` |

#### 2.31 `get_curve_tree_info`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | both |
| aliases | none |
| params | none |
| handler | `S:1142` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `root` | hexstr | | `H:1039,1046`, `S:1148` |
| `depth` | u8 | | `H:1040,1047` |
| `leaf_count` | u64 | | `H:1041,1048` |
| `height` | u64 | **index**: `chain_height - 1` | `H:1042,1049`, `S:1152` |

#### 2.32 `get_curve_tree_checkpoint`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | both |
| aliases | none |
| handler | `S:1157` |

| key | wire type | source |
|---|---|---|
| `block_height` | u64 | `H:1059,1063` |

| key | wire type | source |
|---|---|---|
| `status` | string | base |
| `root` | hexstr | `H:1070,1077`, `S:1177` |
| `depth` | u8 | `H:1071,1078` |
| `leaf_count` | u64 | `H:1072,1079` |
| `block_height` | u64 | `H:1073,1080` |

#### 2.33 `get_archival_emission_claim_source`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | both |
| aliases | none |
| handler | `S:1186` |

| key | wire type | notes | source |
|---|---|---|---|
| `p_id` | hash64 | the persona's `P_canonical_id`; the only request field | `H:1110-1116` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `chain_height` | u64 | count | `H:1209,1281` |
| `current_settled_epoch` | u64 | | `H:1214,1282` |
| `has_bond_record` | bool | presence flag | `H:1217,1283` |
| `join_settlement_epoch` | u64 | | `H:1219,1284` |
| `holdings_kind` | u8 | 0 = shard set, 1 = foundation tree | `H:1220-1222,1285` |
| `held_shard_ids` | [u64] | | `H:1223,1286` |
| `claimed_settlement_epochs` | [u64] | | `H:1226,1287` |
| `bonded_total_atomic` | u64 | | `H:1232,1288` |
| `bad_interval_count` | u64 | | `H:1246,1289` |
| `has_last_served_epoch` | bool | presence flag | `H:1261,1290` |
| `last_served_epoch` | u64 | | `H:1263,1291` |
| `has_last_settled_slash_epoch` | bool | presence flag | `H:1273,1292` |
| `last_settled_slash_epoch` | u64 | | `H:1275,1293` |
| `epochs` | [epoch_snapshot_t] (§1.11) | | `H:1277,1294` |

Rust mirror: `T/archival_reads.rs:84-110`.

#### 2.34 `get_archival_shard_coverage`

| attribute | value |
|---|---|
| transport | JSON-RPC |
| owner | C++ |
| visibility | both |
| aliases | none |
| params | none |
| handler | `S:1223` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `as_of_height` | u64 | | `H:1334,1345` |
| `leaf_count` | u64 | | `H:1335,1346` |
| `frozen_count` | u64 | | `H:1336,1347` |
| `settled_epoch` | u64 | | `H:1337,1348` |
| `budget_atomic` | u64 | | `H:1338,1349` |
| `sigma_work_milli` | u64 | | `H:1339,1350` |
| `profit_estimate_available` | bool | | `H:1340,1351` |
| `shards` | [coverage_row_t] (§1.11) | | `H:1341,1352` |

### REST and binary routes

Route table: `D/server.rs:209-326`. Handlers: `D/server.rs:365-402`.

The DJSON rows (C++ REST) are in `F:170-181`. **For the DJSON rows, a bodyless request skips the KV load** (`F:103`, `if (body_json && body_json[0])`). Their request struct then stays value-initialised, so `OPT` defaults do not apply. The mechanism is documented at `D/handlers/json.rs:507-516`.

#### 2.35 `/get_height` (alias `/getheight`)

| attribute | value |
|---|---|
| transport | REST (GET / POST) |
| owner | Rust native |
| visibility | both |
| aliases | `/getheight` |
| params | body ignored (`D/handlers/json.rs:100`) |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/chain.rs:313` |
| `height` | u64 | chain **count** (top + 1) | `T/chain.rs:314-316`, `D/methods.rs:159-166` |
| `hash` | hash64 | the top block's hash | `T/chain.rs:317-318` |

#### 2.36 `/get_transactions` (alias `/gettransactions`)

| attribute | value |
|---|---|
| transport | REST |
| owner | Rust native |
| visibility | both (restricted callers are capped and see only broadcast pool transactions) |
| aliases | `/gettransactions` |

| key | wire type | notes | source |
|---|---|---|---|
| `txs_hashes` | [string] | hash64 text, not typed | `T/transactions.rs:41-50` |
| `decode_as_json` | bool | default false; **selects a representation** (`as_json`) | `T/transactions.rs:51-52` |
| `prune` | bool? | `OPT false`; **selects a representation** | `T/transactions.rs:53-55` |
| `split` | bool? | `OPT false`; **selects a representation** (`pruned_as_hex` / `prunable_as_hex` against `as_hex`) | `T/transactions.rs:56-58` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/transactions.rs:311` |
| `txs` | [TxEntry] (§1.7)? | | `T/transactions.rs:312-313` |
| `missed_tx` | [hash64]? | | `T/transactions.rs:314-316` |

#### 2.37 `/get_alt_blocks_hashes`

| attribute | value |
|---|---|
| transport | REST |
| owner | **C++** (DJSON `F:170`; handler `S:136`) |
| visibility | both |
| aliases | none |
| params | none |

A Rust client mirror exists at `T/chain_reads.rs:29-35`.

| key | wire type | source |
|---|---|---|
| `status` | string | base |
| `blks_hashes` | [hash64] | `H:123,127`, `S:152` |

#### 2.38 `/is_key_image_spent`

| attribute | value |
|---|---|
| transport | REST |
| owner | Rust native |
| visibility | both (restricted callers are capped) |
| aliases | none |

| key | wire type | notes | source |
|---|---|---|---|
| `key_images` | [string] | hash64 text | `T/transactions.rs:380-387` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/transactions.rs:398` |
| `spent_status` | [u8]? | **positional**: index-paired with `key_images`; 0 unspent, 1 in chain, 2 in pool | `T/transactions.rs:325-339,399-400` |

#### 2.39 `/submit_transaction`

| attribute | value |
|---|---|
| transport | REST, POST only |
| owner | Rust native |
| visibility | both |
| aliases | none |

| key | wire type | notes | source |
|---|---|---|---|
| `tx_blob` | hexstr | | `T/lib.rs:147-151` |

The reply is tagged and has **no `status`**.

| key | wire type | notes | source |
|---|---|---|---|
| `verdict` | string enum | `accepted` / `already_in_pool` / `already_in_chain` / `rejected` | `T/lib.rs:165-206` |
| `height` | u64 | `already_in_chain` only | `T/lib.rs:195-198` |
| `cause` | string enum | `rejected` only: `malformed`, `fee_too_low`, `double_spend_conflict`, `stale_root`, `reference_too_recent`, `reference_not_found`, `join_market_unsupported`; `unrecognized` is only the client's `#[serde(other)]` decode fallback for an unknown value; the daemon never sends it | `T/lib.rs:202-205,218-266` |

A request error is HTTP 400 plain text. An internal fault is HTTP 500 plain text (`D/handlers/submit.rs:29-94`).

#### 2.40 `/get_transaction_pool`

| attribute | value |
|---|---|
| transport | REST |
| owner | C++ (DJSON `F:171`; `S:295`) |
| visibility | both (restricted callers see broadcast-only) |
| aliases | none |
| params | none |

| key | wire type | source |
|---|---|---|
| `status` | string | base |
| `transactions` | [tx_info] (§1.8) | `H:594,599` |
| `spent_key_images` | [spent_key_image_info] | `H:595,600` |

#### 2.41 `/get_transaction_pool_hashes`

| attribute | value |
|---|---|
| transport | REST |
| owner | C++ (DJSON `F:172`; `S:315`) |
| visibility | both |
| aliases | none |
| params | none |

| key | wire type | source |
|---|---|---|
| `status` | string | base |
| `tx_hashes` | [hash64] | `H:619,623` |

#### 2.42 `/get_transaction_pool_stats`

| attribute | value |
|---|---|
| transport | REST |
| owner | C++ (DJSON `F:173`; `S:336`) |
| visibility | both |
| aliases | none |
| params | none |

| key | wire type | source |
|---|---|---|
| `status` | string | base |
| `pool_stats` | txpool_stats (§1.8) | `H:716,720` |

#### 2.43 `/get_info` (alias `/getinfo`)

Same reply as §2.15.

#### 2.44 `/get_blocks_by_height.bin` (alias `/getblocks_by_height.bin`)

| attribute | value |
|---|---|
| transport | **binary** (portable_storage), POST |
| owner | Rust native |
| visibility | both (restricted callers are capped at 1000) |
| aliases | `/getblocks_by_height.bin` |

| key | wire type | notes | source |
|---|---|---|---|
| `heights` | uint64 array? | omitted when empty | `T/bin_commands.rs:164-198` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string (bytes) | | `T/bin_commands.rs:241` |
| `blocks` | [section `{block, txs?}`]? | BlockEntry (§1.12) | `T/bin_commands.rs:242-253` |

#### 2.45 `/get_o_indexes.bin`

| attribute | value |
|---|---|
| transport | **binary**, POST |
| owner | Rust native |
| visibility | both |
| aliases | none |

| key | wire type | notes | source |
|---|---|---|---|
| `txid` | blob of 32 **raw bytes** (not hex) | | `T/bin_commands.rs:62-66,77` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | `"Failed"` when the transaction is unknown | `T/bin_commands.rs:125`, `D/handlers/binary.rs:137-140` |
| `o_indexes` | uint64 array? | | `T/bin_commands.rs:113,126-131` |

#### 2.46 `/get_stem_tallies`

| attribute | value |
|---|---|
| transport | REST |
| owner | C++ (hand-built JSON; `D/handlers/json.rs:598` → `S:786-789` → `src/p2p/net_node.inl:772-826`) |
| visibility | **admin** |
| aliases | none |
| params | none |

The reply has **no `status`**.

| key | wire type | notes | source |
|---|---|---|---|
| `floor` | [object] | per connector; "no data" connectors are omitted | `net_node.inl:794-815` |
| `floor[].connector` | string | connector name | `net_node.inl:806-807` |
| `floor[].achieved_out_connections` | u32 | | `net_node.inl:808-809` |
| `floor[].floor` | u32 | **same key as its parent array** | `net_node.inl:810-811` |
| `floor[].below` | bool | | `net_node.inl:812-813` |
| `tallies` | [object] | per peer | `net_node.inl:816-822` |
| `tallies[].peer` | hexstr | the peer id's 16 bytes, so 32 hex chars (`levin_notify.h:185`) | `src/cryptonote_protocol/levin_notify.cpp:1796-1801` |
| `tallies[].connector` | string | `"unnamed"` if unknown | `levin_notify.cpp:1802-1806` |
| `tallies[].propagated` | u64 | count | `levin_notify.cpp:1807-1808`, `src/cryptonote_protocol/levin_notify.h:186` |
| `tallies[].silent` | u64 | count | `levin_notify.cpp:1809-1810`, `levin_notify.h:187` |
| `tallies[].distinct_sources` | u64 | count | `levin_notify.cpp:1811-1812`, `levin_notify.h:188` |

#### 2.47 `/start_mining`

| attribute | value |
|---|---|
| transport | REST |
| owner | C++ (DJSON `F:175`; `S:163`), with a Rust pre-check (`D/handlers/json.rs:418-452`) |
| visibility | **admin** |
| aliases | none |

| key | wire type | notes | source |
|---|---|---|---|
| `miner_address` | string | required (Rust check) | `H:181,186` |
| `threads_count` | u64 | required; 0 means auto | `H:182,187` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | a failure sentence, or HTTP 400 with the REST envelope | `H:192-197` |

#### 2.48 `/stop_mining`

| attribute | value |
|---|---|
| transport | REST |
| owner | C++ (`F:176`; `S:214`) |
| visibility | **admin** |
| aliases | none |
| params | none |

| key | wire type | source |
|---|---|---|
| `status` | string | `H:214-219` |

#### 2.49 `/mining_status`

| attribute | value |
|---|---|
| transport | REST |
| owner | C++ (`F:177`; `S:234`) |
| visibility | **admin** |
| aliases | none |
| params | none |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `active` | bool | | `H:237,250` |
| `speed` | u64 | **hashes/s** (a percentage in SyncSpan) | `H:238,251` |
| `threads_count` | u32 | | `H:239,252` |
| `address` | string | `""` when not mining | `H:240,253`, `S:261` |
| `pow_algorithm` | string | `"RandomX"` | `H:241,254`, `S:262` |
| `block_target` | u32 | seconds | `H:242,255` |
| `block_reward` | u64 | atomic, a number | `H:243,256` |
| `difficulty` | u64 | next-block difficulty, low 64 | `H:244,257` |
| `wide_difficulty` | hex128 | | `H:245,258` |
| `difficulty_top64` | u64 | | `H:246,259` |

#### 2.50 `/save_bc`

| attribute | value |
|---|---|
| transport | REST |
| owner | C++ (`F:178`; `S:268`) |
| visibility | **admin** |
| aliases | none |
| params | none |

| key | wire type | source |
|---|---|---|
| `status` | string | `H:277-282` |

#### 2.51 `/get_peer_list`

| attribute | value |
|---|---|
| transport | REST |
| owner | Rust native |
| visibility | **admin** |
| aliases | none |

| key | wire type | notes | source |
|---|---|---|---|
| `public_only` | bool? | defaults to **true**; omitted when true | `T/p2p.rs:64-68` |
| `include_blocked` | bool? | defaults to false | `T/p2p.rs:69-71` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | or the offline form | `T/p2p.rs:133` |
| `white_list` | [Peer] (§1.6)? | | `T/p2p.rs:135-136` |
| `gray_list` | [Peer]? | | `T/p2p.rs:137-138` |

#### 2.52 `/set_log_hash_rate`

| attribute | value |
|---|---|
| transport | REST |
| owner | C++ (`F:179`; `S:280`) |
| visibility | **admin** |
| aliases | none |

| key | wire type | notes | source |
|---|---|---|---|
| `visible` | bool | value-initialised to false when the body is empty | `H:514,518` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | `"OK"` or `"NOT MINING"` | `H:523-528` |

#### 2.53 `/stop_daemon`

| attribute | value |
|---|---|
| transport | REST |
| owner | C++ (`F:180`; `S:347`) |
| visibility | **admin** |
| aliases | none |
| params | none |

| key | wire type | source |
|---|---|---|
| `status` | string | `H:738-743` |

#### 2.54 `/get_net_stats`

| attribute | value |
|---|---|
| transport | REST |
| owner | Rust native (`D/methods.rs:1314`) |
| visibility | **admin** |
| aliases | none |
| params | none |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | `T/p2p.rs:52` |
| `start_time` | u64 | unix s | `T/p2p.rs:53-54` |
| `total_packets_in` | u64 | | `T/p2p.rs:55` |
| `total_bytes_in` | u64 | | `T/p2p.rs:56` |
| `total_packets_out` | u64 | | `T/p2p.rs:57` |
| `total_bytes_out` | u64 | | `T/p2p.rs:58` |

#### 2.55 `/pop_blocks`

| attribute | value |
|---|---|
| transport | REST |
| owner | C++ (`F:181`; `S:1028`) |
| visibility | **admin** |
| aliases | none |

| key | wire type | notes | source |
|---|---|---|---|
| `nblocks` | u64 | 0 when the body is empty | `H:984,988` |

| key | wire type | notes | source |
|---|---|---|---|
| `status` | string | | base |
| `height` | u64 | chain **count** after the pop | `H:995,999` |

---

## 3. Observations

### 3.1 Names that encode their kind or unit

| family | instances |
|---|---|
| `_as_hex` | `TxEntry.as_hex`, `pruned_as_hex`, `prunable_as_hex` |
| `as_json` / `json` / `_json` (embedded JSON text in a string) | `TxEntry.as_json`, `get_block.json`, `tx_info.tx_json` |
| `blob` / `_blob` (hex on JSON, raw bytes on `.bin`) | `get_block.blob`; `tx_blob` (in `/submit_transaction` and `tx_info`); `block_blob` (`calc_pow`); `blocktemplate_blob`; `blockhashing_blob`. On `.bin`: `block`, `txs`, and `txid` (raw 32 bytes), with no suffix at all |
| `_hash` / `_id` / `_id_hash` (hash64) | `prev_hash`, `miner_tx_hash`, `pow_hash`, `prunable_hash`, `genesis_hash`, `top_block_hash`, `shard_hash`, `seed_hash`, `next_seed_hash`, `id_hash`, `max_used_block_id_hash`, `last_failed_id_hash`, `block_id`, `prev_id`, `p_id`, `p_canonical_id`, `main_chain_parent_block` (no suffix), `block_hash` |
| `wide_` + `_top64` (the 128-bit triple) | `wide_difficulty` / `difficulty_top64`, `wide_cumulative_difficulty` / `cumulative_difficulty_top64`, `wide_emission_amount` / `emission_amount_top64`, `wide_fee_amount` / `fee_amount_top64`. `get_info` carries `wide_*` **alone**, typed `HexU128`, with no low-64 or top-64 siblings |
| `_atomic` | `budget_atomic`, `bonded_total_atomic`, `expected_profit_atomic`. Other atomic amounts have **no suffix**: `reward`, `expected_reward`, `block_reward`, `fee`, `fee_total`, `emission_amount`, `fee_amount`, `already_generated_coins`, `total_burned` |
| `_milli` / `_micro` / `_pct` | `sigma_work_milli`, `join_scarcity_micro`, `burn_pct`, `histo_98pc` |
| `_seconds` / `_time` / `_timestamp` | `time_range_seconds`, `seconds` (ban), `start_time`, `adjusted_time`, `receive_time`, `last_relayed_time`, `live_time`, `recv_idle_time`, `send_idle_time`, `time_in_pool` (POD only), `timestamp`, `block_timestamp`, `received_timestamp`. `target` / `block_target` are seconds with no suffix |
| `_count` / `num_` / `n` / `_total` / `_size` | `tx_count`, `leaf_count`, `block_count`, `output_count`, `coinbase_output_count`, `frozen_count`, `bonded_count`, `served_count`, `bad_interval_count`, `alt_blocks_count`, `rpc_connections_count`, `*_connections_count`, `*_socket_count`, `tx_pool_unbroadcast_count`, `count`, `num_txes`, `num_failing`, `num_10m`, `num_not_relayed`, `num_double_spends`, `nblocks`, `txs_total`, `bytes_total`, `fee_total`, `tx_pool_size`, `white_peerlist_size`, `grey_peerlist_size`, `blob_size`, `block_size`, `database_size`, `size` |
| `_len` / `_bytes` | `archival_len` (bytes); `total_bytes_in` / `total_bytes_out`; `bytes`, `bytes_min`, `bytes_max`, `bytes_med`; `recv_count` / `send_count` are bytes **without saying so** |
| `_flat` / `_idx` / `_ids` | `bad_intervals_flat`, `bond_idx`, `shard_idx`, `claimant_bond_idx`, `held_shard_ids` |
| `has_` (presence flags) | `has_bond_record`, `has_budget_row`, `has_segment`, `has_last_served_epoch`, `has_last_settled_slash_epoch`, `has_peers` (in `get_info` this one is absence-encoded, not a flag pair) |

### 3.2 Booleans that select a representation or a policy

- **`decode_as_json`, `prune`, `split`** (`/get_transactions`) choose which of `as_hex` / `pruned_as_hex` / `prunable_as_hex` / `as_json` are filled. All four keys are always emitted, possibly `""`.
- **`fill_pow_hash`** has two incompatible restricted-listener policies for one key:
  - `get_block` and `get_block_header_by_height` **blank it silently**. The reply is `pow_hash: ""` with status OK (`D/handlers/json_rpc.rs:183`).
  - `get_last_block_header`, `get_block_header_by_hash` and `get_block_headers_range` **refuse with -19** (`D/methods.rs:823`).
- **`public_only`** defaults to `true`, which is the one inverted default. **`include_blocked`** and **`bad_blocks`** are filters. **`visible`** toggles a log setting.
- **`pruned`** (in the reply) is omitted when false, but `in_pool` is always present. **`in_pool`** selects which of the six arm keys exist.
- **`offline`** in `get_info` decides whether `has_peers` and the connection counts are present. **`p2p`** is a two-value string that says the same thing as `offline` again (`T/info.rs:691-695`).

### 3.3 Positional (array) forms

- **Params:** `on_get_block_hash` takes `[height]`. `submit_block` / `submitblock` take `[blob_hex]`. The legacy `get_block_count` list is ignored.
- **Replies:**
  - `get_fee_estimate.fees` is `[low, normal, high]`.
  - `/is_key_image_spent.spent_status` is paired by index to the request, with no key image echoed.
  - `get_block_header_by_hash.block_headers` is in request order, but each slot echoes `hash`.
  - `bad_intervals_flat` is flattened `[start, end_excl, …]`.
  - `Refusal.params` is `[[k,v],…]`.
  - `credit_pairs` carry indices into sibling arrays.
  - `get_txpool_backlog.backlog` is a packed POD byte string (24 B per entry).

### 3.4 Sentinels and null forms

- `claimant_bond_idx = u64::MAX` means none.
- `pow_hash = ""` means absent. `next_seed_hash` may be `""`.
- `ConnectionInfo.support_flags` and `ConnectionInfo.height` are a literal `null` and always present. `target_height` is `Nullable` and always present.
- `status: "offline"` alone is the whole P2P-off reply.
- `Peer.ip` / `Peer.port` are 0, and `ConnectionInfo.ip` / `ConnectionInfo.port` are `""`, on non-ipv4 arms.
- `mining_status.address` is `""` and `speed`, `threads_count`, `block_reward` are 0 when not mining.

### 3.5 Same key, different meaning or type

| key | readings |
|---|---|
| `difficulty` | u64 low-64 of the block (header), of the **cumulative** tip (`chain_info`), or of the next block (`mining_status`, `get_block_template`). In `get_miner_data` it is a **`0x` hex string** |
| `already_generated_coins` | u64 number (`get_miner_data`) against a decimal string (`get_info`) |
| `ip` | u32 number (`Peer`, both `ban` forms) against a dotted string (`ConnectionInfo`) |
| `port` | u16 (`Peer`) against a string (`ConnectionInfo`) |
| `speed` | hashes/s (`mining_status`) against a percentage (`SyncSpan`) |
| `height` | a chain **count** in `/get_height`, `sync_info`, `get_info`, `/pop_blocks`. A block **index** in `block_header`, `inject_archival_serve_credit`, `get_curve_tree_info` (count − 1). A tip height in `chain_info`. The block height of a transaction in `already_in_chain`. `get_version` uses `current_height` (a count) and `get_archival_emission_claim_source` uses `chain_height` (a count) for the same fact |
| `version` | u32 packed RPC version (`get_version`) against a build string (`get_info`) |
| `ban` | the struct name of two different shapes (GETBANS has `permanent`; SETBANS has the `ban` bool), and also a key inside one of them |
| `floor` | the array key and the inner key in `/get_stem_tallies` |
| `status` | a closed set on Rust replies against free-text error sentences on C++ replies. The two REST refusal forms put error text in different keys (`error` against `status`) |
| `count` | the chain count (`get_block_count`) against a block range length (`get_coinbase_tx_sum`) |

### 3.6 Same thing, different key

| concept | keys |
|---|---|
| P identity | `p_id` (claim source) and `p_canonical_id` (inject) |
| Parent block | `prev_hash` (header, template), `prev_id` (miner data), `prev_block` (template and generateblocks requests), `main_chain_parent_block` |
| Hash lists | `txids` (flush_txpool, relay_tx), `txs_hashes` (`/get_transactions` request, `spent_key_image_info`), `tx_hashes` (`get_block`, pool hashes), `blks_hashes` (alt blocks), `block_hashes` (`chain_info`), `hashes` (header by hash), `missed_tx` (singular for a list), `blocks` (generateblocks ids) |
| A transaction id | `tx_hash` (TxEntry), `id_hash` (`tx_info`), `id` (miner-data backlog), `txid` (`.bin`); `block_id` / `hash` / `block_hash` for blocks |
| Number of blocks | `nblocks` (pop_blocks, SyncSpan), `amount_of_blocks` (generateblocks), `count` (coinbase sum), `block_count` (shard), `length` (`chain_info`) |
| Header-carrying keys | `block_header` (single), `block_headers` (slots), `headers` (range) |
| Grey list | `gray_list` (`/get_peer_list`) against `grey_peerlist_size` (`get_info`) |
| Received time | `receive_time` (`tx_info`) against `received_timestamp` (TxEntry) |
| Tree height | `height` (`get_curve_tree_info`, an index) against `block_height` (`get_curve_tree_checkpoint`) |
| Epoch | `settled_epoch` (coverage), `current_settled_epoch` (claim source), `settlement_epoch` (snapshot, inject) |
| As-of tip | `as_of_height` (coverage) against `chain_height` (claim source) |
| Thread count | `threads_count` in both the `/start_mining` request and `mining_status`; consistent |

### 3.7 Duplication within one reply

- `get_block.miner_tx_hash` repeats `block_header.miner_tx_hash`.
- `get_block.blob` and `json` carry the same block.
- `block_size` always equals `block_weight`.
- The three 128-bit triples each encode one value three times.
- `get_info`'s `offline` and `p2p` each repeat the other.

### 3.8 Surface notes

- `inject_archival_serve_credit` is served on the restricted listener. It is gated only by nettype in the handler, not by `RESTRICTED_METHODS`.
- `get_block_template`, `get_miner_data`, `submit_block` and `get_txpool_backlog` are also served on both listeners.
- C++ JSON-RPC aliases: `getblocktemplate` and `submitblock`. Rust aliases: `getblockcount`, `on_getblockhash`, `getblockheaderbyheight`, `getblock`, `getlastblockheader`, `getblockheaderbyhash`, `getblockheadersrange`. REST aliases: `/getheight`, `/gettransactions`, `/getinfo`, `/getblocks_by_height.bin`.

### 3.9 Counts

- **55 served endpoints** (15 Rust-native JSON-RPC + 19 C++ JSON-RPC + 21 REST/bin), with 54 distinct shapes, because `get_info` and `/get_info` share one reply (§2.43 points to §2.15).
- **454 key rows** in total, counting each shared shape once:
  - 167 in §1 (shared shapes and envelopes).
  - 287 in §2 (per-method params and replies). 48 of these are the repeated `status` row, so §2 holds 239 rows excluding `status`.
  - `get_info` alone has 37.
- The count comes from `grep -c` over the tables, excluding the "no status" table and the visibility-key table.

### 3.10 Not determined

- The exact JSON byte form of `get_txpool_backlog.backlog` (epee POD-as-blob string escaping). Looked at `H:652` only.
- `tx_info.weight` is marked `u64?` (omitted at 0) on the strength of `KV_SERIALIZE_OPT` at `H:555`. This tree's Rust comments say OPT members are omitted at their default (`T/transactions.rs:53-58`), but epee's store path was not opened. It is the only C++-only OPT *reply* member.
- All `S` line numbers were re-verified against the declaration or assignment line.
