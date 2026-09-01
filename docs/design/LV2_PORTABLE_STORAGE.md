# LV-2 — portable_storage codec (decision)

**Status.** **Pinned** (2026-08-13). LV-2a landed in
`rust/shekyl-portable-storage`. LV-2b maps (1001 / 1002 / 1003 / 1007,
`network_address`, and notifies 2001–2004 / 2006–2010) landed in
`shekyl-levin` (2026-08-14). This document remains authoritative for
build-vs-vendor, the crate split, and the LV-2b census. Live `shekyld`
dual-stack (§12 step 4) landed as the `#[ignore]` harness
`rust/shekyl-levin/tests/dual_stack.rs` (`SHEKYLD_BIN`; default crate
tests still spawn no daemon). **Not authoritative for:** the binary layout itself
([`docs/PORTABLE_STORAGE.md`](../PORTABLE_STORAGE.md), completed by
LV-2a) or Levin framing ([`docs/LEVIN_PROTOCOL.md`](../LEVIN_PROTOCOL.md),
[`rust/shekyl-levin`](../../rust/shekyl-levin)).

**Tracked in.** Identifier family `LV-1…LV-N`
([`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2). Work items
named here: **LV-2a** (codec), **LV-2b** (command schemas). **LV-3**
(connection-path cutover) is unchanged and stays deferred.

**Parent.** FOLLOWUPS "Levin p2p migration" (V3.2+). Reopening criterion
(a) of that entry — the p2p migration track is scheduled — is met by this
pin. Implementation is in-scope; it is not V3.0-gating
([`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md): P2P/levin remain C++ at
genesis).

**Process.** Spec-first per
[`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc).
Not a multi-round per-trait PR; [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
is not invoked. Implementation PRs still need their own KATs and the
usual Rust gates.

---

## 0. Timeframes (rule 05)

- **Now.** The live daemon speaks this binary on every handshake, timed
  sync, and notify. A Rust peer that cannot encode/decode it cannot talk
  to `shekyld`. The two former hand-rolled HTTP `.bin` sites
  (`get_o_indexes.bin`, `get_blocks_by_height.bin`) now call
  `shekyl-portable-storage`.
- **Mining-era end.** The format is cryptography-agnostic. Blob *contents*
  grow with PQC (`TransactionV3` + ~5.4 KiB `pqc_auth` per user tx; see
  `LEVIN_PROTOCOL.md`), but the KV envelope does not.
- **V4 lattice-only.** Same envelope. Replacing KV with a different
  payload format is a named protocol cutover, not a silent LV-2 side
  effect (§11).

---

## 1. What LV-2 is

Two layers that look like one crate. Mixing them is how this gets
expensive.

```text
Levin bucket          (LV-1 — rust/shekyl-levin; framing done)
    └── opaque payload bytes
            └── portable_storage binary     ← LV-2a  codec
                    └── typed command structs ← LV-2b  schemas
                            └── cryptonote blobs (shekyl-wire already owns these)
```

**LV-2a** is the self-describing KV format: 9-byte header
(`01 11 01 01 01 01 02 01 01`), type tags 1–13, varints, sections, arrays,
`SERIALIZE_FLAG_ARRAY` (`0x80`). Spec sketch:
[`docs/PORTABLE_STORAGE.md`](../PORTABLE_STORAGE.md) (~70% of a production
spec — gaps in §7).

**LV-2b** is the 27 `BEGIN_KV_SERIALIZE_MAP`s in
[`src/p2p/p2p_protocol_defs.h`](../../src/p2p/p2p_protocol_defs.h) and
[`src/cryptonote_protocol/cryptonote_protocol_defs.h`](../../src/cryptonote_protocol/cryptonote_protocol_defs.h),
plus the `network_address` type-tagged union in
[`contrib/epee/include/net/net_utils_base.h`](../../contrib/epee/include/net/net_utils_base.h)
and the Tor/I2P address maps. Not all 27 appear on the Levin wire (§6).

Payloads in `shekyl-levin` for the Levin-wire maps are typed builders
on LV-2a. Cryptonote blobs stay opaque `Vec<u8>`.

---

## 2. Disposition

**Build first-party. Vendor nothing.**

| Decision | Pin |
| --- | --- |
| Codec crate | New workspace member **`shekyl-portable-storage`**. Binary portable_storage only. Limits are a parameter, not a constant, so HTTP-binary RPC can reuse the same decoder. |
| Command schemas | **`shekyl-levin`**, depending on `shekyl-portable-storage`. Handshake/notify types are p2p protocol, not a generic KV library. |
| Cuprate `cuprate-epee-encoding` | **Reference, not a dependency.** Read `epee_object!` for API shape; implement against *our* C++ captures. |
| Published `epee-encoding` 0.5.0 (crates.io, 2023) | **No.** Stale, unreviewed, still needs a Shekyl wrapper. |
| Replace KV with a new payload format | **Rejected now** (§11). Pre-genesis does not license a new body format while the live daemon still speaks this one. |
| Fold RPC's ~343 other KV maps into LV-2 | **Rejected now** (§10). Same codec, different consumers, different limits. |
| Grow the homegrown `get_o_indexes.bin` reader | **Anti-pattern.** LV-2a deletes it (and the `get_blocks_by_height.bin` twin). |

**Name.** The crate is the format, not the library it came from.
`shekyl-epee` is rejected: epee is Levin + portable_storage + HTTP
invoke + logging + net utils + a dozen other things, and naming the
codec after the grab-bag invites the next author to dump unrelated epee
surface into it. `shekyl-encoding` is already Bech32m and is not
renamed. JSON portable_storage stays out of LV-2a (the daemon RPC
rewrite is Axum / JSON-RPC, not epee JSON). Reopen JSON only on a named
production caller for that dialect (§11).

---

## 3. Options considered

### 3.1 First-party `shekyl-portable-storage` (adopted)

Write the codec against the spec + C++ as byte oracle, then typed structs
for the Levin maps with a derive / `epee_object!`-shaped equivalent of
`KV_SERIALIZE` / `KV_SERIALIZE_OPT` / `KV_SERIALIZE_VAL_POD_AS_BLOB` /
`KV_SERIALIZE_CONTAINER_POD_AS_BLOB`.

Fits shekyl-first ([`10-shekyl-first.mdc`](../../.cursor/rules/10-shekyl-first.mdc)),
the Levin KAT discipline, and Shekyl-only fields (`attestation_witness`,
PQC-sized blobs). Collapses the two existing one-off parsers.

Cost: codec ~3–7 focused days once §7 is written into
`PORTABLE_STORAGE.md`; schemas + address union + handshake/timed-sync
KATs ~1–2 weeks. Spec-gap transcription is a day, not a blocker.

### 3.2 Vendor Cuprate's in-tree `cuprate-epee-encoding`

Real code, MIT, non-serde, `epee_object!` maps 1:1 onto the KV macros.
crates.io is still a `0.0.0-placeholder`. Consuming it is pin-a-git-commit
and vendor — the posture
[`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §8 already recorded
as a rule-17 / rule-10 question, and deferred to this document.

The codec fits. The schemas do not: Cuprate's command types are Monero's
(no `attestation_witness`, no Shekyl address/PQC sizing). We would still
write our maps, inherit DoS limits that may not match
`default_levin_limits`, and take a rebase tax on every Shekyl-only field.

Net savings is the codec body, not the Shekyl-specific surface. Rejected
as a dependency; kept as prior art to read.

### 3.3 Published `epee-encoding` 0.5.0

Same lineage, frozen 2023. Fine as a spike. Wrong as a genesis pin.

---

## 4. Split: LV-2a then LV-2b

Do **not** start LV-2b until LV-2a has byte-identity KATs against C++
`store_to_binary` / `load_from_binary`.

| Slice | What | First live consumer |
| --- | --- | --- |
| **LV-2a** | `shekyl-portable-storage`: encode/decode + Levin-default limits + KATs. Completes `PORTABLE_STORAGE.md` (§7). | Delete the `get_o_indexes.bin` / `get_blocks_by_height.bin` one-offs. Unblocks every later schema. |
| **LV-2b** | The Levin-wire maps in `shekyl-levin`, starting with 1001/1002/1003/1007, then 2002. | First drop: in-crate encode → `invoke()` → `BucketReader`. Live `shekyld` dual-stack: `#[ignore]` harness `tests/dual_stack.rs` (2026-08-14). Then `store_t_to_binary(NOTIFY_NEW_TRANSACTIONS)` can leave `levin_notify.cpp` (LV-3). |

Handshake first: small, no blob nesting, and is what lets a future
LV-3 caller invoke `BucketReader::complete_handshake` from decoded
command 1001 rather than from a side channel. 2002 next: first
blob-wrapping notify, the relay path, wraps `shekyl-wire` tx blobs
inside KV.

The remaining cryptonote notifies (2001, 2003–2004, 2006–2010) ride the
same derive and land with 2002 or immediately after; they are not a
third named slice.

---

## 5. Command inventory

`LEVIN_PROTOCOL.md` listed 1004–1006 (Stat Info / Network State / Peer
ID). Those commands **do not exist** in Shekyl
(`P2P_COMMANDS_POOL_BASE + 7` is support-flags; there is no `+ 4`/`+ 5`/
`+ 6`). 2010 `NOTIFY_GET_TXPOOL_COMPLEMENT` is live in
`cryptonote_protocol_defs.h` and handled in
`cryptonote_protocol_handler.inl`, and was missing from that doc. 2005
was never allocated.

Correct set, verified 2026-08-13 against the two `*_protocol_defs.h`
files:

| ID | Name | Kind |
| --- | --- | --- |
| 1001 | `COMMAND_HANDSHAKE` | request / response |
| 1002 | `COMMAND_TIMED_SYNC` | request / response |
| 1003 | `COMMAND_PING` | request / response |
| 1007 | `COMMAND_REQUEST_SUPPORT_FLAGS` | request / response |
| 2001 | `NOTIFY_NEW_BLOCK` | notify |
| 2002 | `NOTIFY_NEW_TRANSACTIONS` | notify |
| 2003 | `NOTIFY_REQUEST_GET_OBJECTS` | notify |
| 2004 | `NOTIFY_RESPONSE_GET_OBJECTS` | notify |
| 2006 | `NOTIFY_REQUEST_CHAIN` | notify |
| 2007 | `NOTIFY_RESPONSE_CHAIN_ENTRY` | notify |
| 2008 | `NOTIFY_NEW_FLUFFY_BLOCK` | notify |
| 2009 | `NOTIFY_REQUEST_FLUFFY_MISSING_TX` | notify |
| 2010 | `NOTIFY_GET_TXPOOL_COMPLEMENT` | notify |

The companion edit to `LEVIN_PROTOCOL.md` in this pin's landing is the
doc-side correction. LV-2b implements this table, not the stale one.

---

## 6. Schema census

`BEGIN_KV_SERIALIZE_MAP` count in the two protocol-defs headers is
**27**. FOLLOWUPS said "~25". Nested address types live outside those
headers and are load-bearing for handshake peerlists.

### 6.1 On the Levin wire (LV-2b)

| Type | File | Notes |
| --- | --- | --- |
| `basic_node_data` | `p2p_protocol_defs.h` | `network_id` is `VAL_POD_AS_BLOB`; `support_flags` is `OPT` (`rpc_port` / `rpc_credits_per_hash` deleted 2026-08-31 — dead RPC advertisement, census-1 U-5/L-6) |
| `peerlist_entry` | `p2p_protocol_defs.h` | `adr` is `network_address`; `last_seen` / `pruning_seed` are `OPT` (`rpc_port` / `rpc_credits_per_hash` deleted 2026-08-31 — dead RPC advertisement, census-1 U-5/L-6) |
| `COMMAND_HANDSHAKE` request / response | `p2p_protocol_defs.h` | response carries `local_peerlist_new` |
| `COMMAND_TIMED_SYNC` request / response | `p2p_protocol_defs.h` | |
| `COMMAND_PING` request / response | `p2p_protocol_defs.h` | request is an empty map |
| `COMMAND_REQUEST_SUPPORT_FLAGS` request / response | `p2p_protocol_defs.h` | request is an empty map |
| `CORE_SYNC_DATA` | `cryptonote_protocol_defs.h` | handshake/timed-sync payload; `cumulative_difficulty_top64` store-always / load-`OPT`; `top_id` POD-as-blob |
| `tx_blob_entry` | `cryptonote_protocol_defs.h` | pruned-tx path |
| `block_complete_entry` | `cryptonote_protocol_defs.h` | **Shekyl:** `attestation_witness` `OPT` + transport-cap check inside the map. Unpruned `txs` is an array of blobs; pruned `txs` is an array of `tx_blob_entry` |
| `NOTIFY_NEW_BLOCK` request | `cryptonote_protocol_defs.h` | 2001 |
| `NOTIFY_NEW_TRANSACTIONS` request | `cryptonote_protocol_defs.h` | 2002; `_` padding string; `dandelionpp_fluff` `OPT` default **true** |
| `NOTIFY_REQUEST_GET_OBJECTS` request | `cryptonote_protocol_defs.h` | 2003; `blocks` is `CONTAINER_POD_AS_BLOB` |
| `NOTIFY_RESPONSE_GET_OBJECTS` request | `cryptonote_protocol_defs.h` | 2004 |
| `NOTIFY_REQUEST_CHAIN` request | `cryptonote_protocol_defs.h` | 2006 |
| `NOTIFY_RESPONSE_CHAIN_ENTRY` request | `cryptonote_protocol_defs.h` | 2007 |
| `NOTIFY_NEW_FLUFFY_BLOCK` request | `cryptonote_protocol_defs.h` | 2008 |
| `NOTIFY_REQUEST_FLUFFY_MISSING_TX` request | `cryptonote_protocol_defs.h` | 2009 |
| `NOTIFY_GET_TXPOOL_COMPLEMENT` request | `cryptonote_protocol_defs.h` | 2010 |

### 6.2 Address union (LV-2b, nested under `peerlist_entry.adr`)

`epee::net_utils::network_address` is a type-tagged union, not a plain
struct:

| `type` (`uint8`) | Variant | KV fields |
| --- | --- | --- |
| 1 (`ipv4`) | `ipv4_network_address` | `m_ip` (endian-swapped at the KV layer), `m_port` |
| 2 (`ipv6`) | `ipv6_network_address` | `addr` as 16-byte POD-as-blob, `m_port` |
| 3 (`i2p`) | `net::i2p_address` | `host`, `port` (`src/net/i2p_address.cpp`) |
| 4 (`tor`) | `net::tor_address` | `host`, `port` (`src/net/tor_address.cpp`) |

Unknown `type` is a decode failure. This is the handshake peerlist
surface; it is not optional.

### 6.3 KV-capable, not Levin-wire (do not put in LV-2b)

| Type | Why it is out |
| --- | --- |
| `connection_info` | RPC `get_connections` JSON, not a Levin body |
| `network_address_old` | Debug `object_sizes` only; no production caller |
| `connection_entry` | Not a Levin command body |
| `network_config` | Node config (`m_net_config`); not in handshake |
| `anchor_peerlist_entry` | Disk peerlist via Boost serialization, not KV-on-Levin |
| `ipv4_network_subnet` | Ban-list / matching, not a command body |

LV-2a still has to encode whatever those maps would emit if someone
called `store()`, because the codec is format-complete. LV-2b does not
grow typed Rust structs for them until a named caller appears.

---

## 7. Spec gaps in `PORTABLE_STORAGE.md`

The sketch is the right shape (header, varints, section keys, type tags,
array flag). It is not a production spec until LV-2a writes the
following into it, sourced from C++ and pinned by KATs:

1. **Limits.** Recursion 100 (`EPEE_PORTABLE_STORAGE_RECURSION_LIMIT`).
   Levin `default_levin_limits`: 8192 objects / 16384 fields / 16384
   strings (`levin_abstract_invoke2.h`). HTTP-binary
   `default_http_bin_limits`: 65536×3 each
   (formerly `http_abstract_invoke.h`; since the epee HTTP client deletion
   the only holder is `Limits::HTTP_BIN` in `shekyl-portable-storage`). String length `< MAX_STRING_LEN_POSSIBLE`
   (2_000_000_000). Section keys `< 255` bytes, length-prefixed by a
   single byte (already sketched).
2. **`KV_SERIALIZE_OPT`.** Store omits the field when the value equals
   the default; load uses the default when the field is absent. Missing
   this is how handshake peerlists and `dandelionpp_fluff` diverge.
3. **`KV_SERIALIZE_VAL_POD_AS_BLOB`.** A POD is a `SERIALIZE_TYPE_STRING`
   of `sizeof` bytes, not a section.
4. **`KV_SERIALIZE_CONTAINER_POD_AS_BLOB`.** A vector/list of PODs is
   *one* string of concatenated elements, not a typed array. Used by
   hash lists (2003/2006/2007/2009/2010).
5. **`network_address` union** (§6.2), including ipv4's store-time
   `SWAP32LE`.
6. **`block_complete_entry` pruned vs unpruned `txs` encoding**, plus
   `attestation_witness` `OPT` and
   `archival_attestation_witness_within_transport_cap`.
7. **KATs.** At least: empty section, OPT-omitted vs OPT-present,
   POD-as-blob, container-as-blob, nested section, array-of-object,
   ipv4/ipv6/Tor `network_address`, a captured C++ handshake, a captured
   `NOTIFY_NEW_TRANSACTIONS` with and without padding.

The format sketch's "integers may be big-endian" hedge is **false for
Shekyl**: we serialize little-endian. LV-2a pins that.

`SERIALIZE_TYPE_ARRAY` (tag 13, untyped) is unused on our command
bodies. Decode of a tag-13 value is a hard error until a caller exists
— do not invent a representation.

---

## 8. Limits are a parameter

```text
Levin invoke/notify  →  objects 8192, fields 16384, strings 16384
HTTP .bin RPC        →  objects/fields/strings 196608
```

`shekyl-portable-storage` takes a `Limits` struct. Levin command decode uses the
Levin defaults. The `get_o_indexes.bin` consumer uses the HTTP-binary
defaults. Do not bake Levin numbers into the crate root.

Recursion 100 and `MAX_STRING_LEN_POSSIBLE` are format-wide, not
per-transport.

---

## 9. Existing Rust consumers (delete, don't grow)

| Site | What it does today |
| --- | --- |
| `rust/shekyl-rpc-client/src/lib.rs` `get_o_indexes` | Homegrown reader, "only validated to work against this specific function" |
| `rust/shekyl-engine-core/src/engine/daemon_observability.rs` | Second homegrown codec for `get_blocks_by_height.bin` request/response; comments "there is no epee crate" |

LV-2a's landing PR rewires both onto `shekyl-portable-storage` and deletes the
hand-rolled varint/tag parsers. Leaving them is a third codec by
another name.

---

## 10. Out of scope

- **Daemon / wallet RPC KV maps** (~161 + ~173). Same binary format,
  HTTP limits, different crate consumers. They may take a dependency on
  `shekyl-portable-storage` later; they are not LV-2b.
- **JSON portable_storage.** Separable; no production Rust caller.
- **Levin framing, compression, noise/fragment emit.** LV-1.
- **`handle_recv` / `net_node` connection cutover.** LV-3, blocked on
  LV-2b for useful command interop.
- **Boost archive peerlist on disk.** Different format.
- **A new payload format** to replace KV.

---

## 11. Reversion clauses (rule 21)

- **Vendor Cuprate / crates.io `epee-encoding`.** Rejected while (1) the
  crate is unpublished-or-stale, (2) Shekyl command schemas diverge
  (`attestation_witness`, deleted 1004–1006, 2010), and (3) a first-party
  codec with C++ KATs exists or is in flight. Reopen only if a
  source-anchored rule-17 pass shows the vendored codec is byte-identical
  on Shekyl captures *and* exposing our maps through it is cheaper than
  maintaining `shekyl-portable-storage`. Re-evaluation shape: a design amendment to
  this document, not a silent `Cargo.toml` git dep.
- **Replace KV.** Rejected while any live Shekyl node speaks this
  binary. Reopen only on a named protocol cutover (post-genesis hard
  fork or a dual-stack flag with a documented retirement of the C++
  maps). Pre-genesis `rm -rf ~/.shekyl` does **not** license this: the
  C++ daemon is the other side of the socket until LV-3.
- **JSON dialect in `shekyl-portable-storage`.** Rejected until a production caller
  needs epee-JSON rather than Axum JSON-RPC. Reopen via a FOLLOWUPS
  amendment naming the caller.
- **RPC maps in LV-2b.** Rejected until the RPC rewrite names
  `shekyl-portable-storage` as its binary codec. That is a consumer of LV-2a, not an
  expansion of LV-2b.
- **Tag-13 untyped arrays.** Hard-error until a captured C++ body emits
  one. Reopen on that capture.

---

## 12. Implementation sequence

1. Transcribe §7 into `PORTABLE_STORAGE.md` (same PR as the crate, not
   a separate "spec PR" — the KATs are the spec check).
2. Land `shekyl-portable-storage` (LV-2a) with C++ capture KATs and Levin + HTTP
   limit parameters.
3. Rewire `shekyl-rpc-client` / `daemon_observability` onto it; delete
   the one-offs.
4. Land handshake/timed-sync/ping/support-flags in `shekyl-levin`
   (LV-2b first drop). **Landed 2026-08-14** with in-crate
   encode → `invoke()` → `BucketReader` KATs. Live dual-stack
   interop against `shekyld` **landed 2026-08-14** as
   `rust/shekyl-levin/tests/dual_stack.rs` (`#[ignore]`, `SHEKYLD_BIN`;
   default crate tests still spawn no daemon).
5. Land 2002, then the remaining notifies including 2010.
   **Landed 2026-08-14** (`tests/notify_kats.rs`: fluff OPT, empty-container
   omit, `CONTAINER_POD_AS_BLOB`, pruned vs unpruned `txs`, witness cap,
   encode → `notify()` → `BucketReader`).

LV-3 stays its own design round against the index's two-dependency
inventory. This document does not scope it.

---

## 13. Identifier notes (rule 94)

`LV-2a` and `LV-2b` are work items in the existing `LV-1…LV-N` family,
not a new prefix. No registry row is minted. Bare `2a`/`2b` are
forbidden in new prose (they collide with Phase / Bond-PR).
