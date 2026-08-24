# Daemon RPC: Rust/Axum Migration

Phase 1 of the epee-to-Rust migration replaces the daemon's HTTP transport layer
with Axum while keeping all handler logic in C++. **Phase 1 is complete:** the
epee HTTP listener, `--no-rust-rpc`, and inbound daemon `--rpc-login` /
`--rpc-ssl*` surface are deleted, and so (2026-08-21) is epee's HTTP **client**
— `http_client.h`, digest auth (`http_auth`), `net_helper`, the abstract-invoke
templates and the dead `http_server_impl_base` / `http_protocol_handler`
parser that only its own unit test kept warm. epee has no HTTP surface left in
this tree; what remains of it on the RPC path is KV serialization, which Phase
2 replaces in the FFI dispatch path.

## Architecture

```
  Client
    │
    ▼
  Axum (Rust)            ◀─ HTTP transport, CORS (default-deny), body limits, route dispatch
    │
    ▼
  CoreRpc (Rust)         ◀─ FFI wrapper, spawn_blocking for C++ calls
    │
    ▼ C ABI
  core_rpc_ffi.cpp       ◀─ Dispatch tables: URI → handler, epee serialization (Phase 2 target)
    │
    ▼
  core_rpc_server (C++)  ◀─ on_* handlers (plain class; no epee HTTP base)
    │
    ▼
  cryptonote::core / p2p
```

`core_rpc_server` retains its `on_*` methods but no longer inherits
`epee::http_server_impl_base`. Axum is the sole HTTP acceptor. Epee KV
serialization remains inside `core_rpc_ffi.cpp` until Phase 2. Levin P2P
(`nodetool::node_server` / `epee::levin::`) remains C++ until a separate P2P
port — it is not part of this Phase 1 transport deletion.

## Files

| File | Role |
|------|------|
| `src/rpc/core_rpc_ffi.h` | C API header for the FFI facade |
| `src/rpc/core_rpc_ffi.cpp` | Dispatch tables mapping URIs/methods to `on_*` handlers |
| `rust/shekyl-daemon-rpc/` | Axum crate: server, routes, handlers, types |
| `rust/shekyl-daemon-rpc/src/ffi_exports.rs` | `shekyl_daemon_rpc_start/stop` FFI exports (daemon-only) |
| `rust/shekyl-daemon-rpc/src/ctl_client.rs` | `shekyl_daemon_ctl_post/free` — the `shekyld <command>` control client's transport (daemon-only) |
| `src/daemon/rpc_client.h` | `tools::t_rpc_client`: request/response framing for the control client over that export |
| `src/shekyl/shekyl_ffi.h` | C++ declarations for Rust FFI functions |
| `src/daemon/daemon.cpp` | Daemon lifecycle: always starts Axum on the configured RPC port |
| `src/rpc/rpc_args.cpp` | Shared CLI; daemon registers bind/CORS only (`include_listener_tls_auth=false`) |

## Endpoint Coverage

- **JSON REST** endpoints (`/get_info`, `/get_transactions`, etc.)
  - Accept both **GET and POST** (matching historical epee behavior)
  - The legacy `/send_raw_transaction` + `/sendrawtransaction` pair was
    deleted (`design/DAEMON_SUBMIT_VERDICT.md` §9.3); transaction submit
    is the native `/submit_transaction` route below, not an FFI proxy
- **1 native Rust** endpoint: `POST /submit_transaction` — served
  directly by the Rust admission engine (`src/submit/`), never crossing
  the C++ dispatch tables (`design/DAEMON_SUBMIT_VERDICT.md` §2–§3)
- **Binary** endpoints (`/get_blocks.bin`, `/get_o_indexes.bin`, etc.)
  - POST-only; return **400 Bad Request** on parse failure
- **JSON-RPC 2.0** methods via `POST /json_rpc` (includes curve-tree and
  `get_archival_emission_claim_source`)

All URI aliases (e.g. `/getheight` ↔ `/get_height`) are registered on Axum.
Registration is FFI-table + Axum only — MAP macros are gone.

### Deleted decoy surface (no Axum route)

`get_output_distribution` / `/get_output_distribution.bin` (and
`wallet2::get_rct_distribution`) are deleted. FCMP++ does not use ring-decoy
distribution. **Rule-21 reopen:** iff a live wallet path re-acquires a
distribution consumer; re-evaluation shape: restore a typed Axum+FFI route
with a named caller, never “keep epee.”

### Deleted bootstrap-daemon forward (no Axum route, no CLI flag)

`--bootstrap-daemon-address` / `-login` / `-proxy`, the `set_bootstrap_daemon`
RPC and console command, `bootstrap_daemon` / `bootstrap_node_selector`, and
the `use_bootstrap_daemon_if_necessary` forward in front of 26 handlers are
deleted (2026-08-21), together with the `get_info` fields that reported it
(`bootstrap_daemon_address`, `height_without_bootstrap`,
`was_bootstrap_ever_used`), the `untrusted` marker every response carried for
it, and error code `CORE_RPC_ERROR_CODE_UNSUPPORTED_BOOTSTRAP`.

**What it did.** While the local node was more than ten blocks behind, the
daemon re-issued a wallet's queries — `/getblocks.bin` from its restore
height, `/is_key_image_spent`, `/gettransactions` by hash,
`get_output_histogram`, … — to a third-party node (one the operator named, or
in `auto` mode one picked from the peer list's advertised RPC ports), and
returned the answer flagged `untrusted=true`.

**Why it goes** (mission hierarchy: privacy is the product;
[`16-architectural-inheritance`](../.cursor/rules/16-architectural-inheritance.mdc):
inherited flows that contradict the threat model are migrated, not
rationalized). The forward inverts Shekyl's daemon posture — own node by
default; a remote is the *wallet's* explicit, user-visible choice
(`--daemon-address`, onion). It moved the wallet's most identifying query
pattern to a node the user never chose, selected by the daemon from peer
gossip, over clearnet unless a proxy was also configured, and flagged it with a
field no wallet in this tree reads. The wallet can already do the honest
version of this itself, visibly: point at a remote daemon while the local one
syncs. A daemon-side silent forward adds no capability the user lacks; it
removes their knowledge of where their queries went. Same shape as
`get_output_distribution` above — an inherited surface whose only effect is to
widen who sees the wallet.

**Rule-21 reopen.** Evidence that IBD at the device floor
([`76`](../.cursor/rules/76-device-provisioning-floor.mdc), Pi 4) leaves a
fresh install without a usable wallet for longer than the failure-mode UX
([`82`](../.cursor/rules/82-failure-mode-ux.mdc)) can carry, **and** a design
that keeps the choice with the user: a wallet-side "use this remote until my
node catches up" selection, explicit and visible — never a daemon-side forward.
Re-evaluation lands in Rust on the wallet's daemon-selection surface, not as a
restored C++ route.

## RPC is operator-to-operator

Every RPC leg is operator-to-operator: both endpoints are machines the same
person controls. The adversary is the network path between those machines,
never the peer. There is no recommended configuration in which a Shekyl
wallet talks to a daemon someone else controls.

This is an RPC posture, not a P2P posture. The P2P layer talks to strangers
by construction — that is what a blockchain is — and Dandelion++ / Tor exist
because those peers are untrusted. "Shekyl never talks to machines you don't
control" would be false. Accurate form: **RPC is operator-to-operator; P2P is
adversarial by design and hardened separately.**

Consequences that follow from the one threat (someone on the wire between two
machines you own), not from a public-remote-node model:

- Mutual authentication is always available: both ends are provisionable.
  There is no case that degrades to server-only (one-way) auth.
- A CA answers a question this posture does not raise. Enrollment of devices
  you physically hold is fingerprint-allowlist, not delegated trust. (The
  reopen for in-daemon clearnet TLS below is unchanged: onion / reverse
  proxy remains the remote-security story.)
- `--public-node` (advertise restricted RPC over P2P so strangers' wallets
  can find this node) is deleted, together with `/get_public_nodes` (the
  discovery RPC whose only production consumer was the bootstrap-daemon
  `auto` picker). A privacy-maximalist chain whose nodes advertise
  themselves as public remote endpoints is building the Monero remote-node
  ecosystem by default — the ecosystem where wallets routinely talk to
  strangers' nodes. The affordance is what people reach for, regardless of
  what the docs recommend.

**Restricted RPC stays.** `--restricted-rpc` and `--rpc-restricted-bind-port`
are an operator tool: admin console on loopback, view-only on a less-
privileged port for *your* wallet (phone on LAN, a second machine you
own). They are not a public-remote-node product. Advertising the port over
P2P was the half that contradicted the posture; the second listener without
advertising is still both-ends-yours.

**Phone-only gap (deliberate product boundary).** Under operator-to-operator
only, a user with no always-on machine has no supported configuration. That
population is who drives public-remote-node use in Monero; Shekyl's answer
is "run the daemon on a machine you own (desktop, Pi 4, a VPS you control)
and reach it from the phone." **Rule-21 reopen:** a designed light-client
protocol that does not restore foreign-daemon RPC. Disposition is never
"ship `--public-node` as unsupported-but-possible."

## Restricted Mode

In restricted mode (`--restricted-rpc` or a separate restricted bind port) —
the operator's own view-only listener, not a public remote node:

- JSON REST: admin-only routes are not registered in the Axum router.
- JSON-RPC: admin-only methods are rejected with code `-32601` before C++.

Note: the restricted-method list exists in both Axum and (historically) epee
maps — dual-list single-sourcing is a FOLLOWUPS item.

## Auth, TLS, and remote access

| Context | Story |
|---------|--------|
| Local | Plaintext loopback (`127.0.0.1` or `::1`), and loopback only: a wildcard or a network bind is refused at the Rust bind seam (RT-1/RT-2; `--confirm-external-bind` retired). `--rpc-use-ipv6` binds `--rpc-bind-ipv6-address` on the same start. shekyld does **not** register `--rpc-login` or `--rpc-ssl*`. |
| Remote (your other machine) | Onion (address = key; `has_strong_verification` already) or a reverse proxy outside the daemon. Still operator-to-operator. |
| Wallet-RPC | Separate Rust process. `--rpc-login` (HTTP Basic) on loopback; any non-loopback bind requires it and wildcard binds are refused; there is no `--rpc-ssl*` — the encrypted remote leg is pinned mutual TLS (`docs/design/RPC_TRANSPORT_POSTURE.md` RT-4). |
| CLI outbound | `shekyld <command>` reaches the running daemon through `shekyl_daemon_ctl_post` (`shekyl-daemon-rpc/src/ctl_client.rs`, over `shekyl-rpc-transport`): plaintext loopback, no login, no TLS — the outbound half mirrors the inbound ruling. epee's `http_simple_client` is no longer on this path. |

**Rule-21 reopen for in-daemon clearnet TLS / digest auth:** named production
need + threat-model review. Disposition is never “implement Axum `--rpc-ssl`”
as the remote-security story — that remains onion / reverse proxy.

## CORS

Default-deny (`CorsLayer::new()`). When `--rpc-access-control-origins` is set,
Axum honors the comma-separated allow-list (never `*`).

## Connection limits

`--rpc-max-connections` (total), `--rpc-max-connections-per-public-ip`, and
`--rpc-max-connections-per-private-ip` are **enforced by the Axum listener**.
The caps are parsed and cross-validated in `core_rpc_server::init` (C++) and
handed to the Rust listener via `shekyl_daemon_rpc_start`; enforcement itself is
a purpose-built Rust layer (`conn_limit`: `LimitedListener` + `ConnTracker`)
that admits each accepted TCP connection against the total and the applicable
per-IP cap (public vs. private/loopback), immediately closing any connection
over a cap and releasing the slot when a connection closes. `0` means unlimited
for a given dimension. The soft-limit arg remains advisory.

`get_info.rpc_connections_count` reports the live tracked total from that same
layer (both the REST and json_rpc surfaces; restricted RPC continues to
disclose `0`, matching the other peer/connection fields).

## PQC Readiness

- Default body limit: 10 MiB (configurable). With FCMP++ and per-input
  pqc_auths, a typical 2-in/2-out transaction is ~23 KB. The 10 MiB limit
  is sufficient for all realistic transaction sizes including multisig.
- No changes needed to the wire format; the FFI boundary passes raw JSON
  strings and binary blobs without interpretation.
- `get_outs` / `get_outs.bin` endpoints are removed — FCMP++ uses
  full-chain membership proofs, so there is no ring member fetching.
- Curve tree RPC endpoints — registered in the Axum/FFI JSON-RPC dispatch
  table (`src/rpc/core_rpc_ffi.cpp` `get_jsonrpc_table()`) since PR #174
  (2026-06-23):
  - `get_curve_tree_path` — Merkle path for a given leaf
  - `get_curve_tree_info` — current curve tree root hash, depth, leaf count
  - `get_curve_tree_checkpoint` — curve tree snapshot at a given height

## Running

```bash
shekyld                        # Axum on 11029
shekyld --testnet              # Axum on 12029
```

### Port Mapping

| Network  | P2P   | RPC (Axum) |
|----------|-------|------------|
| Mainnet  | 11021 | 11029      |
| Testnet  | 12021 | 12029      |
| Stagenet | 13021 | 13029      |

## Reachability predicate (Phase 1 audit)

A method is **live** iff it has an Axum route (or `/json_rpc` → FFI method)
**and** a live consumer. MAP macros are gone; registration is FFI-only + Axum.

| Surface | Axum | FFI | Live consumer | Disposition |
|---------|------|-----|---------------|-------------|
| `/get_height` (+ `/getheight`), `get_version` | yes | **native Rust** (RK-1: `shekyl-daemon-rpc::methods` over `shekyl_rpc_chain_tip` / `shekyl_rpc_hardforks`) | wallets / console | migrated 2026-08-21 |
| `get_block_count` (+ `getblockcount`), `on_get_block_hash` (+ `on_getblockhash`) | `/json_rpc` | **native Rust** (RK-2: over `shekyl_rpc_chain_tip` / `shekyl_rpc_block_hash_at`) | python-rpc, stressnet | migrated 2026-08-22 |
| `get_block_header_by_height` (+ `getblockheaderbyheight`) | `/json_rpc` | **native Rust** (RK-3: over `shekyl_rpc_block_header_at`) | wallet (`shekyl-rpc-client`), python-rpc, stressnet | migrated 2026-08-23 |
| `get_block` (+ `getblock`) | `/json_rpc` | **native Rust** (RK-3b: over `shekyl_rpc_block_at`) | console (`print_block_by_hash` / `_by_height`, both migrated with it), python-rpc, stressnet | migrated 2026-08-24 |
| JSON REST (info, txs, pool, …) | yes | yes | wallets / CLI | keep (RK-2…RK-9) |
| Binary sync (`/get_blocks.bin`, hashes, indexes) | yes | yes | wallet refresh | keep |
| JSON-RPC admin + query set | `/json_rpc` | yes | wallets / tools | keep |
| `POST /submit_transaction` | native Rust | n/a | wallets | keep |
| `get_archival_emission_claim_source` | `/json_rpc` | yes | claim-builder | keep |
| `get_output_distribution` (+ `.bin`) | **no** | **removed** | none (`get_rct_distribution` deleted) | deleted |
| Bootstrap-daemon forward (`use_bootstrap_daemon_if_necessary`, `/set_bootstrap_daemon`) | **no** | **removed** | none | deleted (privacy ruling above) |
| `--public-node` P2P advertisement + `/get_public_nodes` | **no** | **removed** | none (bootstrap `auto` was the consumer) | deleted (operator-to-operator RPC) |
| epee HTTP listener / `--no-rust-rpc` | n/a | n/a | none | deleted |
| epee HTTP client (`http_client.h`, `http_auth`, `net_helper`, `http_abstract_invoke.h`) + dead server parser | n/a | n/a | none (control client → `shekyl_daemon_ctl_post`; bootstrap forward deleted) | deleted 2026-08-21 |

## Phase 2 (KV cutover)

Specified in [`design/DAEMON_RPC_KV_CUTOVER.md`](design/DAEMON_RPC_KV_CUTOVER.md)
(family `RK-`). The Phase-1 sentence "replace epee portable-storage in
`core_rpc_ffi.cpp` with a Rust-native codec" was re-scoped there: a Rust
codec cannot serialize C++ structs without a `#[repr(C)]` façade of every
wire type (rule 40), so the wire type and the handler of each method move to
Rust **together**, over coarse `shekyl_rpc_*_facts` FFI, with the console
rendering following the method. epee KV leaves the RPC path method by method
and `core_rpc_server.*` / `core_rpc_server_commands_defs.h` / the dispatch
tables here are deleted at RK-X.

## Thread Safety

C++ `on_*` handlers are designed for concurrent access. Axum dispatches each
request on a Tokio worker; FFI calls use `spawn_blocking`. `CoreRpc` is
`Send + Sync`.
