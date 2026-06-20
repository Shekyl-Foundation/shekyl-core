# Shekyl-Oxide Vendoring Workflow

This document defines the required maintenance workflow for vendored
`shekyl-oxide` crates in `shekyl-core`.

## Vendored source location

The vendored crates live under:

- `rust/shekyl-oxide/`

Upstream tracking reference:

- `https://github.com/Shekyl-Foundation/monero-oxide` (`fcmp++` branch)

Vendored snapshot metadata file:

- `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`

## Required update workflow

When upstream ships a fix, use this sequence:

1. Cherry-pick or merge the upstream fix into the Shekyl fork
   (`Shekyl-Foundation/monero-oxide`).
2. Run the fork's tests in isolation in the fork repository.
3. Sync the updated crate subtree into `shekyl-core/rust/shekyl-oxide/`.
4. Update `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`.
5. Run the full `shekyl-core` verification suite:
   - `cd rust && cargo build --locked -p shekyl-fcmp`
   - `cd rust && cargo test --locked --workspace`
   - `ninja shekyld` from the build directory
6. Commit in `shekyl-core` with the upstream commit reference in the message.

Do not do blind direct merges from upstream into consensus-critical code.

## Local patches (applied to the vendored tree, not yet in the fork)

These are Shekyl-originated fixes applied **directly** to the vendored tree,
ahead of the fork. The divergence CI compares only the recorded commit hash to
the fork tip (not file contents), so it is **blind** to these — this list is the
authoritative record. Each must be **upstreamed to the fork**
(`Shekyl-Foundation/monero-oxide@fcmp++`); the next re-vendor that includes the
upstreamed commit then drops the local patch (divergence dissolves, not
accumulates).

| Patch | File | Rationale | Upstream status |
| --- | --- | --- | --- |
| RPC client sets `Content-Type` | `shekyl-oxide/rpc/simple-request/src/lib.rs` (`inner_post`) | The client sent no `Content-Type`; the Shekyl daemon RPC server (`shekyl-daemon-rpc`, axum) requires it (`application/json`; `*.bin` → `application/octet-stream`) and rejects the request before any handler. Universal HTTP correctness. | **TODO: upstream to fork** |
| RPC client emits compliant JSON-RPC 2.0 | `shekyl-oxide/rpc/src/lib.rs` (`Rpc::json_rpc_call`) | The client sent `{method, params}` with no `jsonrpc`/`id`; the server requires `id`. Now emits a compliant `{jsonrpc:"2.0", id, method, params}` envelope. Universal JSON-RPC 2.0 correctness. | **TODO: upstream to fork** |

**Diagnostic (why these surfaced now):** the vendored monero-oxide RPC client
worked against `monerod`'s lenient epee HTTP/JSON-RPC server but not against
`shekyld`, because Shekyl's daemon RPC was cut over to the strict axum
`Json`/binary extractors. This is the daemon being **correctly stricter**
(intentional, not a cutover regression that over-rejects) — which makes the
client fix genuine standards compliance (upstreamable), not a Shekyl-specific
workaround. Surfaced by the Track-2 regtest (first end-to-end wallet↔daemon RPC).

## CI support

- `.github/workflows/shekyl-oxide-divergence.yml` compares the vendored snapshot
  commit to the fork tip and fails when they diverge.
- `.github/workflows/build.yml` contains a portability guard that fails if
  Cargo manifests include absolute local paths.
