# shekyl-levin

Levin p2p **framing** layer — the Shekyl-owned Rust skeleton of the wire
protocol specified in [`docs/LEVIN_PROTOCOL.md`](../../docs/LEVIN_PROTOCOL.md).

## What this crate is

The bottom layer of the p2p stack, byte-identical to the C++ `epee::levin`
implementation:

- the 29-byte bucket header (`bucket_head2`): signature, length, expect-response,
  command, Q/S/B/E flags, protocol version;
- whole-message builders for the notification / request / response flows;
- dummy ("noise") messages and noise-shaped fragmentation for the white-noise
  feature over Tor;
- an incremental stream reader (`BucketReader`) mirroring the
  `async_protocol_handler::handle_recv` state machine: partial reads,
  signature early-reject, packet-size limits (256 KiB pre-handshake / 100 MB
  post), per-command payload caps and the PWD-B3a ingress discriminator
  (`ingress_payload_cap` — live on C++ `handle_recv` via FFI; a dispatch
  command must be a `DefinedCommand`), noise discard,
  fragment reassembly, and message classification. `feed` buffers bytes and
  `next_message` parses one bucket at a time, so — as in `handle_recv`,
  which dispatches inside its parse loop — at most one decoded payload is
  live at a time and an already-delivered message survives a later bucket
  in the same read being malformed.

Byte-identity is pinned by KATs (`tests/oracle_kats.rs`) mirroring the C++
gtests in `tests/unit_tests/levin.cpp` assertion for assertion; round-trip
property tests (`tests/properties.rs`) cover arbitrary payloads, commands,
chunk boundaries, and noise sizes.

## What this crate is not

- **Not the payload codec.** Command bodies are epee `portable_storage`
  blobs; the codec is first-party `shekyl-portable-storage` (LV-2a). This
  crate owns the typed maps (LV-2b): handshake / timed-sync
  (1001 / 1002) plus `network_address`
  and notifies 2002–2004 / 2006–2010. Cryptonote blobs stay opaque bytes.
  Live `shekyld` dual-stack is the `#[ignore]` harness
  `tests/dual_stack.rs` (`SHEKYLD_BIN`); default crate tests spawn no daemon.
- **Not the connection stack.** No sockets, timeouts, invoke/response
  correlation, or peer management.
- **Not a compressor.** The protocol has no compression (Rick, 2026-10-19;
  the measurement is `docs/benchmarks/zstd_ruzstd_levin_20261020.md`). A
  bucket carrying the old `0x10` flag bit is refused at ingress like any
  undefined bit.
- **Emit side wired; read side is not.** Since 2026-08-13 the white-noise
  emitters run through this crate: `epee::levin::make_noise_notify` /
  `make_fragmented_notify` forward to this crate's `noise_notify` /
  `fragmented_notify`, so the fragment-padding algorithm has exactly one
  implementation and the byte-exact `make_fragment.*` gtests exercise it
  live across the boundary. The read side — `BucketReader`, and the C++
  `handle_recv` machinery it will one day replace — stays C++
  (`contrib/epee`, `src/p2p/`, `src/cryptonote_protocol/levin_notify.*`)
  until the scheduled p2p cutover. This crate is the verified foundation
  that cutover starts from.

## Documented divergences from the C++ oracle

**The authoritative census lives in the crate docs** — the module comment at
the top of [`src/lib.rs`](src/lib.rs), rendered by `cargo doc -p shekyl-levin`.
It is deliberately kept in exactly one place: a second copy drifts from the
code and then lies about it, which is the failure this crate is least able to
afford.

In summary, and without restating it: every divergence is *stricter* than
the remaining C++ oracles (`make_header`, `handle_recv`) — none accepts
anything those reject. The list itself is in the crate docs; do not count
or classify it here.

All are unreachable for a conforming sender, and **one stopped being a
divergence at all** at the 2026-09-09 ingress cut — kept in the census as the
record of how it closed, not deleted, because "the difference went away" is
exactly the claim that rots into folklore once the entry is gone. Do not
summarise the census into blanket claims — checking each entry is exactly
what the single-location census exists to force.
