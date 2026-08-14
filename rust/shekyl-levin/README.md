# shekyl-levin

Levin p2p **framing** layer — the Shekyl-owned Rust skeleton of the wire
protocol specified in [`docs/LEVIN_PROTOCOL.md`](../../docs/LEVIN_PROTOCOL.md).

## What this crate is

The bottom layer of the p2p stack, byte-identical to the C++ `epee::levin`
implementation:

- the 33-byte bucket header (`bucket_head2`): signature, length, expect-response,
  command, return code, Q/S/B/E/COMPRESSED flags, protocol version;
- whole-message builders for the notification / request / response flows;
- dummy ("noise") messages and noise-shaped fragmentation for the white-noise
  feature over i2p/Tor;
- the zstd `COMPRESSED` path (cargo feature `zstd`, default on — this crate
  owns the policy; feature off is only for pure-Rust unavailability tests);
- an incremental stream reader (`BucketReader`) mirroring the
  `async_protocol_handler::handle_recv` state machine: partial reads,
  signature early-reject, packet-size limits (256 KiB pre-handshake / 100 MB
  post), a pluggable per-command size-limit hook (the C++
  `connection_context::get_max_bytes` seam — the daemon's command table
  itself is cutover-layer policy), noise discard, fragment reassembly,
  decompression, and message classification. `feed` buffers bytes and
  `next_message` parses one bucket at a time, so — as in `handle_recv`,
  which dispatches inside its parse loop — at most one decoded payload is
  live at a time and an already-delivered message survives a later bucket
  in the same read being malformed.

Byte-identity is pinned by KATs (`tests/oracle_kats.rs`) mirroring the C++
gtests in `tests/unit_tests/levin.cpp` assertion for assertion; round-trip
property tests (`tests/properties.rs`) cover arbitrary payloads, commands,
chunk boundaries, and noise sizes.

## What this crate is not

- **Not the payload codec.** Command bodies (handshake, timed sync, notify
  payloads) are epee `portable_storage` blobs; this crate treats them as
  opaque bytes until LV-2b. The codec is first-party `shekyl-portable-storage`
  (LV-2a); see `docs/design/LV2_PORTABLE_STORAGE.md`. This crate will
  grow typed command structs on that codec — it does not absorb it.
- **Not the connection stack.** No sockets, timeouts, invoke/response
  correlation, or peer management.
- **Framing not wired; compression is.** Since 2026-08-06 the daemon's
  compression path runs through this crate: `contrib/epee`'s
  `levin_compression.cpp` is a marshaling shim over the `shekyl_levin_*`
  FFI (`rust/shekyl-ffi/src/levin_ffi.rs`), and the vendored libzstd here
  is the binary's single zstd (no system libzstd, no `HAVE_ZSTD` gate).
  The framing path — builders, `BucketReader` — stays C++
  (`contrib/epee`, `src/p2p/`, `src/cryptonote_protocol/levin_notify.*`)
  until the scheduled p2p cutover. This crate is the verified foundation
  that cutover starts from.

## Documented divergences from the C++ oracle

**The authoritative census lives in the crate docs** — the module comment at
the top of [`src/lib.rs`](src/lib.rs), rendered by `cargo doc -p shekyl-levin`.
It is deliberately kept in exactly one place: a second copy drifts from the
code and then lies about it, which is the failure this crate is least able to
afford.

In summary, and without restating it: every divergence is *stricter* than the
C++ — none accepts anything the oracle rejects. Five are read-side (three
about fragment reassembly and response classification, one bounding a
decompressed payload by the packet limit in force, one latching the reader
after a fatal error); one is emit-side, where `try_compress_message` returns
malformed input unchanged rather than re-framing it.

All are unreachable for a conforming sender, and **two stopped being
divergences at all** at the 2026-08-06 compression cut — kept in the census
as the record of how they closed, not deleted, because "the difference went
away" is exactly the claim that rots into folklore once the entry is gone.
The post-inflate bound was the one reachable exception (a ~34 MB interop
window against a C++ peer) until the cut brought the C++ receiver onto the
same `min(packet limit, per-command cap)` bound (entry 4); the emit-side
strictness stopped being a difference when `epee::levin::
try_compress_message` became a forwarding shim over this crate, so its
guards — signature, one-message, and the noise class whose constant on-wire
size cover traffic depends on — are now simply the emit path (entry 6). Do
not summarise the census into blanket claims — checking
each entry is exactly what the single-location census exists to force.
