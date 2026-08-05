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
- the zstd `COMPRESSED` path (cargo feature `zstd`, default on — feature off
  mirrors a C++ build without `HAVE_ZSTD`);
- an incremental stream reader (`BucketReader`) mirroring the
  `async_protocol_handler::handle_recv` state machine: partial reads,
  signature early-reject, packet-size limits (256 KiB pre-handshake / 100 MB
  post), a pluggable per-command size-limit hook (the C++
  `connection_context::get_max_bytes` seam — the daemon's command table
  itself is cutover-layer policy), noise discard, fragment reassembly,
  decompression, and message classification.

Byte-identity is pinned by KATs (`tests/oracle_kats.rs`) mirroring the C++
gtests in `tests/unit_tests/levin.cpp` assertion for assertion; round-trip
property tests (`tests/properties.rs`) cover arbitrary payloads, commands,
chunk boundaries, and noise sizes.

## What this crate is not

- **Not the payload codec.** Command bodies (handshake, timed sync, notify
  payloads) are epee `portable_storage` blobs; this crate treats them as
  opaque bytes. A portable_storage codec (or a vendoring decision) is a
  separate, tracked work item.
- **Not the connection stack.** No sockets, timeouts, invoke/response
  correlation, or peer management.
- **Not wired.** The daemon's live path stays C++ (`contrib/epee`,
  `src/p2p/`, `src/cryptonote_protocol/levin_notify.*`) until the scheduled
  p2p cutover. This crate is the verified foundation that cutover starts
  from.

## Documented divergences from the C++ oracle

All three are read-side. Divergences 1–2 are strictly tighter (no conforming
sender trips them). Divergence 3 is a deliberate model cleanup that agrees
with the C++ on every conforming packet (including all
`make_fragmented_notify` output):

1. the reassembled inner fragment header's **signature is verified**; the
   C++ `memcpy`s it without checking;
2. the inner header's `length` must fit the reassembled bytes and the
   delivered payload is **trimmed to that length**; the C++ forwards the
   fragment zero-padding to the command handler and relies on the payload
   parser ignoring trailing bytes;
3. **response classification** uses the logical message header's
   `protocol_version` (inner after reassembly). The C++ sticky
   `m_oponent_protocol_ver` is only refreshed on outer-header parse, so a
   crafted fragment train can disagree on whether a reassembled bucket is
   a response. Conforming outer fragment headers always carry version 1,
   and the protocol's fragment emitters only produce notifications.

Emit-side output is byte-identical, no divergences.
