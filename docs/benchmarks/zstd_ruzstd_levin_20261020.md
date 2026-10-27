# libzstd level 1 against ruzstd `Fastest` on Levin block and transaction payloads, 2026-10-20

**State of this record: measured, not registered, and decided.** One run
per host, no cool-down and no frequency gate. It answers the measurement the
maintainer asked for before the codec swap (2026-10-19): "Before the swap,
measure on the Rust path: ratio and throughput vs libzstd level 1 on real
block/tx payloads, Pi decode time for a full block", with the
declared-frame-size guard kept. The decision it fed is at the end: no swap,
and compression left the protocol.

**The instrument is at `5fbba83ab`.** The corpus capture, the comparison
example and the codec they measured were deleted with compression in the
next commit, so a rerun checks out that commit. The paths below are paths in
that tree.

## What was measured

**Corpus.** `shekyl-engine-core`'s `zstd_corpus_capture`
(`rust/shekyl-engine-core/src/engine/regtest_e2e_zstd_corpus.rs`) at
`7a418a270`, against a regtest `shekyld` built from the same tree. A
mining wallet overfilled the pool with 50 one-input FCMP++ spends
(13,257 bytes each). The C++ producer then mined block 211 from that pool:
23 spends, weight 305,771 against median 300,000. The corpus also holds
the seven coinbase-only blocks before it. The proofs, keys, ciphertexts
and block structure are real, made by the production wallet and daemon.
The activity mix is not a network's, since every spend has the same
shape.

**Payloads.** `rust/shekyl-levin/examples/zstd_corpus_compare.rs` builds
from those blobs the portable-storage payloads the relay compresses:

| class | what | n |
| --- | --- | --- |
| `tx` | one `NOTIFY_NEW_TRANSACTIONS` per pool spend (fluff, unpadded: a padded notification is never compressed) | 50 |
| `tx-batch` | all 50 spends in one notification | 1 |
| `compact` | one `NOTIFY_NEW_COMPACT_BLOCK` per block, bodies included | 8 |
| `compact-header` | the same, no bodies | 8 |
| `objects` | one `RESPONSE_GET_OBJECTS` per block, bodies included | 8 |
| `objects-batch` | all 8 blocks in one response | 1 |

**Arms.** The libzstd arm is the production path: `compress_payload`
(level 1, sent only if strictly smaller), then `inflated_size` (the guard)
and `decompress_into`. The ruzstd 0.9.1 arm is
`compress_to_vec(_, CompressionLevel::Fastest)`, with default features off
(the `hash` feature adds a checksum that libzstd's level-1 frames lack),
and then `FrameDecoder::init`, `content_size` and `decode_all` into a
buffer of the declared size. Timings are the median of enough runs to fill
60 ms, after two warm-up runs.

**Oracle.** For every payload, four decodes are checked byte-for-byte
against the input: libzstd of libzstd, libzstd of ruzstd, ruzstd of
ruzstd, and ruzstd of libzstd. All 76 passed on both hosts.

**Hosts.** The x86_64 development host (11th-gen Core i9, 16 threads).
The floor device (rule 76, the Pi 4) ran a binary cross-built from the
same tree, pinned to core 3, under a quiet claim, with the testnet daemon
resident and idle. Core 3 read 1.5 GHz before the run and 1.3 GHz after.

## Results

### 1. ruzstd 0.9.1 frames fail the bomb guard as they come

ruzstd's encoder writes no `Frame_Content_Size`: it hard-codes `None`,
and 0.9.1 has no API to set it. The production guard refused all 76 raw
ruzstd frames.

The `+fcs` column is the same frame with the field written in after
ruzstd's window byte, in the smallest width that holds the size (RFC 8878
§3.1.1.1.1). That is 2 bytes for 256 to 65,791 bytes and 4 above. The
example's `with_content_size` shows the rewrite. All 76 rewritten frames
passed the production guard and decoded through the production libzstd
path, and ruzstd decoded them too.

ruzstd's own header read (`FrameDecoder::content_size`) returns 0 when
the field is absent. That is indistinguishable from a declared 0, so a
ruzstd-side guard has to refuse 0.

### 2. Ratio: libzstd level 1 compresses none of these payloads

Size is shown as a percentage of the input; "sent" is the number of
payloads that would go out compressed.

| class | input B | libzstd 1 | ruzstd | ruzstd + fcs | sent, libzstd / ruzstd |
| --- | ---: | ---: | ---: | ---: | :---: |
| `tx` | 662,850 | 100.08 % | 100.07 % | 100.08 % | 0 / 0 |
| `tx-batch` | 661,870 | 100.00 % | 99.60 % | 99.60 % | 0 / 1 |
| `compact` | 317,625 | 100.03 % | 99.63 % | 99.64 % | 0 / 1 |
| `compact-header` | 13,168 | 100.61 % | 100.55 % | 100.67 % | 0 / 0 |
| `objects` | 317,673 | 100.03 % | 99.63 % | 99.64 % | 0 / 1 |
| `objects-batch` | 317,295 | 100.01 % | 99.47 % | 99.47 % | 0 / 1 |

**Every libzstd level-1 frame was larger than its input.** All 76 payloads
go out uncompressed today, and the relay's compression call is pure CPU on
this traffic.

**ruzstd shrinks the four payloads of about 300 KB and more by 0.40 % to
0.53 %.** So the send decision changes on those four: they would go out
compressed. The `zstd` CLI on the full block's `objects` payload
(306,753 B) gives 306,775 B at levels 1, 3 and 9, and 305,090 B at
level 19. libzstd finds what ruzstd `Fastest` finds only at its slowest
levels.

### 3. Throughput

All figures are MB/s over each class's summed median times.

| class | host | compress, libzstd 1 | compress, ruzstd | decode, libzstd | decode, ruzstd (own frame) | decode, ruzstd (libzstd frame) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `tx` | dev | 1,818 | 70 | 38,840 | 23,172 | 23,570 |
| `tx` | floor | 305 | 17 | 3,446 | 2,122 | 2,261 |
| `objects` | dev | 2,163 | 63 | 32,245 | 4,897 | 16,917 |
| `objects` | floor | 396 | 9 | 4,055 | 223 | 1,176 |
| `objects-batch` | dev | 2,772 | 65 | 36,938 | 4,108 | 18,760 |
| `objects-batch` | floor | 557 | 9 | 4,115 | 239 | 1,199 |

The full tables, with every payload, are in the TSVs beside this file.

**Compression with ruzstd `Fastest` is 18 to 62 times slower than
libzstd level 1 on the payloads of 13 KB and more.** That was 26–50× on
the development host and 18–62× on the floor device. On the header-only
payloads (1.5 to 2.3 KB) it is about 8× slower. Rerunning with glibc's mmap and trim thresholds raised
(`_dev_host_mmap_threshold.tsv`) left it at 65 MB/s, so the cost is in the
codec, not the allocator.

### 4. The full block on the floor device

The full block is `RESPONSE_GET_OBJECTS` for block 211: 23 spends,
306,753 bytes. Times are the medians from the `compare` run, except the
one marked †, which only the `decode` run measures:

| operation | libzstd | ruzstd |
| --- | ---: | ---: |
| compress | 0.60 ms | 32.5 ms |
| decode its own frame | 0.073 ms | 1.41 ms |
| decode the other codec's frame | 0.083 ms † (ruzstd + fcs) | 0.26 ms (libzstd) |

The separate `decode` run, a fresh process doing only the four decodes,
measured ruzstd's own-frame decode at 2.08 ms on the floor device. On the
development host it measured 215 µs against 63 µs in `compare`. With
glibc's mmap threshold raised, the development host's figure fell to
60 µs. That points to allocation, not decoding. The example builds a new
`FrameDecoder` for every call, and in a fresh process glibc serves and
returns its large buffers through mmap until its threshold adapts. A
decoder that is kept and re-`init`ed (ruzstd supports this) should not pay
that cost; this run did not measure that case. The `compare` figures are
the warm case.

### 5. Where the compress cost lands

The C++ calls the compressor in three places:

- `relay_notify_to_list` (`src/p2p/net_node.inl`) compresses once per
  relay, for every peer on the list.
- `invoke_notify_to_peer` (the same file) compresses on every call. This
  is the path a sync response takes, so a node serving sync pays the
  compressor once per response.
- `make_payload_send_txs` (`src/cryptonote_protocol/levin_notify.cpp`)
  compresses unpadded transaction notifications.

At ruzstd's floor-device rate (9 MB/s), a node serving one full block
pays about 33 ms of CPU, against about 0.6 ms now. One maximal 128 MiB
payload would take about 14 s. Under libzstd level 1 the same work
produces frames that are thrown away for being larger than their input.

### 6. Handshake and timed-sync peer lists

The maintainer's ruling on #1134 (2026-10-19) asked for these with the
same rig, as a check rather than a gate. No corpus holds them, because a
regtest daemon has no peers. The example's `peers` mode builds them with
the production encoder from fixed-seed values: random public addresses,
node identifier, nonce and tip, with every peer on testnet's default port
(12021). Each list is full, at `DISCLOSE_COUNT` (12) entries, the most a
message may carry. A shared port and full lists are the most repetitive
case, so these are the best case for compression.

| payload | input B | libzstd 1 | ruzstd + fcs | saved B, best codec |
| --- | ---: | ---: | ---: | ---: |
| handshake request | 258 | 244 | 264 | 14 |
| handshake response, 12 IPv4 | 731 | 334 | 353 | 397 |
| handshake response, 12 IPv6 | 887 | 476 | 501 | 411 |
| handshake response, 12 Tor | 1,415 | 767 | 991 | 648 |
| handshake response, mixed | 1,011 | 586 | 661 | 425 |
| timed-sync request | 158 | 146 | 168 | 0 (under 256 B, never compressed) |
| timed-sync response, 12 IPv4 | 671 | 277 | 294 | 394 |
| timed-sync response, 12 IPv6 | 827 | 419 | 441 | 408 |
| timed-sync response, 12 Tor | 1,355 | 710 | 930 | 645 |
| timed-sync response, mixed | 951 | 533 | 599 | 418 |

Full rows are in `_peer_lists.tsv`. All 10 payloads passed the four-way
decode check.

**In proportion, the saving is large: a full list compresses to 41–58 %
of its size.** Each entry is one address. That is 6 to 64 bytes of value
(an IPv4 address and port, up to a 62-character onion name and port)
inside a portable-storage section that repeats the same key names (`adr`,
`addr`, `type`, `m_ip`/`addr`/`host`, `m_port`/`port`) in every entry.
The redundancy is in the encoding, not the addresses.

**In absolute terms it is under 650 bytes per message.** A handshake is
once per connection; a timed sync is every 60 s
(`P2P_DEFAULT_HANDSHAKE_INTERVAL`). So the best case is about 650 bytes a
minute per connection, about 11 bytes a second.

**No send path compresses these commands today.** The three C++ call
sites (§5) send notifications. Handshakes and timed syncs are invokes:
the Rust dialer sends the outbound requests, the epee handler answers
inbound ones, and neither path has a compressor. So
removing compression changes nothing on the wire for these payloads
either. The saving above is what compression would add if a send path
were written for them.

## Decision (Rick, 2026-10-19)

Neither the swap nor a decode-only ruzstd. **Compression is removed from the
P2P protocol entirely**: the Levin compression flag, the C++ compression shim,
`shekyl-levin`'s compress module and its FFI exports, and the `zstd` and
`zstd-sys` crates. Testnet upgrades all at once, so no decode-only path is
kept. A bucket that still carries the old `0x10` bit is refused at ingress
like any undefined bit (`SHEKYL_P2P_PROTOCOL.md` PWD-T7).

The reasons:

1. **libzstd level 1 enlarged all 76 block and transaction payloads**
   (§2), so nothing was ever sent compressed.
2. **ruzstd's gain is under 0.6 % at 18–62 times the CPU** (§2, §3).
3. **Compression before encryption is a size side channel**: compressed
   length follows content, and a path observer reads it from the frame.
4. **It undoes the padding buckets**: padding quantizes a message's size so
   its volume cannot be read; compressing after it puts the size back in
   step with the content.

The peer lists (§6) are not a large saving: about 650 bytes a minute per
connection, and earned only by code that does not exist. Their redundancy is
the encoding's repeated key names, and the fix for that is a compact P2P wire
encoding, not a compressor (FOLLOWUPS).

## What this does not cover

- **Other message classes.** Chain entries and the remaining Levin
  commands are not measured.
- **A network's activity mix.** Multi-input spends, staking transactions
  and real block fill were not captured. A testnet capture needs a host
  claim and is not this run.
- **Concurrency.** Each measurement is one thread on an idle host.
