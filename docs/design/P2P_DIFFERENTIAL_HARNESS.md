# P2P differential harness

**Status: OPEN.** D11's gate before any transport deletion. Option off,
on loopback. The comparison is what the peer receives back and whether
the session is established. Cutover waits on the thread budget and the
per-connector deadlines.

## Expected divergences

A difference on one of these is expected. It is not a regression
toward epee, and it is not something the harness "fixes":

- FIN after zero bytes when a connection fails before the channel exists;
- typed causes, with the first one recorded winning;
- admission refusal at accept via atomic reservation;
- derived deadlines, not epee's;
- no local/remote timer split;
- no TOS setting;
- send and receive bounds in bytes.

The comparator's names for these are `fin-after-zero-bytes`,
`typed-cause-first-wins`, `admission-reservation`, `derived-deadline`,
`no-timer-split`, `no-tos`, and `byte-bounds`. A parity field is not
one of those names.

## How two stacks are compared

The epee side is C++, in `boosted_tcp_server`. The seam side is Rust.
The harness does not link epee into a Rust test.

One scripted peer, `shekyl-p2p-harness`'s `peer`, is built on
`shekyl-levin`. It connects to an address, runs a seed, and writes a
transcript: every byte it sent and received, and how the connection
ended. The seed is on the transcript, so a failing case replays
against either host.

Two hosts, each with a recording handler:

- `seam-host`, the Rust host. Until zone bind its socket is the public
  clearnet `listen` with the option off. The session bytes are what
  the seam delivers to the Levin handler. It does not use the
  connector's tests, and it does not open a second admission table.
- `epee-host`, the C++ binary. It hosts `boosted_tcp_server`, serves
  one connection, and writes this transcript. It is the only C++ in
  the harness, and it is not linked into the Rust crate.

`seam-host SEED TRANSCRIPT` and `epee-host SEED TRANSCRIPT` each print
`host:port` on stdout, serve one connection, and write the host
transcript. `peer ADDR SEED TRANSCRIPT` dials that address.

`compare` diffs the two transcripts. A difference in a parity field
(`peer-sent`, `peer-recv`, `peer-end`, `host-delivered`, `host-sent`,
`host-session`) is a finding. A difference on the expected-divergences
list is not. An unknown version line is a parse failure, not a
mismatch.

Seed 1 is the handshake invoke. The dialer sends it and waits. The
session is established when the response is back. `the_same_seed_replays_against_the_seam_host`
runs that seed twice against the seam host.

## Transcript

Version 1 is the current format. Both writers emit it. `compare`
rejects any other version line, so a drift between them is a parse
failure.

The file is UTF-8. One field per line, LF endings, and a trailing LF
after the last line. There is no timestamp. A writer emits exactly
these lines, in this order:

```text
shekyl-p2p-transcript 1
seed <u64 decimal>
role <peer|host>
sent <hex>
recv <hex>
end <established|closed|refused>
```

`seed` is the script. `role` is `peer` or `host`. For a peer, `sent`
is the bytes it wrote and `recv` is the bytes it read. For a host,
`recv` is the bytes delivered to the Levin handler and `sent` is the
bytes that handler sent. Those are the bytes on the connection, the
header included.

Byte fields are lowercase hexadecimal, two digits per byte, no
separators. An empty field is the key, one space, and nothing else.
A digit outside `0-9` and `a-f`, or an odd number of digits, does not
parse.

`end` is `established`, `closed`, or `refused`. `established` means
the handshake response came back. `closed` means the peer closed
before that response. `refused` means the invoke was not a handshake.
It is not a transport cause.

An extra line, a missing field, or a version line other than
`shekyl-p2p-transcript 1` does not parse.

Version 2 is not this format. The backpressure leg needs the order of
events: what was written and read, when the connection stalled and
resumed, and how it ended, still with no timestamps. That lands as
`shekyl-p2p-transcript 2` when that seed is written, rather than being
squeezed into these fields. A golden's first line is the version, so
the format it uses is on the golden.

## Ordering

The in-process legs below can run now. Each one is a seed of the same
peer, against the epee host and the seam host.

The cross-build run cannot. It is a daemon whose zones use the seam,
talking to a daemon still on epee, on testnet: sync, relay, and both
dial directions. Production still uses epee, so that run waits on the
zone-binding commit. It is not blocked on this harness.

## Goldens

Before cutover, the peer runs against both hosts and `compare` diffs
them.

At cutover, the epee host's transcripts for the parity scope — wire
bytes and session outcomes, nothing on the expected-divergences list —
are recorded as golden transcripts and committed, keyed by seed. Then
the epee host is deleted with the rest of epee.

After cutover, in CI, the same peer runs every seed against the Rust
transport. Each run checks the goldens (the peer still sees the same
Levin bytes and gets the same session outcome) and the invariants that
need no reference: whole messages only, stopping reading rather than
closing under backpressure, one cause with the first recorded winning,
FIN after zero bytes, and the byte bounds.

A golden changes only on purpose. When a ruled change alters the wire
— the flip adding Noise, or fixed-window framing — the goldens are
re-recorded in that same pull request, with the ruling cited. A golden
that changes without a ruling behind it is a regression.

Later the same peer drives the Tor leg, and after LV-3 it tests the
Rust Levin layer. The peer stays; the epee host does not.

## In-process legs

`COMMAND_HANDSHAKE` (1001) is an invoke. A notify for 1001 is not this
exchange. Seed 1 is that invoke and its response. The request carries
network id sixteen bytes of `0x11`, IPv4 `0.0.0.0:18080`, support
flags 0, height 1, cumulative difficulty 2, difficulty top64 0, top id
thirty-two bytes of `0xab`, top version 0, and a 32-byte nonce whose
first eight bytes are the seed little-endian. The response is the same
node and sync data with an empty peer list. The invoke is one write.
The legs after it are further seeds, not new hosts:

1. **Byte splits.** The same message sequence, at every read boundary
   a peer can produce. A property test draws random Levin sequences and
   random split points, and both sides hand the Levin handler identical
   bytes.
2. **Size extremes.** Messages at each command's cap, including the
   4 MiB envelopes.
3. **Concurrent senders.** A response on the connection's strand and a
   relay send from the zone's strand at the same moment. The peer
   receives whole messages, never two interleaved mid-message.
4. **Closes.** The peer closes mid-message, the handler refuses a
   delivery, a send does not fit. For each, compare the session
   outcome and the recorded cause.
5. **Backpressure.** A slow handler stops reading on the seam's side.
   It does not close. The peer sees TCP push back, not a reset. The
   order of that stall is version 2 of the transcript, not these
   totals.
