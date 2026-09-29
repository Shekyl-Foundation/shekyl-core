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
- the epee host, a small C++ binary that has not been written yet. It
  is the only C++ in the harness, and it exists only as the reference.
  It writes the same transcript. The next commit is that binary; the
  peer and the comparator do not change for it.

`compare` diffs the two transcripts. A difference in a parity field
(`peer-sent`, `peer-recv`, `peer-end`, `host-delivered`, `host-sent`,
`host-session`) is a finding. A difference on the expected-divergences
list is not.

Seed 1 is the handshake invoke. The dialer sends it and waits. The
session is established when the response is back. `the_same_seed_replays_against_the_seam_host`
runs that seed twice against the seam host.

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
exchange. Seed 1 is that invoke and its response. The legs after it
are further seeds, not new hosts:

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
   It does not close. The peer sees TCP push back, not a reset.
