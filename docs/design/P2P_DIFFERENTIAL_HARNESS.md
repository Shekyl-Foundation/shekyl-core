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

## Ordering

The in-process legs below can run now. Each one uses the same scripted
peer against epee's TCP server and against the seam, and compares the
two results.

The cross-build run cannot. It is a daemon whose zones use the seam,
talking to a daemon still on epee, on testnet: sync, relay, and both
dial directions. Production still uses epee, so that run waits on the
zone-binding commit. It is not blocked on this harness.

## In-process legs

`COMMAND_HANDSHAKE` (1001) is an invoke. The dialer sends it and waits
for the response. The session is established when that response is
back. A notify for 1001 is not this exchange.

`option_off_handshake_invoke_establishes_when_the_response_returns` is
the clearnet option-off leg of that exchange. The epee leg of the same
exchange is still open. The legs after it are still open, and each of
them runs through both servers:

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
