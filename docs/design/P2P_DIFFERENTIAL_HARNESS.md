# P2P differential harness

**Status: OPEN.** D11's gate before any transport deletion. The
comparison is the Levin bytes a peer sees and the session result, option
off, on loopback. Cross-build interop is the following run. Cutover
waits on the thread budget and the per-connector deadlines.

## What is compared

The same Levin notify goes through the clearnet connector with the
option off and through epee's TCP server. A peer's socket bytes are
the notify. The session result is that notify's command. Option off
writes the session bytes onto the socket.

## Expected divergences

A difference on one of these is expected. It is not a regression
toward epee:

- deadlines derived per connector;
- typed close causes, the first cause wins, and FIN after zero bytes
  written;
- admission in Rust, the check and the reservation in one step;
- no local/remote timer split;
- no TOS knob;
- send and receive bounds in bytes.

## This slice

`option_off_shows_the_peer_the_levin_notify` is the clearnet leg: the
peer's read and the session are the handshake notify, and the reader
recovers command 1001.

The epee leg is still open. It sends that same notify through
`boosted_tcp_server` to a loopback peer and compares those socket
bytes and the parsed command. The cross-build run is still open. Neither
is cutover.
