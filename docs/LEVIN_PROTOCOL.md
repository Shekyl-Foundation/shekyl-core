# Levin Protocol
This is a document explaining the current design of the Levin protocol, as
used by Shekyl. The protocol is largely inherited from cryptonote, but has
undergone some changes.

This document also may differ from the `struct bucket_head2` in Shekyl's
code slightly - the spec here is slightly more strict to allow for
extensibility.

One of the goals of this document is to clearly indicate what is being sent
"on the wire" to identify metadata that could de-anonymize users over I2P/Tor.
These issues will be addressed as they are found. See `ANONYMITY_NETWORKS.md` in
the `docs` folder for any outstanding issues.

PQC note:

- the transport header described here is unchanged by the planned PQC rollout
- however, reboot-only `TransactionV3` objects with hybrid signatures will make
  transaction-bearing protocol messages materially larger
- the canonical transaction/authentication format is specified in
  `POST_QUANTUM_CRYPTOGRAPHY.md`

> This document does not currently list all data being sent by the Shekyl
> protocol, that portion is a work-in-progress. Please take the time to do it
> if interested in learning about Shekyl p2p traffic!


## Header
This header is sent for every Shekyl p2p message.

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      0x01     |      0x21     |      0x01     |      0x01     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      0x01     |      0x01     |      0x01     |      0x01     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Length                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  E. Response  |                   Command
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                 Return Code
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |Q|S|B|E|               Reserved
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |      0x01     |      0x00     |      0x00     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     0x00      |
+-+-+-+-+-+-+-+-+
```

### Signature
The first 8 bytes are the "signature" which helps identify the protocol (in
case someone connected to the wrong port, etc). The comments indicate that byte
sequence is from "benders nightmare".

This also can be used by deep packet inspection (DPI) engines to identify
Shekyl when the link is not encrypted. SSL has been proposed as a means to
mitigate this issue, but BIP-151 or the Noise protocol should also be considered.

### Length
The length is an unsigned 64-bit little endian integer. The length does _not_
include the header.

The implementation currently rejects received messages that exceed 100 MB
(base 10) by default.

### Expect Response
A zero-byte if no response is expected from the peer, and a non-zero byte if a
response is expected from the peer. Peers must respond to requests with this
flag in the same order that they were received, however, other messages can be
sent between responses.

There are some commands in the
[cryptonote protocol](#cryptonote-protocol-commands) where a response is
expected from the peer, but this flag is not set. Those responses are returned
as notify messages and can be sent in any order by the peer.

### Command
An unsigned 32-bit little endian integer representing the Shekyl-specific
command being invoked.

### Return Code
A signed 32-bit little endian integer representing the response from the peer
from the last command that was invoked. This is `0` for request messages.

### Flags
 * `Q` - Bit is set if the message is a request.
 * `S` - Bit is set if the message is a response.
 * `B` - Bit is set if this is a the beginning of a [fragmented message](#fragmented-messages).
 * `E` - Bit is set if this is the end of a [fragmented message](#fragmented-messages).

### Version
A fixed value of `1` as an unsigned 32-bit little endian integer.


## Message Flow
The protocol can be subdivided into: (1) notifications, (2) requests,
(3) responses, (4) fragmented messages, and (5) dummy messages. Response
messages must be sent in the same order that a peer issued a request message.
A peer does not have to send a response immediately following a request - any
other message type can be sent instead.

### Notifications
Notifications are one-way messages that can be sent at any time without
an expectation of a response from the peer. The `Q` bit must be set, the `S`,
`B` and `E` bits must be unset, and the `Expect Response` field must be zeroed.

Some notifications must be in response to other notifications. This is not
part of the levin messaging layer, and is described in the
[commands](#commands) section.

### Requests
Requests are the basis of the admin protocol for Shekyl. The `Q` bit must be
set, the `S`, `B` and `E` bits must be unset, and the `Expect Response` field
must be non-zero. The peer is expected to send a response message with the same
`command` number.

### Responses
Response message can only be sent after a peer first issues a request message.
Responses must have the `S` bit set, the `Q`, `B` and `E` bits unset, and have
a zeroed `Expect Response` field. The `Command` field must be the same value
that was sent in the request message. The `Return Code` is specific to the
`Command` being issued (see [commands])(#commands)).

### Fragmented
Fragmented messages were introduced for the "white noise" feature for i2p/tor.
A transaction can be sent in fragments to conceal when "real" data is being
sent instead of dummy messages. Only one fragmented message can be sent at a
time, and bits `B` and `E` are never set at the same time
(see [dummy messages](#dummy)). The re-constructed message must contain a
levin header for a different (non-fragment) message type.

The `Q` and `S` bits are never set and the `Expect Response` field must always
be zero. The first fragment has the `B` bit set, neither `B` nor `E` is set for
"middle" fragments, and `E` is set for the last fragment.

### Dummy
Dummy messages have the `B` and `E` bits set, the `Q` and `S` bits unset, and
the `Expect Response` field zeroed. When a message of this type is received, the
contents can be safely ignored.


## Commands

This document currently focuses on the Levin framing layer and high-level
command inventory. It does not yet enumerate every field in every transaction-
bearing payload.

For the rebooted chain:

- commands that relay transactions or blocks will eventually carry
  `TransactionV3` payloads
- `TransactionV3` introduces dedicated PQ authentication fields outside
  `tx_extra`
- downstream tooling must not assume pre-PQC transaction sizes

### P2P (Admin) Commands

#### (`1001` Request) Handshake
#### (`1001` Response) Handshake
#### (`1002` Request) Timed Sync
#### (`1002` Response) Timed Sync
#### (`1003` Request) Ping
#### (`1003` Response) Ping
#### (`1004` Request) Stat Info
#### (`1004` Response) Stat Info
#### (`1005` Request) Network State
#### (`1005` Response) Network State
#### (`1006` Request) Peer ID
#### (`1006` Response) Peer ID
#### (`1007` Request) Support Flags
#### (`1007` Response) Support Flags

### Cryptonote Protocol Commands

#### (`2001` Notification) New Block

Carries a full serialized block. Post-v3, user transactions within the block
include `pqc_auth` material (~5.4 KB per user tx). Miner coinbase remains
excluded from `pqc_auth`.

#### (`2002` Notification) New Transactions

Carries one or more serialized transactions for mempool relay. This is the
primary message type affected by v3 PQC sizing: each `TransactionV3` user
transaction adds ~5,385 bytes of hybrid authentication data.

Over anonymity networks, this message is the most fingerprinting-sensitive:
it is sent shortly after a wallet constructs a transaction and is the
strongest timing signal linking a peer to a spend event.

#### (`2003` Notification) Request Get Objects
#### (`2004` Notification) Response Get Objects

Response carries requested block/transaction objects. Payload size is
variable and scales linearly with the number of v3 transactions in the
requested range.

#### (`2006` Notification) Request Chain
#### (`2007` Notification) Response Chain Entry

Carries block hashes for chain synchronization. Not affected by v3 PQC
sizing (block headers do not contain `pqc_auth`).

#### (`2008` Notification) New Fluffy Block

Carries block header plus transaction hashes (not full transactions). The
receiving peer requests missing transactions via `2009`. Not directly
affected by PQC sizing, but the follow-up `2002`/`2009` exchange is.

#### (`2009` Notification) Request Fluffy Missing TX

Requests specific transactions by hash. The response contains full
serialized v3 transactions including `pqc_auth`.

### Wire Data Privacy Summary

| Command | PQC size impact | Anonymity sensitivity | Notes |
|---|---|---|---|
| 1001 Handshake | None | Low | Peer identity exchange |
| 1002 Timed Sync | None | Medium | Timestamp fingerprinting risk |
| 2001 New Block | Proportional to tx count | Low | Broadcast, not origin-attributable |
| 2002 New Transactions | +5.4 KB per user tx | High | Origin-attributable timing signal |
| 2003/2004 Get Objects | Proportional to tx count | Low | Sync protocol |
| 2006/2007 Chain Entry | None | None | Hash-only |
| 2008 Fluffy Block | Minimal | Low | Header + hashes |
| 2009 Missing TX | +5.4 KB per requested tx | Medium | Follow-up to fluffy block |
