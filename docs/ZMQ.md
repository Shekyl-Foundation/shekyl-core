# The Current/Future Status of ZMQ in Shekyl

## What is ZMQ?

**ZeroMQ** (ZMQ, ØMQ, 0MQ) is an open-source, embeddable messaging library that provides asynchronous messaging for distributed and concurrent applications. It is not a traditional message broker: there is no central server. The "zero" refers to *zero broker*—applications talk to each other over sockets using patterns such as **publish–subscribe (pub/sub)**.

- **Transports:** Works over in-process, IPC, TCP, and other transports.
- **Patterns:** Request–reply, publish–subscribe, push–pull, and others.
- **Characteristics:** Small footprint, high throughput, language-agnostic (APIs in many languages). Messages are opaque; the application chooses the format (e.g. JSON).

In Shekyl, the daemon can act as a **ZMQ publisher**: it pushes events (new blocks, new mempool transactions, miner data) to clients that subscribe over TCP. This lets wallets, block explorers, or other services react in real time without polling the RPC. The daemon’s ZMQ interface is optional and must be enabled (see build/runtime docs or `--help` for ZMQ options).

For more on ZeroMQ: [zeromq.org](https://zeromq.org/), [Wikipedia – ZeroMQ](https://en.wikipedia.org/wiki/ZeroMQ).

PQC note:

- the rebooted chain's `TransactionV3` format introduces hybrid authentication
  material outside `tx_extra`
- this does not change the existence of ZMQ topics, but it can increase the
  size of `full` transaction and block event payloads substantially
- downstream consumers should treat transaction schema and size assumptions as
  versioned and should follow `docs/POST_QUANTUM_CRYPTOGRAPHY.md`

---

## ZMQ Pub/Sub
Client `ZMQ_SUB` sockets must "subscribe" to topics before it receives any data.
This allows filtering on the server side, so network traffic is reduced. Shekyl
allows for filtering on: (1) format, (2) context, and (3) event.

 * **format** refers to the _wire_ format (i.e. JSON) used to send event
   information.
 * **context** allows for a reduction in fields for the event, so the
   daemon doesn't waste cycles serializing fields that get ignored.
 * **event** refers to status changes occurring within the daemon (i.e. new
   block to main chain).

 * Formats:
   * `json`
 * Contexts:
   * `full` - the entire block or transaction is transmitted (the hash can be
     computed remotely).
   * `minimal` - the bare minimum for a remote client to react to an event is
     sent.
 * Events:
   * `chain_main` - changes to the primary/main blockchain.
   * `txpool_add` - new _publicly visible_ transactions in the mempool.
     Includes previously unseen transactions in a block but _not_ the
     `miner_tx`. Does not "re-publish" after a reorg. Includes `do_not_relay`
     transactions.
   * `miner_data` - provides the necessary data to create a custom block template
     Available only in the `full` context.

The subscription topics are formatted as `format-context-event`, with prefix
matching supported by both Shekyl and ZMQ. The `format`, `context` and `event`
will _never_ have hyphens or colons in their name. For example, subscribing to
`json-minimal-chain_main` will send minimal information in JSON when changes
to the main/primary blockchain occur. Whereas, subscribing to `json-minimal`
will send minimal information in JSON on all available events supported by the
daemon.

On the rebooted chain, consumers of `full` transaction events should expect:

- larger transaction payloads than legacy CryptoNote-only transactions
- a new transaction version for PQ-authenticated user transactions
- dedicated PQ authentication fields rather than hybrid signatures placed in
  `tx_extra`

The Shekyl daemon will ensure that events prefixed by `chain` will be sent in
"chain-order" - the `prev_id` (hash) field will _always_ refer to a previous
block. On rollbacks/reorgs, the event will reference an earlier block in the
chain instead of the last block. The Shekyl daemon also ensures that
`txpool_add` events are sent before `chain_*` events - the `chain_*` messages
will only serialize miner transactions since the other transactions were
previously published via `txpool_add`. This prevents transactions from being
serialized twice, even when the transaction was first observed in a block.

ZMQ Pub/Sub will drop messages if the network is congested, so the above rules
for send order are used for detecting lost messages. A missing gap in `height`
or `prev_id` for `chain_*` events indicates a lost pub message. Missing
`txpool_add` messages can only be detected at the next `chain_` message.

Since blockchain events can be dropped, clients will likely want to have a
timeout against `chain_main` events. The `GetLastBlockHeader` RPC is useful
for checking the current chain state. Dropped messages should be rare in most
conditions.

The Shekyl daemon will send a `txpool_add` pub exactly once for each
transaction, even after a reorg or restarts. Clients should use the
`GetTransactionPool` after a reorg to get all transactions that have been put
back into the tx pool or been invalidated due to a double-spend.


