# Anonymity Networks with Shekyl

> **UPDATE 2026-09-12.** Tor-zone wire-observer cover is operator non-exit
> relay posture, not a protocol carrier. Mixing requires the daemon's Tor
> client (SOCKS and overlay inbound) to be **that same relay process** —
> a sidecar client Tor is uncovered. See [`TOR_RELAY.md`](TOR_RELAY.md)
> and [`design/TOR_COVER_POSTURE.md`](design/TOR_COVER_POSTURE.md). This
> file's remaining body is the Tor P2P usage matrix. I2P is not a network
> this daemon dials. This file is not the cover-posture source of truth: for
> cover, point `tor-socks` at the relay process as `TOR_RELAY.md` shows. A
> second client Tor is uncovered.

Tor is the anonymity network this daemon dials. I2P is not. The usage of
Tor is still considered experimental - there are a few pessimistic
cases where privacy is leaked. The design is intended to maximize privacy of
the source of a transaction by broadcasting it over Tor, while
relying on IPv4 for the remainder of messages to make surrounding node attacks
(via sybil) more difficult.

PQC note:

- the rebooted chain's hybrid signatures will increase transaction sizes
- larger transactions can change traffic-shape characteristics and may make
  relay events more fingerprintable if not considered in analysis
- the PQC transaction/authentication structure is specified in
  `docs/POST_QUANTUM_CRYPTOGRAPHY.md`

### Measured v3 Impact on Anonymity Networks

`TransactionV3` adds **5389** bytes of `pqc_auth` material per user
transaction input (`pqc_auth_weight()`; see `docs/V3_ROLLOUT.md`).
Practical consequences for anonymity relay:

- A typical 2-in/2-out FCMP++ transaction grows from ~2–3 KB to ~7–8 KB.
- On Tor, a single cell is 512 bytes; a v3 transaction spans ~14–16 cells
  vs ~4–6 cells pre-PQC. The burst pattern is more distinctive.
- Fragmented Levin messages (white noise feature) help pad smaller payloads
  but cannot conceal large-burst events unless dummy traffic volume is
  proportionally increased.

### Known Leak Vectors vs Mitigations Matrix

| Leak vector | Severity | Current mitigation | Residual risk |
|---|---|---|---|
| Timestamp correlation (timed sync) | Medium | System clock accuracy; future random offset | Fingerprintable if clock is skewed |
| ISP link timing (intermittent sync) | Medium | Keep `shekyld` running continuously | Users who sync-send-quit are linkable |
| Active bandwidth shaping | High | No second anonymity network is integrated | Tor circuits remain vulnerable |
| Stream reuse (2+ tx same circuit) | Medium | Outgoing-only selection, 5-min rotation, 20-min change lock time | Small fixed outgoing pool → non-trivial reuse probability |
| v3 tx size burst (new) | Medium | Fragmentation + dummy messages | Burst pattern still larger than pre-PQC; requires tuning dummy volume |
| Levin 8-byte signature (DPI) | Low | SSL/BIP-151/Noise proposals | Not yet implemented; clearnet traffic is identifiable |

### Recommended Pre-Mainnet Testing

1. Replay a representative testnet transaction mix over Tor, measuring
   circuit-level timing and cell/fragment counts before and after v3.
2. Measure the ratio of real-to-dummy Levin messages required to make v3
   bursts statistically indistinguishable from pre-PQC traffic.
3. Validate that the 5-minute outgoing-connection rotation is sufficient given
   the higher per-tx relay time for v3 payloads.


## Behavior

With Tor on (`tor = managed`, the default, or `tor = operator`), this node's
own transactions go only over a route that hides its address. When no such
route is available, the node holds them, says so in its posture line, and
keeps them until one is. It never falls back to clearnet on its own.
`tor = off` with `clearnet = on` sends them over clearnet, and the posture line
says that the open network is unencrypted. The posture table is in
[`design/TOR_SUPERVISOR.md`](design/TOR_SUPERVISOR.md) §1.

`shekyl-cli` and `shekyl-wallet-rpc` can reach a daemon through a SOCKS proxy.
The daemon must then provide an onion service for its RPC, separate from the one
for P2P (see [Wallet over Tor](#wallet-over-tor)).


## Peers

Over Tor the node syncs, relays and broadcasts as it does over clearnet. The
posture line names what it is syncing over.

`p2p-peer` adds peers by IP endpoint or onion. `p2p-closed-peer` names the only
peers the node connects to: a non-empty list declares a closed network, on
every connector. Seeds are ordinary peers. An onion peer needs Tor on and an IP
peer needs clearnet on; otherwise the daemon refuses to start and names the
conflict.

For the rebooted chain, the transaction broadcast path should be re-evaluated
with PQ-authenticated transactions because:

- serialized transactions will be materially larger
- fragmentation/delay behavior may become more visible on anonymity networks
- any anti-fingerprinting strategy should be tested against post-PQC payload
  sizes, not legacy assumptions


## Usage

The examples use mainnet's ports: P2P 11021 and RPC 11029. Testnet uses 12021
and 12029, stagenet 13021 and 13029. These options can also go in the
configuration file ([`USER_GUIDE.md`](USER_GUIDE.md), "Configuration file").

### The managed Tor

`tor = managed` is the default. The daemon runs the bundled Tor, dials onions
through it, and publishes a per-boot onion for inbound. There is nothing to
configure.

### Your own Tor: outbound

`tor = operator` dials through a Tor you run, named by its SOCKS endpoint:

```
./shekyld --tor operator --tor-socks 127.0.0.1:9050
```

Without `tor-onion` this is dial-only over Tor. If that SOCKS port asks for a
username and password, set `tor-socks-username` and `tor-socks-password` in the
configuration file; they are not accepted on the command line.

Peers can be named. Repeat the option for more than one:

```
--p2p-peer <56 characters>.onion:11021
--p2p-closed-peer <56 characters>.onion:11021
```

`p2p-closed-peer` closes the network on every connector, which is rarely what
you want.

### Your own Tor: inbound

Configure an onion service in your Tor ("torrc"):

```
HiddenServiceDir /var/lib/tor/data/shekyl
HiddenServicePort 11021 127.0.0.1:11021
```

Tor stores the service's key in `/var/lib/tor/data/shekyl`, and its `hostname`
file holds the `.onion` address. Name that onion and its virtual port with
`tor-onion`, and the local endpoint the torrc forwards to with
`tor-onion-listen`:

```
./shekyld --tor operator --tor-socks 127.0.0.1:9050 \
    --tor-onion <56 characters>.onion:11021 --tor-onion-listen 127.0.0.1:11021
```

The node shares this onion with its Tor peers so they can pass it on. There is
no inbound count: the daemon's descriptor bound is the only inbound bound.

### Wallet over Tor

An onion service can forward to the daemon's RPC, separately from the P2P one.
The local port is the RPC port:

```
HiddenServiceDir /var/lib/tor/data/shekyl-rpc
HiddenServicePort 11029 127.0.0.1:11029
```

Then point the wallet at that onion through the Tor SOCKS port:

```
./shekyl-cli --wallet mywallet \
    --proxy socks5h://127.0.0.1:9050 \
    --daemon-address <56 characters>.onion:11029
```

An onion address authenticates the service and encrypts the connection end to
end. Whoever operates the daemon still sees which blocks the wallet requests
and what it broadcasts; see [`USER_GUIDE.md`](USER_GUIDE.md), "Connecting to a
daemon".

I2P is not a network this daemon dials, and a `.b32.i2p` address is not a peer
or an inbound address.

## Privacy Limitations

There are currently some techniques that could be used to _possibly_ identify
the machine that broadcast a transaction over an anonymity network.

### Timestamps

The peer timed sync command sends the current time in the message. This value
can be used to link an onion address to an IPv4/IPv6 address. If a peer first
sees a transaction over Tor, it could _assume_ (possibly incorrectly) that the
transaction originated from the peer. If both the Tor connection and an
IPv4/IPv6 connection have timestamps that are approximately close in value they
could be used to link the two connections. This is less likely to happen if the
system clock is fairly accurate - many peers on the Shekyl network should have
similar timestamps.

#### Mitigation

Keep the system clock accurate so that fingerprinting is more difficult. In
the future a random offset might be applied to anonymity networks so that if
the system clock is noticeably off (and therefore more fingerprintable),
linking the public IPv4/IPv6 connections with the anonymity networks will be
more difficult.

### Intermittent Shekyl syncing

If a user only runs `shekyld` to send a transaction then quit, this can also
be used by an ISP to link a user to a transaction.

#### Mitigation

Run `shekyld` as often as possible to conceal when transactions are being sent.
Future versions will also have peers that first receive a transaction over an
anonymity network delay the broadcast to public peers by a randomized amount.
This will not completely mitigate a user who syncs up sends then quits, in
part because this rule is not enforceable, so this mitigation strategy is
simply a best effort attempt.

### Active Bandwidth Shaping

An attacker could attempt to bandwidth shape traffic in an attempt to determine
the source of a Tor connection. There isn't a second anonymity network to
move the traffic onto: I2P is not integrated.

#### Mitigation

Tor is the network this daemon dials. Anyone attempting this strategy really
wants to uncover a user, and it seems unlikely that this would be performed
against every Tor user. A later anonymity network is a separate decision; it
is not a flag on this daemon.

### Tor stream used twice

If a single Tor stream is used 2+ times for transmitting a transaction, the
operator of the hidden service can conclude that both transactions came from the
same source. If the subsequent transactions spend a change output from the
earlier transactions, this will also reveal the "real" spend in the ring
signature. This issue was (primarily) raised by @secparam on Twitter.

#### Mitigation

`shekyld` currently selects two outgoing connections every 5 minutes for
transmitting transactions over Tor. Using outgoing connections prevents an
adversary from making many incoming connections to obtain information (this
technique was taken from Dandelion). Outgoing connections also do not have a
persistent public key identity - the creation of a new circuit will generate
a new public key identity. The lock time on a change address is ~20 minutes, so
`shekyld` will have rotated its selected outgoing connections several times in
most cases. However, the number of outgoing connections is typically a small
fixed number, so there is a decent probability of re-use with the same public
key identity.

@secparam (twitter) recommended changing circuits (Tor) as an additional
precaution. This is likely not a good idea - forcibly requesting Tor to change
circuits is observable by the ISP. Instead, `shekyld` should likely disconnect
from peers occasionally. Tor will rotate circuits every ~10 minutes, so
establishing new connections will use a new public key identity and make it
more difficult for the hidden service to link information. This process will
have to be done carefully because closing/reconnecting connections can also
leak information to hidden services if done improperly.

At the current time, if users need to frequently make transactions, Tor
will improve privacy from ISPs and other common adversaries, but still have
some metadata leakages to unknown hidden service operators.

## Transport for the staker-archival path (forward consideration — NOT a genesis commitment)

> **Status:** captured for consideration; no transport work is scheduled. This
> section records the analysis so the eventual transport-selection PR starts from
> a stated position rather than a blank page. Every maturity / capability claim
> below (Arti onion-service support, the Arti 2.x LTS line, Monero's
> over-Tor traffic split) is **to be re-verified at source** when the transport
> PR opens, per [`17-dependency-discipline.mdc`](../.cursor/rules/17-dependency-discipline.mdc) —
> recorded here as the rationale to test, not as banked fact.

The transaction-broadcast transport above is inherited from Monero and is a
*light, latency-tolerant, public-content* path. The **staker-archival** subsystem
(see [`design/V3_STAKER_ARCHIVAL.md`](V3_STAKER_ARCHIVAL.md) and the sim in
[`design/STAKER_ARCHIVAL_SIM.md`](design/STAKER_ARCHIVAL_SIM.md)) introduces a
*second* traffic class with a different threat profile, and the transport choice
turns out to be coupled to the sim's latency findings rather than independent of
them.

### Two traffic classes

- **Light / privacy-critical (latency-tolerant).** Stake claims, archival
  registration, the firewalled pseudonym's liveness re-proofs, and
  challenge–response retention proofs. Small, infrequent, delay-insensitive —
  exactly the class Monero already routes over the anonymity network (handshakes,
  timed syncs, transaction broadcast), with the bulk left on IPv4 to make
  surrounding-node sybil attacks harder. **Tor is a direct, battle-tested fit
  here.**

- **Heavy / archival data path (bandwidth-sensitive).** Deep-shard fetch (the
  retrieval side of coverage). This is where Shekyl **cannot reuse Monero's
  escape hatch.** Monero keeps bulk chain-sync on clearnet because that content
  is public and IP exposure is an accepted leak in its threat model. Shekyl's
  **firewalled-pseudonym requirement** is precisely that the pseudonym `P`'s
  network location not link to the principal, so the archival *serving* path
  must be the onion service, not clearnet. Combined with the query-privacy
  requirement (the fetcher is also over Tor), the heavy fetch becomes
  **onion-service-to-Tor-client** — the rendezvous configuration, the slowest
  path Tor has (three hops each side plus the rendezvous).

### The coupling to the sim (this is the load-bearing point)

The privacy model **structurally forces the heavy data path onto worst-case Tor
latency.** That means the `L2–L6` latency band in
[`STAKER_ARCHIVAL_SIM.md`](design/STAKER_ARCHIVAL_SIM.md) (§*L10*, §*L10
hardening*) is **not a stress-test corner — it is the operating regime by
construction.** The transport choice and the L10 latency findings are the same
physical fact seen from two sides:

- The "real Tor deep-fetch latency" the sim flagged as the post-testnet empirical
  unknown **is** Monero's documented heavy-over-Tor bandwidth pain.
- The sim has **already designed around it**: age-scaled bond duration is
  *win-or-harmless* across `L2–L6` (L10 H1/H4), and the foundation floor backstops
  the `L6` ceiling where backfill cannot keep pace regardless of incentive.

So Tor's heavy-path bandwidth weakness is a **known, bounded, already-modeled**
constraint, not a discovery waiting to happen. The post-testnet measurement only
tells us *where on the L-curve* we sit; it does not reopen the transport choice.

### TCP coupling

Tor carries TCP streams and has **no native UDP transport** (the UDP-oriented
designs are the *alternatives* — Lokinet/LLARP, I2P datagram mode). So the
inherited Levin/TCP P2P stack drops in without an impedance mismatch, and
**TCP-sync and Tor reinforce each other.** The flip side is that the commitment
is coupled: **if UDP/QUIC sync ever returns to the table, it reopens the transport
question**, because it fights Tor's grain. The TCP commitment and the Tor
commitment stand or fall together.

### Candidate transports (Tor primary; rationale to verify)

- **Tor — primary.** Maturity + TCP + persistent-reachable-service + longevity.
  The Rust-native angle is the clincher to verify: **Arti** (Rust Tor) is claimed
  to support *hosting* onion services as of early 2026 (Arti 2.x, committed LTS
  branch), which would let the archival pseudonym run a `.onion` responder
  **in-process** without a C dependency — fitting the Rust-canonical posture
  ([`20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc)). The
  older "Arti has no onion-service support" notes are claimed stale (client-only
  1.x line). **Verify at source before relying on it.**
- **I2P — reasonable secondary.** Inward-facing (good for a closed P2P overlay),
  DHT-based with no directory authorities, datagram-capable. But smaller network,
  the mature implementation (i2pd) is C++ with no Arti-equivalent Rust story, and
  Monero's own I2P integration carries known privacy-leak edge cases. Dual-support
  à la Monero is defensible; primary it is not.
- **Lokinet — rejected.** Monero-lineage onion router on LLARP, UDP/layer-3
  (lower latency) — but UDP is wrong for TCP sync, the network is small, and it is
  tied to the Oxen ecosystem, which is exactly the **longevity risk** Tor is chosen
  to avoid. The thing Tor is valued for (it is not going anywhere) is Lokinet's
  weakest axis.
- **Nym — orthogonal, not a competitor.** A mixnet trades latency for
  flow-correlation resistance (which Tor genuinely lacks), at a delay cost that is
  disqualifying for heavy fetch by design. The only conceivable fit is stronger
  traffic-analysis resistance on the light *async* class (claim/broadcast) — V4+
  exotica, not a sync transport.

### Forks to decide at the transport PR (not now)

1. **Embed Arti in-process** (Rust-canonical, viable on the LTS line *if the
   onion-service-hosting claim verifies*) **vs. external Tor daemon over SOCKS**
   (Monero's model, more battle-tested, but an external dependency). Philosophy
   leans embed; conservatism leans external — a deliberate call, not drift.
2. **Whether to keep the I2P secondary-transport door open** architecturally even
   if it is not built at genesis (a reversion-clause-shaped decision per
   [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)).
3. **The integration's privacy edge cases are the real soundness work**, not "does
   Tor exist." Monero still flags its anonymity-network support as experimental with
   cases where source privacy can leak (this doc, §*Privacy Limitations*), and the
   **rendezvous-forced heavy path is a configuration Monero does not lean on** — so
   it needs its **own threat pass**, not inheritance-by-assumption.

### The one question that feeds the sim

When the transport pass runs, the single transport parameter that actually moves
the model is: **does the heavy path stay pure-rendezvous (worst-case L-regime,
maximal firewall), or is there an acceptable relaxation that buys bandwidth without
linking `P`?** That is the lever that moves where Shekyl lands on the `L2–L6`
curve — and therefore the only transport input the staker-archival sim needs
before the rest of the transport design is settled.
