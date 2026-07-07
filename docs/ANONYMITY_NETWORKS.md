# Anonymity Networks with Shekyl

Currently only Tor and I2P have been integrated into Shekyl. The usage of
these networks is still considered experimental - there are a few pessimistic
cases where privacy is leaked. The design is intended to maximize privacy of
the source of a transaction by broadcasting it over an anonymity network, while
relying on IPv4 for the remainder of messages to make surrounding node attacks
(via sybil) more difficult.

PQC note:

- the rebooted chain's hybrid signatures will increase transaction sizes
- larger transactions can change traffic-shape characteristics and may make
  relay events more fingerprintable if not considered in analysis
- the PQC transaction/authentication structure is specified in
  `docs/POST_QUANTUM_CRYPTOGRAPHY.md`

### Measured v3 Impact on Anonymity Networks

`TransactionV3` adds ~5,385 bytes of `pqc_auth` material per user transaction
(see `docs/V3_ROLLOUT.md` for exact component sizes). Practical consequences
for anonymity relay:

- A typical 2-in/2-out FCMP++ transaction grows from ~2–3 KB to ~7–8 KB.
- On Tor, a single cell is 512 bytes; a v3 transaction spans ~14–16 cells
  vs ~4–6 cells pre-PQC. The burst pattern is more distinctive.
- On I2P, tunnel messages are 1 KB; the same transaction requires ~7–8
  fragments vs ~2–3.
- Fragmented Levin messages (white noise feature) help pad smaller payloads
  but cannot conceal large-burst events unless dummy traffic volume is
  proportionally increased.

### Known Leak Vectors vs Mitigations Matrix

| Leak vector | Severity | Current mitigation | Residual risk |
|---|---|---|---|
| Timestamp correlation (timed sync) | Medium | System clock accuracy; future random offset | Fingerprintable if clock is skewed |
| ISP link timing (intermittent sync) | Medium | Keep `shekyld` running continuously | Users who sync-send-quit are linkable |
| Active bandwidth shaping | High | I2P preferred (non-circuit) | Tor circuits remain vulnerable |
| Stream reuse (2+ tx same circuit) | Medium | Outgoing-only selection, 5-min rotation, 20-min change lock time | Small fixed outgoing pool → non-trivial reuse probability |
| v3 tx size burst (new) | Medium | Fragmentation + dummy messages | Burst pattern still larger than pre-PQC; requires tuning dummy volume |
| Levin 8-byte signature (DPI) | Low | SSL/BIP-151/Noise proposals | Not yet implemented; clearnet traffic is identifiable |

### Recommended Pre-Mainnet Testing

1. Replay a representative testnet transaction mix over Tor and I2P, measuring
   circuit-level timing and cell/fragment counts before and after v3.
2. Measure the ratio of real-to-dummy Levin messages required to make v3
   bursts statistically indistinguishable from pre-PQC traffic.
3. Validate that the 5-minute outgoing-connection rotation is sufficient given
   the higher per-tx relay time for v3 payloads.


## Behavior

If _any_ anonymity network is enabled, transactions being broadcast that lack
a valid "context" (i.e. the transaction did not come from a p2p connection),
will only be sent to peers on anonymity networks. If an anonymity network is
enabled but no peers over an anonymity network are available, an error is
logged and the transaction is kept for future broadcasting over an anonymity
network. The transaction will not be broadcast unless an anonymity connection
is made or until `shekyld` is shutdown and restarted with only public
connections enabled.

Anonymity networks can also be used with `shekyl-cli` and
`shekyl-wallet-rpc` - the wallets will connect to a daemon through a proxy. The
daemon must provide a hidden service for the RPC itself, which is separate from
the hidden service for P2P connections.


## P2P Commands

Only handshakes, peer timed syncs and transaction broadcast messages are
supported over anonymity networks. If one `--add-exclusive-node` p2p address
is specified, then no syncing will take place and only transaction broadcasting
can occur. It is therefore recommended that `--add-exclusive-node` be combined
with additional exclusive IPv4 address(es).

For the rebooted chain, the transaction broadcast path should be re-evaluated
with PQ-authenticated transactions because:

- serialized transactions will be materially larger
- fragmentation/delay behavior may become more visible on anonymity networks
- any anti-fingerprinting strategy should be tested against post-PQC payload
  sizes, not legacy assumptions


## Usage

### Outbound Connections

Connecting to an anonymous address requires the command line option
`--tx-proxy` which tells `shekyld` the ip/port of a socks proxy provided by a
separate process. On most systems the configuration will look like:

```
--tx-proxy tor,127.0.0.1:9050,10
--tx-proxy i2p,127.0.0.1:9000
```

which tells `shekyld` that ".onion" p2p addresses can be forwarded to a socks
proxy at IP 127.0.0.1 port 9050 with a max of 10 outgoing connections and
".b32.i2p" p2p addresses can be forwarded to a socks proxy at IP 127.0.0.1 port
9000 with the default max outgoing connections.

If desired, peers can be manually specified:

```
--add-exclusive-node rveahdfho7wo4b2m.onion:28083
--add-peer rveahdfho7wo4b2m.onion:28083
```

Either option can be listed multiple times, and can specify any mix of Tor,
I2P, and IPv4 addresses. Using `--add-exclusive-node` will prevent the usage of
seed nodes on ALL networks, which will typically be undesirable.

### Inbound Connections

Receiving anonymity connections is done through the option
`--anonymous-inbound`. This option tells `shekyld` the inbound address, network
type, and max connections:

```
--anonymous-inbound rveahdfho7wo4b2m.onion:28083,127.0.0.1:28083,25
--anonymous-inbound cmeua5767mz2q5jsaelk2rxhf67agrwuetaso5dzbenyzwlbkg2q.b32.i2p,127.0.0.1:30000
```

which tells `shekyld` that a max of 25 inbound Tor connections are being
received at address "rveahdfho7wo4b2m.onion:28083" and forwarded to `shekyld`
localhost port 28083, and a default max I2P connections are being received at
address "cmeua5767mz2q5jsaelk2rxhf67agrwuetaso5dzbenyzwlbkg2q.b32.i2p" and
forwarded to `shekyld` localhost port 30000.
These addresses will be shared with outgoing peers, over the same network type,
otherwise the peer will not be notified of the peer address by the proxy.

### Wallet RPC

An anonymity network can be configured to forward incoming connections to a
`shekyld` RPC port - which is independent from the configuration for incoming
P2P anonymity connections. The anonymity network (Tor/i2p) is
[configured in the same manner](#configuration), except the localhost port
must be the RPC port (typically 18081 for mainnet) instead of the p2p port:

```
HiddenServiceDir /var/lib/tor/data/shekyl
HiddenServicePort 18081 127.0.0.1:18081
```

Then the wallet will be configured to use a Tor/i2p address:
```
--proxy 127.0.0.1:9050
--daemon-address rveahdfho7wo4b2m.onion
```

The proxy must match the address type - a Tor proxy will not work properly with
i2p addresses, etc.

i2p and onion addresses provide the information necessary to authenticate and
encrypt the connection from end-to-end. If desired, SSL can also be applied to
the connection with `--daemon-address https://rveahdfho7wo4b2m.onion` which
requires a server certificate that is signed by a "root" certificate on the
machine running the wallet. Alternatively, `--daemon-cert-file` can be used to
specify a certificate to authenticate the server.

Proxies can also be used to connect to "clearnet" (ipv4 addresses or ICANN
domains), but `--daemon-cert-file` _must_ be used for authentication and
encryption.

### Network Types

#### Tor & I2P

Options `--add-exclusive-node` and `--add-peer` recognize ".onion" and
".b32.i2p" addresses, and will properly forward those addresses to the proxy
provided with `--tx-proxy tor,...` or `--tx-proxy i2p,...`.

Option `--anonymous-inbound` also recognizes ".onion" and ".b32.i2p" addresses,
and will automatically be sent out to outgoing Tor/I2P connections so the peer
can distribute the address to its other peers.

##### Configuration

Tor must be configured for hidden services. An example configuration ("torrc")
might look like:

```
HiddenServiceDir /var/lib/tor/data/shekyl
HiddenServicePort 28083 127.0.0.1:28083
```

This will store key information in `/var/lib/tor/data/shekyl` and will forward
"Tor port" 28083 to port 28083 of ip 127.0.0.1. The file
`/var/lib/tor/data/shekyl/hostname` will contain the ".onion" address for use
with `--anonymous-inbound`.

I2P must be configured with a standard server tunnel. Configuration differs by
I2P implementation.

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
the source of a Tor/I2P connection. There isn't great mitigation against
this, but I2P should provide better protection against this attack since
the connections are not circuit based.

#### Mitigation

The best mitigation is to use I2P instead of Tor. However, I2P
has a smaller set of users (less cover traffic) and academic reviews, so there
is a trade off in potential issues. Also, anyone attempting this strategy really
wants to uncover a user, it seems unlikely that this would be performed against
every Tor/I2P user.

### I2P/Tor Stream Used Twice

If a single I2P/Tor stream is used 2+ times for transmitting a transaction, the
operator of the hidden service can conclude that both transactions came from the
same source. If the subsequent transactions spend a change output from the
earlier transactions, this will also reveal the "real" spend in the ring
signature. This issue was (primarily) raised by @secparam on Twitter.

#### Mitigation

`shekyld` currently selects two outgoing connections every 5 minutes for
transmitting transactions over I2P/Tor. Using outgoing connections prevents an
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

At the current time, if users need to frequently make transactions, I2P/Tor
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
(see [`design/V3_STAKER_ARCHIVAL.md`](design/V3_STAKER_ARCHIVAL.md) and the sim in
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
