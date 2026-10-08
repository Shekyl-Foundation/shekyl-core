# RPC channel — one authenticated, encrypted channel for every RPC leg

**Status:** R1 — **DRAFT for ratification.** §3's rulings were given by the
decision authority on 2026-10-08 and are recorded as ruled. §4–§8
(mechanism, failure modes, keys, authorization, listeners, tunnel) are
**proposed** and authorize no implementation. §9 registers the probes;
§10 the questions still open. **RT-O9's grant table blocks RT-W10 until confirmed** (§6.1, §10).
**Verified against:** `shekyl-core` @ `fa18edb50` (`dev`). Every
`file:line` below was read at that commit.
**Token family:** continues `RT-` from
[`RPC_TRANSPORT_POSTURE.md`](RPC_TRANSPORT_POSTURE.md) (R0): rulings
`RT-10…RT-16`, open items `RT-O5…RT-O9` (RT-O5 and RT-O5′ ruled into RT-15), probes `RT-P4…RT-P8`, slices
`RT-W8…RT-W14`. No new family (rule 94); the index row for `RT-` is
extended in the commit that lands this round.
**Decision authority:** Rick.
**Relationship to R0:** R0's §1 premise (every RPC leg is
operator-to-operator; the adversary is the path, never the peer) and §3
threat model are unchanged. This round re-rules R0's *mechanism* (RT-4,
pinned mutual TLS) on new ground (RT-11), replaces the restricted-listener
model, and restricts RT-1 to plaintext listeners. §11 lists what is swept
from the live corpus when this round lands.

---

## 1. Why this round exists

The daemon RPC cannot be reached from another machine the operator owns
without routing around the daemon.

- **Every daemon listener refuses every non-loopback address.**
  `bind_listener` → `refuse_non_loopback`
  ([`bind.rs:66-82`](../../rust/shekyl-daemon-rpc/src/bind.rs)); main and
  restricted, IPv4 and IPv6; no override (`--confirm-external-bind` was
  retired in RT-W2).
- **The remedy it names is unbuilt.** The refusal offers "its onion
  service, a reverse proxy, or a forward of this loopback port". No daemon
  RPC onion exists (RT-W6 open, and scoped to the wallet-RPC leg); RT-4
  pinned mutual TLS is unbuilt on every leg (RT-W4 open); the daemon client
  ([`http_client.rs:240-254`](../../rust/shekyl-rpc-transport/src/http_client.rs))
  speaks native-roots HTTPS only, with no pinning.
- **So the working configuration is a forwarder, and a forwarder is worse
  than what the refusal prevents.** The daemon sees every forwarded request
  as loopback, so the per-IP caps in `conn_limit` go blind; the forwarder is
  an unauthenticated hop the daemon cannot see. The refusal did not remove
  the exposure. It moved it out of view.

The incident that surfaced this: an internal node could only serve a
Foundation web host, across a private peer-to-peer VPN between them,
through such a forwarder.

**What the daemon must not do about it.** The daemon does not inspect,
classify, or certify the network it is attached to — no interface-type
probe, no "trusted link" declaration, no verdict on the operator's VPN,
LAN, or tunnel (§12, rejected). Configuring the network is the operator's
job, as configuring Tor is (`TOR_BUNDLE_DISTRIBUTION.md`: Shekyl ships the
Tor Expert Bundle rather than writing a Tor client). The daemon owns one
thing: **its own channel**, authenticated and encrypted end to end, so that
what lies underneath does not matter.

---

## 2. Scope

The three legs of R0 §2 — L1 (CLI/GUI → `shekyl-wallet-rpc`), L2
(`shekyl-wallet-rpc` → `shekyld`), L3 (remote wallet → `shekyld`) — plus
**third-party consumers of the daemon RPC** (a web front end, an explorer,
a pool), which R0 did not name and which are the incident's case, plus
**the local leg** (RT-15), and **how the daemon runs** (RT-16).
Out of scope, unchanged from R0 §2.1: P2P (governed by
`P2P_TRANSPORT_LAYER.md`), and an already-compromised endpoint.

---

## 3. Rulings (decision authority, 2026-10-08)

### RT-10 — One channel: hybrid post-quantum Noise, mutually authenticated

Every RPC leg that leaves the host runs inside one Shekyl-owned channel:
a Noise handshake, mutually authenticated, hybrid X25519 + ML-KEM-768,
then an AEAD record layer carrying the RPC's HTTP. It replaces RT-4 (pinned
mutual TLS). The pieces exist: `shekyl-p2p-transport` implements
`Noise_NNhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s`
([`noise.rs:6`](../../rust/shekyl-p2p-transport/src/noise.rs)), its
symmetric state, AEAD, and record layer.

*Why Noise and not RT-4's pinned mutual TLS — the ground is RT-11, and
only RT-11.* TLS 1.3 authenticates a peer by a certificate signature. A
hybrid identity in TLS needs composite (or paired) certificates and
verifier plumbing on both ends, which the chosen stack does not ship as a
supported path. Noise authenticates by key agreement, so a hybrid identity
is two static keys whose shared secrets both feed one transcript (§4.1).

Two things are deliberately **not** the ground:

- *Not the provider.* RT-4 runs classical ECDHE on the `ring` provider
  (rustls 0.23.45, `rust/Cargo.lock`), but that is a default: rustls
  accepts a caller-supplied key-exchange group, so a hybrid key exchange
  is reachable in TLS. A reader who reopens on that fact is not reopening
  this ruling.
- *Not RT-4's reopen clause.* That clause reads: "a practical PQ or hybrid
  TLS path in the chosen stack (rustls, or whatever RT-W4 lands on)", with
  the re-evaluation shape "a new RT-P probe row in §7.1 demonstrating the
  hybrid handshake under the served stack, then RT-4 re-ruled". It concerns
  the channel's key exchange. RT-11 asks for something the clause did not
  contemplate — hybrid peer authentication — so RT-4 is re-ruled on new
  ground, and the probe it prescribes would not decide this question.

*Rule-21 reopen:* a TLS stack shipping hybrid peer authentication
(composite certificates or equivalent) as a supported path. Interop would
then be the only remaining argument for TLS, and RT-12 already answers it.

### RT-11 — Authentication is hybrid too

Both parties' static identities are hybrid: an X25519 key **and** an
ML-KEM-768 key, each authenticated in the handshake (§4.1). Not
classical-static authentication with hybrid forward secrecy only. Reason:
rule 30 (`30-cryptography.mdc:14-20`: hybrid is non-negotiable on the
wallet path), and enrolment is the expensive step — moving to hybrid
statics later would re-enrol every device.

### RT-12 — Interoperability is a Shekyl-shipped client adapter, not a second protocol

Consumers that cannot speak the channel (a web stack, curl, a script) run
`shekyl-rpc-tunnel` (§8) on their own host: it holds that host's channel
identity, listens on the host's loopback, and carries traffic to the
daemon over RT-10. The consumer speaks plain HTTP to its own loopback and
needs no change. **No TLS listener is offered beside the channel** — two
mechanisms is two provisioning flows, and one of them weaker (R0 RT-8's
warning).

### RT-13 — Authorization is per connection, not per port

An enrolled key carries a **ceiling**; each connection **requests** a
grant within it in the handshake, and the daemon returns what it granted
(§6). An admin-enrolled workstation opens view sessions by default and
asks for more when it needs it. This replaces `--restricted-rpc` and
`--rpc-restricted-bind-port`.

*Drift discharged.* R0 RT-9 is titled "`--public-node` and the
restricted-RPC listener are removed", but only the first half was
executed: the restricted listener is live
([`daemon.cpp:168-206`](../../src/daemon/daemon.cpp),
[`core_rpc_server.cpp:101-102`](../../src/rpc/core_rpc_server.cpp)), and
`DAEMON_RPC_RUST.md` ("Restricted RPC stays") and the
`removed_flags.cpp:189-190` message say it stays. RT-13 settles the
contradiction: the listener goes, and its job (the operator's own
view-only access) becomes a grant.

### RT-14 — Wildcard binds: refused on plaintext listeners, permitted on the channel listener

R0 RT-1 continues to bind every **plaintext** listener — the tunnel's
loopback side (§8) and anything else that carries the RPC unencrypted.
There the refusal is the daemon declining to offer an unauthenticated
service beyond the host: a property of the daemon, not a judgment of the
operator's network.

The **channel listener** may bind a wildcard. Its security does not depend
on which interface it is reached through, so refusing the wildcard there
would be the daemon judging the operator's diligence — the stance §1
forbids. The refusal would also cost real deployments: a container does not
know its address before start; a tunnel interface that is not yet up when
the daemon starts fails a specific-address bind; and the P2P listener
already binds the wildcard by default
([`net_node.cpp:93-94`](../../src/p2p/net_node.cpp)).

*Residual, named and accepted:* §4.3's pre-authentication surface is
reachable on every interface the wildcard covers — the same exposure class
as the P2P listener.

### RT-15 — The local leg splits by caller identity; every client has one target

**Ruled 2026-10-08.** Who the caller is, relative to the daemon, decides the
leg:

- **The same OS user as the daemon:** an owner-only socket on Unix, an
  owner-only named pipe on Windows — authenticated by OS identity, carrying
  the owner's full grant, with no keys to provision. This is R0 §1.1's
  ratified end-state transport for the daemon, and it covers the default
  install: the GUI running `shekyld` as its child, same user, same session.
- **Anyone else** — a service-mode daemon's callers (RT-16), another user,
  another machine: the channel, on loopback or across hosts.

**One target per client, never a ladder** (the requirement: an operator
must not meet errors merely from connecting). A client is configured with
exactly one target — **"this computer"** (the default) or an explicit node
address — and connects to that target or reports why it cannot. It never
falls back from one leg or node to another. "This computer" resolves to the
single local daemon — the **default instance**, which RT-16 guarantees is
unique (a deliberately named second instance is reached only by naming it,
§7.1) — through that
daemon's **rendezvous** (§7.1): a per-user rendezvous for a run-as-me
daemon (the socket or pipe), a machine-wide one for a service (its loopback
channel address and public bundle). There is never a choice between two
live nodes, and never a silent switch to a different one.

**"Nothing there" and "the wrong thing there" are different failures.** A
missing rendezvous, or one naming a listener that no longer exists, means
the daemon is not running — a plain message (§4.5). A listener that answers
and **fails the peer check** is a hard stop: reported as a security
failure, never retried, never routed around (R0 RT-6: a fallback after a
failed check is a downgrade oracle).

*Plaintext loopback TCP stays as an operator option, at view* (RT-O5,
ruled 2026-10-08, kept for UX). **Off by default** (RT-O5′, ruled
2026-10-08): a fresh install has no unauthenticated listener, and the
operator running a status reader beside the node enables it. Today
it is the admin surface, reachable by every local user of the host; under
RT-15 it carries **only the `view` preset** (§6.1) — a fixed row of the same grant
table the channel uses (§6.1), not a revived `restricted` flag. Reason: a
co-located website or monitoring tool reads network status with no
enrolment and no real exposure in a breach. It stays loopback-only (R0
RT-1/RT-2, RT-14) and keeps R0's `browser_boundary` — JSON-only, and a
`Host` restricted to an IP literal or `localhost` — because it is the
listener a page in a local browser can reach. Anything beyond the least
grant goes over the channel.

### RT-16 — Two supported run modes; never SYSTEM, never root

1. **As the logged-in user** — the default. No elevation; stops at logout.
2. **As a service under a dedicated low-privilege account** — opt-in;
   survives logout. On Windows a per-service virtual account; on Unix a
   dedicated unprivileged user, the posture of the Linux packaging.
   **Never SYSTEM, never root**, written as firmly as the wallet's WP-D7.

*Why the daemon may be a service when the wallet may not.* WP-D7
([`WINDOWS_WALLET_SUPPORT.md:414-419`](WINDOWS_WALLET_SUPPORT.md)) forbids
a service for `shekyl-wallet-rpc` because its pipe derives authority from a
per-user identity that a service account does not have. The daemon holds
no wallet secrets, and in service mode it serves no OS-identity leg at all —
its callers are a different user and reach it over the channel (RT-15) — so
the reasoning does not transfer. A daemon that stops at logout stops
serving the operator's other devices and stops relaying — a poor default
for a node that should be one.

*Why never SYSTEM.* The P2P listener parses hostile network input, much of
it still in inherited C++. Under SYSTEM or root, any parser defect is a
whole-machine compromise; under a virtual account it is a compromise of
that account. On Windows the service also takes the restricted service-SID
type and the minimal required-privilege list (RT-P8 confirms both).

*Consequences.*

- **The mode is declared, never inferred** (proposed). On Unix a unit
  running the daemon under its dedicated user and that same user starting
  it by hand are indistinguishable from inside the process, so the daemon
  cannot work out which leg to serve. Service mode is selected by an
  explicit switch that the installed unit or service registration passes;
  without it the daemon is run-as-me. A daemon never guesses its mode from
  its account, its data directory, or its parent.
- **Service mode is new Rust work, not a revival.** The inherited daemonizer
  was deleted in V3.1 and its five flags retired
  ([`removed_flags.cpp:74-78`](../../src/common/removed_flags.cpp)); none of
  it is restored (rule 15).
- **Installation needs elevation once**, so the service is an opt-in step;
  run-as-me keeps working with none.
- **The data directory moves** for the service: a machine-wide home
  (`%ProgramData%` on Windows) with an ACL admitting the service account
  and Administrators, holding chain data, the daemon's channel bundle, the
  console key (§5), the machine-wide rendezvous (§7.1), and the bundled
  Tor's data and key directories — Tor
  runs as the service's child under the same account, with the
  `TOR_BUNDLE_DISTRIBUTION.md` launch rules unchanged.
- **The Windows installer's order is fixed by measurement** (§9.1, item 6):
  register the service first, because its account name does not resolve
  until it exists; then create the data home **fresh** — never adopt a
  path the installer did not create in this run, since any unelevated user
  can pre-create it and keep the right to rewrite its ACL; then break
  inheritance and assert the ACL, because a new `%ProgramData%`
  subdirectory inherits write access for every user.
- **Switching modes** moves or re-syncs the chain data; the uniform pruning
  posture keeps a re-sync bounded.
- **The two modes do not run side by side** on one installation (proposed):
  two daemons would be two nodes with two bundles, and a client enrolled
  with one meets silence from the other, which reads as a wrong key
  (§4.5). The service installer refuses while a run-as-me daemon is
  running, and the run-as-me daemon refuses to start while the service is
  installed and running — the daemon knowing its own installation, not
  judging the operator's network. The refusal covers the **default
  instance** only: a named instance (§7.1) is a deliberate second node
  with its own rendezvous, and it starts beside either mode.

---

## 4. Mechanism — the handshake (proposed)

### 4.1 Pattern: classical XK ∪ pqXK, with hybrid forward secrecy

The client pins the daemon's static bundle in advance; the daemon learns
the client's identity in the handshake and checks it against its enrolled
set. That is the **XK** shape. Its post-quantum counterpart is PQNoise's
**pqXK** (Angel et al., *Post-Quantum Noise*, ePrint 2022/539, Fig. 2),
where `skem` replaces the static DH tokens and `ekem` replaces `ee`. The
proposal runs both, mixing every shared secret into one chaining key:

```
<- s, s1                      pre-message: daemon's X25519 static, ML-KEM static ek
-> e, e1, es, skem            client eph X25519, eph ML-KEM ek; DH(e, rs); encaps to rs1
<- e, ee, ekem1               daemon eph X25519; DH(e, re); encaps to client e1
-> s, s1, se                  client statics (encrypted); DH(s, re)   payload: grant request
<- skem                       encaps to client s1                     payload: grant
-> (first transport record)   proves the client decapsulated the last skem
```

- **Daemon authentication** is complete when message 2 decrypts: its key
  depends on `es` (classical) and the message-1 `skem` (post-quantum).
- **Client authentication** is classical at message 3 (`se`) and hybrid
  when the client's first transport record decrypts. The daemon acts on
  nothing before then — that record *is* the first request (§6.2).
- **Cost:** two round trips before the first request; three
  encapsulate/decapsulate pairs plus one ephemeral ML-KEM keygen; ~5.8 KB
  of handshake (ML-KEM-768: 1,184 B ek, 1,088 B ct). Paid once per channel
  session; §8 keeps sessions alive.

**This composition is ours.** Its components are analyzed — classical XK
in the fACCE model (Dowling–Rösler–Schwenk), pqXK in PQNoise — and the
combiner is the usual one (each secret mixed into `ck` through HKDF, so
the keys hold if either input holds; impersonation needs both X25519 and
ML-KEM broken). XK ∪ pqXK in this token order is not analyzed anywhere we
know of, and may have no external vectors: the register's PW-2 row
([`P2P_2_REQUIREMENTS_REGISTER.md:170`](P2P_2_REQUIREMENTS_REGISTER.md))
grounds the reference implementation (NoisePQC++) as covering NN, XX, IK
and KK — not XK. Hence RT-P7 is a stated gate (§9).

### 4.2 Why XK, and not KN, KK, or IK

- **KN** — the responder has no static; the client cannot authenticate the
  daemon, so a wallet's queries and submissions go to any impostor.
- **KK** — the responder must know *which* initiator before message 1.
  With several enrolled devices that is either a cleartext client
  selector (the linkability R0 rejected PSK identities for, RFC 9257 §7)
  or trial decryption across the enrolled set.
- **IK** (WireGuard's) saves half a round trip, but the client's identity
  rides message 1 encrypted only to the daemon's static key — not forward
  secret, so a later compromise of that key de-anonymizes every recorded
  handshake — and message 1 is replayable without an added timestamp.
- **XK** sends the client identity in message 3 under ephemeral keys:
  hidden from the path, and forward-secret against a later daemon-key
  compromise. The daemon authenticates before the client reveals anything.

### 4.3 What a stranger can reach

**The daemon's public bundle is not a secret** — every enrolled client
holds it, and enrolment moves it in the clear (§5). So there are two kinds
of stranger:

- **Without the bundle.** Message 1's empty payload carries an AEAD tag
  under a key mixed from `es` and `skem`; a sender who lacks the bundle
  cannot produce a valid one. The daemon sends no byte before message 1
  authenticates, and any failure closes the connection without reply. A
  scanner sees a port that accepts TCP and says nothing.
- **With the bundle, not enrolled.** Message 1 authenticates, so the daemon
  answers with message 2 — confirming that this daemon, with this key, is
  at this address. The connection closes after message 3 when the
  fingerprint is not enrolled. **The bundle is therefore a probing
  capability**: whoever holds it can test addresses for the daemon. §5
  treats it accordingly.

**The pre-authentication surface.** Before anything authenticates, any
sender — bundle or not — makes the daemon do two operations with its
**long-term** keys on attacker-chosen input:

1. X25519 with the static key against an attacker-chosen `e`
   (`x25519-dalek`, constant-time by construction). A low-order `e` gives
   an all-zero result; it is refused and never mixed, as the P2P handshake
   already does (`noise.rs:504`, `low_order_x25519_does_not_mix`). The same
   refusal applies to `se` in message 3, where the key is also long-term.
2. **ML-KEM-768 decapsulation with the static decapsulation key against an
   attacker-chosen ciphertext.** A timing difference here is a remote
   oracle on the long-term key (KyberSlash was exactly this class, in
   implementations). Requirements: decapsulation is constant-time in the
   pinned crate, **demonstrated** by RT-P4, not assumed; ML-KEM's implicit
   rejection returns a pseudorandom key for an invalid ciphertext, and that
   must remain the only behaviour — the failure surfaces solely as message
   1's tag mismatch, with no branch, error variant, timing, or log line that
   distinguishes rejection from a bad tag.

A bundle holder additionally reaches message-2 encapsulation against a
client-supplied ephemeral encapsulation key (input-checked per FIPS 203
before use, as `noise.rs` already does) and message-3 decryption.

Each unauthenticated message costs the daemon one DH and one
decapsulation: a stranger-driven work amplifier, bounded by `conn_limit`
admission before the handshake and by the handshake deadline. Whether more
is needed is decided from RT-P6's measurement, not before it.

### 4.4 Binding and record layer

- **Prologue:** a registered customization (`shekyl/rpc-channel-v1`,
  proposed, `CRYPTO_DOMAIN_REGISTRY.tsv`) followed by the network id
  (`shekyl/p2p-network-id-v1`, already derived from genesis). A testnet
  client cannot complete a handshake with a mainnet daemon. Nettype selects
  data only (rule 71).
- **Record layer:** `shekyl-p2p-transport`'s `aead.rs` and `channel.rs`
  (64 KiB maximum record body, `MAX_BODY = u16::MAX`; rekey every 1,000
  nonces, `channel.rs:18-19`), **extracted into a crate both transports
  depend on**, not copied. The extraction must not move or regenerate the
  pinned handshake vectors (`kat_m1.hex`, `kat_m2.hex`, asserted at
  `noise.rs:549-554`): they stay byte-identical and keep passing in place.
- **HTTP over records.** hyper and axum expect a byte stream; the channel
  delivers records of at most 64 KiB. A stream adapter — `AsyncRead` /
  `AsyncWrite` over seal/open, with backpressure, record splitting for
  large bodies (block batches), and orderly half-close — is the core
  engineering of RT-W9, and RT-P5 proves it first.
- **Length concealment:** RT-O6.

### 4.5 Failure modes (rule 82)

Silence protects the daemon from strangers and leaves the legitimate
operator with a closed connection. **The diagnosis lives in the daemon's
log**; the client's message names the possible causes it cannot tell
apart and points there. End-user wording follows rule 81 (no protocol
internals); the log may be specific.

| Failure | Client can distinguish? | Client says | Daemon log says |
|---|---|---|---|
| Client holds a stale or wrong daemon bundle; client is on another network; version mismatch | No — all close after message 1, no reply | "The node at ADDRESS closed the connection without answering. It does not recognise this client's copy of its key, is on a different network, or runs a different version. The node's log records which." | Rate-limited, aggregated per source: "unauthenticated channel handshake from IP: the sender does not hold this node's current key, is on another network, or speaks another channel version" |
| Client fingerprint not enrolled | Yes — daemon answered, then closed after message 3 | "The node answered but has not enrolled this client. Enrol it on the node with: `shekyld rpc-enrol FINGERPRINT`." | "refused unenrolled client FINGERPRINT from IP" — the fingerprint is printed so the operator can enrol it |
| Client fails the post-quantum confirmation (first record does not decrypt) | Yes — closed after message 4 | "The node rejected this client's identity. Its key files may be damaged; regenerate and re-enrol." | **Warning:** "client FINGERPRINT from IP passed classical authentication and failed post-quantum confirmation" — security-significant |
| Message 2 does not decrypt at the client | Yes | "Something answered at ADDRESS that is not the node you enrolled with. Do not connect; check the address." No retry | Nothing — a daemon with a different key never sends message 2 |
| Requested grant exceeds the ceiling | Yes — message 4 carries the grant | "Connected with GRANT; this client is enrolled for at most CEILING." | "client FINGERPRINT requested REQUEST, granted GRANT" |
| A call outside the connection's grant | Yes | "This connection is not granted METHOD (granted: GRANT)." — never "method not found" | — |
| Handshake deadline expired | Yes | "The node did not complete the handshake in time." | Timeout, with the stage reached |
| The other run mode's daemon is answering at the address (two daemons, two bundles) | No — reads as the first row | As the first row | Prevented, not diagnosed: the two modes refuse to run side by side (RT-16) |
| Session closed by revocation (§5) | Yes | "The node revoked this client's enrolment." | "revoked FINGERPRINT; closed N open sessions" |

**The local leg and target resolution (RT-15).**

| Failure | Client says | Daemon log says |
|---|---|---|
| Target "this computer", no rendezvous for this user or the machine on this network | "No Shekyl node is running on this computer for NETWORK." If a rendezvous exists for another network: "A node is running for OTHER_NETWORK." | — |
| Rendezvous present, nothing listening (the daemon stopped without cleaning up) | "The Shekyl node on this computer is not running (it stopped unexpectedly). Start it again." The stale rendezvous is reported, not treated as a fault | The next start replaces it |
| A daemon was just started and has not published its rendezvous yet | Nothing — the client waits for the publication (an event, not a poll that fails), bounded by the daemon's startup; on expiry: "The node did not finish starting. Its log records why." | Startup progress |
| Unix: no session runtime directory (started under `sudo -u`, cron, or a container) | (Daemon, at start) "This node has no place for its local socket: there is no login session. Install it as a service, keep your session alive after logout (`loginctl enable-linger`), or name a socket directory." Refuses to start | Same line |
| An explicit socket directory is not owned by this user, is not private to it, or cannot hold a socket | (Daemon, at start) "The socket directory PATH cannot be used: REASON." Refuses to start; never adopts or repairs it | Same line |
| An instance name that breaks the naming rule (§7.1) | (Daemon, at start) "An instance name may contain only lower-case letters, digits and hyphens, at most 32 characters." Refuses to start | Same line |
| Starting a daemon while one is already running for this user and network | (Daemon, at start) "A Shekyl node is already running for you on NETWORK. To run a second one beside it, give it a name." Refuses to start | Same line, with the existing node's start time |
| Service mode: the console key file is missing, unreadable by this user, or damaged | "This command needs the node's console key, which is missing or cannot be read. Run it as an administrator; if the key is lost, stop the node and reset it (§5)." Never falls back to another leg | — (the daemon is not contacted) |
| A listener answers at the rendezvous and **fails the peer check** (wrong owner, wrong integrity level) | "Something other than your Shekyl node is answering at its local address. Not connecting." Hard stop; no retry, no other leg | — (the daemon is not the party answering) |
| Windows: the daemon runs for this user in **another logon session** (the pipe admits its own session only) | "Your Shekyl node is running in another sign-in session and can only be reached from there." Known from the rendezvous before dialling | — |
| Target "this computer" is a service, and this client is not enrolled | As the channel's not-enrolled row: "The node answered but has not enrolled this client. Enrol it with: `shekyld rpc-enrol FINGERPRINT`." | "refused unenrolled client FINGERPRINT from IP" |

---

## 5. Keys and enrolment (proposed)

R0 RT-7 stands: generated material only, never typed from memory.

- **Each endpoint generates its own static bundle** (X25519 + ML-KEM-768)
  locally. Private halves never leave the host; storage follows rules 35/36.
- **Daemon → client: the full public bundle**, not a fingerprint — XK
  requires the client to *know* the daemon's static keys (≈1.2 KB; one
  file, or one QR code). **No private material moves, but the bundle is not
  harmless:** it is a probing capability (§4.3). Give it only to devices
  that will be enrolled; do not publish it.
- **Client → daemon: a fingerprint** — cSHAKE256 under a registered
  customization (`shekyl/rpc-static-fingerprint-v1`, proposed) over the
  client's bundle — plus a **ceiling**. The daemon needs only the
  fingerprint, because the client's statics arrive in message 3.
- **Enrolment and revocation are operator actions over the channel**:
  proposed `shekyld rpc-enrol FINGERPRINT --ceiling GRANTS` and
  `shekyld rpc-revoke FINGERPRINT`. No CA, no issuance key (R0 RT-4's
  argument carries over).
- **Who needs a key.** Same-user callers need none (RT-15). Keys exist for
  callers of a service-mode daemon, other users, other machines, and the
  tunnel.
- **Bootstrap — the console key** (proposed; service mode). Enrolment runs
  over the channel, so for a service-mode daemon something must be enrolled
  before anything can enrol. On first start the service generates its own
  bundle and a **console key**, enrols the console key with an admin
  ceiling, and writes the console key's private half to a file readable only
  by the service account and administrators. `shekyld <command>` run by an
  administrator uses it. Placing that file uses an OS ACL once, at creation;
  it is not a per-call authentication path. A run-as-me daemon needs no
  console key: its owner reaches it over the socket or pipe.
- **Enrol at install** (proposed). The step that installs the service
  enrols the installing user's client identity, so the person who opted into
  service mode is not left with a GUI that cannot reach the node it just
  installed. Further users and devices are enrolled with `rpc-enrol`.
- **Revocation takes effect immediately on live sessions.** The daemon
  indexes open channel sessions by client fingerprint; `rpc-revoke` removes
  the enrolment and closes every session that fingerprint holds, and so
  does lowering a ceiling (re-connect to receive the new grant; no
  mid-session downgrade). The enrolled set is daemon state changed only
  through these commands — there is no file to edit behind the daemon's
  back and no reload signal to forget.
- **Recovering a lost console key** (proposed; service mode). Enrolment
  runs only over the channel, so an operator who loses the console key and
  holds no other admin-ceiling key has no way back in through it. The way
  back is offline and local: with the service **stopped**, an administrator
  runs a reset command that generates a new console key, replaces the old
  console enrolment with it, and writes the new private half under the same
  ACL. It refuses while the daemon is running, touches no other enrolment,
  and is logged at the next start. This is a command that changes daemon
  state, not a file edited by hand, so the rule above stands. Who may run
  it is who may write the service's data home — an OS permission the
  operator already manages.
- **Daemon key rotation** re-enrols every client, by construction.

---

## 6. Authorization (proposed)

### 6.1 Grants

**Direction (decision authority, 2026-10-08): named grants, with node
status split out of every view.** The assignment below is proposed
(RT-O9).

A grant is a **set of facts or actions**, not a list of methods. Most
methods fall whole into one grant. `get_info` does not: it mixes facts
about the network with facts about this node, so it is served to any
connection holding `health` and each field is present only when the
connection holds that field's grant. **A field outside the grant is
absent, never zero.** Today's restricted reply writes `0` for a hidden peer
count (`core_rpc_server.cpp:213-232`), which a reader cannot tell from a
node with no peers.

One question draws the line between `health` and `status`: *does a client
need this fact to decide whether it can use this node right now, and is it
the same on every honest node of this build?* Everything `get_version`
returns passes ([`methods.rs:112-145`](../../rust/shekyl-daemon-rpc/src/methods.rs):
RPC contract version, release flag, heights, fork schedule,
consensus-constants digest, nettype, genesis) — it identifies a build and a
network, never a node.

| Grant | Carries |
|---|---|
| `chain` | Chain reads: `/get_height`, `get_block_count`, `on_get_block_hash`, the four block-header methods, `get_block`, `/get_transactions`, `/is_key_image_spent`, `/get_blocks_by_height.bin`, `/get_o_indexes.bin`, `hard_fork_info`, `get_fee_estimate`, `get_curve_tree_info`, `get_curve_tree_checkpoint`, `get_archival_emission_claim_source`, `get_archival_shard_coverage`; and `get_info`'s chain fields (difficulty, cumulative difficulty, block-weight limit and median, transaction count, emission and economics fields) |
| `pool` | The relayed pool: `/get_transaction_pool`, `/get_transaction_pool_hashes`, `/get_transaction_pool_stats`, `get_txpool_backlog`; `get_info`'s pool size. Entries not yet relayed are **not** in this grant (`node`) |
| `health` | Whether this node is usable now: `get_version` whole; from `get_info`, the chain tip (height, top hash), `target_height`, `synchronized`, `busy_syncing`, `offline`, `following_degraded`, the RPC and protocol contract versions, nettype |
| `status` | Facts about **this node**, each a fingerprint: build version string; start time; free space and database size; aggregate inbound and outbound peer counts; RPC connection count; alt-blocks count, `/get_alt_blocks_hashes`, `get_alternate_chains`; `/get_limit`; `/get_net_stats` |
| `peers` | The graph: `get_connections`, `sync_info`, `/get_peer_list`; `get_info`'s per-connector socket counts and peerlist sizes |
| `submit` | `/submit_transaction` |
| `mining-work` | An external miner's loop: `get_block_template`, `get_miner_data`, `submit_block` |
| `mining-control` | This node's own miner: `/start_mining`, `/stop_mining`, `/mining_status`, `/set_log_hash_rate` |
| `bans` | `set_bans`, `get_bans`, `banned` |
| `node` | Everything that controls or exposes the node itself: `/stop_daemon`, `/save_bc`, `/pop_blocks`, `/set_log_level`, `/set_log_categories`, `/set_limit`, `/out_peers`, `/in_peers`, `flush_txpool`, `flush_cache`, `relay_tx`, pool entries not yet relayed, `/get_stem_tallies`, `calc_pow`, `get_coinbase_tx_sum`, `request_archival_shard`, `generateblocks`, `inject_archival_serve_credit`, and enrolment (`rpc-enrol`, `rpc-revoke`) |

*Why each `status` field is out of view.*

| Field | What it gives away |
|---|---|
| Build version string | The patch level, which tells an attacker which defects apply. The RPC contract version stays in `health` |
| Start time | Uptime and restart times correlate this node's onion address with its clearnet address |
| Free space, database size | A host fingerprint. Today's restricted reply rounds the size up to 5 GiB (`core_rpc_server.cpp:248-250`); under the split the field is absent |
| Aggregate peer counts, RPC connection count | Connectivity posture over time |
| Alt-blocks count and hashes | Which forks this node saw |

**Presets** (what an operator names at enrolment; a ceiling is a preset or
an explicit list of grants):

| Preset | Grants |
|---|---|
| `view` | `chain` + `pool` + `health` |
| `wallet` | `view` + `submit` |
| `miner` | `view` + `mining-work` |
| `admin` | every grant |

**`status` and `peers` are in no preset but `admin`.** They are granted
only when the operator names them, so publishing a node's uptime or its
peers is a deliberate act, not something a consumer inherits from the
preset it landed in. The plaintext loopback listener is fixed at `view`
(RT-15); the default request on the channel is `view` (§6.2).

*Changes from today's two-level gate, each to be confirmed* (RT-O9):

- **`/get_alt_blocks_hashes` moves out of the unrestricted-to-everyone
  set** into `status`. It is served on both listeners today
  (`server.rs` route table), and it is the per-hash form of the
  alt-blocks count this split hides. No in-tree client calls it.
- **`/get_limit` and `/get_net_stats`** are placed in `status`: this
  node's rate limits and traffic totals. `/get_limit` is on both
  listeners today.
- **`/get_stem_tallies` stays in `node`, not `peers`.** It is the
  anonymity graph (today admin-only for that reason); a consumer granted
  `peers` to count connections must not receive it.
- **`get_info.restricted` is retired.** The connection's grant is returned
  in the handshake (§6.2); a boolean cannot describe it.

*What the incident's consumer gets.* The web host at `view` reads height,
difficulty and hash rate from `chain`, sync state from `health`, and pool
size from `pool`. Two things it does today need more. Its **seed-node
count** and its **peer-reported network height** both come from
`get_connections`, which is `peers` — peer addresses — and would be an
explicit enrolment; sync state from `health` replaces the second. The
**build version** and **database size** it displays are `status`. Uptime is
`status` too and should stay off a public page for the correlation reason
above.

### 6.2 Per-connection request and visible grant

The client's message-3 payload names the grant it requests; the effective
grant is the request clamped to the ceiling, fixed for the connection's
life. **The daemon returns the effective grant in the message-4 payload**,
so a clamped client knows at connect time, not when a call fails. A call
outside the grant is refused with its own error — a dedicated JSON-RPC
code and HTTP 403 on REST — never "method not found" or a 404. The default
request is the `view` preset (§6.1). Nothing is served until the client's first
transport record decrypts (§4.1).

The `restricted: bool` that today threads through `AppState`, the router,
and the method handlers becomes the connection's grant; the two gate tests
(`server.rs:787`, `json_rpc.rs`
`admin_methods_are_refused_only_on_the_restricted_listener`) re-key to it.

---

## 7. Listeners and ownership (proposed)

- **The channel listener** binds any address, wildcard included (RT-14).
  `refuse_non_loopback` is replaced at the seam for this listener;
  `BoundListener` stays the only thing served.
- **The local leg** is the owner-only socket or pipe for same-user callers
  and the channel for everyone else (RT-15). The plaintext loopback TCP
  listener is an operator option fixed at `view`, loopback-only, with
  `browser_boundary`, off by default (RT-15).
- **The onion** (R0 RT-8) is unchanged in spirit: reachability, not a
  security model; the channel runs inside it.
- **Every new surface is Rust-owned** (rule 20). The channel listener's
  flags, the key paths, the enrolled set, and `rpc-enrol` / `rpc-revoke`
  are parsed, stored and served in `shekyl-daemon-rpc`. Nothing is added
  to C++ `rpc_args` or `core_rpc_server`; the C++ RPC bind and restricted
  flags are deleted, not extended.

### 7.1 Rendezvous (proposed)

A rendezvous is how a client finds "this computer"'s daemon without
guessing. It is published **after** the listener is bound, **atomically**
(write and rename), removed on clean exit, and replaced on the next start.
Every rendezvous path is keyed by the genesis-derived network id, not a
nettype name (rule 71), so daemons of different networks coexist and a
client never reaches the wrong network's node.

- **Unix, run-as-me:** the socket itself, at a fixed name inside a `0700`
  per-user, per-network directory. The directory is the containment (R0
  §1.1 item 1); nobody else can place an object at that name, so no random
  component is needed. **The directory lives under the session runtime
  directory** (`XDG_RUNTIME_DIR`): its lifetime is the login session's,
  which is run-as-me's own lifetime (RT-16), it is local to the machine,
  and a reboot clears it. Three cases follow (proposed):
  - **No runtime directory** — under `sudo -u`, cron, and most containers.
    The daemon refuses to start and names the three ways forward: service
    mode, for a daemon meant to run unattended; `loginctl enable-linger`,
    for an operator deliberately keeping a run-as-me daemon past logout; or
    an explicit socket directory.
  - **An explicit socket directory**, named by the operator, for test and
    container runs that have no session. The daemon asserts it rather than
    adopting it: owned by the daemon's user, mode `0700`, on a local
    filesystem that accepts sockets — or it refuses to start and says
    which condition failed. A client reaches such a daemon only when told
    the same directory; it is never what "this computer" resolves to.
  - **The runtime directory removed under a running daemon** — a daemon
    left in a terminal multiplexer, without lingering, when its user's last
    session ends. The daemon keeps running and loses its local leg; a
    client then reports that no node is running (§4.5), which is wrong.
    Named, not prevented: the daemon cannot stop the session manager from
    removing the directory. It notices the loss and logs it, and the
    refusal above is why a fresh start in that state says so.

  A Unix socket path has a short fixed limit (about 100 bytes), so a path
  that would exceed it is refused at start with the path and the limit
  named, never truncated.
- **Windows, run-as-me:** a named pipe whose name the daemon **draws at
  random on each start** and records — with the logon-session id — in a
  rendezvous file in a per-user, per-network directory under
  `%LOCALAPPDATA%` that only the user can read. A pipe has no containing
  directory, so containment is rebuilt here: with no predictable name there
  is nothing for another user to squat, and the name does not exist until
  the daemon creates it with `first_pipe_instance`. The client's
  owner-SID and integrity-level check (`shekyl-win-sec`,
  [`pipe.rs:12-23`](../../rust/shekyl-win-sec/src/pipe.rs)) runs before
  the client holds a handle, as it does for the wallet. The recorded session
  id lets the client report the other-session case without dialling (§4.5).
  Three refinements from the Windows lane's measurements (RT-P8):
  - **The rendezvous file carries a no-read-up mandatory label, set at
    creation.** Windows' default integrity policy forbids writing up, not
    reading up, so without it a same-user low-integrity process can read
    the current name and, after the daemon exits, claim it. The client's
    integrity floor still refuses that squatter (measured), but the label
    removes the path rather than relying on the refusal. **The label must be
    in the `SECURITY_ATTRIBUTES` passed to `CreateFileW`** —
    `S:(ML;;NR;;;ME)`; `NR` alone suffices (measured: a low-integrity read is
    refused). The two obvious alternatives **silently fail**: a file that
    inherits from a directory labelled `(OI)(CI)` Medium `NR` carries only
    `(I)(NW)`, and `icacls /setintegritylevel Medium:NR` exits 0 while
    applying only `NW` — in both cases a low-integrity read succeeds while
    the file visibly carries a Medium label (measured). So the check that
    guards this reads back the label's **policy bits** and asserts `NR`;
    "a mandatory label is present" passes on the broken file and cannot
    fail. The home is `shekyl-win-sec`'s `create_owner_only_file`
    ([`file.rs:86`](../../rust/shekyl-win-sec/src/file.rs)), which WP-D8
    left unlabelled because the read-up question for files was not that
    slice's (`file.rs:20-21`); it is answered now.
  - **The directory carries its own no-read-up label** as well: a
    low-integrity process cannot open it, so it cannot enumerate the
    rendezvous (measured). The directory's label is not relied on to
    protect the file.
  - **Clean exit deletes the rendezvous before closing the pipe**, so the
    name is never free while a rendezvous still points at it.
  - **Start-up dials an existing rendezvous through the peer check** before
    publishing its own: it answers → another daemon of this user and network
    is running, refuse to start and say so; nothing listening → stale,
    replace it; it fails the check → report the impostor. A bind failure
    alone cannot tell "already running" from "squatted" — both are "Access
    is denied" (measured) — and this dial can.

  Authorization rides the pipe's DACL at open: Windows refuses a
  low-integrity caller before the server sees it (measured), and the DACL
  admits only the owner's logon session. The server can read its caller's
  user, integrity level and logon session, but **only after consuming the
  first byte** (measured), so no part of the design may depend on knowing
  the caller before a read. *Implementer's trap:* `whoami /groups` and .NET
  both hide the logon-session SID the DACL relies on; only a raw token read
  (`GetTokenInformation`, `TokenGroups`, `SE_GROUP_LOGON_ID`) shows it. A
  check written against either tool will report the design unworkable.
- **Service mode, both platforms:** a machine-wide rendezvous in the
  service's data home, readable by users, naming the loopback channel
  address and the daemon's public bundle. A same-user socket or pipe is
  never served by a service.
- **Named instances** (proposed). The rendezvous above is the **default
  instance**: one per user and network, or one per machine and network for
  a service, and the only thing "this computer" resolves to. A daemon
  started with an explicit instance name publishes its rendezvous under
  that name instead and is reached only by a client told the same name. It
  never answers for "this computer" and is never chosen by a client that
  did not ask for it, so RT-15's single target holds. Reason: test and
  measurement runs start a second daemon of the same network beside an
  installed one, as one user, and without a named form the start-up
  refusal (§4.5) would stop them. The name is the operator's label, not a
  nettype; the network id still keys the path (rule 71). **The name is
  operator input that becomes part of a filesystem path**, and on Unix it
  spends the socket-path budget, so it is restricted: lower-case letters,
  digits and hyphens only, at most 32 characters, starting with a letter
  or digit. Anything else is refused at start with the rule stated — never
  sanitised or truncated — so a separator, a `..`, or a reserved Windows
  device name cannot reach the rendezvous path.
- **Start-up dial on Unix.** The Windows start-up rule above applies here
  unchanged: before publishing, dial an existing socket — it answers, so
  another daemon is running, refuse and say so; nothing listens, so it is
  stale, replace it; it fails the owner check, report it. A bare
  "address in use" cannot tell a live daemon from a leftover file.

---

## 8. `shekyl-rpc-tunnel` (proposed)

A small Shekyl binary on the consumer's host:

- generates and holds that host's static bundle; prints its fingerprint
  for enrolment;
- is configured with the daemon's address and public bundle, and the grant
  it requests; reports the grant it received (§6.2);
- listens on the host's **loopback only** — it is plaintext on that side,
  so RT-14 applies: specific address, never a wildcard — through the same
  listen classifier
  ([`listen.rs`](../../rust/shekyl-rpc-transport/src/listen.rs));
- **pools channel sessions.** A consumer that does not keep HTTP
  connections alive would otherwise pay §4.1's two round trips and three
  KEM pairs per request. The tunnel keeps a bounded pool of live sessions
  to the daemon (one grant per pool) and carries local connections over
  them, replacing a session only when it closes. Pool size is measured
  (RT-P6), not guessed.

Any local user on the consumer's host can use its loopback port. Where the
consumer can speak to a socket, the tunnel offers one (R0 §1.1's
construction) instead of loopback TCP.

---

## 9. Probes (pre-registered)

| # | Question | How | Revisits on failure |
|---|---|---|---|
| RT-P4 | Is ML-KEM-768 decapsulation in the pinned crate constant-time with respect to the ciphertext, including the implicit-rejection path? | Statistical timing test (dudect-style) over valid, invalid, and adversarially structured ciphertexts on the floor device and on x86, plus a source read of the decapsulation path for secret-dependent branches and divisions | §4.3; the crate choice for the channel's static key |
| RT-P5 | Does hyper/axum run over the record channel at full RPC load? | Scratch crate: stream adapter over `seal`/`open`; a block-batch response larger than many records; backpressure under a slow reader; half-close; a request split across records; observed failing with the adapter's record splitting removed | RT-W9's adapter design |
| RT-P6 | What does a handshake cost on the floor device (Pi 4), each side? | Time each message and the whole handshake, daemon and client, on the floor device; CPU per unauthenticated message 1 | The handshake-deadline constant (derived from this, not chosen); the tunnel pool size; §4.3's amplification bound |
| RT-P7 | Does §4.1's token order reach the property each stage claims? | ProVerif model: daemon authentication at message 2, client authentication classical at message 3 and hybrid at the first record, secrecy of the transport keys, client-identity hiding — each query observed **failing** under a named edit (e.g. remove `skem` from message 1; remove `se` from message 3) before its success is trusted | §4.1; **gates RT-W9** |
| RT-P8 | Windows: does RT-15's same-user pipe and RT-16's service shape hold on a real box? | Windows lane, on the built daemon: (1) the GUI dials its `shekyld` child through the rendezvous file and the peer check passes; (2) another user's pipe pre-created under a guessed daemon-style name has no effect on startup or dial; (3) a same-user client in a second logon session is refused by the pipe and the client reports it from the rendezvous without dialling; (4) every Windows-side caller of the daemon RPC (GUI backend including its mining control, `shekyld <command>`, the wallet stack) is named with its leg; (5) per-service virtual account: network access, restricted service-SID type, minimal required-privilege list, the bundled Tor as its child; (6) the `%ProgramData%` ACL admits the service account and Administrators only; (7) the side-by-side refusal between the two modes | RT-15, RT-16; RT-W10; RT-W14 |

---

### 9.1 RT-P8 results (Windows lane, 2026-10-08; reported, not reproduced)

- **Caller identity over the pipe:** with the same user on both ends, the
  server read the caller's user, integrity level and logon session,
  matching the client's own report; with a low-integrity client
  deliberately admitted, the server read "Low" while itself at Medium — it
  reads the caller, not itself. Identity is available only after the first
  byte is consumed.
- **Low-integrity callers:** refused by Windows at open under the default
  pipe settings; the server never observes them.
- **Squatting a predictable name:** a low-integrity process can hold one;
  the daemon's bind then fails with "Access is denied", identical to
  "already running". Dialling the name through the peer check passed
  against our listener and refused the squatter as `IntegrityTooLow(Low)`;
  an owner check alone would have been fooled (same user). The name is
  released when the squatting process exits. §7.1's random name,
  no-read-up label and start-up dial follow from these.
- **Loopback TCP:** no caller identity in-band; a port-to-process lookup
  exists but is racy and needs privilege across users.
- **Not run, by environment:** (a) a different-user caller — needs an
  elevated shell or a second account. Not required: RT-15 serves no
  cross-user pipe; the arm matters only if a service-run pipe is ever
  reconsidered (rejected, §12). (b) Separation between two interactive
  sessions of one user — needs a Server edition; the §4.5 other-session
  row rests on it. *Reopen:* the first Server-edition deployment, or any
  report of a same-user second session reaching the pipe. (c) **Item 2 as
  written** — another *user's* pipe under a guessed name — for the same
  reason as (a). What was measured is the nearer case, a same-user
  low-integrity squatter, reported above; the different-user squatter is
  unrun, and §7.1's random name is what the design relies on against it.
- **Rendezvous label (§7.1):** a label set at `CreateFileW` refuses a
  low-integrity read; an inherited label and an `icacls`-applied label both
  carry `NW` only and admit it, while appearing as a Medium label.
- **Item 4 — Windows callers today:** the Windows build produces only
  `shekyld.exe` and `shekyl-mdb-copy.exe`; the wallet stack is linked into
  the GUI (`src-tauri` path-depends on `shekyl-engine-core`,
  `shekyl-rpc-client`, `shekyl-scanner`; its embedded engine builds its
  daemon client from the same address). Three consumers, one leg: the GUI's
  own daemon RPC (including mining control), the GUI's embedded engine, and
  `shekyld <command>` — all same-user, all on the owner-only pipe. Nothing
  on Windows uses the channel in run-as-me mode. When WP-W5 ships
  `shekyl-cli` and `shekyl-wallet-rpc` on Windows (`BuildRust.cmake:390-414`
  gates them today), they join as same-user callers; the design does not
  change.
- **Item 5 — partly:** the restricted service-SID type is in production use
  for network-listening services (9 of 334 on the box, including the
  firewall's; `NetTcpPortSharing` is the closest precedent: listening,
  restricted, one privilege). All run as LocalService; the **virtual-account
  half is unrun** (needs elevation).
- **Item 6 — partly, and the default is wrong for RT-16:** a fresh
  `%ProgramData%` subdirectory inherits `BUILTIN\Users` write, so the
  installer must break inheritance explicitly. `NT SERVICE\shekyld` does
  not resolve before the service exists, so the service is registered
  first and the directory created after. Any unelevated user can pre-create
  `%ProgramData%\<name>`, and as its owner keeps the right to rewrite its
  DACL — so re-asserting the ACL on an existing directory is not enough.
  **The installer never adopts an existing path:** one it did not create
  in this run is moved aside, reported, and replaced by a fresh directory
  owned by Administrators with the asserted ACL (proposed; the ownership
  point is design reasoning, not measured). The real service ACL is unrun
  (needs elevation).
- **Not runnable yet:** item 1 is blocked on RT-W10 — no rendezvous exists
  in the tree, and the lane declined to substitute a model and report it as
  item 1; item 7 is unimplemented.

## 10. Open questions

- **Finding for the Windows wallet lane (not ruled here).** The same
  `create_owner_only_file` writes the **exported seed file** (WP-D8) with
  no mandatory label. The wallet pipe already refuses low-integrity
  callers, so a same-user low-integrity process is inside that threat model
  — yet under the default policy it can read an exported seed. One policy
  for the one function (`NR` at creation for every caller) is the obvious
  fix; it is the wallet lane's to rule, with WP-D8 reopened.
- **RT-O6 — length concealment.** The path observer sees request and
  response sizes and timing; for a syncing wallet those track block sizes.
  In scope for the channel, or accepted and named?
- **RT-O7 — vectors.** RT-P7 checks the design; vectors check the code.
  Rule 30 pins vectors before implementation. With no external source for
  XK ∪ pqXK (PW-2), the proposal is a second, test-only implementation
  written from §4.1 alone as the differential against the production one,
  plus the existing cacophony cross-check for the classical NN path. Also
  the protocol-name string, which is part of the transcript. Implementation
  hazards already known: the `fips203` `DummyRng` issue pinned around in
  `shekyl-crypto-pq/Cargo.toml:55-58`; RT-P4.
- **RT-O8 — the `https://` arm of the daemon client.**
  [`http_client.rs:240-266`](../../rust/shekyl-rpc-transport/src/http_client.rs)
  builds a native-roots TLS connector for `https://` daemon endpoints.
  Under RT-10 no supported posture uses it; deletion takes `rustls`'s
  native-certs path out of the wallet graph.
- **RT-O9 — the grant table. Blocks RT-W10 until confirmed.** The form is
  directed (2026-10-08): named grants, with `status` split from `health`
  and held out of every preset but `admin`. What remains open is the
  assignment in §6.1, in particular:
  - the four changes from today's gate that §6.1 lists
    (`/get_alt_blocks_hashes`, `/get_limit` and `/get_net_stats`,
    `/get_stem_tallies`, `get_info.restricted`);
  - whether `node` should stay one grant. It is every action that today
    needs the admin listener and has no narrower home; splitting it further
    has no consumer asking for it (rule 21);
  - whether the incident's consumer is enrolled for `peers` to keep its
    seed-node count, or the count is dropped from the site;
  - `get_info` served field by field. It is the one method that spans
    grants, and it is still a C++ handler: the grant crosses the FFI as
    more than today's one boolean until `/get_info` moves to Rust (RK-5c).

---

## 11. What this round supersedes (swept when it lands)

- `RPC_TRANSPORT_POSTURE.md`: RT-4's mechanism and table, RT-5/RT-6's
  TLS-specific wording (their requirements — no early data, no downgrade —
  carry to the channel), RT-1's scope (plaintext only, RT-14), RT-W4's and
  RT-W6's slice rows, RT-9's restricted-listener half, §1.1 item 3.
- `DAEMON_RPC_RUST.md`: "Restricted RPC stays", "Restricted Mode", and the
  local and remote rows of the auth table.
- `removed_flags.cpp:189-190` message; `--restricted-rpc`,
  `--rpc-restricted-bind-port`, `--rpc-restricted-bind-ip`,
  `--rpc-restricted-bind-ipv6-address` (`rpc_args.{h,cpp}`,
  `core_rpc_server.cpp`, `daemon.cpp`). The plaintext bind flags are
  re-scoped to the least-grant loopback listener and their parsing moves
  out of C++ `rpc_args` into `shekyl-daemon-rpc` (§7).
- `bind.rs`'s refusal text and its two tests that assert the onion remedy.
- `ctl_client.rs`'s plaintext loopback-TCP path: `shekyld <command>` moves
  to the owner-only socket or pipe for a run-as-me daemon, and to the
  channel with the console key for a service (RT-15, §5).
- Shipped Windows guidance that points operators at Task Scheduler
  (`removed_flags.cpp:159-161`, `INSTALLATION_GUIDE.md:229-235`): replaced
  by RT-16's two run modes (the scheduled task is rejected, §12).
- `shekyl-rt-p2-spike` (R0 marked it disposable).
- `IMPLEMENTATION_INDEX.md` `RT-` row.

---

## 12. Rejected alternatives

- **Pinned mutual TLS (R0 RT-4).** Cannot carry a hybrid identity without
  composite-certificate plumbing (RT-10, RT-11). Its interop advantage is
  delivered by RT-12 instead.
- **Probing the network, or an operator-declared "trusted link".** The
  daemon is not the operator's network manager; the moment it certifies a
  configuration it owns every configuration (decision authority,
  2026-10-08).
- **KN, KK, IK.** §4.2.
- **Classical static authentication with hybrid forward secrecy only.**
  RT-11.
- **Refusing wildcard binds on the channel listener.** A judgment of the
  operator's diligence, with real deployment costs (RT-14).
- **Plaintext loopback TCP as the local admin surface.** Admin for every
  local user (RT-15).
- **The channel for every local caller, same user included.** Gives the
  default GUI-bundled install a key to provision and a key file to steal,
  for no gain over OS identity (RT-15).
- **A fallback ladder** — try the local socket or pipe, then the channel,
  then anything else. Silent switches between nodes, and a fallback after a
  failed peer check is a downgrade oracle (RT-15).
- **The Unix socket under the user's persistent state home** (proposed in
  this round's first review pass, withdrawn). It answered the missing and
  removed runtime directory, but every such case is an unattended daemon,
  which RT-16 assigns to service mode. Its costs were real: socket files
  are unreliable on network-mounted home directories and refused outright
  on some, long home paths spend the socket-path budget, and a crashed
  daemon's socket would survive a reboot. The runtime directory stays,
  with a refusal where it is absent (§7.1).
- **Isolating a test run by pointing daemon and client at a temporary
  state home**, instead of a named instance. Windows' folder lookup ignores
  environment variables, so it would need its own override flag anyway — a
  hidden surface where the instance name is a visible one.
- **A predictable per-user pipe name.** Another user can squat it before the
  daemon starts; the random name in a user-only rendezvous removes the name
  to squat (§7.1).
- **A service-run pipe admitting a configured list of users.** A third,
  per-mode mechanism beside the socket/pipe and the channel; service-mode
  callers use the channel (RT-15).
- **Never running the daemon as a service** (the Windows lane's
  recommendation, declined). A daemon that stops at logout stops serving
  the operator's other devices and stops relaying; the service adds a
  deployment step, not a second authentication surface (RT-16).
- **A scheduled task running the daemon as the user after logout** — the
  apparent no-elevation route to surviving logout. Scheduled tasks are
  unreliable on Windows (they fail for opaque reasons and break on
  updates), and the route fails on its own terms: the task runs in a
  different logon session, so it would not recover a logon-session-locked
  pipe either (WP-D6).
- **Running the daemon as SYSTEM or root.** Any parser defect becomes a
  whole-machine compromise (RT-16).
- **A reload signal or editable file for the enrolled set.** A revocation
  that waits for a reload is a revocation that can be forgotten (§5).

---

## 13. Slices (proposed; none authorized)

| Slice | Contents | Depends on |
|---|---|---|
| RT-W8 | RT-P7 model; RT-O7 vectors and differential; registry rows; RT-P4 | ratification |
| RT-W9 | Record layer extracted into a shared crate (pinned vectors untouched); handshake; the stream adapter under hyper/axum (RT-P5); deadline from RT-P6 | RT-W8 |
| RT-W10 | Daemon: same-user socket/pipe and rendezvous, channel listener, enrolment and revocation, per-connection grants; restricted listener and its C++ flags deleted; plaintext loopback re-scoped to `view` | RT-W9, **RT-O9**, RT-P8 |
| RT-W11 | `shekyl-rpc-tunnel`, with session pooling | RT-W9 |
| RT-W12 | Clients on the channel: the engine's daemon client and `shekyl-wallet-rpc` (L1); `shekyl-gui-wallet`, which dials `HttpRpc::new` directly (open since R0's RT-W7 landing review, `RPC_TRANSPORT_POSTURE.md` §7 RT-O4); `shekyl-mobile-wallet` | RT-W9 |
| RT-W13 | §11 sweep | lands with RT-W10 |
| RT-W14 | Service mode (RT-16): the declared-mode switch; console key and its offline reset; enrol at install; machine-wide rendezvous; Windows service under a virtual account and its installer step (service first, fresh data home never adopted, inheritance broken); Linux unit under a dedicated user; machine-wide data home and ACL; Tor as the service's child; side-by-side refusal | RT-W10, RT-P8 |
