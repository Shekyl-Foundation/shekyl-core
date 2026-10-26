# RPC channel — one authenticated, encrypted channel for every RPC leg

**Status:** R1 — **RULED 2026-10-09** (Rick). Design of record. It
authorizes no implementation; slices are authorized one at a time (§13).
RT-W8 and RT-W9 have landed (RT-W9 on 2026-10-25); no listener is built.
§3's rulings were given on 2026-10-08 and 2026-10-09; §4–§8 (mechanism,
failure modes, keys, authorization, listeners, tunnel) were ratified whole
on 2026-10-09. §9 registers the probes, which are measurements, not open
design. RT-P7 (the model, 2026-10-10) and RT-P4 (constant-time
decapsulation, 2026-10-11) were run in RT-W8 and are met. RT-P5's sizes
part was measured on 2026-10-17, and its record boundaries were observed
with the stream adapter in RT-W9 step 5b on 2026-10-20 (§4.4). RT-P6 was
measured on 2026-10-19 on the floor device, and its stranger was
re-measured with mac1 on 2026-10-20. RT-P9, the handshake's round trips
on an onion leg and a LAN leg to the floor device, ran on 2026-10-20, and
the handshake's deadlines come from it: message 1 within 4 s of `accept`,
the whole handshake within 11 s (§4.3). RT-P8 is partly reported by the
Windows lane and not reproduced; its item 6 is still to run.
**Verified against:** `shekyl-core` @ `a86ba6d13f` (`dev`). Every
`file:line` into this repository was read at that commit. Citations into
clatter name their own commit (§4.1).
**Token family:** continues `RT-` from
[`RPC_TRANSPORT_POSTURE.md`](RPC_TRANSPORT_POSTURE.md) (R0): rulings
`RT-10…RT-16`; open items `RT-O5…RT-O15`, every one now ruled (RT-O5 and
RT-O5′ into RT-15; RT-O9 in four parts, `RT-O9.1`…`RT-O9.4`); probes
`RT-P4…RT-P9`; slices `RT-W8…RT-W15`. RT-O11…RT-O15 are the RT-W8
pre-flight's. `RT-O16…RT-O22` are the RT-W9 pre-flight's
([`RPC_CHANNEL_RT_W9_PREFLIGHT.md`](../completed/RPC_CHANNEL_RT_W9_PREFLIGHT.md)),
ruled 2026-10-11. `RT-O16`, `RT-O18`, `RT-O20` and the sequencing half of
`RT-O21` were re-ruled 2026-10-12 (PR #1034); the re-rulings are what is
built. `RT-O23…RT-O27` are the runtime option requests' (§6.4), posed
by the daemon-configuration cutover and ruled 2026-10-14. `RT-O28` and
`RT-O29` are RT-W9 step 5's, ruled 2026-10-20 (the pre-flight's §4a).
`RT-O30…RT-O36` are the RT-W10 pre-flight's
([`RPC_CHANNEL_RT_W10_PREFLIGHT.md`](RPC_CHANNEL_RT_W10_PREFLIGHT.md)),
ruled 2026-10-25.
Slice `RT-W15` is the daemon console's move to `shekyl-cli` (§13). No new
family (rule 94).
**Decision authority:** Rick.
**Relationship to R0:** R0's §1 premise (every RPC leg is
operator-to-operator; the adversary is the path, never the peer) and §3
threat model are unchanged. This round re-rules R0's *mechanism* (RT-4,
pinned mutual TLS) on new ground (RT-11), replaces the restricted-listener
model, and restricts RT-1 to plaintext listeners. §11 lists what was swept
from the design corpus with the ratification and what each later slice
still removes.

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

**The recommended posture (advice, ruled 2026-10-25).** §4.3's replay
residual is absent where no path can read the handshake. Those postures are:

- **Same host:** the same-user socket or pipe (RT-15). There is no network leg.
- **Between machines:** a tunnel that ends on the daemon's host, such as
  host-to-host WireGuard, or an onion service whose forward to the daemon
  stays on that host. The onion is reachability (§7); the channel runs
  inside it, and the forward is not a second leg a path can read.

Any other leg leaves the handshake readable. That includes the open
internet, a clear LAN, a Tor exit onto a public listener, and a VPN that
ends before the daemon. The ruled channel listener accepts that bind
(RT-14): the operator's network is the operator's. It is strongly
discouraged, because on that leg the operator owns the residual in §4.3.

This is advice to operators. Nothing in the daemon detects which posture
it is in, and nothing depends on it.

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
symmetric state, AEAD, and interim record layer. RT-W9 step 1 extracted
the symmetric state and `Direction` into `shekyl-noise` and left that
interim framer where it is (§4.4, re-ruled 2026-10-12).

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
[`core_rpc_server.cpp:100-101`](../../src/rpc/core_rpc_server.cpp)), and
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
  owner-only named pipe on Windows — authenticated by OS identity. The
  owner is the host's administrator: every grant, plus the two host-only
  classes of §6.1, which are not grants and which no ceiling can contain.
  There are no keys to provision. This is R0 §1.1's
  ratified end-state transport for the daemon, and it covers the default
  install: the GUI running `shekyld` as its child, same user, same session.
- **Anyone else** — a service-mode daemon's callers (RT-16), another user,
  another machine: the channel, on loopback or across hosts.

**One target per client, never a ladder** (the requirement: an operator
must not meet errors merely from connecting). A client is configured with
exactly one target — **"this computer"** (the default) or an explicit node
address — and connects to that target or reports why it cannot. It never
falls back from one leg or node to another. "This computer" resolves to the
single local daemon — the **default instance** (a deliberately named second
instance is reached only by naming it, §7.1). Its uniqueness is what
RT-16's start-up exclusion provides. "This computer" resolves through that
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
   On Unix this is enforced, not assumed: the daemon stops when its
   session's rendezvous goes (§7.1).
2. **As a service under a dedicated low-privilege account** — opt-in;
   survives logout. On Windows a per-service virtual account; on Unix a
   dedicated unprivileged user, the posture of the Linux packaging.
   **Never SYSTEM, never root**, written as firmly as the wallet's WP-D7.

*Why the daemon may be a service when the wallet may not.* WP-D7
([`WINDOWS_WALLET_SUPPORT.md:417-422`](WINDOWS_WALLET_SUPPORT.md)) forbids
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

- **The service-mode unit inherits `Slice=shekyl.slice`** from the shipped
  packaging (ruled 2026-10-12, `ARCHIVAL_CHALLENGE_MECHANISM.md` §9.8):
  the daemon's own top-level slice at `CPUWeight=400`, weighed 4:1
  against `user.slice`, so a per-user wallet serving beside the service
  cannot take the daemon's CPU. The slice is the packaging's; the
  service-mode switch this round adds changes nothing about it. The run
  mode selects the root, and every default path derives from it
  ([`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) IG-13, IG-Q36); Linux keeps
  `/etc/shekyl/shekyld-<network>.toml`.
- **The mode is declared, never inferred.** On Unix a unit
  running the daemon under its dedicated user and that same user starting
  it by hand are indistinguishable from inside the process, so the daemon
  cannot work out which leg to serve. Service mode is selected by an
  explicit switch that the installed unit or service registration passes;
  without it the daemon is run-as-me. A daemon never guesses its mode from
  its account, its data directory, or its parent.
- **`shekyld` answers the Windows Service Control Manager itself** (ruled
  2026-10-13), in Rust, entered only through the `service` switch
  ([`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) IG-Q36; command line only,
  IG-Q37). No wrapper process (NSSM, WinSW, a Shekyl-built host) and no
  self-registration: install and uninstall are the installer's and
  `shekyl-cli`'s, through one shared Rust library, and restart-on-failure
  is the SCM's failure actions, set at install. On POSIX the service
  manager runs the foreground process and the switch is refused. *Why it
  recurred:* the April daemonizer deletion assumed every OS service
  manager runs a foreground process; the SCM kills a registered process
  that never connects to its dispatcher (error 1053). Record:
  [`WINDOWS_SERVICE_RULING_2026-10-13.md`](../completed/WINDOWS_SERVICE_RULING_2026-10-13.md).
- **The process entry moves to Rust** in the daemon-configuration
  cutover (`DAEMON_CONFIG_CUTOVER.md`, PR #1066): the SCM dispatcher must
  run at process entry, and `main()` is C++ until then. RT-W14 depends on
  it.
- **Service mode is new Rust work, not a revival.** The inherited daemonizer
  was deleted in V3.1 and its five flags retired
  (lines 74 to 78 of `src/common/removed_flags.cpp` at `d26148535e`); none of
  it is restored (rule 15).
- **Installation needs elevation once**, so the service is an opt-in step;
  run-as-me keeps working with none.
- **A run-as-me daemon's home is always per-user**: `FOLDERID_LocalAppData`
  on Windows, never Roaming AppData, whatever the token. A machine-wide
  home exists only in service mode and only when the installer created it
  ([`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) IG-13).
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
  can pre-create it and keep the right to rewrite its ACL. **The directory
  is created with its final owner and protected DACL in the
  `SECURITY_ATTRIBUTES` passed to `CreateDirectoryW`**, never created and
  tightened afterwards: a new `%ProgramData%` subdirectory inherits write
  access for every user, so even a moment between creating it and breaking
  inheritance lets an unelevated process place its own entries or a
  reparse point inside. The installer reads the descriptor back and
  compares it before the service is started. This is the directory form of
  §7.1's rule for the rendezvous file — a descriptor applied after creation
  is not the same as one applied at it — and, like that rule, it is
  confirmed by measurement, not assumed (RT-P8 item 6, still to run).
- **Switching modes** moves or re-syncs the chain data; the uniform pruning
  posture keeps a re-sync bounded.
- **One default instance per machine and network: the service takes
  precedence.** Two default daemons would be two nodes with two
  bundles, and a client enrolled with one meets silence from the other,
  which reads as a wrong key (§4.5). A check made only at install or only
  at start cannot prevent that: a service that was stopped can start after
  a run-as-me daemon did, and a service account cannot see into another
  user's session to look for one. So the rule is symmetric in effect
  rather than in mechanism:
  - **A run-as-me default daemon refuses to start** while a service
    default instance for its network is answering at the machine-wide
    rendezvous (§7.1), which every user can read.
  - **A run-as-me default daemon watches the machine-wide rendezvous**, as
    it watches its own (§7.1). When a service default instance appears
    there, it logs why and shuts down cleanly. The service never has to
    find it.
  - **Clients resolve one way during any overlap:** a rendezvous counts
    only while its listener answers and passes the peer check; if both a
    service and a run-as-me default answer, "this computer" is the
    service. A failed peer check on either is still a hard stop (RT-15).

  The service wins because installing and starting it is the machine
  administrator's deliberate act — the daemon knowing its own
  installation, not judging the operator's network. The rule covers the
  **default instance** only; a named instance (§7.1) is a deliberate
  second node and is governed by the rules there.

---

## 4. Mechanism — the handshake (ruled 2026-10-09)

### 4.1 Pattern: `hybridXK` — RULED (RT-O7, 2026-10-09)

The client pins the daemon's static bundle in advance; the daemon learns
the client's identity in the handshake and checks it against its enrolled
set. That is the **XK** shape. Its hybrid form is not ours: the `clatter`
library ships it as a named pattern, `noise_hybrid_xk`
(clatter's `handshakepattern.rs:1238-1254`, version **2.3.0** as published
on crates.io), built by combining
classical XK with PQNoise's pqXK (Angel et al., *Post-Quantum Noise*,
ePrint 2022/539) under PQNoise's ordering rule: *within a message `ekem`
always precedes `skem`, which always precedes all public keys and the
payload.* The channel adopts that token order unchanged.

*The pin is the published 2.3.0, not the unpublished 3.0.0 this section
first cited by commit* (RT-O12, ruled 2026-10-09). The pattern and the
handshake logic are the same in both. 2.3.0 comes from the registry, where
3.0.0 would have been the workspace's first git dependency, and it uses
the versions of `rand_core`, `x25519-dalek` and `chacha20poly1305` the
production graph already carries, where 3.0.0 would have added a second
major version of each to the lock file.

```
<- s                          pre-message: the daemon's static bundle; never sent
...
-> skem, e, es                message 1   payload: empty
<- ekem, e, ee                message 2   payload: empty
-> s, se                      message 3   payload: grant request
<- skem                       message 4   payload: grant
```

This is the whole pattern; nothing is elided. The `...` line is Noise's
own notation and is part of how a pattern is written: it divides the
pre-messages above it — keys each side already holds, hashed into the
transcript and never transmitted — from the handshake messages below it.
There is one pre-message, the daemon's `s`, and there are four messages.
Token by token:

| Message | Token | What it does |
|---|---|---|
| 1, client → daemon | `skem` | encapsulates to the daemon's static ML-KEM key; sends the ciphertext |
| | `e` | sends the client's ephemeral X25519 key, then its ephemeral ML-KEM key |
| | `es` | DH of the client's ephemeral with the daemon's static X25519 key |
| 2, daemon → client | `ekem` | encapsulates to the client's ephemeral ML-KEM key; sends the ciphertext |
| | `e` | sends the daemon's ephemeral X25519 key, then its ephemeral ML-KEM key |
| | `ee` | DH of the two ephemeral X25519 keys |
| 3, client → daemon | `s` | sends the client's static X25519 key, then its static ML-KEM key, each encrypted |
| | `se` | DH of the client's static with the daemon's ephemeral X25519 key |
| 4, daemon → client | `skem` | encapsulates to the client's static ML-KEM key; sends the ciphertext, encrypted |

Every message ends with its payload, encrypted once a key exists — empty
in messages 1 and 2, the grant request in 3, the grant in 4. The handshake
is complete after message 4. The client's first transport message is not
part of the pattern; it is what proves the client decapsulated message 4's
`skem` (below).

**`e` and `s` each carry two keys: the X25519 key, then the ML-KEM-768
key**, hashed and mixed in that order (clatter's README, "Tokens `e` and
`s` handling"). So the pre-message `s` is the whole static bundle, and each
side's `e` is an ephemeral X25519 key and an ephemeral ML-KEM
encapsulation key. One consequence is read from the source, not the
README: the daemon's `e` carries an ephemeral ML-KEM key that nothing in
this pattern encapsulates to (clatter 2.3.0's `handshakestate/hybrid.rs:460-490`
generates and sends both keys for either side). That one key is pure
overhead: 1,184 bytes in message 2 and one ML-KEM key generation on the
daemon that the pattern never uses. Both are already counted in the cost
below — the second of its two ephemeral key generations, and part of
message 2's 2,320 bytes — and are not additional to it. The key is kept,
because dropping it would be a different pattern from the one
cross-checked below.

**Protocol name:** `Noise_hybridXK_25519+MLKEM768_ChaChaPoly_BLAKE2s`,
following clatter's naming scheme. (Its README example writes `X25519`;
its code emits `25519`, the Noise name — clatter 2.3.0's `crypto_impl/x25519.rs:11-13`
— and the name is hashed into the transcript, so the code is what counts.)
The prologue (§4.4) is unchanged.

- **Daemon authentication** is complete when message 2 decrypts: its key
  depends on the message-1 `skem` (post-quantum) and `es` (classical).
- **Client authentication** is classical at message 3 (`se`) and hybrid
  when the client's first transport message opens. The daemon acts on
  nothing before then — that message *is* the first request (§6.2).
  **This boundary is enforced by type, not by convention (RT-W9, ruled
  2026-10-12).** Someone who breaks X25519 can produce a message 3 that
  claims any enrolled client; they cannot read message 4 or produce a
  first transport message. Between message 3 and message 4 the daemon
  holds `DaemonReadyForMessage4`, whose `fingerprint` is the enrolment
  lookup and a claim, not an authenticated client. A caller can copy that
  fingerprint; the copy is still only a claim. After message 4 the daemon
  holds `PendingSession`. The session is released only through one check,
  reached by `open_first_message` or by `lend` and then
  `WithheldSession::release`. `open_first_message` lends its receiving
  direction, for that one call, to an opener the caller supplies, and the
  opener runs to completion before the check. The channel's record framer
  (§4.4) is not part of the handshake. A reader that may see a short read
  uses `lend`: the `RecvDirection` moves out, and the sending
  direction, the client and the request stay in a `WithheldSession` that
  exposes none of them. The caller builds a `ClassedOpener` around the
  lent direction. `record_len` and `open` spend nothing on a short read,
  so the withheld session stays held while the rest of the record arrives,
  and `into_direction` gives the direction back to `release`.
  **The opener's result is not what releases the session (ruled
  2026-10-12).** A direction counts the ciphertexts it has opened, a failed
  tag not among them, and the session is released only if the open
  succeeded *and* the receiving direction itself opened at least one. An
  opener that reports success having opened nothing is refused like any
  other failure, and there is a test with exactly that opener. **The
  direction must also be the session's own.** The caller holds the
  direction and could hand back another session's, one that has already
  opened. `into_directions` stamps both directions with the session's
  handshake hash, and the session is released only if the receiving
  direction handed back carries its own (ruled in the #1039 review; landed
  2026-10-18). A test swaps in a second session's direction, and failed
  against the count-only gate. On success that yields
  `AuthenticatedSession`: the transport directions, the authenticated
  client and message 3's payload. On failure the session is gone.
  `PendingSession` exposes none of those, and `WithheldSession` exposes
  none of what it holds; examples that try are checked not to compile
  (`rust/shekyl-rpc-channel/src/handshake.rs`, `PendingSession`,
  `WithheldSession`). Dropping a `WithheldSession` drops the session
  unreleased.
- **Cost:** two round trips before the first request; three
  encapsulate/decapsulate pairs and two ephemeral ML-KEM key generations.
  On the wire: message 1 is 2,336 bytes, the 2,320-byte Noise message
  (1,088 ciphertext, 32 + 1,184 ephemerals, 16 tag) followed by its
  16-byte mac1 (§4.3); message 2 is 2,320 bytes; message 3 is 1,264 bytes plus
  its payload (32 + 16 and 1,184 + 16 for the two statics, each encrypted
  with its own tag, and the payload's 16-byte tag); message 4 is 1,120
  bytes plus its payload — about 7.0 KB in all. These are measured, not
  only computed: the cross-check asserts them on clatter's output
  (`shekyl-rpc-channel-xcheck`), and it corrected message 3, which this
  section first gave as 1,280. Paid once per channel session; §8 keeps
  sessions alive.

**What is and is not established about this pattern.** No published test
vectors exist for any hybrid Noise pattern. clatter is an independent
implementation of this exact pattern; agreement between two
implementations is evidence, not authority, and clatter states that it
"has not received any formal audit" (its README). The components are
analyzed — classical XK in the fACCE model (Dowling–Rösler–Schwenk), pqXK
in PQNoise — and the combiner is the usual one: each secret is mixed into
`ck` through HKDF, so the keys hold if either input holds and impersonation
needs both X25519 and ML-KEM broken.

**Three anchors** carry the claim. Each is a check that must be **observed
failing under a named edit** before its pass is trusted:

1. **The classical half:** `Noise_XK_25519_ChaChaPoly_BLAKE2s` from the
   community vectors (`cacophony.txt`, which clatter's own harness uses and
   which already anchors the P2P handshake's symmetric state).
2. **The hybrid pattern as a whole:** byte-for-byte against clatter's
   `noise_hybrid_xk`, both sides driven from the same seeded randomness.
   **RT-W8 pins and RT-W9 compares** (RT-O11, ruled 2026-10-09): RT-W8 has
   no handshake of ours, so it drives clatter from seeded randomness with
   the real prologue and commits the messages and transport keys as
   vectors; RT-W9 implements against them, red first. **This anchor is
   complete (RT-W9, step 2).** Shekyl's handshake
   (`rust/shekyl-rpc-channel/src/handshake.rs`), drawing both statics and
   every ephemeral from the same seeded streams through the private
   constructors production calls with the operating system's generator,
   reproduces the four pinned messages, the handshake hash, and a plain
   Noise transport message under each direction
   (`rust/shekyl-rpc-channel/src/pinned_handshake.rs`, RT-O18). The
   comparison was written first and seen failing with no handshake behind
   it, and seen failing again under two named edits: the X25519 ephemeral
   drawn before the `skem` encapsulation (message 1's bytes differ), and
   message 1's tokens in the first draft's order on both sides (message 1
   is 2,336 bytes, not 2,320). The pinned transport bytes are
   `SendDirection::seal` under empty `TRANSPORT_AD`, the same associated data
   `PendingSession::open_first_message` uses. They are one Noise ciphertext,
   not a framed record. Read at
   source: clatter's ML-KEM backend (RustCrypto `ml-kem`, which clatter
   2.3.0 asks for as `0.2.1` and the lock file resolves to **0.2.3**; read
   at both) and ours (`fips203` 0.4.3) draw the same randomness in the same
   order — key generation `d` then `z`, 32 bytes each (`ml-kem`
   `kem.rs:128-132`; `fips203` `ml_kem.rs:156-162`), encapsulation one
   32-byte `m` (`kem.rs:194-200`; `ml_kem.rs:226`) — and both X25519 sides
   draw one 32-byte scalar. Both take the same `rand_core` 0.6 traits, so
   one seeded generator serves both libraries with no adapter between
   them. Within a message clatter draws in token order: for message 1, the
   `skem` encapsulation, then the X25519 ephemeral, then the ML-KEM
   ephemeral. If our implementation, drawing in that order, does not
   reproduce the pinned bytes, the difference is reported — a weaker
   comparison is not substituted and called this anchor.
3. **The design:** the ProVerif model (RT-P7), which gates RT-W9. **Run
   2026-10-10, ProVerif 2.05: every verdict as this section predicts** —
   daemon authentication under either break; client authentication broken
   at message 3 by a broken X25519 and intact at the first record; secrecy
   of the first request and reply and of the client's identity under either
   break; and each named edit failing as it must. Authentication is
   proved injectively, and all of it against a second enrolled client
   whose static keys the attacker holds
   (`rust/shekyl-rpc-channel/model/model.py`; the record is in the RT-W8
   pre-flight, §4.2).

**clatter is a test-only cross-check, never a production dependency** —
the P2P round's read-not-depend posture for `snow` (PW-7a). That is encoded
as a check that can fail: a gate asserting clatter is absent from every
non-dev dependency graph in the workspace (RT-W8). It is declared with its
default features off: they include a binding to the PQClean C
implementation of ML-KEM, and the cross-check needs only the Rust one.

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

- **Without the bundle.** Message 1 carries a mac1 keyed by a hash of
  the bundle (below), and the daemon checks it before anything else. A
  sender who lacks the bundle cannot write one, and its message 1 is
  dropped having cost the daemon one keyed hash: no long-term key is used.
  The daemon sends no byte before message 1 authenticates, and any failure
  closes the connection without reply, with one exception: a message 1
  that passed mac1, was new to the replay window, and found the handshake
  budget empty is answered "busy" (below), and only a holder of the bundle
  can write such a message. A scanner sees a port that accepts TCP and says
  nothing.
- **With the bundle, not enrolled.** Message 1 authenticates, so the daemon
  answers with message 2 — confirming that this daemon, with this key, is
  at this address. The connection closes after message 3 when the
  fingerprint is not enrolled. **The bundle is therefore a probing
  capability**: whoever holds it can test addresses for the daemon. §5
  treats it accordingly.

**The pre-authentication surface.** Before anything authenticates, any
sender — bundle or not — makes the daemon do two operations with its
**long-term** keys on attacker-chosen input:

1. X25519 with the static key against an attacker-chosen `e` (the `es`
   token)
   (`x25519-dalek`, constant-time by construction). A low-order `e` gives
   an all-zero result; it is refused and never mixed, as the P2P handshake
   already does (`noise.rs:407`, `low_order_x25519_does_not_mix`). The same
   refusal applies to `se` in message 3, where the key is also long-term.
2. **ML-KEM-768 decapsulation with the static decapsulation key against an
   attacker-chosen ciphertext** — the first thing message 1 asks for, since
   `skem` leads it. A timing difference here is a remote
   oracle on the long-term key (KyberSlash was exactly this class, in
   implementations). Requirements: decapsulation is constant-time in the
   pinned crate, **demonstrated** by RT-P4, not assumed (**met 2026-10-11**
   on the floor device's Cortex-A72 and on a Tiger Lake x86 core: no
   dependence on the ciphertext of 0.5 % of a decapsulation or more, with
   both builds' code read for branches and divisions; no efficiency-core
   design measured; `docs/benchmarks/rt_p4_mlkem_decaps_timing_20261011.md`);
   ML-KEM's implicit rejection returns a pseudorandom key for an invalid
   ciphertext, and that
   must remain the only behaviour — the failure surfaces solely as message
   1's tag mismatch, with no branch, error variant, or log line that
   distinguishes rejection from a bad tag. Timing is bounded below.

**Decapsulation timing: the bounds (ruled 2026-10-25).** On the laptop,
the shipped build (`+crt-static`) decapsulates an invalid ciphertext about
16 ns slower than a valid one, about 0.03 % of a decapsulation, with the
decapsulation code identical by disassembly to the build that passed
([`rt_p4_mlkem_decaps_timing_20261023.md`](../benchmarks/rt_p4_mlkem_decaps_timing_20261023.md)).
It is recorded as an observed platform property and accepted, because
of four bounds on who could use it:

- **The same-user path decapsulates nothing.** A client on the daemon's
  own host reaches it over the owner-only socket or pipe (§7.1), not the
  channel.
- **Only a bundle holder reaches decapsulation.** mac1 is checked first,
  so a stranger is refused before the static key is used, and the bundle
  goes only to clients that are enrolled (§5).
- **The budget caps the rate** at about 115 handshakes a second, each one
  logged.
- **The key is hybrid.** Recovering the ML-KEM-768 key alone breaks the
  post-quantum half only. Reading a session or impersonating the daemon
  also takes the X25519 key, which only a quantum computer gives.

A valid/invalid split matters only for ciphertexts crafted near a valid
one, whose validity depends on the key (the published attack on the
re-encryption check needed about 2^30 decapsulations against a far larger
signal). So the attacker the bounds leave is an enrolled client, turned,
with a lab-grade timing channel through the network's noise and a quantum
computer. That does not justify more measurement or a key-rotation design.
RT-P4 stays met (§9).

A bundle holder additionally reaches message-2 encapsulation against a
client-supplied ephemeral encapsulation key (input-checked per FIPS 203
before use, as `noise.rs` already does) and message-3 decryption.

**RT-P6 measured that work** on the floor device
([`rt_p6_handshake_cost_20261018.md`](../benchmarks/rt_p6_handshake_cost_20261018.md)):
one message-1 attempt costs the daemon 641 µs of CPU at the median and
818.5 µs at the 99th percentile, and a whole handshake 2,136.1 µs at the
99th. Two mechanisms bound it (ruled 2026-10-20). Re-measured with them
in place ([`rt_p6_mac1_stranger_20261020.md`](../benchmarks/rt_p6_mac1_stranger_20261020.md)):
a message 1 without the bundle costs the daemon 34.1 µs at the 99th
percentile, refused at mac1, and a whole handshake, mac1 included,
2,163.8 µs.

**mac1.** Message 1 travels as the Noise message followed by a 16-byte
mac1. The mac1 is BLAKE2s, keyed, with a 16-byte output, over the Noise
message. Its key is BLAKE2s-256 of the registered label
`shekyl/rpc-mac1-v1` (domain registry, mechanism 7) followed by the
daemon's public bundle: its X25519 key, then its ML-KEM-768 encapsulation
key, the order §5 fixes for the fingerprint.
- **Outside the Noise message:** the mac1 is not hashed into the
  transcript, so the Noise bytes, and RT-W8's pinned vectors, are
  unchanged.
- **Checked first:** after the length and before anything else, including
  FIPS 203's check on the sender's encapsulation key. A failure is
  `HandshakeError::Message1` like every other, and the connection is
  dropped silently.
- **Public material only:** the key is derived from the bundle, so holding
  it is holding the bundle, which this section already treats as a probing
  capability.
- **Why BLAKE2s, not the house cSHAKE256:** BLAKE2s is the hash the suite
  name already commits the channel to, so mac1 adds no primitive, and the
  construction is WireGuard's mac1 with the bundle in place of the static
  key. That is why its label sits in registry mechanism 7, not
  mechanism 1. The two are equivalent against a quantum adversary here:
  the key is derived from public material, so what mac1 protects is "only
  a bundle holder can write this", and forging a 16-byte tag stays a
  guess per attempt.
- **Tested:** a stranger's message 1 (random bytes, a genuine message 1
  made for another daemon, a genuine one with its mac1 changed) is refused
  before any long-term key is used and without spending from the budget.
  The test failed with the check removed.

**The handshake budget.** Every first presentation of a message 1 that
passed mac1 and FIPS 203's encapsulation-key check is paid for from one
token bucket per daemon (`HandshakeBudget`), before either long-term key.
The order is the length, the mac1, the key check, the replay window, then
the charge. A message 1 that finds the bucket empty is answered with the
busy reply below. A bad mac1, a malformed key, and a mac1 already in the
replay window stay silent.
- **The charge bound.** The bucket bounds charges, not measured CPU.
  While it starts full,

  `charges ≤ share × elapsed + capacity`,

  where the share is `HANDSHAKE_CPU_SHARE_PERMILLE` = 250 thousandths of
  one core (confirmed 2026-10-20) and `capacity` is one second of that
  share (`HANDSHAKE_BUDGET_BURST`). A window of one second can therefore
  be charged the burst already saved plus what that second earns. On the
  floor device the share is a sixteenth of the machine, as a consequence
  of the rate. Nothing here reserves a core.
- **The derivation:**
  - Each admission is charged the 99th percentile of the daemon's whole
    handshake with mac1, 2,163.8 µs (`HANDSHAKE_DAEMON_CPU_NANOS`, rowed
    in the measurement ledger on the re-measure), because an admitted
    message 1 may go on to a full handshake. A message 1 that fails at its
    tag costs 665.5 µs at that percentile, below the charge, so a mix of
    admitted attempts is priced at or above its measured p99. The
    percentile is not a maximum: a slower handshake, the mac1 and key
    check that run before any charge, and work an admission does in a
    later window sit outside the bound.
  - A quarter of a second of CPU per second, divided by 2,163.8 µs, is
    **115 handshakes a second**.
  - The burst holds one second of that, 115 at once, so the clients
    reconnecting after a restart are served together.
- **One presentation.** The same lock holds a window of
  `HANDSHAKE_REPLAY_SLOTS` mac1s, one ruled burst (115). A mac1 is
  inserted when it passes mac1 and the key check, whether the bucket then
  pays or answers busy. A second presentation is
  `HandshakeError::Message1`: nothing is sent, nothing is charged, and no
  long-term key is used. The window drops the oldest once a newer mac1
  arrives past that count. A quiet daemon never evicts, so a captured
  message stays dead.
- **Tested:** a flood of message 1s with valid mac1s and broken tags,
  spread over two simulated seconds, uses the long-term keys only as often
  as the budget pays for. The charges those admissions stand for stay
  within the share of the window plus the burst, and a session established
  before the flood still carries records both ways. Every message the
  budget refused for emptiness was answered busy. A replay of an admitted
  message is silent and leaves the next admission for a different mac1.
  A malformed encapsulation key is refused before the window and before
  the charge. The test failed with the budget removed.

**The busy reply (ruled 2026-10-20).** A budget drop is not silent to a
sender that passed mac1, since that sender holds the bundle.
- **The reply:** 16 bytes, keyed BLAKE2s-128 under the mac1 key over the
  registered label `shekyl/rpc-busy-v1` (domain registry, mechanism 7)
  followed by the mac1 of the message 1 it answers
  (`Message1Admission::Busy` carries it). The daemon writes it in place of
  message 2 and closes.
- **Bound to one attempt:** every message 1 carries a fresh ephemeral and
  so a fresh mac1. The reply to an earlier attempt is not the reply to
  this one.
- **The client** keeps the reply it expects when it sends message 1 and
  compares what came back without an early exit
  (`ClientAwaitingMessage2::is_busy`). A match means busy: it backs off
  and retries, and reports "node busy" only when its handshake deadline
  expires. Anything else, a forged "busy" included, is a connection closed
  without an answer.
- **Who gets it:** only a message 1 that passed mac1 and FIPS 203's key
  check and was not already in the replay window. A mac1 failure stays
  silent, budget or no budget. So does a second presentation.
- **Tested:** an empty budget answers busy before any long-term key is
  used, and the sender recognises the reply. A stranger's message on the
  same empty budget is still refused silently. Random bytes, a reply
  under another bundle, the reply to an earlier attempt, one bit changed,
  and a short or long reply are each not busy. Each test failed with its
  check removed: the drop made silent again, the reply unbound from the
  message 1, the length unchecked, and a mac1 failure answered. A known
  answer for the reply, computed with Python's `hashlib`, pins the bytes.

**The deadlines (RT-P9, ruled 2026-10-20 to come from a measurement).**
Both run on the daemon's clock from `accept`, and both come from round
trips on an onion leg to the floor device, since one deadline must serve
an onion client:
- **message 1 received within 4 s** (`MESSAGE1_DEADLINE`);
- **the client's first record opened within 11 s** (`HANDSHAKE_DEADLINE`),
  which ends the handshake.

Each is twice the onion leg's 99th percentile, rounded up to a whole
second (the rule confirmed 2026-10-20): 1,803.4 ms and 5,231.9 ms over 300
connections, each on its own circuit. The LAN figures beside them are 0.7 ms and 8.6 ms. One onion
connection in 300 took longer than the message-1 deadline. Both constants
are rowed in the measurement ledger (`BA-T37`), and RT-W10's listener
enforces them
([`rt_p9_handshake_round_trips_20261020.md`](../benchmarks/rt_p9_handshake_round_trips_20261020.md)).

**When a handshake does not finish (ruled 2026-10-20), the client**
(`HandshakeRetry`, in `shekyl_rpc_channel::retry`; RT-W10's dialer
drives it):
- **after a timeout, retries once,** without telling the user, from a new
  `Client::start`, so with a fresh ephemeral. The retry has a whole
  deadline of its own. A second timeout is reported: "The node did not
  complete the handshake in time."
- **after a busy reply, backs off and starts again.** The back-off `b` is
  250 ms, doubling to 2 s (`BUSY_BACKOFF_INITIAL`, `BUSY_BACKOFF_MAX`,
  confirmed 2026-10-22), and each wait is drawn uniformly from `[b/2, b]`
  from the OS random source (D2), so clients answered busy together do
  not retry together. The policy takes its random source as a parameter.
  With every wait at its top and a reply that comes at once, seven retries
  fit in one deadline. "Node busy" is reported only when the next start
  would fall at or after the current attempt's deadline. After a timeout
  the back-off starts again from 250 ms.
- **Why these waits.** The budget earns a handshake every 8.7 ms at 115 a
  second, so a short first wait usually finds room. A quarter second
  spreads out clients a restart sends back together.
- **Tested:** each rule fails its test when removed (a second retry after
  a timeout, none at all, the retry keeping the old deadline, busy
  reported at once, no backoff growth). Both ends of the draw are tested:
  every wait at the top of its range gives 250, 500, 1,000, 2,000 ms, and
  at the bottom, half that. A start exactly at the deadline is reported
  and one a nanosecond sooner is retried. End to end on the real
  handshake: an empty budget answers busy, the policy says start again,
  and the new attempt, with a different message 1, completes once the
  budget has earned a handshake.

**What remains, and why.**
- **The budget is shared by every sender.** XK hides the client's
  identity until message 3, so before then nothing says whose attempt a
  message 1 is, and there is no per-client fairness. A bundle holder can
  spend the budget and delay other clients' handshakes, within the charge
  bound. The bundle goes only to clients that will be enrolled (§5), and
  that is what limits who can write a mac1.
- **On a leg that can read the handshake, captured message 1s can empty the budget.**
  The replay window is one burst: after `HANDSHAKE_REPLAY_SLOTS` newer
  presentations, the oldest mac1 can be presented once more. A path
  observer who can read message 1s, which needs no bundle, can replay
  them in rotation, each new again when it comes round, and keep the
  handshake budget empty. That is a denial of service: it reveals nothing
  and forges nothing. The residual is absent in the postures §1 names.
  On any other leg it is the operator's to fix, and the project does not
  design against it (ruled 2026-10-25, §12).
- **A path observer sees "busy".** The reply is 16 bytes where message 2
  is 2,320, so whoever watches the connection learns the node refused a
  handshake for load. It learns nothing about the client.
- **mac2 is not built.** WireGuard's second mac carries a cookie bound to
  the sender's source address. Over Tor a source address is the exit or
  the rendezvous and identifies no one, so that cookie would bind nothing.

### 4.4 Binding and record layer

- **Prologue:** a registered customization (`shekyl/rpc-channel-v1`,
  registered in `CRYPTO_DOMAIN_REGISTRY.tsv` by RT-W8) followed by the network id
  (`shekyl/p2p-network-id-v1`, already derived from genesis). The bytes
  (RT-O14, ruled 2026-10-09): the customization string, then the 16-byte
  network id, with no separator and no length prefix — the first part is a
  constant and the second has a fixed length. A testnet
  client cannot complete a handshake with a mainnet daemon. Nettype selects
  data only (rule 71).
- **Record layer — RE-RULED 2026-10-12 (PR #1034). Step 1 landed in
  PR #1038.** The shared crate is `shekyl-noise`. It holds the AEAD
  primitives (`hash`, `hkdf`, `seal`, `open`), crate-private; the handshake
  symmetric state (`SymmetricState`, the protocol name a parameter); and
  two transport directions, each one nonce stream whose caller never
  supplies the nonce.
  Rekey is `REKEY_NONCES` = 1,000 uses of that nonce (`channel.rs:18` at
  the RT-W9 pre-flight pin; the constant now lives in
  `shekyl-noise`'s `direction` module). A handshake ends in
  `SymmetricState::into_directions`: the symmetric state is consumed into
  a `SendDirection` and a `RecvDirection`, and no raw key crosses the
  public API.
  - **Two types, one per direction** (close-out F3, 2026-10-22): a
    `SendDirection` only seals and a `RecvDirection` only opens and
    counts what it opened, so a session's halves cannot be passed in each
    other's place. `compile_fail` doctests pin a swapped pair (E0308) and
    the wrong operation on either half (E0599).
  - **A failing direction is dead** (close-out F5): a failed tag, a nonce
    or epoch that cannot advance after the AEAD step, and a framer's
    refusal of what it opened all poison the direction itself, so it
    refuses every later operation, even taken out of the framer and
    wrapped again. The re-ruling named `TransportKeys::into_directions`. The landed
  split consumes `SymmetricState`, so no key-bundle type exists.
  `SendDirection::seal` and `RecvDirection::open` return the bytes and the
  key epoch of the key that produced them. The epoch advances only when
  rekey runs. The header-protection key is not a field of either
  direction.
  `ck_and_k` and `force_nonce` stay `#[cfg(test)]` inside the crate.
  **SUPERSEDED 2026-10-12:** extracting `channel.rs` into that crate. The
  interim framer stays in `shekyl-p2p-transport`. It is today's `SendHalf`
  / `RecvHalf`: an encrypted 2-byte length and an encrypted body, two
  nonces per record, bodies at most `MAX_RECORD_PLAINTEXT` = 65,535
  (`u16::MAX`). The clearnet seam and the fuzz targets call it, so it is
  live code, not a leftover. This slice does not move it, copy it, or
  rewrite it. P2P's wire bytes do not change here. *Reopen* when
  `FixedWindow` has replaced it and those callers are gone; the
  re-evaluation deletes the interim framer in the P2P round, rather than
  moving it first.
  `kat_m1.hex` and `kat_m2.hex` stayed byte-identical and keep passing in
  `pinned_messages_mix_steps_and_rekey` (`noise.rs`). The key-schedule
  assertions moved with the directions and stay `#[cfg(test)]` inside
  `shekyl-noise`. There is no feature that exports a traffic key. The C5
  bench times one rekey through `rekey-timing`, which only
  `shekyl-p2p-transport`'s `c5-bench` feature enables, and that function
  does not return the derived keys.
- **HTTP over records.** hyper and axum expect a byte stream; the channel
  delivers records of at most `MAX_RECORD_PLAINTEXT` bytes. The stream
  adapter is the crate `shekyl-rpc-stream`: `AsyncRead` / `AsyncWrite`
  over a `ClassedSealer` and a `ClassedOpener`, with backpressure, record splitting for large
  bodies (block batches), and orderly half-close. It is written once,
  against that framer, after the class table exists. It is not written
  against the interim framer. RT-P5 proves it. **Built in RT-W9 step 5b
  (2026-10-20):**
  - **Writes are combined until a flush.** A record is cut at the flush,
    or when a full record's payload is waiting and another byte arrives.
    A full record is the largest class, and the tail is the smallest class
    that holds it. A submission is the exception below: its bytes stay
    buffered until the flush, so the padding can be sealed first.
  - **A flush ends its message** (close-out F1, 2026-10-22). The first
    flush call closes the message to further bytes, before anything is
    sealed or drained. A write that arrives while that flush is still
    pending finishes sealing the old message's records first, then starts
    a new message. It never joins the old one, so an armed submission
    cannot leave inside an ordinary request.
  - **Backpressure.** An ordinary message holds at most one record's
    payload and one sealed record, so a slow reader holds the writer.
    A submission holds its payload until the flush, at most
    `SUBMISSION_CAP` (`SUBMISSION_RECORDS` times the largest payload), and
    then one sealed record at a time.
  - **Reads.** A record delivers its payload. An empty record is accepted
    only in the two shapes a sender makes (close-out F6):
    - **padding:** at most `SUBMISSION_RECORDS - 1` largest-class records,
      followed by exactly the rest of their submission's
      `SUBMISSION_RECORDS` records, all largest-class and carrying payload;
    - **the close record** below, outside any submission.

    Anything else (an empty record in the middle class, a fifth padding
    record, padding after a frame's payload began, a smaller record where
    a frame owes payload, a byte after the close record) is refused. A run
    of empty records yields after `EMPTY_RECORDS_PER_POLL` = 2 instead of
    holding the task.
  - **An authenticated end** (close-out F7). Shutdown flushes, then seals
    the close record: occupancy 0 in the smallest class, which nothing
    else sends. The reader ends the stream at that record. A transport
    that ends without it is a truncation, at a record boundary or inside
    one. Once the peer's close has been read, a transport that refuses our
    own close because the peer has gone completes the shutdown. A write
    after that shutdown returns `BrokenPipe` and does not poison the read
    side, so the response can still be read.
  - **One refusal is final** (close-out F5). A refused record, a
    transport error and a refused submission poison the stream: every
    later read, write, flush and shutdown returns `StreamPoisoned`.
  - **One table in both directions** (RT-O29), pinned by a test at 512,
    16,384 and 65,535.
  - **A submission** (RT-O28): the client arms the stream's
    `SubmissionMark` before the message is classified. Classification is
    when the kind first changes what is sealed: a further byte arrives
    while one full record is buffered, or a flush finds bytes waiting.
    The mark is taken once, at that moment. An arm after it covers the
    next message, and finishing the flush does not clear a mark set for
    that next message. A flush that seals nothing leaves the mark armed.
    The message goes out as exactly `SUBMISSION_RECORDS` = 5 records of
    the largest class. The padding records, occupancy 0, are sealed
    first and the HTTP bytes are a suffix, so the body is not complete,
    and a response cannot start, until the last record.
    - **Why five:** the largest admissible request body is
      `2 × TX_WEIGHT_LIMIT` plus the JSON envelope (`{"tx_blob":""}`,
      14 bytes), and it must fit `SUBMISSION_CAP` with room for the request
      head. A test computes it from `shekyl-wire`'s `TX_WEIGHT_LIMIT`, so
      the count follows the constant.
    - **Past the cap:** a submission that would pass `SUBMISSION_CAP` is
      discarded without a record sealed, and the stream is poisoned.
      Nothing of a submission is on the wire before its flush.
  - **The daemon checks the shape it read** (close-out F2). The reader
    decides as it admits each record, and `InboundShape::ends_in_submission`
    is that verdict. It is true in two cases. A padded frame is one, at the
    record that finishes it. Exactly `SUBMISSION_RECORDS` largest-class
    payload records in a row is the other, counted from a message boundary:
    the start of the stream, a smaller class, a padded frame that just
    finished, or a record the daemon sent. A client sends its next request
    only after the response, and a path observer sees the response between
    them, so two full-size submissions on one connection are each counted
    from a boundary. The next largest-class record clears the verdict, so a
    longer ordinary message is never a submission. A full-size submission
    sent straight after a message that ended on a largest-class record,
    with no response between them, has no boundary in front of it, and the
    daemon refuses it. Only a pipelining client sends that way. An empty
    padding record opens a frame. It does not end the message before it, so
    a later ordinary record cannot borrow that padding and look like a
    shorter frame. RT-W10's `submit_transaction` route refuses any body for
    which the verdict is false when the body has been read.
  - **Tested through hyper:** every `submit_transaction` upload, for a
    transaction of 0, 1, 26,599, 97,585 and `TX_WEIGHT_LIMIT` bytes, is
    exactly five records, and the handler has those five records open
    before it has the body. hyper flushes once per message in both
    directions, which is RT-P5's registered flush policy, observed. Both
    ends exchange the close record at shutdown.
  - **Each check seen failing with it removed:**
    - the splitting (the pre-flight's named edit, which fails the
      block-batch test), the padding, and an end inside a record;
    - from the close-out (2026-10-22), each with its own named edit:
      - a write joining the ending message;
      - no stream-level poison;
      - a clean end without the close record;
      - each of the three read-side padding rules;
      - no yield on a run of empty records;
      - a padded frame's end not counted as a boundary;
      - the daemon's response not counted as a boundary;
      - unbounded ordinary buffering;
      - a moved middle class.
- **Length concealment — RULED (RT-O6, 2026-10-09); RE-RULED 2026-10-18
  on RT-P5's evidence.** *Harm:* a remote wallet's `submit_transaction` is
  one upload whose size marks it and identifies the transaction's shape.
  A path observer learns when the wallet sent and can correlate that with
  the transaction's appearance on the network. *Evidence:* RT-P5's
  registered trace ([`rt_p5_rpc_message_sizes_20261017.md`](../benchmarks/rt_p5_rpc_message_sizes_20261017.md)):
  submissions are 26,599 to 153,688 bytes and every other request is 431
  bytes or smaller. So in the request direction, which a path observer
  separates, size classes cannot hide a submission among other requests.
  The block-fetch responses that share its classes travel the other way.
  The ruling has three parts:
  1. **Response records are padded to classes, `K` = 3,** each boundary
     derived from RT-P5 rounded up to the next power of two:
     **512, 16,384 (16 KiB) and 65,535.** The largest is the maximum
     record, `MAX_RECORD_PLAINTEXT` (`u16::MAX`): 64 KiB would be one byte
     more than a record can carry. The rounding is the margin RT-P5 showed
     a table needs: optimal boundaries sit at the top of the clusters they
     cover, and a second run's responses a few bytes larger stepped over
     them. These classes stand until the mainnet re-derivation (the
     rule-21 reopen below). *Not covered by this ruling:* requests other
     than a submission. Every one in RT-P5's trace is 431 bytes or smaller.
  2. **A submission is padded to one fixed size: the largest possible
     transaction,** so its size identifies no transaction.
     - The fixed size is derived from the consensus bounds when the framer
       is built (RT-W9 step 5) and pinned by a test. The bounds are
       `MAX_TX_EXTRA` (24,576 bytes of `tx_extra`), `TX_WEIGHT_LIMIT` and
       `MAX_TX_SIZE` (1,000,000), all in `shekyl-wire`.
     - The largest transaction the wallet builds is 97,585 bytes: 8 inputs
       and 16 outputs at tree depth 24, from the weight crate's size
       predictor. A valid transaction may carry more `tx_extra` than the
       wallet's own do.
     - Today the submission's body is the transaction hex-encoded in JSON,
       twice its bytes. It becomes binary in the RPC wire-grammar round
       (RW).
  3. **The time of a submission stays visible to a path observer.**
     Padding hides what was sent, not that or when.
     - *Mitigations:* a wallet on the same host as its daemon (no path to
       observe), or a daemon reached at an onion endpoint.
     - *Rule-21 reopen:* a measured timing correlation on a real wallet
       leg, or network volume sufficient to make one practical.
     - *The designed answer for that reopen:* **submission slots.**
       Fixed-size uploads at a fixed interval, each a real submission or
       padding, answered identically.
  - **Two framers over the same direction types. RE-RULED 2026-10-12
    (PR #1034).**
    **SUPERSEDED:** one implementation parameterised by a class table, and
    a single-class table omits the header byte. A table's length is not a
    wire fork. `ClassedSealer` sends the header byte for every table,
    including a table of one class. `FixedWindow` is the P2P end state
    (`P2P_TRANSPORT_LAYER.md`, D14 item 4): no header byte, one known
    length, the plaintext starting with an authenticated 2-byte occupancy.
    RT-W9 does not build `FixedWindow`. The interim framer is neither
    type. The classed framer stores its header-protection key against
    the key epoch of the direction's next nonce, and derives that key again
    only when the epoch changes. The header key is not a field of either
    direction. It is the first output of `HKDF(record key, label)`: the
    record key is the HMAC key and the label is the input. Rekey is
    `HKDF(chaining key, record key)`, so the record key is the input there.
  - **Where the class sizes come from.** They are derived from the HTTP
    message sizes measured in RT-P5 (§9), on generated traffic, by the
    registered rule, then rounded as part 1 above says.
    *Rule-21 reopen (RT-O21):* the classes ship from that registered
    trace. They are derived again when a mainnet RPC trace is registered
    in the measurement ledger, the same shape as RT-P4's registration.
    The re-evaluation is a design-round entry that names which classes
    moved. Rick decides.
  - **How a receiver learns a record's class — RE-RULED (RT-O20,
    2026-10-12, PR #1034).** `ClassedRecord` puts one byte in front of the
    ciphertext. The byte is a `ClassId`, a `u8` index into `ClassTable`,
    not a length. Indices run from 0 through 255, so a table holds at most
    `CLASS_TABLE_MAX` = 256 rows, and it holds at least one. Each row's
    plaintext length is at least
    `OCCUPANCY_LEN` = 2 and at most `MAX_RECORD_PLAINTEXT`.
    - **Header key.** When a direction installs its record key, the
      classed framer stores the first output of the crate's Noise HKDF
      (`aead::hkdf`) over that key and the label
      `shekyl/noise-record-header-v1`. The same derivation runs when rekey
      replaces the record key, and not on any other record. The label is
      read in one function. It is registered with the constant: mechanism
      7, widened in that same change from "prologue label" to "a label
      whose bytes are an input of this crate's Noise HKDF or of the
      handshake hash". It is not mechanism 2, which is `Hkdf::new`. The
      prologue row is unchanged. The mechanism-7 count pin moves by one.
    - **Mask.** The class byte is XORed with the first keystream byte of
      ChaCha20 under the header-protection key and this record's nonce.
      The nonce is the one the record AEAD already uses (`aead.rs:74-77`
      at the pre-flight pin): 12 bytes, four zeros, then the direction
      counter little-endian. It is not on the wire. The header key and the
      record key differ, so the shared nonce is not reuse. ChaCha20 is the
      cipher already inside the AEAD, not a new primitive.
    - **Body.** One AEAD operation. Associated data is the one unmasked
      `ClassId` byte. The plaintext is the 2-byte occupancy, then the
      payload, then pad out to the class's plaintext length. Occupancy 0
      is a valid record. Wire length is `HEADER_LEN` (1) + plaintext
      length + `TAG_LEN` (16).
    - **Read.** A short read is truncation: the nonce is not spent, and
      the half stays usable. A `ClassId` outside the table and a failed
      tag are one error to the caller, and either poisons the half.
    - **What the text above left open, as built in RT-W9 step 5a and
      confirmed 2026-10-20:**
      - **HKDF order:** the record key is in the chaining-key position and
        the label is the input, `HKDF(record key, label)`. This is
        Noise's own order for rekey, `HKDF(ck, k)`.
      - **Keystream:** ChaCha20 block counter 0, byte 0.
      - **Occupancy:** little-endian, like the nonce counter.
      - **Pad:** zeros. A receiver refuses a record whose occupancy
        overruns its class or whose pad is not zero, so a payload has one
        encoding. The refusal is the same error as a failed tag, and it
        poisons the half.
      - **The table:** strictly increasing, so each length has one
        `ClassId`.
      - **The pins:** a known answer for the header key and three masks,
        computed independently in Python (`hmac` over `hashlib.blake2s`,
        and a ChaCha20 block function checked against RFC 8439
        §2.3.2), is in `shekyl-noise`'s tests.
      - **Mechanism 7 is widened** to "a label hashed by the BLAKE2s of a
        Noise handshake or record layer": the prologue, the mac1 and busy
        labels (2026-10-20), and this label.
      - **The handshake's first record:** `PendingSession::lend` moves the
        receiving direction out and holds the rest in `WithheldSession`.
        The caller reads with `ClassedRecord::record_len` and `open`. A
        short read is `Truncated` and the lend stays held. `into_direction`
        then `WithheldSession::release` is the one success exit: the open
        must be `Ok`, the direction must carry this session's handshake
        hash, and it must have opened at least one ciphertext. A refused
        open, including one whose tag already succeeded, is
        `FirstMessageRefused`. `open_first_message` is that same check
        around one callback, for a message that is already whole.
    - **What the mask removes:** a cleartext class byte a middlebox could
      match, and a delimiter written in the clear.
    - **What it does not remove:** burst sizes, and any segmentation the
      public class lengths themselves determine. A length set a parser can
      cut without keys is still cuttable; the mask is not class secrecy.
      Nor does it hide the handshake: its four messages have fixed sizes
      and are recognisable as this handshake.
  - **Timing stays visible** — when a connection opens and how long a burst
    lasts. Cover traffic is out of scope. *Rule-21 reopen:* a measured
    timing correlation on a real wallet leg.

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
| A call for host-only data or an armed test lever from an enrolled key, whatever its ceiling | Yes | "METHOD is served only on the node's own computer, to its administrator." | — |
| A request over a resource bound (§6.3) | Yes | "This request asks for N; the node serves at most LIMIT per request." Never truncated | — |
| A call outside the connection's grant | Yes | "This connection is not granted METHOD (granted: GRANT)." — never "method not found" | — |
| Handshake deadline expired | Yes, after one retry with a fresh ephemeral that also ran out (§4.3) | "The node did not complete the handshake in time." | Timeout, with the stage reached |
| The node's handshake budget is spent (§4.3) | Yes — a busy reply, verified, in place of message 2. The client backs off and retries, and says so only when its handshake deadline expires | "The node is busy and did not accept the connection in time. Try again shortly." | Aggregated: "answered N handshakes busy in the last minute (budget: B a second)" |
| Both a service and a run-as-me default daemon answer for one network (the overlap before the run-as-me daemon stands down) | Yes — both rendezvous answer | Nothing: "this computer" resolves to the service (RT-16). A client enrolled only with the run-as-me node is told "The node answered but has not enrolled this client", as that row | Run-as-me daemon: "a service node for NETWORK is now running on this computer; shutting down" then a clean shutdown |
| Starting a run-as-me default daemon while a service default instance answers for its network | (Daemon, at start) "A Shekyl node is already running on this computer as a service for NETWORK." Refuses to start | Same line |
| Session closed by revocation (§5) | Yes | "The node revoked this client's enrolment." | "revoked FINGERPRINT; closed N open sessions" |

**The local leg and target resolution (RT-15).**

| Failure | Client says | Daemon log says |
|---|---|---|
| Target "this computer", no rendezvous for this user or the machine on this network | "No Shekyl node is running on this computer for NETWORK." If a rendezvous exists for another network: "A node is running for OTHER_NETWORK." | — |
| Rendezvous present, nothing listening (the daemon stopped without cleaning up) | "The Shekyl node on this computer is not running (it stopped unexpectedly). Start it again." The stale rendezvous is reported, not treated as a fault | The next start replaces it |
| A daemon was just started and has not published its rendezvous yet | Nothing — the client waits for the publication (an event, not a poll that fails), bounded by the daemon's startup; on expiry: "The node did not finish starting. Its log records why." | Startup progress |
| Unix: no per-user session directory (started under `sudo -u`, cron, or a container) | (Daemon, at start) "This node has no place for its local socket: there is no login session. Install it as a service, keep your session alive after logout (`loginctl enable-linger`), or name a socket directory." Refuses to start | Same line |
| An explicit socket directory is not owned by this user, is not private to it, or cannot hold a socket | (Daemon, at start) "The socket directory PATH cannot be used: REASON." Refuses to start; never adopts or repairs it | Same line |
| An instance name that breaks the naming rule (§7.1) | (Daemon, at start) "An instance name is 1 to 16 lower-case letters, digits or hyphens, starting with a letter or digit." For `default`: "'default' names the default instance and cannot be an instance name." Refuses to start | Same line |
| Unix: the daemon's socket or its directory disappears while it runs (the session ended, or something removed it) | Clients: "No Shekyl node is running on this computer for NETWORK." — accurate, because the daemon has stopped | "local socket PATH is gone (REASON); shutting down" then a clean shutdown |
| Starting a daemon while one is already running for this user and network | (Daemon, at start) "A Shekyl node is already running for you on NETWORK. To run a second one beside it, give it a name." Refuses to start | Same line, with the existing node's start time |
| Service mode: the console key file is missing, unreadable by this user, or damaged | "This command needs the node's console key, which is missing or cannot be read. Run it as an administrator; if the key is lost, stop the node and reset it (§5)." Never falls back to another leg | — (the daemon is not contacted) |
| A listener answers at the rendezvous and **fails the peer check** (wrong owner, wrong integrity level) | "Something other than your Shekyl node is answering at its local address. Not connecting." Hard stop; no retry, no other leg | — (the daemon is not the party answering) |
| Windows: the daemon runs for this user in **another logon session** (the pipe admits its own session only) | "Your Shekyl node is running in another sign-in session and can only be reached from there." Known from the rendezvous before dialling | — |
| Target "this computer" is a service, and this client is not enrolled | As the channel's not-enrolled row: "The node answered but has not enrolled this client. Enrol it with: `shekyld rpc-enrol FINGERPRINT`." | "refused unenrolled client FINGERPRINT from IP" |

---

## 5. Keys and enrolment (ruled 2026-10-09)

R0 RT-7 stands: generated material only, never typed from memory.

- **Each endpoint generates its own static bundle** (X25519 + ML-KEM-768)
  locally. Private halves never leave the host; storage follows rules 35/36.
- **Daemon → client: the full public bundle**, not a fingerprint — XK
  requires the client to *know* the daemon's static keys (≈1.2 KB; one
  file, or one QR code). **No private material moves, but the bundle is not
  harmless:** it is a probing capability (§4.3). Give it only to devices
  that will be enrolled; do not publish it.
- **Client → daemon: a fingerprint** — cSHAKE256 under a registered
  customization (`shekyl/rpc-static-fingerprint-v1`, registered by RT-W8) over the
  client's bundle — plus a **ceiling**. The bytes (RT-O14, ruled
  2026-10-09): the input is the X25519 public key (32 bytes) then the
  ML-KEM-768 encapsulation key (1,184 bytes), the order the handshake's
  `s` sends them; the output is **32 bytes**. How a fingerprint is shown
  to an operator is presentation, not part of the wire. The daemon needs only the
  fingerprint, because the client's statics arrive in message 3.
- **Enrolment and revocation are operator actions over the channel**:
  `shekyld rpc-enrol FINGERPRINT --ceiling GRANTS` and
  `shekyld rpc-revoke FINGERPRINT`. No CA, no issuance key (R0 RT-4's
  argument carries over).
- **Who may enrol, and how far (RULED, RT-O9.1).** Enrolment is the `enrol`
  grant, carried by the `admin` preset only. **An enrolled ceiling can
  never exceed the enroller's own effective grant** — otherwise every
  boundary in §6.1 is one enrol call from `admin`. The same bound applies
  to raising an existing ceiling.
- **Who may revoke.** A key may revoke only enrolments whose
  ceiling lies within its own effective grant. Otherwise a narrow `enrol`
  holder could revoke the operator's admin keys — a denial of service
  through the boundary RT-O9.1 just drew.
- **Who needs a key.** Same-user callers need none (RT-15). Keys exist for
  callers of a service-mode daemon, other users, other machines, and the
  tunnel.
- **Bootstrap — the console key** (service mode). Enrolment runs
  over the channel, so for a service-mode daemon something must be enrolled
  before anything can enrol. On first start the service generates its own
  bundle and a **console key**, records it as the **host administrator's
  credential** — not an enrolment with a ceiling: it carries every grant
  and the two host-only classes of §6.1, which no enrolled key can — and
  writes the console key's private half to a file readable only
  by the service account and administrators. `shekyld <command>` run by an
  administrator uses it. Placing that file uses an OS ACL once, at creation;
  it is not a per-call authentication path. A run-as-me daemon needs no
  console key: its owner reaches it over the socket or pipe.
- **Enrol at install.** The step that installs the service
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
- **Recovering a lost console key** (service mode). Enrolment
  runs only over the channel, so an operator who loses the console key and
  holds no other admin-ceiling key has no way back in through it. The way
  back is offline and local: an administrator runs a reset command that
  generates a new console key, replaces the old console enrolment with it,
  and writes the new private half under the same ACL. **It takes the data
  home's exclusive lock — the same lock the daemon takes at start and
  holds for its life (§7) — and holds it through the whole replacement.**
  So it cannot run beside a daemon, and a service that starts while it is
  running waits or fails on the lock rather than reading a half-replaced
  enrolment. Checking that the service is stopped and then writing would
  leave exactly that gap. It touches no other enrolment and is logged at
  the next start. This is a command that changes daemon
  state, not a file edited by hand, so the rule above stands. Who may run
  it is who may write the service's data home — an OS permission the
  operator already manages.
- **Daemon key rotation** re-enrols every client, by construction.

---

## 6. Authorization (ruled 2026-10-09)

### 6.1 Grants

**Direction (decision authority, 2026-10-08): named grants, with node
status split out of every view.** Four rulings of the same date shape the
table and are marked **RULED** where they apply. They are numbered as
parts of the open item they answer, `RT-O9.1`…`RT-O9.4`, because a bare
`R1` already means "round 1" in this document: enrolment is its own grant
(RT-O9.1), test levers belong to no grant (RT-O9.2), anonymity data is host-only and
not a grant (RT-O9.3), and cost is a resource policy separate from grants (RT-O9.4,
§6.3). Granular grants are the rule: presets bundle grants to make
administration easy, but permissions coupled in one grant are hard to
separate later. The whole assignment was ratified 2026-10-09 (RT-O9).

A grant is a **set of facts or actions**, not a list of methods. Most
methods fall whole into one grant. `get_info` does not: it mixes facts
about the network with facts about this node, so it is served to any
connection holding `health` and each field is present only when the
connection holds that field's grant. **A field outside the grant is
absent, never zero.** Today's restricted reply writes `0` for a hidden peer
count (`core_rpc_server.cpp:212-231`), which a reader cannot tell from a
node with no peers. Absence means exactly one thing here — *not disclosed
to this caller*. A fact the node has no answer for is `null`, and `0` is a
value: the three wire states of RK-D23, ruled in the RK-5c round
([`DAEMON_RPC_KV_GET_INFO.md`](DAEMON_RPC_KV_GET_INFO.md), ratified
2026-10-09). **When** the withheld fields stop being written as zeros is
ruled there too (RK-Q8, 2026-10-09):
in RK-5c itself, after `has_peers` lands — so the wire change is that
slice's, and RT-W10 inherits absence rather than introducing it. A target
height the core does not have is `null` on `get_info`, `get_version` and
`sync_info` alike (RK-Q7, same date), so an absent field in a `health`
reply is never "no target".

One question draws the line between `health` and `status`: *does a client
need this fact to decide whether it can use this node right now, and is it
transient — saying nothing lasting about this node?* Sync state passes: it
differs between nodes, but it describes a moment, not a host. Everything
`get_version` returns passes for a stronger reason, being the same on every
node of the build ([`methods.rs:112-145`](../../rust/shekyl-daemon-rpc/src/methods.rs):
RPC contract version, release flag, heights, fork schedule,
consensus-constants digest, nettype, genesis) — it identifies a build and a
network, never a node.

| Grant | Carries |
|---|---|
| `chain` | Chain reads: `/get_height`, `get_block_count`, `on_get_block_hash`, the four block-header methods (including their `fill_pow_hash` parameter, RT-O9.4), `get_block`, `/get_transactions`, `/is_key_image_spent`, `/get_blocks_by_height.bin`, `/get_o_indexes.bin`, `get_fee_estimate`, `get_coinbase_tx_sum` (a public chain fact; moved from the admin set, RT-O9.4), `get_curve_tree_info`, `get_curve_tree_checkpoint`, `get_archival_emission_claim_source`, `get_archival_shard_coverage`; and `get_info`'s chain fields (difficulty, cumulative difficulty, block-weight limit and median, transaction count, the difficulty target in seconds (`target`), `adjusted_time`, emission and economics fields) |
| `pool` | The **relayed** pool: `/get_transaction_pool`, `/get_transaction_pool_hashes`, `/get_transaction_pool_stats`, `get_txpool_backlog`; `get_info`'s pool size, counting relayed entries. Entries not yet relayed are in no grant (host-only, RT-O9.3) |
| `health` | Whether this node is usable now: `get_version` whole; from `get_info`, the chain tip (height, top hash), `target_height`, `synchronized`, `busy_syncing`, `offline`, `following_degraded`, **`has_peers`** (a boolean, RK-D14 — never a count), `hiding` (an address-hiding session exists now, with no pin state; `INPUT_GRAMMAR.md` IG-Q67), the RPC and protocol contract versions (the nettype comes from `get_version`); `option_show`, whose rows are each present only when the connection holds the grant the row names (§6.4, RT-O24) |
| `status` | **A level of `health`, not a separate entity: holding `status` holds `health`** (ruled 2026-10-24; Health and Status are levels of detail of one node state, and Status includes everything Health carries). Facts about **this node**, each a fingerprint: the Tor posture, `origination`, the sync connectors and the managed Tor object (`INPUT_GRAMMAR.md` Part E); build version string; start time; free space and database size; aggregate inbound and outbound peer counts; RPC connection count; alt-blocks count, `/get_alt_blocks_hashes`, `get_alternate_chains`; `/get_net_stats`; `option_show`'s `status` rows, this node's rate limits and log settings (§6.4) |
| `peers` | The graph: `get_connections`, `sync_info`, `/get_peer_list`; `get_info`'s per-connector socket counts and peerlist sizes; `option_show`'s `peers` rows: the peer, closed-peer and ban rows (§6.4) |
| `submit` | `/submit_transaction` |
| `mining-work` | An external miner's loop: `get_block_template`, `get_miner_data`, `submit_block`, `calc_pow` (a computation service; moved from the admin set, RT-O9.4) |
| `mining-control` | This node's own miner: `/start_mining`, `/stop_mining`, `/mining_status`, `/set_log_hash_rate` |
| `bans` | `set_bans`, `get_bans`, `banned` |
| `node` | Control of the node, and nothing else: `/stop_daemon`, `/save_bc`, `flush_txpool`, `flush_cache`, `relay_tx`, `request_archival_shard`; **`option_set`, which is setting every row the option table marks runtime**, so marking a row runtime widens this grant (§6.4, RT-O24) |
| `config` | The node's configuration: `option_show`'s default rows, every row that names no other grant, including everything that describes the host or links the operator (the onion, SOCKS endpoints, paths, notify commands, `mine-address`). A secret's value is in no grant (§6.4, RT-O24). Carried by the `admin` preset only |
| `enrol` | `rpc-enrol`, `rpc-revoke` (RT-O9.1). Carried by the `admin` preset only |

*Two notes on `health`, both owned by the RK-5c round.*
`has_peers` is true when the node holds at least one **handshaken** session
on any connector (RK-Q4, ruled there 2026-10-09). It exists because a
caller without `status` no longer sees the peer counts, and without it
could not tell a peerless daemon from a following one. `nettype` and the
three network booleans are **retired from `get_info`** (RK-Q6, ruled there
the same day): the identity source is `get_version` alone, which `health`
carries whole, so the grant is unchanged and only the method that answers
moves.

**Two classes that are not grants.** Every route and method is in exactly
one grant above or in exactly one of these; no ceiling, `admin` included,
can contain either.

- **Host-only data (RULED, RT-O9.3).** `/get_stem_tallies` — per-successor relay
  outcome counts, whose consumer is a human tuning `n_min`, `cut` and
  `cooldown` (`handlers/json.rs:489-506`) — and **unrelayed pool
  entries**: stem-phase and not-yet-broadcast transactions, including ones
  this node originated. The pool's sensitivity flag is what reaches them
  today: the pool listing, its hashes and its statistics
  (`core_rpc_server.cpp:499-543`), `/get_transactions` by hash
  (`handlers/json.rs:191-194`), and `get_info`'s pool size when it counts
  them. These are served **only to the host's administrator**: the owner
  leg (the same-user socket or pipe, RT-15) and the console key (service
  mode, §5). **Never to an enrolled key, whatever its ceiling** — `admin`
  over the channel does not include them. The daemon decides this from
  which of its own credentials is asking, not from the network a request
  arrived on. Reason: no remote job needs this data, and it is exactly what
  Dandelion++ exists to hide. The rule covers data about other people's
  transactions (stem tallies, unrelayed pool entries); `origination`
  describes the node's own sends, names no transaction, and sits in
  `status` (ruled 2026-10-24, `INPUT_GRAMMAR.md` Part E).
- **Armed test levers (RT-O9.2; the arming ruled 2026-10-09).**
  `generateblocks`, `inject_archival_serve_credit` and `/pop_blocks`
  (ruled 2026-10-14, §6.4) are not production capabilities. The regtest
  harnesses depend on `generateblocks`
  (`engine/gf7_sealing_run.rs:94`, `engine/daemon_observability.rs`), so
  RT-W10 carries an **armed-and-pinned override** (rule 71): an explicit
  start switch, `dev-rpc`, logged at every start; when armed, the levers
  are served to the host's administrator only. The switch is the only thing
  that enables them; the network type never does. The switch is refused on
  mainnet with its own error (`INPUT_GRAMMAR.md` IG-Q49): the network type
  can only restrict the switch, never select the behaviour, so rule 71 and
  IG-Q49 both stand as written (RT-O36, ruled 2026-10-25). `/pop_blocks`
  has three users, all served there: the regtest roll-back helper, the
  Python framework and the CT-2 fixture generator (§6.4).
  `inject_archival_serve_credit`'s row in the method table is the host's
  and armed ([`methods.rs:135`](../../rust/shekyl-rpc-types/src/methods.rs),
  the review of #1165), so the restricted listener refuses it; until the
  flip routes the armed handlers, its C++ handler's only other gate is a
  `FAKECHAIN` branch (`core_rpc_server.cpp:946`), which the flip deletes
  with the method.

*Why each `status` field is out of view.*

| Field | What it gives away |
|---|---|
| Build version string | The patch level, which tells an attacker which defects apply. The RPC contract version stays in `health` |
| Start time | Uptime and restart times correlate this node's onion address with its clearnet address |
| Free space, database size | A host fingerprint. Today's restricted reply rounds the size up to 5 GiB (`core_rpc_server.cpp:247-249`); under the split the field is absent |
| Aggregate peer counts, RPC connection count | Connectivity posture over time. The counts are sums over **every** connector (RK-Q3, ruled in the RK-5c round 2026-10-09), where today they count clearnet sessions only, so `status` discloses the node's whole session count |
| Alt-blocks count and hashes | Which forks this node saw |

**Presets** (what an operator names at enrolment; a ceiling is a preset or
an explicit list of grants):

| Preset | Grants |
|---|---|
| `view` | `chain` + `pool` + `health` |
| `wallet` | `view` + `submit` + `status` |
| `miner` | `view` + `mining-work` |
| `admin` | every grant, `enrol` included — and **neither** non-grant class |

**`peers` and `config` are in no preset but `admin`; `status` is in `wallet` and
`admin`** (ruled 2026-10-24, amending RT-O9). A wallet needs Status for full
function: its send flow reads `origination` before broadcasting, and the
enrolled key is the operator's own device. `peers` and `config` are granted
only when the operator names them, so publishing a node's peers or its
configuration is a deliberate act, not something a consumer inherits from
the preset it landed in. **Local wallets are never outsiders.** A same-user
wallet (the GUI, `shekyl-cli`, any wallet that conducts transactions) holds
every grant through the owner leg (RT-15; the GUI through its owning
connection), and a wallet reaching a service-mode daemon over the channel
holds `status` through the `wallet` preset. Health is the level for outside
readers only. The plaintext loopback listener is fixed at `view`
(RT-15); the default request on the channel is `view` (§6.2).

*Changes from today's two-level gate* (ruled 2026-10-09, RT-O9):

- **`/get_alt_blocks_hashes` moves out of the unrestricted-to-everyone
  set** into `status`. It is served on both listeners today
  (`server.rs` route table), and it is the per-hash form of the
  alt-blocks count this split hides. No in-tree client calls it.
- **`/get_limit` and `/get_net_stats`** are placed in `status`: this
  node's rate limits and traffic totals. `/get_limit` is on both
  listeners today.
- **`/get_stem_tallies` and unrelayed pool entries leave the grant model**
  for the host-only class (RT-O9.3). Today any caller of the unrestricted
  listener receives them.
- **`get_coinbase_tx_sum` and `calc_pow` stop being admin-only** (RT-O9.4): they
  were restricted for their cost, which §6.3 now bounds directly.
- **The test levers are in no grant** (RT-O9.2); `generateblocks` is admin-only
  today and `inject_archival_serve_credit` is served on both listeners.
- **`get_info.restricted` is retired.** The connection's grant is returned
  in the handshake (§6.2); a boolean cannot describe it.

**Prerequisite: `get_info` moves to Rust first (RK-5c).** `get_info` is
still a C++ handler, and it is the one reply that must be filled field by
grant. Carrying a grant into C++ would widen the one boolean that crosses
the FFI today into a structure the cutover then deletes. So the daemon's
KV cutover slice that moves `get_info`
([`DAEMON_RPC_KV_CUTOVER.md`](../completed/DAEMON_RPC_KV_CUTOVER.md), RK-5c; its
pre-flight, [`DAEMON_RPC_KV_GET_INFO.md`](DAEMON_RPC_KV_GET_INFO.md), was
ratified 2026-10-09 and records this ordering as RK-D17) lands **before**
RT-W10, and this
round asks three things of it and nothing more:

- each `get_info` field is filled in Rust and is attributable to exactly
  one grant in the table above;
- a field the caller may not see is **absent** from the reply, not zeroed,
  and the reply type says so (RK-Q8 there rules that RK-5c makes the wire
  change);
- the caller's authority reaches the handler as a value that can become a
  grant, not as a `restricted` boolean, so RT-W10 supplies a richer value
  without rewriting the handler.

Until the channel exists, RK-5c serves today's two listeners; how it maps
them onto these fields is that slice's decision. No grant is threaded
through C++ for `get_info` in any slice of this round.

*Prerequisite met, 2026-10-13: RK-5c landed in full (`CORE_RPC_VERSION`
3.54; #1017, #1035, #1057). The handler takes a `Disclosure` value with
status, peers and host axes; a withheld part is absent from the reply
(RK-Q8, 3.48); `restricted` is still written, as the transitional flag
this round retires (RK-Q5 there).*

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
life. **The daemon returns the client's ceiling in the message-4 payload**
(RT-O30, ruled 2026-10-25), and both sides compute the effective grant, the
request clamped to the ceiling, once the first record opens. A clamped
client knows at connect time, not when a call fails, since it knows what it
asked for, and nothing computed from the still-unauthenticated request
leaves the daemon. A call
outside the grant is refused with its own error, the grant class of the
wire's code registry ([`RPC_WIRE.md`](RPC_WIRE.md) RW-Q3), never "method not
found". The default
request is the `view` preset (§6.1). Nothing is served until the client's first
transport record decrypts (§4.1).

**Both payloads are fixed-length (ruled 2026-10-12).** The handshake
carries the message-3 and message-4 payloads as opaque bytes; their
encoding is RT-W10's. Whatever it is, each payload has one length for
every grant, so that neither message's size on the wire tells an observer
what was requested or what was granted. Message 3 is then always the same
size, and so is message 4.

**The payload encoding (RT-O31, ruled 2026-10-25).** Both payloads are
16 bytes: a version byte (1), a little-endian bit set over the twelve
grants in bytes 1–2, and zero in bytes 3–15. Message 3 carries the request;
message 4 carries the ceiling. Which bit is which grant is a code
constant pinned by a known answer (rule 30), with this section's table as
its source. An unknown version, a bit outside the known grants or a
nonzero reserved byte is refused like any malformed message, never
ignored, and the ceiling the daemon writes never carries an unknown bit.
The handshake takes the exact lengths as constants. A sender who has
broken X25519 learns nothing from message 4: it is sealed to the client's
ML-KEM key.

A connection's authority — its grant set, whether it is the host's
administrator, and the armed switch — is stamped on every request and read
by every gate (`shekyl-daemon-rpc` `authority.rs`, RT-W10 step 1). The method
table's policy column says which grant, or which non-grant class, each row
needs (`shekyl-rpc-types` `methods.rs`), and C++ is told only the host flag.

### 6.3 Resource policy (RULED, RT-O9.4 — independent of §6.1)

What a caller **may** ask for is its grant. How **much** work one request
may cost is this policy. They are separate: today's restriction encodes
both as authority, which is why an expensive public fact
(`get_coinbase_tx_sum`) and a computation service (`calc_pow`) sat behind
the admin listener.

- **What is bounded:** the four batch caps
  ([`methods.rs:512-527`](../../rust/shekyl-daemon-rpc/src/methods.rs):
  `RESTRICTED_BLOCK_COUNT`, `RESTRICTED_BLOCK_HEADER_RANGE`,
  `RESTRICTED_TRANSACTIONS_COUNT`, `RESTRICTED_SPENT_KEY_IMAGES_COUNT`) and
  the expensive computations — the number of headers a request may ask
  `fill_pow_hash` for, `calc_pow`, and the span of `get_coinbase_tx_sum`.
- **Who is bounded:** every connection except the host's administrator
  (the owner leg and the console key), **whatever its grant**. An
  `admin`-ceiling key over the channel is bounded like any other.
- **The values are inherited** from the Monero lineage and are not
  re-derived in this round (rule 16: inherited code is not inherited
  architecture, and an inherited constant is not a derived one). *Named
  reopen:* the floor-device measurement in RT-W10, beside RT-P6 — the caps
  are then set from measured cost on the Pi 4, not guessed.
- **A request over a bound is refused with the bound named**, never
  silently truncated.

### 6.4 Runtime options: `option_set` and `option_show` (RT-O23…RT-O27)

**Status: RULED 2026-10-14 (Rick), as written below.** His direction of
the same day, synthesized with the tree at `1b7803f69a` (`dev`), with his
two changes on PR #1073: a secret row carries no `value` member
(RT-O25), and `/pop_blocks` moves to the armed test levers. Points that
came from the tree rather than from the direction say so.

**Origin.** DC-Q16 (Rick, 2026-10-14; the daemon-configuration cutover,
PR #1066, `DAEMON_CONFIG_CUTOVER.md` §2.7) replaces the per-setting runtime
endpoints with one generic set request and one generic show request. Each
carries an option's name and its value as text in the input grammar's
syntax, built by the option table's own constructor, the one the startup
parse uses, and routed to the row's Rust owner. The grammar side is
`INPUT_GRAMMAR.md` IG-12 and IG-Q38. RPC method names and wire shapes are
outside the grammar (`INPUT_GRAMMAR.md` §1), so they are this round's,
as `RT-O23…RT-O27`. The implementing PR is the daemon-config cutover's; it
cites this section.

**RT-O23 — names.** `option_set` and `option_show`: the grammar's
own words (`option set`, `option show`, IG-3), so what an operator types
and what a script calls are the same terms. One spelling each, no alias,
as `request_archival_shard` was born
([`json_rpc.rs:225-227`](../../rust/shekyl-daemon-rpc/src/handlers/json_rpc.rs)).
**JSON-RPC methods only, with no REST path:** one way to call each, not
two. Every route they replace is a REST path today.

**RT-O24 — grants.**

- **`option_set` is in `node`.** Every endpoint it replaces is in `node`
  today. Because the method is generic, marking a row runtime later
  widens what every `node` holder can do, with no new endpoint to review.
  So **`node` includes setting every runtime row**, and §6.1's `node` row
  says so. The grammar table's Runtime column is therefore a grant
  decision and is reviewed as one.
- **`option_show` discloses each row under the grant the row names.** In
  place of IG-9's yes/no `view` field, each row names one of four grants:
  - `health` — what `view: yes` meant. A row may name `health` only if it
    passes §6.1's line for that grant: a client needs it to decide whether
    it can use the node now, and it says nothing lasting about the node.
    No row does today.
  - `status` — this node's rate limits and log settings
    (`p2p-upload-max`, `p2p-download-max`, `log-level`, `log-category`). `/get_limit` sits in `status` today, so its readers
    keep the rate limits at the same grant.
  - `peers` — the peer, closed-peer and ban rows.
  - **`config`, the default** — every other row, including everything
    that describes the host or links the operator: the onion, SOCKS
    endpoints, paths, notify commands, `mine-address`. `config` is a new
    grant, carried by the `admin` preset only, like `peers` (`status` is
    also in `wallet`, ruled 2026-10-24).

  A grant is a set of facts (§6.1), and this keeps it one. A dashboard
  that wants the rate limits holds `status` and is never shown the onion,
  the paths or the peers. Today every row is `view: no`
  (`INPUT_GRAMMAR.md` §5), so every row starts as `config`, and no
  decision anyone has made about a specific row changes. Changing the
  field's shape now costs nothing; changing it later would be a
  migration. **The grammar side lands in PR #1074**, ruled by Rick the
  same day: IG-9's `view` field becomes the row's disclosing grant, with a
  Grant column in `INPUT_GRAMMAR.md` §5 carrying the `status` assignments
  listed above, and IG-12 and IG-Q38 move `option set` from the admin
  grant to `node`. *From the tree:* `log-category` is placed beside
  `log-level` here, since today one filter holds both
  ([`filter.rs:107-131`](../../rust/shekyl-logging/src/filter.rs)).
- **Who may call `option_show`:** like `get_info`, any connection holding
  `health`; each row is present only when the connection holds the row's
  grant. A row the caller may not see is **absent** from the reply, never
  zeroed or emptied (§6.1, rule 43). A secret's value is never shown, at
  any grant. No row is host-only (RT-O9.3).
- ***From the tree:* the interim mapping, before RT-W10.** The methods
  land on today's two listeners, before the channel exists. `option_set`'s
  row in the method table is the host's
  ([`methods.rs:124`](../../rust/shekyl-rpc-types/src/methods.rs)), and it
  is in the specified list the gate test compares against
  (`restricted_method_list_matches_the_specification`, `json_rpc.rs:751`),
  so the restricted listener refuses it. `option_show` is served on both
  listeners, and its rows are chosen through `Disclosure`
  ([`info.rs:70`](../../rust/shekyl-daemon-rpc/src/info.rs)), which already
  carries `status` and `peers` axes; it gains a `config` axis, set by
  `Disclosure::FULL` and clear in `Disclosure::VIEW`. That is RK-5c's shape,
  a value that can become a grant, so RT-W10 maps a connection's grants
  onto it without rewriting the handler.

**RT-O25 — wire shape.**

- **`option_set`** takes `{"options": [{"name": …, "value": …}, …]}`; each
  value is text in the grammar's syntax (`"512KiB/s"`, `"unlimited"`,
  `"warn"`), the same text the command line and the file accept. It
  applies **all or nothing**: every pair is built and checked first, and
  none applies if any is refused. A refused request reports every refusal in
  it, not the first; the startup file is likewise validated whole. A name
  given twice, an unknown name and an empty list are each refused. The
  reply lists each row it set, in the shape `option_show` uses, with
  source `runtime`.
- **Build, then apply, under RT-O27's one lock.** *Ruled by Rick on PR
  #1066, 2026-10-14, with the inbound-cap ruling (`INPUT_GRAMMAR.md`
  IG-Q40); `DAEMON_CONFIG_CUTOVER.md` §2.7 there.* The rows go to two
  owners: the link limiter and `shekyl-logging`. No runtime row's validity
  depends on its owner's live state, so every refusal is the
  constructor's, and a set runs two steps:
  1. **build**: every value through its constructor;
  2. **apply**: each owner takes the built value and **cannot fail**.

  Every refusal is reported before anything is applied, so the set is all
  or nothing. **What all or
  nothing promises:** every row of a request is applied or none is, and no
  reply and no `option_show` ever sees part of a request, since both run
  under the lock. Each owner applies all of its own rows from one request
  in one step: the link limiter takes both rates at once. Across owners
  the apply is a sequence, not one instant, so a transfer may meet a new
  rate a moment before the log level changes. That is safe because no
  invariant spans two owners. A runtime row whose validity depends on
  another owner's row is refused when the table is reviewed, which RT-O24
  already makes a grant decision, or it moves to the other row's owner.
  One configuration snapshot read by every owner was weighed and is not
  used: it would make the live value the snapshot's rather than the
  owner's (DC-Q16), and couple every subsystem to one shared object.
  The startup parse runs the same constructors: one rule on both
  surfaces (IG-12). *From the tree:* the logging owner does not meet
  step 2 yet. Its runtime path swaps the filter through a reload handle whose
  `reload` returns a `Result`
  ([`ffi.rs:639`](../../rust/shekyl-logging/src/ffi.rs)), and the handle
  is reached only through the FFI module. The implementing PR gives the
  owner a Rust interface that holds the handle for the life of the process.
  PR #1069 (every log sink queued, so a log call never blocks) changed
  the sinks and left the filter and the reload path as they are, so this
  finding stands and the interface is built on its result.
- **What a change does to traffic already running** (same ruling). A
  rate limit takes effect on the next transfer and never aborts one in
  flight.
- **`option_show`** takes an optional `{"names": [...]}`. With no names, it
  returns every row the caller may see, in table order. Each row carries
  `name`, `source` (`default`, `file`, `cli` or `runtime`), `runtime`
  (whether `option_set` accepts it), and then one of two forms:
  - **a value row** carries `value`: the value as text in the grammar's
    syntax, or `null` when the row has no value (unset). A runtime row is
    never `null`, because its default is a value (below);
  - **a secret row** carries no `value` member. It carries `secret: true`
    and `set: true` or `false`. A secret's text is never sent.

  `value` is text or `null` and nothing else: no string marker stands for
  a secret (rule 43). Readers decode a row into a two-variant type and
  refuse a row with both forms or neither. A name the caller asked for
  but may not see is absent from the reply; an unknown name is refused.
- **At the rename** (`RPC_WIRE.md` RW-Q8, `CORE_RPC_VERSION` 4.0),
  `INPUT_GRAMMAR.md` IG-Q42 (ruled 2026-10-19) renames this wire:
  `option_set` takes `{"value": {<name>: <value>, …}}`, a map, so a name
  cannot be given twice; both replies are the list of rows itself, with no
  `options` key; `option_show`'s `names` is `name`; and a secret row's
  `set` is `assigned`. Every other rule above stands.
- **What `option_show` prints, `option_set` accepts.** The text shown for
  a value is valid input to `option_set` and builds the same value. A
  property test over every runtime row holds this. **Every runtime row's
  default is a value**, written as text like any other: `unlimited` for a
  rate, and `none` for `log-category` (no per-category overrides). So `option_show` never
  prints `null` for a runtime row, and the property needs no special
  case. `null` appears only on a row that is not runtime and has no
  value, and `option_set` refuses such rows anyway. *Found against the
  grammar:* `log-category` defaulted to unset with no way to write it
  (`INPUT_GRAMMAR.md` §5), so an operator who set it could not return it
  to its default without a restart. The spelling `none` is the
  grammar's, ruled the same day as IG-Q39 in PR #1074. For `log-category`,
  the inherited runtime path reads an empty category list as "logging off"
  ([`filter.rs:155-162`](../../rust/shekyl-logging/src/filter.rs)), an
  in-band meaning (rule 43) that the generic set does not inherit.
- **Errors.** A configuration refusal carries the IG-11 diagnostic: its
  stable code (`config.value.range`, the startup-only refusal, …), the
  option, the source (`runtime`) and the named parameters. Its human
  text comes from the one IG-11 renderer, so a client sees what the
  startup parse would print. Today's error object has only `code` and
  `message` ([`types.rs:53-56`](../../rust/shekyl-daemon-rpc/src/types.rs)).
  The implementing PR therefore adds JSON-RPC 2.0's optional `data` member,
  carrying the list of diagnostics, and one new numeric code for a
  configuration refusal, the next free after `-25`
  ([`archival.rs:84`](../../rust/shekyl-rpc-types/src/archival.rs)). It
  bumps `CORE_RPC_VERSION` for both. A call outside the caller's grant is
  refused as §6.2 says; that code is RT-W10's, not minted here.

**RT-O26 — where the handlers live.** Both handlers are native in
`shekyl-daemon-rpc` and never cross into C++. They take an options handle
supplied by the composition root, which is `shekyl-daemon` (N1,
`DRS_X_STORE_FLIP.md` DX-Q3's amendments): it builds `shekyl-node`'s `Node` and passes the
node's handles the same way. The image crate's shard view stays a trait
object (`AppState::shard_view`,
[`server.rs:61`](../../rust/shekyl-daemon-rpc/src/server.rs)); it is not
the server's source until the flip, because the Rust store is not yet the
chain the RPC describes. The RPC
crate depends on the options interface, not on the subsystems; the
composition root wires each runtime row to its owner. No new FFI.

**RT-O27 — what a change leaves behind.**

- **One lock for the whole set operation**, not one per row. Per-row
  locking breaks all-or-nothing: two multi-row sets, one ordered
  upload-then-download and the other download-then-upload, can interleave
  and leave a mix of both. `option_show` reads under the same lock, so a
  reply never pairs one set's upload rate with another's download rate.
- **Every applied set is logged once**: the caller (the enrolled key's
  fingerprint, or the owner leg; until RT-W10, the listener), each row,
  its old value and its new one. Nothing is persisted, and the daemon
  never writes its config file.
- **No row is both runtime and secret**, asserted by a gate on the table,
  so the audit line's values can never carry a secret.
- **Raising the log level at runtime never makes the log record the
  host-only class** (stem data and unrelayed pool entries, RT-O9.3). An
  enrolled key cannot read the log, but the data would sit on disk. This
  is a check owned by `shekyl-logging`, not a block on this work.

**What replaces what.** The implementing PR deletes each route below with
its handler, and fixes its callers in the same PR.

| Today | Grant today (§6.1) | After |
|---|---|---|
| `/set_limit` | `node` | `option_set` on `p2p-upload-max`, `p2p-download-max` |
| `/in_peers` | `node` | deleted with its option (`INPUT_GRAMMAR.md` IG-Q40); the descriptor safety bound is the only inbound bound |
| `/out_peers` | `node` | deleted with its option; the outbound degree is a protocol constant |
| `/set_log_level`, `/set_log_categories` | `node` | `option_set` on `log-level`, `log-category` |
| `/get_limit` | `status` | `option_show`; the rate-limit rows are `status` (RT-O24) |

Census at `1b7803f69a`: the routes
([`server.rs:267-354`](../../rust/shekyl-daemon-rpc/src/server.rs)), the
router (`:413-432`) and the path list (`:664-688`); the forwarding handlers
([`json.rs:293`](../../rust/shekyl-daemon-rpc/src/handlers/json.rs),
`:389-394`, through the dispatch at `:75-91`). Callers: the Rust console's
`print_net_stats`, which reads `/get_limit`
([`console/mod.rs:1126-1169`](../../rust/shekyl-daemon-rpc/src/console/mod.rs))
with its tests (`console/tests.rs:1130-1170`); the Python framework
([`daemon.py:360-455`](../../utils/python-rpc/framework/daemon.py)); the
C++ client test
([`daemon_rpc_client.cpp:107-155`](../../tests/unit_tests/daemon_rpc_client.cpp));
the regtest check of `print_net_stats`
([`regtest_e2e.rs:5817-5876`](../../rust/shekyl-engine-core/src/engine/regtest_e2e.rs));
and the C++ console
([`rpc_command_executor.cpp`](../../src/daemon/rpc_command_executor.cpp)),
which dies with R8 (`INPUT_GRAMMAR.md` IG-Q25). **`/get_limit` is replaced,
not ported:** it leaves RK-8 (`DAEMON_RPC_KV_CUTOVER.md` §2), and the
comments at `regtest_e2e.rs:5866` and `console/mod.rs:1128` that say RK-8
migrates it are corrected by the implementing PR.

**`/pop_blocks` is an armed test lever (ruled 2026-10-14).**
`DAEMON_CONFIG_CUTOVER.md` §4 (PR #1066) left to this lane whether the
route goes with the console word, which IG-Q25 gives no successor. It
moves to the armed test levers (RT-O9.2, §6.1): in no grant, served to the
host's administrator only, and only when the logged start switch is
armed. Its three users take it there: the regtest roll-back helper
([`regtest_e2e.rs:777-785`](../../rust/shekyl-engine-core/src/engine/regtest_e2e.rs)),
the Python framework (`daemon.py:217-221`) and the CT-2 fixture generator
([`gen_ct2_fixture.py:159`](../../rust/shekyl-curve-tree/tests/fixtures/gen_ct2_fixture.py)).
*Reason:* rewinding a node's chain is no capability for an enrolled remote
key; paired with an eclipse, it lets someone rewind a node and then feed
it a chain. RT-W10 step 1 built it: the row's policy is `Armed`
(`shekyl-rpc-types` `methods.rs`), and the request's authority admits it
only through `admit_armed`, on the admin listener with the start switch
set
([`authority.rs`](../../rust/shekyl-daemon-rpc/src/authority.rs)); the
router test `pop_blocks_needs_the_armed_switch` holds it. The
daemon-configuration cutover recorded the gap as DC-F14 (PR #1066). **Reopen (rule 21):**
a demonstrated operator recovery need returns it as a ruled capability.

---

## 7. Listeners and ownership (ruled 2026-10-09)

- **The channel listener** binds any address, wildcard included (RT-14).
  `refuse_non_loopback` is replaced at the seam for this listener;
  `BoundListener` stays the only thing served.
- **The local leg** is the owner-only socket or pipe for same-user callers
  and the channel for everyone else (RT-15). The plaintext loopback TCP
  listener is an operator option fixed at `view`, loopback-only, with
  `browser_boundary`, off by default (RT-15).
- **The onion** (R0 RT-8) is unchanged in spirit: reachability, not a
  security model; the channel runs inside it.
- **One daemon per data home, by lock.** A daemon takes an
  exclusive lock on its data home before it reads any state and holds it
  until it exits. Every offline tool that changes daemon state — the
  console-key reset (§5) is the first — takes the same lock. The lock is
  the single answer to three questions: two daemons on one data home, a
  named instance pointed at the default's state (§7.1), and an offline
  command racing a start.
- **Every new surface is Rust-owned** (rule 20). The channel listener's
  flags, the key paths, the enrolled set, and `rpc-enrol` / `rpc-revoke`
  are parsed, stored and served in `shekyl-daemon-rpc`. Nothing is added
  to C++ `rpc_args` or `core_rpc_server`; the C++ RPC bind and restricted
  flags are deleted, not extended.

### 7.1 Rendezvous (ruled 2026-10-09)

A rendezvous is how a client finds "this computer"'s daemon without
guessing. It is published **after** the listener is bound, **atomically**
(write and rename), removed on clean exit, and replaced on the next start.
Every rendezvous path is keyed by the genesis-derived network id, not a
nettype name (rule 71), so daemons of different networks coexist and a
client never reaches the wrong network's node.

- **Unix, run-as-me:** the socket itself, one file per daemon, directly
  inside the per-user session directory and named by a hash of the network
  id and the instance (RT-O10, below). That directory is the containment
  (R0 §1.1 item 1): it is owned by the user and closed to everyone else,
  the daemon asserts that before binding, and nobody else can place an
  object there — so the name needs no secret component. **RULED (2026-10-09): the directory lives under
  the per-user session directory, and the daemon's life is its
  rendezvous's.**
  - **Where.** Linux: `XDG_RUNTIME_DIR`. macOS:
    `confstr(_CS_DARWIN_USER_TEMP_DIR)`, which has no `XDG_RUNTIME_DIR`.
    Each is local to the machine, private to the user, and cleared with
    the session or at reboot — run-as-me's own lifetime (RT-16).
  - **Neither exists** — under `sudo -u`, cron, and most containers. The
    daemon refuses to start and names the three ways forward: service mode,
    for a daemon meant to run unattended; `loginctl enable-linger`, for an
    operator deliberately keeping a run-as-me daemon past logout; or an
    explicit socket directory.
  - **An explicit, operator-named socket directory — RULED (decision
    authority, 2026-10-09).** CI runners and other session-less test hosts
    have no runtime directory, and the regtest harnesses start `shekyld`
    there. The daemon asserts the directory rather than adopting it: owned
    by the daemon's user, mode `0700`, on a local filesystem that accepts
    sockets — or it refuses to start and says which condition failed. A
    client reaches such a daemon only when told the same directory; it is
    never what "this computer" resolves to.
  - **The daemon watches its own rendezvous.** If the socket or its
    directory disappears — the session ended under a daemon left in a
    terminal multiplexer, or something removed it — the daemon logs why and
    **shuts down cleanly**. So RT-16's sentence is exactly true: a
    run-as-me daemon stops when its session ends. And "no node is running"
    (§4.5) is then always accurate: there is no state in which a daemon
    runs with its local leg gone.

  **The rendezvous name — RULED (RT-O10, decision authority, 2026-10-09):
  a hash of network and instance, on every platform.** `<name>` is derived
  from the network id and the instance name (`default`, or the operator's
  name). The Unix socket is `<base>/shekyl-<name>.sock`; the Windows
  rendezvous file is `%LOCALAPPDATA%\Shekyl\shekyl-<name>` (below).
  **One naming function and one known-answer test serve both platforms**,
  under the registered customization `shekyl/rpc-rendezvous-name-v1`
  (`CRYPTO_DOMAIN_REGISTRY.tsv`). **An instance name therefore reaches no
  path anywhere.** `<name>` is the first 12 bytes of
  cSHAKE256 under that customization over the 16-byte network id followed
  by the instance name's ASCII bytes (RT-O14, ruled 2026-10-09: the
  fixed-length part first, so no length prefix is needed), written as 24
  lower-case hex characters. A daemon and a client compute the
  same name from the same two inputs; nothing is looked up.

  *The arithmetic.* A Unix socket path is limited to 108 bytes on Linux
  and 104 on macOS, terminator included. After `<base>` the name costs
  1 + 7 + 24 + 5 = 37 bytes, whatever the instance is called.
  - *Linux.* `<base>` is `/run/user/<uid>`, at most 20 bytes for a 32-bit
    uid: 20 + 37 + 1 = **58 of 108**.
  - *macOS.* `<base>` is typically 48 bytes (`/var/folders/xx/` + a
    30-character name + `/T`; from the platform's documented layout, **not
    measured** — the estate has no macOS host): 48 + 37 + 1 = **86 of
    104**, 18 bytes of margin against a base longer than expected.
  - *An operator-named directory* has whatever length the operator chose.
    A path over the limit is refused at start with the path and the limit
    named, never truncated.

  *What the hash costs, and its answer.* Nobody can read the path and tell
  which network or instance it belongs to. So the daemon logs one line at
  every start — network, instance, rendezvous path — and **`shekyld status`
  prints the same line**, so an operator can always ask a running node
  where it is. A client that finds nothing says which network and instance
  it looked for, never the hash (§4.5). The readable layout this replaces —
  `<base>/shekyl/<network>/<instance>/rpc.sock` — was 87 bytes on Linux
  and 115 on macOS at a 16-character name, and 106 on macOS for the
  default instance alone.

  The character set and the 16-character limit on instance names (below)
  stand as ruled, for one reason: a name is something an operator types.
  Path safety is no longer a reason, on any platform.
- **Windows, run-as-me:** a named pipe whose name the daemon **draws at
  random on each start** and records — with the logon-session id — in a
  rendezvous file, `%LOCALAPPDATA%\Shekyl\shekyl-<name>`, that only the
  user can read. `<name>` is the same derivation as the Unix socket's
  (RT-O10, above): one function, one known-answer test, and no
  per-network or per-instance directory. A pipe has no containing
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
  - **The directory `%LOCALAPPDATA%\Shekyl` carries its own no-read-up
    label** as well: a low-integrity process cannot open it, so it cannot
    enumerate the rendezvous (measured). The directory's label is not
    relied on to protect the file. **That directory is reserved for
    rendezvous files and holds nothing else**. The label denies
    a low-integrity reader everything inside, so a file with a different
    audience must not be put there by accident; nothing in the tree uses
    this directory today (`shekyl-cli` keeps its history under
    `%LOCALAPPDATA%\shekyl-cli`, the GUI under the roaming profile), and
    anything that later wants a per-user Shekyl directory takes a
    different one. The daemon creates the directory with its descriptor
    and label in the creating call, and where it already exists asserts
    both — owner and the label's policy bits — rather than adopting it.
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
- **Service mode, both platforms:** a machine-wide rendezvous file,
  `<service data home>/shekyl-<name>`, readable by users, naming the
  loopback channel address and the daemon's public bundle. `<name>` is the
  RT-O10 derivation — the same function and the same known-answer test as
  the Unix socket and the Windows rendezvous file. **The service data home
  is its containment** (RT-16: an ACL admitting the service account and
  Administrators to write; nobody else can place a file there). A same-user
  socket or pipe is never served by a service.
- **Named instances.** The rendezvous above is the **default
  instance**: one per user and network, or one per machine and network for
  a service, and the only thing "this computer" resolves to. A daemon
  started with an explicit instance name publishes its rendezvous under
  that name instead and is reached only by a client told the same name. It
  never answers for "this computer" and is never chosen by a client that
  did not ask for it, so RT-15's single target holds.

  **A name is a label for a second node, not the second node.**
  A named instance needs everything a node owns, and none of it is
  derived from the name: its own **data home** — chain store, channel
  bundle, console key, enrolled set and Tor state all live there — and its
  own **P2P and channel listener addresses**. A named instance must be
  started with an explicit data home; started without one it refuses,
  rather than defaulting to the default instance's. Sharing is caught, not
  assumed away: every daemon takes its data home's exclusive lock before
  reading any state and holds it for its life (§7), so a second daemon on
  the same data home fails at start and says who holds it; a listener
  address already in use fails its bind and says so. Nothing is namespaced
  automatically, because a second node's resources are the operator's
  decision and a derived default would hide where a node's state lives.

  Reason for the form: test and
  measurement runs start a second daemon of the same network beside an
  installed one, as one user, and without a named form the start-up
  refusal (§4.5) would stop them. The name is the operator's label, not a
  nettype; the network id still keys the rendezvous, through the hash
  (rule 71). **RULED (2026-10-09):** the name is 1 to 16 characters from
  `[a-z0-9-]`, and its first character is a letter or a digit. The reason
  is typeability: an operator types this name on a command line and reads
  it in a log. It is **not** a path-safety rule — since RT-O10 a name
  reaches no path on any platform. `default` is **reserved and refused by
  name**, because it would be confused with the default instance; nothing
  else is reserved. Anything refused is refused at start with the rule
  stated, never sanitised or truncated.

  **Invariant (decision authority, 2026-10-09): an instance name never
  becomes a filesystem path component or an IPC object name.** A socket, a
  rendezvous file, a pipe, a lock, shared memory, a log file — each uses
  the RT-O10 derivation, never the name itself. This is what makes the
  name rule a typeability rule and nothing more: no character an operator
  could type can reach the filesystem or an IPC namespace, so there is no
  list of dangerous names to keep. The earlier reservation of the Windows
  device names (`con`, `prn`, `aux`, `nul`, `com0` to `com9`, `lpt0` to
  `lpt9`) is **struck**: it guarded a directory named after the instance,
  and no such directory exists.

  **Operator-facing registration names may carry the instance name
  directly** — a Windows service name, a systemd unit name. The instance
  character set is already valid in both, and the operator must be able to
  read them: a service list that showed a hash would not say which node it
  is.
- **Start-up dial on Unix.** The Windows start-up rule above applies here
  unchanged: before publishing, dial an existing socket — it answers, so
  another daemon is running, refuse and say so; nothing listens, so it is
  stale, replace it; it fails the owner check, report it. A bare
  "address in use" cannot tell a live daemon from a leftover file.

---

## 8. `shekyl-rpc-tunnel` (ruled 2026-10-09)

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
  (RT-P6), not guessed. RT-P6's input to it (ruled 2026-10-20): a session
  costs the tunnel about 2.16 ms of CPU on the floor device to open, and
  the daemon the same.

Any local user on the consumer's host can use its loopback port. Where the
consumer can speak to a socket, the tunnel offers one (R0 §1.1's
construction) instead of loopback TCP.

---

## 9. Probes (pre-registered)

| # | Question | How | Revisits on failure |
|---|---|---|---|
| RT-P4 | Is ML-KEM-768 decapsulation in the pinned crate constant-time with respect to the ciphertext, including the implicit-rejection path? | Statistical timing test (dudect-style) over valid, invalid, and adversarially structured ciphertexts on the floor device and on x86, plus a source read of the decapsulation path for secret-dependent branches and divisions. **Met 2026-10-11** under a re-registered method, on the floor device and on a Tiger Lake laptop core; the first registration's floor-device run failed and was traced to its harness (`docs/benchmarks/rt_p4_mlkem_decaps_timing_20261010.md`, `docs/benchmarks/rt_p4_mlkem_decaps_timing_20261011.md`). **Standing check, gated from RT-W9 step 6** (`scripts/ci/check_rt_p4_standing.py`, in the bundled grep gates): it reads the toolchain, the lock-file closure of `fips203` (the crates in the decapsulation image), the recognised keys of `[profile.release]`, `cmake/BuildRust.cmake`, the gitian descriptors and `rust/.cargo/config.toml`. Anything it does not recognise fails on its own and is not also a re-run. It compares each attested run (`docs/benchmarks/rt_p4_attestation.toml`) with the recognised snapshot for its target, and every target that carries rustflags is either one of those runs or an explicit unmeasured row. The laptop's run predates `+crt-static` on the MSVC targets (2026-10-19). The re-run with the shipped flags failed its lines on 2026-10-25 ([`rt_p4_mlkem_decaps_timing_20261023.md`](../benchmarks/rt_p4_mlkem_decaps_timing_20261023.md): `valid-vs-invalid` `|t|` 25.43, `fixed-vs-invalid` 21.72, about 16 to 18 ns at the fastest decapsulations), with the decapsulation code identical by disassembly to the passing build's. **Ruled 2026-10-25:** the difference is an observed platform property, accepted under §4.3's bounds, and **RT-P4 stays met** on the identical code and the floor device's run. The standing check accepts a build whose decapsulation code is disassembly-identical to an attested run, with the comparison committed; a change to that code needs a timing run. At its next required run, the pass line is invalid-vs-invalid differing only in the decrypted message, with valid-vs-invalid reported as information | §4.3; the crate choice for the channel's static key |
| RT-P5 | Does hyper/axum run over the record channel at full RPC load? | Two registered parts (RT-O21, sequencing re-ruled 2026-10-12). The size distribution is HTTP message sizes per method on the generated traffic, and the classes are derived from it. The adapter is `shekyl-rpc-stream` over `ClassedRecord`, not the interim framer: a block-batch response larger than one record, backpressure under a slow reader, half-close, a request split across records, observed failing with splitting removed. The flush policy is named in the registration; the record boundaries it produces are observed with the adapter. **Sizes part measured 2026-10-17** ([`rt_p5_rpc_message_sizes_20261017.md`](../benchmarks/rt_p5_rpc_message_sizes_20261017.md)): candidate tables for K = 1 to 8, with K = 3 ruled 2026-10-18 (RT-O6); the record also finds that, in the request direction, every K ≥ 2 puts at least one record of every submission in a class no other request uses (at K = 2 the class-union with every other request is one tail in the smaller class), and for K ≥ 3 a submission's classes are shared with at most two other requests and with none for K ≥ 6, against RT-O6's stated mechanism. **Record-boundaries part observed 2026-10-20 in RT-W9 step 5b** with `shekyl-rpc-stream` through hyper (§4.4): hyper flushes once per message in both directions, the registered flush policy (`hyper_flushes_once_per_message`), and the named edit, splitting removed, fails the block-batch test | RT-W9's adapter design |
| RT-P6 | What does a handshake cost on the floor device (Pi 4), each side? | Time each message and the whole handshake, daemon and client, on the floor device; CPU per unauthenticated message 1; the cost of sealing and opening one record at each response class RT-O6 ruled on 2026-10-18: 512, 16,384 and 65,535 bytes. A submission padded to its fixed size is whole 65,535-byte records and a tail, so its cost follows from the largest class's. **Measured 2026-10-19 on the floor device** ([`rt_p6_handshake_cost_20261018.md`](../benchmarks/rt_p6_handshake_cost_20261018.md)): both sides about 2.16 ms of CPU per handshake, 4.3 ms together at the 99th percentile; a stranger's message 1 costs the daemon 818.5 µs at the 99th percentile; the handshake deadlines come from measured onion and clearnet round trips (RT-P9), not from this run (ruled 2026-10-20); the amplification is answered by mac1 and a handshake budget sized from it (§4.3); the client's 2.16 ms is an input to RT-W11's pool. **The stranger re-measured with mac1 on 2026-10-20** ([`rt_p6_mac1_stranger_20261020.md`](../benchmarks/rt_p6_mac1_stranger_20261020.md)): a message 1 without the bundle costs the daemon 34.1 µs at the 99th percentile, refused at mac1; the daemon's whole handshake with mac1 is 2,163.8 µs, the cost the budget now charges | §4.3's amplification bound and the handshake budget's charge; the tunnel pool size (RT-W11). The handshake deadlines come from RT-P9, not from this probe |
| RT-P7 | Does `hybridXK`'s canonical token order (§4.1) reach the property each stage claims? | ProVerif model: daemon authentication at message 2, client authentication classical at message 3 and hybrid at the first record, secrecy of the transport keys, client-identity hiding — each query observed **failing** under a named edit (e.g. remove `skem` from message 1; move it after `e`; remove `se` from message 3) before its success is trusted | §4.1; **gates RT-W9** |
| RT-P8 | Windows: does RT-15's same-user pipe and RT-16's service shape hold on a real box? | Windows lane, on the built daemon: (1) the GUI dials its `shekyld` child through the rendezvous file and the peer check passes; (2) another user's pipe pre-created under a guessed daemon-style name has no effect on startup or dial; (3) a same-user client in a second logon session is refused by the pipe and the client reports it from the rendezvous without dialling; (4) every Windows-side caller of the daemon RPC (GUI backend including its mining control, `shekyld <command>`, the wallet stack) is named with its leg; (5) per-service virtual account: network access, restricted service-SID type, minimal required-privilege list, the bundled Tor as its child; (6) the `%ProgramData%` data home is created with its owner and protected DACL in one `CreateDirectoryW` call, reads back as admitting the service account and Administrators only, and an unelevated process racing the creation cannot place an entry inside; (7) the side-by-side refusal between the two modes | RT-15, RT-16; RT-W10; RT-W14 |
| RT-P9 | How long does the handshake take on a real network leg to the floor device, over Tor and over a LAN? | The real handshake, mac1 and the budget in place, one TCP connection per sample from the development workstation to a daemon role on the floor device: through Tor to a temporary onion service, each connection on its own circuit, and directly over the LAN, 300 each. Each side stamps each message; the daemon's clock starts at `accept`. **Registered and run 2026-10-20** ([`rt_p9_handshake_round_trips_20261020.md`](../benchmarks/rt_p9_handshake_round_trips_20261020.md)), with the derivation fixed before the run: each deadline is twice the onion leg's 99th percentile from `accept`, rounded up to a whole second, the LAN figure beside it. **Attempt 2 met its gates:** message 1 within 4 s (onion p99 1,803.4 ms; LAN 0.7 ms), the whole handshake within 11 s (onion p99 5,231.9 ms; LAN 8.6 ms). Attempt 1 was void: the client looped without pause on the LAN and the handshake budget dropped part of it, as designed | The message-1 deadline and the whole-handshake deadline (derived from this, not chosen) |

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
  owned by Administrators, created **with** its protected descriptor and
  not tightened after creation (RT-16 — ruled, and still design reasoning
  rather than measurement: the ownership point and the atomic creation are
  what RT-P8 item 6 has yet to observe). The lane's own
  run broke inheritance after creating the directory, which is the order
  RT-16 now rules out. The real service ACL is unrun (needs elevation).
- **Not runnable yet:** item 1 is blocked on RT-W10 — no rendezvous exists
  in the tree, and the lane declined to substitute a model and report it as
  item 1; item 7 is unimplemented.

## 10. Open items

Every item is ruled. What message 4 carries is RT-O30 (§6.2), ruled
2026-10-25 with the rest of the RT-W10 pre-flight's questions.

- **RT-O30…RT-O36 — the RT-W10 pre-flight's questions. RULED 2026-10-25**
  ([`RPC_CHANNEL_RT_W10_PREFLIGHT.md`](RPC_CHANNEL_RT_W10_PREFLIGHT.md) §4).
  Message 4 carries the ceiling; the payloads are 16 fixed bytes; a
  connection's grant is stamped on each request, from one route-to-grant
  table checked exactly once by a test; plaintext loopback keeps its
  method set until RT-W12, the console moving to the socket in RT-W10; the
  key and the enrolments live in the data home; the service-mode pieces go
  with RT-W14; the armed switch is network-restricted, not
  network-selected (§6.1).

`RT-O23…RT-O27` were ruled 2026-10-14 and are recorded in §6.4.

- **A finding against WP-D8, owned where WP-D8 lives.** The same
  `create_owner_only_file` writes the **exported seed file** with no
  mandatory label, and the measurement behind §7.1's label rule says a
  same-user low-integrity process can read a file with that descriptor.
  The wallet pipe already refuses such a caller, so it is inside that
  round's threat model. This round does not rule on it. It is recorded in
  the owning text — [`WINDOWS_WALLET_SUPPORT.md`](WINDOWS_WALLET_SUPPORT.md)
  WP-D8, reopened 2026-10-09 with the measurement and the proposed fix —
  and carried in `FOLLOWUPS.md` under that document.
- **RT-O6 — length concealment. RE-RULED 2026-10-18 on RT-P5's evidence
  (§4.4):** response records in three classes, 512, 16,384 and 65,535
  (RT-P5's `K` = 3 boundaries rounded up to powers of two, capped at the
  maximum record); a submission padded to the largest possible transaction;
  a submission's timing stays visible, mitigated by a same-host wallet or
  an onion endpoint, with submission slots the designed answer for its
  rule-21 reopen. **RULED 2026-10-09:** in scope, as bucketed
  padding in the record layer. **RE-RULED 2026-10-12 (PR #1034):** the
  shared piece is `Direction`, not one framer with a mode. `ClassedRecord`
  is the channel's framer; `FixedWindow` is the P2P end state and is not
  built in RT-W9. Class sizes from RT-P5; timing stays visible,
  cover traffic out of scope with a rule-21 reopen. Recorded in §4.4.
- **RT-O7 — the pattern and its vectors. RULED 2026-10-09:** the pattern
  is clatter's `hybridXK` in its canonical token order, and the claim rests
  on three anchors — the community XK vectors, byte equality with clatter
  under shared seeded randomness, and the ProVerif model. The test-only
  second implementation proposed earlier is withdrawn; clatter replaces it,
  test-only, with a gate asserting it is in no production dependency graph.
  Recorded in §4.1. Implementation hazards already known and unchanged: the
  `fips203` `DummyRng` issue pinned around in
  `shekyl-crypto-pq/Cargo.toml:55-58`; RT-P4.
- **RT-O8 — the `https://` arm of the daemon client. RULED 2026-10-09:
  deleted, in RT-W12.** No supported posture uses TLS to a daemon; its only
  use was R0's reverse-proxy remote story, which the channel replaces.
  Deleting it before the channel client exists would strand that path, so
  the deletion lands with RT-W12 and not before. It removes `hyper-rustls`
  and native-roots loading from the wallet's dependency graph
  ([`http_client.rs:240-266`](../../rust/shekyl-rpc-transport/src/http_client.rs)).
- **RT-O10 — the rendezvous name. RULED 2026-10-09: a hash of network and
  instance, on every platform.** It began as the Unix socket path: the
  readable layout fit Linux and exceeded the macOS limit even for the
  default instance. The ruling is wider than the problem that raised it.
  The Unix socket and the Windows rendezvous file are both named
  `shekyl-<name>`, with `<name>` from one function under
  `shekyl/rpc-rendezvous-name-v1` and one known-answer test, and so is the
  service-mode rendezvous in the service's data home. An instance name
  reaches no path anywhere (58 of 108 bytes on Linux, 86 of 104 on macOS);
  §7.1 states that as an invariant, and the Windows device-name
  reservation it made unnecessary is struck. The daemon's start-up log and `shekyld status` print the same
  network, instance and path line. The hash is 12 bytes, 24 hex characters. The
  macOS base length is still unmeasured; the margin is 18 bytes. Recorded
  in §7.1.

- **RT-O9 — the grant table. RULED** in four parts on 2026-10-08
  (`RT-O9.1`…`RT-O9.4`: `enrol` its own grant; test levers in no grant;
  anonymity data host-only; cost a separate resource policy) and whole on
  2026-10-09: the assignment of §6.1, its presets, the changes from today's
  gate, the revocation bound (§5) and the arming switch for the test
  levers. Recorded in §5, §6.1 and §6.3. Two things it leaves are work,
  not questions, and each has an owner:
  - **RT-W12** shows that the wallet engine pages its requests within
    §6.3's batch caps. Today those caps bind only the restricted listener,
    so the engine has not met them on its usual connection; a remote wallet
    on the channel will.
  - **The incident's consumer** is enrolled for `peers` to keep its
    seed-node count, or drops the count. That is its operator's choice at
    enrolment, which is what the grant model is for.

- **RT-O11…RT-O15 — the RT-W8 pre-flight's questions. RULED 2026-10-09**
  ([`RPC_CHANNEL_RT_W8_PREFLIGHT.md`](RPC_CHANNEL_RT_W8_PREFLIGHT.md) §4).
  **RT-O11:** RT-W8 pins vectors from clatter and RT-W9 compares our
  handshake against them (§4.1). **RT-O12:** clatter 2.3.0 from crates.io,
  test-only, in one `publish = false` cross-check crate behind a
  production-graph gate (§4.1). **RT-O13:** the channel crate,
  `shekyl-rpc-channel`, is created in RT-W8 holding the three constants and
  the two naming functions; RT-W9 adds the handshake. **RT-O14:** the byte
  encodings of the prologue, the rendezvous name and the static fingerprint
  (§4.4, §5, §7.1). **RT-O15:** the ProVerif model lives in the channel
  crate with a runner and a CI job that fails if a property fails or a
  deliberately broken variant passes.
- **RT-O16…RT-O22 — the RT-W9 pre-flight's questions. RULED 2026-10-11;
  RT-O16, RT-O18, RT-O20 and the sequencing of RT-O21 RE-RULED 2026-10-12
  (PR #1034).**
  ([`RPC_CHANNEL_RT_W9_PREFLIGHT.md`](../completed/RPC_CHANNEL_RT_W9_PREFLIGHT.md) §4).
  The re-rulings are what is built. **RT-O16 — SUPERSEDED, the
  test-support feature:** the pinned vector assertions stay in
  `pinned_messages_mix_steps_and_rekey` (`noise.rs`); the key-schedule
  assertions moved with `Direction` and stay `#[cfg(test)]` inside
  `shekyl-noise`. No feature exports a traffic key. **RT-O17:**
  `SymmetricState` is in `shekyl-noise` and takes the protocol name as a
  parameter. The crate also holds `Direction`. A handshake ends in
  `SymmetricState::into_directions`. It does not hold the interim framer. **RT-O18 — SUPERSEDED, the test-support entry:** the
  comparison is an in-crate test with a private constructor; one generator
  source is compiled into that test and into the cross-check crate;
  production construction takes no generator; clatter stays in the
  cross-check crate alone. **RT-O19:** the handshake lives in
  `shekyl-rpc-channel`; the stream adapter is `shekyl-rpc-stream`.
  **RT-O20 — RE-RULED:** `ClassedRecord` carries one masked `ClassId` byte
  on every table, specified in §4.4; `FixedWindow` is a separate type and
  is not built here; rekey stays at `REKEY_NONCES` until the P2P round
  decides for both. **RT-O21:** HTTP message sizes per method are measured
  before the adapter exists; record boundaries are observed from
  `ClassedRecord` under the registered flush policy; a generated wallet
  syncs a generated regtest chain of full-size transactions. The classes
  ship from that trace and are derived again when a mainnet RPC trace is
  registered in the measurement ledger. **RT-O22:** the RT-P4 standing
  check also attests the release build's codegen settings. Two registry
  rows, one reason, for the two protocol-name literals.
- **RT-O28 and RT-O29 — RT-W9 step 5's questions. RULED 2026-10-20**
  ([`RPC_CHANNEL_RT_W9_PREFLIGHT.md`](../completed/RPC_CHANNEL_RT_W9_PREFLIGHT.md)
  §4a). **RT-O28:** a submission is padded by the adapter, at the client's
  request, to a fixed count of largest-class records, padding sealed
  before the payload. **RT-O29:** one class table in both directions.
  Recorded in §4.4.
- **RT-W9's close-out — RULED 2026-10-22.** The busy back-off waits are
  confirmed, each drawn uniformly from `[b/2, b]` from the OS random
  source (§4.3). The registry gate gains a call-site pin for mechanism 7,
  so an unregistered label fails it. RT-O22's codegen standing check
  reads every flag source (`rust/rust-toolchain.toml`, the lock-file
  closure of the ML-KEM crate, `[profile.release]`, `cmake/BuildRust.cmake`,
  the gitian descriptors and `rust/.cargo/config.toml`) and fails on any
  key or flag it does not recognise; an unrecognised key is not also a
  re-run. Its attestation file is seeded with the flags exactly as
  attested, a rustflags target with no run is named there, and RT-P4 is
  re-run on the Windows laptop with the shipped flags. **Ruled
  2026-10-25:** the time-bound message 1 is not built; it is out of scope
  (§12).

---

## 11. What this round supersedes

Two kinds of thing, removed at two different times. A design that has been
re-ruled is deleted from the design corpus with the ruling. A description
of code stays true until the code changes, so it leaves with the slice that
changes the code.

### 11.1 Swept from the design corpus with the ratification (2026-10-09)

Deleted, not annotated: the history is in git, and §12 carries the
one-line reason for each rejection.

- `RPC_TRANSPORT_POSTURE.md`: RT-4's mechanism and its PSK / pinned-cert
  table; the TLS-specific wording of RT-5 and RT-6, whose requirements — no
  early data, no downgrade — carry to the channel; RT-1's scope, narrowed to
  plaintext listeners (RT-14); RT-9's restricted-listener half; §1.1's
  third transport; and the RT-W4 and RT-W6 slice rows, now marked
  superseded so that nobody reads them as open work. R0's premise, threat
  model and landed slices are untouched.
- `IMPLEMENTATION_INDEX.md`: the `RT-` row says ruled.

*Removed since, by its slice:* `shekyl-rt-p2-spike`, the pinned-mutual-TLS
probe crate R0 marked disposable — deleted in RT-W8.
`shekyl-engine-core/src/engine/stake_engine/serving/daemon_tip.rs` no longer
reads `get_info.restricted`; the peer check reads `has_peers`
(`shekyl-engine-core/src/engine/stake_engine/serving/daemon_tip.rs:280`,
RK-5c commit 7, 2026-10-10). RT-W13 confirms the read is gone.

### 11.2 Still true today; removed by the slice that changes the code

| What describes today's code | Removed by |
|---|---|
| `DAEMON_RPC_RUST.md`: "Restricted RPC stays", "Restricted Mode", and the local and remote rows of the auth table | RT-W10 |
| The `removed_flags.cpp:189-190` message; `--restricted-rpc`, `--rpc-restricted-bind-port`, `--rpc-restricted-bind-ip`, `--rpc-restricted-bind-ipv6-address` (`rpc_args.{h,cpp}`, `core_rpc_server.cpp`, `daemon.cpp`). The plaintext bind flags are re-scoped to the `view` loopback listener and their parsing moves out of C++ `rpc_args` into `shekyl-daemon-rpc` (§7) | RT-W10 |
| The callers that **pass** those flags: `shekyl-gui-wallet` starts its daemon with `--restricted-rpc` (`src-tauri/src/daemon_manager.rs:115`), and the regtest end-to-end harness starts a second listener with `--rpc-restricted-bind-port` (`engine/regtest_e2e.rs`, `start_with_restricted_listener`). Each gets its replacement in the commit that deletes the flag, or the GUI's daemon and those tests stop starting | RT-W10 |
| `bind.rs`'s refusal text and its two tests that assert the onion remedy | RT-W10 |
| `ctl_client.rs`'s plaintext loopback-TCP path: `shekyld <command>` moves to the owner-only socket or pipe for a run-as-me daemon, and to the channel with the console key for a service (RT-15, §5) | RT-W10 |
| `shekyl-cli/src/commands/mine.rs:68`: the "restricted listener" refusal becomes a check for `mining-control` in the grant the handshake returned | RT-W10 |
| The daemon client's `https://` arm (`rust/shekyl-rpc-transport/src/http_client.rs:240-266`), and with it `hyper-rustls` and native-roots loading in the wallet's graph — not before the channel client exists (RT-O8) | RT-W12 |
| Shipped Windows guidance that points operators at Task Scheduler (`removed_flags.cpp:159-161`, `INSTALLATION_GUIDE.md:229-235`): replaced by RT-16's two run modes (the scheduled task is rejected, §12) | RT-W14 |

RT-W13 is the check that this table is empty: every row above gone, and
no reader of a deleted flag or field left in the tree.

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
- **Our own token order for the hybrid pattern** (`-> e, e1, es, skem`, in
  this round's first draft). It put `skem` after the public keys, against
  PQNoise's ordering rule, and it was a composition nobody else
  implements. The canonical `hybridXK` order is adopted (§4.1, RT-O7).
- **A test-only second implementation as the differential.** Two
  implementations by one team share one team's reading of the pattern;
  clatter is independent (§4.1).
- **clatter, or any Noise library, as a production dependency.** Read, not
  depended on (PW-7a's posture for `snow`); test-only, with a gate.
- **Leaving record sizes visible**, and **cover traffic** to hide timing.
  The first leaks when a wallet sends; the second is out of scope with a
  named reopen (§4.4, RT-O6).
- **A time-bound message 1 — REJECTED 2026-10-25.** A coarse epoch under
  mac1, a store of every mac1 in the accepted span that never evicts and
  answers busy when full, and a mac1-keyed clock reply. It defends only
  against a path observer replaying captured message 1s to deny service
  on a leg §1 does not recommend (§4.3). The project ships a channel whose
  residual is absent in the postures §1 names, and does not design against
  an operator's choice to run outside them: building for every such choice
  adds complexity that weakens the design for everyone. Out of scope, not
  deferred. **Reopen (rule 21):** a posture §1 recommends no longer
  conceals the handshake bytes from a path observer. The decision authority
  re-rules in this section; no symbol is minted until then.
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
- **A readable socket path** — `<base>/shekyl/<network>/<instance>/rpc.sock`.
  It exceeds the macOS path limit even for the default instance (RT-O10).
- **A shortened network component on macOS only.** It fits with five bytes
  to spare against an unmeasured base length, and gives the two Unix
  platforms different layouts for one mechanism.
- **A list of reserved instance names for path safety** (the Windows
  device names). A list guards one known hazard and misses the next; the
  invariant that a name never becomes a filesystem path component or an
  IPC object name removes the hazard class (§7.1). `default` stays reserved for a
  different reason: confusion with the default instance.
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
- **An `anonymity` grant** holding the stem tallies and unrelayed pool
  entries, for measurement tooling. A grant can be put in a ceiling and
  used from another machine; no remote job needs this data, and it is what
  Dandelion++ hides. It is host-only, not a grant (RT-O9.3, §6.1).
- **Enrolment inside `node`.** A `node` holder could enrol itself an
  `admin` key and step around every other boundary (RT-O9.1).
- **Encoding cost as authority** — keeping `get_coinbase_tx_sum` and
  `calc_pow` admin-only because they are expensive (RT-O9.4, §6.3).
- **A reload signal or editable file for the enrolled set.** A revocation
  that waits for a reload is a revocation that can be forgotten (§5).

---

## 13. Slices (ruled; authorized one at a time)

The slices are part of the ruled design. Ruling them does not start them:
each is authorized on its own, by the decision authority, and has its own
rule-26 pre-flight before its first production commit.

**Order (ruled 2026-10-25).** The RT-W9 close-out; RT-W10's pre-flight and
its authorization; RT-W10; RT-W11; then RT-W12, RT-W13 and RT-W14. The
Foundation daemon reaching the website, the problem that started this
round, needs only RT-W10 and RT-W11, so the wallet and engine clients
(RT-W12) come after them, and **RT-W12 follows RT-W11 directly** (RT-O33,
ruled 2026-10-25): until RT-W12 moves the clients to the same-user socket,
the plaintext admin listener on loopback is reachable by any local user,
not only the daemon's owner.

| Slice | Contents | Depends on | Authorization |
|---|---|---|---|
| RT-W8 | RT-P7 model on the canonical order; the three anchors of §4.1 — community XK vectors, vectors pinned from clatter 2.3.0 under seeded randomness, which RT-W9 compares our handshake against (RT-O11), each observed changing under a named edit; the gate asserting clatter is in no non-dev dependency graph; registry rows, including `shekyl/rpc-rendezvous-name-v1` with its known-answer vector pinned before the naming function is written (rule 30); RT-P4; creates `shekyl-rpc-channel` with the constants and naming functions (RT-O13); deletes `shekyl-rt-p2-spike` (§11.2) | ratification (given 2026-10-09) | **Authorized 2026-10-09.** Pre-flight: [`RPC_CHANNEL_RT_W8_PREFLIGHT.md`](RPC_CHANNEL_RT_W8_PREFLIGHT.md) |
| RT-W9 | `shekyl-noise` holds `SymmetricState` and the typed `SendDirection` and `RecvDirection` (pinned handshake vectors untouched; the interim framer stays in `shekyl-p2p-transport`); the `hybridXK` handshake; `ClassedSealer` and `ClassedOpener` and the stream adapter `shekyl-rpc-stream` (RT-P5); padded records in size classes derived from RT-P5 (RT-O6). `FixedWindow` is the P2P end state and is not built here. Two exclusion rows in the domain registry, one shared reason, for the two Noise protocol-name literals — the RPC channel's and the P2P handshake's — which are mixed into a handshake hash and are standard pattern names, not Shekyl domain strings; the header-protection label `shekyl/noise-record-header-v1` is a separate mechanism-7 row, landed with the constant; the handshake's deadlines from RT-P9 (4 s for message 1, 11 s for the whole handshake, `shekyl_rpc_channel::deadline`). From RT-P6's follow-through (§4.3, ruled 2026-10-20): mac1 on message 1 (`shekyl/rpc-mac1-v1`), the handshake budget (a quarter of one core, 115 handshakes a second), the busy reply (`shekyl/rpc-busy-v1`) and the replay window. The client's retry policy (`shekyl_rpc_channel::retry`): one silent retry after a timeout, and a jittered back-off after busy (§4.3). The replay residual on a leg that can read the handshake is the operator's (§4.3, §12). **Standing check, from RT-W9 on (ruled 2026-10-11):** the RT-P4 harness is re-run under the same registered lines whenever the decapsulation closure of the ML-KEM crate or the Rust toolchain changes, and a gate attests the release build's codegen settings from every flag source (RT-O22; §10, 2026-10-22) | RT-W8 | **authorized 2026-10-11, decision-anchored to PR #1034**; pre-flight [`RPC_CHANNEL_RT_W9_PREFLIGHT.md`](../completed/RPC_CHANNEL_RT_W9_PREFLIGHT.md); `RT-O16`…`RT-O22` ruled 2026-10-11, and `RT-O16`, `RT-O18`, `RT-O20` and the sequencing of `RT-O21` re-ruled 2026-10-12; step 1 is built (`SymmetricState`, `Direction`, `into_directions`); step 2 is built in PR #1039: the `hybridXK` handshake in `shekyl-rpc-channel`, ending in `into_directions`, compared with the pinned vectors from `rust/shekyl-rpc-channel/src/pinned_handshake.rs` (RT-O18); step 5a builds `ClassedRecord` in `shekyl-noise` (2026-10-20); step 5b builds `shekyl-rpc-stream` (2026-10-20), to RT-O28 and RT-O29 as ruled in the pre-flight's §4a; mac1, the budget and busy are built in PR #1137 and the deadlines and retry policy in PR #1139 (2026-10-20); the close-out of 2026-10-22 is built in PRs #1156 (the stream), #1159 (the noise crate and handshake), #1163 (these docs) and #1173 (step 6: the two exclusion rows, the mechanism-7 call-site pin and the standing-check gate, which passes with the laptop's shipped build attested by its committed disassembly comparison, RT-P4 staying met, §4.3, §9 RT-P4); the time-bound message 1 is out of scope (ruled 2026-10-25, §12). **LANDED 2026-10-25** |
| RT-W10 | Daemon: same-user socket/pipe and rendezvous, the daemon watching its own rendezvous and shutting down when it goes, the operator-named socket directory, the instance-name rule (§7.1), channel listener, enrolment and revocation, per-connection grants, the host-only class and the armed test-lever switch (§6.1), the resource policy and its floor-device measurement (§6.3); the `restricted` flag deleted from the Rust handlers and the FFI (the restricted listener's C++ flags went on 2026-10-15, in the daemon-configuration cutover); plaintext loopback re-scoped to `view`. **The listener logs a connection, counts it against a client and records a last-seen time only from the authenticated client `AuthenticatedSession` yields, never from the fingerprint `DaemonReadyForMessage4` exposes for the enrolment lookup (§4.1, ruled 2026-10-12).** A copied fingerprint is still only a claim. Its pre-flight settles what message 4 carries (§6.2). **The `submit_transaction` route fails closed on the record shape (close-out F2, 2026-10-22):** it refuses any body for which the connection's `InboundShape::ends_in_submission` is false when the body has been read, so a client that did not pad, or armed another connection, is refused rather than answered. **For its pre-flight (close-out, 2026-10-22):** message 3 has no upper length bound (`handshake.rs:716` checks only the minimum); §6.2 rules the message-3 and message-4 payloads fixed-length, so once the grant encoding is fixed the handshake takes the exact lengths as constants, refuses any other length, and the listener knows how many bytes to read; the listener's read bounds; the 4 s and 11 s deadlines in the accept loop; mac1, the budget and busy, wired through | RT-W9, **RT-O9**, RT-P8, **RK-5c** (`get_info` native, §6.1; met 2026-10-13) | **authorized 2026-10-25**; pre-flight [`RPC_CHANNEL_RT_W10_PREFLIGHT.md`](RPC_CHANNEL_RT_W10_PREFLIGHT.md), RT-O30…RT-O36 ruled 2026-10-25; five steps, one pull request each; step 1 (grants as types, the armed switch) built in PR #1197 (2026-10-26) |
| RT-W11 | `shekyl-rpc-tunnel`, with session pooling; the pool sized with RT-P6's cost of a session as an input, about 2.16 ms of CPU each side on the floor device (§8, ruled 2026-10-20). **Client contracts for a submission (close-out F2, 2026-10-22):** the tunnel holds its own connections (hyper's `client::conn::http1`, not the pooled `Client`) and arms `SubmissionMark` on the connection it sends the submission on, and that connection carries nothing else until the response; the submission body is one complete, buffered body (`Full`), never a streaming one | RT-W9 | not authorized |
| RT-W12 | Clients on the channel: the engine's daemon client and `shekyl-wallet-rpc` (L1); `shekyl-cli`, once it serves the console on the shared client (RT-W15); `shekyl-gui-wallet`, which dials `HttpRpc::new` directly (open since R0's RT-W7 landing review, `RPC_TRANSPORT_POSTURE.md` §7 RT-O4); `shekyl-mobile-wallet`; **deletes the daemon client's `https://` arm**, `hyper-rustls` and native-roots loading with it (RT-O8); shows the engine pages its requests within §6.3's batch caps (RT-O9). **Client contracts for a submission (close-out F2, 2026-10-22):** each client holds its own connections (hyper's `client::conn::http1`, not the pooled `Client`) and arms `SubmissionMark` on the connection it sends the submission on, and that connection carries nothing else until the response; the submission body is one complete, buffered body (`Full`), never a streaming one | RT-W9 | not authorized |
| RT-W13 | The check that §11.2 is empty: every row gone, no reader of a deleted flag or field left | lands with RT-W10; re-run after RT-W12 and RT-W14 | not authorized |
| RT-W14 | Service mode (RT-16): the declared-mode switch; console key and its offline reset; enrol at install; machine-wide rendezvous; Windows service under a virtual account and its installer step (service first, fresh data home never adopted, inheritance broken); Linux unit under a dedicated user; machine-wide data home and ACL; Tor as the service's child; side-by-side refusal | RT-W10, RT-P8, the Rust process entry (the daemon-configuration cutover, PR #1066) | not authorized |
| RT-W15 | R8: `shekyl-cli` serves the daemon console (`INPUT_GRAMMAR.md` §13), on `shekyl-rpc-client` and `shekyl-rpc-types` (RK-D1, `RPC_WIRE.md`); the Rust console's renderers move into it with their tests; its private HTTP client, its reply types and its free-text status matching go; the C++ console, `shekyld <command>`'s client mode and `rpc_client.h` are deleted | — | authorized 2026-10-17 |
