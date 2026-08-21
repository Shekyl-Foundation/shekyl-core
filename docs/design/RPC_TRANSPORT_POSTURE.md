# RPC transport posture

**Status:** R0 — **RULED 2026-08-21.** RT-1…RT-9 ratified as written; RT-O3
and RT-O4 ruled (§7); RT-O2 closed as a corrected error; RT-O1 stays a
probe whose result cannot move the mechanism (§7.1). **RT-W1 landed** with
this round; RT-W2, RT-W5 and RT-W7 are authorized; RT-W3 starts now.
**Verified against:** `shekyl-core` @ `abb4e58dd` (PR #526 head). Every
`file:line` below was read at that commit; the draft's anchors were against
the pre-#526 layout and are re-anchored here.
**Token family:** `RT-`, registered in `IMPLEMENTATION_INDEX.md` in the
commit that lands this doc (rule 94). Neighbours actually present in the
index as families: `R`, `RF-`, `RP-` (`RPC-` occurs only in prose, not as a
family); `RT-` is free.
**Decision authority:** Rick. Review notes from the landing pass are marked
**Review note** and are corrections or additions to the draft, not rulings.

---

## 1. The posture, stated once

> **Every Shekyl RPC leg is operator-to-operator. Both endpoints are machines
> the same person controls. The adversary is the network path between them,
> never the peer.**
>
> There is no recommended configuration in which a Shekyl wallet speaks to a
> daemon somebody else controls.

The reason is structural, not a matter of degree. A daemon sees which blocks
a wallet requests, when it requests them, and which transactions it submits.
That is not a leak in a daemon — it is what a daemon is for. No protocol
change, no transport encryption, and no policy statement can prevent a daemon
operator from retaining and correlating what the daemon must be told in order
to serve. Therefore a foreign daemon cannot appear in any recommended posture,
and the software must not make it convenient, discoverable, or advertised.

We cannot prevent a determined user from pointing a wallet at a stranger's
node. We can decline to build the road.

---

## 2. Scope — the three legs

| Leg | Client | Server | Impl today |
|---|---|---|---|
| L1 | `shekyl-cli` / GUI | `shekyl-wallet-rpc` | Rust (`axum`) |
| L2 | `shekyl-wallet-rpc` | `shekyld` RPC | Rust client → C++ server |
| L3 | remote wallet | `shekyld` RPC | Rust client → C++ server |

`ListenAddr` ([`server.rs:54-69`](../../rust/shekyl-wallet-rpc/src/server.rs))
and `AuthConfig` ([`auth.rs:22-33`](../../rust/shekyl-wallet-rpc/src/auth.rs))
are L1's current surface. [`rpc_args.cpp:92-99`](../../src/rpc/rpc_args.cpp)
is L2/L3's.

### 2.1 Explicitly out of scope

**P2P is not RPC.** The peer-to-peer layer talks to strangers by construction;
that is what a blockchain is. P2P adversary-hardening is the Dandelion++ and
Tor-transit work and is governed elsewhere. A reader who takes §1 to mean
"Shekyl never contacts machines you don't control" has misread it. The
accurate form is: **RPC is operator-to-operator; P2P is adversarial by design
and hardened separately.**

**An already-compromised endpoint.** Consistent with the Windows round's §6
ruling: a compromised same-user process at Medium integrity or above, and any
root/Administrator/SYSTEM compromise, are out of scope on both platforms. We
defend the OS's own sandbox boundary, not an adversary who has crossed it.

---

## 3. Threat model — one threat, three legs

Because the peer is trusted by construction (§1) and a compromised endpoint is
out of scope (§2.1), exactly one adversary remains on every leg: **an
attacker with access to the network path between two machines the operator
owns.**

Capabilities assumed: passive observation, active injection, ARP/DNS spoofing,
and possession of any credential that has ever traversed the wire in a
recoverable form.

Where that adversary lives, concretely, and why "it's my own LAN" is not a
mitigation:

- Other devices on the same subnet — IoT plugs, a smart TV, a guest phone, a
  printer. None are hardened; several are unpatchable.
- The router or AP, including one supplied by an ISP.
- Any interface a wildcard bind reaches that the operator did not enumerate:
  a VPN that comes up later, an airport hotspot, a bridge added by a container
  runtime.

**The network being yours is not what provides the security.** This sentence
belongs in the user-facing documentation verbatim, because "it's my own
network" is precisely the reasoning that produces a request for a plaintext
option. (*Landed with RT-W1:* `EXECUTABLES.md` §3 and `USER_GUIDE.md`'s
wallet-RPC section carry the sentence verbatim, in bold.)

---

## 4. Rulings

### RT-1 — Wildcard binds are refused

`0.0.0.0`, `::`, and `[::]` are refused on every RPC listener. A specific
non-loopback address is permitted.

*Rationale.* A wildcard bind is a bind to interfaces that do not exist yet.
Binding a specific address is a decision about a network the operator can see;
binding a wildcard is standing consent to networks they cannot. Refusing it is
not administering the operator's network — it is declining to let them consent
on behalf of their future self. That is also why this is a refusal and not the
daemon's one-time `--confirm-external-bind`
([`rpc_args.cpp:168`](../../src/rpc/rpc_args.cpp)): an acknowledgement given
today cannot cover an interface that appears later.

Note `::` also captures IPv4 via dual-stack on most platforms, so refusing it
is not redundant with refusing `0.0.0.0`.

*Revisits on failure:* nothing. This is unconditional.

**Ruled 2026-08-21 — at startup, not at parse, and not both.** The draft
said "at parse time". RT-W1 enforces it at **startup, before bind, on every
path that binds** — one `validate_listen` consulted by both `run_server` and
`spawn_in_process_with` — rather than in `ListenAddr::parse`. Reason: an
embedder can construct `ListenAddr::Tcp(addr)` without ever calling `parse`,
so a parse-time refusal would cover the CLI flag and miss the API; the bind
seam covers both, and there is exactly one place the rule lives. Not both:
a rule in two places drifts — one gets updated and the other becomes a
second opinion. One seam at the bind, negative-controlled at both call
sites. **Named successor, filed here:** a `ValidatedListen` type — the bind
seam accepting only a value that has passed the refusals, so a third caller
cannot skip them. **Trigger:** a third bind site, or an out-of-workspace
embedder. Until then the two-site negative control is the check. The
IPv4-mapped spellings (`[::ffff:0.0.0.0]`) are folded by `to_canonical` so
the rule cannot be sidestepped by notation. The tests prove the **wiring**:
a wildcard config is fed to each bind path and must be refused by each, and
both halves were observed red with the call deleted at that site before the
green was trusted.

### RT-2 — Unauthenticated non-loopback is refused

`AuthConfig::Disabled` on any non-loopback bind is a hard refusal, not a
warning. There is no defensible deployment of an auth-less wallet RPC on a
network interface.

*Independent of RT-4.* This lands whether or not the transport work proceeds.
Loopback with auth disabled stays allowed — it is the in-process host's
posture and the OS enforces the machine boundary — and the Unix socket and
the Windows pipe pass through, because their authorization rides the
transport.

### RT-3 — Remote legs are mutually authenticated and encrypted

No cleartext RPC leaves the host. HTTP Basic
([`auth.rs:26-32`](../../rust/shekyl-wallet-rpc/src/auth.rs)) puts the
credential on the wire in **every request**; under §3 that is equivalent to
publishing it. Basic is retained only for loopback and is superseded on
remote legs by RT-4.

### RT-4 — Mechanism: pinned mutual TLS with a server-side fingerprint allowlist

Each endpoint generates its own keypair locally. Public-key fingerprints are
exchanged out of band. The server holds an allowlist of client fingerprints;
each client pins the server's fingerprint. No CA.

**Why not a CA.** A CA exists to delegate trust to parties the root does not
directly enrol. Under §1 every client is a device the operator physically
holds — there is no delegation, only enrolment. A CA would add a long-lived
*issuance-authority* private key that, once created, must be stored, backed
up, rotated, and protected. The allowlist does not protect that key; it makes
it **not exist**. Revocation is deleting a line.

**Why the client generates its own keypair.** If the server mints the client's
keypair, the client's *private key* must travel — QR, USB, copy-paste,
possibly a cloud clipboard. Self-generation means only *public* material
crosses, where interception is harmless. Server-as-root-of-trust is correct;
server-as-key-generator is not.

**Why not external-PSK TLS.** PSK was the first proposal and is rejected on
four counts, each of which pinned certs avoid by construction. Anchors were
read for this document, not remembered:

| Hazard | External PSK | Pinned certs |
|---|---|---|
| Forward secrecy | TLS 1.3 offers `psk_ke` (PSK only) and `psk_dhe_ke` (PSK + (EC)DHE) (RFC 8446 §4.2.9); PSK-only is "at the cost of losing forward secrecy for the application data" (§2.2). `psk_dhe_ke` must be **asserted** on the negotiated connection, not assumed from a library default | always (EC)DHE — no mode to get wrong |
| Wire privacy | the PSK identity is carried in the ClientHello's `pre_shared_key` extension (RFC 8446 §4.2.11), and "TLS does little to keep PSK identity information private … the identifier appearing in cleartext in a ClientHello" lets a passive adversary link connections (RFC 9257 §7) | client certificates are sent after the ServerHello, encrypted — **in TLS 1.3**; see the protocol floor below |
| Reflection | the Selfie attack "reroutes a connection from the client to the server on the same endpoint" and needs an endpoint holding both roles with one PSK (RFC 9257 §4.1) | distinct keypairs per role — no symmetry to exploit |
| Provisioning | TLS 1.3 "mandates that each PSK only be used with a single hash function", and cross-version reuse "may produce related outputs" — hence RFC 9258's importer binding identity, context, protocol and KDF | none |

**Protocol floor — TLS 1.3 only, stated rather than implied (review
correction, 2026-08-21).** The wire-privacy row above holds only in TLS 1.3:
TLS 1.2 sends the client certificate in cleartext, which would hand the
device identity to exactly the passive path adversary §3 names. So RT-4's
mechanism is TLS 1.3 with no 1.2 fallback (RT-6 forbids the fallback; this
names the floor), and RT-P2 does not leave it to a library default: the probe
builds both ends with `with_protocol_versions(&[&TLS13])` and **asserts the
negotiated version** on the live connection. The ratified text depended on
this; it is now written down.

**Review note — citation correction.** The draft attributed the tracking
language to "RFC 9973"; no such clause could be located. The sentence as
quoted is RFC 9257 §7 (*Guidance for External PSK Usage in TLS*), and the
table cites that.

PSK's one advantage — symmetric keys are quantum-resistant, whereas
ECDHE+signature is not — is recorded as a considered trade, not an oversight.
The channel carries a session, not a long-term commitment. *Rule-21 reopen:*
a practical PQ or hybrid TLS path in the chosen stack.

**Scaling note.** Symmetric pinning (each side pins the other's exact cert)
does not scale past two endpoints without N² provisioning. A server-side
allowlist gives the laptop-plus-phone case linear provisioning while keeping
the server as the single root of trust — which was the correct instinct behind
the CA proposal.

**Review note — the daemon precedent.** `shekyld` ruled 2026-07-10 (FOLLOWUPS,
"Daemon Axum: onion-as-remote-RPC") that there is no in-daemon clearnet TLS;
remote is an onion service or a reverse proxy outside the process. RT-4 is
deliberately different for L1 and, if RT-O3 rules "now", for L2/L3: the
wallet RPC holds spend authority and its clients must be *mutually*
authenticated, which a reverse proxy that terminates TLS and forwards
cleartext does not give the process itself. When RT-O3 is ruled, it must say
in one sentence whether the daemon's reasoning transfers.

### RT-5 — 0-RTT is disabled

Early data is replayable by design: it "is not forward secret" and there are
"no guarantees of non-replay between connections" (RFC 8446 §2.3). A replayed
`transfer` is not theoretical.

### RT-6 — No downgrade path

A listener configured for authenticated TLS refuses cleartext and refuses
unpinned TLS. There is no "try TLS, fall back to plain." Any fallback is a
downgrade oracle.

### RT-7 — Enrolment is where the security lives

The pairing step must be short-lived, single-use, bound to the specific
enrolment session, and high-entropy enough to resist online guessing. A
pairing code that is reusable or long-lived is a password with extra steps.

Any secret a human can type is a secret a human will choose. Generated
material only, displayed for transfer (QR / base32); no code path accepts a
user-supplied key or fingerprint typed from memory. (RFC 9257 §4.2 is the
reference for why: with a low-entropy secret "the exhaustive search phase …
can be mounted offline" from one captured handshake; §6 sets the 128-bit
floor. Generated 256-bit material clears it by construction.)

### RT-8 — Tor is a reachability option, not a second security model

Tor onion service is an **additional** listener for the case where the client
is not on the operator's network: NAT traversal, no port forwarding, no
dynamic DNS. It is not a replacement for TCP and not a security upgrade over
RT-4.

Routing a same-subnet hop through three relays is indefensible on latency for
the modal deployment (desktop daemon; laptop and phone on the same LAN), so
**TCP is first-class, not a fallback**.

**RT-4 runs inside the onion service as well.** The failure mode to avoid is
Tor authenticating via onion client auth while TCP authenticates via pinning —
two provisioning flows, two config surfaces, and one of them weaker. One trust
decision, one enrolment flow, regardless of transport.

### RT-9 — `--public-node` and the restricted-RPC listener are removed

[`command_line_args.h:102-106`](../../src/daemon/command_line_args.h) offers
exactly what §1 excludes: "Allow other users to use the node as a remote
(restricted RPC mode, view-only commands) **and advertise it over P2P**." The
restricted-RPC second listener it drives is wired at
[`daemon.cpp:156-176`](../../src/daemon/daemon.cpp).

It defaults false, so this is not a live exposure. It is a documented,
supported, *advertised* path to the excluded configuration — and the
advertising half is the aggravating factor: a node running it becomes
**findable** by strangers rather than merely reachable.

*Rationale by precedent.* This is the `wallet2.cpp` argument. An affordance is
what people reach for regardless of what the documentation recommends, and a
rule enforced by documentation is a check that cannot fail. A
privacy-maximalist chain whose nodes advertise themselves as public remote
endpoints builds the public-remote-node ecosystem by default — the ecosystem
in which users' wallets routinely talk to strangers' nodes.

*Alternative considered and rejected:* keep the capability, remove the
advertising. Rejected because it preserves the road while removing only the
signpost, and because the restricted-RPC listener is the surface that has to
be maintained either way.

**Review note — scope of the removal.** `public_node` is referenced from
**eleven** files at `abb4e58dd`, not two — the first count here said ten and
was corrected by a second enumeration (`public_node|public-node|public_rpc_port`):
`daemon/{command_line_args.h, daemon.h, main.cpp}`,
`rpc/{core_rpc_server.{h,cpp}, core_rpc_server_commands_defs.h,
core_rpc_ffi.cpp, bootstrap_daemon.{h,cpp}}`, `daemon/command_server.cpp`
(help text only), and `utils/python-rpc/framework/daemon.py`. The
bootstrap-daemon path is the client half of the same ecosystem (a node
*using* a public remote) and falls under §1 as well; its disposition was
taken explicitly in PR #533's `20c869b1d` (the forward deleted, with a
rule-21 reopen in `DAEMON_RPC_RUST.md`). RT-W5 enumerates the reference set
first (the Phase-5 lesson: enumerate the set, then verify; never enumerate
the container) rather than deleting the flag and leaving the road.

---

## 5. The gap this creates, named rather than discovered

**A user whose only device is a phone has no supported configuration.** That
population is precisely what drives public-remote-node use elsewhere. §1's
answer — run the daemon on a desktop and reach it from the phone — works for
operators who own an always-on machine and does not work at all for those who
do not.

Three dispositions are available:

1. Accept it as a deliberate product boundary.
2. Solve it later with a light-client protocol.
3. Ship the foreign-node path as unsupported-but-possible, with the §1
   consequences stated at the point of configuration.

**Proposed: (1), with (2) as the named successor.** Under privacy > features
this is defensible, but it must be written down as a decision — otherwise it
is rediscovered as a bug report and answered ad hoc by whoever is on hand.

---

## 6. Sequencing question — L2/L3 are C++ today

`shekyld`'s RPC server is C++ (`src/rpc/`). Adding pinned mutual TLS to the
epee stack is a materially larger lift than adding it to `axum`, and the
daemon RPC has a Rust migration ahead of it. Hardening the C++ path now may be
work that is deleted.

Note L2/L3 are currently **ahead** of L1 on bind safety:
[`rpc_args.cpp:92-99`](../../src/rpc/rpc_args.cpp) already defaults to
`127.0.0.1`/`::1` and already has `--confirm-external-bind` (checked at
[`:168`](../../src/rpc/rpc_args.cpp)) — which `shekyl-wallet-rpc` lacked
entirely until RT-W1, and which RT-W1 now exceeds (refusal, not
confirmation).

*Needs a ruling.* Either harden C++ now, or hold L2/L3 behind the Rust
migration and land RT-1/RT-2 there as a small C++ change in the interim.
(Rule 20's lean: a small C++ *deletion or refusal* is acceptable; a C++
*TLS implementation* is the debt the Rust migration would have to pay down
again.)

---

## 7. Open items

- **RT-O1 — stack probe.** Does `rustls` support external PSK? Provisional
  answer: **no** — resumption PSK only, external PSK long-requested but not
  shipped as of knowledge cutoff; a search found no evidence otherwise. This
  is *not* verified. Under RT-4 the answer no longer gates the design, but
  the probe should still run and be recorded, because "we chose certs" reads
  better with "and here is what PSK support actually was."
  *Also verify:* pinned mutual TLS with a custom verifier under the
  `axum`/`hyper` shape `shekyl-wallet-rpc` uses. Pre-registered as RT-W3's
  table below.
- **RT-O2 — cross-compile consequence. CLOSED 2026-08-21: the premise is
  false.** The draft said `shekyl-wallet-rpc` is cross-compilable from Linux
  today and that TLS would end that. Checked against the lock file
  (`cargo tree -p shekyl-wallet-rpc -i ring`): `ring` is **already** in
  both `shekyl-wallet-rpc`'s and `shekyl-cli`'s graphs, via
  `rustls ← hyper-rustls ← shekyl-rpc-transport ← shekyl-engine-core` — the
  daemon client already speaks HTTPS. Neither crate has ever been
  cross-compilable from this box (the WP-W2 round worked around exactly
  that), and the Windows scouting step runs **natively** on the MSVC runner,
  where `ring` builds. Server-side TLS changes nothing about either. The
  review note that recorded this as a hard sequencing constraint on RT-W4
  was an error — a claim written down without being checked — and is
  withdrawn; RT-P3 goes with it. RT-W4 depends on RT-W3 and ratification,
  nothing else. (Decision authority, 2026-08-21: the premise was asserted
  by the draft's author and hardened in review; both halves owned.)

  **Second-order lesson, recorded because it generalises.** RT-4 was the
  *only* item in this round with a sequencing dependency, and it came from
  a claim nobody checked. **A false constraint is more expensive than a
  missing one**: it reorders work silently and nobody notices, because a
  plan that waits looks like a plan that is careful. A constraint earns a
  place in a slicing table only with the command that demonstrated it.
- **RT-O3 — §6: harden now. RULED 2026-08-21.** RT-W2 lands RT-1 and RT-2
  on the daemon's `rpc_args` at the two confirm gates —
  [`rpc_args.cpp:168`](../../src/rpc/rpc_args.cpp) (IPv4) and
  [`:196`](../../src/rpc/rpc_args.cpp) (IPv6). `--confirm-external-bind` is
  a confirmation gate, not a refusal — with the flag, `0.0.0.0` binds — so
  the daemon is ahead in defaults and weaker in kind. Small, no epee TLS
  surface, and it survives the Rust RPC migration as a spec requirement
  rather than as code to port (rule 20 permits a C++ refusal; it forbids a
  C++ TLS implementation).
  **The 2026-07-10 daemon reasoning does not transfer to RT-4.** That ruling
  was made about a channel whose compromise costs privacy and chain view.
  RT-4 governs L1, where compromise costs **spend authority**, and it
  requires *mutual* authentication — the onion / reverse-proxy answer
  authenticates one direction and leaves client identity to whatever the
  proxy decides; a reverse proxy terminating TLS also puts the plaintext in
  a third process the wallet does not control, acceptable for block
  requests and not for a passphrase. Different asset, different
  requirement. What does transfer is the operator-supplied-transport
  instinct, and RT-8 keeps it — as reachability, not as the security model.
- **RT-O4 — §5: deliberate product boundary. RULED 2026-08-21.** A
  light-client protocol is the named successor — unowned and unhomed until
  someone opens it, and written down here so the gap returns as a design
  question, not a bug report. **Addition:** a non-loopback, non-configured
  `--daemon-address` **warns at the point of configuration, in §1's terms**
  — the daemon operator sees which blocks you request and what you
  broadcast, and no transport fixes that. Discouragement where it is
  consumed. Today the CLI's network-posture disclosure warns about the
  *network path* (a clear-network daemon address is observable in transit);
  neither side says §1's thing about the *operator*, and
  `shekyl-wallet-rpc`'s own `--daemon-address` discloses nothing. That is
  slice RT-W7.

**Ratified 2026-08-21:** (a) RT-1…RT-9 as rulings, including RT-9's removal
slice; (b) RT-1 at startup, not parse, not both; (c) RT-O3 as above; (d)
RT-O4 as above. The citation, anchor and neighbour corrections were
factual; RT-O2 is closed as a corrected error, not a ruling.

### 7.1 RT-W3 probes, pre-registered (the scratch-crate treatment of `WINDOWS_WALLET_PROBE_SHEET.md`)

| # | Question | How | Predicted | Revisits on failure |
|---|---|---|---|---|
| RT-P1 | Does the pinned rustls expose an **external** (out-of-band) PSK API for TLS 1.3? | Scratch crate: configure client and server with an externally provisioned PSK, handshake, assert the negotiated mode is `psk_dhe_ke` | **No** public API (RT-O1's provisional answer). **Pre-registered 2026-08-21, before the probe runs: the result cannot change the mechanism.** RT-4 is ruled; the four hazards in its table are properties of PSK, not of its library support, so a positive result answers a question that is no longer load-bearing. A *yes* is recorded as "and here is what support actually was" — not a reason to revisit. Written down now so a surprising result does not invite relitigating a settled ruling | **Nothing.** If *yes*, the PQ trade in RT-4 gains a concrete alternative to name at reopen time; the reopen trigger itself (a practical PQ/hybrid TLS path) is unchanged |
| RT-P2 | Does pinned mutual TLS work in the shape `shekyl-wallet-rpc` uses — rustls under hyper under axum, custom server-cert verifier on the client, client cert **required** on the server, server-side fingerprint allowlist? | Scratch crate: self-signed keypairs both ends, pin by SPKI fingerprint, assert a wrong pin on **either** side fails the handshake — **the bite check, and the half that matters most: a pinned-mTLS harness that never observes a rejection is a check that cannot fail** — and assert an un-allowlisted client is refused | Works; all three refusals fire | **RT-4** — if axum/hyper cannot be driven with a required client cert without unacceptable plumbing, the mechanism is re-ranked |
| RT-P3 | ~~What does `ring` in the wallet-rpc graph do to the Windows lane?~~ **Withdrawn 2026-08-21** — `ring` is already in the graph (RT-O2), so the probe would measure today's state, not TLS's effect | — | — | — |

---

## 8. Slices

| Slice | Contents | Depends on | State |
|---|---|---|---|
| RT-W1 | RT-1 + RT-2 on `shekyl-wallet-rpc`; help text; operator docs rewritten against the real binary (they described the retired C++ server) | nothing — lands now | **LANDED on this branch 2026-08-21** (`validate_listen`, both bind paths, wiring tests observed red then green) |
| RT-W2 | RT-1 + RT-2 on the C++ daemon RPC (`rpc_args.cpp:168`, `:196`) | — | **authorized 2026-08-21** (RT-O3) |
| RT-W3 | Stack probes (§7.1: RT-P1, RT-P2) | — | **starts now**; RT-P1's result cannot move RT-4 |
| RT-W4 | RT-4/5/6/7 on L1 | RT-W3 | open |
| RT-W5 | RT-9 removal, the eleven-file reference set enumerated first | — | **authorized 2026-08-21** |
| RT-W6 | RT-8 onion listener | RT-W4 | open |
| RT-W7 | `--daemon-address` warns in §1's terms at the point of configuration, CLI and `shekyl-wallet-rpc` both (RT-O4's addition) | — | **authorized 2026-08-21** |

RT-W1 is ruled, independent, small, and strictly reduces attack surface. It
should not wait for the transport design — and did not.
