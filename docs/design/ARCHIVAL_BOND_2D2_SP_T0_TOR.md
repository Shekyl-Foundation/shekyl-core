# 2d-2 SP-T0 — bundled-Tor lifecycle + control-port measurement (Round 0)

**Status:** ROUND 0 — scoping pre-flight (2026-06-28). Deepens the `ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`
§12/§15 SP-T0 sketch into a buildable plan. No code yet.
**Scope:** the wallet-owned Tor instance the per-`P` SOCKS clients (SP-T1) dial through, **and** the
control-port channel the keystone's measured circuit-ID test (SP-T1's measured half) rides. SP-T0 is
the dependency both halves of SP-T1 sit on.
**Parent designs:** `ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` (§3 DQ2, §12 SP-T0, §14, §15, §16),
`shekyl-p-transport` (SP-T1 type half, PR #204).
**Process rule:** `26-sub-pr-design-discipline`; `17-dependency-discipline` (the control-port client +
the bundled binary); `21-reversion-clause-discipline`; `82-failure-mode-ux` (the bootstrap state).

---

## 0. What SP-T0 is — one process, two local channels

SP-T0 owns the wallet's Tor instance and exposes **two loopback-only channels**:

- The **SOCKS port** — SP-T1's `PTorClient`s dial through it; each per-`P` username keys a distinct
  `IsolateSOCKSAuth` circuit. The type side landed in PR #204; SP-T0 makes the port real.
- The **control port** (cookie-authed) — **two consumers**: (a) bootstrap progress for the
  "Connecting…" UX gate, and (b) the keystone's **measured circuit-ID disjointness test** (SP-T1's
  measured half — §15/§16: control-port circuit IDs, *not* exit-IP).

Both are **loopback, local-only**: neither crosses the network. The control port carries no privacy
payload outward — it observes circuit metadata for the wallet's *own* clients. It is a C6/forensic
surface (like the SOCKS username): its data (circuit IDs, our own targets) **must not be logged**.

---

## 1. The substrate (grounded)

- `cli/daemon.rs::DaemonClient` already does `ureq` + SOCKS (`config_builder().proxy(…)`) — the model
  SP-T1's `PTorClient` follows — but it does **not** manage a Tor process and does **not** touch the
  control port. SP-T0 is greenfield on both.
- `ureq` is HTTP-over-SOCKS only. The control port is a **separate protocol** (Tor control: line-based
  text over a TCP socket). `ureq` cannot speak it → SP-T0 needs a control-port client (DQ-T0.2).
- The engine is async (`tokio`/`kameo`): a child process + a control socket ⇒ `tokio::process` +
  `tokio` TCP, owned by an actor with a clear lifecycle.

---

## 2. Decision questions

### DQ-T0.1 — process ownership + lifecycle

The Tor process is a wallet-session resource with a real lifecycle (start → bootstrap → ready →
shutdown) and is the natural failure boundary. **Lean: a dedicated `TorService` actor** (kameo) owns
the child + the control connection; `PTorClient` construction and the measurement are its consumers.
Launch via `tokio::process::Command` with a wallet-private `SocksPort` + `ControlPort` and
cookie/SAFECOOKIE auth (the `DataDirectory` / guard-persistence choice is **DQ-T0.7**, not an
incidental flag). Shut down on wallet close (SIGTERM + wait) — **and issue `TAKEOWNERSHIP` post-auth
(or launch with `__OwningControllerProcess`)** so the child Tor exits when the controlling connection
drops. That covers the **crash-orphan** case SIGTERM+wait does not: a panic / SIGKILL / power loss
sends no SIGTERM, leaving an orphaned Tor with a live SOCKS port **and the powerful control port that
DQ-T0.2's security pin exists to contain**. The parent plan already chose `__OwningControllerProcess`
(§3, "the daemon dies with the wallet"); this reconciles the lifecycle to it. No `PTorClient` is handed
out until bootstrap completes (DQ-T0.3).

### DQ-T0.2 — the control-port client (the keystone dependency call, `17`)

**Scope the decision over the *whole* control-port consumer set, not just the measurement** — or it is
re-decided at SP-T3. The full command surface across 2d-2:

| Consumer | Commands |
| --- | --- |
| Auth (all) | cookie / **SAFECOOKIE** handshake |
| SP-T0 bootstrap gate (DQ-T0.3) | `GETINFO status/bootstrap-phase` (or `SETEVENTS STATUS_CLIENT`) |
| SP-T1 measured test (DQ-T0.4) | `SETEVENTS STREAM` + the stream→circuit attach |
| **SP-T3 onion serving (GF-9)** | **`ADD_ONION` / `DEL_ONION`** — publish `P`'s `p_slot`-bound v3 HS, rotate it with the persona |
| Lifecycle (DQ-T0.1) | **`TAKEOWNERSHIP`** — the child Tor dies with the controlling connection (the crash-orphan cover) |

Each command is line-based and individually simple, so a **roll-our-own minimal client is defensible**
(the own-the-thin-glue / minimize-deps posture) — *if* the surface stays this small. What a maintained
crate (`torut`, arti control surfaces — **verify at source, `17`; do not take maintenance/security on
faith**) amortizes is the protocol's *edge cases* — and they are **not co-equal**:

- **The structural hazard (one): async events interleaved with command replies.** The control protocol
  multiplexes async event lines (`6xx`) with synchronous command replies on a single socket; a reader
  that mis-frames one event **poisons every subsequent read**. If the roll-our-own lean holds, **the
  event/reply demuxer is where the reference-grade design and the bulk of the KATs go** — the risk is
  concentrated there, not spread across the commands.
- **Bounded parsing nuisances (two): multi-line / quoted `GETINFO` replies, and the auth handshake.**
  Real, but local and individually testable.

**Coupling — the security pin and the dependency call are not independent.** The pin (below) chose
**SAFECOOKIE**, the most complex auth path (the `AUTHCHALLENGE` HMAC handshake) and the single largest
contributor to the "handshake" nuisance — so a roll-our-own owes a **SAFECOOKIE-handshake KAT against a
real Tor specifically**, on top of the generic per-command KATs.

**Resolution (grounded — rule-17 source-check, 2026-06).** Verified the candidates at source, not by
reputation:

| Candidate | Maintained? | Legacy deps | Fit |
| --- | --- | --- | --- |
| `torut` | **No** — 0.2.1, Oct 2021; self-described "does not implement all methods" | sha2/sha3/ed25519-dalek/hmac/serde | unmaintained → out |
| `tor_control` | **No** — last release 2017 | — | out |
| arti | yes, but it **is** Tor, not a C-Tor *controller* (its RPC controls arti) | heavy | the §10 "be-Tor" anchor, not a control client |
| **`tor-interface`** (Gosling) | **Yes** — 0.6.7, Apr 2026; security-project pedigree | **hmac/sha2/zeroize** (minimal) | launches/bootstraps Tor + v3 onion — but a high-level `TorProvider` (connect/onion → `OnionStream`); **confirmed in 0.6.7 source** — no raw SOCKS port (`Socks5ProxyConfig` user/pass is *upstream*-proxy creds, the **opposite direction** from `IsolateSOCKSAuth`); no raw `STREAM`/CircID (`AsyncEvent` is `pub(crate)`, controller/control-stream are private `mod`, only `TorEvent` public) |
| roll-our-own | us | none new | exactly our surface, **raw** |

**Verdict: roll-our-own minimal — grounded in the *mismatch*, not in "nothing is maintained."** The
maintained option (`tor-interface`) abstracts away exactly the two raw capabilities our design rests
on: the **raw SOCKS port** (SP-T1's per-`P` `IsolateSOCKSAuth` `ureq` clients dial it directly) and
**raw `STREAM`/CircID events** (the DQ-T0.4 measurement). A `TorProvider` that owns the connection
(`OnionStream`) and hides the control port cannot drive per-`P` SOCKS isolation or measure circuit
disjointness; adopting it means a thin process-launch slice while still rolling our own for the
load-bearing raw layer — the worst of both. Both disqualifiers are now confirmed in the 0.6.7
*source* (the table row), and they are **independent** — either alone is sufficient.

**De-risk with the reference, not the dependency.** `tor-interface`/Gosling is MIT-licensed and
maintained, so **read it as the reference implementation** without taking the dependency — the modules
are `legacy_tor_controller.rs` / `legacy_tor_control_stream.rs`, control-spec-section-annotated:

- **SAFECOOKIE** — `AuthenticateMethod::SafeCookie`, the `AUTHCHALLENGE SERVERHASH/SERVERNONCE` parse,
  `authenticate_cmd` (control-spec §3.5) — the reference for the dedicated SAFECOOKIE KAT.
- **`ADD_ONION`/`DEL_ONION`** — `add_onion_cmd`/`del_onion_cmd`
  (key/flags/max_streams/virt_port/client_auth, §3.27/§3.38) — exactly the SP-T3 surface. These
  control commands *create* an onion service whose **inbound** serving is a different actor shape
  from this control client (untrusted peers, high-latency circuits) — its serving-side threat
  model (decoupled accept loop, per-connection timeouts, `max_request_size`) is pinned in
  [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md) §6a for SP-T3.
- **The demux — adopt its *poll/phase* model, not a concurrent reader.** Gosling's demux is **not** a
  fully-async reader: `read_reply()` returns `Option<Reply>` tagged with a `StatusCode`, and
  `wait_async_events()` drains the `650`s at controlled points (the public `update()` is the same
  poll-to-drain). It *sidesteps* the hardest interleaving — a `650` arriving mid command-reply — by
  **phasing** command-issue and event-drain rather than reading concurrently. **SP-T0a should adopt the
  same discipline**, which the kameo `TorService` actor (DQ-T0.1) affords for free: drain events
  between command handlers in its message loop. The reference does **not** validate a fully-async reader
  handling events on a separate task while a command is in flight — that harder demux is SP-T0a's to own
  if it ever reaches for it, so don't. (For DQ-T0.4 the hazard is milder anyway: the measurement request
  goes out the **SOCKS** connection while events are read on the **control** connection — different
  sockets, naturally decoupled.)

Raw access *and* a battle-tested reference for the hard parts. Scope to exactly the §DQ-T0.2 table;
SAFECOOKIE-handshake + per-command + demux KATs against a real Tor.

**Reopen (`21`) — conjunctive, both axes; `CircuitToken` is a false door.** `tor-interface` *does*
offer circuit isolation, but via an **opaque `CircuitToken`** (`generate_token`/`release_token`) — which
is **not** a reopen, for two independent reasons. (1) **Isolation-contract ownership (CX-1):** a token
moves token→circuit injectivity into *tor-interface*'s internal contract, whereas Shekyl's CX-1 closure
requires the isolation key be Shekyl's *own* persona-derived `derive_socks_user`, unrepresentable-to-
share **in Shekyl's types**. (2) **Measurement (DQ-T0.4):** raw CircID is still hidden, so even granted
isolation, it can't be *verified*. So reopen **only if a future `tor-interface` exposes BOTH** the raw
isolation key (so Shekyl owns `derive_socks_user`, not an opaque token) **and** raw `STREAM`/CircID (so
DQ-T0.4 is performable). A version that merely surfaced `CircuitToken`'s underlying username still fails
axis 2 — the criterion must not trip on it.

**Security-surface pin (load-bearing).** The control port is *powerful* — `GETINFO` can deanonymize,
`SETCONF` can reconfigure, `ADD_ONION` manages services. Keep it **wallet-private + loopback-only +
cookie/SAFECOOKIE-authed**, and the client must expose **only the minimal command set above** — **no
general `SETCONF` passthrough**, no arbitrary-command API. The new protocol must not become a broad
attack surface inside the wallet.

### DQ-T0.3 — bootstrap health-gate ("Connecting…")

Before any `PTorClient` is handed out, gate on Tor bootstrap = 100% (poll the bootstrap phase /
subscribe to client-status events). Surface the phase to the UX (`82`: "Connecting to the network…",
not a frozen wallet). Timeout → the §5 backoff/posture path, not a hang.

### DQ-T0.4 — the measured circuit-ID disjointness test (SP-T1's measured half)

The keystone's proof, owed since §16. The §15 sketch ("distinct targets, read the `NEW` event's
CircID") is the **false-positive-prone** version; the corrected measurement:

- **M1 — same target, not distinct, with a negative control.** Issue `P`'s and the principal's requests
  to the **same** target. Distinct targets can land on different circuits for routing reasons *other*
  than the username isolation — a false "isolation works." Same target makes the **username the only
  variable**, so a circuit-id difference is *caused by* the isolation. Pair it with a **negative
  control** — two streams over the *same* username → expect the **same** circuit — so the test can fail
  in both directions.
- **M2 — the invariant-(c) leg.** Test **`P_A` vs `P_B`** (two distinct personas), not only `P` vs
  principal — that is the per-persona-distinct property the firewall actually rests on.
- **M3 — read CircID at *stream attach*, not on `NEW`.** A `STREAM … NEW` event has **CircID = 0** (not
  yet attached); the circuit id is populated at `SENTCONNECT`/`SUCCEEDED`. Read it there.
- **M4 — bounded attach timeout.** Wait for attach with a bounded timeout (Tor up but a circuit stalls
  → the test *fails*, never hangs); harness-gated.

**Co-validation — build M1's pair *with* the SP-T0a control client, not after it.** This measurement is
the first end-to-end exercise of SP-T0a's `STREAM`-event/CircID-read path, so M1's two legs are *also*
the control client's **event-parsing acceptance test**, not only the isolation proof. The failure they
jointly catch: a mis-framed demux, or reading CircID at `NEW` (=0) instead of attach (M3), makes *every*
stream read `0` — the **same-username** leg then passes trivially (`0==0`, a false green) while the
**different-username** (isolation) leg *fails* (`0` vs `0` reads as "same circuit"). So the **pair**
surfaces a broken reader that either leg alone would miss, and a green measured test is simultaneously
asserting *the reader is correct* **and** *the circuits are disjoint* — do not read it as purely the
latter. Co-develop the DQ-T0.4 pair with SP-T0a against the system-Tor harness; the keystone measurement
hands you the read-path acceptance test for free.

It measures circuit-disjointness *directly* — exit-IP is unsound here (§16). A control-port
**integration** test (real Tor): runs in an integration job / `#[ignore]` in unit runs, not the unit
gate. Closes the keystone the SP-T1 crate doc points forward to.

### DQ-T0.5 — packaging (reuse-not-own, §15)

Do **not** own a Tor build. Inherit reproducible packaging where it exists (Guix `tor`); **hash-pin**
the Tor Project's official released binary — the **Tor Expert Bundle**
(<https://www.torproject.org/download/tor/>), the standalone `tor` artifact for embedders — on targets
you cannot build reproducibly (Windows the trusted-blob exception). The recurring obligation is a **release-checklist line** — watch the Expert Bundle page for releases/advisories → bump the
pinned version/hash → re-verify — not a maintained build. **This line is an explicit SP-T0c
deliverable:** `docs/RELEASE_CHECKLIST.md` carries no Tor entry today, and a duty that lives only in a
design doc evaporates — SP-T0c's definition of done is "the bundle **and** the checklist line," not just
the bundle. (Per-target Guix coverage for macOS/Windows is a packaging detail to work; reuse-don't-own
bounds the cost regardless.)

**Dev pin (recorded 2026-06-29 — the seed for that checklist entry):** verified
`tor-expert-bundle-linux-x86_64-15.0.16.tar.gz` (Tor `0.4.9.9`) — SHA256
`71c838387ec0019a7c7f9f60a5538f7fcae0521a29924c992b84189c9ec4d7f1`, GPG-signed by the **Tor Browser
Developers** key `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290` (signing subkey
`CAAE408AEBE2288E96FC5D5E157432CF78A65729`). The durable pin is *that signing key*, not just this one
hash — a version bump re-verifies the new manifest's signature against the same fingerprint, then records
the new tarball hash. Dev/CI integration KATs discover the launchable binary via the
`SHEKYL_TEST_TOR_BINARY` env var (skip-if-unset), so the unit gate and CI-without-Tor stay green; only an
integration job with a bundled Tor exercises the live path.

The Arti reopen-anchor
(§10) stays on its real trigger — SOCKS-isolation proving unenforceable — which **DQ-T0.4 is what
would detect**.

### DQ-T0.6 — failure handling

Tor crash / control-socket drop / bootstrap timeout → the §5 liveness path (backoff + posture),
**never a panic**. The `TorService` actor is the failure boundary; `PTorClient` construction
**fails closed** — no silent fallback to a non-isolated connection.

### DQ-T0.7 — `DataDirectory` / cross-session guard posture (don't decide this by accident)

The `DataDirectory` choice silently sets the **entry-guard rotation policy** — a privacy-relevant
property — so it gets a named decision, not one word in a launch sentence.

- **Within-session** — the §7 residual (`P` and the principal share one guard) — is **unaffected**
  either way: same process, same guards.
- **Cross-session** is the real fork. **Ephemeral** `DataDirectory` → a *fresh entry guard every
  wallet session*; **persistent** → a stable guard set across sessions.

The tradeoff cuts both ways:

- **Persistent (Tor's own design):** guards exist precisely to *minimise lifetime exposure* — a stable,
  probably-honest guard is safer than repeatedly drawing fresh ones, each a new chance to draw a
  malicious one; frequent rotation is what the guard spec **discourages**. And **§3's own "deviation
  from Tor defaults = a signature"** principle points the same way: persistent *is* the default.
- **Ephemeral (wallet-forensic):** no on-disk Tor identity / guard history — a C6/local-forensic win.

**Lean: persistent**, with the forensic concern met by a **wallet-private, encrypted-at-rest**
`DataDirectory` (no plaintext on-disk identity, *without* fighting Tor's guard design or deviating from
defaults). **Reopen to ephemeral** if an encrypted wallet-private data dir proves infeasible on a
target, or if a cross-session-guard correlation against the §7 model is shown to outweigh the
malicious-guard-draw risk. (Cross-ref §7.)

---

## 3. SP decomposition (sub-PRs)

| SP | Deliverable | Notes |
| --- | --- | --- |
| **SP-T0a** | **Control-port client** (DQ-T0.2) — the minimal client + KATs against a real Tor (auth, bootstrap, `STREAM`, **and `ADD_ONION`/`DEL_ONION` for SP-T3**). | The keystone; buildable against a *system* Tor before bundling. The rule-17 call (scoped over the whole consumer set) lives here. |
| **SP-T0b** | **`TorService` lifecycle** (DQ-T0.1/.3/.6) — managed child, bootstrap gate, shutdown, failure→backoff; exposes the SOCKS endpoint to SP-T1/SP-T2. | Develops against a system Tor. |
| **SP-T0c** | **Packaging** (DQ-T0.5) — Guix + hash-pin the **Tor Expert Bundle**; bundled-binary discovery/launch; **add the watch/bump/re-verify line to `docs/RELEASE_CHECKLIST.md`** (DoD, not just the bundle). | The ship step. |
| **SP-T1-measured** | **Circuit-ID disjointness test** (DQ-T0.4) — over SP-T0a+b; closes the SP-T1 keystone. | Integration job. **Gated on SP-T0 alone — not #205** (§5). |

### 3a. SP-T0a actor boundary — type obligations for the integration half

A hindsight review of the **pure core** (PR #208 — `shekyl-tor::control::framing` +
`safecookie`) confirmed the primitives are correct and shaped for the poll/phase
actor (SAFECOOKIE key strings + HMAC message order, constant-time `verify_slice`,
the data-block / dot-unstuff / status-mismatch corners, redaction on `Display`
*and* `Debug`). The framer and crypto correctly stay **sans-IO / pure**, so the
next bugs live at the **seams the actor consumes** — recorded here so PR-2 designs
them in rather than discovers them:

- **Verify→authenticate as a typestate (single highest-value evolution).**
  SAFECOOKIE's property is that the controller verifies `SERVERHASH` *before*
  sending `AUTHENTICATE`. Today `verify_server_hash(…) -> bool` (`#[must_use]`) and
  `client_hash(…) -> [u8; 32]` are independent calls — nothing makes *skipping* the
  verify a type error. When the handshake actor lands, evolve the return to
  `verify_server_hash(…) -> Option<ServerVerified<'a>>`, the **sole** path to the
  client hash (`verified.client_hash()`). Two properties make it *actually*
  unforgeable, not merely intended to be — pin both, or it is theatre:
  - **Non-forgeable by construction.** `ServerVerified` has a **private field, no
    `Default`, no public constructor** — mintable *only* by `verify_server_hash`
    returning `Some`. This is the same sole-constructor discipline
    `PTorClient::for_persona` already enforces in `shekyl-p-transport`; it's the
    established pattern, not a fresh call. A stray `pub fn new` or a derived
    `Default` quietly undoes the whole typestate.
  - **Borrow, don't own.** `ServerVerified<'a>` holds `&'a ControlCookie` + the two
    `[u8; 32]` nonces; `client_hash(&self)`. The borrow is *forced* by the cookie
    being `!Clone` + `ZeroizeOnDrop` (can't copy it, won't move it out of the actor)
    and it **scopes the token to the handshake window** — a stale verification can't
    be stashed and reused, and the cookie zeroizes the moment `AUTHENTICATE` lands.
    The lifetime *is* the security property.

  Then "send `AUTHENTICATE` without a successful verify" is unrepresentable. The
  current `bool`/standalone-`client_hash` pair is the seam this attaches to.
- **The demux as a typed fork at ingress.** `ControlReply::is_async_event()` is the
  right primitive and the framer stays dumb, but a `bool` on a shared `ControlReply`
  lets the command-correlation path receive an event by mistake. At the one point
  the actor drains the framer, fork into
  `enum Framed { CommandReply(ControlReply), AsyncEvent(ControlReply) }` so the
  awaiting-command path and the `SETEVENTS` drain each handle only their own
  variant. The framer produces `ControlReply`; the actor classifies **once**, at
  the boundary — the poll/phase pathway made unmisusable.
- **Deferred actor obligations (pin with the same rigor the two files model):**
  - **CSPRNG client nonce, fresh per handshake.** The `&[u8; 32]` nonce is the seam;
    the actor must source it from a vetted CSPRNG — never a counter, never reused —
    or the challenge-response is gutted (rule 30/35).
  - **`AUTHCHALLENGE` reply parsing** is the deferred security-critical step:
    decoding `SERVERHASH=`/`SERVERNONCE=` hex and length-checking the nonce is where
    parsing bugs hide. The type discipline already sets the bar — the nonce is
    `[u8; 32]` (the parser must validate exactly 32 bytes at decode), while
    `verify_server_hash`'s `received: &[u8]` is variable and `verify_slice` tolerates
    any length. Carry the independent-KAT discipline into that parser.
  - **Cookie-file length.** `ControlCookie::new([u8; 32])` forces reading exactly 32
    bytes and rejecting a truncated/oversized `control_auth_cookie` at the boundary —
    keep it; do **not** add a `from_slice` escape hatch that bypasses it.
  - **`Err` → teardown → §5.** Every `FramingError` is a desync with no safe resync
    (the type says so); wire each to **DQ-T0.6**'s failure path so a desync
    deterministically becomes the backoff/§5 posture, never a silent reconnect that
    retries into the same corruption.

### 3b. SP-T0b bootstrap readiness — the pinned contract (decided: internal GETINFO poll)

A hindsight review of the **landed** actor (PR #212) surfaced one seam: `TorControl`
reserves a `bootstrap: BootstrapState` field (the actor is meant to hold readiness
*internally*), but nothing yet drives it. **Decided: the actor owns a self-contained
`GETINFO status/bootstrap-phase` poll task** that drives `BootstrapState` and publishes
it as a `watch` — pinned here for SP-T0b the way §3a was pinned for PR-2.

> **Retraction (recorded, not erased — [`21`]).** An earlier draft pinned an *internal
> tap*: the actor would `SETEVENTS STATUS_CLIENT` and drive `BootstrapState` from the
> async `BOOTSTRAP PROGRESS` events. **Withdrawn.** The tap makes bootstrap detection
> ride `SETEVENTS`, which is a **shared, replace-not-add** resource the consumer also
> uses (the measurement's `SETEVENTS STREAM`) — so the actor would have had to own the
> *union* (`STREAM STATUS_CLIENT`), track the active set, and never let a consumer's
> `SetEvents` silently clobber `STATUS_CLIENT`. A `GETINFO` poll is a **command**
> (request/reply), not a subscription: it never touches `SETEVENTS`, so that entire
> coupling — the "`SETEVENTS`-union invariant" **and** the tap-vs-route routing change —
> **does not exist**. Two things the earlier draft asked for are therefore
> **deliberately absent, and their absence is the retraction holding: no `STATUS_CLIENT`
> subscription, no union invariant, no routing change.** Stated flatly because it is easy
> to re-derive by accident: the measurement's bare `SETEVENTS STREAM` is correct
> **permanently**, not "until SP-T0b" — there is no shared subscription for it to clobber.

**Why (the principle survives the mechanism change).** A consumer should depend on what
it *needs* — a one-bit "is the transport usable yet?" fact — not on *how the actor learned
it*. Making every consumer reimplement bootstrap-detection against Tor's wire format (and
re-break the day Tor changes it, or we swap to **Arti**, which reports readiness
completely differently) is a **leak of the abstraction the `TorService` exists to
provide**: the actor *is* the boundary between "the Tor control protocol" and "the rest of
the wallet." The poll confines the protocol knowledge (`GETINFO` keys, `PROGRESS=`
parsing) to the one component that already speaks it and hands everyone else the bit —
exactly what the tap would have, without entangling `SETEVENTS`. The cost is a poll
instead of a push, but bootstrap is a **one-time** startup event over tens of seconds: a
~1s poll adds negligible latency, and the decoupling is worth far more.

**The pinned contract (for SP-T0b):**

1. **Readiness is a fact, not an event:** expose `tokio::sync::watch<BootstrapState>`;
   the consumer holds the receiver (mirroring how `EventSink` hands out the `STREAM`
   channel). `watch` over `broadcast` because a **late** subscriber sees the *current*
   state immediately — a `ShardService` that starts *after* bootstrap completed must not
   wait forever for an event that already fired.
2. **An actor-owned poll task, spawned in `on_start`,** drives the watch through the
   **public `ask`** path — `GETINFO status/bootstrap-phase`, poll-to-100-then-stop. It
   subscribes nothing (`SETEVENTS` untouched), reshapes no routing, and stops once it
   observes `PROGRESS=100`/`TAG=done` (the watch then holds `Ready`). This is the same
   `ask` surface the DQ-T0.4 harness already exercises as its own gate.
3. **Detection (actor) vs policy (SP-T0b) — the same coupling discipline one level up.**
   *Detection:* the poll task parses `bootstrap-phase`, drives `BootstrapState`, publishes
   the watch — it knows Tor is at 100%, nothing more. *Policy:* SP-T0b's lifecycle owns
   the deadline, the backoff, and timeout → `Failed` → §5; it `await`s the readiness bit
   and acts on it, parsing nothing. The protocol knowledge lives in exactly one place, and
   both consumers *and* SP-T0b's own lifecycle depend only on the bit.
4. **Managed-vs-attached child** on the `child` seam field: SP-T0b decides whether the
   actor spawned `tor` (managed → it owns shutdown) or attached to a running one (attached
   → it must not kill it). Shutdown rides the **`TAKEOWNERSHIP`** already landed in PR-2 —
   the control connection dropping exits a managed `tor` even on a crash — so "kill the
   child" is a backstop, not the primary path.

**One open sub-decision (settle at build, not here): the poll task's own error contract.**
If `ask` returns `SendError` mid-poll — the actor stopped because the control connection
dropped *during* bootstrap — the poll task should publish `BootstrapState::Failed` and
exit, so a consumer awaiting readiness gets `Failed` promptly rather than hanging until the
lifecycle timeout fires. That keeps **both** failure paths terminating the watch promptly —
*Tor never reaches 100%* (lifecycle deadline) and *the connection died mid-bootstrap*
(poll-task error) — differing only in which one the lifecycle policy attributes.
Recommended resolution above; pin it deliberately when SP-T0b builds. It does not change
the shape.

> **Note for the DQ-T0.4 measurement (built before SP-T0b):** it gates its first dial on
> bootstrap=100% via its own `GETINFO status/bootstrap-phase` poll (a test apparatus, not a
> production consumer), so it does not block on this contract. When SP-T0b lands the
> `watch`, the measurement's *gate* can migrate to awaiting the bit — but its `SETEVENTS
> STREAM` **never changes**, because under the poll design there is no `STATUS_CLIENT`
> subscription and hence no union invariant. That bare subscription is correct for good.

---

## 4. Threat-model cross-check (origin-only — §7)

- **Control port is loopback, local-only** — it never crosses the network and observes circuit metadata
  for the wallet's *own* clients (no third-party exposure). C6/forensic surface: its data must not be
  logged (same discipline as the SOCKS username).
- **SOCKS port** is the per-`P` isolation lever (SP-T1); SP-T0 only makes it real — the isolation
  property is unchanged.
- **One process ⇒ shared guard set** = the deliberate §7 residual (do not split instances to "fix" it).
- **No new origin surface:** SP-T0 is the substrate the §0–§7 boundary already assumed; it adds a local
  control channel, not a network one.

---

## 5. Dependency posture + build order

- **Keystone: SP-T0a (control-port client)** — the measured property rides on it, and it is the rule-17
  dependency call (scoped over the **whole** consumer set, DQ-T0.2). **Buildable now** against a
  *system* Tor (no bundling needed to develop/test the protocol).
- **The gate lattice (distinct gates — don't over-bundle):**
  - **SP-T1 measured test → SP-T0 *only*.** It exercises `P`-vs-principal / `P_A`-vs-`P_B` circuit
    isolation — pure transport, no scan loop, no `PCanonicalId`. It lands against PR-204's *current*
    types the moment SP-T0's harness exists, **before #205** — so the keystone's measured property is
    demonstrable without waiting on PR-B. (At the alignment the type swap is a one-line
    `PCircuitTag::from_canonical_id` → `PCanonicalId::from_bytes` change *in the test*, not a rewrite.)
  - **`PCanonicalId` alignment → #205** (the type must exist; FOLLOWUPS — and it *deletes* `PCircuitTag`).
  - **SP-T2 (`PBlockSource`) → SP-T0 + #205** (needs SP-T0b's SOCKS endpoint, PR-B's generic `task.rs`
    plus the `BlockSource` `pub(crate)` → `pub` bump, and `PCanonicalId`).
- **Build order:** SP-T0a is **two PRs of one actor** — PR-1 (landed pure core) → **PR-2** (the `tokio`
  actor + the *authed* control connection) — then **SP-T0b layers onto the same actor**, it is **not** a
  parallel crate. §0/§3 put *one* `TorService` actor over both the child and the control connection, and
  SP-T0b's load-bearing pieces both ride PR-2's authed connection: the bootstrap gate polls progress over
  the control port (`GETINFO status/bootstrap-phase`, §3b), and `TAKEOWNERSHIP` (the T1 orphan-prevention)
  is a post-auth control command. So **serialize**: PR-2 freezes the actor's shape (struct fields, message
  enum, poll/phase loop) first; SP-T0b builds child-management + bootstrap-gate + `TAKEOWNERSHIP` on top.
  The *only* genuinely PR-2-independent slice is the bare child-spawn + SIGTERM-on-clean-close — pre-stage
  that for concurrency **only once PR-2 has frozen the actor shape**, else two agents collide on the one
  shared object and you reconcile a merge instead of a design. Then → **SP-T1-measured** (gated on SP-T0
  alone) → SP-T0c (packaging). SP-T3 shares SP-T0a's client (the `ADD_ONION` surface — DQ-T0.2). SP-T2
  lands when SP-T0 + #205 are both in.
- **Independent of PR-B (#205):** SP-T0 doesn't touch the scan loop, so it can start now.

---

## 6. Reopen anchors (`21`)

- **control-port client = roll-our-own** — reopen **only if** a maintained crate exposes **both** the
  raw isolation key (so Shekyl owns `derive_socks_user`) **and** raw `STREAM`/CircID (so DQ-T0.4 is
  performable); `tor-interface`'s opaque `CircuitToken` is a *false door* that satisfies neither (see
  DQ-T0.2's reopen). Verify in source, not docs.
- **embedded Arti** (the §10 anchor) — unchanged, on its real trigger (SOCKS-isolation unenforceable);
  DQ-T0.4 is the detector for that trigger.
- **packaging targets** — the per-target Guix / hash-pin split is a detail to work at SP-T0c.

## Revision history

- **2026-06-28:** Created. Round-0 scoping for SP-T0: the two loopback channels (SOCKS + control), the
  control-port-client dependency call (lean roll-our-own minimal, rule-17 gate) **scoped over the whole
  consumer set including SP-T3's `ADD_ONION`** + the security-surface pin (minimal commands, no
  `SETCONF` passthrough), the `TorService` lifecycle + bootstrap health-gate, the corrected measured
  test (**M1 same-target + negative control, M2 `P_A`-vs-`P_B`, M3 CircID at attach not `NEW`, M4
  bounded timeout**), reuse-not-own packaging, the origin-only cross-check, and the **gate lattice**
  (measured test → SP-T0 alone; `PCanonicalId` alignment/`PCircuitTag` deletion → #205; SP-T2 → both).
- **2026-06-28 (round-0 review):** T1 — crash-orphan cover via `TAKEOWNERSHIP`/`__OwningControllerProcess`
  (reconciles DQ-T0.1 to parent §3), added to the DQ-T0.2 command surface. T2 — promoted the
  `DataDirectory` choice to **DQ-T0.7** (cross-session guard posture; lean persistent + encrypted
  wallet-private dir, per Tor's guard design and §3 deviation-is-signature). T3 — DQ-T0.2 names the
  **async event/reply demux as the one structural hazard** (vs. bounded nuisances) and the SAFECOOKIE
  coupling (a dedicated handshake KAT). Minor — DQ-T0.5/SP-T0c pin the **Tor Expert Bundle**
  (torproject.org/download/tor) as the hash-pin source and make the `RELEASE_CHECKLIST.md` line an
  explicit SP-T0c deliverable.
- **2026-06-28 (DQ-T0.2 resolved — rule-17 source-check):** verified the control-client candidates at
  source. `torut` (Oct 2021) and `tor_control` (2017) are unmaintained; arti is *be-Tor*, not a
  controller. The one maintained, minimal-dep option — **`tor-interface`/Gosling (Apr 2026,
  hmac/sha2/zeroize)** — is a high-level `TorProvider` that **abstracts away the raw SOCKS port and raw
  `STREAM`/CircID events** our per-`P` isolation + measurement need. **Verdict: roll-our-own minimal**,
  grounded in that mismatch (not "nothing maintained"), **with Gosling read as the reference impl** for
  the demux / SAFECOOKIE / `ADD_ONION` edge cases. Reopen if a crate cleanly exposes raw SOCKS + raw
  events (confirm in source).
- **2026-06-29 (DQ-T0.2 — confirmed at source):** read `tor-interface-0.6.7` directly (closing the
  65%-doc-coverage caveat). Both disqualifiers verified and **independent**: no raw SOCKS port
  (`Socks5ProxyConfig` is *upstream*-proxy creds, the opposite direction from `IsolateSOCKSAuth`); no raw
  `STREAM`/CircID (`AsyncEvent` `pub(crate)`, controller/control-stream private `mod`, only `TorEvent`
  public). Tightened the reopen to a **conjunctive** criterion — the opaque `CircuitToken` is a *false
  door* (fails CX-1 ownership **and** DQ-T0.4 measurement); reopen needs **both** the raw isolation key
  **and** raw CircID. Pinned the reference (`legacy_tor_controller.rs`): SAFECOOKIE §3.5 +
  `ADD_ONION`/`DEL_ONION` §3.27/§3.38, and its **poll/phase demux** (not a concurrent reader) as the
  model SP-T0a's `TorService` actor adopts for free.
- **2026-06-29 (DQ-T0.4 co-validation note):** the M1 same/different-username pair (with M3's
  attach-time read) is *also* SP-T0a's event-parsing acceptance test — a zeroed-CircID reader (bad demux
  / `NEW` read) makes the same-username leg falsely green while the different-username leg fails, so the
  pair catches a broken reader; co-develop them. A green measured test asserts *reader-correctness*, not
  just isolation.
- **2026-06-29 (PCanonicalId alignment landed — PR #209):** §5's `PCircuitTag` → `PCanonicalId`
  dependency (gated on #205) is **done** — `shekyl-p-transport` now takes `&PCanonicalId` and
  `PCircuitTag` is deleted (byte-preserving). §5's `PCircuitTag::from_canonical_id` →
  `PCanonicalId::from_bytes` note is now historical; SP-T0a's measured test consumes the clean type.
- **2026-06-29 (SP-T0a pure-core review → §3a):** A hindsight pass over PR #208 (framer + SAFECOOKIE)
  found no correctness bugs and surfaced the actor-boundary type work for PR-2 — added §3a: the
  verify→authenticate typestate (`-> Option<ServerVerified>`), the `Framed` event/command fork at
  ingress, and the four deferred actor obligations (CSPRNG nonce, `AUTHCHALLENGE` parsing, cookie-file
  length, `Err` → DQ-T0.6 teardown). The pure modules correctly defer these; PR-2 designs them in.
- **2026-06-30 (§3b pinned — SP-T0b bootstrap readiness, poll not tap):** pinned the SP-T0b contract:
  `watch<BootstrapState>` (consumer holds the receiver, like `EventSink`), driven by an **actor-owned
  `GETINFO status/bootstrap-phase` poll task** in `on_start` over the public `ask` (poll-to-100-then-stop);
  detection (actor drives the watch) vs policy (SP-T0b lifecycle owns deadline → `Failed` → §5); managed-
  vs-attached child on the `child` seam, shutdown riding `TAKEOWNERSHIP`. **Retraction (`21`):** an earlier
  draft pinned an *internal tap* (`SETEVENTS STATUS_CLIENT`, drive from async `BOOTSTRAP PROGRESS`, with a
  `SETEVENTS`-union invariant + a tap-vs-route change). Withdrawn — a `GETINFO` poll is a command, not a
  subscription, so it never touches `SETEVENTS`; the union invariant and routing change **cannot exist**,
  and the DQ-T0.4 harness's bare `SETEVENTS STREAM` is correct **permanently** (nothing to clobber). One
  open sub-decision left for the build: the poll task's own error contract (recommended — publish
  `BootstrapState::Failed` and exit on a mid-poll `SendError`, so readiness never hangs). Corrected the
  §5 build-order line and the PR-217 harness comment to match; the fossil is caught before SP-T0b builds.
