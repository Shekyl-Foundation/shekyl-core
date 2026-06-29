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

**Lean: roll-our-own minimal**, scoped to exactly the table above, with the **demuxer as the reference
surface** and SAFECOOKIE-handshake + per-command KATs against a real Tor; reopen to a crate only if it
is clearly lighter on the rule-17 axes (audit + vendor + Guix reproduce). **The grounded
`torut`-vs-arti-vs-roll-our-own decision matrix is SP-T0a's opener — DQ-T0.2 resolves from it, not from
this lean.**

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
bounds the cost regardless.) The Arti reopen-anchor
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
- **Build order:** SP-T0a ∥ SP-T0b (against system Tor) → **SP-T1-measured** (gated on SP-T0 alone) →
  SP-T0c (packaging). SP-T3 shares SP-T0a's client (the `ADD_ONION` surface — DQ-T0.2). SP-T2 lands
  when SP-T0 + #205 are both in.
- **Independent of PR-B (#205):** SP-T0 doesn't touch the scan loop, so it can start now.

---

## 6. Reopen anchors (`21`)

- **control-port client = roll-our-own** — reopen if a maintained crate proves clearly lighter on the
  rule-17 axes (verify the candidates first).
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
