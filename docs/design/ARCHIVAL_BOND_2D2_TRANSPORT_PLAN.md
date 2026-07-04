# 2d-2 — Archival network transport & reconcile (P-isolated Tor)

**Status:** ROUND 0 — build decomposition (2026-06-28); scoping framing §0–§10 frozen,
§11–§15 add the buildable SP decomposition (grounded surface map, SP enumeration, type-safety,
dependency posture, per-SP design). The transport is greenfield (no Arti/Tor/onion code on
dev; the only network primitive is `ureq` + `socks-proxy` in `rust/shekyl-cli/Cargo.toml:25`,
and the wallet→daemon path is HTTP(S) `DaemonClient` over `SimpleRequestRpc`,
`rust/shekyl-engine-core/src/engine/daemon.rs`). 2d-1 pinned the *seams* (below); 2d-2 fills
them. **The scope is deliberately small** — most of the apparent surface dissolved on
grounding (see §0): the privacy job is one boundary, the liveness job is ordinary, and the
censorship-circumvention job is not ours.
**Scope:** the network layer of the principal ↔ `P` firewall (gate-6) — `P`'s transport
(circuit, fetch, broadcast, serving) and the reconcile that consumes 2d-1's scan.
**Parent designs:** `ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` (the seams + DQ1 isolation boundary),
`ARCHIVAL_FIREWALL_GATE6.md` (the firewall charter), `ARCHIVAL_FIREWALL_THREATS.md` (C2/C3 +
TM-3/TM-5/TM-6), `ARCHIVAL_RETENTION_GATE2.md` (the challenge/response wire),
`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` (the slash model — read it, §0).
**Process rule:** `26-sub-pr-design-discipline.mdc`; `17-dependency-discipline.mdc` (the
bundled Tor binary); `21-reversion-clause-discipline.mdc`.

---

## 0. What 2d-2 is for — one boundary, and the things that aren't it

**`P` is a public pseudonym, and that is the design, not a leak.** `P` declares its shards
(`bond_wire::HoldingsDescriptor::shard_ids`, cleartext), earns visibly (`serve_credit_bit`,
public consensus state), answers challenges **on-chain under its own `p_canonical_id`**
(`txin_archival_serve_credit_response`, GATE2 §5), and serves retrievals. All of that is
*supposed* to be seen. **The firewall protects exactly one edge: `P ↔ principal-wallet ↔
human`** (gate-6 charter, `ARCHIVAL_FIREWALL_GATE6.md` §"charter is P ↔ principal"), and on
the network axis the only thing that can cross it is the **origin** of `P`'s traffic — its
circuit, IP, or a timing-correlation to the principal's *own* activity.

Three things are therefore **out of 2d-2's scope by design**, each having repeatedly inflated
this round before being grounded away:

- **Hiding `P`'s shards / earnings / challenge-responses.** Public by construction; nothing to
  hide.
- **`P`↔`P` unlinkability.** Clustering two personas reveals "same operator," which never
  reaches the human (the principal sits behind a *different* wall — cover, funding
  decorrelation, network origin — that clustering does not weaken). This is why TM-1's
  cardinality analysis was a phantom (`ARCHIVAL_TM1_CLUSTERING.md` §0).
- **Reaching Tor where it is actively blocked** (censored regions). That is the Tor Project's
  cat-and-mouse, played by people who do it daily; we use Tor's defaults (deviation creates a
  signature) and **link to their bridge docs** — we do not reimplement it (§8).

So 2d-2's privacy job is **network-origin isolation, and only that.**

---

## 1. The boundary (DQ1, one layer down from 2d-1)

2d-1's lesson: the firewall isn't the code (the decode is pure) — it's keys/state/fetch.
2d-2's is the same shape on the network: the firewall isn't the cryptography (the bond is
already unlinkable on-chain under `P`) — it's the **network resources `P` shares with the
principal.** A C2 network observer or C3 infrastructure operator who sees `P`'s traffic and
the principal's traffic over a **shared resource** (same circuit, same exit-ward IP,
correlated timing) links them regardless of the on-chain crypto.

**The boundary, stated:** `P` operates a **fully isolated network identity** — its own
circuit, its own block source (fetch and tip), its own broadcast path, its own inbound
service — **sharing no network resource with the principal**, with timing not correlated to
the principal's activity. The unit of isolation is the **per-`P` transport**, and the
make-it-unrepresentable move is SP-0's already: the block source is a per-`P` *injected*
interface, so `P` structurally cannot reach for the principal's connection — the same shape
as `PScanCursor` not being passable where `BlockchainTip` is expected.

**The two halves (different requirements, like 2d-1's two readers):**

- **(A) Transport** — the network isolation: `P`'s circuit, fetch, broadcast, serving, timing.
  **Unlinkability-critical** (the §0 boundary).
- **(B) Reconcile** — GC of phantom `bonded_slots` / `p_slot`, consuming SP-6's
  `PReconcileSet`. **Completeness-critical** (the SP-6 rule: GC only on confirmed-absence
  within `covered`, never on absence-from-one-source). Sits *on* transport but carries no
  timing-decorrelation burden; transport carries no completeness burden.

---

## 2. The 2d-1 seams 2d-2 plugs into (state verified against dev, 2026-06-28)

The 2d-1 plan *designed* these seams; only some are **code on dev**. The rest are
design-level names (do not cite them as landed surfaces — the read-the-code rule). 2d-1's
SP-3/SP-5 (PR-A, **#201**) landed the dual-extractor scan-step; **PR-B is in progress** (the
driving task + SP-4 finalize + the cadence); SP-6/SP-7 are future.

| Seam | State on dev | What 2d-2 does with it |
| --- | --- | --- |
| `BlockSource` (SP-0) — per-`P`, fetch-everything | **landed** | Provide the Tor-backed impl underneath the unchanged trait |
| `ScanStep` / `run_dual_extractor` (SP-3/SP-5) | **landed (PR-A #201)** — the task owns the `BlockSource`; bond-posts are *"collected for SP-6 reconcile"* | The Tor `BlockSource` feeds it; reconcile consumes its public bond-post matches |
| Scan **cadence** (SP-5 / TM-6) — "no hardwired timer" | **not built** — the driving task is **PR-B, in progress**; pinned as a *design* constraint, not yet a `ScanSchedule` type | Drive it constant-rate/jittered over the per-`P` circuit — **gated on PR-B exposing an injectable cadence** |
| `VerifiedRange` / `PReconcileSet` (SP-6) | **0 files — design-level, future** | Consume for half (B); **gated on SP-6 being built** (PR-A only *collects* the inputs) |
| `CoverDiscovery` (SP-7) — re-fund takes `AbsentVerified` only | **0 files — design-level, future** | Honor it once built; no auto-escalation of `Incomplete` |
| `tip_height()` = "this source's *claimed* tip" (TM-3) | concept (in the plan) | Resolved by **posture**, not multi-source machinery (§4) |
| `_spread` / `_bond_first` broadcast stub | **drawn** (the `TODO(2d)` in `stake_engine.rs`); the write-side *seam* it will feed is built (SP-T4a `PTransactionSubmitter` + `BroadcastPosture`), but the draw is **not** wired into any broadcast | Wire discretionary-broadcast timing (both the `_spread` delay **and** the `_bond_first` order-coin) over the per-`P` circuit (§5) — gated on the consumer wiring (2c-2a/2c-2b), not the seam |

**Implication for 2d-2 half (B):** the reconcile is **blocked** until SP-6 (`PReconcileSet`)
and the PR-B driving task exist; only half (A) transport can proceed now. The doc treats (B)
as a forward-dependency, not a present build.

---

## 3. DQ2 — transport mechanism: **external bundled Tor over SOCKS** (resolved)

**Decision:** an **external Tor daemon, bundled and wallet-owned, reached over SOCKS**, with
per-`P` circuit isolation via `IsolateSOCKSAuth`. **Not** embedded Arti — Arti is the named
rule-21 reopen. The reasoning (privacy-first *and* supply-chain, both load-bearing): bundling
the **binary** is an *installation, not a codebase* — you inherit the Tor Project's auditors
and a single signed artifact instead of Arti's fast-moving crate graph (the surface
`shekyl-oxide` was vendored to avoid). `ureq 3` already carries the `socks-proxy` capability.

**The managed-child-process lifecycle (what makes the UX feel embedded without vendoring):**

1. **Always our own instance — never reuse a system Tor.** Easier *and* safer: no detection
   code, no unknown config/version, the isolation flags are ours to enforce. The cost (a
   second `tor` if the user also runs Tor Browser) is trivial and independent.
2. The wallet **spawns `tor`** with a generated ephemeral config — `SocksPort auto`,
   `ControlPort auto` + cookie auth, a wallet-private `DataDirectory`,
   `__OwningControllerProcess` (the daemon dies with the wallet) — and **discovers the SOCKS
   port over the control port**. No user-visible port, ever.
3. **Bootstrap is a state, not a hang.** Gate all fetch/broadcast/serve on bootstrap=100%;
   show "Connecting to the privacy network… 60%" (rule 82). A pre-bootstrap broadcast would
   leak over clearnet — forbidden.
4. **Per-`P` isolation = per-identity SOCKS credentials.** Distinct `user:pass` →
   `IsolateSOCKSAuth` → distinct circuit (verified at the Tor source —
   [Tor SOCKS-extensions spec](https://spec.torproject.org/socks-extensions.html),
   [Whonix Stream Isolation](https://www.whonix.org/wiki/Stream_Isolation)). The
   architecture is **one transport
   client per network identity** carrying its own credentials — almost certainly a separate
   `ureq::Agent` per identity (proxy/auth is per-`Agent` — **verified in ureq 3.3.0**: `Config::proxy`,
   no per-request override, SP-T1), which makes the per-`P` `Agent` the typed boundary (`P` cannot use
   the principal's `Agent`).
5. **Use Tor's defaults; do not "harden" them.** Distinct circuits may share an **exit** (that
   is the obfuscation working, not a discriminator) and **do** share the **entry guard** (Tor
   pins a small guard set — revealing only "this IP uses Tor," the anonymity set). Multi-guard
   / custom configs *create* a signature. Defaults, full stop.

**Verify, don't trust the flag.** `IsolateSOCKSAuth` is a "looks-set-but-isn't" config — ship
the isolation claim on a **measured** different-exit-IP test between two identities at
startup, not on the option being present.

**Obligation pinned (the price of "installation not codebase"):** the bundled Tor binary is
version- + sha256- + signature-pinned (one line in `AUDIT_SCOPE.md`; Guix reproduces it as a
pinned-hash input — `17-dependency-discipline`), and the **release checklist gets a line:
track Tor security advisories → re-bundle.**

---

## 4. Recommended posture + disclosed alternatives

`P` must get its chain view (challenges, tip) from a source it can trust, but "trusted" ≠
"local" — a self-hosted remote node is equally yours. Three postures, ranked, with the risk
on each axis disclosed at the moment of choice (the silent-compliance lens — the safe path is
the loud default; deviations are disclosed costs). Note the slash is **sustained-failure-gated
(§5)**, so none of these is a single-shot bond cliff.

| Posture | TM-3 (source withholds/lies) | TM-6 (scan fingerprint) | Trade |
| --- | --- | --- | --- |
| **① Local full node — RECOMMENDED (loud default)** | **unreachable** (own validated tip) | **unreachable** (no network scan) | storage-heavy; the only posture with no third-party in the loop |
| **② Own remote node** (your hardware, over the network) | dissolves **by trust** | **live** — a generic sync pattern (fetch-everything), mitigated automatically by the per-`P` circuit + injectable cadence | storage-heavy + a wallet↔node link the per-`P` transport already wraps |
| **③ Untrusted remote daemon** | **live but bounded** — sustained, *undetected* censorship over `n` windows slashes; `P` detects failing responses and re-sources before `m`-of-`n` trips | **live** | low storage; a disclosed risk, not a cliff |

Disposition: ① is the default the wallet steers to (bond structurally unexposed); ② is a
disclosed *privacy* cost with an automatic mitigation; ③ is a disclosed cost the user opts
into — *"using someone else's node, if it consistently fails to deliver your challenges or
relay your responses, can eventually cost your bond, and it sees your traffic — run your own
node, here or on your own server."*

**Daemon observability — the two-axis read-model (settled by SP-T2 Round-0, measured 2026-07-02).**
The postures differ in *what the daemon-facing surface leaks*, and weighing **one** axis (persona
unlinkability) in isolation briefly pulled the recommendation toward remote-over-Tor; weighing
**both** axes re-confirms own-node:

- **Scan-pattern confidentiality:** ①/② leak *nothing to a stranger* — the scan terminates at your
  own daemon. ③ shows a third party the scan itself (every requested height, per connection; height
  trajectories are also cross-session fingerprints), and Tor anonymizes *who* is scanning, not
  *what* is scanned.
- **Persona unlinkability:** ①'s enumeration residual — N distinct `127.0.0.1` connections make the
  persona count readable from the **host TCP table** (an OS-level fact below the RPC layer; measured:
  no RPC field exposes it, and no per-IP cap gates it) — is observable **only from the box itself**,
  where an adversary already has strictly stronger tools (`/proc`, wallet memory); it is the *least*
  of a compromised host's problems. ③ unlinks personas on the network path but re-exposes them to
  the terminating daemon: N terminating connections, **arrival-synchronized tip fetches** (every new
  block, all N personas fetch within a small window — a deterministic steady-state correlation), and
  a residual timing coupling (measured ~0.3 ms, scheduler-level, post-lock-free-read).

Net: **run your own node (① here, ② on your own server) is the privacy default**; ③ is the
**actively-discouraged** fallback for users who genuinely cannot run one, its residuals disclosed as
the *reasons* for the discouragement rather than silently hardened. Wallet-side mitigation of ③'s
residuals (fetch-time jitter, decoys) reopens only if ③ is ever promoted to a supported posture.
Full derivation + the measured numbers: `ARCHIVAL_BOND_2D2_SP_T2_FETCH.md` (DQ-T2.5 settled
disposition, §3 Round-0 results, §5).

---

## 5. The liveness model — ordinary, not a capital knife-edge (grounded in code)

`P`'s challenge-response is an **on-chain broadcast** (`txin_archival_serve_credit_response`,
GATE2 §5) that must mine within `(H_fire, H_credit_deadline]`. The naive read — "one missed
deadline = slash" — is **wrong**, and the code says so: the slash is **sliding-window
`m`-of-`n`** (`failure_confirmation.rs::run_sliding`) — it fires only when `miss_count >=
miss_threshold` within the last `sliding_window_epochs` baseline observations, and a *single*
transient that trips it is scored a `false_slash`, which the policy tunes `m` above the
single-outage span to drive to ≈0.002.

So a transient — a guard hiccup, one censored window — is **absorbed** by Tor's own circuit
failover + retry + the sliding window. Only **sustained** failure slashes, and at that point
the network genuinely cannot distinguish a censored honest staker from an absent one — the
bond exists to make that indistinguishability costly, so the slash is **the mechanism
working**, not a threat to defend.

Consequences for the design:

- **Multi-path N-peer broadcast is a latency nicety, not bond protection.** Submit the
  response over the per-`P` circuit; optionally to a few independent peers to land it faster
  with fewer retries. Don't build it as a capital defense.
- **"Submit early / monitor / escalate" is ordinary good behavior** (more margin, fewer
  retries), not a knife-edge protocol.
- **Origin constraint (the only privacy item here):** the response, being public-content,
  needs no content protection — only that its **origin stays in `P`-space**, never shared with
  the principal. The per-`P` circuit delivers this; the discretionary-broadcast timing
  (`_spread`/`_bond_first`) reuses the anchor-free entry-gap draw so a *bond-post* doesn't
  correlate in time with the principal's activity.

---

## 6. Serving reachability — the inbound onion (real, backoff-gated)

`P` must be **inbound-reachable** to be challenged (GATE2 §3.4: *"reachability: P must be
reachable at H_fire"*) and to answer organic retrievals — so `P` runs a **v3 Tor onion
service**. Two pins:

- **The HS key is `p_slot`-bound + seed-derived (GF-9), so the `.onion` rotates with the
  persona.** A fresh rotation presents a fresh network identity — the onion must never bridge
  the succession (that would re-open the temporal channel `P` rotation exists to break). This
  is the one serving item that touches the §0 boundary.
- **Reachability is backoff-gated, not a knife-edge.** An unreachable `P` simply retries into
  the next window; only *sustained* unreachability slashes (§5, same `m`-of-`n`). Availability
  is an economic incentive (offline `P` doesn't earn), not a privacy cliff.

The retrieval *pattern* and the served shard set are **public by design** (§0) — they map to
`P`'s public holdings, not to the principal — so they are not a channel to defend.

### 6a. Serving-side hardening — the inbound implementation threat model (SP-T3)

The onion is an **inbound** surface, and that is a *different actor shape* from everything
built for SP-T0/SP-T1/SP-T2. Those are outbound or loopback: SP-T0's control client is one
**trusted** loopback request/reply connection; SP-T1/SP-T2 **dial out**. The onion service
instead **accepts** connections from **untrusted** remote peers over high-latency circuits —
so it does **not** inherit SP-T0a's single-mailbox actor pattern (the SP-T0a module doc's
head-of-line note is benign on loopback control but becomes a real DoS here). Three
protections, the inbound analogues of the client-side ones already shipped:

- **Decoupled accept loop.** The listener runs on its own `tokio::spawn`, and each accepted
  connection is handled **off** the actor mailbox (spawn-per-connection), so one slow peer or
  a stalled rendezvous circuit cannot head-of-line-block the service.
- **Per-connection timeouts.** Tor circuits carry large, attacker-influenced latency, so every
  accept→read step is `tokio::time::timeout`-bounded; a stalled peer is dropped rather than
  holding a file descriptor, bounding FD exhaustion. (The client side is already bounded —
  `HANDSHAKE_READ_TIMEOUT`, the DQ-T0.4 dial `CAPTURE_TIMEOUT`.)
- **Payload bound.** A `max_request_size` caps an inbound request **before** allocation, so a
  hostile peer cannot flood memory with an oversized payload — the inbound mirror of the
  control framer's `MAX_REPLY_BYTES` (already carried as an "adversarial-network bound").

These are **requirements pinned for SP-T3's build, not code now** (`21`): the inbound listener
has no consumer until the onion serving surface exists, so provisioning it earlier is exactly
the speculation the `owned_net`-extraction discipline avoided. Captured here so SP-T3 starts
with the serving threat model in hand rather than rediscovering it under a live onion.

---

## 7. The threat model (the one privacy axis)

**Adversary:** C2 (network observer — guard-level + timing-correlation, the case Tor does not
defeat) and C3 (infrastructure operator), with the patience multiplier.

**The only question:** can the adversary tie the **origin** of `P`'s network activity to the
principal? It can **only** if they share an origin — same IP, same circuit, or `P`'s emission
timing correlating with the principal's *separate* activity. Per-`P` circuit isolation severs
the first two by construction. The residual is the third — **`P`-emission vs principal-emission
timing** — and it is *not* "hide when `P` acts" (the response window is public, deterministic;
nothing to hide) but the narrower "do not run `P` and the principal over a shared or
time-correlated path," which the per-`P` transport already largely delivers.

Everything else an observer sees of `P` — shards, rewards, responses, serving, `P`↔`P`
clustering — is conceded by §0 and is **not in the threat model.**

**TM-5 (counterparty) folds here:** what a JoinMarket bond co-participant observes at the
network layer (coordination endpoint, signing-circuit) — a closer observer than C2, and a
transport-layer question (does the coordination path share origin with `P`'s or the
principal's), not a separate round. Bound the join's anonymity set against a Sybil fraction.

---

## 8. Explicitly out of scope (with reasons)

- **Censored-region Tor reachability (bridges / pluggable transports).** The Tor Project's
  domain; we use defaults (deviation = signature) and **link to their bridge docs**. Also not
  a capital cliff (§5 absorbs transient blocking; sustained regional censorship is
  indistinguishable from non-service and correctly slashes — the operator's connectivity to
  fix). A documentation pointer, not a build.
- **Hiding `P`'s public life** (shards, earnings, responses, serving, `P`↔`P` linkage) — §0.
- **Embedded in-process Tor (Arti)** — rule-21 reopen if the bundled-daemon UX or SOCKS-
  isolation guarantee proves untenable.

---

## 9. Genesis & supply-chain

2d-2 is **off-wire wallet/transport behavior — nothing new freezes** (the one genesis-relevant
pin, injectable cadence, is already placed in 2d-1). The single genesis-adjacent item is the
**bundled Tor binary as a supply-chain input** (pin + verify + `AUDIT_SCOPE.md` + Guix
reproduction + the re-bundle release line — §3), handled under `17-dependency-discipline`, not
a consensus change.

---

## 10. DQ summary, build order, reopen anchors

| DQ | Disposition |
| --- | --- |
| DQ1 — boundary | Network-resource disjointness; per-`P` injected transport (§1) |
| DQ2 — transport mechanism | **Resolved**: bundled wallet-owned Tor over SOCKS, per-`P` `IsolateSOCKSAuth` (§3) |
| DQ3 — discretionary broadcast timing | Wire `_spread`/`_bond_first` over the per-`P` circuit, anchor-free draw (§5) |
| DQ4 — tip currency / TM-3 | Resolved by **posture** (§4), not multi-source machinery; untrusted-remote keeps the bounded risk |
| DQ5 — reconcile GC | Consume `PReconcileSet`, GC only on confirmed-absence; **gated on PR-201** (§2) |
| DQ6 — counterparty (TM-5) | Folds into transport (§7) |

**Build order:** bundled-Tor lifecycle + the per-`P` `Agent`/SOCKS client + the
different-exit verification test (the isolation claim rides on it being measured) → the
`BlockSource`/`DaemonEngine` Tor impl behind SP-0 → the v3 onion service (GF-9 HS rotation) →
discretionary-broadcast timing (DQ3) → reconcile GC (DQ5, after PR-201).

**Reopen anchors (`21`):** embedded Arti (if bundled-daemon UX/SOCKS isolation proves
untenable); multi-source tip (if a real staker posture other than ①/② emerges that the
posture disposition does not cover); per-`P`-`Agent` shape — **verified per-`Agent` in ureq 3.3.0**
(SP-T1, PR #204), so this anchor is closed unless a future ureq moves proxy to per-request.

## 11. Round 0 — landed substrate (grounded at source, 2026-06-28)

The scoping framing (§0–§10) is frozen. Round 0 turns it into a buildable decomposition,
starting one layer deeper than §2: the *real* substrate, read at the function, not the seam name.

**The transport surface map — three daemon-access surfaces; only one is `P`'s.**

| Surface | What it is | Whose circuit | 2d-2's relationship |
| --- | --- | --- | --- |
| **SP-0 `BlockSource`** (`engine-core/pscan/block_source.rs`, over `shekyl-rpc-client`) | the per-`P` fetch keystone — whole-block-by-height, **no selective fetch** (isolation is the trait's *shape*). 2d-1 ships `DaemonBlockSource`, a placeholder over an existing `DaemonEngine`. | **`P`'s** | **the seam 2d-2 implements** — the real per-`P`-isolated transport goes *behind this trait* |
| `cli/daemon.rs::DaemonClient` (`ureq` + SOCKS) | the lightweight, "independent-of-wallet2-FFI" client for unauthenticated CLI queries (`get_info`, …) | **principal's** | a circuit `P` must stay disjoint from; the `IsolateSOCKSAuth` *model* |
| `engine-core::DaemonClient` over `SimpleRequestRpc` | the wallet2-FFI refresh path | **principal's** | the other circuit `P` must stay disjoint from |

The firewall requirement is exactly: **`P`'s `BlockSource` transport shares a circuit with
neither principal surface.** That is the whole of half (A).

**What 2d-1 explicitly defers to 2d-2 (from the SP-0 trait doc), reconciled to §0–§10:**

| 2d-1 `block_source.rs` says | scoping decision | Round 0 disposition |
| --- | --- | --- |
| "swaps an **Arti** transport behind the same trait" (:15) | DQ2: **bundled Tor over SOCKS, not Arti** | per-`P` SOCKS-auth `ureq` client, not Arti; **2d-1 comment is stale** → SP-T5 |
| isolation: "separate connection, no shared cache" (:16-17) | §1 boundary (network-resource disjointness) | the load-bearing build → **SP-T1/SP-T2** |
| tip-currency "needs multiple `P`-isolated sources" (:90) | DQ4: resolved by **posture**, not multi-source | posture, not machinery; **2d-1 comment is stale** → SP-T5 |
| absence-proof "requires header-chain anchoring" (:99) | already **SP-7** (2d-1 funding gate) | unchanged — 2d-1's job |

**The isolation lever, grounded.** `IsolateSOCKSAuth` keys a distinct Tor circuit on the SOCKS
**username**. In `cli/daemon.rs` the proxy is bound **per-`Agent`** (`config_builder.proxy(…)`,
not per-request) — so *a distinct circuit needs a distinct `Agent`*. And the username the
doc-comment claims (`shekyl-cli-daemon`) is **not wired** — `main.rs:135` passes `--proxy` raw,
no username — so today's "separate circuit" is aspirational. 2d-2 **wires** the username,
**per-`P`**. (This is why SP-T1, not SP-T2, is the keystone: the circuit, not the fetch.)

**Principal-side isolation is a separate ticket — deliberately out of this round.** The principal's
two `DaemonClient`s sharing one no-auth circuit is *within-principal* correlation (it links two
principal streams to one user — true, and already principal-side), so it never crosses the
`P↔principal` boundary, and the firewall claim does not depend on it (`P` is isolated via its
per-`P` username regardless). The sharper reason to keep it out: wiring the principal to
`IsolateSOCKSAuth` gives the principal **non-empty** usernames, introducing a **namespace-collision
obligation** with `P`'s usernames — and a collision (`P` + principal on one circuit) *is* the
firewall break. This round keeps the collision-free invariant — **principal = empty, `P` =
non-empty** (§13(b)) — and leaves principal-side isolation to its own ticket, with its own care.

---

## 12. SP-# enumeration (half A buildable now; half B gated on SP-6)

`SP-T#` = transport (half A), `SP-R#` = reconcile (half B), to avoid collision with 2d-1's `SP-#`.

**Half (A) — transport (unlinkability-critical; buildable now):**

| SP | Deliverable | Depends on |
| --- | --- | --- |
| **SP-T0** | **Bundled-Tor lifecycle** — wallet owns/launches/health-gates/shuts-down a Tor child process; wallet-private SOCKS + control port; **reuse-not-own packaging** (Guix + hash-pin, §15). | — (foundation) |
| **SP-T1** | **Per-`P` SOCKS-auth client + the circuit-ID verification test** — a `ureq::Agent` with a **persona-derived SOCKS username** (→ distinct `IsolateSOCKSAuth` circuit); test asserts **control-port circuit-ID disjointness** (§15). **The keystone.** | SP-T0 |
| **SP-T2** | **The `BlockSource` Tor impl** behind SP-0 — `P`'s whole-block fetch over its SP-T1 client, **added *beside*** the direct-localhost source (posture→impl per §478; *not* a replacement of `DaemonBlockSource` — see `ARCHIVAL_BOND_2D2_SP_T2_FETCH.md` §0). | SP-T1, SP-0 (landed) |
| **SP-T3** | **v3 onion serving** (GF-9) — `P`'s inbound onion; HS key `p_slot`-bound, rotates with the persona; published only while serving; backoff-gated. | SP-T0; GATE2 serve/challenge surface |
| **SP-T4** | **All `P` broadcasts** — origin-in-`P`-space *always* (discretionary `_spread`/`_bond_first` **and** the deadline-critical challenge-response submission), write-side no-principal-path (CX-2); anchor-free *timing* where applicable. | SP-T1; broadcast stub |
| **SP-T5** | **Reconcile the stale 2d-1 comments** (Arti→SOCKS, multi-source→posture) — small code-only PR. | — |

**Half (B) — reconcile (completeness-critical; gated):**

| SP | Deliverable | Gated on |
| --- | --- | --- |
| **SP-R0** | **Reconcile GC over the per-`P` transport** — consume SP-6's `PReconcileSet`; GC phantom `bonded_slots`/`p_slot` **only** on confirmed-absence within `covered`. | **SP-6** (`PReconcileSet`, not built — downstream of PR-B) |

**Out of this round (separate ticket):** principal-side `IsolateSOCKSAuth` — wiring the principal's
two `DaemonClient`s to non-empty usernames. Kept out to protect the firewall round's collision
invariant (principal = empty, `P` = non-empty; §11 / §13(b)).

---

## 13. Type-safety — make sharing the principal's circuit *unrepresentable*

SP-0 already makes the selective-fetch leak unrepresentable (no method to call). 2d-2 adds the
*circuit* half: building a `P`-transport that rides the principal's — or another persona's —
circuit must be **uncallable**, not merely discouraged — the DQ1 move, one layer down.

- **`PCircuitTag` carries three invariants, pinned on the type — not in a comment.** It is derived
  from the active persona binding (`p_slot` / `p_canonical_id`), **not** free-form; SP-T1 computes
  the SOCKS username `derive_socks_user(tag)` from it. That derivation is load-bearing in three
  distinct ways. (b) and (c) are enforced **by construction, not by `debug_assert!`** (CX-1): the
  assert is compiled out in release — an empty username would escape (b) — and a *per-call* assert
  cannot see a *cross-call* injectivity break (c) at all. So `derive_socks_user` returns a
  `SocksUsername` newtype = fixed-width hex of **cSHAKE256** over the full `p_canonical_id`
  (customization `shekyl/p-socks-user-v1`, mirroring `derive_output_handle`), **non-empty by
  construction** (b, absolute) and **collision-resistant** (c, negligible-collision — not literal
  injectivity); a pinned KAT + an injectivity test then *verify*, not *enforce*
  (the SP-0 / SP-T2 bar):
  - **(a) local-only.** The username is host↔Tor (`IsolateSOCKSAuth`), never on the wire — the only
    exposure is a local log artifact (C6/forensic), so it is **not logged.**
  - **(b) non-empty ⇒ disjoint from the principal.** This round's core invariant is *principal =
    no-auth (empty username), `P` = always non-empty.* An empty or principal-colliding username
    puts `P` and the principal on the **same circuit** — the firewall break itself. The derivation
    **structurally guarantees non-empty**, so the invariant survives a future principal-isolation
    ticket (which gives the principal non-empty usernames, and with them a collision obligation —
    §11).
  - **(c) per-persona distinct (collision-resistant, not literal injectivity).** Two personas
    sharing a username would share a circuit, **bridging the succession at the network layer** — the
    same temporal break as a shared onion across rotation. The username derivation thus performs the
    **circuit-side analogue of GF-9 onion-rotation**; this per-persona distinctness is
    temporal-channel protection, not incidental. It is collision-resistance, not a literal injection:
    two personas collide only on a cSHAKE256 collision — negligible at 256-bit width (and an operator
    runs only a handful of personas).
- **No principal path in.** SP-T2's `BlockSource` impl is constructible **only** from an SP-T1
  per-`P` client — no `From<principal DaemonClient>`, no `Default`. The principal's `DaemonClient`
  (cli or engine) cannot be coerced into `P`'s `BlockSource`; the carrying type won't take it.
  Mirrors `PScanCursor` not being passable where `BlockchainTip` is expected (DQ1).
- **One Tor process, never one circuit.** `P` and the principal share the bundled Tor *process* but
  never a *circuit*: invariants (b)+(c) make "distinct usernames → distinct circuits" the only
  representable state — riding on the persona-derivation the type guarantees, not on operator config.
  One process *does* mean a **shared guard set** — the §7 guard-level/timing residual; severing it
  via separate instances is *worse* (a non-default config is itself a guard-visible fingerprint), so
  the coupling is the deliberate trade, not a gap to fix (§16).

---

## 14. Dependency posture — the keystone, build order, parallelism

- **Keystone: SP-T1** (per-`P` client + the circuit-ID verification test). All of half (A)
  rides on it, and it is **buildable now** — SP-0 is landed, `ureq`+`socks-proxy` is in-tree
  (`shekyl-cli`), and `cli/daemon.rs` is a working (single-username) model. The test is
  load-bearing and must measure the *right* property: control-port **circuit-ID disjointness**, not
  exit-IP (unsound here — §15) — "verify at source," applied to the circuit itself.
- **Build order:** SP-T0 ∥ SP-T1 → SP-T2 → SP-T3 ∥ SP-T4 → **SP-R0 (after SP-6)**. SP-T5
  (comment fix) any time.
- **SP-T1 splits — sequence so the measured half doesn't stall.** The *type half* (`SocksUsername`
  newtype, `PTorClient::for_persona`, the no-principal-path / no-`Default` enforcement — where the
  CX-1/CX-2 closures become *code*) is buildable **now**, no Tor needed: it is what makes sharing a
  circuit unrepresentable at compile time. The *measured half* (the control-port circuit-ID test) is
  the entire reason SP-T1 is the keystone — *"design → measured property"* — and it needs SP-T0's
  running Tor (SOCKS + control port). So build the type half immediately **and stand up SP-T0's
  Tor-with-control-port harness alongside** (even a minimal test instance), rather than treating
  SP-T0 as strictly downstream — or the keystone's load-bearing half waits on an unstarted SP-T0.
- **Parallelism:** SP-T0 and SP-T1 co-develop (T1's test needs T0's SOCKS port; the client *shape*
  designs against a fixture). SP-T3 (inbound serving) is independent of SP-T2 (outbound fetch) once
  SP-T0 exists. SP-R0 is the only gated item.
- **The gate, stated:** half (B) cannot land until SP-6 (`PReconcileSet`) exists (downstream of
  PR-B). Half (A) does **not** wait on it — the transport is independent of the reconcile.

---

## 15. Per-SP design (enforcement-point-with-the-type)

Detail for the load-bearing SPs; the rest carry their §12 contract.

**SP-T1 — the per-`P` SOCKS-auth client (keystone).**

- *Type (landed — `shekyl-p-transport`, PR #204):* `PTorClient { agent: ureq::Agent, username:
  SocksUsername }`, built by `PTorClient::for_persona(&PCircuitTag, &TorSocksEndpoint)`. The
  username is `derive_socks_user(tag)` = **cSHAKE256** over the full `p_canonical_id` (customization
  `shekyl/p-socks-user-v1`) — persona-derived, never an argument; **no** constructor takes a username
  or a principal client. `SocksUsername` is non-empty + injective *by construction* (the CX-1
  closure); `PCircuitTag` has a truncated `Debug`, and the proxy error carries only the `SocketAddr`
  endpoint — never the username-bearing URI (invariant (a)); `TorSocksEndpoint` is a `SocketAddr`
  (IPv6-safe, URL-injection-unrepresentable); `PTorClient` is `Send + Sync` (actor state). Proxy is
  bound **per-`Agent`** in ureq 3.3.0 (verified) → one Agent per `P`.
- *Verification test (ships with the enabler, not deferred) — control-port circuit-ID
  disjointness:* over `P`'s client and a principal (no-auth) client, issue one request each to
  *distinct* targets, read the two `STREAM` events' **circuit IDs** from the Tor **control port**,
  assert they differ. This measures circuit-disjointness *directly*. **Exit-IP comparison is
  unsound here** and must not be used: *different exits ⟹ different circuits* but *same exit ⇏ same
  circuit* (shared exits are normal Tor) — so an exit test cannot tell "same circuit" (the failure)
  from "different circuits, same exit" (fine), the exact case it must distinguish. The control port
  is **already open** for SP-T0's bootstrap read, so this is a second consumer, not a new dependency.

**SP-T2 — the `BlockSource` Tor impl.**

- *Type:* `PBlockSource { client: PTorClient }` implementing the landed `BlockSource`;
  `tip_height`/`block_at` go over `client`. Bump the trait `pub(crate)` → `pub` (the one-word
  change the SP-0 doc anticipates) when it implements from another crate.
- *Enforcement:* `PBlockSource::new(client: PTorClient)` is the only way in — no principal
  `DaemonClient` path, no `Default`. This is where "P fetches on its own circuit" becomes the only
  representable state.
- *Posture→impl (do not conflate):* *remote* posture ⇒ `PBlockSource(PTorClient)` (fetch over `P`'s
  circuit); *local* posture ⇒ a **direct localhost** `BlockSource` (no circuit — origin-safe
  trivially). Both origin-safe, for different reasons; the mapping is explicit so a local posture
  cannot accidentally route its fetch over a shared network circuit.

**SP-T0 — bundled-Tor lifecycle.** *(Round 0:
[`ARCHIVAL_BOND_2D2_SP_T0_TOR.md`](ARCHIVAL_BOND_2D2_SP_T0_TOR.md) — the buildable plan: the
control-port-client dependency call (lean roll-our-own), the `TorService` lifecycle + bootstrap
gate, the measured circuit-ID test that closes the keystone, reuse-not-own packaging.)* A managed
child process with a wallet-private
`SocksPort`/`ControlPort`; health-gate readiness before any `PTorClient` is handed out; shut down
on wallet close. The `ControlPort` (cookie auth) serves *two* consumers — bootstrap-progress for the
"Connecting…" state **and** SP-T1's circuit-ID check. **Reuse, never own, the Tor build** (`17`):
inherit reproducible packaging where it exists (Guix ships a `tor` package → reproducibility + a
bump-the-version update path, no maintained build) and **hash-pin the Tor Project's official
released binary** on targets you cannot build reproducibly (Windows the obvious trusted-blob
exception). The recurring obligation is then a **release-checklist line** — track Tor advisories →
bump pinned version/hash → re-verify — not a per-platform build. Failure → the §5 backoff/posture
path, not a panic. *(The Arti reopen-anchor (§10) stays anchored on its real trigger — the
SOCKS-isolation guarantee proving unenforceable — not on packaging weight: Arti trades a
binary-to-track for a large, fast-moving source tree, heavier on the supply-chain/Guix axes, not
lighter. Per-target Guix coverage for macOS/Windows is a packaging detail to work; reuse-don't-own
bounds the cost regardless.)*

**SP-T3 — onion serving (GF-9).** A v3 HS whose key is `p_slot`-bound and **rotates with the
persona**; published only while `P` actively serves; backoff-gated on repeated failure (the §5
liveness model — *not* a slash trigger). Depends on the GATE2 serve/challenge surface.

**SP-T4 — all `P` broadcasts (CX-2).** Every `P`-originated tx — the discretionary
`_spread`/`_bond_first` **and** the deadline-critical challenge-response (serve-credit) submission —
emits over the `PTorClient` circuit, with **no constructor path that accepts the principal's
`DaemonClient`** (the write-side mirror of SP-T2). The default broadcast-via-daemon path would
originate from principal-space — the write-side firewall break — so origin-in-`P`-space is enforced
by the type, not §5 prose. *Timing:* anchor-free draw for the discretionary sends (DQ3); **N/A for
the challenge-response** (§7: its response window is public — nothing to jitter, only the origin to
isolate).

> **SP-T4a (the seam) is built** — see
> [`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md`](ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md): a per-`P`
> `PTransactionSubmitter` (no principal-`DaemonClient` path) + a broadcast `Posture` that
> **forbids ③ by type** — a *different, narrower* type than the fetch `Posture`, with **no
> `ThirdParty` variant at all**, because first-seen-origin is a discrete, categorical, avoidable
> leak where fetch-③ is continuous, statistical, and unavoidable (the read/write selectors are
> deliberately different types) — plus the axis-4 `DaemonAmbiguous` retry contract. Production
> wiring of the discretionary consumer is gated on the funding/tx-assembly + 2c-2a/2c-2b
> `StakeEngine` wiring, **not** on the seam. **SP-T4b** (the deadline-critical challenge-response
> submission) reuses this seam once a GATE2 wallet-side build/sign/submit producer for
> `ArchivalServeCreditResponse` exists. The **GF-7** principal-timeline timing residual is a
> **genesis gate** (measured `P(link | T_obs)` before launch), not a deferred round.

**SP-R0 — reconcile GC (gated).** On SP-6's `PReconcileSet`, GC phantom `bonded_slots`/`p_slot`
**only** on confirmed-absence within `covered` (the SP-6 rule); never on absence-from-one-source.
Designed here, built after SP-6. **Frame the removal around the slot ledger** (2d-1 records-driven
retirement): the done-side record is *authoritative*, the live `bonded_slots` is *advisory*, and
no-reuse is already enforced by `StakingBlock::monotone_current_slot` (`staking_block.rs:75`) — so
SP-R0's job is the *removal*, not the trigger, and `covered` *corroborates* the presence-events the
ledger expects.

**Carried from the SP-6 part-2 (PR #211) review — pin so SP-R0 picks them up:**

- **Prune-on-retire (correctness, not optional).** SP-6's match set accumulates **monotonically**:
  `ingest` only appends (`accrual.rs`), nothing prunes — correct for SP-6 (a match must survive until
  SP-R0 corroborates it, ~`MAX_CLAIM_AGE_W`≈270k blocks later), but it means **SP-R0's durable removal
  must prune a persona's matches when it retires the slot**, in the *same atomic step* that drops the
  `bonded_slots` entry (and the `pending_unbonds` entry). Otherwise the persisted `bond_post_matches`
  set grows unbounded over the wallet's life. The seal-cost comment already flags the per-post growth
  profile; the **bound on that growth is this retire-time prune** — it belongs with the slot-ledger
  removal, not as a separate pass.
- **`reconcile()` index (optimization, only if it profiles hot).** `PReconcileSet::reconcile` is a
  linear scan over `matches` per persona — fine here (the GC is infrequent and `bonded_slots` is
  small), but if SP-R0 ever reconciles *many* phantom slots against a *large* match set, build a
  `HashMap<PCanonicalId, &BondPostMatch>` once at reconcile time to turn `O(slots × matches)` into
  `O(slots)`. **Premature to build now** — note it, don't pre-optimize.

**Defense-in-depth recorded (free, no action):** the GC's "absent ⇒ phantom" inference is fail-safe
even if the genesis-start assumption were violated. `covered` starts at `[0, 0)` and `P` scans from
height 0 (required for "absent anywhere" to be meaningful), but if `covered.low()` were ever non-zero,
the half-open gate in `reconcile()` returns `OutsideCovered` for the unscanned prefix — **never** a
wrong `AbsentWithinCovered`. The exhaustiveness-from-genesis invariant is enforced by the cursor and
*fails safe at the query* if it were ever violated.

---

## 16. Threat-model cross-check (closing Round 0)

Each SP walked against the §7 invariant — *can the adversary tie `P`'s network origin to the
principal?* — severity-ordered. The walk found two SPs where "unrepresentable" was claimed or
implied but **not yet built**; both are fixed into §13/§15 above, on paper, **before SP-T1** — which
is the cross-check earning its place.

| # | SP | Finding | Disposition |
| --- | --- | --- | --- |
| **CX-1** | SP-T1 (keystone) | `PCircuitTag` (b)/(c) cannot rest on `debug_assert!` — it is compiled out in release (an empty username escapes (b)), and a *per-call* assert cannot see a *cross-call* injectivity violation at all (so (c) is uncheckable that way). | **Fixed (§13):** `derive_socks_user` returns a `SocksUsername` newtype **non-empty by construction** (fixed-width hex of `H(domain_sep ‖ p_canonical_id)`) and **injective by construction** (collision-resistant hash over the *full* `p_canonical_id`, no truncation/modulo). `debug_assert!` + an injectivity test become *verification*, not enforcement — the SP-0/SP-T2 "make it unrepresentable" bar. |
| **CX-2** | challenge-response broadcast | The deadline-critical serve-credit response (the §5 liveness tx) is an outbound broadcast that is **not** discretionary (SP-T4 as written), **not** a fetch (SP-T2), **not** the inbound onion (SP-T3) — it fell through the SPs, and the default broadcast path is the daemon connection (principal-space → the **write-side** break). §5 had it in prose only. | **Fixed (§12/§15):** broaden SP-T4 to **all `P` broadcasts** — origin-in-`P`-space *always* (rides `PTorClient`, no constructor accepting the principal's `DaemonClient`, the write-side mirror of SP-T2); discretionary *timing* where applicable, N/A for the response (public window). |

**Two notes recorded (correct as-is — do not "fix"):**

- **SP-T0 guard coupling is the deliberate §7 residual.** "One Tor process, never one circuit"
  (§13) means `P` and the principal share one **guard set** — exactly where §7's named residual
  (guard-level + timing correlation, the case Tor does not defeat) lives. Severing it means
  *separate Tor instances*, which is **worse**: a non-default config is itself a fingerprint to any
  guard observer (a weaker adversary than the correlator the shared guard exposes). Accept the
  coupling; the doc states it so a future reader does not split instances.
- **SP-T2 posture→impl mapping.** `PTorClient`-only closes the *remote* fetch. The *local* posture
  fetches over **localhost** (no circuit; origin-safe trivially) — a **different** `BlockSource`
  impl. Pin the mapping — *remote ⇒ `PBlockSource(PTorClient)`; local ⇒ direct localhost* — so the
  local posture cannot accidentally route its fetch over a shared network circuit.

**Closes clean:** SP-T3 (onion = inbound origin-isolation; GF-9 rotation = the inbound analogue of
CX-1(c); publish/unpublish tracks `P`'s public bond, no new leak; shares the SP-T0 guard residual),
SP-T5 (no origin surface), SP-R0 (reads ride the per-`P` transport; GC is internal/invisible — the
DQ8-retire fetch-everything + fixed-cadence argument; gated on SP-6).

**Round 0 closes with the §7 invariant shut** for the read side and the type — modulo the two fixes
folded above, made on paper rather than retrofitted around the first build.

---

## 17. Considered and refuted (the round's grounding journey)

Recorded deliberately — the dead ends save the next designer the rounds they cost here. The
throughline: **ground the mechanism in the *implementation* before building on it** (read the
function, not the grep — each item below was rigorous analysis of a mechanism the code does
not implement). The scope shrank to §0–§7 precisely *because* these collapsed.

| Premise built on | Disposition | Grounded at |
| --- | --- | --- |
| **Serving requires a full validating node → scan is forced local → TM-3/TM-6 dissolve** | **Refuted.** The chain model is light-client (daemon serves leaves, wallet verifies vs. per-block header `curve_tree_root`); no doc requires a validating node. Remote scan is a supported posture, not a phantom. | `CURVE_TREE_CLIENT.md`; grep for "full node required" (empty) |
| **Slash forces a *local* node** | **Refuted.** "Trusted" ≠ "local" — a self-hosted *remote* node is equally trusted. The real structure is the three-posture taxonomy (§4): trust dissolves TM-3 (local *or* own-remote); only locality dissolves TM-6. | the posture analysis, §4 |
| **Challenge-response is a single-missed-deadline capital knife-edge** | **Refuted at the code.** The slash is **sliding-window m-of-n** — `failure_confirmation::run_sliding` slashes only when `miss_count >= miss_threshold` within the window; a single transient is a scored `false_slash` the tuning avoids. A transient is absorbed by retry + Tor failover; only *sustained* failure slashes (the mechanism working). | `run_sliding`, `ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` |
| **Multi-path liveness has a privacy tension (N paths = N origin exposures)** | **Dissolved.** `P` is public (§0); the vin is public-content; multi-path only keeps each path's origin in `P`-space, never the principal's — no competing privacy axis. So multi-path is a *latency nicety*, not bond protection. | §0 charter + §5 |
| **Guard-level censorship is a hard liveness floor needing bundled PT/bridges** | **Over-scoped → out of scope.** Default-Tor guard behavior is correct (deviation creates a signature); reaching Tor where it is *blocked* is the Tor Project's cat-and-mouse — a doc pointer (§8), not our machinery — and §5's backoff makes it not a capital cliff. | Tor SOCKS/guard model (§3) |
| **Operator runs K *simultaneous* personas; cardinality is a structural 2d-2 hand-off** | **Retracted** — the design is sequential (`stake_engine`: "never two active personas"); the channel does not exist. | `ARCHIVAL_TM1_CLUSTERING.md` §0 |

The cost of not grounding first was real — several rounds of analysis on mechanisms the code
forecloses. This record exists so the next round starts from the grounded model.

---

## Revision history

- **2026-06-28:** Created. Boundary (network-resource disjointness) + the §0 P-is-public
  charter; DQ2 resolved (bundled wallet-owned Tor over SOCKS, managed-child-process lifecycle,
  per-`P` `IsolateSOCKSAuth`, default-Tor, verify-by-measurement); posture taxonomy; the
  liveness model grounded in `run_sliding` (sliding-window `m`-of-`n`, not a single-shot
  cliff); serving onion with `p_slot`-bound HS rotation; the narrow origin-only threat model;
  censorship-circumvention out of scope; §17 records the considered-and-refuted journey.
- **2026-06-28 (Round 0):** Added the buildable decomposition (§11–§15), grounded at source:
  the transport surface map (P's seam = behind SP-0 `BlockSource`; the two `DaemonClient`s are
  the principal's); three stale 2d-1 comments reconciled to the scoping decisions (Arti→SOCKS,
  multi-source→posture) and the unwired `IsolateSOCKSAuth` username flagged; SP-T0–T5 (half A)
  and SP-R0 (half B, gated on SP-6); the `PCircuitTag`/`PTorClient` type-safety move; keystone =
  SP-T1 (per-`P` client + measured different-exit test). Considered-and-refuted renumbered §11→§16.
- **2026-06-28 (Round 0 discussion):** Resolved the four open calls. (1) Principal-side isolation →
  separate ticket, to keep the empty-vs-non-empty collision invariant out of the firewall round's
  core (§11/§12). (2) The `PCircuitTag` username escalated from a no-log note to **three type-pinned
  invariants** (§13): local-only (a), non-empty/principal-disjoint (b, firewall-critical), injective
  in `p_slot` (c, temporal-critical — the circuit-side analogue of GF-9 onion rotation). (3) SP-T1's
  test pinned to **control-port circuit-ID disjointness** (exit-IP unsound: same-exit ⇏ same-circuit);
  the control port is already open for SP-T0 bootstrap (§14/§15). (4) Bundled Tor stands; cost bounded
  by **reuse-not-own** (Guix package + hash-pinned official binary, release-checklist update), Arti
  anchor stays on its real trigger not packaging (§15).
- **2026-06-28 (Round 0 close — threat-model cross-check, §16):** Walked each SP against §7; found
  and fixed two gaps **before build**. **CX-1** (keystone): `PCircuitTag` (b)/(c) moved from
  `debug_assert!` to **by-construction** (`SocksUsername` newtype — non-empty + injective; assert +
  test now *verify*, not enforce). **CX-2**: the challenge-response broadcast had origin-isolation in
  §5 prose but no enforcing SP, so SP-T4 broadened to **all `P` broadcasts** (write-side
  no-principal-path). Two correct-as-is notes recorded (SP-T0 shared-guard = the deliberate §7
  residual; SP-T2 posture→impl mapping). §7 closes for the read side and the type.
  Considered-and-refuted §16→§17.
- **2026-06-28 (SP-T1 type half landed — PR #204):** Reconciled the doc to the code. §15 type
  sketch → the landed `PTorClient { agent, username }` + cSHAKE256 derivation; §13 names the
  primitive (cSHAKE256, not a generic hash); §14/§10 mark the ureq per-`Agent` reopen anchor
  **verified-clear** (3.3.0 `Config::proxy`, no per-request override). Review hardening folded into
  the crate: `SocketAddr` endpoint (IPv6-safe), truncated `PCircuitTag` `Debug`, username-leak-free
  proxy error, `Send + Sync`. The measured half (control-port circuit-ID test) still ships with SP-T0.
- **2026-06-29 (SP-T1 type follow-up landed — PR #209):** `PCircuitTag` was the **placeholder** named
  throughout §13/§15/CX-1; #205 having promoted the persona id to `shekyl_types::PCanonicalId`, SP-T1's
  `derive_socks_user`/`for_persona` now take `&PCanonicalId` and `PCircuitTag` is **deleted**
  (byte-preserving — the pinned username KATs are unchanged). **Read every `PCircuitTag` above as
  `PCanonicalId`:** the type-safety rationale (the three CX-1 invariants on `SocksUsername`, the
  unrepresentability bar) holds verbatim — only the *input* newtype changed from a local placeholder to
  the workspace type the engine already threads.
