# 2d-2 — Archival network transport & reconcile (P-isolated Tor)

**Status:** SCOPING (2026-06-28). The transport is greenfield (no Arti/Tor/onion code on
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
| `_spread` / `_bond_first` broadcast stub | **landed** (`stake_engine.rs:956-962`, `TODO(2d)`) | Wire discretionary-broadcast timing over the per-`P` circuit (§5) |

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
   `ureq::Agent` per identity (proxy/auth is per-`Agent`; **confirm against the ureq 3.x API
   before building**), which makes the per-`P` `Agent` the typed boundary (`P` cannot use the
   principal's `Agent`).
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
posture disposition does not cover); per-`P`-`Agent` shape (if ureq 3.x configures proxy
per-request, not per-`Agent`).

## 11. Considered and refuted (the round's grounding journey)

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
  censorship-circumvention out of scope; §11 records the considered-and-refuted journey.
