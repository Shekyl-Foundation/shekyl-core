# 2d-2 SP-T2 — the per-`P` block-fetch `BlockSource` (Round 0)

**Status:** ROUND 0 — scoping pre-flight (2026-07-02). Deepens the
`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` §478 SP-T2 sketch into a buildable plan. No code yet.
**Scope:** the production `BlockSource` implementation `P` uses to fetch whole blocks over its
**own** per-`P` circuit (the SP-T1 `PTorClient`), plus the daemon-side observability investigation
the fetch model depends on. SP-T2 sits behind SP-0's `BlockSource` trait (`shekyl-engine-core`).
**Parent designs:** `ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` (§4 posture, §478 SP-T2, §416 no-principal-path),
`shekyl-p-transport` (SP-T1 client, PR #204), `ARCHIVAL_BOND_2D2_SP_T0_TOR.md` (the SOCKS endpoint).
**Process rules:** `26-sub-pr-design-discipline` (this round); `05-system-thinking`;
`20-rust-vs-cpp-policy` (the daemon axis); `21-reversion-clause-discipline`; `17-dependency-discipline`
(the RPC transport). Mission lens: **#1 (privacy is the product)** is binding — the daemon
investigation below is a *privacy* investigation wearing a throughput costume.

---

## 0. What SP-T2 is — **add**, not replace (the framing correction)

The transport-plan summary table (§367) says SP-T2 is "the live impl **replacing**
`DaemonBlockSource`." That is wrong, and the detailed §478 already contradicts it:

> *remote* posture ⇒ `PBlockSource(PTorClient)` (fetch over `P`'s circuit); *local* posture ⇒ a
> **direct localhost** `BlockSource` (no circuit — origin-safe trivially). … the mapping is explicit
> so a local posture cannot accidentally route its fetch over a shared network circuit.

So SP-T2 **adds** the Tor-isolated `PBlockSource` *beside* the direct-localhost source, both behind
one `BlockSource` trait, **posture-selected**. There is no privacy reason to route your *own*
loopback node through a Tor circuit; the local posture keeps a direct `BlockSource` (that is what
`DaemonBlockSource` is, once given a per-`P` connection — DQ-T2.4). §367 is corrected to "add" in
this round.

---

## 1. The substrate (grounded)

- **The seam:** `BlockSource` (`shekyl-engine-core/src/engine/pscan/block_source.rs`) — `pub(crate)`
  today, with `tip_height() -> BlockHeight` and `block_at(h) -> Option<ScannableBlock>` (an
  `Ok(None)` = *provable* absence, a 2d-2 property; the 2d-1 `DaemonBlockSource` returns `Err` for
  missing because it cannot prove absence). The trait doc anticipates the `pub(crate)` → `pub`
  bump "when 2d-2's transport needs to implement it from another crate."
- **The placeholder:** `DaemonBlockSource<D: DaemonEngine>` — a firewall-*shaped* view over an
  **existing (shared, principal) `DaemonEngine`**; establishes the interface, has **no per-`P`
  isolation**. Its block-parse is `default_fetch_scannable_block` (`engine/block_fetch.rs`), a
  **default method over the bare `Rpc` trait** — so it is reusable by any `Rpc`, not tied to the
  actor.
- **The RPC surface:** `Rpc` (`shekyl-rpc-client`, `Sync + Clone`) whose one primitive is
  `rpc_call<Params, Response>(method, params)`; every daemon method (`get_height`, block fetch, …)
  is a default over it. `SimpleRequestRpc` (`shekyl-rpc-transport`, `SimpleRequestRpc::new(url)`) is
  the concrete `simple-request`/hyper impl.
- **The circuit:** `PTorClient` (`shekyl-p-transport`, SP-T1) — a `ureq::Agent` bound to `P`'s
  per-`P` SOCKS username; `for_persona(...)` / `agent()`. The SOCKS endpoint comes from SP-T0's
  `TorService` (`current_socks()` → `TorSocksEndpoint`).
- **Consumers:** none yet — SP-T2 is the first real `BlockSource` consumer; the SP-5 scan loop is
  where the posture→impl selection lands.

---

## 2. Decision questions

### DQ-T2.1 — crate placement + the `pub` trait bump

`PBlockSource` needs the trait (`engine-core`), the block types (`ScannableBlock`∈`shekyl-scanner`,
`BlockHeight`∈`shekyl-types`), the RPC (`rpc-client`/`rpc-transport`), and the circuit
(`shekyl-p-transport`). **Lean: implement `PBlockSource` in `shekyl-engine-core`** (a sibling to
`DaemonBlockSource`, where the trait + `default_fetch_scannable_block` already live), taking a
`PTorClient` in. Putting it in `shekyl-p-transport` would invert layering (transport → engine-core).
Bump the trait `pub(crate)` → `pub` only if a cross-crate impl is actually chosen; if it stays in
engine-core, `pub(crate)` suffices and the bump is deferred (the SP-0 doc's "one-word change"
remains a one-word change). **Resolve at build.**

### DQ-T2.2 — the RPC-over-Tor transport is a **source-verified per-`P`-isolation requirement**, not an ergonomics call

`PBlockSource` fetches via `Rpc` over `P`'s circuit. Two options: reuse `SimpleRequestRpc` pointed
at `P`'s daemon through the per-`P` SOCKS proxy, or a thin `PRpc` over the `PTorClient` `ureq::Agent`.
**The deciding criterion is not ergonomics — it is whether per-instance circuit isolation survives
the HTTP layer.** `SimpleRequestRpc` is `simple-request`/hyper (async), and hyper clients pool
connections: **if two `PBlockSource`s ever share a hyper `Client`, they share a connection pool /
DNS resolver / keep-alive state, and the per-`P` circuit isolation SP-T1 proved is silently defeated
*above* the SOCKS proxy.** So this DQ is a **rule-17 source-check**: verify that each `PBlockSource`
gets its own client, its own proxy binding, and **no shared pool across personas** — the same
per-instance discipline SP-T1 verified for the `ureq::Agent` dialer. If `SimpleRequestRpc` cannot
guarantee per-instance isolation, the thin `PRpc` over the SP-T1 `Agent` is a **correctness
requirement**, not a preference. (SP-T1 already chose `ureq` precisely for raw per-`Agent` SOCKS
binding; the `Agent` is the isolated primitive — reusing it is the safe default unless the source
check clears `SimpleRequestRpc`.)

### DQ-T2.3 — posture→impl selector (no conflation)

`local` ⇒ direct-localhost `BlockSource`; `remote` (own-remote ② / untrusted ③) ⇒
`PBlockSource(PTorClient)`. Enforced structurally: `PBlockSource::new(client: PTorClient)` is the
**only** constructor — no principal `DaemonClient` path, no `Default` (§416). The selector lives at
the SP-5 scan-loop wiring, and must make "a local posture routes its fetch over a shared network
circuit" **unrepresentable**, not merely discouraged.

### DQ-T2.4 — `DaemonBlockSource` local-posture per-`P` connection (its own commit) — **and the enumeration tension**

For the local posture to be correct, each `P` needs its **own direct `127.0.0.1` connection**, not
the principal's shared `DaemonEngine` (the §1 network-resource-disjointness boundary applies even to
a local node). This is a small change to `DaemonBlockSource` (its own commit).

**But note the coin's other side:** giving each `P` its own direct loopback connection is *exactly
what makes the persona count observable to the local daemon* (DQ-T2.5 #enumeration). The per-`P`
connection is **both the isolation mechanism and the enumeration surface** — the design states this
tension where the commit lands; it is not two unrelated facts.

### DQ-T2.5 — the daemon investigation: **observability, not throughput** (measured this round)

The wallet's per-`P` transport is only real if the daemon serves N concurrent per-`P` fetch streams
**without leaking the personas to an adversary watching the daemon.** Grounded facts:
`core_rpc_server` is an `epee` HTTP server with `rpc_max_connections{,_per_private_ip,_per_public_ip}`;
block reads go through LMDB (`get_block_from_height`, MVCC concurrent readers) but the core/RPC layer
takes `CRITICAL_REGION` locks in places. Reframed to the mission-#1 lens, that is **two adversarial
questions**, each with a rule-21 disposition — the success metric is *what leaks*, never blocks/sec:

1. **Enumeration.** In the local posture, all N personas + the principal connect from `127.0.0.1`,
   so the daemon (or anything with a view of its connection table — a subpoena, a compromise, a
   co-located process) **can count concurrent per-`P` connections and infer the persona count**,
   defeating exactly the per-`P` unlinkability the firewall exists for. *Likely disposition:* this
   is a **stated privacy cost of the `local` posture**, recorded in the §4 read-model (below), not a
   throughput footnote — and an argument on the *unlinkability axis* for the remote-over-Tor posture
   (distinct circuits unlink the personas *at the network layer*; caveat that a single shared remote
   daemon still sees N terminating connections — remote hides the count from a **path/network**
   observer, not unconditionally from the terminating node).
2. **Cross-persona timing correlation.** If N per-`P` `get_block` streams **serialize on a coarse
   blockchain lock**, persona A's fetch latency becomes correlated with persona B's fetch activity —
   a shared-resource **timing side-channel** between personas that must be unlinkable. So "do N
   streams run in parallel" is partly a *privacy* question in a throughput costume. **The
   measurement must capture whether serialization is observable as a cross-persona timing signal,
   not how many blocks/sec.** *Disposition follows the measurement:*
   - **No measurable signal** (lock held for µs, swamped by Tor jitter in the remote posture): the
     rust-vs-cpp instinct holds — the lock-granularity change is a **liveness/UX** cost, deferred to
     the daemon→Rust port with a rule-21 reopen.
   - **A measurable signal:** it is a **mission-#1** item, and the fork is *who decorrelates* — the
     **wallet** (a `PBlockSource` fetch-scheduling-jitter / randomized-order responsibility, landed
     **now**) or the **daemon** (C++ lock surgery, deferred). **Default to the wallet-side
     mitigation** — it does not wait on the C++ surgery and holds regardless of which daemon `P`
     dials.

**Why measure *now*, not when the fetch path exists (the sharp reason):** the measurement's *result
changes the wallet-side design*. If #2 shows a timing signal, `PBlockSource` acquires a
timing-decorrelation responsibility (a design decision in DQ-T2.2/T2.3). Freezing the `PBlockSource`
design *before* the measurement means either over-building a decorrelation shim speculatively
(violating get-it-right-not-speculatively) or under-building and retrofitting. Measure first, and
`PBlockSource` knows what it is responsible for.

---

## 3. The measurement (Round-0 task, before the wallet design freezes)

Vehicle: a regtest/FAKECHAIN `shekyld` (the Track-2 rig) with a small block set, driven by N
concurrent `get_block`-by-height fetchers from `127.0.0.1`.

- **M-enum:** with N persona connections open, read the daemon's connection table (or the
  `per_private_ip` accounting) — confirm the count is observable, and whether the `per_private_ip`
  cap default gates N. *Output:* the §4 stated-cost paragraph + the cap default to document/set.
- **M-timing:** drive N concurrent `get_block` streams; instrument the block-fetch lock-hold under
  contention (lock-hold duration, and whether a probe persona's latency shifts measurably with
  another persona's fetch activity). *Output:* signal / no-signal, feeding the DQ-T2.5 #2 fork.

Both are read-only against a throwaway regtest chain; neither modifies the daemon.

---

## 4. Decomposition (commit-slices — one PR unless it grows exceptionally large)

Per the ~10-commit-as-CI-cost-guideline, one reviewable PR, sliced by commit:

1. **Framing + docs** — correct §367 (add-not-replace), the §4 posture enumeration read-model,
   this Round-0 doc's decisions.
2. **`DaemonBlockSource` per-`P` direct connection** (DQ-T2.4) — with the enumeration tension stated.
3. **The RPC-over-Tor transport** (DQ-T2.2) — the source-verified per-`P`-isolated `Rpc`
   (`SimpleRequestRpc`-per-instance or `PRpc`), with an isolation KAT.
4. **`PBlockSource`** (DQ-T2.1/.3) — `new(client)` only, `tip_height`/`block_at` over #3 reusing
   `default_fetch_scannable_block`; plus the timing-decorrelation responsibility **iff** M-timing
   showed a signal.
5. **Posture→impl selector** at the scan-loop wiring (DQ-T2.3) — local→direct, remote→`PBlockSource`,
   conflation unrepresentable.
6. **Daemon disposition** — record M-enum / M-timing results + the rule-21 reopen(s) in FOLLOWUPS /
   the daemon→Rust-port note.

The `Ok(None)` provable-absence property (withheld-body robustness) is **out of scope for SP-T2** —
it is header-chain-anchoring work (a later 2d-2 robustness slice); `PBlockSource` inherits
`DaemonBlockSource`'s "missing ⇒ `Err`" until then. (Rule-21 reopen: the withheld-body robustness
slice.)

---

## 5. The §4 posture read-model update (lands in the transport plan)

The enumeration finding (DQ-T2.5 #1) is a **posture property**, so it is stated in the transport
plan's §4, not buried here: the `local` posture's per-`P` loopback connections make the persona
count observable to the local daemon / its connection table — a named privacy residual that
sharpens `local` as *convenience-with-a-disclosed-cost* rather than strictly-best, and informs
(the round settles) whether the *privacy-recommended* default shifts toward remote-over-Tor on the
unlinkability axis. Draft lands in `ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` §4.
