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
**without leaking the personas to an adversary watching the daemon.** Grounded facts (verified at
source):

- The daemon's RPC is served by **our own Rust/Axum layer** (`rust/shekyl-daemon-rpc`); the C++
  `epee` HTTP acceptor is deliberately left unbound, so its
  `rpc_max_connections{,_per_private_ip,_per_public_ip}` caps are **dead in this path and gate
  nothing** — the `per_private_ip=25` default does *not* limit N loopback personas. Axum dispatches
  into the C++ `core_rpc_server` handlers via an FFI shim.
- The real scanner fetch (`default_fetch_scannable_block`, `block_fetch.rs:79`) calls **JSON-RPC
  `get_block`**, which enters the coarse `CRITICAL_REGION_LOCAL(m_blockchain_lock)`
  (`blockchain.cpp:941`, via `get_block_by_hash`). The binary `get_blocks_by_height.bin` path reads
  LMDB directly (`get_block_from_height`, MVCC concurrent readers) and takes **no `m_blockchain_lock`**
  — a lock-free read path already exists.
- **The RPC client *and server* are ours to change** (already Rust). This widens the disposition
  space below: the fix need not be C++ lock surgery.

Reframed to the mission-#1 lens, that is **two adversarial questions**, each with a rule-21
disposition — the success metric is *what leaks*, never blocks/sec:

1. **Enumeration — an OS-level loopback residual, *below* the RPC layer.** In the local posture, all
   N personas + the principal open connections from `127.0.0.1`, so **anything with a view of the
   host's TCP table** (`ss`/`netstat`/`/proc/net/tcp`, a co-resident process, a host compromise, a
   subpoena) **can count the concurrent connections and infer the persona count**, defeating exactly
   the per-`P` unlinkability the firewall exists for. Two grounded sharpenings: (a) the leak is *not*
   an RPC field — our Axum layer today exposes **no** RPC-connection-count and enforces **no** per-IP
   cap (the epee `per_private_ip` accounting is dead), so nothing in the RPC *response* surface reveals
   N; (b) because the leak lives in the **OS network stack, below our RPC layer**, "the RPC server is
   ours" does **not** rescue `local` here — rewriting the server cannot un-see N loopback TCP
   connections. *Disposition:* a **stated privacy cost of the `local` posture**, recorded in the §4
   read-model (below), not a throughput footnote, plus a **positive design invariant** (greppable and
   testable, not a "don't make it worse" vibe): **the RPC layer holds no per-connection
   persona-distinguishing state** — no per-IP accounting, no per-connection logging that survives the
   request, no connection-count metric exposed on any endpoint. Framed as an invariant a reviewer can
   check it ("does any handler retain per-connection state?"), and it concedes the irreducible floor
   plainly: the OS loopback TCP table is below our layer, so **"our RPC, therefore private" is false
   for `local`** — loopback enumeration is an operating-system fact, not an RPC one, and one more
   reason `local` is convenience-tier while remote-over-Tor is the privacy default. It is likewise an
   argument on the *unlinkability axis* for remote-over-Tor (distinct circuits unlink the personas *at
   the network layer*; caveat that a single shared remote daemon still sees N terminating connections —
   remote hides the count from a **path/network** observer, not unconditionally from the terminating
   node).
2. **Cross-persona timing correlation — a *remote-posture* threat, measured now.** The two leaks are
   **posture-complementary, not parallel**. Enumeration (#1) is the **`local`** leak: N loopback
   connections already link the personas by source address, so timing adds nothing there — *`local`'s
   timing story is "don't care, enumeration already dominates."* Cross-persona timing is the
   **remote-shared-daemon** leak, and it is only reachable *because* remote defeats enumeration:
   distinct exit circuits unlink the personas at the network layer, so the residual re-linking channel
   is the daemon's own shared state. If N per-`P` `get_block` streams **serialize on a coarse
   blockchain lock**, persona A's fetch latency becomes a measurable function of persona B's activity,
   and a **single shared remote daemon** can **re-link the Tor-unlinked circuits** into one
   coordinated client through that coupling — undoing exactly the unlinkability remote-over-Tor exists
   to provide. So this is **mission-#1**, but *in the remote posture specifically*.

   The disposition turns on **magnitude, not presence.** A coupling of tens of µs is swamped by the
   ms-scale jitter of a Tor circuit and the re-linking fails; a coupling of tens of ms survives Tor
   jitter and the re-linking succeeds. The measurement (§3) therefore outputs the **coupling-magnitude
   distribution** — how far a probe persona's latency shifts per unit of a contending persona's
   activity, in absolute time — not a signal/no-signal boolean. The fork:
   - **Coupling below the remote-threat floor** (magnitude ≪ Tor circuit jitter): the rust-vs-cpp
     instinct holds — the lock-granularity change is a **liveness/UX** cost, deferred to the
     daemon→Rust port with a rule-21 reopen. `PBlockSource` carries **no** decorrelation duty.
   - **Coupling at or above the floor** (magnitude comparable to / exceeding Tor jitter): a
     mitigation lands, and — because the coupling *is* `m_blockchain_lock` and a **lock-free read path
     already exists** — the fork has three rungs, cheapest first:
     1. **Serve the per-`P` read lock-free** — route the fetch through a **single-height**
        `get_block_from_height` LMDB read instead of the lock-taking `get_block`, dissolving the
        cross-persona serialization *at the source* with **no wallet jitter and no C++ lock surgery**,
        in **our own Rust RPC/FFI layer**. But rung 1 is a **consistency-correctness question wearing a
        privacy fix's clothes** — free *only* if the lock-free read is **consistency-equivalent to the
        locked read under writer contention**; a scanner acting on a torn / reorg-straddling view is
        worse than a slow scanner. Verified at source (`get_block_from_height` / `on_get_blocks_by_height`
        / the LMDB txn path):
        - **Single-block atomicity is LMDB's, not the lock's:** each `get_block_from_height` takes a
          fresh fully-committed MVCC snapshot (`TXN_PREFIX_RDONLY` renew-then-reset per call), so no
          single block read can tear or straddle a commit; `m_blockchain_lock` adds **nothing** to
          single-block atomicity.
        - **What the lock genuinely adds** is (a) a main+alt two-table lookup so a block migrating
          between chains mid-reorg is never missed by both reads — but this compensates for
          `on_get_block`'s *own* unlocked height→hash step (`blockchain.cpp:907`, no lock), which the
          atomic height→block `.bin` read has no analogue for, so a **by-height** read does not need it;
          and (b) cross-read snapshot coherence across a **multi-height** batch — which **neither path**
          provides across the scanner's existing *three separate* RPC calls
          (`get_block`+`get_transactions`+`get_o_indexes`), so the scanner does not rely on it.
        - **Therefore, for a single-height per-`P` read the lock-free path is consistency-equivalent** —
          the torn-view risk lives only in multi-height batches, which rung 1 avoids by construction
          (one block per call); worst case under an *unbatched* reorg a lock-free reader sees a *valid,
          whole, shorter chain* (a normal reorg the scanner already handles), never a torn block.

        This is a source **argument**, not a proof: the harness must **confirm** it with a
        writer-contention diff (§3 M-consistency), and rung 1 must not silently mint a **substitute**
        shared-resource channel one layer up (shared thread-pool queuing; the per-thread read txn is
        already per-call-fresh) — also measured (§3 M-substitute). If the diff diverges, the lock was
        doing consistency work the bare read drops, and the honest fix is rung 2 or a *bigger* rung 1
        (a consistency-preserving lock-free read built properly in Rust, not "just call `.bin`").
     2. **Wallet-side decorrelation** — a fetch-scheduling-jitter / randomized-order duty scoped to the
        **remote `PBlockSource` only** (`DaemonBlockSource`/`local` neither needs it, since enumeration
        already dwarfs timing there, nor gets it; it belongs at the `PBlockSource` layer, not the
        shared `BlockSource` trait, precisely because the threat is remote-only). The **fallback** if
        residual coupling survives the lock-free path.
     3. **C++ lock surgery** on `m_blockchain_lock` — last resort, deferred to the daemon→Rust port.

     **Default to rung 1 iff the lock-free path is *both* lower-coupling (§3 timing delta) *and*
     consistency-equivalent under the writer-contention diff (§3 M-consistency); else rung 2.** Rung 1
     exists *because the RPC server is ours.*

**Why measure *now*, not when the fetch path exists (the sharp reason):** the measurement's *result
changes the wallet-side design*. If #2's coupling magnitude survives the remote-threat evaluation
(§3b), the **remote** `PBlockSource` acquires a timing-decorrelation responsibility (a design
decision in DQ-T2.2/T2.3); if it does not, `PBlockSource` is a plain fetch shim. Freezing the
`PBlockSource` design *before* the measurement means either over-building a decorrelation shim
speculatively (violating get-it-right-not-speculatively) or under-building and retrofitting. Measure
first, and `PBlockSource` knows what it is responsible for.

---

## 3. The measurement (Round-0 task, before the wallet design freezes)

Vehicle: a regtest/FAKECHAIN `shekyld` (the Track-2 rig) with a small block set, driven by N
concurrent `get_block`-by-height fetchers from `127.0.0.1`.

- **M-enum:** with N persona connections open to the regtest daemon, confirm the count is observable
  in the **host TCP table** (`ss -t` / `/proc/net/tcp`, connections to the RPC port from `127.0.0.1`),
  and confirm the RPC *surface* leaks nothing — no RPC-connection-count field, and the (dead epee)
  `per_private_ip` cap does not gate N. *Output:* the §4 stated-cost paragraph (the residual is
  OS-intrinsic, below the RPC layer) + the design guardrail that our Rust RPC server must not add
  per-IP counting/caps.
- **M-timing:** drive N concurrent fetch streams and measure per-persona latency under contention —
  but the rig measures the **mechanism**, and the threat evaluation is a separate step on top of it
  (the reason the harness measures against the right adversary from the first line):
  - **(a) Mechanism — local Track-2 rig, *comparing both read paths*.** Characterize the
    daemon-internal coupling directly on loopback, *no Tor*, driving N concurrent fetchers on **each**
    path: the lock-taking **JSON-RPC `get_block`** (the real scanner path, `block_fetch.rs:79`) *and*
    the lock-free **`get_blocks_by_height.bin`** (`get_block_from_height`, no `m_blockchain_lock`). The
    load-bearing number is **how far a probe persona's latency shifts per unit of a contending
    persona's fetch activity, in absolute time**; the **delta between the two paths isolates the
    `m_blockchain_lock` contribution**. *Output:* the **coupling-magnitude distribution on each path**,
    not a signal/no-signal boolean. Loopback is the *correct* vehicle because the coupling is
    daemon-internal — Tor would only add noise to a mechanism measurement.
  - **(b) Threat evaluation — analysis on the magnitude.** Evaluate that distribution against the
    **remote-shared-daemon adversary**: does the coupling survive a Tor circuit's own jitter (compare
    the magnitude distribution against known Tor per-circuit latency-jitter)? *Output:* the DQ-T2.5 #2
    fork — below-floor ⇒ liveness/UX defer; at-or-above-floor ⇒ **rung 1** (serve lock-free) if the
    lock-free path measured coupling-free **and** consistency-equivalent (below), else **rung 2**
    (remote-`PBlockSource` decorrelation). The `local` posture is **not** evaluated here: its timing is
    subsumed by enumeration (#1).
- **M-consistency (the correctness gate on rung 1 — measures what makes rung 1 *safe*, not fast).**
  A latency-only harness would greenlight rung 1 without ever testing the thing that makes it safe, so
  the harness diffs **outputs**, not just timings: drive N per-`P` **single-height** reads on **both**
  paths *while the daemon is accepting blocks / doing a small reorg mid-fetch* (`generateblocks` +
  `pop_blocks` on the regtest chain), and **diff the two paths' returned blocks for the same heights**.
  *Output:* agreement under writer contention ⇒ rung 1 genuinely free (the timing question collapses to
  "serve lock-free, done"); divergence ⇒ the lock is doing consistency work the bare read drops ⇒ rung
  2 or a consistency-preserving Rust-side read. The source argument in DQ-T2.5 #2 (single-block reads
  are LMDB-atomic; the lock's multi-read guarantees aren't ones the by-height scanner relies on)
  predicts agreement — this measurement is what turns that prediction into a decision.
- **M-substitute (the boundary-shift check).** Rung 1 moves the per-`P` isolation boundary (SP-T1's
  proxy-isolation property), so the lock-free path is measured under **N-persona** contention — not
  just single-stream — so a *new* shared-resource coupling one layer up (a shared MVCC txn reused
  across personas, a shared read buffer, a shared thread pool with observable queuing) cannot hide
  behind the dissolved `m_blockchain_lock`. *Output:* the lock-free path's own coupling-magnitude
  distribution under N personas; dissolving the lock must not silently substitute a fresh timing
  channel.

M-enum / M-timing / M-substitute are read-only; **M-consistency** additionally drives the daemon's own
block-accept / `pop_blocks` on the throwaway regtest chain (the writer contention it must measure).
None modify the daemon *binary* — all drive existing RPC routes.

---

## 4. Decomposition (commit-slices — one PR unless it grows exceptionally large)

Per the ~10-commit-as-CI-cost-guideline, one reviewable PR, sliced by commit:

1. **Framing + docs** — correct §367 (add-not-replace), the §4 posture enumeration read-model,
   this Round-0 doc's decisions.
2. **`DaemonBlockSource` per-`P` direct connection** (DQ-T2.4) — with the enumeration tension stated.
3. **The RPC-over-Tor transport** (DQ-T2.2) — the source-verified per-`P`-isolated `Rpc`
   (`SimpleRequestRpc`-per-instance or `PRpc`), with an isolation KAT.
4. **`PBlockSource`** (DQ-T2.1/.3) — `new(client)` only, `tip_height`/`block_at` over #3 reusing
   `default_fetch_scannable_block`; plus a timing-decorrelation responsibility on the **remote** impl
   **iff** the M-timing coupling magnitude survived the remote-threat evaluation (§3b) — never on
   `DaemonBlockSource`/`local`.
5. **Posture→impl selector** at the scan-loop wiring (DQ-T2.3) — local→direct, remote→`PBlockSource`,
   conflation unrepresentable.
6. **Daemon disposition** — record M-enum / M-timing / **M-consistency** / **M-substitute** results
   (both read paths) + the chosen rung. Rung 1 is gated on the M-consistency diff **agreeing** *and*
   M-substitute showing **no** new channel; if selected (serve per-`P` reads via a **single-height**
   lock-free read), that is an **in-scope Rust RPC/FFI change** here, not a deferral; rungs 2/3 carry
   rule-21 reopens (FOLLOWUPS / the daemon→Rust-port note).

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
